//! Outbound notification capabilities and delivery workers.

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lettre::message::{Mailbox, Message};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use liblinkkeys::generated::types::{GetNotificationCapabilitiesResponse, NotificationCapability};
use rand::Rng;

use crate::db::models::NotificationOutboxItem;
use crate::db::DbPool;

const DEFAULT_LEASE_SECONDS: i64 = 60;
const DEFAULT_MAX_ATTEMPTS: i64 = 8;
const DEFAULT_POLL_MILLISECONDS: u64 = 1_000;
const MAX_BACKOFF_SECONDS: i64 = 3_600;
static EMAIL_WORKER_READY: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmtpSecurity {
    StartTls,
    Tls,
    Plaintext,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmtpTlsBackend {
    Rustls,
    Native,
}

#[derive(Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub security: SmtpSecurity,
    pub tls_backend: SmtpTlsBackend,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from: String,
    pub timeout: Duration,
    pub public_origin: String,
    pub outbox_key: [u8; 32],
    pub max_attempts: i64,
    pub lease_seconds: i64,
    pub poll_interval: Duration,
}

impl std::fmt::Debug for SmtpConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SmtpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("security", &self.security)
            .field("tls_backend", &self.tls_backend)
            .field("credentials", &"[redacted]")
            .field("from", &"[redacted]")
            .field("public_origin", &self.public_origin)
            .field("outbox_key", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl SmtpConfig {
    pub fn from_env() -> Result<Option<Self>, String> {
        let host = match std::env::var("SMTP_HOST") {
            Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
            _ => return Ok(None),
        };
        if host.contains("://") || host.chars().any(char::is_whitespace) {
            return Err("SMTP_HOST must contain one host name or IP address".to_string());
        }
        let security = match env_value("SMTP_SECURITY", "starttls").as_str() {
            "starttls" => SmtpSecurity::StartTls,
            "tls" => SmtpSecurity::Tls,
            "plaintext" => SmtpSecurity::Plaintext,
            _ => return Err("SMTP_SECURITY must be starttls, tls, or plaintext".to_string()),
        };
        let tls_backend = match env_value("SMTP_TLS_BACKEND", "rustls").as_str() {
            "rustls" => SmtpTlsBackend::Rustls,
            "native" => SmtpTlsBackend::Native,
            _ => return Err("SMTP_TLS_BACKEND must be rustls or native".to_string()),
        };
        if tls_backend == SmtpTlsBackend::Native && !cfg!(feature = "smtp-native-tls") {
            return Err(
                "SMTP_TLS_BACKEND=native requires a build with the smtp-native-tls feature"
                    .to_string(),
            );
        }
        if security == SmtpSecurity::Plaintext
            && std::env::var("SMTP_ALLOW_PLAINTEXT").as_deref() != Ok("true")
        {
            return Err("SMTP_SECURITY=plaintext requires SMTP_ALLOW_PLAINTEXT=true".to_string());
        }
        if security == SmtpSecurity::Plaintext && !is_loopback_host(&host) {
            return Err("Plaintext SMTP is limited to a loopback relay".to_string());
        }
        let port = parse_env("SMTP_PORT")?.unwrap_or(match security {
            SmtpSecurity::Tls => 465,
            SmtpSecurity::StartTls => 587,
            SmtpSecurity::Plaintext => 25,
        });
        if port == 0 {
            return Err("SMTP_PORT must be an integer from 1 to 65535".to_string());
        }
        let username = nonempty_env("SMTP_USERNAME");
        let password = secret_env("SMTP_PASSWORD");
        if username.is_some() != password.is_some() {
            return Err("SMTP_USERNAME and SMTP_PASSWORD must be set together".to_string());
        }
        let from = std::env::var("SMTP_FROM")
            .map_err(|_| "SMTP_FROM is required when SMTP is enabled".to_string())?;
        from.parse::<Mailbox>()
            .map_err(|_| "SMTP_FROM must be a valid mailbox".to_string())?;
        let public_origin = std::env::var("PUBLIC_ORIGIN")
            .map_err(|_| "PUBLIC_ORIGIN is required when SMTP is enabled".to_string())?;
        validate_public_origin(&public_origin)?;
        let timeout_seconds = parse_env("SMTP_TIMEOUT_SECONDS")?.unwrap_or(30_u64);
        if timeout_seconds == 0 {
            return Err("SMTP_TIMEOUT_SECONDS must be greater than zero".to_string());
        }
        let max_attempts = parse_env("OUTBOX_MAX_ATTEMPTS")?.unwrap_or(DEFAULT_MAX_ATTEMPTS);
        if max_attempts < 1 {
            return Err("OUTBOX_MAX_ATTEMPTS must be greater than zero".to_string());
        }
        let lease_seconds = parse_env("OUTBOX_LEASE_SECONDS")?.unwrap_or(DEFAULT_LEASE_SECONDS);
        if lease_seconds < 1 {
            return Err("OUTBOX_LEASE_SECONDS must be greater than zero".to_string());
        }
        let minimum_lease = i64::try_from(timeout_seconds)
            .ok()
            .and_then(|value| value.checked_mul(2))
            .ok_or_else(|| "SMTP_TIMEOUT_SECONDS is too large".to_string())?;
        if lease_seconds < minimum_lease {
            return Err(
                "OUTBOX_LEASE_SECONDS must be at least twice SMTP_TIMEOUT_SECONDS".to_string(),
            );
        }
        let poll_milliseconds =
            parse_env("OUTBOX_POLL_MILLISECONDS")?.unwrap_or(DEFAULT_POLL_MILLISECONDS);
        if poll_milliseconds < 10 {
            return Err("OUTBOX_POLL_MILLISECONDS must be at least 10".to_string());
        }
        Ok(Some(Self {
            host,
            port,
            security,
            tls_backend,
            username,
            password,
            from,
            timeout: Duration::from_secs(timeout_seconds),
            public_origin: public_origin.trim_end_matches('/').to_string(),
            outbox_key: outbox_key()?,
            max_attempts,
            lease_seconds,
            poll_interval: Duration::from_millis(poll_milliseconds),
        }))
    }
}

fn env_value(name: &str, default: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| default.to_string())
        .trim()
        .to_ascii_lowercase()
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn secret_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn parse_env<T>(name: &str) -> Result<Option<T>, String>
where
    T: std::str::FromStr,
{
    std::env::var(name)
        .ok()
        .map(|value| {
            value
                .parse::<T>()
                .map_err(|_| format!("{name} has an invalid value"))
        })
        .transpose()
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

pub(crate) fn validate_public_origin(value: &str) -> Result<(), String> {
    let origin = reqwest::Url::parse(value)
        .map_err(|_| "PUBLIC_ORIGIN must be a valid HTTPS origin".to_string())?;
    if origin.scheme() != "https"
        || origin.host_str().is_none()
        || origin.cannot_be_a_base()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
        || !origin.username().is_empty()
        || origin.password().is_some()
    {
        return Err("PUBLIC_ORIGIN must be an HTTPS origin without a path".to_string());
    }
    Ok(())
}

pub fn email_available() -> bool {
    EMAIL_WORKER_READY.load(Ordering::SeqCst)
}

pub fn capabilities() -> GetNotificationCapabilitiesResponse {
    let mut response = capabilities_for(email_available());
    if !crate::services::password::authentication_enabled() {
        response.capabilities.clear();
    }
    response
}

pub fn capabilities_for(email_ready: bool) -> GetNotificationCapabilitiesResponse {
    let capabilities = if email_ready {
        ["verify_contact", "reset_password"]
            .into_iter()
            .map(|purpose| NotificationCapability {
                purpose: purpose.to_string(),
                channel: "email".to_string(),
                destination_kind: "email".to_string(),
            })
            .collect()
    } else {
        Vec::new()
    };
    GetNotificationCapabilitiesResponse { capabilities }
}

pub trait NotificationDispatcher {
    fn dispatch(&self, intent: NotificationIntent) -> Result<(), String>;
}

pub struct NotificationIntent {
    pub user_id: String,
    pub purpose: String,
    pub channel: String,
    pub destination: String,
    pub token_digest: String,
    pub secret_payload: Vec<u8>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// When present, the database creates the challenge only while this
    /// password credential remains active.
    pub required_credential_id: Option<String>,
}

pub struct DatabaseNotificationDispatcher {
    pool: DbPool,
}

impl DatabaseNotificationDispatcher {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

impl NotificationDispatcher for DatabaseNotificationDispatcher {
    fn dispatch(&self, intent: NotificationIntent) -> Result<(), String> {
        let payload = encrypt_payload(&intent.secret_payload)?;
        self.pool
            .create_account_challenge_and_outbox(
                &intent.user_id,
                &intent.purpose,
                &intent.channel,
                &intent.destination,
                &intent.token_digest,
                payload,
                intent.expires_at,
                intent.required_credential_id.as_deref(),
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PreparedEmail {
    pub from: String,
    pub to: String,
    pub subject: String,
    pub body: String,
}

impl std::fmt::Debug for PreparedEmail {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedEmail")
            .field("to", &"[redacted]")
            .field("subject", &self.subject)
            .field("text", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryFailure {
    pub category: &'static str,
    pub permanent: bool,
}

type DeliveryFuture<'a> = Pin<Box<dyn Future<Output = Result<(), DeliveryFailure>> + Send + 'a>>;

pub trait EmailTransport: Send + Sync {
    fn send<'a>(&'a self, message: PreparedEmail) -> DeliveryFuture<'a>;
}

pub trait DeliveryChannel: Send + Sync {
    fn channel(&self) -> &'static str;
    fn supports(&self, purpose: &str) -> bool;
    fn deliver<'a>(
        &'a self,
        item: &'a NotificationOutboxItem,
        secret_payload: &'a [u8],
    ) -> DeliveryFuture<'a>;
}

pub struct EmailDeliveryChannel {
    from: String,
    transport: Arc<dyn EmailTransport>,
}

impl EmailDeliveryChannel {
    pub fn new(from: String, transport: Arc<dyn EmailTransport>) -> Self {
        Self { from, transport }
    }

    fn prepare(
        &self,
        item: &NotificationOutboxItem,
        payload: &[u8],
    ) -> Result<PreparedEmail, DeliveryFailure> {
        let link = std::str::from_utf8(payload).map_err(|_| DeliveryFailure {
            category: "invalid_payload",
            permanent: true,
        })?;
        let (subject, introduction) = match item.purpose.as_str() {
            "verify_contact" => (
                "Verify your LinkKeys email address",
                "Use this link to verify your email address:",
            ),
            "reset_password" => (
                "Reset your LinkKeys password",
                "Use this link to set a new password:",
            ),
            _ => {
                return Err(DeliveryFailure {
                    category: "unsupported_purpose",
                    permanent: true,
                })
            }
        };
        Ok(PreparedEmail {
            from: self.from.clone(),
            to: item.destination.clone(),
            subject: subject.to_string(),
            body: format!(
                "A request was made for your LinkKeys account at {domain}.\n\n{introduction}\n\n{link}\n\nThis link expires at {expires}. If you did not request this action, you can ignore this message.",
                domain = crate::conversions::get_domain_name(),
                expires = item.expires_at,
            ),
        })
    }
}

impl DeliveryChannel for EmailDeliveryChannel {
    fn channel(&self) -> &'static str {
        "email"
    }

    fn supports(&self, purpose: &str) -> bool {
        matches!(purpose, "verify_contact" | "reset_password")
    }

    fn deliver<'a>(
        &'a self,
        item: &'a NotificationOutboxItem,
        secret_payload: &'a [u8],
    ) -> DeliveryFuture<'a> {
        let message = match self.prepare(item, secret_payload) {
            Ok(value) => value,
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        self.transport.send(message)
    }
}

pub struct SmtpEmailTransport {
    mailer: AsyncSmtpTransport<Tokio1Executor>,
}

impl SmtpEmailTransport {
    pub fn new(config: &SmtpConfig) -> Result<Self, String> {
        let tls = match config.security {
            SmtpSecurity::Plaintext => Tls::None,
            SmtpSecurity::StartTls => Tls::Required(tls_parameters(config)?),
            SmtpSecurity::Tls => Tls::Wrapper(tls_parameters(config)?),
        };
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host)
            .port(config.port)
            .tls(tls)
            .timeout(Some(config.timeout));
        if let (Some(username), Some(password)) = (&config.username, &config.password) {
            builder = builder.credentials(Credentials::new(username.clone(), password.clone()));
        }
        Ok(Self {
            mailer: builder.build(),
        })
    }
}

fn tls_parameters(config: &SmtpConfig) -> Result<TlsParameters, String> {
    match config.tls_backend {
        SmtpTlsBackend::Rustls => TlsParameters::new_rustls(config.host.clone())
            .map_err(|_| "Could not configure Rustls for SMTP".to_string()),
        SmtpTlsBackend::Native => {
            #[cfg(feature = "smtp-native-tls")]
            {
                TlsParameters::new_native(config.host.clone())
                    .map_err(|_| "Could not configure native TLS for SMTP".to_string())
            }
            #[cfg(not(feature = "smtp-native-tls"))]
            {
                Err("Native TLS is not available in this build".to_string())
            }
        }
    }
}

impl EmailTransport for SmtpEmailTransport {
    fn send<'a>(&'a self, message: PreparedEmail) -> DeliveryFuture<'a> {
        let email = (|| {
            let from = message
                .from
                .parse::<Mailbox>()
                .map_err(|_| DeliveryFailure {
                    category: "invalid_sender",
                    permanent: true,
                })?;
            let to = message.to.parse::<Mailbox>().map_err(|_| DeliveryFailure {
                category: "invalid_destination",
                permanent: true,
            })?;
            Message::builder()
                .from(from)
                .to(to)
                .subject(message.subject)
                .body(message.body)
                .map_err(|_| DeliveryFailure {
                    category: "message_build",
                    permanent: true,
                })
        })();
        Box::pin(async move {
            let email = email?;
            self.mailer.send(email).await.map(|_| ()).map_err(|error| {
                if error.is_permanent() {
                    DeliveryFailure {
                        category: "smtp_permanent",
                        permanent: true,
                    }
                } else if error.is_timeout() {
                    DeliveryFailure {
                        category: "smtp_timeout",
                        permanent: false,
                    }
                } else if error.is_tls() {
                    DeliveryFailure {
                        category: "smtp_tls",
                        permanent: false,
                    }
                } else {
                    DeliveryFailure {
                        category: "smtp_temporary",
                        permanent: false,
                    }
                }
            })
        })
    }
}

#[derive(Default)]
pub struct InMemoryEmailTransport {
    messages: Mutex<Vec<PreparedEmail>>,
    failures: Mutex<Vec<DeliveryFailure>>,
}

impl InMemoryEmailTransport {
    pub fn messages(&self) -> Vec<PreparedEmail> {
        self.messages.lock().expect("message lock").clone()
    }

    pub fn fail_next(&self, failure: DeliveryFailure) {
        self.failures.lock().expect("failure lock").push(failure);
    }
}

impl EmailTransport for InMemoryEmailTransport {
    fn send<'a>(&'a self, message: PreparedEmail) -> DeliveryFuture<'a> {
        let failure = self.failures.lock().expect("failure lock").pop();
        if failure.is_none() {
            self.messages.lock().expect("message lock").push(message);
        }
        Box::pin(async move { failure.map_or(Ok(()), Err) })
    }
}

pub struct OutboxWorker {
    pool: DbPool,
    channel: Arc<dyn DeliveryChannel>,
    worker_id: String,
    key: [u8; 32],
    max_attempts: i64,
    lease_seconds: i64,
}

impl OutboxWorker {
    pub fn new(
        pool: DbPool,
        channel: Arc<dyn DeliveryChannel>,
        key: [u8; 32],
        max_attempts: i64,
        lease_seconds: i64,
    ) -> Self {
        Self {
            pool,
            channel,
            worker_id: uuid::Uuid::now_v7().to_string(),
            key,
            max_attempts,
            lease_seconds,
        }
    }

    pub async fn run_once(&self) -> Result<bool, String> {
        self.pool
            .expire_notification_outbox()
            .map_err(|error| error.to_string())?;
        let Some(item) = self
            .pool
            .claim_notification_outbox(self.channel.channel(), &self.worker_id, self.lease_seconds)
            .map_err(|error| error.to_string())?
        else {
            return Ok(false);
        };
        match self.deliver(&item).await {
            Ok(()) => {
                let changed = self
                    .pool
                    .finish_notification_outbox(
                        &item.id,
                        &self.worker_id,
                        "delivered",
                        chrono::Utc::now(),
                        None,
                        true,
                    )
                    .map_err(|error| error.to_string())?;
                if changed != 1 {
                    return Err("The outbox delivery lease was lost".to_string());
                }
                log::info!(
                    "Delivered notification outbox item {} for purpose {}",
                    item.id,
                    item.purpose
                );
            }
            Err(failure) => {
                let terminal = failure.permanent || item.attempt_count >= self.max_attempts;
                let state = if terminal { "failed" } else { "pending" };
                let next = if terminal {
                    chrono::Utc::now()
                } else {
                    next_attempt(item.attempt_count)
                };
                let changed = self
                    .pool
                    .finish_notification_outbox(
                        &item.id,
                        &self.worker_id,
                        state,
                        next,
                        Some(failure.category),
                        terminal,
                    )
                    .map_err(|error| error.to_string())?;
                if changed != 1 {
                    return Err("The outbox delivery lease was lost".to_string());
                }
                log::warn!(
                    "Notification outbox item {} attempt {} ended with category {}",
                    item.id,
                    item.attempt_count,
                    failure.category
                );
            }
        }
        Ok(true)
    }

    async fn deliver(&self, item: &NotificationOutboxItem) -> Result<(), DeliveryFailure> {
        if item.channel != self.channel.channel() || !self.channel.supports(&item.purpose) {
            return Err(DeliveryFailure {
                category: "unsupported_channel",
                permanent: true,
            });
        }
        let encrypted = item.encrypted_payload.as_deref().ok_or(DeliveryFailure {
            category: "missing_payload",
            permanent: true,
        })?;
        let payload =
            liblinkkeys::crypto::decrypt_with_key(&self.key, encrypted).map_err(|_| {
                DeliveryFailure {
                    category: "payload_decryption",
                    permanent: true,
                }
            })?;
        let lease_expires_at = item
            .lease_expires_at
            .as_deref()
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.with_timezone(&chrono::Utc))
            .ok_or(DeliveryFailure {
                category: "invalid_lease",
                permanent: false,
            })?;
        let remaining = lease_expires_at.signed_duration_since(chrono::Utc::now());
        let configured_timeout =
            std::time::Duration::from_secs((self.lease_seconds / 2).max(1) as u64);
        let timeout = (remaining.to_std().unwrap_or_default() / 2).min(configured_timeout);
        if timeout.is_zero() {
            return Err(DeliveryFailure {
                category: "delivery_timeout",
                permanent: false,
            });
        }
        match tokio::time::timeout(timeout, self.channel.deliver(item, &payload)).await {
            Ok(result) => result,
            Err(_) => Err(DeliveryFailure {
                category: "delivery_timeout",
                permanent: false,
            }),
        }
    }
}

fn next_attempt(attempt_count: i64) -> chrono::DateTime<chrono::Utc> {
    let exponent = u32::try_from(attempt_count.saturating_sub(1).min(10)).unwrap_or(0);
    let base = (5_i64.saturating_mul(2_i64.pow(exponent))).min(MAX_BACKOFF_SECONDS);
    let jitter = rand::thread_rng().gen_range(0..=(base / 4).max(1));
    chrono::Utc::now() + chrono::Duration::seconds(base + jitter)
}

struct AvailabilityGuard;

impl Drop for AvailabilityGuard {
    fn drop(&mut self) {
        EMAIL_WORKER_READY.store(false, Ordering::SeqCst);
    }
}

pub fn start_worker(
    pool: DbPool,
    ready: Arc<AtomicBool>,
) -> Result<Option<std::thread::JoinHandle<()>>, String> {
    let Some(config) = SmtpConfig::from_env()? else {
        return Ok(None);
    };
    let (startup_tx, startup_rx) = std::sync::mpsc::sync_channel(1);
    let handle = std::thread::Builder::new()
        .name("linkkeys-outbox".to_string())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(value) => value,
                Err(_) => {
                    let _ = startup_tx.send(Err(
                        "Could not start the outbound worker runtime".to_string()
                    ));
                    return;
                }
            };
            runtime.block_on(async {
                // Lettre starts a Tokio task for its connection pool when the
                // transport is built. Build and own it inside this runtime.
                let transport = match SmtpEmailTransport::new(&config) {
                    Ok(value) => Arc::new(value),
                    Err(error) => {
                        let _ = startup_tx.send(Err(error));
                        return;
                    }
                };
                let channel = Arc::new(EmailDeliveryChannel::new(config.from.clone(), transport));
                let worker = OutboxWorker::new(
                    pool,
                    channel,
                    config.outbox_key,
                    config.max_attempts,
                    config.lease_seconds,
                );
                let poll_interval = config.poll_interval;
                let _availability = AvailabilityGuard;
                EMAIL_WORKER_READY.store(true, Ordering::SeqCst);
                log::info!(
                    "Outbound email worker is configured; relay delivery has not yet been tested"
                );
                if startup_tx.send(Ok(())).is_err() {
                    return;
                }
                while !ready.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                loop {
                    match worker.run_once().await {
                        Ok(true) => continue,
                        Ok(false) => tokio::time::sleep(poll_interval).await,
                        Err(_) => {
                            log::error!("Notification outbox worker failed");
                            tokio::time::sleep(poll_interval).await;
                        }
                    }
                }
            });
        })
        .map_err(|_| "Could not start the outbound worker thread".to_string())?;
    match startup_rx.recv() {
        Ok(Ok(())) => Ok(Some(handle)),
        Ok(Err(error)) => {
            let _ = handle.join();
            Err(error)
        }
        Err(_) => {
            let _ = handle.join();
            Err("The outbound worker stopped during startup".to_string())
        }
    }
}

pub fn outbox_key() -> Result<[u8; 32], String> {
    let raw = std::env::var("OUTBOX_ENCRYPTION_KEY")
        .map_err(|_| "OUTBOX_ENCRYPTION_KEY is required for outbound notifications".to_string())?;
    if raw.len() == 64 {
        let mut key = [0_u8; 32];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&raw[index * 2..index * 2 + 2], 16).map_err(|_| {
                "OUTBOX_ENCRYPTION_KEY must be 32 bytes in hexadecimal or base64url".to_string()
            })?;
        }
        return Ok(key);
    }
    use base64ct::{Base64UrlUnpadded, Encoding};
    let decoded = Base64UrlUnpadded::decode_vec(&raw).map_err(|_| {
        "OUTBOX_ENCRYPTION_KEY must be 32 bytes in hexadecimal or base64url".to_string()
    })?;
    decoded
        .try_into()
        .map_err(|_| "OUTBOX_ENCRYPTION_KEY must contain 32 bytes".to_string())
}

pub fn encrypt_payload(payload: &[u8]) -> Result<Vec<u8>, String> {
    liblinkkeys::crypto::encrypt_with_key(&outbox_key()?, payload)
        .map_err(|error| error.to_string())
}
