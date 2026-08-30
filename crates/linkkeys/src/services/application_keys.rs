//! Application-key enrollment, attestation, renewal, revocation, and the
//! anonymous public read.
//!
//! This is the server boundary over the pure rules in
//! [`liblinkkeys::application_keys`]. Everything that needs a database, a
//! clock, configuration, or the domain's own signing keys lives here; every
//! quorum, possession, and temporal rule lives there and is tested there.
//!
//! # What the home domain does and does not do
//!
//! It associates an application instance with a canonical account identity,
//! verifies proof of possession, verifies application-key quorum operations,
//! makes short-lived attestations for individual public keys, and publishes
//! keys, attestations, and revocations. It does NOT authorize an application's
//! peers, see its messages, sign its messages, or hold any of its private
//! keys. There is no `sign-payload` operation and there must never be one: it
//! would make this server an online signing oracle whose load scales with an
//! application's message and peer volume instead of with key enrollment.
//!
//! # Authentication
//!
//! Only initial enrollment is account-authenticated (it runs on the `Account`
//! service, where the account owner has already proven who they are). Adding,
//! renewing, and revoking are authenticated at the APPLICATION layer by the
//! application's own signatures over a canonical payload — the authority for
//! those operations is the application key quorum, not a transport credential.
//! The public read and the challenge issue are anonymous by design.

use chrono::{DateTime, Duration, Utc};
use liblinkkeys::application_keys::{
    self as ak, ApplicationKeyError, ApplicationKeyRef, InstanceRef,
};
use liblinkkeys::generated::services::ServiceError;
use liblinkkeys::generated::types::{
    AddApplicationKeyRequest, AddApplicationKeyResponse, ApplicationKeyAddition,
    ApplicationKeyRevocation, EnrollApplicationInstanceRequest, EnrollApplicationInstanceResponse,
    GetApplicationKeysRequest, GetApplicationKeysResponse, RenewApplicationKeyAttestationRequest,
    RenewApplicationKeyAttestationResponse, RevokeApplicationKeyRequest,
    RevokeApplicationKeyResponse, SignedApplicationKeyAttestation,
    StartApplicationKeyChallengeRequest, StartApplicationKeyChallengeResponse,
};
use std::sync::LazyLock;

use crate::conversions::get_domain_name;
use crate::db::models::ApplicationKey as ApplicationKeyRow;
use crate::db::DbPool;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Operator-tunable bounds for the application-key surface.
///
/// Every one of these is a bound on an ATTACKER as much as a knob for an
/// operator, so each is validated at startup rather than trusted at use.
#[derive(Debug, Clone)]
pub struct AppKeyConfig {
    /// How long one attestation is good for. This value IS the revocation
    /// propagation window: a verifier may accept a revoked key until its
    /// current attestation expires.
    pub attestation_lifetime_seconds: i64,
    /// The longest key lifetime this domain will attest, whatever the
    /// application asks for.
    pub max_key_lifetime_seconds: i64,
    /// How far back the public read reports revocations.
    pub revocation_window_seconds: i64,
    /// Tolerated clock skew for every timestamp check.
    pub clock_skew_seconds: i64,
    /// How long an issued challenge nonce stays usable.
    pub challenge_ttl_seconds: i64,
    /// The most keys one instance may hold. This is the real bound on the
    /// revocation list: the list can only grow as fast as keys can be added.
    pub max_keys_per_instance: i64,
    /// The most revocation records the public read will return. Exceeding it
    /// is an ERROR, never a truncated list.
    pub max_revocations: i64,
    /// The largest encoded public response this domain will produce.
    pub max_response_bytes: usize,
    /// Renewals allowed per hour for one subject+application+instance.
    pub renewal_quota_per_hour: f64,
    /// Key additions allowed per hour for one subject+application+instance.
    pub addition_quota_per_hour: f64,
}

impl AppKeyConfig {
    fn from_env() -> Result<Self, String> {
        use crate::config::{nonneg_i64_env, nonzero_u64_env, positive_f64_env};
        Ok(Self {
            attestation_lifetime_seconds: nonneg_i64_env(
                "APPLICATION_KEY_ATTESTATION_LIFETIME_SECONDS",
                ak::DEFAULT_ATTESTATION_LIFETIME_SECONDS,
            )?,
            max_key_lifetime_seconds: nonneg_i64_env(
                "APPLICATION_KEY_MAX_LIFETIME_SECONDS",
                365 * 86_400,
            )?,
            revocation_window_seconds: nonneg_i64_env(
                "APPLICATION_KEY_REVOCATION_WINDOW_SECONDS",
                ak::DEFAULT_REVOCATION_WINDOW_SECONDS,
            )?,
            clock_skew_seconds: nonneg_i64_env("APPLICATION_KEY_CLOCK_SKEW_SECONDS", 300)?,
            challenge_ttl_seconds: nonneg_i64_env("APPLICATION_KEY_CHALLENGE_TTL_SECONDS", 300)?,
            max_keys_per_instance: nonneg_i64_env("APPLICATION_KEY_MAX_KEYS_PER_INSTANCE", 16)?,
            max_revocations: nonneg_i64_env("APPLICATION_KEY_MAX_REVOCATIONS", 1024)?,
            max_response_bytes: nonzero_u64_env("APPLICATION_KEY_MAX_RESPONSE_BYTES", 512 * 1024)?
                as usize,
            renewal_quota_per_hour: positive_f64_env(
                "APPLICATION_KEY_RENEWAL_QUOTA_PER_HOUR",
                60.0,
            )?,
            addition_quota_per_hour: positive_f64_env(
                "APPLICATION_KEY_ADDITION_QUOTA_PER_HOUR",
                10.0,
            )?,
        })
    }

    /// Refuse a self-defeating configuration at startup rather than discover
    /// it in the field.
    pub fn validate(&self) -> Result<(), String> {
        if self.attestation_lifetime_seconds <= self.clock_skew_seconds * 10 {
            return Err(format!(
                "APPLICATION_KEY_ATTESTATION_LIFETIME_SECONDS ({}) must exceed the permitted \
                 clock skew ({}) by a wide margin",
                self.attestation_lifetime_seconds, self.clock_skew_seconds
            ));
        }
        // The one failure this design refuses to have: a revoked but unexpired
        // key that verifies clean because its revocation fell out of the
        // look-back window.
        ak::validate_revocation_window(
            self.revocation_window_seconds,
            self.max_key_lifetime_seconds,
            self.attestation_lifetime_seconds,
            self.clock_skew_seconds,
        )
        .map_err(|e| e.to_string())?;
        if self.max_keys_per_instance < ak::MIN_SIGNING_KEYS as i64 {
            return Err(format!(
                "APPLICATION_KEY_MAX_KEYS_PER_INSTANCE ({}) is below the {} signing keys an \
                 instance must hold",
                self.max_keys_per_instance,
                ak::MIN_SIGNING_KEYS
            ));
        }
        Ok(())
    }
}

static CONFIG: LazyLock<AppKeyConfig> = LazyLock::new(|| {
    AppKeyConfig::from_env().unwrap_or_else(|e| {
        // A bad value here is an operator error that must be loud. The startup
        // check below turns it into a refusal to serve; this fallback only
        // keeps a mis-set variable from panicking a request thread.
        log::error!("application key configuration is invalid: {e}");
        AppKeyConfig {
            attestation_lifetime_seconds: ak::DEFAULT_ATTESTATION_LIFETIME_SECONDS,
            max_key_lifetime_seconds: 365 * 86_400,
            revocation_window_seconds: ak::DEFAULT_REVOCATION_WINDOW_SECONDS,
            clock_skew_seconds: 300,
            challenge_ttl_seconds: 300,
            max_keys_per_instance: 16,
            max_revocations: 1024,
            max_response_bytes: 512 * 1024,
            renewal_quota_per_hour: 60.0,
            addition_quota_per_hour: 10.0,
        }
    })
});

pub fn config() -> &'static AppKeyConfig {
    &CONFIG
}

/// Startup gate. The server must call this and refuse to start on an error —
/// a configuration in which a revoked, unexpired key could verify clean is not
/// something to discover from a security incident.
pub fn validate_configuration() -> Result<(), String> {
    AppKeyConfig::from_env()?.validate()
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

fn bad_request(message: impl Into<String>) -> ServiceError {
    ServiceError {
        code: 400,
        message: message.into(),
    }
}

fn not_found(message: impl Into<String>) -> ServiceError {
    ServiceError {
        code: 404,
        message: message.into(),
    }
}

fn forbidden(message: impl Into<String>) -> ServiceError {
    ServiceError {
        code: 403,
        message: message.into(),
    }
}

fn too_many(message: impl Into<String>) -> ServiceError {
    ServiceError {
        code: 429,
        message: message.into(),
    }
}

/// Internal failures are logged with their cause and answered with a flat
/// message. A caller of an anonymous surface learns nothing about our internals.
fn internal(context: &str, cause: impl std::fmt::Display) -> ServiceError {
    log::error!("application keys: {context}: {cause}");
    ServiceError {
        code: 500,
        message: "internal error".to_string(),
    }
}

/// Protocol rule violations are safe to report verbatim: they describe the
/// caller's own request, never our state. They never include key material.
fn protocol(e: ApplicationKeyError) -> ServiceError {
    bad_request(e.to_string())
}

// ---------------------------------------------------------------------------
// Row conversion
// ---------------------------------------------------------------------------

fn to_key_ref(row: &ApplicationKeyRow) -> ApplicationKeyRef {
    ApplicationKeyRef {
        key_id: row.key_id.clone(),
        key_usage: row.key_usage.clone(),
        algorithm: row.algorithm.clone(),
        public_key: row.public_key.clone(),
        fingerprint: row.fingerprint.clone(),
        created_at: row.created_at.clone(),
        expires_at: row.expires_at.clone(),
        revoked_at: row.revoked_at.clone(),
    }
}

fn parse_rfc3339(value: &str) -> Result<DateTime<Utc>, ServiceError> {
    DateTime::parse_from_rfc3339(value)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| bad_request(format!("bad timestamp: {e}")))
}

// ---------------------------------------------------------------------------
// Challenges
// ---------------------------------------------------------------------------

/// Issue a single-use nonce for an add or a renew.
///
/// This operation is anonymous and deliberately answers IDENTICALLY for a
/// known and an unknown instance. A nonce is useless without the matching
/// private key, and answering differently would turn this into an
/// instance-existence oracle — exactly the reconnaissance surface the design
/// refuses to add.
pub fn start_challenge(
    pool: &DbPool,
    request: StartApplicationKeyChallengeRequest,
    now: DateTime<Utc>,
) -> Result<StartApplicationKeyChallengeResponse, ServiceError> {
    if request.purpose != ak::PURPOSE_ADD && request.purpose != ak::PURPOSE_RENEW {
        return Err(bad_request(format!(
            "purpose must be {} or {}",
            ak::PURPOSE_ADD,
            ak::PURPOSE_RENEW
        )));
    }
    // This operation is anonymous and it WRITES a row, so every value that
    // reaches storage is bounded first. Without this an unauthenticated caller
    // could use the identifier fields as a payload.
    check_identifier("subject_user_id", &request.subject_user_id)?;
    check_identifier("application_id", &request.application_id)?;
    check_identifier("instance_id", &request.instance_id)?;
    // The caller supplies no fingerprint here, so only the use, the algorithm,
    // and the key length are checkable. `check_key_shape` covers all three
    // once it is given the fingerprint of the key it was handed.
    ak::check_key_shape(
        &request.key_usage,
        &request.algorithm,
        &request.public_key,
        &liblinkkeys::crypto::fingerprint(&request.public_key),
    )
    .map_err(protocol)?;

    let cfg = config();
    let nonce = random_nonce();
    let challenge_id = uuid::Uuid::now_v7().to_string();
    let expires_at = now + Duration::seconds(cfg.challenge_ttl_seconds);

    // Opportunistic cleanup keeps the challenge table from growing without a
    // scheduled job. It is TIME-GATED rather than run per call: this path is
    // anonymous and rate-limited to a high request rate, and a delete scan on
    // every request would hand an attacker a cheap way to make us do expensive
    // work. Best effort either way — a failure here must not fail the call.
    if should_sweep_challenges(now) {
        if let Err(e) = pool.delete_expired_application_key_challenges(now) {
            log::debug!("application keys: could not sweep expired challenges: {e}");
        }
    }

    pool.insert_application_key_challenge(
        &challenge_id,
        &request.subject_user_id,
        &request.application_id,
        &request.instance_id,
        &request.purpose,
        &request.key_usage,
        &request.algorithm,
        &request.public_key,
        &nonce,
        expires_at,
    )
    .map_err(|e| internal("storing challenge", e))?;

    // An Ed25519 key gets the plaintext and proves possession by signing it.
    // An X25519 key cannot sign, so it gets the nonce SEALED to the public key
    // it claims, and proves possession by returning the plaintext it recovers.
    // Without that second path an instance could enrol a key another party
    // holds.
    if request.key_usage == ak::KEY_USAGE_AGREE {
        let recipient: [u8; 32] = request
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| bad_request("x25519 public key must be 32 bytes"))?;
        let sealed =
            ak::seal_challenge(&nonce, &recipient).map_err(|e| internal("sealing challenge", e))?;
        return Ok(StartApplicationKeyChallengeResponse {
            challenge_id,
            challenge: None,
            sealed_challenge: Some(sealed),
            expires_at: expires_at.to_rfc3339(),
        });
    }

    Ok(StartApplicationKeyChallengeResponse {
        challenge_id,
        challenge: Some(nonce),
        sealed_challenge: None,
        expires_at: expires_at.to_rfc3339(),
    })
}

/// At most one expired-challenge sweep per this many seconds, process-wide.
const CHALLENGE_SWEEP_INTERVAL_SECONDS: i64 = 60;

static LAST_CHALLENGE_SWEEP: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

fn should_sweep_challenges(now: DateTime<Utc>) -> bool {
    use std::sync::atomic::Ordering;
    let now_secs = now.timestamp();
    let last = LAST_CHALLENGE_SWEEP.load(Ordering::Relaxed);
    if now_secs - last < CHALLENGE_SWEEP_INTERVAL_SECONDS {
        return false;
    }
    // Compare-and-swap so a burst of concurrent requests produces one sweep,
    // not one per request.
    LAST_CHALLENGE_SWEEP
        .compare_exchange(last, now_secs, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}

fn random_nonce() -> Vec<u8> {
    use rand::RngCore;
    let mut nonce = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Consume the challenge a request names and confirm it matches the request in
/// every way that matters. Single use is enforced by the database, so a replay
/// finds nothing to consume.
struct ChallengeUse<'a> {
    challenge_id: &'a str,
    presented_nonce: &'a [u8],
    purpose: &'a str,
    instance: &'a InstanceRef<'a>,
    key_usage: &'a str,
    algorithm: &'a str,
    public_key: &'a [u8],
}

fn consume_challenge(
    pool: &DbPool,
    use_of: ChallengeUse<'_>,
    now: DateTime<Utc>,
) -> Result<(), ServiceError> {
    let ChallengeUse {
        challenge_id,
        presented_nonce,
        purpose,
        instance,
        key_usage,
        algorithm,
        public_key,
    } = use_of;
    let row = pool
        .consume_application_key_challenge(challenge_id, now)
        .map_err(|e| internal("consuming challenge", e))?
        .ok_or_else(|| bad_request("challenge is unknown, expired, or already used"))?;

    // Constant-time compare: the nonce is the proof-of-possession secret for a
    // key-agreement key, so a timing oracle here would leak it byte by byte.
    if !constant_time_eq(&row.nonce, presented_nonce) {
        return Err(bad_request("challenge does not match"));
    }
    if row.purpose != purpose
        || row.subject_user_id != instance.subject_user_id
        || row.application_id != instance.application_id
        || row.instance_id != instance.instance_id
        || row.key_usage != key_usage
        || row.algorithm != algorithm
        || row.public_key != public_key
    {
        return Err(bad_request("challenge was issued for a different request"));
    }
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Attestation issuance
// ---------------------------------------------------------------------------

/// Make and store a fresh attestation for one key.
///
/// This is the only place in this module that touches the domain's private
/// keys, and it is the expensive part of the whole design — see
/// [`crate::services::warm_signer`] for why the derivation is cached.
fn issue_attestation(
    pool: &DbPool,
    instance: &InstanceRef<'_>,
    key: &ApplicationKeyRef,
    key_row_id: &str,
    now: DateTime<Utc>,
) -> Result<SignedApplicationKeyAttestation, ServiceError> {
    let cfg = config();
    let attestation = ak::build_attestation(instance, key, now, cfg.attestation_lifetime_seconds);

    let signed = crate::services::warm_signer::with_active_signers(pool, |signers| {
        let claim_signers: Vec<liblinkkeys::claims::ClaimSigner<'_>> = signers
            .iter()
            .map(|s| liblinkkeys::claims::ClaimSigner {
                domain: instance.subject_domain,
                key_id: s.key_id,
                algorithm: s.algorithm,
                private_key_bytes: s.private_key,
            })
            .collect();
        ak::sign_attestation(&attestation, &claim_signers)
    })
    .map_err(|e| internal("signing attestation", e))?
    .map_err(|e| internal("signing attestation", e))?;

    let expires_at = parse_rfc3339(&attestation.attestation_expires_at)?;
    let bytes = liblinkkeys::generated::encode_signed_application_key_attestation(&signed);
    pool.upsert_application_key_attestation(key_row_id, &bytes, now, expires_at)
        .map_err(|e| internal("storing attestation", e))?;

    invalidate_cache(instance);
    Ok(signed)
}

/// Drop the cached public response for one instance. Called after EVERY write
/// that changes what the public read would return, and only after the database
/// transaction has succeeded — the database stays the source of truth.
fn invalidate_cache(instance: &InstanceRef<'_>) {
    crate::services::pubkey_cache::invalidate_application_keys(
        instance.subject_user_id,
        instance.subject_domain,
        instance.application_id,
        instance.instance_id,
    );
}

// ---------------------------------------------------------------------------
// Initial enrollment
// ---------------------------------------------------------------------------

/// Enrol a new application instance for an ALREADY AUTHENTICATED account.
///
/// `subject_user_id` comes from the authenticated session or API key, never
/// from the request body — otherwise any caller could enrol keys against
/// somebody else's identity.
pub fn enroll_instance(
    pool: &DbPool,
    subject_user_id: &str,
    request: EnrollApplicationInstanceRequest,
    now: DateTime<Utc>,
) -> Result<EnrollApplicationInstanceResponse, ServiceError> {
    let cfg = config();
    let domain = get_domain_name();
    let instance = InstanceRef {
        subject_user_id,
        subject_domain: &domain,
        application_id: &request.application_id,
        instance_id: &request.instance_id,
    };
    check_identifier("application_id", &request.application_id)?;
    check_identifier("instance_id", &request.instance_id)?;

    if request.keys.len() as i64 > cfg.max_keys_per_instance {
        return Err(bad_request(format!(
            "an instance may hold at most {} keys",
            cfg.max_keys_per_instance
        )));
    }

    let additions =
        ak::verify_initial_enrollment(&request.keys, &instance, now, cfg.clock_skew_seconds)
            .map_err(protocol)?;

    // Enrollment signs one attestation per key, so it is the single most
    // expensive operation an authenticated account can ask for. An account
    // credential is not a rate limit; bound it the same way an addition is.
    // Safe to key on the triple here because the account is authenticated and
    // the subject comes from that session, not from the request.
    quota_check("enrollment", &instance, &ADDITION_QUOTA)?;

    // Every key still consumes its own challenge, so enrolment cannot replay a
    // batch that was captured on the wire.
    for addition in &additions {
        consume_challenge(
            pool,
            ChallengeUse {
                challenge_id: &addition.challenge_id,
                presented_nonce: &addition.challenge,
                purpose: ak::PURPOSE_ADD,
                instance: &instance,
                key_usage: &addition.key_usage,
                algorithm: &addition.algorithm,
                public_key: &addition.public_key,
            },
            now,
        )?;
    }

    let existing = pool
        .find_application_instance(
            subject_user_id,
            &request.application_id,
            &request.instance_id,
        )
        .map_err(|e| internal("looking up instance", e))?;

    let row = pool
        .upsert_application_instance(
            subject_user_id,
            &request.application_id,
            &request.instance_id,
            now,
        )
        .map_err(|e| internal("creating instance", e))?;

    // Re-enrolling an existing instance is a TRUST RESET, not a quiet update.
    // It is recorded so an operator can see that an instance's key history was
    // restarted rather than rotated.
    if existing.is_some() {
        if let Err(e) = pool.record_application_trust_reset(&row.id, now) {
            log::warn!("application keys: could not record trust reset: {e}");
        }
        log::warn!(
            "application keys: trust reset for application {} instance {} of subject {}",
            request.application_id,
            request.instance_id,
            subject_user_id
        );
    }

    let mut attestations = Vec::with_capacity(additions.len());
    for addition in &additions {
        let key = store_key(pool, &row.id, addition, now)?;
        attestations.push(issue_attestation(
            pool,
            &instance,
            &to_key_ref(&key),
            &key.id,
            now,
        )?);
    }

    Ok(EnrollApplicationInstanceResponse {
        subject_user_id: subject_user_id.to_string(),
        subject_domain: domain.clone(),
        application_id: request.application_id,
        instance_id: request.instance_id,
        attestations,
    })
}

fn store_key(
    pool: &DbPool,
    instance_row_id: &str,
    addition: &ApplicationKeyAddition,
    now: DateTime<Utc>,
) -> Result<ApplicationKeyRow, ServiceError> {
    let cfg = config();
    // The domain never attests a key for longer than it is willing to, however
    // long the application asked for.
    let lifetime = addition
        .requested_key_lifetime_seconds
        .min(cfg.max_key_lifetime_seconds);
    pool.insert_application_key(
        instance_row_id,
        &addition.key_id,
        &addition.key_usage,
        &addition.algorithm,
        &addition.public_key,
        &addition.fingerprint,
        now,
        now + Duration::seconds(lifetime),
    )
    .map_err(|e| match e {
        diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        ) => bad_request(format!("key {} already exists", addition.key_id)),
        other => internal("storing application key", other),
    })
}

/// Identifiers appear in cache keys, log lines, and the public read. Bound
/// them so a caller cannot use one as a payload.
fn check_identifier(field: &str, value: &str) -> Result<(), ServiceError> {
    if value.is_empty() || value.len() > 128 {
        return Err(bad_request(format!(
            "{field} must be between 1 and 128 characters"
        )));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(bad_request(format!(
            "{field} may contain only letters, digits, '-', '_', and '.'"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Adding a key
// ---------------------------------------------------------------------------

/// Add one key to an enrolled instance, authorized by two distinct valid
/// application signing keys. There is no account authentication here and none
/// is needed: the quorum IS the authority.
pub fn add_key(
    pool: &DbPool,
    request: AddApplicationKeyRequest,
    now: DateTime<Utc>,
) -> Result<AddApplicationKeyResponse, ServiceError> {
    let cfg = config();
    let domain = get_domain_name();

    // The signed payload names its own instance, so it is read before anything
    // is looked up — and then every field is checked against what was signed.
    let addition =
        liblinkkeys::generated::decode_application_key_addition(&request.request.addition)
            .map_err(|e| bad_request(format!("could not decode addition: {e}")))?;
    let instance = InstanceRef {
        subject_user_id: &addition.subject_user_id,
        subject_domain: &domain,
        application_id: &addition.application_id,
        instance_id: &addition.instance_id,
    };

    let (row, keys) = load_instance(pool, &instance)?;

    let key_refs: Vec<ApplicationKeyRef> = keys.iter().map(to_key_ref).collect();
    let verified = ak::verify_addition(
        &request.request,
        &key_refs,
        &instance,
        now,
        cfg.clock_skew_seconds,
    )
    .map_err(protocol)?;

    // The quota is spent only AFTER the quorum signatures verify. Spending it
    // first would make it drainable by anyone who knows the three
    // identifiers — the caller does not have to hold a key to send garbage,
    // and an attacker could lock a victim's instance out of its own key
    // rotation. Signature verification is what makes this key safe to use.
    quota_check("addition", &instance, &ADDITION_QUOTA)?;

    if keys.iter().any(|k| k.key_id == verified.key_id) {
        return Err(bad_request(format!(
            "key {} already exists",
            verified.key_id
        )));
    }
    let live = keys.iter().filter(|k| k.revoked_at.is_none()).count() as i64;
    if live >= cfg.max_keys_per_instance {
        return Err(bad_request(format!(
            "an instance may hold at most {} keys",
            cfg.max_keys_per_instance
        )));
    }

    consume_challenge(
        pool,
        ChallengeUse {
            challenge_id: &verified.challenge_id,
            presented_nonce: &verified.challenge,
            purpose: ak::PURPOSE_ADD,
            instance: &instance,
            key_usage: &verified.key_usage,
            algorithm: &verified.algorithm,
            public_key: &verified.public_key,
        },
        now,
    )?;

    let key = store_key(pool, &row.id, &verified, now)?;
    let attestation = issue_attestation(pool, &instance, &to_key_ref(&key), &key.id, now)?;
    Ok(AddApplicationKeyResponse { attestation })
}

// ---------------------------------------------------------------------------
// Renewal
// ---------------------------------------------------------------------------

/// Re-attest an existing key.
///
/// Idempotent by design: while the stored attestation keeps more than half of
/// its lifetime, the stored bytes are returned and NO new signature is made.
/// Authentication alone is not a rate limit — an enrolled instance could
/// otherwise drive the most expensive operation on this server at any rate it
/// liked — so a per-instance quota sits on top.
pub fn renew_attestation(
    pool: &DbPool,
    request: RenewApplicationKeyAttestationRequest,
    now: DateTime<Utc>,
) -> Result<RenewApplicationKeyAttestationResponse, ServiceError> {
    let cfg = config();
    let domain = get_domain_name();

    let renewal = liblinkkeys::generated::decode_application_key_renewal(&request.request.renewal)
        .map_err(|e| bad_request(format!("could not decode renewal: {e}")))?;
    let instance = InstanceRef {
        subject_user_id: &renewal.subject_user_id,
        subject_domain: &domain,
        application_id: &renewal.application_id,
        instance_id: &renewal.instance_id,
    };

    let (_row, keys) = load_instance(pool, &instance)?;

    let target_row = keys
        .iter()
        .find(|k| k.key_id == renewal.key_id)
        .ok_or_else(|| not_found(format!("unknown application key {}", renewal.key_id)))?;
    let target = to_key_ref(target_row);
    let siblings: Vec<ApplicationKeyRef> = keys.iter().map(to_key_ref).collect();

    let verified = ak::verify_renewal(
        &request.request,
        &target,
        &siblings,
        &instance,
        now,
        cfg.clock_skew_seconds,
    )
    .map_err(protocol)?;

    // Spent only after the possession proof verifies, for the same reason as
    // an addition: an unauthenticated caller must not be able to exhaust an
    // instance's renewal budget and so strand it with expiring attestations.
    quota_check("renewal", &instance, &RENEWAL_QUOTA)?;

    consume_challenge(
        pool,
        ChallengeUse {
            challenge_id: &verified.challenge_id,
            presented_nonce: &verified.challenge,
            purpose: ak::PURPOSE_RENEW,
            instance: &instance,
            key_usage: &target.key_usage,
            algorithm: &target.algorithm,
            public_key: &target.public_key,
        },
        now,
    )?;

    // The idempotent path: a stored attestation with most of its life left is
    // returned as-is. This is what absorbs retry and restart storms.
    if let Some(stored) = pool
        .get_application_key_attestation(&target_row.id)
        .map_err(|e| internal("reading stored attestation", e))?
    {
        let fresh_enough = !ak::needs_new_attestation(&stored.attested_at, &stored.expires_at, now)
            .map_err(protocol)?;
        if fresh_enough {
            let attestation = liblinkkeys::generated::decode_signed_application_key_attestation(
                &stored.signed_attestation,
            )
            .map_err(|e| internal("decoding stored attestation", e))?;
            return Ok(RenewApplicationKeyAttestationResponse {
                attestation,
                signed: false,
            });
        }
    }

    let attestation = issue_attestation(pool, &instance, &target, &target_row.id, now)?;
    Ok(RenewApplicationKeyAttestationResponse {
        attestation,
        signed: true,
    })
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

/// Record a permanent, sibling-signed revocation.
///
/// The evidence is stored verbatim and republished: a verifier checks it for
/// itself against the sibling keys it already holds, so this domain is not a
/// trusted third party for its own users' revocations.
pub fn revoke_key(
    pool: &DbPool,
    request: RevokeApplicationKeyRequest,
    now: DateTime<Utc>,
) -> Result<RevokeApplicationKeyResponse, ServiceError> {
    let cfg = config();
    let domain = get_domain_name();
    let rev = request.revocation;
    let instance = InstanceRef {
        subject_user_id: &rev.subject_user_id,
        subject_domain: &domain,
        application_id: &rev.application_id,
        instance_id: &rev.instance_id,
    };

    let (row, keys) = load_instance(pool, &instance)?;
    let key_refs: Vec<ApplicationKeyRef> = keys.iter().map(to_key_ref).collect();

    ak::check_revocation_effective_time(&rev.revoked_at, now, cfg.clock_skew_seconds)
        .map_err(protocol)?;
    ak::verify_revocation(&rev, &key_refs, &instance).map_err(protocol)?;

    let effective = parse_rfc3339(&rev.revoked_at)?;
    let record = liblinkkeys::generated::encode_application_key_revocation(&rev);
    pool.insert_application_key_revocation(
        &row.id,
        &rev.target_key_id,
        &rev.target_fingerprint,
        effective,
        &record,
    )
    .map_err(|e| internal("storing revocation", e))?;
    pool.revoke_application_key(&row.id, &rev.target_key_id, effective)
        .map_err(|e| internal("marking key revoked", e))?;

    invalidate_cache(&instance);
    log::info!(
        "application keys: revoked key {} of application {} instance {}",
        rev.target_key_id,
        rev.application_id,
        rev.instance_id
    );
    Ok(RevokeApplicationKeyResponse {
        revoked_at: rev.revoked_at,
    })
}

// ---------------------------------------------------------------------------
// The anonymous public read
// ---------------------------------------------------------------------------

/// Serve one instance's public key material.
///
/// Anonymous: no API key, no client certificate. That does not make the
/// response untrusted — the caller pins our TLS key to our DNS fingerprint set
/// and verifies every signed object itself. It does mean this handler must
/// touch only public columns and must never cause a private-key decryption or
/// a signature.
///
/// The revocation list is COMPLETE for the configured look-back or the call
/// fails. It is never truncated and never paginated: a caller that read a
/// partial list would hold a revoked key that looks valid, and every SDK
/// author would inherit that risk.
pub fn get_application_keys(
    pool: &DbPool,
    request: GetApplicationKeysRequest,
    now: DateTime<Utc>,
) -> Result<GetApplicationKeysResponse, ServiceError> {
    let cfg = config();
    let domain = get_domain_name();
    let since = now - Duration::seconds(cfg.revocation_window_seconds);

    let records = pool
        .load_application_public_records(
            &request.subject_user_id,
            &request.application_id,
            &request.instance_id,
            Some(since),
        )
        .map_err(|e| internal("reading public application keys", e))?
        .ok_or_else(|| not_found("unknown application instance"))?;

    if records.revocation_records.len() as i64 > cfg.max_revocations {
        // An error, never a short list. A caller must always know it has the
        // whole picture.
        return Err(ServiceError {
            code: 507,
            message: format!(
                "this instance has more than the {} revocation records this domain will \
                 return in one response",
                cfg.max_revocations
            ),
        });
    }

    let mut keys = Vec::with_capacity(records.signed_attestations.len());
    for bytes in &records.signed_attestations {
        keys.push(
            liblinkkeys::generated::decode_signed_application_key_attestation(bytes)
                .map_err(|e| internal("decoding stored attestation", e))?,
        );
    }
    let mut revocations: Vec<ApplicationKeyRevocation> =
        Vec::with_capacity(records.revocation_records.len());
    for bytes in &records.revocation_records {
        revocations.push(
            liblinkkeys::generated::decode_application_key_revocation(bytes)
                .map_err(|e| internal("decoding stored revocation", e))?,
        );
    }

    Ok(GetApplicationKeysResponse {
        subject_user_id: records.subject_user_id,
        subject_domain: domain,
        application_id: records.application_id,
        instance_id: records.instance_id,
        keys,
        revocations,
    })
}

/// The cached encoded form of [`get_application_keys`]. A hit repeats neither
/// the database read nor the CBOR encoding, and concurrent misses for the same
/// instance are coalesced into one database query.
pub fn get_application_keys_encoded(
    pool: &DbPool,
    request: GetApplicationKeysRequest,
    now: DateTime<Utc>,
) -> Result<std::sync::Arc<Vec<u8>>, ServiceError> {
    let cfg = config();
    let domain = get_domain_name();
    let key = crate::services::pubkey_cache::application_keys_key(
        &request.subject_user_id,
        &domain,
        &request.application_id,
        &request.instance_id,
    );
    let lookup = request.clone();
    let loaded = crate::services::pubkey_cache::APPLICATION_KEYS
        .get_or_load(&key, || match get_application_keys(pool, lookup, now) {
            Ok(response) => Ok(Some(
                liblinkkeys::generated::encode_get_application_keys_response(&response),
            )),
            // A missing instance is cached NEGATIVELY, for much less time than
            // a real answer, so a scan for unknown instances does not become a
            // database read per request.
            Err(e) if e.code == 404 => Ok(None),
            Err(e) => Err(crate::services::pubkey_cache::CacheError::Load(e.message)),
        })
        .map_err(|e| internal("loading application keys", e))?;

    let bytes = loaded.ok_or_else(|| not_found("unknown application instance"))?;
    if bytes.len() > cfg.max_response_bytes {
        return Err(ServiceError {
            code: 507,
            message: "this instance's public key material exceeds the configured response size"
                .to_string(),
        });
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Shared loading and quotas
// ---------------------------------------------------------------------------

fn load_instance(
    pool: &DbPool,
    instance: &InstanceRef<'_>,
) -> Result<
    (
        crate::db::models::ApplicationInstance,
        Vec<ApplicationKeyRow>,
    ),
    ServiceError,
> {
    let row = pool
        .find_application_instance(
            instance.subject_user_id,
            instance.application_id,
            instance.instance_id,
        )
        .map_err(|e| internal("looking up instance", e))?
        .ok_or_else(|| forbidden("unknown application instance"))?;
    let keys = pool
        .list_application_keys(&row.id)
        .map_err(|e| internal("listing application keys", e))?;
    Ok((row, keys))
}

/// Per-instance quotas on the two operations that cost this server real work.
///
/// Keyed by the AUTHENTICATED triple, which is safe here precisely because
/// these operations are signature-authenticated: an attacker cannot claim
/// another instance's identity without its keys, so it cannot drain another
/// instance's quota. (The anonymous public read must NOT be keyed this way,
/// and is not — see [`crate::services::public_ratelimit`].)
static RENEWAL_QUOTA: LazyLock<crate::services::ratelimit::RateLimiter> = LazyLock::new(|| {
    let per_hour = config().renewal_quota_per_hour;
    crate::services::ratelimit::RateLimiter::new(
        per_hour.max(1.0),
        per_hour / 3600.0,
        4096,
        per_hour * 100.0,
        per_hour * 100.0 / 3600.0,
    )
});

static ADDITION_QUOTA: LazyLock<crate::services::ratelimit::RateLimiter> = LazyLock::new(|| {
    let per_hour = config().addition_quota_per_hour;
    crate::services::ratelimit::RateLimiter::new(
        per_hour.max(1.0),
        per_hour / 3600.0,
        4096,
        per_hour * 100.0,
        per_hour * 100.0 / 3600.0,
    )
});

/// An injective encoding of the four identifiers that name one instance.
fn quota_key(instance: &InstanceRef<'_>) -> String {
    let mut key = String::new();
    for part in [
        instance.subject_user_id,
        instance.subject_domain,
        instance.application_id,
        instance.instance_id,
    ] {
        key.push_str(&part.len().to_string());
        key.push(':');
        key.push_str(part);
    }
    key
}

fn quota_check(
    what: &str,
    instance: &InstanceRef<'_>,
    limiter: &crate::services::ratelimit::RateLimiter,
) -> Result<(), ServiceError> {
    // Length-prefixed, so the encoding is injective whatever the identifiers
    // contain. A plain separator-joined key would let two different instances
    // share one bucket — one could then exhaust the other's quota, which is
    // exactly the cross-tenant confusion this key exists to prevent. The
    // identifiers ARE validated upstream today, but relying on that here would
    // make this correct only by an invariant held somewhere else.
    let key = quota_key(instance);
    if limiter.check(&key) {
        return Ok(());
    }
    log::warn!(
        "application keys: {what} quota exhausted for application {} instance {}",
        instance.application_id,
        instance.instance_id
    );
    Err(too_many(format!("{what} quota exceeded; try again later")))
}
