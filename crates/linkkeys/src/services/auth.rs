use crate::db::models::User;
use crate::db::DbPool;
use chrono::{DateTime, Utc};
use liblinkkeys::generated::types::AuthenticationRequirements;
use std::collections::BTreeSet;
use std::fmt;

pub const CREDENTIAL_TYPE_PASSWORD: &str = "password";
pub const CREDENTIAL_TYPE_API_KEY: &str = "api_key";
pub const METHOD_TYPE_PASSWORD: &str = "password";
pub const METHOD_TYPE_API_KEY: &str = "api_key";

/// Convert a login name to the username stored by this provider.
///
/// A user can enter a bare username or a full LinkKeys name for this domain.
/// A full name for another domain is not valid on this provider.
pub fn normalize_login_username(input: &str) -> Option<String> {
    normalize_login_username_for_domain(input, &crate::conversions::get_domain_name())
}

fn normalize_login_username_for_domain(input: &str, domain: &str) -> Option<String> {
    let input = input.trim();
    if input.is_empty() {
        return None;
    }

    let mut parts = input.split('@');
    let username = parts.next()?;
    let suffix = parts.next();
    if parts.next().is_some() || username.is_empty() || username != username.trim() {
        return None;
    }
    if suffix.is_some_and(|value| value.is_empty() || !value.eq_ignore_ascii_case(domain)) {
        return None;
    }
    Some(username.to_string())
}

/// Return the rate-limit key for a login name.
///
/// Bare and same-domain forms use one key. Invalid names still get a stable
/// key, so callers can limit them without accepting them.
pub fn login_rate_limit_key(input: &str) -> String {
    normalize_login_username(input)
        .unwrap_or_else(|| input.trim().to_string())
        .to_lowercase()
}

/// Provider-owned metadata for one authentication method. RPs never select a
/// method by name. Provider policy uses these properties when it decides which
/// methods satisfy an assurance request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationMethod {
    pub method_type: &'static str,
    pub device_backed: bool,
}

/// The authentication methods proved in one provider session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationEvidence {
    pub method_types: BTreeSet<String>,
    pub authenticated_at: DateTime<Utc>,
}

impl AuthenticationEvidence {
    pub fn single(method_type: &str) -> Self {
        Self {
            method_types: [method_type.to_string()].into_iter().collect(),
            authenticated_at: Utc::now(),
        }
    }

    pub fn factor_count(&self) -> usize {
        self.method_types.len()
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticationResult {
    pub user: User,
    pub evidence: AuthenticationEvidence,
    /// The credential that proved this authentication, when the method uses a
    /// stored credential. Callers use this value for compare-and-swap checks
    /// before they create a session or replace a password.
    pub credential_id: Option<String>,
}

/// Provider policy result after combining its own minimum with the RP's
/// factor-count request. Method selection remains entirely provider-owned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssuranceRequirement {
    pub minimum_factor_count: usize,
}

const MAX_REQUESTED_FACTOR_COUNT: i64 = 16;

pub fn resolve_assurance_requirement(
    requested: Option<&AuthenticationRequirements>,
    provider_minimum_factor_count: usize,
) -> Result<AssuranceRequirement, AuthError> {
    let requested_count = requested.map(|r| r.minimum_factor_count).unwrap_or(1);
    if !(1..=MAX_REQUESTED_FACTOR_COUNT).contains(&requested_count) {
        return Err(AuthError::InvalidAssuranceRequest);
    }
    Ok(AssuranceRequirement {
        minimum_factor_count: provider_minimum_factor_count.max(requested_count as usize),
    })
}

pub fn evidence_satisfies(
    evidence: &AuthenticationEvidence,
    requirement: AssuranceRequirement,
) -> bool {
    evidence.factor_count() >= requirement.minimum_factor_count
}

/// Browser authentication methods enabled by this provider build. Adding a
/// method later requires registering its provider-owned properties here; RP
/// protocol data never contains these identifiers.
pub fn enabled_browser_methods() -> Vec<AuthenticationMethod> {
    vec![AuthenticationMethod {
        method_type: METHOD_TYPE_PASSWORD,
        device_backed: false,
    }]
}

pub fn provider_can_satisfy(requirement: AssuranceRequirement) -> bool {
    enabled_browser_methods()
        .into_iter()
        .map(|method| method.method_type)
        .collect::<BTreeSet<_>>()
        .len()
        >= requirement.minimum_factor_count
}

#[derive(Debug)]
pub enum AuthError {
    InvalidCredentials,
    InvalidAssuranceRequest,
    DbError(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::InvalidCredentials => write!(f, "invalid credentials"),
            AuthError::InvalidAssuranceRequest => {
                write!(f, "invalid authentication assurance request")
            }
            AuthError::DbError(msg) => write!(f, "database error: {}", msg),
        }
    }
}

pub trait Authenticator: Send + Sync {
    fn method(&self) -> AuthenticationMethod;
    fn authenticate(&self, username: &str, credential: &str) -> Result<User, AuthError>;

    fn authenticate_with_evidence(
        &self,
        username: &str,
        credential: &str,
    ) -> Result<AuthenticationResult, AuthError> {
        let user = self.authenticate(username, credential)?;
        Ok(AuthenticationResult {
            user,
            evidence: AuthenticationEvidence::single(self.method().method_type),
            credential_id: None,
        })
    }
}

/// Authenticates users via username + password, checked against auth_credentials
/// with credential_type = "password".
pub struct PasswordAuthenticator {
    pool: DbPool,
}

impl PasswordAuthenticator {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

impl Authenticator for PasswordAuthenticator {
    fn method(&self) -> AuthenticationMethod {
        AuthenticationMethod {
            method_type: METHOD_TYPE_PASSWORD,
            device_backed: false,
        }
    }

    fn authenticate(&self, username: &str, password: &str) -> Result<User, AuthError> {
        self.authenticate_password(username, password)
            .map(|result| result.user)
    }

    fn authenticate_with_evidence(
        &self,
        username: &str,
        password: &str,
    ) -> Result<AuthenticationResult, AuthError> {
        self.authenticate_password(username, password)
    }
}

impl PasswordAuthenticator {
    fn authenticate_password(
        &self,
        username: &str,
        password: &str,
    ) -> Result<AuthenticationResult, AuthError> {
        let Some(username) = normalize_login_username(username) else {
            return Err(AuthError::InvalidCredentials);
        };
        if !crate::services::password::valid_login_shape(&username, password) {
            return Err(AuthError::InvalidCredentials);
        }
        let found = match &self.pool {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| AuthError::DbError(e.to_string()))?;
                crate::db::users::pg::find_by_username(&mut conn, &username)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| AuthError::DbError(e.to_string()))?;
                crate::db::users::sqlite::find_by_username(&mut conn, &username)
            }
        };
        let user = match found {
            Ok(u) => u,
            Err(_) => {
                // SEC-05: equalize timing so a missing username is not
                // distinguishable from a wrong password by response latency.
                crate::services::password::dummy_verify_bounded(password);
                return Err(AuthError::InvalidCredentials);
            }
        };

        let creds = self
            .pool
            .find_credentials_for_user(&user.id, CREDENTIAL_TYPE_PASSWORD)
            .map_err(|e| AuthError::DbError(e.to_string()))?;

        if creds.is_empty() {
            crate::services::password::dummy_verify_bounded(password);
            return Err(AuthError::InvalidCredentials);
        }

        for cred in &creds {
            let outcome = crate::services::password::verify(password, &cred.credential_hash);
            if outcome.verified {
                if outcome.needs_rehash {
                    self.rehash_to_argon2id(&cred.id, password);
                }
                return Ok(AuthenticationResult {
                    user,
                    evidence: AuthenticationEvidence::single(METHOD_TYPE_PASSWORD),
                    credential_id: Some(cred.id.clone()),
                });
            }
        }

        Err(AuthError::InvalidCredentials)
    }
}

impl PasswordAuthenticator {
    /// Upgrade a legacy (bcrypt) credential to Argon2id after a successful
    /// verify. Best-effort: a hashing or DB failure here must not block a login
    /// the user already passed, so errors are logged and swallowed — the upgrade
    /// simply retries on the next login.
    fn rehash_to_argon2id(&self, credential_id: &str, password: &str) {
        match crate::services::password::hash_for_storage(password) {
            Ok(new_hash) => {
                if let Err(e) = self.pool.update_credential_hash(credential_id, &new_hash) {
                    log::warn!("Failed to upgrade credential hash to Argon2id: {}", e);
                }
            }
            Err(e) => log::warn!("Failed to compute Argon2id hash for upgrade: {}", e),
        }
    }
}

/// Authenticates users via API key (bearer token).
/// API key format: <user-id>.<secret>. Legacy keys can contain the first eight
/// hexadecimal characters of the user ID. New keys use the full user ID so
/// the database lookup selects one account before the expensive bcrypt check.
pub struct ApiKeyAuthenticator {
    pool: DbPool,
}

#[derive(Debug, Clone)]
pub struct ApiKeyAuthentication {
    pub user: User,
    pub credential_id: String,
}

impl ApiKeyAuthenticator {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub fn authenticate_key(&self, api_key: &str) -> Result<User, AuthError> {
        self.authenticate_key_with_credential(api_key)
            .map(|authentication| authentication.user)
    }

    pub fn authenticate_key_with_credential(
        &self,
        api_key: &str,
    ) -> Result<ApiKeyAuthentication, AuthError> {
        // Parse prefix.secret format
        let (prefix, secret) = api_key
            .split_once('.')
            .ok_or(AuthError::InvalidCredentials)?;

        if !valid_api_key_shape(prefix, secret) {
            return Err(AuthError::InvalidCredentials);
        }

        // Current keys use an indexed digest lookup. This also makes a legacy
        // key cheap after its first successful authentication upgrades it.
        let digest = api_key_hash(secret);
        if let Some(credential) = self
            .pool
            .find_active_credential_by_hash(CREDENTIAL_TYPE_API_KEY, &digest)
            .map_err(|error| AuthError::DbError(error.to_string()))?
        {
            let user = self
                .pool
                .find_user_by_id(&credential.user_id)
                .map_err(|_| AuthError::InvalidCredentials)?;
            return Ok(ApiKeyAuthentication {
                user,
                credential_id: credential.id,
            });
        }

        // Only an old eight-character prefix can need bcrypt. Collect the
        // candidates before doing any expensive work. A bounded cohort keeps
        // one first-use request from consuming unbounded CPU.
        if prefix.len() != 8 {
            return Err(AuthError::InvalidCredentials);
        }
        if !crate::services::ratelimit::LEGACY_API_PREFIX.check(prefix) {
            return Err(AuthError::InvalidCredentials);
        }
        let candidates = self
            .pool
            .find_legacy_api_key_candidates(prefix, (MAX_LEGACY_API_KEY_CANDIDATES + 1) as i64)
            .map_err(|error| AuthError::DbError(error.to_string()))?;

        if candidates.len() > MAX_LEGACY_API_KEY_CANDIDATES {
            log::warn!(
                "Rejected a legacy API key because its prefix matched {} active credentials",
                candidates.len()
            );
            return Err(AuthError::InvalidCredentials);
        }
        if candidates.is_empty() {
            return Err(AuthError::InvalidCredentials);
        }
        let _permit = ApiKeyWorkPermit::acquire().ok_or(AuthError::InvalidCredentials)?;
        for (user, credential) in candidates {
            if bcrypt::verify(secret, &credential.credential_hash).unwrap_or(false) {
                if let Err(error) = self.pool.update_credential_hash(&credential.id, &digest) {
                    log::warn!("Failed to upgrade an API-key hash: {error}");
                }
                return Ok(ApiKeyAuthentication {
                    user,
                    credential_id: credential.id,
                });
            }
        }

        Err(AuthError::InvalidCredentials)
    }
}

const API_KEY_SECRET_LENGTH: usize = 43;
const MAX_ACTIVE_API_KEY_WORK: usize = 1;
const MAX_LEGACY_API_KEY_CANDIDATES: usize = 32;
static ACTIVE_API_KEY_WORK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

struct ApiKeyWorkPermit;

impl ApiKeyWorkPermit {
    fn acquire() -> Option<Self> {
        use std::sync::atomic::Ordering;
        ACTIVE_API_KEY_WORK
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < MAX_ACTIVE_API_KEY_WORK).then_some(active + 1)
            })
            .ok()
            .map(|_| Self)
    }
}

impl Drop for ApiKeyWorkPermit {
    fn drop(&mut self) {
        ACTIVE_API_KEY_WORK.fetch_sub(1, std::sync::atomic::Ordering::Release);
    }
}

fn valid_api_key_shape(prefix: &str, secret: &str) -> bool {
    let valid_prefix = (prefix.len() == 8 && prefix.bytes().all(|byte| byte.is_ascii_hexdigit()))
        || (prefix.len() == 36 && uuid::Uuid::parse_str(prefix).is_ok());
    valid_prefix
        && secret.len() == API_KEY_SECRET_LENGTH
        && secret
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn api_key_hash(secret: &str) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use sha2::{Digest, Sha256};

    format!(
        "sha256:{}",
        Base64UrlUnpadded::encode_string(&Sha256::digest(secret.as_bytes()))
    )
}

/// Generate an API key for a user. Returns the key and its storage digest.
/// Format: <user-id>.<32-bytes-random-base64url>
pub fn generate_api_key(user_id: &str) -> (String, String) {
    use base64ct::{Base64UrlUnpadded, Encoding};

    let secret_bytes: [u8; 32] = rand::random();
    let secret = Base64UrlUnpadded::encode_string(&secret_bytes);
    let api_key = format!("{}.{}", user_id, secret);
    let hash = api_key_hash(&secret);
    (api_key, hash)
}

#[cfg(test)]
mod assurance_tests {
    use super::*;

    #[test]
    fn rp_can_request_only_a_factor_count() {
        let requirement = resolve_assurance_requirement(
            Some(&AuthenticationRequirements {
                minimum_factor_count: 2,
            }),
            1,
        )
        .unwrap();
        assert_eq!(requirement.minimum_factor_count, 2);
    }

    #[test]
    fn provider_policy_can_raise_the_rp_floor() {
        let requirement = resolve_assurance_requirement(None, 3).unwrap();
        assert_eq!(requirement.minimum_factor_count, 3);
    }

    #[test]
    fn distinct_provider_methods_count_as_factors() {
        let evidence = AuthenticationEvidence {
            method_types: ["password".to_string(), "device".to_string()]
                .into_iter()
                .collect(),
            authenticated_at: Utc::now(),
        };
        assert!(evidence_satisfies(
            &evidence,
            AssuranceRequirement {
                minimum_factor_count: 2,
            }
        ));
    }

    #[test]
    fn invalid_factor_counts_are_rejected() {
        for minimum_factor_count in [0, -1, 17] {
            assert!(resolve_assurance_requirement(
                Some(&AuthenticationRequirements {
                    minimum_factor_count,
                }),
                1,
            )
            .is_err());
        }
    }
}

#[cfg(test)]
mod login_username_tests {
    use super::normalize_login_username_for_domain;

    const DOMAIN: &str = "catalystlinkkeys.com";

    #[test]
    fn accepts_bare_and_matching_domain_login_names() {
        assert_eq!(
            normalize_login_username_for_domain("househansmann", DOMAIN).as_deref(),
            Some("househansmann")
        );
        assert_eq!(
            normalize_login_username_for_domain("househansmann@catalystlinkkeys.com", DOMAIN,)
                .as_deref(),
            Some("househansmann")
        );
        assert_eq!(
            normalize_login_username_for_domain(" househansmann@CATALYSTLINKKEYS.COM ", DOMAIN,)
                .as_deref(),
            Some("househansmann")
        );
    }

    #[test]
    fn rejects_foreign_and_malformed_domain_login_names() {
        for input in [
            "househansmann@example.com",
            "@catalystlinkkeys.com",
            "househansmann@",
            "househansmann@@catalystlinkkeys.com",
            "househansmann @catalystlinkkeys.com",
        ] {
            assert_eq!(
                normalize_login_username_for_domain(input, DOMAIN),
                None,
                "accepted {input:?}"
            );
        }
    }
}
