//! Application accounts on a relying party (request-app-management.md).
//!
//! - Admin operations: rename an account, set an application id, named API
//!   keys, account limits, and application usage.
//! - The distinct-user cap: `decrypt-token` admits a user to an application
//!   only while the application is under its limit. Users are counted as
//!   keyed hashes of their identity; the identity is never stored.
//! - A request rate for each account.
//! - Daily `Rp` usage counts, aggregated in memory and flushed to a
//!   [`UsageStore`] about once a minute.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::Instant;

use hkdf::Hkdf;
use sha2::Sha256;
use time::{Date, OffsetDateTime};

use liblinkkeys::generated::services::ServiceError;
use liblinkkeys::generated::types::{
    AccountLimits, AdminUser, ApiKeyInfo, CreateApiKeyRequest, CreateApiKeyResponse,
    GetAccountLimitsRequest, GetAccountLimitsResponse, GetApplicationUsageRequest,
    GetApplicationUsageResponse, ListApiKeysRequest, ListApiKeysResponse, RenameUserRequest,
    RenameUserResponse, RevokeApiKeyRequest, RevokeApiKeyResponse, RpUsageDay,
    SetAccountLimitsRequest, SetAccountLimitsResponse, SetApplicationIdRequest,
    SetApplicationIdResponse,
};

use crate::db::applications::{AccountLimitsRecord, UsageDayRecord};
use crate::db::models::AuthCredential;
use crate::db::DbPool;

/// Longest usage range one request may read.
const MAX_USAGE_DAYS: i64 = 400;
/// Longest distinct-user window an administrator may set.
const MAX_WINDOW_DAYS: i32 = 366;
/// Longest API key name.
const MAX_KEY_NAME_CHARS: usize = 64;

fn bad_request(message: impl Into<String>) -> ServiceError {
    ServiceError {
        code: 400,
        message: message.into(),
    }
}

fn not_found(message: &str) -> ServiceError {
    ServiceError {
        code: 404,
        message: message.to_string(),
    }
}

fn internal(step: &str, e: impl std::fmt::Display) -> ServiceError {
    log::error!("{step} failed: {e}");
    ServiceError {
        code: 500,
        message: format!("{step} failed"),
    }
}

fn find_user(pool: &DbPool, user_id: &str) -> Result<crate::db::models::User, ServiceError> {
    match pool.find_user_by_id(user_id) {
        Ok(u) => Ok(u),
        Err(diesel::result::Error::NotFound) => Err(not_found("no such account")),
        Err(e) => Err(internal("reading the account", e)),
    }
}

fn admin_user(user: &crate::db::models::User) -> AdminUser {
    crate::services::admin::user_to_admin_user(user)
}

fn is_unique_violation(e: &diesel::result::Error) -> bool {
    matches!(
        e,
        diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::UniqueViolation, _)
    )
}

// ---------------------------------------------------------------------------
// Admin: accounts and application ids
// ---------------------------------------------------------------------------

/// `Admin/rename-user`. The account id stays; every credential, claim, grant,
/// and consent of the account is kept.
pub fn rename_user(
    pool: &DbPool,
    req: RenameUserRequest,
) -> Result<RenameUserResponse, ServiceError> {
    let username = req.username.trim();
    crate::services::admin::validate_username(username)?;
    find_user(pool, &req.user_id)?;
    match pool.rename_user(&req.user_id, username) {
        Ok(user) => {
            let _ = pool.write_audit("user.renamed", Some(&user.id), None, Some(username));
            Ok(RenameUserResponse {
                user: admin_user(&user),
            })
        }
        Err(e) if is_unique_violation(&e) => Err(bad_request("that username is taken")),
        Err(e) => Err(internal("renaming the account", e)),
    }
}

/// `Admin/set-application-id`. Only an administrator of this domain sets the
/// id; users see a new application, so earlier consent does not carry over.
pub fn set_application_id(
    pool: &DbPool,
    req: SetApplicationIdRequest,
) -> Result<SetApplicationIdResponse, ServiceError> {
    validate_application_id(&req.application_id)?;
    let user = find_user(pool, &req.user_id)?;
    if !user.is_application() {
        return Err(bad_request("the account is not an application account"));
    }
    let user = pool
        .set_application_id(&req.user_id, &req.application_id)
        .map_err(|e| internal("setting the application id", e))?;
    let _ = pool.write_audit(
        "user.application_id_set",
        Some(&user.id),
        None,
        Some(&req.application_id),
    );
    Ok(SetApplicationIdResponse {
        user: admin_user(&user),
    })
}

/// An application id is 1-128 of A-Z a-z 0-9 - _ . (the act-as identifier
/// rule).
pub fn validate_application_id(application_id: &str) -> Result<(), ServiceError> {
    if liblinkkeys::application_keys::is_valid_identifier(application_id) {
        Ok(())
    } else {
        Err(bad_request(
            "application_id must be 1-128 characters of letters, digits, '-', '_', and '.'",
        ))
    }
}

// ---------------------------------------------------------------------------
// Admin: named API keys
// ---------------------------------------------------------------------------

/// The last four characters of an API key secret.
pub fn key_hint(api_key: &str) -> String {
    let chars: Vec<char> = api_key.chars().collect();
    chars[chars.len().saturating_sub(4)..].iter().collect()
}

fn key_info(c: &AuthCredential) -> ApiKeyInfo {
    ApiKeyInfo {
        key_id: c.id.clone(),
        name: c.name.clone().unwrap_or_else(|| "default".to_string()),
        hint: c.hint.clone().unwrap_or_default(),
        created_at: c.created_at,
        last_used_at: c.last_used_at,
    }
}

/// Create an API key for `user_id` and return the full key once. Enforces the
/// account's `max_api_keys`.
pub fn issue_api_key(
    pool: &DbPool,
    user_id: &str,
    name: &str,
) -> Result<(AuthCredential, String), ServiceError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_KEY_NAME_CHARS {
        return Err(bad_request(format!(
            "an API key name has 1 to {MAX_KEY_NAME_CHARS} characters"
        )));
    }
    let limits = pool
        .account_limits(user_id)
        .map_err(|e| internal("reading account limits", e))?;
    if let Some(max) = limits.max_api_keys {
        let active = pool
            .list_api_keys(user_id)
            .map_err(|e| internal("listing API keys", e))?
            .len();
        if active >= usize::try_from(max).unwrap_or(0) {
            return Err(bad_request(format!(
                "the account already has its maximum of {max} API keys; revoke one first"
            )));
        }
    }
    let (api_key, hash) = crate::services::auth::generate_api_key(user_id);
    let credential = pool
        .create_named_auth_credential(
            user_id,
            crate::services::auth::CREDENTIAL_TYPE_API_KEY,
            &hash,
            Some(name),
            Some(&key_hint(&api_key)),
        )
        .map_err(|e| internal("storing the API key", e))?;
    Ok((credential, api_key))
}

pub fn create_api_key(
    pool: &DbPool,
    req: CreateApiKeyRequest,
) -> Result<CreateApiKeyResponse, ServiceError> {
    let user = find_user(pool, &req.user_id)?;
    if !user.is_active || user.purged_at.is_some() {
        return Err(bad_request("the account is not active"));
    }
    let (credential, api_key) = issue_api_key(pool, &req.user_id, &req.name)?;
    let _ = pool.write_audit(
        "api_key.created",
        Some(&req.user_id),
        None,
        Some(&credential.id),
    );
    Ok(CreateApiKeyResponse {
        key: key_info(&credential),
        api_key,
    })
}

pub fn list_api_keys(
    pool: &DbPool,
    req: ListApiKeysRequest,
) -> Result<ListApiKeysResponse, ServiceError> {
    find_user(pool, &req.user_id)?;
    let keys = pool
        .list_api_keys(&req.user_id)
        .map_err(|e| internal("listing API keys", e))?;
    Ok(ListApiKeysResponse {
        keys: keys.iter().map(key_info).collect(),
    })
}

/// Revoke one API key. The next call with it fails.
pub fn revoke_api_key(
    pool: &DbPool,
    req: RevokeApiKeyRequest,
) -> Result<RevokeApiKeyResponse, ServiceError> {
    let revoked = pool
        .revoke_api_key(&req.user_id, &req.key_id, OffsetDateTime::now_utc())
        .map_err(|e| internal("revoking the API key", e))?;
    if revoked == 0 {
        return Err(not_found("no such active API key of this account"));
    }
    let _ = pool.write_audit(
        "api_key.revoked",
        Some(&req.user_id),
        None,
        Some(&req.key_id),
    );
    Ok(RevokeApiKeyResponse { revoked: true })
}

// ---------------------------------------------------------------------------
// Admin: limits
// ---------------------------------------------------------------------------

fn limits_to_wire(r: &AccountLimitsRecord) -> AccountLimits {
    AccountLimits {
        max_api_keys: r.max_api_keys.map(i64::from),
        max_distinct_users: r.max_distinct_users.map(i64::from),
        distinct_user_window_days: i64::from(r.distinct_user_window_days),
        requests_per_minute: r.requests_per_minute.map(i64::from),
        request_burst: r.request_burst.map(i64::from),
    }
}

fn positive(name: &str, v: Option<i64>) -> Result<Option<i32>, ServiceError> {
    match v {
        None => Ok(None),
        Some(n) if n > 0 && n <= i64::from(i32::MAX) => Ok(Some(n as i32)),
        Some(_) => Err(bad_request(format!("{name} must be a positive number"))),
    }
}

fn limits_from_wire(l: &AccountLimits) -> Result<AccountLimitsRecord, ServiceError> {
    let window = l.distinct_user_window_days;
    if window < 1 || window > i64::from(MAX_WINDOW_DAYS) {
        return Err(bad_request(format!(
            "distinct_user_window_days must be 1 to {MAX_WINDOW_DAYS}"
        )));
    }
    let record = AccountLimitsRecord {
        max_api_keys: positive("max_api_keys", l.max_api_keys)?,
        max_distinct_users: positive("max_distinct_users", l.max_distinct_users)?,
        distinct_user_window_days: window as i32,
        requests_per_minute: positive("requests_per_minute", l.requests_per_minute)?,
        request_burst: positive("request_burst", l.request_burst)?,
    };
    if record.request_burst.is_some() && record.requests_per_minute.is_none() {
        return Err(bad_request("request_burst needs requests_per_minute"));
    }
    Ok(record)
}

pub fn get_account_limits(
    pool: &DbPool,
    req: GetAccountLimitsRequest,
) -> Result<GetAccountLimitsResponse, ServiceError> {
    find_user(pool, &req.user_id)?;
    let limits = pool
        .account_limits(&req.user_id)
        .map_err(|e| internal("reading account limits", e))?;
    Ok(GetAccountLimitsResponse {
        limits: limits_to_wire(&limits),
    })
}

pub fn set_account_limits(
    pool: &DbPool,
    req: SetAccountLimitsRequest,
) -> Result<SetAccountLimitsResponse, ServiceError> {
    find_user(pool, &req.user_id)?;
    let record = limits_from_wire(&req.limits)?;
    pool.set_account_limits(&req.user_id, &record)
        .map_err(|e| internal("storing account limits", e))?;
    forget_rate_bucket(&req.user_id);
    let _ = pool.write_audit("account.limits_set", Some(&req.user_id), None, None);
    Ok(SetAccountLimitsResponse {
        limits: limits_to_wire(&record),
    })
}

// ---------------------------------------------------------------------------
// Distinct users
// ---------------------------------------------------------------------------

const USER_HASH_INFO: &[u8] = b"linkkeys-application-user-hash-v1alpha";

/// The keyed hash of a user identity (`user_id@domain`). The key is derived
/// from `DOMAIN_KEY_PASSPHRASE` and this domain's name, so the hash means
/// nothing outside this server. A passphrase change starts new hashes, which
/// resets the counts.
pub fn user_hash(passphrase: &str, user_identity: &str) -> [u8; 32] {
    let domain = crate::conversions::get_domain_name();
    let (prk, _) = Hkdf::<Sha256>::extract(Some(domain.as_bytes()), passphrase.as_bytes());
    let hk = Hkdf::<Sha256>::from_prk(&prk).expect("a SHA-256 PRK has the right length");
    let mut info = Vec::with_capacity(USER_HASH_INFO.len() + 1 + user_identity.len());
    info.extend_from_slice(USER_HASH_INFO);
    info.push(0);
    info.extend_from_slice(user_identity.as_bytes());
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// The result of admitting a user to an application.
#[derive(Debug, PartialEq, Eq)]
pub enum Admission {
    Admitted,
    /// A new user, and the application is at its distinct-user limit.
    Full,
}

/// Admit the user `user_identity` to the application account `account_id` at
/// `now`: a user already seen in the window is always admitted; a new user is
/// admitted while the application is under its `max_distinct_users`. An
/// admitted user's last-seen time is recorded.
///
/// Two new users that arrive at the same instant can both see room for one;
/// the limit is a product limit, so going over by the number of concurrent
/// first logins is acceptable.
pub fn admit_user(
    pool: &DbPool,
    account_id: &str,
    passphrase: &str,
    user_identity: &str,
    now: OffsetDateTime,
) -> Result<Admission, diesel::result::Error> {
    let limits = pool.account_limits(account_id)?;
    let hash = user_hash(passphrase, user_identity);
    let since = now - time::Duration::days(i64::from(limits.distinct_user_window_days));
    if let Some(max) = limits.max_distinct_users {
        let known = pool.application_user_seen_since(account_id, &hash, since)?;
        if !known && pool.count_application_users_since(account_id, since)? >= i64::from(max) {
            return Ok(Admission::Full);
        }
    }
    pool.record_application_user(account_id, &hash, now)?;
    Ok(Admission::Admitted)
}

/// Remove application users older than the longest window an administrator
/// may set. Run at start-up.
pub fn prune_on_startup(pool: &DbPool) {
    let before = OffsetDateTime::now_utc() - time::Duration::days(i64::from(MAX_WINDOW_DAYS));
    match pool.prune_application_users(before) {
        Ok(n) if n > 0 => log::info!("removed {n} application user record(s) past every window"),
        Ok(_) => {}
        Err(e) => log::error!("pruning application users failed: {e}"),
    }
    match pool.prune_rp_login_nonces(OffsetDateTime::now_utc()) {
        Ok(n) if n > 0 => log::info!("removed {n} expired RP login record(s)"),
        Ok(_) => {}
        Err(e) => log::error!("pruning RP login records failed: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Account request rate
// ---------------------------------------------------------------------------

struct Bucket {
    tokens: f64,
    last: Instant,
}

static RATE_BUCKETS: LazyLock<Mutex<HashMap<String, Bucket>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Upper bound on tracked accounts; the oldest bucket is dropped beyond it.
const MAX_RATE_BUCKETS: usize = 8192;

fn forget_rate_bucket(account_id: &str) {
    if let Ok(mut buckets) = RATE_BUCKETS.lock() {
        buckets.remove(account_id);
    }
}

/// Charge one request to the account's rate limit, if it has one. False when
/// the account is over its rate. A poisoned lock fails open, like the other
/// limiters.
pub fn account_request_allowed(limits: &AccountLimitsRecord, account_id: &str) -> bool {
    let Some(per_minute) = limits.requests_per_minute else {
        return true;
    };
    let capacity = f64::from(limits.request_burst.unwrap_or(per_minute));
    let refill_per_sec = f64::from(per_minute) / 60.0;
    let Ok(mut buckets) = RATE_BUCKETS.lock() else {
        return true;
    };
    let now = Instant::now();
    if !buckets.contains_key(account_id) && buckets.len() >= MAX_RATE_BUCKETS {
        if let Some(oldest) = buckets
            .iter()
            .min_by_key(|(_, b)| b.last)
            .map(|(k, _)| k.clone())
        {
            buckets.remove(&oldest);
        }
    }
    let bucket = buckets.entry(account_id.to_string()).or_insert(Bucket {
        tokens: capacity,
        last: now,
    });
    let elapsed = now.duration_since(bucket.last).as_secs_f64();
    bucket.tokens = (bucket.tokens + elapsed * refill_per_sec).min(capacity);
    bucket.last = now;
    if bucket.tokens >= 1.0 {
        bucket.tokens -= 1.0;
        true
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// Usage counts
// ---------------------------------------------------------------------------

/// Where daily usage counts live. The database implements it; a shared store
/// (Redis) can replace it without a change to `Admin/get-application-usage`.
pub trait UsageStore: Send + Sync {
    /// Add counts to one (account, day, operation) bucket.
    fn add(
        &self,
        account_id: &str,
        day: Date,
        operation: &str,
        succeeded: i64,
        failed: i64,
    ) -> Result<(), String>;
    /// The buckets of one account between two days, inclusive.
    fn list(
        &self,
        account_id: &str,
        first: Date,
        last: Date,
    ) -> Result<Vec<UsageDayRecord>, String>;
}

impl UsageStore for DbPool {
    fn add(
        &self,
        account_id: &str,
        day: Date,
        operation: &str,
        succeeded: i64,
        failed: i64,
    ) -> Result<(), String> {
        self.add_rp_usage(account_id, day, operation, succeeded, failed)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn list(
        &self,
        account_id: &str,
        first: Date,
        last: Date,
    ) -> Result<Vec<UsageDayRecord>, String> {
        self.list_rp_usage(account_id, first, last)
            .map_err(|e| e.to_string())
    }
}

type UsageKey = (String, Date, String);

static PENDING_USAGE: LazyLock<Mutex<HashMap<UsageKey, (i64, i64)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Count one `Rp` operation of an account. In memory until the next flush.
pub fn record_usage(account_id: &str, operation: &str, succeeded: bool) {
    let day = OffsetDateTime::now_utc().date();
    let Ok(mut pending) = PENDING_USAGE.lock() else {
        return;
    };
    let entry = pending
        .entry((account_id.to_string(), day, operation.to_string()))
        .or_insert((0, 0));
    if succeeded {
        entry.0 += 1;
    } else {
        entry.1 += 1;
    }
}

/// Write the pending counts to `store`. Counts that fail to write are kept
/// for the next flush.
pub fn flush_usage(store: &dyn UsageStore) {
    let drained: Vec<(UsageKey, (i64, i64))> = match PENDING_USAGE.lock() {
        Ok(mut pending) => pending.drain().collect(),
        Err(_) => return,
    };
    let mut failed = Vec::new();
    for ((account, day, op), (ok, err)) in drained {
        if let Err(e) = store.add(&account, day, &op, ok, err) {
            log::warn!("could not store Rp usage counts: {e}");
            failed.push(((account, day, op), (ok, err)));
        }
    }
    if failed.is_empty() {
        return;
    }
    if let Ok(mut pending) = PENDING_USAGE.lock() {
        for (key, (ok, err)) in failed {
            let entry = pending.entry(key).or_insert((0, 0));
            entry.0 += ok;
            entry.1 += err;
        }
    }
}

/// Flush usage counts about once a minute for the life of the process.
pub fn spawn_usage_flusher(store: std::sync::Arc<dyn UsageStore>) {
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
        flush_usage(store.as_ref());
    });
}

/// `Admin/get-application-usage`.
pub fn get_application_usage(
    pool: &DbPool,
    req: GetApplicationUsageRequest,
) -> Result<GetApplicationUsageResponse, ServiceError> {
    find_user(pool, &req.user_id)?;
    if req.last_day < req.first_day {
        return Err(bad_request("last_day is before first_day"));
    }
    if (req.last_day - req.first_day).whole_days() > MAX_USAGE_DAYS {
        return Err(bad_request(format!(
            "a usage range covers at most {MAX_USAGE_DAYS} days"
        )));
    }
    flush_usage(pool);
    let days = UsageStore::list(pool, &req.user_id, req.first_day, req.last_day)
        .map_err(|e| internal("reading usage", e))?;
    let limits = pool
        .account_limits(&req.user_id)
        .map_err(|e| internal("reading account limits", e))?;
    let since = OffsetDateTime::now_utc()
        - time::Duration::days(i64::from(limits.distinct_user_window_days));
    let distinct_users = pool
        .count_application_users_since(&req.user_id, since)
        .map_err(|e| internal("counting users", e))?;
    Ok(GetApplicationUsageResponse {
        distinct_users,
        distinct_user_window_days: i64::from(limits.distinct_user_window_days),
        max_distinct_users: limits.max_distinct_users.map(i64::from),
        days: days
            .into_iter()
            .map(|d| RpUsageDay {
                day: d.day,
                operation: d.operation,
                succeeded: d.succeeded,
                failed: d.failed,
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_hash_is_keyed_and_stable() {
        let a = user_hash("pass-one", "u1@example.com");
        assert_eq!(a, user_hash("pass-one", "u1@example.com"));
        assert_ne!(a, user_hash("pass-two", "u1@example.com"));
        assert_ne!(a, user_hash("pass-one", "u2@example.com"));
    }

    #[test]
    fn key_hint_is_the_last_four_characters() {
        assert_eq!(key_hint("abc.defgh"), "efgh");
        assert_eq!(key_hint("ab"), "ab");
    }

    #[test]
    fn account_rate_limit_applies_only_when_set() {
        let none = AccountLimitsRecord::default();
        for _ in 0..1000 {
            assert!(account_request_allowed(&none, "unlimited"));
        }
        let limited = AccountLimitsRecord {
            requests_per_minute: Some(60),
            request_burst: Some(2),
            ..AccountLimitsRecord::default()
        };
        let id = uuid::Uuid::now_v7().to_string();
        assert!(account_request_allowed(&limited, &id));
        assert!(account_request_allowed(&limited, &id));
        assert!(!account_request_allowed(&limited, &id));
    }

    #[test]
    fn limits_are_validated() {
        let mut l = limits_to_wire(&AccountLimitsRecord::default());
        assert!(limits_from_wire(&l).is_ok());
        l.max_distinct_users = Some(0);
        assert!(limits_from_wire(&l).is_err());
        l.max_distinct_users = Some(100);
        l.distinct_user_window_days = 0;
        assert!(limits_from_wire(&l).is_err());
        l.distinct_user_window_days = 30;
        l.request_burst = Some(5);
        assert!(limits_from_wire(&l).is_err(), "a burst needs a rate");
    }
}
