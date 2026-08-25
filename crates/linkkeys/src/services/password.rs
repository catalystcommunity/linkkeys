//! Password validation, hashing, and verification.
//!
//! Hashing uses Argon2id (via `liblinkkeys::crypto`). Verification also accepts
//! the legacy bcrypt scheme so credentials created before the migration keep
//! working; when a legacy hash verifies, the caller is told to re-hash it with
//! Argon2id so the upgrade happens transparently on next login.

use liblinkkeys::generated::services::ServiceError;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::LazyLock;

pub const MIN_PASSWORD_LENGTH: usize = 8;
pub const MAX_USERNAME_LENGTH: usize = 254;

/// Return whether password authentication is available on this server.
pub fn authentication_enabled() -> bool {
    std::env::var("ENABLE_PASSWORD_AUTH").map_or(true, |value| value == "true")
}

pub fn valid_login_shape(username: &str, password: &str) -> bool {
    !username.trim().is_empty()
        && username.len() <= MAX_USERNAME_LENGTH
        && password.len() <= MAX_PASSWORD_LENGTH
}

/// A fixed Argon2id hash used to spend verification time on the user-not-found
/// path, so a missing username can't be told apart from a wrong password by
/// response latency (SEC-05). Computed once; the plaintext is irrelevant.
static DUMMY_HASH: LazyLock<String> = LazyLock::new(|| {
    liblinkkeys::crypto::hash_password("linkkeys-timing-equalizer").unwrap_or_default()
});
static ACTIVE_PASSWORD_WORK: AtomicUsize = AtomicUsize::new(0);
const MAX_ACTIVE_PASSWORD_WORK: usize = 4;

struct PasswordWorkPermit;

impl PasswordWorkPermit {
    fn acquire() -> Option<Self> {
        ACTIVE_PASSWORD_WORK
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < MAX_ACTIVE_PASSWORD_WORK).then_some(active + 1)
            })
            .ok()
            .map(|_| Self)
    }
}

impl Drop for PasswordWorkPermit {
    fn drop(&mut self) {
        ACTIVE_PASSWORD_WORK.fetch_sub(1, Ordering::Release);
    }
}

/// Spend roughly one password-verification's worth of time without revealing
/// whether a user exists. Call on the username-not-found branch before returning
/// an auth failure. The result is intentionally discarded.
pub fn dummy_verify(password: &str) {
    if DUMMY_HASH.is_empty() {
        // Extremely unlikely fallback: still hash so timing stays comparable.
        let _ = liblinkkeys::crypto::hash_password(password);
        return;
    }
    let _ = liblinkkeys::crypto::verify_password(password, &DUMMY_HASH);
}

/// Run dummy password work only when a bounded worker slot is available.
pub fn dummy_verify_bounded(password: &str) -> bool {
    let Some(_permit) = PasswordWorkPermit::acquire() else {
        return false;
    };
    dummy_verify(password);
    true
}

/// Upper bound on password length. This is a denial-of-service guard on hashing
/// work, NOT a storage limit: the stored hash is fixed-length regardless of
/// input, and the DB column is unbounded (`VARCHAR`/`TEXT`). Argon2id has no
/// 72-byte truncation like bcrypt, so this can be generous.
pub const MAX_PASSWORD_LENGTH: usize = 1024;

/// Validate a candidate password against the length policy. The minimum uses
/// Unicode scalar values so it matches the user-facing character rule. The
/// maximum uses encoded bytes to bound hashing work.
pub fn validate(password: &str) -> Result<(), ServiceError> {
    if password.chars().count() < MIN_PASSWORD_LENGTH {
        return Err(ServiceError {
            code: 400,
            message: format!(
                "Password must be at least {} characters",
                MIN_PASSWORD_LENGTH
            ),
        });
    }
    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(ServiceError {
            code: 400,
            message: format!("Password must be at most {} bytes", MAX_PASSWORD_LENGTH),
        });
    }
    Ok(())
}

/// Hash a new password for storage with Argon2id, returning a PHC string.
pub fn hash_for_storage(password: &str) -> Result<String, ServiceError> {
    let _permit = PasswordWorkPermit::acquire().ok_or_else(|| ServiceError {
        code: 503,
        message: "Password processing is busy. Try again".to_string(),
    })?;
    liblinkkeys::crypto::hash_password(password).map_err(|e| ServiceError {
        code: 1,
        message: format!("hash error: {}", e),
    })
}

/// Outcome of verifying a password against a stored credential hash.
pub struct VerifyOutcome {
    /// Whether the password matched the stored hash.
    pub verified: bool,
    /// True when the password matched a legacy (bcrypt) hash and should be
    /// re-hashed with Argon2id. Always false for Argon2id hashes.
    pub needs_rehash: bool,
}

/// Verify `password` against a stored credential hash, supporting both Argon2id
/// (current) and bcrypt (legacy). Scheme is detected by the PHC/bcrypt prefix.
pub fn verify(password: &str, stored_hash: &str) -> VerifyOutcome {
    let Some(_permit) = PasswordWorkPermit::acquire() else {
        return VerifyOutcome {
            verified: false,
            needs_rehash: false,
        };
    };
    if stored_hash.starts_with("$argon2") {
        VerifyOutcome {
            verified: liblinkkeys::crypto::verify_password(password, stored_hash),
            needs_rehash: false,
        }
    } else {
        // Legacy bcrypt (`$2a$` / `$2b$` / `$2y$`). bcrypt::verify returns Err on
        // a malformed hash; treat that as a non-match rather than an error so a
        // corrupt row can't be distinguished from a wrong password.
        VerifyOutcome {
            verified: bcrypt::verify(password, stored_hash).unwrap_or(false),
            needs_rehash: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{validate, MIN_PASSWORD_LENGTH};

    #[test]
    fn password_minimum_counts_unicode_characters() {
        assert!(validate(&"🔑".repeat(MIN_PASSWORD_LENGTH)).is_ok());
        assert!(validate(&"🔑".repeat(MIN_PASSWORD_LENGTH - 1)).is_err());
    }
}
