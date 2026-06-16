//! Password validation, hashing, and verification.
//!
//! Hashing uses Argon2id (via `liblinkkeys::crypto`). Verification also accepts
//! the legacy bcrypt scheme so credentials created before the migration keep
//! working; when a legacy hash verifies, the caller is told to re-hash it with
//! Argon2id so the upgrade happens transparently on next login.

use liblinkkeys::generated::services::ServiceError;

pub const MIN_PASSWORD_LENGTH: usize = 8;

/// Upper bound on password length. This is a denial-of-service guard on hashing
/// work, NOT a storage limit: the stored hash is fixed-length regardless of
/// input, and the DB column is unbounded (`VARCHAR`/`TEXT`). Argon2id has no
/// 72-byte truncation like bcrypt, so this can be generous.
pub const MAX_PASSWORD_LENGTH: usize = 1024;

/// Validate a candidate password against the length policy. Length is measured
/// in bytes (`str::len`) to bound hashing work precisely; multi-byte UTF-8
/// passphrases are therefore counted by their encoded size.
pub fn validate(password: &str) -> Result<(), ServiceError> {
    if password.len() < MIN_PASSWORD_LENGTH {
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
