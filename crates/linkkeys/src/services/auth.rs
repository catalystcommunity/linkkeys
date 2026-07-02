use crate::db::models::User;
use crate::db::DbPool;
use std::fmt;

pub const CREDENTIAL_TYPE_PASSWORD: &str = "password";
pub const CREDENTIAL_TYPE_API_KEY: &str = "api_key";

#[derive(Debug)]
pub enum AuthError {
    InvalidCredentials,
    DbError(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::InvalidCredentials => write!(f, "invalid credentials"),
            AuthError::DbError(msg) => write!(f, "database error: {}", msg),
        }
    }
}

pub trait Authenticator: Send + Sync {
    fn authenticate(&self, username: &str, credential: &str) -> Result<User, AuthError>;
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
    fn authenticate(&self, username: &str, password: &str) -> Result<User, AuthError> {
        let found = match &self.pool {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| AuthError::DbError(e.to_string()))?;
                crate::db::users::pg::find_by_username(&mut conn, username)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| AuthError::DbError(e.to_string()))?;
                crate::db::users::sqlite::find_by_username(&mut conn, username)
            }
        };
        let user = match found {
            Ok(u) => u,
            Err(_) => {
                // SEC-05: equalize timing so a missing username is not
                // distinguishable from a wrong password by response latency.
                crate::services::password::dummy_verify(password);
                return Err(AuthError::InvalidCredentials);
            }
        };

        let creds = self
            .pool
            .find_credentials_for_user(&user.id, CREDENTIAL_TYPE_PASSWORD)
            .map_err(|e| AuthError::DbError(e.to_string()))?;

        for cred in &creds {
            let outcome = crate::services::password::verify(password, &cred.credential_hash);
            if outcome.verified {
                if outcome.needs_rehash {
                    self.rehash_to_argon2id(&cred.id, password);
                }
                return Ok(user);
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
        match liblinkkeys::crypto::hash_password(password) {
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
/// API key format: <8-char-user-id-prefix>.<secret>
/// The prefix enables O(1) user lookup before the expensive bcrypt verify.
pub struct ApiKeyAuthenticator {
    pool: DbPool,
}

impl ApiKeyAuthenticator {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub fn authenticate_key(&self, api_key: &str) -> Result<User, AuthError> {
        // Parse prefix.secret format
        let (prefix, secret) = api_key
            .split_once('.')
            .ok_or(AuthError::InvalidCredentials)?;

        if prefix.len() != 8 {
            return Err(AuthError::InvalidCredentials);
        }

        // The prefix is only a lookup hint, not a unique key — UUIDv7 prefixes
        // are timestamp-derived, so users created close in time share one.
        // Correctness comes from the bcrypt check, so we try EVERY user matching
        // the prefix rather than an arbitrary `.first()` (which would lock out
        // all but one of the colliders — db-07). The match set is small.
        let users = self.find_users_by_id_prefix(prefix)?;

        for user in users {
            let creds = self
                .pool
                .find_credentials_for_user(&user.id, CREDENTIAL_TYPE_API_KEY)
                .map_err(|e| AuthError::DbError(e.to_string()))?;

            for cred in &creds {
                if bcrypt::verify(secret, &cred.credential_hash).unwrap_or(false) {
                    return Ok(user);
                }
            }
        }

        Err(AuthError::InvalidCredentials)
    }

    fn find_users_by_id_prefix(&self, prefix: &str) -> Result<Vec<User>, AuthError> {
        // Validate prefix contains only hex chars and dashes (UUID characters)
        if !prefix.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
            return Err(AuthError::InvalidCredentials);
        }

        match &self.pool {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                use diesel::prelude::*;
                let mut conn = p.get().map_err(|e| AuthError::DbError(e.to_string()))?;
                let pattern = format!("{}%", prefix);
                // Use diesel's text cast + parameterized LIKE to avoid injection.
                // The prefix is already validated to contain only hex chars and dashes.
                crate::schema::pg::users::table
                    .filter(
                        diesel::dsl::sql::<diesel::sql_types::Text>("CAST(id AS TEXT)")
                            .like(&pattern),
                    )
                    .load::<crate::db::models::pg::UserRow>(&mut conn)
                    .map(|rows| rows.into_iter().map(Into::into).collect())
                    .map_err(|e| AuthError::DbError(e.to_string()))
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                use diesel::prelude::*;
                let mut conn = p.get().map_err(|e| AuthError::DbError(e.to_string()))?;
                let pattern = format!("{}%", prefix);
                crate::schema::sqlite::users::table
                    .filter(crate::schema::sqlite::users::id.like(&pattern))
                    .load::<crate::db::models::sqlite::UserRow>(&mut conn)
                    .map(|rows| rows.into_iter().map(Into::into).collect())
                    .map_err(|e| AuthError::DbError(e.to_string()))
            }
        }
    }
}

/// Generate an API key for a user. Returns (api_key, bcrypt_hash).
/// Format: <first-8-chars-of-user-id>.<32-bytes-random-base64url>
pub fn generate_api_key(user_id: &str) -> (String, String) {
    use base64ct::{Base64UrlUnpadded, Encoding};

    let prefix = &user_id[..8.min(user_id.len())];
    let secret_bytes: [u8; 32] = rand::random();
    let secret = Base64UrlUnpadded::encode_string(&secret_bytes);
    let api_key = format!("{}.{}", prefix, secret);
    let hash = bcrypt::hash(&secret, 12).expect("Failed to hash API key");
    (api_key, hash)
}
