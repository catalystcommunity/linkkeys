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
        let user = match &self.pool {
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
        }
        .map_err(|_| AuthError::InvalidCredentials)?;

        let creds = self
            .pool
            .find_credentials_for_user(&user.id, CREDENTIAL_TYPE_PASSWORD)
            .map_err(|e| AuthError::DbError(e.to_string()))?;

        for cred in &creds {
            if bcrypt::verify(password, &cred.credential_hash).unwrap_or(false) {
                return Ok(user);
            }
        }

        Err(AuthError::InvalidCredentials)
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

        // Find user whose ID starts with this prefix
        let user = self.find_user_by_id_prefix(prefix)?;

        let creds = self
            .pool
            .find_credentials_for_user(&user.id, CREDENTIAL_TYPE_API_KEY)
            .map_err(|e| AuthError::DbError(e.to_string()))?;

        for cred in &creds {
            if bcrypt::verify(secret, &cred.credential_hash).unwrap_or(false) {
                return Ok(user);
            }
        }

        Err(AuthError::InvalidCredentials)
    }

    fn find_user_by_id_prefix(&self, prefix: &str) -> Result<User, AuthError> {
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
                    .first::<crate::db::models::pg::UserRow>(&mut conn)
                    .map(Into::into)
                    .map_err(|_| AuthError::InvalidCredentials)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                use diesel::prelude::*;
                let mut conn = p.get().map_err(|e| AuthError::DbError(e.to_string()))?;
                let pattern = format!("{}%", prefix);
                crate::schema::sqlite::users::table
                    .filter(crate::schema::sqlite::users::id.like(&pattern))
                    .first::<crate::db::models::sqlite::UserRow>(&mut conn)
                    .map(Into::into)
                    .map_err(|_| AuthError::InvalidCredentials)
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
