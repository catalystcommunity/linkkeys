use crate::db::models::User;
use crate::db::DbPool;
use std::fmt;

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
    fn authenticate(&self, username: &str, password: &str) -> Result<User, AuthError>;
}

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

        if bcrypt::verify(password, &user.password_hash).unwrap_or(false) {
            Ok(user)
        } else {
            Err(AuthError::InvalidCredentials)
        }
    }
}
