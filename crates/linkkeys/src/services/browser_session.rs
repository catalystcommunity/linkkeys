//! Browser-session operations shared by the HTML routes and the CSIL carrier.

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use liblinkkeys::generated::services::ServiceError;
use liblinkkeys::generated::types::{
    AdminUser, BrowserSessionInfo, IntrospectBrowserSessionResponse,
};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::db::{models, DbPool};
use crate::services::auth::AuthenticationEvidence;

pub const COOKIE_NAME: &str = "__Host-linkkeys_session";
const ABSOLUTE_TTL_SECONDS: i64 = 43_200;
const IDLE_TTL_SECONDS: i64 = 3_600;

pub fn absolute_ttl_seconds() -> i64 {
    ABSOLUTE_TTL_SECONDS
}

pub fn idle_ttl_seconds() -> i64 {
    IDLE_TTL_SECONDS
}

pub fn token_digest(token: &str) -> String {
    let bytes = Sha256::digest(token.as_bytes());
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_time(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|v| v.with_timezone(&Utc))
}

fn methods(value: &str) -> Vec<String> {
    value
        .split(',')
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .collect()
}

fn active(session: &models::BrowserSession) -> bool {
    let Some(last_seen) = parse_time(&session.last_seen_at) else {
        return false;
    };
    let Some(expires) = parse_time(&session.expires_at) else {
        return false;
    };
    let now = Utc::now();
    session.revoked_at.is_none()
        && now <= expires
        && now >= last_seen
        && now.signed_duration_since(last_seen).num_seconds() <= idle_ttl_seconds()
}

pub fn create(
    pool: &DbPool,
    user_id: &str,
    evidence: &AuthenticationEvidence,
) -> Result<(String, models::BrowserSession), ServiceError> {
    let mut secret = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let token = Base64UrlUnpadded::encode_string(&secret);
    let digest = token_digest(&token);
    let now = Utc::now();
    let expires = now + chrono::Duration::seconds(absolute_ttl_seconds());
    let method_list = evidence
        .method_types
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .join(",");
    let row = pool
        .create_browser_session(
            &digest,
            user_id,
            now,
            evidence.authenticated_at,
            &method_list,
            expires,
        )
        .map_err(db_error)?;
    Ok((token, row))
}

/// Create a session only if the password credential that proved the login is
/// still active. The database serializes this check with password replacement.
pub fn create_after_password(
    pool: &DbPool,
    user_id: &str,
    credential_id: &str,
    evidence: &AuthenticationEvidence,
) -> Result<(String, models::BrowserSession), ServiceError> {
    let mut secret = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let token = Base64UrlUnpadded::encode_string(&secret);
    let digest = token_digest(&token);
    let now = Utc::now();
    let expires = now + chrono::Duration::seconds(absolute_ttl_seconds());
    let method_list = evidence
        .method_types
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .join(",");
    let row = pool
        .create_browser_session_if_password_active(
            &digest,
            user_id,
            credential_id,
            now,
            evidence.authenticated_at,
            &method_list,
            expires,
        )
        .map_err(db_error)?;
    Ok((token, row))
}

pub fn get(
    pool: &DbPool,
    token: &str,
    refresh: bool,
) -> Result<Option<models::BrowserSession>, ServiceError> {
    let digest = token_digest(token);
    let Some(session) = pool.find_browser_session(&digest).map_err(db_error)? else {
        return Ok(None);
    };
    if !active(&session) {
        let _ = pool.revoke_browser_session(&digest);
        return Ok(None);
    }
    let user = pool.find_user_by_id(&session.user_id).map_err(db_error)?;
    if !user.is_active || user.purged_at.is_some() {
        let _ = pool.revoke_browser_session(&digest);
        return Ok(None);
    }
    let should_refresh = parse_time(&session.last_seen_at)
        .is_some_and(|last_seen| Utc::now().signed_duration_since(last_seen).num_seconds() >= 60);
    if refresh && should_refresh {
        if let Err(error) = pool.touch_browser_session(&digest, Utc::now()) {
            log::warn!("Could not refresh browser session activity: {error}");
        }
    }
    Ok(Some(session))
}

/// Recheck the exact stored session immediately before a security-sensitive
/// result is issued after asynchronous work.
pub fn valid_digest_for_user(
    pool: &DbPool,
    digest: &str,
    user_id: &str,
) -> Result<bool, ServiceError> {
    let session = pool.find_browser_session(digest).map_err(db_error)?;
    Ok(session.is_some_and(|session| session.user_id == user_id && active(&session)))
}

pub fn revoke(pool: &DbPool, token: &str) -> Result<(), ServiceError> {
    match pool
        .revoke_browser_session(&token_digest(token))
        .map_err(db_error)?
    {
        1 => Ok(()),
        _ => Err(ServiceError {
            code: 403,
            message: "Authentication required".to_string(),
        }),
    }
}

pub fn info(
    pool: &DbPool,
    session: &models::BrowserSession,
) -> Result<BrowserSessionInfo, ServiceError> {
    let user = pool.find_user_by_id(&session.user_id).map_err(db_error)?;
    let effective_expires = parse_time(&session.expires_at)
        .zip(parse_time(&session.last_seen_at))
        .map(|(absolute, last_seen)| {
            absolute.min(last_seen + chrono::Duration::seconds(idle_ttl_seconds()))
        })
        .map(|value| value.to_rfc3339())
        .unwrap_or_else(|| session.expires_at.clone());
    Ok(BrowserSessionInfo {
        user: AdminUser {
            id: user.id,
            username: user.username,
            display_name: user.display_name,
            is_active: user.is_active,
            created_at: user.created_at,
            updated_at: user.updated_at,
            purged_at: user.purged_at,
            purge_reason: user.purge_reason,
        },
        issued_at: session.issued_at.clone(),
        authenticated_at: session.authenticated_at.clone(),
        expires_at: effective_expires,
        authentication_methods: methods(&session.authentication_methods),
    })
}

pub fn introspection(session: &models::BrowserSession) -> IntrospectBrowserSessionResponse {
    let effective_expires = parse_time(&session.expires_at)
        .zip(parse_time(&session.last_seen_at))
        .map(|(absolute, last_seen)| {
            absolute.min(last_seen + chrono::Duration::seconds(idle_ttl_seconds()))
        })
        .map(|value| value.to_rfc3339())
        .unwrap_or_else(|| session.expires_at.clone());
    IntrospectBrowserSessionResponse {
        user_id: session.user_id.clone(),
        user_domain: crate::conversions::get_domain_name(),
        authenticated_at: session.authenticated_at.clone(),
        expires_at: effective_expires,
        authentication_methods: methods(&session.authentication_methods),
    }
}

fn db_error(error: diesel::result::Error) -> ServiceError {
    log::error!("Browser session database operation failed: {error}");
    ServiceError {
        code: 500,
        message: "Internal database error".to_string(),
    }
}
