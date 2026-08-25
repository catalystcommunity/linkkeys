//! Public password-recovery operations.

use liblinkkeys::generated::services::ServiceError;
use liblinkkeys::generated::types::{
    CompletePasswordRecoveryResponse, PasswordPolicy, RequestPasswordRecoveryResponse,
    ValidatePasswordRecoveryResponse,
};

use crate::db::DbPool;
use crate::services::notification::NotificationDispatcher;
use crate::services::{notification, password, verification};

const RECOVERY_TTL_MINUTES: i64 = 60;
const MAX_IDENTIFIER_LENGTH: usize = 320;
const TOKEN_LENGTH: usize = 43;

pub fn request(
    pool: &DbPool,
    identifier: &str,
    source_key: &str,
) -> Result<RequestPasswordRecoveryResponse, ServiceError> {
    if !password::authentication_enabled()
        || identifier.trim().is_empty()
        || identifier.len() > MAX_IDENTIFIER_LENGTH
    {
        return Ok(RequestPasswordRecoveryResponse {});
    }
    let normalized = identifier.trim().to_lowercase();
    let allowed = crate::services::ratelimit::RECOVERY_SOURCE.check(source_key);
    if !allowed || !password::dummy_verify_bounded(identifier) || !notification::email_available() {
        return Ok(RequestPasswordRecoveryResponse {});
    }
    let contact = if normalized.contains('@') {
        pool.find_recovery_contact(&normalized)
            .ok()
            .flatten()
            .filter(|value| {
                value
                    .purposes
                    .split(',')
                    .any(|purpose| purpose == "reset_password")
            })
    } else {
        pool.find_user_by_username(identifier.trim())
            .ok()
            .and_then(|user| pool.list_verified_contacts(&user.id).ok())
            .and_then(|rows| {
                rows.into_iter().find(|value| {
                    value.channel == "email"
                        && value.revoked_at.is_none()
                        && value
                            .purposes
                            .split(',')
                            .any(|purpose| purpose == "reset_password")
                })
            })
    };
    let Some(contact) = contact else {
        return Ok(RequestPasswordRecoveryResponse {});
    };
    let account_is_active = pool
        .find_user_by_id(&contact.user_id)
        .is_ok_and(|user| user.is_active && user.purged_at.is_none());
    if !account_is_active {
        return Ok(RequestPasswordRecoveryResponse {});
    }
    let account_key = verification::token_digest(&contact.user_id);
    let destination_key = verification::token_digest(&contact.destination);
    if !crate::services::ratelimit::RECOVERY_ACCOUNT.check(&account_key)
        || !crate::services::ratelimit::RECOVERY_DESTINATION.check(&destination_key)
    {
        return Ok(RequestPasswordRecoveryResponse {});
    }
    let token = verification::new_token();
    let digest = verification::token_digest(&token);
    let expires = chrono::Utc::now() + chrono::Duration::minutes(RECOVERY_TTL_MINUTES);
    let origin = std::env::var("PUBLIC_ORIGIN")
        .unwrap_or_else(|_| format!("https://{}", crate::conversions::get_domain_name()));
    let link = format!(
        "{}/app/password/reset#token={token}",
        origin.trim_end_matches('/')
    );
    if notification::DatabaseNotificationDispatcher::new(pool.clone())
        .dispatch(notification::NotificationIntent {
            user_id: contact.user_id,
            purpose: "reset_password".to_string(),
            channel: "email".to_string(),
            destination: contact.destination,
            token_digest: digest,
            secret_payload: link.into_bytes(),
            expires_at: expires,
            required_credential_id: None,
        })
        .is_err()
    {
        // Keep the public response identical for known and unknown accounts.
        log::error!("Could not queue password recovery");
    }
    Ok(RequestPasswordRecoveryResponse {})
}

pub fn validate(
    pool: &DbPool,
    token: &str,
) -> Result<ValidatePasswordRecoveryResponse, ServiceError> {
    require_password_authentication()?;
    if token.len() != TOKEN_LENGTH {
        return Err(invalid());
    }
    let challenge = pool
        .find_account_challenge(&verification::token_digest(token), "reset_password")
        .map_err(db_err)?
        .ok_or_else(invalid)?;
    Ok(ValidatePasswordRecoveryResponse {
        expires_at: challenge.expires_at,
        password_policy: PasswordPolicy {
            min_length: password::MIN_PASSWORD_LENGTH as i64,
            max_length: password::MAX_PASSWORD_LENGTH as i64,
        },
    })
}

pub fn complete(
    pool: &DbPool,
    token: &str,
    new_password: &str,
) -> Result<CompletePasswordRecoveryResponse, ServiceError> {
    require_password_authentication()?;
    if token.len() != TOKEN_LENGTH {
        return Err(invalid());
    }
    password::validate(new_password)?;
    let challenge = pool
        .find_account_challenge(&verification::token_digest(token), "reset_password")
        .map_err(db_err)?
        .ok_or_else(invalid)?;
    let hash = password::hash_for_storage(new_password)?;
    pool.complete_password_recovery(&challenge.id, &hash)
        .map_err(|error| match error {
            diesel::result::Error::NotFound => invalid(),
            other => db_err(other),
        })?;
    Ok(CompletePasswordRecoveryResponse { success: true })
}

fn require_password_authentication() -> Result<(), ServiceError> {
    password::authentication_enabled()
        .then_some(())
        .ok_or_else(|| svc_err(400, "Password recovery is not available"))
}

fn invalid() -> ServiceError {
    svc_err(400, "The password recovery link is invalid or expired")
}

fn svc_err(code: i32, message: &str) -> ServiceError {
    ServiceError {
        code,
        message: message.to_string(),
    }
}

fn db_err(_: diesel::result::Error) -> ServiceError {
    log::error!("Password recovery database operation failed");
    svc_err(500, "Internal database error")
}
