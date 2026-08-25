//! Verified-contact operations and compatibility entry points for the HTML UI.

use base64ct::{Base64UrlUnpadded, Encoding};
use liblinkkeys::claim_policy::ValueType;
use liblinkkeys::generated::services::ServiceError;
use liblinkkeys::generated::types::{
    Claim, ConfirmContactVerificationResponse, ListVerifiedContactMethodsResponse,
    RequestContactVerificationResponse, RevokeVerifiedContactMethodResponse, VerifiedContactMethod,
};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::db::DbPool;
use crate::services::auth::{Authenticator, PasswordAuthenticator};
use crate::services::notification::NotificationDispatcher;
use crate::services::{notification, self_service};

const VERIFICATION_TTL_HOURS: i64 = 24;

pub fn normalize_email(value: &str) -> Result<String, ServiceError> {
    let value = value.trim().to_lowercase();
    if ValueType::Email.validate(value.as_bytes()).is_err() {
        return Err(svc_err(400, "The email address is invalid"));
    }
    Ok(value)
}

pub fn list_verified_contacts(
    pool: &DbPool,
    user_id: &str,
) -> Result<ListVerifiedContactMethodsResponse, ServiceError> {
    let rows = pool.list_verified_contacts(user_id).map_err(db_err)?;
    Ok(ListVerifiedContactMethodsResponse {
        contact_methods: rows.into_iter().map(contact_to_csil).collect(),
    })
}

pub fn revoke_verified_contact(
    pool: &DbPool,
    user_id: &str,
    contact_method_id: &str,
    current_password: &str,
) -> Result<RevokeVerifiedContactMethodResponse, ServiceError> {
    let credential_id = authenticate_current_password(pool, user_id, current_password)?;
    match pool
        .revoke_verified_contact(user_id, contact_method_id, &credential_id)
        .map_err(|error| match error {
            diesel::result::Error::NotFound => {
                svc_err(403, "The current password is no longer valid. Try again")
            }
            other => db_err(other),
        })? {
        1 => Ok(RevokeVerifiedContactMethodResponse { success: true }),
        _ => Err(svc_err(404, "The verified contact was not found")),
    }
}

pub fn request_contact_verification(
    pool: &DbPool,
    user_id: &str,
    channel: &str,
    destination: &str,
    current_password: &str,
) -> Result<RequestContactVerificationResponse, ServiceError> {
    if !crate::services::password::authentication_enabled() {
        return Err(svc_err(400, "Contact verification is not available"));
    }
    if channel != "email" || !notification::email_available() {
        return Err(svc_err(400, "This notification channel is not available"));
    }
    let destination = normalize_email(destination)?;
    let credential_id = authenticate_current_password(pool, user_id, current_password)?;
    if !crate::services::ratelimit::EMAIL.check(user_id) {
        return Err(svc_err(
            429,
            "Too many verification requests. Wait before you try again",
        ));
    }
    let policy = pool
        .find_claim_policy("email")
        .map_err(db_err)?
        .ok_or_else(|| svc_err(400, "Email verification is not enabled on this domain"))?;
    if destination.len() as i64 > policy.max_bytes {
        return Err(svc_err(400, "The email address is too long"));
    }
    let token = new_token();
    let digest = token_digest(&token);
    let expires = chrono::Utc::now() + chrono::Duration::hours(VERIFICATION_TTL_HOURS);
    let link = format!("{}/app/verify/contact#token={token}", public_origin());
    notification::DatabaseNotificationDispatcher::new(pool.clone())
        .dispatch(notification::NotificationIntent {
            user_id: user_id.to_string(),
            purpose: "verify_contact".to_string(),
            channel: "email".to_string(),
            destination,
            token_digest: digest,
            secret_payload: link.into_bytes(),
            expires_at: expires,
            required_credential_id: Some(credential_id),
        })
        .map_err(|_| {
            log::error!("Could not queue contact verification");
            svc_err(500, "Could not send the verification message")
        })?;
    Ok(RequestContactVerificationResponse {
        expires_at: expires.to_rfc3339(),
    })
}

fn authenticate_current_password(
    pool: &DbPool,
    user_id: &str,
    current_password: &str,
) -> Result<String, ServiceError> {
    if !crate::services::ratelimit::STEP_UP.check(user_id) {
        return Err(svc_err(
            429,
            "Too many password attempts. Wait before you try again",
        ));
    }
    let user = pool.find_user_by_id(user_id).map_err(db_err)?;
    PasswordAuthenticator::new(pool.clone())
        .authenticate_with_evidence(&user.username, current_password)
        .map_err(|_| svc_err(403, "The current password is incorrect"))?
        .credential_id
        .ok_or_else(|| svc_err(403, "The current password is incorrect"))
}

pub fn confirm_contact_verification(
    pool: &DbPool,
    user_id: &str,
    token: &str,
) -> Result<ConfirmContactVerificationResponse, ServiceError> {
    let digest = token_digest(token);
    let challenge = pool
        .find_account_challenge(&digest, "verify_contact")
        .map_err(db_err)?
        .ok_or_else(|| svc_err(400, "The verification link is invalid or expired"))?;
    if challenge.user_id != user_id {
        return Err(svc_err(400, "The verification link is invalid or expired"));
    }
    let email_claim = self_service::prepare_signed_claim(
        pool,
        user_id,
        "email",
        challenge.destination.as_bytes(),
    )?;
    let verified_claim =
        self_service::prepare_signed_claim(pool, user_id, "email_verified", b"true")?;
    let contact = pool
        .confirm_contact_challenge(&challenge.id, &[email_claim, verified_claim])
        .map_err(|error| match error {
            diesel::result::Error::NotFound => {
                svc_err(400, "The verification link is invalid or expired")
            }
            other => db_err(other),
        })?;
    let claims = pool
        .list_active_claims(user_id)
        .map_err(db_err)?
        .into_iter()
        .filter(|value| value.claim_type == "email" || value.claim_type == "email_verified")
        .map(|value| Claim::from(&value))
        .collect();
    Ok(ConfirmContactVerificationResponse {
        contact_method: contact_to_csil(contact),
        claims,
    })
}

pub fn request_email_verification(
    pool: &DbPool,
    user_id: &str,
    email: &str,
    current_password: &str,
) -> Result<(), ServiceError> {
    request_contact_verification(pool, user_id, "email", email, current_password).map(|_| ())
}

pub fn confirm_email_verification(
    pool: &DbPool,
    token: &str,
    user_id: &str,
) -> Result<String, ServiceError> {
    confirm_contact_verification(pool, user_id, token).map(|value| value.contact_method.destination)
}

pub fn new_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    Base64UrlUnpadded::encode_string(&bytes)
}

pub fn token_digest(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|value| format!("{value:02x}"))
        .collect()
}

fn public_origin() -> String {
    std::env::var("PUBLIC_ORIGIN")
        .unwrap_or_else(|_| format!("https://{}", crate::conversions::get_domain_name()))
        .trim_end_matches('/')
        .to_string()
}

fn contact_to_csil(value: crate::db::models::VerifiedContactMethod) -> VerifiedContactMethod {
    VerifiedContactMethod {
        id: value.id,
        channel: value.channel,
        destination: value.destination,
        verified_at: value.verified_at,
        purposes: value.purposes.split(',').map(str::to_string).collect(),
        revoked_at: value.revoked_at,
    }
}

fn svc_err(code: i32, message: &str) -> ServiceError {
    ServiceError {
        code,
        message: message.to_string(),
    }
}

fn db_err(_: diesel::result::Error) -> ServiceError {
    log::error!("Account security database operation failed");
    svc_err(500, "Internal database error")
}
