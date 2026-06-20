//! Email verification (the lane-B flow). A user asks to verify an address; we
//! store a single-use token and email a confirmation link. When the link is
//! visited, the IDP signs both the `email` value and an `email_verified` boolean
//! and deletes the token. No phone/SMS flow exists by design.

use std::env;

use liblinkkeys::claim_policy::ValueType;
use liblinkkeys::generated::services::ServiceError;

use crate::conversions::get_domain_name;
use crate::db::DbPool;
use crate::services::self_service;

/// How long a verification link is valid.
const VERIFICATION_TTL_HOURS: i64 = 24;

fn svc_err(code: i32, msg: &str) -> ServiceError {
    ServiceError {
        code,
        message: msg.to_string(),
    }
}

fn db_err(e: diesel::result::Error) -> ServiceError {
    log::error!("Database error: {}", e);
    svc_err(500, "Internal database error")
}

/// Public base URL for building the confirmation link, from `PUBLIC_ORIGIN` or
/// `https://<domain>`.
fn public_origin() -> String {
    env::var("PUBLIC_ORIGIN").unwrap_or_else(|_| format!("https://{}", get_domain_name()))
}

/// Begin verifying `email` for `subject_id`: validate the address, store a token,
/// and send the confirmation link. The address is not signed until the link is
/// confirmed.
// TODO(follow-up): rate-limit per user and per target address. Today a
// logged-in user can trigger a confirmation email to any address on each submit
// (no false verification results — signing still needs the click — but it is an
// authenticated spam amplifier). Add a per-user/per-recipient throttle and/or a
// cap on outstanding tokens before wiring a real SMTP backend.
pub fn request_email_verification(
    pool: &DbPool,
    subject_id: &str,
    email: &str,
) -> Result<(), ServiceError> {
    // Honor the registry: the type must exist and bound the value size.
    let row = pool
        .find_claim_policy("email")
        .map_err(db_err)?
        .ok_or_else(|| svc_err(400, "email verification is not enabled on this domain"))?;
    if email.len() as i64 > row.max_bytes {
        return Err(svc_err(400, "email address is too long"));
    }
    if ValueType::Email.validate(email.as_bytes()).is_err() {
        return Err(svc_err(400, "that doesn't look like an email address"));
    }

    let token = uuid::Uuid::now_v7().to_string();
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(VERIFICATION_TTL_HOURS);
    pool.create_email_verification(&token, subject_id, email, expires_at)
        .map_err(db_err)?;

    let link = format!(
        "{}/account/identity/verify-email?token={}",
        public_origin(),
        token
    );
    crate::email::send_verification_email(email, &link).map_err(|e| svc_err(500, &e))?;
    Ok(())
}

/// Confirm a verification token: sign `email` and `email_verified` for the
/// subject and consume the token. `session_user_id` is the logged-in user
/// visiting the link; it must match the account that requested verification so a
/// leaked link can't be redeemed under a different session. Returns the verified
/// address.
pub fn confirm_email_verification(
    pool: &DbPool,
    token: &str,
    session_user_id: &str,
) -> Result<String, ServiceError> {
    let v = pool
        .find_email_verification(token)
        .map_err(db_err)?
        .ok_or_else(|| {
            svc_err(
                400,
                "this verification link is invalid or has already been used",
            )
        })?;

    if v.user_id != session_user_id {
        return Err(svc_err(
            403,
            "this verification link belongs to a different account",
        ));
    }

    let expired = chrono::DateTime::parse_from_rfc3339(&v.expires_at)
        .map(|e| chrono::Utc::now() > e.with_timezone(&chrono::Utc))
        .unwrap_or(true);
    if expired {
        let _ = pool.delete_email_verification(token);
        return Err(svc_err(400, "this verification link has expired"));
    }

    // Sign the address itself and the boolean flag, both bound to the subject.
    self_service::sign_and_store(pool, &v.user_id, "email", v.email.as_bytes())?;
    self_service::sign_and_store(pool, &v.user_id, "email_verified", b"true")?;

    pool.delete_email_verification(token).map_err(db_err)?;
    Ok(v.email)
}
