use liblinkkeys::generated::services::ServiceError;
use liblinkkeys::generated::types::{
    AdminUser, ChangePasswordRequest, ChangePasswordResponse, Claim, CreateProfileRequest,
    CreateProfileResponse, GetMyInfoResponse, RemoveMyClaimRequest, RemoveMyClaimResponse,
    RequestVerificationRequest, RequestVerificationResponse, SetMyClaimRequest, SetMyClaimResponse,
    SetMyClaimSharingRequest, SetMyClaimSharingResponse,
};

use crate::db::DbPool;
use crate::services::{attestation, auth, password, self_service};

fn db_err(e: diesel::result::Error) -> ServiceError {
    log::error!("Database error: {}", e);
    ServiceError {
        code: 500,
        message: "Internal database error".to_string(),
    }
}

pub fn change_password(
    pool: &DbPool,
    user_id: &str,
    req: ChangePasswordRequest,
) -> Result<ChangePasswordResponse, ServiceError> {
    password::validate(&req.new_password)?;

    // Remove old password credentials
    let old_creds = pool
        .find_credentials_for_user(user_id, auth::CREDENTIAL_TYPE_PASSWORD)
        .map_err(db_err)?;
    for cred in &old_creds {
        pool.remove_credential(&cred.id).map_err(db_err)?;
    }

    // Create new password credential
    let hash = password::hash_for_storage(&req.new_password)?;
    pool.create_auth_credential(user_id, auth::CREDENTIAL_TYPE_PASSWORD, &hash)
        .map_err(db_err)?;

    Ok(ChangePasswordResponse { success: true })
}

pub fn get_my_info(pool: &DbPool, user_id: &str) -> Result<GetMyInfoResponse, ServiceError> {
    let user = pool.find_user_by_id(user_id).map_err(db_err)?;
    let relations = pool
        .list_relations_for_subject("user", user_id)
        .map_err(db_err)?;
    let claims = pool.list_active_claims(user_id).map_err(db_err)?;

    Ok(GetMyInfoResponse {
        user: AdminUser {
            id: user.id,
            username: user.username,
            display_name: user.display_name,
            is_active: user.is_active,
            created_at: user.created_at,
            updated_at: user.updated_at,
        },
        relations: relations
            .iter()
            .map(|r| liblinkkeys::generated::types::Relation {
                id: r.id.clone(),
                subject_type: r.subject_type.clone(),
                subject_id: r.subject_id.clone(),
                relation: r.relation.clone(),
                object_type: r.object_type.clone(),
                object_id: r.object_id.clone(),
                created_at: r.created_at.clone(),
                removed_at: r.removed_at.clone(),
            })
            .collect(),
        claims: claims.iter().map(|c| -> Claim { c.into() }).collect(),
    })
}

/// CSIL-RPC entry point for `Account/set-my-claim`: the caller sets one of
/// their OWN claim values. `user_id` is the TCP dispatcher's authenticated
/// caller, never a field on `req` — a client cannot target another user's
/// claims through this op. Reuses the exact claim-policy evaluation
/// `services::self_service::set_my_claim` performs for the web identity
/// editor (`web::profile_ui::set_claim_submit`) and for
/// `Admin/set-user-claim`.
pub fn set_my_claim(
    pool: &DbPool,
    user_id: &str,
    req: SetMyClaimRequest,
) -> Result<SetMyClaimResponse, ServiceError> {
    let outcome =
        self_service::set_my_claim(pool, user_id, &req.claim_type, req.claim_value.as_bytes())?;

    let claim = match outcome {
        self_service::SetOutcome::Signed | self_service::SetOutcome::StoredUnsigned => pool
            .list_active_claims(user_id)
            .map_err(db_err)?
            .into_iter()
            .find(|c| c.claim_type == req.claim_type)
            .map(|c| (&c).into()),
        self_service::SetOutcome::VerificationRequired | self_service::SetOutcome::Queued => None,
    };

    let outcome_str = match outcome {
        self_service::SetOutcome::Signed => "signed",
        self_service::SetOutcome::StoredUnsigned => "stored_unsigned",
        self_service::SetOutcome::VerificationRequired => "verification_required",
        self_service::SetOutcome::Queued => "queued",
    };

    Ok(SetMyClaimResponse {
        outcome: outcome_str.to_string(),
        claim,
    })
}

/// CSIL-RPC entry point for `Account/remove-my-claim`: the caller removes one
/// of their OWN active claims. `user_id` is the authenticated caller;
/// `self_service::remove_my_claim` rejects the request if `req.claim_id`
/// belongs to a different user.
pub fn remove_my_claim(
    pool: &DbPool,
    user_id: &str,
    req: RemoveMyClaimRequest,
) -> Result<RemoveMyClaimResponse, ServiceError> {
    self_service::remove_my_claim(pool, user_id, &req.claim_id)?;
    Ok(RemoveMyClaimResponse { success: true })
}

/// CSIL-RPC entry point for `Account/set-my-claim-sharing`: the caller sets
/// or clears a standing release preference (pre-approval to share with ALL
/// audiences, `"*"`) for one of their OWN claim types. `user_id` is the TCP
/// dispatcher's authenticated caller, never a field on `req` — a client
/// cannot pre-share another user's claim through this op. Reuses
/// `services::self_service::set_my_claim_sharing`, the same call
/// `web::profile_ui::set_share_submit` makes.
pub fn set_my_claim_sharing(
    pool: &DbPool,
    user_id: &str,
    req: SetMyClaimSharingRequest,
) -> Result<SetMyClaimSharingResponse, ServiceError> {
    self_service::set_my_claim_sharing(pool, user_id, &req.claim_type, req.share)?;
    Ok(SetMyClaimSharingResponse {})
}

/// CSIL-RPC entry point for `Account/create-profile`: create an additional
/// presentable profile for the caller's OWN account. Reuses
/// `services::self_service::create_profile`, the same call
/// `web::profile_ui::create_profile_submit` makes.
pub fn create_profile(
    pool: &DbPool,
    user_id: &str,
    req: CreateProfileRequest,
) -> Result<CreateProfileResponse, ServiceError> {
    let profile = self_service::create_profile(pool, user_id, req.label.as_deref())?;
    Ok(CreateProfileResponse {
        profile: (&profile).into(),
    })
}

/// CSIL-RPC entry point for `Account/request-verification`: mint a
/// home-domain-signed signing-request bundle for the caller's OWN account,
/// addressed to `req.issuer_domain`, asking it to attest
/// `req.requested_claim_types`. Reuses `services::attestation::mint_signing_request`,
/// the same call backing the web `/account/request-verification` /
/// `/account/request-verification.bin` routes.
pub fn request_verification(
    pool: &DbPool,
    user_id: &str,
    req: RequestVerificationRequest,
) -> Result<RequestVerificationResponse, ServiceError> {
    let signed_request = attestation::mint_signing_request(
        pool,
        user_id,
        &req.issuer_domain,
        &req.requested_claim_types,
    )?;
    Ok(RequestVerificationResponse { signed_request })
}
