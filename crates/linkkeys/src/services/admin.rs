use std::env;

use liblinkkeys::generated::services::ServiceError;
use liblinkkeys::generated::types::{
    AdminUser, CheckPermissionRequest, CheckPermissionResponse, Claim, CreateUserRequest,
    CreateUserResponse, DeactivateUserRequest, DeactivateUserResponse, GetUserRequest,
    GetUserResponse, GrantRelationRequest, GrantRelationResponse, ListRelationsRequest,
    ListRelationsResponse, ListUsersRequest, ListUsersResponse, RemoveClaimRequest,
    RemoveClaimResponse, RemoveCredentialRequest, RemoveCredentialResponse, RemoveRelationRequest,
    RemoveRelationResponse, ResetPasswordRequest, ResetPasswordResponse, SetClaimRequest,
    SetClaimResponse, UpdateUserRequest, UpdateUserResponse,
};

use crate::db::models;
use crate::db::DbPool;
use crate::services::{auth, password};

fn svc_err(msg: &str) -> ServiceError {
    ServiceError {
        code: 1,
        message: msg.to_string(),
    }
}

fn db_err(e: diesel::result::Error) -> ServiceError {
    log::error!("Database error: {}", e);
    ServiceError {
        code: 500,
        message: "Internal database error".to_string(),
    }
}

const VALID_RELATIONS: &[&str] = &[
    "admin",
    "manage_users",
    "manage_claims",
    "api_access",
    "member",
];
const VALID_SUBJECT_TYPES: &[&str] = &["user", "group"];
const VALID_OBJECT_TYPES: &[&str] = &["domain", "group", "user"];

fn user_to_admin_user(user: &models::User) -> AdminUser {
    AdminUser {
        id: user.id.clone(),
        username: user.username.clone(),
        display_name: user.display_name.clone(),
        is_active: user.is_active,
        created_at: user.created_at.clone(),
        updated_at: user.updated_at.clone(),
    }
}

fn relation_to_csil(rel: &models::Relation) -> liblinkkeys::generated::types::Relation {
    liblinkkeys::generated::types::Relation {
        id: rel.id.clone(),
        subject_type: rel.subject_type.clone(),
        subject_id: rel.subject_id.clone(),
        relation: rel.relation.clone(),
        object_type: rel.object_type.clone(),
        object_id: rel.object_id.clone(),
        created_at: rel.created_at.clone(),
        removed_at: rel.removed_at.clone(),
    }
}

pub fn list_users(
    pool: &DbPool,
    _req: ListUsersRequest,
) -> Result<ListUsersResponse, ServiceError> {
    let users = pool.list_all_users().map_err(db_err)?;
    Ok(ListUsersResponse {
        users: users.iter().map(user_to_admin_user).collect(),
    })
}

pub fn get_user(pool: &DbPool, req: GetUserRequest) -> Result<GetUserResponse, ServiceError> {
    let user = pool.find_user_by_id(&req.user_id).map_err(db_err)?;
    Ok(GetUserResponse {
        user: user_to_admin_user(&user),
    })
}

pub fn create_user(
    pool: &DbPool,
    req: CreateUserRequest,
) -> Result<CreateUserResponse, ServiceError> {
    let user = pool
        .create_user(&req.username, &req.display_name)
        .map_err(db_err)?;

    let api_key = if let Some(ref pw) = req.password {
        password::validate(pw)?;
        // Store password credential
        let hash = password::hash_for_storage(pw)?;
        pool.create_auth_credential(&user.id, auth::CREDENTIAL_TYPE_PASSWORD, &hash)
            .map_err(db_err)?;
        None
    } else {
        // Generate API key
        let (key, hash) = auth::generate_api_key(&user.id);
        pool.create_auth_credential(&user.id, auth::CREDENTIAL_TYPE_API_KEY, &hash)
            .map_err(db_err)?;
        Some(key)
    };

    // Generate keypairs
    let passphrase =
        env::var("DOMAIN_KEY_PASSPHRASE").map_err(|_| svc_err("DOMAIN_KEY_PASSPHRASE not set"))?;
    for years in &[2i64, 3, 4] {
        let (verifying_key, signing_key) = liblinkkeys::crypto::generate_ed25519_keypair();
        let pk_bytes = verifying_key.as_bytes().to_vec();
        let sk_bytes = signing_key.to_bytes();
        let encrypted = liblinkkeys::crypto::encrypt_private_key(&sk_bytes, passphrase.as_bytes())
            .map_err(|e| svc_err(&format!("encrypt error: {}", e)))?;
        let fp = liblinkkeys::crypto::fingerprint(&pk_bytes);
        let expires = chrono::Utc::now() + chrono::Duration::days(365 * years);
        pool.create_user_key(&user.id, &pk_bytes, &encrypted, &fp, "ed25519", expires)
            .map_err(db_err)?;
    }

    Ok(CreateUserResponse {
        user: user_to_admin_user(&user),
        api_key,
    })
}

pub fn update_user(
    pool: &DbPool,
    req: UpdateUserRequest,
) -> Result<UpdateUserResponse, ServiceError> {
    let user = if let Some(ref display_name) = req.display_name {
        pool.update_display_name(&req.user_id, display_name)
            .map_err(db_err)?
    } else {
        pool.find_user_by_id(&req.user_id).map_err(db_err)?
    };
    Ok(UpdateUserResponse {
        user: user_to_admin_user(&user),
    })
}

pub fn deactivate_user(
    pool: &DbPool,
    req: DeactivateUserRequest,
) -> Result<DeactivateUserResponse, ServiceError> {
    let user = pool.deactivate_user(&req.user_id).map_err(db_err)?;
    pool.revoke_all_credentials_for_user(&req.user_id)
        .map_err(db_err)?;
    Ok(DeactivateUserResponse {
        user: user_to_admin_user(&user),
    })
}

pub fn activate_user(pool: &DbPool, user_id: &str) -> Result<AdminUser, ServiceError> {
    let user = pool.activate_user(user_id).map_err(db_err)?;
    Ok(user_to_admin_user(&user))
}

pub fn reset_password(
    pool: &DbPool,
    req: ResetPasswordRequest,
) -> Result<ResetPasswordResponse, ServiceError> {
    password::validate(&req.new_password)?;

    // Remove old password credentials
    let old_creds = pool
        .find_credentials_for_user(&req.user_id, auth::CREDENTIAL_TYPE_PASSWORD)
        .map_err(db_err)?;
    for cred in &old_creds {
        pool.remove_credential(&cred.id).map_err(db_err)?;
    }

    // Create new password credential
    let hash = password::hash_for_storage(&req.new_password)?;
    pool.create_auth_credential(&req.user_id, auth::CREDENTIAL_TYPE_PASSWORD, &hash)
        .map_err(db_err)?;

    Ok(ResetPasswordResponse { success: true })
}

pub fn remove_credential(
    pool: &DbPool,
    req: RemoveCredentialRequest,
) -> Result<RemoveCredentialResponse, ServiceError> {
    // Verify the credential exists before removing
    let _credential = pool
        .find_credential_by_id(&req.credential_id)
        .map_err(|e| match e {
            diesel::result::Error::NotFound => ServiceError {
                code: 404,
                message: "Credential not found".to_string(),
            },
            other => db_err(other),
        })?;
    pool.remove_credential(&req.credential_id).map_err(db_err)?;
    Ok(RemoveCredentialResponse { success: true })
}

pub fn set_claim(pool: &DbPool, req: SetClaimRequest) -> Result<SetClaimResponse, ServiceError> {
    let passphrase =
        env::var("DOMAIN_KEY_PASSPHRASE").map_err(|_| svc_err("DOMAIN_KEY_PASSPHRASE not set"))?;

    let domain_keys = pool.list_active_domain_keys().map_err(db_err)?;
    // Sign with every active domain key (>=3 by design) so the claim carries a
    // quorum of signatures from this domain.
    let signers = crate::claim_signing::active_signers(&domain_keys, passphrase.as_bytes())
        .map_err(|e| svc_err(&e.to_string()))?;

    use chrono::Timelike;
    let expires_chrono = req
        .expires_at
        .as_deref()
        .map(|s| chrono::DateTime::parse_from_rfc3339(s).map(|dt| dt.with_timezone(&chrono::Utc)))
        .transpose()
        .map_err(|e| svc_err(&format!("invalid expires_at: {}", e)))?
        // Normalize to whole seconds: the expires_at is part of the claim's
        // signed payload, so it must round-trip byte-identically through both
        // Postgres (timestamptz, microsecond) and SQLite (RFC3339 text) storage.
        .map(|dt| dt.with_nanosecond(0).unwrap_or(dt));

    let claim_id = uuid::Uuid::now_v7().to_string();
    let claim_value_bytes = req.claim_value.as_bytes();
    let expires_str = expires_chrono.as_ref().map(|e| e.to_rfc3339());
    // The subject is a local user, so the subject's home domain is our own.
    let subject_domain = crate::conversions::get_domain_name();

    let signed_claim = crate::claim_signing::sign_with_active(
        &liblinkkeys::claims::ClaimSpec {
            claim_id: &claim_id,
            claim_type: &req.claim_type,
            claim_value: claim_value_bytes,
            user_id: &req.user_id,
            subject_domain: &subject_domain,
            expires_at: expires_str.as_deref(),
        },
        &signers,
    )
    .map_err(|e| svc_err(&e.to_string()))?;

    let stored = pool
        .create_claim(
            &claim_id,
            &req.user_id,
            &req.claim_type,
            claim_value_bytes,
            &signed_claim.signatures,
            expires_chrono,
        )
        .map_err(db_err)?;

    let claim: Claim = (&stored).into();
    Ok(SetClaimResponse { claim })
}

/// Approve a queued self-asserted claim: sign the held value with the domain's
/// active keys, store it for the subject, and mark the queue entry approved.
/// Signs with our own keys (the IDP is vouching), so there is no foreign-key
/// concern with the held value.
pub fn approve_claim(pool: &DbPool, approval_id: &str, admin_id: &str) -> Result<(), ServiceError> {
    let approval = pool.find_approval(approval_id).map_err(|e| match e {
        diesel::result::Error::NotFound => ServiceError {
            code: 404,
            message: "Approval not found".to_string(),
        },
        other => db_err(other),
    })?;
    if approval.status != "pending" {
        return Err(svc_err("approval already resolved"));
    }
    crate::services::self_service::sign_and_store(
        pool,
        &approval.user_id,
        &approval.claim_type,
        &approval.claim_value,
    )?;
    pool.resolve_approval(approval_id, "approved", admin_id)
        .map_err(db_err)?;
    Ok(())
}

/// Reject a queued claim: mark it rejected without signing anything.
pub fn reject_claim(pool: &DbPool, approval_id: &str, admin_id: &str) -> Result<(), ServiceError> {
    pool.resolve_approval(approval_id, "rejected", admin_id)
        .map_err(db_err)?;
    Ok(())
}

pub fn remove_claim(
    pool: &DbPool,
    req: RemoveClaimRequest,
) -> Result<RemoveClaimResponse, ServiceError> {
    // Verify the claim exists before removing
    let _claim = pool.find_claim_by_id(&req.claim_id).map_err(|e| match e {
        diesel::result::Error::NotFound => ServiceError {
            code: 404,
            message: "Claim not found".to_string(),
        },
        other => db_err(other),
    })?;
    pool.remove_claim(&req.claim_id).map_err(db_err)?;
    Ok(RemoveClaimResponse { success: true })
}

pub fn grant_relation(
    pool: &DbPool,
    req: GrantRelationRequest,
) -> Result<GrantRelationResponse, ServiceError> {
    if !VALID_RELATIONS.contains(&req.relation.as_str()) {
        return Err(ServiceError {
            code: 400,
            message: format!(
                "Unknown relation type: {}. Valid: {:?}",
                req.relation, VALID_RELATIONS
            ),
        });
    }
    if !VALID_SUBJECT_TYPES.contains(&req.subject_type.as_str()) {
        return Err(ServiceError {
            code: 400,
            message: format!(
                "Unknown subject type: {}. Valid: {:?}",
                req.subject_type, VALID_SUBJECT_TYPES
            ),
        });
    }
    if !VALID_OBJECT_TYPES.contains(&req.object_type.as_str()) {
        return Err(ServiceError {
            code: 400,
            message: format!(
                "Unknown object type: {}. Valid: {:?}",
                req.object_type, VALID_OBJECT_TYPES
            ),
        });
    }

    // Normalization (db-05): subject_type / relation / object_type are already
    // canonical — they're validated above against the lowercase VALID_* sets, so
    // case/variant divergence can't be stored. The free-form id fields are
    // whitespace-trimmed for consistency; they are NOT case-folded because
    // identifiers (group names, etc.) may be legitimately case-sensitive.
    let rel = pool
        .create_relation(
            &req.subject_type,
            req.subject_id.trim(),
            &req.relation,
            &req.object_type,
            req.object_id.trim(),
        )
        .map_err(db_err)?;
    Ok(GrantRelationResponse {
        relation: relation_to_csil(&rel),
    })
}

pub fn remove_relation(
    pool: &DbPool,
    req: RemoveRelationRequest,
) -> Result<RemoveRelationResponse, ServiceError> {
    pool.remove_relation(&req.relation_id).map_err(db_err)?;
    Ok(RemoveRelationResponse { success: true })
}

pub fn list_relations(
    pool: &DbPool,
    req: ListRelationsRequest,
) -> Result<ListRelationsResponse, ServiceError> {
    let relations = match (
        &req.subject_type,
        &req.subject_id,
        &req.object_type,
        &req.object_id,
    ) {
        (Some(st), Some(si), _, _) => pool.list_relations_for_subject(st, si).map_err(db_err)?,
        (_, _, Some(ot), Some(oi)) => pool.list_relations_for_object(ot, oi).map_err(db_err)?,
        _ => {
            // If no filters, list all for domain object as a reasonable default
            return Err(svc_err(
                "Must provide subject_type+subject_id or object_type+object_id",
            ));
        }
    };
    Ok(ListRelationsResponse {
        relations: relations.iter().map(relation_to_csil).collect(),
    })
}

pub fn check_permission_handler(
    pool: &DbPool,
    req: CheckPermissionRequest,
) -> Result<CheckPermissionResponse, ServiceError> {
    let allowed = pool
        .check_permission(
            &req.user_id,
            &req.relation,
            &req.object_type,
            &req.object_id,
        )
        .map_err(db_err)?;
    Ok(CheckPermissionResponse { allowed })
}
