use liblinkkeys::generated::services::ServiceError;
use liblinkkeys::generated::types::{
    AdminUser, ChangePasswordRequest, ChangePasswordResponse, Claim, GetMyInfoResponse,
};

use crate::db::DbPool;
use crate::services::{auth, password};

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
