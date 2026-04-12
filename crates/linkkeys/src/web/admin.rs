use rocket::http::{ContentType, Status};
use rocket::State;

use linkkeys::conversions::get_domain_name;
use linkkeys::db::DbPool;
use linkkeys::services::admin;
use linkkeys::services::authorization;

use liblinkkeys::generated::types::{
    CheckPermissionRequest, CreateUserRequest, DeactivateUserRequest, GrantRelationRequest,
    ListRelationsRequest, ListUsersRequest, RemoveClaimRequest, RemoveCredentialRequest,
    RemoveRelationRequest, ResetPasswordRequest, SetClaimRequest, UpdateUserRequest,
};

use super::guard::AuthenticatedUser;

fn require_permission(
    pool: &DbPool,
    user_id: &str,
    relation: &str,
) -> Result<(), Status> {
    let domain = get_domain_name();
    if !authorization::user_has_permission(pool, user_id, relation, "domain", &domain) {
        return Err(Status::Forbidden);
    }
    Ok(())
}

fn json_ok<T: serde::Serialize>(val: &T) -> Result<(ContentType, Vec<u8>), Status> {
    serde_json::to_vec(val)
        .map(|v| (ContentType::JSON, v))
        .map_err(|_| Status::InternalServerError)
}

fn svc_err_to_status(e: liblinkkeys::generated::services::ServiceError) -> Status {
    log::warn!("Service error: {}", e.message);
    Status::InternalServerError
}

#[rocket::get("/admin/v1alpha/users")]
pub fn admin_list_users(
    pool: &State<DbPool>,
    user: AuthenticatedUser,
) -> Result<(ContentType, Vec<u8>), Status> {
    require_permission(pool.inner(), &user.0.id, authorization::RELATION_MANAGE_USERS)?;
    let req = ListUsersRequest {
        offset: None,
        limit: None,
    };
    let resp = admin::list_users(pool.inner(), req).map_err(svc_err_to_status)?;
    json_ok(&resp)
}

#[rocket::get("/admin/v1alpha/users/<user_id>")]
pub fn admin_get_user(
    pool: &State<DbPool>,
    user: AuthenticatedUser,
    user_id: &str,
) -> Result<(ContentType, Vec<u8>), Status> {
    require_permission(pool.inner(), &user.0.id, authorization::RELATION_MANAGE_USERS)?;
    let req = liblinkkeys::generated::types::GetUserRequest {
        user_id: user_id.to_string(),
    };
    let resp = admin::get_user(pool.inner(), req).map_err(svc_err_to_status)?;
    json_ok(&resp)
}

#[rocket::post("/admin/v1alpha/users", data = "<body>")]
pub fn admin_create_user(
    pool: &State<DbPool>,
    user: AuthenticatedUser,
    body: String,
) -> Result<(ContentType, Vec<u8>), Status> {
    require_permission(pool.inner(), &user.0.id, authorization::RELATION_MANAGE_USERS)?;
    let req: CreateUserRequest = serde_json::from_str(&body).map_err(|_| Status::BadRequest)?;
    let resp = admin::create_user(pool.inner(), req).map_err(svc_err_to_status)?;
    json_ok(&resp)
}

#[rocket::post("/admin/v1alpha/users/<user_id>/update", data = "<body>")]
pub fn admin_update_user(
    pool: &State<DbPool>,
    user: AuthenticatedUser,
    user_id: &str,
    body: String,
) -> Result<(ContentType, Vec<u8>), Status> {
    require_permission(pool.inner(), &user.0.id, authorization::RELATION_MANAGE_USERS)?;
    let mut req: UpdateUserRequest =
        serde_json::from_str(&body).map_err(|_| Status::BadRequest)?;
    req.user_id = user_id.to_string();
    let resp = admin::update_user(pool.inner(), req).map_err(svc_err_to_status)?;
    json_ok(&resp)
}

#[rocket::post("/admin/v1alpha/users/<user_id>/deactivate")]
pub fn admin_deactivate_user(
    pool: &State<DbPool>,
    user: AuthenticatedUser,
    user_id: &str,
) -> Result<(ContentType, Vec<u8>), Status> {
    require_permission(pool.inner(), &user.0.id, authorization::RELATION_MANAGE_USERS)?;
    if user_id == user.0.id {
        return Err(Status::BadRequest); // Cannot deactivate yourself
    }
    let req = DeactivateUserRequest {
        user_id: user_id.to_string(),
    };
    let resp = admin::deactivate_user(pool.inner(), req).map_err(svc_err_to_status)?;
    json_ok(&resp)
}

#[rocket::post("/admin/v1alpha/users/<user_id>/reset-password", data = "<body>")]
pub fn admin_reset_password(
    pool: &State<DbPool>,
    user: AuthenticatedUser,
    user_id: &str,
    body: String,
) -> Result<(ContentType, Vec<u8>), Status> {
    require_permission(pool.inner(), &user.0.id, authorization::RELATION_MANAGE_USERS)?;
    let mut req: ResetPasswordRequest =
        serde_json::from_str(&body).map_err(|_| Status::BadRequest)?;
    req.user_id = user_id.to_string();
    let resp = admin::reset_password(pool.inner(), req).map_err(svc_err_to_status)?;
    json_ok(&resp)
}

#[rocket::post("/admin/v1alpha/credentials/<id>/remove")]
pub fn admin_remove_credential(
    pool: &State<DbPool>,
    user: AuthenticatedUser,
    id: &str,
) -> Result<(ContentType, Vec<u8>), Status> {
    require_permission(pool.inner(), &user.0.id, authorization::RELATION_MANAGE_USERS)?;
    let req = RemoveCredentialRequest {
        credential_id: id.to_string(),
    };
    let resp = admin::remove_credential(pool.inner(), req).map_err(svc_err_to_status)?;
    json_ok(&resp)
}

#[rocket::post("/admin/v1alpha/users/<user_id>/claims", data = "<body>")]
pub fn admin_set_claim(
    pool: &State<DbPool>,
    user: AuthenticatedUser,
    user_id: &str,
    body: String,
) -> Result<(ContentType, Vec<u8>), Status> {
    require_permission(pool.inner(), &user.0.id, authorization::RELATION_MANAGE_CLAIMS)?;
    let mut req: SetClaimRequest =
        serde_json::from_str(&body).map_err(|_| Status::BadRequest)?;
    req.user_id = user_id.to_string();
    let resp = admin::set_claim(pool.inner(), req).map_err(svc_err_to_status)?;
    json_ok(&resp)
}

#[rocket::post("/admin/v1alpha/claims/<claim_id>/remove")]
pub fn admin_remove_claim(
    pool: &State<DbPool>,
    user: AuthenticatedUser,
    claim_id: &str,
) -> Result<(ContentType, Vec<u8>), Status> {
    require_permission(pool.inner(), &user.0.id, authorization::RELATION_MANAGE_CLAIMS)?;
    let req = RemoveClaimRequest {
        claim_id: claim_id.to_string(),
    };
    let resp = admin::remove_claim(pool.inner(), req).map_err(svc_err_to_status)?;
    json_ok(&resp)
}

#[rocket::post("/admin/v1alpha/relations", data = "<body>")]
pub fn admin_grant_relation(
    pool: &State<DbPool>,
    user: AuthenticatedUser,
    body: String,
) -> Result<(ContentType, Vec<u8>), Status> {
    require_permission(pool.inner(), &user.0.id, authorization::RELATION_ADMIN)?;
    let req: GrantRelationRequest =
        serde_json::from_str(&body).map_err(|_| Status::BadRequest)?;
    let resp = admin::grant_relation(pool.inner(), req).map_err(svc_err_to_status)?;
    json_ok(&resp)
}

#[rocket::post("/admin/v1alpha/relations/<id>/remove")]
pub fn admin_remove_relation(
    pool: &State<DbPool>,
    user: AuthenticatedUser,
    id: &str,
) -> Result<(ContentType, Vec<u8>), Status> {
    require_permission(pool.inner(), &user.0.id, authorization::RELATION_ADMIN)?;
    let req = RemoveRelationRequest {
        relation_id: id.to_string(),
    };
    let resp = admin::remove_relation(pool.inner(), req).map_err(svc_err_to_status)?;
    json_ok(&resp)
}

#[rocket::get("/admin/v1alpha/relations?<subject_type>&<subject_id>&<object_type>&<object_id>")]
pub fn admin_list_relations(
    pool: &State<DbPool>,
    user: AuthenticatedUser,
    subject_type: Option<&str>,
    subject_id: Option<&str>,
    object_type: Option<&str>,
    object_id: Option<&str>,
) -> Result<(ContentType, Vec<u8>), Status> {
    require_permission(pool.inner(), &user.0.id, authorization::RELATION_ADMIN)?;
    let req = ListRelationsRequest {
        subject_type: subject_type.map(String::from),
        subject_id: subject_id.map(String::from),
        object_type: object_type.map(String::from),
        object_id: object_id.map(String::from),
    };
    let resp = admin::list_relations(pool.inner(), req).map_err(svc_err_to_status)?;
    json_ok(&resp)
}

#[rocket::post("/admin/v1alpha/check-permission", data = "<body>")]
pub fn admin_check_permission(
    pool: &State<DbPool>,
    user: AuthenticatedUser,
    body: String,
) -> Result<(ContentType, Vec<u8>), Status> {
    require_permission(pool.inner(), &user.0.id, authorization::RELATION_ADMIN)?;
    let req: CheckPermissionRequest =
        serde_json::from_str(&body).map_err(|_| Status::BadRequest)?;
    let resp = admin::check_permission_handler(pool.inner(), req).map_err(svc_err_to_status)?;
    json_ok(&resp)
}
