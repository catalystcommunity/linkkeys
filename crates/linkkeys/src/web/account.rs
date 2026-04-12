use rocket::http::{ContentType, Status};
use rocket::State;

use linkkeys::db::DbPool;
use linkkeys::services::account;

use liblinkkeys::generated::types::ChangePasswordRequest;

use super::guard::AuthenticatedUser;

fn json_ok<T: serde::Serialize>(val: &T) -> Result<(ContentType, Vec<u8>), Status> {
    serde_json::to_vec(val)
        .map(|v| (ContentType::JSON, v))
        .map_err(|_| Status::InternalServerError)
}

fn svc_err_to_status(e: liblinkkeys::generated::services::ServiceError) -> Status {
    log::warn!("Service error: {}", e.message);
    Status::InternalServerError
}

#[rocket::post("/account/v1alpha/change-password", data = "<body>")]
pub fn account_change_password(
    pool: &State<DbPool>,
    user: AuthenticatedUser,
    body: String,
) -> Result<(ContentType, Vec<u8>), Status> {
    let req: ChangePasswordRequest =
        serde_json::from_str(&body).map_err(|_| Status::BadRequest)?;
    let resp =
        account::change_password(pool.inner(), &user.0.id, req).map_err(svc_err_to_status)?;
    json_ok(&resp)
}

#[rocket::get("/account/v1alpha/me")]
pub fn account_get_my_info(
    pool: &State<DbPool>,
    user: AuthenticatedUser,
) -> Result<(ContentType, Vec<u8>), Status> {
    let resp = account::get_my_info(pool.inner(), &user.0.id).map_err(svc_err_to_status)?;
    json_ok(&resp)
}
