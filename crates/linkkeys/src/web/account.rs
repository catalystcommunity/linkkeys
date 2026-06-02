use rocket::http::{ContentType, Status};
use rocket::State;

use crate::db::DbPool;
use crate::services::account;

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

/// Web JSON change-password request. Carries `current_password` (which the CSIL
/// `ChangePasswordRequest` does not) so the HTTP API can require re-auth without
/// a CSIL change — mirroring the HTML form. (The TCP/CSIL Account path still
/// lacks this field; adding it there needs the CSIL change — see
/// docs/csilgen-requests.)
#[derive(serde::Deserialize)]
struct ChangePasswordJsonRequest {
    current_password: String,
    new_password: String,
}

#[rocket::post("/account/v1alpha/change-password", data = "<body>")]
pub fn account_change_password(
    pool: &State<DbPool>,
    user: AuthenticatedUser,
    body: String,
) -> Result<(ContentType, Vec<u8>), Status> {
    let req: ChangePasswordJsonRequest =
        serde_json::from_str(&body).map_err(|_| Status::BadRequest)?;

    // Require current-password re-auth (svc-05): holding the API key alone must
    // not be enough to take over the account by resetting the password.
    let authenticator = crate::services::auth::PasswordAuthenticator::new(pool.inner().clone());
    if crate::services::auth::Authenticator::authenticate(
        &authenticator,
        &user.0.username,
        &req.current_password,
    )
    .is_err()
    {
        return Err(Status::Unauthorized);
    }

    let svc_req = ChangePasswordRequest {
        new_password: req.new_password,
    };
    let resp =
        account::change_password(pool.inner(), &user.0.id, svc_req).map_err(svc_err_to_status)?;
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
