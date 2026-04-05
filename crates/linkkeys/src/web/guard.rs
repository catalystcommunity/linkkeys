use linkkeys::db::models::User;
use linkkeys::db::DbPool;
use linkkeys::services::auth::ApiKeyAuthenticator;
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};

/// Rocket request guard that authenticates via bearer token (API key).
/// Extracts `Authorization: Bearer <key>`, verifies against auth_credentials.
pub struct BearerUser(pub User);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for BearerUser {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let pool = match request.rocket().state::<DbPool>() {
            Some(p) => p,
            None => return Outcome::Error((Status::InternalServerError, ())),
        };

        let auth_header = match request.headers().get_one("Authorization") {
            Some(h) => h,
            None => return Outcome::Error((Status::Unauthorized, ())),
        };

        let api_key = match auth_header.strip_prefix("Bearer ") {
            Some(k) => k,
            None => return Outcome::Error((Status::Unauthorized, ())),
        };

        let authenticator = ApiKeyAuthenticator::new(pool.clone());
        match authenticator.authenticate_key(api_key) {
            Ok(user) => Outcome::Success(BearerUser(user)),
            Err(_) => Outcome::Error((Status::Unauthorized, ())),
        }
    }
}
