use crate::db::models::User;
use crate::db::DbPool;
use crate::services::auth::ApiKeyAuthenticator;
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};

/// CSRF protection for cookie-authenticated, state-changing POSTs.
///
/// We rely on the browser-enforced `Origin`/`Referer` headers rather than a
/// synchronizer token: a cross-site attacker page cannot set `Origin` to our
/// host. The request's source authority (from `Origin`, falling back to
/// `Referer`) must equal the `Host` header. A POST with neither header is
/// rejected (a legitimate same-origin form submit always carries one).
pub struct SameOriginPost;

/// Extract the `host:port` authority from an Origin/Referer URL
/// (`scheme://authority[/path...]`).
fn url_authority(url: &str) -> Option<&str> {
    let after_scheme = url.split_once("://")?.1;
    Some(
        after_scheme
            .split(['/', '?', '#'])
            .next()
            .unwrap_or(after_scheme),
    )
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for SameOriginPost {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let host = match request.headers().get_one("Host") {
            Some(h) => h,
            None => return Outcome::Error((Status::Forbidden, ())),
        };
        let source = request
            .headers()
            .get_one("Origin")
            .or_else(|| request.headers().get_one("Referer"));
        match source.and_then(url_authority) {
            Some(authority) if authority == host => Outcome::Success(SameOriginPost),
            _ => Outcome::Error((Status::Forbidden, ())),
        }
    }
}

/// Rocket request guard for authenticated endpoints.
/// Authenticates via bearer token. Rejects inactive users.
/// Does NOT check permissions — handlers call authorization::user_has_permission().
pub struct AuthenticatedUser(pub User);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUser {
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
            Ok(user) => {
                if !user.is_active {
                    return Outcome::Error((Status::Unauthorized, ()));
                }
                Outcome::Success(AuthenticatedUser(user))
            }
            Err(_) => Outcome::Error((Status::Unauthorized, ())),
        }
    }
}
