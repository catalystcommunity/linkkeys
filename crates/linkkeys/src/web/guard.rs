use crate::db::models::User;
use crate::db::DbPool;
use crate::services::auth::ApiKeyAuthenticator;
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use std::net::IpAddr;

pub struct RequestSource(pub String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RequestSource {
    type Error = std::convert::Infallible;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let direct = request.remote().map(|value| value.ip());
        let key = direct
            .map(|direct| {
                request_source_ip(
                    direct,
                    request.headers().get_one("X-Forwarded-For"),
                    &std::env::var("TRUSTED_PROXY_CIDRS").unwrap_or_default(),
                )
                .to_string()
            })
            .unwrap_or_else(|| "unknown-http-peer".to_string());
        Outcome::Success(RequestSource(key))
    }
}

fn request_source_ip(direct: IpAddr, forwarded_for: Option<&str>, trusted_cidrs: &str) -> IpAddr {
    let trusted = trusted_cidrs
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter_map(|value| value.parse::<ipnet::IpNet>().ok())
        .collect::<Vec<_>>();
    let is_trusted = |address: &IpAddr| trusted.iter().any(|network| network.contains(address));
    if !is_trusted(&direct) {
        return direct;
    }
    forwarded_for
        .into_iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter_map(|value| value.parse::<IpAddr>().ok())
        .rev()
        .find(|address| !is_trusted(address))
        .unwrap_or(direct)
}

/// CSRF protection for cookie-authenticated, state-changing POSTs.
///
/// We rely on the browser-enforced `Origin`/`Referer` headers rather than a
/// synchronizer token: a cross-site attacker page cannot set `Origin` to our
/// host. The request's source authority (from `Origin`, falling back to
/// `Referer`) must equal the `Host` header. A POST with neither header is
/// rejected (a legitimate same-origin form submit always carries one).
pub struct SameOriginPost;

fn same_public_origin(source: &str, host: &str, configured_origin: Option<&str>) -> bool {
    let source = match reqwest::Url::parse(source) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let expected_text = configured_origin
        .map(str::to_string)
        .unwrap_or_else(|| format!("https://{host}"));
    let expected = match reqwest::Url::parse(&expected_text) {
        Ok(value) => value,
        Err(_) => return false,
    };
    source.scheme() == "https"
        && expected.scheme() == "https"
        && source.host_str() == expected.host_str()
        && source.port_or_known_default() == expected.port_or_known_default()
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
        match source {
            Some(value)
                if same_public_origin(
                    value,
                    host,
                    std::env::var("PUBLIC_ORIGIN").ok().as_deref(),
                ) =>
            {
                Outcome::Success(SameOriginPost)
            }
            _ => Outcome::Error((Status::Forbidden, ())),
        }
    }
}

/// The UI locale for a request, negotiated once and threaded into rendering.
///
/// Precedence: an explicit `?lang=` query override, then a `lang` cookie (a
/// remembered choice), then the browser's `Accept-Language` header. Anything
/// unrecognised falls back to `en-US` inside `liblinkkeys::i18n::negotiate`, so
/// this guard is infallible — every request resolves to a shipped locale.
pub struct Locale(pub String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Locale {
    type Error = std::convert::Infallible;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let override_locale = request
            .query_value::<String>("lang")
            .and_then(Result::ok)
            .filter(|s| !s.trim().is_empty())
            .or_else(|| request.cookies().get("lang").map(|c| c.value().to_string()));
        let accept = request
            .headers()
            .get_one("Accept-Language")
            .unwrap_or_default();
        let locale = liblinkkeys::i18n::negotiate(accept, override_locale.as_deref());
        Outcome::Success(Locale(locale))
    }
}

/// Rocket request guard for authenticated endpoints.
/// Authenticates via bearer token. Rejects inactive users.
/// Does NOT check permissions — handlers call authorization::user_has_permission().
pub struct AuthenticatedUser(pub User, pub String);

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
        let source = match RequestSource::from_request(request).await {
            Outcome::Success(value) => value,
            _ => return Outcome::Error((Status::InternalServerError, ())),
        };
        if !crate::services::ratelimit::API_KEY_SOURCE.check(&source.0) {
            return Outcome::Error((Status::TooManyRequests, ()));
        }

        let authenticator = ApiKeyAuthenticator::new(pool.clone());
        match authenticator.authenticate_key_with_credential(api_key) {
            Ok(authentication) => {
                if !authentication.user.is_active {
                    return Outcome::Error((Status::Unauthorized, ()));
                }
                Outcome::Success(AuthenticatedUser(
                    authentication.user,
                    authentication.credential_id,
                ))
            }
            Err(_) => Outcome::Error((Status::Unauthorized, ())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{request_source_ip, same_public_origin};

    #[test]
    fn forwarded_source_requires_a_trusted_direct_peer() {
        let direct = "192.0.2.10".parse().unwrap();
        assert_eq!(
            request_source_ip(direct, Some("198.51.100.20"), "10.0.0.0/8"),
            direct
        );
        assert_eq!(
            request_source_ip(
                "10.0.0.4".parse().unwrap(),
                Some("198.51.100.20, 10.0.0.3"),
                "10.0.0.0/8"
            ),
            "198.51.100.20".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[test]
    fn csrf_origin_includes_scheme_host_and_port() {
        assert!(same_public_origin(
            "https://id.example.test/form",
            "internal:8000",
            Some("https://id.example.test")
        ));
        assert!(!same_public_origin(
            "http://id.example.test/form",
            "id.example.test",
            None
        ));
        assert!(!same_public_origin(
            "https://id.example.test:444/form",
            "id.example.test",
            None
        ));
    }
}
