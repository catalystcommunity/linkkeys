//! Browser-cookie integration for the server-side session store.

use rocket::http::{Cookie, CookieJar, SameSite};

use crate::db::DbPool;
use crate::services::auth::AuthenticationEvidence;
use crate::services::browser_session;

#[derive(Debug, Clone)]
pub(super) struct ProviderSession {
    pub user_id: String,
    pub authenticated_at: i64,
    pub method_types: std::collections::BTreeSet<String>,
}

impl ProviderSession {
    pub(super) fn evidence(&self) -> AuthenticationEvidence {
        AuthenticationEvidence {
            method_types: self.method_types.clone(),
            authenticated_at: chrono::DateTime::from_timestamp(self.authenticated_at, 0)
                .unwrap_or_else(chrono::Utc::now),
        }
    }
}

fn cookie(value: String) -> Cookie<'static> {
    let mut cookie = Cookie::new(browser_session::COOKIE_NAME, value);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_secure(true);
    cookie
}

pub(super) fn add_session_cookie(cookies: &CookieJar<'_>, token: String) {
    cookies.add(cookie(token));
}

pub(super) fn remove_session_cookie(cookies: &CookieJar<'_>) {
    cookies.remove(cookie(String::new()));
}

fn parse_time(value: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.timestamp())
}

fn read_session(cookies: &CookieJar<'_>, pool: &DbPool, refresh: bool) -> Option<ProviderSession> {
    let token = cookies
        .get(browser_session::COOKIE_NAME)?
        .value()
        .to_string();
    let stored = match browser_session::get(pool, &token, refresh) {
        Ok(Some(value)) => value,
        _ => {
            cookies.remove(cookie(String::new()));
            return None;
        }
    };
    Some(ProviderSession {
        user_id: stored.user_id,
        authenticated_at: parse_time(&stored.authenticated_at)?,
        method_types: stored
            .authentication_methods
            .split(',')
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect(),
    })
}

pub(super) fn get_session_user_id(cookies: &CookieJar<'_>, pool: &DbPool) -> Option<String> {
    read_session(cookies, pool, true).map(|value| value.user_id)
}

pub(super) fn establish_provider_session(
    cookies: &CookieJar<'_>,
    pool: &DbPool,
    user_id: &str,
    evidence: &AuthenticationEvidence,
    credential_id: &str,
) -> Option<crate::db::models::BrowserSession> {
    match browser_session::create_after_password(pool, user_id, credential_id, evidence) {
        Ok((token, session)) => {
            add_session_cookie(cookies, token);
            Some(session)
        }
        Err(error) => {
            log::error!("Could not create browser session: {}", error.message);
            None
        }
    }
}

pub(super) fn peek_provider_session(
    cookies: &CookieJar<'_>,
    pool: &DbPool,
) -> Option<ProviderSession> {
    read_session(cookies, pool, false)
}

pub(super) fn touch_provider_session(cookies: &CookieJar<'_>, pool: &DbPool) {
    let _ = read_session(cookies, pool, true);
}

pub(super) fn clear_session(cookies: &CookieJar<'_>, pool: &DbPool) {
    if let Some(value) = cookies.get(browser_session::COOKIE_NAME) {
        if let Err(error) = browser_session::revoke(pool, value.value()) {
            log::warn!("Could not revoke browser session: {}", error.message);
        }
    }
    remove_session_cookie(cookies);
}
