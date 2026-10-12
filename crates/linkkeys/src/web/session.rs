//! Browser-cookie integration for the server-side session store.

use rocket::http::{Cookie, CookieJar, SameSite};

use crate::services::browser_session;

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
