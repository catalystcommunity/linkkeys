use rocket::http::CookieJar;
use rocket::response::content::RawHtml;
use rocket::response::Redirect;
use rocket::State;

use crate::conversions::{get_domain_name, html_escape};
use crate::db::DbPool;
use crate::services::auth::{Authenticator, PasswordAuthenticator};
use crate::services::{account, authorization};

use liblinkkeys::generated::types::ChangePasswordRequest;

pub(super) use super::session::{
    clear_session, establish_provider_session, get_session_user_id, peek_provider_session,
    touch_provider_session,
};

// -- Layout helpers --

/// Writing direction for a locale's primary subtag. Only the RTL scripts we're
/// likely to ship need naming; everything else is left-to-right. Keeps the HTML
/// correct for future community translations without waiting on one to land.
pub(super) fn text_direction(locale: &str) -> &'static str {
    let lang = locale.split(['-', '_']).next().unwrap_or(locale);
    match lang {
        "ar" | "he" | "fa" | "ur" | "ps" | "syr" | "dv" | "yi" => "rtl",
        _ => "ltr",
    }
}

/// The en-US layout. Kept for pages not yet localised; localised pages call
/// [`layout_with_locale`] so the `<html lang/dir>` reflects the reader's locale.
pub(super) fn layout(title: &str, nav_html: &str, content: &str) -> RawHtml<String> {
    layout_with_locale(title, nav_html, content, liblinkkeys::i18n::EN_US)
}

pub(super) fn layout_with_locale(
    title: &str,
    nav_html: &str,
    content: &str,
    locale: &str,
) -> RawHtml<String> {
    RawHtml(format!(
        r#"<!DOCTYPE html>
<html lang="{lang}" dir="{dir}">
<head><title>{title} — LinkKeys</title>
<style>
body {{ font-family: sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }}
nav {{ display: flex; gap: 16px; padding: 12px 0; border-bottom: 1px solid #ddd; margin-bottom: 24px; }}
nav a {{ text-decoration: none; color: #333; padding: 4px 8px; border-radius: 4px; }}
nav a:hover {{ background: #f0f0f0; }}
nav a.active {{ font-weight: bold; color: #0066cc; }}
nav .spacer {{ flex: 1; }}
table {{ border-collapse: collapse; width: 100%; margin: 16px 0; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background: #f5f5f5; }}
input, select {{ padding: 8px; margin: 4px 0; }}
input[type="text"], input[type="password"] {{ width: 100%; box-sizing: border-box; }}
button, input[type="submit"] {{ padding: 8px 16px; cursor: pointer; }}
.btn-danger {{ background: #c00; color: white; border: none; border-radius: 4px; }}
.btn-primary {{ background: #0066cc; color: white; border: none; border-radius: 4px; }}
.error {{ color: red; background: #fff0f0; padding: 12px; border-radius: 4px; margin: 12px 0; }}
.success {{ color: green; background: #f0fff0; padding: 12px; border-radius: 4px; margin: 12px 0; }}
.info {{ background: #f0f0f0; padding: 12px; border-radius: 4px; margin: 12px 0; }}
code {{ background: #eee; padding: 2px 4px; border-radius: 2px; }}
h1 {{ margin-top: 0; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 0.8em; }}
.badge-active {{ background: #dff0d8; color: #3c763d; }}
.badge-inactive {{ background: #f2dede; color: #a94442; }}
</style>
</head>
<body>
<nav>{nav}</nav>
{content}
</body>
</html>"#,
        lang = html_escape(locale),
        dir = text_direction(locale),
        title = title,
        nav = nav_html,
        content = content,
    ))
}

pub(super) fn build_nav(current: &str, is_admin: bool, is_logged_in: bool) -> String {
    let mut nav = String::new();
    if is_logged_in {
        let account_class = if current == "account" {
            " class=\"active\""
        } else {
            ""
        };
        nav.push_str(&format!(
            r#"<a href="/account"{}>Account</a>"#,
            account_class
        ));
        let identity_class = if current == "identity" {
            " class=\"active\""
        } else {
            ""
        };
        nav.push_str(&format!(
            r#"<a href="/account/identity"{}>My Identity</a>"#,
            identity_class
        ));
        if is_admin {
            let admin_class = if current == "admin" {
                " class=\"active\""
            } else {
                ""
            };
            nav.push_str(&format!(
                r#"<a href="/user-admin"{}>User Admin</a>"#,
                admin_class
            ));
            let policy_class = if current == "policy" {
                " class=\"active\""
            } else {
                ""
            };
            nav.push_str(&format!(
                r#"<a href="/policy-admin"{}>Policy Admin</a>"#,
                policy_class
            ));
        }
        nav.push_str(r#"<span class="spacer"></span>"#);
        nav.push_str(r#"<form method="POST" action="/account/logout" style="margin:0"><button type="submit" style="background:none;border:none;cursor:pointer;color:#666;">Logout</button></form>"#);
    } else {
        nav.push_str(r#"<a href="/account/login">Login</a>"#);
    }
    nav
}

/// Check if the current session user has admin (manage_users) permission on the domain.
pub(super) fn is_user_admin(pool: &DbPool, user_id: &str) -> bool {
    let domain = get_domain_name();
    authorization::user_has_permission(pool, user_id, "manage_users", "domain", &domain)
}

pub(super) fn flash_html(msg: Option<&str>, error: Option<&str>) -> String {
    let mut html = String::new();
    if let Some(m) = msg {
        html.push_str(&format!(r#"<div class="success">{}</div>"#, html_escape(m)));
    }
    if let Some(e) = error {
        html.push_str(&format!(r#"<div class="error">{}</div>"#, html_escape(e)));
    }
    html
}

// -- Login --

#[rocket::get("/account/login?<error>")]
pub fn login_page(error: Option<&str>) -> RawHtml<String> {
    let nav = build_nav("account", false, false);
    let error_html = error
        .map(|e| format!(r#"<div class="error">{}</div>"#, html_escape(e)))
        .unwrap_or_default();
    let content = format!(
        r#"<h1>Login</h1>
<p>Domain: <strong>{domain}</strong></p>
{error}
<form method="POST" action="/account/login">
  <label>Username</label>
  <input type="text" name="username" autocomplete="username" autofocus />
  <label>Password</label>
  <input type="password" name="password" autocomplete="current-password" />
  <br/><br/>
  <button type="submit" class="btn-primary">Log In</button>
</form>"#,
        domain = html_escape(&get_domain_name()),
        error = error_html,
    );
    layout("Login", &nav, &content)
}

#[derive(rocket::FromForm)]
pub struct LoginForm {
    username: String,
    password: String,
}

#[rocket::post("/account/login", data = "<form>")]
pub fn login_submit(
    _csrf: super::guard::SameOriginPost,
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    source: super::guard::RequestSource,
    form: rocket::form::Form<LoginForm>,
) -> Result<Redirect, Box<Redirect>> {
    // SEC-05: throttle online brute force, keyed by username.
    if !crate::services::ratelimit::LOGIN_SOURCE.check(&source.0)
        || !crate::services::ratelimit::LOGIN.check(&form.username.trim().to_lowercase())
    {
        return Err(Box::new(Redirect::found(
            "/account/login?error=Too+many+attempts.+Please+wait+and+try+again.",
        )));
    }

    let authenticator = PasswordAuthenticator::new(pool.inner().clone());
    match authenticator.authenticate_with_evidence(&form.username, &form.password) {
        Ok(authentication) => {
            let user = &authentication.user;
            let Some(credential_id) = authentication.credential_id.as_deref() else {
                return Err(Box::new(Redirect::found(
                    "/account/login?error=Invalid+username+or+password",
                )));
            };
            if establish_provider_session(
                cookies,
                pool.inner(),
                &user.id,
                &authentication.evidence,
                credential_id,
            )
            .is_none()
            {
                return Err(Box::new(Redirect::found(
                    "/account/login?error=Could+not+create+session",
                )));
            }
            Ok(Redirect::found("/account"))
        }
        Err(_) => Err(Box::new(Redirect::found(
            "/account/login?error=Invalid+username+or+password",
        ))),
    }
}

// -- Logout --

#[rocket::post("/account/logout")]
pub fn logout(
    _csrf: super::guard::SameOriginPost,
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
) -> Redirect {
    clear_session(cookies, pool.inner());
    Redirect::found("/account/login")
}

// -- Account Dashboard --

#[rocket::get("/account?<msg>&<error>")]
pub fn account_dashboard(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    locale: super::guard::Locale,
    msg: Option<&str>,
    error: Option<&str>,
) -> Result<RawHtml<String>, Box<Redirect>> {
    let user_id = match get_session_user_id(cookies, pool.inner()) {
        Some(id) => id,
        None => return Err(Box::new(Redirect::found("/account/login"))),
    };
    let loc = locale.0.as_str();
    use liblinkkeys::i18n::t;

    let info = match account::get_my_info(pool.inner(), &user_id) {
        Ok(i) => i,
        Err(_) => {
            clear_session(cookies, pool.inner());
            return Err(Box::new(Redirect::found(
                "/account/login?error=Session+expired",
            )));
        }
    };

    let admin = is_user_admin(pool.inner(), &user_id);
    let nav = build_nav("account", admin, true);
    let flash = flash_html(msg, error);

    // Show each claim by its human, locale-resolved name — never the raw
    // machine claim_type. The internal "relations" (authz tuples) are omitted
    // from this end-user view entirely; they carry no user-facing meaning.
    let claims_html = if info.claims.is_empty() {
        format!(
            "<h2>{}</h2><p>{}</p>",
            html_escape(t(loc, "account.my_claims")),
            html_escape(t(loc, "account.no_claims")),
        )
    } else {
        let mut h = format!(
            r#"<h2>{title}</h2>
<table><tr><th>{type_col}</th><th>{value_col}</th><th>{expires_col}</th></tr>"#,
            title = html_escape(t(loc, "account.my_claims")),
            type_col = html_escape(t(loc, "account.type_col")),
            value_col = html_escape(t(loc, "account.value_col")),
            expires_col = html_escape(t(loc, "account.expires_col")),
        );
        for claim in &info.claims {
            let value_str = String::from_utf8(claim.claim_value.clone())
                .unwrap_or_else(|_| format!("{:?}", claim.claim_value));
            let label = pool
                .resolved_label(&claim.claim_type, loc)
                .map(|(l, _)| l)
                .unwrap_or_else(|_| claim.claim_type.clone());
            h.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&label),
                html_escape(&value_str),
                html_escape(
                    claim
                        .expires_at
                        .as_deref()
                        .unwrap_or_else(|| t(loc, "account.never"))
                ),
            ));
        }
        h.push_str("</table>");
        h
    };

    let content = format!(
        r#"{flash}
<h1>{title}</h1>
<div class="info">
  <p><strong>{username_label}:</strong> {username}</p>
  <p><strong>{display_name_label}:</strong> {display_name}</p>
  <p><strong>{user_id_label}:</strong> <code>{user_id}</code></p>
  <p><strong>{status_label}:</strong> {status}</p>
</div>
<p><a href="/account/change-password">{change_password}</a></p>
{claims}"#,
        flash = flash,
        title = html_escape(t(loc, "account.title")),
        username_label = html_escape(t(loc, "account.username_label")),
        display_name_label = html_escape(t(loc, "account.display_name_label")),
        user_id_label = html_escape(t(loc, "account.user_id_label")),
        status_label = html_escape(t(loc, "account.status_label")),
        change_password = html_escape(t(loc, "account.change_password_link")),
        username = html_escape(&info.user.username),
        display_name = html_escape(&info.user.display_name),
        user_id = html_escape(&info.user.id),
        status = if info.user.is_active {
            r#"<span class="badge badge-active">Active</span>"#
        } else {
            r#"<span class="badge badge-inactive">Inactive</span>"#
        },
        claims = claims_html,
    );

    Ok(layout_with_locale("Account", &nav, &content, loc))
}

// -- Change Password --

#[rocket::get("/account/change-password?<msg>&<error>")]
pub fn change_password_page(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    msg: Option<&str>,
    error: Option<&str>,
) -> Result<RawHtml<String>, Box<Redirect>> {
    let user_id = match get_session_user_id(cookies, pool.inner()) {
        Some(id) => id,
        None => return Err(Box::new(Redirect::found("/account/login"))),
    };
    let user = match pool.find_user_by_id(&user_id) {
        Ok(user) => user,
        Err(_) => return Err(Box::new(Redirect::found("/account/login"))),
    };
    let admin = is_user_admin(pool.inner(), &user_id);
    let nav = build_nav("account", admin, true);
    let flash = flash_html(msg, error);

    let content = format!(
        r#"{flash}
<h1>Change Password</h1>
<form method="POST" action="/account/change-password">
  <input type="hidden" name="username" value="{username}" autocomplete="username" />
  <label>Current Password</label>
  <input type="password" name="current_password" autocomplete="current-password" required />
  <label>New Password</label>
  <input type="password" name="new_password" autocomplete="new-password" required minlength="8" />
  <label>Confirm Password</label>
  <input type="password" name="confirm_password" autocomplete="new-password" required minlength="8" />
  <br/><br/>
  <button type="submit" class="btn-primary">Change Password</button>
</form>
<p><a href="/account">Back to Account</a></p>"#,
        flash = flash,
        username = html_escape(&user.username),
    );

    Ok(layout("Change Password", &nav, &content))
}

#[derive(rocket::FromForm)]
pub struct ChangePasswordForm {
    #[field(name = "username")]
    _username: Option<String>,
    current_password: String,
    new_password: String,
    confirm_password: String,
}

#[rocket::post("/account/change-password", data = "<form>")]
pub fn change_password_submit(
    _csrf: super::guard::SameOriginPost,
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    form: rocket::form::Form<ChangePasswordForm>,
) -> Redirect {
    let user_id = match get_session_user_id(cookies, pool.inner()) {
        Some(id) => id,
        None => return Redirect::found("/account/login"),
    };

    if form.new_password != form.confirm_password {
        return Redirect::found("/account/change-password?error=Passwords+do+not+match");
    }

    let req = ChangePasswordRequest {
        current_password: form.current_password.clone(),
        new_password: form.new_password.clone(),
    };

    match account::change_password(pool.inner(), &user_id, req) {
        Ok(_) => Redirect::found("/account?msg=Password+changed+successfully"),
        Err(e) => Redirect::found(format!(
            "/account/change-password?error={}",
            urlencoding::encode(&e.message)
        )),
    }
}
