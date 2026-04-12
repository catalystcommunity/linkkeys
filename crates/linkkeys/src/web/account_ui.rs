use rocket::http::{Cookie, CookieJar, SameSite};
use rocket::response::content::RawHtml;
use rocket::response::Redirect;
use rocket::State;

use linkkeys::conversions::{get_domain_name, html_escape};
use linkkeys::db::DbPool;
use linkkeys::services::auth::{Authenticator, PasswordAuthenticator};
use linkkeys::services::{account, authorization};

use liblinkkeys::generated::types::ChangePasswordRequest;

// -- Session helpers --

pub(super) fn get_session_user_id(cookies: &CookieJar<'_>) -> Option<String> {
    cookies.get_private("user_id").map(|c| c.value().to_string())
}

fn set_session(cookies: &CookieJar<'_>, user_id: &str) {
    let mut cookie = Cookie::new("user_id", user_id.to_string());
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_secure(true);
    cookies.add_private(cookie);
}

fn clear_session(cookies: &CookieJar<'_>) {
    cookies.remove_private("user_id");
}

// -- Layout helpers --

pub(super) fn layout(title: &str, nav_html: &str, content: &str) -> RawHtml<String> {
    RawHtml(format!(
        r#"<!DOCTYPE html>
<html>
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

fn flash_html(msg: Option<&str>, error: Option<&str>) -> String {
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
  <input type="text" name="username" autofocus />
  <label>Password</label>
  <input type="password" name="password" />
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
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    form: rocket::form::Form<LoginForm>,
) -> Result<Redirect, Redirect> {
    let authenticator = PasswordAuthenticator::new(pool.inner().clone());
    match authenticator.authenticate(&form.username, &form.password) {
        Ok(user) => {
            set_session(cookies, &user.id);
            Ok(Redirect::found("/account"))
        }
        Err(_) => Err(Redirect::found(
            "/account/login?error=Invalid+username+or+password",
        )),
    }
}

// -- Logout --

#[rocket::post("/account/logout")]
pub fn logout(cookies: &CookieJar<'_>) -> Redirect {
    clear_session(cookies);
    Redirect::found("/account/login")
}

// -- Account Dashboard --

#[rocket::get("/account?<msg>&<error>")]
pub fn account_dashboard(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    msg: Option<&str>,
    error: Option<&str>,
) -> Result<RawHtml<String>, Redirect> {
    let user_id = match get_session_user_id(cookies) {
        Some(id) => id,
        None => return Err(Redirect::found("/account/login")),
    };

    let info = match account::get_my_info(pool.inner(), &user_id) {
        Ok(i) => i,
        Err(_) => {
            clear_session(cookies);
            return Err(Redirect::found("/account/login?error=Session+expired"));
        }
    };

    let admin = is_user_admin(pool.inner(), &user_id);
    let nav = build_nav("account", admin, true);
    let flash = flash_html(msg, error);

    let mut claims_html = String::from(
        r#"<h2>My Claims</h2>
<table><tr><th>Type</th><th>Value</th><th>Expires</th></tr>"#,
    );
    for claim in &info.claims {
        let value_str = String::from_utf8(claim.claim_value.clone())
            .unwrap_or_else(|_| format!("{:?}", claim.claim_value));
        claims_html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&claim.claim_type),
            html_escape(&value_str),
            html_escape(claim.expires_at.as_deref().unwrap_or("never")),
        ));
    }
    claims_html.push_str("</table>");
    if info.claims.is_empty() {
        claims_html = String::from("<h2>My Claims</h2><p>No claims.</p>");
    }

    let mut relations_html = String::from(
        r#"<h2>My Relations</h2>
<table><tr><th>Relation</th><th>Object Type</th><th>Object ID</th></tr>"#,
    );
    for rel in &info.relations {
        relations_html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&rel.relation),
            html_escape(&rel.object_type),
            html_escape(&rel.object_id),
        ));
    }
    relations_html.push_str("</table>");
    if info.relations.is_empty() {
        relations_html = String::from("<h2>My Relations</h2><p>No relations.</p>");
    }

    let content = format!(
        r#"{flash}
<h1>Account Dashboard</h1>
<div class="info">
  <p><strong>Username:</strong> {username}</p>
  <p><strong>Display Name:</strong> {display_name}</p>
  <p><strong>User ID:</strong> <code>{user_id}</code></p>
  <p><strong>Status:</strong> {status}</p>
</div>
<p><a href="/account/change-password">Change Password</a></p>
{claims}
{relations}"#,
        flash = flash,
        username = html_escape(&info.user.username),
        display_name = html_escape(&info.user.display_name),
        user_id = html_escape(&info.user.id),
        status = if info.user.is_active {
            r#"<span class="badge badge-active">Active</span>"#
        } else {
            r#"<span class="badge badge-inactive">Inactive</span>"#
        },
        claims = claims_html,
        relations = relations_html,
    );

    Ok(layout("Account", &nav, &content))
}

// -- Change Password --

#[rocket::get("/account/change-password?<msg>&<error>")]
pub fn change_password_page(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    msg: Option<&str>,
    error: Option<&str>,
) -> Result<RawHtml<String>, Redirect> {
    let user_id = match get_session_user_id(cookies) {
        Some(id) => id,
        None => return Err(Redirect::found("/account/login")),
    };
    let admin = is_user_admin(pool.inner(), &user_id);
    let nav = build_nav("account", admin, true);
    let flash = flash_html(msg, error);

    let content = format!(
        r#"{flash}
<h1>Change Password</h1>
<form method="POST" action="/account/change-password">
  <label>New Password</label>
  <input type="password" name="new_password" required minlength="8" />
  <label>Confirm Password</label>
  <input type="password" name="confirm_password" required minlength="8" />
  <br/><br/>
  <button type="submit" class="btn-primary">Change Password</button>
</form>
<p><a href="/account">Back to Account</a></p>"#,
        flash = flash,
    );

    Ok(layout("Change Password", &nav, &content))
}

#[derive(rocket::FromForm)]
pub struct ChangePasswordForm {
    new_password: String,
    confirm_password: String,
}

#[rocket::post("/account/change-password", data = "<form>")]
pub fn change_password_submit(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    form: rocket::form::Form<ChangePasswordForm>,
) -> Redirect {
    let user_id = match get_session_user_id(cookies) {
        Some(id) => id,
        None => return Redirect::found("/account/login"),
    };

    if form.new_password != form.confirm_password {
        return Redirect::found("/account/change-password?error=Passwords+do+not+match");
    }

    let req = ChangePasswordRequest {
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
