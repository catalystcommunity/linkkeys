use rocket::http::{CookieJar, Status};
use rocket::response::content::RawHtml;
use rocket::response::Redirect;
use rocket::State;

use linkkeys::conversions::{get_domain_name, html_escape};
use linkkeys::db::DbPool;
use linkkeys::services::{admin, authorization};

use liblinkkeys::generated::types::{
    CreateUserRequest, DeactivateUserRequest, GetUserRequest, GrantRelationRequest,
    ListRelationsRequest, ListUsersRequest, RemoveClaimRequest, RemoveRelationRequest,
    ResetPasswordRequest, SetClaimRequest, UpdateUserRequest,
};

use super::account_ui::{build_nav, get_session_user_id, layout};

// -- Permission helper --

fn require_admin_session(
    pool: &DbPool,
    cookies: &CookieJar<'_>,
) -> Result<String, Result<RawHtml<String>, Status>> {
    let user_id = get_session_user_id(cookies)
        .ok_or(Err(Status::Unauthorized))?;

    let domain = get_domain_name();
    if !authorization::user_has_permission(pool, &user_id, "manage_users", "domain", &domain) {
        return Err(Err(Status::Forbidden));
    }

    Ok(user_id)
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

// -- User list --

#[rocket::get("/user-admin?<msg>&<error>")]
pub fn admin_ui_user_list(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    msg: Option<&str>,
    error: Option<&str>,
) -> Result<RawHtml<String>, Status> {
    let user_id = require_admin_session(pool.inner(), cookies).map_err(|e| e.unwrap_err())?;
    let nav = build_nav("admin", true, true);
    let flash = flash_html(msg, error);

    let req = ListUsersRequest {
        offset: None,
        limit: None,
    };
    let resp = admin::list_users(pool.inner(), req).map_err(|_| Status::InternalServerError)?;

    let mut rows = String::new();
    for u in &resp.users {
        let status = if u.is_active {
            r#"<span class="badge badge-active">Active</span>"#
        } else {
            r#"<span class="badge badge-inactive">Inactive</span>"#
        };
        rows.push_str(&format!(
            r#"<tr><td><a href="/user-admin/users/{id}">{id_short}</a></td><td>{username}</td><td>{display_name}</td><td>{status}</td></tr>"#,
            id = html_escape(&u.id),
            id_short = html_escape(&u.id[..8.min(u.id.len())]),
            username = html_escape(&u.username),
            display_name = html_escape(&u.display_name),
            status = status,
        ));
    }

    let content = format!(
        r#"{flash}
<h1>User Administration</h1>
<p><a href="/user-admin/users/create" class="btn-primary" style="text-decoration:none;padding:8px 16px;border-radius:4px;">Create User</a></p>
<table>
<tr><th>ID</th><th>Username</th><th>Display Name</th><th>Status</th></tr>
{rows}
</table>"#,
        flash = flash,
        rows = rows,
    );

    let _ = user_id;
    Ok(layout("User Admin", &nav, &content))
}

// -- Create user form --

#[rocket::get("/user-admin/users/create?<error>")]
pub fn admin_ui_create_user_page(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    error: Option<&str>,
) -> Result<RawHtml<String>, Status> {
    let _user_id = require_admin_session(pool.inner(), cookies).map_err(|e| e.unwrap_err())?;
    let nav = build_nav("admin", true, true);
    let flash = flash_html(None, error);

    let content = format!(
        r#"{flash}
<h1>Create User</h1>
<form method="POST" action="/user-admin/users/create">
  <label>Username</label>
  <input type="text" name="username" required />
  <label>Display Name</label>
  <input type="text" name="display_name" required />
  <label>Password (leave blank for API key)</label>
  <input type="password" name="password" minlength="8" />
  <br/><br/>
  <button type="submit" class="btn-primary">Create User</button>
</form>
<p><a href="/user-admin">Back to User List</a></p>"#,
        flash = flash,
    );

    Ok(layout("Create User", &nav, &content))
}

#[derive(rocket::FromForm)]
pub struct CreateUserForm {
    username: String,
    display_name: String,
    password: Option<String>,
}

#[rocket::post("/user-admin/users/create", data = "<form>")]
pub fn admin_ui_create_user_submit(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    form: rocket::form::Form<CreateUserForm>,
) -> Result<Redirect, Status> {
    let _user_id = require_admin_session(pool.inner(), cookies).map_err(|e| e.unwrap_err())?;

    let password = form.password.as_deref().and_then(|p| {
        if p.is_empty() { None } else { Some(p.to_string()) }
    });

    let req = CreateUserRequest {
        username: form.username.clone(),
        display_name: form.display_name.clone(),
        password,
    };

    match admin::create_user(pool.inner(), req) {
        Ok(resp) => {
            let msg = if let Some(ref key) = resp.api_key {
                format!("User+created.+API+key:+{}", urlencoding::encode(key))
            } else {
                "User+created+successfully".to_string()
            };
            Ok(Redirect::found(format!("/user-admin?msg={}", msg)))
        }
        Err(e) => Ok(Redirect::found(format!(
            "/user-admin/users/create?error={}",
            urlencoding::encode(&e.message)
        ))),
    }
}

// -- User detail --

#[rocket::get("/user-admin/users/<target_user_id>?<msg>&<error>")]
pub fn admin_ui_user_detail(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    target_user_id: &str,
    msg: Option<&str>,
    error: Option<&str>,
) -> Result<RawHtml<String>, Status> {
    let _user_id = require_admin_session(pool.inner(), cookies).map_err(|e| e.unwrap_err())?;
    let nav = build_nav("admin", true, true);
    let flash = flash_html(msg, error);

    let req = GetUserRequest {
        user_id: target_user_id.to_string(),
    };
    let user_resp = admin::get_user(pool.inner(), req).map_err(|_| Status::NotFound)?;
    let u = &user_resp.user;

    // Claims
    let claims = pool
        .list_active_claims(target_user_id)
        .map_err(|_| Status::InternalServerError)?;

    let mut claims_html = String::from(
        r#"<h2>Claims</h2>
<table><tr><th>Type</th><th>Value</th><th>Expires</th><th>Action</th></tr>"#,
    );
    for c in &claims {
        let value_str = String::from_utf8(c.claim_value.clone())
            .unwrap_or_else(|_| format!("{:?}", c.claim_value));
        claims_html.push_str(&format!(
            r#"<tr><td>{ct}</td><td>{cv}</td><td>{exp}</td><td><form method="POST" action="/user-admin/claims/{cid}/remove" style="margin:0"><button type="submit" class="btn-danger">Remove</button></form></td></tr>"#,
            ct = html_escape(&c.claim_type),
            cv = html_escape(&value_str),
            exp = html_escape(c.expires_at.as_deref().unwrap_or("never")),
            cid = html_escape(&c.id),
        ));
    }
    claims_html.push_str("</table>");
    if claims.is_empty() {
        claims_html = String::from("<h2>Claims</h2><p>No claims.</p>");
    }

    // Add claim form
    let add_claim_html = format!(
        r#"<h3>Add Claim</h3>
<form method="POST" action="/user-admin/users/{uid}/claims">
  <label>Claim Type</label>
  <input type="text" name="claim_type" required />
  <label>Claim Value</label>
  <input type="text" name="claim_value" required />
  <label>Expires At (RFC3339, optional)</label>
  <input type="text" name="expires_at" placeholder="2027-01-01T00:00:00Z" />
  <br/><br/>
  <button type="submit" class="btn-primary">Add Claim</button>
</form>"#,
        uid = html_escape(target_user_id),
    );

    // Relations
    let relations = pool
        .list_relations_for_subject("user", target_user_id)
        .map_err(|_| Status::InternalServerError)?;

    let mut relations_html = String::from(
        r#"<h2>Relations</h2>
<table><tr><th>Relation</th><th>Object Type</th><th>Object ID</th><th>Action</th></tr>"#,
    );
    for r in &relations {
        if r.removed_at.is_some() {
            continue;
        }
        relations_html.push_str(&format!(
            r#"<tr><td>{rel}</td><td>{ot}</td><td>{oi}</td><td><form method="POST" action="/user-admin/relations/{rid}/remove" style="margin:0"><button type="submit" class="btn-danger">Remove</button></form></td></tr>"#,
            rel = html_escape(&r.relation),
            ot = html_escape(&r.object_type),
            oi = html_escape(&r.object_id),
            rid = html_escape(&r.id),
        ));
    }
    relations_html.push_str("</table>");
    if relations.iter().all(|r| r.removed_at.is_some()) {
        relations_html = String::from("<h2>Relations</h2><p>No active relations.</p>");
    }

    // Add relation form
    let add_relation_html = format!(
        r#"<h3>Grant Relation</h3>
<form method="POST" action="/user-admin/relations">
  <input type="hidden" name="subject_type" value="user" />
  <input type="hidden" name="subject_id" value="{uid}" />
  <label>Relation</label>
  <select name="relation">
    <option value="admin">admin</option>
    <option value="manage_users">manage_users</option>
    <option value="manage_claims">manage_claims</option>
    <option value="api_access">api_access</option>
    <option value="member">member</option>
  </select>
  <label>Object Type</label>
  <select name="object_type">
    <option value="domain">domain</option>
    <option value="group">group</option>
    <option value="user">user</option>
  </select>
  <label>Object ID</label>
  <input type="text" name="object_id" required value="{domain}" />
  <br/><br/>
  <button type="submit" class="btn-primary">Grant Relation</button>
</form>"#,
        uid = html_escape(target_user_id),
        domain = html_escape(&get_domain_name()),
    );

    let status_badge = if u.is_active {
        r#"<span class="badge badge-active">Active</span>"#
    } else {
        r#"<span class="badge badge-inactive">Inactive</span>"#
    };

    let activate_deactivate = if u.is_active {
        format!(
            r#"<form method="POST" action="/user-admin/users/{uid}/deactivate" style="display:inline"><button type="submit" class="btn-danger" onclick="return confirm('Deactivate this user?')">Deactivate User</button></form>"#,
            uid = html_escape(&u.id),
        )
    } else {
        format!(
            r#"<form method="POST" action="/user-admin/users/{uid}/activate" style="display:inline"><button type="submit" class="btn-primary">Activate User</button></form>"#,
            uid = html_escape(&u.id),
        )
    };

    let content = format!(
        r#"{flash}
<h1>User: {display_name}</h1>
<div class="info">
  <p><strong>ID:</strong> <code>{id}</code></p>
  <p><strong>Username:</strong> {username}</p>
  <p><strong>Status:</strong> {status}</p>
  <p><strong>Created:</strong> {created}</p>
  <p><strong>Updated:</strong> {updated}</p>
</div>

<h2>Edit Display Name</h2>
<form method="POST" action="/user-admin/users/{uid}/update">
  <input type="text" name="display_name" value="{display_name_val}" required />
  <button type="submit" class="btn-primary">Update</button>
</form>

<h2>Actions</h2>
{activate_deactivate}

<h2>Reset Password</h2>
<form method="POST" action="/user-admin/users/{uid}/reset-password">
  <label>New Password</label>
  <input type="password" name="new_password" required minlength="8" />
  <br/><br/>
  <button type="submit" class="btn-primary">Reset Password</button>
</form>

{claims}
{add_claim}

{relations}
{add_relation}

<p><a href="/user-admin">Back to User List</a></p>"#,
        flash = flash,
        display_name = html_escape(&u.display_name),
        id = html_escape(&u.id),
        username = html_escape(&u.username),
        status = status_badge,
        created = html_escape(&u.created_at),
        updated = html_escape(&u.updated_at),
        uid = html_escape(&u.id),
        display_name_val = html_escape(&u.display_name),
        activate_deactivate = activate_deactivate,
        claims = claims_html,
        add_claim = add_claim_html,
        relations = relations_html,
        add_relation = add_relation_html,
    );

    Ok(layout("User Detail", &nav, &content))
}

// -- Update display name --

#[derive(rocket::FromForm)]
pub struct UpdateDisplayNameForm {
    display_name: String,
}

#[rocket::post("/user-admin/users/<target_user_id>/update", data = "<form>", rank = 2)]
pub fn admin_ui_update_user(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    target_user_id: &str,
    form: rocket::form::Form<UpdateDisplayNameForm>,
) -> Result<Redirect, Status> {
    let _user_id = require_admin_session(pool.inner(), cookies).map_err(|e| e.unwrap_err())?;

    let req = UpdateUserRequest {
        user_id: target_user_id.to_string(),
        display_name: Some(form.display_name.clone()),
    };

    match admin::update_user(pool.inner(), req) {
        Ok(_) => Ok(Redirect::found(format!(
            "/user-admin/users/{}?msg=Display+name+updated",
            urlencoding::encode(target_user_id)
        ))),
        Err(e) => Ok(Redirect::found(format!(
            "/user-admin/users/{}?error={}",
            urlencoding::encode(target_user_id),
            urlencoding::encode(&e.message)
        ))),
    }
}

// -- Deactivate --

#[rocket::post("/user-admin/users/<target_user_id>/deactivate", rank = 2)]
pub fn admin_ui_deactivate_user(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    target_user_id: &str,
) -> Result<Redirect, Status> {
    let user_id = require_admin_session(pool.inner(), cookies).map_err(|e| e.unwrap_err())?;

    if target_user_id == user_id {
        return Ok(Redirect::found(format!(
            "/user-admin/users/{}?error=Cannot+deactivate+yourself",
            urlencoding::encode(target_user_id)
        )));
    }

    let req = DeactivateUserRequest {
        user_id: target_user_id.to_string(),
    };

    match admin::deactivate_user(pool.inner(), req) {
        Ok(_) => Ok(Redirect::found(format!(
            "/user-admin/users/{}?msg=User+deactivated",
            urlencoding::encode(target_user_id)
        ))),
        Err(e) => Ok(Redirect::found(format!(
            "/user-admin/users/{}?error={}",
            urlencoding::encode(target_user_id),
            urlencoding::encode(&e.message)
        ))),
    }
}

// -- Activate --

#[rocket::post("/user-admin/users/<target_user_id>/activate")]
pub fn admin_ui_activate_user(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    target_user_id: &str,
) -> Result<Redirect, Status> {
    let _user_id = require_admin_session(pool.inner(), cookies).map_err(|e| e.unwrap_err())?;

    match admin::activate_user(pool.inner(), target_user_id) {
        Ok(_) => Ok(Redirect::found(format!(
            "/user-admin/users/{}?msg=User+activated",
            urlencoding::encode(target_user_id)
        ))),
        Err(e) => Ok(Redirect::found(format!(
            "/user-admin/users/{}?error={}",
            urlencoding::encode(target_user_id),
            urlencoding::encode(&e.message)
        ))),
    }
}

// -- Reset password --

#[derive(rocket::FromForm)]
pub struct ResetPasswordForm {
    new_password: String,
}

#[rocket::post("/user-admin/users/<target_user_id>/reset-password", data = "<form>", rank = 2)]
pub fn admin_ui_reset_password(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    target_user_id: &str,
    form: rocket::form::Form<ResetPasswordForm>,
) -> Result<Redirect, Status> {
    let _user_id = require_admin_session(pool.inner(), cookies).map_err(|e| e.unwrap_err())?;

    let req = ResetPasswordRequest {
        user_id: target_user_id.to_string(),
        new_password: form.new_password.clone(),
    };

    match admin::reset_password(pool.inner(), req) {
        Ok(_) => Ok(Redirect::found(format!(
            "/user-admin/users/{}?msg=Password+reset+successfully",
            urlencoding::encode(target_user_id)
        ))),
        Err(e) => Ok(Redirect::found(format!(
            "/user-admin/users/{}?error={}",
            urlencoding::encode(target_user_id),
            urlencoding::encode(&e.message)
        ))),
    }
}

// -- Add claim --

#[derive(rocket::FromForm)]
pub struct AddClaimForm {
    claim_type: String,
    claim_value: String,
    expires_at: Option<String>,
}

#[rocket::post("/user-admin/users/<target_user_id>/claims", data = "<form>", rank = 2)]
pub fn admin_ui_add_claim(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    target_user_id: &str,
    form: rocket::form::Form<AddClaimForm>,
) -> Result<Redirect, Status> {
    let _user_id = require_admin_session(pool.inner(), cookies).map_err(|e| e.unwrap_err())?;

    let expires_at = form.expires_at.as_deref().and_then(|s| {
        if s.is_empty() { None } else { Some(s.to_string()) }
    });

    let req = SetClaimRequest {
        user_id: target_user_id.to_string(),
        claim_type: form.claim_type.clone(),
        claim_value: form.claim_value.clone(),
        expires_at,
    };

    match admin::set_claim(pool.inner(), req) {
        Ok(_) => Ok(Redirect::found(format!(
            "/user-admin/users/{}?msg=Claim+added",
            urlencoding::encode(target_user_id)
        ))),
        Err(e) => Ok(Redirect::found(format!(
            "/user-admin/users/{}?error={}",
            urlencoding::encode(target_user_id),
            urlencoding::encode(&e.message)
        ))),
    }
}

// -- Remove claim --

#[rocket::post("/user-admin/claims/<claim_id>/remove")]
pub fn admin_ui_remove_claim(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    claim_id: &str,
) -> Result<Redirect, Status> {
    let _user_id = require_admin_session(pool.inner(), cookies).map_err(|e| e.unwrap_err())?;

    // Look up the claim to get user_id for redirect
    let claim = pool.find_claim_by_id(claim_id).map_err(|_| Status::NotFound)?;

    let req = RemoveClaimRequest {
        claim_id: claim_id.to_string(),
    };

    match admin::remove_claim(pool.inner(), req) {
        Ok(_) => Ok(Redirect::found(format!(
            "/user-admin/users/{}?msg=Claim+removed",
            urlencoding::encode(&claim.user_id)
        ))),
        Err(e) => Ok(Redirect::found(format!(
            "/user-admin/users/{}?error={}",
            urlencoding::encode(&claim.user_id),
            urlencoding::encode(&e.message)
        ))),
    }
}

// -- Grant relation --

#[derive(rocket::FromForm)]
pub struct GrantRelationForm {
    subject_type: String,
    subject_id: String,
    relation: String,
    object_type: String,
    object_id: String,
}

#[rocket::post("/user-admin/relations", data = "<form>", rank = 2)]
pub fn admin_ui_grant_relation(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    form: rocket::form::Form<GrantRelationForm>,
) -> Result<Redirect, Status> {
    let _user_id = require_admin_session(pool.inner(), cookies).map_err(|e| e.unwrap_err())?;

    let redirect_uid = form.subject_id.clone();
    let req = GrantRelationRequest {
        subject_type: form.subject_type.clone(),
        subject_id: form.subject_id.clone(),
        relation: form.relation.clone(),
        object_type: form.object_type.clone(),
        object_id: form.object_id.clone(),
    };

    match admin::grant_relation(pool.inner(), req) {
        Ok(_) => Ok(Redirect::found(format!(
            "/user-admin/users/{}?msg=Relation+granted",
            urlencoding::encode(&redirect_uid)
        ))),
        Err(e) => Ok(Redirect::found(format!(
            "/user-admin/users/{}?error={}",
            urlencoding::encode(&redirect_uid),
            urlencoding::encode(&e.message)
        ))),
    }
}

// -- Remove relation --

#[rocket::post("/user-admin/relations/<relation_id>/remove", rank = 2)]
pub fn admin_ui_remove_relation(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    relation_id: &str,
) -> Result<Redirect, Status> {
    let _user_id = require_admin_session(pool.inner(), cookies).map_err(|e| e.unwrap_err())?;

    // Look up the relation to figure out redirect target
    let relations_req = ListRelationsRequest {
        subject_type: None,
        subject_id: None,
        object_type: Some("domain".to_string()),
        object_id: Some(get_domain_name()),
    };
    // We need the subject_id to redirect back. Try to find it.
    let all_rels = admin::list_relations(pool.inner(), relations_req);

    let req = RemoveRelationRequest {
        relation_id: relation_id.to_string(),
    };

    match admin::remove_relation(pool.inner(), req) {
        Ok(_) => {
            // Try to redirect to the user page; fall back to list
            if let Ok(resp) = all_rels {
                if let Some(rel) = resp.relations.iter().find(|r| r.id == relation_id) {
                    return Ok(Redirect::found(format!(
                        "/user-admin/users/{}?msg=Relation+removed",
                        urlencoding::encode(&rel.subject_id)
                    )));
                }
            }
            Ok(Redirect::found("/user-admin?msg=Relation+removed"))
        }
        Err(e) => Ok(Redirect::found(format!(
            "/user-admin?error={}",
            urlencoding::encode(&e.message)
        ))),
    }
}
