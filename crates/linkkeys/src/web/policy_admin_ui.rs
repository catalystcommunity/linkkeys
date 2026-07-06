//! Admin policy editor: the one technical surface in the system, but a guided
//! one — dropdowns, not a policy language. It manages the claim-type registry
//! (what may be set, how it's signed), the trusted issuers for attested types,
//! the per-audience release defaults, and the approval queue.
//!
//! Registry / release / approvals are gated by `manage_claims` (it already means
//! "controls claims on this domain"). Each button is one `admin`/`DbPool` call,
//! so the same operations back a future CLI.

use rocket::http::{CookieJar, Status};
use rocket::response::content::RawHtml;
use rocket::response::Redirect;
use rocket::State;

use crate::conversions::{get_domain_name, html_escape};
use crate::db::models::ClaimTypePolicy;
use crate::db::DbPool;
use crate::net::Net;
use crate::services::{admin, attestation, authorization};

use super::account_ui::{build_nav, flash_html, get_session_user_id, is_user_admin, layout};
use super::profile_ui::qr_svg;
use liblinkkeys::consent::{compute_authorized_claims, resolve_consent_screen, DomainPolicy};
use liblinkkeys::generated::types::{
    Claim, ClaimRequest, RequestedClaim, SignedSigningRequest, SigningRequest,
};

fn require_manage_claims(pool: &DbPool, cookies: &CookieJar<'_>) -> Result<String, Status> {
    let user_id = get_session_user_id(cookies).ok_or(Status::Unauthorized)?;
    let domain = get_domain_name();
    if !authorization::user_has_permission(pool, &user_id, "manage_claims", "domain", &domain) {
        return Err(Status::Forbidden);
    }
    Ok(user_id)
}

fn require_issue_page_access(pool: &DbPool, cookies: &CookieJar<'_>) -> Result<String, Status> {
    let user_id = get_session_user_id(cookies).ok_or(Status::Unauthorized)?;
    let domain = get_domain_name();
    if authorization::user_has_permission(
        pool,
        &user_id,
        authorization::RELATION_MANAGE_CLAIMS,
        "domain",
        &domain,
    ) {
        return Ok(user_id);
    }
    if pool
        .list_relations_for_subject("user", &user_id)
        .map(|rels| {
            rels.iter().any(|r| {
                r.relation == authorization::RELATION_ISSUE_CLAIMS && r.object_type == "claim_type"
            })
        })
        .unwrap_or(false)
    {
        return Ok(user_id);
    }
    Err(Status::Forbidden)
}

fn select(name: &str, options: &[&str], current: &str) -> String {
    let mut s = format!(r#"<select name="{}">"#, name);
    for opt in options {
        let sel = if *opt == current { " selected" } else { "" };
        s.push_str(&format!(
            r#"<option value="{o}"{sel}>{o}</option>"#,
            o = html_escape(opt),
            sel = sel
        ));
    }
    s.push_str("</select>");
    s
}

const VALUE_TYPES: &[&str] = &[
    "text",
    "url",
    "email",
    "bool",
    "int",
    "float",
    "decimal",
    "date",
    "timestamp",
    "opaque",
];
const SET_RULES: &[&str] = &[
    "user_self",
    "idp_on_request",
    "trusted_issuer_only",
    "admin_only",
    "deny",
];
const SIGNING_RULES: &[&str] = &["self_signed", "verified", "attested", "unsigned"];

#[rocket::get("/policy-admin?<msg>&<error>")]
pub fn policy_admin(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    msg: Option<&str>,
    error: Option<&str>,
) -> Result<RawHtml<String>, Status> {
    render_policy_admin(pool.inner(), cookies, msg, error, "")
}

fn render_policy_admin(
    pool: &DbPool,
    cookies: &CookieJar<'_>,
    msg: Option<&str>,
    error: Option<&str>,
    test_panel: &str,
) -> Result<RawHtml<String>, Status> {
    let user_id = require_manage_claims(pool, cookies)?;
    let admin_nav = is_user_admin(pool, &user_id);
    let nav = build_nav("policy", admin_nav, true);
    let flash = flash_html(msg, error);

    let policies = pool
        .list_claim_policies()
        .map_err(|_| Status::InternalServerError)?;
    let issuers = pool
        .list_all_trusted_issuers()
        .map_err(|_| Status::InternalServerError)?;
    let releases = pool
        .list_release_policies()
        .map_err(|_| Status::InternalServerError)?;
    let approvals = pool
        .list_pending_approvals()
        .map_err(|_| Status::InternalServerError)?;

    // -- Registry table --
    let mut reg_rows = String::new();
    for p in &policies {
        let flags = format!(
            "{}{}{}{}",
            if p.user_settable {
                "user-settable "
            } else {
                ""
            },
            if p.default_auto_sign {
                "auto-sign "
            } else {
                ""
            },
            if p.requires_approval { "approval " } else { "" },
            if p.suggested { "suggested" } else { "" },
        );
        reg_rows.push_str(&format!(
            r#"<tr><td><code>{ct}</code></td><td>{label}</td><td>{vt}</td><td>{set}</td><td>{sign}</td><td>{flags}</td>
<td><form method="POST" action="/policy-admin/claim-types/delete" style="margin:0"><input type="hidden" name="claim_type" value="{ct}"/><button class="btn-danger" type="submit">Delete</button></form></td></tr>"#,
            ct = html_escape(&p.claim_type),
            label = html_escape(&p.label),
            vt = html_escape(&p.value_type),
            set = html_escape(&p.set_rule),
            sign = html_escape(&p.signing_rule),
            flags = flags,
        ));
    }
    let claim_type_datalist = format!(
        r#"<datalist id="claim-type-options">{}</datalist>"#,
        policies
            .iter()
            .map(|p| format!(
                r#"<option value="{}"></option>"#,
                html_escape(&p.claim_type)
            ))
            .collect::<String>()
    );

    // -- Trusted issuers --
    let mut issuer_rows = String::new();
    for i in &issuers {
        issuer_rows.push_str(&format!(
            r#"<tr><td><code>{ct}</code></td><td>{dom}</td>
<td><form method="POST" action="/policy-admin/trusted-issuers/delete" style="margin:0"><input type="hidden" name="claim_type" value="{ct}"/><input type="hidden" name="issuer_domain" value="{dom}"/><button class="btn-danger" type="submit">Remove</button></form></td></tr>"#,
            ct = html_escape(&i.claim_type),
            dom = html_escape(&i.issuer_domain),
        ));
    }

    // -- Release defaults --
    let mut release_rows = String::new();
    for r in &releases {
        release_rows.push_str(&format!(
            r#"<tr><td>{aud}</td><td><code>{ct}</code></td><td>{disp}</td>
<td><form method="POST" action="/policy-admin/release/delete" style="margin:0"><input type="hidden" name="audience" value="{aud}"/><input type="hidden" name="claim_type" value="{ct}"/><button class="btn-danger" type="submit">Delete</button></form></td></tr>"#,
            aud = html_escape(&r.audience),
            ct = html_escape(&r.claim_type),
            disp = html_escape(&r.disposition),
        ));
    }

    // -- Approvals --
    let mut approval_rows = String::new();
    for a in &approvals {
        let value = String::from_utf8(a.claim_value.clone()).unwrap_or_else(|_| "(binary)".into());
        approval_rows.push_str(&format!(
            r#"<tr><td><code>{uid}</code></td><td>{ct}</td><td>{val}</td>
<td><form method="POST" action="/policy-admin/approvals/approve" style="display:inline;margin:0"><input type="hidden" name="id" value="{id}"/><button class="btn-primary" type="submit">Approve</button></form>
<form method="POST" action="/policy-admin/approvals/reject" style="display:inline;margin:0"><input type="hidden" name="id" value="{id}"/><button class="btn-danger" type="submit">Reject</button></form></td></tr>"#,
            uid = html_escape(&a.user_id[..8.min(a.user_id.len())]),
            ct = html_escape(&a.claim_type),
            val = html_escape(&value),
            id = html_escape(&a.id),
        ));
    }

    // -- Per-locale claim name translations (operator overrides) --
    let mut label_rows = String::new();
    for p in &policies {
        if let Ok(labels) = pool.list_claim_labels_i18n(&p.claim_type) {
            for l in &labels {
                label_rows.push_str(&format!(
                    r#"<tr><td><code>{ct}</code></td><td>{loc}</td><td>{label}</td><td>{desc}</td>
<td><form method="POST" action="/policy-admin/claim-types/label/delete" style="margin:0"><input type="hidden" name="claim_type" value="{ct}"/><input type="hidden" name="locale" value="{loc}"/><button class="btn-danger" type="submit">Delete</button></form></td></tr>"#,
                    ct = html_escape(&l.claim_type),
                    loc = html_escape(&l.locale),
                    label = html_escape(&l.label),
                    desc = html_escape(l.description.as_deref().unwrap_or("")),
                ));
            }
        }
    }

    let content = format!(
        r#"{flash}
{claim_type_datalist}
<h1>Policy Administration</h1>
<p>Control which claims this domain recognises, how they get signed, who you trust to attest them, and what is released to relying parties by default.</p>
<p><a href="/policy-admin/issue">Issue an attestation from a user's request →</a></p>
{test_panel}

<h2>Claim types</h2>
<table><tr><th>Type</th><th>Label</th><th>Value</th><th>Set rule</th><th>Signing</th><th>Flags</th><th></th></tr>{reg_rows}</table>

<h3>Add / edit a claim type</h3>
<form method="POST" action="/policy-admin/claim-types">
  <label>Claim type (id)</label><input type="text" name="claim_type" list="claim-type-options" required placeholder="e.g. pronouns"/>
  <label>Label</label><input type="text" name="label" required/>
  <label>Description</label><input type="text" name="description"/>
  <label>Value type</label>{value_type_sel}
  <label>Max bytes</label><input type="text" name="max_bytes" value="33792"/>
  <label>Set rule</label>{set_rule_sel}
  <label>Signing rule</label>{signing_rule_sel}
  <label><input type="checkbox" name="user_settable" value="1"/> User-settable</label>
  <label><input type="checkbox" name="default_auto_sign" value="1"/> Auto-sign by default</label>
  <label><input type="checkbox" name="requires_approval" value="1"/> Requires approval</label>
  <label><input type="checkbox" name="suggested" value="1"/> Suggested</label>
  <br/><button type="submit" class="btn-primary">Save claim type</button>
</form>

<h2>Claim name translations</h2>
<p>Show claim names to people in their own language. Enter a locale (e.g. <code>es-ES</code>, <code>pt-BR</code>) and the translated name. Anything you don't translate falls back to English automatically.</p>
<table><tr><th>Claim type</th><th>Locale</th><th>Name</th><th>Description</th><th></th></tr>{label_rows}</table>
<form method="POST" action="/policy-admin/claim-types/label">
  <input type="text" name="claim_type" list="claim-type-options" required placeholder="claim type"/>
  <input type="text" name="locale" required placeholder="es-ES"/>
  <input type="text" name="label" required placeholder="translated name"/>
  <input type="text" name="description" placeholder="translated description (optional)"/>
  <button type="submit" class="btn-primary">Save translation</button>
</form>

<h2>Trusted issuers</h2>
<p>Domains whose signature you accept as attestation for a claim type (e.g. a government entity for <code>age_over_21</code>).</p>
<table><tr><th>Claim type</th><th>Issuer domain</th><th></th></tr>{issuer_rows}</table>
<form method="POST" action="/policy-admin/trusted-issuers">
  <input type="text" name="claim_type" list="claim-type-options" required placeholder="claim type"/>
  <input type="text" name="issuer_domain" required placeholder="issuer.example"/>
  <button type="submit" class="btn-primary">Add issuer</button>
</form>

<h3>Test issuer signing policy</h3>
<p>Evaluate subject-domain deny rules and, optionally, whether a specific user may issue a claim type. This does not save anything.</p>
<form method="POST" action="/policy-admin/issuer/test">
  <label>Subject domain</label><input type="text" name="subject_domain" required placeholder="example.com"/>
  <label>Denied subject domains</label><input type="text" name="denied_domains" value="{deny_domains}" placeholder="bad.example, blocked.example"/>
  <label>Denied TLDs</label><input type="text" name="denied_tlds" value="{deny_tlds}" placeholder="ru, zip"/>
  <label>Issuer user id (optional)</label><input type="text" name="issuer_user_id" placeholder="uuid"/>
  <label>Claim type for user authorization test</label><input type="text" name="claim_type" list="claim-type-options" placeholder="claim type"/>
  <br/><button type="submit" class="btn-primary">Test issuer policy</button>
</form>

<h2>Release defaults</h2>
<p>Per-audience policy applied at consent. Audience <code>*</code> is the global default. <code>forced_allow</code> always releases; <code>forced_deny</code> never does (deny wins).</p>
<table><tr><th>Audience</th><th>Claim type</th><th>Disposition</th><th></th></tr>{release_rows}</table>
<form method="POST" action="/policy-admin/release">
  <input type="text" name="audience" required placeholder="* or app.example"/>
  <input type="text" name="claim_type" list="claim-type-options" required placeholder="claim type"/>
  {disposition_sel}
  <button type="submit" class="btn-primary">Save rule</button>
</form>

<h3>Test release policy</h3>
<p>Exercise the consent resolver with a temporary unsaved rule. Required claims remain user-toggleable unless a domain policy locks them.</p>
<form method="POST" action="/policy-admin/release/test">
  <label>Audience</label><input type="text" name="audience" required value="linkidspec.com"/>
  <label>Required requested claims</label><input type="text" name="required_claims" value="display_name, handle"/>
  <label>Optional requested claims</label><input type="text" name="optional_claims" value="email, over_21, address"/>
  <label>User selected claims</label><input type="text" name="user_choices" value="display_name, handle, email"/>
  <label>Available claims (blank = all requested)</label><input type="text" name="available_claims" placeholder="display_name, handle, email, over_21, address"/>
  <label>Temporary unsaved audience</label><input type="text" name="temp_audience" placeholder="* or app.example"/>
  <label>Temporary unsaved claim type</label><input type="text" name="temp_claim_type" list="claim-type-options" placeholder="claim type"/>
  {temp_disposition_sel}
  <br/><button type="submit" class="btn-primary">Test release policy</button>
</form>

<h2>Pending approvals</h2>
<table><tr><th>Subject</th><th>Claim</th><th>Value</th><th></th></tr>{approval_rows}</table>
"#,
        flash = flash,
        claim_type_datalist = claim_type_datalist,
        test_panel = test_panel,
        reg_rows = reg_rows,
        label_rows = label_rows,
        value_type_sel = select("value_type", VALUE_TYPES, "text"),
        set_rule_sel = select("set_rule", SET_RULES, "user_self"),
        signing_rule_sel = select("signing_rule", SIGNING_RULES, "self_signed"),
        issuer_rows = issuer_rows,
        deny_domains =
            html_escape(&std::env::var("ATTESTATION_DENY_SUBJECT_DOMAINS").unwrap_or_default()),
        deny_tlds =
            html_escape(&std::env::var("ATTESTATION_DENY_SUBJECT_TLDS").unwrap_or_default()),
        release_rows = release_rows,
        disposition_sel = select(
            "disposition",
            &["forced_allow", "forced_deny"],
            "forced_allow"
        ),
        temp_disposition_sel = select(
            "temp_disposition",
            &["forced_allow", "forced_deny"],
            "forced_allow"
        ),
        approval_rows = approval_rows,
    );

    Ok(layout("Policy Admin", &nav, &content))
}

fn redirect_ok(msg: &str) -> Redirect {
    Redirect::found(format!("/policy-admin?msg={}", urlencoding::encode(msg)))
}
fn redirect_err(msg: &str) -> Redirect {
    Redirect::found(format!("/policy-admin?error={}", urlencoding::encode(msg)))
}

#[derive(rocket::FromForm)]
pub struct PolicyForm {
    claim_type: String,
    label: String,
    description: Option<String>,
    value_type: String,
    max_bytes: String,
    set_rule: String,
    signing_rule: String,
    user_settable: Option<String>,
    default_auto_sign: Option<String>,
    requires_approval: Option<String>,
    suggested: Option<String>,
}

#[rocket::post("/policy-admin/claim-types", data = "<form>")]
pub fn upsert_policy(
    _csrf: super::guard::SameOriginPost,
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    form: rocket::form::Form<PolicyForm>,
) -> Result<Redirect, Status> {
    require_manage_claims(pool.inner(), cookies)?;
    let max_bytes = match form.max_bytes.trim().parse::<i64>() {
        Ok(n) if n > 0 => n,
        _ => return Ok(redirect_err("max bytes must be a positive number")),
    };
    // Validate the enum strings server-side rather than trusting the dropdowns —
    // an unparseable rule would otherwise be stored and 500 at set time.
    use liblinkkeys::claim_policy::{SetRule, SigningRule, ValueType};
    if ValueType::parse(&form.value_type).is_none() {
        return Ok(redirect_err("invalid value type"));
    }
    if SetRule::parse(&form.set_rule).is_none() {
        return Ok(redirect_err("invalid set rule"));
    }
    if SigningRule::parse(&form.signing_rule).is_none() {
        return Ok(redirect_err("invalid signing rule"));
    }
    let policy = ClaimTypePolicy {
        claim_type: form.claim_type.trim().to_string(),
        label: form.label.trim().to_string(),
        description: form.description.clone().unwrap_or_default(),
        value_type: form.value_type.clone(),
        max_bytes,
        set_rule: form.set_rule.clone(),
        signing_rule: form.signing_rule.clone(),
        requires_approval: form.requires_approval.is_some(),
        user_settable: form.user_settable.is_some(),
        default_auto_sign: form.default_auto_sign.is_some(),
        suggested: form.suggested.is_some(),
    };
    match pool.upsert_claim_policy(policy) {
        Ok(_) => Ok(redirect_ok("Claim type saved")),
        Err(_) => Ok(redirect_err("Could not save claim type")),
    }
}

#[derive(rocket::FromForm)]
pub struct ClaimTypeForm {
    claim_type: String,
}

#[rocket::post("/policy-admin/claim-types/delete", data = "<form>")]
pub fn delete_policy(
    _csrf: super::guard::SameOriginPost,
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    form: rocket::form::Form<ClaimTypeForm>,
) -> Result<Redirect, Status> {
    require_manage_claims(pool.inner(), cookies)?;
    match pool.delete_claim_policy(form.claim_type.trim()) {
        Ok(_) => Ok(redirect_ok("Claim type deleted")),
        Err(_) => Ok(redirect_err("Could not delete claim type")),
    }
}

#[derive(rocket::FromForm)]
pub struct ClaimLabelForm {
    claim_type: String,
    locale: String,
    label: String,
    description: Option<String>,
}

#[rocket::post("/policy-admin/claim-types/label", data = "<form>")]
pub fn upsert_claim_label(
    _csrf: super::guard::SameOriginPost,
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    form: rocket::form::Form<ClaimLabelForm>,
) -> Result<Redirect, Status> {
    require_manage_claims(pool.inner(), cookies)?;
    let claim_type = form.claim_type.trim();
    let locale = form.locale.trim();
    let label = form.label.trim();
    if claim_type.is_empty() || locale.is_empty() || label.is_empty() {
        return Ok(redirect_err("claim type, locale and name are required"));
    }
    // Only translate a claim type that actually exists in the registry.
    if !matches!(pool.find_claim_policy(claim_type), Ok(Some(_))) {
        return Ok(redirect_err("unknown claim type"));
    }
    let description = form
        .description
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let entry = crate::db::models::ClaimLabelI18n {
        claim_type: claim_type.to_string(),
        locale: locale.to_string(),
        label: label.to_string(),
        description,
    };
    match pool.upsert_claim_label_i18n(entry) {
        Ok(_) => Ok(redirect_ok("Translation saved")),
        Err(_) => Ok(redirect_err("Could not save translation")),
    }
}

#[derive(rocket::FromForm)]
pub struct ClaimLabelDeleteForm {
    claim_type: String,
    locale: String,
}

#[rocket::post("/policy-admin/claim-types/label/delete", data = "<form>")]
pub fn delete_claim_label(
    _csrf: super::guard::SameOriginPost,
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    form: rocket::form::Form<ClaimLabelDeleteForm>,
) -> Result<Redirect, Status> {
    require_manage_claims(pool.inner(), cookies)?;
    match pool.delete_claim_label_i18n(form.claim_type.trim(), form.locale.trim()) {
        Ok(_) => Ok(redirect_ok("Translation deleted")),
        Err(_) => Ok(redirect_err("Could not delete translation")),
    }
}

#[derive(rocket::FromForm)]
pub struct IssuerForm {
    claim_type: String,
    issuer_domain: String,
}

#[rocket::post("/policy-admin/trusted-issuers", data = "<form>")]
pub async fn add_issuer(
    _csrf: super::guard::SameOriginPost,
    pool: &State<DbPool>,
    net: &State<Net>,
    cookies: &CookieJar<'_>,
    form: rocket::form::Form<IssuerForm>,
) -> Result<Redirect, Status> {
    require_manage_claims(pool.inner(), cookies)?;
    let issuer = form.issuer_domain.trim();
    if pool
        .add_trusted_issuer(form.claim_type.trim(), issuer)
        .is_err()
    {
        return Ok(redirect_err("Could not add issuer"));
    }
    // Cache the issuer's keys now (trust-establishment time) so the synchronous
    // deposit op can verify attestations from it later. Best-effort: if the
    // issuer is unreachable, the trust is still recorded and keys can be cached
    // on a later deposit/refresh.
    if issuer != get_domain_name() {
        if let Ok(keys) = super::rp::fetch_domain_keys(pool.inner(), net.inner(), issuer).await {
            for k in keys {
                let pk = crate::db::models::PeerKey {
                    domain: issuer.to_string(),
                    key_id: k.key_id,
                    public_key: k.public_key,
                    algorithm: k.algorithm,
                    fingerprint: k.fingerprint,
                    key_usage: k.key_usage,
                    expires_at: k.expires_at,
                    revoked_at: k.revoked_at,
                };
                let _ = pool.cache_peer_key(&pk);
            }
        }
    }
    Ok(redirect_ok("Trusted issuer added"))
}

#[rocket::post("/policy-admin/trusted-issuers/delete", data = "<form>")]
pub fn remove_issuer(
    _csrf: super::guard::SameOriginPost,
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    form: rocket::form::Form<IssuerForm>,
) -> Result<Redirect, Status> {
    require_manage_claims(pool.inner(), cookies)?;
    match pool.remove_trusted_issuer(form.claim_type.trim(), form.issuer_domain.trim()) {
        Ok(_) => Ok(redirect_ok("Trusted issuer removed")),
        Err(_) => Ok(redirect_err("Could not remove issuer")),
    }
}

#[derive(rocket::FromForm)]
pub struct ReleaseForm {
    audience: String,
    claim_type: String,
    disposition: String,
}

#[rocket::post("/policy-admin/release", data = "<form>")]
pub fn upsert_release(
    _csrf: super::guard::SameOriginPost,
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    form: rocket::form::Form<ReleaseForm>,
) -> Result<Redirect, Status> {
    require_manage_claims(pool.inner(), cookies)?;
    if form.disposition != "forced_allow" && form.disposition != "forced_deny" {
        return Ok(redirect_err("invalid disposition"));
    }
    match pool.upsert_release_policy(
        form.audience.trim(),
        form.claim_type.trim(),
        &form.disposition,
    ) {
        Ok(_) => Ok(redirect_ok("Release rule saved")),
        Err(_) => Ok(redirect_err("Could not save release rule")),
    }
}

#[derive(rocket::FromForm)]
pub struct ReleaseDeleteForm {
    audience: String,
    claim_type: String,
}

#[rocket::post("/policy-admin/release/delete", data = "<form>")]
pub fn delete_release(
    _csrf: super::guard::SameOriginPost,
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    form: rocket::form::Form<ReleaseDeleteForm>,
) -> Result<Redirect, Status> {
    require_manage_claims(pool.inner(), cookies)?;
    match pool.delete_release_policy(form.audience.trim(), form.claim_type.trim()) {
        Ok(_) => Ok(redirect_ok("Release rule deleted")),
        Err(_) => Ok(redirect_err("Could not delete release rule")),
    }
}

fn csv_list(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn requested_claims(types: &[String]) -> Vec<RequestedClaim> {
    types
        .iter()
        .map(|claim_type| RequestedClaim {
            claim_type: claim_type.clone(),
            datatype: "string".to_string(),
        })
        .collect()
}

fn test_claim(claim_type: &str) -> Claim {
    Claim {
        claim_id: format!("test-{}", claim_type),
        user_id: "test-user".to_string(),
        claim_type: claim_type.to_string(),
        claim_value: b"test".to_vec(),
        signatures: Vec::new(),
        attested_at: "2026-07-01T00:00:00Z".to_string(),
        created_at: "2026-07-01T00:00:00Z".to_string(),
        expires_at: None,
        revoked_at: None,
    }
}

fn release_policy_for_test(
    pool: &DbPool,
    audience: &str,
    temp_audience: &str,
    temp_claim_type: &str,
    temp_disposition: &str,
) -> Result<DomainPolicy, Status> {
    let rows = pool
        .list_release_policies_for_audience(audience)
        .map_err(|_| Status::InternalServerError)?;
    let mut policy = DomainPolicy::default();
    for r in rows {
        match r.disposition.as_str() {
            "forced_allow" => policy.forced_allow.push(r.claim_type),
            "forced_deny" => policy.forced_deny.push(r.claim_type),
            _ => {}
        }
    }

    let temp_audience = temp_audience.trim();
    let temp_claim_type = temp_claim_type.trim();
    if !temp_audience.is_empty()
        && !temp_claim_type.is_empty()
        && (temp_audience == "*" || temp_audience == audience)
    {
        match temp_disposition {
            "forced_allow" => policy.forced_allow.push(temp_claim_type.to_string()),
            "forced_deny" => policy.forced_deny.push(temp_claim_type.to_string()),
            _ => {}
        }
    }
    Ok(policy)
}

#[derive(rocket::FromForm)]
pub struct ReleaseTestForm {
    audience: String,
    required_claims: String,
    optional_claims: String,
    user_choices: String,
    available_claims: Option<String>,
    temp_audience: Option<String>,
    temp_claim_type: Option<String>,
    temp_disposition: String,
}

#[rocket::post("/policy-admin/release/test", data = "<form>")]
pub fn test_release_policy(
    _csrf: super::guard::SameOriginPost,
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    form: rocket::form::Form<ReleaseTestForm>,
) -> Result<RawHtml<String>, Status> {
    require_manage_claims(pool.inner(), cookies)?;
    let audience = form.audience.trim();
    if form.temp_disposition != "forced_allow" && form.temp_disposition != "forced_deny" {
        return render_policy_admin(
            pool.inner(),
            cookies,
            None,
            Some("invalid temporary disposition"),
            "",
        );
    }

    let required = csv_list(&form.required_claims);
    let optional = csv_list(&form.optional_claims);
    let mut default_available = required.clone();
    default_available.extend(optional.clone());
    let available_names = form
        .available_claims
        .as_deref()
        .map(csv_list)
        .filter(|v| !v.is_empty())
        .unwrap_or(default_available);
    let available: Vec<Claim> = available_names.iter().map(|ct| test_claim(ct)).collect();
    let req = ClaimRequest {
        required: requested_claims(&required),
        optional: requested_claims(&optional),
    };
    let temp_audience = form.temp_audience.as_deref().unwrap_or("");
    let temp_claim_type = form.temp_claim_type.as_deref().unwrap_or("");
    let policy = release_policy_for_test(
        pool.inner(),
        audience,
        temp_audience,
        temp_claim_type,
        &form.temp_disposition,
    )?;
    let screen = resolve_consent_screen(&req, &available, None, &policy);
    let user_choices = csv_list(&form.user_choices);
    let authorized = compute_authorized_claims(&req, &user_choices, &policy);

    let mut rows = String::new();
    for row in screen.rows {
        rows.push_str(&format!(
            r#"<tr><td><code>{ct}</code></td><td>{req}</td><td>{avail}</td><td>{locked}</td><td>{policy}</td><td>{defaulted}</td></tr>"#,
            ct = html_escape(&row.claim_type),
            req = if row.required { "required" } else { "optional" },
            avail = if row.available { "yes" } else { "no" },
            locked = if row.locked { "yes" } else { "no" },
            policy = html_escape(&format!("{:?}", row.policy)),
            defaulted = if row.default_granted() { "checked" } else { "unchecked" },
        ));
    }
    let panel = format!(
        r#"<div class="success">
<h2>Release policy test result</h2>
<p><strong>Audience:</strong> {audience}<br/>
<strong>Effective allow:</strong> {allow}<br/>
<strong>Effective deny:</strong> {deny}<br/>
<strong>Authorized after user choices:</strong> {authorized}</p>
<table><tr><th>Claim</th><th>RP marked</th><th>Available</th><th>Locked</th><th>Policy</th><th>Initial checkbox</th></tr>{rows}</table>
</div>"#,
        audience = html_escape(audience),
        allow = html_escape(&policy.forced_allow.join(", ")),
        deny = html_escape(&policy.forced_deny.join(", ")),
        authorized = html_escape(&authorized.join(", ")),
        rows = rows,
    );
    render_policy_admin(pool.inner(), cookies, None, None, &panel)
}

#[derive(rocket::FromForm)]
pub struct IssuerPolicyTestForm {
    subject_domain: String,
    denied_domains: String,
    denied_tlds: String,
    issuer_user_id: Option<String>,
    claim_type: Option<String>,
}

#[rocket::post("/policy-admin/issuer/test", data = "<form>")]
pub fn test_issuer_policy(
    _csrf: super::guard::SameOriginPost,
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    form: rocket::form::Form<IssuerPolicyTestForm>,
) -> Result<RawHtml<String>, Status> {
    require_manage_claims(pool.inner(), cookies)?;
    let denied_domains = csv_list(&form.denied_domains);
    let denied_tlds = csv_list(&form.denied_tlds);
    let domain_decision = attestation::subject_domain_policy_decision_with_denies(
        &form.subject_domain,
        &denied_domains,
        &denied_tlds,
    );
    let user_result = match (
        form.issuer_user_id.as_deref().map(str::trim),
        form.claim_type.as_deref().map(str::trim),
    ) {
        (Some(user_id), Some(claim_type)) if !user_id.is_empty() && !claim_type.is_empty() => {
            let can_issue = attestation::user_can_issue_claim(pool.inner(), user_id, claim_type);
            format!(
                "{} may {}issue {}",
                html_escape(user_id),
                if can_issue { "" } else { "not " },
                html_escape(claim_type)
            )
        }
        _ => "No user authorization check requested".to_string(),
    };
    let panel = format!(
        r#"<div class="success">
<h2>Issuer policy test result</h2>
<p><strong>Subject domain:</strong> {subject}<br/>
<strong>Subject-domain decision:</strong> {decision} ({reason})<br/>
<strong>User issue authorization:</strong> {user_result}<br/>
<strong>Attested claim TTL:</strong> {ttl} seconds</p>
</div>"#,
        subject = html_escape(form.subject_domain.trim()),
        decision = if domain_decision.allowed {
            "allowed"
        } else {
            "denied"
        },
        reason = html_escape(&domain_decision.reason),
        user_result = user_result,
        ttl = attestation::attested_claim_ttl_seconds(),
    );
    render_policy_admin(pool.inner(), cookies, None, None, &panel)
}

#[derive(rocket::FromForm)]
pub struct ApprovalForm {
    id: String,
}

#[rocket::post("/policy-admin/approvals/approve", data = "<form>")]
pub fn approve(
    _csrf: super::guard::SameOriginPost,
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    form: rocket::form::Form<ApprovalForm>,
) -> Result<Redirect, Status> {
    let admin_id = require_manage_claims(pool.inner(), cookies)?;
    match admin::approve_claim(pool.inner(), &form.id, &admin_id) {
        Ok(()) => Ok(redirect_ok("Claim approved and signed")),
        Err(e) => Ok(redirect_err(&e.message)),
    }
}

#[rocket::post("/policy-admin/approvals/reject", data = "<form>")]
pub fn reject(
    _csrf: super::guard::SameOriginPost,
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    form: rocket::form::Form<ApprovalForm>,
) -> Result<Redirect, Status> {
    let admin_id = require_manage_claims(pool.inner(), cookies)?;
    match admin::reject_claim(pool.inner(), &form.id, &admin_id) {
        Ok(()) => Ok(redirect_ok("Claim rejected")),
        Err(e) => Ok(redirect_err(&e.message)),
    }
}

// -- Receive & issue: the issuer admin accepts a signing request and signs --

/// Decode a base64url(CBOR(SignedSigningRequest)) string into the envelope and
/// its inner request.
fn decode_request(b64: &str) -> Option<(SignedSigningRequest, SigningRequest)> {
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    let bytes = Base64UrlUnpadded::decode_vec(b64.trim()).ok()?;
    let signed = liblinkkeys::generated::decode_signed_signing_request(&bytes).ok()?;
    let req = liblinkkeys::generated::decode_signing_request(&signed.request).ok()?;
    Some((signed, req))
}

/// Verify a pasted signing request: it must be addressed to us, and its
/// signature must check out against the subject domain's (fetched) keys.
async fn verify_pasted(
    pool: &DbPool,
    net: &Net,
    signed: &SignedSigningRequest,
    req: &SigningRequest,
) -> Result<(), String> {
    let our = get_domain_name();
    if req.issuer_domain != our {
        return Err(format!(
            "This request is addressed to {}, not this domain.",
            req.issuer_domain
        ));
    }
    let keys = super::rp::fetch_domain_keys(pool, net, &req.subject_domain)
        .await
        .map_err(|e| format!("could not fetch {} keys: {}", req.subject_domain, e))?;
    let keysets = vec![liblinkkeys::claims::DomainKeySet {
        domain: req.subject_domain.clone(),
        keys,
    }];
    liblinkkeys::signing_request::verify_signing_request(
        signed,
        &req.subject_domain,
        &our,
        &keysets,
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

#[rocket::get("/policy-admin/issue?<error>")]
pub fn issue_page(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    error: Option<&str>,
) -> Result<RawHtml<String>, Status> {
    let user_id = require_issue_page_access(pool.inner(), cookies)?;
    let nav = build_nav("policy", is_user_admin(pool.inner(), &user_id), true);
    let content = format!(
        r#"{flash}
<h1>Issue an attestation</h1>
<p>Paste a verification request a user brought to you (QR text or file contents).
We verify it was really signed by their domain, then you attest what you've
checked. Your signature travels with the claim so anyone can verify it.</p>
<form method="POST" action="/policy-admin/issue">
  <label>Signing request (base64)</label>
  <textarea name="request" rows="5" style="width:100%" required></textarea>
  <br/><button type="submit" class="btn-primary">Verify request</button>
</form>"#,
        flash = flash_html(None, error),
    );
    Ok(layout("Issue Attestation", &nav, &content))
}

#[derive(rocket::FromForm)]
pub struct IssueForm {
    request: String,
}

#[rocket::post("/policy-admin/issue", data = "<form>")]
pub async fn issue_verify(
    _csrf: super::guard::SameOriginPost,
    pool: &State<DbPool>,
    net: &State<Net>,
    cookies: &CookieJar<'_>,
    form: rocket::form::Form<IssueForm>,
) -> Result<RawHtml<String>, Status> {
    let user_id = require_issue_page_access(pool.inner(), cookies)?;
    let nav = build_nav("policy", is_user_admin(pool.inner(), &user_id), true);

    let (signed, req) = match decode_request(&form.request) {
        Some(v) => v,
        None => {
            return Ok(layout(
                "Issue Attestation",
                &nav,
                &format!(
                    "{}<p><a href=\"/policy-admin/issue\">Back</a></p>",
                    flash_html(None, Some("That doesn't decode as a signing request."))
                ),
            ))
        }
    };
    if let Err(e) = verify_pasted(pool.inner(), net.inner(), &signed, &req).await {
        return Ok(layout(
            "Issue Attestation",
            &nav,
            &format!(
                "{}<p><a href=\"/policy-admin/issue\">Back</a></p>",
                flash_html(None, Some(&e))
            ),
        ));
    }

    // Verified — show the subject + requested types and a values form. The admin
    // fills `claim_type=value` lines for what they're willing to attest.
    let prefill: String = req
        .requested_claim_types
        .iter()
        .map(|t| format!("{}=", t))
        .collect::<Vec<_>>()
        .join("\n");
    let content = format!(
        r#"<h1>Issue an attestation</h1>
<div class="success">Verified — really signed by {subject_domain}.</div>
<p><strong>Subject:</strong> <code>{subject}</code>@{subject_domain}<br/>
<strong>Requested:</strong> {types}</p>
<form method="POST" action="/policy-admin/issue/sign">
  <input type="hidden" name="request" value="{request}"/>
  <label>What you attest (one <code>claim_type=value</code> per line; e.g. <code>age_over_21=true</code>)</label>
  <textarea name="values" rows="5" style="width:100%">{prefill}</textarea>
  <br/><button type="submit" class="btn-primary">Sign &amp; issue</button>
</form>"#,
        subject = html_escape(&req.subject_user_id),
        subject_domain = html_escape(&req.subject_domain),
        types = html_escape(&req.requested_claim_types.join(", ")),
        request = html_escape(form.request.trim()),
        prefill = html_escape(&prefill),
    );
    Ok(layout("Issue Attestation", &nav, &content))
}

#[derive(rocket::FromForm)]
pub struct IssueSignForm {
    request: String,
    values: String,
}

#[rocket::post("/policy-admin/issue/sign", data = "<form>")]
pub async fn issue_sign(
    _csrf: super::guard::SameOriginPost,
    pool: &State<DbPool>,
    net: &State<Net>,
    cookies: &CookieJar<'_>,
    form: rocket::form::Form<IssueSignForm>,
) -> Result<RawHtml<String>, Status> {
    let user_id = require_issue_page_access(pool.inner(), cookies)?;
    let nav = build_nav("policy", is_user_admin(pool.inner(), &user_id), true);

    let (signed, req) = match decode_request(&form.request) {
        Some(v) => v,
        None => return Err(Status::BadRequest),
    };
    // Re-verify before signing anything (the hidden field is client-supplied).
    if let Err(e) = verify_pasted(pool.inner(), net.inner(), &signed, &req).await {
        return Ok(layout(
            "Issue Attestation",
            &nav,
            &flash_html(None, Some(&e)),
        ));
    }

    use base64ct::{Base64UrlUnpadded, Encoding as _};
    let requested: std::collections::BTreeSet<&str> = req
        .requested_claim_types
        .iter()
        .map(String::as_str)
        .collect();
    let mut out = String::new();
    for line in form.values.lines() {
        let line = line.trim();
        let Some((ct, val)) = line.split_once('=') else {
            continue;
        };
        let (ct, val) = (ct.trim(), val.trim());
        if ct.is_empty() || val.is_empty() {
            continue;
        }
        if !requested.contains(ct) {
            out.push_str(&format!(
                r#"<div class="error">{} was not requested — skipped.</div>"#,
                html_escape(ct)
            ));
            continue;
        }
        if !attestation::user_can_issue_claim(pool.inner(), &user_id, ct) {
            out.push_str(&format!(
                r#"<div class="error">You are not authorized to issue {} — skipped.</div>"#,
                html_escape(ct)
            ));
            continue;
        }
        match attestation::issue_attested_claim(
            pool.inner(),
            &req.subject_user_id,
            &req.subject_domain,
            ct,
            val.as_bytes(),
        ) {
            Ok(claim) => {
                // Deposit it server-to-server to the subject's home domain (the
                // normal path — no user round-trip). If that domain is
                // unreachable, fall back to handing the user the signed claim.
                match super::rp::deposit_claim_to_domain(net.inner(), &req.subject_domain, &claim)
                    .await
                {
                    Ok(()) => out.push_str(&format!(
                        r#"<div class="success"><strong>{ct}</strong> = {val} — signed and deposited to {dom}.</div>"#,
                        ct = html_escape(ct),
                        val = html_escape(val),
                        dom = html_escape(&req.subject_domain),
                    )),
                    Err(e) => {
                        let cbor = liblinkkeys::generated::encode_claim(&claim);
                        let b64 = Base64UrlUnpadded::encode_string(&cbor);
                        let qr = qr_svg(&b64)
                            .unwrap_or_else(|| "<p>(too large for a QR code)</p>".to_string());
                        out.push_str(&format!(
                            r#"<div style="border:1px solid #eee;border-radius:6px;padding:12px;margin:12px 0">
<strong>{ct}</strong> = {val} — signed, but couldn't deposit ({err}). Hand this to the user:
<div style="max-width:240px">{qr}</div>
<textarea readonly rows="3" style="width:100%">{b64}</textarea>
</div>"#,
                            ct = html_escape(ct),
                            val = html_escape(val),
                            err = html_escape(&e),
                            qr = qr,
                            b64 = html_escape(&b64),
                        ));
                    }
                }
            }
            Err(e) => out.push_str(&format!(
                r#"<div class="error">{}: {}</div>"#,
                html_escape(ct),
                html_escape(&e.message)
            )),
        }
    }
    if out.is_empty() {
        out = "<p>Nothing issued — add at least one <code>claim_type=value</code> line.</p>"
            .to_string();
    }

    let content = format!(
        r#"<h1>Issued</h1>
<p>Each attestation is signed and deposited to the subject's home domain, where
anyone can verify your signature. If a domain was unreachable, hand the user the
claim shown and they can add it themselves.</p>
{out}
<p><a href="/policy-admin/issue">Issue another</a></p>"#,
        out = out,
    );
    Ok(layout("Issued", &nav, &content))
}
