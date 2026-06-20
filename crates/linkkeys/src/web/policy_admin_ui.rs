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
use liblinkkeys::generated::types::{SignedSigningRequest, SigningRequest};

fn require_manage_claims(pool: &DbPool, cookies: &CookieJar<'_>) -> Result<String, Status> {
    let user_id = get_session_user_id(cookies).ok_or(Status::Unauthorized)?;
    let domain = get_domain_name();
    if !authorization::user_has_permission(pool, &user_id, "manage_claims", "domain", &domain) {
        return Err(Status::Forbidden);
    }
    Ok(user_id)
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
    let user_id = require_manage_claims(pool.inner(), cookies)?;
    let admin_nav = is_user_admin(pool.inner(), &user_id);
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

    let content = format!(
        r#"{flash}
<h1>Policy Administration</h1>
<p>Control which claims this domain recognises, how they get signed, who you trust to attest them, and what is released to relying parties by default.</p>
<p><a href="/policy-admin/issue">Issue an attestation from a user's request →</a></p>

<h2>Claim types</h2>
<table><tr><th>Type</th><th>Label</th><th>Value</th><th>Set rule</th><th>Signing</th><th>Flags</th><th></th></tr>{reg_rows}</table>

<h3>Add / edit a claim type</h3>
<form method="POST" action="/policy-admin/claim-types">
  <label>Claim type (id)</label><input type="text" name="claim_type" required placeholder="e.g. pronouns"/>
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

<h2>Trusted issuers</h2>
<p>Domains whose signature you accept as attestation for a claim type (e.g. a government entity for <code>age_over_21</code>).</p>
<table><tr><th>Claim type</th><th>Issuer domain</th><th></th></tr>{issuer_rows}</table>
<form method="POST" action="/policy-admin/trusted-issuers">
  <input type="text" name="claim_type" required placeholder="claim type"/>
  <input type="text" name="issuer_domain" required placeholder="issuer.example"/>
  <button type="submit" class="btn-primary">Add issuer</button>
</form>

<h2>Release defaults</h2>
<p>Per-audience policy applied at consent. Audience <code>*</code> is the global default. <code>forced_allow</code> always releases; <code>forced_deny</code> never does (deny wins).</p>
<table><tr><th>Audience</th><th>Claim type</th><th>Disposition</th><th></th></tr>{release_rows}</table>
<form method="POST" action="/policy-admin/release">
  <input type="text" name="audience" required placeholder="* or app.example"/>
  <input type="text" name="claim_type" required placeholder="claim type"/>
  {disposition_sel}
  <button type="submit" class="btn-primary">Save rule</button>
</form>

<h2>Pending approvals</h2>
<table><tr><th>Subject</th><th>Claim</th><th>Value</th><th></th></tr>{approval_rows}</table>
"#,
        flash = flash,
        reg_rows = reg_rows,
        value_type_sel = select("value_type", VALUE_TYPES, "text"),
        set_rule_sel = select("set_rule", SET_RULES, "user_self"),
        signing_rule_sel = select("signing_rule", SIGNING_RULES, "self_signed"),
        issuer_rows = issuer_rows,
        release_rows = release_rows,
        disposition_sel = select(
            "disposition",
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
    let signed: SignedSigningRequest = ciborium::de::from_reader(&bytes[..]).ok()?;
    let req: SigningRequest = ciborium::de::from_reader(&signed.request[..]).ok()?;
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
    let user_id = require_manage_claims(pool.inner(), cookies)?;
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
    let user_id = require_manage_claims(pool.inner(), cookies)?;
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
    let user_id = require_manage_claims(pool.inner(), cookies)?;
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
                        let mut cbor = Vec::new();
                        if ciborium::ser::into_writer(&claim, &mut cbor).is_err() {
                            continue;
                        }
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
