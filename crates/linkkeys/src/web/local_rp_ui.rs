//! DNS-less local RP browser routes and UI (Phase 6 of
//! `dns-less-local-rp-design.md` at the repo root).
//!
//! Mirrors the existing DNS-pinned flow's shape (`GET /auth/authorize` ->
//! password form -> `POST /auth/consent`) as closely as the different wire
//! shapes allow: no session cookie carries the authenticated user across the
//! two legs — an IDP-signed login proof does (`super::mint_login_proof` /
//! `super::verify_login_proof`), reused verbatim with the local RP's
//! `fingerprint` standing in for `relying_party`, and a base64url encoding of
//! the login request's raw `nonce` bytes standing in for the DNS flow's
//! string nonce.
//!
//! Differences from the DNS-pinned flow, all deliberate (see the design doc):
//! - The local RP's descriptor carries its own keys (self-signed, SSH-host
//!   style), so there is no DNS/HTTP key fetch — every check here is local
//!   and synchronous.
//! - Domain admission policy (`disabled` / `admin-approval-required` /
//!   `allow-by-default`) and per-fingerprint approval status gate the flow
//!   before consent is ever shown; an unknown fingerprint under
//!   `admin-approval-required` ends in a *pending* notice page, not a
//!   redirect.
//! - The callback carries a claim-get ticket, not claims: on approval this
//!   module issues a ticket (`crate::services::local_rp::issue_ticket`),
//!   builds and domain-signs a `LocalRpCallbackPayload`, seals it with the
//!   negotiated AEAD suite (`liblinkkeys::crypto::AeadSuite::select_supported`
//!   over the descriptor's advertised suites), and redirects with
//!   `encrypted_token=` — never `encrypted_token` from the DNS flow's
//!   sealed-box-over-an-assertion shape.
//! - A missing/declined required claim is a hard IDP-side error page here
//!   (no redirect), unlike the DNS flow, which narrows the authorized set and
//!   lets the RP/app decide.

use rocket::form::FromForm;
use rocket::http::Status;
use rocket::response::content::RawHtml;
use rocket::response::Redirect;
use rocket::State;

use base64ct::{Base64UrlUnpadded, Encoding as _};
use rand::Rng;

use crate::conversions::{get_domain_name, html_escape};
use crate::db::DbPool;

use liblinkkeys::consent::ConsentScreen;
use liblinkkeys::crypto::AeadSuite;
use liblinkkeys::generated::types::{
    ClaimRequest, LocalRpDescriptor, LocalRpLoginRequest, RequestedClaim,
};
use liblinkkeys::i18n::{t, t_with};
use liblinkkeys::local_rp::LocalRpError;

use super::guard;
use super::nonce_store;

/// Lifetime of the encrypted callback payload (Wire Precision: "callback
/// lifetime is short, default 5 minutes").
const LOCAL_RP_CALLBACK_TTL_SECONDS: i64 = 300;
/// Lifetime of an issued claim-get ticket (design doc: "Valid for a bounded
/// window, default 1 hour").
const LOCAL_RP_TICKET_TTL_SECONDS: i64 = 3600;

// ---------------------------------------------------------------------
// Request validation
// ---------------------------------------------------------------------

/// Reasons a `signed_request` for `/auth/local-rp` may be rejected before any
/// login/consent step. Each maps to a friendly, i18n-cataloged message; none
/// of these ever redirect to the (unvalidated, possibly hostile) callback URL.
#[derive(Debug)]
enum ValidateLocalRpRequestError {
    Malformed,
    SignatureInvalid,
    Expired,
    CallbackSchemeInvalid,
    NoCommonSuite,
}

impl ValidateLocalRpRequestError {
    fn i18n_key(&self) -> &'static str {
        match self {
            Self::Malformed => "local_rp.error.malformed",
            Self::SignatureInvalid => "local_rp.error.signature_invalid",
            Self::Expired => "local_rp.error.expired",
            Self::CallbackSchemeInvalid => "local_rp.error.bad_scheme",
            Self::NoCommonSuite => "local_rp.error.no_common_suite",
        }
    }
}

/// True when `url` starts with an `http://` or `https://` scheme, exactly
/// (Wire Precision / "Callback URL Rules": every other scheme — `javascript:`,
/// `data:`, custom app schemes — is rejected outright).
fn callback_scheme_ok(url: &str) -> bool {
    match url.split_once("://") {
        Some((scheme, _)) => {
            let scheme = scheme.to_ascii_lowercase();
            scheme == "http" || scheme == "https"
        }
        None => false,
    }
}

/// The host (and port, if present) a callback URL will be sent back to, for
/// consent-screen display only (Consent UI Requirements: "the callback host
/// the browser will be sent back to"). Best-effort: falls back to the whole
/// URL if it cannot be parsed, which is still safe to display verbatim (it's
/// never used for a security decision — the signed payload carries the
/// authoritative `callback_url`).
fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://")?.1;
    let host_with_extras = after_scheme.split(['/', '?', '#']).next()?;
    if host_with_extras.is_empty() {
        return None;
    }
    let host = host_with_extras
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(host_with_extras);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// First 16 hex chars of a fingerprint, for compact display (design doc: "show
/// a short prefix (first 16 hex chars) with the full value available on
/// demand").
fn short_fingerprint(fp: &str) -> &str {
    &fp[..fp.len().min(16)]
}

/// Decode + fully verify a `signed_request` parameter: envelope signature,
/// nested descriptor (signature, fingerprint binding), timestamps (both
/// request and descriptor, clock-skew tolerant), callback URL scheme, and
/// AEAD suite negotiability. Everything needed to proceed (or reject) is
/// resolved here so every route re-validates identically rather than trusting
/// a previous step's output.
fn validate_signed_local_rp_request(
    signed_request_param: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(LocalRpLoginRequest, LocalRpDescriptor, AeadSuite), ValidateLocalRpRequestError> {
    let signed =
        liblinkkeys::encoding::signed_local_rp_login_request_from_url_param(signed_request_param)
            .map_err(|_| ValidateLocalRpRequestError::Malformed)?;

    let request = liblinkkeys::local_rp::verify_local_rp_login_request(
        &signed,
        now,
        liblinkkeys::local_rp::DEFAULT_CLOCK_SKEW_SECONDS,
    )
    .map_err(|e| match e {
        LocalRpError::Decode(_) => ValidateLocalRpRequestError::Malformed,
        LocalRpError::Expired | LocalRpError::NotYetValid => ValidateLocalRpRequestError::Expired,
        _ => ValidateLocalRpRequestError::SignatureInvalid,
    })?;

    let descriptor =
        liblinkkeys::generated::decode_local_rp_descriptor(&request.descriptor.descriptor)
            .map_err(|_| ValidateLocalRpRequestError::Malformed)?;

    if !callback_scheme_ok(&request.callback_url) {
        return Err(ValidateLocalRpRequestError::CallbackSchemeInvalid);
    }

    let suite = AeadSuite::select_supported(&descriptor.supported_suites)
        .ok_or(ValidateLocalRpRequestError::NoCommonSuite)?;

    Ok((request, descriptor, suite))
}

/// Pre-authentication gate: policy-disabled and denied/revoked fingerprints
/// are rejected before ever asking for a password (design doc step 8 happens
/// before step 9's "user authenticates and consents"). Returns the friendly
/// message to show on an IDP error page, or `Ok(())` to proceed to login.
fn precheck_local_rp_gate(pool: &DbPool, fingerprint: &str, locale: &str) -> Result<(), String> {
    let policy = pool
        .effective_local_rp_policy()
        .map_err(|_| t(locale, "local_rp.error.internal").to_string())?;
    if policy == crate::db::local_rp::POLICY_DISABLED {
        return Err(t(locale, "local_rp.error.policy_disabled").to_string());
    }
    if let Some(rp) = pool
        .find_local_rp(fingerprint)
        .map_err(|_| t(locale, "local_rp.error.internal").to_string())?
    {
        if rp.status == crate::db::local_rp::STATUS_DENIED
            || rp.status == crate::db::local_rp::STATUS_REVOKED
        {
            return Err(t(locale, "local_rp.error.rejected").to_string());
        }
    }
    Ok(())
}

/// Outcome of resolving an authenticated login attempt against domain policy
/// and the local RP approval registry (design doc step 8, post-authentication
/// half): either the login may proceed to consent (carrying the resolved
/// registry row, for its `created_at` "first seen" display), it must wait for
/// admin approval, or it is rejected outright.
enum Admission {
    Approved(Box<crate::db::models::LocalRp>),
    Pending,
    ErrorPage(String),
}

/// Resolve admission for an authenticated user's attempt (must only be
/// called after the caller has authenticated `user_id`): applies domain
/// policy plus the pending-queue guard / allow-by-default auto-approval from
/// `crate::services::local_rp`, per the design's status matrix:
/// disabled -> reject; denied/revoked fingerprint -> reject; approved
/// fingerprint -> continue; unknown fingerprint -> pending (admin-approval)
/// or auto-approved (allow-by-default); known-but-pending fingerprint ->
/// refresh last-seen/drift and stay pending (unless an admin has since acted).
fn resolve_local_rp_admission(
    pool: &DbPool,
    user_id: &str,
    descriptor: &LocalRpDescriptor,
    locale: &str,
) -> Admission {
    let policy = match pool.effective_local_rp_policy() {
        Ok(p) => p,
        Err(_) => return Admission::ErrorPage(t(locale, "local_rp.error.internal").to_string()),
    };
    if policy == crate::db::local_rp::POLICY_DISABLED {
        return Admission::ErrorPage(t(locale, "local_rp.error.policy_disabled").to_string());
    }

    let existing = match pool.find_local_rp(&descriptor.fingerprint) {
        Ok(e) => e,
        Err(_) => return Admission::ErrorPage(t(locale, "local_rp.error.internal").to_string()),
    };

    match existing {
        Some(rp)
            if rp.status == crate::db::local_rp::STATUS_DENIED
                || rp.status == crate::db::local_rp::STATUS_REVOKED =>
        {
            Admission::ErrorPage(t(locale, "local_rp.error.rejected").to_string())
        }
        Some(rp) if rp.status == crate::db::local_rp::STATUS_APPROVED => {
            Admission::Approved(Box::new(rp))
        }
        Some(_pending) => refresh_pending_attempt(pool, user_id, descriptor, locale),
        None if policy == crate::db::local_rp::POLICY_ALLOW_BY_DEFAULT => {
            match crate::services::local_rp::record_allow_by_default_login(
                pool,
                user_id,
                &descriptor.fingerprint,
                &descriptor.signing_public_key,
                &descriptor.encryption_public_key,
                &descriptor.app_name,
                descriptor.local_domain_hint.as_deref(),
            ) {
                Ok(rp) if rp.status == crate::db::local_rp::STATUS_APPROVED => {
                    Admission::Approved(Box::new(rp))
                }
                Ok(rp)
                    if rp.status == crate::db::local_rp::STATUS_DENIED
                        || rp.status == crate::db::local_rp::STATUS_REVOKED =>
                {
                    Admission::ErrorPage(t(locale, "local_rp.error.rejected").to_string())
                }
                Ok(_) => Admission::Pending,
                Err(_) => Admission::ErrorPage(t(locale, "local_rp.error.internal").to_string()),
            }
        }
        None => match crate::services::local_rp::record_login_attempt(
            pool,
            user_id,
            &descriptor.fingerprint,
            &descriptor.signing_public_key,
            &descriptor.encryption_public_key,
            &descriptor.app_name,
            descriptor.local_domain_hint.as_deref(),
        ) {
            Ok(_) => Admission::Pending,
            Err(
                crate::services::local_rp::PendingAttemptError::PendingCapReached
                | crate::services::local_rp::PendingAttemptError::PerUserPendingCapReached,
            ) => Admission::ErrorPage(t(locale, "local_rp.error.pending_cap_reached").to_string()),
            Err(_) => Admission::ErrorPage(t(locale, "local_rp.error.internal").to_string()),
        },
    }
}

/// Refresh an already-pending (or otherwise already-known, non-terminal)
/// fingerprint's last-seen/drift on a repeat authenticated attempt, then
/// re-check its resulting status — an admin may have acted between attempts.
fn refresh_pending_attempt(
    pool: &DbPool,
    user_id: &str,
    descriptor: &LocalRpDescriptor,
    locale: &str,
) -> Admission {
    match crate::services::local_rp::record_login_attempt(
        pool,
        user_id,
        &descriptor.fingerprint,
        &descriptor.signing_public_key,
        &descriptor.encryption_public_key,
        &descriptor.app_name,
        descriptor.local_domain_hint.as_deref(),
    ) {
        Ok(crate::services::local_rp::PendingAttemptOutcome::Refreshed { local_rp, drift }) => {
            if !drift.is_empty() {
                log::warn!(
                    "local RP {} metadata drift on repeat attempt: {:?}",
                    descriptor.fingerprint,
                    drift.iter().map(|d| d.field).collect::<Vec<_>>()
                );
            }
            match local_rp.status.as_str() {
                s if s == crate::db::local_rp::STATUS_APPROVED => {
                    Admission::Approved(Box::new(local_rp))
                }
                s if s == crate::db::local_rp::STATUS_DENIED
                    || s == crate::db::local_rp::STATUS_REVOKED =>
                {
                    Admission::ErrorPage(t(locale, "local_rp.error.rejected").to_string())
                }
                _ => Admission::Pending,
            }
        }
        Ok(crate::services::local_rp::PendingAttemptOutcome::Created(_)) => Admission::Pending,
        Err(_) => Admission::ErrorPage(t(locale, "local_rp.error.internal").to_string()),
    }
}

// ---------------------------------------------------------------------
// Claim request / consent screen
// ---------------------------------------------------------------------

/// A requested claim type's display datatype, resolved from this domain's
/// claim-type registry (`ClaimTypePolicy::value_type`), falling back to
/// plain text for a type the domain has never registered. Unlike the
/// DNS-pinned flow (whose RP supplies a per-claim datatype in its request),
/// a local RP's request only carries bare claim-type names.
fn claim_datatype(pool: &DbPool, claim_type: &str) -> String {
    pool.find_claim_policy(claim_type)
        .ok()
        .flatten()
        .map(|p| p.value_type)
        .unwrap_or_else(|| "text".to_string())
}

/// Build a `ClaimRequest` (required/optional `RequestedClaim` rows, each with
/// a resolved datatype) from a `LocalRpLoginRequest`'s bare
/// `required_claims`/`requested_claims` string lists, so the existing
/// consent-screen machinery (`liblinkkeys::consent`) can be reused verbatim.
fn build_claim_request(pool: &DbPool, requested: &[String], required: &[String]) -> ClaimRequest {
    use std::collections::BTreeSet;

    let required_set: BTreeSet<&str> = required.iter().map(String::as_str).collect();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut req_list = Vec::new();
    let mut opt_list = Vec::new();

    for ct in required.iter().chain(requested.iter()) {
        if !seen.insert(ct.as_str()) {
            continue;
        }
        let rc = RequestedClaim {
            claim_type: ct.clone(),
            datatype: claim_datatype(pool, ct),
        };
        if required_set.contains(ct.as_str()) {
            req_list.push(rc);
        } else {
            opt_list.push(rc);
        }
    }

    ClaimRequest {
        required: req_list,
        optional: opt_list,
    }
}

fn resolve_labels(
    pool: &DbPool,
    screen: &ConsentScreen,
    locale: &str,
) -> std::collections::HashMap<String, String> {
    let mut labels = std::collections::HashMap::new();
    for row in &screen.rows {
        if !labels.contains_key(&row.claim_type) {
            if let Ok((label, _)) = pool.resolved_label(&row.claim_type, locale) {
                labels.insert(row.claim_type.clone(), label);
            }
        }
    }
    labels
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

fn render_local_rp_login_form(
    signed_request: &str,
    descriptor: &LocalRpDescriptor,
    username: &str,
    locale: &str,
    error: Option<&str>,
) -> RawHtml<String> {
    let error_html = error
        .map(|e| format!(r#"<p class="error">{}</p>"#, html_escape(e)))
        .unwrap_or_default();

    let subtitle = t_with(
        locale,
        "local_rp.login.subtitle",
        &[("app", &descriptor.app_name)],
    );

    RawHtml(format!(
        r#"<!DOCTYPE html>
<html lang="{lang}"><head><title>{title}</title>
<style>
body {{ font-family: sans-serif; max-width: 400px; margin: 80px auto; }}
input {{ display: block; width: 100%; padding: 8px; margin: 8px 0; box-sizing: border-box; }}
button {{ padding: 10px 20px; margin-top: 12px; }}
.error {{ color: red; }}
</style>
</head>
<body>
<h2>{title}</h2>
<p>{domain_label}: <strong>{domain}</strong></p>
<p>{subtitle}</p>
{error}
<form method="POST" action="/auth/local-rp">
  <input type="hidden" name="signed_request" value="{sr}" />
  <label>{username_label}</label>
  <input type="text" name="username" value="{username}" autofocus />
  <label>{password_label}</label>
  <input type="password" name="password" />
  <button type="submit">{submit}</button>
</form>
</body>
</html>"#,
        lang = html_escape(locale),
        title = html_escape(t(locale, "login.title")),
        domain_label = html_escape(t(locale, "login.domain_label")),
        domain = html_escape(&get_domain_name()),
        subtitle = html_escape(&subtitle),
        error = error_html,
        sr = html_escape(signed_request),
        username_label = html_escape(t(locale, "login.username_label")),
        username = html_escape(username),
        password_label = html_escape(t(locale, "login.password_label")),
        submit = html_escape(t(locale, "login.submit")),
    ))
}

fn render_local_rp_pending_page(locale: &str, app_name: &str) -> RawHtml<String> {
    super::render_notice_page(
        locale,
        t(locale, "local_rp.pending.title"),
        &t_with(locale, "local_rp.pending.body", &[("app", app_name)]),
    )
}

/// Render the local-RP consent screen. On top of the standard claim rows
/// (identical machinery to `/auth/consent`), this carries the additional
/// security context the design's "Consent UI Requirements" mandate: the app
/// name labeled unverified, a plain-language non-DNS-verified warning, the
/// callback host, the short (and full) fingerprint, and the first-seen date.
#[allow(clippy::too_many_arguments)]
fn render_local_rp_consent_form(
    pool: &DbPool,
    signed_request: &str,
    login_proof: &str,
    descriptor: &LocalRpDescriptor,
    rp_row: &crate::db::models::LocalRp,
    callback_host: &str,
    screen: &ConsentScreen,
    labels: &std::collections::HashMap<String, String>,
    locale: &str,
    error: Option<&str>,
) -> RawHtml<String> {
    use liblinkkeys::consent::PolicyDisposition;

    let domain = get_domain_name();
    let label_of =
        |ct: &str| -> String { labels.get(ct).cloned().unwrap_or_else(|| ct.to_string()) };

    let error_html = error
        .map(|e| format!(r#"<p class="error">{}</p>"#, html_escape(e)))
        .unwrap_or_default();

    let security_html = format!(
        r#"<div style="background:#fff7df;border:1px solid #ead39a;padding:10px 14px;border-radius:6px;margin-bottom:12px;">
<p style="margin:0 0 6px;"><strong>{unverified}</strong></p>
<p style="margin:0 0 6px;">{warning}</p>
<p style="margin:0;">{host_label} <code>{host}</code></p>
<p style="margin:4px 0 0;">{fp_label} <code>{short_fp}</code> &mdash; {full_fp_label} <code>{full_fp}</code></p>
<p style="margin:4px 0 0;">{first_seen_label} {first_seen}</p>
</div>"#,
        unverified = html_escape(&t_with(
            locale,
            "local_rp.consent.unverified_badge",
            &[("app", &descriptor.app_name)]
        )),
        warning = html_escape(t(locale, "local_rp.consent.warning")),
        host_label = html_escape(t(locale, "local_rp.consent.callback_host_label")),
        host = html_escape(callback_host),
        fp_label = html_escape(t(locale, "local_rp.consent.fingerprint_label")),
        short_fp = html_escape(short_fingerprint(&descriptor.fingerprint)),
        full_fp_label = html_escape(t(locale, "local_rp.consent.fingerprint_full_label")),
        full_fp = html_escape(&descriptor.fingerprint),
        first_seen_label = html_escape(t(locale, "local_rp.consent.first_seen_label")),
        first_seen = html_escape(&rp_row.created_at),
    );

    let mut rows = String::new();
    for row in &screen.rows {
        let ct = html_escape(&row.claim_type);
        let name = html_escape(&label_of(&row.claim_type));
        let need = if row.required {
            t(locale, "consent.required")
        } else {
            t(locale, "consent.optional")
        };
        let avail = if row.available {
            String::new()
        } else if row.policy != PolicyDisposition::ForcedDeny
            && super::missing_claim_user_settable(pool, &row.claim_type)
        {
            let input_type = super::input_type_for_datatype(&row.datatype);
            format!(
                r#"
<div style="margin:6px 0 0 28px;">
  <input type="hidden" name="claim_type_to_set" value="{ct}" />
  <input type="{input_type}" name="claim_value_to_set" placeholder="{placeholder}" style="display:block;width:100%;max-width:320px;padding:6px 8px;box-sizing:border-box;" />
</div>"#,
                ct = ct,
                input_type = input_type,
                placeholder = html_escape(t(locale, "consent.add_value_placeholder")),
            )
        } else {
            format!(
                r#" <span style="color:#a60">({})</span>"#,
                html_escape(t(locale, "consent.no_value"))
            )
        };

        let control = match row.policy {
            PolicyDisposition::ForcedAllow => format!(
                r#"<input type="checkbox" checked disabled /> <em>{}</em>"#,
                html_escape(&t_with(
                    locale,
                    "consent.forced_allow",
                    &[("service", &domain)]
                ))
            ),
            PolicyDisposition::ForcedDeny => format!(
                r#"<input type="checkbox" disabled /> <em>{}</em>"#,
                html_escape(&t_with(
                    locale,
                    "consent.forced_deny",
                    &[("service", &domain)]
                ))
            ),
            PolicyDisposition::User => {
                let checked = if row.default_granted() { "checked" } else { "" };
                format!(
                    r#"<input type="checkbox" name="grant" value="{ct}" {checked} />"#,
                    ct = ct,
                    checked = checked,
                )
            }
        };

        rows.push_str(&format!(
            r#"<li>{control} <strong>{name}</strong> <small>({need})</small>{avail}</li>"#,
            control = control,
            name = name,
            need = html_escape(need),
            avail = avail,
        ));
    }

    RawHtml(format!(
        r#"<!DOCTYPE html>
<html lang="{lang}"><head><title>LinkKeys</title>
<style>
body {{ font-family: sans-serif; max-width: 480px; margin: 60px auto; }}
ul {{ list-style: none; padding: 0; }}
li {{ padding: 8px 0; border-bottom: 1px solid #eee; }}
button {{ padding: 10px 20px; margin-top: 16px; }}
.btn-cancel {{ background: none; border: none; color: #666; text-decoration: underline; cursor: pointer; margin-left: 12px; }}
.error {{ color: red; }}
em {{ color: #555; }}
</style>
</head>
<body>
<h2>{title}</h2>
{security}
<p>{subtitle}</p>
{error}
<form method="POST" action="/auth/local-rp/consent">
  <input type="hidden" name="signed_request" value="{sr}" />
  <input type="hidden" name="login_proof" value="{proof}" />
  <ul>
{rows}
  </ul>
  <button type="submit" name="decision" value="share">{submit}</button>
  <button type="submit" name="decision" value="cancel" class="btn-cancel" formnovalidate>{cancel}</button>
</form>
</body>
</html>"#,
        lang = html_escape(locale),
        title = html_escape(&t_with(
            locale,
            "consent.title",
            &[("app", &descriptor.app_name)]
        )),
        security = security_html,
        subtitle = html_escape(&t_with(
            locale,
            "consent.subtitle",
            &[("app", &descriptor.app_name), ("domain", &domain)]
        )),
        error = error_html,
        sr = html_escape(signed_request),
        proof = html_escape(login_proof),
        rows = rows,
        submit = html_escape(t(locale, "consent.submit")),
        cancel = html_escape(t(locale, "consent.cancel")),
    ))
}

// ---------------------------------------------------------------------
// Finalization: ticket issue + signed/sealed callback
// ---------------------------------------------------------------------

/// Complete an approved local-RP login: enforce the required-claims gate
/// (design doc: a missing/declined required claim is a hard IDP-side error,
/// no redirect), burn the request's single-use nonce, persist a standing
/// consent grant (audience = the local RP fingerprint, so a repeat login can
/// skip re-consent exactly like the DNS flow), issue a claim-get ticket,
/// build+sign the domain-signed callback payload, seal it with the
/// already-negotiated AEAD suite, and produce the callback redirect URL.
#[allow(clippy::too_many_arguments)]
fn finalize_local_rp_login(
    pool: &DbPool,
    nonces: &nonce_store::NonceStore,
    locale: &str,
    user: &crate::db::models::User,
    request: &LocalRpLoginRequest,
    descriptor: &LocalRpDescriptor,
    suite: AeadSuite,
    req: &ClaimRequest,
    authorized_claims: &[String],
) -> Result<String, String> {
    let all_required_satisfied = request
        .required_claims
        .iter()
        .all(|rc| authorized_claims.iter().any(|a| a == rc));
    if !all_required_satisfied {
        return Err(t(locale, "local_rp.error.required_claim_missing").to_string());
    }

    // Single-use: burn the request's nonce now, at ticket-issuance time, so
    // an abandoned consent screen doesn't consume the login request early.
    // Scoped to the descriptor's fingerprint (not nonce bytes alone): two
    // unrelated local RPs that happen to choose colliding nonce bytes must
    // not spuriously burn each other's login — this is availability-only
    // (the actual replay/identity guarantees come from the signature and
    // fingerprint binding elsewhere), but an unscoped key could otherwise
    // reject a legitimate login purely by coincidence.
    let nonce_key = format!(
        "local-rp:{}:{}",
        descriptor.fingerprint,
        Base64UrlUnpadded::encode_string(&request.nonce)
    );
    if !nonces.record(&nonce_key) {
        return Err(t(locale, "local_rp.error.replayed").to_string());
    }

    let requested = super::requested_types(req);
    if !requested.is_empty() {
        let now = chrono::Utc::now();
        let issued_at = now.to_rfc3339();
        let expires_at =
            (now + chrono::Duration::seconds(super::consent_ttl_seconds())).to_rfc3339();
        let grant_id = uuid::Uuid::now_v7().to_string();
        let signed = super::sign_consent_grant_for_user(
            pool,
            &grant_id,
            &user.id,
            &descriptor.fingerprint,
            authorized_claims,
            &issued_at,
            &expires_at,
        )
        .map_err(|_| t(locale, "local_rp.error.internal").to_string())?;
        let grant_bytes = liblinkkeys::generated::encode_signed_consent_grant(&signed);
        pool.upsert_consent_grant(
            &grant_id,
            &user.id,
            &get_domain_name(),
            &descriptor.fingerprint,
            authorized_claims,
            &requested,
            &grant_bytes,
            None,
            &issued_at,
            &expires_at,
        )
        .map_err(|_| t(locale, "local_rp.error.internal").to_string())?;
    }

    // Issue the claim-get ticket: 32 random bytes, opaque; only the SHA-256
    // hex is ever stored (design doc / Wire Precision: "Claim ticket bytes").
    let mut raw_ticket = [0u8; 32];
    rand::thread_rng().fill(&mut raw_ticket);
    let ticket_hash = liblinkkeys::crypto::fingerprint(&raw_ticket);
    let ticket_expires_at =
        chrono::Utc::now() + chrono::Duration::seconds(LOCAL_RP_TICKET_TTL_SECONDS);
    crate::services::local_rp::issue_ticket(
        pool,
        &ticket_hash,
        &descriptor.fingerprint,
        &user.id,
        &get_domain_name(),
        authorized_claims,
        ticket_expires_at,
    )
    .map_err(|_| t(locale, "local_rp.error.internal").to_string())?;

    let now = chrono::Utc::now();
    let issued_at = now.to_rfc3339();
    let expires_at = (now + chrono::Duration::seconds(LOCAL_RP_CALLBACK_TTL_SECONDS)).to_rfc3339();
    let payload = liblinkkeys::local_rp::build_local_rp_callback_payload(
        &user.id,
        &get_domain_name(),
        raw_ticket.to_vec(),
        &descriptor.fingerprint,
        &request.callback_url,
        request.nonce.clone(),
        request.state.clone(),
        &issued_at,
        &expires_at,
    );

    let domain_keys = pool
        .list_active_domain_keys()
        .map_err(|_| t(locale, "local_rp.error.internal").to_string())?;
    let dk = super::pick_active_signing_key(&domain_keys)
        .ok_or_else(|| t(locale, "local_rp.error.internal").to_string())?;
    let passphrase = std::env::var("DOMAIN_KEY_PASSPHRASE")
        .map_err(|_| t(locale, "local_rp.error.internal").to_string())?;
    let sk_bytes =
        liblinkkeys::crypto::decrypt_private_key(&dk.private_key_encrypted, passphrase.as_bytes())
            .map_err(|_| t(locale, "local_rp.error.internal").to_string())?;
    let algorithm = liblinkkeys::crypto::SigningAlgorithm::parse_str(&dk.algorithm)
        .ok_or_else(|| t(locale, "local_rp.error.internal").to_string())?;
    let signed_payload = liblinkkeys::local_rp::sign_local_rp_callback_payload(
        &payload, &dk.id, algorithm, &sk_bytes,
    )
    .map_err(|_| t(locale, "local_rp.error.internal").to_string())?;

    let enc_pk: [u8; 32] = descriptor
        .encryption_public_key
        .as_slice()
        .try_into()
        .map_err(|_| t(locale, "local_rp.error.internal").to_string())?;
    let encrypted = liblinkkeys::local_rp::seal_local_rp_callback(
        &signed_payload,
        suite,
        &enc_pk,
        &descriptor.fingerprint,
        request.nonce.clone(),
        request.state.clone(),
        &issued_at,
        &expires_at,
    )
    .map_err(|_| t(locale, "local_rp.error.internal").to_string())?;

    let encoded = liblinkkeys::encoding::local_rp_encrypted_callback_to_url_param(&encrypted)
        .map_err(|_| t(locale, "local_rp.error.internal").to_string())?;

    let separator = if request.callback_url.contains('?') {
        "&"
    } else {
        "?"
    };
    Ok(format!(
        "{}{}encrypted_token={}",
        request.callback_url, separator, encoded
    ))
}

/// Shared by the login-submission shortcut (a prior standing grant already
/// covers this request) and, indirectly, the consent-submission route: mint a
/// login proof and render the consent screen, or skip straight to
/// finalization when nothing new needs to be asked.
#[allow(clippy::too_many_arguments)]
fn proceed_to_consent_or_finalize(
    pool: &DbPool,
    nonces: &nonce_store::NonceStore,
    locale: &str,
    user: &crate::db::models::User,
    request: &LocalRpLoginRequest,
    descriptor: &LocalRpDescriptor,
    suite: AeadSuite,
    rp_row: &crate::db::models::LocalRp,
    signed_request_param: &str,
) -> Result<Redirect, RawHtml<String>> {
    let req = build_claim_request(pool, &request.requested_claims, &request.required_claims);
    let policy = match super::domain_policy_for(pool, &descriptor.fingerprint) {
        Ok(p) => p,
        Err(_) => {
            return Err(super::render_error_page(t(
                locale,
                "local_rp.error.internal",
            )))
        }
    };

    if let Some(prior) = pool
        .find_active_consent_grant(&user.id, &descriptor.fingerprint)
        .ok()
        .flatten()
    {
        if super::grant_covers(&prior, &req) {
            let authorized =
                liblinkkeys::consent::compute_authorized_claims(&req, &prior.claim_types, &policy);
            if super::first_missing_user_required(&req, &authorized, &policy).is_none()
                && super::first_authorized_required_without_value(pool, &user.id, &req, &authorized)
                    .is_none()
            {
                let authorized =
                    match super::filter_authorized_to_active_values(pool, &user.id, &authorized) {
                        Ok(a) => a,
                        Err(_) => {
                            return Err(super::render_error_page(t(
                                locale,
                                "local_rp.error.internal",
                            )))
                        }
                    };
                return finalize_local_rp_login(
                    pool,
                    nonces,
                    locale,
                    user,
                    request,
                    descriptor,
                    suite,
                    &req,
                    &authorized,
                )
                .map(Redirect::found)
                .map_err(|e| super::render_error_page(&e));
            }
        }
    }

    let nonce_b64 = Base64UrlUnpadded::encode_string(&request.nonce);
    let proof = match super::mint_login_proof(pool, &user.id, &nonce_b64, &descriptor.fingerprint) {
        Ok(p) => p,
        Err(_) => {
            return Err(super::render_error_page(t(
                locale,
                "local_rp.error.internal",
            )))
        }
    };
    let screen =
        super::build_consent_screen(pool, &user.id, &descriptor.fingerprint, &req, &policy);
    let labels = resolve_labels(pool, &screen, locale);
    let callback_host =
        extract_host(&request.callback_url).unwrap_or_else(|| request.callback_url.clone());
    Err(render_local_rp_consent_form(
        pool,
        signed_request_param,
        &proof,
        descriptor,
        rp_row,
        &callback_host,
        &screen,
        &labels,
        locale,
        None,
    ))
}

// ---------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------

#[rocket::get("/auth/local-rp?<signed_request>")]
pub(super) fn auth_local_rp_get(
    pool: &State<DbPool>,
    locale: guard::Locale,
    signed_request: Option<&str>,
) -> Result<RawHtml<String>, Status> {
    let sr = signed_request.ok_or(Status::BadRequest)?;
    let now = chrono::Utc::now();
    let (_request, descriptor, _suite) = match validate_signed_local_rp_request(sr, now) {
        Ok(v) => v,
        Err(e) => return Ok(super::render_error_page(t(&locale.0, e.i18n_key()))),
    };
    if let Err(msg) = precheck_local_rp_gate(pool, &descriptor.fingerprint, &locale.0) {
        return Ok(super::render_error_page(&msg));
    }
    Ok(render_local_rp_login_form(
        sr,
        &descriptor,
        "",
        &locale.0,
        None,
    ))
}

#[derive(FromForm)]
pub(super) struct LocalRpAuthorizeForm {
    username: String,
    password: String,
    signed_request: Option<String>,
}

#[rocket::post("/auth/local-rp", data = "<form>")]
pub(super) fn auth_local_rp_post(
    pool: &State<DbPool>,
    nonces: &State<nonce_store::NonceStore>,
    locale: guard::Locale,
    form: rocket::form::Form<LocalRpAuthorizeForm>,
) -> Result<Redirect, RawHtml<String>> {
    let Some(sr) = form.signed_request.as_deref() else {
        return Err(super::render_error_page(t(
            &locale.0,
            "local_rp.error.malformed",
        )));
    };
    let now = chrono::Utc::now();
    let (request, descriptor, suite) = match validate_signed_local_rp_request(sr, now) {
        Ok(v) => v,
        Err(e) => return Err(super::render_error_page(t(&locale.0, e.i18n_key()))),
    };
    if let Err(msg) = precheck_local_rp_gate(pool, &descriptor.fingerprint, &locale.0) {
        return Err(super::render_error_page(&msg));
    }

    let render_form_error = |msg: &str| {
        render_local_rp_login_form(sr, &descriptor, &form.username, &locale.0, Some(msg))
    };

    if !crate::services::ratelimit::LOGIN.check(&form.username.trim().to_lowercase()) {
        return Err(render_form_error(t(
            &locale.0,
            "local_rp.login.rate_limited",
        )));
    }

    let authenticator = crate::services::auth::PasswordAuthenticator::new(pool.inner().clone());
    let user = match crate::services::auth::Authenticator::authenticate(
        &authenticator,
        &form.username,
        &form.password,
    ) {
        Ok(u) => u,
        Err(_) => {
            return Err(render_form_error(t(
                &locale.0,
                "local_rp.login.invalid_credentials",
            )))
        }
    };
    if user.is_admin_account {
        return Err(super::render_error_page(t(
            &locale.0,
            "local_rp.login.admin_account_blocked",
        )));
    }

    match resolve_local_rp_admission(pool, &user.id, &descriptor, &locale.0) {
        Admission::ErrorPage(msg) => Err(super::render_error_page(&msg)),
        Admission::Pending => Err(render_local_rp_pending_page(
            &locale.0,
            &descriptor.app_name,
        )),
        Admission::Approved(rp_row) => proceed_to_consent_or_finalize(
            pool,
            nonces,
            &locale.0,
            &user,
            &request,
            &descriptor,
            suite,
            &rp_row,
            sr,
        ),
    }
}

#[derive(FromForm)]
pub(super) struct LocalRpConsentForm {
    signed_request: String,
    login_proof: String,
    grant: Vec<String>,
    claim_type_to_set: Vec<String>,
    claim_value_to_set: Vec<String>,
    decision: Option<String>,
}

#[rocket::post("/auth/local-rp/consent", data = "<form>")]
pub(super) fn auth_local_rp_consent_post(
    pool: &State<DbPool>,
    nonces: &State<nonce_store::NonceStore>,
    locale: guard::Locale,
    form: rocket::form::Form<LocalRpConsentForm>,
) -> Result<Redirect, RawHtml<String>> {
    if form.decision.as_deref() == Some("cancel") {
        return Err(super::render_notice_page(
            &locale.0,
            t(&locale.0, "consent.cancelled_title"),
            t(&locale.0, "consent.cancelled_body"),
        ));
    }

    let Ok((user_id, proof_nonce, proof_fp)) = super::verify_login_proof(pool, &form.login_proof)
    else {
        return Err(super::render_error_page(t(
            &locale.0,
            "local_rp.error.login_proof_invalid",
        )));
    };

    let now = chrono::Utc::now();
    let (request, descriptor, suite) =
        match validate_signed_local_rp_request(&form.signed_request, now) {
            Ok(v) => v,
            Err(e) => return Err(super::render_error_page(t(&locale.0, e.i18n_key()))),
        };

    let nonce_b64 = Base64UrlUnpadded::encode_string(&request.nonce);
    if proof_nonce != nonce_b64 || proof_fp != descriptor.fingerprint {
        return Err(super::render_error_page(t(
            &locale.0,
            "local_rp.error.login_proof_invalid",
        )));
    }

    let user = match pool.find_user_by_id(&user_id) {
        Ok(u) => u,
        Err(_) => {
            return Err(super::render_error_page(t(
                &locale.0,
                "local_rp.error.internal",
            )))
        }
    };

    // Race safety: the domain's admission policy may have been disabled
    // between rendering consent and this submission (mirrors the
    // per-fingerprint status recheck immediately below).
    match pool.effective_local_rp_policy() {
        Ok(p) if p == crate::db::local_rp::POLICY_DISABLED => {
            return Err(super::render_error_page(t(
                &locale.0,
                "local_rp.error.policy_disabled",
            )))
        }
        Ok(_) => {}
        Err(_) => {
            return Err(super::render_error_page(t(
                &locale.0,
                "local_rp.error.internal",
            )))
        }
    }

    // Race safety: the fingerprint must still be approved (an admin may have
    // revoked/denied it between rendering consent and this submission).
    let existing = match pool.find_local_rp(&descriptor.fingerprint) {
        Ok(Some(rp)) if rp.status == crate::db::local_rp::STATUS_APPROVED => rp,
        _ => {
            return Err(super::render_error_page(t(
                &locale.0,
                "local_rp.error.rejected",
            )))
        }
    };

    let req = build_claim_request(pool, &request.requested_claims, &request.required_claims);
    let policy = match super::domain_policy_for(pool, &descriptor.fingerprint) {
        Ok(p) => p,
        Err(_) => {
            return Err(super::render_error_page(t(
                &locale.0,
                "local_rp.error.internal",
            )))
        }
    };
    let authorized = liblinkkeys::consent::compute_authorized_claims(&req, &form.grant, &policy);
    let authorized = match super::store_inline_claim_values(
        pool,
        &user.id,
        &req,
        &authorized,
        &form.claim_type_to_set,
        &form.claim_value_to_set,
    ) {
        Ok(a) => a,
        Err(e) => {
            let screen =
                super::build_consent_screen(pool, &user.id, &descriptor.fingerprint, &req, &policy);
            let labels = resolve_labels(pool, &screen, &locale.0);
            let callback_host =
                extract_host(&request.callback_url).unwrap_or_else(|| request.callback_url.clone());
            return Err(render_local_rp_consent_form(
                pool,
                &form.signed_request,
                &form.login_proof,
                &descriptor,
                &existing,
                &callback_host,
                &screen,
                &labels,
                &locale.0,
                Some(&e),
            ));
        }
    };

    match finalize_local_rp_login(
        pool,
        nonces,
        &locale.0,
        &user,
        &request,
        &descriptor,
        suite,
        &req,
        &authorized,
    ) {
        Ok(url) => Ok(Redirect::found(url)),
        Err(msg) => Err(super::render_error_page(&msg)),
    }
}
