//! User-facing profile & identity editor: the non-technical surface where a
//! person fills in the things they want to share (display name, handle, …),
//! sees a "Verified by <domain>" badge when the IDP could validate and sign the
//! value, and — when the operator allows more than one — creates additional
//! pseudonymous profiles. Deletion is intentionally absent: removing a profile
//! is an admin action.
//!
//! Every button maps to one `services::self_service` call; the page is a thin
//! renderer so the same operations back a future CLI / agent unchanged.

use rocket::http::{ContentType, CookieJar, Status};
use rocket::response::content::RawHtml;
use rocket::response::Redirect;
use rocket::State;

use crate::conversions::{get_domain_name, html_escape};
use crate::db::{max_profiles_per_account, DbPool};
use crate::services::attestation;
use crate::services::self_service::{self, SetOutcome};

/// Render `data` as an inline SVG QR code, if it fits. Returns None for data too
/// large to encode (caller falls back to the base64 text).
pub(super) fn qr_svg(data: &str) -> Option<String> {
    use qrcode::render::svg;
    use qrcode::QrCode;
    QrCode::new(data.as_bytes())
        .ok()
        .map(|code| code.render::<svg::Color>().min_dimensions(240, 240).build())
}

fn parse_type_list(types: &str) -> Vec<String> {
    types
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

use super::account_ui::{build_nav, flash_html, get_session_user_id, is_user_admin, layout};

/// The verified-state badge for a claim the user holds (or lack of one).
fn value_badge(signed: bool) -> &'static str {
    if signed {
        r#"<span class="badge badge-active">Verified ✓</span>"#
    } else {
        r#"<span class="badge badge-inactive">Not verified</span>"#
    }
}

#[rocket::get("/account/identity?<msg>&<error>")]
pub fn identity_editor(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    msg: Option<&str>,
    error: Option<&str>,
) -> Result<RawHtml<String>, Box<Redirect>> {
    let account_id = match get_session_user_id(cookies) {
        Some(id) => id,
        None => return Err(Box::new(Redirect::found("/account/login"))),
    };
    // The default profile shares the account id; per-profile claim keying for
    // additional personas is still pending, so the editor operates on it.
    let subject_id = account_id.clone();

    let policies = self_service::list_user_settable_policies(pool.inner())
        .map_err(|_| Box::new(Redirect::found("/account?error=Could+not+load+policies")))?;
    let claims = pool
        .list_active_claims(&subject_id)
        .map_err(|_| Box::new(Redirect::found("/account?error=Could+not+load+claims")))?;
    let prefs = pool.list_profile_prefs(&subject_id).unwrap_or_default();
    // Claim types the user has chosen to share with any domain (audience "*").
    let any_domain: std::collections::HashSet<String> = pool
        .list_user_release_allows(&subject_id, "*")
        .unwrap_or_default()
        .into_iter()
        .collect();

    let current = |ct: &str| -> Option<(String, bool)> {
        claims.iter().find(|c| c.claim_type == ct).map(|c| {
            let v = String::from_utf8(c.claim_value.clone()).unwrap_or_default();
            (v, !c.signatures.is_empty())
        })
    };
    let pref_for = |ct: &str, default: bool| -> bool {
        prefs
            .iter()
            .find(|p| p.claim_type == ct)
            .map(|p| p.auto_sign)
            .unwrap_or(default)
    };

    let admin = is_user_admin(pool.inner(), &account_id);
    let nav = build_nav("identity", admin, true);
    let flash = flash_html(msg, error);

    let mut rows = String::new();
    for p in &policies {
        let (value, signed) = current(&p.claim_type).unwrap_or((String::new(), false));
        let signable = p.signing_rule == "self_signed" || p.signing_rule == "verified";
        let badge = if current(&p.claim_type).is_some() {
            value_badge(signed)
        } else {
            ""
        };
        // Auto-sign toggle only where signing is possible.
        let auto_sign_field = if signable {
            let checked = if pref_for(&p.claim_type, p.default_auto_sign) {
                "checked"
            } else {
                ""
            };
            format!(
                r#"<label style="font-weight:normal"><input type="checkbox" name="auto_sign" value="1" {checked}/> Keep this verified</label>"#,
                checked = checked
            )
        } else {
            String::new()
        };
        let hint = if p.description.is_empty() {
            String::new()
        } else {
            format!(
                r#"<div style="color:#666;font-size:0.85em">{}</div>"#,
                html_escape(&p.description)
            )
        };
        let share_checked = if any_domain.contains(&p.claim_type) {
            "checked"
        } else {
            ""
        };
        rows.push_str(&format!(
            r#"<div style="border:1px solid #eee;border-radius:6px;padding:12px;margin:12px 0">
  <form method="POST" action="/account/identity/claim">
    <input type="hidden" name="claim_type" value="{ct}"/>
    <div style="display:flex;justify-content:space-between;align-items:center">
      <strong>{label}</strong> {badge}
    </div>
    {hint}
    <input type="text" name="value" value="{value}" placeholder="{label}"/>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-top:6px">
      {auto_sign}
      <button type="submit" class="btn-primary">Save</button>
    </div>
  </form>
  <form method="POST" action="/account/identity/share" style="margin-top:6px">
    <input type="hidden" name="claim_type" value="{ct}"/>
    <label style="font-weight:normal"><input type="checkbox" name="share_any" value="1" {share_checked} onchange="this.form.submit()"/> Share with any domain automatically</label>
    <noscript><button type="submit">Update sharing</button></noscript>
  </form>
</div>"#,
            ct = html_escape(&p.claim_type),
            label = html_escape(&p.label),
            badge = badge,
            hint = hint,
            value = html_escape(&value),
            auto_sign = auto_sign_field,
            share_checked = share_checked,
        ));
    }
    if policies.is_empty() {
        rows.push_str("<p>Your domain hasn't enabled any self-service claims yet.</p>");
    }

    // Multi-profile section only when the operator has raised the cap.
    let profiles_section = if max_profiles_per_account() > 1 {
        let profiles = self_service::list_profiles(pool.inner(), &account_id).unwrap_or_default();
        let mut list = String::new();
        for pr in &profiles {
            list.push_str(&format!(
                "<li>{} <code>{}</code></li>",
                html_escape(pr.label.as_deref().unwrap_or("(default)")),
                html_escape(&pr.id[..8.min(pr.id.len())]),
            ));
        }
        format!(
            r#"<h2>Profiles</h2>
<p>Separate personas you can present to different sites. Linkage between them is yours to reveal — never the system's.</p>
<ul>{list}</ul>
<form method="POST" action="/account/profiles/create">
  <input type="text" name="label" placeholder="New profile label"/>
  <button type="submit" class="btn-primary">Create profile</button>
</form>"#,
            list = list,
        )
    } else {
        String::new()
    };

    // Verified credentials: every claim the user holds, checked live against the
    // signer's keys, with WHO signed it. This is the one-click verify — an
    // attested claim reads "signed by dmv.test ✓", a self-asserted one shows its
    // own domain (or "self-asserted" when unsigned).
    let mut creds = String::new();
    for c in &claims {
        let claim: liblinkkeys::generated::types::Claim = c.into();
        let v = attestation::verify_stored_claim(pool.inner(), &claim);
        let badge = if v.verified {
            r#"<span class="badge badge-active">Verified ✓</span>"#
        } else {
            r#"<span class="badge badge-inactive">Unverified</span>"#
        };
        let signers = if v.signed_by.is_empty() {
            "self-asserted".to_string()
        } else {
            v.signed_by.join(", ")
        };
        creds.push_str(&format!(
            "<tr><td><code>{ct}</code></td><td>{val}</td><td>{badge}</td><td>{signers}</td></tr>",
            ct = html_escape(&v.claim_type),
            val = html_escape(&v.value),
            badge = badge,
            signers = html_escape(&signers),
        ));
    }
    let creds_section = if creds.is_empty() {
        String::new()
    } else {
        format!(
            r#"<h2>Verified credentials</h2>
<p>What you hold and who vouches for each — checked live against the signer's keys.</p>
<table><tr><th>Claim</th><th>Value</th><th>Status</th><th>Signed by</th></tr>{creds}</table>"#,
            creds = creds,
        )
    };

    let content = format!(
        r#"{flash}
<h1>My Identity</h1>
<p>Fill in what you'd like to be able to share. A <span class="badge badge-active">Verified ✓</span> badge means <strong>{domain}</strong> has checked and signed the value, so sites can trust it came from your domain.</p>
{rows}
<p><a href="/account/request-verification">Request verification from a third party →</a></p>
{creds_section}
{profiles}
<p><a href="/account">Back to Account</a></p>"#,
        flash = flash,
        domain = html_escape(&get_domain_name()),
        rows = rows,
        creds_section = creds_section,
        profiles = profiles_section,
    );

    Ok(layout("My Identity", &nav, &content))
}

#[derive(rocket::FromForm)]
pub struct SetClaimForm {
    claim_type: String,
    value: String,
    auto_sign: Option<String>,
}

#[rocket::post("/account/identity/claim", data = "<form>")]
pub fn set_claim_submit(
    _csrf: super::guard::SameOriginPost,
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    form: rocket::form::Form<SetClaimForm>,
) -> Redirect {
    let account_id = match get_session_user_id(cookies) {
        Some(id) => id,
        None => return Redirect::found("/account/login"),
    };
    let subject_id = account_id;
    let auto_sign = form.auto_sign.is_some();

    // Record the auto-sign preference first so the set respects it.
    let _ = self_service::set_signing_pref(pool.inner(), &subject_id, &form.claim_type, auto_sign);

    match self_service::set_my_claim(
        pool.inner(),
        &subject_id,
        &form.claim_type,
        form.value.as_bytes(),
    ) {
        Ok(SetOutcome::VerificationRequired) => {
            // Lane B: kick off the verification flow now (email is the only one).
            match crate::services::verification::request_email_verification(
                pool.inner(),
                &subject_id,
                form.value.trim(),
            ) {
                Ok(()) => Redirect::found(format!(
                    "/account/identity?msg={}",
                    urlencoding::encode("Check your inbox for a verification link")
                )),
                Err(e) => Redirect::found(format!(
                    "/account/identity?error={}",
                    urlencoding::encode(&e.message)
                )),
            }
        }
        Ok(outcome) => {
            let msg = match outcome {
                SetOutcome::Signed => "Saved and verified",
                SetOutcome::StoredUnsigned => "Saved",
                SetOutcome::Queued => "Submitted for review",
                SetOutcome::VerificationRequired => unreachable!(),
            };
            Redirect::found(format!(
                "/account/identity?msg={}",
                urlencoding::encode(msg)
            ))
        }
        Err(e) => Redirect::found(format!(
            "/account/identity?error={}",
            urlencoding::encode(&e.message)
        )),
    }
}

#[rocket::get("/account/identity/verify-email?<token>")]
pub fn verify_email(pool: &State<DbPool>, cookies: &CookieJar<'_>, token: &str) -> Redirect {
    // Require a session, and confirm the link under the SAME account that
    // requested it — the service rechecks token.user_id == session user, so a
    // leaked link can't be redeemed by someone else.
    let session_user = match get_session_user_id(cookies) {
        Some(id) => id,
        None => return Redirect::found("/account/login"),
    };
    match crate::services::verification::confirm_email_verification(
        pool.inner(),
        token,
        &session_user,
    ) {
        Ok(_) => Redirect::found(format!(
            "/account/identity?msg={}",
            urlencoding::encode("Email verified")
        )),
        Err(e) => Redirect::found(format!(
            "/account/identity?error={}",
            urlencoding::encode(&e.message)
        )),
    }
}

#[derive(rocket::FromForm)]
pub struct ShareForm {
    claim_type: String,
    share_any: Option<String>,
}

#[rocket::post("/account/identity/share", data = "<form>")]
pub fn set_share_submit(
    _csrf: super::guard::SameOriginPost,
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    form: rocket::form::Form<ShareForm>,
) -> Redirect {
    let account_id = match get_session_user_id(cookies) {
        Some(id) => id,
        None => return Redirect::found("/account/login"),
    };
    // Only let a user pre-share a claim type that actually exists and is theirs
    // to set — don't accumulate junk standing prefs from crafted POSTs.
    let known = matches!(
        pool.find_claim_policy(&form.claim_type),
        Ok(Some(ref p)) if p.user_settable
    );
    if !known {
        return Redirect::found("/account/identity?error=Unknown+claim+type");
    }
    let result = if form.share_any.is_some() {
        pool.add_user_release_pref(&account_id, "*", &form.claim_type)
    } else {
        pool.remove_user_release_pref(&account_id, "*", &form.claim_type)
    };
    match result {
        Ok(_) => Redirect::found("/account/identity?msg=Sharing+updated"),
        Err(_) => Redirect::found("/account/identity?error=Could+not+update+sharing"),
    }
}

/// "Request verification" — the user picks an issuer and claim types, and we
/// mint a home-domain-signed signing request rendered three ways (QR, base64
/// text, downloadable file) so they can carry it to the issuer however they
/// like, including printing a QR with no portable device.
#[rocket::get("/account/request-verification?<issuer>&<types>&<error>")]
pub fn request_verification(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    issuer: Option<&str>,
    types: Option<&str>,
    error: Option<&str>,
) -> Result<RawHtml<String>, Box<Redirect>> {
    let account_id = match get_session_user_id(cookies) {
        Some(id) => id,
        None => return Err(Box::new(Redirect::found("/account/login"))),
    };
    let admin = is_user_admin(pool.inner(), &account_id);
    let nav = build_nav("identity", admin, true);
    let flash = flash_html(None, error);

    let issuer_val = issuer.unwrap_or("").trim().to_string();
    let types_val = types.unwrap_or("").trim().to_string();

    let mut result = String::new();
    if !issuer_val.is_empty() && !types_val.is_empty() {
        let type_list = parse_type_list(&types_val);
        match attestation::mint_signing_request(pool.inner(), &account_id, &issuer_val, &type_list)
        {
            Ok(signed) => {
                let mut cbor = Vec::new();
                if ciborium::ser::into_writer(&signed, &mut cbor).is_ok() {
                    use base64ct::{Base64UrlUnpadded, Encoding as _};
                    let b64 = Base64UrlUnpadded::encode_string(&cbor);
                    let qr = qr_svg(&b64)
                        .unwrap_or_else(|| "<p>(request too large for a QR code)</p>".to_string());
                    let dl = format!(
                        "/account/request-verification.bin?issuer={}&types={}",
                        urlencoding::encode(&issuer_val),
                        urlencoding::encode(&types_val)
                    );
                    result = format!(
                        r#"<h2>Your verification request</h2>
<p>Show this to <strong>{issuer}</strong>, or save/print it. It asks them to attest: <strong>{types}</strong>. Valid for a couple of days.</p>
<div style="max-width:260px">{qr}</div>
<p><a href="{dl}">Download as a file</a></p>
<label>Or copy this text</label>
<textarea readonly rows="4" style="width:100%">{b64}</textarea>"#,
                        issuer = html_escape(&issuer_val),
                        types = html_escape(&types_val),
                        qr = qr,
                        dl = dl,
                        b64 = html_escape(&b64),
                    );
                }
            }
            Err(e) => {
                result = format!(r#"<div class="error">{}</div>"#, html_escape(&e.message));
            }
        }
    }

    let content = format!(
        r#"{flash}
<h1>Request verification</h1>
<p>Ask a trusted third party (a government office, a company, even a neighbor) to
attest something about you. They sign it; anyone can later verify their signature.</p>
<form method="GET" action="/account/request-verification">
  <label>Who will attest (their domain)</label>
  <input type="text" name="issuer" value="{issuer}" placeholder="dmv.example"/>
  <label>What to attest (comma-separated)</label>
  <input type="text" name="types" value="{types}" placeholder="age_over_21, legal_name"/>
  <br/><br/><button type="submit" class="btn-primary">Create request</button>
</form>
{result}
<p><a href="/account/identity">Back to My Identity</a></p>"#,
        flash = flash,
        issuer = html_escape(&issuer_val),
        types = html_escape(&types_val),
        result = result,
    );
    Ok(layout("Request Verification", &nav, &content))
}

/// Raw CBOR(SignedSigningRequest) download of the same request.
#[rocket::get("/account/request-verification.bin?<issuer>&<types>")]
pub fn request_verification_download(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    issuer: &str,
    types: &str,
) -> Result<(ContentType, Vec<u8>), Status> {
    let account_id = get_session_user_id(cookies).ok_or(Status::Unauthorized)?;
    let type_list = parse_type_list(types);
    if issuer.trim().is_empty() || type_list.is_empty() {
        return Err(Status::BadRequest);
    }
    let signed =
        attestation::mint_signing_request(pool.inner(), &account_id, issuer.trim(), &type_list)
            .map_err(|_| Status::InternalServerError)?;
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&signed, &mut cbor).map_err(|_| Status::InternalServerError)?;
    Ok((ContentType::Binary, cbor))
}

#[derive(rocket::FromForm)]
pub struct CreateProfileForm {
    label: String,
}

#[rocket::post("/account/profiles/create", data = "<form>")]
pub fn create_profile_submit(
    _csrf: super::guard::SameOriginPost,
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    form: rocket::form::Form<CreateProfileForm>,
) -> Redirect {
    let account_id = match get_session_user_id(cookies) {
        Some(id) => id,
        None => return Redirect::found("/account/login"),
    };
    let label = form.label.trim();
    let label = if label.is_empty() { None } else { Some(label) };
    match self_service::create_profile(pool.inner(), &account_id, label) {
        Ok(_) => Redirect::found("/account/identity?msg=Profile+created"),
        Err(e) => Redirect::found(format!(
            "/account/identity?error={}",
            urlencoding::encode(&e.message)
        )),
    }
}
