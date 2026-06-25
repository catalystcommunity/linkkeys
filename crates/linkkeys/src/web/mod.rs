mod account;
mod account_ui;
mod admin;
mod admin_ui;
mod guard;
pub mod nonce_store;
mod policy_admin_ui;
mod profile_ui;
pub mod rp;

use rocket::form::FromForm;
use rocket::http::{ContentType, CookieJar, Status};
use rocket::response::content::RawHtml;
use rocket::response::status::Custom;
use rocket::response::Redirect;
use rocket::{Config, State};
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rand::Rng;

use crate::conversions::{get_domain_name, html_escape};
use crate::db::DbPool;
use crate::net::Net;
use crate::services::auth::PasswordAuthenticator;
use crate::services::handshake::HandshakeHandler;
use crate::services::hello::HelloHandler;

use liblinkkeys::consent::{
    self, compute_authorized_claims, resolve_consent_screen, ConsentScreen, DomainPolicy,
    DEFAULT_CONSENT_TTL_SECONDS,
};
use liblinkkeys::generated::types::{
    AuthRequest, Claim, ClaimRequest, ConsentGrant, DomainPublicKey, GetDomainKeysResponse,
    GetUserKeysResponse, UserInfo,
};

/// Wall-clock budget for a `signed_request` to be considered fresh, from
/// the time the RP signed it to the time the user submits the login form.
/// Covers the redirect-to-IDP hop, page render, and user typing time.
const MAX_AUTH_REQUEST_AGE_SECONDS: i64 = 300;

/// Wall-clock budget for a relying party's signed `/userinfo` request to be
/// considered fresh, and the window over which a redeemed assertion nonce is
/// remembered as spent. Covers the RP's callback handling and its outbound
/// call to the IDP.
const MAX_USERINFO_REQUEST_AGE_SECONDS: i64 = 300;

#[derive(Serialize, Deserialize)]
struct HelloRequest {
    name: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct HelloResponse {
    greeting: String,
}

#[derive(Serialize, Deserialize)]
struct CheckResultResponse {
    result: bool,
}

fn cbor_response(data: Vec<u8>) -> (ContentType, Vec<u8>) {
    (ContentType::new("application", "cbor"), data)
}

fn json_response(data: Vec<u8>) -> (ContentType, Vec<u8>) {
    (ContentType::JSON, data)
}

fn db_err_to_status(e: diesel::result::Error) -> Status {
    match e {
        diesel::result::Error::NotFound => Status::NotFound,
        _ => Status::InternalServerError,
    }
}

/// Choose a random active *signing* key. Encryption keys (X25519) are excluded:
/// their algorithm is not a `SigningAlgorithm`, so signing with one fails (and
/// once a domain has an encryption key, an unfiltered random pick would
/// intermittently 500). Returns `None` when the domain has no active signing
/// key. Shared by every signing path so the filter can't be forgotten in one.
pub fn pick_active_signing_key(
    domain_keys: &[crate::db::models::DomainKey],
) -> Option<&crate::db::models::DomainKey> {
    let signing: Vec<&crate::db::models::DomainKey> = domain_keys
        .iter()
        .filter(|k| k.key_usage == "sign")
        .collect();
    if signing.is_empty() {
        return None;
    }
    Some(signing[rand::thread_rng().gen_range(0..signing.len())])
}

/// The subject an assertion/claim is issued FOR. Per the trust model
/// (docs/claim-trust-verification.md) this is ALWAYS the account UUID: profiles
/// are presentation override sets, not separate cryptographic subjects, so they
/// never become the subject. Unlinkable personas are separate accounts, not
/// profiles. Kept as a function so the single source of truth is documented and
/// any future per-presentation re-binding lives in one place.
fn resolve_subject_profile(_pool: &DbPool, account_id: &str) -> String {
    account_id.to_string()
}

/// Sign an identity assertion for the given user with a randomly chosen active
/// signing key. `authorized_claims` is the consented claim-type set the assertion
/// carries; `get-user-info` scopes its release to exactly this set. The assertion
/// subject is the user's presentable profile (never the root anchor).
fn sign_assertion_for_user(
    pool: &DbPool,
    user: &crate::db::models::User,
    audience: &str,
    nonce: &str,
    authorized_claims: Vec<String>,
) -> Result<String, Status> {
    let domain_keys = pool
        .list_active_domain_keys()
        .map_err(|_| Status::InternalServerError)?;
    let dk = pick_active_signing_key(&domain_keys).ok_or(Status::InternalServerError)?;

    let passphrase = env::var("DOMAIN_KEY_PASSPHRASE").map_err(|_| Status::InternalServerError)?;
    let sk_bytes =
        liblinkkeys::crypto::decrypt_private_key(&dk.private_key_encrypted, passphrase.as_bytes())
            .map_err(|_| Status::InternalServerError)?;

    let algorithm = liblinkkeys::crypto::SigningAlgorithm::parse_str(&dk.algorithm)
        .ok_or(Status::InternalServerError)?;

    let subject = resolve_subject_profile(pool, &user.id);
    let assertion = liblinkkeys::assertions::build_assertion(
        &subject,
        &get_domain_name(),
        audience,
        nonce,
        Some(&user.display_name),
        300, // 5 minute TTL
        authorized_claims,
    );

    let signed = liblinkkeys::assertions::sign_assertion(&assertion, &dk.id, algorithm, &sk_bytes)
        .map_err(|_| Status::InternalServerError)?;

    liblinkkeys::encoding::assertion_to_url_param(&signed).map_err(|_| Status::InternalServerError)
}

/// Lifetime of a newly issued consent grant, from `CONSENT_GRANT_TTL_SECONDS`
/// (default one year). Re-consent happens automatically once a grant expires.
fn consent_ttl_seconds() -> i64 {
    env::var("CONSENT_GRANT_TTL_SECONDS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_CONSENT_TTL_SECONDS)
}

/// Home-domain claim-release policy for an audience, from the `release_policies`
/// table: rows for that audience plus the global `*` defaults. Forced rows are
/// shown to the user but cannot be toggled; deny wins over allow. The table is
/// seeded on first boot from the deprecated `CONSENT_FORCED_ALLOW` /
/// `CONSENT_FORCED_DENY` env vars (see `DbPool::seed_default_policies`).
fn domain_policy_for(pool: &DbPool, audience: &str) -> Result<DomainPolicy, ()> {
    // Fail CLOSED: `forced_deny` is a security control. If the policy can't be
    // loaded, do NOT fall back to an empty (allow-everything) policy — propagate
    // the error so the caller aborts rather than releasing claims an admin denied.
    let rows = pool
        .list_release_policies_for_audience(audience)
        .map_err(|e| log::error!("release policy load failed for {}: {}", audience, e))?;
    let mut forced_allow = Vec::new();
    let mut forced_deny = Vec::new();
    for r in rows {
        match r.disposition.as_str() {
            "forced_allow" => forced_allow.push(r.claim_type),
            "forced_deny" => forced_deny.push(r.claim_type),
            other => log::warn!("release_policies: unknown disposition {:?}", other),
        }
    }
    Ok(DomainPolicy {
        forced_allow,
        forced_deny,
    })
}

/// The claim types an RP requested (required ∪ optional), as a flat list.
fn requested_types(req: &ClaimRequest) -> Vec<String> {
    req.required
        .iter()
        .chain(req.optional.iter())
        .map(|r| r.claim_type.clone())
        .collect()
}

/// True when a prior standing grant already saw every claim type the RP is
/// requesting now — i.e. the RP hasn't asked for anything *new* since the user
/// last consented. Compares against the grant's `requested_types`, which records
/// everything previously offered (including optionals the user declined), so a
/// re-listed declined optional does NOT re-prompt. A type the RP has since
/// promoted to required is caught separately by `first_unsatisfied_required` on
/// the skip path, which falls through to a fresh prompt rather than completing
/// without it.
fn grant_covers(prior: &crate::db::models::ConsentGrantRow, req: &ClaimRequest) -> bool {
    use std::collections::BTreeSet;
    let known: BTreeSet<&str> = prior.requested_types.iter().map(String::as_str).collect();
    requested_types(req)
        .iter()
        .all(|t| known.contains(t.as_str()))
}

/// The first RP-required claim type that must block completion: one the user
/// has not granted and domain policy has not denied. `None` => every required
/// claim is satisfied (granted, or absolved because the home domain forced_deny
/// it — the domain's deny is absolute and overrides the RP's "required" flag).
fn first_unsatisfied_required<'a>(
    req: &'a ClaimRequest,
    authorized: &[String],
    policy: &DomainPolicy,
) -> Option<&'a str> {
    use std::collections::BTreeSet;
    let granted: BTreeSet<&str> = authorized.iter().map(String::as_str).collect();
    let denied: BTreeSet<&str> = policy.forced_deny.iter().map(String::as_str).collect();
    req.required
        .iter()
        .map(|r| r.claim_type.as_str())
        .find(|ct| !granted.contains(ct) && !denied.contains(ct))
}

/// Reconstruct the protocol `ConsentGrant` from a stored row for the consent
/// screen (only `claim_types` drives pre-checking).
fn prior_grant_object(row: &crate::db::models::ConsentGrantRow) -> ConsentGrant {
    ConsentGrant {
        grant_id: row.id.clone(),
        user_id: row.user_id.clone(),
        subject_domain: row.subject_domain.clone(),
        audience: row.audience.clone(),
        claim_types: row.claim_types.clone(),
        issued_at: row.issued_at.clone(),
        expires_at: row.expires_at.clone(),
        revoked_at: row.revoked_at.clone(),
    }
}

/// Build the consent screen for (user, request) under the current policy:
/// resolves the user's available claims and any prior standing grant for the
/// requesting `audience`.
fn build_consent_screen(
    pool: &DbPool,
    user_id: &str,
    audience: &str,
    req: &ClaimRequest,
    policy: &DomainPolicy,
) -> ConsentScreen {
    let available: Vec<Claim> = pool
        .list_active_claims(user_id)
        .map(|c| c.iter().map(Into::into).collect())
        .unwrap_or_default();
    let prior = pool
        .find_active_consent_grant(user_id, audience)
        .ok()
        .flatten();
    let prior_obj = prior.as_ref().map(prior_grant_object);
    let mut screen = resolve_consent_screen(req, &available, prior_obj.as_ref(), policy);

    // Fold in the user's standing release preferences (claims they chose to
    // pre-share with this audience or with any domain). These rows arrive
    // pre-checked — the user still confirms, but with zero friction. Locked
    // (policy-forced) rows are left untouched.
    let standing = pool
        .list_user_release_allows(user_id, audience)
        .unwrap_or_default();
    let allow: std::collections::BTreeSet<&str> = standing.iter().map(String::as_str).collect();
    for row in &mut screen.rows {
        if row.policy == consent::PolicyDisposition::User && allow.contains(row.claim_type.as_str())
        {
            row.previously_granted = true;
        }
    }
    screen
}

/// A relying-party self-claim with its verification status, for display and
/// policy. `verified` means every attesting domain contributed a valid
/// signature over a claim about *this* relying party.
struct VerifiedRpClaim {
    claim_type: String,
    value: String,
    attested_by: Vec<String>,
    verified: bool,
}

/// The RP's request is attacker-influenced and resolving an attesting domain
/// triggers a DNS+HTTP key fetch, so cap both the claims processed and the
/// distinct domains fetched: a malicious RP must not be able to drive unbounded
/// outbound requests (SSRF/amplification) during a victim's login.
const MAX_RP_CLAIMS: usize = 16;
const MAX_ATTESTING_DOMAINS: usize = 8;

/// Verify the claims an RP asserted about itself: resolve each distinct
/// attesting domain's keys (local DB or DNS+HTTP) at most once, then check each
/// claim's signatures bind to `relying_party`. Unresolvable/invalid signers
/// leave `verified = false` — the claim is still surfaced (and recorded), just
/// not trusted. This is the hook a richer policy can branch on (e.g. treat a
/// `government_entity` claim attested by `us.gov` differently); the prototype
/// displays + records it. Fetches are bounded (see the constants above).
async fn verify_relying_party_claims(
    pool: &DbPool,
    net: &Net,
    relying_party: &str,
    claims: &[liblinkkeys::generated::types::DomainClaim],
) -> Vec<VerifiedRpClaim> {
    use std::collections::BTreeMap;

    let claims = &claims[..claims.len().min(MAX_RP_CLAIMS)];

    // Distinct attesting domains across the (capped) claims, resolved once each
    // up to a hard cap. Domains beyond the cap simply go unresolved => their
    // claims read as unverified, which is safe.
    let mut wanted: Vec<String> = Vec::new();
    for c in claims {
        for d in liblinkkeys::domain_claims::attesting_domains(c) {
            if !wanted.contains(&d) {
                wanted.push(d);
            }
        }
    }
    wanted.truncate(MAX_ATTESTING_DOMAINS);

    let mut resolved: BTreeMap<String, Vec<DomainPublicKey>> = BTreeMap::new();
    for d in &wanted {
        if let Ok(keys) = rp::fetch_domain_keys(pool, net, d).await {
            resolved.insert(d.clone(), keys);
        }
    }

    let mut out = Vec::with_capacity(claims.len());
    for claim in claims {
        let signer_domains = liblinkkeys::domain_claims::attesting_domains(claim);
        let keysets: Vec<liblinkkeys::claims::DomainKeySet> = signer_domains
            .iter()
            .filter_map(|d| {
                resolved
                    .get(d)
                    .map(|keys| liblinkkeys::claims::DomainKeySet {
                        domain: d.clone(),
                        keys: keys.clone(),
                    })
            })
            .collect();
        let verified =
            liblinkkeys::domain_claims::verify_domain_claim(claim, relying_party, &keysets).is_ok();
        out.push(VerifiedRpClaim {
            claim_type: claim.claim_type.clone(),
            value: String::from_utf8_lossy(&claim.claim_value).to_string(),
            attested_by: signer_domains,
            verified,
        });
    }
    out
}

/// Sign a consent grant for the user with **all** active domain signing keys
/// (mirroring claim signing: multiple keys give rotation resilience while the
/// verification quorum needs only one valid signature per domain).
fn sign_consent_grant_for_user(
    pool: &DbPool,
    grant_id: &str,
    user_id: &str,
    audience: &str,
    claim_types: &[String],
    issued_at: &str,
    expires_at: &str,
) -> Result<liblinkkeys::generated::types::SignedConsentGrant, Status> {
    let domain = get_domain_name();
    let domain_keys = pool
        .list_active_domain_keys()
        .map_err(|_| Status::InternalServerError)?;
    let passphrase = env::var("DOMAIN_KEY_PASSPHRASE").map_err(|_| Status::InternalServerError)?;

    // Own the decrypted private keys so the borrowed signers can reference them.
    let mut materials: Vec<(String, liblinkkeys::crypto::SigningAlgorithm, Vec<u8>)> = Vec::new();
    for dk in domain_keys.iter().filter(|k| k.key_usage == "sign") {
        let Some(algorithm) = liblinkkeys::crypto::SigningAlgorithm::parse_str(&dk.algorithm)
        else {
            continue;
        };
        let sk = liblinkkeys::crypto::decrypt_private_key(
            &dk.private_key_encrypted,
            passphrase.as_bytes(),
        )
        .map_err(|_| Status::InternalServerError)?;
        materials.push((dk.id.clone(), algorithm, sk));
    }
    if materials.is_empty() {
        return Err(Status::InternalServerError);
    }

    let signers: Vec<liblinkkeys::claims::ClaimSigner> = materials
        .iter()
        .map(|(key_id, algorithm, sk)| liblinkkeys::claims::ClaimSigner {
            domain: &domain,
            key_id,
            algorithm: *algorithm,
            private_key_bytes: sk,
        })
        .collect();

    let spec = consent::ConsentSpec {
        grant_id,
        user_id,
        subject_domain: &domain,
        audience,
        claim_types,
        issued_at,
        expires_at,
    };
    consent::sign_consent(&spec, &signers).map_err(|_| Status::InternalServerError)
}

/// Verify a token and check that the audience matches the expected value.
fn verify_token_with_audience(
    pool: &DbPool,
    token_param: &str,
    expected_audience: Option<&str>,
) -> Result<liblinkkeys::generated::types::IdentityAssertion, Status> {
    let signed = liblinkkeys::encoding::assertion_from_url_param(token_param)
        .map_err(|_| Status::BadRequest)?;

    let domain_keys = pool
        .list_active_domain_keys()
        .map_err(|_| Status::InternalServerError)?;
    let csil_keys: Vec<DomainPublicKey> = domain_keys.iter().map(Into::into).collect();

    let assertion = liblinkkeys::assertions::verify_assertion(&signed, &csil_keys)
        .map_err(|_| Status::Unauthorized)?;

    if let Some(expected) = expected_audience {
        if assertion.audience != expected {
            return Err(Status::Unauthorized);
        }
    }

    Ok(assertion)
}

// -- Landing page --

#[rocket::get("/")]
fn index(pool: &State<DbPool>, cookies: &CookieJar<'_>) -> RawHtml<String> {
    let (is_logged_in, is_admin) = match account_ui::get_session_user_id(cookies) {
        Some(uid) => (true, account_ui::is_user_admin(pool.inner(), &uid)),
        None => (false, false),
    };
    let nav = account_ui::build_nav("", is_admin, is_logged_in);
    let domain = get_domain_name();
    let content = format!(
        r#"<h1>LinkKeys for {domain}</h1>
<p>Find out more about LinkKeys at <a href="https://github.com/catalystcommunity/linkkeys">https://github.com/catalystcommunity/linkkeys</a> or join the discord!</p>"#,
        domain = html_escape(&domain),
    );
    account_ui::layout(&format!("LinkKeys for {}", domain), &nav, &content)
}

// -- Healthcheck / Readiness --

#[rocket::get("/healthcheck")]
fn healthcheck() -> (ContentType, Vec<u8>) {
    let resp = CheckResultResponse { result: true };
    let mut out = Vec::new();
    ciborium::ser::into_writer(&resp, &mut out).expect("CBOR serialization cannot fail for bool");
    cbor_response(out)
}

#[rocket::get("/readiness")]
fn readiness(ready: &State<Arc<AtomicBool>>) -> Result<(ContentType, Vec<u8>), Status> {
    if ready.load(Ordering::SeqCst) {
        let resp = CheckResultResponse { result: true };
        let mut out = Vec::new();
        ciborium::ser::into_writer(&resp, &mut out).map_err(|_| Status::InternalServerError)?;
        Ok(cbor_response(out))
    } else {
        Err(Status::ServiceUnavailable)
    }
}

// -- Hello --

#[rocket::post("/hello", data = "<body>")]
fn hello_post(body: Vec<u8>) -> Result<(ContentType, Vec<u8>), Custom<String>> {
    let request: HelloRequest = if body.is_empty() {
        HelloRequest { name: None }
    } else {
        ciborium::de::from_reader(&body[..])
            .map_err(|e| Custom(Status::BadRequest, format!("Invalid CBOR: {}", e)))?
    };

    let handler = HelloHandler;
    let greeting = handler.hello(request.name);

    let resp = HelloResponse { greeting };
    let mut out = Vec::new();
    ciborium::ser::into_writer(&resp, &mut out).map_err(|e| {
        Custom(
            Status::InternalServerError,
            format!("CBOR encode error: {}", e),
        )
    })?;
    Ok(cbor_response(out))
}

#[rocket::get("/hello")]
fn hello_get() -> Result<(ContentType, Vec<u8>), Status> {
    let handler = HelloHandler;
    let greeting = handler.hello(None);

    let resp = HelloResponse { greeting };
    let mut out = Vec::new();
    ciborium::ser::into_writer(&resp, &mut out).map_err(|_| Status::InternalServerError)?;
    Ok(cbor_response(out))
}

// -- Domain Keys --

fn build_domain_keys_response(pool: &DbPool) -> Result<GetDomainKeysResponse, Status> {
    let keys = pool
        .list_active_domain_keys()
        .map_err(|_| Status::InternalServerError)?;
    Ok(GetDomainKeysResponse {
        domain: get_domain_name(),
        keys: keys.iter().map(Into::into).collect(),
    })
}

// TODO: deprecated, remove later — server-to-server key/handshake/userinfo retrieval moved to the TCP CSIL-RPC transport.
#[rocket::get("/v1alpha/domain-keys")]
fn domain_keys_cbor(pool: &State<DbPool>) -> Result<(ContentType, Vec<u8>), Status> {
    let resp = build_domain_keys_response(pool)?;
    let mut out = Vec::new();
    ciborium::ser::into_writer(&resp, &mut out).map_err(|_| Status::InternalServerError)?;
    Ok(cbor_response(out))
}

// TODO: deprecated, remove later — server-to-server key/handshake/userinfo retrieval moved to the TCP CSIL-RPC transport.
#[rocket::get("/v1alpha/domain-keys.json")]
fn domain_keys_json(pool: &State<DbPool>) -> Result<(ContentType, Vec<u8>), Status> {
    let resp = build_domain_keys_response(pool)?;
    let out = serde_json::to_vec(&resp).map_err(|_| Status::InternalServerError)?;
    Ok(json_response(out))
}

// -- User Keys --

fn build_user_keys_response(pool: &DbPool, user_id: &str) -> Result<GetUserKeysResponse, Status> {
    pool.find_user_by_id(user_id).map_err(db_err_to_status)?;
    let keys = pool
        .list_active_user_keys(user_id)
        .map_err(db_err_to_status)?;
    Ok(GetUserKeysResponse {
        user_id: user_id.to_string(),
        domain: get_domain_name(),
        keys: keys.iter().map(Into::into).collect(),
    })
}

// TODO: deprecated, remove later — server-to-server key/handshake/userinfo retrieval moved to the TCP CSIL-RPC transport.
#[rocket::get("/v1alpha/users/<user_id>/keys")]
fn user_keys_cbor(pool: &State<DbPool>, user_id: &str) -> Result<(ContentType, Vec<u8>), Status> {
    let resp = build_user_keys_response(pool, user_id)?;
    let mut out = Vec::new();
    ciborium::ser::into_writer(&resp, &mut out).map_err(|_| Status::InternalServerError)?;
    Ok(cbor_response(out))
}

// TODO: deprecated, remove later — server-to-server key/handshake/userinfo retrieval moved to the TCP CSIL-RPC transport.
#[rocket::get("/v1alpha/users/<user_id>/keys.json")]
fn user_keys_json(pool: &State<DbPool>, user_id: &str) -> Result<(ContentType, Vec<u8>), Status> {
    let resp = build_user_keys_response(pool, user_id)?;
    let out = serde_json::to_vec(&resp).map_err(|_| Status::InternalServerError)?;
    Ok(json_response(out))
}

// -- Handshake --

// TODO: deprecated, remove later — server-to-server key/handshake/userinfo retrieval moved to the TCP CSIL-RPC transport.
#[rocket::post("/v1alpha/handshake", data = "<body>")]
fn handshake_cbor(body: Vec<u8>) -> Result<(ContentType, Vec<u8>), Status> {
    use liblinkkeys::generated::services::Handshake;
    let request: liblinkkeys::generated::types::HandshakeRequest =
        ciborium::de::from_reader(&body[..]).map_err(|_| Status::BadRequest)?;
    let resp = HandshakeHandler
        .handshake(&(), request)
        .map_err(|_| Status::InternalServerError)?;
    let mut out = Vec::new();
    ciborium::ser::into_writer(&resp, &mut out).map_err(|_| Status::InternalServerError)?;
    Ok(cbor_response(out))
}

// TODO: deprecated, remove later — server-to-server key/handshake/userinfo retrieval moved to the TCP CSIL-RPC transport.
#[rocket::post("/v1alpha/handshake.json", data = "<body>")]
fn handshake_json(body: String) -> Result<(ContentType, Vec<u8>), Status> {
    use liblinkkeys::generated::services::Handshake;
    let request: liblinkkeys::generated::types::HandshakeRequest =
        serde_json::from_str(&body).map_err(|_| Status::BadRequest)?;
    let resp = HandshakeHandler
        .handshake(&(), request)
        .map_err(|_| Status::InternalServerError)?;
    let out = serde_json::to_vec(&resp).map_err(|_| Status::InternalServerError)?;
    Ok(json_response(out))
}

// -- Auth: Browser-facing HTML login flow --

/// Render the login form for a verified `signed_request`. The "Logging in to
/// X" label and the round-tripped hidden field both derive from the verified
/// request — `signed_request` is the only field that matters on POST.
fn render_login_form(
    signed_request: &str,
    relying_party: &str,
    username: &str,
    error: Option<&str>,
) -> RawHtml<String> {
    let error_html = error
        .map(|e| format!(r#"<p class="error">{}</p>"#, html_escape(e)))
        .unwrap_or_default();

    let label_html = format!(
        r#"<p>Logging in to <strong>{}</strong></p>"#,
        html_escape(relying_party)
    );
    let hidden_inputs = format!(
        r#"  <input type="hidden" name="signed_request" value="{}" />"#,
        html_escape(signed_request)
    );

    RawHtml(format!(
        r#"<!DOCTYPE html>
<html>
<head><title>LinkKeys Login</title>
<style>
body {{ font-family: sans-serif; max-width: 400px; margin: 80px auto; }}
input {{ display: block; width: 100%; padding: 8px; margin: 8px 0; box-sizing: border-box; }}
button {{ padding: 10px 20px; margin-top: 12px; }}
.error {{ color: red; }}
</style>
</head>
<body>
<h2>LinkKeys Login</h2>
<p>Domain: <strong>{domain}</strong></p>
{label}
{error}
<form method="POST" action="/auth/authorize">
{hidden}
  <label>Username</label>
  <input type="text" name="username" value="{username}" autofocus />
  <label>Password</label>
  <input type="password" name="password" />
  <button type="submit">Log In</button>
</form>
</body>
</html>"#,
        domain = html_escape(&get_domain_name()),
        label = label_html,
        error = error_html,
        hidden = hidden_inputs,
        username = html_escape(username),
    ))
}

// -- Login proof: cross-step binding for the two-leg consent flow --
//
// WHY: the consent step (POST /auth/consent) happens in a *separate* request
// from the password step (POST /auth/authorize), so it must re-establish *which
// authenticated user* is consenting. Trusting an ambient IDP session cookie for
// that would open a consent-CSRF: anyone holding a victim's session cookie could
// drive a consent POST for an attacker-chosen RP and exfiltrate the victim's
// claims. Instead, the password step mints a short-lived token SIGNED BY THE
// IDP's own domain key that binds (user_id, this login request's nonce). It
// rides in a hidden form field — not a cookie — so it is not ambient: it is
// scoped to exactly this login request (the nonce must match the re-validated
// signed_request) and expires quickly. The IDP signature makes it unforgeable;
// the user never sees a long-lived IDP session as a side effect of an RP login.
// It never leaves the IDP, so it is server-internal and not part of the CSIL
// protocol.

const LOGIN_PROOF_TAG: &str = "linkkeys-login-proof-v1";
/// Lifetime of a login proof: long enough to read a consent screen, short
/// enough to bound replay.
const LOGIN_PROOF_TTL_SECONDS: i64 = 600;

#[derive(Serialize, Deserialize)]
struct LoginProofEnvelope {
    payload: Vec<u8>,
    signing_key_id: String,
    signature: Vec<u8>,
}

/// Canonical bytes a login proof signs: a domain-separated CBOR tuple binding
/// the authenticated user to a single login request — both its `login_nonce`
/// and its `relying_party` — plus expiry. Binding the relying party means the
/// proof can only complete consent for the RP it was minted for, independent of
/// whether RP-chosen nonces happen to be unique.
fn login_proof_payload(
    user_id: &str,
    login_nonce: &str,
    relying_party: &str,
    expires_at: &str,
) -> Vec<u8> {
    let payload = (
        LOGIN_PROOF_TAG,
        user_id,
        login_nonce,
        relying_party,
        expires_at,
    );
    let mut out = Vec::new();
    ciborium::ser::into_writer(&payload, &mut out)
        .expect("CBOR serialization of login proof cannot fail");
    out
}

/// Mint a base64url login proof binding `user_id` to this login request
/// (`login_nonce`, `relying_party`), signed with an active domain signing key.
fn mint_login_proof(
    pool: &DbPool,
    user_id: &str,
    login_nonce: &str,
    relying_party: &str,
) -> Result<String, Status> {
    use base64ct::{Base64UrlUnpadded, Encoding as _};

    let domain_keys = pool
        .list_active_domain_keys()
        .map_err(|_| Status::InternalServerError)?;
    let dk = pick_active_signing_key(&domain_keys).ok_or(Status::InternalServerError)?;
    let passphrase = env::var("DOMAIN_KEY_PASSPHRASE").map_err(|_| Status::InternalServerError)?;
    let sk_bytes =
        liblinkkeys::crypto::decrypt_private_key(&dk.private_key_encrypted, passphrase.as_bytes())
            .map_err(|_| Status::InternalServerError)?;
    let algorithm = liblinkkeys::crypto::SigningAlgorithm::parse_str(&dk.algorithm)
        .ok_or(Status::InternalServerError)?;

    let expires_at =
        (chrono::Utc::now() + chrono::Duration::seconds(LOGIN_PROOF_TTL_SECONDS)).to_rfc3339();
    let payload = login_proof_payload(user_id, login_nonce, relying_party, &expires_at);
    let signature = liblinkkeys::crypto::sign_with_algorithm(algorithm, &payload, &sk_bytes)
        .map_err(|_| Status::InternalServerError)?;

    let envelope = LoginProofEnvelope {
        payload,
        signing_key_id: dk.id.clone(),
        signature,
    };
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&envelope, &mut cbor).map_err(|_| Status::InternalServerError)?;
    Ok(Base64UrlUnpadded::encode_string(&cbor))
}

/// Verify a login proof against this IDP's active signing keys; returns the
/// bound `(user_id, login_nonce, relying_party)` if the signature is valid, the
/// tag matches, and it has not expired. The caller MUST additionally check
/// `login_nonce` and `relying_party` against the re-validated signed_request to
/// bind the two legs together.
fn verify_login_proof(pool: &DbPool, proof: &str) -> Result<(String, String, String), ()> {
    use base64ct::{Base64UrlUnpadded, Encoding as _};

    let cbor = Base64UrlUnpadded::decode_vec(proof).map_err(|_| ())?;
    let envelope: LoginProofEnvelope = ciborium::de::from_reader(&cbor[..]).map_err(|_| ())?;

    let domain_keys = pool.list_active_domain_keys().map_err(|_| ())?;
    let csil_keys: Vec<DomainPublicKey> = domain_keys.iter().map(Into::into).collect();
    let key = csil_keys
        .iter()
        .find(|k| k.key_id == envelope.signing_key_id)
        .ok_or(())?;
    liblinkkeys::assertions::check_signing_key_valid(key).map_err(|_| ())?;
    liblinkkeys::crypto::resolve_and_verify(
        &key.algorithm,
        &envelope.payload,
        &envelope.signature,
        &key.public_key,
    )
    .map_err(|_| ())?;

    let (tag, user_id, login_nonce, relying_party, expires_at): (
        String,
        String,
        String,
        String,
        String,
    ) = ciborium::de::from_reader(&envelope.payload[..]).map_err(|_| ())?;
    if tag != LOGIN_PROOF_TAG {
        return Err(());
    }
    let expires = chrono::DateTime::parse_from_rfc3339(&expires_at).map_err(|_| ())?;
    if chrono::Utc::now() > expires {
        return Err(());
    }
    Ok((user_id, login_nonce, relying_party))
}

/// Render the consent screen: one row per requested claim, each showing whether
/// it is required, its datatype, whether the user has a value, and any locked
/// home-domain policy disposition. The signed_request and an IDP-signed login
/// proof ride in hidden fields so the consent POST re-validates the exact same
/// request and re-establishes the authenticated user without a session cookie.
fn render_consent_form(
    signed_request: &str,
    login_proof: &str,
    relying_party: &str,
    screen: &ConsentScreen,
    rp_claims: &[VerifiedRpClaim],
    error: Option<&str>,
) -> RawHtml<String> {
    use liblinkkeys::consent::PolicyDisposition;

    let error_html = error
        .map(|e| format!(r#"<p class="error">{}</p>"#, html_escape(e)))
        .unwrap_or_default();

    // "About this site": the RP's self-asserted claims and their attestation.
    let about_html = if rp_claims.is_empty() {
        String::new()
    } else {
        let mut items = String::new();
        for c in rp_claims {
            let badge = if c.verified {
                format!(
                    r#"<span style="color:#080">✓ attested by {}</span>"#,
                    html_escape(&c.attested_by.join(", "))
                )
            } else {
                r#"<span style="color:#a00">⚠ unverified</span>"#.to_string()
            };
            items.push_str(&format!(
                r#"<li><strong>{}</strong>: {} — {}</li>"#,
                html_escape(&c.claim_type),
                html_escape(&c.value),
                badge,
            ));
        }
        format!(
            r#"<div style="background:#f6f6f6;padding:8px 12px;border-radius:6px;margin-bottom:12px;">
<p style="margin:0 0 4px;">About <strong>{rp}</strong>:</p>
<ul style="margin:0;">{items}</ul>
</div>"#,
            rp = html_escape(relying_party),
            items = items,
        )
    };

    let mut rows = String::new();
    for row in &screen.rows {
        let ct = html_escape(&row.claim_type);
        let dt = html_escape(&row.datatype);
        let need = if row.required { "required" } else { "optional" };
        let avail = if row.available {
            String::new()
        } else {
            r#" <span style="color:#a60">(no value stored — nothing will be sent)</span>"#
                .to_string()
        };

        let control = match row.policy {
            PolicyDisposition::ForcedAllow => {
                r#"<input type="checkbox" checked disabled /> <em>always shared (your provider's policy)</em>"#
                    .to_string()
            }
            PolicyDisposition::ForcedDeny => {
                r#"<input type="checkbox" disabled /> <em>never shared (your provider's policy)</em>"#
                    .to_string()
            }
            PolicyDisposition::User => {
                let checked = if row.default_granted() { "checked" } else { "" };
                let required_attr = if row.required { "required" } else { "" };
                format!(
                    r#"<input type="checkbox" name="grant" value="{ct}" {checked} {required_attr} />"#,
                    ct = ct,
                    checked = checked,
                    required_attr = required_attr,
                )
            }
        };

        rows.push_str(&format!(
            r#"<li>{control} <strong>{ct}</strong> <small>({dt}, {need})</small>{avail}</li>"#,
            control = control,
            ct = ct,
            dt = dt,
            need = need,
            avail = avail,
        ));
    }

    RawHtml(format!(
        r#"<!DOCTYPE html>
<html>
<head><title>LinkKeys Consent</title>
<style>
body {{ font-family: sans-serif; max-width: 480px; margin: 60px auto; }}
ul {{ list-style: none; padding: 0; }}
li {{ padding: 8px 0; border-bottom: 1px solid #eee; }}
button {{ padding: 10px 20px; margin-top: 16px; }}
.error {{ color: red; }}
em {{ color: #555; }}
</style>
</head>
<body>
<h2>Share your information</h2>
{about}
<p><strong>{rp}</strong> is requesting access to the following from <strong>{domain}</strong>.
Choose what to share. You can change this later by signing in again.</p>
{error}
<form method="POST" action="/auth/consent">
  <input type="hidden" name="signed_request" value="{sr}" />
  <input type="hidden" name="login_proof" value="{proof}" />
  <ul>
{rows}
  </ul>
  <button type="submit">Continue</button>
</form>
</body>
</html>"#,
        about = about_html,
        rp = html_escape(relying_party),
        domain = html_escape(&get_domain_name()),
        error = error_html,
        sr = html_escape(signed_request),
        proof = html_escape(login_proof),
        rows = rows,
    ))
}

/// Complete a login: burn the single-use request nonce, persist the consent
/// decision as a standing grant (when the RP requested anything), sign the
/// identity assertion carrying `authorized_claims`, encrypt it for the RP, and
/// produce the callback redirect. On failure returns a user-facing message for
/// the caller to render in its own page/form.
async fn finalize_login(
    pool: &DbPool,
    net: &Net,
    nonces: &nonce_store::NonceStore,
    user: &crate::db::models::User,
    request: &AuthRequest,
    authorized_claims: Vec<String>,
    requested: Vec<String>,
) -> Result<Redirect, String> {
    // Single-use: burn the trusted CBOR nonce now, at token issuance, so an
    // abandoned consent screen doesn't consume the login request prematurely.
    if !nonces.record(&format!("login:{}", request.nonce)) {
        return Err(
            "This login request has already been used. Please start a new login.".to_string(),
        );
    }

    // CBOR-record the claims the RP asserted about itself: the non-repudiable
    // evidence of what it offered, recorded even when no user data is released.
    let offered_cbor: Option<Vec<u8>> = match request.relying_party_claims.as_deref() {
        Some(claims) if !claims.is_empty() => {
            let mut b = Vec::new();
            ciborium::ser::into_writer(claims, &mut b)
                .map_err(|_| "Failed to encode offered claims.".to_string())?;
            Some(b)
        }
        _ => None,
    };

    // Persist a standing grant whenever the RP requested anything (even an empty
    // authorized set records "asked, granted nothing") OR asserted claims about
    // itself (so the offered terms are recorded even on an auth-only login).
    if !requested.is_empty() || offered_cbor.is_some() {
        let now = chrono::Utc::now();
        let issued_at = now.to_rfc3339();
        let expires_at = (now + chrono::Duration::seconds(consent_ttl_seconds())).to_rfc3339();
        let grant_id = uuid::Uuid::now_v7().to_string();
        let signed = sign_consent_grant_for_user(
            pool,
            &grant_id,
            &user.id,
            &request.relying_party,
            &authorized_claims,
            &issued_at,
            &expires_at,
        )
        .map_err(|_| "Failed to sign consent grant.".to_string())?;
        let mut grant_bytes = Vec::new();
        ciborium::ser::into_writer(&signed, &mut grant_bytes)
            .map_err(|_| "Failed to encode consent grant.".to_string())?;
        pool.upsert_consent_grant(
            &grant_id,
            &user.id,
            &get_domain_name(),
            &request.relying_party,
            &authorized_claims,
            &requested,
            &grant_bytes,
            offered_cbor.as_deref(),
            &issued_at,
            &expires_at,
        )
        .map_err(|_| "Failed to store consent grant.".to_string())?;
    }

    let token = sign_assertion_for_user(
        pool,
        user,
        &request.relying_party,
        &request.nonce,
        authorized_claims,
    )
    .map_err(|_| "Internal server error during signing.".to_string())?;

    let encrypted = encrypt_token_for_rp(pool, net, &token, &request.relying_party)
        .await
        .map_err(|_| "Failed to encrypt token for relying party.".to_string())?;

    let separator = if request.callback_url.contains('?') {
        "&"
    } else {
        "?"
    };
    Ok(Redirect::found(format!(
        "{}{}encrypted_token={}",
        request.callback_url, separator, encrypted
    )))
}

#[rocket::get("/auth/authorize?<user_hint>&<signed_request>")]
async fn auth_authorize_get(
    pool: &State<DbPool>,
    net: &State<Net>,
    user_hint: Option<&str>,
    signed_request: Option<&str>,
) -> Result<RawHtml<String>, Status> {
    // signed_request is the only accepted flow. A request without it (or one
    // that fails verification) renders an error page, never a login form — so
    // an attacker who can craft a URL cannot phish credentials onto a
    // legitimate-looking page.
    let sr = signed_request.ok_or(Status::BadRequest)?;
    match validate_signed_request(pool, net, sr).await {
        Ok(request) => Ok(render_login_form(
            sr,
            &request.relying_party,
            user_hint.unwrap_or(""),
            None,
        )),
        Err(e) => Ok(render_error_page(e.user_message())),
    }
}

#[derive(FromForm)]
struct AuthorizeForm {
    username: String,
    password: String,
    /// The signed_request blob — the only field that matters; it carries the
    /// verified relying_party, callback_url, and nonce.
    signed_request: Option<String>,
}

#[rocket::post("/auth/authorize", data = "<form>")]
async fn auth_authorize_post(
    pool: &State<DbPool>,
    net: &State<Net>,
    nonces: &State<nonce_store::NonceStore>,
    form: rocket::form::Form<AuthorizeForm>,
) -> Result<Redirect, RawHtml<String>> {
    if let Some(sr) = form.signed_request.as_deref() {
        handle_signed_request_post(pool, net, nonces, &form, sr).await
    } else {
        Err(render_error_page(
            "Missing signed_request. This login flow is no longer supported.",
        ))
    }
}

async fn handle_signed_request_post(
    pool: &State<DbPool>,
    net: &State<Net>,
    nonces: &State<nonce_store::NonceStore>,
    form: &AuthorizeForm,
    signed_request_param: &str,
) -> Result<Redirect, RawHtml<String>> {
    let request = match validate_signed_request(pool, net, signed_request_param).await {
        Ok(r) => r,
        Err(e) => return Err(render_error_page(e.user_message())),
    };

    let render_form_error = |msg: &str| {
        render_login_form(
            signed_request_param,
            &request.relying_party,
            &form.username,
            Some(msg),
        )
    };

    let authenticator = PasswordAuthenticator::new(pool.inner().clone());
    let user = match crate::services::auth::Authenticator::authenticate(
        &authenticator,
        &form.username,
        &form.password,
    ) {
        Ok(u) => u,
        Err(_) => return Err(render_form_error("Invalid username or password.")),
    };

    // Administrator accounts administer the domain and do not "go elsewhere":
    // they have no presentable profile and may not be presented to a relying
    // party. Refuse before showing any consent screen.
    if user.is_admin_account {
        return Err(render_error_page(
            "This is an administrator account and cannot be used to sign in to applications.",
        ));
    }

    // Audience is the relying-party DOMAIN (what a verifier checks), not the
    // full callback URL. The login-request nonce is burned inside finalize_login
    // at token issuance — not here — so an abandoned consent screen doesn't
    // consume a legitimate request.
    let Ok(policy) = domain_policy_for(pool, &request.relying_party) else {
        return Err(render_form_error(
            "Could not load the release policy. Please try again.",
        ));
    };
    match request.requested_claims.clone() {
        // Authentication only: no claims requested, nothing to consent to.
        None => finalize_login(pool, net, nonces, &user, &request, vec![], vec![])
            .await
            .map_err(|m| render_form_error(&m)),
        Some(req) => {
            let requested = requested_types(&req);

            // Skip the consent prompt when a standing grant already covers
            // everything the RP is asking for; reissue under current policy.
            if let Some(prior) = pool
                .find_active_consent_grant(&user.id, &request.relying_party)
                .ok()
                .flatten()
            {
                // Skip only if the prior decision still satisfies every required
                // claim — e.g. an RP that upgraded a previously-declined optional
                // to required must re-prompt, not silently complete without it.
                if grant_covers(&prior, &req) {
                    let authorized = compute_authorized_claims(&req, &prior.claim_types, &policy);
                    if first_unsatisfied_required(&req, &authorized, &policy).is_none() {
                        return finalize_login(
                            pool, net, nonces, &user, &request, authorized, requested,
                        )
                        .await
                        .map_err(|m| render_form_error(&m));
                    }
                }
            }

            // Consent needed: mint an IDP-signed login proof binding this user
            // to this login request, carried in the consent form so /auth/consent
            // re-establishes the authenticated user without a session cookie.
            let proof =
                match mint_login_proof(pool, &user.id, &request.nonce, &request.relying_party) {
                    Ok(p) => p,
                    Err(_) => {
                        return Err(render_form_error(
                            "Internal server error preparing consent.",
                        ))
                    }
                };
            let rp_claims = match request.relying_party_claims.as_deref() {
                Some(c) => verify_relying_party_claims(pool, net, &request.relying_party, c).await,
                None => Vec::new(),
            };
            let screen =
                build_consent_screen(pool, &user.id, &request.relying_party, &req, &policy);
            Err(render_consent_form(
                signed_request_param,
                &proof,
                &request.relying_party,
                &screen,
                &rp_claims,
                None,
            ))
        }
    }
}

#[derive(FromForm)]
struct ConsentForm {
    /// The same signed_request the login form carried; re-validated here.
    signed_request: String,
    /// IDP-signed proof of the authenticated user, bound to this login request.
    login_proof: String,
    /// The claim types the user chose to share (one value per checked box).
    grant: Vec<String>,
}

/// Second leg of the browser consent flow. The user authenticated in the
/// previous request; an IDP-signed login proof (not a session cookie) carries
/// their identity, bound to this login request's nonce. We verify the proof,
/// re-validate the signed_request, confirm the proof was minted for *this*
/// request, apply policy, enforce required claims, then finalize as the
/// no-consent path does. See the login-proof note above for the rationale.
#[rocket::post("/auth/consent", data = "<form>")]
async fn auth_consent_post(
    pool: &State<DbPool>,
    net: &State<Net>,
    nonces: &State<nonce_store::NonceStore>,
    form: rocket::form::Form<ConsentForm>,
) -> Result<Redirect, RawHtml<String>> {
    let Ok((user_id, proof_nonce, proof_rp)) = verify_login_proof(pool, &form.login_proof) else {
        return Err(render_error_page(
            "Your login could not be verified. Please start the login again.",
        ));
    };

    let request = match validate_signed_request(pool, net, &form.signed_request).await {
        Ok(r) => r,
        Err(e) => return Err(render_error_page(e.user_message())),
    };
    // Bind the two legs: the proof must have been minted for this exact request
    // — same nonce AND same relying party.
    if proof_nonce != request.nonce || proof_rp != request.relying_party {
        return Err(render_error_page(
            "This consent does not match the login request. Please start the login again.",
        ));
    }
    let Some(req) = request.requested_claims.clone() else {
        return Err(render_error_page(
            "This login request does not request any claims.",
        ));
    };
    let user = match pool.find_user_by_id(&user_id) {
        Ok(u) => u,
        Err(_) => return Err(render_error_page("Your account could not be found.")),
    };

    let Ok(policy) = domain_policy_for(pool, &request.relying_party) else {
        return Err(render_error_page(
            "Could not load the release policy. Please try again.",
        ));
    };
    let authorized = compute_authorized_claims(&req, &form.grant, &policy);

    // A required claim the user declined (and policy didn't deny) blocks
    // completion: re-render the consent screen with an error.
    if let Some(missing) = first_unsatisfied_required(&req, &authorized, &policy) {
        let rp_claims = match request.relying_party_claims.as_deref() {
            Some(c) => verify_relying_party_claims(pool, net, &request.relying_party, c).await,
            None => Vec::new(),
        };
        let screen = build_consent_screen(pool, &user_id, &request.relying_party, &req, &policy);
        return Err(render_consent_form(
            &form.signed_request,
            &form.login_proof,
            &request.relying_party,
            &screen,
            &rp_claims,
            Some(&format!(
                "\u{201c}{}\u{201d} is required to continue.",
                missing
            )),
        ));
    }

    finalize_login(
        pool,
        net,
        nonces,
        &user,
        &request,
        authorized,
        requested_types(&req),
    )
    .await
    .map_err(|m| render_error_page(&m))
}

/// Reasons a `signed_request` may be rejected. Each maps to a
/// user-visible error string; structurally distinct so callers (and
/// tests) can branch on the failure mode.
#[derive(Debug)]
pub enum ValidateAuthRequestError {
    Malformed,
    KeyFetchFailed,
    SignatureInvalid,
    Expired,
    CallbackNotHttps,
    CallbackOffDomain,
    CallbackUnparseable,
}

impl ValidateAuthRequestError {
    pub fn user_message(&self) -> &'static str {
        match self {
            Self::Malformed => "The login request was malformed.",
            Self::KeyFetchFailed => "Could not retrieve the relying party's public keys.",
            Self::SignatureInvalid => "The login request signature is invalid.",
            Self::Expired => "The login request has expired. Please start a new login.",
            Self::CallbackNotHttps => "The callback URL must use https.",
            Self::CallbackOffDomain => "The callback URL is not within the relying party's domain.",
            Self::CallbackUnparseable => "The callback URL is malformed.",
        }
    }
}

/// True when the callback URL is `https://` and its host equals
/// `rp_domain` or is a strict subdomain of it. Used as a defense-in-depth
/// check on top of the RP's signature: even a misbehaving RP cannot
/// authorize callbacks to a domain it doesn't own.
fn callback_within_rp_domain(callback_url: &str, rp_domain: &str) -> Result<bool, ()> {
    let rest = match callback_url.strip_prefix("https://") {
        Some(r) => r,
        None => return Ok(false),
    };
    let host_with_extras = rest.split(['/', '?', '#']).next().ok_or(())?;
    if host_with_extras.is_empty() {
        return Err(());
    }
    let after_userinfo = match host_with_extras.rsplit_once('@') {
        Some((_, host)) => host,
        None => host_with_extras,
    };
    // Strip port, but only the last ':' segment if it's all digits — this
    // also leaves bracketed IPv6 hosts intact for the equality check.
    let host = if let Some((h, port)) = after_userinfo.rsplit_once(':') {
        if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            h
        } else {
            after_userinfo
        }
    } else {
        after_userinfo
    };
    if host.is_empty() {
        return Err(());
    }
    Ok(host == rp_domain || host.ends_with(&format!(".{}", rp_domain)))
}

/// Validate a `signed_request` URL parameter end-to-end:
/// 1. Decode the base64url+CBOR envelope (untrusted).
/// 2. Peek at `relying_party` so we know which RP's keys to fetch.
/// 3. Fetch RP keys (local DB or DNS+HTTP).
/// 4. Verify signature + timestamp via `verify_auth_request`.
/// 5. Defense-in-depth: callback must be https and within rp_domain.
///
/// On success returns the trusted `AuthRequest`. The URL/form-supplied
/// `relying_party`, `callback_url`, and `nonce` are *not* consulted —
/// callers should use the returned `AuthRequest`'s fields exclusively.
pub async fn validate_signed_request(
    pool: &DbPool,
    net: &Net,
    signed_request_param: &str,
) -> Result<AuthRequest, ValidateAuthRequestError> {
    let envelope = liblinkkeys::encoding::signed_auth_request_from_url_param(signed_request_param)
        .map_err(|_| ValidateAuthRequestError::Malformed)?;

    // Untrusted preview: we only need `relying_party` to know whose keys
    // to fetch. Every other field is re-read from the verified bytes.
    let preview: AuthRequest = ciborium::de::from_reader(envelope.request.as_slice())
        .map_err(|_| ValidateAuthRequestError::Malformed)?;
    let rp_domain = preview.relying_party.clone();

    let rp_keys = rp::fetch_rp_keys(pool, net, &rp_domain)
        .await
        .map_err(|e| {
            log::warn!("RP key fetch failed for relying_party={}: {}", rp_domain, e);
            ValidateAuthRequestError::KeyFetchFailed
        })?;
    if rp_keys.is_empty() {
        log::warn!(
            "RP key fetch for relying_party={} returned no trusted keys",
            rp_domain
        );
        return Err(ValidateAuthRequestError::KeyFetchFailed);
    }

    let request = liblinkkeys::auth_request::verify_auth_request(
        &envelope,
        &rp_keys,
        MAX_AUTH_REQUEST_AGE_SECONDS,
    )
    .map_err(|e| match e {
        liblinkkeys::assertions::VerifyError::Expired => ValidateAuthRequestError::Expired,
        _ => ValidateAuthRequestError::SignatureInvalid,
    })?;

    if !request.callback_url.starts_with("https://") {
        return Err(ValidateAuthRequestError::CallbackNotHttps);
    }
    match callback_within_rp_domain(&request.callback_url, &request.relying_party) {
        Ok(true) => {}
        Ok(false) => return Err(ValidateAuthRequestError::CallbackOffDomain),
        Err(()) => return Err(ValidateAuthRequestError::CallbackUnparseable),
    }

    Ok(request)
}

/// Render a minimal error page (for signed_request validation failures
/// where re-rendering the login form would be misleading or unsafe).
fn render_error_page(message: &str) -> RawHtml<String> {
    RawHtml(format!(
        r#"<!DOCTYPE html>
<html><head><title>LinkKeys Login Error</title>
<style>body {{ font-family: sans-serif; max-width: 400px; margin: 80px auto; }}
.error {{ color: red; }}</style></head>
<body><h2>LinkKeys Login</h2>
<p class="error">{}</p>
</body></html>"#,
        html_escape(message)
    ))
}

/// Encrypt a signed assertion token for a relying party.
///
/// Resolves RP keys via `rp::fetch_rp_keys` (local DB if same instance,
/// DNS+HTTP otherwise), derives an X25519 public key from the first
/// active key, and seals the assertion to it.
pub async fn encrypt_token_for_rp(
    pool: &DbPool,
    net: &Net,
    token_url_param: &str,
    rp_domain: &str,
) -> Result<String, Status> {
    let rp_keys = rp::fetch_rp_keys(pool, net, rp_domain)
        .await
        .map_err(|_| Status::BadGateway)?;

    // Seal to the RP's dedicated X25519 ENCRYPTION key (key_usage == "encrypt"),
    // whose 32-byte public_key is used directly — no Ed25519→X25519 conversion.
    let rp_enc_key = rp_keys
        .iter()
        .find(|k| k.key_usage == "encrypt")
        .ok_or(Status::BadGateway)?;
    let x25519_pub: [u8; 32] = rp_enc_key
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| Status::InternalServerError)?;

    // The token is already base64url-encoded CBOR of SignedIdentityAssertion.
    // Decode it back to raw CBOR bytes for encryption.
    let signed_assertion = liblinkkeys::encoding::assertion_from_url_param(token_url_param)
        .map_err(|_| Status::InternalServerError)?;
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&signed_assertion, &mut cbor_bytes)
        .map_err(|_| Status::InternalServerError)?;

    // Encrypt with sealed box
    let sealed = liblinkkeys::crypto::sealed_box_encrypt(&cbor_bytes, &x25519_pub)
        .map_err(|_| Status::InternalServerError)?;

    let encrypted_token = liblinkkeys::generated::types::EncryptedToken {
        ephemeral_public_key: sealed.ephemeral_public_key,
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
    };

    liblinkkeys::encoding::encrypted_token_to_url_param(&encrypted_token)
        .map_err(|_| Status::InternalServerError)
}

// -- Userinfo: Token-based API --

/// Redeem an assertion for user info, bound to the relying party that the
/// assertion was issued for (crypto-06 / web-04 / tcp-02).
///
/// The caller is no longer an anonymous bearer of the assertion: it must wrap
/// the token in a `SignedUserInfoRequest` and sign it with its domain key. We
/// verify that proof-of-possession against the relying party's DNS-pinned
/// signing keys, then require the proven `relying_party` to equal the
/// assertion's `audience`. Redemption is single-use within the assertion TTL.
pub async fn build_userinfo_signed(
    pool: &DbPool,
    net: &Net,
    signed: &liblinkkeys::generated::types::SignedUserInfoRequest,
) -> Result<UserInfo, Status> {
    // Read the (still untrusted) inner request only to learn which relying
    // party is asking. The signature below is verified over these exact bytes,
    // so decoding-before-verifying leaks no trust.
    let claimed: liblinkkeys::generated::types::UserInfoRequest =
        ciborium::de::from_reader(signed.request.as_slice()).map_err(|_| Status::BadRequest)?;

    // Resolve the relying party's signing keys (RP-inlined + DNS-pinned, or an
    // authoritative fetch) and verify the proof-of-possession over the request.
    let rp_keys = rp::resolve_rp_signing_keys(
        pool,
        net,
        &claimed.relying_party,
        signed.public_keys.as_deref(),
    )
    .await
    .map_err(|_| Status::BadGateway)?;

    let request = liblinkkeys::userinfo::verify_user_info_request(
        signed,
        &rp_keys,
        MAX_USERINFO_REQUEST_AGE_SECONDS,
    )
    .map_err(|_| Status::Unauthorized)?;

    // Bind redemption to the assertion's audience: the proven requester domain
    // MUST equal the domain the token was issued for.
    let token_str = String::from_utf8(request.token).map_err(|_| Status::BadRequest)?;
    let assertion = verify_token_with_audience(pool, &token_str, Some(&request.relying_party))?;

    // Single-use redemption via the durable nonce store (web-03/web-04),
    // namespaced "userinfo:" so it's independent of the login-request replay
    // check. record_nonce returns false if this assertion was already redeemed.
    let burned = pool
        .record_nonce(
            &format!("userinfo:{}", assertion.nonce),
            std::time::Duration::from_secs(MAX_USERINFO_REQUEST_AGE_SECONDS as u64),
        )
        .map_err(|_| Status::InternalServerError)?;
    if !burned {
        return Err(Status::Unauthorized);
    }

    let user = pool
        .find_user_by_id(&assertion.user_id)
        .map_err(db_err_to_status)?;
    let claims = pool
        .list_active_claims(&assertion.user_id)
        .map_err(|_| Status::InternalServerError)?;

    // Scope the released claims to exactly what the user consented to for this
    // audience, as recorded in the assertion. Fail-closed: an assertion with an
    // empty authorized_claims releases no claims.
    let all_claims: Vec<Claim> = claims.iter().map(Into::into).collect();
    let scoped = consent::scope_claims(&all_claims, &assertion.authorized_claims);

    // Echo the subject the assertion was issued for (a presentable profile id),
    // NOT the account id. For a default single-profile account these are equal;
    // keeping them distinct here ensures that once non-default personas resolve
    // their own claims, the response never leaks the account id (which would link
    // personas). The display_name is the account's for now (per-profile display
    // is a later step).
    Ok(UserInfo {
        user_id: assertion.user_id,
        domain: get_domain_name(),
        display_name: user.display_name,
        claims: scoped,
    })
}

// TODO: deprecated, remove later — server-to-server key/handshake/userinfo retrieval moved to the TCP CSIL-RPC transport.
#[rocket::post("/v1alpha/userinfo", data = "<body>")]
async fn userinfo_cbor(
    pool: &State<DbPool>,
    net: &State<Net>,
    body: Vec<u8>,
) -> Result<(ContentType, Vec<u8>), Status> {
    let signed: liblinkkeys::generated::types::SignedUserInfoRequest =
        ciborium::de::from_reader(&body[..]).map_err(|_| Status::BadRequest)?;

    let resp = build_userinfo_signed(pool, net, &signed).await?;
    let mut out = Vec::new();
    ciborium::ser::into_writer(&resp, &mut out).map_err(|_| Status::InternalServerError)?;
    Ok(cbor_response(out))
}

/// Generic CBOR-RPC carrier: the web's second-class mirror of the TCP service
/// dispatch. The body is a CBOR `RequestEnvelope`; we run the same `dispatch()`
/// and return the CBOR `ResponseEnvelope`. This is how the web carries the whole
/// RPC surface (e.g. `Attestation/deposit-claim`) without per-op routes — a
/// browser is never the intended caller here, another server is. `dispatch` is
/// synchronous (diesel), so run it on a blocking thread.
#[rocket::post("/csil/v1/rpc", data = "<body>")]
async fn rpc_cbor(
    pool: &State<DbPool>,
    ready: &State<Arc<AtomicBool>>,
    body: Vec<u8>,
) -> (ContentType, Vec<u8>) {
    let pool = pool.inner().clone();
    let ready = ready.inner().clone();
    let resp = rocket::tokio::task::spawn_blocking(move || {
        crate::tcp::dispatch_envelope(&body, &ready, &pool, None)
    })
    .await
    .unwrap_or_default();
    cbor_response(resp)
}

// -- TLS + Launch --

fn generate_self_signed_cert() -> (String, String) {
    let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("Failed to generate self-signed cert");
    let cert_pem = certified_key.cert.pem();
    let key_pem = certified_key.key_pair.serialize_pem();
    (cert_pem, key_pem)
}

pub async fn launch_rocket(db_pool: DbPool, ready_flag: Arc<AtomicBool>) {
    let disable_tls = env::var("DISABLE_TLS").unwrap_or_default() == "true";
    let default_port = if disable_tls { "8080" } else { "8443" };
    let port: u16 = env::var("HTTPS_PORT")
        .unwrap_or_else(|_| default_port.to_string())
        .parse()
        .unwrap_or(8443);

    let tls = if disable_tls {
        log::info!(
            "Starting Rocket HTTP server on port {} (TLS disabled)",
            port
        );
        None
    } else {
        log::info!("Starting Rocket HTTPS server on port {}", port);
        let (cert_pem, key_pem) = generate_self_signed_cert();
        Some(rocket::config::TlsConfig::from_bytes(
            cert_pem.as_bytes(),
            key_pem.as_bytes(),
        ))
    };

    // Session-cookie signing/encryption key. Persist it via ROCKET_SECRET_KEY so
    // sessions survive restarts and are consistent across replicas; otherwise
    // generate an ephemeral key (dev only) and warn loudly (svc-04).
    let secret_key = match env::var("ROCKET_SECRET_KEY") {
        Ok(material) if material.len() >= 32 => {
            rocket::config::SecretKey::derive_from(material.as_bytes())
        }
        Ok(_) => {
            log::error!(
                "ROCKET_SECRET_KEY is set but too short (need >= 32 chars); \
                 generating an ephemeral key — sessions will not persist."
            );
            rocket::config::SecretKey::generate().expect("Failed to generate Rocket secret key")
        }
        Err(_) => {
            log::warn!(
                "ROCKET_SECRET_KEY not set; generating an ephemeral session key. \
                 Sessions will NOT survive restart or work across replicas. \
                 Set ROCKET_SECRET_KEY (>= 32 chars) in production."
            );
            rocket::config::SecretKey::generate().expect("Failed to generate Rocket secret key")
        }
    };

    let config = Config {
        port,
        address: "0.0.0.0".parse().unwrap(),
        tls,
        secret_key,
        ..Config::default()
    };

    let rocket_instance = build_rocket(db_pool, ready_flag, Net::production(), config);
    if let Err(e) = rocket_instance.launch().await {
        log::error!("Rocket failed: {}", e);
        std::process::exit(1);
    }
}

/// Assemble the Rocket instance — all routes and managed state — for a given
/// pool, network seam, and config. `launch_rocket` wraps this with production
/// config and `Net::production()`; tests build it with a fake `Net` and drive it
/// through a `rocket::local` client, exercising every handler end-to-end with no
/// network socket. Route mounting (incl. the feature gates) is identical to
/// production so tests cover the real wiring.
pub fn build_rocket(
    db_pool: DbPool,
    ready_flag: Arc<AtomicBool>,
    net: Net,
    config: Config,
) -> rocket::Rocket<rocket::Build> {
    let mut routes = rocket::routes![
        index,
        healthcheck,
        readiness,
        hello_get,
        hello_post,
        domain_keys_cbor,
        domain_keys_json,
        user_keys_cbor,
        user_keys_json,
        handshake_cbor,
        handshake_json,
        userinfo_cbor,
        rpc_cbor,
    ];

    // Mount password auth routes (login form) when enabled (default: true)
    if env::var("ENABLE_PASSWORD_AUTH").unwrap_or_else(|_| "true".to_string()) == "true" {
        log::info!("Password auth enabled");
        routes.extend(rocket::routes![
            auth_authorize_get,
            auth_authorize_post,
            auth_consent_post
        ]);
    }

    let nonce_store =
        nonce_store::NonceStore::new(db_pool.clone(), std::time::Duration::from_secs(300));
    let rp_claims_config = crate::rp_config::RpClaimsConfig::load_from_env();
    let mut rocket_instance = rocket::custom(config)
        .mount("/", routes)
        .manage(db_pool)
        .manage(ready_flag)
        .manage(nonce_store)
        .manage(rp_claims_config)
        .manage(net);

    // Mount RP endpoints when enabled
    if env::var("ENABLE_RP_ENDPOINTS").unwrap_or_default() == "true" {
        log::info!("RP endpoints enabled");
        rocket_instance = rocket_instance.mount(
            "/",
            rocket::routes![
                rp::sign_request_json,
                rp::decrypt_token_json,
                rp::verify_assertion_json,
                rp::fetch_userinfo_json,
            ],
        );
    }

    // Mount admin API endpoints (permission checked in handlers)
    rocket_instance = rocket_instance.mount(
        "/",
        rocket::routes![
            admin::admin_list_users,
            admin::admin_get_user,
            admin::admin_create_user,
            admin::admin_update_user,
            admin::admin_deactivate_user,
            admin::admin_reset_password,
            admin::admin_remove_credential,
            admin::admin_set_claim,
            admin::admin_remove_claim,
            admin::admin_grant_relation,
            admin::admin_remove_relation,
            admin::admin_list_relations,
            admin::admin_check_permission,
        ],
    );

    // Mount account (self-service) API endpoints
    rocket_instance = rocket_instance.mount(
        "/",
        rocket::routes![
            account::account_change_password,
            account::account_get_my_info,
        ],
    );

    // Mount server-rendered HTML UI for account self-service
    rocket_instance = rocket_instance.mount(
        "/",
        rocket::routes![
            account_ui::login_page,
            account_ui::login_submit,
            account_ui::logout,
            account_ui::account_dashboard,
            account_ui::change_password_page,
            account_ui::change_password_submit,
            profile_ui::identity_editor,
            profile_ui::set_claim_submit,
            profile_ui::create_profile_submit,
            profile_ui::verify_email,
            profile_ui::set_share_submit,
            profile_ui::request_verification,
            profile_ui::request_verification_download,
        ],
    );

    // Mount server-rendered HTML UI for user administration
    rocket_instance = rocket_instance.mount(
        "/",
        rocket::routes![
            admin_ui::admin_ui_user_list,
            admin_ui::admin_ui_create_user_page,
            admin_ui::admin_ui_create_user_submit,
            admin_ui::admin_ui_user_detail,
            admin_ui::admin_ui_update_user,
            admin_ui::admin_ui_deactivate_user,
            admin_ui::admin_ui_activate_user,
            admin_ui::admin_ui_reset_password,
            admin_ui::admin_ui_add_claim,
            admin_ui::admin_ui_remove_claim,
            admin_ui::admin_ui_grant_relation,
            admin_ui::admin_ui_remove_relation,
        ],
    );

    // Mount the admin policy editor (claim-type registry, trusted issuers,
    // release defaults, approval queue).
    rocket_instance = rocket_instance.mount(
        "/",
        rocket::routes![
            policy_admin_ui::policy_admin,
            policy_admin_ui::upsert_policy,
            policy_admin_ui::delete_policy,
            policy_admin_ui::add_issuer,
            policy_admin_ui::remove_issuer,
            policy_admin_ui::upsert_release,
            policy_admin_ui::delete_release,
            policy_admin_ui::approve,
            policy_admin_ui::reject,
            policy_admin_ui::issue_page,
            policy_admin_ui::issue_verify,
            policy_admin_ui::issue_sign,
        ],
    );

    rocket_instance
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_host_exact_match() {
        assert_eq!(
            callback_within_rp_domain("https://todandlorna.com/cb", "todandlorna.com"),
            Ok(true)
        );
    }

    #[test]
    fn callback_host_subdomain_match() {
        assert_eq!(
            callback_within_rp_domain(
                "https://longhouse.todandlorna.com/auth/callback",
                "todandlorna.com",
            ),
            Ok(true)
        );
    }

    #[test]
    fn callback_host_off_domain_rejected() {
        assert_eq!(
            callback_within_rp_domain("https://attacker.com/x", "todandlorna.com"),
            Ok(false)
        );
    }

    #[test]
    fn callback_host_lookalike_rejected() {
        // "evil-todandlorna.com" must NOT match — the dot is required.
        assert_eq!(
            callback_within_rp_domain("https://evil-todandlorna.com/x", "todandlorna.com"),
            Ok(false)
        );
    }

    #[test]
    fn callback_non_https_rejected() {
        assert_eq!(
            callback_within_rp_domain("http://todandlorna.com/cb", "todandlorna.com"),
            Ok(false)
        );
    }

    #[test]
    fn callback_with_port_accepted() {
        assert_eq!(
            callback_within_rp_domain("https://app.example.com:8443/cb", "example.com"),
            Ok(true)
        );
    }

    #[test]
    fn callback_with_userinfo_uses_host() {
        // userinfo precedes '@'; host check should still apply to the
        // real host, not get spoofed by a username that contains a dot.
        assert_eq!(
            callback_within_rp_domain(
                "https://user.attacker.com@todandlorna.com/cb",
                "todandlorna.com"
            ),
            Ok(true)
        );
        assert_eq!(
            callback_within_rp_domain("https://todandlorna.com@attacker.com/cb", "todandlorna.com"),
            Ok(false)
        );
    }
}
