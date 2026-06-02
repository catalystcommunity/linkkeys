mod account;
mod account_ui;
mod admin;
mod admin_ui;
mod guard;
pub mod nonce_store;
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
use crate::services::auth::PasswordAuthenticator;
use crate::services::handshake::HandshakeHandler;
use crate::services::hello::HelloHandler;

use liblinkkeys::generated::types::{
    AuthRequest, DomainPublicKey, GetDomainKeysResponse, GetUserKeysResponse, UserInfo,
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
    let signing: Vec<&crate::db::models::DomainKey> =
        domain_keys.iter().filter(|k| k.key_usage == "sign").collect();
    if signing.is_empty() {
        return None;
    }
    Some(signing[rand::thread_rng().gen_range(0..signing.len())])
}

/// Sign an identity assertion for the given user with a randomly chosen active
/// signing key.
fn sign_assertion_for_user(
    pool: &DbPool,
    user: &crate::db::models::User,
    audience: &str,
    nonce: &str,
) -> Result<String, Status> {
    let domain_keys = pool.list_active_domain_keys().map_err(|_| Status::InternalServerError)?;
    let dk = pick_active_signing_key(&domain_keys).ok_or(Status::InternalServerError)?;

    let passphrase = env::var("DOMAIN_KEY_PASSPHRASE").map_err(|_| Status::InternalServerError)?;
    let sk_bytes =
        liblinkkeys::crypto::decrypt_private_key(&dk.private_key_encrypted, passphrase.as_bytes())
            .map_err(|_| Status::InternalServerError)?;

    let algorithm = liblinkkeys::crypto::SigningAlgorithm::parse_str(&dk.algorithm)
        .ok_or(Status::InternalServerError)?;

    let assertion = liblinkkeys::assertions::build_assertion(
        &user.id,
        &get_domain_name(),
        audience,
        nonce,
        Some(&user.display_name),
        300, // 5 minute TTL
    );

    let signed = liblinkkeys::assertions::sign_assertion(&assertion, &dk.id, algorithm, &sk_bytes)
        .map_err(|_| Status::InternalServerError)?;

    liblinkkeys::encoding::assertion_to_url_param(&signed)
        .map_err(|_| Status::InternalServerError)
}

/// Verify a token and check that the audience matches the expected value.
fn verify_token_with_audience(
    pool: &DbPool,
    token_param: &str,
    expected_audience: Option<&str>,
) -> Result<liblinkkeys::generated::types::IdentityAssertion, Status> {
    let signed = liblinkkeys::encoding::assertion_from_url_param(token_param)
        .map_err(|_| Status::BadRequest)?;

    let domain_keys = pool.list_active_domain_keys().map_err(|_| Status::InternalServerError)?;
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
        ciborium::ser::into_writer(&resp, &mut out)
            .map_err(|_| Status::InternalServerError)?;
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
    ciborium::ser::into_writer(&resp, &mut out)
        .map_err(|e| Custom(Status::InternalServerError, format!("CBOR encode error: {}", e)))?;
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
    let keys = pool.list_active_domain_keys().map_err(|_| Status::InternalServerError)?;
    Ok(GetDomainKeysResponse {
        domain: get_domain_name(),
        keys: keys.iter().map(Into::into).collect(),
    })
}

#[rocket::get("/v1alpha/domain-keys")]
fn domain_keys_cbor(pool: &State<DbPool>) -> Result<(ContentType, Vec<u8>), Status> {
    let resp = build_domain_keys_response(pool)?;
    let mut out = Vec::new();
    ciborium::ser::into_writer(&resp, &mut out).map_err(|_| Status::InternalServerError)?;
    Ok(cbor_response(out))
}

#[rocket::get("/v1alpha/domain-keys.json")]
fn domain_keys_json(pool: &State<DbPool>) -> Result<(ContentType, Vec<u8>), Status> {
    let resp = build_domain_keys_response(pool)?;
    let out = serde_json::to_vec(&resp).map_err(|_| Status::InternalServerError)?;
    Ok(json_response(out))
}

// -- User Keys --

fn build_user_keys_response(pool: &DbPool, user_id: &str) -> Result<GetUserKeysResponse, Status> {
    pool.find_user_by_id(user_id).map_err(db_err_to_status)?;
    let keys = pool.list_active_user_keys(user_id).map_err(db_err_to_status)?;
    Ok(GetUserKeysResponse {
        user_id: user_id.to_string(),
        domain: get_domain_name(),
        keys: keys.iter().map(Into::into).collect(),
    })
}

#[rocket::get("/v1alpha/users/<user_id>/keys")]
fn user_keys_cbor(pool: &State<DbPool>, user_id: &str) -> Result<(ContentType, Vec<u8>), Status> {
    let resp = build_user_keys_response(pool, user_id)?;
    let mut out = Vec::new();
    ciborium::ser::into_writer(&resp, &mut out).map_err(|_| Status::InternalServerError)?;
    Ok(cbor_response(out))
}

#[rocket::get("/v1alpha/users/<user_id>/keys.json")]
fn user_keys_json(pool: &State<DbPool>, user_id: &str) -> Result<(ContentType, Vec<u8>), Status> {
    let resp = build_user_keys_response(pool, user_id)?;
    let out = serde_json::to_vec(&resp).map_err(|_| Status::InternalServerError)?;
    Ok(json_response(out))
}

// -- Handshake --

#[rocket::post("/v1alpha/handshake", data = "<body>")]
fn handshake_cbor(body: Vec<u8>) -> Result<(ContentType, Vec<u8>), Status> {
    use liblinkkeys::generated::services::Handshake;
    let request: liblinkkeys::generated::types::HandshakeRequest =
        ciborium::de::from_reader(&body[..]).map_err(|_| Status::BadRequest)?;
    let resp = HandshakeHandler.handshake(&(), request).map_err(|_| Status::InternalServerError)?;
    let mut out = Vec::new();
    ciborium::ser::into_writer(&resp, &mut out).map_err(|_| Status::InternalServerError)?;
    Ok(cbor_response(out))
}

#[rocket::post("/v1alpha/handshake.json", data = "<body>")]
fn handshake_json(body: String) -> Result<(ContentType, Vec<u8>), Status> {
    use liblinkkeys::generated::services::Handshake;
    let request: liblinkkeys::generated::types::HandshakeRequest =
        serde_json::from_str(&body).map_err(|_| Status::BadRequest)?;
    let resp = HandshakeHandler.handshake(&(), request).map_err(|_| Status::InternalServerError)?;
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

#[rocket::get("/auth/authorize?<user_hint>&<signed_request>")]
async fn auth_authorize_get(
    pool: &State<DbPool>,
    user_hint: Option<&str>,
    signed_request: Option<&str>,
) -> Result<RawHtml<String>, Status> {
    // signed_request is the only accepted flow. A request without it (or one
    // that fails verification) renders an error page, never a login form — so
    // an attacker who can craft a URL cannot phish credentials onto a
    // legitimate-looking page.
    let sr = signed_request.ok_or(Status::BadRequest)?;
    match validate_signed_request(pool, sr).await {
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
    nonces: &State<nonce_store::NonceStore>,
    form: rocket::form::Form<AuthorizeForm>,
) -> Result<Redirect, RawHtml<String>> {
    if let Some(sr) = form.signed_request.as_deref() {
        handle_signed_request_post(pool, nonces, &form, sr).await
    } else {
        Err(render_error_page(
            "Missing signed_request. This login flow is no longer supported.",
        ))
    }
}

async fn handle_signed_request_post(
    pool: &State<DbPool>,
    nonces: &State<nonce_store::NonceStore>,
    form: &AuthorizeForm,
    signed_request_param: &str,
) -> Result<Redirect, RawHtml<String>> {
    let request = match validate_signed_request(pool, signed_request_param).await {
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

    // Replay protection: burn the *trusted* CBOR nonce only AFTER successful
    // authentication, so a wrong password (or an attacker pre-submitting a known
    // signed_request) cannot consume a legitimate login request (web-09).
    // Namespaced "login:" so it doesn't collide with the userinfo-redemption
    // single-use check, which burns the same nonce under "userinfo:".
    if !nonces.record(&format!("login:{}", request.nonce)) {
        return Err(render_error_page(
            "This login request has already been used. Please start a new login.",
        ));
    }

    // Audience is the relying-party DOMAIN (what a verifier checks), not the
    // full callback URL.
    let token = sign_assertion_for_user(pool, &user, &request.relying_party, &request.nonce)
        .map_err(|_| render_form_error("Internal server error during signing."))?;

    let encrypted = encrypt_token_for_rp(pool, &token, &request.relying_party)
        .await
        .map_err(|_| render_form_error("Failed to encrypt token for relying party."))?;

    let separator = if request.callback_url.contains('?') {
        "&"
    } else {
        "?"
    };
    let redirect_url = format!(
        "{}{}encrypted_token={}",
        request.callback_url, separator, encrypted
    );
    Ok(Redirect::found(redirect_url))
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
            Self::CallbackOffDomain => {
                "The callback URL is not within the relying party's domain."
            }
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
    signed_request_param: &str,
) -> Result<AuthRequest, ValidateAuthRequestError> {
    let envelope = liblinkkeys::encoding::signed_auth_request_from_url_param(signed_request_param)
        .map_err(|_| ValidateAuthRequestError::Malformed)?;

    // Untrusted preview: we only need `relying_party` to know whose keys
    // to fetch. Every other field is re-read from the verified bytes.
    let preview: AuthRequest = ciborium::de::from_reader(envelope.request.as_slice())
        .map_err(|_| ValidateAuthRequestError::Malformed)?;
    let rp_domain = preview.relying_party.clone();

    let rp_keys = rp::fetch_rp_keys(pool, &rp_domain)
        .await
        .map_err(|_| ValidateAuthRequestError::KeyFetchFailed)?;
    if rp_keys.is_empty() {
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
    token_url_param: &str,
    rp_domain: &str,
) -> Result<String, Status> {
    let rp_keys = rp::fetch_rp_keys(pool, rp_domain)
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
    signed: &liblinkkeys::generated::types::SignedUserInfoRequest,
) -> Result<UserInfo, Status> {
    // Read the (still untrusted) inner request only to learn which relying
    // party is asking. The signature below is verified over these exact bytes,
    // so decoding-before-verifying leaks no trust.
    let claimed: liblinkkeys::generated::types::UserInfoRequest =
        ciborium::de::from_reader(signed.request.as_slice()).map_err(|_| Status::BadRequest)?;

    // Resolve the relying party's signing keys (RP-inlined + DNS-pinned, or an
    // authoritative fetch) and verify the proof-of-possession over the request.
    let rp_keys =
        rp::resolve_rp_signing_keys(pool, &claimed.relying_party, signed.public_keys.as_deref())
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

    let user = pool.find_user_by_id(&assertion.user_id).map_err(db_err_to_status)?;
    let claims = pool
        .list_active_claims(&assertion.user_id)
        .map_err(|_| Status::InternalServerError)?;

    Ok(UserInfo {
        user_id: user.id,
        domain: get_domain_name(),
        display_name: user.display_name,
        claims: claims.iter().map(Into::into).collect(),
    })
}

#[rocket::post("/v1alpha/userinfo", data = "<body>")]
async fn userinfo_cbor(
    pool: &State<DbPool>,
    body: Vec<u8>,
) -> Result<(ContentType, Vec<u8>), Status> {
    let signed: liblinkkeys::generated::types::SignedUserInfoRequest =
        ciborium::de::from_reader(&body[..]).map_err(|_| Status::BadRequest)?;

    let resp = build_userinfo_signed(pool, &signed).await?;
    let mut out = Vec::new();
    ciborium::ser::into_writer(&resp, &mut out).map_err(|_| Status::InternalServerError)?;
    Ok(cbor_response(out))
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
        log::info!("Starting Rocket HTTP server on port {} (TLS disabled)", port);
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
    ];

    // Mount password auth routes (login form) when enabled (default: true)
    if env::var("ENABLE_PASSWORD_AUTH").unwrap_or_else(|_| "true".to_string()) == "true" {
        log::info!("Password auth enabled");
        routes.extend(rocket::routes![auth_authorize_get, auth_authorize_post]);
    }

    let nonce_store =
        nonce_store::NonceStore::new(db_pool.clone(), std::time::Duration::from_secs(300));
    let mut rocket_instance = rocket::custom(config)
        .mount("/", routes)
        .manage(db_pool)
        .manage(ready_flag)
        .manage(nonce_store);

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

    if let Err(e) = rocket_instance.launch().await {
        log::error!("Rocket failed: {}", e);
        std::process::exit(1);
    }
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
            callback_within_rp_domain(
                "https://todandlorna.com@attacker.com/cb",
                "todandlorna.com"
            ),
            Ok(false)
        );
    }
}
