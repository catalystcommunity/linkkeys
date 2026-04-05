mod guard;
pub mod nonce_store;
pub mod rp;

use rocket::form::FromForm;
use rocket::http::{ContentType, Status};
use rocket::response::content::RawHtml;
use rocket::response::status::Custom;
use rocket::response::Redirect;
use rocket::{Config, State};
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rand::Rng;

use linkkeys::conversions::{get_domain_name, html_escape};
use linkkeys::db::DbPool;
use linkkeys::services::auth::PasswordAuthenticator;
use linkkeys::services::handshake::HandshakeHandler;
use linkkeys::services::hello::HelloHandler;

use liblinkkeys::generated::types::{
    DomainPublicKey, GetDomainKeysResponse, GetUserKeysResponse, UserInfo,
};

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

/// Sign an identity assertion for the given user, using the first active domain key.
fn sign_assertion_for_user(
    pool: &DbPool,
    user: &linkkeys::db::models::User,
    audience: &str,
    nonce: &str,
) -> Result<String, Status> {
    let domain_keys = pool.list_active_domain_keys().map_err(|_| Status::InternalServerError)?;
    if domain_keys.is_empty() {
        return Err(Status::InternalServerError);
    }
    let dk = &domain_keys[rand::thread_rng().gen_range(0..domain_keys.len())];

    let passphrase = env::var("DOMAIN_KEY_PASSPHRASE").map_err(|_| Status::InternalServerError)?;
    let sk_bytes =
        liblinkkeys::crypto::decrypt_private_key(&dk.private_key_encrypted, passphrase.as_bytes())
            .map_err(|_| Status::InternalServerError)?;

    let algorithm = liblinkkeys::crypto::SigningAlgorithm::from_str(&dk.algorithm)
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

/// Validate a callback URL against the allowed origins list.
/// ALLOWED_CALLBACK_ORIGINS env var: comma-separated list of allowed URL prefixes.
/// If unset, only https://localhost origins are allowed (safe default).
fn validate_callback_url(url: &str) -> bool {
    let allowed = env::var("ALLOWED_CALLBACK_ORIGINS").unwrap_or_default();
    let origins: Vec<&str> = if allowed.is_empty() {
        vec!["https://localhost"]
    } else {
        allowed.split(',').map(|s| s.trim()).collect()
    };
    origins.iter().any(|origin| url.starts_with(origin))
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

fn render_login_form(
    callback_url: &str,
    nonce: &str,
    username: &str,
    error: Option<&str>,
    relying_party: Option<&str>,
) -> RawHtml<String> {
    let error_html = error
        .map(|e| format!(r#"<p class="error">{}</p>"#, html_escape(e)))
        .unwrap_or_default();

    let rp_hidden = relying_party
        .map(|rp| format!(r#"  <input type="hidden" name="relying_party" value="{}" />"#, html_escape(rp)))
        .unwrap_or_default();

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
{error}
<form method="POST" action="/auth/authorize">
  <input type="hidden" name="callback_url" value="{callback_url}" />
  <input type="hidden" name="nonce" value="{nonce}" />
{rp_hidden}
  <label>Username</label>
  <input type="text" name="username" value="{username}" autofocus />
  <label>Password</label>
  <input type="password" name="password" />
  <button type="submit">Log In</button>
</form>
</body>
</html>"#,
        domain = html_escape(&get_domain_name()),
        error = error_html,
        callback_url = html_escape(callback_url),
        nonce = html_escape(nonce),
        rp_hidden = rp_hidden,
        username = html_escape(username),
    ))
}

#[rocket::get("/auth/authorize?<callback_url>&<nonce>&<user_hint>&<relying_party>&<signed_request>")]
fn auth_authorize_get(
    callback_url: &str,
    nonce: &str,
    user_hint: Option<&str>,
    relying_party: Option<&str>,
    signed_request: Option<&str>,
) -> Result<RawHtml<String>, Status> {
    match (relying_party, signed_request) {
        (Some(_rp), Some(_sr)) => {
            // New flow: relying party proves identity via signed request.
            // The callback URL validation is still enforced as defense-in-depth
            // until full signed_request verification is implemented with DNS
            // lookup and RP key fetch (requires async, planned for RpKeyCache).
            if !validate_callback_url(callback_url) {
                return Err(Status::BadRequest);
            }
        }
        (None, None) => {
            // Legacy flow: validate callback URL against allowlist
            if !validate_callback_url(callback_url) {
                return Err(Status::BadRequest);
            }
        }
        _ => {
            // One present without the other is invalid
            return Err(Status::BadRequest);
        }
    }
    Ok(render_login_form(
        callback_url,
        nonce,
        user_hint.unwrap_or(""),
        None,
        relying_party,
    ))
}

#[derive(FromForm)]
struct AuthorizeForm {
    callback_url: String,
    nonce: String,
    username: String,
    password: String,
    relying_party: Option<String>,
}

#[rocket::post("/auth/authorize", data = "<form>")]
async fn auth_authorize_post(
    pool: &State<DbPool>,
    nonces: &State<nonce_store::NonceStore>,
    form: rocket::form::Form<AuthorizeForm>,
) -> Result<Redirect, RawHtml<String>> {
    // Check nonce hasn't been used before (replay protection)
    if !nonces.record(&form.nonce) {
        return Err(render_login_form(
            &form.callback_url,
            &form.nonce,
            &form.username,
            Some("This login request has already been used. Please start a new login."),
            form.relying_party.as_deref(),
        ));
    }

    let has_rp = form.relying_party.is_some();

    if !has_rp && !validate_callback_url(&form.callback_url) {
        return Err(render_login_form(
            &form.callback_url,
            &form.nonce,
            &form.username,
            Some("Callback URL not allowed. Contact the domain administrator."),
            None,
        ));
    }

    let authenticator = PasswordAuthenticator::new(pool.inner().clone());

    let user = match linkkeys::services::auth::Authenticator::authenticate(
        &authenticator,
        &form.username,
        &form.password,
    ) {
        Ok(u) => u,
        Err(_) => {
            return Err(render_login_form(
                &form.callback_url,
                &form.nonce,
                &form.username,
                Some("Invalid username or password."),
                form.relying_party.as_deref(),
            ));
        }
    };

    let token = sign_assertion_for_user(pool, &user, &form.callback_url, &form.nonce)
        .map_err(|_| {
            render_login_form(
                &form.callback_url,
                &form.nonce,
                &form.username,
                Some("Internal server error during signing."),
                form.relying_party.as_deref(),
            )
        })?;

    let separator = if form.callback_url.contains('?') { "&" } else { "?" };

    if let Some(ref rp_domain) = form.relying_party {
        // New flow: encrypt the token for the relying party
        match encrypt_token_for_rp(&token, rp_domain).await {
            Ok(encrypted) => {
                let redirect_url = format!("{}{}encrypted_token={}", form.callback_url, separator, encrypted);
                Ok(Redirect::found(redirect_url))
            }
            Err(_) => {
                Err(render_login_form(
                    &form.callback_url,
                    &form.nonce,
                    &form.username,
                    Some("Failed to encrypt token for relying party."),
                    form.relying_party.as_deref(),
                ))
            }
        }
    } else {
        // Legacy flow: plain token in URL
        let redirect_url = format!("{}{}token={}", form.callback_url, separator, token);
        Ok(Redirect::found(redirect_url))
    }
}

/// Encrypt a signed assertion token for a relying party.
/// Fetches the RP's public keys via DNS + HTTP, converts to X25519, encrypts.
async fn encrypt_token_for_rp(
    token_url_param: &str,
    rp_domain: &str,
) -> Result<String, Status> {
    // Fetch RP's domain keys
    let rp_keys = rp::fetch_domain_keys(rp_domain).await.map_err(|_| Status::BadGateway)?;
    if rp_keys.is_empty() {
        return Err(Status::BadGateway);
    }

    // Use the first active RP key for encryption
    let rp_key = &rp_keys[0];

    // Convert RP's Ed25519 public key to X25519
    let x25519_pub = liblinkkeys::crypto::ed25519_public_to_x25519(&rp_key.public_key)
        .map_err(|_| Status::InternalServerError)?;

    // The token is already base64url-encoded CBOR of SignedIdentityAssertion.
    // Decode it back to raw CBOR bytes for encryption.
    let signed_assertion = liblinkkeys::encoding::assertion_from_url_param(token_url_param)
        .map_err(|_| Status::InternalServerError)?;
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&signed_assertion, &mut cbor_bytes)
        .map_err(|_| Status::InternalServerError)?;

    // Encrypt with sealed box
    let (ephemeral_pk, nonce, ciphertext) = liblinkkeys::crypto::sealed_box_encrypt(&cbor_bytes, &x25519_pub)
        .map_err(|_| Status::InternalServerError)?;

    let encrypted_token = liblinkkeys::generated::types::EncryptedToken {
        ephemeral_public_key: ephemeral_pk,
        nonce,
        ciphertext,
    };

    liblinkkeys::encoding::encrypted_token_to_url_param(&encrypted_token)
        .map_err(|_| Status::InternalServerError)
}

// -- Userinfo: Token-based API --

fn build_userinfo(pool: &DbPool, token_str: &str) -> Result<UserInfo, Status> {
    let assertion = verify_token_with_audience(pool, token_str, None)?;
    let user = pool.find_user_by_id(&assertion.user_id).map_err(db_err_to_status)?;
    let claims = pool.list_active_claims(&assertion.user_id).map_err(|_| Status::InternalServerError)?;

    Ok(UserInfo {
        user_id: user.id,
        domain: get_domain_name(),
        display_name: user.display_name,
        claims: claims.iter().map(Into::into).collect(),
    })
}

#[rocket::post("/v1alpha/userinfo", data = "<body>")]
fn userinfo_cbor(pool: &State<DbPool>, body: Vec<u8>) -> Result<(ContentType, Vec<u8>), Status> {
    let request: liblinkkeys::generated::types::GetUserInfoRequest =
        ciborium::de::from_reader(&body[..]).map_err(|_| Status::BadRequest)?;
    let token_str = String::from_utf8(request.token).map_err(|_| Status::BadRequest)?;

    let resp = build_userinfo(pool, &token_str)?;
    let mut out = Vec::new();
    ciborium::ser::into_writer(&resp, &mut out).map_err(|_| Status::InternalServerError)?;
    Ok(cbor_response(out))
}

#[derive(Deserialize)]
struct UserInfoJsonRequest {
    token: String,
}

#[rocket::post("/v1alpha/userinfo.json", data = "<body>")]
fn userinfo_json(pool: &State<DbPool>, body: String) -> Result<(ContentType, Vec<u8>), Status> {
    let request: UserInfoJsonRequest =
        serde_json::from_str(&body).map_err(|_| Status::BadRequest)?;

    let resp = build_userinfo(pool, &request.token)?;
    let out = serde_json::to_vec(&resp).map_err(|_| Status::InternalServerError)?;
    Ok(json_response(out))
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

    let config = Config {
        port,
        address: "0.0.0.0".parse().unwrap(),
        tls,
        ..Config::default()
    };

    let mut rocket_instance = rocket::custom(config)
        .mount(
            "/",
            rocket::routes![
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
                auth_authorize_get,
                auth_authorize_post,
                userinfo_cbor,
                userinfo_json,
            ],
        )
        .manage(db_pool)
        .manage(ready_flag)
        .manage(nonce_store::NonceStore::new(std::time::Duration::from_secs(300)));

    // Mount RP endpoints when enabled
    if env::var("ENABLE_RP_ENDPOINTS").unwrap_or_default() == "true" {
        log::info!("RP endpoints enabled");
        rocket_instance = rocket_instance.mount(
            "/",
            rocket::routes![
                rp::sign_request_json,
                rp::decrypt_token_json,
                rp::verify_assertion_json,
            ],
        );
    }

    if let Err(e) = rocket_instance.launch().await {
        log::error!("Rocket failed: {}", e);
        std::process::exit(1);
    }
}
