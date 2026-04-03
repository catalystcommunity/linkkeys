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
    let dk = &domain_keys[rand::random::<usize>() % domain_keys.len()];

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
) -> RawHtml<String> {
    let error_html = error
        .map(|e| format!(r#"<p class="error">{}</p>"#, html_escape(e)))
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
        username = html_escape(username),
    ))
}

#[rocket::get("/auth/authorize?<callback_url>&<nonce>&<user_hint>")]
fn auth_authorize_get(
    callback_url: &str,
    nonce: &str,
    user_hint: Option<&str>,
) -> Result<RawHtml<String>, Status> {
    if !validate_callback_url(callback_url) {
        return Err(Status::BadRequest);
    }
    Ok(render_login_form(callback_url, nonce, user_hint.unwrap_or(""), None))
}

#[derive(FromForm)]
struct AuthorizeForm {
    callback_url: String,
    nonce: String,
    username: String,
    password: String,
}

#[rocket::post("/auth/authorize", data = "<form>")]
fn auth_authorize_post(
    pool: &State<DbPool>,
    form: rocket::form::Form<AuthorizeForm>,
) -> Result<Redirect, RawHtml<String>> {
    if !validate_callback_url(&form.callback_url) {
        return Err(render_login_form(
            &form.callback_url,
            &form.nonce,
            &form.username,
            Some("Callback URL not allowed. Contact the domain administrator."),
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
            )
        })?;

    let separator = if form.callback_url.contains('?') { "&" } else { "?" };
    let redirect_url = format!("{}{}token={}", form.callback_url, separator, token);

    Ok(Redirect::found(redirect_url))
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

    if let Err(e) = rocket::custom(config)
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
        .launch()
        .await
    {
        log::error!("Rocket failed: {}", e);
        std::process::exit(1);
    }
}
