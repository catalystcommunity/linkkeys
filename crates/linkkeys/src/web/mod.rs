use rocket::http::{ContentType, Status};
use rocket::response::status::Custom;
use rocket::{Config, State};
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use linkkeys::db::DbPool;
use linkkeys::services::hello::HelloHandler;

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

/// Health check — always returns 200 once the listener is up.
#[rocket::get("/healthcheck")]
fn healthcheck() -> (ContentType, Vec<u8>) {
    let resp = CheckResultResponse { result: true };
    let mut out = Vec::new();
    ciborium::ser::into_writer(&resp, &mut out).expect("CBOR serialization cannot fail for bool");
    cbor_response(out)
}

/// Readiness probe — 200 after migrations, 503 before.
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

/// Hello endpoint — CBOR in, CBOR out.
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

/// Hello GET for easy testing with curl.
#[rocket::get("/hello")]
fn hello_get() -> Result<(ContentType, Vec<u8>), Status> {
    let handler = HelloHandler;
    let greeting = handler.hello(None);

    let resp = HelloResponse { greeting };
    let mut out = Vec::new();
    ciborium::ser::into_writer(&resp, &mut out).map_err(|_| Status::InternalServerError)?;
    Ok(cbor_response(out))
}

/// Generate an ephemeral self-signed TLS certificate in memory.
fn generate_self_signed_cert() -> (String, String) {
    let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("Failed to generate self-signed cert");
    let cert_pem = certified_key.cert.pem();
    let key_pem = certified_key.key_pair.serialize_pem();
    (cert_pem, key_pem)
}

pub async fn launch_rocket(db_pool: DbPool, ready_flag: Arc<AtomicBool>) {
    let port: u16 = env::var("HTTPS_PORT")
        .unwrap_or_else(|_| "8443".to_string())
        .parse()
        .unwrap_or(8443);

    log::info!("Starting Rocket HTTPS server on port {}", port);

    let (cert_pem, key_pem) = generate_self_signed_cert();
    let tls = rocket::config::TlsConfig::from_bytes(cert_pem.as_bytes(), key_pem.as_bytes());

    let config = Config {
        port,
        address: "0.0.0.0".parse().unwrap(),
        tls: Some(tls),
        ..Config::default()
    };

    if let Err(e) = rocket::custom(config)
        .mount(
            "/",
            rocket::routes![healthcheck, readiness, hello_get, hello_post],
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
