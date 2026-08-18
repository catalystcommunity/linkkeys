//! The CBOR authorize API (`/rp/authorize/validate`, `/rp/authorize/finalize`)
//! is the browser-flow equivalent of the `Rp` CSIL-RPC oracles: finalize mints a
//! signed login assertion for a named user. `AuthenticatedUser` alone is only
//! "some valid, active API key" and checks no permission, so these routes must
//! additionally require the dedicated `api_access` relation (SEC-06) — otherwise
//! any active key could mint an assertion for any user. These tests pin that
//! gate, and pin that every failure answers a structured CBOR `ApiError` body
//! (never a bare status, never HTML).
//!
//! The negative case needs no valid `signed_request`: the gate runs *before*
//! request validation, so a bogus body still proves rejection. The positive case
//! asserts the gate is passed — a bogus body then yields `BadRequest`, not
//! `Forbidden`, which is exactly "auth passed, payload rejected".

mod common;

use common::data_factory::{create_auth_credential, create_relation, create_user, DataMap};
use liblinkkeys::generated::types::{
    ApiErrorCode, AuthorizeFinalizeRequest, AuthorizeValidateRequest,
};
use linkkeys::services::auth;
use rocket::http::{Header, Status};
use rocket::local::asynchronous::Client;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

const TEST_DOMAIN: &str = "rpauth.test";

fn api_key_for(pool: &linkkeys::db::DbPool, user_id: &str) -> String {
    let (api_key, hash) = auth::generate_api_key(user_id);
    create_auth_credential(pool, user_id, auth::CREDENTIAL_TYPE_API_KEY, &hash);
    api_key
}

async fn client_for(pool: &linkkeys::db::DbPool) -> Client {
    let config = rocket::Config {
        secret_key: rocket::config::SecretKey::derive_from(&[7u8; 64]),
        ..rocket::Config::debug_default()
    };
    let rocket = linkkeys::web::build_rocket(
        pool.clone(),
        Arc::new(AtomicBool::new(true)),
        common::net::offline_net(),
        config,
    );
    Client::tracked(rocket).await.expect("rocket client")
}

fn validate_body() -> Vec<u8> {
    liblinkkeys::generated::encode_authorize_validate_request(&AuthorizeValidateRequest {
        signed_request: "not-a-real-request".to_string(),
    })
}

fn finalize_body() -> Vec<u8> {
    liblinkkeys::generated::encode_authorize_finalize_request(&AuthorizeFinalizeRequest {
        user_id: "00000000-0000-0000-0000-000000000000".to_string(),
        signed_request: "x".to_string(),
        authorized_claims: vec![],
    })
}

/// Both routes reject a valid, active API key that lacks the `api_access`
/// relation, and only after granting it does the request get past the gate.
/// Every rejection carries a decodable CBOR `ApiError` body.
#[rocket::async_test]
async fn authorize_routes_require_api_access_relation() {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    let pool = common::create_test_pool();
    let client = client_for(&pool).await;

    // A valid, active API-key user — but with no relations granted.
    let user = create_user(&pool, &DataMap::new());
    let key = api_key_for(&pool, &user.id);
    let bearer = || Header::new("Authorization", format!("Bearer {}", key));

    // --- Without api_access: gate rejects with Forbidden, before validation. ---
    for (path, body) in [
        ("/rp/authorize/validate", validate_body()),
        ("/rp/authorize/finalize", finalize_body()),
    ] {
        let resp = client
            .post(path)
            .header(bearer())
            .body(body)
            .dispatch()
            .await;
        assert_eq!(
            resp.status(),
            Status::Forbidden,
            "{} must require api_access (got {})",
            path,
            resp.status()
        );
        let err = liblinkkeys::generated::decode_api_error(
            &resp.into_bytes().await.expect("response body"),
        )
        .expect("Forbidden must carry a CBOR ApiError body");
        assert_eq!(err.code, ApiErrorCode::Forbidden);
        assert!(!err.message.is_empty());
    }

    // --- Grant api_access: the gate now passes, so the bogus signed_request is
    //     rejected as BadRequest rather than the request being Forbidden. ---
    create_relation(&pool, "user", &user.id, "api_access", "domain", TEST_DOMAIN);
    for (path, body) in [
        ("/rp/authorize/validate", validate_body()),
        ("/rp/authorize/finalize", finalize_body()),
    ] {
        let resp = client
            .post(path)
            .header(bearer())
            .body(body)
            .dispatch()
            .await;
        assert_ne!(
            resp.status(),
            Status::Forbidden,
            "{} must pass the gate once api_access is granted (got {})",
            path,
            resp.status()
        );
        let err = liblinkkeys::generated::decode_api_error(
            &resp.into_bytes().await.expect("response body"),
        )
        .expect("payload rejection must carry a CBOR ApiError body");
        assert_eq!(err.code, ApiErrorCode::BadRequest);
    }
}

/// No credentials at all is Unauthorized (the `AuthenticatedUser` layer), never
/// silently allowed — and even a guard failure answers a CBOR `ApiError` via
/// the default catcher, not Rocket's HTML page.
#[rocket::async_test]
async fn authorize_routes_reject_missing_auth() {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    let pool = common::create_test_pool();
    let client = client_for(&pool).await;

    let resp = client
        .post("/rp/authorize/validate")
        .body(validate_body())
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Unauthorized);
    let err =
        liblinkkeys::generated::decode_api_error(&resp.into_bytes().await.expect("response body"))
            .expect("Unauthorized must carry a CBOR ApiError body");
    assert_eq!(err.code, ApiErrorCode::Unauthorized);
}
