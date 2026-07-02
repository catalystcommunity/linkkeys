//! Tests for the `Rp` helper service over the TCP dispatch (the path a
//! browser-facing relying party uses to delegate to its RP server). Exercises
//! API-key auth gating, the local `sign-request` happy path, and the fact that
//! ops needing an onward server-to-server call (verify-assertion) are refused
//! when no outbound context is present.

mod common;

use common::data_factory::{
    create_auth_credential, create_domain_key, create_relation, create_user, DataMap,
};
use liblinkkeys::generated::types::{RpSignRequest, RpVerifyRequest};
use linkkeys::services::auth;

const TEST_DOMAIN: &str = "rp.test";

/// Grant the api_access relation an RP service account needs to drive the Rp
/// service (SEC-06): a bare API key is no longer sufficient.
fn grant_api_access(pool: &linkkeys::db::DbPool, user_id: &str) {
    create_relation(pool, "user", user_id, "api_access", "domain", TEST_DOMAIN);
}

fn setup() -> linkkeys::db::DbPool {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    common::create_test_pool()
}

/// Mint an API key for `user_id` and store its credential, returning the raw key.
fn api_key_for(pool: &linkkeys::db::DbPool, user_id: &str) -> String {
    let (api_key, hash) = auth::generate_api_key(user_id);
    create_auth_credential(pool, user_id, auth::CREDENTIAL_TYPE_API_KEY, &hash);
    api_key
}

fn sign_request_payload() -> Vec<u8> {
    liblinkkeys::generated::encode_rp_sign_request(&RpSignRequest {
        callback_url: "https://rp.test/callback".to_string(),
        nonce: "nonce-1".to_string(),
        requested_claims: None,
        flow_context: None,
    })
}

#[test]
fn rp_ops_require_api_key() {
    let pool = setup();
    // No auth in the envelope -> rejected before reaching the op.
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Rp",
        "sign-request",
        sign_request_payload(),
        None,
        &pool,
        None,
    );
    assert_ne!(status, 0, "Rp ops must require an API key");
}

#[test]
fn rp_sign_request_happy_path() {
    let pool = setup();
    let user = create_user(&pool, &DataMap::new());
    let api_key = api_key_for(&pool, &user.id);
    grant_api_access(&pool, &user.id);
    // A signing domain key + the matching passphrase let the core sign.
    create_domain_key(&pool);

    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Rp",
        "sign-request",
        sign_request_payload(),
        Some(&api_key),
        &pool,
        None,
    );
    assert_eq!(
        status, 0,
        "sign-request should succeed with auth + a signing key"
    );
    let resp =
        liblinkkeys::generated::decode_rp_sign_response(&body).expect("decode RpSignResponse");
    assert!(
        !resp.signed_request.is_empty(),
        "a signed auth request is returned"
    );
}

#[test]
fn rp_ops_require_api_access_relation() {
    // SEC-06: a valid API key without the api_access relation is Forbidden — it
    // must not be able to drive the domain sign/decrypt oracles.
    let pool = setup();
    let user = create_user(&pool, &DataMap::new());
    let api_key = api_key_for(&pool, &user.id);
    create_domain_key(&pool);
    // Note: no grant_api_access here.
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Rp",
        "sign-request",
        sign_request_payload(),
        Some(&api_key),
        &pool,
        None,
    );
    assert_ne!(
        status, 0,
        "Rp ops must require the api_access relation, not just any API key"
    );
}

#[test]
fn rp_unknown_op_rejected() {
    let pool = setup();
    let user = create_user(&pool, &DataMap::new());
    let api_key = api_key_for(&pool, &user.id);
    grant_api_access(&pool, &user.id);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Rp",
        "no-such-op",
        Vec::new(),
        Some(&api_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "unknown Rp op is an error");
}

#[test]
fn rp_verify_assertion_needs_outbound_context() {
    let pool = setup();
    let user = create_user(&pool, &DataMap::new());
    let api_key = api_key_for(&pool, &user.id);
    grant_api_access(&pool, &user.id);

    let payload = liblinkkeys::generated::encode_rp_verify_request(&RpVerifyRequest {
        signed_assertion: "AAAA".to_string(),
        expected_domain: "other.test".to_string(),
    });

    // The test seam provides no outbound context, so the onward call to the
    // issuing IDP is refused before any network access — authenticated, but
    // unavailable on this carrier.
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Rp",
        "verify-assertion",
        payload,
        Some(&api_key),
        &pool,
        None,
    );
    assert_ne!(
        status, 0,
        "verify-assertion is refused (no outbound context on this carrier)"
    );
}
