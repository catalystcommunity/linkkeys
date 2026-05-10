//! Integration tests for the `signed_request`-trusted login flow.
//!
//! These exercise `web::validate_signed_request` as a library function:
//! decode → fetch RP keys → verify signature/timestamp → defense-in-depth
//! callback-host check. The handler that calls this in turn (form GET/POST)
//! is thin orchestration, so getting the validator right is what matters.

mod common;

use chrono::{Duration, Utc};
use liblinkkeys::auth_request::{build_auth_request, sign_auth_request};
use liblinkkeys::crypto::{self, SigningAlgorithm};
use liblinkkeys::encoding::signed_auth_request_to_url_param;
use liblinkkeys::generated::types::AuthRequest;
use linkkeys::web::{validate_signed_request, ValidateAuthRequestError};

const TEST_DOMAIN: &str = "todandlorna.com";
const TEST_PASSPHRASE: &[u8] = b"test-passphrase";

/// Set up a self-RP DB: the IDP and RP are the same instance, so RP keys
/// resolve via the local domain-keys DB. Returns the pool, key id, and
/// raw signing key bytes so tests can mint signed_requests.
fn self_rp_setup() -> (linkkeys::db::DbPool, String, Vec<u8>) {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");

    let pool = common::create_test_pool();
    let (vk, sk) = crypto::generate_ed25519_keypair();
    let pk_bytes = vk.as_bytes().to_vec();
    let sk_bytes = sk.to_bytes().to_vec();
    let encrypted_sk = crypto::encrypt_private_key(&sk_bytes, TEST_PASSPHRASE).unwrap();
    let fp = crypto::fingerprint(&pk_bytes);
    let expires = Utc::now() + Duration::days(365);
    let dk = pool
        .create_domain_key(&pk_bytes, &encrypted_sk, &fp, "ed25519", expires)
        .expect("create_domain_key");
    (pool, dk.id, sk_bytes)
}

/// Mint a signed_request URL param for the given AuthRequest. Bypasses
/// `build_auth_request` so tests can override timestamp.
fn mint_signed_request(request: &AuthRequest, key_id: &str, sk_bytes: &[u8]) -> String {
    let signed = sign_auth_request(request, key_id, SigningAlgorithm::Ed25519, sk_bytes).unwrap();
    signed_auth_request_to_url_param(&signed).unwrap()
}

#[rocket::async_test]
async fn validates_self_rp_subdomain_callback() {
    // The longhouse regression: IDP/RP are todandlorna.com, app is at
    // longhouse.todandlorna.com. Subdomain callback must be accepted,
    // RP keys must resolve from the local DB.
    let (pool, key_id, sk_bytes) = self_rp_setup();
    let request = build_auth_request(
        TEST_DOMAIN,
        "https://longhouse.todandlorna.com/auth/callback",
        "nonce-1",
        &key_id,
    );
    let param = mint_signed_request(&request, &key_id, &sk_bytes);

    let validated = validate_signed_request(&pool, &param)
        .await
        .expect("subdomain callback should be accepted");

    assert_eq!(validated.relying_party, TEST_DOMAIN);
    assert_eq!(
        validated.callback_url,
        "https://longhouse.todandlorna.com/auth/callback"
    );
    assert_eq!(validated.nonce, "nonce-1");
}

#[rocket::async_test]
async fn returns_trusted_cbor_values_only() {
    // Only the signed envelope is consulted: `validate_signed_request`
    // takes only the param, not any URL/form fields. This test asserts
    // the return value is exactly what was in the verified CBOR — there
    // is no other input it could possibly come from.
    let (pool, key_id, sk_bytes) = self_rp_setup();
    let request = build_auth_request(
        TEST_DOMAIN,
        "https://todandlorna.com/cb",
        "trusted-nonce",
        &key_id,
    );
    let param = mint_signed_request(&request, &key_id, &sk_bytes);

    let validated = validate_signed_request(&pool, &param).await.unwrap();
    assert_eq!(validated.relying_party, TEST_DOMAIN);
    assert_eq!(validated.callback_url, "https://todandlorna.com/cb");
    assert_eq!(validated.nonce, "trusted-nonce");
}

#[rocket::async_test]
async fn rejects_tampered_signature() {
    let (pool, key_id, sk_bytes) = self_rp_setup();
    let request = build_auth_request(
        TEST_DOMAIN,
        "https://todandlorna.com/cb",
        "n",
        &key_id,
    );
    // Tamper the signature bytes (not the request bytes): keeps the CBOR
    // valid so the unverified preview decode succeeds, but breaks the
    // signature check — the precise failure mode we want to assert on.
    let mut signed =
        sign_auth_request(&request, &key_id, SigningAlgorithm::Ed25519, &sk_bytes).unwrap();
    if let Some(byte) = signed.signature.first_mut() {
        *byte ^= 0xff;
    }
    let param = signed_auth_request_to_url_param(&signed).unwrap();

    let err = validate_signed_request(&pool, &param).await.unwrap_err();
    assert!(matches!(err, ValidateAuthRequestError::SignatureInvalid));
}

#[rocket::async_test]
async fn rejects_request_with_tampered_payload_bytes() {
    // Flipping payload bytes can leave CBOR un-parseable (Malformed) or
    // parseable-but-bad (SignatureInvalid) depending on which byte. Either
    // failure mode is a *reject*, which is what callers actually depend on.
    let (pool, key_id, sk_bytes) = self_rp_setup();
    let request = build_auth_request(
        TEST_DOMAIN,
        "https://todandlorna.com/cb",
        "n",
        &key_id,
    );
    let mut signed =
        sign_auth_request(&request, &key_id, SigningAlgorithm::Ed25519, &sk_bytes).unwrap();
    if let Some(byte) = signed.request.first_mut() {
        *byte ^= 0xff;
    }
    let param = signed_auth_request_to_url_param(&signed).unwrap();

    let err = validate_signed_request(&pool, &param).await.unwrap_err();
    assert!(matches!(
        err,
        ValidateAuthRequestError::Malformed | ValidateAuthRequestError::SignatureInvalid
    ));
}

#[rocket::async_test]
async fn rejects_expired_request() {
    let (pool, key_id, sk_bytes) = self_rp_setup();
    // Stamp an old timestamp directly: MAX_AUTH_REQUEST_AGE_SECONDS=300,
    // so 600s in the past is decisively expired.
    let request = AuthRequest {
        relying_party: TEST_DOMAIN.to_string(),
        callback_url: "https://todandlorna.com/cb".to_string(),
        nonce: "n".to_string(),
        timestamp: (Utc::now() - Duration::seconds(600)).to_rfc3339(),
        signing_key_id: key_id.clone(),
    };
    let param = mint_signed_request(&request, &key_id, &sk_bytes);

    let err = validate_signed_request(&pool, &param).await.unwrap_err();
    assert!(matches!(err, ValidateAuthRequestError::Expired));
}

#[rocket::async_test]
async fn rejects_off_domain_callback() {
    // Even with a valid signature, a callback host outside the RP's
    // domain is refused. This catches a misbehaving (or compromised)
    // RP signing redirects to attacker-controlled hosts.
    let (pool, key_id, sk_bytes) = self_rp_setup();
    let request = build_auth_request(
        TEST_DOMAIN,
        "https://attacker.com/auth/callback",
        "n",
        &key_id,
    );
    let param = mint_signed_request(&request, &key_id, &sk_bytes);

    let err = validate_signed_request(&pool, &param).await.unwrap_err();
    assert!(matches!(err, ValidateAuthRequestError::CallbackOffDomain));
}

#[rocket::async_test]
async fn rejects_non_https_callback() {
    let (pool, key_id, sk_bytes) = self_rp_setup();
    let request = build_auth_request(
        TEST_DOMAIN,
        "http://todandlorna.com/cb",
        "n",
        &key_id,
    );
    let param = mint_signed_request(&request, &key_id, &sk_bytes);

    let err = validate_signed_request(&pool, &param).await.unwrap_err();
    assert!(matches!(err, ValidateAuthRequestError::CallbackNotHttps));
}

#[rocket::async_test]
async fn rejects_malformed_signed_request() {
    let (pool, _key_id, _sk_bytes) = self_rp_setup();
    // Not valid base64+CBOR.
    let err = validate_signed_request(&pool, "not!valid!base64!")
        .await
        .unwrap_err();
    assert!(matches!(err, ValidateAuthRequestError::Malformed));
}
