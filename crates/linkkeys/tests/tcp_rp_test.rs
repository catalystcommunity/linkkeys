//! Tests for the `Rp` helper service over the TCP dispatch (the path a
//! browser-facing relying party uses to delegate to its RP server). Exercises
//! API-key auth gating, the local `sign-request` happy path, and the fact that
//! ops needing an onward server-to-server call (verify-assertion) are refused
//! when no outbound context is present.

mod common;

use common::data_factory::{
    create_auth_credential, create_domain_encryption_key, create_domain_key, create_relation,
    create_user, DataMap,
};
use liblinkkeys::generated::types::{
    EncryptedToken, RpDecryptRequest, RpSignRequest, RpVerifyRequest,
};
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
    sign_request_payload_for("https://rp.test/callback")
}

fn sign_request_payload_for(callback_url: &str) -> Vec<u8> {
    sign_request_payload_with(callback_url, None)
}

fn sign_request_payload_with(callback_url: &str, application_id: Option<&str>) -> Vec<u8> {
    liblinkkeys::generated::encode_rp_sign_request(&RpSignRequest {
        callback_url: callback_url.to_string(),
        nonce: "nonce-1".to_string(),
        application_id: application_id.map(str::to_string),
        requested_claims: None,
        authentication_requirements: None,
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

/// An api_access API-key account with a domain signing key, ready to call
/// sign-request. Returns the pool, the account id, and the raw API key.
fn rp_caller() -> (linkkeys::db::DbPool, String, String) {
    let pool = setup();
    let mut overrides = DataMap::new();
    overrides.insert("username".to_string(), serde_json::json!("homegrafana"));
    overrides.insert(
        "display_name".to_string(),
        serde_json::json!("Home Grafana"),
    );
    let user = create_user(&pool, &overrides);
    let api_key = api_key_for(&pool, &user.id);
    grant_api_access(&pool, &user.id);
    create_domain_key(&pool);
    (pool, user.id, api_key)
}

fn sign(
    pool: &linkkeys::db::DbPool,
    api_key: &str,
    callback_url: &str,
) -> Result<liblinkkeys::generated::types::AuthRequest, i32> {
    sign_as(pool, api_key, callback_url, None)
}

fn sign_as(
    pool: &linkkeys::db::DbPool,
    api_key: &str,
    callback_url: &str,
    application_id: Option<&str>,
) -> Result<liblinkkeys::generated::types::AuthRequest, i32> {
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Rp",
        "sign-request",
        sign_request_payload_with(callback_url, application_id),
        Some(api_key),
        pool,
        None,
    );
    if status != 0 {
        return Err(status);
    }
    let resp =
        liblinkkeys::generated::decode_rp_sign_response(&body).expect("decode RpSignResponse");
    let envelope = liblinkkeys::encoding::signed_auth_request_from_url_param(&resp.signed_request)
        .expect("decode signed request");
    Ok(liblinkkeys::generated::decode_auth_request(&envelope.request).expect("decode request"))
}

#[test]
fn rp_sign_request_signs_callback_on_another_domain_and_names_the_caller() {
    // The application is the API-key principal of rp.test. It can live at
    // any https URL: the domain signature authorizes the callback.
    let (pool, user_id, api_key) = rp_caller();

    let request = sign(
        &pool,
        &api_key,
        "https://homegrafana.catalystsquad.com/login/callback?lk_state=x",
    )
    .expect("off-domain https callback is signed");
    assert_eq!(request.relying_party, TEST_DOMAIN);
    assert_eq!(
        request.callback_url,
        "https://homegrafana.catalystsquad.com/login/callback?lk_state=x"
    );
    let app = request.application.expect("the calling principal is named");
    // The same identity shape as an act-as ApplicationRef. With no
    // application_id, the account's username names the application.
    assert_eq!(app.application.subject_user_id, user_id);
    assert_eq!(app.application.subject_domain, TEST_DOMAIN);
    assert_eq!(app.application.application_id, "homegrafana");
    assert_eq!(app.display_name, "Home Grafana");
}

#[test]
fn rp_sign_request_names_an_application_under_the_caller_only() {
    let (pool, user_id, api_key) = rp_caller();

    let request = sign_as(&pool, &api_key, "https://rp.test/cb", Some("dashboards"))
        .expect("an explicit application_id is signed");
    let app = request
        .application
        .expect("application is named")
        .application;
    assert_eq!(app.application_id, "dashboards");
    // The account is always the authenticated caller: no request field can
    // name a sibling account's application.
    assert_eq!(app.subject_user_id, user_id);

    for bad in ["", "has space", "slash/no"] {
        assert_eq!(
            sign_as(&pool, &api_key, "https://rp.test/cb", Some(bad)).err(),
            Some(1),
            "{bad:?}"
        );
    }
}

#[test]
fn rp_sign_request_refuses_non_https_callback() {
    let (pool, _user_id, api_key) = rp_caller();
    for url in [
        "http://rp.test/callback",
        "https://rp.test@attacker.example/cb",
        "not a url",
    ] {
        // A bad-request refusal travels as the MalformedEnvelope wire status.
        assert_eq!(sign(&pool, &api_key, url).err(), Some(1), "{url}");
    }
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

fn decrypt_request_payload(encrypted_token: &EncryptedToken) -> Vec<u8> {
    let param = liblinkkeys::encoding::encrypted_token_to_url_param(encrypted_token)
        .expect("encode EncryptedToken url param");
    liblinkkeys::generated::encode_rp_decrypt_request(&RpDecryptRequest {
        encrypted_token: param,
    })
}

/// Suite negotiation retrofit (dns-less-local-rp-design.md, Phase 3): an
/// `EncryptedToken.suite` id outside the AEAD suite registry must be rejected
/// outright rather than silently falling back to the baseline.
#[test]
fn rp_decrypt_token_rejects_unsupported_suite() {
    let pool = setup();
    let user = create_user(&pool, &DataMap::new());
    let api_key = api_key_for(&pool, &user.id);
    grant_api_access(&pool, &user.id);
    create_domain_key(&pool);

    let bad_token = EncryptedToken {
        ephemeral_public_key: vec![0u8; 32],
        ciphertext: vec![0u8; 16],
        nonce: vec![0u8; 12],
        suite: Some("made-up-suite".to_string()),
    };

    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Rp",
        "decrypt-token",
        decrypt_request_payload(&bad_token),
        Some(&api_key),
        &pool,
        None,
    );
    assert_ne!(
        status, 0,
        "an EncryptedToken.suite outside the registry must be rejected"
    );
}

/// An absent `suite` (the pre-retrofit wire shape) must still decrypt under
/// the mandatory-to-implement baseline (aes-256-gcm) — the hard cutover
/// changes what gets negotiated, not what "no suite on the wire" means.
#[test]
fn rp_decrypt_token_absent_suite_defaults_to_baseline() {
    let pool = setup();
    let user = create_user(&pool, &DataMap::new());
    let api_key = api_key_for(&pool, &user.id);
    grant_api_access(&pool, &user.id);
    let signing_key = create_domain_key(&pool);
    let (enc_pub, _enc_priv) = create_domain_encryption_key(&pool, &signing_key);

    let enc_pub_arr: [u8; 32] = enc_pub.as_slice().try_into().unwrap();
    let sealed = liblinkkeys::crypto::sealed_box_encrypt(
        b"plaintext assertion cbor",
        &enc_pub_arr,
        liblinkkeys::crypto::AeadSuite::Aes256Gcm,
    )
    .unwrap();
    let token = EncryptedToken {
        ephemeral_public_key: sealed.ephemeral_public_key,
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
        suite: None,
    };

    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Rp",
        "decrypt-token",
        decrypt_request_payload(&token),
        Some(&api_key),
        &pool,
        None,
    );
    assert_eq!(status, 0, "absent suite must decrypt under the baseline");
    let resp = liblinkkeys::generated::decode_rp_decrypt_response(&body).expect("decode response");
    assert!(!resp.signed_assertion.is_empty());
}

/// A present, supported non-baseline suite (chacha20-poly1305) must also
/// round-trip end to end through the TCP `decrypt-token` op.
#[test]
fn rp_decrypt_token_round_trips_with_explicit_non_baseline_suite() {
    let pool = setup();
    let user = create_user(&pool, &DataMap::new());
    let api_key = api_key_for(&pool, &user.id);
    grant_api_access(&pool, &user.id);
    let signing_key = create_domain_key(&pool);
    let (enc_pub, _enc_priv) = create_domain_encryption_key(&pool, &signing_key);

    let enc_pub_arr: [u8; 32] = enc_pub.as_slice().try_into().unwrap();
    let sealed = liblinkkeys::crypto::sealed_box_encrypt(
        b"plaintext assertion cbor",
        &enc_pub_arr,
        liblinkkeys::crypto::AeadSuite::ChaCha20Poly1305,
    )
    .unwrap();
    let token = EncryptedToken {
        ephemeral_public_key: sealed.ephemeral_public_key,
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
        suite: Some("chacha20-poly1305".to_string()),
    };

    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Rp",
        "decrypt-token",
        decrypt_request_payload(&token),
        Some(&api_key),
        &pool,
        None,
    );
    assert_eq!(
        status, 0,
        "an advertised non-baseline suite must decrypt successfully"
    );
    let resp = liblinkkeys::generated::decode_rp_decrypt_response(&body).expect("decode response");
    assert!(!resp.signed_assertion.is_empty());
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
