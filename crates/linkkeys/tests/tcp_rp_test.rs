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
    ApplicationRef, EncryptedToken, RpDecryptRequest, RpErrorCode, RpSignRequest, RpVerifyRequest,
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
    liblinkkeys::generated::encode_rp_sign_request(&RpSignRequest {
        callback_url: callback_url.to_string(),
        nonce: "nonce-1".to_string(),
        requested_claims: None,
        authentication_requirements: None,
        flow_context: None,
    })
    .unwrap()
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

/// An application account (kind `application`): the only kind of account
/// that may drive `Rp/sign-request`.
fn create_app_account(
    pool: &linkkeys::db::DbPool,
    username: &str,
    display_name: &str,
    application_id: &str,
) -> linkkeys::db::models::User {
    pool.create_account(username, display_name, Some(application_id))
        .expect("create application account")
}

#[test]
fn rp_sign_request_happy_path() {
    let pool = setup();
    let user = create_app_account(&pool, "rp-app", "RP App", "rp-app");
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
    rp_caller_for("homegrafana")
}

/// Like [`rp_caller`], with an administrator-set `application_id`.
fn rp_caller_for(application_id: &str) -> (linkkeys::db::DbPool, String, String) {
    let pool = setup();
    let user = create_app_account(&pool, "homegrafana", "Home Grafana", application_id);
    let api_key = api_key_for(&pool, &user.id);
    grant_api_access(&pool, &user.id);
    create_domain_key(&pool);
    (pool, user.id, api_key)
}

/// The refusal of an `Rp` operation: a transport status, or a typed
/// `RpError` reply.
#[derive(Debug, PartialEq)]
enum Refusal {
    Status(i32),
    Rp(RpErrorCode),
}

/// Call an `Rp` operation with an outbound context. A status-0 reply carries
/// the arm named by `variant`; an `RpError` arm becomes `Refusal::Rp`.
fn rp_call(
    pool: &linkkeys::db::DbPool,
    api_key: &str,
    op: &str,
    payload: Vec<u8>,
    success_variant: &str,
) -> Result<Vec<u8>, Refusal> {
    let reply = linkkeys::tcp::dispatch_for_test_with_net(
        "Rp",
        op,
        payload,
        Some(api_key),
        pool,
        &common::net::offline_net(),
    );
    if reply.status != 0 {
        return Err(Refusal::Status(reply.status));
    }
    match reply.variant.as_deref() {
        Some("RpError") => {
            let error =
                liblinkkeys::generated::decode_rp_error(&reply.payload).expect("decode RpError");
            Err(Refusal::Rp(error.code))
        }
        Some(v) if v == success_variant => Ok(reply.payload),
        other => panic!("unexpected reply variant {other:?}"),
    }
}

fn sign(
    pool: &linkkeys::db::DbPool,
    api_key: &str,
    callback_url: &str,
) -> Result<liblinkkeys::generated::types::AuthRequest, Refusal> {
    let body = rp_call(
        pool,
        api_key,
        "sign-request",
        sign_request_payload_for(callback_url),
        "RpSignResponse",
    )?;
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
    let app = request.application;
    // The same identity shape as an act-as ApplicationRef: the calling
    // account, this domain, and the account's administrator-set id.
    assert_eq!(app.application.subject_user_id, user_id);
    assert_eq!(app.application.subject_domain, TEST_DOMAIN);
    assert_eq!(app.application.application_id, "homegrafana");
    assert_eq!(app.display_name, "Home Grafana");
}

#[test]
fn rp_sign_request_names_the_callers_own_application_only() {
    let (pool, user_id, api_key) = rp_caller_for("dashboards");

    let request =
        sign(&pool, &api_key, "https://rp.test/cb").expect("the caller's application is signed");
    let app = request.application.application;
    // The application id is the one an administrator set on the account,
    // not the username, and no request field can choose another.
    assert_eq!(app.application_id, "dashboards");
    // The account is always the authenticated caller.
    assert_eq!(app.subject_user_id, user_id);
    assert_eq!(app.subject_domain, TEST_DOMAIN);
}

#[test]
fn rp_sign_request_refuses_a_human_account() {
    // An api_access API key on a human account must not get a signed auth
    // request: only an application account names an application principal.
    let pool = setup();
    let user = create_user(&pool, &DataMap::new());
    let api_key = api_key_for(&pool, &user.id);
    grant_api_access(&pool, &user.id);
    create_domain_key(&pool);
    assert_eq!(
        sign(&pool, &api_key, "https://rp.test/cb").err(),
        Some(Refusal::Rp(RpErrorCode::NotApplicationAccount)),
        "a human account must not sign auth requests"
    );
}

#[test]
fn rp_sign_request_refuses_non_https_callback() {
    let (pool, _user_id, api_key) = rp_caller();
    for url in [
        "http://rp.test/callback",
        "https://rp.test@attacker.example/cb",
        "not a url",
    ] {
        assert_eq!(
            sign(&pool, &api_key, url).err(),
            Some(Refusal::Rp(RpErrorCode::BadRequest)),
            "{url}"
        );
    }
}

#[test]
fn rp_ops_require_api_access_relation() {
    // SEC-06: a valid API key without the api_access relation is Forbidden — it
    // must not be able to drive the domain sign/decrypt oracles.
    let pool = setup();
    let user = create_app_account(&pool, "rp-app", "RP App", "rp-app");
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
    .unwrap()
}

/// Suite negotiation retrofit (dns-less-local-rp-design.md, Phase 3): an
/// `EncryptedToken.suite` id outside the AEAD suite registry must be rejected
/// outright rather than silently falling back to the baseline.
#[test]
fn rp_decrypt_token_rejects_unsupported_suite() {
    let pool = setup();
    let user = create_app_account(&pool, "rp-app", "RP App", "rp-app");
    let api_key = api_key_for(&pool, &user.id);
    grant_api_access(&pool, &user.id);
    create_domain_key(&pool);

    // The typed `EncryptedToken` cannot hold an unregistered suite, so
    // encode a valid token and rewrite its `suite` number on the wire to an
    // id outside the registry — the shape a hostile or newer peer would send.
    let token = EncryptedToken {
        ephemeral_public_key: vec![0u8; 32],
        ciphertext: vec![0u8; 16],
        nonce: vec![0u8; 12],
        suite: Some(liblinkkeys::crypto::AeadSuite::Aes256Gcm),
    };
    let mut value: ciborium::Value = ciborium::from_reader(
        liblinkkeys::generated::encode_encrypted_token(&token)
            .unwrap()
            .as_slice(),
    )
    .expect("decode token cbor");
    let entries = value.as_map_mut().expect("token is a CBOR map");
    let suite = entries
        .iter_mut()
        .find(|(k, _)| k.as_text() == Some("suite"))
        .expect("suite entry");
    suite.1 = ciborium::Value::Integer(99.into());
    let mut bad_cbor = Vec::new();
    ciborium::into_writer(&value, &mut bad_cbor).expect("encode token cbor");
    use base64ct::Encoding;
    let bad_payload = liblinkkeys::generated::encode_rp_decrypt_request(&RpDecryptRequest {
        encrypted_token: base64ct::Base64UrlUnpadded::encode_string(&bad_cbor),
    })
    .unwrap();

    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Rp",
        "decrypt-token",
        bad_payload,
        Some(&api_key),
        &pool,
        None,
    );
    assert_ne!(
        status, 0,
        "an EncryptedToken.suite outside the registry must be rejected"
    );
}

/// A signed identity assertion from this domain (a single-instance IDP+RP,
/// whose keys are local) for `application`, sealed to this domain's
/// encryption key under `suite`. Its login is started (the nonce recorded)
/// for the application's account, as `sign-request` does.
fn sealed_assertion(
    pool: &linkkeys::db::DbPool,
    user_id: &str,
    application: ApplicationRef,
    suite: Option<liblinkkeys::crypto::AeadSuite>,
) -> EncryptedToken {
    let nonce = uuid::Uuid::now_v7().to_string();
    start_login(pool, &application.subject_user_id, &nonce);
    sealed_assertion_with_nonce(pool, user_id, application, suite, &nonce)
}

fn start_login(pool: &linkkeys::db::DbPool, account_id: &str, nonce: &str) {
    use sha2::Digest as _;
    let hash: [u8; 32] = sha2::Sha256::digest(nonce.as_bytes()).into();
    pool.insert_rp_login_nonce(
        account_id,
        &hash,
        liblinkkeys::timestamp::now_whole_milliseconds() + time::Duration::hours(1),
    )
    .unwrap();
}

fn sealed_assertion_with_nonce(
    pool: &linkkeys::db::DbPool,
    user_id: &str,
    application: ApplicationRef,
    suite: Option<liblinkkeys::crypto::AeadSuite>,
    nonce: &str,
) -> EncryptedToken {
    let signing_key = create_domain_key(pool);
    let (enc_pub, _enc_priv) = create_domain_encryption_key(pool, &signing_key);
    let assertion = liblinkkeys::assertions::build_assertion(
        user_id,
        TEST_DOMAIN,
        TEST_DOMAIN,
        nonce,
        None,
        300,
        Vec::new(),
        application,
    );
    let sk = liblinkkeys::crypto::decrypt_private_key(
        &signing_key.private_key_encrypted,
        b"test-passphrase",
    )
    .unwrap();
    let signed = liblinkkeys::assertions::sign_assertion(
        &assertion,
        &signing_key.id,
        liblinkkeys::crypto::SigningAlgorithm::Ed25519,
        &sk,
    )
    .unwrap();
    let plaintext = liblinkkeys::generated::encode_signed_identity_assertion(&signed).unwrap();
    let enc_pub_arr: [u8; 32] = enc_pub.as_slice().try_into().unwrap();
    let wire_suite = suite.unwrap_or(liblinkkeys::crypto::AeadSuite::Aes256Gcm);
    let sealed =
        liblinkkeys::crypto::sealed_box_encrypt(&plaintext, &enc_pub_arr, &wire_suite).unwrap();
    EncryptedToken {
        ephemeral_public_key: sealed.ephemeral_public_key,
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
        suite,
    }
}

fn app_ref(user_id: &str, application_id: &str) -> ApplicationRef {
    ApplicationRef {
        subject_user_id: user_id.to_string(),
        subject_domain: TEST_DOMAIN.to_string(),
        application_id: application_id.to_string(),
    }
}

fn decrypt(
    pool: &linkkeys::db::DbPool,
    api_key: &str,
    token: &EncryptedToken,
) -> Result<liblinkkeys::generated::types::RpDecryptResponse, Refusal> {
    let body = rp_call(
        pool,
        api_key,
        "decrypt-token",
        decrypt_request_payload(token),
        "RpDecryptResponse",
    )?;
    Ok(liblinkkeys::generated::decode_rp_decrypt_response(&body).expect("decode response"))
}

/// An absent `suite` (the pre-retrofit wire shape) must still decrypt under
/// the mandatory-to-implement baseline (aes-256-gcm).
#[test]
fn rp_decrypt_token_absent_suite_defaults_to_baseline() {
    let (pool, user_id, api_key) = rp_caller();
    let token = sealed_assertion(&pool, "user-1", app_ref(&user_id, "homegrafana"), None);
    let resp = decrypt(&pool, &api_key, &token).expect("absent suite decrypts under the baseline");
    assert!(!resp.signed_assertion.is_empty());
}

/// A present, supported non-baseline suite (chacha20-poly1305) must also
/// round-trip end to end through the TCP `decrypt-token` op.
#[test]
fn rp_decrypt_token_round_trips_with_explicit_non_baseline_suite() {
    let (pool, user_id, api_key) = rp_caller();
    let token = sealed_assertion(
        &pool,
        "user-1",
        app_ref(&user_id, "homegrafana"),
        Some(liblinkkeys::crypto::AeadSuite::Chacha20Poly1305),
    );
    let resp = decrypt(&pool, &api_key, &token).expect("a non-baseline suite decrypts");
    assert!(!resp.signed_assertion.is_empty());
}

/// One tenant of a shared RP cannot read a token issued for another.
#[test]
fn rp_decrypt_token_refuses_another_applications_token() {
    let (pool, user_id, api_key) = rp_caller();
    let other = create_app_account(&pool, "other-app", "Other", "other-app");
    for application in [
        app_ref(&user_id, "dashboards"),
        app_ref(&other.id, "other-app"),
    ] {
        let token = sealed_assertion(&pool, "user-1", application, None);
        assert_eq!(
            decrypt(&pool, &api_key, &token).err(),
            Some(Refusal::Rp(RpErrorCode::ApplicationMismatch))
        );
    }
}

/// A new user over the application's distinct-user limit is refused; a user
/// already in the window still gets in.
#[test]
fn rp_decrypt_token_enforces_the_distinct_user_limit() {
    let (pool, user_id, api_key) = rp_caller();
    pool.set_account_limits(
        &user_id,
        &linkkeys::db::applications::AccountLimitsRecord {
            max_distinct_users: Some(1),
            ..Default::default()
        },
    )
    .unwrap();
    let app = || app_ref(&user_id, "homegrafana");
    decrypt(
        &pool,
        &api_key,
        &sealed_assertion(&pool, "user-1", app(), None),
    )
    .expect("the first user is admitted");
    assert_eq!(
        decrypt(
            &pool,
            &api_key,
            &sealed_assertion(&pool, "user-2", app(), None)
        )
        .err(),
        Some(Refusal::Rp(RpErrorCode::ApplicationUserLimit)),
        "a second user goes over the limit"
    );
    decrypt(
        &pool,
        &api_key,
        &sealed_assertion(&pool, "user-1", app(), None),
    )
    .expect("a known user is still admitted");
    let since = liblinkkeys::timestamp::now_whole_milliseconds() - time::Duration::days(30);
    assert_eq!(
        pool.count_application_users_since(&user_id, since).unwrap(),
        1
    );
}

/// Only an open login of this application is finished, and only once: a
/// forged assertion with a nonce the application never sent, or a replayed
/// token, is refused before the user is counted.
#[test]
fn rp_decrypt_token_needs_an_open_login_of_the_caller() {
    let (pool, user_id, api_key) = rp_caller();
    let never_started = sealed_assertion_with_nonce(
        &pool,
        "user-1",
        app_ref(&user_id, "homegrafana"),
        None,
        "forged-nonce",
    );
    assert_eq!(
        decrypt(&pool, &api_key, &never_started).err(),
        Some(Refusal::Rp(RpErrorCode::BadRequest))
    );
    let token = sealed_assertion(&pool, "user-1", app_ref(&user_id, "homegrafana"), None);
    decrypt(&pool, &api_key, &token).expect("an open login is finished");
    assert_eq!(
        decrypt(&pool, &api_key, &token).err(),
        Some(Refusal::Rp(RpErrorCode::BadRequest)),
        "a finished login cannot be replayed"
    );
    let since = liblinkkeys::timestamp::now_whole_milliseconds() - time::Duration::days(30);
    assert_eq!(
        pool.count_application_users_since(&user_id, since).unwrap(),
        1
    );
}

/// `sign-request` starts the login that `decrypt-token` finishes.
#[test]
fn rp_sign_request_records_the_login_nonce() {
    let (pool, user_id, api_key) = rp_caller();
    sign(&pool, &api_key, "https://rp.test/cb").unwrap();
    use sha2::Digest as _;
    let hash: [u8; 32] = sha2::Sha256::digest(b"nonce-1").into();
    assert!(pool
        .rp_login_nonce_open(
            &user_id,
            &hash,
            liblinkkeys::timestamp::now_whole_milliseconds()
        )
        .unwrap());
}

/// A token that holds no assertion is refused before anything is counted.
#[test]
fn rp_decrypt_token_refuses_a_token_without_an_assertion() {
    let (pool, _user_id, api_key) = rp_caller();
    let signing_key = create_domain_key(&pool);
    let (enc_pub, _) = create_domain_encryption_key(&pool, &signing_key);
    let enc_pub_arr: [u8; 32] = enc_pub.as_slice().try_into().unwrap();
    let sealed = liblinkkeys::crypto::sealed_box_encrypt(
        b"not an assertion",
        &enc_pub_arr,
        &liblinkkeys::crypto::AeadSuite::Aes256Gcm,
    )
    .unwrap();
    let token = EncryptedToken {
        ephemeral_public_key: sealed.ephemeral_public_key,
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
        suite: None,
    };
    assert_eq!(
        decrypt(&pool, &api_key, &token).err(),
        Some(Refusal::Rp(RpErrorCode::BadRequest))
    );
}

#[test]
fn rp_verify_assertion_needs_outbound_context() {
    let pool = setup();
    let user = create_app_account(&pool, "rp-app", "RP App", "rp-app");
    let api_key = api_key_for(&pool, &user.id);
    grant_api_access(&pool, &user.id);

    let payload = liblinkkeys::generated::encode_rp_verify_request(&RpVerifyRequest {
        signed_assertion: "AAAA".to_string(),
        expected_domain: "other.test".to_string(),
    })
    .unwrap();

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
