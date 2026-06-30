//! End-to-end test of the TCP `Identity/get-user-info` path via the
//! `dispatch_for_test` seam — no socket, no TLS. This is the regression guard
//! for the consent-scoping fix: the TCP path must release only the claim types
//! named in the assertion's `authorized_claims` (it previously returned all).

mod common;

use common::data_factory::{create_user, DataMap};
use liblinkkeys::generated::types::{GetUserInfoRequest, UserInfo};
use liblinkkeys::{assertions, crypto, encoding};

const TEST_DOMAIN: &str = "tcp-scope.test";
const TEST_PASSPHRASE: &[u8] = b"test-passphrase";

/// Seed a signing key (returning its id + raw secret so the test can sign an
/// assertion), and two claims for `user_id`.
fn seed(pool: &linkkeys::db::DbPool, user_id: &str) -> (String, Vec<u8>) {
    let (vk, sk) = crypto::generate_ed25519_keypair();
    let pk = vk.as_bytes().to_vec();
    let sk_bytes = sk.to_bytes().to_vec();
    let enc = crypto::encrypt_private_key(&sk_bytes, TEST_PASSPHRASE).unwrap();
    let fp = crypto::fingerprint(&pk);
    let expires = chrono::Utc::now() + chrono::Duration::days(365);
    let dk = pool
        .create_domain_key(&pk, &enc, &fp, "ed25519", expires)
        .expect("create_domain_key");

    for (ct, val) in [("email", b"a@b.com".as_slice()), ("ssn", b"123".as_slice())] {
        pool.create_claim(
            &uuid::Uuid::now_v7().to_string(),
            user_id,
            ct,
            val,
            &[],
            None,
        )
        .expect("create claim");
    }
    (dk.id, sk_bytes)
}

/// A URL-param token for `user_id`, audience `audience`, authorizing exactly
/// `authorized`, signed by the seeded key.
fn token(
    key_id: &str,
    sk: &[u8],
    user_id: &str,
    audience: &str,
    nonce: &str,
    authorized: Vec<String>,
) -> Vec<u8> {
    let assertion = assertions::build_assertion(
        user_id,
        TEST_DOMAIN,
        audience,
        nonce,
        Some("Test User"),
        300,
        authorized,
    );
    let signed =
        assertions::sign_assertion(&assertion, key_id, crypto::SigningAlgorithm::Ed25519, sk)
            .unwrap();
    encoding::assertion_to_url_param(&signed)
        .unwrap()
        .into_bytes()
}

fn call_get_user_info(
    pool: &linkkeys::db::DbPool,
    token_bytes: Vec<u8>,
    client_domain: &str,
) -> (i32, Option<UserInfo>) {
    let payload = liblinkkeys::generated::encode_get_user_info_request(&GetUserInfoRequest {
        token: token_bytes,
    });
    let (status, body) = linkkeys::tcp::dispatch_for_test(
        "Identity",
        "get-user-info",
        payload,
        pool,
        Some(client_domain),
    );
    let info = if status == 0 {
        Some(liblinkkeys::generated::decode_user_info(&body).expect("decode UserInfo"))
    } else {
        None
    };
    (status, info)
}

#[test]
fn tcp_get_user_info_releases_only_authorized_claims() {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");

    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    let (key_id, sk) = seed(&pool, &user.id);
    let audience = "rp.example";

    // Authorize only "email"; the caller (mTLS client_domain) is the audience.
    let tok = token(
        &key_id,
        &sk,
        &user.id,
        audience,
        "n-authorized",
        vec!["email".to_string()],
    );
    let (status, info) = call_get_user_info(&pool, tok, audience);
    assert_eq!(status, 0, "expected success");
    let mut types: Vec<String> = info
        .unwrap()
        .claims
        .into_iter()
        .map(|c| c.claim_type)
        .collect();
    types.sort();
    assert_eq!(
        types,
        vec!["email".to_string()],
        "only the authorized claim is released"
    );
}

#[test]
fn tcp_get_user_info_empty_authorization_releases_nothing() {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");

    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    let (key_id, sk) = seed(&pool, &user.id);
    let audience = "rp.example";

    let tok = token(&key_id, &sk, &user.id, audience, "n-empty", vec![]);
    let (status, info) = call_get_user_info(&pool, tok, audience);
    assert_eq!(status, 0);
    assert!(
        info.unwrap().claims.is_empty(),
        "fail-closed: nothing authorized => nothing released"
    );
}

#[test]
fn tcp_get_user_info_wrong_audience_rejected() {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");

    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    let (key_id, sk) = seed(&pool, &user.id);

    // Assertion is for audience "rp.example" but the mTLS caller is someone else.
    let tok = token(
        &key_id,
        &sk,
        &user.id,
        "rp.example",
        "n-aud",
        vec!["email".to_string()],
    );
    let (status, _) = call_get_user_info(&pool, tok, "attacker.example");
    assert_ne!(
        status, 0,
        "caller that is not the audience must be rejected"
    );
}
