//! Integration tests for the signed `/userinfo` proof-of-possession binding
//! (crypto-06 / web-04). A relying party must wrap the assertion token in a
//! `SignedUserInfoRequest` signed by its domain key; the IDP verifies the PoP,
//! requires `relying_party == assertion.audience`, and allows a single
//! redemption per assertion.
//!
//! These exercise the self-RP path (relying_party == DOMAIN_NAME), so the IDP
//! resolves the RP's signing keys from its own DB — no DNS/HTTP round-trip — and
//! the full server wiring (`web::build_userinfo_signed`) runs end to end.

mod common;

use common::data_factory::{create_domain_key, create_user, DataMap};
use liblinkkeys::{assertions, crypto, encoding, userinfo};

const TEST_DOMAIN: &str = "userinfo-pop.test";
const TEST_PASSPHRASE: &[u8] = b"test-passphrase";

/// Build a signed, URL-param-encoded assertion for `user_id` whose audience is
/// `audience`, signed by `dk`.
fn make_token(
    dk: &linkkeys::db::models::DomainKey,
    user_id: &str,
    audience: &str,
    nonce: &str,
) -> String {
    let sk_bytes = crypto::decrypt_private_key(&dk.private_key_encrypted, TEST_PASSPHRASE).unwrap();
    let assertion =
        assertions::build_assertion(user_id, TEST_DOMAIN, audience, nonce, Some("Test User"), 300);
    let signed =
        assertions::sign_assertion(&assertion, &dk.id, crypto::SigningAlgorithm::Ed25519, &sk_bytes)
            .unwrap();
    encoding::assertion_to_url_param(&signed).unwrap()
}

/// Sign a `SignedUserInfoRequest` for `token`, claiming to be `relying_party`,
/// using `dk` as the proof-of-possession key.
fn sign_request(
    dk: &linkkeys::db::models::DomainKey,
    token: &str,
    relying_party: &str,
    nonce: &str,
) -> liblinkkeys::generated::types::SignedUserInfoRequest {
    let sk_bytes = crypto::decrypt_private_key(&dk.private_key_encrypted, TEST_PASSPHRASE).unwrap();
    let request =
        userinfo::build_user_info_request(token.as_bytes().to_vec(), relying_party, nonce);
    userinfo::sign_user_info_request(
        &request,
        &dk.id,
        crypto::SigningAlgorithm::Ed25519,
        &sk_bytes,
        None,
    )
    .unwrap()
}

#[rocket::async_test]
async fn signed_userinfo_request_returns_claims() {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");

    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    let dk = create_domain_key(&pool);

    let token = make_token(&dk, &user.id, TEST_DOMAIN, "nonce-ok");
    let signed = sign_request(&dk, &token, TEST_DOMAIN, "req-nonce-ok");

    let info = linkkeys::web::build_userinfo_signed(&pool, &signed)
        .await
        .expect("valid signed userinfo request from the audience domain");

    assert_eq!(info.user_id, user.id);
    assert_eq!(info.domain, TEST_DOMAIN);
}

#[rocket::async_test]
async fn signed_userinfo_request_is_single_use() {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");

    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    let dk = create_domain_key(&pool);

    let token = make_token(&dk, &user.id, TEST_DOMAIN, "nonce-single");
    let signed = sign_request(&dk, &token, TEST_DOMAIN, "req-nonce-single");

    // First redemption succeeds.
    linkkeys::web::build_userinfo_signed(&pool, &signed)
        .await
        .expect("first redemption");

    // A second redemption of the same assertion is rejected (the nonce is burned).
    let again = linkkeys::web::build_userinfo_signed(&pool, &signed).await;
    assert_eq!(again.err(), Some(rocket::http::Status::Unauthorized));
}

#[rocket::async_test]
async fn signed_userinfo_request_audience_mismatch_rejected() {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");

    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    let dk = create_domain_key(&pool);

    // Assertion is issued for a DIFFERENT audience than the request claims.
    // The PoP signature still verifies (same domain key), but the audience
    // binding must reject it.
    let token = make_token(&dk, &user.id, "someone-else.test", "nonce-aud");
    let signed = sign_request(&dk, &token, TEST_DOMAIN, "req-nonce-aud");

    let result = linkkeys::web::build_userinfo_signed(&pool, &signed).await;
    assert_eq!(result.err(), Some(rocket::http::Status::Unauthorized));
}

#[rocket::async_test]
async fn signed_userinfo_request_tampered_rejected() {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");

    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    let dk = create_domain_key(&pool);

    let token = make_token(&dk, &user.id, TEST_DOMAIN, "nonce-tamper");
    let mut signed = sign_request(&dk, &token, TEST_DOMAIN, "req-nonce-tamper");

    // Corrupt the proof-of-possession signature: the request body still decodes
    // and the RP key still resolves, but the PoP verification must fail.
    if let Some(byte) = signed.signature.first_mut() {
        *byte ^= 0xff;
    }

    let result = linkkeys::web::build_userinfo_signed(&pool, &signed).await;
    assert_eq!(result.err(), Some(rocket::http::Status::Unauthorized));
}
