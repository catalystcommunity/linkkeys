//! Integration test for consent scoping at the `/userinfo` boundary: the IDP
//! releases only the claim types named in the assertion's `authorized_claims`,
//! regardless of how many claims the user actually holds. This exercises the
//! full server wiring (`web::build_userinfo_signed` → `consent::scope_claims`)
//! over a real database via the self-RP path.

mod common;

use common::data_factory::{create_domain_key, create_user, DataMap};
use liblinkkeys::{assertions, crypto, encoding, userinfo};

const TEST_DOMAIN: &str = "consent-scope.test";
const TEST_PASSPHRASE: &[u8] = b"test-passphrase";

/// A signed, URL-param-encoded assertion authorizing exactly `authorized` claim
/// types for `TEST_DOMAIN` as audience.
fn make_token(
    dk: &linkkeys::db::models::DomainKey,
    user_id: &str,
    nonce: &str,
    authorized: Vec<String>,
) -> String {
    let sk_bytes = crypto::decrypt_private_key(&dk.private_key_encrypted, TEST_PASSPHRASE).unwrap();
    let assertion = assertions::build_assertion(
        user_id,
        TEST_DOMAIN,
        TEST_DOMAIN,
        nonce,
        Some("Test User"),
        300,
        authorized,
    );
    let signed = assertions::sign_assertion(
        &assertion,
        &dk.id,
        crypto::SigningAlgorithm::Ed25519,
        &sk_bytes,
    )
    .unwrap();
    encoding::assertion_to_url_param(&signed).unwrap()
}

fn sign_request(
    dk: &linkkeys::db::models::DomainKey,
    token: &str,
    nonce: &str,
) -> liblinkkeys::generated::types::SignedUserInfoRequest {
    let sk_bytes = crypto::decrypt_private_key(&dk.private_key_encrypted, TEST_PASSPHRASE).unwrap();
    let request = userinfo::build_user_info_request(token.as_bytes().to_vec(), TEST_DOMAIN, nonce);
    userinfo::sign_user_info_request(
        &request,
        &dk.id,
        crypto::SigningAlgorithm::Ed25519,
        &sk_bytes,
        None,
    )
    .unwrap()
}

/// Give `user` two claims of distinct types.
fn seed_claims(pool: &linkkeys::db::DbPool, user_id: &str) {
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
}

fn claim_types(info: &liblinkkeys::generated::types::UserInfo) -> Vec<String> {
    let mut ts: Vec<String> = info.claims.iter().map(|c| c.claim_type.clone()).collect();
    ts.sort();
    ts
}

#[rocket::async_test]
async fn userinfo_releases_only_authorized_claims() {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");

    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    let dk = create_domain_key(&pool);
    seed_claims(&pool, &user.id);

    // Authorize only "email": "ssn" must not be released even though it exists.
    let token = make_token(&dk, &user.id, "scope-email", vec!["email".to_string()]);
    let signed = sign_request(&dk, &token, "req-email");
    let info = linkkeys::web::build_userinfo_signed(&pool, &common::net::offline_net(), &signed)
        .await
        .expect("valid redemption");
    assert_eq!(claim_types(&info), vec!["email".to_string()]);
}

#[rocket::async_test]
async fn userinfo_with_empty_authorization_releases_nothing() {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");

    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    let dk = create_domain_key(&pool);
    seed_claims(&pool, &user.id);

    // Fail-closed: an assertion that authorizes nothing releases no claims.
    let token = make_token(&dk, &user.id, "scope-none", vec![]);
    let signed = sign_request(&dk, &token, "req-none");
    let info = linkkeys::web::build_userinfo_signed(&pool, &common::net::offline_net(), &signed)
        .await
        .expect("valid redemption");
    assert!(
        info.claims.is_empty(),
        "expected no claims, got {:?}",
        claim_types(&info)
    );
}
