//! End-to-end test of finalize's failure ordering over the CBOR authorize API:
//! the RP encryption-key fetch runs BEFORE the single-use nonce burn, so an
//! encryption-side failure (the vouch-tag incident class) leaves the login
//! request retryable instead of consuming it — where a retry used to fail with
//! a second, different error ("already used"). Also pins the distinct error
//! codes: `rp_encrypt_key_untrusted` for the failed attempt, success on retry
//! once the key exists, and `request_already_used` on replay after success.

mod common;

use common::data_factory::{create_auth_credential, create_relation, create_user, DataMap};
use liblinkkeys::auth_request::{build_auth_request, sign_auth_request};
use liblinkkeys::crypto::{self, SigningAlgorithm};
use liblinkkeys::encoding::signed_auth_request_to_url_param;
use liblinkkeys::generated::types::{ApiErrorCode, AuthorizeFinalizeRequest};
use linkkeys::services::auth;
use rocket::http::{Header, Status};
use rocket::local::asynchronous::Client;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

const TEST_DOMAIN: &str = "finalize-retry.test";
const PASSPHRASE: &[u8] = b"test-passphrase";

#[rocket::async_test]
async fn failed_encryption_leaves_login_request_retryable() {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");

    let pool = common::create_test_pool();

    // -- Seed the IDP: a signing key only. The missing (never-vouched)
    //    encryption key is the point: token encryption must fail exactly the
    //    way it does when trust_keys drops an unvouched key.
    let (vk, sk) = crypto::generate_ed25519_keypair();
    let pk = vk.as_bytes().to_vec();
    let sk_bytes = sk.to_bytes().to_vec();
    let enc_sk = crypto::encrypt_private_key(&sk_bytes, PASSPHRASE).unwrap();
    let fp = crypto::fingerprint(&pk);
    let expires = chrono::Utc::now() + chrono::Duration::days(365);
    let signing = pool
        .create_domain_key(&pk, &enc_sk, &fp, "ed25519", expires)
        .expect("signing key");

    // The end user logging in, and the API-key caller driving the consent UI.
    let user = create_user(&pool, &DataMap::new());
    let caller = create_user(&pool, &DataMap::new());
    let (api_key, hash) = auth::generate_api_key(&caller.id);
    create_auth_credential(&pool, &caller.id, auth::CREDENTIAL_TYPE_API_KEY, &hash);
    create_relation(
        &pool,
        "user",
        &caller.id,
        "api_access",
        "domain",
        TEST_DOMAIN,
    );

    // -- Mint an auth-only signed_request (self-RP, so key fetch is local DB).
    let req = build_auth_request(
        TEST_DOMAIN,
        &format!("https://{}/cb", TEST_DOMAIN),
        "finalize-retry-nonce",
        &signing.id,
        None,
        None,
    );
    let signed_req =
        sign_auth_request(&req, &signing.id, SigningAlgorithm::Ed25519, &sk_bytes).unwrap();
    let sr = signed_auth_request_to_url_param(&signed_req).unwrap();

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
    let client = Client::tracked(rocket).await.expect("rocket client");

    let finalize_body =
        liblinkkeys::generated::encode_authorize_finalize_request(&AuthorizeFinalizeRequest {
            user_id: user.id.clone(),
            signed_request: sr.clone(),
            authorized_claims: vec![],
        });
    let bearer = || Header::new("Authorization", format!("Bearer {}", api_key));

    // -- 1. No trusted encryption key: 502 with the specific code that tells
    //    the RP operator to re-vouch.
    let resp = client
        .post("/rp/authorize/finalize")
        .header(bearer())
        .body(finalize_body.clone())
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::BadGateway);
    let err =
        liblinkkeys::generated::decode_api_error(&resp.into_bytes().await.expect("body")).unwrap();
    assert_eq!(err.code, ApiErrorCode::RpEncryptKeyUntrusted);

    // -- 2. Provision the vouched encryption key and retry the SAME
    //    signed_request: it must succeed — the failed attempt did not burn
    //    the nonce.
    let (epub, epriv) = crypto::generate_x25519_keypair();
    let efp = crypto::fingerprint(&epub);
    let epriv_enc = crypto::encrypt_private_key(&epriv, PASSPHRASE).unwrap();
    let vouch = liblinkkeys::dns::sign_key_vouch(
        &efp,
        &expires.to_rfc3339(),
        SigningAlgorithm::Ed25519,
        &sk_bytes,
    )
    .unwrap();
    pool.create_domain_encryption_key(&epub, &epriv_enc, &efp, &signing.id, &vouch, expires)
        .expect("encryption key");

    let resp = client
        .post("/rp/authorize/finalize")
        .header(bearer())
        .body(finalize_body.clone())
        .dispatch()
        .await;
    assert_eq!(
        resp.status(),
        Status::Ok,
        "retry after provisioning the key must succeed — the failed attempt \
         must not have burned the nonce"
    );
    let ok = liblinkkeys::generated::decode_authorize_finalize_response(
        &resp.into_bytes().await.expect("body"),
    )
    .unwrap();
    assert!(ok.redirect_url.contains("encrypted_token="));

    // -- 3. Replay after success: the nonce is now burned, and the client gets
    //    the distinct "start a new login" code, not a generic 500.
    let resp = client
        .post("/rp/authorize/finalize")
        .header(bearer())
        .body(finalize_body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Conflict);
    let err =
        liblinkkeys::generated::decode_api_error(&resp.into_bytes().await.expect("body")).unwrap();
    assert_eq!(err.code, ApiErrorCode::RequestAlreadyUsed);
}
