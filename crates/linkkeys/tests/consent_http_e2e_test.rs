//! End-to-end test of the browser consent flow over real Rocket routing via the
//! in-process local client — every handler runs, with NO network socket (the
//! `Net` seam is the offline fake; the self-RP path uses the local DB).
//!
//! One test drives the whole flow plus antagonistic variants sequentially, so a
//! single `DOMAIN_NAME` is set (avoids env races with parallel tests).

mod common;

use common::data_factory::{create_auth_credential, create_user, DataMap};
use liblinkkeys::auth_request::{build_auth_request, sign_auth_request};
use liblinkkeys::crypto::{self, SigningAlgorithm};
use liblinkkeys::encoding::signed_auth_request_to_url_param;
use liblinkkeys::generated::types::{AuthFlowContext, ClaimRequest, RequestedClaim};
use rocket::http::{ContentType, Status};
use rocket::local::asynchronous::Client;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

const TEST_DOMAIN: &str = "e2e.test";
const PASSPHRASE: &[u8] = b"test-passphrase";
const USERNAME: &str = "alice";
const PASSWORD: &str = "correct horse battery staple";

/// Pull a hidden form field's value out of rendered HTML.
fn hidden_field(html: &str, name: &str) -> String {
    let marker = format!(r#"name="{}" value=""#, name);
    let start = html
        .find(&marker)
        .unwrap_or_else(|| panic!("field {} present", name))
        + marker.len();
    let rest = &html[start..];
    let end = rest.find('"').expect("closing quote");
    rest[..end].to_string()
}

fn form(body: &str) -> (ContentType, String) {
    (ContentType::Form, body.to_string())
}

#[rocket::async_test]
async fn consent_flow_end_to_end() {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    std::env::set_var("ENABLE_PASSWORD_AUTH", "true");

    let pool = common::create_test_pool();

    // -- Seed the IDP: signing key (keep sk to mint the signed_request),
    //    a vouched X25519 encryption key (the assertion is sealed to it),
    //    a user with a password, and two claims.
    let (vk, sk) = crypto::generate_ed25519_keypair();
    let pk = vk.as_bytes().to_vec();
    let sk_bytes = sk.to_bytes().to_vec();
    let enc_sk = crypto::encrypt_private_key(&sk_bytes, PASSPHRASE).unwrap();
    let fp = crypto::fingerprint(&pk);
    let expires = chrono::Utc::now() + chrono::Duration::days(365);
    let signing = pool
        .create_domain_key(&pk, &enc_sk, &fp, "ed25519", expires)
        .expect("signing key");

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

    let mut overrides = DataMap::new();
    overrides.insert("username".to_string(), serde_json::json!(USERNAME));
    let user = create_user(&pool, &overrides);
    let hash = linkkeys::services::password::hash_for_storage(PASSWORD).unwrap();
    create_auth_credential(&pool, &user.id, "password", &hash);
    for (ct, val) in [("email", b"a@b.com".as_slice()), ("ssn", b"123".as_slice())] {
        pool.create_claim(
            &uuid::Uuid::now_v7().to_string(),
            &user.id,
            ct,
            val,
            &[],
            None,
            chrono::Utc::now(),
        )
        .expect("claim");
    }

    // -- Mint a signed_request requesting email (required) + ssn (optional).
    let mut req = build_auth_request(
        TEST_DOMAIN,
        &format!("https://{}/cb", TEST_DOMAIN),
        "login-nonce-1",
        &signing.id,
        Some(ClaimRequest {
            required: vec![RequestedClaim {
                claim_type: "email".to_string(),
                datatype: "email".to_string(),
            }],
            optional: vec![RequestedClaim {
                claim_type: "ssn".to_string(),
                datatype: "text".to_string(),
            }],
        }),
        None,
    );
    req.relying_party_claims = None;
    let signed_req =
        sign_auth_request(&req, &signing.id, SigningAlgorithm::Ed25519, &sk_bytes).unwrap();
    let sr = signed_auth_request_to_url_param(&signed_req).unwrap();

    // -- Build the real Rocket app and drive it in-process (no socket).
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

    // 1. GET the login form (happy).
    let resp = client
        .get(format!("/auth/authorize?signed_request={}", sr))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body = resp.into_string().await.unwrap();
    assert!(
        body.contains("Log In"),
        "login form renders for a valid request"
    );

    // 1b. GET with a malformed signed_request renders an error page, not a form
    //     (antagonistic: never phish credentials onto a crafted URL).
    let resp = client
        .get("/auth/authorize?signed_request=not-valid")
        .dispatch()
        .await;
    let body = resp.into_string().await.unwrap();
    assert!(
        body.contains("malformed"),
        "malformed request => error page"
    );
    assert!(
        !body.contains("name=\"password\""),
        "no login form on a bad request"
    );

    // 2. POST wrong password (antagonistic) => login form with an error.
    let resp = client
        .post("/auth/authorize")
        .header(ContentType::Form)
        .body(format!(
            "username={}&password=wrong&signed_request={}",
            USERNAME, sr
        ))
        .dispatch()
        .await;
    let body = resp.into_string().await.unwrap();
    assert!(
        body.contains("Invalid username or password"),
        "wrong password rejected"
    );

    // 3. POST correct credentials => consent screen with a login proof.
    let (ct, b) = form(&format!(
        "username={}&password={}&signed_request={}",
        USERNAME,
        PASSWORD.replace(' ', "+"),
        sr
    ));
    let resp = client
        .post("/auth/authorize")
        .header(ct)
        .body(b)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let consent_html = resp.into_string().await.unwrap();
    assert!(
        consent_html.contains("What do you want to share with"),
        "consent screen renders"
    );
    let proof = hidden_field(&consent_html, "login_proof");

    // 3b. Cancel must issue nothing: a neutral notice page, no redirect, no
    //     sealed token. It short-circuits before any grant is written.
    let resp = client
        .post("/auth/consent")
        .header(ContentType::Form)
        .body(format!(
            "signed_request={}&login_proof={}&decision=cancel",
            sr, proof
        ))
        .dispatch()
        .await;
    assert_eq!(
        resp.status(),
        Status::Ok,
        "cancel renders a notice, not a redirect"
    );
    assert!(
        resp.headers().get_one("Location").is_none(),
        "cancel must not redirect to any callback"
    );
    let cancel_html = resp.into_string().await.unwrap();
    assert!(
        cancel_html.contains("cancelled"),
        "cancel shows a cancelled notice"
    );

    // 4. POST consent declining the required claim. The IDP preserves the
    //    user's choice and redirects; the RP/app decides whether missing
    //    required claims are fatal.
    let resp = client
        .post("/auth/consent")
        .header(ContentType::Form)
        .body(format!("signed_request={}&login_proof={}", sr, proof))
        .dispatch()
        .await;
    assert!(
        resp.status().class().is_redirection(),
        "declined required claim still completes at the IDP, got {:?}",
        resp.status()
    );
    let location = resp.headers().get_one("Location").unwrap_or("");
    assert!(
        location.contains("encrypted_token="),
        "callback carries the sealed token"
    );

    let grant = pool
        .find_active_consent_grant(&user.id, TEST_DOMAIN)
        .expect("query grant")
        .expect("a grant was stored");
    assert!(
        grant.claim_types.is_empty(),
        "grant records that no requested claims were shared"
    );

    // 5. A later signed claims-update request that asks for a new type must
    //    re-prompt instead of silently reusing the prior standing grant.
    let mut update_req = build_auth_request(
        TEST_DOMAIN,
        &format!("https://{}/cb", TEST_DOMAIN),
        "login-nonce-2",
        &signing.id,
        Some(ClaimRequest {
            required: vec![RequestedClaim {
                claim_type: "email".to_string(),
                datatype: "email".to_string(),
            }],
            optional: vec![
                RequestedClaim {
                    claim_type: "ssn".to_string(),
                    datatype: "text".to_string(),
                },
                RequestedClaim {
                    claim_type: "phone".to_string(),
                    datatype: "text".to_string(),
                },
            ],
        }),
        Some(AuthFlowContext {
            flow: "claims_update".to_string(),
            prior_session: Some("rp-session-1".to_string()),
            request_reason: Some("the app now supports phone recovery".to_string()),
        }),
    );
    update_req.relying_party_claims = None;
    let signed_update = sign_auth_request(
        &update_req,
        &signing.id,
        SigningAlgorithm::Ed25519,
        &sk_bytes,
    )
    .unwrap();
    let update_sr = signed_auth_request_to_url_param(&signed_update).unwrap();
    let (ct, b) = form(&format!(
        "username={}&password={}&signed_request={}",
        USERNAME,
        PASSWORD.replace(' ', "+"),
        update_sr
    ));
    let resp = client
        .post("/auth/authorize")
        .header(ct)
        .body(b)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let update_consent_html = resp.into_string().await.unwrap();
    assert!(
        update_consent_html.contains("This is an updated request"),
        "claims-update context is displayed"
    );
    assert!(
        update_consent_html.contains("phone"),
        "newly requested claim appears on the consent screen"
    );

    // 6. Replaying the same consent (login nonce already burned) is refused.
    let resp = client
        .post("/auth/consent")
        .header(ContentType::Form)
        .body(format!("signed_request={}&login_proof={}", sr, proof))
        .dispatch()
        .await;
    let body = resp.into_string().await.unwrap();
    assert!(
        body.contains("already been used"),
        "the login request is single-use"
    );
}
