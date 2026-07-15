//! End-to-end tests of the DNS-less local RP browser routes (Phase 6 of
//! dns-less-local-rp-design.md): `GET /auth/local-rp`, `POST /auth/local-rp`,
//! `POST /auth/local-rp/consent`. Driven over the real Rocket routing via the
//! in-process local client (no network socket), exactly like
//! `consent_http_e2e_test.rs` drives the DNS-pinned flow.
//!
//! The happy path additionally decrypts the callback with the local RP's own
//! encryption key (as the SDK would) and redeems the resulting ticket over
//! the real TCP dispatch seam (`linkkeys::tcp::dispatch_for_test`), so the
//! whole browser-to-ticket-redemption chain is exercised, not just the HTTP
//! surface.

mod common;

use common::data_factory::{
    create_auth_credential, create_local_rp_with_signing_key, create_user, DataMap,
};
use liblinkkeys::crypto::{self, AeadSuite};
use liblinkkeys::generated::types::DomainPublicKey;
use liblinkkeys::local_rp::{
    build_local_rp_descriptor, build_local_rp_login_request, sign_local_rp_descriptor,
    sign_local_rp_login_request, DEFAULT_CLOCK_SKEW_SECONDS,
};
use rocket::http::{ContentType, Status};
use rocket::local::asynchronous::Client;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

const TEST_DOMAIN: &str = "local-rp-web.test";
const PASSPHRASE: &[u8] = b"test-passphrase";
const USERNAME: &str = "alice";
const PASSWORD: &str = "correct horse battery staple";

/// Pull a hidden form field's value out of rendered HTML.
fn hidden_field(html: &str, name: &str) -> String {
    let marker = format!(r#"name="{}" value=""#, name);
    let start = html
        .find(&marker)
        .unwrap_or_else(|| panic!("field {} present in:\n{}", name, html))
        + marker.len();
    let rest = &html[start..];
    let end = rest.find('"').expect("closing quote");
    rest[..end].to_string()
}

fn form(body: String) -> (ContentType, String) {
    (ContentType::Form, body)
}

struct LocalRpFixture {
    signed_request: String,
    fingerprint: String,
    signing_pk: [u8; 32],
    signing_sk: Vec<u8>,
    enc_pk: [u8; 32],
    enc_sk: [u8; 32],
    callback_url: String,
}

/// Build and sign a fresh `SignedLocalRpLoginRequest`, url-param-encoded, for
/// a brand-new (never-before-seen) local RP identity. Callers can override
/// the callback URL, supported suites, and requested/required claims.
fn build_fixture(
    callback_url: &str,
    supported_suites: Vec<String>,
    requested_claims: Vec<String>,
    required_claims: Vec<String>,
) -> LocalRpFixture {
    let (vk, sk) = crypto::generate_ed25519_keypair();
    let pk_arr: [u8; 32] = vk.as_bytes().to_owned();
    let signing_sk = sk.to_bytes().to_vec();
    let (enc_pk_vec, enc_sk_vec) = crypto::generate_x25519_keypair();
    let enc_pk: [u8; 32] = enc_pk_vec.as_slice().try_into().unwrap();
    let enc_sk: [u8; 32] = enc_sk_vec.as_slice().try_into().unwrap();
    let fingerprint = crypto::fingerprint(&pk_arr);

    let now = chrono::Utc::now();
    let descriptor = build_local_rp_descriptor(
        "Test Jukebox",
        Some("jukebox.local"),
        &pk_arr,
        &enc_pk,
        supported_suites,
        &(now - chrono::Duration::minutes(1)).to_rfc3339(),
        &(now + chrono::Duration::days(3650)).to_rfc3339(),
    );
    let signed_descriptor = sign_local_rp_descriptor(&descriptor, &signing_sk).unwrap();

    let mut nonce = [0u8; 16];
    let mut state = [0u8; 16];
    rand::Rng::fill(&mut rand::thread_rng(), &mut nonce);
    rand::Rng::fill(&mut rand::thread_rng(), &mut state);

    let request = build_local_rp_login_request(
        signed_descriptor,
        callback_url,
        nonce.to_vec(),
        state.to_vec(),
        requested_claims,
        required_claims,
        &now.to_rfc3339(),
        &(now + chrono::Duration::minutes(5)).to_rfc3339(),
    );
    let signed_request = sign_local_rp_login_request(&request, &signing_sk).unwrap();
    let sr =
        liblinkkeys::encoding::signed_local_rp_login_request_to_url_param(&signed_request).unwrap();

    LocalRpFixture {
        signed_request: sr,
        fingerprint,
        signing_pk: pk_arr,
        signing_sk,
        enc_pk,
        enc_sk,
        callback_url: callback_url.to_string(),
    }
}

fn default_fixture(callback_url: &str) -> LocalRpFixture {
    build_fixture(
        callback_url,
        vec!["aes-256-gcm".to_string()],
        vec![
            "display_name".to_string(),
            "email".to_string(),
            "handle".to_string(),
        ],
        vec!["handle".to_string()],
    )
}

/// Seed a domain signing key (used to sign the outgoing callback payload)
/// and a user with a password plus the default claim set's three claims.
fn seed_idp_and_user(pool: &linkkeys::db::DbPool) -> linkkeys::db::models::User {
    let (vk, sk) = crypto::generate_ed25519_keypair();
    let pk = vk.as_bytes().to_vec();
    let sk_bytes = sk.to_bytes().to_vec();
    let enc_sk = crypto::encrypt_private_key(&sk_bytes, PASSPHRASE).unwrap();
    let fp = crypto::fingerprint(&pk);
    let expires = chrono::Utc::now() + chrono::Duration::days(365);
    pool.create_domain_key(&pk, &enc_sk, &fp, "ed25519", expires)
        .expect("signing key");

    let mut overrides = DataMap::new();
    overrides.insert("username".to_string(), serde_json::json!(USERNAME));
    let user = create_user(pool, &overrides);
    let hash = linkkeys::services::password::hash_for_storage(PASSWORD).unwrap();
    create_auth_credential(pool, &user.id, "password", &hash);

    for (ct, val) in [
        ("display_name", b"Alice Example".as_slice()),
        ("email", b"alice@example.com".as_slice()),
        ("handle", b"alice_h".as_slice()),
    ] {
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
    user
}

async fn build_client(pool: &linkkeys::db::DbPool) -> Client {
    let config = rocket::Config {
        secret_key: rocket::config::SecretKey::derive_from(&[9u8; 64]),
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

fn login_password_form(sr: &str) -> String {
    format!(
        "username={}&password={}&signed_request={}",
        USERNAME,
        PASSWORD.replace(' ', "+"),
        sr
    )
}

// ---------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------

#[rocket::async_test]
async fn approved_local_rp_happy_path_end_to_end() {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    std::env::set_var("ENABLE_PASSWORD_AUTH", "true");

    let pool = common::create_test_pool();
    pool.seed_default_policies().expect("seed policies");
    let user = seed_idp_and_user(&pool);

    let fx = default_fixture("http://127.0.0.1:9999/callback");

    // Pre-approve the fixture's exact fingerprint/keys.
    pool.insert_local_rp(
        &fx.fingerprint,
        fx.signing_pk.as_ref(),
        fx.enc_pk.as_ref(),
        "Test Jukebox",
        Some("jukebox.local"),
        linkkeys::db::local_rp::STATUS_APPROVED,
        None,
    )
    .expect("insert approved local rp");

    let client = build_client(&pool).await;

    // 1. GET renders the login form for an approved fingerprint.
    let resp = client
        .get(format!(
            "/auth/local-rp?signed_request={}",
            fx.signed_request
        ))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let body = resp.into_string().await.unwrap();
    assert!(body.contains("Test Jukebox"), "app name shown on login");

    // 2. POST correct credentials => consent screen (no prior grant yet).
    let (ct, b) = form(login_password_form(&fx.signed_request));
    let resp = client
        .post("/auth/local-rp")
        .header(ct)
        .body(b)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let consent_html = resp.into_string().await.unwrap();
    assert!(
        consent_html.contains("unverified") || consent_html.contains("Unverified"),
        "consent screen carries the unverified-app warning"
    );
    assert!(
        consent_html.contains(&fx.fingerprint[..16]),
        "short fingerprint is shown"
    );
    assert!(consent_html.contains("127.0.0.1"), "callback host is shown");
    let proof = hidden_field(&consent_html, "login_proof");

    // 3. POST consent granting everything => redirect carrying encrypted_token=.
    let (ct, b) = form(format!(
        "signed_request={}&login_proof={}&grant=display_name&grant=email&grant=handle",
        fx.signed_request, proof
    ));
    let resp = client
        .post("/auth/local-rp/consent")
        .header(ct)
        .body(b)
        .dispatch()
        .await;
    assert!(
        resp.status().class().is_redirection(),
        "consent completes with a redirect, got {:?}",
        resp.status()
    );
    let location = resp
        .headers()
        .get_one("Location")
        .expect("redirect Location header")
        .to_string();
    assert!(
        location.starts_with(&fx.callback_url),
        "redirect targets the callback URL"
    );
    assert!(
        location.contains("encrypted_token="),
        "callback carries the sealed token"
    );

    // 4. Decrypt the callback exactly as the SDK would: open the sealed box
    //    with the local RP's own encryption key, verify the domain signature,
    //    cross-check the header against the payload, then check every field.
    let token = location.split("encrypted_token=").nth(1).unwrap();
    let encrypted = liblinkkeys::encoding::local_rp_encrypted_callback_from_url_param(token)
        .expect("decode LocalRpEncryptedCallback");
    let (header, signed_payload) = liblinkkeys::local_rp::open_local_rp_callback(
        &encrypted,
        &fx.enc_sk,
        &[AeadSuite::Aes256Gcm],
    )
    .expect("open callback with the RP's encryption key");

    let domain_keys = pool.list_active_domain_keys().unwrap();
    let csil_keys: Vec<DomainPublicKey> = domain_keys.iter().map(Into::into).collect();
    let now = chrono::Utc::now();
    let payload = liblinkkeys::local_rp::verify_local_rp_callback_payload(
        &signed_payload,
        &csil_keys,
        now,
        DEFAULT_CLOCK_SKEW_SECONDS,
    )
    .expect("callback payload signature verifies against domain keys");
    liblinkkeys::local_rp::check_callback_header_matches_payload(&header, &payload)
        .expect("header matches payload");

    assert_eq!(payload.user_id, user.id);
    assert_eq!(payload.user_domain, TEST_DOMAIN);
    assert_eq!(payload.audience_fingerprint, fx.fingerprint);
    assert_eq!(payload.callback_url, fx.callback_url);

    // 5. Redeem the ticket over the real TCP dispatch seam.
    let redemption_request = liblinkkeys::local_rp::build_local_rp_ticket_redemption_request(
        payload.claim_ticket.clone(),
        &fx.fingerprint,
        &now.to_rfc3339(),
    );
    let signed_redemption = liblinkkeys::local_rp::sign_local_rp_ticket_redemption_request(
        &redemption_request,
        &fx.signing_sk,
    )
    .unwrap();
    let redemption_bytes = liblinkkeys::generated::encode_signed_local_rp_ticket_redemption_request(
        &signed_redemption,
    );
    let (status, resp_bytes) = linkkeys::tcp::dispatch_for_test(
        "LocalRp",
        "redeem-claim-ticket",
        redemption_bytes,
        &pool,
        None,
    );
    assert_eq!(status, 0, "ticket redemption should succeed");
    let redeemed = liblinkkeys::generated::decode_local_rp_ticket_redemption_response(&resp_bytes)
        .expect("decode LocalRpTicketRedemptionResponse");
    assert_eq!(redeemed.user_id, user.id);
    assert_eq!(redeemed.user_domain, TEST_DOMAIN);
    for ct in ["display_name", "email", "handle"] {
        assert!(
            redeemed.claims.iter().any(|c| c.claim_type == ct),
            "granted claim {ct} present in redemption"
        );
    }

    // 6. Replaying the ORIGINAL signed_request (a prior grant now covers it,
    //    so it takes the finalize shortcut directly) must fail: the nonce was
    //    already burned.
    let (ct, b) = form(login_password_form(&fx.signed_request));
    let resp = client
        .post("/auth/local-rp")
        .header(ct)
        .body(b)
        .dispatch()
        .await;
    let body = resp.into_string().await.unwrap();
    assert!(
        body.contains("already been used"),
        "replayed signed_request must be rejected, got:\n{body}"
    );
}

// ---------------------------------------------------------------------
// Pending path
// ---------------------------------------------------------------------

#[rocket::async_test]
async fn unknown_local_rp_under_admin_approval_goes_pending() {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    std::env::set_var("ENABLE_PASSWORD_AUTH", "true");

    let pool = common::create_test_pool();
    pool.seed_default_policies().expect("seed policies");
    seed_idp_and_user(&pool);

    let fx = default_fixture("http://127.0.0.1:9999/callback");
    assert!(pool.find_local_rp(&fx.fingerprint).unwrap().is_none());

    let client = build_client(&pool).await;
    let (ct, b) = form(login_password_form(&fx.signed_request));
    let resp = client
        .post("/auth/local-rp")
        .header(ct)
        .body(b)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    assert!(
        resp.headers().get_one("Location").is_none(),
        "no redirect for a pending RP"
    );
    let body = resp.into_string().await.unwrap();
    assert!(
        body.contains("Waiting for approval") || body.contains("pending"),
        "unknown RP shows a pending notice, got:\n{body}"
    );

    let row = pool
        .find_local_rp(&fx.fingerprint)
        .unwrap()
        .expect("a pending row was created");
    assert_eq!(row.status, "pending");
}

// ---------------------------------------------------------------------
// Denied / revoked
// ---------------------------------------------------------------------

async fn assert_rejected_no_redirect(status: &str) {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    std::env::set_var("ENABLE_PASSWORD_AUTH", "true");

    let pool = common::create_test_pool();
    pool.seed_default_policies().expect("seed policies");
    seed_idp_and_user(&pool);

    let mut overrides = DataMap::new();
    overrides.insert("status".to_string(), serde_json::json!(status));
    let (rp, signing_sk) = create_local_rp_with_signing_key(&pool, &overrides);

    // Build a request whose descriptor carries the SAME keys as the stored
    // (denied/revoked) row, so its fingerprint matches exactly.
    let signing_pk_arr: [u8; 32] = rp.signing_public_key.as_slice().try_into().unwrap();
    let enc_pk_arr: [u8; 32] = rp.encryption_public_key.as_slice().try_into().unwrap();
    let now = chrono::Utc::now();
    let descriptor = build_local_rp_descriptor(
        "Rejected App",
        None,
        &signing_pk_arr,
        &enc_pk_arr,
        vec!["aes-256-gcm".to_string()],
        &(now - chrono::Duration::minutes(1)).to_rfc3339(),
        &(now + chrono::Duration::days(3650)).to_rfc3339(),
    );
    let signed_descriptor = sign_local_rp_descriptor(&descriptor, &signing_sk).unwrap();
    let request = build_local_rp_login_request(
        signed_descriptor,
        "http://127.0.0.1:9999/callback",
        b"nonce".to_vec(),
        b"state".to_vec(),
        vec!["handle".to_string()],
        vec!["handle".to_string()],
        &now.to_rfc3339(),
        &(now + chrono::Duration::minutes(5)).to_rfc3339(),
    );
    let signed_request = sign_local_rp_login_request(&request, &signing_sk).unwrap();
    let sr =
        liblinkkeys::encoding::signed_local_rp_login_request_to_url_param(&signed_request).unwrap();

    let client = build_client(&pool).await;

    // GET rejects before ever asking for a password.
    let resp = client
        .get(format!("/auth/local-rp?signed_request={}", sr))
        .dispatch()
        .await;
    let body = resp.into_string().await.unwrap();
    assert!(
        !body.contains("name=\"password\""),
        "no login form for a {status} RP"
    );

    // A POST attempt (in case the GET check were ever bypassed) also rejects
    // with no redirect to the callback URL.
    let (ct, b) = form(login_password_form(&sr));
    let resp = client
        .post("/auth/local-rp")
        .header(ct)
        .body(b)
        .dispatch()
        .await;
    assert!(
        resp.headers().get_one("Location").is_none(),
        "a {status} RP must never be redirected to its callback URL"
    );
}

#[rocket::async_test]
async fn denied_local_rp_rejected_no_redirect() {
    assert_rejected_no_redirect("denied").await;
}

#[rocket::async_test]
async fn revoked_local_rp_rejected_no_redirect() {
    assert_rejected_no_redirect("revoked").await;
}

// ---------------------------------------------------------------------
// Disabled policy
// ---------------------------------------------------------------------

#[rocket::async_test]
async fn disabled_policy_rejects_before_login() {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    std::env::set_var("ENABLE_PASSWORD_AUTH", "true");

    let pool = common::create_test_pool();
    pool.seed_default_policies().expect("seed policies");
    seed_idp_and_user(&pool);
    pool.set_local_rp_domain_policy(linkkeys::db::local_rp::POLICY_DISABLED)
        .unwrap();

    let fx = default_fixture("http://127.0.0.1:9999/callback");
    let client = build_client(&pool).await;

    let resp = client
        .get(format!(
            "/auth/local-rp?signed_request={}",
            fx.signed_request
        ))
        .dispatch()
        .await;
    let body = resp.into_string().await.unwrap();
    assert!(
        !body.contains("name=\"password\""),
        "no login form when disabled"
    );
    assert!(
        body.contains("does not allow") || body.contains("not allow"),
        "disabled-policy message shown, got:\n{body}"
    );
}

/// LOW fix: the domain's admission policy is re-checked at consent submit,
/// not just at login-render time — mirroring the per-fingerprint status
/// recheck a few lines below it in `auth_local_rp_consent_post`. An admin
/// disabling local-RP mode between rendering consent and the user submitting
/// it must still block the login.
#[rocket::async_test]
async fn disabled_policy_between_consent_render_and_submit_rejected() {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    std::env::set_var("ENABLE_PASSWORD_AUTH", "true");

    let pool = common::create_test_pool();
    pool.seed_default_policies().expect("seed policies");
    seed_idp_and_user(&pool);

    let fx = default_fixture("http://127.0.0.1:9999/callback");
    pool.insert_local_rp(
        &fx.fingerprint,
        fx.signing_pk.as_ref(),
        fx.enc_pk.as_ref(),
        "Test Jukebox",
        Some("jukebox.local"),
        linkkeys::db::local_rp::STATUS_APPROVED,
        None,
    )
    .expect("insert approved local rp");

    let client = build_client(&pool).await;

    // Render consent while the policy still allows local-RP mode.
    let (ct, b) = form(login_password_form(&fx.signed_request));
    let resp = client
        .post("/auth/local-rp")
        .header(ct)
        .body(b)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let consent_html = resp.into_string().await.unwrap();
    let proof = hidden_field(&consent_html, "login_proof");

    // An admin disables local-RP mode domain-wide before the user submits.
    pool.set_local_rp_domain_policy(linkkeys::db::local_rp::POLICY_DISABLED)
        .unwrap();

    let (ct, b) = form(format!(
        "signed_request={}&login_proof={}&grant=display_name&grant=email&grant=handle",
        fx.signed_request, proof
    ));
    let resp = client
        .post("/auth/local-rp/consent")
        .header(ct)
        .body(b)
        .dispatch()
        .await;
    assert!(
        resp.headers().get_one("Location").is_none(),
        "a disabled-policy domain must never redirect to the callback URL"
    );
    let body = resp.into_string().await.unwrap();
    assert!(
        body.contains("does not allow") || body.contains("not allow"),
        "disabled-policy message shown, got:\n{body}"
    );
}

// ---------------------------------------------------------------------
// Bad callback scheme
// ---------------------------------------------------------------------

async fn assert_bad_scheme_rejected(callback_url: &str) {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    std::env::set_var("ENABLE_PASSWORD_AUTH", "true");

    let pool = common::create_test_pool();
    pool.seed_default_policies().expect("seed policies");
    seed_idp_and_user(&pool);

    let fx = default_fixture(callback_url);
    let client = build_client(&pool).await;

    let resp = client
        .get(format!(
            "/auth/local-rp?signed_request={}",
            fx.signed_request
        ))
        .dispatch()
        .await;
    let body = resp.into_string().await.unwrap();
    assert!(
        !body.contains("name=\"password\""),
        "no login form for scheme {callback_url}"
    );
    assert!(
        body.contains("isn't a web page") || body.contains("web page"),
        "friendly bad-scheme message shown, got:\n{body}"
    );
}

#[rocket::async_test]
async fn javascript_scheme_callback_rejected() {
    assert_bad_scheme_rejected("javascript:alert(1)").await;
}

#[rocket::async_test]
async fn custom_app_scheme_callback_rejected() {
    assert_bad_scheme_rejected("myapp://callback").await;
}

// ---------------------------------------------------------------------
// No common AEAD suite
// ---------------------------------------------------------------------

#[rocket::async_test]
async fn no_common_suite_rejected() {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    std::env::set_var("ENABLE_PASSWORD_AUTH", "true");

    let pool = common::create_test_pool();
    pool.seed_default_policies().expect("seed policies");
    seed_idp_and_user(&pool);

    let fx = build_fixture(
        "http://127.0.0.1:9999/callback",
        vec!["made-up-suite-nobody-supports".to_string()],
        vec!["handle".to_string()],
        vec!["handle".to_string()],
    );
    let client = build_client(&pool).await;

    let resp = client
        .get(format!(
            "/auth/local-rp?signed_request={}",
            fx.signed_request
        ))
        .dispatch()
        .await;
    let body = resp.into_string().await.unwrap();
    assert!(!body.contains("name=\"password\""), "no login form");
    assert!(
        body.contains("could not agree") || body.contains("agree on a way"),
        "no-common-suite message shown, got:\n{body}"
    );
}

// ---------------------------------------------------------------------
// Required claim missing
// ---------------------------------------------------------------------

#[rocket::async_test]
async fn declined_required_claim_is_a_hard_error() {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    std::env::set_var("ENABLE_PASSWORD_AUTH", "true");

    let pool = common::create_test_pool();
    pool.seed_default_policies().expect("seed policies");
    seed_idp_and_user(&pool);

    // "ssn" is required but the user has no such claim and will not grant it.
    let fx = build_fixture(
        "http://127.0.0.1:9999/callback",
        vec!["aes-256-gcm".to_string()],
        vec!["ssn".to_string()],
        vec!["ssn".to_string()],
    );

    pool.insert_local_rp(
        &fx.fingerprint,
        fx.signing_pk.as_ref(),
        fx.enc_pk.as_ref(),
        "Needs SSN",
        None,
        linkkeys::db::local_rp::STATUS_APPROVED,
        None,
    )
    .expect("insert approved local rp");

    let client = build_client(&pool).await;
    let (ct, b) = form(login_password_form(&fx.signed_request));
    let resp = client
        .post("/auth/local-rp")
        .header(ct)
        .body(b)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let consent_html = resp.into_string().await.unwrap();
    let proof = hidden_field(&consent_html, "login_proof");

    // Submit consent WITHOUT granting the required "ssn" claim.
    let (ct, b) = form(format!(
        "signed_request={}&login_proof={}",
        fx.signed_request, proof
    ));
    let resp = client
        .post("/auth/local-rp/consent")
        .header(ct)
        .body(b)
        .dispatch()
        .await;
    assert!(
        resp.headers().get_one("Location").is_none(),
        "a missing required claim must not redirect to the callback URL"
    );
    let body = resp.into_string().await.unwrap();
    assert!(
        body.contains("did not share") || body.contains("needs information"),
        "required-claim-missing message shown, got:\n{body}"
    );
}
