//! End-to-end tests of the DNS-less local RP sign-in through the browser app
//! (dns-less-local-rp-design.md): `GET /auth/local-rp` hands the request to
//! the app, which calls `BrowserAuthorization/inspect-local-rp` and
//! `complete-local-rp`. Driven over the real Rocket routing via the
//! in-process local client (no network socket), like
//! `consent_http_e2e_test.rs` drives the DNS-pinned flow.
//!
//! The happy path also decrypts the callback with the local RP's own
//! encryption key (as the SDK would) and redeems the resulting ticket over the
//! real TCP dispatch seam (`linkkeys::tcp::dispatch_for_test`), so the whole
//! browser-to-ticket-redemption chain is exercised.

mod common;

use common::data_factory::{
    create_app_access_policy, create_auth_credential, create_local_rp_with_signing_key,
    create_user, DataMap,
};
use csilgen_transport::rpc::{RpcRequest, RpcResponse};
use csilgen_transport::Status as RpcStatus;
use liblinkkeys::crypto::{self, AeadSuite};
use liblinkkeys::generated::types::{
    BrowserLocalRpCompleteRequest, BrowserLocalRpInspectRequest, BrowserLocalRpInspectResponse,
    DomainPublicKey, SessionPasswordLoginRequest,
};
use liblinkkeys::local_rp::{
    build_local_rp_descriptor, build_local_rp_login_request, sign_local_rp_descriptor,
    sign_local_rp_login_request, DEFAULT_CLOCK_SKEW_SECONDS,
};
use rocket::http::{ContentType, Header, Status};
use rocket::local::asynchronous::Client;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, LazyLock};

const TEST_DOMAIN: &str = "local-rp-web.test";
const PASSPHRASE: &[u8] = b"test-passphrase";
const USERNAME: &str = "alice";
const PASSWORD: &str = "correct horse battery staple";
static PASSWORD_HASH: LazyLock<String> =
    LazyLock::new(|| linkkeys::services::password::hash_for_storage(PASSWORD).unwrap());

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
    // A username per test: the login rate limit is per username and shared
    // by every test in this process.
    let username = format!(
        "{USERNAME}-{}",
        &uuid::Uuid::now_v7().simple().to_string()[20..]
    );
    overrides.insert("username".to_string(), serde_json::json!(username));
    let user = create_user(pool, &overrides);
    create_auth_credential(pool, &user.id, "password", &PASSWORD_HASH);

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

/// `GET /auth/local-rp`: always a redirect, either into the browser app or to
/// its error page. Returns the Location.
async fn entry(client: &Client, query: &str) -> String {
    let resp = client
        .get(format!("/auth/local-rp?{query}"))
        .dispatch()
        .await;
    assert_eq!(
        resp.status(),
        Status::Found,
        "the entry link always redirects"
    );
    resp.headers()
        .get_one("Location")
        .expect("Location header")
        .to_string()
}

async fn rpc(client: &Client, service: &str, op: &str, payload: Vec<u8>) -> RpcResponse {
    let resp = client
        .post("/csil/v1/rpc")
        .header(ContentType::new("application", "cbor"))
        .header(Header::new("Host", TEST_DOMAIN))
        .header(Header::new("Origin", format!("https://{TEST_DOMAIN}")))
        .body(RpcRequest::new(service, op, payload).encode().unwrap())
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    RpcResponse::decode(&resp.into_bytes().await.unwrap()).unwrap()
}

/// Password checks are capped process-wide (`MAX_ACTIVE_PASSWORD_WORK`), and
/// the tests in this file run in parallel, so they sign in one at a time.
static SIGN_IN: rocket::tokio::sync::Mutex<()> = rocket::tokio::sync::Mutex::const_new(());

async fn sign_in(client: &Client, user: &linkkeys::db::models::User) {
    let _one_at_a_time = SIGN_IN.lock().await;
    let resp = rpc(
        client,
        "Session",
        "login-password",
        liblinkkeys::generated::encode_session_password_login_request(
            &SessionPasswordLoginRequest {
                username: format!("{}@{TEST_DOMAIN}", user.username),
                password: PASSWORD.to_string(),
            },
        ),
    )
    .await;
    assert_eq!(
        resp.status,
        RpcStatus::Ok,
        "sign-in succeeds: {:?}",
        resp.error
    );
}

async fn inspect(client: &Client, sr: &str) -> RpcResponse {
    rpc(
        client,
        "BrowserAuthorization",
        "inspect-local-rp",
        liblinkkeys::generated::encode_browser_local_rp_inspect_request(
            &BrowserLocalRpInspectRequest {
                signed_request: sr.to_string(),
            },
        ),
    )
    .await
}

fn inspected(resp: &RpcResponse) -> BrowserLocalRpInspectResponse {
    assert_eq!(
        resp.status,
        RpcStatus::Ok,
        "inspect failed: {:?}",
        resp.error
    );
    liblinkkeys::generated::decode_browser_local_rp_inspect_response(&resp.payload).unwrap()
}

async fn complete(client: &Client, sr: &str, claims: &[&str], standing: bool) -> RpcResponse {
    rpc(
        client,
        "BrowserAuthorization",
        "complete-local-rp",
        liblinkkeys::generated::encode_browser_local_rp_complete_request(
            &BrowserLocalRpCompleteRequest {
                signed_request: sr.to_string(),
                authorized_claims: claims.iter().map(|c| c.to_string()).collect(),
                claim_types_to_set: Vec::new(),
                claim_values_to_set: Vec::new(),
                use_standing_grant: standing.then_some(true),
            },
        ),
    )
    .await
}

/// A refused call: not OK, no redirect URL, and the given reason code.
fn assert_refused(resp: &RpcResponse, reason: &str) {
    assert_ne!(resp.status, RpcStatus::Ok, "expected a refusal ({reason})");
    assert_eq!(resp.error.as_deref(), Some(reason));
}

fn redirect_url(resp: &RpcResponse) -> String {
    assert_eq!(
        resp.status,
        RpcStatus::Ok,
        "complete failed: {:?}",
        resp.error
    );
    liblinkkeys::generated::decode_browser_local_rp_complete_response(&resp.payload)
        .unwrap()
        .redirect_url
}

fn approve(pool: &linkkeys::db::DbPool, fx: &LocalRpFixture, name: &str) {
    pool.insert_local_rp(
        &fx.fingerprint,
        fx.signing_pk.as_ref(),
        fx.enc_pk.as_ref(),
        name,
        Some("jukebox.local"),
        linkkeys::db::local_rp::STATUS_APPROVED,
        None,
    )
    .expect("insert approved local rp");
}

fn setup() -> linkkeys::db::DbPool {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    std::env::set_var("ENABLE_PASSWORD_AUTH", "true");
    let pool = common::create_test_pool();
    pool.seed_default_policies().expect("seed policies");
    pool
}

/// Re-sign the fixture's request with a fresh nonce, state, and window.
fn resigned(
    fx: &LocalRpFixture,
    flow_context: Option<liblinkkeys::generated::types::AuthFlowContext>,
) -> String {
    let original =
        liblinkkeys::encoding::signed_local_rp_login_request_from_url_param(&fx.signed_request)
            .unwrap();
    let mut request =
        liblinkkeys::generated::decode_local_rp_login_request(&original.request).unwrap();
    let now = chrono::Utc::now();
    request.nonce = rand::random::<[u8; 16]>().to_vec();
    request.state = rand::random::<[u8; 16]>().to_vec();
    request.issued_at = now.to_rfc3339();
    request.expires_at = (now + chrono::Duration::minutes(5)).to_rfc3339();
    request.flow_context = flow_context;
    let signed = sign_local_rp_login_request(&request, &fx.signing_sk).unwrap();
    liblinkkeys::encoding::signed_local_rp_login_request_to_url_param(&signed).unwrap()
}

// ---------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------

#[rocket::async_test]
async fn approved_local_rp_happy_path_end_to_end() {
    let pool = setup();
    let user = seed_idp_and_user(&pool);
    let fx = default_fixture("http://127.0.0.1:9999/callback");
    approve(&pool, &fx, "Test Jukebox");
    let client = build_client(&pool).await;

    // 1. The entry link hands the request to the app in the fragment and
    //    keeps the username hint.
    let location = entry(
        &client,
        &format!("signed_request={}&username=Alice%2Bwork", fx.signed_request),
    )
    .await;
    assert!(location.starts_with("/app/local-rp?username=Alice%2Bwork#request="));
    assert!(location.ends_with(&urlencoding::encode(&fx.signed_request).into_owned()));

    // 2. Without a browser session the app cannot inspect the request.
    assert_ne!(
        inspect(&client, &fx.signed_request).await.status,
        RpcStatus::Ok
    );

    // 3. Signed in: the consent screen data, with the unverified app's
    //    identity and callback host. No standing grant yet.
    sign_in(&client, &user).await;
    let screen = inspected(&inspect(&client, &fx.signed_request).await);
    assert_eq!(screen.admission, "consent");
    assert_eq!(screen.app_name, "Test Jukebox");
    assert_eq!(screen.fingerprint, fx.fingerprint);
    assert_eq!(screen.callback_host, "127.0.0.1:9999");
    assert!(screen.first_seen_at.is_some());
    assert_eq!(screen.claims.len(), 3);
    assert_eq!(screen.already_consented, None);

    // 4. Consent to everything: the redirect carries the sealed token.
    let location = redirect_url(
        &complete(
            &client,
            &fx.signed_request,
            &["display_name", "email", "handle"],
            false,
        )
        .await,
    );
    assert!(location.starts_with(&fx.callback_url));
    assert!(location.contains("encrypted_token="));

    // 5. Decrypt the callback exactly as the SDK would: open the sealed box
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

    // 6. Redeem the ticket over the real TCP dispatch seam.
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
    let (status, resp_bytes) = linkkeys::tcp::dispatch_for_test(
        "LocalRp",
        "redeem-claim-ticket",
        liblinkkeys::generated::encode_signed_local_rp_ticket_redemption_request(
            &signed_redemption,
        ),
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

    // 7. An explicit claims update always reopens the choices.
    let update = resigned(
        &fx,
        Some(liblinkkeys::generated::types::AuthFlowContext {
            flow: "claims_update".to_string(),
            prior_session: Some("local-session-1".to_string()),
            request_reason: Some("update sharing".to_string()),
        }),
    );
    let screen = inspected(&inspect(&client, &update).await);
    assert_eq!(screen.already_consented, None);
    assert_eq!(screen.request_reason.as_deref(), Some("update sharing"));

    // 8. A normal fresh request is covered by the standing grant and
    //    completes without another consent screen.
    let fresh = resigned(&fx, None);
    let screen = inspected(&inspect(&client, &fresh).await);
    assert_eq!(screen.already_consented, Some(true));
    assert!(redirect_url(&complete(&client, &fresh, &[], true).await).contains("encrypted_token="));

    // 9. Replaying the original request fails: its nonce is burned.
    assert_refused(
        &complete(&client, &fx.signed_request, &[], true).await,
        "replayed",
    );
}

// ---------------------------------------------------------------------
// Pending path
// ---------------------------------------------------------------------

#[rocket::async_test]
async fn unknown_local_rp_under_admin_approval_goes_pending() {
    let pool = setup();
    let user = seed_idp_and_user(&pool);
    let fx = default_fixture("http://127.0.0.1:9999/callback");
    assert!(pool.find_local_rp(&fx.fingerprint).unwrap().is_none());
    let client = build_client(&pool).await;

    assert!(
        entry(&client, &format!("signed_request={}", fx.signed_request))
            .await
            .starts_with("/app/local-rp#request=")
    );
    sign_in(&client, &user).await;
    let screen = inspected(&inspect(&client, &fx.signed_request).await);
    assert_eq!(screen.admission, "pending");
    assert!(
        screen.claims.is_empty(),
        "a pending app is shown nothing else"
    );

    let row = pool
        .find_local_rp(&fx.fingerprint)
        .unwrap()
        .expect("a pending row was created");
    assert_eq!(row.status, "pending");
    assert_refused(
        &complete(&client, &fx.signed_request, &["handle"], false).await,
        "rejected",
    );
}

// ---------------------------------------------------------------------
// Denied / revoked
// ---------------------------------------------------------------------

async fn assert_rejected_no_redirect(status: &str) {
    let pool = setup();
    let user = seed_idp_and_user(&pool);

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

    // The entry link refuses before the person is asked to sign in.
    assert_eq!(
        entry(&client, &format!("signed_request={sr}")).await,
        "/app/error?reason=rejected",
        "a {status} RP is refused at the entry link"
    );

    // Calling the app operations directly (in case the entry check were ever
    // bypassed) also refuses, with no redirect URL.
    sign_in(&client, &user).await;
    assert_refused(&inspect(&client, &sr).await, "rejected");
    assert_refused(
        &complete(&client, &sr, &["handle"], false).await,
        "rejected",
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
    let pool = setup();
    seed_idp_and_user(&pool);
    pool.set_local_rp_domain_policy(linkkeys::db::local_rp::POLICY_DISABLED)
        .unwrap();
    let fx = default_fixture("http://127.0.0.1:9999/callback");
    let client = build_client(&pool).await;
    assert_eq!(
        entry(&client, &format!("signed_request={}", fx.signed_request)).await,
        "/app/error?reason=policy_disabled"
    );
}

/// The domain's admission policy is checked again when consent completes, not
/// only when the consent screen loads. An admin disabling local-RP mode in
/// between must still block the sign-in.
#[rocket::async_test]
async fn disabled_policy_between_consent_render_and_submit_rejected() {
    let pool = setup();
    let user = seed_idp_and_user(&pool);
    let fx = default_fixture("http://127.0.0.1:9999/callback");
    approve(&pool, &fx, "Test Jukebox");
    let client = build_client(&pool).await;

    sign_in(&client, &user).await;
    assert_eq!(
        inspected(&inspect(&client, &fx.signed_request).await).admission,
        "consent"
    );
    pool.set_local_rp_domain_policy(linkkeys::db::local_rp::POLICY_DISABLED)
        .unwrap();
    assert_refused(
        &complete(
            &client,
            &fx.signed_request,
            &["display_name", "email", "handle"],
            false,
        )
        .await,
        "policy_disabled",
    );
}

// ---------------------------------------------------------------------
// App access policies
// ---------------------------------------------------------------------

#[rocket::async_test]
async fn allow_list_policy_blocks_local_apps_but_deny_list_does_not() {
    let pool = setup();
    let user = seed_idp_and_user(&pool);
    let fx = default_fixture("http://127.0.0.1:9999/callback");
    approve(&pool, &fx, "Test Jukebox");
    let client = build_client(&pool).await;
    sign_in(&client, &user).await;

    // A local app has no domain, so a deny list never matches it.
    let mut deny_all = DataMap::new();
    deny_all.insert("patterns".to_string(), serde_json::json!(["*"]));
    create_app_access_policy(&pool, &deny_all);
    assert_eq!(
        inspected(&inspect(&client, &fx.signed_request).await).admission,
        "consent"
    );

    // An allow list blocks it: no allow pattern can match it.
    let mut allow_only = DataMap::new();
    allow_only.insert("mode".to_string(), serde_json::json!("allow"));
    allow_only.insert("patterns".to_string(), serde_json::json!(["only.example"]));
    allow_only.insert("message".to_string(), serde_json::json!("Demo account."));
    allow_only.insert(
        "targets".to_string(),
        serde_json::json!([{ "kind": "user", "user_id": user.id }]),
    );
    create_app_access_policy(&pool, &allow_only);
    let screen = inspected(&inspect(&client, &fx.signed_request).await);
    assert_eq!(screen.admission, "blocked");
    let denial = screen.access_denied.expect("the denial");
    assert_eq!(denial.domain, None);
    assert_eq!(denial.messages, vec!["Demo account.".to_string()]);
    assert!(screen.claims.is_empty());

    let refused = complete(
        &client,
        &fx.signed_request,
        &["display_name", "email", "handle"],
        false,
    )
    .await;
    assert_eq!(refused.status, RpcStatus::Forbidden);
    assert!(
        refused
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("Demo account."),
        "{:?}",
        refused.error
    );

    // A blocked account does not register an unknown app.
    let unknown = default_fixture("http://127.0.0.1:9998/callback");
    let screen = inspected(&inspect(&client, &unknown.signed_request).await);
    assert_eq!(screen.admission, "blocked");
    assert!(pool.find_local_rp(&unknown.fingerprint).unwrap().is_none());
}

// ---------------------------------------------------------------------
// Bad callback scheme
// ---------------------------------------------------------------------

async fn assert_bad_scheme_rejected(callback_url: &str) {
    let pool = setup();
    seed_idp_and_user(&pool);
    let fx = default_fixture(callback_url);
    let client = build_client(&pool).await;
    assert_eq!(
        entry(&client, &format!("signed_request={}", fx.signed_request)).await,
        "/app/error?reason=bad_scheme",
        "scheme {callback_url} is refused"
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
    let pool = setup();
    seed_idp_and_user(&pool);
    let fx = build_fixture(
        "http://127.0.0.1:9999/callback",
        vec!["made-up-suite-nobody-supports".to_string()],
        vec!["handle".to_string()],
        vec!["handle".to_string()],
    );
    let client = build_client(&pool).await;
    assert_eq!(
        entry(&client, &format!("signed_request={}", fx.signed_request)).await,
        "/app/error?reason=no_common_suite"
    );
}

#[rocket::async_test]
async fn a_missing_or_damaged_request_goes_to_the_error_page() {
    let pool = setup();
    let client = build_client(&pool).await;
    let resp = client.get("/auth/local-rp").dispatch().await;
    assert_eq!(
        resp.headers().get_one("Location"),
        Some("/app/error?reason=malformed")
    );
    assert_eq!(
        entry(&client, "signed_request=not-a-request").await,
        "/app/error?reason=malformed"
    );
}

// ---------------------------------------------------------------------
// Required claim missing
// ---------------------------------------------------------------------

#[rocket::async_test]
async fn declined_required_claim_is_a_hard_error() {
    let pool = setup();
    let user = seed_idp_and_user(&pool);

    // "ssn" is required but the user has no such claim and will not grant it.
    let fx = build_fixture(
        "http://127.0.0.1:9999/callback",
        vec!["aes-256-gcm".to_string()],
        vec!["ssn".to_string()],
        vec!["ssn".to_string()],
    );
    approve(&pool, &fx, "Needs SSN");
    let client = build_client(&pool).await;
    sign_in(&client, &user).await;
    assert_eq!(
        inspected(&inspect(&client, &fx.signed_request).await).admission,
        "consent"
    );
    assert_refused(
        &complete(&client, &fx.signed_request, &[], false).await,
        "required_claim_missing",
    );
}

// ---------------------------------------------------------------------
// Newly requested claim
// ---------------------------------------------------------------------

/// Re-sign the fixture's request with a fresh nonce and a new requested
/// claim list (the app's claim list grew).
fn resigned_with_claims(fx: &LocalRpFixture, requested_claims: &[&str]) -> String {
    let original =
        liblinkkeys::encoding::signed_local_rp_login_request_from_url_param(&fx.signed_request)
            .unwrap();
    let mut request =
        liblinkkeys::generated::decode_local_rp_login_request(&original.request).unwrap();
    let now = chrono::Utc::now();
    request.nonce = rand::random::<[u8; 16]>().to_vec();
    request.state = rand::random::<[u8; 16]>().to_vec();
    request.issued_at = now.to_rfc3339();
    request.expires_at = (now + chrono::Duration::minutes(5)).to_rfc3339();
    request.requested_claims = requested_claims.iter().map(|c| c.to_string()).collect();
    let signed = sign_local_rp_login_request(&request, &fx.signing_sk).unwrap();
    liblinkkeys::encoding::signed_local_rp_login_request_to_url_param(&signed).unwrap()
}

/// An optional claim the local app adds after the first consent reopens
/// consent once, marked new. Declining it is remembered.
#[rocket::async_test]
async fn new_optional_claim_reopens_local_rp_consent_once() {
    let pool = setup();
    let user = seed_idp_and_user(&pool);
    let fx = build_fixture(
        "http://127.0.0.1:9999/callback",
        vec!["aes-256-gcm".to_string()],
        vec!["handle".to_string()],
        vec!["handle".to_string()],
    );
    approve(&pool, &fx, "Test Jukebox");
    let client = build_client(&pool).await;
    sign_in(&client, &user).await;

    // First consent: nothing is marked new.
    let screen = inspected(&inspect(&client, &fx.signed_request).await);
    assert!(screen.claims.iter().all(|c| c.newly_requested.is_none()));
    redirect_url(&complete(&client, &fx.signed_request, &["handle"], false).await);

    // The app now also asks for optional display_name.
    let grown = resigned_with_claims(&fx, &["handle", "display_name"]);
    let screen = inspected(&inspect(&client, &grown).await);
    assert_eq!(
        screen.already_consented, None,
        "an unseen optional claim must reopen consent"
    );
    let flag = |claim_type: &str| {
        screen
            .claims
            .iter()
            .find(|c| c.claim_type == claim_type)
            .expect("row present")
            .newly_requested
    };
    assert_eq!(flag("display_name"), Some(true));
    assert_eq!(flag("handle"), None);
    assert_ne!(
        complete(&client, &grown, &[], true).await.status,
        RpcStatus::Ok,
        "standing completion must refuse while a claim is new"
    );

    // Decline display_name; the next sign-in is silent.
    redirect_url(&complete(&client, &grown, &["handle"], false).await);
    let again = resigned_with_claims(&fx, &["handle", "display_name"]);
    let screen = inspected(&inspect(&client, &again).await);
    assert_eq!(
        screen.already_consented,
        Some(true),
        "a declined claim is not new"
    );
    assert_eq!(screen.authorized_claims, Some(vec!["handle".to_string()]));
}
