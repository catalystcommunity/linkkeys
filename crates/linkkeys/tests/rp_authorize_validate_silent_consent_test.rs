//! Silent re-consent on the headless CBOR API (`POST /rp/authorize/validate`):
//! when the caller sends `user_id`, the server evaluates that user's standing
//! consent grant against the request and reports whether a finalize would
//! succeed without showing consent again. This is the API-side counterpart of
//! the browser flow's built-in silent SSO (covered end-to-end in
//! `consent_http_e2e_test.rs`, step 7) — both go through the same
//! `silent_authorization` helper, so this file only pins the API's own
//! surface: the optional `user_id` in, the optional `already_consented` /
//! `authorized_claims` out.

mod common;

use common::data_factory::{create_auth_credential, create_relation, create_user, DataMap};
use liblinkkeys::auth_request::{build_auth_request, sign_auth_request};
use liblinkkeys::crypto::{self, SigningAlgorithm};
use liblinkkeys::encoding::signed_auth_request_to_url_param;
use liblinkkeys::generated::types::{AuthFlowContext, ClaimRequest, RequestedClaim};
use linkkeys::services::auth;
use rocket::http::{ContentType, Header, Status};
use rocket::local::asynchronous::Client;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

const TEST_DOMAIN: &str = "rpauthvalidate.test";
const PASSPHRASE: &[u8] = b"test-passphrase";
const USERNAME: &str = "alice";
const PASSWORD: &str = "correct horse battery staple";

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

fn api_key_for(pool: &linkkeys::db::DbPool, user_id: &str) -> String {
    let (api_key, hash) = auth::generate_api_key(user_id);
    create_auth_credential(pool, user_id, auth::CREDENTIAL_TYPE_API_KEY, &hash);
    api_key
}

/// Build and sign an auth request requiring `email` (and nothing else), with
/// the given nonce and optional claims_update flow context.
fn signed_email_request(
    signing_id: &str,
    sk_bytes: &[u8],
    nonce: &str,
    claims_update: bool,
) -> String {
    let mut req = build_auth_request(
        TEST_DOMAIN,
        &format!("https://{}/cb", TEST_DOMAIN),
        nonce,
        signing_id,
        Some(ClaimRequest {
            required: vec![RequestedClaim {
                claim_type: "email".to_string(),
                datatype: "email".to_string(),
            }],
            optional: vec![],
        }),
        claims_update.then(|| AuthFlowContext {
            flow: "claims_update".to_string(),
            prior_session: None,
            request_reason: None,
        }),
    );
    req.relying_party_claims = None;
    let signed = sign_auth_request(&req, signing_id, SigningAlgorithm::Ed25519, sk_bytes).unwrap();
    signed_auth_request_to_url_param(&signed).unwrap()
}

async fn call_validate(
    client: &Client,
    bearer: &str,
    signed_request: &str,
    user_id: Option<&str>,
) -> liblinkkeys::generated::types::AuthorizeValidateResponse {
    let body = liblinkkeys::generated::encode_authorize_validate_request(
        &liblinkkeys::generated::types::AuthorizeValidateRequest {
            signed_request: signed_request.to_string(),
            user_id: user_id.map(str::to_string),
        },
    );
    let resp = client
        .post("/rp/authorize/validate")
        .header(Header::new("Authorization", format!("Bearer {}", bearer)))
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok, "validate must succeed");
    liblinkkeys::generated::decode_authorize_validate_response(
        &resp.into_bytes().await.expect("response body"),
    )
    .expect("decodable AuthorizeValidateResponse")
}

#[rocket::async_test]
async fn validate_reports_silent_consent_from_a_standing_grant() {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    std::env::set_var("ENABLE_PASSWORD_AUTH", "true");

    let pool = common::create_test_pool();
    pool.seed_default_policies().expect("seed policies");

    // -- Seed the IDP: signing key, a vouched encryption key (finalize inside
    //    the browser flow needs it to seal the token when we drive real
    //    consent below), a user with a password and an `email` claim.
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
    let email_claim = pool
        .create_claim(
            &uuid::Uuid::now_v7().to_string(),
            &user.id,
            "email",
            b"a@b.com",
            &[],
            None,
            chrono::Utc::now(),
        )
        .expect("email claim");

    // The API caller: a separate active key with the api_access relation.
    let caller = create_user(&pool, &DataMap::new());
    let bearer = api_key_for(&pool, &caller.id);
    create_relation(
        &pool,
        "user",
        &caller.id,
        "api_access",
        "domain",
        TEST_DOMAIN,
    );

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

    pool.upsert_release_policy(TEST_DOMAIN, "email", "forced_allow")
        .expect("force email release");

    // 1. No grant yet: user_id is sent, but there is nothing to authorize
    //    silently. The forced-allow policy must not skip the first disclosure.
    //    Both fields must be absent.
    let sr1 = signed_email_request(&signing.id, &sk_bytes, "validate-nonce-1", false);
    let resp = call_validate(&client, &bearer, &sr1, Some(&user.id)).await;
    assert_eq!(resp.relying_party, TEST_DOMAIN);
    assert_eq!(resp.requested_claims, vec!["email".to_string()]);
    assert_eq!(
        resp.already_consented, None,
        "no prior grant => already_consented absent"
    );
    assert_eq!(
        resp.authorized_claims, None,
        "no prior grant => authorized_claims absent"
    );

    // 1b. Same request, no user_id at all: an old client that never learned
    //     about the field must see the same absent response.
    let resp_anon = call_validate(&client, &bearer, &sr1, None).await;
    assert_eq!(resp_anon.already_consented, None);
    assert_eq!(resp_anon.authorized_claims, None);

    // 2. Drive the real browser consent flow once to create a standing grant
    //    covering `email` for (user, TEST_DOMAIN).
    let sr_login = signed_email_request(&signing.id, &sk_bytes, "validate-nonce-2", false);
    let resp = client
        .post("/auth/authorize")
        .header(ContentType::Form)
        .header(Header::new("Host", TEST_DOMAIN))
        .header(Header::new("Origin", format!("https://{TEST_DOMAIN}")))
        .body(format!(
            "username={}%40{}&password={}&signed_request={}",
            USERNAME,
            TEST_DOMAIN,
            PASSWORD.replace(' ', "+"),
            sr_login
        ))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok, "consent screen renders");
    let consent_html = resp.into_string().await.unwrap();
    let proof = hidden_field(&consent_html, "login_proof");
    let resp = client
        .post("/auth/consent")
        .header(ContentType::Form)
        .header(Header::new("Host", TEST_DOMAIN))
        .header(Header::new("Origin", format!("https://{TEST_DOMAIN}")))
        .body(format!(
            "signed_request={}&login_proof={}&grant=email",
            sr_login, proof
        ))
        .dispatch()
        .await;
    assert!(
        resp.status().class().is_redirection(),
        "consent completes the login, got {:?}",
        resp.status()
    );
    let grant = pool
        .find_active_consent_grant(&user.id, TEST_DOMAIN)
        .expect("query grant")
        .expect("a grant was stored");
    assert_eq!(grant.claim_types, vec!["email".to_string()]);

    // 3. A fresh signed_request for the same claim, now covered by the
    //    standing grant: already_consented is true and authorized_claims
    //    lists exactly what a silent finalize would release.
    let sr2 = signed_email_request(&signing.id, &sk_bytes, "validate-nonce-3", false);
    let resp = call_validate(&client, &bearer, &sr2, Some(&user.id)).await;
    assert_eq!(resp.already_consented, Some(true));
    assert_eq!(resp.authorized_claims, Some(vec!["email".to_string()]));

    // 4. A claims_update request must always re-prompt, even though the
    //    standing grant would otherwise cover it.
    let sr3 = signed_email_request(&signing.id, &sk_bytes, "validate-nonce-4", true);
    let resp = call_validate(&client, &bearer, &sr3, Some(&user.id)).await;
    assert_eq!(
        resp.already_consented, None,
        "claims_update must never silently authorize"
    );
    assert_eq!(resp.authorized_claims, None);

    // 5. The required claim's only active value is removed after the grant
    //    was issued: silently authorizing it would release an empty
    //    userinfo response, so the API must fall back to "no".
    pool.remove_claim(&email_claim.id).expect("remove claim");
    let sr4 = signed_email_request(&signing.id, &sk_bytes, "validate-nonce-5", false);
    let resp = call_validate(&client, &bearer, &sr4, Some(&user.id)).await;
    assert_eq!(
        resp.already_consented, None,
        "authorized-but-valueless required claim must not silently finalize"
    );
    assert_eq!(resp.authorized_claims, None);

    // 6. An unknown user_id is treated as "no", not an error.
    let sr5 = signed_email_request(&signing.id, &sk_bytes, "validate-nonce-6", false);
    let resp = call_validate(
        &client,
        &bearer,
        &sr5,
        Some("00000000-0000-0000-0000-000000000000"),
    )
    .await;
    assert_eq!(resp.already_consented, None);
    assert_eq!(resp.authorized_claims, None);
}
