//! End-to-end test for the SPA authorization boundary.
//!
//! The test uses Rocket's local client. It exercises the same routes, cookies,
//! CSIL envelopes, consent logic, and database writes as a browser.

mod common;

use common::data_factory::{create_auth_credential, create_user, DataMap};
use csilgen_transport::rpc::{RpcRequest, RpcResponse};
use csilgen_transport::Status as RpcStatus;
use liblinkkeys::auth_request::{build_auth_request, sign_auth_request};
use liblinkkeys::crypto::{self, SigningAlgorithm};
use liblinkkeys::encoding::signed_auth_request_to_url_param;
use liblinkkeys::generated::types::{
    AuthenticationRequirements, BrowserAuthorizationCompleteRequest,
    BrowserAuthorizationInspectRequest, ClaimRequest, RequestedClaim, SessionPasswordLoginRequest,
};
use rocket::http::{ContentType, Header, Status};
use rocket::local::asynchronous::Client;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

const TEST_DOMAIN: &str = "e2e.test";
const PASSPHRASE: &[u8] = b"test-passphrase";
const USERNAME: &str = "alice";
const PASSWORD: &str = "correct horse battery staple";

fn envelope(service: &str, operation: &str, payload: Vec<u8>) -> Vec<u8> {
    RpcRequest::new(service, operation, payload)
        .encode()
        .expect("encode RPC request")
}

async fn rpc(client: &Client, service: &str, operation: &str, payload: Vec<u8>) -> RpcResponse {
    let response = client
        .post("/csil/v1/rpc")
        .header(ContentType::new("application", "cbor"))
        .header(Header::new("Host", TEST_DOMAIN))
        .header(Header::new("Origin", format!("https://{TEST_DOMAIN}")))
        .body(envelope(service, operation, payload))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    RpcResponse::decode(&response.into_bytes().await.expect("RPC response body"))
        .expect("decode RPC response")
}

fn signed_request(
    signing_key_id: &str,
    signing_key: &[u8],
    nonce: &str,
    claims: Option<ClaimRequest>,
    requirements: Option<AuthenticationRequirements>,
) -> String {
    let mut request = build_auth_request(
        TEST_DOMAIN,
        &format!("https://{TEST_DOMAIN}/cb"),
        nonce,
        signing_key_id,
        claims,
        None,
    );
    request.relying_party_claims = None;
    request.authentication_requirements = requirements;
    let signed = sign_auth_request(
        &request,
        signing_key_id,
        SigningAlgorithm::Ed25519,
        signing_key,
    )
    .expect("sign authorization request");
    signed_auth_request_to_url_param(&signed).expect("encode authorization request")
}

#[rocket::async_test]
async fn spa_consent_flow_end_to_end() {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    std::env::set_var("ENABLE_PASSWORD_AUTH", "true");

    let pool = common::create_test_pool();
    pool.seed_default_policies().expect("seed policies");

    let (verification_key, signing_key) = crypto::generate_ed25519_keypair();
    let public_key = verification_key.as_bytes().to_vec();
    let signing_key_bytes = signing_key.to_bytes().to_vec();
    let encrypted_signing_key =
        crypto::encrypt_private_key(&signing_key_bytes, PASSPHRASE).unwrap();
    let fingerprint = crypto::fingerprint(&public_key);
    let expires = chrono::Utc::now() + chrono::Duration::days(365);
    let signing = pool
        .create_domain_key(
            &public_key,
            &encrypted_signing_key,
            &fingerprint,
            "ed25519",
            expires,
        )
        .expect("signing key");

    let (encryption_public_key, encryption_private_key) = crypto::generate_x25519_keypair();
    let encryption_fingerprint = crypto::fingerprint(&encryption_public_key);
    let encrypted_private_key =
        crypto::encrypt_private_key(&encryption_private_key, PASSPHRASE).unwrap();
    let vouch = liblinkkeys::dns::sign_key_vouch(
        &encryption_fingerprint,
        &expires.to_rfc3339(),
        SigningAlgorithm::Ed25519,
        &signing_key_bytes,
    )
    .unwrap();
    pool.create_domain_encryption_key(
        &encryption_public_key,
        &encrypted_private_key,
        &encryption_fingerprint,
        &signing.id,
        &vouch,
        expires,
    )
    .expect("encryption key");

    let mut overrides = DataMap::new();
    overrides.insert("username".to_string(), serde_json::json!(USERNAME));
    let user = create_user(&pool, &overrides);
    let hash = linkkeys::services::password::hash_for_storage(PASSWORD).unwrap();
    create_auth_credential(&pool, &user.id, "password", &hash);
    for (claim_type, value) in [("email", b"a@b.com".as_slice()), ("ssn", b"123".as_slice())] {
        pool.create_claim(
            &uuid::Uuid::now_v7().to_string(),
            &user.id,
            claim_type,
            value,
            &[],
            None,
            chrono::Utc::now(),
        )
        .expect("claim");
    }
    pool.upsert_release_policy(TEST_DOMAIN, "email", "forced_allow")
        .expect("force email release");

    let authorization = signed_request(
        &signing.id,
        &signing_key_bytes,
        "spa-login-nonce-1",
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

    let config = rocket::Config {
        secret_key: rocket::config::SecretKey::derive_from(&[7_u8; 64]),
        ..rocket::Config::debug_default()
    };
    let rocket = linkkeys::web::build_rocket(
        pool.clone(),
        Arc::new(AtomicBool::new(true)),
        common::net::offline_net(),
        config,
    );
    let client = Client::tracked(rocket).await.expect("Rocket client");

    let response = client
        .get(format!(
            "/auth/authorize?username=alice%40{TEST_DOMAIN}&signed_request={authorization}"
        ))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Found);
    let expected_location =
        format!("/app/authorize?username=alice%40{TEST_DOMAIN}#request={authorization}");
    assert_eq!(
        response.headers().get_one("Location"),
        Some(expected_location.as_str())
    );

    let response = client
        .get(format!(
            "/auth/authorize?user_hint=legacy%2Bname&signed_request={authorization}"
        ))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Found);
    let expected_location =
        format!("/app/authorize?username=legacy%2Bname#request={authorization}");
    assert_eq!(
        response.headers().get_one("Location"),
        Some(expected_location.as_str())
    );

    let response = client
        .get(format!(
            "/auth/authorize?username=preferred&user_hint=legacy&signed_request={authorization}"
        ))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Found);
    let expected_location = format!("/app/authorize?username=preferred#request={authorization}");
    assert_eq!(
        response.headers().get_one("Location"),
        Some(expected_location.as_str())
    );

    let response = client
        .get("/auth/authorize?signed_request=not-valid")
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let body = response.into_string().await.unwrap();
    assert!(body.contains("malformed"));
    assert!(!body.contains("name=\"password\""));

    let inspect_payload = liblinkkeys::generated::encode_browser_authorization_inspect_request(
        &BrowserAuthorizationInspectRequest {
            signed_request: authorization.clone(),
        },
    );
    let response = rpc(
        &client,
        "BrowserAuthorization",
        "inspect",
        inspect_payload.clone(),
    )
    .await;
    assert_eq!(response.status, RpcStatus::Forbidden);

    let wrong_login = rpc(
        &client,
        "Session",
        "login-password",
        liblinkkeys::generated::encode_session_password_login_request(
            &SessionPasswordLoginRequest {
                username: USERNAME.to_string(),
                password: "wrong password".to_string(),
            },
        ),
    )
    .await;
    assert_ne!(wrong_login.status, RpcStatus::Ok);

    let login = rpc(
        &client,
        "Session",
        "login-password",
        liblinkkeys::generated::encode_session_password_login_request(
            &SessionPasswordLoginRequest {
                username: format!("{USERNAME}@{TEST_DOMAIN}"),
                password: PASSWORD.to_string(),
            },
        ),
    )
    .await;
    assert_eq!(login.status, RpcStatus::Ok);

    let response = rpc(&client, "BrowserAuthorization", "inspect", inspect_payload).await;
    assert_eq!(response.status, RpcStatus::Ok);
    let inspection =
        liblinkkeys::generated::decode_browser_authorization_inspect_response(&response.payload)
            .expect("decode inspection");
    assert_eq!(inspection.relying_party, TEST_DOMAIN);
    assert_eq!(inspection.claims.len(), 2);
    assert_eq!(inspection.already_consented, None);
    assert_eq!(inspection.authorized_claims, None);
    assert!(inspection
        .claims
        .iter()
        .any(|claim| claim.claim_type == "email"
            && claim.required
            && claim.available
            && claim.policy == "forced_allow"));
    assert!(inspection
        .claims
        .iter()
        .any(|claim| claim.claim_type == "ssn" && !claim.required && claim.available));

    let complete_payload = liblinkkeys::generated::encode_browser_authorization_complete_request(
        &BrowserAuthorizationCompleteRequest {
            signed_request: authorization.clone(),
            authorized_claims: vec!["email".to_string()],
            claim_types_to_set: Vec::new(),
            claim_values_to_set: Vec::new(),
            use_standing_grant: None,
        },
    );
    let response = rpc(
        &client,
        "BrowserAuthorization",
        "complete",
        complete_payload.clone(),
    )
    .await;
    assert_eq!(response.status, RpcStatus::Ok);
    let completion =
        liblinkkeys::generated::decode_browser_authorization_complete_response(&response.payload)
            .expect("decode completion");
    assert!(completion.redirect_url.starts_with("https://e2e.test/cb?"));
    assert!(completion.redirect_url.contains("encrypted_token="));

    let grant = pool
        .find_active_consent_grant(&user.id, TEST_DOMAIN)
        .expect("query grant")
        .expect("stored grant");
    assert_eq!(grant.claim_types, vec!["email"]);

    let repeat_authorization = signed_request(
        &signing.id,
        &signing_key_bytes,
        "spa-login-nonce-repeat",
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
    let response = rpc(
        &client,
        "BrowserAuthorization",
        "inspect",
        liblinkkeys::generated::encode_browser_authorization_inspect_request(
            &BrowserAuthorizationInspectRequest {
                signed_request: repeat_authorization.clone(),
            },
        ),
    )
    .await;
    assert_eq!(response.status, RpcStatus::Ok);
    let repeat_inspection =
        liblinkkeys::generated::decode_browser_authorization_inspect_response(&response.payload)
            .expect("decode repeat inspection");
    assert_eq!(repeat_inspection.already_consented, Some(true));
    assert_eq!(
        repeat_inspection.authorized_claims,
        Some(vec!["email".to_string()])
    );

    let response = rpc(
        &client,
        "BrowserAuthorization",
        "complete",
        liblinkkeys::generated::encode_browser_authorization_complete_request(
            &BrowserAuthorizationCompleteRequest {
                signed_request: repeat_authorization,
                authorized_claims: repeat_inspection.authorized_claims.unwrap(),
                claim_types_to_set: Vec::new(),
                claim_values_to_set: Vec::new(),
                use_standing_grant: Some(true),
            },
        ),
    )
    .await;
    assert_eq!(response.status, RpcStatus::Ok);

    let changed_policy_authorization = signed_request(
        &signing.id,
        &signing_key_bytes,
        "spa-login-nonce-changed-policy",
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
    let response = rpc(
        &client,
        "BrowserAuthorization",
        "inspect",
        liblinkkeys::generated::encode_browser_authorization_inspect_request(
            &BrowserAuthorizationInspectRequest {
                signed_request: changed_policy_authorization.clone(),
            },
        ),
    )
    .await;
    assert_eq!(response.status, RpcStatus::Ok);
    let prior_policy_inspection =
        liblinkkeys::generated::decode_browser_authorization_inspect_response(&response.payload)
            .expect("decode prior-policy inspection");
    assert_eq!(prior_policy_inspection.already_consented, Some(true));

    pool.upsert_release_policy(TEST_DOMAIN, "ssn", "forced_allow")
        .expect("force a newly requested claim");
    let response = rpc(
        &client,
        "BrowserAuthorization",
        "complete",
        liblinkkeys::generated::encode_browser_authorization_complete_request(
            &BrowserAuthorizationCompleteRequest {
                signed_request: changed_policy_authorization.clone(),
                authorized_claims: prior_policy_inspection.authorized_claims.unwrap(),
                claim_types_to_set: Vec::new(),
                claim_values_to_set: Vec::new(),
                use_standing_grant: Some(true),
            },
        ),
    )
    .await;
    assert_ne!(response.status, RpcStatus::Ok);

    let response = rpc(
        &client,
        "BrowserAuthorization",
        "inspect",
        liblinkkeys::generated::encode_browser_authorization_inspect_request(
            &BrowserAuthorizationInspectRequest {
                signed_request: changed_policy_authorization,
            },
        ),
    )
    .await;
    assert_eq!(response.status, RpcStatus::Ok);
    let changed_policy_inspection =
        liblinkkeys::generated::decode_browser_authorization_inspect_response(&response.payload)
            .expect("decode changed-policy inspection");
    assert_eq!(changed_policy_inspection.already_consented, None);
    assert_eq!(changed_policy_inspection.authorized_claims, None);

    let replay = rpc(
        &client,
        "BrowserAuthorization",
        "complete",
        complete_payload,
    )
    .await;
    assert_ne!(replay.status, RpcStatus::Ok);

    let missing_claim_authorization = signed_request(
        &signing.id,
        &signing_key_bytes,
        "spa-login-nonce-2",
        Some(ClaimRequest {
            required: vec![RequestedClaim {
                claim_type: "display_name".to_string(),
                datatype: "text".to_string(),
            }],
            optional: Vec::new(),
        }),
        None,
    );
    let response = rpc(
        &client,
        "BrowserAuthorization",
        "inspect",
        liblinkkeys::generated::encode_browser_authorization_inspect_request(
            &BrowserAuthorizationInspectRequest {
                signed_request: missing_claim_authorization.clone(),
            },
        ),
    )
    .await;
    assert_eq!(response.status, RpcStatus::Ok);
    let inspection =
        liblinkkeys::generated::decode_browser_authorization_inspect_response(&response.payload)
            .unwrap();
    assert!(inspection.claims.iter().any(|claim| {
        claim.claim_type == "display_name" && !claim.available && claim.user_settable
    }));

    let response = rpc(
        &client,
        "BrowserAuthorization",
        "complete",
        liblinkkeys::generated::encode_browser_authorization_complete_request(
            &BrowserAuthorizationCompleteRequest {
                signed_request: missing_claim_authorization,
                authorized_claims: vec!["display_name".to_string()],
                claim_types_to_set: vec!["display_name".to_string()],
                claim_values_to_set: vec!["Ada".to_string()],
                use_standing_grant: None,
            },
        ),
    )
    .await;
    assert_eq!(response.status, RpcStatus::Ok);
    let claims = pool.list_active_claims(&user.id).expect("claims");
    let display_name = claims
        .iter()
        .find(|claim| claim.claim_type == "display_name")
        .expect("display name claim");
    assert_eq!(display_name.claim_value, b"Ada");
    assert!(!display_name.signatures.is_empty());

    let assurance_authorization = signed_request(
        &signing.id,
        &signing_key_bytes,
        "spa-login-nonce-3",
        None,
        Some(AuthenticationRequirements {
            minimum_factor_count: 2,
        }),
    );
    let response = client
        .get(format!(
            "/auth/authorize?signed_request={assurance_authorization}"
        ))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let body = response.into_string().await.unwrap();
    assert!(body.contains("cannot satisfy"));
    assert!(!body.contains("name=\"password\""));
}
