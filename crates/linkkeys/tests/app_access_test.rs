//! App access policies: which applications an account may sign in to.
//!
//! The pattern and decision rules have unit tests in
//! `liblinkkeys::app_access`. This file covers the server side: which stored
//! policies apply to an account (user, group, and claim targets), admin
//! validation, the admin relation on the ops, and enforcement on the browser
//! inspect/complete operations and the app-owned consent API.

mod common;

use common::data_factory::{
    create_app_access_policy, create_auth_credential, create_relation, create_user, DataMap,
};
use csilgen_transport::rpc::{RpcRequest, RpcResponse};
use csilgen_transport::Status as RpcStatus;
use liblinkkeys::auth_request::{build_auth_request, sign_auth_request};
use liblinkkeys::crypto::{self, SigningAlgorithm};
use liblinkkeys::encoding::signed_auth_request_to_url_param;
use liblinkkeys::generated::types::{
    ApiErrorCode, AppAccessTarget, AuthorizeFinalizeRequest, AuthorizeValidateRequest,
    BrowserAuthorizationCompleteRequest, BrowserAuthorizationInspectRequest, ClaimRequest,
    EmptyRequest, PreviewAppAccessRequest, RemoveAppAccessPolicyRequest, RequestedClaim,
    SessionPasswordLoginRequest, SetAppAccessPolicyRequest,
};
use linkkeys::db::DbPool;
use linkkeys::services::app_access::{
    denial_for, preview_app_access, remove_app_access_policy, set_app_access_policy,
};
use linkkeys::services::auth;
use rocket::http::{ContentType, Header, Status};
use rocket::local::asynchronous::Client;
use serde_json::json;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

const TEST_DOMAIN: &str = "appaccess.test";
const PASSPHRASE: &[u8] = b"test-passphrase";
const USERNAME: &str = "appaccess-alice";
const PASSWORD: &str = "correct horse battery staple";

fn setup() -> DbPool {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    common::create_test_pool()
}

fn overrides(pairs: serde_json::Value) -> DataMap {
    pairs
        .as_object()
        .expect("a JSON object")
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

fn user_target(user_id: &str) -> serde_json::Value {
    json!({ "kind": "user", "user_id": user_id })
}

fn add_claim(pool: &DbPool, user_id: &str, claim_type: &str, value: &str) {
    pool.create_claim(
        &uuid::Uuid::now_v7().to_string(),
        user_id,
        claim_type,
        value.as_bytes(),
        &[],
        None,
        chrono::Utc::now(),
    )
    .expect("claim");
}

/// A `YYYY-MM-DD` birth date `years` years before today, minus `days` days.
fn birth_date(years: i32, days: i64) -> String {
    let today = chrono::Utc::now().date_naive();
    let anniversary = today
        .checked_sub_months(chrono::Months::new(years as u32 * 12))
        .expect("a valid date");
    (anniversary - chrono::Duration::days(days))
        .format("%Y-%m-%d")
        .to_string()
}

fn blocked(pool: &DbPool, user_id: &str, domain: Option<&str>) -> bool {
    denial_for(pool, user_id, domain).expect("check").is_some()
}

fn set_request(
    name: &str,
    mode: &str,
    patterns: &[&str],
    targets: Vec<AppAccessTarget>,
) -> SetAppAccessPolicyRequest {
    SetAppAccessPolicyRequest {
        id: None,
        name: name.to_string(),
        mode: mode.to_string(),
        patterns: patterns.iter().map(|p| p.to_string()).collect(),
        message: None,
        targets,
    }
}

fn target(kind: &str) -> AppAccessTarget {
    AppAccessTarget {
        kind: kind.to_string(),
        user_id: None,
        group_name: None,
        claim_type: None,
        claim_operator: None,
        claim_value: None,
    }
}

// ---------------------------------------------------------------------------
// Which policies apply
// ---------------------------------------------------------------------------

#[test]
fn no_policy_allows_every_sign_in() {
    let pool = setup();
    let user = create_user(&pool, &DataMap::new());
    assert!(!blocked(&pool, &user.id, Some("shop.ru")));
    assert!(!blocked(&pool, &user.id, None));
}

#[test]
fn user_deny_policy_blocks_only_that_user_and_matching_domains() {
    let pool = setup();
    let alice = create_user(&pool, &DataMap::new());
    let bob = create_user(&pool, &DataMap::new());
    create_app_access_policy(
        &pool,
        &overrides(json!({
            "patterns": ["*.ru"],
            "message": "Ask IT for an exception.",
            "targets": [user_target(&alice.id)],
        })),
    );

    let denial = denial_for(&pool, &alice.id, Some("Shop.RU."))
        .unwrap()
        .expect("blocked");
    assert_eq!(denial.domain.as_deref(), Some("shop.ru"));
    assert_eq!(
        denial.messages,
        vec!["Ask IT for an exception.".to_string()]
    );
    assert!(!blocked(&pool, &alice.id, Some("shop.example")));
    assert!(
        !blocked(&pool, &alice.id, None),
        "a deny list never blocks a local app"
    );
    assert!(!blocked(&pool, &bob.id, Some("shop.ru")));
}

#[test]
fn allow_policy_limits_user_to_listed_domains() {
    let pool = setup();
    let demo = create_user(&pool, &DataMap::new());
    create_app_access_policy(
        &pool,
        &overrides(json!({
            "mode": "allow",
            "patterns": ["demo.example", "*.demo.example"],
            "targets": [user_target(&demo.id)],
        })),
    );
    assert!(!blocked(&pool, &demo.id, Some("demo.example")));
    assert!(!blocked(&pool, &demo.id, Some("app.demo.example")));
    assert!(blocked(&pool, &demo.id, Some("other.example")));
    assert!(
        blocked(&pool, &demo.id, None),
        "an allow list blocks a local app"
    );
}

#[test]
fn everyone_deny_wins_over_user_allow() {
    let pool = setup();
    let user = create_user(&pool, &DataMap::new());
    create_app_access_policy(
        &pool,
        &overrides(json!({
            "mode": "allow",
            "patterns": ["*"],
            "targets": [user_target(&user.id)],
        })),
    );
    create_app_access_policy(&pool, &overrides(json!({ "patterns": ["*.ru"] })));
    assert!(!blocked(&pool, &user.id, Some("shop.example")));
    assert!(blocked(&pool, &user.id, Some("shop.ru")));
}

#[test]
fn group_target_covers_members_only() {
    let pool = setup();
    let member = create_user(&pool, &DataMap::new());
    let outsider = create_user(&pool, &DataMap::new());
    create_relation(&pool, "user", &member.id, "member", "group", "kids");
    create_app_access_policy(
        &pool,
        &overrides(json!({
            "patterns": ["*"],
            "targets": [{ "kind": "group", "group_name": "kids" }],
        })),
    );
    assert!(blocked(&pool, &member.id, Some("app.example")));
    assert!(!blocked(&pool, &outsider.id, Some("app.example")));
}

#[test]
fn claim_targets_cover_users_by_age_and_presence() {
    let pool = setup();
    let child = create_user(&pool, &DataMap::new());
    let adult = create_user(&pool, &DataMap::new());
    let unknown = create_user(&pool, &DataMap::new());
    add_claim(&pool, &child.id, "birthdate", &birth_date(15, 0));
    add_claim(&pool, &adult.id, "birthdate", &birth_date(16, 0));
    create_app_access_policy(
        &pool,
        &overrides(json!({
            "name": "under-16",
            "patterns": ["*.adult.example"],
            "targets": [{
                "kind": "claim",
                "claim_type": "birthdate",
                "claim_operator": "age_under",
                "claim_value": "16",
            }],
        })),
    );
    assert!(blocked(&pool, &child.id, Some("shop.adult.example")));
    assert!(
        !blocked(&pool, &adult.id, Some("shop.adult.example")),
        "16 today is not under 16"
    );
    assert!(!blocked(&pool, &unknown.id, Some("shop.adult.example")));

    create_app_access_policy(
        &pool,
        &overrides(json!({
            "name": "no-birthdate",
            "patterns": ["*.adult.example"],
            "targets": [{ "kind": "claim", "claim_type": "birthdate", "claim_operator": "absent" }],
        })),
    );
    assert!(blocked(&pool, &unknown.id, Some("shop.adult.example")));
    assert!(!blocked(&pool, &adult.id, Some("shop.adult.example")));
}

#[test]
fn claim_equals_target_matches_case_insensitively() {
    let pool = setup();
    let staff = create_user(&pool, &DataMap::new());
    let guest = create_user(&pool, &DataMap::new());
    add_claim(&pool, &staff.id, "role", "Staff");
    add_claim(&pool, &guest.id, "role", "guest");
    create_app_access_policy(
        &pool,
        &overrides(json!({
            "mode": "allow",
            "patterns": ["intranet.example"],
            "targets": [{
                "kind": "claim",
                "claim_type": "role",
                "claim_operator": "equals",
                "claim_value": "staff",
            }],
        })),
    );
    assert!(blocked(&pool, &staff.id, Some("public.example")));
    assert!(!blocked(&pool, &guest.id, Some("public.example")));
}

// ---------------------------------------------------------------------------
// Admin operations
// ---------------------------------------------------------------------------

#[test]
fn set_policy_canonicalizes_patterns_and_targets() {
    let pool = setup();
    let user = create_user(&pool, &DataMap::new());
    let mut req = set_request(
        "  Demo  ",
        "allow",
        &[" Demo.EXAMPLE. ", "demo.example", "**.demo.example"],
        vec![
            AppAccessTarget {
                user_id: Some(user.id.clone()),
                ..target("user")
            },
            AppAccessTarget {
                user_id: Some(user.id.clone()),
                ..target("user")
            },
            AppAccessTarget {
                claim_type: Some(" birthdate ".to_string()),
                claim_operator: Some("age_under".to_string()),
                claim_value: Some(" 16 ".to_string()),
                ..target("claim")
            },
        ],
    );
    req.message = Some("   ".to_string());
    let policy = set_app_access_policy(&pool, req).expect("saved").policy;
    assert_eq!(policy.name, "Demo");
    assert_eq!(policy.patterns, vec!["demo.example", "*.demo.example"]);
    assert_eq!(policy.message, None, "a blank message is no message");
    assert_eq!(policy.targets.len(), 2, "duplicate targets collapse");
    assert_eq!(policy.targets[1].claim_type.as_deref(), Some("birthdate"));
    assert_eq!(policy.targets[1].claim_value.as_deref(), Some("16"));

    let stored = pool.list_app_access_policies().unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].patterns.len(), 2);
}

#[test]
fn set_policy_rejects_invalid_input() {
    let pool = setup();
    let everyone = || vec![target("everyone")];
    let cases: Vec<(&str, SetAppAccessPolicyRequest)> = vec![
        (
            "empty name",
            set_request(" ", "deny", &["*.ru"], everyone()),
        ),
        ("bad mode", set_request("p", "block", &["*.ru"], everyone())),
        ("no patterns", set_request("p", "deny", &[], everyone())),
        (
            "bad pattern",
            set_request("p", "deny", &["shop?.ru"], everyone()),
        ),
        (
            "empty label",
            set_request("p", "deny", &["a..ru"], everyone()),
        ),
        (
            "bad kind",
            set_request("p", "deny", &["*.ru"], vec![target("team")]),
        ),
        (
            "user without id",
            set_request("p", "deny", &["*.ru"], vec![target("user")]),
        ),
        (
            "unknown user",
            set_request(
                "p",
                "deny",
                &["*.ru"],
                vec![AppAccessTarget {
                    user_id: Some(uuid::Uuid::now_v7().to_string()),
                    ..target("user")
                }],
            ),
        ),
        (
            "group without name",
            set_request("p", "deny", &["*.ru"], vec![target("group")]),
        ),
        (
            "bad operator",
            set_request(
                "p",
                "deny",
                &["*.ru"],
                vec![AppAccessTarget {
                    claim_type: Some("birthdate".to_string()),
                    claim_operator: Some("older_than".to_string()),
                    ..target("claim")
                }],
            ),
        ),
        (
            "bad age",
            set_request(
                "p",
                "deny",
                &["*.ru"],
                vec![AppAccessTarget {
                    claim_type: Some("birthdate".to_string()),
                    claim_operator: Some("age_under".to_string()),
                    claim_value: Some("sixteen".to_string()),
                    ..target("claim")
                }],
            ),
        ),
    ];
    for (case, req) in cases {
        let err = set_app_access_policy(&pool, req).expect_err(case);
        assert_eq!(err.code, 400, "{case}: {}", err.message);
    }
    let mut long_message = set_request("p", "deny", &["*.ru"], everyone());
    long_message.message = Some("x".repeat(1001));
    assert_eq!(
        set_app_access_policy(&pool, long_message).unwrap_err().code,
        400
    );
    assert!(pool.list_app_access_policies().unwrap().is_empty());
}

#[test]
fn set_policy_by_id_replaces_it_whole_and_names_stay_unique() {
    let pool = setup();
    let user = create_user(&pool, &DataMap::new());
    let first = set_app_access_policy(
        &pool,
        set_request("first", "deny", &["*.ru", "*.cn"], vec![target("everyone")]),
    )
    .unwrap()
    .policy;
    set_app_access_policy(
        &pool,
        set_request("second", "deny", &["*.kp"], vec![target("everyone")]),
    )
    .unwrap();

    let mut update = set_request(
        "first renamed",
        "allow",
        &["ok.example"],
        vec![AppAccessTarget {
            user_id: Some(user.id.clone()),
            ..target("user")
        }],
    );
    update.id = Some(first.id.clone());
    update.message = Some("Demo only.".to_string());
    set_app_access_policy(&pool, update).unwrap();
    let stored = pool.list_app_access_policies().unwrap();
    let updated = stored.iter().find(|p| p.id == first.id).unwrap();
    assert_eq!(updated.name, "first renamed");
    assert_eq!(updated.mode, "allow");
    assert_eq!(updated.patterns, vec!["ok.example"]);
    assert_eq!(updated.targets.len(), 1);
    assert_eq!(
        updated.targets[0].user_id.as_deref(),
        Some(user.id.as_str())
    );
    assert_eq!(updated.message.as_deref(), Some("Demo only."));

    let duplicate = set_app_access_policy(&pool, set_request("second", "deny", &["*.ru"], vec![]));
    assert_eq!(duplicate.unwrap_err().code, 409);
    let mut unknown = set_request("third", "deny", &["*.ru"], vec![]);
    unknown.id = Some(uuid::Uuid::now_v7().to_string());
    assert_eq!(set_app_access_policy(&pool, unknown).unwrap_err().code, 404);
}

#[test]
fn remove_policy_lifts_it_and_unknown_ids_are_not_found() {
    let pool = setup();
    let user = create_user(&pool, &DataMap::new());
    let policy = create_app_access_policy(&pool, &overrides(json!({ "patterns": ["*"] })));
    assert!(blocked(&pool, &user.id, Some("app.example")));
    remove_app_access_policy(
        &pool,
        RemoveAppAccessPolicyRequest {
            id: policy.id.clone(),
        },
    )
    .unwrap();
    assert!(!blocked(&pool, &user.id, Some("app.example")));
    assert!(
        pool.list_app_access_policies().unwrap().is_empty(),
        "patterns and targets go too"
    );
    for id in [policy.id, "not-a-uuid".to_string()] {
        let err = remove_app_access_policy(&pool, RemoveAppAccessPolicyRequest { id }).unwrap_err();
        assert_eq!(err.code, 404);
    }
}

#[test]
fn preview_reports_applied_and_blocking_policies() {
    let pool = setup();
    let user = create_user(&pool, &DataMap::new());
    create_app_access_policy(
        &pool,
        &overrides(
            json!({ "name": "allow-demo", "mode": "allow", "patterns": ["demo.example"], "targets": [user_target(&user.id)] }),
        ),
    );
    create_app_access_policy(
        &pool,
        &overrides(json!({ "name": "no-ru", "patterns": ["*.ru"], "message": "Region blocked." })),
    );
    create_app_access_policy(
        &pool,
        &overrides(
            json!({ "name": "other-group", "patterns": ["*"], "targets": [{ "kind": "group", "group_name": "nobody" }] }),
        ),
    );
    let preview = |domain: Option<&str>| {
        preview_app_access(
            &pool,
            PreviewAppAccessRequest {
                user_id: user.id.clone(),
                domain: domain.map(str::to_string),
            },
        )
        .unwrap()
    };
    let allowed = preview(Some("demo.example"));
    assert!(allowed.allowed);
    assert_eq!(allowed.applied_policies, vec!["allow-demo", "no-ru"]);
    assert!(allowed.blocking_policies.is_empty());

    let denied = preview(Some("shop.ru"));
    assert!(!denied.allowed);
    assert_eq!(denied.blocking_policies, vec!["no-ru"]);
    assert_eq!(denied.messages, vec!["Region blocked."]);

    let local = preview(None);
    assert!(!local.allowed);
    assert_eq!(local.blocking_policies, vec!["allow-demo"]);

    let unknown = preview_app_access(
        &pool,
        PreviewAppAccessRequest {
            user_id: uuid::Uuid::now_v7().to_string(),
            domain: None,
        },
    );
    assert_eq!(unknown.unwrap_err().code, 400);
}

#[test]
fn app_access_admin_ops_require_admin() {
    let pool = setup();
    let make_caller = |is_admin: bool| {
        let user = create_user(&pool, &DataMap::new());
        create_relation(
            &pool,
            "user",
            &user.id,
            "manage_users",
            "domain",
            TEST_DOMAIN,
        );
        if is_admin {
            create_relation(&pool, "user", &user.id, "admin", "domain", TEST_DOMAIN);
        }
        let (api_key, hash) = auth::generate_api_key(&user.id);
        create_auth_credential(&pool, &user.id, auth::CREDENTIAL_TYPE_API_KEY, &hash);
        (user, api_key)
    };
    let (nonadmin, nonadmin_key) = make_caller(false);
    let (_admin, admin_key) = make_caller(true);
    let set_payload = liblinkkeys::generated::encode_set_app_access_policy_request(&set_request(
        "tcp",
        "deny",
        &["*.ru"],
        vec![target("everyone")],
    ));
    let ops: Vec<(&str, Vec<u8>)> = vec![
        (
            "list-app-access-policies",
            liblinkkeys::generated::encode_empty_request(&EmptyRequest {}),
        ),
        ("set-app-access-policy", set_payload.clone()),
        (
            "remove-app-access-policy",
            liblinkkeys::generated::encode_remove_app_access_policy_request(
                &RemoveAppAccessPolicyRequest {
                    id: uuid::Uuid::now_v7().to_string(),
                },
            ),
        ),
        (
            "preview-app-access",
            liblinkkeys::generated::encode_preview_app_access_request(&PreviewAppAccessRequest {
                user_id: nonadmin.id.clone(),
                domain: None,
            }),
        ),
    ];
    for (op, payload) in ops {
        let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
            "Admin",
            op,
            payload,
            Some(&nonadmin_key),
            &pool,
            None,
        );
        assert_ne!(status, 0, "{op}: a caller without admin must be forbidden");
    }
    assert!(pool.list_app_access_policies().unwrap().is_empty());

    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "set-app-access-policy",
        set_payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0, "an admin caller must succeed");
    let saved = liblinkkeys::generated::decode_set_app_access_policy_response(&body).unwrap();
    assert_eq!(saved.policy.patterns, vec!["*.ru"]);
}

// ---------------------------------------------------------------------------
// Enforcement on the sign-in paths
// ---------------------------------------------------------------------------

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

/// An IDP that is also the relying party (offline network), a user with a
/// password and an `email` claim, and an API caller with `api_access`.
async fn seeded_idp() -> (
    DbPool,
    Client,
    String,
    Vec<u8>,
    linkkeys::db::models::User,
    String,
) {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    std::env::set_var("ENABLE_PASSWORD_AUTH", "true");

    let pool = common::create_test_pool();
    pool.seed_default_policies().expect("seed policies");

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

    let user = create_user(&pool, &overrides(json!({ "username": USERNAME })));
    let hash = linkkeys::services::password::hash_for_storage(PASSWORD).unwrap();
    create_auth_credential(&pool, &user.id, "password", &hash);
    add_claim(&pool, &user.id, "email", "a@b.com");

    let caller = create_user(&pool, &DataMap::new());
    let (bearer, key_hash) = auth::generate_api_key(&caller.id);
    create_auth_credential(&pool, &caller.id, auth::CREDENTIAL_TYPE_API_KEY, &key_hash);
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
    (pool, client, signing.id, sk_bytes, user, bearer)
}

fn signed_email_request(signing_id: &str, sk_bytes: &[u8], nonce: &str) -> String {
    let mut req = build_auth_request(
        TEST_DOMAIN,
        &format!("https://{TEST_DOMAIN}/cb"),
        nonce,
        signing_id,
        Some(ClaimRequest {
            required: vec![RequestedClaim {
                claim_type: "email".to_string(),
                datatype: "email".to_string(),
            }],
            optional: Vec::new(),
        }),
        None,
    );
    req.relying_party_claims = None;
    let signed = sign_auth_request(&req, signing_id, SigningAlgorithm::Ed25519, sk_bytes).unwrap();
    signed_auth_request_to_url_param(&signed).unwrap()
}

async fn sign_in(client: &Client) {
    let login = rpc(
        client,
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
    assert_eq!(login.status, RpcStatus::Ok, "sign-in succeeds");
}

async fn inspect(
    client: &Client,
    signed_request: &str,
) -> liblinkkeys::generated::types::BrowserAuthorizationInspectResponse {
    let resp = rpc(
        client,
        "BrowserAuthorization",
        "inspect",
        liblinkkeys::generated::encode_browser_authorization_inspect_request(
            &BrowserAuthorizationInspectRequest {
                signed_request: signed_request.to_string(),
            },
        ),
    )
    .await;
    assert_eq!(resp.status, RpcStatus::Ok, "inspect succeeds");
    liblinkkeys::generated::decode_browser_authorization_inspect_response(&resp.payload).unwrap()
}

async fn complete(client: &Client, signed_request: &str) -> RpcResponse {
    rpc(
        client,
        "BrowserAuthorization",
        "complete",
        liblinkkeys::generated::encode_browser_authorization_complete_request(
            &BrowserAuthorizationCompleteRequest {
                signed_request: signed_request.to_string(),
                authorized_claims: vec!["email".to_string()],
                claim_types_to_set: Vec::new(),
                claim_values_to_set: Vec::new(),
                use_standing_grant: None,
            },
        ),
    )
    .await
}

#[rocket::async_test]
async fn blocked_user_gets_a_denial_and_cannot_complete_a_browser_sign_in() {
    let (pool, client, signing_id, sk_bytes, user, _bearer) = seeded_idp().await;
    let policy = create_app_access_policy(
        &pool,
        &overrides(json!({
            "patterns": ["*.test"],
            "message": "Demo accounts cannot use this app.",
            "targets": [user_target(&user.id)],
        })),
    );
    sign_in(&client).await;
    let request = signed_email_request(&signing_id, &sk_bytes, "browser-blocked");

    let inspected = inspect(&client, &request).await;
    let denial = inspected
        .access_denied
        .expect("the inspect response carries the denial");
    assert_eq!(denial.domain.as_deref(), Some(TEST_DOMAIN));
    assert_eq!(denial.messages, vec!["Demo accounts cannot use this app."]);
    assert!(
        inspected.claims.is_empty(),
        "a blocked sign-in shows no claims"
    );
    assert!(inspected.already_consented.is_none());

    let refused = complete(&client, &request).await;
    assert_eq!(refused.status, RpcStatus::Forbidden);
    assert!(
        refused
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("Demo accounts cannot use this app."),
        "the refusal carries the admin message: {:?}",
        refused.error
    );
    assert!(
        pool.find_active_consent_grant(&user.id, TEST_DOMAIN)
            .unwrap()
            .is_none(),
        "a refused sign-in stores no consent"
    );

    remove_app_access_policy(&pool, RemoveAppAccessPolicyRequest { id: policy.id }).unwrap();
    assert!(inspect(&client, &request).await.access_denied.is_none());
    assert_eq!(
        complete(&client, &request).await.status,
        RpcStatus::Ok,
        "the refused attempt did not burn the request"
    );
}

#[rocket::async_test]
async fn app_owned_consent_api_reports_and_enforces_the_denial() {
    let (pool, client, signing_id, sk_bytes, user, bearer) = seeded_idp().await;
    create_app_access_policy(
        &pool,
        &overrides(json!({
            "mode": "allow",
            "patterns": ["only.example"],
            "message": "Demo account.",
            "targets": [user_target(&user.id)],
        })),
    );
    let request = signed_email_request(&signing_id, &sk_bytes, "api-blocked");
    let bearer_header = || Header::new("Authorization", format!("Bearer {bearer}"));

    let validate = |user_id: Option<String>| {
        let body =
            liblinkkeys::generated::encode_authorize_validate_request(&AuthorizeValidateRequest {
                signed_request: request.clone(),
                user_id,
            });
        client
            .post("/rp/authorize/validate")
            .header(bearer_header())
            .body(body)
            .dispatch()
    };
    let resp = validate(Some(user.id.clone())).await;
    assert_eq!(resp.status(), Status::Ok);
    let validated = liblinkkeys::generated::decode_authorize_validate_response(
        &resp.into_bytes().await.unwrap(),
    )
    .unwrap();
    let denial = validated
        .access_denied
        .expect("validate reports the denial");
    assert_eq!(denial.messages, vec!["Demo account."]);
    assert!(validated.already_consented.is_none());

    let resp = validate(None).await;
    let anonymous = liblinkkeys::generated::decode_authorize_validate_response(
        &resp.into_bytes().await.unwrap(),
    )
    .unwrap();
    assert!(
        anonymous.access_denied.is_none(),
        "no user_id, no policy evaluation"
    );

    let resp = client
        .post("/rp/authorize/finalize")
        .header(bearer_header())
        .body(liblinkkeys::generated::encode_authorize_finalize_request(
            &AuthorizeFinalizeRequest {
                user_id: user.id.clone(),
                signed_request: request.clone(),
                authorized_claims: vec!["email".to_string()],
            },
        ))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Forbidden);
    let err = liblinkkeys::generated::decode_api_error(&resp.into_bytes().await.unwrap()).unwrap();
    assert_eq!(err.code, ApiErrorCode::Forbidden);
    assert!(err.message.contains("Demo account."), "{}", err.message);
    assert!(pool
        .find_active_consent_grant(&user.id, TEST_DOMAIN)
        .unwrap()
        .is_none());
}
