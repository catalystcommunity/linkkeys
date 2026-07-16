//! Tests for the SELF-service surface on the `Account` TCP service (slice 5):
//! `set-my-claim`, `remove-my-claim`, `create-profile`, `request-verification`,
//! and (slice 6) `set-my-claim-sharing`.
//!
//! Unlike the `Admin` service ops added in slices 1-4, these act on the
//! CALLER's own identity — the authenticated user the TCP dispatcher resolves
//! from the API key, never a `user_id` field on the request (these request
//! types don't even have one). `required_relation_for_op("Account", _)`
//! returns `None` for every op, so — unlike the `Admin` tests — there is no
//! "requires admin" check here; instead each test uses a plain caller with NO
//! relations at all, confirming the op succeeds without any admin/manage_*
//! relation. The cross-user tests below are the critical ones: they confirm a
//! caller can never use these ops to read or mutate another user's data, even
//! when handed that user's own record id (e.g. a `claim_id`).

mod common;

use common::data_factory::{
    create_auth_credential, create_claim_policy, create_domain_key, create_user, DataMap,
};
use liblinkkeys::generated::types::{
    CreateProfileRequest, EmptyRequest, RemoveMyClaimRequest, RequestVerificationRequest,
    SetMyClaimRequest, SetMyClaimSharingRequest,
};
use linkkeys::services::auth;
use serde_json::Value;

const TEST_DOMAIN: &str = "test.com";

fn setup() -> linkkeys::db::DbPool {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    common::create_test_pool()
}

/// Create a plain user (NO relations — not admin, not manage_claims, nothing)
/// with an API key. Self-service ops must work for this caller purely off
/// their own authenticated identity.
fn make_caller(pool: &linkkeys::db::DbPool) -> (linkkeys::db::models::User, String) {
    let user = create_user(pool, &DataMap::new());
    let (api_key, hash) = auth::generate_api_key(&user.id);
    create_auth_credential(pool, &user.id, auth::CREDENTIAL_TYPE_API_KEY, &hash);
    (user, api_key)
}

fn user_settable_claim_type(pool: &linkkeys::db::DbPool, claim_type: &str) {
    create_claim_policy(
        pool,
        &DataMap::from([
            ("claim_type".into(), Value::String(claim_type.into())),
            ("user_settable".into(), Value::Bool(true)),
            ("set_rule".into(), Value::String("user_self".into())),
            ("signing_rule".into(), Value::String("self_signed".into())),
        ]),
    );
}

// ---------------------------------------------------------------------
// set-my-claim
// ---------------------------------------------------------------------

#[test]
fn set_my_claim_requires_no_admin_relation_and_is_visible_in_my_info() {
    let pool = setup();
    user_settable_claim_type(&pool, "handle");
    let (user, api_key) = make_caller(&pool);

    let payload = liblinkkeys::generated::encode_set_my_claim_request(&SetMyClaimRequest {
        claim_type: "handle".to_string(),
        claim_value: "octoclaude".to_string(),
    });
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Account",
        "set-my-claim",
        payload,
        Some(&api_key),
        &pool,
        None,
    );
    assert_eq!(
        status, 0,
        "a plain (non-admin) caller must be able to set their own claim"
    );
    let resp = liblinkkeys::generated::decode_set_my_claim_response(&body)
        .expect("decode SetMyClaimResponse");
    // No auto-sign preference recorded => registry default (false) => stored
    // unsigned, mirroring `self_service::set_my_claim`'s SelfSign/auto_sign=false
    // path.
    assert_eq!(resp.outcome, "stored_unsigned");
    let claim = resp.claim.expect("claim present for a stored outcome");
    assert_eq!(claim.claim_type, "handle");
    assert_eq!(claim.claim_value, b"octoclaude");
    assert_eq!(claim.user_id, user.id, "the claim is about the caller");

    // And it shows up through get-my-info, the same read path the web editor
    // uses.
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Account",
        "get-my-info",
        liblinkkeys::generated::encode_empty_request(&EmptyRequest {}),
        Some(&api_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);
    let info =
        liblinkkeys::generated::decode_get_my_info_response(&body).expect("decode GetMyInfo");
    assert!(info
        .claims
        .iter()
        .any(|c| c.claim_type == "handle" && c.claim_value == b"octoclaude"));
}

#[test]
fn set_my_claim_rejects_non_user_settable_type() {
    let pool = setup();
    // user_settable defaults to false in create_claim_policy.
    create_claim_policy(
        &pool,
        &DataMap::from([("claim_type".into(), Value::String("email_verified".into()))]),
    );
    let (_user, api_key) = make_caller(&pool);

    let payload = liblinkkeys::generated::encode_set_my_claim_request(&SetMyClaimRequest {
        claim_type: "email_verified".to_string(),
        claim_value: "true".to_string(),
    });
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Account",
        "set-my-claim",
        payload,
        Some(&api_key),
        &pool,
        None,
    );
    assert_ne!(
        status, 0,
        "a claim type the registry did not open to self-service must be rejected"
    );
}

// ---------------------------------------------------------------------
// remove-my-claim
// ---------------------------------------------------------------------

fn set_claim_via_tcp(
    pool: &linkkeys::db::DbPool,
    api_key: &str,
    claim_type: &str,
    value: &str,
) -> String {
    let payload = liblinkkeys::generated::encode_set_my_claim_request(&SetMyClaimRequest {
        claim_type: claim_type.to_string(),
        claim_value: value.to_string(),
    });
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Account",
        "set-my-claim",
        payload,
        Some(api_key),
        pool,
        None,
    );
    assert_eq!(status, 0, "setup: set-my-claim must succeed");
    liblinkkeys::generated::decode_set_my_claim_response(&body)
        .expect("decode SetMyClaimResponse")
        .claim
        .expect("claim present")
        .claim_id
}

#[test]
fn remove_my_claim_removes_own_claim() {
    let pool = setup();
    user_settable_claim_type(&pool, "handle");
    let (user, api_key) = make_caller(&pool);
    let claim_id = set_claim_via_tcp(&pool, &api_key, "handle", "octoclaude");

    let payload = liblinkkeys::generated::encode_remove_my_claim_request(&RemoveMyClaimRequest {
        claim_id: claim_id.clone(),
    });
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Account",
        "remove-my-claim",
        payload,
        Some(&api_key),
        &pool,
        None,
    );
    assert_eq!(status, 0, "removing your own claim must succeed");
    let resp = liblinkkeys::generated::decode_remove_my_claim_response(&body)
        .expect("decode RemoveMyClaimResponse");
    assert!(resp.success);

    let active = pool.list_active_claims(&user.id).expect("list claims");
    assert!(
        active.iter().all(|c| c.id != claim_id),
        "the removed claim must no longer be active"
    );
}

/// The critical isolation test: a caller must NEVER be able to remove another
/// user's claim, even when handed that user's real claim id. `remove-my-claim`
/// takes no `user_id` — only the authenticated caller's own id is ever the
/// acting subject — so `self_service::remove_my_claim` must reject a claim_id
/// that resolves to someone else.
#[test]
fn remove_my_claim_cannot_target_another_users_claim() {
    let pool = setup();
    user_settable_claim_type(&pool, "handle");
    let (victim, victim_key) = make_caller(&pool);
    let (_attacker, attacker_key) = make_caller(&pool);

    let victim_claim_id = set_claim_via_tcp(&pool, &victim_key, "handle", "victim-handle");

    let payload = liblinkkeys::generated::encode_remove_my_claim_request(&RemoveMyClaimRequest {
        claim_id: victim_claim_id.clone(),
    });
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Account",
        "remove-my-claim",
        payload,
        Some(&attacker_key),
        &pool,
        None,
    );
    assert_ne!(
        status, 0,
        "a caller must not be able to remove another user's claim"
    );

    let active = pool.list_active_claims(&victim.id).expect("list claims");
    assert!(
        active.iter().any(|c| c.id == victim_claim_id),
        "the victim's claim must remain active after the rejected attempt"
    );
}

// ---------------------------------------------------------------------
// create-profile
// ---------------------------------------------------------------------

// Account creation already provisions one presentable "default" profile
// (id == account_id, is_root=false — see `DbPool::create_user`) alongside the
// never-leaked root anchor, so the operator must raise the cap above the
// default of 1 before an ADDITIONAL profile can be created (mirrors
// `web::profile_ui::identity_editor`'s `max_profiles_per_account() > 1` gate
// on rendering the "create profile" section at all).
fn raise_profile_cap() {
    std::env::set_var("MAX_PROFILES_PER_ACCOUNT", "3");
}

#[test]
fn create_profile_creates_presentable_profile_on_own_account() {
    let pool = setup();
    raise_profile_cap();
    let (user, api_key) = make_caller(&pool);

    let payload = liblinkkeys::generated::encode_create_profile_request(&CreateProfileRequest {
        label: Some("Gaming persona".to_string()),
    });
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Account",
        "create-profile",
        payload,
        Some(&api_key),
        &pool,
        None,
    );
    assert_eq!(
        status, 0,
        "a plain (non-admin) caller must be able to create their own profile"
    );
    let resp = liblinkkeys::generated::decode_create_profile_response(&body)
        .expect("decode CreateProfileResponse");
    assert_eq!(resp.profile.account_id, user.id);
    assert!(!resp.profile.is_root);
    assert_eq!(resp.profile.label.as_deref(), Some("Gaming persona"));

    let stored = pool
        .list_presentable_profiles_for_account(&user.id)
        .expect("list profiles");
    assert!(
        stored.iter().any(|p| p.id == resp.profile.id),
        "the newly created profile must be listed for the account"
    );
}

/// A caller cannot create a profile on someone else's account: `create-profile`
/// takes no `account_id` field at all — the acting account is always the
/// authenticated caller.
#[test]
fn create_profile_request_has_no_target_account_field() {
    let pool = setup();
    raise_profile_cap();
    let (user_a, api_key_a) = make_caller(&pool);
    let (user_b, _api_key_b) = make_caller(&pool);

    let payload = liblinkkeys::generated::encode_create_profile_request(&CreateProfileRequest {
        label: None,
    });
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Account",
        "create-profile",
        payload,
        Some(&api_key_a),
        &pool,
        None,
    );
    assert_eq!(status, 0);
    let resp = liblinkkeys::generated::decode_create_profile_response(&body)
        .expect("decode CreateProfileResponse");
    assert_eq!(resp.profile.account_id, user_a.id);
    assert_ne!(resp.profile.account_id, user_b.id);
}

// ---------------------------------------------------------------------
// request-verification
// ---------------------------------------------------------------------

#[test]
fn request_verification_returns_nonempty_signed_bundle_for_caller() {
    let pool = setup();
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    create_domain_key(&pool);
    let (user, api_key) = make_caller(&pool);

    let payload =
        liblinkkeys::generated::encode_request_verification_request(&RequestVerificationRequest {
            issuer_domain: "issuer.test".to_string(),
            requested_claim_types: vec!["age_over_21".to_string()],
        });
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Account",
        "request-verification",
        payload,
        Some(&api_key),
        &pool,
        None,
    );
    assert_eq!(
        status, 0,
        "a plain (non-admin) caller must be able to request their own verification bundle"
    );
    let resp = liblinkkeys::generated::decode_request_verification_response(&body)
        .expect("decode RequestVerificationResponse");
    assert!(
        !resp.signed_request.request.is_empty(),
        "the signing request bundle must not be empty"
    );
    assert!(
        !resp.signed_request.signatures.is_empty(),
        "the bundle must be signed by this domain's active keys"
    );

    // The bundle is about the CALLER, addressed to the requested issuer — not
    // some other subject.
    let inner = liblinkkeys::generated::decode_signing_request(&resp.signed_request.request)
        .expect("decode inner SigningRequest");
    assert_eq!(inner.subject_user_id, user.id);
    assert_eq!(inner.subject_domain, TEST_DOMAIN);
    assert_eq!(inner.issuer_domain, "issuer.test");
    assert_eq!(inner.requested_claim_types, vec!["age_over_21".to_string()]);
}

// ---------------------------------------------------------------------
// set-my-claim-sharing
// ---------------------------------------------------------------------

fn share_via_tcp(pool: &linkkeys::db::DbPool, api_key: &str, claim_type: &str, share: bool) -> i32 {
    let payload =
        liblinkkeys::generated::encode_set_my_claim_sharing_request(&SetMyClaimSharingRequest {
            claim_type: claim_type.to_string(),
            share,
        });
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Account",
        "set-my-claim-sharing",
        payload,
        Some(api_key),
        pool,
        None,
    );
    status
}

#[test]
fn set_my_claim_sharing_turns_on_a_standing_release_pref_for_all_audiences() {
    let pool = setup();
    user_settable_claim_type(&pool, "handle");
    let (user, api_key) = make_caller(&pool);

    let status = share_via_tcp(&pool, &api_key, "handle", true);
    assert_eq!(
        status, 0,
        "a plain (non-admin) caller must be able to pre-share their own claim type"
    );

    let prefs = pool
        .list_user_release_prefs(&user.id)
        .expect("list release prefs");
    assert!(
        prefs
            .iter()
            .any(|(audience, claim_type)| audience == "*" && claim_type == "handle"),
        "turning sharing on must record a standing '*' release preference"
    );
}

#[test]
fn set_my_claim_sharing_turns_off_removes_the_pref() {
    let pool = setup();
    user_settable_claim_type(&pool, "handle");
    let (user, api_key) = make_caller(&pool);

    assert_eq!(share_via_tcp(&pool, &api_key, "handle", true), 0);
    assert_eq!(share_via_tcp(&pool, &api_key, "handle", false), 0);

    let prefs = pool
        .list_user_release_prefs(&user.id)
        .expect("list release prefs");
    assert!(
        prefs
            .iter()
            .all(|(audience, claim_type)| !(audience == "*" && claim_type == "handle")),
        "turning sharing off must remove the standing '*' release preference"
    );
}

#[test]
fn set_my_claim_sharing_rejects_unknown_claim_type() {
    let pool = setup();
    let (_user, api_key) = make_caller(&pool);

    let status = share_via_tcp(&pool, &api_key, "no_such_claim_type", true);
    assert_ne!(
        status, 0,
        "an unknown claim type must not become a standing release preference"
    );
}

#[test]
fn set_my_claim_sharing_rejects_non_user_settable_claim_type() {
    let pool = setup();
    // user_settable defaults to false in create_claim_policy.
    create_claim_policy(
        &pool,
        &DataMap::from([("claim_type".into(), Value::String("email_verified".into()))]),
    );
    let (_user, api_key) = make_caller(&pool);

    let status = share_via_tcp(&pool, &api_key, "email_verified", true);
    assert_ne!(
        status, 0,
        "a claim type the registry did not open to self-service must not be pre-shareable"
    );
}

/// The critical isolation test: a caller must NEVER be able to set another
/// user's standing release preference. `set-my-claim-sharing` takes no
/// `user_id` field — only the authenticated caller is ever the acting
/// subject — so turning sharing on for one caller must leave every other
/// account's preferences untouched.
#[test]
fn set_my_claim_sharing_acts_only_on_the_authenticated_caller() {
    let pool = setup();
    user_settable_claim_type(&pool, "handle");
    let (actor, actor_key) = make_caller(&pool);
    let (bystander, _bystander_key) = make_caller(&pool);

    assert_eq!(share_via_tcp(&pool, &actor_key, "handle", true), 0);

    let actor_prefs = pool
        .list_user_release_prefs(&actor.id)
        .expect("list release prefs");
    assert!(actor_prefs
        .iter()
        .any(|(audience, claim_type)| audience == "*" && claim_type == "handle"));

    let bystander_prefs = pool
        .list_user_release_prefs(&bystander.id)
        .expect("list release prefs");
    assert!(
        bystander_prefs.is_empty(),
        "a caller's own share toggle must not affect another account's preferences"
    );
}
