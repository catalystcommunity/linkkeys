//! Tests for the trusted-issuer and release-default admin surface on the
//! `Admin` TCP service (policy-admin web UI parity, slice 2):
//! `list-trusted-issuers`, `add-trusted-issuer`, `remove-trusted-issuer`,
//! `list-release-rules`, `set-release-rule`, `remove-release-rule`.
//!
//! These are a second CSIL-RPC entry point onto the exact same DB calls
//! `web/policy_admin_ui.rs`'s handlers make
//! (`add_issuer`/`remove_issuer`/`upsert_release`/`delete_release`), so an
//! external controller holding an admin-relation API key can manage them
//! without the web UI.
//!
//! Every op requires the `admin` relation (explicit `required_relation_for_op`
//! arm, not the `_ =>` fallthrough, mirroring
//! `tcp_claim_type_admin_test.rs`) — each test below confirms a non-admin
//! caller is forbidden before confirming an admin succeeds.

mod common;

use common::data_factory::{
    create_auth_credential, create_relation, create_release_rule, create_trusted_issuer,
    create_user, DataMap,
};
use liblinkkeys::generated::types::{
    AddTrustedIssuerRequest, EmptyRequest, RemoveReleaseRuleRequest, RemoveTrustedIssuerRequest,
    SetReleaseRuleRequest,
};
use linkkeys::services::auth;

const TEST_DOMAIN: &str = "test.com";

fn setup() -> linkkeys::db::DbPool {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    common::create_test_pool()
}

/// Create a service-account user with an API key, granting `admin` on the
/// domain only when `is_admin` is true. Returns the API key.
fn make_caller(pool: &linkkeys::db::DbPool, is_admin: bool) -> String {
    let user = create_user(pool, &DataMap::new());
    if is_admin {
        create_relation(pool, "user", &user.id, "admin", "domain", TEST_DOMAIN);
    }
    let (api_key, hash) = auth::generate_api_key(&user.id);
    create_auth_credential(pool, &user.id, auth::CREDENTIAL_TYPE_API_KEY, &hash);
    api_key
}

// ---------------------------------------------------------------------
// list-trusted-issuers
// ---------------------------------------------------------------------

#[test]
fn list_trusted_issuers_requires_admin() {
    let pool = setup();
    create_trusted_issuer(&pool, "age_over_21", "gov.example");
    let payload = liblinkkeys::generated::encode_empty_request(&EmptyRequest {});

    let nonadmin_key = make_caller(&pool, false);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "list-trusted-issuers",
        payload.clone(),
        Some(&nonadmin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a caller without admin must be forbidden");

    let admin_key = make_caller(&pool, true);
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "list-trusted-issuers",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0, "an admin caller must succeed");
    let resp = liblinkkeys::generated::decode_list_trusted_issuers_response(&body)
        .expect("decode ListTrustedIssuersResponse");
    assert_eq!(resp.trusted_issuers.len(), 1);
    assert_eq!(resp.trusted_issuers[0].claim_type, "age_over_21");
    assert_eq!(resp.trusted_issuers[0].issuer_domain, "gov.example");
}

// ---------------------------------------------------------------------
// add-trusted-issuer
// ---------------------------------------------------------------------

#[test]
fn add_trusted_issuer_requires_admin() {
    let pool = setup();
    let payload =
        liblinkkeys::generated::encode_add_trusted_issuer_request(&AddTrustedIssuerRequest {
            claim_type: "citizenship".to_string(),
            issuer_domain: "passports.example".to_string(),
        });

    let nonadmin_key = make_caller(&pool, false);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "add-trusted-issuer",
        payload.clone(),
        Some(&nonadmin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a caller without admin must be forbidden");
    assert!(
        pool.list_all_trusted_issuers().unwrap().is_empty(),
        "forbidden call must not have written anything"
    );

    let admin_key = make_caller(&pool, true);
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "add-trusted-issuer",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0, "an admin caller must succeed");
    let resp = liblinkkeys::generated::decode_add_trusted_issuer_response(&body)
        .expect("decode AddTrustedIssuerResponse");
    assert_eq!(resp.trusted_issuer.claim_type, "citizenship");
    assert_eq!(resp.trusted_issuer.issuer_domain, "passports.example");
}

#[test]
fn add_then_list_trusted_issuer_round_trips() {
    let pool = setup();
    let admin_key = make_caller(&pool, true);

    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "add-trusted-issuer",
        liblinkkeys::generated::encode_add_trusted_issuer_request(&AddTrustedIssuerRequest {
            claim_type: "age_over_21".to_string(),
            issuer_domain: "dmv.example".to_string(),
        }),
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);

    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "list-trusted-issuers",
        liblinkkeys::generated::encode_empty_request(&EmptyRequest {}),
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);
    let resp = liblinkkeys::generated::decode_list_trusted_issuers_response(&body)
        .expect("decode ListTrustedIssuersResponse");
    assert!(resp
        .trusted_issuers
        .iter()
        .any(|t| t.claim_type == "age_over_21" && t.issuer_domain == "dmv.example"));
}

/// `add-trusted-issuer` is insert-if-absent: adding the same pair twice
/// must not create a duplicate row or error.
#[test]
fn add_trusted_issuer_is_idempotent() {
    let pool = setup();
    let admin_key = make_caller(&pool, true);
    let req = AddTrustedIssuerRequest {
        claim_type: "age_over_21".to_string(),
        issuer_domain: "dmv.example".to_string(),
    };

    for i in 0..2 {
        let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
            "Admin",
            "add-trusted-issuer",
            liblinkkeys::generated::encode_add_trusted_issuer_request(&req),
            Some(&admin_key),
            &pool,
            None,
        );
        assert_eq!(status, 0, "add #{} must succeed", i);
    }

    let matches: Vec<_> = pool
        .list_all_trusted_issuers()
        .unwrap()
        .into_iter()
        .filter(|t| t.claim_type == "age_over_21" && t.issuer_domain == "dmv.example")
        .collect();
    assert_eq!(matches.len(), 1, "must not create a duplicate row");
}

// ---------------------------------------------------------------------
// remove-trusted-issuer
// ---------------------------------------------------------------------

#[test]
fn remove_trusted_issuer_requires_admin_and_deletes() {
    let pool = setup();
    create_trusted_issuer(&pool, "age_over_21", "dmv.example");
    let payload =
        liblinkkeys::generated::encode_remove_trusted_issuer_request(&RemoveTrustedIssuerRequest {
            claim_type: "age_over_21".to_string(),
            issuer_domain: "dmv.example".to_string(),
        });

    let nonadmin_key = make_caller(&pool, false);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "remove-trusted-issuer",
        payload.clone(),
        Some(&nonadmin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a caller without admin must be forbidden");
    assert_eq!(
        pool.list_all_trusted_issuers().unwrap().len(),
        1,
        "forbidden call must not have deleted anything"
    );

    let admin_key = make_caller(&pool, true);
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "remove-trusted-issuer",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0, "an admin caller must succeed");
    let resp = liblinkkeys::generated::decode_remove_trusted_issuer_response(&body)
        .expect("decode RemoveTrustedIssuerResponse");
    assert!(resp.success);
    assert!(
        pool.list_all_trusted_issuers().unwrap().is_empty(),
        "the trusted issuer must be gone"
    );
}

// ---------------------------------------------------------------------
// list-release-rules
// ---------------------------------------------------------------------

#[test]
fn list_release_rules_requires_admin() {
    let pool = setup();
    create_release_rule(&pool, "*", "email", "forced_allow");
    let payload = liblinkkeys::generated::encode_empty_request(&EmptyRequest {});

    let nonadmin_key = make_caller(&pool, false);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "list-release-rules",
        payload.clone(),
        Some(&nonadmin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a caller without admin must be forbidden");

    let admin_key = make_caller(&pool, true);
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "list-release-rules",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0, "an admin caller must succeed");
    let resp = liblinkkeys::generated::decode_list_release_rules_response(&body)
        .expect("decode ListReleaseRulesResponse");
    assert_eq!(resp.release_rules.len(), 1);
    assert_eq!(resp.release_rules[0].audience, "*");
    assert_eq!(resp.release_rules[0].claim_type, "email");
    assert_eq!(resp.release_rules[0].disposition, "forced_allow");
}

// ---------------------------------------------------------------------
// set-release-rule
// ---------------------------------------------------------------------

#[test]
fn set_release_rule_requires_admin() {
    let pool = setup();
    let payload = liblinkkeys::generated::encode_set_release_rule_request(&SetReleaseRuleRequest {
        audience: "rp.example".to_string(),
        claim_type: "email".to_string(),
        disposition: "forced_deny".to_string(),
    });

    let nonadmin_key = make_caller(&pool, false);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "set-release-rule",
        payload.clone(),
        Some(&nonadmin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a caller without admin must be forbidden");
    assert!(
        pool.list_release_policies().unwrap().is_empty(),
        "forbidden call must not have written anything"
    );

    let admin_key = make_caller(&pool, true);
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "set-release-rule",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0, "an admin caller must succeed");
    let resp = liblinkkeys::generated::decode_set_release_rule_response(&body)
        .expect("decode SetReleaseRuleResponse");
    assert_eq!(resp.release_rule.audience, "rp.example");
    assert_eq!(resp.release_rule.claim_type, "email");
    assert_eq!(resp.release_rule.disposition, "forced_deny");
}

#[test]
fn set_then_list_release_rule_round_trips() {
    let pool = setup();
    let admin_key = make_caller(&pool, true);

    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "set-release-rule",
        liblinkkeys::generated::encode_set_release_rule_request(&SetReleaseRuleRequest {
            audience: "rp.example".to_string(),
            claim_type: "handle".to_string(),
            disposition: "forced_allow".to_string(),
        }),
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);

    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "list-release-rules",
        liblinkkeys::generated::encode_empty_request(&EmptyRequest {}),
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);
    let resp = liblinkkeys::generated::decode_list_release_rules_response(&body)
        .expect("decode ListReleaseRulesResponse");
    let entry = resp
        .release_rules
        .iter()
        .find(|r| r.audience == "rp.example" && r.claim_type == "handle")
        .expect("release rule present after set");
    assert_eq!(entry.disposition, "forced_allow");
}

/// `set-release-rule` is an upsert keyed on (audience, claim_type): setting
/// the same pair twice with a different disposition must update the one
/// row, not create a second.
#[test]
fn set_release_rule_upserts_existing() {
    let pool = setup();
    let admin_key = make_caller(&pool, true);

    for disposition in ["forced_allow", "forced_deny"] {
        let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
            "Admin",
            "set-release-rule",
            liblinkkeys::generated::encode_set_release_rule_request(&SetReleaseRuleRequest {
                audience: "*".to_string(),
                claim_type: "role".to_string(),
                disposition: disposition.to_string(),
            }),
            Some(&admin_key),
            &pool,
            None,
        );
        assert_eq!(status, 0);
    }

    let matches: Vec<_> = pool
        .list_release_policies()
        .unwrap()
        .into_iter()
        .filter(|r| r.audience == "*" && r.claim_type == "role")
        .collect();
    assert_eq!(matches.len(), 1, "upsert must not create a duplicate row");
    assert_eq!(matches[0].disposition, "forced_deny");
}

#[test]
fn set_release_rule_rejects_invalid_disposition() {
    let pool = setup();
    let admin_key = make_caller(&pool, true);
    let payload = liblinkkeys::generated::encode_set_release_rule_request(&SetReleaseRuleRequest {
        audience: "*".to_string(),
        claim_type: "email".to_string(),
        disposition: "maybe".to_string(),
    });

    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "set-release-rule",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "an invalid disposition must be rejected");
    assert!(
        pool.list_release_policies().unwrap().is_empty(),
        "a rejected set-release-rule call must not persist anything"
    );
}

// ---------------------------------------------------------------------
// remove-release-rule
// ---------------------------------------------------------------------

#[test]
fn remove_release_rule_requires_admin_and_deletes() {
    let pool = setup();
    create_release_rule(&pool, "*", "email", "forced_allow");
    let payload =
        liblinkkeys::generated::encode_remove_release_rule_request(&RemoveReleaseRuleRequest {
            audience: "*".to_string(),
            claim_type: "email".to_string(),
        });

    let nonadmin_key = make_caller(&pool, false);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "remove-release-rule",
        payload.clone(),
        Some(&nonadmin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a caller without admin must be forbidden");
    assert_eq!(
        pool.list_release_policies().unwrap().len(),
        1,
        "forbidden call must not have deleted anything"
    );

    let admin_key = make_caller(&pool, true);
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "remove-release-rule",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0, "an admin caller must succeed");
    let resp = liblinkkeys::generated::decode_remove_release_rule_response(&body)
        .expect("decode RemoveReleaseRuleResponse");
    assert!(resp.success);
    assert!(
        pool.list_release_policies().unwrap().is_empty(),
        "the release rule must be gone"
    );
}
