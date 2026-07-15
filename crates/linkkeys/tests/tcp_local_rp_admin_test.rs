//! Tests for the DNS-less local RP admin surface on the `Admin` TCP service
//! (dns-less-local-rp-design.md, Phase 7): `list-local-rps`, `get-local-rp`,
//! `approve-local-rp`, `deny-local-rp`, `revoke-local-rp`.
//!
//! Every op requires the `admin` relation (Wire Precision "Service and
//! authorization placement": explicit `required_relation_for_op` arm, not the
//! `_ =>` fallthrough) — each test below confirms a non-admin caller is
//! forbidden before confirming an admin succeeds, mirroring the pattern in
//! `admin_service_test.rs::recheck_pins_requires_admin_and_tcp_carrier`.

mod common;

use std::collections::HashMap;

use common::data_factory::{
    create_auth_credential, create_local_rp, create_local_rp_claim_ticket, create_relation,
    create_user, DataMap,
};
use liblinkkeys::generated::types::{
    ApproveLocalRpRequest, DenyLocalRpRequest, GetLocalRpPolicyRequest, GetLocalRpRequest,
    ListLocalRpsRequest, RevokeLocalRpRequest, SetLocalRpPolicyRequest,
};
use linkkeys::services::auth;
use serde_json::Value;

const TEST_DOMAIN: &str = "test.com";

fn setup() -> linkkeys::db::DbPool {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    common::create_test_pool()
}

fn status_map(status: &str) -> DataMap {
    let mut m = HashMap::new();
    m.insert("status".to_string(), Value::String(status.to_string()));
    m
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
// list-local-rps
// ---------------------------------------------------------------------

#[test]
fn list_local_rps_requires_admin() {
    let pool = setup();
    create_local_rp(&pool, &status_map("pending"));
    let payload = liblinkkeys::generated::encode_list_local_rps_request(&ListLocalRpsRequest {
        offset: None,
        limit: None,
        status: None,
    });

    let nonadmin_key = make_caller(&pool, false);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "list-local-rps",
        payload.clone(),
        Some(&nonadmin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a caller without admin must be forbidden");

    let admin_key = make_caller(&pool, true);
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "list-local-rps",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0, "an admin caller must succeed");
    let resp = liblinkkeys::generated::decode_list_local_rps_response(&body)
        .expect("decode ListLocalRpsResponse");
    assert_eq!(resp.local_rps.len(), 1);
}

#[test]
fn list_local_rps_filters_by_status() {
    let pool = setup();
    create_local_rp(&pool, &status_map("pending"));
    create_local_rp(&pool, &status_map("pending"));
    create_local_rp(&pool, &status_map("approved"));
    let admin_key = make_caller(&pool, true);

    let payload = liblinkkeys::generated::encode_list_local_rps_request(&ListLocalRpsRequest {
        offset: None,
        limit: None,
        status: Some("pending".to_string()),
    });
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "list-local-rps",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);
    let resp = liblinkkeys::generated::decode_list_local_rps_response(&body)
        .expect("decode ListLocalRpsResponse");
    assert_eq!(resp.local_rps.len(), 2);
    assert!(resp.local_rps.iter().all(|rp| rp.status == "pending"));
}

#[test]
fn list_local_rps_paginates_with_offset_and_limit() {
    let pool = setup();
    for _ in 0..5 {
        create_local_rp(&pool, &status_map("pending"));
    }
    let admin_key = make_caller(&pool, true);

    let payload = liblinkkeys::generated::encode_list_local_rps_request(&ListLocalRpsRequest {
        offset: Some(1),
        limit: Some(2),
        status: Some("pending".to_string()),
    });
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "list-local-rps",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);
    let resp = liblinkkeys::generated::decode_list_local_rps_response(&body)
        .expect("decode ListLocalRpsResponse");
    assert_eq!(resp.local_rps.len(), 2, "limit=2 must cap the page size");
}

// ---------------------------------------------------------------------
// get-local-rp
// ---------------------------------------------------------------------

#[test]
fn get_local_rp_requires_admin() {
    let pool = setup();
    let rp = create_local_rp(&pool, &status_map("pending"));
    let payload = liblinkkeys::generated::encode_get_local_rp_request(&GetLocalRpRequest {
        fingerprint: rp.fingerprint.clone(),
    });

    let nonadmin_key = make_caller(&pool, false);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "get-local-rp",
        payload.clone(),
        Some(&nonadmin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a caller without admin must be forbidden");

    let admin_key = make_caller(&pool, true);
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "get-local-rp",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);
    let resp = liblinkkeys::generated::decode_get_local_rp_response(&body)
        .expect("decode GetLocalRpResponse");
    assert_eq!(resp.local_rp.fingerprint, rp.fingerprint);
    assert_eq!(resp.local_rp.app_name, rp.app_name);
    assert_eq!(resp.local_rp.status, "pending");
    assert_eq!(resp.local_rp.created_at, rp.created_at);
}

#[test]
fn get_local_rp_unknown_fingerprint_errors() {
    let pool = setup();
    let admin_key = make_caller(&pool, true);
    let payload = liblinkkeys::generated::encode_get_local_rp_request(&GetLocalRpRequest {
        fingerprint: "0000000000000000000000000000000000000000000000000000000000000".to_string(),
    });
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "get-local-rp",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "an unknown fingerprint must error");
}

// ---------------------------------------------------------------------
// approve-local-rp
// ---------------------------------------------------------------------

#[test]
fn approve_local_rp_requires_admin_and_transitions_pending_to_approved() {
    let pool = setup();
    let rp = create_local_rp(&pool, &status_map("pending"));
    let payload = liblinkkeys::generated::encode_approve_local_rp_request(&ApproveLocalRpRequest {
        fingerprint: rp.fingerprint.clone(),
        admin_notes: Some("looks legit".to_string()),
    });

    let nonadmin_key = make_caller(&pool, false);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "approve-local-rp",
        payload.clone(),
        Some(&nonadmin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a caller without admin must be forbidden");

    let admin_key = make_caller(&pool, true);
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "approve-local-rp",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);
    let resp = liblinkkeys::generated::decode_approve_local_rp_response(&body)
        .expect("decode ApproveLocalRpResponse");
    assert_eq!(resp.local_rp.status, "approved");
    assert_eq!(resp.local_rp.admin_notes.as_deref(), Some("looks legit"));
}

// ---------------------------------------------------------------------
// deny-local-rp
// ---------------------------------------------------------------------

#[test]
fn deny_local_rp_requires_admin_and_transitions_pending_to_denied() {
    let pool = setup();
    let rp = create_local_rp(&pool, &status_map("pending"));
    let payload = liblinkkeys::generated::encode_deny_local_rp_request(&DenyLocalRpRequest {
        fingerprint: rp.fingerprint.clone(),
        admin_notes: None,
    });

    let nonadmin_key = make_caller(&pool, false);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "deny-local-rp",
        payload.clone(),
        Some(&nonadmin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a caller without admin must be forbidden");

    let admin_key = make_caller(&pool, true);
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "deny-local-rp",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);
    let resp = liblinkkeys::generated::decode_deny_local_rp_response(&body)
        .expect("decode DenyLocalRpResponse");
    assert_eq!(resp.local_rp.status, "denied");
}

#[test]
fn deny_local_rp_from_approved_fails_cleanly() {
    let pool = setup();
    let rp = create_local_rp(&pool, &status_map("approved"));
    let admin_key = make_caller(&pool, true);
    let payload = liblinkkeys::generated::encode_deny_local_rp_request(&DenyLocalRpRequest {
        fingerprint: rp.fingerprint.clone(),
        admin_notes: None,
    });
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "deny-local-rp",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_ne!(
        status, 0,
        "deny is only valid from pending; an approved RP must fail cleanly"
    );
    // The row must be untouched by the rejected transition.
    let still = pool
        .find_local_rp(&rp.fingerprint)
        .unwrap()
        .expect("rp still exists");
    assert_eq!(still.status, "approved");
}

// ---------------------------------------------------------------------
// revoke-local-rp
// ---------------------------------------------------------------------

#[test]
fn revoke_local_rp_requires_admin_and_transitions_approved_to_revoked() {
    let pool = setup();
    let rp = create_local_rp(&pool, &status_map("approved"));
    let payload = liblinkkeys::generated::encode_revoke_local_rp_request(&RevokeLocalRpRequest {
        fingerprint: rp.fingerprint.clone(),
        admin_notes: Some("compromised".to_string()),
    });

    let nonadmin_key = make_caller(&pool, false);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "revoke-local-rp",
        payload.clone(),
        Some(&nonadmin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a caller without admin must be forbidden");

    let admin_key = make_caller(&pool, true);
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "revoke-local-rp",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);
    let resp = liblinkkeys::generated::decode_revoke_local_rp_response(&body)
        .expect("decode RevokeLocalRpResponse");
    assert_eq!(resp.local_rp.status, "revoked");
    assert_eq!(resp.local_rp.admin_notes.as_deref(), Some("compromised"));
}

#[test]
fn revoke_local_rp_from_pending_fails_cleanly() {
    let pool = setup();
    let rp = create_local_rp(&pool, &status_map("pending"));
    let admin_key = make_caller(&pool, true);
    let payload = liblinkkeys::generated::encode_revoke_local_rp_request(&RevokeLocalRpRequest {
        fingerprint: rp.fingerprint.clone(),
        admin_notes: None,
    });
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "revoke-local-rp",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_ne!(
        status, 0,
        "revoke is only valid from approved; a pending RP must fail cleanly"
    );
    let still = pool
        .find_local_rp(&rp.fingerprint)
        .unwrap()
        .expect("rp still exists");
    assert_eq!(
        still.status, "pending",
        "the rejected transition must not mutate the row"
    );
}

/// Phase 7: revoking a local RP must also delete its outstanding claim
/// tickets (belt-and-suspenders on top of `redeem_ticket`'s own
/// approval-status check).
#[test]
fn revoke_local_rp_deletes_outstanding_tickets() {
    let pool = setup();
    let rp = create_local_rp(&pool, &status_map("approved"));
    let mut ticket_overrides = DataMap::new();
    ticket_overrides.insert(
        "fingerprint".to_string(),
        Value::String(rp.fingerprint.clone()),
    );
    let ticket = create_local_rp_claim_ticket(&pool, &ticket_overrides);
    assert!(
        pool.find_local_rp_claim_ticket(&ticket.ticket_hash)
            .unwrap()
            .is_some(),
        "ticket exists before revoke"
    );

    let admin_key = make_caller(&pool, true);
    let payload = liblinkkeys::generated::encode_revoke_local_rp_request(&RevokeLocalRpRequest {
        fingerprint: rp.fingerprint.clone(),
        admin_notes: None,
    });
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "revoke-local-rp",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);

    assert!(
        pool.find_local_rp_claim_ticket(&ticket.ticket_hash)
            .unwrap()
            .is_none(),
        "revoking the RP must delete its outstanding claim tickets"
    );
}

#[test]
fn revoke_local_rp_unknown_fingerprint_errors() {
    let pool = setup();
    let admin_key = make_caller(&pool, true);
    let payload = liblinkkeys::generated::encode_revoke_local_rp_request(&RevokeLocalRpRequest {
        fingerprint: "unknown-fingerprint".to_string(),
        admin_notes: None,
    });
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "revoke-local-rp",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "an unknown fingerprint must error");
}

// ---------------------------------------------------------------------
// get-local-rp-policy / set-local-rp-policy
// (dns-less-local-rp-design.md, "Server Work"/"CSIL Work": "Domain policy
// APIs/CLI/config to set local RP mode" — surfaces
// `DbPool::set_local_rp_domain_policy`, previously exercised only by
// `crates/linkkeys/src/db/local_rp.rs`'s own tests.)
// ---------------------------------------------------------------------

fn get_policy_payload() -> Vec<u8> {
    liblinkkeys::generated::encode_get_local_rp_policy_request(&GetLocalRpPolicyRequest {})
}

fn set_policy_payload(policy: &str) -> Vec<u8> {
    liblinkkeys::generated::encode_set_local_rp_policy_request(&SetLocalRpPolicyRequest {
        policy: policy.to_string(),
    })
}

#[test]
fn get_local_rp_policy_requires_admin() {
    let pool = setup();

    let nonadmin_key = make_caller(&pool, false);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "get-local-rp-policy",
        get_policy_payload(),
        Some(&nonadmin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a caller without admin must be forbidden");

    let admin_key = make_caller(&pool, true);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "get-local-rp-policy",
        get_policy_payload(),
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0, "an admin caller must succeed");
}

#[test]
fn get_local_rp_policy_defaults_to_admin_approval_required_when_unset() {
    let pool = setup();
    let admin_key = make_caller(&pool, true);

    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "get-local-rp-policy",
        get_policy_payload(),
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);
    let resp = liblinkkeys::generated::decode_get_local_rp_policy_response(&body)
        .expect("decode GetLocalRpPolicyResponse");
    assert_eq!(
        resp.policy,
        linkkeys::db::local_rp::DEFAULT_POLICY,
        "an unset domain must report the design doc's default policy"
    );
}

#[test]
fn set_local_rp_policy_requires_admin() {
    let pool = setup();
    let payload = set_policy_payload(linkkeys::db::local_rp::POLICY_DISABLED);

    let nonadmin_key = make_caller(&pool, false);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "set-local-rp-policy",
        payload.clone(),
        Some(&nonadmin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a caller without admin must be forbidden");

    let admin_key = make_caller(&pool, true);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "set-local-rp-policy",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0, "an admin caller must succeed");
}

#[test]
fn set_then_get_local_rp_policy_round_trips() {
    let pool = setup();
    let admin_key = make_caller(&pool, true);

    for policy in [
        linkkeys::db::local_rp::POLICY_DISABLED,
        linkkeys::db::local_rp::POLICY_ALLOW_BY_DEFAULT,
        linkkeys::db::local_rp::POLICY_ADMIN_APPROVAL_REQUIRED,
    ] {
        let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
            "Admin",
            "set-local-rp-policy",
            set_policy_payload(policy),
            Some(&admin_key),
            &pool,
            None,
        );
        assert_eq!(status, 0, "set-local-rp-policy({}) must succeed", policy);
        let set_resp = liblinkkeys::generated::decode_set_local_rp_policy_response(&body)
            .expect("decode SetLocalRpPolicyResponse");
        assert_eq!(set_resp.policy, policy);

        let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
            "Admin",
            "get-local-rp-policy",
            get_policy_payload(),
            Some(&admin_key),
            &pool,
            None,
        );
        assert_eq!(status, 0);
        let get_resp = liblinkkeys::generated::decode_get_local_rp_policy_response(&body)
            .expect("decode GetLocalRpPolicyResponse");
        assert_eq!(
            get_resp.policy, policy,
            "get must round-trip the just-set policy"
        );
    }
}

#[test]
fn set_local_rp_policy_rejects_invalid_vocabulary() {
    let pool = setup();
    let admin_key = make_caller(&pool, true);

    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "set-local-rp-policy",
        set_policy_payload("sure-why-not"),
        Some(&admin_key),
        &pool,
        None,
    );
    assert_ne!(
        status, 0,
        "a value outside the recognised vocabulary must be rejected"
    );

    // The rejected write must not have created/changed a stored row: the
    // effective policy is still the unset-default.
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "get-local-rp-policy",
        get_policy_payload(),
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);
    let resp = liblinkkeys::generated::decode_get_local_rp_policy_response(&body)
        .expect("decode GetLocalRpPolicyResponse");
    assert_eq!(resp.policy, linkkeys::db::local_rp::DEFAULT_POLICY);
}
