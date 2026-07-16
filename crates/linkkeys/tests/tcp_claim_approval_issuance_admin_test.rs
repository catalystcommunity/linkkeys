//! Tests for the claim-approval queue and admin-issued-attestation surface on
//! the `Admin` TCP service (policy-admin web UI parity, slice 3):
//! `list-pending-claim-approvals`, `approve-claim`, `reject-claim`,
//! `admin-issue-attestation`.
//!
//! The first three are a second CSIL-RPC entry point onto the exact same
//! DB/service calls `web/policy_admin_ui.rs`'s `list_pending_approvals`/
//! `approve`/`reject` handlers make (`DbPool::list_pending_approvals`,
//! `services::admin::approve_claim`/`reject_claim`), so an external
//! controller holding an admin-relation API key can work the approval queue
//! without the web UI.
//!
//! `admin-issue-attestation` reuses the same signing call
//! `web/policy_admin_ui.rs`'s `issue_sign` makes
//! (`services::attestation::issue_attested_claim`) to sign+store an attested
//! claim directly for one of this domain's own users — see the CSIL doc
//! comment on `AdminIssueAttestationRequest` for how this is scoped
//! differently from `Rp/issue-attestation` and `Attestation/deposit-claim`.
//!
//! Every op requires the `admin` relation (explicit `required_relation_for_op`
//! arm, not the `_ =>` fallthrough, mirroring `tcp_policy_issuer_release_admin_test.rs`)
//! — each test below confirms a non-admin caller is forbidden before
//! confirming an admin succeeds.

mod common;

use common::data_factory::{
    create_auth_credential, create_domain_key, create_pending_approval, create_relation,
    create_user, DataMap,
};
use liblinkkeys::generated::types::{
    AdminIssueAttestationRequest, ApproveClaimRequest, EmptyRequest, RejectClaimRequest,
};
use linkkeys::services::auth;

const TEST_DOMAIN: &str = "test.com";

fn setup() -> linkkeys::db::DbPool {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    let pool = common::create_test_pool();
    create_domain_key(&pool);
    pool
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
// list-pending-claim-approvals
// ---------------------------------------------------------------------

#[test]
fn list_pending_claim_approvals_requires_admin() {
    let pool = setup();
    let subject = create_user(&pool, &DataMap::new());
    create_pending_approval(&pool, &subject.id, "display_name", b"Ada");
    let payload = liblinkkeys::generated::encode_empty_request(&EmptyRequest {});

    let nonadmin_key = make_caller(&pool, false);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "list-pending-claim-approvals",
        payload.clone(),
        Some(&nonadmin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a caller without admin must be forbidden");

    let admin_key = make_caller(&pool, true);
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "list-pending-claim-approvals",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0, "an admin caller must succeed");
    let resp = liblinkkeys::generated::decode_list_pending_claim_approvals_response(&body)
        .expect("decode ListPendingClaimApprovalsResponse");
    assert_eq!(resp.approvals.len(), 1);
    assert_eq!(resp.approvals[0].user_id, subject.id);
    assert_eq!(resp.approvals[0].claim_type, "display_name");
    assert_eq!(resp.approvals[0].claim_value, b"Ada");
    assert_eq!(resp.approvals[0].status, "pending");
}

// ---------------------------------------------------------------------
// approve-claim
// ---------------------------------------------------------------------

#[test]
fn approve_claim_requires_admin() {
    let pool = setup();
    let subject = create_user(&pool, &DataMap::new());
    let approval_id = create_pending_approval(&pool, &subject.id, "display_name", b"Ada");
    let payload = liblinkkeys::generated::encode_approve_claim_request(&ApproveClaimRequest {
        approval_id: approval_id.clone(),
    });

    let nonadmin_key = make_caller(&pool, false);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "approve-claim",
        payload.clone(),
        Some(&nonadmin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a caller without admin must be forbidden");
    assert_eq!(
        pool.list_pending_approvals().unwrap().len(),
        1,
        "forbidden call must not have resolved the approval"
    );
    assert!(
        pool.list_active_claims(&subject.id)
            .unwrap()
            .iter()
            .all(|c| c.claim_type != "display_name"),
        "forbidden call must not have signed/stored anything"
    );

    let admin_key = make_caller(&pool, true);
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "approve-claim",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0, "an admin caller must succeed");
    let resp = liblinkkeys::generated::decode_approve_claim_response(&body)
        .expect("decode ApproveClaimResponse");
    assert!(resp.success);
}

#[test]
fn approve_claim_moves_it_out_of_the_queue_and_signs_it() {
    let pool = setup();
    let subject = create_user(&pool, &DataMap::new());
    let approval_id = create_pending_approval(&pool, &subject.id, "display_name", b"Ada");
    let admin_key = make_caller(&pool, true);

    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "approve-claim",
        liblinkkeys::generated::encode_approve_claim_request(&ApproveClaimRequest { approval_id }),
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);

    // Gone from the pending queue...
    assert!(
        pool.list_pending_approvals().unwrap().is_empty(),
        "approved entry must no longer be pending"
    );
    // ...and signed + stored for the subject.
    let claims = pool.list_active_claims(&subject.id).unwrap();
    let dn = claims
        .iter()
        .find(|c| c.claim_type == "display_name")
        .expect("approved claim must be stored");
    assert_eq!(dn.claim_value, b"Ada");
    assert!(
        !dn.signatures.is_empty(),
        "an approved claim must be signed with the domain's active keys"
    );
}

#[test]
fn approve_claim_rejects_unknown_id() {
    let pool = setup();
    let admin_key = make_caller(&pool, true);
    let payload = liblinkkeys::generated::encode_approve_claim_request(&ApproveClaimRequest {
        approval_id: uuid::Uuid::now_v7().to_string(),
    });

    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "approve-claim",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "approving a nonexistent id must fail");
}

// ---------------------------------------------------------------------
// reject-claim
// ---------------------------------------------------------------------

#[test]
fn reject_claim_requires_admin() {
    let pool = setup();
    let subject = create_user(&pool, &DataMap::new());
    let approval_id = create_pending_approval(&pool, &subject.id, "display_name", b"Ada");
    let payload = liblinkkeys::generated::encode_reject_claim_request(&RejectClaimRequest {
        approval_id: approval_id.clone(),
    });

    let nonadmin_key = make_caller(&pool, false);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "reject-claim",
        payload.clone(),
        Some(&nonadmin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a caller without admin must be forbidden");
    assert_eq!(
        pool.list_pending_approvals().unwrap().len(),
        1,
        "forbidden call must not have resolved the approval"
    );

    let admin_key = make_caller(&pool, true);
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "reject-claim",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0, "an admin caller must succeed");
    let resp = liblinkkeys::generated::decode_reject_claim_response(&body)
        .expect("decode RejectClaimResponse");
    assert!(resp.success);
}

#[test]
fn reject_claim_moves_it_out_of_the_queue_without_signing_it() {
    let pool = setup();
    let subject = create_user(&pool, &DataMap::new());
    let approval_id = create_pending_approval(&pool, &subject.id, "display_name", b"Ada");
    let admin_key = make_caller(&pool, true);

    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "reject-claim",
        liblinkkeys::generated::encode_reject_claim_request(&RejectClaimRequest { approval_id }),
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);

    assert!(
        pool.list_pending_approvals().unwrap().is_empty(),
        "rejected entry must no longer be pending"
    );
    assert!(
        pool.list_active_claims(&subject.id)
            .unwrap()
            .iter()
            .all(|c| c.claim_type != "display_name"),
        "a rejected claim must never be signed/stored"
    );
}

// ---------------------------------------------------------------------
// admin-issue-attestation
// ---------------------------------------------------------------------

#[test]
fn admin_issue_attestation_requires_admin() {
    let pool = setup();
    let subject = create_user(&pool, &DataMap::new());
    let payload = liblinkkeys::generated::encode_admin_issue_attestation_request(
        &AdminIssueAttestationRequest {
            user_id: subject.id.clone(),
            claim_type: "age_over_21".to_string(),
            claim_value: b"true".to_vec(),
        },
    );

    let nonadmin_key = make_caller(&pool, false);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "admin-issue-attestation",
        payload.clone(),
        Some(&nonadmin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a caller without admin must be forbidden");
    assert!(
        pool.list_active_claims(&subject.id).unwrap().is_empty(),
        "forbidden call must not have signed/stored anything"
    );

    let admin_key = make_caller(&pool, true);
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "admin-issue-attestation",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0, "an admin caller must succeed");
    let resp = liblinkkeys::generated::decode_admin_issue_attestation_response(&body)
        .expect("decode AdminIssueAttestationResponse");
    assert_eq!(resp.claim.claim_type, "age_over_21");
    assert_eq!(resp.claim.claim_value, b"true");
    assert_eq!(resp.claim.user_id, subject.id);
    assert!(
        !resp.claim.signatures.is_empty(),
        "an issued attestation must be signed with the domain's active keys"
    );
}

#[test]
fn admin_issue_attestation_stores_a_verifiable_signed_claim() {
    let pool = setup();
    let subject = create_user(&pool, &DataMap::new());
    let admin_key = make_caller(&pool, true);

    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "admin-issue-attestation",
        liblinkkeys::generated::encode_admin_issue_attestation_request(
            &AdminIssueAttestationRequest {
                user_id: subject.id.clone(),
                claim_type: "age_over_21".to_string(),
                claim_value: b"true".to_vec(),
            },
        ),
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);
    let resp = liblinkkeys::generated::decode_admin_issue_attestation_response(&body)
        .expect("decode AdminIssueAttestationResponse");

    // Actually stored for the subject...
    let claims = pool.list_active_claims(&subject.id).unwrap();
    let stored = claims
        .iter()
        .find(|c| c.claim_type == "age_over_21")
        .expect("issued attestation must be stored");
    assert_eq!(stored.claim_value, b"true");

    // ...and the signature verifies against our own (active) domain keys.
    let stored_claim: liblinkkeys::generated::types::Claim = stored.into();
    let v = linkkeys::services::attestation::verify_stored_claim(&pool, &stored_claim);
    assert!(v.verified, "the issued attestation must verify");
    assert_eq!(v.signed_by, vec![TEST_DOMAIN.to_string()]);

    // The response's own claim round-trips through the same verification.
    let v2 = linkkeys::services::attestation::verify_stored_claim(&pool, &resp.claim);
    assert!(v2.verified);
}

#[test]
fn admin_issue_attestation_rejects_unknown_user() {
    let pool = setup();
    let admin_key = make_caller(&pool, true);
    let payload = liblinkkeys::generated::encode_admin_issue_attestation_request(
        &AdminIssueAttestationRequest {
            user_id: uuid::Uuid::now_v7().to_string(),
            claim_type: "age_over_21".to_string(),
            claim_value: b"true".to_vec(),
        },
    );

    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "admin-issue-attestation",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "issuing for a nonexistent user must fail");
}
