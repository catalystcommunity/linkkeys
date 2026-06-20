// End-to-end-ish tests for the claim-signing policy registry and user
// self-service, against a real DB in a rolled-back transaction (DataUtils
// pattern). The pure set/sign decision is unit-tested in
// `liblinkkeys::claim_policy`; here we exercise the storage + signing adapter.

mod common;

use common::data_factory::DataMap;
use common::{create_test_pool, data_factory};
use linkkeys::services::self_service::{self, SetOutcome};

fn setup() -> (linkkeys::db::DbPool, String) {
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    std::env::set_var("DOMAIN_NAME", "test.com");
    let pool = create_test_pool();
    data_factory::create_domain_key(&pool);
    pool.seed_default_policies().expect("seed policies");
    let user = data_factory::create_user(&pool, &DataMap::new());
    (pool, user.id)
}

#[test]
fn lane_a_self_set_is_signed() {
    let (pool, uid) = setup();
    let outcome = self_service::set_my_claim(&pool, &uid, "display_name", b"Ada").unwrap();
    assert_eq!(outcome, SetOutcome::Signed);

    let claims = pool.list_active_claims(&uid).unwrap();
    let dn = claims
        .iter()
        .find(|c| c.claim_type == "display_name")
        .expect("display_name stored");
    assert_eq!(dn.claim_value, b"Ada");
    assert!(
        !dn.signatures.is_empty(),
        "lane A value must carry a signature"
    );
}

#[test]
fn auto_sign_off_stores_unsigned() {
    let (pool, uid) = setup();
    self_service::set_signing_pref(&pool, &uid, "display_name", false).unwrap();
    let outcome = self_service::set_my_claim(&pool, &uid, "display_name", b"Ada").unwrap();
    assert_eq!(outcome, SetOutcome::StoredUnsigned);

    let claims = pool.list_active_claims(&uid).unwrap();
    let dn = claims
        .iter()
        .find(|c| c.claim_type == "display_name")
        .unwrap();
    assert!(
        dn.signatures.is_empty(),
        "auto-sign off must store unsigned"
    );
}

#[test]
fn set_replaces_prior_value() {
    let (pool, uid) = setup();
    self_service::set_my_claim(&pool, &uid, "display_name", b"First").unwrap();
    self_service::set_my_claim(&pool, &uid, "display_name", b"Second").unwrap();
    let active: Vec<_> = pool
        .list_active_claims(&uid)
        .unwrap()
        .into_iter()
        .filter(|c| c.claim_type == "display_name")
        .collect();
    assert_eq!(active.len(), 1, "only one active value per type");
    assert_eq!(active[0].claim_value, b"Second");
}

#[test]
fn unknown_claim_type_rejected() {
    let (pool, uid) = setup();
    assert!(self_service::set_my_claim(&pool, &uid, "not_a_real_type", b"x").is_err());
}

#[test]
fn invalid_value_rejected() {
    let (pool, uid) = setup();
    // `website` requires a URL value.
    assert!(self_service::set_my_claim(&pool, &uid, "website", b"not a url").is_err());
    assert!(self_service::set_my_claim(&pool, &uid, "website", b"https://example.com").is_ok());
}

#[test]
fn email_set_requires_verification() {
    let (pool, uid) = setup();
    let outcome = self_service::set_my_claim(&pool, &uid, "email", b"a@b.com").unwrap();
    assert_eq!(outcome, SetOutcome::VerificationRequired);
    // Nothing signed yet — verification hasn't happened.
    let claims = pool.list_active_claims(&uid).unwrap();
    assert!(claims.iter().all(|c| c.claim_type != "email"));
}

#[test]
fn user_release_prefs_apply_to_any_audience() {
    let (pool, uid) = setup();
    pool.add_user_release_pref(&uid, "*", "handle").unwrap();
    let allows = pool
        .list_user_release_allows(&uid, "anything.example")
        .unwrap();
    assert!(allows.contains(&"handle".to_string()));

    pool.remove_user_release_pref(&uid, "*", "handle").unwrap();
    let allows = pool
        .list_user_release_allows(&uid, "anything.example")
        .unwrap();
    assert!(!allows.contains(&"handle".to_string()));
}

#[test]
fn release_policy_audience_plus_global() {
    let (pool, uid) = setup();
    let _ = uid;
    pool.upsert_release_policy("*", "email", "forced_deny")
        .unwrap();
    pool.upsert_release_policy("app.example", "handle", "forced_allow")
        .unwrap();
    let rows = pool
        .list_release_policies_for_audience("app.example")
        .unwrap();
    assert!(rows
        .iter()
        .any(|r| r.claim_type == "email" && r.disposition == "forced_deny"));
    assert!(rows
        .iter()
        .any(|r| r.claim_type == "handle" && r.disposition == "forced_allow"));
    // A different audience sees only the global rule.
    let other = pool
        .list_release_policies_for_audience("other.example")
        .unwrap();
    assert!(other.iter().any(|r| r.claim_type == "email"));
    assert!(!other.iter().any(|r| r.claim_type == "handle"));
}

#[test]
fn registry_seed_is_idempotent() {
    let (pool, _uid) = setup();
    let before = pool.list_claim_policies().unwrap().len();
    pool.seed_default_policies().unwrap();
    let after = pool.list_claim_policies().unwrap().len();
    assert_eq!(before, after, "re-seeding must not duplicate");
    assert!(before >= 8, "starter registry present");
}

#[test]
fn approval_queue_round_trip() {
    let (pool, uid) = setup();
    // Make display_name require approval, then a user set should queue.
    let mut p = pool.find_claim_policy("display_name").unwrap().unwrap();
    p.requires_approval = true;
    pool.upsert_claim_policy(p).unwrap();

    let outcome = self_service::set_my_claim(&pool, &uid, "display_name", b"Ada").unwrap();
    assert_eq!(outcome, SetOutcome::Queued);
    let pending = pool.list_pending_approvals().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].claim_type, "display_name");
}
