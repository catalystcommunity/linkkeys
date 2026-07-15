// Tests for DNS-less local RP identity persistence (Phase 4 of
// dns-less-local-rp-design.md): domain policy storage, the local RP approval
// registry, the pending-queue guard, the status-transition matrix, and
// claim-get ticket lifecycle. DataUtils pattern: real DB, rolled-back
// transaction per test (see common/mod.rs).

mod common;

use chrono::{Duration, Utc};
use common::create_test_pool;
use common::data_factory::{self, DataMap};
use linkkeys::db::local_rp as db;
use linkkeys::services::local_rp::{
    self, PendingAttemptError, PendingAttemptOutcome, StatusTransitionError, TicketRedeemError,
};

fn setup() -> linkkeys::db::DbPool {
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    std::env::set_var("DOMAIN_NAME", "test.com");
    create_test_pool()
}

// ---------------------------------------------------------------------
// Factory sanity
// ---------------------------------------------------------------------

#[test]
fn factory_creates_local_rp_with_defaults() {
    let pool = setup();
    let rp = data_factory::create_local_rp(&pool, &DataMap::new());
    assert_eq!(rp.status, "pending");
    assert_eq!(rp.fingerprint.len(), 64, "fingerprint is sha256 hex");
    assert!(rp.local_domain_hint.is_none());

    let found = pool
        .find_local_rp(&rp.fingerprint)
        .unwrap()
        .expect("just-created local RP should be findable");
    assert_eq!(found.app_name, rp.app_name);
}

#[test]
fn factory_creates_local_rp_claim_ticket_with_defaults() {
    let pool = setup();
    let ticket = data_factory::create_local_rp_claim_ticket(&pool, &DataMap::new());
    assert_eq!(ticket.granted_claims, vec!["handle", "email"]);

    let rp = pool
        .find_local_rp(&ticket.fingerprint)
        .unwrap()
        .expect("factory should have created a backing local RP");
    assert_eq!(
        rp.status, "approved",
        "ticket factory defaults to an approved RP"
    );

    let user = pool.find_user_by_id(&ticket.user_id).unwrap();
    assert!(user.is_active);
}

// ---------------------------------------------------------------------
// Domain policy
// ---------------------------------------------------------------------

#[test]
fn policy_defaults_to_admin_approval_required_when_unset() {
    let pool = setup();
    assert_eq!(
        pool.effective_local_rp_policy().unwrap(),
        db::POLICY_ADMIN_APPROVAL_REQUIRED
    );
}

#[test]
fn policy_set_and_get_round_trip() {
    let pool = setup();
    pool.set_local_rp_domain_policy(db::POLICY_DISABLED)
        .unwrap();
    assert_eq!(
        pool.effective_local_rp_policy().unwrap(),
        db::POLICY_DISABLED
    );

    // Setting again (upsert) replaces rather than duplicating.
    pool.set_local_rp_domain_policy(db::POLICY_ALLOW_BY_DEFAULT)
        .unwrap();
    assert_eq!(
        pool.effective_local_rp_policy().unwrap(),
        db::POLICY_ALLOW_BY_DEFAULT
    );
}

#[test]
fn policy_rejects_unrecognised_vocabulary() {
    let pool = setup();
    let err = pool
        .set_local_rp_domain_policy("sure-why-not")
        .expect_err("invalid policy string must be rejected");
    assert!(err.contains("invalid"));
    // Unset remains at the default since the write was rejected.
    assert_eq!(
        pool.effective_local_rp_policy().unwrap(),
        db::POLICY_ADMIN_APPROVAL_REQUIRED
    );
}

// ---------------------------------------------------------------------
// Pending-queue guard
// ---------------------------------------------------------------------

fn fresh_identity() -> (String, Vec<u8>, Vec<u8>) {
    let (signing_pk, _sk) = liblinkkeys::crypto::generate_ed25519_keypair();
    let (enc_pk, _esk) = liblinkkeys::crypto::generate_x25519_keypair();
    let signing_pk_bytes = signing_pk.as_bytes().to_vec();
    let fingerprint = liblinkkeys::crypto::fingerprint(&signing_pk_bytes);
    (fingerprint, signing_pk_bytes, enc_pk)
}

#[test]
fn unauthenticated_context_cannot_create_pending_entry() {
    let pool = setup();
    let (fingerprint, signing_pk, enc_pk) = fresh_identity();

    // "unauthenticated" is enforced by API shape: there is no way to call
    // this without a user id that resolves to an active user. A bogus id
    // (never created) stands in for "no authenticated user".
    let err = local_rp::record_login_attempt(
        &pool,
        "00000000-0000-0000-0000-000000000000",
        &fingerprint,
        &signing_pk,
        &enc_pk,
        "Some App",
        None,
    )
    .expect_err("unauthenticated attempt must not create a pending entry");
    assert!(matches!(err, PendingAttemptError::NotAuthenticated));

    assert!(
        pool.find_local_rp(&fingerprint).unwrap().is_none(),
        "no row should have been created"
    );
}

#[test]
fn deactivated_user_cannot_create_pending_entry() {
    let pool = setup();
    let user = data_factory::create_user(&pool, &DataMap::new());
    pool.deactivate_user(&user.id).unwrap();
    let (fingerprint, signing_pk, enc_pk) = fresh_identity();

    let err = local_rp::record_login_attempt(
        &pool,
        &user.id,
        &fingerprint,
        &signing_pk,
        &enc_pk,
        "Some App",
        None,
    )
    .expect_err("a deactivated user is not an authenticated attempt");
    assert!(matches!(err, PendingAttemptError::NotAuthenticated));
}

#[test]
fn first_attempt_creates_pending_entry() {
    let pool = setup();
    let user = data_factory::create_user(&pool, &DataMap::new());
    let (fingerprint, signing_pk, enc_pk) = fresh_identity();

    let outcome = local_rp::record_login_attempt(
        &pool,
        &user.id,
        &fingerprint,
        &signing_pk,
        &enc_pk,
        "My Jukebox",
        Some("jukebox.local"),
    )
    .unwrap();

    match outcome {
        PendingAttemptOutcome::Created(rp) => {
            assert_eq!(rp.fingerprint, fingerprint);
            assert_eq!(rp.status, "pending");
            assert_eq!(rp.app_name, "My Jukebox");
            assert_eq!(rp.local_domain_hint.as_deref(), Some("jukebox.local"));
        }
        other => panic!("expected Created, got {:?}", other),
    }
}

#[test]
fn repeat_attempt_dedupes_and_refreshes_last_seen() {
    let pool = setup();
    let user = data_factory::create_user(&pool, &DataMap::new());
    let (fingerprint, signing_pk, enc_pk) = fresh_identity();

    local_rp::record_login_attempt(
        &pool,
        &user.id,
        &fingerprint,
        &signing_pk,
        &enc_pk,
        "My Jukebox",
        None,
    )
    .unwrap();

    let outcome = local_rp::record_login_attempt(
        &pool,
        &user.id,
        &fingerprint,
        &signing_pk,
        &enc_pk,
        "My Jukebox",
        None,
    )
    .unwrap();

    match outcome {
        PendingAttemptOutcome::Refreshed { local_rp, drift } => {
            assert!(drift.is_empty(), "identical metadata must not drift");
            assert!(local_rp.last_seen_at.is_some());
        }
        other => panic!("expected Refreshed, got {:?}", other),
    }

    // Still exactly one row for this fingerprint.
    let count = pool.count_local_rps_by_status("pending").unwrap();
    assert_eq!(count, 1);
}

#[test]
fn repeat_attempt_with_changed_metadata_reports_drift() {
    let pool = setup();
    let user = data_factory::create_user(&pool, &DataMap::new());
    let (fingerprint, signing_pk, enc_pk) = fresh_identity();

    local_rp::record_login_attempt(
        &pool,
        &user.id,
        &fingerprint,
        &signing_pk,
        &enc_pk,
        "Original Name",
        Some("orig.local"),
    )
    .unwrap();

    let outcome = local_rp::record_login_attempt(
        &pool,
        &user.id,
        &fingerprint,
        &signing_pk,
        &enc_pk,
        "Renamed App",
        Some("renamed.local"),
    )
    .unwrap();

    match outcome {
        PendingAttemptOutcome::Refreshed { local_rp, drift } => {
            assert_eq!(drift.len(), 2);
            assert!(drift.iter().any(|d| d.field == "app_name"
                && d.previous == "Original Name"
                && d.reported == "Renamed App"));
            assert!(drift
                .iter()
                .any(|d| d.field == "local_domain_hint" && d.reported == "renamed.local"));
            // Metadata is display/audit only, but the stored row does reflect
            // the latest reported values so admins see current claimed identity.
            assert_eq!(local_rp.app_name, "Renamed App");
        }
        other => panic!("expected Refreshed, got {:?}", other),
    }
}

#[test]
fn pending_cap_blocks_new_fingerprints_but_not_refreshes() {
    let pool = setup();

    // Fill the pending queue to the GLOBAL capacity using many distinct
    // "filler" users, each contributing no more than the PER-USER cap — so
    // this loop exercises the global cap in isolation, never tripping the
    // per-user cap (that has its own dedicated test below).
    let filler_users: Vec<_> = (0..(local_rp::MAX_PENDING_LOCAL_RPS
        / local_rp::MAX_PENDING_LOCAL_RPS_PER_USER))
        .map(|_| data_factory::create_user(&pool, &DataMap::new()))
        .collect();

    let mut known: Option<(String, Vec<u8>, Vec<u8>)> = None;
    for i in 0..local_rp::MAX_PENDING_LOCAL_RPS {
        let filler = &filler_users[(i as usize) % filler_users.len()];
        let (fingerprint, signing_pk, enc_pk) = fresh_identity();
        local_rp::record_login_attempt(
            &pool,
            &filler.id,
            &fingerprint,
            &signing_pk,
            &enc_pk,
            &format!("App {}", i),
            None,
        )
        .unwrap();
        if i == 0 {
            known = Some((fingerprint, signing_pk, enc_pk));
        }
    }
    assert_eq!(
        pool.count_local_rps_by_status("pending").unwrap(),
        local_rp::MAX_PENDING_LOCAL_RPS
    );

    // A brand-new fingerprint from a FRESH user (zero pending entries of
    // their own, so the per-user cap is not what blocks them) is refused
    // once the GLOBAL cap is reached.
    let user = data_factory::create_user(&pool, &DataMap::new());
    let (new_fp, new_signing, new_enc) = fresh_identity();
    let err = local_rp::record_login_attempt(
        &pool,
        &user.id,
        &new_fp,
        &new_signing,
        &new_enc,
        "One Too Many",
        None,
    )
    .expect_err("cap must block a new fingerprint");
    assert!(matches!(err, PendingAttemptError::PendingCapReached));
    assert!(pool.find_local_rp(&new_fp).unwrap().is_none());

    // But re-attempting an ALREADY-known fingerprint still refreshes fine —
    // the cap only blocks growth, not dedupe.
    let (fingerprint, signing_pk, enc_pk) = known.unwrap();
    let outcome = local_rp::record_login_attempt(
        &pool,
        &user.id,
        &fingerprint,
        &signing_pk,
        &enc_pk,
        "App 0",
        None,
    )
    .unwrap();
    assert!(matches!(outcome, PendingAttemptOutcome::Refreshed { .. }));
}

/// SEC M3: a single authenticated user must not be able to occupy the whole
/// pending-approval queue by itself — the per-user cap blocks them well
/// before the (much larger) global cap would.
#[test]
fn per_user_pending_cap_blocks_one_users_new_fingerprints_but_not_another_users() {
    let pool = setup();
    let hoarder = data_factory::create_user(&pool, &DataMap::new());

    for i in 0..local_rp::MAX_PENDING_LOCAL_RPS_PER_USER {
        let (fingerprint, signing_pk, enc_pk) = fresh_identity();
        local_rp::record_login_attempt(
            &pool,
            &hoarder.id,
            &fingerprint,
            &signing_pk,
            &enc_pk,
            &format!("Hoarder App {}", i),
            None,
        )
        .unwrap();
    }

    // One more NEW fingerprint from the SAME user is refused — even though
    // the global cap (100) is nowhere near reached.
    let (new_fp, new_signing, new_enc) = fresh_identity();
    let err = local_rp::record_login_attempt(
        &pool,
        &hoarder.id,
        &new_fp,
        &new_signing,
        &new_enc,
        "One Too Many For This User",
        None,
    )
    .expect_err("per-user cap must block a new fingerprint from the same user");
    assert!(matches!(err, PendingAttemptError::PerUserPendingCapReached));
    assert!(pool.find_local_rp(&new_fp).unwrap().is_none());
    assert_eq!(
        pool.count_local_rps_by_status("pending").unwrap(),
        local_rp::MAX_PENDING_LOCAL_RPS_PER_USER,
        "the blocked attempt must not have created a row"
    );

    // A DIFFERENT user, with no pending entries of their own, is unaffected —
    // the per-user cap does not leak into a global block.
    let other_user = data_factory::create_user(&pool, &DataMap::new());
    let (other_fp, other_signing, other_enc) = fresh_identity();
    let outcome = local_rp::record_login_attempt(
        &pool,
        &other_user.id,
        &other_fp,
        &other_signing,
        &other_enc,
        "Different User's App",
        None,
    )
    .unwrap();
    assert!(matches!(outcome, PendingAttemptOutcome::Created(_)));
}

// ---------------------------------------------------------------------
// Allow-by-default admission (Phase 6 browser-route policy path)
// ---------------------------------------------------------------------

#[test]
fn allow_by_default_unauthenticated_context_rejected() {
    let pool = setup();
    let (fingerprint, signing_pk, enc_pk) = fresh_identity();

    let err = local_rp::record_allow_by_default_login(
        &pool,
        "00000000-0000-0000-0000-000000000000",
        &fingerprint,
        &signing_pk,
        &enc_pk,
        "Some App",
        None,
    )
    .expect_err("unauthenticated attempt must not auto-approve");
    assert!(matches!(
        err,
        local_rp::AllowByDefaultError::NotAuthenticated
    ));
    assert!(pool.find_local_rp(&fingerprint).unwrap().is_none());
}

#[test]
fn allow_by_default_first_contact_is_immediately_approved() {
    let pool = setup();
    let user = data_factory::create_user(&pool, &DataMap::new());
    let (fingerprint, signing_pk, enc_pk) = fresh_identity();

    let rp = local_rp::record_allow_by_default_login(
        &pool,
        &user.id,
        &fingerprint,
        &signing_pk,
        &enc_pk,
        "My Jukebox",
        Some("jukebox.local"),
    )
    .unwrap();
    assert_eq!(rp.status, "approved");
    assert_eq!(rp.fingerprint, fingerprint);

    let found = pool.find_local_rp(&fingerprint).unwrap().unwrap();
    assert_eq!(found.status, "approved");
}

#[test]
fn allow_by_default_does_not_override_an_existing_denial() {
    let pool = setup();
    let user = data_factory::create_user(&pool, &DataMap::new());

    let mut overrides = DataMap::new();
    overrides.insert("status".to_string(), serde_json::json!("denied"));
    let rp = data_factory::create_local_rp(&pool, &overrides);

    let (signing_pk, _sk) = liblinkkeys::crypto::generate_ed25519_keypair();
    let (enc_pk, _esk) = liblinkkeys::crypto::generate_x25519_keypair();

    let returned = local_rp::record_allow_by_default_login(
        &pool,
        &user.id,
        &rp.fingerprint,
        signing_pk.as_bytes(),
        &enc_pk,
        "Some App",
        None,
    )
    .unwrap();
    assert_eq!(
        returned.status, "denied",
        "an existing denial must never be silently promoted to approved"
    );
}

// ---------------------------------------------------------------------
// Status transitions
// ---------------------------------------------------------------------

#[test]
fn valid_transitions_succeed() {
    let pool = setup();

    let mut overrides = DataMap::new();
    overrides.insert("status".to_string(), serde_json::json!("pending"));
    let rp = data_factory::create_local_rp(&pool, &overrides);

    let approved = local_rp::transition_status(&pool, &rp.fingerprint, "approved", None).unwrap();
    assert_eq!(approved.status, "approved");

    let revoked =
        local_rp::transition_status(&pool, &rp.fingerprint, "revoked", Some("compromised"))
            .unwrap();
    assert_eq!(revoked.status, "revoked");
    assert_eq!(revoked.admin_notes.as_deref(), Some("compromised"));

    // denied -> approved (admin changed their mind) on a fresh entry.
    let mut denied_overrides = DataMap::new();
    denied_overrides.insert("status".to_string(), serde_json::json!("denied"));
    let denied_rp = data_factory::create_local_rp(&pool, &denied_overrides);
    let reapproved =
        local_rp::transition_status(&pool, &denied_rp.fingerprint, "approved", None).unwrap();
    assert_eq!(reapproved.status, "approved");
}

#[test]
fn invalid_transitions_rejected() {
    let pool = setup();

    // pending -> revoked is not in the matrix.
    let mut pending_overrides = DataMap::new();
    pending_overrides.insert("status".to_string(), serde_json::json!("pending"));
    let pending_rp = data_factory::create_local_rp(&pool, &pending_overrides);
    let err =
        local_rp::transition_status(&pool, &pending_rp.fingerprint, "revoked", None).unwrap_err();
    assert!(matches!(err, StatusTransitionError::Invalid { .. }));
    // Row is untouched.
    assert_eq!(
        pool.find_local_rp(&pending_rp.fingerprint)
            .unwrap()
            .unwrap()
            .status,
        "pending"
    );

    // approved -> denied is not in the matrix.
    let mut approved_overrides = DataMap::new();
    approved_overrides.insert("status".to_string(), serde_json::json!("approved"));
    let approved_rp = data_factory::create_local_rp(&pool, &approved_overrides);
    let err =
        local_rp::transition_status(&pool, &approved_rp.fingerprint, "denied", None).unwrap_err();
    assert!(matches!(err, StatusTransitionError::Invalid { .. }));

    // revoked -> approved is not in the matrix (revocation is terminal).
    let mut revoked_overrides = DataMap::new();
    revoked_overrides.insert("status".to_string(), serde_json::json!("revoked"));
    let revoked_rp = data_factory::create_local_rp(&pool, &revoked_overrides);
    let err =
        local_rp::transition_status(&pool, &revoked_rp.fingerprint, "approved", None).unwrap_err();
    assert!(matches!(err, StatusTransitionError::Invalid { .. }));

    // denied -> denied (same-state no-op) is not in the matrix.
    let mut denied_overrides = DataMap::new();
    denied_overrides.insert("status".to_string(), serde_json::json!("denied"));
    let denied_rp = data_factory::create_local_rp(&pool, &denied_overrides);
    let err =
        local_rp::transition_status(&pool, &denied_rp.fingerprint, "denied", None).unwrap_err();
    assert!(matches!(err, StatusTransitionError::Invalid { .. }));
}

#[test]
fn transition_on_unknown_fingerprint_is_not_found() {
    let pool = setup();
    let err =
        local_rp::transition_status(&pool, "0".repeat(64).as_str(), "approved", None).unwrap_err();
    assert!(matches!(err, StatusTransitionError::NotFound));
}

// ---------------------------------------------------------------------
// Claim ticket lifecycle
// ---------------------------------------------------------------------

#[test]
fn ticket_issue_and_redeem_succeeds_for_approved_rp() {
    let pool = setup();
    let ticket = data_factory::create_local_rp_claim_ticket(&pool, &DataMap::new());

    let redeemed =
        local_rp::redeem_ticket(&pool, &ticket.ticket_hash, &ticket.fingerprint, Utc::now())
            .unwrap();
    assert_eq!(redeemed.ticket_hash, ticket.ticket_hash);
    assert_eq!(redeemed.granted_claims, ticket.granted_claims);
}

#[test]
fn ticket_redemption_is_multi_use_within_window() {
    let pool = setup();
    let ticket = data_factory::create_local_rp_claim_ticket(&pool, &DataMap::new());

    local_rp::redeem_ticket(&pool, &ticket.ticket_hash, &ticket.fingerprint, Utc::now()).unwrap();
    // Redeeming again later (still within the window) must still succeed —
    // tickets are multi-use, not single-use.
    let second = local_rp::redeem_ticket(
        &pool,
        &ticket.ticket_hash,
        &ticket.fingerprint,
        Utc::now() + Duration::minutes(1),
    )
    .unwrap();
    assert_eq!(second.ticket_hash, ticket.ticket_hash);
}

/// C1: a ticket must only redeem when the caller's possession-proven
/// fingerprint matches the fingerprint the ticket was actually issued to — a
/// DIFFERENT (even otherwise-valid) local RP fingerprint must not be able to
/// redeem it just by knowing the raw ticket bytes.
#[test]
fn ticket_redemption_rejects_wrong_authenticated_fingerprint() {
    let pool = setup();
    let ticket = data_factory::create_local_rp_claim_ticket(&pool, &DataMap::new());

    // A different, genuinely-registered-and-approved local RP's fingerprint —
    // not the one this ticket was issued to.
    let mut other_overrides = DataMap::new();
    other_overrides.insert("status".to_string(), serde_json::json!("approved"));
    let other_rp = data_factory::create_local_rp(&pool, &other_overrides);
    assert_ne!(other_rp.fingerprint, ticket.fingerprint);

    let err = local_rp::redeem_ticket(
        &pool,
        &ticket.ticket_hash,
        &other_rp.fingerprint,
        Utc::now(),
    )
    .unwrap_err();
    assert!(matches!(err, TicketRedeemError::FingerprintMismatch));

    // The rightful fingerprint still redeems it fine.
    local_rp::redeem_ticket(&pool, &ticket.ticket_hash, &ticket.fingerprint, Utc::now()).unwrap();
}

#[test]
fn expired_ticket_redemption_fails() {
    let pool = setup();
    let mut overrides = DataMap::new();
    overrides.insert(
        "expires_at".to_string(),
        serde_json::json!((Utc::now() - Duration::minutes(5)).to_rfc3339()),
    );
    let ticket = data_factory::create_local_rp_claim_ticket(&pool, &overrides);

    let err = local_rp::redeem_ticket(&pool, &ticket.ticket_hash, &ticket.fingerprint, Utc::now())
        .unwrap_err();
    assert!(matches!(err, TicketRedeemError::Expired));
}

/// Phase 7 (dns-less-local-rp-design.md admin surface): revoking a local RP
/// now also deletes its outstanding claim tickets outright — cheap and
/// unambiguous cleanup on top of `redeem_ticket`'s own approval-status check,
/// which remains the actual enforcement point (a ticket issued *after*
/// revocation could never exist, but this belt-and-suspenders delete means a
/// pre-revocation ticket row does not linger either). So post-revoke
/// redemption now fails `NotFound` (the row is gone), not `RpNotApproved`.
#[test]
fn revoked_rp_kills_outstanding_tickets() {
    let pool = setup();
    let mut rp_overrides = DataMap::new();
    rp_overrides.insert("status".to_string(), serde_json::json!("approved"));
    let rp = data_factory::create_local_rp(&pool, &rp_overrides);

    let mut ticket_overrides = DataMap::new();
    ticket_overrides.insert(
        "fingerprint".to_string(),
        serde_json::json!(rp.fingerprint.clone()),
    );
    let ticket = data_factory::create_local_rp_claim_ticket(&pool, &ticket_overrides);

    // Redemption works while approved...
    local_rp::redeem_ticket(&pool, &ticket.ticket_hash, &rp.fingerprint, Utc::now()).unwrap();

    // ...but dies the instant the RP is revoked: the ticket row itself is
    // deleted, so redemption now fails not-found.
    local_rp::transition_status(&pool, &rp.fingerprint, "revoked", Some("compromised")).unwrap();
    assert!(
        pool.find_local_rp_claim_ticket(&ticket.ticket_hash)
            .unwrap()
            .is_none(),
        "revoke must delete the RP's outstanding claim tickets"
    );
    let err = local_rp::redeem_ticket(&pool, &ticket.ticket_hash, &rp.fingerprint, Utc::now())
        .unwrap_err();
    assert!(matches!(err, TicketRedeemError::NotFound));
}

#[test]
fn wrong_ticket_hash_is_not_found() {
    let pool = setup();
    let _ticket = data_factory::create_local_rp_claim_ticket(&pool, &DataMap::new());
    let bogus_hash = liblinkkeys::crypto::fingerprint(b"not-the-real-ticket");
    let err =
        local_rp::redeem_ticket(&pool, &bogus_hash, &_ticket.fingerprint, Utc::now()).unwrap_err();
    assert!(matches!(err, TicketRedeemError::NotFound));
}

#[test]
fn purge_expired_tickets_removes_only_expired_rows() {
    let pool = setup();

    let mut expired_overrides = DataMap::new();
    expired_overrides.insert(
        "expires_at".to_string(),
        serde_json::json!((Utc::now() - Duration::minutes(5)).to_rfc3339()),
    );
    let expired = data_factory::create_local_rp_claim_ticket(&pool, &expired_overrides);

    let valid = data_factory::create_local_rp_claim_ticket(&pool, &DataMap::new());

    let purged = local_rp::purge_expired_tickets(&pool, Utc::now()).unwrap();
    assert_eq!(purged, 1);

    assert!(pool
        .find_local_rp_claim_ticket(&expired.ticket_hash)
        .unwrap()
        .is_none());
    assert!(pool
        .find_local_rp_claim_ticket(&valid.ticket_hash)
        .unwrap()
        .is_some());
}
