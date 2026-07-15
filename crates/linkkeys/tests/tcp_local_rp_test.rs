//! Tests for the DNS-less local RP `LocalRp/redeem-claim-ticket` TCP op
//! (dns-less-local-rp-design.md, Phase 5), plus confirmation that the
//! existing unauthenticated `DomainKeys` ops (`get-domain-keys`,
//! `get-revocations`) are reachable by an unauthenticated TLS peer over TCP —
//! the "Required Network Access" section of the design doc leans on that
//! already being true.
//!
//! `redeem-claim-ticket` is unauthenticated at the transport layer (no API
//! key, `client_domain: None` throughout) — authentication is the
//! application-layer possession proof: the request is signed with the local
//! RP's own Ed25519 signing key and verified against the STORED signing key
//! for the claimed fingerprint.

mod common;

use std::collections::HashMap;

use common::data_factory::{
    create_local_rp_claim_ticket, create_local_rp_with_signing_key, create_user, DataMap,
};
use liblinkkeys::generated::types::{GetRevocationsRequest, SetClaimRequest};
use linkkeys::db::models::LocalRp;
use linkkeys::services::admin;
use serde_json::Value;

const TEST_DOMAIN: &str = "local-rp.test";

fn setup() -> linkkeys::db::DbPool {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    common::create_test_pool()
}

fn status_map(status: &str) -> DataMap {
    let mut m = HashMap::new();
    m.insert("status".to_string(), Value::String(status.to_string()));
    m
}

/// Build and sign a `SignedLocalRpTicketRedemptionRequest` for `raw_ticket`,
/// bound to `fingerprint`, signed with `signing_sk_bytes`, `issued_at` given
/// as an exact RFC3339 string (so tests can pass a stale one).
fn build_signed_redemption(
    raw_ticket: &[u8],
    fingerprint: &str,
    issued_at: &str,
    signing_sk_bytes: &[u8],
) -> Vec<u8> {
    let request = liblinkkeys::local_rp::build_local_rp_ticket_redemption_request(
        raw_ticket.to_vec(),
        fingerprint,
        issued_at,
    );
    let signed =
        liblinkkeys::local_rp::sign_local_rp_ticket_redemption_request(&request, signing_sk_bytes)
            .expect("sign ticket redemption request");
    liblinkkeys::generated::encode_signed_local_rp_ticket_redemption_request(&signed)
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Give the test user a "handle" claim (part of the default granted-claims
/// set the ticket factory uses) so the happy-path test has something to
/// assert on in the redemption response. Mirrors
/// `admin_service_test.rs::test_service_set_claim`.
fn give_handle_claim(pool: &linkkeys::db::DbPool, user_id: &str) {
    common::data_factory::create_domain_key(pool);
    admin::set_claim(
        pool,
        SetClaimRequest {
            user_id: user_id.to_string(),
            claim_type: "handle".to_string(),
            claim_value: "alice".to_string(),
            expires_at: None,
        },
    )
    .expect("set handle claim");
}

fn dispatch_redeem(pool: &linkkeys::db::DbPool, payload: Vec<u8>) -> (i32, Vec<u8>) {
    linkkeys::tcp::dispatch_for_test("LocalRp", "redeem-claim-ticket", payload, pool, None)
}

// ---------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------

#[test]
fn redeem_claim_ticket_happy_path() {
    let pool = setup();
    let (rp, signing_sk): (LocalRp, Vec<u8>) =
        create_local_rp_with_signing_key(&pool, &status_map("approved"));
    let user = create_user(&pool, &DataMap::new());
    give_handle_claim(&pool, &user.id);

    let raw_ticket = vec![7u8; 32];
    let ticket_hash = liblinkkeys::crypto::fingerprint(&raw_ticket);
    let mut overrides = DataMap::new();
    overrides.insert(
        "fingerprint".to_string(),
        Value::String(rp.fingerprint.clone()),
    );
    overrides.insert("user_id".to_string(), Value::String(user.id.clone()));
    overrides.insert("ticket_hash".to_string(), Value::String(ticket_hash));
    create_local_rp_claim_ticket(&pool, &overrides);

    let payload =
        build_signed_redemption(&raw_ticket, &rp.fingerprint, &now_rfc3339(), &signing_sk);
    let (status, body) = dispatch_redeem(&pool, payload);
    assert_eq!(status, 0, "approved RP + valid ticket should redeem");

    let resp = liblinkkeys::generated::decode_local_rp_ticket_redemption_response(&body)
        .expect("decode LocalRpTicketRedemptionResponse");
    assert_eq!(resp.user_id, user.id);
    assert_eq!(resp.user_domain, "test.com");
    assert!(
        resp.claims.iter().any(|c| c.claim_type == "handle"),
        "granted claim set includes the handle claim"
    );
    assert!(
        !resp
            .claims
            .iter()
            .find(|c| c.claim_type == "handle")
            .unwrap()
            .signatures
            .is_empty(),
        "returned claim carries its existing signature"
    );
}

/// Tickets are multi-use within their validity window — redeeming the same
/// ticket twice must both succeed.
#[test]
fn redeem_claim_ticket_multi_use_within_window_works() {
    let pool = setup();
    let (rp, signing_sk) = create_local_rp_with_signing_key(&pool, &status_map("approved"));
    let user = create_user(&pool, &DataMap::new());

    let raw_ticket = vec![9u8; 32];
    let ticket_hash = liblinkkeys::crypto::fingerprint(&raw_ticket);
    let mut overrides = DataMap::new();
    overrides.insert(
        "fingerprint".to_string(),
        Value::String(rp.fingerprint.clone()),
    );
    overrides.insert("user_id".to_string(), Value::String(user.id.clone()));
    overrides.insert("ticket_hash".to_string(), Value::String(ticket_hash));
    create_local_rp_claim_ticket(&pool, &overrides);

    for attempt in 0..2 {
        let payload =
            build_signed_redemption(&raw_ticket, &rp.fingerprint, &now_rfc3339(), &signing_sk);
        let (status, _) = dispatch_redeem(&pool, payload);
        assert_eq!(status, 0, "redemption attempt {attempt} should succeed");
    }
}

// ---------------------------------------------------------------------
// Possession proof / identity rejections
// ---------------------------------------------------------------------

#[test]
fn redeem_claim_ticket_wrong_key_rejected() {
    let pool = setup();
    let (rp, _real_sk) = create_local_rp_with_signing_key(&pool, &status_map("approved"));
    // A second, unrelated key pair — simulates an attacker who stole a ticket
    // but does not hold the real local RP's private signing key.
    let (_other_rp, wrong_sk) = create_local_rp_with_signing_key(&pool, &status_map("approved"));

    let raw_ticket = vec![1u8; 32];
    let ticket_hash = liblinkkeys::crypto::fingerprint(&raw_ticket);
    let mut overrides = DataMap::new();
    overrides.insert(
        "fingerprint".to_string(),
        Value::String(rp.fingerprint.clone()),
    );
    overrides.insert("ticket_hash".to_string(), Value::String(ticket_hash));
    create_local_rp_claim_ticket(&pool, &overrides);

    // Claims fingerprint `rp.fingerprint` but signs with a different key.
    let payload = build_signed_redemption(&raw_ticket, &rp.fingerprint, &now_rfc3339(), &wrong_sk);
    let (status, _) = dispatch_redeem(&pool, payload);
    assert_ne!(
        status, 0,
        "a signature from the wrong key must not redeem another RP's ticket"
    );
}

/// C1 (critical): a ticket issued to RP A must not be redeemable by RP B,
/// even when B is a genuinely-approved local RP presenting a validly signed
/// request under B's OWN key/fingerprint. Before the fix, `redeem-claim-ticket`
/// looked the ticket up purely by hash and only re-checked the ISSUANCE-bound
/// RP's approval status — it never checked that the ticket's bound
/// fingerprint equalled the caller's possession-proven fingerprint. That
/// meant anyone who learned A's raw ticket bytes (e.g. a compromised
/// callback, a shared clipboard, a malicious co-installed app intercepting
/// the redirect) could redeem A's ticket through ANY other approved local
/// RP's own signing key, defeating "a stolen ticket is useless without the
/// RP's private key".
#[test]
fn redeem_claim_ticket_wrong_rp_with_valid_own_key_rejected() {
    let pool = setup();
    // RP A: the ticket's rightful owner.
    let (rp_a, _a_sk) = create_local_rp_with_signing_key(&pool, &status_map("approved"));
    // RP B: a completely different, independently approved local RP with its
    // own genuine, validly-registered signing key.
    let (rp_b, b_sk) = create_local_rp_with_signing_key(&pool, &status_map("approved"));
    assert_ne!(rp_a.fingerprint, rp_b.fingerprint);

    let raw_ticket = vec![42u8; 32];
    let ticket_hash = liblinkkeys::crypto::fingerprint(&raw_ticket);
    let mut overrides = DataMap::new();
    overrides.insert(
        "fingerprint".to_string(),
        Value::String(rp_a.fingerprint.clone()),
    );
    overrides.insert("ticket_hash".to_string(), Value::String(ticket_hash));
    create_local_rp_claim_ticket(&pool, &overrides);

    // B builds and signs a redemption request with ITS OWN key, claiming ITS
    // OWN fingerprint (a fully legitimate, correctly-signed possession
    // proof for B) — but carrying A's stolen raw ticket bytes.
    let payload = build_signed_redemption(&raw_ticket, &rp_b.fingerprint, &now_rfc3339(), &b_sk);
    let (status, _) = dispatch_redeem(&pool, payload);
    assert_ne!(
        status, 0,
        "an approved RP with a genuinely valid signature must not be able to redeem \
         another RP's ticket merely by knowing its raw bytes"
    );

    // Sanity: the rightful owner, RP A, can still redeem its own ticket.
    let payload_a = build_signed_redemption(&raw_ticket, &rp_a.fingerprint, &now_rfc3339(), &_a_sk);
    let (status_a, _) = dispatch_redeem(&pool, payload_a);
    assert_eq!(
        status_a, 0,
        "the rightful RP must still be able to redeem its own ticket"
    );
}

#[test]
fn redeem_claim_ticket_unknown_fingerprint_rejected() {
    let pool = setup();
    // Generate a signing key that was never registered as a local RP at all.
    let (pk, sk) = liblinkkeys::crypto::generate_ed25519_keypair();
    let fingerprint = liblinkkeys::crypto::fingerprint(pk.as_bytes());

    let raw_ticket = vec![2u8; 32];
    let payload =
        build_signed_redemption(&raw_ticket, &fingerprint, &now_rfc3339(), &sk.to_bytes());
    let (status, _) = dispatch_redeem(&pool, payload);
    assert_ne!(status, 0, "an unregistered fingerprint must be rejected");
}

#[test]
fn redeem_claim_ticket_pending_rp_rejected() {
    let pool = setup();
    let (rp, signing_sk) = create_local_rp_with_signing_key(&pool, &status_map("pending"));

    let raw_ticket = vec![3u8; 32];
    let payload =
        build_signed_redemption(&raw_ticket, &rp.fingerprint, &now_rfc3339(), &signing_sk);
    let (status, _) = dispatch_redeem(&pool, payload);
    assert_ne!(
        status, 0,
        "a pending (not-yet-approved) RP must be rejected"
    );
}

#[test]
fn redeem_claim_ticket_denied_rp_rejected() {
    let pool = setup();
    let (rp, signing_sk) = create_local_rp_with_signing_key(&pool, &status_map("denied"));

    let raw_ticket = vec![4u8; 32];
    let payload =
        build_signed_redemption(&raw_ticket, &rp.fingerprint, &now_rfc3339(), &signing_sk);
    let (status, _) = dispatch_redeem(&pool, payload);
    assert_ne!(status, 0, "a denied RP must be rejected");
}

#[test]
fn redeem_claim_ticket_revoked_rp_rejected() {
    let pool = setup();
    let (rp, signing_sk) = create_local_rp_with_signing_key(&pool, &status_map("revoked"));

    let raw_ticket = vec![5u8; 32];
    let payload =
        build_signed_redemption(&raw_ticket, &rp.fingerprint, &now_rfc3339(), &signing_sk);
    let (status, _) = dispatch_redeem(&pool, payload);
    assert_ne!(
        status, 0,
        "a revoked RP must be rejected — revocation kills outstanding tickets"
    );
}

// ---------------------------------------------------------------------
// Ticket-state rejections
// ---------------------------------------------------------------------

#[test]
fn redeem_claim_ticket_expired_ticket_rejected() {
    let pool = setup();
    let (rp, signing_sk) = create_local_rp_with_signing_key(&pool, &status_map("approved"));

    let raw_ticket = vec![6u8; 32];
    let ticket_hash = liblinkkeys::crypto::fingerprint(&raw_ticket);
    let mut overrides = DataMap::new();
    overrides.insert(
        "fingerprint".to_string(),
        Value::String(rp.fingerprint.clone()),
    );
    overrides.insert("ticket_hash".to_string(), Value::String(ticket_hash));
    overrides.insert(
        "expires_at".to_string(),
        Value::String((chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339()),
    );
    create_local_rp_claim_ticket(&pool, &overrides);

    let payload =
        build_signed_redemption(&raw_ticket, &rp.fingerprint, &now_rfc3339(), &signing_sk);
    let (status, _) = dispatch_redeem(&pool, payload);
    assert_ne!(status, 0, "an expired ticket must be rejected");
}

#[test]
fn redeem_claim_ticket_stale_issued_at_rejected() {
    let pool = setup();
    let (rp, signing_sk) = create_local_rp_with_signing_key(&pool, &status_map("approved"));

    let raw_ticket = vec![8u8; 32];
    let ticket_hash = liblinkkeys::crypto::fingerprint(&raw_ticket);
    let mut overrides = DataMap::new();
    overrides.insert(
        "fingerprint".to_string(),
        Value::String(rp.fingerprint.clone()),
    );
    overrides.insert("ticket_hash".to_string(), Value::String(ticket_hash));
    create_local_rp_claim_ticket(&pool, &overrides);

    // Well outside DEFAULT_CLOCK_SKEW_SECONDS (300s).
    let stale_issued_at = (chrono::Utc::now() - chrono::Duration::minutes(20)).to_rfc3339();
    let payload =
        build_signed_redemption(&raw_ticket, &rp.fingerprint, &stale_issued_at, &signing_sk);
    let (status, _) = dispatch_redeem(&pool, payload);
    assert_ne!(
        status, 0,
        "a redemption request with a stale issued_at must be rejected"
    );
}

// ---------------------------------------------------------------------
// User state rejections (Phase 4 finding: purge minimizes, never deletes)
// ---------------------------------------------------------------------

#[test]
fn redeem_claim_ticket_deactivated_user_rejected() {
    let pool = setup();
    let (rp, signing_sk) = create_local_rp_with_signing_key(&pool, &status_map("approved"));
    let user = create_user(&pool, &DataMap::new());
    pool.deactivate_user(&user.id).expect("deactivate user");

    let raw_ticket = vec![10u8; 32];
    let ticket_hash = liblinkkeys::crypto::fingerprint(&raw_ticket);
    let mut overrides = DataMap::new();
    overrides.insert(
        "fingerprint".to_string(),
        Value::String(rp.fingerprint.clone()),
    );
    overrides.insert("user_id".to_string(), Value::String(user.id.clone()));
    overrides.insert("ticket_hash".to_string(), Value::String(ticket_hash));
    create_local_rp_claim_ticket(&pool, &overrides);

    let payload =
        build_signed_redemption(&raw_ticket, &rp.fingerprint, &now_rfc3339(), &signing_sk);
    let (status, _) = dispatch_redeem(&pool, payload);
    assert_ne!(status, 0, "a deactivated user's ticket must be rejected");
}

/// User purge minimizes the row rather than deleting it (so the ticket's FK
/// never cascades away) — the redemption status check is the backstop.
#[test]
fn redeem_claim_ticket_purged_user_rejected() {
    let pool = setup();
    let (rp, signing_sk) = create_local_rp_with_signing_key(&pool, &status_map("approved"));
    let user = create_user(&pool, &DataMap::new());
    pool.purge_user_tombstone(&user.id, Some("test purge"))
        .expect("purge user");

    let raw_ticket = vec![11u8; 32];
    let ticket_hash = liblinkkeys::crypto::fingerprint(&raw_ticket);
    let mut overrides = DataMap::new();
    overrides.insert(
        "fingerprint".to_string(),
        Value::String(rp.fingerprint.clone()),
    );
    overrides.insert("user_id".to_string(), Value::String(user.id.clone()));
    overrides.insert("ticket_hash".to_string(), Value::String(ticket_hash));
    create_local_rp_claim_ticket(&pool, &overrides);

    let payload =
        build_signed_redemption(&raw_ticket, &rp.fingerprint, &now_rfc3339(), &signing_sk);
    let (status, _) = dispatch_redeem(&pool, payload);
    assert_ne!(status, 0, "a purged user's ticket must be rejected");
}

// ---------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------

/// The `TICKET_REDEMPTION` bucket allows a burst of 20 before blocking
/// (`crate::services::ratelimit`), and it meters possession-proven requests
/// only — so every request here is VALIDLY signed by the true key holder
/// (the test holds the RP's real signing key). Hammering the (randomly
/// generated, so test-unique) fingerprint past its burst must trip the
/// limiter. This also exercises "multi-use within window" implicitly for the
/// attempts that succeed before the limiter trips.
#[test]
fn redeem_claim_ticket_rate_limit_triggers() {
    let pool = setup();
    let (rp, signing_sk) = create_local_rp_with_signing_key(&pool, &status_map("approved"));

    let raw_ticket = vec![12u8; 32];
    let ticket_hash = liblinkkeys::crypto::fingerprint(&raw_ticket);
    let mut overrides = DataMap::new();
    overrides.insert(
        "fingerprint".to_string(),
        Value::String(rp.fingerprint.clone()),
    );
    overrides.insert("ticket_hash".to_string(), Value::String(ticket_hash));
    create_local_rp_claim_ticket(&pool, &overrides);

    let mut saw_rate_limited = false;
    for _ in 0..30 {
        let payload =
            build_signed_redemption(&raw_ticket, &rp.fingerprint, &now_rfc3339(), &signing_sk);
        let (status, _) = dispatch_redeem(&pool, payload);
        if status != 0 {
            saw_rate_limited = true;
            break;
        }
    }
    assert!(
        saw_rate_limited,
        "hammering the same fingerprint past its burst must eventually be rate limited"
    );
}

/// The rate limiter must be un-spoofable: it debits only AFTER the possession
/// proof succeeds, so an attacker flooding a victim RP's fingerprint with
/// invalid-signature requests cannot exhaust the victim's bucket and lock the
/// real app out of redemptions (a cheap remote DoS otherwise). Flood well
/// past the burst size with wrong-key requests claiming the victim's
/// fingerprint, then confirm the victim's own validly-signed redemption
/// still succeeds.
#[test]
fn redeem_claim_ticket_rate_limit_not_consumed_by_invalid_signatures() {
    let pool = setup();
    let (victim, victim_sk) = create_local_rp_with_signing_key(&pool, &status_map("approved"));
    // Attacker key: never registered anywhere, definitely not the victim's.
    let (_attacker_pk, attacker_sk) = liblinkkeys::crypto::generate_ed25519_keypair();

    let raw_ticket = vec![13u8; 32];
    let ticket_hash = liblinkkeys::crypto::fingerprint(&raw_ticket);
    let mut overrides = DataMap::new();
    overrides.insert(
        "fingerprint".to_string(),
        Value::String(victim.fingerprint.clone()),
    );
    overrides.insert("ticket_hash".to_string(), Value::String(ticket_hash));
    create_local_rp_claim_ticket(&pool, &overrides);

    // Flood: 30 requests (burst is 20) claiming the victim's fingerprint but
    // signed with the attacker's key. Every one must fail the possession
    // proof — and none may debit the victim's bucket.
    for _ in 0..30 {
        let payload = build_signed_redemption(
            &raw_ticket,
            &victim.fingerprint,
            &now_rfc3339(),
            &attacker_sk.to_bytes(),
        );
        let (status, _) = dispatch_redeem(&pool, payload);
        assert_ne!(status, 0, "wrong-key requests must always be rejected");
    }

    // The victim's own validly-signed redemption still succeeds: the flood
    // did not consume the victim's rate-limit bucket.
    let payload =
        build_signed_redemption(&raw_ticket, &victim.fingerprint, &now_rfc3339(), &victim_sk);
    let (status, _) = dispatch_redeem(&pool, payload);
    assert_eq!(
        status, 0,
        "an invalid-signature flood must not exhaust the victim's rate-limit bucket"
    );
}

/// Malformed payloads are rejected before the rate limiter would even have a
/// fingerprint to key on — sanity check that decode failure alone doesn't
/// panic or succeed.
#[test]
fn redeem_claim_ticket_malformed_payload_rejected() {
    let pool = setup();
    let (status, _) = dispatch_redeem(&pool, vec![0xff, 0x00, 0x01]);
    assert_ne!(status, 0, "malformed payload must be rejected");
}

// ---------------------------------------------------------------------
// Confirmation: unauthenticated domain-key / revocation fetch (Required
// Network Access section) — already-existing dispatch, no changes made here.
// ---------------------------------------------------------------------

#[test]
fn get_domain_keys_answers_unauthenticated_peer() {
    let pool = setup();
    common::data_factory::create_domain_key(&pool);

    let (status, body) =
        linkkeys::tcp::dispatch_for_test("DomainKeys", "get-domain-keys", Vec::new(), &pool, None);
    assert_eq!(
        status, 0,
        "get-domain-keys must answer an unauthenticated TCP peer"
    );
    let resp = liblinkkeys::generated::decode_get_domain_keys_response(&body)
        .expect("decode GetDomainKeysResponse");
    assert_eq!(resp.domain, TEST_DOMAIN);
    assert!(
        !resp.keys.is_empty(),
        "the active domain key created above is returned"
    );
}

#[test]
fn get_revocations_answers_unauthenticated_peer() {
    let pool = setup();

    let payload = liblinkkeys::generated::encode_get_revocations_request(&GetRevocationsRequest {
        since: None,
    });
    let (status, body) =
        linkkeys::tcp::dispatch_for_test("DomainKeys", "get-revocations", payload, &pool, None);
    assert_eq!(
        status, 0,
        "get-revocations must answer an unauthenticated TCP peer"
    );
    liblinkkeys::generated::decode_get_revocations_response(&body)
        .expect("decode GetRevocationsResponse");
}
