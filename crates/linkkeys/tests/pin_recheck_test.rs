//! SEC-01/02: TOFU pin recheck policy — first-seen, unchanged, single-key
//! rotation (accepted), and multi-key mismatch (refused + queued for review).

mod common;

use linkkeys::services::pins::{check_and_update_pin, PinOutcome};

fn fps(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

#[test]
fn first_seen_then_unchanged_regardless_of_order() {
    let pool = common::create_test_pool();
    let d = "peer.test";
    assert_eq!(
        check_and_update_pin(&pool, d, &fps(&["aa", "bb", "cc"])),
        PinOutcome::FirstSeen
    );
    // Same set, different order/dup -> still unchanged.
    assert_eq!(
        check_and_update_pin(&pool, d, &fps(&["cc", "aa", "bb", "bb"])),
        PinOutcome::Unchanged
    );
    let pin = pool.find_domain_pin(d).unwrap().unwrap();
    assert_eq!(pin.fingerprints, "aa,bb,cc");
}

#[test]
fn single_key_rotation_is_accepted_and_repinned() {
    let pool = common::create_test_pool();
    let d = "peer.test";
    check_and_update_pin(&pool, d, &fps(&["aa", "bb", "cc"]));

    // cc rotated to dd — exactly one pinned fingerprint gone.
    assert_eq!(
        check_and_update_pin(&pool, d, &fps(&["aa", "bb", "dd"])),
        PinOutcome::Rotated
    );
    // The pin now reflects the new set.
    assert_eq!(
        check_and_update_pin(&pool, d, &fps(&["aa", "bb", "dd"])),
        PinOutcome::Unchanged
    );
    // And it was audited.
    let audit = pool.list_audit(50).unwrap();
    assert!(audit.iter().any(|a| a.event == "pin.rotated"));
}

#[test]
fn multi_key_mismatch_is_refused_and_queued() {
    let pool = common::create_test_pool();
    let d = "peer.test";
    check_and_update_pin(&pool, d, &fps(&["aa", "bb", "cc"]));

    // Two pinned fingerprints vanish at once -> refuse + queue a human review.
    let out = check_and_update_pin(&pool, d, &fps(&["aa", "xx", "yy"]));
    assert_eq!(out, PinOutcome::Mismatch);
    assert!(!out.is_trusted());

    let reviews = pool.list_pending_reviews("key_mismatch").unwrap();
    assert!(
        reviews.iter().any(|r| r.subject.as_deref() == Some(d)),
        "a key_mismatch review item was enqueued for the domain"
    );
    // The pin is NOT changed (fail closed): the original set stands.
    let pin = pool.find_domain_pin(d).unwrap().unwrap();
    assert_eq!(pin.fingerprints, "aa,bb,cc");
}
