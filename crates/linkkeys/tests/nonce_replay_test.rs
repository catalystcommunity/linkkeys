mod common;

use std::time::Duration;

// Durable nonce store: first use succeeds, replay is rejected, distinct nonces
// are independent. Exercises the real DB-backed `record_nonce` (no in-memory
// shortcut) inside the rolled-back test transaction.

#[test]
fn test_first_use_then_replay_rejected() {
    let pool = common::create_test_pool();
    let ttl = Duration::from_secs(300);
    assert!(
        pool.record_nonce("nonce-a", ttl).unwrap(),
        "first use must succeed"
    );
    assert!(
        !pool.record_nonce("nonce-a", ttl).unwrap(),
        "replay must be rejected"
    );
}

#[test]
fn test_distinct_nonces_independent() {
    let pool = common::create_test_pool();
    let ttl = Duration::from_secs(300);
    assert!(pool.record_nonce("nonce-1", ttl).unwrap());
    assert!(pool.record_nonce("nonce-2", ttl).unwrap());
    assert!(!pool.record_nonce("nonce-1", ttl).unwrap());
    assert!(!pool.record_nonce("nonce-2", ttl).unwrap());
}

#[test]
fn test_namespaced_nonces_do_not_collide() {
    // The login and userinfo paths burn the same underlying nonce under
    // different prefixes; both must be recordable independently.
    let pool = common::create_test_pool();
    let ttl = Duration::from_secs(300);
    assert!(pool.record_nonce("login:abc", ttl).unwrap());
    assert!(pool.record_nonce("userinfo:abc", ttl).unwrap());
    assert!(!pool.record_nonce("login:abc", ttl).unwrap());
}
