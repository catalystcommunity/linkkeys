//! Tests for `services::warm_signer`: the warm in-memory cache of the home
//! domain's active signing keys (see `signing-things-request.md`,
//! "Home-domain signing cost").
//!
//! All tests share process-wide global state (the cache singleton and its
//! counters), so every test takes `SERIAL` first to run one at a time even
//! though `cargo test` runs `#[test]` functions on separate threads by
//! default within one binary. Cross-binary interference isn't possible:
//! each integration-test file is its own process.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::data_factory::create_domain_key;
use linkkeys::services::warm_signer;

const PASS: &[u8] = b"test-passphrase";

static SERIAL: Mutex<()> = Mutex::new(());

fn short_ttl() -> Duration {
    Duration::from_millis(30)
}

#[test]
fn warm_hit_returns_same_key_material_and_signatures_verify() {
    let _guard = SERIAL.lock().unwrap();
    warm_signer::invalidate();
    let pool = common::create_test_pool();

    let k1 = create_domain_key(&pool);
    let k2 = create_domain_key(&pool);
    let k3 = create_domain_key(&pool);

    // Cold derivation.
    let cold = warm_signer::active_signers(&pool, PASS).expect("cold derive");
    assert_eq!(cold.len(), 3, "all three active signing keys are warm");

    // Warm hit: same Arc contents (same decrypted bytes), and it must not
    // trigger another derivation.
    let before = warm_signer::stats().derivations;
    let warm = warm_signer::active_signers(&pool, PASS).expect("warm hit");
    let after = warm_signer::stats().derivations;
    assert_eq!(before, after, "a warm hit must not re-derive");

    let cold_ids: Vec<&str> = cold.iter().map(|s| s.key_id).collect();
    let warm_ids: Vec<&str> = warm.iter().map(|s| s.key_id).collect();
    assert_eq!(cold_ids, warm_ids);

    for signer in warm.iter() {
        let key_row = [&k1, &k2, &k3]
            .into_iter()
            .find(|k| k.id == signer.key_id)
            .expect("signer key_id matches a created domain key");

        // The warm signer's key material must match a fresh decryption of
        // the same row.
        let direct = liblinkkeys::crypto::decrypt_private_key(&key_row.private_key_encrypted, PASS)
            .expect("direct decrypt");
        assert_eq!(&direct[..], signer.private_key);

        // And a signature made from the warm signer must verify against the
        // domain's published public key.
        let message = b"attestation payload";
        let sig =
            liblinkkeys::crypto::sign_with_algorithm(signer.algorithm, message, signer.private_key)
                .expect("sign with warm key");
        liblinkkeys::crypto::verify_with_algorithm(
            signer.algorithm,
            message,
            &sig,
            &key_row.public_key,
        )
        .expect("signature verifies against the domain public key");
    }
}

#[test]
fn concurrent_cold_callers_single_flight_into_one_derivation() {
    let _guard = SERIAL.lock().unwrap();
    warm_signer::invalidate();
    let pool = common::create_test_pool();
    create_domain_key(&pool);
    create_domain_key(&pool);
    create_domain_key(&pool);

    let before = warm_signer::stats().derivations;

    const N: usize = 16;
    let started = Arc::new(AtomicUsize::new(0));
    std::thread::scope(|scope| {
        let pool = &pool;
        let started = &started;
        let handles: Vec<_> = (0..N)
            .map(|_| {
                scope.spawn(move || {
                    started.fetch_add(1, Ordering::SeqCst);
                    warm_signer::active_signers(pool, PASS).expect("concurrent active_signers")
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread panicked");
        }
    });
    assert_eq!(started.load(Ordering::SeqCst), N);

    let after = warm_signer::stats().derivations;
    assert_eq!(
        after - before,
        1,
        "N concurrent cold callers must trigger exactly one Argon2id derivation"
    );
}

#[test]
fn cache_evicts_on_its_bounded_interval_and_derives_again() {
    let _guard = SERIAL.lock().unwrap();
    warm_signer::invalidate();
    let pool = common::create_test_pool();
    create_domain_key(&pool);

    let ttl = short_ttl();
    let before_derivations = warm_signer::stats().derivations;

    let first = warm_signer::active_signers_with_ttl(&pool, PASS, ttl).expect("first derive");
    let first_key_id = first.iter().next().unwrap().key_id.to_string();
    // Release the caller's own reference so the cache holds the only Arc;
    // otherwise eviction can't drop the entry once the cache stops pointing
    // at it below.
    drop(first);

    assert_eq!(warm_signer::stats().derivations, before_derivations + 1);

    std::thread::sleep(ttl + Duration::from_millis(50));

    let before_evictions = warm_signer::stats().evictions;
    let second =
        warm_signer::active_signers_with_ttl(&pool, PASS, ttl).expect("re-derive after TTL");
    assert_eq!(
        warm_signer::stats().derivations,
        before_derivations + 2,
        "expiry must trigger a fresh derivation, not a cache hit"
    );
    assert!(
        warm_signer::stats().evictions > before_evictions,
        "the expired entry must have been evicted (zeroized + munlocked)"
    );
    assert_eq!(second.iter().next().unwrap().key_id, first_key_id);
}

#[test]
fn invalidate_forces_the_next_call_to_derive_again() {
    let _guard = SERIAL.lock().unwrap();
    warm_signer::invalidate();
    let pool = common::create_test_pool();
    create_domain_key(&pool);

    let _first = warm_signer::active_signers(&pool, PASS).expect("first derive");
    let before = warm_signer::stats().derivations;

    // Still within TTL: would normally be a hit.
    warm_signer::active_signers(&pool, PASS).expect("warm hit");
    assert_eq!(warm_signer::stats().derivations, before);

    warm_signer::invalidate();
    warm_signer::active_signers(&pool, PASS).expect("post-invalidate derive");
    assert_eq!(
        warm_signer::stats().derivations,
        before + 1,
        "invalidate() must force the next call to re-derive"
    );
}

#[test]
fn revoked_or_expired_domain_keys_never_appear_in_the_warm_set() {
    let _guard = SERIAL.lock().unwrap();
    warm_signer::invalidate();
    let pool = common::create_test_pool();

    let keep = create_domain_key(&pool);
    let revoked = create_domain_key(&pool);
    pool.revoke_domain_key(&revoked.id)
        .expect("revoke test key");

    let warm = warm_signer::active_signers(&pool, PASS).expect("derive with a revoked sibling");
    let ids: Vec<&str> = warm.iter().map(|s| s.key_id).collect();
    assert!(ids.contains(&keep.id.as_str()));
    assert!(
        !ids.contains(&revoked.id.as_str()),
        "a revoked domain key must never be served warm"
    );
}

#[test]
fn evicting_an_entry_is_reflected_in_the_eviction_count() {
    let _guard = SERIAL.lock().unwrap();
    warm_signer::invalidate();
    let pool = common::create_test_pool();
    create_domain_key(&pool);
    create_domain_key(&pool);

    let set = warm_signer::active_signers(&pool, PASS).expect("derive");
    let n = set.len();
    drop(set);

    let before = warm_signer::stats().evictions;
    warm_signer::invalidate();
    let after = warm_signer::stats().evictions;
    assert_eq!(
        after - before,
        n as u64,
        "invalidating a fully-dereferenced warm set must evict every entry \
         (each entry zeroizes and munlocks itself on drop)"
    );
}

#[test]
fn with_active_signers_reads_the_passphrase_from_the_environment() {
    let _guard = SERIAL.lock().unwrap();
    warm_signer::invalidate();
    let pool = common::create_test_pool();
    create_domain_key(&pool);

    // SAFETY-ish: this test holds `SERIAL` for its whole body, and no other
    // test in this binary reads/writes this env var, so there is no race on
    // the process environment across tests here.
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    let result = warm_signer::with_active_signers(&pool, |signers| signers.len());
    std::env::remove_var("DOMAIN_KEY_PASSPHRASE");

    assert_eq!(result.expect("with_active_signers must succeed"), 1);
}
