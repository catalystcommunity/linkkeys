//! Tests for `services::pubkey_cache`: the bounded, coalescing, encoded-
//! response cache in front of home-domain public-key reads. No database is
//! needed here — this module is pure in-process cache logic, so these tests
//! construct `ResponseCache` directly with explicit parameters rather than
//! going through the env-configured `LazyLock` statics.

use linkkeys::services::pubkey_cache::{CacheError, CacheKey, ResponseCache};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

fn app_key(subject: &str, domain: &str, app: &str, instance: &str) -> CacheKey {
    CacheKey::ApplicationKey {
        subject_user_id: subject.to_string(),
        subject_domain: domain.to_string(),
        application_id: app.to_string(),
        instance_id: instance.to_string(),
    }
}

// A hit must not repeat database row mapping or CBOR encoding: the cache
// holds the encoded bytes, so the loader runs once and every subsequent hit
// returns the same bytes without calling it again.
#[test]
fn hit_does_not_re_invoke_the_loader() {
    let cache = ResponseCache::new(
        100,
        1_000_000,
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let key = app_key("subject-1", "example.com", "tinku", "instance-1");
    let calls = AtomicUsize::new(0);

    let load = || {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(Some(b"encoded-response-bytes".to_vec()))
    };

    let first = cache.get_or_load(&key, load).unwrap();
    assert_eq!(
        first.as_deref().map(|b| b.as_slice()),
        Some(&b"encoded-response-bytes"[..])
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Second and third calls must hit the cache, not the loader.
    for _ in 0..2 {
        let hit = cache
            .get_or_load(&key, || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(Some(b"should-not-be-called".to_vec()))
            })
            .unwrap();
        assert_eq!(
            hit.as_deref().map(|b| b.as_slice()),
            Some(&b"encoded-response-bytes"[..])
        );
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "cached bytes must not re-run the loader"
    );

    let stats = cache.stats();
    assert_eq!(stats.misses, 1);
    assert_eq!(stats.hits, 2);
}

// A hit must return the identical bytes the loader produced, sharing the same
// underlying allocation (Arc), not a copy made from re-encoding.
#[test]
fn hit_returns_the_same_backing_allocation() {
    let cache = ResponseCache::new(
        100,
        1_000_000,
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let key = app_key("subject-1", "example.com", "tinku", "instance-1");

    let first = cache
        .get_or_load(&key, || Ok(Some(vec![1, 2, 3])))
        .unwrap()
        .unwrap();
    let second = cache
        .get_or_load(&key, || panic!("loader must not run on a cache hit"))
        .unwrap()
        .unwrap();
    assert!(
        Arc::ptr_eq(&first, &second),
        "a hit must share the cached allocation"
    );
}

// Bounded by both entry count and total bytes: inserting far past the
// configured budget must not let either gauge grow past its bound.
#[test]
fn eviction_keeps_entry_count_and_byte_count_within_budget() {
    let max_entries = 20usize;
    let max_bytes = 20 * 200usize; // 200 bytes per entry, so entries are the binding constraint here too
    let cache = ResponseCache::new(
        max_entries,
        max_bytes,
        Duration::from_secs(60),
        Duration::from_secs(1),
    );

    for i in 0..2_000 {
        let key = app_key("subject", "example.com", "tinku", &format!("instance-{i}"));
        let payload = vec![7u8; 200];
        cache
            .get_or_load(&key, || Ok(Some(payload.clone())))
            .unwrap();

        let stats = cache.stats();
        assert!(
            stats.entries as usize <= max_entries,
            "entry count {} exceeded budget {max_entries} after inserting instance-{i}",
            stats.entries
        );
        assert!(
            stats.bytes as usize <= max_bytes,
            "byte count {} exceeded budget {max_bytes} after inserting instance-{i}",
            stats.bytes
        );
    }

    let stats = cache.stats();
    assert!(stats.entries as usize <= max_entries);
    assert!(stats.bytes as usize <= max_bytes);
    assert!(
        stats.evictions > 0,
        "inserting far past the budget must have evicted entries"
    );
}

// A response larger than the whole byte budget is returned to the caller but
// never stored, so it cannot single-handedly blow the byte bound.
#[test]
fn oversized_response_is_served_but_not_cached() {
    let cache = ResponseCache::new(10, 100, Duration::from_secs(60), Duration::from_secs(1));
    let key = app_key("subject", "example.com", "tinku", "huge");
    let big = vec![0u8; 1_000];

    let result = cache.get_or_load(&key, || Ok(Some(big.clone()))).unwrap();
    assert_eq!(
        result.unwrap().len(),
        1_000,
        "the caller must still get the bytes"
    );

    let stats = cache.stats();
    assert_eq!(stats.entries, 0, "an oversized response must not be stored");
    assert_eq!(stats.bytes, 0);

    // Prove it was not stored: a second call re-invokes the loader.
    let calls = AtomicUsize::new(0);
    cache
        .get_or_load(&key, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(big.clone()))
        })
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

// Negative caching: an `Ok(None)` loader result is cached, so a repeated
// lookup for an unknown subject/instance does not repeat the query, and the
// negative TTL is much shorter than the positive TTL.
#[test]
fn negative_entries_suppress_repeated_lookups_and_expire_quickly() {
    let cache = ResponseCache::new(
        100,
        1_000_000,
        Duration::from_secs(60),
        Duration::from_millis(30),
    );
    let key = app_key("subject", "example.com", "tinku", "unknown-instance");
    let calls = AtomicUsize::new(0);

    let result = cache
        .get_or_load(&key, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        })
        .unwrap();
    assert!(result.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Immediately repeating the lookup must hit the negative entry.
    let cached = cache
        .get_or_load(&key, || {
            panic!("must not re-run the loader for a live negative entry")
        })
        .unwrap();
    assert!(cached.is_none());
    assert_eq!(cache.stats().negative_hits, 1);

    // After the (short) negative TTL elapses, the loader runs again.
    thread::sleep(Duration::from_millis(60));
    cache
        .get_or_load(&key, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        })
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "an expired negative entry must be reloaded"
    );
}

// The negative-TTL-must-be-shorter-than-positive-TTL rule: a misconfiguration
// (negative >= positive) is clamped to a value strictly shorter than the
// positive TTL, and a construction with a correctly ordered pair is left
// untouched. This project's choice is to clamp and log rather than refuse
// the configuration, because this cache is built from a lazily-initialized
// static on the request path and must not take the whole server down over a
// single misconfigured env var.
#[test]
fn misconfigured_negative_ttl_is_clamped_below_the_positive_ttl() {
    let ttl = Duration::from_secs(100);

    let equal = ResponseCache::new(10, 10_000, ttl, ttl);
    assert!(
        equal.negative_ttl() < equal.ttl(),
        "an equal negative TTL must be clamped strictly below the positive TTL"
    );

    let longer = ResponseCache::new(10, 10_000, ttl, Duration::from_secs(200));
    assert!(
        longer.negative_ttl() < longer.ttl(),
        "a longer negative TTL must be clamped strictly below the positive TTL"
    );

    let well_formed = ResponseCache::new(10, 10_000, ttl, Duration::from_secs(5));
    assert_eq!(
        well_formed.negative_ttl(),
        Duration::from_secs(5),
        "an already-shorter negative TTL must be left alone"
    );
}

// Single-flight coalescing: N concurrent misses for the SAME key must result
// in exactly one loader call, and every caller gets the same bytes.
#[test]
fn concurrent_misses_for_the_same_key_coalesce_to_one_loader_call() {
    let cache = Arc::new(ResponseCache::new(
        100,
        1_000_000,
        Duration::from_secs(60),
        Duration::from_secs(1),
    ));
    let key = app_key("subject", "example.com", "tinku", "hot-instance");
    let loader_calls = Arc::new(AtomicUsize::new(0));

    const THREADS: usize = 16;
    let barrier = Arc::new(Barrier::new(THREADS));
    let mut handles = Vec::new();

    for _ in 0..THREADS {
        let cache = Arc::clone(&cache);
        let key = key.clone();
        let loader_calls = Arc::clone(&loader_calls);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            cache
                .get_or_load(&key, || {
                    loader_calls.fetch_add(1, Ordering::SeqCst);
                    // Hold the "database work" open briefly so other threads
                    // reliably observe an in-flight load rather than racing
                    // to each be first.
                    thread::sleep(Duration::from_millis(50));
                    Ok(Some(b"single-flight-bytes".to_vec()))
                })
                .unwrap()
        }));
    }

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    assert_eq!(
        loader_calls.load(Ordering::SeqCst),
        1,
        "exactly one loader call must serve every concurrent caller"
    );
    for result in &results {
        assert_eq!(
            result.as_deref().map(|b| b.as_slice()),
            Some(&b"single-flight-bytes"[..])
        );
    }

    let stats = cache.stats();
    assert_eq!(stats.misses, 1);
    assert_eq!(stats.coalesced_loads as usize, THREADS - 1);
}

// Misses for DIFFERENT keys must not block each other, even when they land
// in the same shard's lock momentarily during bookkeeping.
#[test]
fn concurrent_misses_for_different_keys_do_not_block_each_other() {
    let cache = Arc::new(ResponseCache::new(
        100,
        1_000_000,
        Duration::from_secs(60),
        Duration::from_secs(1),
    ));

    const THREADS: usize = 8;
    let barrier = Arc::new(Barrier::new(THREADS));
    let mut handles = Vec::new();

    let start = std::time::Instant::now();
    for i in 0..THREADS {
        let cache = Arc::clone(&cache);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let key = app_key("subject", "example.com", "tinku", &format!("instance-{i}"));
            barrier.wait();
            cache
                .get_or_load(&key, || {
                    // Each loader is slow; if misses serialized on a shared
                    // lock this whole test would take THREADS * 150ms.
                    thread::sleep(Duration::from_millis(150));
                    Ok(Some(format!("bytes-{i}").into_bytes()))
                })
                .unwrap()
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(150 * (THREADS as u64) / 2),
        "misses for different keys must run concurrently, took {elapsed:?}"
    );
}

// A cache entry must never cross a subject, application, or instance
// boundary: three near-identical keys differing in exactly one component
// each get their own entry, and each returns only its own bytes.
#[test]
fn keys_never_cross_subject_application_or_instance_boundaries() {
    let cache = ResponseCache::new(
        100,
        1_000_000,
        Duration::from_secs(60),
        Duration::from_secs(1),
    );

    let base = app_key("subject-a", "example.com", "app-a", "instance-a");
    let different_subject = app_key("subject-b", "example.com", "app-a", "instance-a");
    let different_application = app_key("subject-a", "example.com", "app-b", "instance-a");
    let different_instance = app_key("subject-a", "example.com", "app-a", "instance-b");
    let different_domain = app_key("subject-a", "other.example.com", "app-a", "instance-a");

    let variants: [(&CacheKey, &str); 5] = [
        (&base, "base"),
        (&different_subject, "subject"),
        (&different_application, "application"),
        (&different_instance, "instance"),
        (&different_domain, "domain"),
    ];

    for (key, label) in variants {
        let payload = format!("bytes-for-{label}").into_bytes();
        let stored = payload.clone();
        let result = cache
            .get_or_load(key, || Ok(Some(stored.clone())))
            .unwrap()
            .unwrap();
        assert_eq!(&*result, &payload[..], "loader ran for {label}");
    }

    // Re-reading each key must return only its own bytes — never another
    // variant's — and must not re-invoke the loader (proves each is its own
    // stored entry, not aliasing one shared slot).
    for (key, label) in variants {
        let expected = format!("bytes-for-{label}").into_bytes();
        let result = cache
            .get_or_load(key, || panic!("{label} must already be cached"))
            .unwrap()
            .unwrap();
        assert_eq!(
            &*result,
            &expected[..],
            "{label} entry leaked another entry's bytes"
        );
    }

    assert_eq!(
        cache.stats().entries,
        5,
        "five distinct keys must produce five distinct entries"
    );
}

// `invalidate` removes exactly the named entry and leaves the rest untouched.
#[test]
fn invalidate_removes_only_the_named_entry() {
    let cache = ResponseCache::new(
        100,
        1_000_000,
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let target = app_key("subject", "example.com", "tinku", "target");
    let other = app_key("subject", "example.com", "tinku", "other");

    cache
        .get_or_load(&target, || Ok(Some(b"target-bytes".to_vec())))
        .unwrap();
    cache
        .get_or_load(&other, || Ok(Some(b"other-bytes".to_vec())))
        .unwrap();
    assert_eq!(cache.stats().entries, 2);

    cache.invalidate(&target);
    assert_eq!(cache.stats().entries, 1);

    // The invalidated key must reload from the loader.
    let calls = AtomicUsize::new(0);
    let reloaded = cache
        .get_or_load(&target, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(b"target-bytes-v2".to_vec()))
        })
        .unwrap()
        .unwrap();
    assert_eq!(&*reloaded, b"target-bytes-v2");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // The other key must still be cached, untouched.
    let still_cached = cache
        .get_or_load(&other, || panic!("the untouched entry must not reload"))
        .unwrap()
        .unwrap();
    assert_eq!(&*still_cached, b"other-bytes");
}

// `invalidate_all` clears every entry and resets the gauges to zero.
#[test]
fn invalidate_all_clears_every_entry() {
    let cache = ResponseCache::new(
        100,
        1_000_000,
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    for i in 0..10 {
        let key = app_key("subject", "example.com", "tinku", &format!("instance-{i}"));
        cache.get_or_load(&key, || Ok(Some(vec![1, 2, 3]))).unwrap();
    }
    assert_eq!(cache.stats().entries, 10);

    cache.invalidate_all();
    let stats = cache.stats();
    assert_eq!(stats.entries, 0);
    assert_eq!(stats.bytes, 0);
}

// An expired positive entry is treated as a miss and reloaded, not served
// stale.
#[test]
fn expired_entries_are_reloaded_not_served_stale() {
    let cache = ResponseCache::new(
        100,
        1_000_000,
        Duration::from_millis(30),
        Duration::from_millis(1),
    );
    let key = app_key("subject", "example.com", "tinku", "instance");

    cache
        .get_or_load(&key, || Ok(Some(b"v1".to_vec())))
        .unwrap();
    thread::sleep(Duration::from_millis(60));

    let reloaded = cache
        .get_or_load(&key, || Ok(Some(b"v2".to_vec())))
        .unwrap()
        .unwrap();
    assert_eq!(
        &*reloaded, b"v2",
        "an expired entry must not be served after its TTL"
    );
    assert_eq!(cache.stats().misses, 2, "expiry must count as a fresh miss");
}

// A loader error is never cached: the next call retries rather than being
// stuck with a cached failure or a phantom entry.
#[test]
fn loader_errors_are_not_cached() {
    let cache = ResponseCache::new(
        100,
        1_000_000,
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let key = app_key("subject", "example.com", "tinku", "instance");

    let err = cache
        .get_or_load(&key, || {
            Err::<Option<Vec<u8>>, CacheError>(CacheError::from("db unavailable"))
        })
        .unwrap_err();
    assert_eq!(err.to_string(), "db unavailable");
    assert_eq!(
        cache.stats().entries,
        0,
        "a failed load must not create an entry"
    );

    let recovered = cache
        .get_or_load(&key, || Ok(Some(b"recovered".to_vec())))
        .unwrap()
        .unwrap();
    assert_eq!(&*recovered, b"recovered");
}

// The domain-key snapshot use case: DomainKeys and Revocations are distinct
// keys sharing one cache instance, each independently invalidated.
#[test]
fn domain_snapshot_keys_are_independent() {
    let cache = ResponseCache::new(
        8,
        1_000_000,
        Duration::from_secs(60),
        Duration::from_secs(1),
    );

    cache
        .get_or_load(&CacheKey::DomainKeys, || {
            Ok(Some(b"domain-keys-bytes".to_vec()))
        })
        .unwrap();
    cache
        .get_or_load(&CacheKey::Revocations, || {
            Ok(Some(b"revocations-bytes".to_vec()))
        })
        .unwrap();

    cache.invalidate(&CacheKey::DomainKeys);

    let calls = AtomicUsize::new(0);
    cache
        .get_or_load(&CacheKey::DomainKeys, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(b"domain-keys-bytes-v2".to_vec()))
        })
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "invalidating DomainKeys must force a reload"
    );

    let revocations = cache
        .get_or_load(&CacheKey::Revocations, || {
            panic!("Revocations must be unaffected")
        })
        .unwrap()
        .unwrap();
    assert_eq!(&*revocations, b"revocations-bytes");
}
