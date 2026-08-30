//! Black-box tests for `services::public_ratelimit`: bounded abuse controls
//! for the ANONYMOUS public-key read surface (domain-key, application-key,
//! and revocation reads share this one budget). See `signing-things-request.md`,
//! "Public-key rate limits and DDoS protection".
//!
//! These tests only use the module's public API — the same surface the TCP
//! dispatch layer (`public_read_gate` in `src/tcp/mod.rs`) uses — so they
//! double as a check that the public API is actually usable from outside the
//! crate. Every test builds its own `PublicReadLimiter` from explicit
//! `PublicReadLimiterConfig` values (never touching process environment
//! variables), so tests are independent of each other and of `PUBLIC_READS`.

use ipnet::IpNet;
use linkkeys::services::public_ratelimit::{
    normalize_source, LimitReason, PublicReadDecision, PublicReadLimiter, PublicReadLimiterConfig,
    SourceKey,
};
use std::net::{IpAddr, SocketAddr};

fn ipv4_peer(a: u8, b: u8, c: u8, d: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::from([a, b, c, d]), 443)
}

/// Layers other than the one under test should not interfere.
fn generous_config() -> PublicReadLimiterConfig {
    PublicReadLimiterConfig {
        global_capacity: 1_000_000.0,
        global_refill_per_sec: 1_000_000.0,
        distinct_source_threshold: 1_000_000,
        ..PublicReadLimiterConfig::default()
    }
}

#[test]
fn default_bucket_allows_100_then_blocks() {
    let limiter = PublicReadLimiter::new(generous_config());
    let source = limiter.source_key(ipv4_peer(10, 0, 0, 1), None);
    for _ in 0..100 {
        assert_eq!(limiter.check(&source), PublicReadDecision::Allow);
    }
    match limiter.check(&source) {
        PublicReadDecision::Limited {
            reason: LimitReason::PerSource,
            retry_after_seconds,
        } => {
            assert!(retry_after_seconds >= 1);
        }
        other => panic!("expected PerSource limit on request 101, got {other:?}"),
    }
}

#[test]
fn refill_restores_capacity() {
    let config = PublicReadLimiterConfig {
        per_source_capacity: 2.0,
        per_source_refill_per_sec: 1000.0, // refills almost immediately
        ..generous_config()
    };
    let limiter = PublicReadLimiter::new(config);
    let source = limiter.source_key(ipv4_peer(10, 0, 0, 2), None);
    assert_eq!(limiter.check(&source), PublicReadDecision::Allow);
    assert_eq!(limiter.check(&source), PublicReadDecision::Allow);
    assert!(matches!(
        limiter.check(&source),
        PublicReadDecision::Limited {
            reason: LimitReason::PerSource,
            ..
        }
    ));
    std::thread::sleep(std::time::Duration::from_millis(20));
    assert_eq!(limiter.check(&source), PublicReadDecision::Allow);
}

#[test]
fn configuration_override_changes_behaviour() {
    // A much smaller budget than the documented 100-request default proves
    // configuration actually changes enforced behaviour.
    let config = PublicReadLimiterConfig {
        per_source_capacity: 5.0,
        per_source_refill_per_sec: 0.0001,
        ..generous_config()
    };
    let limiter = PublicReadLimiter::new(config);
    let source = limiter.source_key(ipv4_peer(10, 0, 0, 3), None);
    for _ in 0..5 {
        assert_eq!(limiter.check(&source), PublicReadDecision::Allow);
    }
    assert!(matches!(
        limiter.check(&source),
        PublicReadDecision::Limited {
            reason: LimitReason::PerSource,
            ..
        }
    ));
}

#[test]
fn ipv6_addresses_in_the_same_prefix_share_a_bucket() {
    let a: IpAddr = "2001:db8:1234:5678::1".parse().unwrap();
    let b: IpAddr = "2001:db8:1234:5678:ffff:ffff:ffff:ffff".parse().unwrap();
    let c: IpAddr = "2001:db8:1234:5679::1".parse().unwrap();

    let key_a = normalize_source(SocketAddr::new(a, 1), None, &[], 64);
    let key_b = normalize_source(SocketAddr::new(b, 1), None, &[], 64);
    let key_c = normalize_source(SocketAddr::new(c, 1), None, &[], 64);

    assert_eq!(key_a, key_b, "same /64 must share a bucket");
    assert_ne!(key_a, key_c, "different /64 must not share a bucket");

    // The prefix length is configurable: a /48 merges what a /64 would treat
    // as distinct.
    let key_a48 = normalize_source(SocketAddr::new(a, 1), None, &[], 48);
    let key_c48 = normalize_source(SocketAddr::new(c, 1), None, &[], 48);
    assert_eq!(
        key_a48, key_c48,
        "same /48 must share a bucket when configured"
    );
}

#[test]
fn more_than_10000_distinct_sources_stay_bounded() {
    // Uses the real 10,000 default distinct-source threshold; only the
    // global bucket is widened so it can't be what's rejecting requests.
    let config = PublicReadLimiterConfig {
        global_capacity: 10_000_000.0,
        global_refill_per_sec: 10_000_000.0,
        ..PublicReadLimiterConfig::default()
    };
    let limiter = PublicReadLimiter::new(config);
    assert_eq!(limiter.tracked_source_count(), 0);

    for i in 0..15_000u32 {
        let peer = SocketAddr::new(IpAddr::from(i.to_be_bytes()), 1);
        let source = limiter.source_key(peer, None);
        limiter.check(&source);
        assert!(
            limiter.tracked_source_count() <= 10_000,
            "tracked-source count exceeded the configured bound at i={i}"
        );
    }
    assert_eq!(limiter.tracked_source_count(), 10_000);
    assert!(limiter.protection_mode_entries() >= 1);
    assert!(
        limiter.rejected_overflow() > 0,
        "sources past the threshold should overflow"
    );
}

#[test]
fn protection_mode_preserves_known_sources_and_allocates_no_state_for_new_ones() {
    let config = PublicReadLimiterConfig {
        distinct_source_threshold: 3,
        overflow_capacity: 1.0,
        overflow_refill_per_sec: 0.0001,
        ..generous_config()
    };
    let limiter = PublicReadLimiter::new(config);

    let known: Vec<SourceKey> = (0..3)
        .map(|i| limiter.source_key(ipv4_peer(10, 1, 0, i), None))
        .collect();
    for key in &known {
        assert_eq!(limiter.check(key), PublicReadDecision::Allow);
    }
    assert_eq!(limiter.tracked_source_count(), 3);

    // A brand-new source now finds the tracker full: protection mode.
    let newcomer = limiter.source_key(ipv4_peer(10, 1, 1, 1), None);
    assert_eq!(limiter.check(&newcomer), PublicReadDecision::Allow); // overflow bucket had 1 token
    assert!(matches!(
        limiter.check(&newcomer),
        PublicReadDecision::Limited {
            reason: LimitReason::Overflow,
            ..
        }
    ));
    // No per-source state was allocated for it: the tracked count is
    // unchanged.
    assert_eq!(limiter.tracked_source_count(), 3);

    // A source that was already known continues under its own budget.
    assert_eq!(limiter.check(&known[0]), PublicReadDecision::Allow);

    assert_eq!(
        limiter.protection_mode_entries(),
        1,
        "one bounded event per window, not per request"
    );
}

#[test]
fn source_rotation_cannot_bypass_the_global_limit() {
    let config = PublicReadLimiterConfig {
        per_source_capacity: 1_000_000.0,
        per_source_refill_per_sec: 1_000_000.0,
        distinct_source_threshold: 1_000_000,
        global_capacity: 5.0,
        global_refill_per_sec: 0.0001,
        ..PublicReadLimiterConfig::default()
    };
    let limiter = PublicReadLimiter::new(config);

    let mut allowed = 0;
    for i in 0..50u32 {
        let peer = SocketAddr::new(IpAddr::from(i.to_be_bytes()), 1);
        let source = limiter.source_key(peer, None); // a fresh source every time
        if limiter.check(&source) == PublicReadDecision::Allow {
            allowed += 1;
        }
    }
    assert_eq!(
        allowed, 5,
        "the independent global bucket must still cap total admissions"
    );
    assert!(limiter.rejected_global() > 0);
}

#[test]
fn attacker_claimed_identifiers_cannot_drain_a_victim_source_bucket() {
    // The limiter's public API — `check(&SourceKey)` and
    // `source_key(peer, forwarded_for)` — never accepts a subject UUID,
    // application id, instance id, or RP fingerprint at all: the key is a
    // pure function of the transport peer address. Demonstrate that
    // hammering a *different* source (standing in for an attacker who claims
    // a victim's identifiers in request content the limiter never sees)
    // does not touch the victim's own budget.
    let config = PublicReadLimiterConfig {
        per_source_capacity: 3.0,
        ..generous_config()
    };
    let limiter = PublicReadLimiter::new(config);

    let victim = limiter.source_key(ipv4_peer(203, 0, 113, 9), None);
    let attacker = limiter.source_key(ipv4_peer(198, 51, 100, 7), None);
    assert_ne!(victim, attacker);

    for _ in 0..10 {
        limiter.check(&attacker);
    }

    // The victim's bucket is untouched: it still has its full budget.
    for _ in 0..3 {
        assert_eq!(limiter.check(&victim), PublicReadDecision::Allow);
    }
    assert!(matches!(
        limiter.check(&victim),
        PublicReadDecision::Limited {
            reason: LimitReason::PerSource,
            ..
        }
    ));
}

#[test]
fn normalize_source_ignores_everything_but_the_transport_peer() {
    let peer = ipv4_peer(192, 0, 2, 1);
    let a = normalize_source(peer, None, &[], 64);
    let b = normalize_source(peer, None, &[], 64);
    assert_eq!(a, b, "the same peer must always normalize to the same key");
}

#[test]
fn trusted_proxy_forwarded_header_is_honored_only_when_configured() {
    let proxy_addr: IpAddr = "10.9.9.9".parse().unwrap();
    let trusted: Vec<IpNet> = vec![format!("{proxy_addr}/32").parse().unwrap()];
    let peer = SocketAddr::new(proxy_addr, 443);

    // The trusted proxy appends the address of whoever connected TO IT (the
    // real client) on the right; anything to the left could have been
    // supplied by that client itself and must not be trusted.
    let header = "198.51.100.20, 203.0.113.5";
    let via_trusted = normalize_source(peer, Some(header), &trusted, 64);
    let direct = normalize_source(
        SocketAddr::new("203.0.113.5".parse().unwrap(), 1),
        None,
        &[],
        64,
    );
    assert_eq!(
        via_trusted, direct,
        "a trusted proxy's rightmost XFF entry should be honored"
    );

    // Same header, but the proxy is NOT in the trusted list: ignored, so the
    // key is derived from the direct peer instead.
    let via_untrusted = normalize_source(peer, Some(header), &[], 64);
    let direct_proxy = normalize_source(peer, None, &[], 64);
    assert_eq!(
        via_untrusted, direct_proxy,
        "an untrusted proxy's header must be ignored"
    );
}

#[test]
fn window_rotation_frees_memory() {
    let config = PublicReadLimiterConfig {
        distinct_source_threshold: 5,
        window_seconds: 1,
        ..generous_config()
    };
    let limiter = PublicReadLimiter::new(config);
    for i in 0..5u8 {
        let source = limiter.source_key(ipv4_peer(10, 2, 0, i), None);
        limiter.check(&source);
    }
    assert_eq!(limiter.tracked_source_count(), 5);

    std::thread::sleep(std::time::Duration::from_millis(1100));

    // The next check rotates the (elapsed) window lazily.
    let fresh = limiter.source_key(ipv4_peer(10, 2, 1, 1), None);
    limiter.check(&fresh);
    assert_eq!(
        limiter.tracked_source_count(),
        1,
        "the old window's tracked set must be dropped"
    );
}

#[test]
fn different_sources_spread_across_shards_and_make_concurrent_progress() {
    let limiter = std::sync::Arc::new(PublicReadLimiter::new(generous_config()));
    assert!(limiter.shard_count() >= 2);

    // Structural assertion: many distinct sources land in more than one
    // shard, so the per-source hot path cannot be serializing every request
    // on a single mutex by construction.
    let keys: Vec<SourceKey> = (0..64u32)
        .map(|i| limiter.source_key(SocketAddr::new(IpAddr::from(i.to_be_bytes()), 1), None))
        .collect();
    let distinct_shards: std::collections::HashSet<usize> =
        keys.iter().map(|k| limiter.shard_index(k)).collect();
    assert!(
        distinct_shards.len() > 1,
        "sources should spread across multiple shards"
    );

    // Functional assertion: threads hammering different sources concurrently
    // all make progress (no deadlock, correct per-source accounting),
    // without asserting anything about wall-clock timing.
    let mut handles = Vec::new();
    for t in 0..8u32 {
        let limiter = limiter.clone();
        handles.push(std::thread::spawn(move || {
            let peer = SocketAddr::new(IpAddr::from((1000 + t).to_be_bytes()), 1);
            let source = limiter.source_key(peer, None);
            let mut allowed = 0;
            for _ in 0..20 {
                if limiter.check(&source) == PublicReadDecision::Allow {
                    allowed += 1;
                }
            }
            allowed
        }));
    }
    for handle in handles {
        let allowed = handle.join().expect("worker thread panicked");
        assert_eq!(
            allowed, 20,
            "each thread's own source has its own untouched 100-token bucket"
        );
    }
}

#[test]
fn config_from_env_defaults_match_documented_values() {
    // Sanity check the documented defaults without depending on process
    // environment state (tests may run in parallel and share env vars).
    let d = PublicReadLimiterConfig::default();
    assert_eq!(d.per_source_capacity, 100.0);
    assert_eq!(d.per_source_refill_per_sec, 100.0 / 60.0);
    assert_eq!(d.distinct_source_threshold, 10_000);
    assert_eq!(d.window_seconds, 60);
    assert_eq!(d.ipv6_prefix_len, 64);
    assert!(d.trusted_proxies.is_empty());
}

#[test]
fn source_key_from_str_matches_normalize_source_for_valid_addresses() {
    // The dispatch layer (`src/tcp/mod.rs`) only has a plain address string
    // (no port), so it goes through `source_key_from_str` rather than
    // `normalize_source` directly. It must still derive the same key an
    // equivalent `SocketAddr` would.
    use linkkeys::services::public_ratelimit::source_key_from_str;
    let from_str = source_key_from_str("203.0.113.9");
    let from_socket = normalize_source(
        SocketAddr::new("203.0.113.9".parse().unwrap(), 0),
        None,
        &[],
        64,
    );
    assert_eq!(from_str, from_socket);

    // An unparseable sentinel (e.g. "peer address unavailable") does not
    // panic and still yields a stable key.
    let a = source_key_from_str("unknown-tcp-peer");
    let b = source_key_from_str("unknown-tcp-peer");
    assert_eq!(a, b);
    assert_ne!(a, from_str);
}

/// The per-source BUCKET MAP — the structure that actually holds rate-limit
/// state — must stay bounded, not merely the distinct-source window.
///
/// The window resets on its own every minute, so a test that only measures it
/// proves nothing. An attacker cycling fresh addresses at a rate that never
/// even trips protection mode was previously able to grow this map forever.
#[test]
fn the_per_source_bucket_map_stays_bounded_under_endless_fresh_sources() {
    use linkkeys::services::public_ratelimit::{
        normalize_source, PublicReadLimiter, PublicReadLimiterConfig,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let limiter = PublicReadLimiter::new(PublicReadLimiterConfig {
        // A high global rate, so the global bucket does not mask the point.
        global_capacity: 1_000_000.0,
        global_refill_per_sec: 1_000_000.0,
        distinct_source_threshold: 256,
        shard_count: 4,
        ..PublicReadLimiterConfig::default()
    });

    let bound = limiter.max_bucket_entries();
    for i in 0..50_000u32 {
        let octets = i.to_be_bytes();
        let ip = IpAddr::V4(Ipv4Addr::new(10, octets[1], octets[2], octets[3]));
        let key = normalize_source(SocketAddr::new(ip, 0), None, &[], 64);
        limiter.check(&key);
        assert!(
            limiter.bucket_entry_count() <= bound,
            "bucket map grew past its bound at source {i}: {} > {bound}",
            limiter.bucket_entry_count()
        );
    }
    assert!(
        limiter.bucket_entry_count() <= bound,
        "final entry count {} exceeds bound {bound}",
        limiter.bucket_entry_count()
    );
}

/// Pruning must not hand a limited source its budget back. A bucket is only
/// dropped once it has refilled to capacity, which is indistinguishable from
/// never having existed.
#[test]
fn a_source_being_limited_keeps_its_limit_while_others_churn() {
    use linkkeys::services::public_ratelimit::{
        normalize_source, PublicReadDecision, PublicReadLimiter, PublicReadLimiterConfig,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let limiter = PublicReadLimiter::new(PublicReadLimiterConfig {
        per_source_capacity: 5.0,
        // Effectively no refill for the duration of this test, so a spent
        // bucket stays spent and must not be pruned away.
        per_source_refill_per_sec: 0.000_001,
        global_capacity: 1_000_000.0,
        global_refill_per_sec: 1_000_000.0,
        distinct_source_threshold: 64,
        shard_count: 2,
        ..PublicReadLimiterConfig::default()
    });

    let victim = normalize_source(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 0),
        None,
        &[],
        64,
    );
    for _ in 0..5 {
        assert!(matches!(limiter.check(&victim), PublicReadDecision::Allow));
    }
    assert!(matches!(
        limiter.check(&victim),
        PublicReadDecision::Limited { .. }
    ));

    // Churn far past the bound, forcing many prune passes.
    for i in 0..5_000u32 {
        let octets = i.to_be_bytes();
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, octets[2], octets[3]));
        limiter.check(&normalize_source(SocketAddr::new(ip, 0), None, &[], 64));
    }

    assert!(
        matches!(limiter.check(&victim), PublicReadDecision::Limited { .. }),
        "churn must not restore a limited source's budget"
    );
}
