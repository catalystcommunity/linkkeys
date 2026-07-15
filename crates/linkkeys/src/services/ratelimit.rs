//! Bounded, in-process rate limiting (SEC-05).
//!
//! A token-bucket keyed by an arbitrary string (e.g. a username or an email
//! address), held in a single `Mutex<HashMap>`. Designed for the project's
//! low-CPU / low-memory target: memory is capped by `max_entries` with
//! opportunistic eviction of idle buckets, and the whole map is cleared if it
//! ever exceeds the cap (bounded memory is worth more than perfect fairness
//! here). This is a best-effort abuse/DoS brake, not a distributed quota — it is
//! per-process, so it also does not need to survive restarts.
//!
//! It is deliberately NOT a security boundary on its own: authorization and
//! credential checks still run. It only slows online brute force and blunts
//! spam amplification.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::Instant;

struct Bucket {
    tokens: f64,
    last: Instant,
}

pub struct RateLimiter {
    inner: Mutex<HashMap<String, Bucket>>,
    /// Burst size — the maximum number of tokens a bucket can hold.
    capacity: f64,
    /// Tokens replenished per second.
    refill_per_sec: f64,
    /// Hard cap on tracked keys, bounding memory.
    max_entries: usize,
}

impl RateLimiter {
    fn new(capacity: f64, refill_per_sec: f64, max_entries: usize) -> Self {
        RateLimiter {
            inner: Mutex::new(HashMap::new()),
            capacity,
            refill_per_sec,
            max_entries,
        }
    }

    /// Consume one token for `key`. Returns true if allowed, false if the caller
    /// is currently rate limited. A poisoned lock fails open (returns true): the
    /// limiter must never wedge a legitimate login.
    pub fn check(&self, key: &str) -> bool {
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return true,
        };
        let now = Instant::now();

        if map.len() >= self.max_entries {
            // Drop buckets idle long enough to have fully refilled (they carry no
            // useful state). If that isn't enough, clear everything — memory is
            // the hard constraint on this target.
            let full_refill_secs = self.capacity / self.refill_per_sec;
            map.retain(|_, b| now.duration_since(b.last).as_secs_f64() < full_refill_secs);
            if map.len() >= self.max_entries {
                map.clear();
            }
        }

        let bucket = map.entry(key.to_string()).or_insert(Bucket {
            tokens: self.capacity,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        bucket.last = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Password-login attempts, keyed by (lowercased) username. ~5 rapid attempts,
/// then one every 6 seconds. Blunts online brute force per account.
pub static LOGIN: LazyLock<RateLimiter> = LazyLock::new(|| RateLimiter::new(5.0, 1.0 / 6.0, 4096));

/// Verification-email sends, keyed by recipient/user. 3 quick sends, then one
/// per minute — enough for a genuine retry, not for spamming.
pub static EMAIL: LazyLock<RateLimiter> = LazyLock::new(|| RateLimiter::new(3.0, 1.0 / 60.0, 4096));

/// Local RP claim-ticket redemption attempts over TCP (`LocalRp/redeem-claim-
/// ticket`), keyed by the local RP fingerprint. Tickets are deliberately
/// multi-use within their validity window (design doc: "the app can retry or
/// refresh"), so this is more generous than `LOGIN`: ~20 quick attempts, then
/// one every 3 seconds.
///
/// This bucket meters POSSESSION-PROVEN requests only: the dispatch debits it
/// after the redemption signature has verified against the stored signing
/// key, never before. The fingerprint in a redemption request is
/// attacker-chosen, so debiting on the unverified value would let anyone who
/// can reach the TCP port spam a victim RP's fingerprint and exhaust the
/// legitimate app's bucket — a cheap remote DoS of a specific local RP.
/// Post-proof, only the actual key holder can ever consume its own bucket;
/// unverified garbage costs the server one indexed lookup plus one Ed25519
/// verify and never touches the limiter.
pub static TICKET_REDEMPTION: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(20.0, 1.0 / 3.0, 4096));

#[cfg(test)]
mod tests {
    use super::RateLimiter;

    #[test]
    fn allows_burst_then_blocks() {
        let rl = RateLimiter::new(3.0, 0.0001, 16);
        assert!(rl.check("a"));
        assert!(rl.check("a"));
        assert!(rl.check("a"));
        // Bucket exhausted, negligible refill -> blocked.
        assert!(!rl.check("a"));
        // A different key has its own bucket.
        assert!(rl.check("b"));
    }

    #[test]
    fn memory_is_bounded() {
        let rl = RateLimiter::new(1.0, 1000.0, 8);
        for i in 0..100 {
            rl.check(&format!("key-{i}"));
        }
        assert!(rl.inner.lock().unwrap().len() <= 8);
    }
}
