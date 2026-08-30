//! Bounded, in-process rate limiting (SEC-05).
//!
//! A token-bucket keyed by an arbitrary string (e.g. a username or an email
//! address), held in a single `Mutex<HashMap>`. Designed for the project's
//! low-CPU / low-memory target: memory is capped by `max_entries` with
//! opportunistic idle and oldest-entry eviction. A global bucket prevents key
//! rotation from bypassing the limit. This is a best-effort abuse/DoS brake,
//! not a distributed quota. It is per-process and does not survive restarts.
//!
//! It is deliberately NOT a security boundary on its own: authorization and
//! credential checks still run. It only slows online brute force and blunts
//! spam amplification.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::Instant;

struct Bucket {
    tokens: f64,
    last: Instant,
}

pub struct RateLimiter {
    inner: Mutex<LimiterState>,
    /// Burst size — the maximum number of tokens a bucket can hold.
    capacity: f64,
    /// Tokens replenished per second.
    refill_per_sec: f64,
    /// Hard cap on tracked keys, bounding memory.
    max_entries: usize,
    global_capacity: f64,
    global_refill_per_sec: f64,
}

struct LimiterState {
    buckets: HashMap<[u8; 32], Bucket>,
    global: Bucket,
}

impl RateLimiter {
    pub fn new(
        capacity: f64,
        refill_per_sec: f64,
        max_entries: usize,
        global_capacity: f64,
        global_refill_per_sec: f64,
    ) -> Self {
        RateLimiter {
            inner: Mutex::new(LimiterState {
                buckets: HashMap::new(),
                global: Bucket {
                    tokens: global_capacity,
                    last: Instant::now(),
                },
            }),
            capacity,
            refill_per_sec,
            max_entries,
            global_capacity,
            global_refill_per_sec,
        }
    }

    /// Consume one token for `key`. Returns true if allowed, false if the caller
    /// is currently rate limited. A poisoned lock fails open (returns true): the
    /// limiter must never wedge a legitimate login.
    pub fn check(&self, key: &str) -> bool {
        let mut state = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return true,
        };
        let now = Instant::now();
        let key: [u8; 32] = Sha256::digest(key.as_bytes()).into();
        let global_elapsed = now.duration_since(state.global.last).as_secs_f64();
        state.global.tokens = (state.global.tokens + global_elapsed * self.global_refill_per_sec)
            .min(self.global_capacity);
        state.global.last = now;
        if state.global.tokens < 1.0 {
            return false;
        }

        if !state.buckets.contains_key(&key) && state.buckets.len() >= self.max_entries {
            // Drop buckets that have fully refilled. If all buckets are active,
            // evict the oldest one. The independent global bucket prevents key
            // rotation from resetting the total request quota.
            let full_refill_secs = self.capacity / self.refill_per_sec;
            state
                .buckets
                .retain(|_, b| now.duration_since(b.last).as_secs_f64() < full_refill_secs);
            if state.buckets.len() >= self.max_entries {
                let oldest = state
                    .buckets
                    .iter()
                    .min_by_key(|(_, bucket)| bucket.last)
                    .map(|(key, _)| *key);
                if let Some(oldest) = oldest {
                    state.buckets.remove(&oldest);
                }
            }
        }

        let bucket = state.buckets.entry(key).or_insert(Bucket {
            tokens: self.capacity,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        bucket.last = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            state.global.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Password-login attempts, keyed by (lowercased) username. ~5 rapid attempts,
/// then one every 6 seconds. Blunts online brute force per account.
pub static LOGIN: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(5.0, 1.0 / 6.0, 4096, 100.0, 10.0));
/// Password work by network source. This bound protects the shared Argon2 work
/// slots when an attacker rotates usernames.
pub static LOGIN_SOURCE: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(20.0, 1.0, 4096, 100.0, 10.0));
/// API-key checks by network source. API keys are for applications, so this
/// limit permits a larger burst than browser login.
pub static API_KEY_SOURCE: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(10.0, 2.0, 4096, 100.0, 20.0));
/// Expensive legacy API-key checks by the old eight-character user prefix.
/// A successful check upgrades the stored digest and leaves this path.
pub static LEGACY_API_PREFIX: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(1.0, 1.0 / 60.0, 4096, 20.0, 1.0));
/// Current-password checks for an authenticated account.
pub static STEP_UP: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(5.0, 1.0 / 6.0, 4096, 100.0, 10.0));

/// Verification-email sends, keyed by recipient/user. 3 quick sends, then one
/// per minute — enough for a genuine retry, not for spamming.
pub static EMAIL: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(3.0, 1.0 / 60.0, 4096, 100.0, 5.0));

/// Public recovery requests. Separate source, account, and destination keys
/// prevent one caller from flooding the service, one account, or one contact.
pub static RECOVERY_SOURCE: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(5.0, 1.0 / 60.0, 4096, 100.0, 5.0));
pub static RECOVERY_ACCOUNT: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(3.0, 1.0 / 300.0, 4096, 100.0, 5.0));
pub static RECOVERY_DESTINATION: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(3.0, 1.0 / 300.0, 4096, 100.0, 5.0));
/// Public recovery-token checks. This protects indexed database lookups without
/// consuming the smaller quota that controls outbound recovery messages.
pub static RECOVERY_TOKEN_SOURCE: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(30.0, 5.0, 4096, 500.0, 50.0));

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
    LazyLock::new(|| RateLimiter::new(20.0, 1.0 / 3.0, 4096, 200.0, 20.0));

#[cfg(test)]
mod tests {
    use super::RateLimiter;

    #[test]
    fn allows_burst_then_blocks() {
        let rl = RateLimiter::new(3.0, 0.0001, 16, 16.0, 0.0001);
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
        let rl = RateLimiter::new(1.0, 1000.0, 8, 1000.0, 1000.0);
        for i in 0..100 {
            rl.check(&format!("key-{i}"));
        }
        assert!(rl.inner.lock().unwrap().buckets.len() <= 8);
    }

    #[test]
    fn new_keys_do_not_bypass_the_global_limit_or_block_admission_forever() {
        let rl = RateLimiter::new(1.0, 0.0001, 2, 3.0, 0.0001);
        assert!(rl.check("victim"));
        assert!(rl.check("other"));
        assert!(rl.check("attacker"));
        assert!(!rl.check("new-source"));
        assert!(!rl.check("victim"));
        assert!(rl.inner.lock().unwrap().buckets.len() <= 2);
    }
}
