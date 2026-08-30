//! Bounded, coalescing, in-process cache of already-encoded CBOR response
//! bytes, sitting in front of the home-domain public key reads (see
//! "Home-domain response cache" in `signing-things-request.md`).
//!
//! Caching here is load-bearing, not an optimization: it keeps repeated
//! home-domain reads out of normal peer message verification and protects the
//! domain during traffic spikes. The database stays the source of truth. A
//! cache hit must never repeat row mapping or CBOR encoding — the cache holds
//! the already-encoded `Arc<Vec<u8>>` response bytes directly.
//!
//! Two configured instances live here:
//!
//! - [`DOMAIN_SNAPSHOT_CACHE`] holds one immutable encoded snapshot each of
//!   the domain-keys response and the revocations response. Domain key
//!   changes are rare; the service layer must call [`ResponseCache::invalidate`]
//!   after a key addition, renewal, expiry transition, or revocation. A short
//!   TTL is still a backstop against a missed invalidation call and against
//!   the `recent_revocations_available` flag going stale purely from the
//!   passage of time.
//! - [`APPLICATION_KEY_CACHE`] holds one entry per `(subject UUID + domain,
//!   application id, instance id)` triple. A write that adds, renews,
//!   expires, or revokes an application key must invalidate exactly the
//!   affected entry after its database transaction commits.
//!
//! Design notes:
//!
//! - **Coalescing.** Concurrent misses for the same key run the loader
//!   exactly once; other callers wait on that one call's result. This is a
//!   stampede guard, not a general async primitive — `get_or_load` blocks the
//!   calling thread, which is fine on the diesel `spawn_blocking` path this
//!   cache is meant for.
//! - **Sharding.** The key space is split across [`NUM_SHARDS`] independent
//!   mutexes so unrelated keys never serialize on one lock. Only the shard
//!   for the looked-up key is ever touched by a hit or a miss.
//! - **Bounds.** Entry count and byte count are tracked as cache-wide atomic
//!   gauges. An insert that would push either gauge over its configured
//!   budget triggers bounded LRU eviction (a plain linear scan per shard —
//!   shards are small, and this is not a hot path) until the cache is back
//!   within budget, or a fixed attempt cap is hit. A single encoded response
//!   larger than the whole byte budget is served but never stored.
//! - **Negative caching.** A loader that returns `Ok(None)` (unknown subject
//!   or instance) is cached briefly under a separate, deliberately short TTL,
//!   so a repeated lookup for a nonexistent target does not repeat the query.
//!
//! Never log cached bytes, key material, credentials, or claim values. A
//! [`CacheKey`] names a subject UUID and application/instance identifiers,
//! which are not secret and may appear in logs; the response bytes never may.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Number of independent shards the key space is split across. Chosen so
/// concurrent lookups of different keys do not serialize on one mutex, while
/// staying small enough that a per-shard linear LRU scan is cheap.
const NUM_SHARDS: usize = 16;

/// The domain-key snapshot cache is fixed-shape: today it holds at most one
/// entry each for the domain-keys response and the revocations response.
/// It is not configured by entry/byte-count env vars (only its TTL is, per
/// `DOMAIN_KEY_SNAPSHOT_TTL_SECONDS`) because its key space is small and
/// known in advance.
const DOMAIN_SNAPSHOT_MAX_ENTRIES: usize = 8;
const DOMAIN_SNAPSHOT_MAX_BYTES: usize = 8 * 1024 * 1024;
/// Negative caching is not meaningful for the domain snapshot (its keys are
/// fixed, not attacker- or caller-chosen), but the constructor requires a
/// negative TTL strictly shorter than the positive one, so this stays small.
const DOMAIN_SNAPSHOT_NEGATIVE_TTL_SECONDS: u64 = 1;

const DEFAULT_DOMAIN_SNAPSHOT_TTL_SECONDS: u64 = 60;
const DEFAULT_MAX_ENTRIES: u64 = 10_000;
const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_TTL_SECONDS: u64 = 300;
const DEFAULT_NEGATIVE_TTL_SECONDS: u64 = 10;

/// A key naming exactly one cached response. Equality and hashing are
/// structural (derived), so two keys can never collide by concatenation —
/// e.g. an application id of `"a"` with instance `"bc"` cannot be confused
/// with application id `"ab"` and instance `"c"`. This is the property that
/// keeps a cache entry from crossing a subject, application, or instance
/// boundary.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CacheKey {
    /// The encoded `GetDomainKeysResponse` snapshot.
    DomainKeys,
    /// The encoded `GetRevocationsResponse` snapshot.
    Revocations,
    /// One application instance's encoded key/attestation response.
    ApplicationKey {
        subject_user_id: String,
        subject_domain: String,
        application_id: String,
        instance_id: String,
    },
}

impl std::fmt::Display for CacheKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CacheKey::DomainKeys => write!(f, "domain-keys"),
            CacheKey::Revocations => write!(f, "revocations"),
            CacheKey::ApplicationKey {
                subject_user_id,
                subject_domain,
                application_id,
                instance_id,
            } => write!(
                f,
                "application-key:{subject_user_id}@{subject_domain}/{application_id}/{instance_id}"
            ),
        }
    }
}

/// A loader failure. Deliberately opaque (a message only) — this crosses a
/// thread boundary to every coalesced waiter, so it must never carry a
/// database row, a decrypted key, or other sensitive payload.
#[derive(Clone, Debug)]
pub enum CacheError {
    /// The loader (the database read, the row mapping, or the CBOR encode)
    /// failed. Carries only a display message — never row contents or key
    /// material.
    Load(String),
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CacheError::Load(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for CacheError {}

impl From<String> for CacheError {
    fn from(value: String) -> Self {
        CacheError::Load(value)
    }
}

impl From<&str> for CacheError {
    fn from(value: &str) -> Self {
        CacheError::Load(value.to_string())
    }
}

/// Bounded snapshot of the cache's counters. All counters are monotonic
/// totals except `entries` and `bytes`, which are current gauges.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub coalesced_loads: u64,
    pub negative_hits: u64,
    pub entries: u64,
    pub bytes: u64,
}

#[derive(Clone)]
enum CacheValue {
    Positive(Arc<Vec<u8>>),
    Negative,
}

struct Entry {
    value: CacheValue,
    expires_at: Instant,
    last_used: Instant,
    size_bytes: usize,
}

/// Coordination point for one in-flight load. Every caller that observes a
/// miss for a key that is already loading clones this `Arc`, drops the shard
/// lock, and waits here — the leader (the caller that started the load) is
/// the only one that ever calls the loader.
struct InFlight {
    result: Mutex<Option<Result<CacheValue, CacheError>>>,
    cv: Condvar,
}

impl InFlight {
    fn new() -> Self {
        InFlight {
            result: Mutex::new(None),
            cv: Condvar::new(),
        }
    }

    fn wait(&self) -> Result<CacheValue, CacheError> {
        let mut guard = self.result.lock().unwrap_or_else(|e| e.into_inner());
        while guard.is_none() {
            guard = self.cv.wait(guard).unwrap_or_else(|e| e.into_inner());
        }
        guard.clone().expect("checked is_none in the loop above")
    }

    fn finish(&self, result: Result<CacheValue, CacheError>) {
        {
            let mut guard = self.result.lock().unwrap_or_else(|e| e.into_inner());
            *guard = Some(result);
        }
        self.cv.notify_all();
    }
}

enum Slot {
    Ready(Entry),
    Loading(Arc<InFlight>),
}

#[derive(Default)]
struct ShardState {
    map: HashMap<CacheKey, Slot>,
}

/// A generic, bounded, coalescing cache of encoded response bytes. See the
/// module documentation for the design rationale.
pub struct ResponseCache {
    shards: Vec<Mutex<ShardState>>,
    max_entries: usize,
    max_bytes: usize,
    ttl: Duration,
    negative_ttl: Duration,

    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
    coalesced_loads: AtomicU64,
    negative_hits: AtomicU64,
    current_entries: AtomicU64,
    current_bytes: AtomicU64,
}

/// If `negative_ttl` is not strictly shorter than `ttl`, the negative-cache
/// invariant this design depends on (a wrong or unknown-target answer must
/// expire much sooner than a real one) is violated. Refusing to start over a
/// misconfigured env var would take down the whole server for a value that
/// only affects one cache's staleness window, so this clamps to a value well
/// under `ttl` and logs — it does not panic or refuse the configuration.
fn clamp_negative_ttl(ttl: Duration, negative_ttl: Duration) -> Duration {
    if negative_ttl < ttl {
        return negative_ttl;
    }
    let clamped_millis = (ttl.as_millis() / 10).max(1) as u64;
    let clamped = Duration::from_millis(clamped_millis);
    log::warn!(
        "pubkey cache negative TTL ({negative_ttl:?}) must be strictly shorter than the \
         positive TTL ({ttl:?}); clamping the negative TTL to {clamped:?}"
    );
    clamped
}

impl ResponseCache {
    /// `max_entries` and `max_bytes` bound the cache cache-wide (not per
    /// shard). `ttl` is the lifetime of a positive (hit) entry. `negative_ttl`
    /// is the lifetime of a negative (miss-suppressing) entry; if it is not
    /// strictly shorter than `ttl`, it is clamped down and a warning is
    /// logged (see [`clamp_negative_ttl`]).
    pub fn new(
        max_entries: usize,
        max_bytes: usize,
        ttl: Duration,
        negative_ttl: Duration,
    ) -> Self {
        let negative_ttl = clamp_negative_ttl(ttl, negative_ttl);
        let shard_count = NUM_SHARDS.min(max_entries.max(1));
        ResponseCache {
            shards: (0..shard_count)
                .map(|_| Mutex::new(ShardState::default()))
                .collect(),
            max_entries,
            max_bytes,
            ttl,
            negative_ttl,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            coalesced_loads: AtomicU64::new(0),
            negative_hits: AtomicU64::new(0),
            current_entries: AtomicU64::new(0),
            current_bytes: AtomicU64::new(0),
        }
    }

    /// The effective positive-entry TTL (after any clamp at construction).
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// The effective negative-entry TTL (after any clamp at construction).
    pub fn negative_ttl(&self) -> Duration {
        self.negative_ttl
    }

    fn shard_index(&self, key: &CacheKey) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() % self.shards.len() as u64) as usize
    }

    fn lock_shard(&self, idx: usize) -> MutexGuard<'_, ShardState> {
        self.shards[idx].lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Returns cached bytes on a hit (`Ok(Some(_))` for a positive entry,
    /// `Ok(None)` for a cached negative entry). On a miss, runs `load` exactly
    /// once across every concurrent caller for this key; the others block on
    /// that one call's result. `load` returning `Ok(None)` stores a short
    /// negative entry; `Ok(Some(bytes))` stores `bytes` as the new positive
    /// entry (unless it alone exceeds the configured byte budget, in which
    /// case it is returned but not stored). `Err` is never cached, so the
    /// next call retries.
    pub fn get_or_load<F>(
        &self,
        key: &CacheKey,
        load: F,
    ) -> Result<Option<Arc<Vec<u8>>>, CacheError>
    where
        F: FnOnce() -> Result<Option<Vec<u8>>, CacheError>,
    {
        let idx = self.shard_index(key);
        let now = Instant::now();

        enum Action {
            HitPositive(Arc<Vec<u8>>),
            HitNegative,
            Wait(Arc<InFlight>),
            Lead(Arc<InFlight>),
        }

        let action = {
            let mut state = self.lock_shard(idx);
            let expired =
                matches!(state.map.get(key), Some(Slot::Ready(entry)) if entry.expires_at <= now);
            if expired {
                if let Some(Slot::Ready(old)) = state.map.remove(key) {
                    self.current_entries.fetch_sub(1, Ordering::Relaxed);
                    self.current_bytes
                        .fetch_sub(old.size_bytes as u64, Ordering::Relaxed);
                }
            }
            match state.map.get_mut(key) {
                Some(Slot::Ready(entry)) => {
                    entry.last_used = now;
                    match &entry.value {
                        CacheValue::Positive(bytes) => Action::HitPositive(Arc::clone(bytes)),
                        CacheValue::Negative => Action::HitNegative,
                    }
                }
                Some(Slot::Loading(inflight)) => Action::Wait(Arc::clone(inflight)),
                None => {
                    let inflight = Arc::new(InFlight::new());
                    state
                        .map
                        .insert(key.clone(), Slot::Loading(Arc::clone(&inflight)));
                    Action::Lead(inflight)
                }
            }
        };

        match action {
            Action::HitPositive(bytes) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                Ok(Some(bytes))
            }
            Action::HitNegative => {
                self.negative_hits.fetch_add(1, Ordering::Relaxed);
                Ok(None)
            }
            Action::Wait(inflight) => {
                self.coalesced_loads.fetch_add(1, Ordering::Relaxed);
                match inflight.wait() {
                    Ok(CacheValue::Positive(bytes)) => Ok(Some(bytes)),
                    Ok(CacheValue::Negative) => Ok(None),
                    Err(e) => Err(e),
                }
            }
            Action::Lead(inflight) => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                let outcome = load();
                let result: Result<CacheValue, CacheError> = match outcome {
                    Ok(Some(bytes)) => Ok(CacheValue::Positive(Arc::new(bytes))),
                    Ok(None) => Ok(CacheValue::Negative),
                    Err(e) => Err(e),
                };
                self.finalize(idx, key, &inflight, result.clone());
                inflight.finish(result.clone());
                match result {
                    Ok(CacheValue::Positive(bytes)) => Ok(Some(bytes)),
                    Ok(CacheValue::Negative) => Ok(None),
                    Err(e) => Err(e),
                }
            }
        }
    }

    /// Store the loader's outcome, replacing the `Loading` placeholder — but
    /// only while that placeholder is still the one this call started
    /// (compared by `Arc` identity). If it was removed or replaced in the
    /// meantime (e.g. an `invalidate` raced with this load), the outcome is
    /// still returned to every waiter, but nothing is resurrected into the
    /// map.
    fn finalize(
        &self,
        idx: usize,
        key: &CacheKey,
        inflight: &Arc<InFlight>,
        result: Result<CacheValue, CacheError>,
    ) {
        let mut state = self.lock_shard(idx);
        let still_ours =
            matches!(state.map.get(key), Some(Slot::Loading(cur)) if Arc::ptr_eq(cur, inflight));
        if !still_ours {
            return;
        }
        match result {
            Ok(value) => {
                let size_bytes = match &value {
                    CacheValue::Positive(bytes) => bytes.len(),
                    CacheValue::Negative => 0,
                };
                if size_bytes > self.max_bytes {
                    // A single response larger than the whole budget is never
                    // stored — the caller still gets it back from get_or_load.
                    state.map.remove(key);
                    return;
                }
                let ttl = match &value {
                    CacheValue::Positive(_) => self.ttl,
                    CacheValue::Negative => self.negative_ttl,
                };
                let now = Instant::now();
                state.map.insert(
                    key.clone(),
                    Slot::Ready(Entry {
                        value,
                        expires_at: now + ttl,
                        last_used: now,
                        size_bytes,
                    }),
                );
                self.current_entries.fetch_add(1, Ordering::Relaxed);
                self.current_bytes
                    .fetch_add(size_bytes as u64, Ordering::Relaxed);
            }
            Err(_) => {
                state.map.remove(key);
            }
        }
        drop(state);
        self.enforce_bounds();
    }

    /// Evict LRU entries, one at a time, round-robin across shards, until the
    /// cache-wide entry and byte gauges are within their configured budgets
    /// or a bounded number of attempts is exhausted. Never holds more than
    /// one shard lock at a time, so this cannot deadlock against a concurrent
    /// lookup on another shard.
    fn enforce_bounds(&self) {
        let max_attempts = self.shards.len().saturating_mul(8).max(1);
        for (attempts, shard) in self.shards.iter().cycle().enumerate() {
            if attempts >= max_attempts {
                break;
            }
            let within_budget = self.current_entries.load(Ordering::Relaxed) as usize
                <= self.max_entries
                && self.current_bytes.load(Ordering::Relaxed) as usize <= self.max_bytes;
            if within_budget {
                break;
            }
            let mut state = shard.lock().unwrap_or_else(|e| e.into_inner());
            let lru_key = state
                .map
                .iter()
                .filter_map(|(k, slot)| match slot {
                    Slot::Ready(entry) => Some((k.clone(), entry.last_used)),
                    Slot::Loading(_) => None,
                })
                .min_by_key(|(_, last_used)| *last_used)
                .map(|(k, _)| k);
            if let Some(lru_key) = lru_key {
                if let Some(Slot::Ready(removed)) = state.map.remove(&lru_key) {
                    self.current_entries.fetch_sub(1, Ordering::Relaxed);
                    self.current_bytes
                        .fetch_sub(removed.size_bytes as u64, Ordering::Relaxed);
                    self.evictions.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Remove exactly one entry. The service layer calls this after a
    /// database transaction that adds, renews, expires, or revokes the key
    /// material behind `key` commits.
    pub fn invalidate(&self, key: &CacheKey) {
        let idx = self.shard_index(key);
        let mut state = self.lock_shard(idx);
        if let Some(Slot::Ready(old)) = state.map.remove(key) {
            self.current_entries.fetch_sub(1, Ordering::Relaxed);
            self.current_bytes
                .fetch_sub(old.size_bytes as u64, Ordering::Relaxed);
        }
    }

    /// Drop every cached entry. Intended for tests and administrative reset;
    /// production invalidation should use [`Self::invalidate`] with the
    /// specific affected key.
    pub fn invalidate_all(&self) {
        for shard in &self.shards {
            let mut state = shard.lock().unwrap_or_else(|e| e.into_inner());
            for slot in state.map.values() {
                if let Slot::Ready(entry) = slot {
                    self.current_entries.fetch_sub(1, Ordering::Relaxed);
                    self.current_bytes
                        .fetch_sub(entry.size_bytes as u64, Ordering::Relaxed);
                }
            }
            state.map.clear();
        }
    }

    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            coalesced_loads: self.coalesced_loads.load(Ordering::Relaxed),
            negative_hits: self.negative_hits.load(Ordering::Relaxed),
            entries: self.current_entries.load(Ordering::Relaxed),
            bytes: self.current_bytes.load(Ordering::Relaxed),
        }
    }
}

fn env_u64_or_log(name: &str, default: u64) -> u64 {
    crate::config::nonzero_u64_env(name, default).unwrap_or_else(|error| {
        log::error!("{error}; using default {default}");
        default
    })
}

/// One immutable encoded snapshot each of the domain-keys response and the
/// revocations response (keys [`CacheKey::DomainKeys`] and
/// [`CacheKey::Revocations`]). The service layer must call
/// [`ResponseCache::invalidate`] with the relevant key after a domain-key
/// addition, renewal, expiry transition, or revocation commits. The
/// `DOMAIN_KEY_SNAPSHOT_TTL_SECONDS` TTL (default 60s) is a backstop against
/// a missed invalidation and against `recent_revocations_available` going
/// stale purely from elapsed time — not the primary invalidation mechanism.
pub static DOMAIN_SNAPSHOT_CACHE: LazyLock<ResponseCache> = LazyLock::new(|| {
    let ttl_secs = env_u64_or_log(
        "DOMAIN_KEY_SNAPSHOT_TTL_SECONDS",
        DEFAULT_DOMAIN_SNAPSHOT_TTL_SECONDS,
    );
    ResponseCache::new(
        DOMAIN_SNAPSHOT_MAX_ENTRIES,
        DOMAIN_SNAPSHOT_MAX_BYTES,
        Duration::from_secs(ttl_secs),
        Duration::from_secs(DOMAIN_SNAPSHOT_NEGATIVE_TTL_SECONDS),
    )
});

/// One entry per `(subject UUID + domain, application id, instance id)`
/// triple (`CacheKey::ApplicationKey`). The service layer must call
/// [`invalidate_application_keys`] with the exact affected instance after a
/// write that adds, renews, expires, or revokes an application key commits.
///
/// Defaults: 10,000 entries, 64 MiB, a 5-minute positive TTL, and a 10-second
/// negative TTL (30x shorter than the positive TTL, well clear of the
/// "much shorter" requirement). The response-bounds section of the design
/// estimates a worst-case per-instance response near 110 KB after ten years
/// of monthly rotation, so 64 MiB comfortably holds the default 10,000-entry
/// budget with headroom before entries evict.
pub static APPLICATION_KEYS: LazyLock<ResponseCache> = LazyLock::new(|| {
    let max_entries = env_u64_or_log("PUBKEY_CACHE_MAX_ENTRIES", DEFAULT_MAX_ENTRIES) as usize;
    let max_bytes = env_u64_or_log("PUBKEY_CACHE_MAX_BYTES", DEFAULT_MAX_BYTES) as usize;
    let ttl = Duration::from_secs(env_u64_or_log(
        "PUBKEY_CACHE_TTL_SECONDS",
        DEFAULT_TTL_SECONDS,
    ));
    let negative_ttl = Duration::from_secs(env_u64_or_log(
        "PUBKEY_CACHE_NEGATIVE_TTL_SECONDS",
        DEFAULT_NEGATIVE_TTL_SECONDS,
    ));
    ResponseCache::new(max_entries, max_bytes, ttl, negative_ttl)
});

/// Build the [`CacheKey`] for one application instance's cached public read.
/// `subject_domain` is the canonical domain component of `subject_user_id`'s
/// `UUID@domain` identity, not necessarily this server's own domain (a caller
/// resolves it before calling here).
pub fn application_keys_key(
    subject_user_id: &str,
    subject_domain: &str,
    application_id: &str,
    instance_id: &str,
) -> CacheKey {
    CacheKey::ApplicationKey {
        subject_user_id: subject_user_id.to_string(),
        subject_domain: subject_domain.to_string(),
        application_id: application_id.to_string(),
        instance_id: instance_id.to_string(),
    }
}

/// Invalidate exactly the [`APPLICATION_KEYS`] entry for one application
/// instance. Call this after a write that adds, renews, expires, or revokes
/// one of its keys, and only after that write's database transaction has
/// committed successfully — the database is the source of truth, and an
/// invalidation before commit could drop the cache entry for a write that
/// then fails to land.
pub fn invalidate_application_keys(
    subject_user_id: &str,
    subject_domain: &str,
    application_id: &str,
    instance_id: &str,
) {
    APPLICATION_KEYS.invalidate(&application_keys_key(
        subject_user_id,
        subject_domain,
        application_id,
        instance_id,
    ));
}
