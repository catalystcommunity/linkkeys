//! Bounded, TTL'd cache of DNS-published `_linkkeys` fingerprint sets,
//! fronting the mTLS client-certificate verifier so a per-handshake lookup is
//! a plain in-memory read rather than network I/O on the async connection
//! task's own thread (signing-things-request.md, "Connection scalability":
//! "identified server-to-server operations need bounded and CACHED DNS pin
//! resolution").
//!
//! `rustls`'s `ClientCertVerifier::verify_client_cert` is a synchronous
//! callback invoked from inside the async TLS handshake future
//! (`tokio_rustls::TlsAcceptor::accept`), on whichever worker thread happens
//! to be polling that connection's task at the time. Blocking that thread on
//! a real DNS round trip inside the callback stalls every other task
//! scheduled on the same worker — unacceptable on an async connection model.
//!
//! `verify_client_cert` first consults this cache (a plain mutex lock, no
//! I/O):
//!
//! - Hit (positive or negative): answered immediately, no I/O.
//! - Miss: a small, separate, configurable semaphore
//!   (`FingerprintClientCertVerifier`'s `sync_fallback`, NOT this cache's
//!   `max_concurrent_refreshes`) gates a BOUNDED synchronous fallback —
//!   `dns::resolve_fingerprints_via`'s ambient-runtime-aware `block_in_place`
//!   path — so a domain LinkKeys hasn't seen recently still gets a correct
//!   answer on its first attempt, not a guaranteed-fail-once. Only when that
//!   small semaphore is exhausted (a flood of distinct unknown domains) does
//!   the callback fall back to failing THIS attempt closed and firing a
//!   background `tokio::spawn` refresh for next time.
//!
//! ## Why this cache must be bounded (security review, 2026-08-29)
//!
//! The cache key is the domain string read from a CLIENT-PRESENTED X.509
//! certificate's SAN/CN (`extract_domain_from_cert`), read BEFORE any trust
//! decision — a self-signed cert with an arbitrary SAN costs an attacker
//! nothing. Every distinct claimed domain that gets past handshake admission
//! would otherwise grow this map forever AND fire a real outbound DNS lookup
//! per domain, forever. Both are bounded here:
//!
//! - `entries` has a hard cap (`max_entries`) with LRU-ish eviction (expired
//!   entries are reclaimed first; otherwise the least-recently-touched entry
//!   is evicted) — see `evict_one`. It never grows past the cap.
//! - Expired entries are also reclaimed on an amortized schedule (every
//!   `SWEEP_EVERY_N_INSERTS`-th insert sweeps the whole map), not only lazily
//!   when the same domain happens to be looked up again — see `maybe_sweep`.
//! - Background refreshes are bounded by `max_concurrent_refreshes` (a
//!   `Semaphore`); a refresh request that finds no permit available is
//!   DROPPED, not queued — see `spawn_refresh`.
//! - Negative entries (an unresolvable/attacker-invented domain) still cost
//!   one bounded map slot with a short TTL, counted against the SAME cap as
//!   positive entries — there is no separate, differently-bounded structure
//!   for them. Negative caching is kept (rather than caching nothing until a
//!   domain resolves) specifically BECAUSE the alternative is worse for the
//!   background-refresh bound above: with no negative cache, every single
//!   connection attempt against the same fake domain would re-trigger a
//!   background DNS lookup attempt against the refresh semaphore, instead of
//!   being absorbed by one short-lived negative hit.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use crate::config::nonzero_u64_env;
use crate::net::DnsResolver;

/// Reclaim (or evict) one entry every this many inserts, regardless of
/// whether the map is at its cap — an amortized sweep so expired entries
/// don't linger just because nobody happens to re-look-up that exact domain.
/// Small enough to keep pace under sustained insert pressure, large enough
/// that the O(n) scan it triggers is rare relative to insert volume.
const SWEEP_EVERY_N_INSERTS: u64 = 64;

#[derive(Debug)]
enum EntryKind {
    Positive(Vec<String>),
    Negative,
}

#[derive(Debug)]
struct Entry {
    kind: EntryKind,
    expires_at: Instant,
    /// Updated on every cache HIT (`get`) as well as on insert — this is what
    /// makes eviction least-recently-USED rather than least-recently-INSERTED,
    /// so a domain LinkKeys actually talks to repeatedly stays resident even
    /// under eviction pressure from a flood of one-off attacker domains.
    last_touched: Instant,
}

/// Result of a cache lookup for one domain.
pub enum PinLookup {
    /// A cached, still-fresh fingerprint set.
    Hit(Vec<String>),
    /// A cached, still-fresh "DNS resolution failed" result.
    NegativeHit,
    /// No usable cache entry — the caller must fail this attempt closed and
    /// may call [`DnsPinCache::spawn_refresh`] to populate the cache for the
    /// next attempt (subject to the background-refresh concurrency bound).
    Miss,
}

/// Env-driven configuration. See the module docs above for the bounds this
/// enforces and why each one exists.
#[derive(Clone)]
pub struct DnsPinCacheConfig {
    /// `TCP_MTLS_DNS_PIN_POSITIVE_TTL_SECONDS` (default 300).
    pub positive_ttl: Duration,
    /// `TCP_MTLS_DNS_PIN_NEGATIVE_TTL_SECONDS` (default 30).
    pub negative_ttl: Duration,
    /// `TCP_MTLS_DNS_PIN_CACHE_MAX_ENTRIES` (default 10,000). Hard cap on
    /// distinct domains tracked at once — positive and negative entries
    /// share this one budget.
    pub max_entries: usize,
    /// `TCP_MTLS_DNS_PIN_MAX_CONCURRENT_REFRESHES` (default 16). Bounds how
    /// many background DNS lookups (`spawn_refresh`) may be in flight at
    /// once; a refresh request beyond this is dropped, not queued.
    pub max_concurrent_refreshes: usize,
}

impl DnsPinCacheConfig {
    pub fn from_env() -> Result<Self, String> {
        Ok(DnsPinCacheConfig {
            positive_ttl: Duration::from_secs(nonzero_u64_env(
                "TCP_MTLS_DNS_PIN_POSITIVE_TTL_SECONDS",
                300,
            )?),
            negative_ttl: Duration::from_secs(nonzero_u64_env(
                "TCP_MTLS_DNS_PIN_NEGATIVE_TTL_SECONDS",
                30,
            )?),
            max_entries: nonzero_u64_env("TCP_MTLS_DNS_PIN_CACHE_MAX_ENTRIES", 10_000)? as usize,
            max_concurrent_refreshes: nonzero_u64_env(
                "TCP_MTLS_DNS_PIN_MAX_CONCURRENT_REFRESHES",
                16,
            )? as usize,
        })
    }
}

#[derive(Debug)]
pub struct DnsPinCache {
    entries: Mutex<HashMap<String, Entry>>,
    /// Domains with an in-flight background refresh, so concurrent misses for
    /// the same domain coalesce into one DNS lookup rather than one each.
    /// Bounded transitively by `refresh_semaphore`: an entry is inserted here
    /// and then immediately removed again in the same call if no permit is
    /// available (see `spawn_refresh`), so this can never hold more entries
    /// than the semaphore has permits (plus a vanishing race window).
    refreshing: Mutex<HashSet<String>>,
    refresh_semaphore: Arc<tokio::sync::Semaphore>,

    max_entries: usize,
    positive_ttl: Duration,
    negative_ttl: Duration,
    inserts_since_sweep: AtomicU64,

    hits: AtomicU64,
    misses: AtomicU64,
    refreshes_started: AtomicU64,
    refreshes_failed: AtomicU64,
    refreshes_dropped: AtomicU64,
    evictions: AtomicU64,
    swept: AtomicU64,
}

impl DnsPinCache {
    pub fn new(config: DnsPinCacheConfig) -> Self {
        DnsPinCache {
            entries: Mutex::new(HashMap::new()),
            refreshing: Mutex::new(HashSet::new()),
            refresh_semaphore: Arc::new(tokio::sync::Semaphore::new(
                config.max_concurrent_refreshes.max(1),
            )),
            max_entries: config.max_entries.max(1),
            positive_ttl: config.positive_ttl,
            negative_ttl: config.negative_ttl,
            inserts_since_sweep: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            refreshes_started: AtomicU64::new(0),
            refreshes_failed: AtomicU64::new(0),
            refreshes_dropped: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            swept: AtomicU64::new(0),
        }
    }

    /// Look up `domain`. Never blocks, never performs I/O. A poisoned lock is
    /// recovered rather than propagated (mirrors `public_ratelimit`), so one
    /// panic elsewhere cannot permanently disable certificate verification.
    pub fn get(&self, domain: &str) -> PinLookup {
        let now = Instant::now();
        let mut entries = self.lock_entries();
        let result = match entries.get_mut(domain) {
            Some(entry) if entry.expires_at > now => {
                entry.last_touched = now;
                self.hits.fetch_add(1, Ordering::Relaxed);
                Some(match &entry.kind {
                    EntryKind::Positive(fingerprints) => PinLookup::Hit(fingerprints.clone()),
                    EntryKind::Negative => PinLookup::NegativeHit,
                })
            }
            Some(_) => None, // expired
            None => None,
        };
        match result {
            Some(hit) => hit,
            None => {
                // Lazy cleanup of exactly the (expired) entry being looked up
                // — a cheap freebie, but NOT the only cleanup mechanism; see
                // `maybe_sweep` and `evict_one` for the bounds that matter
                // under attacker-chosen domains that are never looked up
                // twice.
                entries.remove(domain);
                self.misses.fetch_add(1, Ordering::Relaxed);
                PinLookup::Miss
            }
        }
    }

    pub fn insert_positive(&self, domain: &str, fingerprints: Vec<String>) {
        self.insert(domain, EntryKind::Positive(fingerprints), self.positive_ttl);
    }

    pub fn insert_negative(&self, domain: &str) {
        self.insert(domain, EntryKind::Negative, self.negative_ttl);
    }

    /// Drop any cached entry (positive or negative) for `domain`, without
    /// inserting a replacement. Used when a pin is rotated or refused
    /// (`services::pins::check_and_update_pin`) so a retired or disputed
    /// fingerprint cannot keep authenticating from a stale cache entry for
    /// up to its TTL.
    pub fn invalidate(&self, domain: &str) {
        self.lock_entries().remove(domain);
    }

    /// Current number of tracked domains (positive + negative). Exposed for
    /// metrics and for the bounded-growth test.
    pub fn len(&self) -> usize {
        self.lock_entries().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn insert(&self, domain: &str, kind: EntryKind, ttl: Duration) {
        let now = Instant::now();
        let mut entries = self.lock_entries();

        self.maybe_sweep(&mut entries, now);

        if !entries.contains_key(domain) && entries.len() >= self.max_entries {
            self.evict_one(&mut entries, now);
        }

        entries.insert(
            domain.to_string(),
            Entry {
                kind,
                expires_at: now + ttl,
                last_touched: now,
            },
        );
    }

    /// Free one slot: prefer reclaiming an already-expired entry (costs
    /// nothing real — that trust was already stale); only fall back to
    /// evicting a still-live entry (the least-recently-touched one) when
    /// nothing is expired. Never grows `entries` past `max_entries`.
    fn evict_one(&self, entries: &mut HashMap<String, Entry>, now: Instant) {
        if let Some(expired) = entries
            .iter()
            .find(|(_, entry)| entry.expires_at <= now)
            .map(|(domain, _)| domain.clone())
        {
            entries.remove(&expired);
            self.evictions.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if let Some(oldest) = entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_touched)
            .map(|(domain, _)| domain.clone())
        {
            entries.remove(&oldest);
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Amortized sweep: every `SWEEP_EVERY_N_INSERTS`-th insert scans the
    /// whole map and drops every expired entry, independent of whether the
    /// map is at its cap and independent of which domain is currently being
    /// inserted. Bounds how long an expired entry for a domain nobody
    /// happens to re-look-up can linger, without a dedicated background
    /// timer task (which would need an ambient Tokio runtime this type
    /// cannot assume — plain `#[test]`s construct one directly with none).
    fn maybe_sweep(&self, entries: &mut HashMap<String, Entry>, now: Instant) {
        let n = self.inserts_since_sweep.fetch_add(1, Ordering::Relaxed) + 1;
        if !n.is_multiple_of(SWEEP_EVERY_N_INSERTS) {
            return;
        }
        let before = entries.len();
        entries.retain(|_, entry| entry.expires_at > now);
        let removed = before - entries.len();
        if removed > 0 {
            self.swept.fetch_add(removed as u64, Ordering::Relaxed);
        }
    }

    fn lock_entries(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.entries
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// If no refresh is already in flight for `domain` AND a background-
    /// refresh permit is available, spawn one on the ambient Tokio runtime.
    /// Must be called from within a Tokio execution context — true for every
    /// real call site (only ever reached from inside the async TLS accept
    /// future). Fire-and-forget: the caller does not wait for this to
    /// complete, it only benefits the NEXT lookup.
    ///
    /// Bounded: at most `max_concurrent_refreshes` background lookups run at
    /// once. A request beyond that is DROPPED (not queued) — many distinct
    /// attacker-claimed domains cannot turn into an unbounded number of
    /// concurrent outbound DNS queries.
    pub fn spawn_refresh(self: &Arc<Self>, dns: Arc<dyn DnsResolver>, domain: String) {
        {
            let mut refreshing = self
                .refreshing
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if !refreshing.insert(domain.clone()) {
                return; // already in flight for this domain
            }
        }

        let permit = match self.refresh_semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                self.refreshing
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .remove(&domain);
                self.refreshes_dropped.fetch_add(1, Ordering::Relaxed);
                log::debug!(
                    "DNS pin cache: dropping background refresh for {domain} — \
                     max_concurrent_refreshes already in flight"
                );
                return;
            }
        };

        self.refreshes_started.fetch_add(1, Ordering::Relaxed);
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let _permit = permit; // held for the lookup's duration, then dropped
            match crate::dns::resolve_fingerprints_async(dns.as_ref(), &domain).await {
                Ok(fingerprints) => this.insert_positive(&domain, fingerprints),
                Err(error) => {
                    log::debug!("DNS pin cache: refresh for {domain} failed: {error}");
                    this.refreshes_failed.fetch_add(1, Ordering::Relaxed);
                    this.insert_negative(&domain);
                }
            }
            this.refreshing
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .remove(&domain);
        });
    }

    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }
    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }
    pub fn refreshes_started(&self) -> u64 {
        self.refreshes_started.load(Ordering::Relaxed)
    }
    pub fn refreshes_failed(&self) -> u64 {
        self.refreshes_failed.load(Ordering::Relaxed)
    }
    pub fn refreshes_dropped(&self) -> u64 {
        self.refreshes_dropped.load(Ordering::Relaxed)
    }
    pub fn evictions(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }
    pub fn swept(&self) -> u64 {
        self.swept.load(Ordering::Relaxed)
    }
}

/// The one process-wide mTLS DNS pin cache, shared by:
///
/// - `tcp::tls::FingerprintClientCertVerifier` (production path, via
///   `tcp::build_tls_config`) — reads it during every inbound handshake.
/// - `tcp::TcpServer::new`, which seeds it from the persisted TOFU pin table
///   (`domain_key_pins`, `DbPool::list_domain_pins`) at startup, so "the
///   process just restarted" does not mean "every peer is first contact
///   again" — see `tcp::seed_dns_pin_cache_from_db`.
/// - `services::pins::check_and_update_pin` — keeps the cache in step with
///   pin creation/rotation/refusal (including via `Admin/recheck-pins`), so a
///   retired fingerprint cannot keep authenticating from a stale cache entry.
///
/// Global (like `services::public_ratelimit::PUBLIC_READS`) because there is
/// exactly one TLS listener per process and this cache's whole point —
/// bridging "the outbound pin table already trusts this domain" and "a
/// verifier callback deep inside rustls needs a synchronous answer" — only
/// makes sense as one shared, process-wide view. Tests that need an isolated
/// cache (e.g. `tls_mtls_e2e_test.rs`) construct their own local
/// `DnsPinCache` directly and pass it into
/// `FingerprintClientCertVerifier::new` instead of using this static.
pub static MTLS_DNS_PIN_CACHE: LazyLock<Arc<DnsPinCache>> = LazyLock::new(|| {
    let config = DnsPinCacheConfig::from_env().unwrap_or_else(|error| {
        panic!("invalid mTLS DNS pin cache configuration: {error}");
    });
    Arc::new(DnsPinCache::new(config))
});

#[cfg(test)]
mod tests {
    use super::*;

    fn small_cache(max_entries: usize) -> DnsPinCache {
        DnsPinCache::new(DnsPinCacheConfig {
            positive_ttl: Duration::from_secs(60),
            negative_ttl: Duration::from_secs(5),
            max_entries,
            max_concurrent_refreshes: 4,
        })
    }

    #[test]
    fn miss_then_positive_insert_becomes_hit() {
        let cache = small_cache(100);
        assert!(matches!(cache.get("example.test"), PinLookup::Miss));
        cache.insert_positive("example.test", vec!["abc".to_string()]);
        match cache.get("example.test") {
            PinLookup::Hit(fps) => assert_eq!(fps, vec!["abc".to_string()]),
            _ => panic!("expected a hit"),
        }
        assert_eq!(cache.misses(), 1);
        assert_eq!(cache.hits(), 1);
    }

    #[test]
    fn negative_insert_becomes_negative_hit_then_expires() {
        let cache = DnsPinCache::new(DnsPinCacheConfig {
            positive_ttl: Duration::from_secs(60),
            negative_ttl: Duration::from_millis(1),
            max_entries: 100,
            max_concurrent_refreshes: 4,
        });
        cache.insert_negative("gone.test");
        assert!(matches!(cache.get("gone.test"), PinLookup::NegativeHit));
        std::thread::sleep(Duration::from_millis(20));
        assert!(matches!(cache.get("gone.test"), PinLookup::Miss));
    }

    #[test]
    fn positive_entry_expires_after_ttl() {
        let cache = DnsPinCache::new(DnsPinCacheConfig {
            positive_ttl: Duration::from_millis(1),
            negative_ttl: Duration::from_secs(60),
            max_entries: 100,
            max_concurrent_refreshes: 4,
        });
        cache.insert_positive("short.test", vec!["fp".to_string()]);
        std::thread::sleep(Duration::from_millis(20));
        assert!(matches!(cache.get("short.test"), PinLookup::Miss));
    }

    #[test]
    fn invalidate_drops_a_positive_entry() {
        let cache = small_cache(100);
        cache.insert_positive("rotated.test", vec!["old-fp".to_string()]);
        assert!(matches!(cache.get("rotated.test"), PinLookup::Hit(_)));
        cache.invalidate("rotated.test");
        assert!(matches!(cache.get("rotated.test"), PinLookup::Miss));
    }

    /// The security-review test: an attacker who can present arbitrary X.509
    /// SANs (free, one per connection attempt) must not be able to grow this
    /// map without bound. Insert far more distinct domains than the cap and
    /// assert the tracked count never exceeds it.
    #[test]
    fn entry_count_stays_bounded_under_many_distinct_fake_domains() {
        const CAP: usize = 50;
        let cache = small_cache(CAP);
        for i in 0..5000 {
            cache.insert_positive(&format!("attacker-{i}.invalid"), vec!["fp".to_string()]);
            assert!(
                cache.len() <= CAP,
                "cache grew past its cap ({} > {CAP}) after {} inserts",
                cache.len(),
                i + 1
            );
        }
        assert_eq!(cache.len(), CAP, "cache should be exactly full, not shrunk");
        assert!(cache.evictions() > 0, "eviction must have actually run");
    }

    /// Negative entries must be bounded by the same cap as positive ones —
    /// not a separate, unbounded structure.
    #[test]
    fn negative_entries_count_against_the_same_cap() {
        const CAP: usize = 20;
        let cache = small_cache(CAP);
        for i in 0..500 {
            cache.insert_negative(&format!("unresolvable-{i}.invalid"));
            assert!(cache.len() <= CAP);
        }
        assert_eq!(cache.len(), CAP);
    }

    /// A domain that is looked up repeatedly (kept "hot") must survive
    /// eviction pressure from a flood of one-off domains that are never
    /// looked up again — proves eviction is LRU-ish, not FIFO/random.
    #[test]
    fn frequently_touched_entry_survives_eviction_pressure() {
        const CAP: usize = 10;
        let cache = small_cache(CAP);
        cache.insert_positive("hot.test", vec!["fp".to_string()]);
        for i in 0..1000 {
            // Keep "hot.test" freshly touched between each flood insert.
            assert!(matches!(cache.get("hot.test"), PinLookup::Hit(_)));
            cache.insert_positive(&format!("flood-{i}.invalid"), vec!["fp".to_string()]);
        }
        assert!(
            matches!(cache.get("hot.test"), PinLookup::Hit(_)),
            "a repeatedly-touched entry must not be evicted by one-off churn"
        );
    }

    /// The amortized sweep must actually reclaim expired entries over time,
    /// not only when the exact same domain is looked up again.
    #[test]
    fn amortized_sweep_reclaims_expired_entries_without_relookup() {
        let cache = DnsPinCache::new(DnsPinCacheConfig {
            positive_ttl: Duration::from_millis(1),
            negative_ttl: Duration::from_millis(1),
            max_entries: 1000,
            max_concurrent_refreshes: 4,
        });
        // Insert exactly SWEEP_EVERY_N_INSERTS - 1 short-lived "victim"
        // entries (none of these inserts themselves land on a sweep
        // boundary), let them expire, then make exactly ONE more insert —
        // the SWEEP_EVERY_N_INSERTS-th overall — which must trigger the
        // amortized sweep and reclaim all of them before adding itself.
        for i in 0..(SWEEP_EVERY_N_INSERTS as usize - 1) {
            cache.insert_positive(&format!("expiring-{i}.test"), vec!["fp".to_string()]);
        }
        std::thread::sleep(Duration::from_millis(20));
        cache.insert_positive("trigger.test", vec!["fp".to_string()]);
        assert!(
            cache.swept() > 0,
            "the amortized sweep should have reclaimed expired entries"
        );
        assert_eq!(
            cache.len(),
            1,
            "expired entries should have been reclaimed, leaving only the fresh trigger entry"
        );
    }
}
