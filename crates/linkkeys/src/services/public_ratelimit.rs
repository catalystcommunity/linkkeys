//! Bounded abuse controls for the ANONYMOUS public-key read surface (SEC-05
//! sibling; see `signing-things-request.md`, "Public-key rate limits and DDoS
//! protection").
//!
//! `DomainKeys/get-domain-keys`, `DomainKeys/get-revocations`, and the
//! application-key read all serve public material to unauthenticated callers.
//! They share ONE budget here (the design says so explicitly, unless
//! measurement shows separate budgets are safer). This module is a sibling to
//! `services::ratelimit`, not a modification of it: that module keys buckets
//! by attacker-*claimed* identifiers (username, recipient, fingerprint) that
//! are meaningful once a credential or possession check has already run.
//! Nothing here is ever behind a credential check, so the key MUST be a
//! transport-level fact the caller cannot choose to be someone else's value:
//! the normalized source IP address. `SourceKey` and `normalize_source` are
//! the only way to derive it, and neither takes a subject UUID, application
//! id, instance id, or RP fingerprint as input — an attacker who claims a
//! victim's identifier still only ever debits their own bucket.
//!
//! Three independent layers, all of which must pass for a request to be
//! allowed:
//!
//! 1. A per-source token bucket (`PerSource`).
//! 2. Distinct-source protection (`Overflow`): a rotating, bounded set caps
//!    how many distinct sources may hold per-source state in the current
//!    window. Once full, a new source draws on one shared overflow bucket and
//!    allocates no per-source state — otherwise one request from each of a
//!    million addresses fills memory.
//! 3. A global token bucket (`Global`), independent of source, so rotating
//!    through fresh addresses cannot bypass the aggregate limit.
//!
//! The per-source map is sharded (default 16 shards, power of two, selected
//! by a hash of the source) so concurrent requests from different sources do
//! not serialize on one mutex before the handler even runs.

use ipnet::IpNet;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::Instant;

use crate::config::{nonzero_u64_env, positive_f64_env, string_env};

// Defaults, named once so `PublicReadLimiterConfig::default()` and
// `from_env()` cannot drift apart.
const DEFAULT_RATE_PER_MINUTE: u64 = 100;
const DEFAULT_BURST: u64 = 100;
// The present handler (`crates/linkkeys/src/services/domain_keys.rs` and its
// siblings) is cheap: one indexed query, one recent-revocation check, and a
// small CBOR encode — no signing, no private-key decryption, no outbound DNS
// (see signing-things-request.md, "Cost of public reads"). 2000 requests/sec
// is comfortably inside what a modest host can sustain for that shape of
// work while still bounding worst-case aggregate load; a 2x burst absorbs a
// short spike without an unbounded queue forming in front of it.
const DEFAULT_GLOBAL_RATE_PER_SECOND: f64 = 2000.0;
const DEFAULT_GLOBAL_BURST: u64 = 4000;
// The overflow bucket is intentionally small: it exists so a protection-mode
// window does not go fully dark for new sources, not to give an attacker who
// is minting fresh addresses a second large budget.
const DEFAULT_OVERFLOW_RATE_PER_SECOND: f64 = 50.0;
const DEFAULT_OVERFLOW_BURST: u64 = 100;
const DEFAULT_DISTINCT_SOURCE_THRESHOLD: u64 = 10_000;
const DEFAULT_WINDOW_SECONDS: u64 = 60;
const DEFAULT_IPV6_PREFIX: u8 = 64;
const DEFAULT_SHARD_COUNT: usize = 16;

/// Opaque, hashed identity of a normalized request source. Two requests that
/// normalize to the same source (same IPv4 address, or same IPv6 address
/// under the configured prefix) share one budget. Derived ONLY from the
/// transport-level peer address (or, for a configured trusted proxy, the
/// address it forwards) — never from request content. See `normalize_source`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SourceKey([u8; 32]);

/// Turn a direct socket peer address, plus an optional forwarded-for header
/// value and the operator's trusted-proxy list, into the one normalized
/// `SourceKey` this module recognizes. This is the ONLY correct way to derive
/// a source key; dispatch code must not hash or truncate an address itself.
///
/// The forwarded header is honored only when `peer.ip()` matches an entry in
/// `trusted_proxies` — otherwise it is attacker-controlled input and is
/// ignored. When honored, the RIGHTMOST comma-separated address is used: that
/// is the address the trusted proxy itself observed and appended, whereas
/// anything to its left could have been supplied by the original client.
pub fn normalize_source(
    peer: SocketAddr,
    forwarded_for: Option<&str>,
    trusted_proxies: &[IpNet],
    ipv6_prefix_len: u8,
) -> SourceKey {
    let effective_ip = resolve_effective_ip(peer, forwarded_for, trusted_proxies);
    let canonical = canonicalize(effective_ip, ipv6_prefix_len);
    SourceKey(Sha256::digest(canonical.as_bytes()).into())
}

fn resolve_effective_ip(
    peer: SocketAddr,
    forwarded_for: Option<&str>,
    trusted_proxies: &[IpNet],
) -> IpAddr {
    let peer_ip = peer.ip();
    if trusted_proxies.iter().any(|net| net.contains(&peer_ip)) {
        if let Some(header) = forwarded_for {
            if let Some(rightmost) = header.rsplit(',').next() {
                if let Ok(parsed) = rightmost.trim().parse::<IpAddr>() {
                    return parsed;
                }
            }
        }
    }
    peer_ip
}

fn canonicalize(ip: IpAddr, ipv6_prefix_len: u8) -> String {
    match ip {
        IpAddr::V4(v4) => format!("v4:{v4}"),
        IpAddr::V6(v6) => {
            let prefix = ipv6_prefix_len.min(128);
            let network = match ipnet::Ipv6Net::new(v6, prefix) {
                Ok(net) => net.network(),
                Err(_) => v6,
            };
            format!("v6:{network}/{prefix}")
        }
    }
}

/// A compact (8-byte) fingerprint of a `SourceKey`, used for shard selection
/// and for membership in the bounded distinct-source set. Derived from the
/// already-uniform SHA-256 output, so collisions among even 10,000+ tracked
/// entries are not a practical concern.
fn compact_hash(key: &SourceKey) -> u64 {
    u64::from_le_bytes(key.0[0..8].try_into().expect("SourceKey is 32 bytes"))
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn full(capacity: f64) -> Self {
        Bucket {
            tokens: capacity,
            last: Instant::now(),
        }
    }

    /// Has this bucket refilled to capacity? Such an entry is
    /// indistinguishable from one that was never created, so it can be
    /// dropped without changing any decision. This is what makes pruning the
    /// per-source map safe rather than a way to grant free requests.
    fn is_spent(&self, now: Instant, capacity: f64, refill_per_sec: f64) -> bool {
        let elapsed = now.duration_since(self.last).as_secs_f64();
        (self.tokens + elapsed * refill_per_sec) >= capacity
    }

    /// Refill, then attempt to consume one token. `Ok(())` on success; on
    /// failure, `Err(seconds)` gives a whole-second, minimum-1 retry hint.
    fn try_consume(&mut self, now: Instant, capacity: f64, refill_per_sec: f64) -> Result<(), u64> {
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * refill_per_sec).min(capacity);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            let deficit = 1.0 - self.tokens;
            let wait = (deficit / refill_per_sec).ceil().max(1.0);
            Err(wait as u64)
        }
    }
}

struct DistinctWindow {
    started: Instant,
    tracked: HashSet<u64>,
    protection_logged: bool,
}

impl DistinctWindow {
    fn new(now: Instant) -> Self {
        DistinctWindow {
            started: now,
            tracked: HashSet::new(),
            protection_logged: false,
        }
    }
}

enum SourceAdmission {
    /// Already holds per-source state this window; use it.
    Known,
    /// New this window, room in the bounded tracker; per-source state may be
    /// created.
    NewAdmitted,
    /// New this window, tracker is full (protection mode); no per-source
    /// state is allocated — use the shared overflow bucket instead.
    Overflow,
}

struct Shard {
    buckets: Mutex<HashMap<SourceKey, Bucket>>,
}

/// Explicit, non-env constructor parameters for `PublicReadLimiter::new`, so
/// tests (and any future caller) can build a limiter without touching
/// process environment variables. `Default` mirrors the same defaults
/// `from_env()` falls back to.
#[derive(Clone)]
pub struct PublicReadLimiterConfig {
    pub per_source_capacity: f64,
    pub per_source_refill_per_sec: f64,
    pub global_capacity: f64,
    pub global_refill_per_sec: f64,
    pub overflow_capacity: f64,
    pub overflow_refill_per_sec: f64,
    pub distinct_source_threshold: usize,
    pub window_seconds: u64,
    pub ipv6_prefix_len: u8,
    pub trusted_proxies: Vec<IpNet>,
    /// Number of per-source map shards. Rounded up to a power of two, and up
    /// to at least 1.
    pub shard_count: usize,
}

impl Default for PublicReadLimiterConfig {
    fn default() -> Self {
        PublicReadLimiterConfig {
            per_source_capacity: DEFAULT_BURST as f64,
            per_source_refill_per_sec: DEFAULT_RATE_PER_MINUTE as f64 / 60.0,
            global_capacity: DEFAULT_GLOBAL_BURST as f64,
            global_refill_per_sec: DEFAULT_GLOBAL_RATE_PER_SECOND,
            overflow_capacity: DEFAULT_OVERFLOW_BURST as f64,
            overflow_refill_per_sec: DEFAULT_OVERFLOW_RATE_PER_SECOND,
            distinct_source_threshold: DEFAULT_DISTINCT_SOURCE_THRESHOLD as usize,
            window_seconds: DEFAULT_WINDOW_SECONDS,
            ipv6_prefix_len: DEFAULT_IPV6_PREFIX,
            trusted_proxies: Vec::new(),
            shard_count: DEFAULT_SHARD_COUNT,
        }
    }
}

fn parse_trusted_proxy(raw: &str) -> Result<IpNet, String> {
    if let Ok(net) = raw.parse::<IpNet>() {
        return Ok(net);
    }
    let ip: IpAddr = raw
        .parse()
        .map_err(|_| format!("PUBLIC_READ_TRUSTED_PROXIES: invalid address or CIDR: {raw}"))?;
    let prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    IpNet::new(ip, prefix)
        .map_err(|error| format!("PUBLIC_READ_TRUSTED_PROXIES: invalid address {raw}: {error}"))
}

fn parse_trusted_proxies(raw: &str) -> Result<Vec<IpNet>, String> {
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(parse_trusted_proxy)
        .collect()
}

impl PublicReadLimiterConfig {
    /// Read configuration from the environment, falling back to
    /// `Default::default()`'s values (see module docs for the rationale
    /// behind the global/overflow defaults).
    pub fn from_env() -> Result<Self, String> {
        let rate_per_minute =
            nonzero_u64_env("PUBLIC_READ_RATE_PER_MINUTE", DEFAULT_RATE_PER_MINUTE)?;
        let burst = nonzero_u64_env("PUBLIC_READ_BURST", DEFAULT_BURST)?;
        let global_rate_per_second = positive_f64_env(
            "PUBLIC_READ_GLOBAL_RATE_PER_SECOND",
            DEFAULT_GLOBAL_RATE_PER_SECOND,
        )?;
        let global_burst = nonzero_u64_env("PUBLIC_READ_GLOBAL_BURST", DEFAULT_GLOBAL_BURST)?;
        let overflow_rate_per_second = positive_f64_env(
            "PUBLIC_READ_OVERFLOW_RATE_PER_SECOND",
            DEFAULT_OVERFLOW_RATE_PER_SECOND,
        )?;
        let overflow_burst = nonzero_u64_env("PUBLIC_READ_OVERFLOW_BURST", DEFAULT_OVERFLOW_BURST)?;
        let distinct_source_threshold = nonzero_u64_env(
            "PUBLIC_READ_DISTINCT_SOURCE_THRESHOLD",
            DEFAULT_DISTINCT_SOURCE_THRESHOLD,
        )?;
        let window_seconds = nonzero_u64_env("PUBLIC_READ_WINDOW_SECONDS", DEFAULT_WINDOW_SECONDS)?;
        let ipv6_prefix = nonzero_u64_env("PUBLIC_READ_IPV6_PREFIX", DEFAULT_IPV6_PREFIX as u64)?;
        if ipv6_prefix > 128 {
            return Err("PUBLIC_READ_IPV6_PREFIX must be between 1 and 128".to_string());
        }
        let trusted_proxies_raw = string_env("PUBLIC_READ_TRUSTED_PROXIES", "");
        let trusted_proxies = parse_trusted_proxies(&trusted_proxies_raw)?;

        Ok(PublicReadLimiterConfig {
            per_source_capacity: burst as f64,
            per_source_refill_per_sec: rate_per_minute as f64 / 60.0,
            global_capacity: global_burst as f64,
            global_refill_per_sec: global_rate_per_second,
            overflow_capacity: overflow_burst as f64,
            overflow_refill_per_sec: overflow_rate_per_second,
            distinct_source_threshold: distinct_source_threshold as usize,
            window_seconds,
            ipv6_prefix_len: ipv6_prefix as u8,
            trusted_proxies,
            shard_count: DEFAULT_SHARD_COUNT,
        })
    }
}

/// Why a request was limited.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LimitReason {
    /// The request's own per-source bucket is empty.
    PerSource,
    /// The source is new for this window and distinct-source protection mode
    /// is active; the shared overflow bucket is empty.
    Overflow,
    /// The independent global bucket is empty.
    Global,
}

/// The limiter's decision for one request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PublicReadDecision {
    Allow,
    Limited {
        reason: LimitReason,
        retry_after_seconds: u64,
    },
}

/// Bounded abuse controls shared by every anonymous public-key read
/// operation. See the module docs for the three layers this enforces.
///
/// Concurrency: the per-source map is split into `shard_count` independently
/// locked shards, so two requests from different sources do not contend for
/// the same mutex. The global and overflow buckets are each one small
/// `Mutex<Bucket>` — cheap critical sections, not a bottleneck for this
/// handler's cost profile.
pub struct PublicReadLimiter {
    shards: Vec<Shard>,
    per_source_capacity: f64,
    per_source_refill_per_sec: f64,

    global: Mutex<Bucket>,
    global_capacity: f64,
    global_refill_per_sec: f64,

    overflow: Mutex<Bucket>,
    overflow_capacity: f64,
    overflow_refill_per_sec: f64,

    distinct: Mutex<DistinctWindow>,
    distinct_source_threshold: usize,
    window_seconds: u64,

    /// Hard bound on the per-source bucket map, per shard. The distinct-source
    /// tracker bounds how many NEW sources may allocate state in one window,
    /// and it resets each window; this map does not reset, so it needs a bound
    /// of its own or an attacker cycling addresses below the protection
    /// threshold grows it without limit.
    max_buckets_per_shard: usize,

    ipv6_prefix_len: u8,
    trusted_proxies: Vec<IpNet>,

    accepted: AtomicU64,
    rejected_per_source: AtomicU64,
    rejected_overflow: AtomicU64,
    rejected_global: AtomicU64,
    protection_mode_entries: AtomicU64,
    tracked_source_count: AtomicUsize,
}

impl PublicReadLimiter {
    pub fn new(config: PublicReadLimiterConfig) -> Self {
        let shard_count = config.shard_count.max(1).next_power_of_two();
        let shards = (0..shard_count)
            .map(|_| Shard {
                buckets: Mutex::new(HashMap::new()),
            })
            .collect();
        let now = Instant::now();
        PublicReadLimiter {
            shards,
            per_source_capacity: config.per_source_capacity,
            per_source_refill_per_sec: config.per_source_refill_per_sec,
            global: Mutex::new(Bucket::full(config.global_capacity)),
            global_capacity: config.global_capacity,
            global_refill_per_sec: config.global_refill_per_sec,
            overflow: Mutex::new(Bucket::full(config.overflow_capacity)),
            overflow_capacity: config.overflow_capacity,
            overflow_refill_per_sec: config.overflow_refill_per_sec,
            distinct: Mutex::new(DistinctWindow::new(now)),
            distinct_source_threshold: config.distinct_source_threshold,
            window_seconds: config.window_seconds,
            // The whole map holds at most one window's worth of admitted
            // sources, spread over the shards, with a small floor so a tiny
            // configuration still works.
            max_buckets_per_shard: (config.distinct_source_threshold.div_ceil(shard_count)).max(16),
            ipv6_prefix_len: config.ipv6_prefix_len,
            trusted_proxies: config.trusted_proxies,
            accepted: AtomicU64::new(0),
            rejected_per_source: AtomicU64::new(0),
            rejected_overflow: AtomicU64::new(0),
            rejected_global: AtomicU64::new(0),
            protection_mode_entries: AtomicU64::new(0),
            tracked_source_count: AtomicUsize::new(0),
        }
    }

    /// The one correct way for dispatch code to turn a connection's peer
    /// address (plus any forwarded-for header value) into the `SourceKey`
    /// this limiter's configuration expects — it applies this instance's
    /// trusted-proxy list and IPv6 prefix length.
    pub fn source_key(&self, peer: SocketAddr, forwarded_for: Option<&str>) -> SourceKey {
        normalize_source(
            peer,
            forwarded_for,
            &self.trusted_proxies,
            self.ipv6_prefix_len,
        )
    }

    pub fn ipv6_prefix_len(&self) -> u8 {
        self.ipv6_prefix_len
    }

    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Which shard a given source's per-source state lives in. Exposed so
    /// tests can assert the sharding actually spreads sources out, rather
    /// than asserting on wall-clock timing.
    pub fn shard_index(&self, key: &SourceKey) -> usize {
        (compact_hash(key) as usize) & (self.shards.len() - 1)
    }

    fn admit(&self, key: &SourceKey, now: Instant) -> SourceAdmission {
        let mut window = self
            .distinct
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if now.duration_since(window.started).as_secs_f64() >= self.window_seconds as f64 {
            *window = DistinctWindow::new(now);
        }

        let compact = compact_hash(key);
        if window.tracked.contains(&compact) {
            return SourceAdmission::Known;
        }
        if window.tracked.len() < self.distinct_source_threshold {
            window.tracked.insert(compact);
            self.tracked_source_count
                .store(window.tracked.len(), Ordering::Relaxed);
            return SourceAdmission::NewAdmitted;
        }

        // Bounded set is full: protection mode for the rest of this window.
        // Log/count this exactly once per window, not once per request.
        if !window.protection_logged {
            window.protection_logged = true;
            self.protection_mode_entries.fetch_add(1, Ordering::Relaxed);
            log::warn!(
                "public_ratelimit: distinct-source protection mode engaged ({} tracked sources this window)",
                window.tracked.len()
            );
        }
        SourceAdmission::Overflow
    }

    /// Bring one shard back under its bound.
    ///
    /// Two passes, both bounded by the shard's own size, which is itself
    /// bounded — so this can never become expensive:
    ///
    /// 1. Drop every entry whose bucket has refilled to capacity. Such an
    ///    entry is indistinguishable from one that never existed, so dropping
    ///    it grants nobody an extra request.
    /// 2. If that was not enough, drop least-recently-used entries. This CAN
    ///    return some tokens to a source that is being actively limited, which
    ///    is the deliberate trade: a bounded map that occasionally forgives a
    ///    little is safe, and an unbounded one is a way to kill the process.
    ///    Reaching pass 2 at all means more distinct sources are being
    ///    actively limited than the configured threshold, which is what the
    ///    global bucket is there to catch.
    fn prune_shard(
        buckets: &mut HashMap<SourceKey, Bucket>,
        now: Instant,
        capacity: f64,
        refill_per_sec: f64,
        target: usize,
    ) {
        buckets.retain(|_, bucket| !bucket.is_spent(now, capacity, refill_per_sec));
        while buckets.len() >= target {
            let Some(oldest) = buckets
                .iter()
                .min_by_key(|(_, bucket)| bucket.last)
                .map(|(key, _)| *key)
            else {
                break;
            };
            buckets.remove(&oldest);
        }
    }

    /// Total per-source bucket entries currently held, across every shard.
    ///
    /// This is the structure that actually holds rate-limit state, and it is
    /// the one a bounded-memory test must measure — `tracked_source_count`
    /// reports the distinct-source WINDOW, which resets on its own and so
    /// proves nothing about this map.
    pub fn bucket_entry_count(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| {
                shard
                    .buckets
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .len()
            })
            .sum()
    }

    /// The configured per-shard bound, for tests and for operator reporting.
    pub fn max_bucket_entries(&self) -> usize {
        self.max_buckets_per_shard * self.shards.len()
    }

    /// Decide whether one anonymous public-key read from `source` is
    /// allowed. Never panics; a poisoned internal lock is recovered rather
    /// than propagated, so one panic elsewhere cannot permanently disable
    /// the abuse controls.
    pub fn check(&self, source: &SourceKey) -> PublicReadDecision {
        let now = Instant::now();

        match self.admit(source, now) {
            SourceAdmission::Known | SourceAdmission::NewAdmitted => {
                let shard = &self.shards[self.shard_index(source)];
                let mut buckets = shard
                    .buckets
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner());
                // The distinct-source tracker bounds how many NEW sources may
                // allocate state in one window, but it resets every window
                // while this map does not. Without a bound of its own, an
                // attacker sending fresh addresses at a rate that never even
                // trips protection mode grows this map forever. Bound it here.
                if !buckets.contains_key(source) && buckets.len() >= self.max_buckets_per_shard {
                    Self::prune_shard(
                        &mut buckets,
                        now,
                        self.per_source_capacity,
                        self.per_source_refill_per_sec,
                        self.max_buckets_per_shard,
                    );
                }
                let bucket = buckets
                    .entry(*source)
                    .or_insert_with(|| Bucket::full(self.per_source_capacity));
                let result = bucket.try_consume(
                    now,
                    self.per_source_capacity,
                    self.per_source_refill_per_sec,
                );
                drop(buckets);
                if let Err(retry_after_seconds) = result {
                    self.rejected_per_source.fetch_add(1, Ordering::Relaxed);
                    return PublicReadDecision::Limited {
                        reason: LimitReason::PerSource,
                        retry_after_seconds,
                    };
                }
            }
            SourceAdmission::Overflow => {
                let mut overflow = self
                    .overflow
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner());
                let result =
                    overflow.try_consume(now, self.overflow_capacity, self.overflow_refill_per_sec);
                drop(overflow);
                if let Err(retry_after_seconds) = result {
                    self.rejected_overflow.fetch_add(1, Ordering::Relaxed);
                    return PublicReadDecision::Limited {
                        reason: LimitReason::Overflow,
                        retry_after_seconds,
                    };
                }
            }
        }

        let mut global = self
            .global
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let result = global.try_consume(now, self.global_capacity, self.global_refill_per_sec);
        drop(global);
        match result {
            Ok(()) => {
                self.accepted.fetch_add(1, Ordering::Relaxed);
                PublicReadDecision::Allow
            }
            Err(retry_after_seconds) => {
                self.rejected_global.fetch_add(1, Ordering::Relaxed);
                PublicReadDecision::Limited {
                    reason: LimitReason::Global,
                    retry_after_seconds,
                }
            }
        }
    }

    pub fn accepted(&self) -> u64 {
        self.accepted.load(Ordering::Relaxed)
    }
    pub fn rejected_per_source(&self) -> u64 {
        self.rejected_per_source.load(Ordering::Relaxed)
    }
    pub fn rejected_overflow(&self) -> u64 {
        self.rejected_overflow.load(Ordering::Relaxed)
    }
    pub fn rejected_global(&self) -> u64 {
        self.rejected_global.load(Ordering::Relaxed)
    }
    pub fn protection_mode_entries(&self) -> u64 {
        self.protection_mode_entries.load(Ordering::Relaxed)
    }
    /// Number of distinct sources holding per-source state in the current
    /// window. Bounded by the configured distinct-source threshold.
    pub fn tracked_source_count(&self) -> usize {
        self.tracked_source_count.load(Ordering::Relaxed)
    }
}

/// Production limiter, configured from the environment. See module docs and
/// `PublicReadLimiterConfig::from_env` for the recognized variables and their
/// defaults.
pub static PUBLIC_READS: LazyLock<PublicReadLimiter> = LazyLock::new(|| {
    let config = PublicReadLimiterConfig::from_env().unwrap_or_else(|error| {
        panic!("invalid public-read rate limit configuration: {error}");
    });
    PublicReadLimiter::new(config)
});

/// Convenience adapter for callers that only have a plain address string and
/// no port (e.g. the synchronous TCP handler, which resolves its peer to
/// `stream.peer_addr().ip().to_string()` before any TLS or framing work).
/// There is no forwarded-header concept on a raw TCP/TLS connection, so this
/// always uses the direct value and normalizes IPv6 with the production
/// `PUBLIC_READS` limiter's configured prefix length. A value that does not
/// parse as an address (e.g. a "peer address unavailable" sentinel) is
/// hashed as-is, so every such connection shares one bucket rather than
/// panicking or silently bypassing the limiter.
pub fn source_key_from_str(source: &str) -> SourceKey {
    match source.parse::<IpAddr>() {
        Ok(ip) => normalize_source(
            SocketAddr::new(ip, 0),
            None,
            &[],
            PUBLIC_READS.ipv6_prefix_len(),
        ),
        Err(_) => SourceKey(Sha256::digest(format!("raw:{source}").as_bytes()).into()),
    }
}

// The full behavioral test suite (bucket, distinct-source, protection-mode,
// global, concurrency, etc.) lives in `crates/linkkeys/tests/
// public_ratelimit_test.rs` as a black-box integration test, exercising only
// this module's public API — the same surface the dispatch layer uses. Kept
// here, module-internal, is only what needs access to a private item.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_proxies_parses_bare_ips_and_cidrs() {
        let parsed = parse_trusted_proxies(" 10.0.0.1 , 192.168.0.0/16 , ::1 ").unwrap();
        assert_eq!(parsed.len(), 3);
        assert!(parsed[0].contains(&"10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(parsed[1].contains(&"192.168.5.5".parse::<IpAddr>().unwrap()));
        assert!(parsed[2].contains(&"::1".parse::<IpAddr>().unwrap()));
    }
}
