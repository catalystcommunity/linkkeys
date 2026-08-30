//! Configuration and bounded metrics for the async TCP connection server
//! (signing-things-request.md, "Connection scalability"). Config is read once
//! from the environment at server startup; metrics are plain atomics with
//! getters, matching the counter style already used in
//! `services::public_ratelimit` and `services::pubkey_cache` — there is no
//! metrics framework in this repo.
//!
//! Both types are per-`TcpServer`-instance (not global `static`s): a test
//! binary may build several servers in one process, and each needs its own
//! independent counters and limiter state.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use crate::config::{nonzero_u64_env, positive_f64_env};
use crate::services::public_ratelimit::{LimitReason, PublicReadLimiterConfig};

/// Everything the async TCP server reads from the environment. See each
/// field's constructing env-var name below for the recognized variable and
/// its default.
#[derive(Clone)]
pub struct TcpServerConfig {
    /// `TCP_MAX_CONNECTIONS` (default 200,000). Hard cap on concurrently open
    /// sockets, counted from `accept()` to close — covers connections still
    /// mid-handshake as well as established ones. This is deliberately also
    /// this server's memory safety valve (see module docs on
    /// `TcpMetrics::shed_connection_limit`): each connection's steady-state
    /// footprint is small and bounded (no per-connection megabyte buffers —
    /// see `TCP_MAX_INFLIGHT_FRAMES`/`TCP_WRITE_QUEUE_BOUND`), so bounding the
    /// connection count bounds memory. It does NOT scale with worker-thread
    /// count — there are no per-connection OS threads to scale with.
    pub max_connections: usize,
    /// `TCP_HANDSHAKE_TIMEOUT_SECONDS` (default 5). Upper bound on the time a
    /// connection may spend acquiring a handshake permit plus completing the
    /// TLS handshake.
    pub handshake_timeout: Duration,
    /// `TCP_HANDSHAKE_CONCURRENCY` (default 512). Semaphore permits bounding
    /// how many TLS handshakes (CPU-costly) may run at once, independent of
    /// `max_connections` (which bounds already-established, mostly-idle
    /// connections — there can be far more of those than concurrent
    /// handshakes).
    pub handshake_concurrency: usize,
    /// `TCP_IDLE_TIMEOUT_SECONDS` (default 1800). Maximum time a connection
    /// may sit waiting for the START of the next frame (i.e. between
    /// requests) before it is dropped as idle. Long, because a legitimately
    /// idle SDK connection is exactly what this server must hold cheaply at
    /// scale.
    pub idle_timeout: Duration,
    /// `TCP_IO_TIMEOUT_SECONDS` (default 60, same variable name and default
    /// the previous blocking server used). Maximum time a single read (once a
    /// frame has started) or write may take — catches a slowloris stalling
    /// mid-frame or mid-response.
    pub io_timeout: Duration,
    /// `TCP_MAX_INFLIGHT_FRAMES` (default 8). Bounded capacity of the
    /// reader→dispatcher channel: how many frames may be read off the socket
    /// and queued for processing before the reader stalls (backpressure).
    pub max_inflight_frames: usize,
    /// `TCP_WRITE_QUEUE_BOUND` (default 8). Bounded capacity of the
    /// dispatcher→writer channel: how many completed responses may be queued
    /// waiting to be flushed to a slow client before the dispatcher stalls.
    /// Never unbounded — a stalled reader on the client side must eventually
    /// stall this server's processing of that connection, not grow memory.
    pub write_queue_bound: usize,
    /// `TCP_MTLS_DNS_SYNC_FALLBACK_CONCURRENCY` (default 4). Permits in the
    /// small, SEPARATE semaphore (never `handshake_concurrency`) that bounds
    /// how many handshakes may, at once, fall back to a synchronous DNS
    /// lookup on an mTLS pin-cache miss. See
    /// `tcp::tls::FingerprintClientCertVerifier`'s `sync_fallback` field doc.
    /// (The pin cache's own TTLs/entry cap/background-refresh concurrency
    /// are configured separately, in `tcp::dns_pin_cache::DnsPinCacheConfig`
    /// — that cache is process-global, unlike this per-server-instance
    /// semaphore.)
    pub dns_sync_fallback_concurrency: usize,
    /// Rate-limit configuration for TLS handshake ADMISSION — reuses
    /// `services::public_ratelimit::PublicReadLimiter` (per-source token
    /// bucket, distinct-source overflow protection, independent global
    /// bucket), configured from `TCP_HANDSHAKE_*` variables rather than the
    /// `PUBLIC_READ_*` ones the public-key-read surface uses. See
    /// `handshake_limiter_config_from_env`.
    pub handshake_limiter: PublicReadLimiterConfig,
    /// `TCP_LISTEN_BACKLOG` (default 1024). The kernel's accept queue depth:
    /// how many completed-but-not-yet-accepted connections may wait.
    ///
    /// Rust's `std::net::TcpListener::bind` hardcodes 128 and offers no way to
    /// change it, so a fast connection burst can see resets no matter what
    /// `net.core.somaxconn` says — raising the sysctl alone does nothing,
    /// because the value the process passes to `listen(2)` is the other half
    /// of the calculation. This server is built for large connection counts,
    /// so it sets the backlog itself.
    ///
    /// The kernel silently clamps this to `net.core.somaxconn`, so raising it
    /// here only helps once that sysctl is raised too. See
    /// `docs/deploying-at-scale.md`.
    pub listen_backlog: i32,
}

impl TcpServerConfig {
    pub fn from_env() -> Result<Self, String> {
        Ok(TcpServerConfig {
            max_connections: nonzero_u64_env("TCP_MAX_CONNECTIONS", 200_000)? as usize,
            handshake_timeout: Duration::from_secs(nonzero_u64_env(
                "TCP_HANDSHAKE_TIMEOUT_SECONDS",
                5,
            )?),
            handshake_concurrency: nonzero_u64_env("TCP_HANDSHAKE_CONCURRENCY", 512)? as usize,
            idle_timeout: Duration::from_secs(nonzero_u64_env("TCP_IDLE_TIMEOUT_SECONDS", 1800)?),
            io_timeout: Duration::from_secs(nonzero_u64_env("TCP_IO_TIMEOUT_SECONDS", 60)?),
            max_inflight_frames: nonzero_u64_env("TCP_MAX_INFLIGHT_FRAMES", 8)? as usize,
            write_queue_bound: nonzero_u64_env("TCP_WRITE_QUEUE_BOUND", 8)? as usize,
            dns_sync_fallback_concurrency: nonzero_u64_env(
                "TCP_MTLS_DNS_SYNC_FALLBACK_CONCURRENCY",
                4,
            )? as usize,
            handshake_limiter: handshake_limiter_config_from_env()?,
            listen_backlog: nonzero_u64_env("TCP_LISTEN_BACKLOG", 1024)?.min(i32::MAX as u64)
                as i32,
        })
    }
}

/// `PublicReadLimiterConfig` read from `TCP_HANDSHAKE_*` variables instead of
/// `PUBLIC_READ_*`. Defaults are deliberately stricter than the public-read
/// defaults: a TLS handshake is far more expensive (asymmetric crypto) than
/// the cheap indexed reads the public-key surface guards.
///
/// Trusted-proxy forwarding is intentionally NOT supported here: there is no
/// forwarded-header concept at the raw-TCP layer this limiter runs at (the
/// same reasoning `public_ratelimit::source_key_from_str`'s doc comment
/// gives for the plain-TCP peer address) — the source is always the direct
/// socket peer.
fn handshake_limiter_config_from_env() -> Result<PublicReadLimiterConfig, String> {
    let rate_per_minute = nonzero_u64_env("TCP_HANDSHAKE_RATE_PER_MINUTE", 60)?;
    let burst = nonzero_u64_env("TCP_HANDSHAKE_BURST", 20)?;
    let global_rate_per_second = positive_f64_env("TCP_HANDSHAKE_GLOBAL_RATE_PER_SECOND", 500.0)?;
    let global_burst = nonzero_u64_env("TCP_HANDSHAKE_GLOBAL_BURST", 1000)?;
    let overflow_rate_per_second =
        positive_f64_env("TCP_HANDSHAKE_OVERFLOW_RATE_PER_SECOND", 20.0)?;
    let overflow_burst = nonzero_u64_env("TCP_HANDSHAKE_OVERFLOW_BURST", 40)?;
    let distinct_source_threshold =
        nonzero_u64_env("TCP_HANDSHAKE_DISTINCT_SOURCE_THRESHOLD", 10_000)?;
    let window_seconds = nonzero_u64_env("TCP_HANDSHAKE_WINDOW_SECONDS", 60)?;
    let ipv6_prefix = nonzero_u64_env("TCP_HANDSHAKE_IPV6_PREFIX", 64)?;
    if ipv6_prefix > 128 {
        return Err("TCP_HANDSHAKE_IPV6_PREFIX must be between 1 and 128".to_string());
    }

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
        trusted_proxies: Vec::new(),
        shard_count: 16,
    })
}

/// Bounded connection/handshake counters for one `TcpServer` instance. Plain
/// atomics with getters (module docs above) — never logs or exposes key
/// material, API keys, claim values, or message contents, only counts.
#[derive(Default)]
pub struct TcpMetrics {
    accepted_connections: AtomicU64,
    /// Gauge: currently open sockets from `accept()` to close (handshaking or
    /// established).
    open_connections: AtomicU64,
    /// Gauge: sockets that completed the TLS handshake and are serving the
    /// message loop.
    established_connections: AtomicU64,
    /// Gauge: sockets currently inside `TlsAcceptor::accept` (or waiting for
    /// a handshake-concurrency permit).
    handshakes_in_progress: AtomicU64,
    handshake_timeouts: AtomicU64,
    /// TLS/protocol handshake failures (bad cert, fingerprint mismatch, etc.)
    /// — distinct from a timeout.
    handshake_rejections: AtomicU64,
    shed_connection_limit: AtomicU64,
    shed_handshake_per_source: AtomicU64,
    shed_handshake_overflow: AtomicU64,
    shed_handshake_global: AtomicU64,
    frames_processed: AtomicU64,
    /// Gauge: total bytes currently allocated across all connections for a
    /// frame body that has been read off the wire but not yet decoded/handed
    /// to dispatch. Exists so a test can assert connections do not hold
    /// megabyte-scale buffers while idle, without relying on process RSS
    /// (signing-things-request.md, connection tests: "idle connection memory
    /// measurement... assert on your own accounting").
    frame_buffer_bytes: AtomicUsize,
}

impl TcpMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub(super) fn record_accepted(&self) {
        self.accepted_connections.fetch_add(1, Ordering::Relaxed);
        self.open_connections.fetch_add(1, Ordering::Relaxed);
    }
    pub(super) fn record_closed(&self) {
        self.open_connections.fetch_sub(1, Ordering::Relaxed);
    }
    pub(super) fn record_handshake_started(&self) {
        self.handshakes_in_progress.fetch_add(1, Ordering::Relaxed);
    }
    pub(super) fn record_handshake_ended(&self) {
        self.handshakes_in_progress.fetch_sub(1, Ordering::Relaxed);
    }
    pub(super) fn record_handshake_timeout(&self) {
        self.handshake_timeouts.fetch_add(1, Ordering::Relaxed);
    }
    pub(super) fn record_handshake_rejection(&self) {
        self.handshake_rejections.fetch_add(1, Ordering::Relaxed);
    }
    pub(super) fn record_established(&self) {
        self.established_connections.fetch_add(1, Ordering::Relaxed);
    }
    pub(super) fn record_unestablished(&self) {
        self.established_connections.fetch_sub(1, Ordering::Relaxed);
    }
    pub(super) fn record_shed_connection_limit(&self) {
        self.shed_connection_limit.fetch_add(1, Ordering::Relaxed);
    }
    pub(super) fn record_handshake_shed(&self, reason: LimitReason) {
        match reason {
            LimitReason::PerSource => &self.shed_handshake_per_source,
            LimitReason::Overflow => &self.shed_handshake_overflow,
            LimitReason::Global => &self.shed_handshake_global,
        }
        .fetch_add(1, Ordering::Relaxed);
    }
    pub(super) fn record_frame_processed(&self) {
        self.frames_processed.fetch_add(1, Ordering::Relaxed);
    }
    pub(super) fn add_frame_buffer_bytes(&self, bytes: usize) {
        self.frame_buffer_bytes.fetch_add(bytes, Ordering::Relaxed);
    }
    pub(super) fn sub_frame_buffer_bytes(&self, bytes: usize) {
        self.frame_buffer_bytes.fetch_sub(bytes, Ordering::Relaxed);
    }

    pub fn accepted_connections(&self) -> u64 {
        self.accepted_connections.load(Ordering::Relaxed)
    }
    pub fn open_connections(&self) -> u64 {
        self.open_connections.load(Ordering::Relaxed)
    }
    pub fn established_connections(&self) -> u64 {
        self.established_connections.load(Ordering::Relaxed)
    }
    pub fn handshakes_in_progress(&self) -> u64 {
        self.handshakes_in_progress.load(Ordering::Relaxed)
    }
    pub fn handshake_timeouts(&self) -> u64 {
        self.handshake_timeouts.load(Ordering::Relaxed)
    }
    pub fn handshake_rejections(&self) -> u64 {
        self.handshake_rejections.load(Ordering::Relaxed)
    }
    pub fn shed_connection_limit(&self) -> u64 {
        self.shed_connection_limit.load(Ordering::Relaxed)
    }
    pub fn shed_handshake_per_source(&self) -> u64 {
        self.shed_handshake_per_source.load(Ordering::Relaxed)
    }
    pub fn shed_handshake_overflow(&self) -> u64 {
        self.shed_handshake_overflow.load(Ordering::Relaxed)
    }
    pub fn shed_handshake_global(&self) -> u64 {
        self.shed_handshake_global.load(Ordering::Relaxed)
    }
    pub fn frames_processed(&self) -> u64 {
        self.frames_processed.load(Ordering::Relaxed)
    }
    /// Current total bytes held for read-but-unprocessed frame bodies, across
    /// every connection on this server. See the field doc above.
    pub fn frame_buffer_bytes(&self) -> usize {
        self.frame_buffer_bytes.load(Ordering::Relaxed)
    }
}

/// Log the effective file-descriptor limit and the configured connection
/// limit at startup (signing-things-request.md: "Report the effective
/// file-descriptor limit AND the connection limit at startup"). Best-effort:
/// a platform without `getrlimit` (non-unix) just logs the configured limit.
pub fn report_fd_and_connection_limits(max_connections: usize) {
    // Headroom for the listening socket, the database connection pool, log
    // files, and other process-level file descriptors that are not
    // connections.
    const RESERVED_FDS: u64 = 256;

    #[cfg(unix)]
    {
        // Safety: `rlimit` is a plain C struct of two integers; `getrlimit`
        // with a valid RLIMIT_NOFILE resource and a pointer to it is the
        // documented, safe usage of this libc call.
        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0 {
            log::info!(
                "TCP server file-descriptor limit: soft={} hard={}; configured TCP_MAX_CONNECTIONS={}",
                limit.rlim_cur,
                limit.rlim_max,
                max_connections
            );
            if (max_connections as u64).saturating_add(RESERVED_FDS) > limit.rlim_cur {
                log::warn!(
                    "TCP_MAX_CONNECTIONS ({}) leaves little or no headroom under the soft \
                     file-descriptor limit ({}); raise the process ulimit (`ulimit -n`) or \
                     lower TCP_MAX_CONNECTIONS",
                    max_connections,
                    limit.rlim_cur
                );
            }
        } else {
            log::warn!(
                "Could not read the file-descriptor limit (getrlimit failed); configured \
                 TCP_MAX_CONNECTIONS={}",
                max_connections
            );
        }
    }
    #[cfg(not(unix))]
    {
        log::info!(
            "configured TCP_MAX_CONNECTIONS={} (file-descriptor limit reporting is unix-only)",
            max_connections
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_default_to_zero() {
        let m = TcpMetrics::new();
        assert_eq!(m.accepted_connections(), 0);
        assert_eq!(m.open_connections(), 0);
        assert_eq!(m.established_connections(), 0);
        assert_eq!(m.frame_buffer_bytes(), 0);
    }

    #[test]
    fn metrics_track_accept_and_close() {
        let m = TcpMetrics::new();
        m.record_accepted();
        m.record_accepted();
        assert_eq!(m.accepted_connections(), 2);
        assert_eq!(m.open_connections(), 2);
        m.record_closed();
        assert_eq!(m.open_connections(), 1);
        assert_eq!(
            m.accepted_connections(),
            2,
            "accepted is cumulative, not a gauge"
        );
    }

    #[test]
    fn metrics_track_handshake_shed_reasons() {
        let m = TcpMetrics::new();
        m.record_handshake_shed(LimitReason::PerSource);
        m.record_handshake_shed(LimitReason::Overflow);
        m.record_handshake_shed(LimitReason::Overflow);
        m.record_handshake_shed(LimitReason::Global);
        assert_eq!(m.shed_handshake_per_source(), 1);
        assert_eq!(m.shed_handshake_overflow(), 2);
        assert_eq!(m.shed_handshake_global(), 1);
    }

    #[test]
    fn frame_buffer_accounting_returns_to_zero() {
        let m = TcpMetrics::new();
        m.add_frame_buffer_bytes(4096);
        assert_eq!(m.frame_buffer_bytes(), 4096);
        m.sub_frame_buffer_bytes(4096);
        assert_eq!(m.frame_buffer_bytes(), 0);
    }

    #[test]
    fn handshake_limiter_config_reads_defaults() {
        // Clear any of these that might be set in the test process
        // environment, so this asserts the documented defaults.
        for var in [
            "TCP_HANDSHAKE_RATE_PER_MINUTE",
            "TCP_HANDSHAKE_BURST",
            "TCP_HANDSHAKE_GLOBAL_RATE_PER_SECOND",
        ] {
            std::env::remove_var(var);
        }
        let cfg = handshake_limiter_config_from_env().unwrap();
        assert_eq!(cfg.per_source_capacity, 20.0);
        assert_eq!(cfg.per_source_refill_per_sec, 1.0);
        assert!(cfg.trusted_proxies.is_empty());
    }
}
