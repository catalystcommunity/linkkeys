pub mod dns_pin_cache;
pub mod limits;
pub mod tls;

use std::collections::BTreeSet;
use std::env;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

use crate::conversions::get_domain_name;
use crate::db::DbPool;
use crate::services::handshake::HandshakeHandler;
use crate::services::hello::HelloHandler;
use crate::services::public_ratelimit::{PublicReadDecision, PublicReadLimiter};
use limits::{TcpMetrics, TcpServerConfig};

use liblinkkeys::generated::types::{
    DepositClaimResponse, DomainPublicKey, GetDomainKeysResponse, GetUserKeysResponse, UserInfo,
};

// The RPC envelope is the canonical CSIL-RPC transport (`csilgen-transport`),
// not a bespoke struct — `RpcRequest` / `RpcResponse` carry the tag-24 payload,
// version, status registry, and `variant`. Framing on this TCP carrier is the
// length-prefixed frames in `read_frame`/`write_frame` (matches the spec's
// length-delimited stream carrier). `RpcRequest`'s fields (`service`, `op`,
// `payload`, `auth`) line up with what `dispatch` already reads.
use csilgen_transport::rpc::{RpcRequest, RpcResponse};
use csilgen_transport::Status;

#[derive(Serialize, Deserialize)]
struct HelloRequest {
    name: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct HelloResponse {
    greeting: String,
}

#[derive(Serialize, Deserialize)]
struct CheckResultResponse {
    result: bool,
}

/// Capabilities the dispatch needs for ops that make an onward server-to-server
/// call (the `Rp` service's verify-assertion / userinfo-fetch reach the issuing
/// IDP). Populated for both the TCP and (soon) any other carrier that has a
/// database pool and a Tokio runtime handle available; the web `/csil/v1/rpc`
/// carrier and the test harness pass `None` — those ops have dedicated
/// routes/tests elsewhere.
///
/// `rt` is a plain `Handle` to whatever runtime is currently driving the
/// connection. Every dispatch call this carries is made from INSIDE a
/// `tokio::task::spawn_blocking` closure (see `dispatch_one_frame` below), never
/// from an async task's own poll — so `rt.block_on(...)` here is the
/// officially-supported "call async code from a spawn_blocking closure"
/// bridge, not a nested-runtime hazard. `dispatch`, `dispatch_rp`, and
/// friends are unaware of any of this; they only ever see `&Handle`, exactly
/// as before.
pub struct OutboundCtx<'a> {
    pub net: &'a crate::net::Net,
    pub rt: &'a tokio::runtime::Handle,
}

struct DispatchContext<'a> {
    client_domain: Option<&'a str>,
    recovery_source_key: &'a str,
    outbound: Option<&'a OutboundCtx<'a>>,
    browser_user: Option<&'a crate::db::models::User>,
    ui_configuration: Option<&'a crate::services::ui::LoadedUiConfiguration>,
}

/// Everything a spawned connection task needs, cheap to clone (every field is
/// an `Arc`/pool handle or otherwise already `Clone`-cheap).
#[derive(Clone)]
struct ConnectionContext {
    ready_flag: Arc<AtomicBool>,
    db_pool: DbPool,
    net: crate::net::Net,
    ui_configuration: crate::services::ui::LoadedUiConfiguration,
}

/// Event-driven TCP server: one Tokio task per connection, asynchronous
/// rustls I/O (`tokio_rustls`), no OS thread held for a connection's
/// lifetime. See `signing-things-request.md`, "Connection scalability", for
/// the full design this implements.
pub struct TcpServer {
    listener: tokio::net::TcpListener,
    ready_flag: Arc<AtomicBool>,
    db_pool: DbPool,
    tls_acceptor: TlsAcceptor,
    net: crate::net::Net,
    config: Arc<TcpServerConfig>,
    metrics: Arc<TcpMetrics>,
    handshake_limiter: Arc<PublicReadLimiter>,
    handshake_semaphore: Arc<tokio::sync::Semaphore>,
    /// Total open sockets, accept()-to-close (handshaking or established).
    /// This IS the established-connection limit and the memory safety valve
    /// in one knob — see `TcpServerConfig::max_connections`'s doc comment for
    /// why a second, separate "memory limit" config would not be more
    /// meaningful without real per-connection memory profiling.
    active_connections: Arc<AtomicUsize>,
    ui_configuration: crate::services::ui::LoadedUiConfiguration,
}

impl TcpServer {
    pub fn new(
        ready_flag: Arc<AtomicBool>,
        db_pool: DbPool,
        net: crate::net::Net,
        ui_configuration: crate::services::ui::LoadedUiConfiguration,
    ) -> std::io::Result<Self> {
        let port = crate::config::nonzero_u16_env("TCP_PORT", liblinkkeys::dns::DEFAULT_TCP_PORT)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
        let config = Arc::new(
            TcpServerConfig::from_env()
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?,
        );

        // Bind synchronously (as before — this runs once at startup, before
        // any connection is being served) and hand the socket to Tokio.
        let std_listener = std::net::TcpListener::bind(format!("0.0.0.0:{}", port))?;
        set_listen_backlog(&std_listener, config.listen_backlog);
        std_listener.set_nonblocking(true)?;
        let listener = tokio::net::TcpListener::from_std(std_listener)?;

        // Seed the process-wide mTLS pin cache from the persisted TOFU pin
        // table BEFORE the listener starts serving, so a process restart
        // does not turn every already-trusted peer back into "first
        // contact" (see `seed_dns_pin_cache_from_db` and
        // `dns_pin_cache::MTLS_DNS_PIN_CACHE`'s doc comment).
        seed_dns_pin_cache_from_db(&db_pool);

        let tls_config = match build_tls_config(&db_pool, net.dns.clone(), config.clone()) {
            Ok(config) => {
                log::info!("TCP server listening on port {} (mutual TLS, async)", port);
                config
            }
            Err(e) => {
                log::error!("TCP TLS setup failed: {}. Ensure domain keys are initialized and DOMAIN_KEY_PASSPHRASE is set.", e);
                return Err(std::io::Error::other(e.to_string()));
            }
        };

        limits::report_fd_and_connection_limits(config.max_connections);
        log::info!(
            "TCP server config: max_connections={} handshake_timeout={:?} handshake_concurrency={} \
             idle_timeout={:?} io_timeout={:?} max_inflight_frames={} write_queue_bound={} \
             dns_sync_fallback_concurrency={}",
            config.max_connections,
            config.handshake_timeout,
            config.handshake_concurrency,
            config.idle_timeout,
            config.io_timeout,
            config.max_inflight_frames,
            config.write_queue_bound,
            config.dns_sync_fallback_concurrency,
        );

        let handshake_limiter = Arc::new(PublicReadLimiter::new(config.handshake_limiter.clone()));
        let handshake_semaphore =
            Arc::new(tokio::sync::Semaphore::new(config.handshake_concurrency));

        Ok(TcpServer {
            listener,
            ready_flag,
            db_pool,
            tls_acceptor: TlsAcceptor::from(tls_config),
            net,
            config,
            metrics: Arc::new(TcpMetrics::new()),
            handshake_limiter,
            handshake_semaphore,
            active_connections: Arc::new(AtomicUsize::new(0)),
            ui_configuration,
        })
    }

    /// Bounded metrics for this server instance (signing-things-request.md,
    /// "Connection and cache metrics").
    pub fn metrics(&self) -> Arc<TcpMetrics> {
        self.metrics.clone()
    }

    /// Accept loop. Runs for the life of the process — the previous
    /// implementation had no shutdown hook either (`thread::spawn(move ||
    /// tcp_server.run())` in `main.rs`, never joined); that behavior is
    /// unchanged here, just as an async task instead of a spawned OS thread.
    pub async fn run(self) {
        loop {
            let (stream, peer_addr) = match self.listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    log::error!("Error accepting connection: {}", e);
                    continue;
                }
            };
            self.metrics.record_accepted();

            // Cheapest possible rejection first, before any TLS/DNS/rate-limit
            // work: a hard cap on concurrently open sockets. Shedding here
            // (rather than after the handshake) is what keeps an attacker from
            // exhausting memory/file-descriptors simply by opening many raw
            // TCP connections and never completing a handshake.
            let previously_open = self.active_connections.fetch_add(1, Ordering::SeqCst);
            if previously_open >= self.config.max_connections {
                self.active_connections.fetch_sub(1, Ordering::SeqCst);
                self.metrics.record_shed_connection_limit();
                drop(stream);
                continue;
            }

            let ctx = ConnectionContext {
                ready_flag: self.ready_flag.clone(),
                db_pool: self.db_pool.clone(),
                net: self.net.clone(),
                ui_configuration: self.ui_configuration.clone(),
            };
            let acceptor = self.tls_acceptor.clone();
            let handshake_limiter = self.handshake_limiter.clone();
            let handshake_semaphore = self.handshake_semaphore.clone();
            let active_connections = self.active_connections.clone();
            let metrics = self.metrics.clone();
            let config = self.config.clone();

            tokio::spawn(async move {
                let _slot = OpenConnectionGuard {
                    active_connections,
                    metrics: metrics.clone(),
                };
                handle_connection(
                    stream,
                    peer_addr,
                    acceptor,
                    handshake_limiter,
                    handshake_semaphore,
                    config,
                    metrics,
                    ctx,
                )
                .await;
            });
        }
    }
}

/// Decrements the open-connection count and gauge no matter how the
/// connection task ends (normal return, early `return`, or panic unwind) —
/// covers rate-limited, handshake-timed-out/rejected, and normally-closed
/// connections alike with one accounting path.
struct OpenConnectionGuard {
    active_connections: Arc<AtomicUsize>,
    metrics: Arc<TcpMetrics>,
}

impl Drop for OpenConnectionGuard {
    fn drop(&mut self) {
        self.active_connections.fetch_sub(1, Ordering::SeqCst);
        self.metrics.record_closed();
    }
}

/// Decrements the established-connection gauge when a connection that
/// completed its handshake ends, for any reason.
struct EstablishedGuard {
    metrics: Arc<TcpMetrics>,
}

impl Drop for EstablishedGuard {
    fn drop(&mut self) {
        self.metrics.record_unestablished();
    }
}

/// Build TLS ServerConfig with mutual TLS from the first active domain key.
fn build_tls_config(
    db_pool: &DbPool,
    dns: Arc<dyn crate::net::DnsResolver>,
    config: Arc<TcpServerConfig>,
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error>> {
    let passphrase =
        env::var("DOMAIN_KEY_PASSPHRASE").map_err(|_| "DOMAIN_KEY_PASSPHRASE not set")?;

    let domain_keys = db_pool
        .list_active_domain_keys()
        .map_err(|e| format!("Failed to list domain keys: {}", e))?;

    let dk = domain_keys
        .first()
        .ok_or("No active domain keys — run 'domain init' first")?;

    let sk_bytes =
        liblinkkeys::crypto::decrypt_private_key(&dk.private_key_encrypted, passphrase.as_bytes())
            .map_err(|e| format!("Failed to decrypt domain key: {}", e))?;

    let seed: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new(
        sk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Domain key is not 32 bytes")?,
    );

    let domain_name = get_domain_name();
    let (cert_der, key_der) = tls::generate_domain_tls_cert(&domain_name, &seed)?;

    // No dedicated runtime needed for the verifier any more (contrast with
    // the previous blocking implementation): `FingerprintClientCertVerifier`
    // touches the process-wide `dns_pin_cache::MTLS_DNS_PIN_CACHE`
    // synchronously on the hot (hit) path, takes a bounded synchronous DNS
    // fallback on a miss (gated by `sync_fallback`), and only ever hands
    // real DNS work off to a background `tokio::spawn` task when that
    // fallback is exhausted — see `tcp::dns_pin_cache` and the verifier's
    // doc comments.
    let sync_fallback = Arc::new(tokio::sync::Semaphore::new(
        config.dns_sync_fallback_concurrency,
    ));
    let client_verifier = Arc::new(tls::FingerprintClientCertVerifier::new(
        dns,
        dns_pin_cache::MTLS_DNS_PIN_CACHE.clone(),
        sync_fallback,
    ));

    tls::build_server_config(cert_der, key_der, client_verifier)
}

/// Seed the process-wide mTLS DNS pin cache
/// (`dns_pin_cache::MTLS_DNS_PIN_CACHE`) from the persisted TOFU pin table
/// (`domain_key_pins`) at startup. That table already holds the last-known-
/// good fingerprint set for every domain this server has resolved via the
/// OUTBOUND path (`services::pins::check_and_update_pin`, driven by RP
/// lookups, `linkkeys pins recheck`, etc.) — seeding the INBOUND
/// verification cache from it means "the process just restarted" no longer
/// means "every peer we already trust is first contact again", which is the
/// common case a bare, request-scoped cache would otherwise get wrong on
/// every deploy/restart. Best-effort: a DB error here is logged, not fatal
/// — the cache still self-heals via the bounded synchronous fallback and
/// background refresh on the first real handshake for each domain.
fn seed_dns_pin_cache_from_db(db_pool: &DbPool) {
    match db_pool.list_domain_pins() {
        Ok(pins) => {
            let mut seeded = 0usize;
            for pin in pins {
                let fingerprints: Vec<String> = pin
                    .fingerprints
                    .split(',')
                    .filter(|fp| !fp.is_empty())
                    .map(str::to_string)
                    .collect();
                if fingerprints.is_empty() {
                    continue;
                }
                dns_pin_cache::MTLS_DNS_PIN_CACHE.insert_positive(&pin.domain, fingerprints);
                seeded += 1;
            }
            log::info!(
                "Seeded the mTLS DNS pin cache with {} known domain(s) from domain_key_pins",
                seeded
            );
        }
        Err(e) => {
            log::warn!(
                "Could not seed the mTLS DNS pin cache from domain_key_pins: {}. Inbound \
                 verification will still work via the bounded synchronous DNS fallback and \
                 background refresh, just without a warm start.",
                e
            );
        }
    }
}

/// Read one length-prefixed frame body, given its length has already been
/// read. Allocates exactly `len` bytes — never `MAX_FRAME_SIZE` — so an idle
/// or small-message connection never holds a megabyte-scale buffer
/// (signing-things-request.md: "`MAX_FRAME_SIZE` is a cap, not an allocation
/// size").
async fn read_frame_body(
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
    len: usize,
) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_frame_async(
    writer: &mut (impl tokio::io::AsyncWrite + Unpin),
    data: &[u8],
) -> std::io::Result<()> {
    if data.len() > MAX_FRAME_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Response frame too large",
        ));
    }
    let len = (data.len() as u32).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(data).await?;
    writer.flush().await
}

pub(crate) const MAX_FRAME_SIZE: usize = 1024 * 1024;

type ServerTlsStream = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;

/// Per-connection lifecycle: rate-limit the handshake attempt, bound
/// concurrent handshakes with a semaphore, bound the handshake's total time
/// with a timeout, then hand off to the message loop. Never propagates an
/// error to its caller — every exit path (rate-limited, semaphore-timed-out,
/// handshake failed/timed out, or the message loop ending) is handled here so
/// `TcpServer::run`'s accept loop never sees a per-connection failure.
#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    acceptor: TlsAcceptor,
    handshake_limiter: Arc<PublicReadLimiter>,
    handshake_semaphore: Arc<tokio::sync::Semaphore>,
    config: Arc<TcpServerConfig>,
    metrics: Arc<TcpMetrics>,
    ctx: ConnectionContext,
) {
    let _ = stream.set_nodelay(true);

    // Source-IP handshake rate limit BEFORE any expensive handshake work
    // (signing-things-request.md: "Apply a source-IP handshake rate limit
    // BEFORE expensive handshake work where possible"). There is no
    // forwarded-header concept at this layer — always the direct peer.
    let source_key = handshake_limiter.source_key(peer_addr, None);
    match handshake_limiter.check(&source_key) {
        PublicReadDecision::Allow => {}
        PublicReadDecision::Limited { reason, .. } => {
            metrics.record_handshake_shed(reason);
            log::debug!("TCP handshake rate limited for {}: {:?}", peer_addr, reason);
            return;
        }
    }

    metrics.record_handshake_started();
    let handshake_result = tokio::time::timeout(config.handshake_timeout, async {
        // Configurable semaphore bounding concurrent TLS handshakes — CPU-
        // costly crypto, bounded independently of the (much larger)
        // established-connection limit.
        let _permit = handshake_semaphore
            .acquire()
            .await
            .expect("handshake semaphore is never closed");
        acceptor.accept(stream).await
    })
    .await;
    metrics.record_handshake_ended();

    let tls_stream: ServerTlsStream = match handshake_result {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            metrics.record_handshake_rejection();
            log::debug!("TLS handshake failed for {}: {}", peer_addr, e);
            return;
        }
        Err(_) => {
            metrics.record_handshake_timeout();
            log::debug!("TLS handshake timed out for {}", peer_addr);
            return;
        }
    };

    // The verified client certificate (if the caller is a domain) is now
    // available. mTLS client auth is optional; a caller with no cert yields
    // no client domain.
    let client_domain = {
        let (_, server_conn) = tls_stream.get_ref();
        server_conn
            .peer_certificates()
            .and_then(|certs| certs.first())
            .and_then(tls::verified_client_domain)
    };

    metrics.record_established();
    let _established = EstablishedGuard {
        metrics: metrics.clone(),
    };

    let source_key_str = peer_addr.ip().to_string();
    message_loop(
        tls_stream,
        &ctx,
        client_domain.as_deref(),
        &source_key_str,
        &config,
        &metrics,
    )
    .await;
}

/// Maximum CBOR nesting depth allowed. Prevents stack overflow from deeply
/// nested payloads while leaving room for real signed request envelopes, which
/// carry nested maps/arrays for request bodies and multiple signatures.
const MAX_CBOR_DEPTH: usize = 64;

/// Scan raw CBOR bytes and reject if nesting depth exceeds the limit.
/// CBOR major types 4 (array) and 5 (map) increase depth; their items decrease it
/// as they're consumed. This is a conservative linear scan, not a full parser.
pub(crate) fn check_cbor_depth(data: &[u8]) -> bool {
    let mut stack: Vec<Option<usize>> = Vec::new();
    let mut i = 0;
    while i < data.len() {
        while matches!(stack.last(), Some(Some(0))) {
            stack.pop();
        }
        if let Some(Some(remaining)) = stack.last_mut() {
            *remaining = remaining.saturating_sub(1);
        }

        let major = data[i] >> 5;
        let additional = data[i] & 0x1f;
        i += 1;

        let value = match additional {
            0..=23 => Some(additional as u64),
            24 => {
                if i >= data.len() {
                    return false;
                }
                let v = data[i] as u64;
                i += 1;
                Some(v)
            }
            25 => {
                if i + 2 > data.len() {
                    return false;
                }
                let v = u16::from_be_bytes([data[i], data[i + 1]]) as u64;
                i += 2;
                Some(v)
            }
            26 => {
                if i + 4 > data.len() {
                    return false;
                }
                let v = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as u64;
                i += 4;
                Some(v)
            }
            27 => {
                if i + 8 > data.len() {
                    return false;
                }
                let v = u64::from_be_bytes([
                    data[i],
                    data[i + 1],
                    data[i + 2],
                    data[i + 3],
                    data[i + 4],
                    data[i + 5],
                    data[i + 6],
                    data[i + 7],
                ]);
                i += 8;
                Some(v)
            }
            28..=30 => return false, // reserved, malformed
            31 => None,
            _ => unreachable!(),
        };

        match major {
            0 | 1 => {} // unsigned/negative int — no nesting
            2 | 3 => {
                let Some(len) = value else {
                    return false;
                };
                let Ok(len) = usize::try_from(len) else {
                    return false;
                };
                // `checked_add`: a declared length near usize::MAX would
                // otherwise wrap and turn this bounds check into a pass.
                let Some(end) = i.checked_add(len) else {
                    return false;
                };
                if end > data.len() {
                    return false;
                }
                i = end;
            }
            4 | 5 => {
                let entries = match value {
                    Some(len) if major == 4 => len,
                    Some(len) => len.saturating_mul(2),
                    None => return false,
                };
                let Ok(entries) = usize::try_from(entries) else {
                    return false;
                };
                // An array or map cannot hold more items than there are bytes
                // left to encode them in — every item costs at least one byte.
                // A larger declared count is unsatisfiable, so the payload is
                // malformed whatever else it says.
                //
                // Kept as defence in depth. The generated CBOR decoder used
                // to pre-allocate from the DECLARED count
                // (`Vec::with_capacity(n)` in `codec.gen.rs`), so a nine-byte
                // anonymous request declaring 2^40 array elements made the
                // process attempt a 35 TB allocation and abort. csilgen has
                // since been fixed to bound the length before the cast, and
                // the generated code here carries that fix.
                //
                // This guard stays anyway: it runs BEFORE any decode, on the
                // envelope as well as the payload, so it does not depend on
                // any particular generator version being checked in. A
                // regenerate against an older csilgen would otherwise silently
                // reopen the hole.
                if entries > data.len() - i {
                    return false;
                }
                stack.push(Some(entries));
                if stack.len() > MAX_CBOR_DEPTH {
                    return false;
                }
            }
            6 => {} // tag — next item is the tagged value
            7 => {
                if additional == 31 || value.is_none() {
                    return false;
                }
            }
            _ => return false,
        }
    }
    stack.into_iter().all(|remaining| remaining == Some(0))
}

/// Drive one established connection's request/response traffic as three
/// cooperating stages, joined by two bounded channels:
///
/// ```text
/// socket --read_loop--> [frame_tx: max_inflight_frames] --dispatch_loop--> [resp_tx: write_queue_bound] --write_loop--> socket
/// ```
///
/// - `read_loop` only reads frames and enforces the idle/I/O timeouts and
///   size/depth checks; it never runs `dispatch` itself. Its `frame_tx.send`
///   blocks once `max_inflight_frames` frames are queued for processing —
///   that's the "process a bounded number of in-flight frames per
///   connection" requirement: a fast pipelining client can only run this far
///   ahead of a slower server before the read side itself stalls, which in
///   turn applies TCP-level backpressure to the client.
/// - `dispatch_loop` drains `frame_tx` strictly in order (a single consumer,
///   so response order matches request order with no extra bookkeeping),
///   runs `dispatch` via `spawn_blocking`, and pushes the encoded response
///   into `resp_tx`.
/// - `write_loop` drains `resp_tx` and writes each response to the socket.
///   `resp_tx.send` blocking once `write_queue_bound` responses are queued
///   is the "apply write backpressure; never build an unbounded response
///   queue" requirement: a client that stops reading eventually stalls
///   `dispatch_loop`, which stalls `read_loop`, which stops draining the
///   socket — bounded backpressure end to end, no unbounded buffer anywhere.
///
/// All three stages share one connection's lifetime and wind down as a
/// cascade: whichever stage ends first (cleanly or with an error) drops its
/// half of a channel, which makes the next stage's `recv()` return `None`
/// and return in turn, and so on. `tokio::join!` waits for all three to
/// finish (rather than `try_join!`'s cancel-on-first-error), which is what
/// lets that drain-to-completion cascade actually run instead of abruptly
/// dropping a stage mid-poll.
async fn message_loop(
    stream: ServerTlsStream,
    ctx: &ConnectionContext,
    client_domain: Option<&str>,
    recovery_source_key: &str,
    config: &Arc<TcpServerConfig>,
    metrics: &Arc<TcpMetrics>,
) {
    let (reader, writer) = tokio::io::split(stream);
    let (frame_tx, frame_rx) = mpsc::channel::<Vec<u8>>(config.max_inflight_frames.max(1));
    let (resp_tx, resp_rx) = mpsc::channel::<Vec<u8>>(config.write_queue_bound.max(1));

    let read = read_loop(reader, frame_tx, config.clone(), metrics.clone());
    let dispatch = dispatch_loop(
        frame_rx,
        resp_tx,
        ctx.clone(),
        client_domain.map(str::to_string),
        recovery_source_key.to_string(),
        metrics.clone(),
    );
    let write = write_loop(writer, resp_rx, config.io_timeout);

    let (read_result, (), write_result) = tokio::join!(read, dispatch, write);
    if let Err(e) = read_result {
        log::debug!("Connection read side closed: {}", e);
    }
    if let Err(e) = write_result {
        log::debug!("Connection write side closed: {}", e);
    }
}

/// Reads frames off the wire and hands them to `dispatch_loop` via `tx`.
/// Applies the idle timeout (waiting for a new frame to start) and the I/O
/// timeout (once a frame's length prefix has arrived, reading its body must
/// complete promptly — catches a slowloris stalling mid-frame). A clean EOF
/// or an idle timeout both end the loop normally (`Ok(())`); anything else is
/// a hard error that tears the connection down.
async fn read_loop(
    mut reader: tokio::io::ReadHalf<ServerTlsStream>,
    tx: mpsc::Sender<Vec<u8>>,
    config: Arc<TcpServerConfig>,
    metrics: Arc<TcpMetrics>,
) -> std::io::Result<()> {
    loop {
        let mut len_buf = [0u8; 4];
        match tokio::time::timeout(config.idle_timeout, reader.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                return Ok(());
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(()), // idle timeout: a normal, quiet disconnect
        }

        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_FRAME_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Frame too large ({} bytes, max {})", len, MAX_FRAME_SIZE),
            ));
        }

        // Exact-size allocation, not MAX_FRAME_SIZE — see `read_frame_body`.
        metrics.add_frame_buffer_bytes(len);
        let body = tokio::time::timeout(config.io_timeout, read_frame_body(&mut reader, len)).await;
        let frame = match body {
            Ok(Ok(frame)) => frame,
            Ok(Err(e)) => {
                metrics.sub_frame_buffer_bytes(len);
                return Err(e);
            }
            Err(_) => {
                metrics.sub_frame_buffer_bytes(len);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "frame body read timed out",
                ));
            }
        };

        // Bounded hand-off: blocks (backpressure) once `max_inflight_frames`
        // frames are already queued for `dispatch_loop`.
        if tx.send(frame).await.is_err() {
            metrics.sub_frame_buffer_bytes(len);
            return Ok(()); // dispatch_loop is gone; nothing left to do
        }
        metrics.sub_frame_buffer_bytes(len);
    }
}

/// Drains frames in order, dispatches each one (off the async runtime, via
/// `spawn_blocking` — see `OutboundCtx`'s doc comment for why that's required
/// and not merely a nicety), and forwards the encoded response to
/// `write_loop` via `resp_tx`. Never returns an error itself: a dispatch
/// panic becomes an internal-error response rather than tearing down the
/// connection, matching the sync server's `catch_unwind` behavior for the
/// CBOR-decode path and extending it to dispatch as a whole.
async fn dispatch_loop(
    mut frame_rx: mpsc::Receiver<Vec<u8>>,
    resp_tx: mpsc::Sender<Vec<u8>>,
    ctx: ConnectionContext,
    client_domain: Option<String>,
    recovery_source_key: String,
    metrics: Arc<TcpMetrics>,
) {
    while let Some(frame) = frame_rx.recv().await {
        let response = dispatch_one_frame(&frame, &ctx, &client_domain, &recovery_source_key).await;
        metrics.record_frame_processed();
        if resp_tx.send(response).await.is_err() {
            return; // write_loop is gone; connection is tearing down
        }
    }
}

/// Validate and dispatch exactly one already-read frame, returning the
/// encoded response. Depth checks and the API-key auth-attempt rate limit
/// happen here, unchanged from the previous synchronous implementation; the
/// actual `dispatch(...)` call happens inside `spawn_blocking` because it (via
/// `OutboundCtx`) may call `Handle::block_on` for onward server-to-server
/// calls, which would panic if invoked directly from this async task.
async fn dispatch_one_frame(
    frame: &[u8],
    ctx: &ConnectionContext,
    client_domain: &Option<String>,
    recovery_source_key: &str,
) -> Vec<u8> {
    if !check_cbor_depth(frame) {
        return error_response(1, "Malformed request: excessive nesting depth");
    }

    let envelope: RpcRequest = match std::panic::catch_unwind(|| RpcRequest::decode(frame)) {
        Ok(Ok(env)) => env,
        Ok(Err(e)) => return error_response(1, &format!("Invalid request envelope: {}", e)),
        Err(_) => {
            // Deserialization panicked (e.g. stack overflow) — don't crash
            // the connection.
            log::warn!(
                "CBOR deserialization panicked on frame of {} bytes",
                frame.len()
            );
            return error_response(1, "Malformed request");
        }
    };

    // The inner payload is decoded per-op inside dispatch; depth-check it
    // here too so a deeply-nested payload can't stack-overflow a handler
    // (tcp-05). It's already size-bounded by the 1 MiB frame cap.
    if !check_cbor_depth(&envelope.payload) {
        return error_response(1, "Malformed request: excessive nesting depth");
    }
    if envelope.auth.is_some()
        && !crate::services::ratelimit::API_KEY_SOURCE.check(recovery_source_key)
    {
        return error_response(5, "Too many authentication attempts. Wait and try again");
    }

    let rt = tokio::runtime::Handle::current();
    let net = ctx.net.clone();
    let db_pool = ctx.db_pool.clone();
    let ready_flag = ctx.ready_flag.clone();
    let ui_configuration = ctx.ui_configuration.clone();
    let client_domain = client_domain.clone();
    let recovery_source_key = recovery_source_key.to_string();

    tokio::task::spawn_blocking(move || {
        let outbound = OutboundCtx { net: &net, rt: &rt };
        dispatch(
            &envelope,
            &ready_flag,
            &db_pool,
            DispatchContext {
                client_domain: client_domain.as_deref(),
                recovery_source_key: &recovery_source_key,
                outbound: Some(&outbound),
                browser_user: None,
                ui_configuration: Some(&ui_configuration),
            },
        )
    })
    .await
    .unwrap_or_else(|e| {
        log::error!("dispatch task panicked: {}", e);
        error_response(4, "internal error")
    })
}

/// Drains completed responses and writes them to the socket, bounded by the
/// I/O timeout per write.
async fn write_loop(
    mut writer: tokio::io::WriteHalf<ServerTlsStream>,
    mut resp_rx: mpsc::Receiver<Vec<u8>>,
    io_timeout: std::time::Duration,
) -> std::io::Result<()> {
    while let Some(response) = resp_rx.recv().await {
        tokio::time::timeout(io_timeout, write_frame_async(&mut writer, &response))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "write timed out"))??;
    }
    Ok(())
}

/// Map an internal database error to a generic client message, logging the
/// detail server-side. Avoids leaking schema/SQL internals over the wire to
/// unauthenticated TCP callers (svc-02).
fn db_error_message(e: impl std::fmt::Display) -> String {
    log::warn!("TCP dispatch database error: {}", e);
    "internal database error".to_string()
}

fn cache_claim_signer_keys(
    db_pool: &DbPool,
    claim: &liblinkkeys::generated::types::Claim,
    outbound: Option<&OutboundCtx>,
) {
    let Some(ctx) = outbound else {
        return;
    };
    let our = get_domain_name();
    let domains: BTreeSet<String> = claim
        .signatures
        .iter()
        .map(|s| s.domain.clone())
        .filter(|d| d != &our)
        .collect();
    for domain in domains {
        let keys = match ctx
            .rt
            .block_on(crate::web::rp::fetch_domain_keys(db_pool, ctx.net, &domain))
        {
            Ok(keys) => keys,
            Err(e) => {
                log::warn!("Could not fetch signer keys for {}: {}", domain, e);
                continue;
            }
        };
        for key in keys {
            let peer = crate::db::models::PeerKey {
                domain: domain.clone(),
                key_id: key.key_id,
                public_key: key.public_key,
                algorithm: key.algorithm,
                fingerprint: key.fingerprint,
                key_usage: key.key_usage,
                expires_at: key.expires_at,
                revoked_at: key.revoked_at,
            };
            if let Err(e) = db_pool.cache_peer_key(&peer) {
                log::warn!(
                    "Could not cache signer key {} for {}: {}",
                    peer.key_id,
                    domain,
                    e
                );
            }
        }
    }
}

/// A running test instance of the async connection server, bound to an
/// ephemeral loopback port. See [`spawn_for_test`].
pub struct TestServer {
    pub addr: SocketAddr,
    pub metrics: Arc<TcpMetrics>,
    _task: tokio::task::JoinHandle<()>,
}

/// Raise the kernel accept queue beyond the 128 that `std::net::TcpListener`
/// hardcodes.
///
/// Linux lets `listen(2)` be called again on an already-listening socket to
/// change the backlog, which is the only way to set it from safe std code.
/// This matters at the connection counts this server targets: a burst that
/// arrives faster than the accept loop drains it is refused at the kernel,
/// and no amount of `net.core.somaxconn` tuning helps while the process
/// itself asks for 128.
///
/// Best effort. The kernel clamps the value to `net.core.somaxconn`, and a
/// failure here leaves the default backlog in place rather than stopping the
/// server from starting — a smaller queue is a performance limit, not a
/// correctness one.
#[cfg(unix)]
fn set_listen_backlog(listener: &std::net::TcpListener, backlog: i32) {
    use std::os::fd::AsRawFd;
    // Safety: `listener` owns a valid listening socket for the duration of
    // this call, and `listen` on an existing listening socket only updates
    // the queue depth.
    let result = unsafe { libc::listen(listener.as_raw_fd(), backlog) };
    if result != 0 {
        log::warn!(
            "could not raise the TCP listen backlog to {backlog}: {}; keeping the default",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(not(unix))]
fn set_listen_backlog(_listener: &std::net::TcpListener, _backlog: i32) {}

/// Test/diagnostic harness entry point: run the REAL async listener/accept/
/// handshake/message-loop code (`TcpServer::run`) against an already-built
/// rustls `ServerConfig`, bound to an ephemeral loopback port — bypassing
/// only `TcpServer::new`'s domain-key/`DOMAIN_KEY_PASSPHRASE`-backed startup
/// (`build_tls_config`), which connection-layer tests (handshake timeout,
/// frame limits, backpressure, load shedding, persistent reuse) have no need
/// of. Mirrors [`dispatch_for_test`] for the connection layer: a network-
/// bypass-free seam that still exercises the real code path end to end.
///
/// The returned server keeps running until every `TestServer` handle
/// (including any additional `Arc`s created via `metrics()`) is dropped and
/// the process ends — matching production's fire-and-forget lifetime — but
/// since the accept task holds the listener, dropping the returned
/// `TestServer` (which drops its `JoinHandle`, aborting nothing on its own —
/// `JoinHandle::drop` merely detaches, so the accept task keeps running for
/// the rest of the test process) is enough for a short-lived test process.
pub async fn spawn_for_test(
    tls_config: Arc<rustls::ServerConfig>,
    db_pool: DbPool,
    config: TcpServerConfig,
) -> std::io::Result<TestServer> {
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    set_listen_backlog(&std_listener, config.listen_backlog);
    std_listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(std_listener)?;
    let addr = listener.local_addr()?;

    let config = Arc::new(config);
    let metrics = Arc::new(TcpMetrics::new());
    let handshake_limiter = Arc::new(PublicReadLimiter::new(config.handshake_limiter.clone()));
    let handshake_semaphore = Arc::new(tokio::sync::Semaphore::new(config.handshake_concurrency));
    let ui_configuration = crate::services::ui::load()
        .expect("default UI configuration loads with no UI_CONFIG_FILE/UI_DIST_DIR set");

    let server = TcpServer {
        listener,
        ready_flag: Arc::new(AtomicBool::new(true)),
        db_pool,
        tls_acceptor: TlsAcceptor::from(tls_config),
        net: crate::net::Net::production(),
        config,
        metrics: metrics.clone(),
        handshake_limiter,
        handshake_semaphore,
        active_connections: Arc::new(AtomicUsize::new(0)),
        ui_configuration,
    };
    let task = tokio::spawn(server.run());

    Ok(TestServer {
        addr,
        metrics,
        _task: task,
    })
}

/// Test/diagnostic harness entry point: run the TCP service dispatch directly,
/// bypassing the socket, TLS, and framing entirely. `client_domain` is the
/// mTLS-proven caller domain the real server would have extracted from the
/// client certificate (`None` = unauthenticated peer). Returns the response
/// envelope's `(status, payload)` — status 0 is success. This is the
/// network-bypass seam for TCP end-to-end tests.
pub fn dispatch_for_test(
    service: &str,
    op: &str,
    payload: Vec<u8>,
    db_pool: &DbPool,
    client_domain: Option<&str>,
) -> (i32, Vec<u8>) {
    dispatch_for_test_authed(service, op, payload, None, db_pool, client_domain)
}

/// Like [`dispatch_for_test`] but carries an `auth` API key in the envelope, for
/// exercising the authenticated services (Admin/Account/Rp) through the dispatch.
/// Like the plain helper it provides no outbound context, so `Rp` ops that make
/// an onward server-to-server call return "unavailable on this carrier".
pub fn dispatch_for_test_authed(
    service: &str,
    op: &str,
    payload: Vec<u8>,
    auth: Option<&str>,
    db_pool: &DbPool,
    client_domain: Option<&str>,
) -> (i32, Vec<u8>) {
    let mut request = RpcRequest::new(service, op, payload);
    if let Some(a) = auth {
        request = request.with_auth(a);
    }
    let ready = Arc::new(AtomicBool::new(true));
    let bytes = dispatch(
        &request,
        &ready,
        db_pool,
        DispatchContext {
            client_domain,
            recovery_source_key: "test-peer",
            outbound: None,
            browser_user: None,
            ui_configuration: None,
        },
    );
    let resp = RpcResponse::decode(&bytes).expect("response decodes");
    (resp.status.code() as i32, resp.payload)
}

/// Decode a CSIL-RPC request envelope and dispatch it, returning the response
/// envelope bytes. This is the single entry the generic CBOR-RPC carrier (the
/// web `POST /csil/v1/rpc`) shares with the TCP server, so the web carries the
/// same RPC surface without per-op routes. `client_domain` is the mTLS-proven
/// peer over TCP, `None` over the web.
pub fn dispatch_envelope(
    envelope_bytes: &[u8],
    ready_flag: &Arc<AtomicBool>,
    db_pool: &DbPool,
    client_domain: Option<&str>,
) -> Vec<u8> {
    let request = match RpcRequest::decode(envelope_bytes) {
        Ok(r) => r,
        Err(e) => return error_response(1, &format!("Invalid envelope: {}", e)),
    };
    // The web carrier runs inside tokio and cannot `block_on`, so it provides no
    // outbound context; the `Rp` helper ops (which need it) have dedicated HTTP
    // routes and are not served over `/csil/v1/rpc`.
    dispatch(
        &request,
        ready_flag,
        db_pool,
        DispatchContext {
            client_domain,
            recovery_source_key: "http-peer",
            outbound: None,
            browser_user: None,
            ui_configuration: None,
        },
    )
}

/// Dispatch an HTTP CSIL request with an optional browser-session identity.
pub fn dispatch_envelope_with_browser(
    envelope_bytes: &[u8],
    ready_flag: &Arc<AtomicBool>,
    db_pool: &DbPool,
    browser_user: Option<&crate::db::models::User>,
    recovery_source_key: &str,
) -> Vec<u8> {
    let request = match RpcRequest::decode(envelope_bytes) {
        Ok(request) => request,
        Err(error) => return error_response(1, &format!("Invalid envelope: {error}")),
    };
    dispatch(
        &request,
        ready_flag,
        db_pool,
        DispatchContext {
            client_domain: None,
            recovery_source_key,
            outbound: None,
            browser_user,
            ui_configuration: None,
        },
    )
}

fn dispatch(
    envelope: &RpcRequest,
    ready_flag: &Arc<AtomicBool>,
    db_pool: &DbPool,
    context: DispatchContext<'_>,
) -> Vec<u8> {
    let DispatchContext {
        client_domain,
        recovery_source_key,
        outbound,
        browser_user,
        ui_configuration,
    } = context;
    match (envelope.service.as_str(), envelope.op.as_str()) {
        ("Ops", "healthcheck") => ok_response(cbor_response(&CheckResultResponse { result: true })),
        ("Ops", "readiness") => ok_response(cbor_response(&CheckResultResponse {
            result: ready_flag.load(Ordering::SeqCst),
        })),
        ("Hello", "hello") => {
            let request: HelloRequest = match ciborium::de::from_reader(&envelope.payload[..]) {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            let handler = HelloHandler;
            ok_response(cbor_response(&HelloResponse {
                greeting: handler.hello(request.name),
            }))
        }
        ("Handshake", "handshake") => {
            use liblinkkeys::generated::services::Handshake;
            let request = match liblinkkeys::generated::decode_handshake_request(&envelope.payload)
            {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            match HandshakeHandler.handshake(&(), request) {
                Ok(resp) => ok_response(liblinkkeys::generated::encode_handshake_response(&resp)),
                Err(error) => error_response(4, &error.message),
            }
        }
        // Both domain-key reads are anonymous, so they draw on the same
        // public-read budget as the application-key reads: an unbounded
        // anonymous surface is a denial-of-service surface whatever it serves.
        //
        // The response is served from an encoded snapshot. Domain key changes
        // are rare, so one immutable snapshot answers almost every call
        // without a database round trip or a re-encode. It is invalidated on
        // a domain-key write and additionally carries a short time limit,
        // which covers both a missed invalidation and the
        // `recent_revocations_available` flag going stale simply because time
        // passed.
        ("DomainKeys", "get-domain-keys") => {
            if let Err(response) = public_read_gate(recovery_source_key) {
                return response;
            }
            let loaded = crate::services::pubkey_cache::DOMAIN_SNAPSHOT_CACHE.get_or_load(
                &crate::services::pubkey_cache::CacheKey::DomainKeys,
                || {
                    let keys = db_pool.list_active_domain_keys().map_err(|e| {
                        crate::services::pubkey_cache::CacheError::Load(db_error_message(e))
                    })?;
                    Ok(Some(
                        liblinkkeys::generated::encode_get_domain_keys_response(
                            &GetDomainKeysResponse {
                                domain: get_domain_name(),
                                keys: keys.iter().map(Into::into).collect(),
                                recent_revocations_available: Some(
                                    crate::services::revocations::recent_revocations_available(
                                        db_pool,
                                    ),
                                ),
                            },
                        ),
                    ))
                },
            );
            match loaded {
                Ok(Some(bytes)) => ok_response(bytes.as_ref().clone()),
                Ok(None) => error_response(4, "internal database error"),
                Err(e) => error_response(4, &e.to_string()),
            }
        }
        ("DomainKeys", "get-revocations") => {
            if let Err(response) = public_read_gate(recovery_source_key) {
                return response;
            }
            let request =
                match liblinkkeys::generated::decode_get_revocations_request(&envelope.payload) {
                    Ok(r) => r,
                    Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
                };
            // Only the default (unbounded `since`) read is snapshot-cached.
            // A caller-supplied `since` makes the response caller-specific,
            // and caching one entry per distinct `since` would let an
            // anonymous caller fill the cache with values of its own choosing.
            if request.since.is_some() {
                let revocations =
                    crate::services::revocations::serve(db_pool, request.since.as_deref());
                return ok_response(liblinkkeys::generated::encode_get_revocations_response(
                    &liblinkkeys::generated::types::GetRevocationsResponse { revocations },
                ));
            }
            let loaded = crate::services::pubkey_cache::DOMAIN_SNAPSHOT_CACHE.get_or_load(
                &crate::services::pubkey_cache::CacheKey::Revocations,
                || {
                    let revocations = crate::services::revocations::serve(db_pool, None);
                    Ok(Some(
                        liblinkkeys::generated::encode_get_revocations_response(
                            &liblinkkeys::generated::types::GetRevocationsResponse { revocations },
                        ),
                    ))
                },
            );
            match loaded {
                Ok(Some(bytes)) => ok_response(bytes.as_ref().clone()),
                Ok(None) => error_response(4, "internal database error"),
                Err(e) => error_response(4, &e.to_string()),
            }
        }
        // Unauthenticated, like DomainKeys/Ops: any CSIL-RPC client (browser
        // POST /csil/v1/rpc or native TCP) fetches the UI catalog before or
        // without authenticating. `get-translations` merges this domain's
        // per-locale claim-type labels (crate::db, Part C) into the pure
        // liblinkkeys::i18n catalog, so one call returns both UI chrome and
        // claim labels for the negotiated locale.
        ("I18n", "get-translations") => {
            let request =
                match liblinkkeys::generated::decode_translations_request(&envelope.payload) {
                    Ok(r) => r,
                    Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
                };
            let locale = liblinkkeys::i18n::negotiate(
                request.accept_language.as_deref().unwrap_or(""),
                request.locale.as_deref(),
            );
            let mut messages = liblinkkeys::i18n::catalog_for(&locale);
            if let Ok(policies) = db_pool.list_claim_policies() {
                for policy in &policies {
                    if let Ok((label, description)) =
                        db_pool.resolved_label(&policy.claim_type, &locale)
                    {
                        messages.insert(format!("claim.{}.label", policy.claim_type), label);
                        if !description.is_empty() {
                            messages.insert(
                                format!("claim.{}.description", policy.claim_type),
                                description,
                            );
                        }
                    }
                }
            }
            ok_response(liblinkkeys::generated::encode_translations_response(
                &liblinkkeys::generated::types::TranslationsResponse {
                    locale,
                    available_locales: liblinkkeys::i18n::available_locales(),
                    messages: messages.into_iter().collect(),
                },
            ))
        }
        ("I18n", "list-locales") => {
            ok_response(liblinkkeys::generated::encode_list_locales_response(
                &liblinkkeys::generated::types::ListLocalesResponse {
                    available_locales: liblinkkeys::i18n::available_locales(),
                },
            ))
        }
        ("Ui", "get-configuration") => match ui_configuration
            .map(crate::services::ui::public_configuration)
            .map(Ok)
            .unwrap_or_else(crate::services::ui::configuration)
        {
            Ok(response) => {
                ok_response(liblinkkeys::generated::encode_get_ui_configuration_response(&response))
            }
            Err(error) => service_error_response(error),
        },
        ("Notification", "get-capabilities") => ok_response(
            liblinkkeys::generated::encode_get_notification_capabilities_response(
                &crate::services::notification::capabilities(),
            ),
        ),
        ("Recovery", "request-password-recovery") => {
            let request = match liblinkkeys::generated::decode_request_password_recovery_request(
                &envelope.payload,
            ) {
                Ok(value) => value,
                Err(error) => return error_response(2, &format!("Invalid payload: {error}")),
            };
            match crate::services::recovery::request(
                db_pool,
                &request.identifier,
                recovery_source_key,
            ) {
                Ok(response) => ok_response(
                    liblinkkeys::generated::encode_request_password_recovery_response(&response),
                ),
                Err(error) => service_error_response(error),
            }
        }
        ("Recovery", "validate-password-recovery") => {
            if !crate::services::ratelimit::RECOVERY_TOKEN_SOURCE.check(recovery_source_key) {
                return error_response(5, "Too many recovery attempts. Wait and try again");
            }
            let request = match liblinkkeys::generated::decode_validate_password_recovery_request(
                &envelope.payload,
            ) {
                Ok(value) => value,
                Err(error) => return error_response(2, &format!("Invalid payload: {error}")),
            };
            match crate::services::recovery::validate(db_pool, &request.token) {
                Ok(response) => ok_response(
                    liblinkkeys::generated::encode_validate_password_recovery_response(&response),
                ),
                Err(error) => service_error_response(error),
            }
        }
        ("Recovery", "complete-password-recovery") => {
            if !crate::services::ratelimit::RECOVERY_TOKEN_SOURCE.check(recovery_source_key) {
                return error_response(5, "Too many recovery attempts. Wait and try again");
            }
            let request = match liblinkkeys::generated::decode_complete_password_recovery_request(
                &envelope.payload,
            ) {
                Ok(value) => value,
                Err(error) => return error_response(2, &format!("Invalid payload: {error}")),
            };
            match crate::services::recovery::complete(
                db_pool,
                &request.token,
                &request.new_password,
            ) {
                Ok(response) => ok_response(
                    liblinkkeys::generated::encode_complete_password_recovery_response(&response),
                ),
                Err(error) => service_error_response(error),
            }
        }
        ("Session", "introspect") => {
            let caller = match authenticate_tcp_request(&envelope.auth, db_pool) {
                Ok(value) => value,
                Err(response) => return response,
            };
            if !crate::services::authorization::user_has_permission(
                db_pool,
                &caller.id,
                "ui_extension",
                "domain",
                &get_domain_name(),
            ) {
                return error_response(5, "Forbidden");
            }
            let request = match liblinkkeys::generated::decode_introspect_browser_session_request(
                &envelope.payload,
            ) {
                Ok(value) => value,
                Err(error) => return error_response(2, &format!("Invalid payload: {error}")),
            };
            match crate::services::browser_session::get(db_pool, &request.session_cookie, false) {
                Ok(Some(session)) => ok_response(
                    liblinkkeys::generated::encode_introspect_browser_session_response(
                        &crate::services::browser_session::introspection(&session),
                    ),
                ),
                Ok(None) => error_response(5, "Invalid browser session"),
                Err(error) => service_error_response(error),
            }
        }
        ("UserKeys", "get-user-keys") => {
            let request =
                match liblinkkeys::generated::decode_get_user_keys_request(&envelope.payload) {
                    Ok(r) => r,
                    Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
                };
            match db_pool.list_active_user_keys(&request.user_id) {
                Ok(keys) => ok_response(liblinkkeys::generated::encode_get_user_keys_response(
                    &GetUserKeysResponse {
                        user_id: request.user_id,
                        domain: get_domain_name(),
                        keys: keys.iter().map(Into::into).collect(),
                    },
                )),
                Err(e) => error_response(4, &db_error_message(e)),
            }
        }
        ("Identity", "get-user-info") => {
            let request =
                match liblinkkeys::generated::decode_get_user_info_request(&envelope.payload) {
                    Ok(r) => r,
                    Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
                };
            let token_str = match String::from_utf8(request.token) {
                Ok(s) => s,
                Err(_) => return error_response(2, "Invalid token encoding"),
            };
            let signed = match liblinkkeys::encoding::assertion_from_url_param(&token_str) {
                Ok(s) => s,
                Err(_) => return error_response(2, "Invalid token format"),
            };
            let domain_keys = match db_pool.list_active_domain_keys() {
                Ok(keys) => keys,
                Err(e) => return error_response(4, &db_error_message(e)),
            };
            let csil_keys: Vec<DomainPublicKey> = domain_keys.iter().map(Into::into).collect();
            let assertion = match liblinkkeys::assertions::verify_assertion(&signed, &csil_keys) {
                Ok(a) => a,
                Err(_) => return error_response(5, "Token verification failed"),
            };
            // Audience binding (crypto-06/tcp-02/tcp-03): the assertion may only
            // be redeemed by the relying party it was issued for. On TCP, the
            // caller's identity is the FP-pinned mTLS client cert domain proven
            // during the handshake; require it to equal the assertion audience.
            // No verified client cert => no proven caller => refuse.
            match client_domain {
                Some(domain) if domain == assertion.audience => {}
                _ => return error_response(5, "Caller is not the assertion audience"),
            }
            // Single-use redemption (parity with the web /userinfo path): an
            // assertion may be exchanged for user info at most once within its
            // TTL, so a leaked/observed token cannot be replayed. Namespaced
            // "userinfo:" to match the web burn and stay independent of login.
            match db_pool.record_nonce(
                &format!("userinfo:{}", assertion.nonce),
                std::time::Duration::from_secs(300),
            ) {
                Ok(true) => {}
                Ok(false) => return error_response(5, "Token already redeemed"),
                Err(e) => return error_response(4, &db_error_message(e)),
            }
            let user = match db_pool.find_user_by_id(&assertion.user_id) {
                Ok(u) => u,
                Err(_) => return error_response(4, "User not found"),
            };
            let claims = match db_pool.list_active_claims(&assertion.user_id) {
                Ok(c) => c,
                Err(e) => return error_response(4, &db_error_message(e)),
            };
            // Scope to exactly the claim types the user consented to for this
            // audience, recorded in the assertion. Parity with the web
            // /userinfo path; fail-closed (empty authorized_claims => nothing).
            let all_claims: Vec<liblinkkeys::generated::types::Claim> =
                claims.iter().map(Into::into).collect();
            let scoped =
                liblinkkeys::consent::scope_claims(&all_claims, &assertion.authorized_claims);
            ok_response(liblinkkeys::generated::encode_user_info(&UserInfo {
                user_id: user.id,
                domain: get_domain_name(),
                display_name: user.display_name,
                claims: scoped,
            }))
        }
        // DNS-less local RP claim-ticket redemption (dns-less-local-rp-design.md,
        // Application keys. No operation here takes an API key.
        //
        // get-application-keys and start-key-challenge are public: the first
        // returns only public material, the second returns a nonce that is
        // useless without the matching private key. add-key,
        // renew-attestation, and revoke-key are authenticated at the
        // APPLICATION layer by the application's own signatures over a
        // canonical payload — the same shape LocalRp/redeem-claim-ticket
        // already uses — because the authority for those operations is the
        // application key quorum, not a transport credential. Initial
        // enrollment is the exception and lives on Account, where the account
        // owner has already authenticated.
        //
        // Every one of these is anonymous at the transport layer, so all of
        // them pass the public-read limiter first: an anonymous surface with
        // no bound is a denial-of-service surface.
        ("ApplicationKeys", op) => {
            if let Err(response) = public_read_gate(recovery_source_key) {
                return response;
            }
            dispatch_application_keys(op, &envelope.payload, db_pool)
        }
        // Phase 5). Unauthenticated at the transport layer like DomainKeys/Ops
        // and Attestation/deposit-claim — authentication is the application-
        // layer possession proof: the request is signed with the local RP's
        // own Ed25519 signing key, verified against the STORED key for the
        // claimed fingerprint (never a key supplied in the request).
        ("LocalRp", "redeem-claim-ticket") => {
            dispatch_local_rp_redeem_claim_ticket(&envelope.payload, db_pool)
        }
        ("Admin", op) => {
            if op == "authenticate"
                && !crate::services::ratelimit::LOGIN_SOURCE.check(recovery_source_key)
            {
                return error_response(5, "Too many attempts. Wait and try again");
            }
            let user = match authenticate_request(&envelope.auth, db_pool, browser_user) {
                Ok(u) => u,
                Err(resp) => return resp,
            };
            let domain = get_domain_name();
            if let Some(required) =
                crate::services::authorization::required_relation_for_op("Admin", op)
            {
                if !crate::services::authorization::user_has_permission(
                    db_pool, &user.id, required, "domain", &domain,
                ) {
                    return error_response(5, "Forbidden");
                }
            }
            // SEC-04: account-takeover-capable ops (reset-password, deactivate,
            // remove-credential) against a protected admin account require the
            // caller to hold full `admin`, not merely `manage_users`.
            if let Some(target) = admin_op_protected_target(op, &envelope.payload, db_pool) {
                if !crate::services::authorization::caller_may_manage_target(
                    db_pool, &user.id, &target,
                ) {
                    return error_response(5, "Forbidden: target is a protected admin account");
                }
            }
            // SEC-01: recheck-pins needs outbound DNS, so it runs on the TCP
            // carrier and is handled here (dispatch_admin has no net context).
            if op == "recheck-pins" {
                return dispatch_admin_recheck_pins(&envelope.payload, db_pool, outbound);
            }
            // approve-claim/reject-claim record which admin resolved the queue
            // entry, so they need the caller's identity — dispatch_admin's
            // generic admin_op! macro only threads (db_pool, request), so these
            // two are handled here where `user.id` is in scope.
            if op == "approve-claim" {
                return dispatch_admin_approve_claim(&envelope.payload, db_pool, &user.id);
            }
            if op == "reject-claim" {
                return dispatch_admin_reject_claim(&envelope.payload, db_pool, &user.id);
            }
            dispatch_admin(op, &envelope.payload, db_pool, &user.id)
        }
        ("Account", op) => {
            let user = match authenticate_request(&envelope.auth, db_pool, browser_user) {
                Ok(u) => u,
                Err(resp) => return resp,
            };
            dispatch_account(op, &envelope.payload, db_pool, &user)
        }
        // Relying-party helpers a browser-facing RP (e.g. the demo site) delegates
        // to its RP server over TCP. API-key authenticated. verify-assertion and
        // userinfo-fetch make an onward server-to-server call to the issuing IDP,
        // so they require the outbound context (TCP carrier only).
        ("Rp", op) => {
            let user = match authenticate_tcp_request(&envelope.auth, db_pool) {
                Ok(u) => u,
                Err(resp) => return resp,
            };
            // SEC-06: require the api_access relation, not just any valid API key.
            if let Some(required) =
                crate::services::authorization::required_relation_for_op("Rp", op)
            {
                if !crate::services::authorization::user_has_permission(
                    db_pool,
                    &user.id,
                    required,
                    "domain",
                    &get_domain_name(),
                ) {
                    return error_response(5, "Forbidden");
                }
            }
            dispatch_rp(op, &envelope.payload, db_pool, outbound)
        }
        // Server-to-server: an issuer deposits a claim it signed about one of our
        // accounts. The issuer's signature is the authority (verified against its
        // cached keys + our trusted-issuer policy), so no caller auth is required
        // beyond that — anyone may carry a valid trusted attestation to us.
        ("Attestation", "deposit-claim") => {
            let request =
                match liblinkkeys::generated::decode_deposit_claim_request(&envelope.payload) {
                    Ok(r) => r,
                    Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
                };
            let claim = request.claim;
            if db_pool.find_user_by_id(&claim.user_id).is_err() {
                return error_response(4, "Unknown subject");
            }
            cache_claim_signer_keys(db_pool, &claim, outbound);
            match crate::services::attestation::verify_and_store_attested(
                db_pool,
                &claim.user_id,
                &claim,
            ) {
                Ok(()) => ok_response(liblinkkeys::generated::encode_deposit_claim_response(
                    &DepositClaimResponse { stored: true },
                )),
                Err(e) => error_response(5, &e.message),
            }
        }
        _ => error_response(
            3,
            &format!(
                "Unknown service/operation: {}/{}",
                envelope.service, envelope.op
            ),
        ),
    }
}

/// For the account-takeover-capable Admin ops, decode the target user id from
/// the payload (resolving a credential id to its owning user for
/// remove-credential). Returns None for ops that don't manage an account, or
/// when the payload can't be decoded — the op's own handler surfaces the decode
/// error. Used only to gate SEC-04's protected-admin check.
fn admin_op_protected_target(op: &str, payload: &[u8], db_pool: &DbPool) -> Option<String> {
    use liblinkkeys::generated::codec;
    match op {
        "reset-password" => codec::decode_reset_password_request(payload)
            .ok()
            .map(|r| r.user_id),
        "deactivate-user" => codec::decode_deactivate_user_request(payload)
            .ok()
            .map(|r| r.user_id),
        "remove-credential" => {
            let req = codec::decode_remove_credential_request(payload).ok()?;
            db_pool
                .find_credential_by_id(&req.credential_id)
                .ok()
                .map(|c| c.user_id)
        }
        _ => None,
    }
}

/// SEC-01: admin-gated pin recheck. Runs on the TCP carrier because it makes
/// outbound DNS lookups. With no `domain` it rechecks every pinned domain.
fn dispatch_admin_recheck_pins(
    payload: &[u8],
    db_pool: &DbPool,
    outbound: Option<&OutboundCtx>,
) -> Vec<u8> {
    let Some(ctx) = outbound else {
        return error_response(
            6,
            "recheck-pins requires the TCP carrier (needs outbound DNS)",
        );
    };
    let request = match liblinkkeys::generated::decode_recheck_pins_request(payload) {
        Ok(r) => r,
        Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
    };
    let results = ctx.rt.block_on(async {
        match request.domain.as_deref() {
            Some(d) => vec![(
                d.to_string(),
                crate::services::pins::recheck_domain(db_pool, ctx.net, d).await,
            )],
            None => crate::services::pins::recheck_all(db_pool, ctx.net).await,
        }
    });
    let results = results
        .into_iter()
        .map(
            |(domain, r)| liblinkkeys::generated::types::PinRecheckResult {
                domain,
                outcome: match r {
                    Ok(o) => format!("{o:?}"),
                    Err(e) => format!("error: {e}"),
                },
            },
        )
        .collect();
    ok_response(liblinkkeys::generated::encode_recheck_pins_response(
        &liblinkkeys::generated::types::RecheckPinsResponse { results },
    ))
}

/// `Admin/approve-claim`: approve a queued self-asserted claim, recording
/// `caller_id` as the resolving admin. Handled outside `dispatch_admin`
/// (see the call site) because it needs the caller's identity.
fn dispatch_admin_approve_claim(payload: &[u8], db_pool: &DbPool, caller_id: &str) -> Vec<u8> {
    use liblinkkeys::generated::codec;
    let request = match codec::decode_approve_claim_request(payload) {
        Ok(r) => r,
        Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
    };
    match crate::services::admin::approve_claim_request(db_pool, request, caller_id) {
        Ok(resp) => ok_response(codec::encode_approve_claim_response(&resp)),
        Err(e) => error_response(4, &e.message),
    }
}

/// `Admin/reject-claim`: reject a queued self-asserted claim, recording
/// `caller_id` as the resolving admin. See [`dispatch_admin_approve_claim`].
fn dispatch_admin_reject_claim(payload: &[u8], db_pool: &DbPool, caller_id: &str) -> Vec<u8> {
    use liblinkkeys::generated::codec;
    let request = match codec::decode_reject_claim_request(payload) {
        Ok(r) => r,
        Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
    };
    match crate::services::admin::reject_claim_request(db_pool, request, caller_id) {
        Ok(resp) => ok_response(codec::encode_reject_claim_response(&resp)),
        Err(e) => error_response(4, &e.message),
    }
}

/// Whether a ticket-redemption request's `issued_at` is within the design's
/// bounded clock-skew tolerance of `now` (`liblinkkeys::local_rp::
/// DEFAULT_CLOCK_SKEW_SECONDS`, ±300s). `LocalRpTicketRedemptionRequest` has
/// no `expires_at` (unlike the login/callback structures) — freshness is a
/// single-sided window around `issued_at`, checked here rather than via
/// `liblinkkeys::local_rp::check_timestamps` (which expects an
/// issued/expires pair).
fn ticket_redemption_issued_at_fresh(issued_at: &str, now: chrono::DateTime<chrono::Utc>) -> bool {
    let Ok(issued) = chrono::DateTime::parse_from_rfc3339(issued_at) else {
        return false;
    };
    let issued = issued.with_timezone(&chrono::Utc);
    (now - issued).num_seconds().abs() <= liblinkkeys::local_rp::DEFAULT_CLOCK_SKEW_SECONDS
}

/// `LocalRp/redeem-claim-ticket` (dns-less-local-rp-design.md, Phase 5).
/// Order matters (Wire Precision, "Service and authorization placement" +
/// Phase 5 notes):
/// 1. decode (cheap CBOR, no crypto)
/// 2. peek at the unverified inner request only to learn which fingerprint
///    to look up
/// 3. look up the local RP row by that fingerprint; reject unless `approved`
/// 4. verify the envelope signature against the STORED signing key
///    (possession proof — never a key supplied in the request)
/// 5. rate-limit, keyed on the now-POSSESSION-PROVEN fingerprint. The debit
///    deliberately happens only after the signature verifies: the fingerprint
///    in the request is attacker-chosen, so metering before the proof would
///    let anyone who can reach the TCP port spam a *victim's* fingerprint
///    and exhaust the legitimate app's bucket — a cheap remote DoS of a
///    specific local RP. Placed here, only the actual key holder can ever
///    consume its own bucket. The unverified path's worst-case cost is one
///    indexed PK lookup plus one Ed25519 verify, matching the cost posture
///    of the other unauthenticated ops (get-domain-keys already does
///    unmetered DB reads).
/// 6. check `issued_at` freshness
/// 7. redeem the ticket via the Phase 4 path (hash, POSSESSION-PROVEN
///    fingerprint binding, expiry + approval re-check) — the fingerprint
///    check is what stops RP B from redeeming a ticket issued to RP A merely
///    by learning A's ticket bytes; only the RP the ticket was actually
///    issued to may ever redeem it
/// 8. reject a deactivated/purged ticket owner (Phase 4 finding: purge
///    minimizes rather than deletes the user row, so the ticket's FK never
///    cascades away on purge — this is the backstop)
/// 9. assemble the consent-frozen claim set at current values, with their
///    existing per-claim signatures, reusing the same
///    `list_active_claims` + `scope_claims` pattern `Identity/get-user-info`
///    and `Account/get-my-info` already use.
fn dispatch_local_rp_redeem_claim_ticket(payload: &[u8], db_pool: &DbPool) -> Vec<u8> {
    let signed =
        match liblinkkeys::generated::decode_signed_local_rp_ticket_redemption_request(payload) {
            Ok(s) => s,
            Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
        };

    // Cheap peek at the still-unverified inner request, only to learn which
    // fingerprint to look up. This is a plain CBOR decode, not a signature
    // check: a caller cannot gain anything by lying about the fingerprint
    // here, since the signature verified below must match the STORED key for
    // whatever fingerprint is actually looked up.
    let claimed =
        match liblinkkeys::generated::decode_local_rp_ticket_redemption_request(&signed.request) {
            Ok(r) => r,
            Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
        };

    let rp = match db_pool.find_local_rp(&claimed.fingerprint) {
        Ok(Some(rp)) => rp,
        Ok(None) => return error_response(5, "Unknown local RP"),
        Err(e) => return error_response(4, &db_error_message(e)),
    };
    if rp.status != crate::db::local_rp::STATUS_APPROVED {
        return error_response(5, "Local RP is not approved");
    }

    let request = match liblinkkeys::local_rp::verify_local_rp_ticket_redemption_request(
        &signed,
        &rp.signing_public_key,
        &rp.fingerprint,
    ) {
        Ok(r) => r,
        Err(_) => return error_response(5, "Ticket redemption signature verification failed"),
    };

    // Only a possession-proven request may consume the RP's bucket (see the
    // ordering rationale in the doc comment above).
    if !crate::services::ratelimit::TICKET_REDEMPTION.check(&rp.fingerprint) {
        return error_response(
            5,
            "Too many ticket redemption attempts. Please wait and try again.",
        );
    }

    let now = chrono::Utc::now();
    if !ticket_redemption_issued_at_fresh(&request.issued_at, now) {
        return error_response(5, "Ticket redemption request is not fresh");
    }

    // Never log the raw ticket bytes; only its hash ever leaves this scope.
    // `rp.fingerprint` is the caller's POSSESSION-PROVEN identity (the
    // signature above already verified against the STORED key for this
    // fingerprint) — passing it into `redeem_ticket` is what binds redemption
    // to the redeeming RP, not merely to whoever knows the ticket bytes.
    let ticket_hash = liblinkkeys::crypto::fingerprint(&request.claim_ticket);
    let ticket =
        match crate::services::local_rp::redeem_ticket(db_pool, &ticket_hash, &rp.fingerprint, now)
        {
            Ok(t) => t,
            Err(crate::services::local_rp::TicketRedeemError::NotFound) => {
                return error_response(5, "Claim ticket not found")
            }
            // Deliberately the SAME message/status as `NotFound`: a ticket bound
            // to a different RP must not be distinguishable from a ticket that
            // doesn't exist, or the error would be a fingerprint-guessing oracle.
            Err(crate::services::local_rp::TicketRedeemError::FingerprintMismatch) => {
                return error_response(5, "Claim ticket not found")
            }
            Err(crate::services::local_rp::TicketRedeemError::Expired) => {
                return error_response(5, "Claim ticket has expired")
            }
            Err(crate::services::local_rp::TicketRedeemError::RpNotApproved(_)) => {
                return error_response(5, "Local RP is not approved")
            }
            Err(crate::services::local_rp::TicketRedeemError::Db(e)) => {
                return error_response(4, &db_error_message(e))
            }
        };

    let user = match db_pool.find_user_by_id(&ticket.user_id) {
        Ok(u) => u,
        Err(_) => return error_response(4, "User not found"),
    };
    if !user.is_active || user.purged_at.is_some() {
        return error_response(5, "User is deactivated or purged");
    }

    let claims = match db_pool.list_active_claims(&ticket.user_id) {
        Ok(c) => c,
        Err(e) => return error_response(4, &db_error_message(e)),
    };
    let all_claims: Vec<liblinkkeys::generated::types::Claim> =
        claims.iter().map(Into::into).collect();
    let scoped = liblinkkeys::consent::scope_claims(&all_claims, &ticket.granted_claims);

    ok_response(
        liblinkkeys::generated::encode_local_rp_ticket_redemption_response(
            &liblinkkeys::generated::types::LocalRpTicketRedemptionResponse {
                user_id: ticket.user_id,
                user_domain: ticket.user_domain,
                claims: scoped,
                ticket_expires_at: ticket.expires_at,
            },
        ),
    )
}

fn dispatch_admin(op: &str, payload: &[u8], db_pool: &DbPool, caller_id: &str) -> Vec<u8> {
    use crate::services::admin;
    use liblinkkeys::generated::codec;

    macro_rules! admin_op {
        ($decode:path, $handler:expr, $encode:path) => {{
            let request = match $decode(payload) {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            match $handler(db_pool, request) {
                Ok(resp) => ok_response($encode(&resp)),
                Err(e) => error_response(4, &e.message),
            }
        }};
    }

    match op {
        "list-users" => admin_op!(
            codec::decode_list_users_request,
            admin::list_users,
            codec::encode_list_users_response
        ),
        "get-user" => admin_op!(
            codec::decode_get_user_request,
            admin::get_user,
            codec::encode_get_user_response
        ),
        "create-user" => admin_op!(
            codec::decode_create_user_request,
            admin::create_user,
            codec::encode_create_user_response
        ),
        "authenticate" => admin_op!(
            codec::decode_authenticate_request,
            admin::authenticate,
            codec::encode_authenticate_response
        ),
        "update-user" => admin_op!(
            codec::decode_update_user_request,
            admin::update_user,
            codec::encode_update_user_response
        ),
        "deactivate-user" => {
            let request = match codec::decode_deactivate_user_request(payload) {
                Ok(value) => value,
                Err(error) => return error_response(2, &format!("Invalid payload: {error}")),
            };
            match admin::deactivate_user_as(db_pool, caller_id, request) {
                Ok(response) => ok_response(codec::encode_deactivate_user_response(&response)),
                Err(error) => error_response(4, &error.message),
            }
        }
        "activate-user" => admin_op!(
            codec::decode_activate_user_request,
            admin::activate_user_request,
            codec::encode_activate_user_response
        ),
        // Admin-ops slice 4 (CLI/web-only surfaces exposed over CSIL-RPC):
        // purge-user and revoke-domain-key are destructive/terminal, so both
        // are explicit `required_relation_for_op` arms requiring `admin`
        // (see services/authorization.rs), not merely `manage_users`.
        "purge-user" => admin_op!(
            codec::decode_purge_user_request,
            admin::purge_user,
            codec::encode_purge_user_response
        ),
        "revoke-domain-key" => admin_op!(
            codec::decode_revoke_domain_key_request,
            admin::revoke_domain_key,
            codec::encode_revoke_domain_key_response
        ),
        "reset-password" => admin_op!(
            codec::decode_reset_password_request,
            admin::reset_password,
            codec::encode_reset_password_response
        ),
        "remove-credential" => admin_op!(
            codec::decode_remove_credential_request,
            admin::remove_credential,
            codec::encode_remove_credential_response
        ),
        "set-claim" => admin_op!(
            codec::decode_set_claim_request,
            admin::set_claim,
            codec::encode_set_claim_response
        ),
        "remove-claim" => admin_op!(
            codec::decode_remove_claim_request,
            admin::remove_claim,
            codec::encode_remove_claim_response
        ),
        "list-user-claims" => admin_op!(
            codec::decode_list_user_claims_request,
            admin::list_user_claims,
            codec::encode_list_user_claims_response
        ),
        "get-user-claims" => admin_op!(
            codec::decode_admin_user_claims_request,
            admin::get_user_claims,
            codec::encode_admin_user_claims_response
        ),
        "set-user-claim" => admin_op!(
            codec::decode_set_user_claim_request,
            admin::set_user_claim,
            codec::encode_set_user_claim_response
        ),
        "list-settable-policies" => admin_op!(
            codec::decode_empty_request,
            admin::list_settable_policies,
            codec::encode_list_settable_policies_response
        ),
        "grant-relation" => admin_op!(
            codec::decode_grant_relation_request,
            admin::grant_relation,
            codec::encode_grant_relation_response
        ),
        "remove-relation" => admin_op!(
            codec::decode_remove_relation_request,
            admin::remove_relation,
            codec::encode_remove_relation_response
        ),
        "list-relations" => admin_op!(
            codec::decode_list_relations_request,
            admin::list_relations,
            codec::encode_list_relations_response
        ),
        "check-permission" => admin_op!(
            codec::decode_check_permission_request,
            admin::check_permission_handler,
            codec::encode_check_permission_response
        ),
        // DNS-less local RP admin surface (dns-less-local-rp-design.md, Phase 7).
        "list-local-rps" => admin_op!(
            codec::decode_list_local_rps_request,
            admin::list_local_rps,
            codec::encode_list_local_rps_response
        ),
        "get-local-rp" => admin_op!(
            codec::decode_get_local_rp_request,
            admin::get_local_rp,
            codec::encode_get_local_rp_response
        ),
        "approve-local-rp" => admin_op!(
            codec::decode_approve_local_rp_request,
            admin::approve_local_rp,
            codec::encode_approve_local_rp_response
        ),
        "deny-local-rp" => admin_op!(
            codec::decode_deny_local_rp_request,
            admin::deny_local_rp,
            codec::encode_deny_local_rp_response
        ),
        "revoke-local-rp" => admin_op!(
            codec::decode_revoke_local_rp_request,
            admin::revoke_local_rp,
            codec::encode_revoke_local_rp_response
        ),
        "get-local-rp-policy" => admin_op!(
            codec::decode_get_local_rp_policy_request,
            admin::get_local_rp_policy,
            codec::encode_get_local_rp_policy_response
        ),
        "set-local-rp-policy" => admin_op!(
            codec::decode_set_local_rp_policy_request,
            admin::set_local_rp_policy,
            codec::encode_set_local_rp_policy_response
        ),
        "purge-local-rp-tickets" => admin_op!(
            codec::decode_purge_local_rp_tickets_request,
            admin::purge_local_rp_tickets,
            codec::encode_purge_local_rp_tickets_response
        ),
        // Claim-type registry admin (policy-admin web UI parity): second
        // entry point onto the exact same DB calls
        // `web/policy_admin_ui.rs`'s handlers make.
        "list-claim-types" => admin_op!(
            codec::decode_empty_request,
            admin::list_claim_types,
            codec::encode_list_claim_types_response
        ),
        "set-claim-type" => admin_op!(
            codec::decode_set_claim_type_request,
            admin::set_claim_type,
            codec::encode_set_claim_type_response
        ),
        "remove-claim-type" => admin_op!(
            codec::decode_remove_claim_type_request,
            admin::remove_claim_type,
            codec::encode_remove_claim_type_response
        ),
        "set-claim-type-label" => admin_op!(
            codec::decode_set_claim_type_label_request,
            admin::set_claim_type_label,
            codec::encode_set_claim_type_label_response
        ),
        "remove-claim-type-label" => admin_op!(
            codec::decode_remove_claim_type_label_request,
            admin::remove_claim_type_label,
            codec::encode_remove_claim_type_label_response
        ),
        // Trusted-issuer and release-default admin (policy-admin web UI
        // parity, slice 2): second entry point onto the exact same DB calls
        // `web/policy_admin_ui.rs`'s handlers make.
        "list-trusted-issuers" => admin_op!(
            codec::decode_empty_request,
            admin::list_trusted_issuers,
            codec::encode_list_trusted_issuers_response
        ),
        "add-trusted-issuer" => admin_op!(
            codec::decode_add_trusted_issuer_request,
            admin::add_trusted_issuer,
            codec::encode_add_trusted_issuer_response
        ),
        "remove-trusted-issuer" => admin_op!(
            codec::decode_remove_trusted_issuer_request,
            admin::remove_trusted_issuer,
            codec::encode_remove_trusted_issuer_response
        ),
        "list-release-rules" => admin_op!(
            codec::decode_empty_request,
            admin::list_release_rules,
            codec::encode_list_release_rules_response
        ),
        "set-release-rule" => admin_op!(
            codec::decode_set_release_rule_request,
            admin::set_release_rule,
            codec::encode_set_release_rule_response
        ),
        "remove-release-rule" => admin_op!(
            codec::decode_remove_release_rule_request,
            admin::remove_release_rule,
            codec::encode_remove_release_rule_response
        ),
        // Claim-approval queue and admin-issued attestations (policy-admin web
        // UI parity, slice 3): third entry point onto the exact same DB/service
        // calls `web/policy_admin_ui.rs`'s handlers make (approve-claim and
        // reject-claim themselves are dispatched one level up, in `dispatch`,
        // since they need the caller's identity — see
        // `dispatch_admin_approve_claim`/`dispatch_admin_reject_claim`).
        "list-pending-claim-approvals" => admin_op!(
            codec::decode_empty_request,
            admin::list_pending_claim_approvals,
            codec::encode_list_pending_claim_approvals_response
        ),
        "admin-issue-attestation" => admin_op!(
            codec::decode_admin_issue_attestation_request,
            admin::admin_issue_attestation,
            codec::encode_admin_issue_attestation_response
        ),
        _ => error_response(3, &format!("Unknown Admin operation: {}", op)),
    }
}

fn dispatch_account(
    op: &str,
    payload: &[u8],
    db_pool: &DbPool,
    user: &crate::db::models::User,
) -> Vec<u8> {
    use crate::services::account;

    match op {
        "change-password" => {
            let request = match liblinkkeys::generated::decode_change_password_request(payload) {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            match account::change_password(db_pool, &user.id, request) {
                Ok(resp) => ok_response(liblinkkeys::generated::encode_change_password_response(
                    &resp,
                )),
                Err(error) => service_error_response(error),
            }
        }
        "get-my-info" => match account::get_my_info(db_pool, &user.id) {
            Ok(resp) => ok_response(liblinkkeys::generated::encode_get_my_info_response(&resp)),
            Err(e) => error_response(4, &e.message),
        },
        "list-settable-policies" => match crate::services::admin::list_settable_policies(
            db_pool,
            liblinkkeys::generated::types::EmptyRequest {},
        ) {
            Ok(response) => ok_response(
                liblinkkeys::generated::encode_list_settable_policies_response(&response),
            ),
            Err(error) => service_error_response(error),
        },
        "set-my-claim" => {
            let request = match liblinkkeys::generated::decode_set_my_claim_request(payload) {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            match account::set_my_claim(db_pool, &user.id, request) {
                Ok(resp) => {
                    ok_response(liblinkkeys::generated::encode_set_my_claim_response(&resp))
                }
                Err(e) => error_response(4, &e.message),
            }
        }
        "remove-my-claim" => {
            let request = match liblinkkeys::generated::decode_remove_my_claim_request(payload) {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            match account::remove_my_claim(db_pool, &user.id, request) {
                Ok(resp) => ok_response(liblinkkeys::generated::encode_remove_my_claim_response(
                    &resp,
                )),
                Err(e) => error_response(4, &e.message),
            }
        }
        "set-my-claim-sharing" => {
            let request = match liblinkkeys::generated::decode_set_my_claim_sharing_request(payload)
            {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            match account::set_my_claim_sharing(db_pool, &user.id, request) {
                Ok(resp) => {
                    ok_response(liblinkkeys::generated::encode_set_my_claim_sharing_response(&resp))
                }
                Err(e) => error_response(4, &e.message),
            }
        }
        "create-profile" => {
            let request = match liblinkkeys::generated::decode_create_profile_request(payload) {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            match account::create_profile(db_pool, &user.id, request) {
                Ok(resp) => ok_response(liblinkkeys::generated::encode_create_profile_response(
                    &resp,
                )),
                Err(e) => error_response(4, &e.message),
            }
        }
        "request-verification" => {
            let request = match liblinkkeys::generated::decode_request_verification_request(payload)
            {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            match account::request_verification(db_pool, &user.id, request) {
                Ok(resp) => {
                    ok_response(liblinkkeys::generated::encode_request_verification_response(&resp))
                }
                Err(e) => error_response(4, &e.message),
            }
        }
        "list-verified-contact-methods" => {
            match crate::services::verification::list_verified_contacts(db_pool, &user.id) {
                Ok(response) => ok_response(
                    liblinkkeys::generated::encode_list_verified_contact_methods_response(
                        &response,
                    ),
                ),
                Err(error) => service_error_response(error),
            }
        }
        "revoke-verified-contact-method" => {
            let request =
                match liblinkkeys::generated::decode_revoke_verified_contact_method_request(payload)
                {
                    Ok(value) => value,
                    Err(error) => return error_response(2, &format!("Invalid payload: {error}")),
                };
            match crate::services::verification::revoke_verified_contact(
                db_pool,
                &user.id,
                &request.contact_method_id,
                &request.current_password,
            ) {
                Ok(response) => ok_response(
                    liblinkkeys::generated::encode_revoke_verified_contact_method_response(
                        &response,
                    ),
                ),
                Err(error) => service_error_response(error),
            }
        }
        "request-contact-verification" => {
            let request = match liblinkkeys::generated::decode_request_contact_verification_request(
                payload,
            ) {
                Ok(value) => value,
                Err(error) => return error_response(2, &format!("Invalid payload: {error}")),
            };
            match crate::services::verification::request_contact_verification(
                db_pool,
                &user.id,
                &request.channel,
                &request.destination,
                &request.current_password,
            ) {
                Ok(response) => ok_response(
                    liblinkkeys::generated::encode_request_contact_verification_response(&response),
                ),
                Err(error) => service_error_response(error),
            }
        }
        "confirm-contact-verification" => {
            let request = match liblinkkeys::generated::decode_confirm_contact_verification_request(
                payload,
            ) {
                Ok(value) => value,
                Err(error) => return error_response(2, &format!("Invalid payload: {error}")),
            };
            match crate::services::verification::confirm_contact_verification(
                db_pool,
                &user.id,
                &request.token,
            ) {
                Ok(response) => ok_response(
                    liblinkkeys::generated::encode_confirm_contact_verification_response(&response),
                ),
                Err(error) => service_error_response(error),
            }
        }
        "enroll-application-instance" => {
            let request =
                match liblinkkeys::generated::decode_enroll_application_instance_request(payload) {
                    Ok(r) => r,
                    Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
                };
            // The subject is the AUTHENTICATED account, never a value from the
            // request body. Initial enrollment is the one bootstrap exception
            // to application-key quorum, so the account owner's identity is
            // the whole authority for it; taking the subject from the payload
            // would let any caller enrol keys against somebody else.
            match crate::services::application_keys::enroll_instance(
                db_pool,
                &user.id,
                request,
                chrono::Utc::now(),
            ) {
                Ok(resp) => ok_response(
                    liblinkkeys::generated::encode_enroll_application_instance_response(&resp),
                ),
                Err(error) => service_error_response(error),
            }
        }
        _ => error_response(3, &format!("Unknown Account operation: {}", op)),
    }
}

/// Map a web-layer `Status` (the Rp cores' error type) to a CSIL error response.
fn rp_status_to_error(e: crate::web::rp::CoreError) -> Vec<u8> {
    let code = match e.status.code {
        400 => 2,       // BadRequest -> invalid payload
        401 | 403 => 5, // Unauthorized / Forbidden -> auth/verification
        _ => 4,         // BadGateway / InternalServerError -> internal
    };
    // The message names the failed step (CoreError guarantees it is wire-safe),
    // so a caller can act on the failure instead of guessing at a bare status.
    error_response(code, &e.message)
}

/// Dispatch a `Rp` helper op, reusing the same core functions the web JSON routes
/// call. `sign-request` and `decrypt-token` are local; `verify-assertion` and
/// `userinfo-fetch` make an onward call to the issuing IDP and so require the
/// outbound context (present on the TCP carrier, absent on the web carrier and in
/// the test harness, where they return an error).
fn dispatch_rp(
    op: &str,
    payload: &[u8],
    db_pool: &DbPool,
    outbound: Option<&OutboundCtx>,
) -> Vec<u8> {
    use crate::web::rp;
    use liblinkkeys::generated::codec;

    match op {
        "sign-request" => {
            let req = match codec::decode_rp_sign_request(payload) {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            let cfg = crate::rp_config::RpClaimsConfig::load_from_env();
            match rp::sign_request_core(
                db_pool,
                &cfg,
                &req.callback_url,
                &req.nonce,
                req.requested_claims,
                req.authentication_requirements,
                req.flow_context,
            ) {
                Ok(resp) => ok_response(codec::encode_rp_sign_response(&resp)),
                Err(s) => rp_status_to_error(s),
            }
        }
        "decrypt-token" => {
            let req = match codec::decode_rp_decrypt_request(payload) {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            match rp::decrypt_token_core(db_pool, &req.encrypted_token) {
                Ok(resp) => ok_response(codec::encode_rp_decrypt_response(&resp)),
                Err(s) => rp_status_to_error(s),
            }
        }
        "verify-assertion" => {
            let req = match codec::decode_rp_verify_request(payload) {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            let ctx = match outbound {
                Some(c) => c,
                None => return error_response(4, "operation unavailable on this carrier"),
            };
            match ctx.rt.block_on(rp::verify_assertion_core(
                db_pool,
                ctx.net,
                &req.signed_assertion,
                &req.expected_domain,
            )) {
                Ok(resp) => ok_response(codec::encode_rp_verify_response(&resp)),
                Err(s) => rp_status_to_error(s),
            }
        }
        "userinfo-fetch" => {
            let req = match codec::decode_rp_user_info_request(payload) {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            let ctx = match outbound {
                Some(c) => c,
                None => return error_response(4, "operation unavailable on this carrier"),
            };
            match ctx.rt.block_on(rp::fetch_userinfo_core(
                db_pool,
                ctx.net,
                req.token,
                &req.api_base,
                &req.domain,
            )) {
                Ok(resp) => ok_response(codec::encode_user_info(&resp)),
                Err(s) => rp_status_to_error(s),
            }
        }
        "issue-attestation" => {
            let req = match codec::decode_rp_issue_attestation_request(payload) {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            let ctx = match outbound {
                Some(c) => c,
                None => return error_response(4, "operation unavailable on this carrier"),
            };
            match ctx.rt.block_on(rp::issue_attestation_core(
                db_pool,
                ctx.net,
                req.signed_request,
                &req.claim_type,
                &req.claim_value,
            )) {
                Ok(resp) => ok_response(codec::encode_rp_issue_attestation_response(&resp)),
                Err(s) => rp_status_to_error(s),
            }
        }
        "resolve-domain-keys" => {
            let request = match codec::decode_rp_resolve_domain_keys_request(payload) {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            // Resolving a remote domain needs an onward server-to-server call
            // on a cache miss, so it needs the outbound context the web
            // carrier does not have.
            let ctx = match outbound {
                Some(ctx) => ctx,
                None => return error_response(4, "operation unavailable on this carrier"),
            };
            match crate::services::rp_cache::resolve_domain_keys(db_pool, ctx.net, ctx.rt, request)
            {
                Ok(resp) => ok_response(codec::encode_rp_resolve_domain_keys_response(&resp)),
                Err(error) => service_error_response(error),
            }
        }
        "resolve-application-keys" => {
            let request = match codec::decode_rp_resolve_application_keys_request(payload) {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            let ctx = match outbound {
                Some(ctx) => ctx,
                None => return error_response(4, "operation unavailable on this carrier"),
            };
            match crate::services::rp_cache::resolve_application_keys(
                db_pool, ctx.net, ctx.rt, request,
            ) {
                Ok(resp) => ok_response(codec::encode_rp_resolve_application_keys_response(&resp)),
                Err(error) => service_error_response(error),
            }
        }
        _ => error_response(3, &format!("Unknown Rp operation: {}", op)),
    }
}

/// A successful CSIL-RPC reply carrying a typed payload. Our operations declare a
/// single output type (no `/ ErrorType` arms yet), so `variant` is omitted; if we
/// later add typed error arms, set it to the chosen arm's CSIL type name.
fn ok_response(payload_bytes: Vec<u8>) -> Vec<u8> {
    RpcResponse {
        id: None,
        status: Status::Ok,
        variant: None,
        error: None,
        payload: payload_bytes,
    }
    .encode()
    .expect("encode RPC response")
}

/// CBOR-encode a hand-written (non-CSIL) response struct still carrying serde.
/// The generated CSIL types use the codec instead; this is only for the small
/// local structs (`HelloResponse`, `CheckResultResponse`) served on TCP.
fn cbor_response<T: Serialize>(payload: &T) -> Vec<u8> {
    let mut payload_bytes = Vec::new();
    ciborium::ser::into_writer(payload, &mut payload_bytes)
        .expect("CBOR serialization of response payload");
    payload_bytes
}

/// Map our historical transport status ints onto the CSIL-RPC status registry and
/// build a transport-error response (no typed payload). These are *transport*
/// failures, never application errors (which would ride as a status-0 variant).
fn error_response(status: i32, message: &str) -> Vec<u8> {
    let status = match status {
        1 | 2 => Status::MalformedEnvelope,
        3 => Status::UnknownServiceOrOp,
        4 => Status::Internal,
        5 => Status::Forbidden,
        // Rate limiting answers Unavailable rather than Forbidden. Forbidden
        // tells a client its credentials are wrong and it should stop;
        // Unavailable tells it to back off and retry, which is the correct
        // action here and the one every SDK's error mapping already
        // understands. The retry delay travels in the message.
        6 => Status::Unavailable,
        other => Status::Other(other as i64),
    };
    RpcResponse::transport_error(status, message)
        .encode()
        .expect("encode RPC error response")
}

/// Bound the anonymous public-key surface before it does any work.
///
/// The limiter is keyed on the DIRECT socket peer address only. It is never
/// keyed on a subject UUID, application id, or instance id taken from the
/// request: an attacker who supplied a victim's value would drain the victim's
/// bucket instead of its own.
fn public_read_gate(source_key: &str) -> Result<(), Vec<u8>> {
    use crate::services::public_ratelimit::{PublicReadDecision, PUBLIC_READS};
    match PUBLIC_READS.check(&crate::services::public_ratelimit::source_key_from_str(
        source_key,
    )) {
        PublicReadDecision::Allow => Ok(()),
        PublicReadDecision::Limited {
            retry_after_seconds,
            ..
        } => Err(error_response(
            6,
            &format!("Rate limited. Try again in {retry_after_seconds} seconds"),
        )),
    }
}

fn dispatch_application_keys(op: &str, payload: &[u8], db_pool: &DbPool) -> Vec<u8> {
    use liblinkkeys::generated::codec;
    let now = chrono::Utc::now();
    macro_rules! app_key_op {
        ($decode:path, $handler:expr, $encode:path) => {{
            let request = match $decode(payload) {
                Ok(request) => request,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            match $handler(db_pool, request, now) {
                Ok(response) => ok_response($encode(&response)),
                Err(e) => service_error_response(e),
            }
        }};
    }
    match op {
        // Served from the encoded-response cache: a hit repeats neither the
        // database read nor the CBOR encoding, and concurrent misses for one
        // instance are coalesced into a single query.
        "get-application-keys" => {
            let request = match codec::decode_get_application_keys_request(payload) {
                Ok(request) => request,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            match crate::services::application_keys::get_application_keys_encoded(
                db_pool, request, now,
            ) {
                Ok(bytes) => ok_response(bytes.as_ref().clone()),
                Err(e) => service_error_response(e),
            }
        }
        "start-key-challenge" => app_key_op!(
            codec::decode_start_application_key_challenge_request,
            crate::services::application_keys::start_challenge,
            codec::encode_start_application_key_challenge_response
        ),
        "add-key" => app_key_op!(
            codec::decode_add_application_key_request,
            crate::services::application_keys::add_key,
            codec::encode_add_application_key_response
        ),
        "renew-attestation" => app_key_op!(
            codec::decode_renew_application_key_attestation_request,
            crate::services::application_keys::renew_attestation,
            codec::encode_renew_application_key_attestation_response
        ),
        "revoke-key" => app_key_op!(
            codec::decode_revoke_application_key_request,
            crate::services::application_keys::revoke_key,
            codec::encode_revoke_application_key_response
        ),
        _ => error_response(3, &format!("Unknown ApplicationKeys operation: {}", op)),
    }
}

fn service_error_response(error: liblinkkeys::generated::services::ServiceError) -> Vec<u8> {
    let status = if matches!(error.code, 401 | 403) {
        5
    } else if error.code == 429 {
        // Back off and retry, not "your credentials are wrong".
        6
    } else if error.code >= 500 {
        4
    } else {
        2
    };
    error_response(status, &error.message)
}

fn authenticate_request(
    auth: &Option<String>,
    db_pool: &DbPool,
    browser_user: Option<&crate::db::models::User>,
) -> Result<crate::db::models::User, Vec<u8>> {
    if auth.is_some() {
        return authenticate_tcp_request(auth, db_pool);
    }
    browser_user
        .filter(|user| user.is_active && user.purged_at.is_none())
        .cloned()
        .ok_or_else(|| error_response(5, "Authentication required"))
}

/// Authenticate a TCP request using the auth field from the envelope.
/// Returns the authenticated user or an error response ready to send.
fn authenticate_tcp_request(
    auth: &Option<String>,
    db_pool: &DbPool,
) -> Result<crate::db::models::User, Vec<u8>> {
    let api_key = match auth {
        Some(key) => key,
        None => return Err(error_response(5, "Authentication required")),
    };

    let authenticator = crate::services::auth::ApiKeyAuthenticator::new(db_pool.clone());
    match authenticator.authenticate_key(api_key) {
        Ok(user) => {
            if !user.is_active {
                return Err(error_response(5, "Account deactivated"));
            }
            Ok(user)
        }
        Err(_) => Err(error_response(5, "Invalid credentials")),
    }
}

#[cfg(test)]
mod depth_tests {
    use super::check_cbor_depth;

    #[test]
    fn test_simple_cbor_passes() {
        // A simple CBOR map with string keys — typical request envelope
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&serde_json::json!({"hello": "world"}), &mut buf).unwrap();
        assert!(check_cbor_depth(&buf));
    }

    #[test]
    fn test_deeply_nested_array_rejected() {
        // Build CBOR with 100 nested arrays: each is major type 4, additional 1 (one-element array)
        let mut data = vec![0x81; 100];
        data.push(0x00); // integer 0 at the bottom
        assert!(!check_cbor_depth(&data));
    }

    #[test]
    fn test_moderate_nesting_passes() {
        // 10 levels of nesting — well under the limit
        let mut data = vec![0x81; 10];
        data.push(0x00);
        assert!(check_cbor_depth(&data));
    }

    #[test]
    fn test_empty_input_passes() {
        assert!(check_cbor_depth(&[]));
    }

    /// A nine-byte payload that DECLARES 2^40 array elements must be refused
    /// before it reaches the generated decoder.
    ///
    /// The generated decoder pre-allocates from the declared count, so without
    /// this guard that payload makes the process attempt a 35 TB allocation
    /// and abort — a remote denial of service from an anonymous caller, on
    /// every public operation. Every reachable declared-length shape is
    /// covered here: array, map, byte string, and text string.
    #[test]
    fn a_declared_length_larger_than_the_input_is_refused() {
        // Array header, additional info 27 (eight-byte count), 2^40 items.
        let huge_array = [0x9b, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(!check_cbor_depth(&huge_array));

        // Map header with the same absurd count.
        let huge_map = [0xbb, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(!check_cbor_depth(&huge_map));

        // Byte string and text string with a length near usize::MAX, which
        // would wrap an unchecked `i + len` bounds test into a pass.
        let huge_bytes = [0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert!(!check_cbor_depth(&huge_bytes));
        let huge_text = [0x7b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert!(!check_cbor_depth(&huge_text));

        // A count that is merely larger than what remains is equally
        // unsatisfiable, and must be refused just the same.
        let slightly_too_big = [0x83, 0x01, 0x02];
        assert!(!check_cbor_depth(&slightly_too_big));

        // The honest version of the same shape still passes.
        let honest = [0x83, 0x01, 0x02, 0x03];
        assert!(check_cbor_depth(&honest));
    }

    #[test]
    fn test_deeply_nested_maps_rejected() {
        // 100 nested maps: each is major type 5, additional 1 (one-entry map).
        // Must exceed MAX_CBOR_DEPTH (64) to be rejected — see the array test.
        let mut data = Vec::new();
        for _ in 0..100 {
            data.push(0xa1); // map of 1 entry
            data.push(0x61); // text string of length 1
            data.push(b'k'); // key "k"
        }
        data.push(0x00); // value 0
        assert!(!check_cbor_depth(&data));
    }
}
