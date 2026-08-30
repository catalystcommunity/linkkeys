//! Client-side load generators. Each subcommand connects to a `server`
//! subcommand process (found via `--info-file`) over the real network stack —
//! no in-process shortcut — and measures one thing at a time, per
//! `docs/load-testing.md`'s "measure one thing at a time" rule:
//!
//! - `connections`: how many established, mostly-idle connections can be
//!   held open.
//! - `handshake-bench`: TLS handshake rate in isolation.
//! - `request-bench`: request/response throughput over already-established
//!   connections.
//! - `ddos`: the distinct-source protection controls, via many simulated
//!   sources bound to distinct `127.x.x.x` loopback addresses (the entire
//!   `127.0.0.0/8` block routes to loopback on Linux with no interface
//!   configuration needed — verified for this harness, see
//!   docs/load-testing.md).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::Args;
use rustls::pki_types::ServerName;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::{client::TlsStream, TlsConnector};

use csilgen_transport::rpc::{RpcRequest, RpcResponse};

/// Mirrors `server::ServerInfo`'s JSON shape.
#[derive(Deserialize)]
struct ServerInfo {
    port: u16,
    domain: String,
    fingerprint: String,
    #[allow(dead_code)]
    pid: u32,
}

fn load_server_info(path: &PathBuf) -> Result<ServerInfo, Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "reading info file {}: {e} (is the `server` subcommand running?)",
            path.display()
        )
    })?;
    Ok(serde_json::from_str(&raw)?)
}

/// The `n`th distinct loopback address after `base`, wrapped within
/// `127.0.0.0/8`. The whole block is local on Linux with no `ip addr add`
/// needed (verified — see docs/load-testing.md), so this is how the DDoS and
/// connection-scale subcommands get many distinct simulated source addresses
/// without any host network configuration.
fn nth_loopback_addr(base: Ipv4Addr, n: u32) -> Ipv4Addr {
    let base_bits = u32::from(base);
    let bits = base_bits.wrapping_add(n) & 0x00FF_FFFF | 0x7F00_0000;
    Ipv4Addr::from(bits)
}

fn parse_base_ip(raw: &str) -> Result<Ipv4Addr, Box<dyn std::error::Error>> {
    raw.parse::<Ipv4Addr>()
        .map_err(|e| format!("invalid --client-ip-base {raw:?}: {e}").into())
}

/// Why one connection attempt failed, coarse-grained. The server's own
/// metrics (printed by the `server` subcommand) are the authoritative
/// breakdown of WHICH control rejected a connection — see this module's docs
/// and docs/load-testing.md's "what the client can and cannot see" note: a
/// connection dropped by the handshake rate limiter and a connection dropped
/// by a genuine network problem look identical from here (both surface as a
/// TLS-stage failure), because the server closes the raw socket without
/// sending any TLS bytes either way.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum FailureStage {
    Connect,
    TlsHandshake,
    Timeout,
}

impl FailureStage {
    fn label(self) -> &'static str {
        match self {
            FailureStage::Connect => "tcp_connect_error",
            FailureStage::TlsHandshake => "tls_handshake_error_or_server_reject",
            FailureStage::Timeout => "attempt_timeout",
        }
    }
}

fn build_connector(fingerprint: &str) -> Result<TlsConnector, Box<dyn std::error::Error>> {
    let config = linkkeys_rpc_client::tls::build_client_config(vec![fingerprint.to_string()])?;
    Ok(TlsConnector::from(config))
}

/// Bind an outbound socket to `client_ip:0` (OS-chosen ephemeral port) and
/// complete a TLS handshake against `server_addr`/`domain`, within
/// `attempt_timeout`.
async fn connect_and_handshake(
    server_addr: SocketAddr,
    domain: &str,
    client_ip: IpAddr,
    connector: &TlsConnector,
    attempt_timeout: Duration,
) -> Result<TlsStream<TcpStream>, FailureStage> {
    let attempt = async {
        let socket = match client_ip {
            IpAddr::V4(_) => TcpSocket::new_v4(),
            IpAddr::V6(_) => TcpSocket::new_v6(),
        }
        .map_err(|_| FailureStage::Connect)?;
        socket
            .bind(SocketAddr::new(client_ip, 0))
            .map_err(|_| FailureStage::Connect)?;
        let stream = socket
            .connect(server_addr)
            .await
            .map_err(|_| FailureStage::Connect)?;
        let _ = stream.set_nodelay(true);
        let name = ServerName::try_from(domain.to_string()).map_err(|_| FailureStage::Connect)?;
        connector
            .connect(name, stream)
            .await
            .map_err(|_| FailureStage::TlsHandshake)
    };
    match tokio::time::timeout(attempt_timeout, attempt).await {
        Ok(result) => result,
        Err(_) => Err(FailureStage::Timeout),
    }
}

fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

async fn write_frame(stream: &mut TlsStream<TcpStream>, bytes: &[u8]) -> std::io::Result<()> {
    stream.write_all(&frame(bytes)).await?;
    stream.flush().await
}

async fn read_response_frame(stream: &mut TlsStream<TcpStream>) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Encode a CSIL-RPC request envelope. `payload_json` is fed through
/// `ciborium` the same way `tests/tcp_async_connection_test.rs`'s
/// `hello_request_frame` does — `serde_json::Value` implements `Serialize`,
/// so this reaches the wire as the equivalent CBOR map.
///
/// Deliberately NOT length-framed here — `write_frame` applies the one
/// length prefix a request gets; framing here too would double-wrap it and
/// the server would reject the result as a malformed envelope with trailing
/// bytes (a bug this harness hit and fixed during development — see
/// docs/load-testing.md).
fn encode_request(service: &str, op: &str, payload_json: serde_json::Value) -> Vec<u8> {
    let mut payload = Vec::new();
    ciborium::ser::into_writer(&payload_json, &mut payload).expect("encode request payload");
    let request = RpcRequest::new(service, op, payload);
    request.encode().expect("encode RpcRequest")
}

fn hello_request() -> Vec<u8> {
    encode_request("Hello", "hello", serde_json::json!({"name": null}))
}

fn domain_keys_request() -> Vec<u8> {
    encode_request("DomainKeys", "get-domain-keys", serde_json::json!({}))
}

// ---------------------------------------------------------------------------
// connections: hold N established, mostly-idle connections
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct ConnectionsArgs {
    /// Info file written by the `server` subcommand.
    #[arg(long, default_value = "loadtest-data/loadtest-info.json")]
    pub info_file: PathBuf,
    /// Target number of established connections to open and hold.
    #[arg(long, default_value_t = 1000)]
    pub count: u32,
    /// Maximum connection attempts in flight at once. Bounds client-side
    /// resource use during the ramp; does not bound how many connections are
    /// held once established.
    #[arg(long, default_value_t = 2000)]
    pub concurrency: u32,
    /// How long to hold established connections idle before closing them.
    #[arg(long, default_value_t = 20)]
    pub hold_secs: u64,
    /// Per-attempt (connect + TLS handshake) timeout.
    #[arg(long, default_value_t = 10)]
    pub attempt_timeout_secs: u64,
    /// First loopback source address. Successive attempts round-robin
    /// through `--client-ip-count` addresses starting here, to spread
    /// connections across more than one ephemeral-port range (see
    /// docs/load-testing.md, "ephemeral ports are the real client-side
    /// limit").
    #[arg(long, default_value = "127.0.1.0")]
    pub client_ip_base: String,
    /// Number of distinct source addresses to round-robin across.
    #[arg(long, default_value_t = 32)]
    pub client_ip_count: u32,
    /// Print a progress line every this many completed attempts.
    #[arg(long, default_value_t = 5000)]
    pub progress_every: u32,
}

pub async fn run_connections(args: ConnectionsArgs) -> Result<(), Box<dyn std::error::Error>> {
    let info = load_server_info(&args.info_file)?;
    let server_addr: SocketAddr = format!("127.0.0.1:{}", info.port).parse()?;
    let connector = build_connector(&info.fingerprint)?;
    let base_ip = parse_base_ip(&args.client_ip_base)?;
    let client_ip_count = args.client_ip_count.max(1);
    let attempt_timeout = Duration::from_secs(args.attempt_timeout_secs);
    let hold = Duration::from_secs(args.hold_secs);

    println!(
        "connections: target={} concurrency={} hold_secs={} client_ips={} (base {})",
        args.count, args.concurrency, args.hold_secs, client_ip_count, args.client_ip_base
    );

    let semaphore = Arc::new(Semaphore::new(args.concurrency as usize));
    let success = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let fail_reasons: Arc<Mutex<HashMap<&'static str, u64>>> = Arc::new(Mutex::new(HashMap::new()));
    let attempted = Arc::new(AtomicU64::new(0));

    let started = Instant::now();
    let mut handles = Vec::with_capacity(args.count as usize);
    for i in 0..args.count {
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore open");
        let connector = connector.clone();
        let domain = info.domain.clone();
        let success = success.clone();
        let failed = failed.clone();
        let fail_reasons = fail_reasons.clone();
        let attempted = attempted.clone();
        let client_ip = IpAddr::V4(nth_loopback_addr(base_ip, i % client_ip_count));

        handles.push(tokio::spawn(async move {
            let result =
                connect_and_handshake(server_addr, &domain, client_ip, &connector, attempt_timeout)
                    .await;
            // Release the attempt slot as soon as the handshake resolves —
            // holding idle afterward must not throttle the connection RATE.
            drop(permit);
            let n = attempted.fetch_add(1, Ordering::Relaxed) + 1;
            if n.is_multiple_of(args.progress_every.max(1) as u64) {
                println!(
                    "  progress: attempted={n} success={} failed={}",
                    success.load(Ordering::Relaxed),
                    failed.load(Ordering::Relaxed)
                );
            }
            match result {
                Ok(mut stream) => {
                    success.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(hold).await;
                    let _ = stream.shutdown().await;
                }
                Err(stage) => {
                    failed.fetch_add(1, Ordering::Relaxed);
                    let mut reasons = fail_reasons.lock().expect("fail_reasons mutex");
                    *reasons.entry(stage.label()).or_insert(0) += 1;
                }
            }
        }));
    }
    for handle in handles {
        let _ = handle.await;
    }

    let elapsed = started.elapsed();
    let success_count = success.load(Ordering::Relaxed);
    let failed_count = failed.load(Ordering::Relaxed);
    println!(
        "connections: DONE in {:?} — requested={} established={} failed={}",
        elapsed, args.count, success_count, failed_count
    );
    if failed_count > 0 {
        println!(
            "  failure reasons: {:?}",
            fail_reasons.lock().expect("fail_reasons mutex")
        );
    }
    println!(
        "  NOTE: 'established' here means this client's own TLS handshake completed. It does \
         not by itself distinguish a connection the server's handshake rate limiter rejected \
         from one it accepted then closed for an unrelated reason — cross-reference the \
         server process's METRICS lines (shed_handshake_*, handshake_rejections) for that \
         breakdown."
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// handshake-bench: TLS handshake rate in isolation
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct HandshakeBenchArgs {
    #[arg(long, default_value = "loadtest-data/loadtest-info.json")]
    pub info_file: PathBuf,
    /// How long to run the benchmark.
    #[arg(long, default_value_t = 10)]
    pub duration_secs: u64,
    /// Concurrent connect+handshake+close cycles in flight.
    #[arg(long, default_value_t = 64)]
    pub concurrency: u32,
    #[arg(long, default_value_t = 10)]
    pub attempt_timeout_secs: u64,
    #[arg(long, default_value = "127.0.2.0")]
    pub client_ip_base: String,
    #[arg(long, default_value_t = 32)]
    pub client_ip_count: u32,
}

pub async fn run_handshake_bench(
    args: HandshakeBenchArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let info = load_server_info(&args.info_file)?;
    let server_addr: SocketAddr = format!("127.0.0.1:{}", info.port).parse()?;
    let connector = build_connector(&info.fingerprint)?;
    let base_ip = parse_base_ip(&args.client_ip_base)?;
    let client_ip_count = args.client_ip_count.max(1);
    let attempt_timeout = Duration::from_secs(args.attempt_timeout_secs);
    let deadline = Instant::now() + Duration::from_secs(args.duration_secs);

    println!(
        "handshake-bench: duration_secs={} concurrency={}",
        args.duration_secs, args.concurrency
    );

    let completed = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let counter = Arc::new(AtomicU64::new(0));

    let mut workers = Vec::with_capacity(args.concurrency as usize);
    for w in 0..args.concurrency {
        let connector = connector.clone();
        let domain = info.domain.clone();
        let completed = completed.clone();
        let failed = failed.clone();
        let counter = counter.clone();
        workers.push(tokio::spawn(async move {
            while Instant::now() < deadline {
                let n = counter.fetch_add(1, Ordering::Relaxed);
                let client_ip = IpAddr::V4(nth_loopback_addr(
                    base_ip,
                    (n as u32).wrapping_add(w) % client_ip_count,
                ));
                match connect_and_handshake(
                    server_addr,
                    &domain,
                    client_ip,
                    &connector,
                    attempt_timeout,
                )
                .await
                {
                    Ok(mut stream) => {
                        completed.fetch_add(1, Ordering::Relaxed);
                        let _ = stream.shutdown().await;
                    }
                    Err(_) => {
                        failed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    for w in workers {
        let _ = w.await;
    }

    let completed_count = completed.load(Ordering::Relaxed);
    let failed_count = failed.load(Ordering::Relaxed);
    let rate = completed_count as f64 / args.duration_secs as f64;
    println!(
        "handshake-bench: DONE — completed={} failed={} over {}s => {:.1} handshakes/sec \
         (client-observed; this is a DIFFERENT number from established-connection COUNT)",
        completed_count, failed_count, args.duration_secs, rate
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// request-bench: request/response throughput over persistent connections
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct RequestBenchArgs {
    #[arg(long, default_value = "loadtest-data/loadtest-info.json")]
    pub info_file: PathBuf,
    /// Number of persistent connections to open once, then reuse for the
    /// whole benchmark (signing-things-request.md: "permit SDKs to reuse
    /// persistent connections").
    #[arg(long, default_value_t = 32)]
    pub connections: u32,
    #[arg(long, default_value_t = 10)]
    pub duration_secs: u64,
    /// Which anonymous public-key operation to drive.
    #[arg(long, default_value = "domain-keys", value_parser = ["domain-keys", "hello"])]
    pub op: String,
    #[arg(long, default_value = "127.0.3.0")]
    pub client_ip_base: String,
    #[arg(long, default_value_t = 32)]
    pub client_ip_count: u32,
    /// Per-connection (connect + TLS handshake) timeout for the initial
    /// setup phase, before the timed request loop starts.
    #[arg(long, default_value_t = 10)]
    pub attempt_timeout_secs: u64,
}

pub async fn run_request_bench(args: RequestBenchArgs) -> Result<(), Box<dyn std::error::Error>> {
    let info = load_server_info(&args.info_file)?;
    let server_addr: SocketAddr = format!("127.0.0.1:{}", info.port).parse()?;
    let connector = build_connector(&info.fingerprint)?;
    let base_ip = parse_base_ip(&args.client_ip_base)?;
    let client_ip_count = args.client_ip_count.max(1);
    let request = if args.op == "hello" {
        hello_request()
    } else {
        domain_keys_request()
    };

    println!(
        "request-bench: op={} connections={} duration_secs={}",
        args.op, args.connections, args.duration_secs
    );

    // Establish the persistent connections up front — connection cost is not
    // part of this measurement.
    let mut streams = Vec::with_capacity(args.connections as usize);
    for i in 0..args.connections {
        let client_ip = IpAddr::V4(nth_loopback_addr(base_ip, i % client_ip_count));
        let stream = connect_and_handshake(
            server_addr,
            &info.domain,
            client_ip,
            &connector,
            Duration::from_secs(args.attempt_timeout_secs),
        )
        .await
        .map_err(|stage| {
            format!(
                "failed to establish request-bench connection {i}: {:?}",
                stage
            )
        })?;
        streams.push(stream);
    }
    println!("  {} persistent connections established", streams.len());

    let deadline = Instant::now() + Duration::from_secs(args.duration_secs);
    let completed = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    let logged_sample = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let mut workers = Vec::with_capacity(streams.len());
    for mut stream in streams {
        let request = request.clone();
        let completed = completed.clone();
        let errors = errors.clone();
        let logged_sample = logged_sample.clone();
        workers.push(tokio::spawn(async move {
            while Instant::now() < deadline {
                if write_frame(&mut stream, &request).await.is_err() {
                    errors.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                match read_response_frame(&mut stream).await {
                    Ok(bytes) => match RpcResponse::decode(&bytes) {
                        Ok(resp) if resp.status.is_ok() => {
                            completed.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(resp) => {
                            if !logged_sample.swap(true, Ordering::Relaxed) {
                                eprintln!(
                                    "  DEBUG sample non-ok response: status={:?} error={:?}",
                                    resp.status, resp.error
                                );
                            }
                            errors.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            if !logged_sample.swap(true, Ordering::Relaxed) {
                                eprintln!(
                                    "  DEBUG sample decode error: {e:?} bytes_len={}",
                                    bytes.len()
                                );
                            }
                            errors.fetch_add(1, Ordering::Relaxed);
                        }
                    },
                    Err(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                }
            }
        }));
    }
    for w in workers {
        let _ = w.await;
    }

    let completed_count = completed.load(Ordering::Relaxed);
    let error_count = errors.load(Ordering::Relaxed);
    let rate = completed_count as f64 / args.duration_secs as f64;
    println!(
        "request-bench: DONE — completed={} errors={} over {}s => {:.1} requests/sec \
         (a DIFFERENT number from connection count and handshake rate)",
        completed_count, error_count, args.duration_secs, rate
    );
    if error_count > 0 {
        println!(
            "  NOTE: errors can include the anonymous public-read rate limiter \
             (PUBLIC_READ_* env vars) rejecting requests, not only network failures — \
             raise PUBLIC_READ_RATE_PER_MINUTE / PUBLIC_READ_GLOBAL_* on the server \
             process to measure raw dispatch/cache throughput instead of the default \
             DoS-protection ceiling. See docs/load-testing.md."
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ddos: distinct-source protection controls
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct DdosArgs {
    #[arg(long, default_value = "loadtest-data/loadtest-info.json")]
    pub info_file: PathBuf,
    /// Number of distinct simulated sources. Each source makes one connection
    /// attempt from its own loopback address. Default exceeds the handshake
    /// limiter's default `TCP_HANDSHAKE_DISTINCT_SOURCE_THRESHOLD` (10,000),
    /// so protection mode should engage during this run.
    #[arg(long, default_value_t = 12_000)]
    pub sources: u32,
    /// Attempts in flight at once.
    #[arg(long, default_value_t = 1000)]
    pub concurrency: u32,
    #[arg(long, default_value_t = 5)]
    pub attempt_timeout_secs: u64,
    #[arg(long, default_value = "127.5.0.0")]
    pub client_ip_base: String,
    #[arg(long, default_value_t = 5000)]
    pub progress_every: u32,
}

pub async fn run_ddos(args: DdosArgs) -> Result<(), Box<dyn std::error::Error>> {
    let info = load_server_info(&args.info_file)?;
    let server_addr: SocketAddr = format!("127.0.0.1:{}", info.port).parse()?;
    let connector = build_connector(&info.fingerprint)?;
    let base_ip = parse_base_ip(&args.client_ip_base)?;
    let attempt_timeout = Duration::from_secs(args.attempt_timeout_secs);

    println!(
        "ddos: sources={} concurrency={} (one connection attempt per distinct source address)",
        args.sources, args.concurrency
    );

    let semaphore = Arc::new(Semaphore::new(args.concurrency as usize));
    let allowed = Arc::new(AtomicU64::new(0));
    let denied = Arc::new(AtomicU64::new(0));
    let attempted = Arc::new(AtomicU64::new(0));

    let started = Instant::now();
    let mut handles = Vec::with_capacity(args.sources as usize);
    for i in 0..args.sources {
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore open");
        let connector = connector.clone();
        let domain = info.domain.clone();
        let allowed = allowed.clone();
        let denied = denied.clone();
        let attempted = attempted.clone();
        // One source == one address: this is the "distinct sources" axis the
        // limiter tracks, not a raw connection-count axis.
        let client_ip = IpAddr::V4(nth_loopback_addr(base_ip, i));

        handles.push(tokio::spawn(async move {
            let result =
                connect_and_handshake(server_addr, &domain, client_ip, &connector, attempt_timeout)
                    .await;
            drop(permit);
            let n = attempted.fetch_add(1, Ordering::Relaxed) + 1;
            if n.is_multiple_of(args.progress_every.max(1) as u64) {
                println!(
                    "  progress: attempted={n} allowed={} denied={}",
                    allowed.load(Ordering::Relaxed),
                    denied.load(Ordering::Relaxed)
                );
            }
            match result {
                Ok(mut stream) => {
                    allowed.fetch_add(1, Ordering::Relaxed);
                    let _ = stream.shutdown().await;
                }
                Err(_) => {
                    denied.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    for handle in handles {
        let _ = handle.await;
    }

    let elapsed = started.elapsed();
    println!(
        "ddos: DONE in {:?} — sources={} client-observed-allowed={} client-observed-denied={}",
        elapsed,
        args.sources,
        allowed.load(Ordering::Relaxed),
        denied.load(Ordering::Relaxed)
    );
    println!(
        "  This client cannot distinguish 'handshake rate limiter denied it' from 'some \
         other TLS-stage failure' on its own (see the `connections` subcommand's NOTE). \
         Read the server process's METRICS lines for shed_handshake_per_source, \
         shed_handshake_overflow, shed_handshake_global, and open_connections during this \
         run — those are the authoritative distinct-source-protection numbers. \
         See docs/load-testing.md."
    );
    Ok(())
}
