//! `server` subcommand: runs the real async TCP server
//! (`linkkeys::tcp::spawn_for_test`) standalone in its own process, so its
//! process RSS reflects only server-side memory. Every `TCP_*` and
//! `PUBLIC_READ_*` environment variable the production server reads
//! (`crates/linkkeys/src/tcp/limits.rs`, `crates/linkkeys/src/services/
//! public_ratelimit.rs`) still applies here — set them before launching this
//! subcommand exactly as an operator would for a real deployment. This
//! harness does not invent a second config surface.
//!
//! Uses a self-signed, no-client-auth TLS config (like
//! `tests/tcp_async_connection_test.rs`'s `no_client_auth_tls_config`): this
//! harness measures connection/handshake/dispatch/cache SCALE, which is
//! orthogonal to mTLS client-certificate verification (covered separately by
//! `tls_mtls_e2e_test.rs`). Domain-key bootstrap (`linkkeys domain init`,
//! `DOMAIN_KEY_PASSPHRASE`) is therefore not needed to run this tool.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Args;
use liblinkkeys::crypto;
use linkkeys::db;
use linkkeys::tcp::limits::{self, TcpServerConfig};
use linkkeys::tcp::{self, tls};
use serde::Serialize;

#[derive(Args)]
pub struct ServerArgs {
    /// SQLite database file. Created and migrated if missing. A real file
    /// (not `:memory:`), so the connection pool behaves like production's —
    /// SQLite's `:memory:` database is private to one connection, which would
    /// silently defeat a pool with more than one connection.
    #[arg(long, default_value = "loadtest-data/loadtest.sqlite3")]
    pub db_path: PathBuf,

    /// TLS SNI / certificate domain name. Client subcommands read this from
    /// the info file, so it rarely needs to be set explicitly.
    #[arg(long, default_value = "loadtest.local")]
    pub domain: String,

    /// Where to write `{"port","domain","fingerprint","pid"}` once the
    /// listener is bound and ready. Client subcommands read this file to find
    /// the server.
    #[arg(long, default_value = "loadtest-data/loadtest-info.json")]
    pub info_file: PathBuf,

    /// Print one metrics snapshot line (JSON, prefixed `METRICS `) on this
    /// interval while running.
    #[arg(long, default_value_t = 5)]
    pub metrics_interval_secs: u64,

    /// Exit automatically after this many seconds. 0 means run until Ctrl-C.
    #[arg(long, default_value_t = 0)]
    pub duration_secs: u64,
}

#[derive(Serialize)]
struct ServerInfo {
    port: u16,
    domain: String,
    fingerprint: String,
    pid: u32,
}

#[derive(Serialize)]
struct MetricsSnapshot<'a> {
    label: &'a str,
    elapsed_secs: f64,
    accepted_connections: u64,
    open_connections: u64,
    established_connections: u64,
    handshakes_in_progress: u64,
    handshake_timeouts: u64,
    handshake_rejections: u64,
    shed_connection_limit: u64,
    shed_handshake_per_source: u64,
    shed_handshake_overflow: u64,
    shed_handshake_global: u64,
    frames_processed: u64,
    frame_buffer_bytes: usize,
    /// This process's own resident-set size — see module docs on why "this
    /// process" is server-only here. `None` when `/proc/self/status` cannot
    /// be read (non-Linux, or a restricted sandbox).
    process_rss_bytes: Option<u64>,
}

/// Best-effort resident-set size of the current process, from
/// `/proc/self/status`'s `VmRSS` line (kilobytes, converted to bytes). Linux-
/// only, and deliberately reported as a separate, noisier figure alongside
/// the server's own bounded byte-accounting gauges — see
/// `docs/load-testing.md`, "Two memory numbers, and why they differ".
fn process_rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest.trim().trim_end_matches(" kB").trim().parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

fn print_metrics(label: &str, metrics: &tcp::limits::TcpMetrics, start: Instant) {
    let snapshot = MetricsSnapshot {
        label,
        elapsed_secs: start.elapsed().as_secs_f64(),
        accepted_connections: metrics.accepted_connections(),
        open_connections: metrics.open_connections(),
        established_connections: metrics.established_connections(),
        handshakes_in_progress: metrics.handshakes_in_progress(),
        handshake_timeouts: metrics.handshake_timeouts(),
        handshake_rejections: metrics.handshake_rejections(),
        shed_connection_limit: metrics.shed_connection_limit(),
        shed_handshake_per_source: metrics.shed_handshake_per_source(),
        shed_handshake_overflow: metrics.shed_handshake_overflow(),
        shed_handshake_global: metrics.shed_handshake_global(),
        frames_processed: metrics.frames_processed(),
        frame_buffer_bytes: metrics.frame_buffer_bytes(),
        process_rss_bytes: process_rss_bytes(),
    };
    match serde_json::to_string(&snapshot) {
        Ok(json) => println!("METRICS {json}"),
        Err(e) => eprintln!("failed to encode metrics snapshot: {e}"),
    }
}

pub async fn run(args: ServerArgs) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = args.db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = args.info_file.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Real sqlite file, migrated exactly like production startup
    // (`linkkeys::db::create_pool` + `run_migrations_with_locking`), so
    // `DomainKeys/get-domain-keys` and friends exercise the real dispatch +
    // cache path, not a bypass.
    std::env::set_var("DATABASE_BACKEND", "sqlite");
    std::env::set_var("DATABASE_URL", args.db_path.to_string_lossy().to_string());
    let db_pool = db::create_pool();
    db::run_migrations_with_locking(&db_pool);

    std::env::set_var("DOMAIN_NAME", &args.domain);

    let (verifying_key, signing_key) = crypto::generate_ed25519_keypair();
    let fingerprint = crypto::fingerprint(verifying_key.as_bytes());
    let seed = signing_key.to_bytes();
    let (cert_der, key_der) = tls::generate_domain_tls_cert(&args.domain, &seed)?;
    let certs = vec![rustls_pki_types::CertificateDer::from(cert_der)];
    let key =
        rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(key_der));
    let tls_config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?,
    );

    let config = TcpServerConfig::from_env()?;
    println!(
        "config: max_connections={} handshake_timeout={:?} handshake_concurrency={} \
         idle_timeout={:?} io_timeout={:?} max_inflight_frames={} write_queue_bound={} \
         handshake_per_source_capacity={} handshake_global_capacity={} \
         handshake_distinct_source_threshold={}",
        config.max_connections,
        config.handshake_timeout,
        config.handshake_concurrency,
        config.idle_timeout,
        config.io_timeout,
        config.max_inflight_frames,
        config.write_queue_bound,
        config.handshake_limiter.per_source_capacity,
        config.handshake_limiter.global_capacity,
        config.handshake_limiter.distinct_source_threshold,
    );
    limits::report_fd_and_connection_limits(config.max_connections);

    let test_server = tcp::spawn_for_test(tls_config, db_pool, config).await?;
    let info = ServerInfo {
        port: test_server.addr.port(),
        domain: args.domain.clone(),
        fingerprint,
        pid: std::process::id(),
    };
    std::fs::write(&args.info_file, serde_json::to_string_pretty(&info)?)?;
    println!(
        "listening on 127.0.0.1:{} pid={} (info written to {})",
        info.port,
        info.pid,
        args.info_file.display()
    );

    let start = Instant::now();
    let interval_secs = args.metrics_interval_secs.max(1);
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                print_metrics("running", &test_server.metrics, start);
                if args.duration_secs > 0 && start.elapsed().as_secs() >= args.duration_secs {
                    break;
                }
            }
            _ = tokio::signal::ctrl_c() => {
                println!("received ctrl-c, shutting down");
                break;
            }
        }
    }
    print_metrics("final", &test_server.metrics, start);
    Ok(())
}
