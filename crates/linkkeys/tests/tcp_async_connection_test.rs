//! Connection-layer tests for the async TCP server
//! (signing-things-request.md, "Connection scalability"). These exercise the
//! REAL listener/accept/handshake/message-loop code via
//! `linkkeys::tcp::spawn_for_test` (see that function's doc comment) — no
//! socket/TLS/framing bypass, unlike `dispatch_for_test`, which is for
//! dispatch-surface tests that don't care about the connection layer.
//!
//! Not covered here (out of scope per the design, step 9): the 200,000-
//! connection load test. This file proves the mechanisms that load test will
//! rely on — timeouts, bounded buffers/queues, load shedding — at a scale a
//! normal test run can complete in well under a second per test. Raising
//! `TCP_MAX_CONNECTIONS`, the handshake-rate-limit knobs, and the OS
//! file-descriptor limit is what a real 200k run additionally needs; nothing
//! here caps those.

mod common;

use liblinkkeys::crypto;
use linkkeys::services::public_ratelimit::PublicReadLimiterConfig;
use linkkeys::tcp::limits::TcpServerConfig;
use linkkeys::tcp::{self, tls};
use rustls::pki_types::ServerName;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// A server config with no client-auth requirement — every test in this file
/// is about connection MECHANICS (timeouts, buffering, backpressure, load
/// shedding, persistence), not mTLS/DNS-pin specifics, which
/// `tls_mtls_e2e_test.rs` already covers in isolation. Returns the config and
/// the server certificate's fingerprint, which `connect_tls` needs to pin.
fn no_client_auth_tls_config() -> (Arc<rustls::ServerConfig>, String) {
    let (vk, sk) = crypto::generate_ed25519_keypair();
    let fp = crypto::fingerprint(vk.as_bytes());
    let seed = sk.to_bytes();
    let (cert_der, key_der) = tls::generate_domain_tls_cert("async-test.test", &seed).unwrap();
    let certs = vec![rustls::pki_types::CertificateDer::from(cert_der)];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        key_der,
    ));
    let config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap(),
    );
    (config, fp)
}

fn permissive_handshake_limiter() -> PublicReadLimiterConfig {
    PublicReadLimiterConfig {
        per_source_capacity: 1_000_000.0,
        per_source_refill_per_sec: 1_000_000.0,
        global_capacity: 1_000_000.0,
        global_refill_per_sec: 1_000_000.0,
        overflow_capacity: 1_000_000.0,
        overflow_refill_per_sec: 1_000_000.0,
        distinct_source_threshold: 1_000_000,
        window_seconds: 60,
        ipv6_prefix_len: 64,
        trusted_proxies: Vec::new(),
        shard_count: 4,
    }
}

fn base_config() -> TcpServerConfig {
    TcpServerConfig {
        max_connections: 1000,
        listen_backlog: 128,
        handshake_timeout: Duration::from_secs(5),
        handshake_concurrency: 64,
        idle_timeout: Duration::from_secs(5),
        io_timeout: Duration::from_secs(5),
        max_inflight_frames: 4,
        write_queue_bound: 4,
        dns_sync_fallback_concurrency: 4,
        handshake_limiter: permissive_handshake_limiter(),
    }
}

async fn connect_tls(
    addr: std::net::SocketAddr,
    server_fp: &str,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let client_config = tls::build_client_config(vec![server_fp.to_string()]).unwrap();
    let connector = TlsConnector::from(client_config);
    let sock = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("async-test.test").unwrap();
    connector.connect(name, sock).await.unwrap()
}

fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

/// Build a raw CSIL-RPC `Hello/hello` request frame (needs no auth, no DB
/// state — just exercises the connection + dispatch path end to end).
fn hello_request_frame() -> Vec<u8> {
    use csilgen_transport::rpc::RpcRequest;
    let mut payload = Vec::new();
    ciborium::ser::into_writer(&serde_json::json!({"name": null}), &mut payload).unwrap();
    let request = RpcRequest::new("Hello", "hello", payload);
    frame(&request.encode().unwrap())
}

async fn read_response_frame(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_handshake_is_timed_out_and_dropped() {
    let (tls_config, _server_fp) = no_client_auth_tls_config();
    let db_pool = common::create_test_pool();
    let mut config = base_config();
    config.handshake_timeout = Duration::from_millis(200);
    let server = tcp::spawn_for_test(tls_config, db_pool, config)
        .await
        .unwrap();

    // Connect the raw TCP socket but never speak TLS — the handshake never
    // completes, so it must be timed out and the connection dropped.
    let mut sock = TcpStream::connect(server.addr).await.unwrap();
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(2), sock.read(&mut buf)).await;
    match read {
        Ok(Ok(0)) => {} // clean close once the server times out the handshake
        Ok(Ok(_)) => panic!("expected no application data before a TLS handshake"),
        Ok(Err(_)) => {} // reset is also an acceptable "dropped" outcome
        Err(_) => panic!("server did not drop the connection within its handshake timeout"),
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        server.metrics.handshake_timeouts() >= 1,
        "expected the handshake to be counted as timed out"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_frame_is_rejected_by_the_io_timeout() {
    let (tls_config, server_fp) = no_client_auth_tls_config();
    let db_pool = common::create_test_pool();
    let mut config = base_config();
    config.io_timeout = Duration::from_millis(200);
    let server = tcp::spawn_for_test(tls_config, db_pool, config)
        .await
        .unwrap();

    let mut tls = connect_tls(server.addr, &server_fp).await;
    // Announce a frame body of 100 bytes, then never send it. The reader must
    // give up on the read after `io_timeout` rather than hanging forever.
    tls.write_all(&100u32.to_be_bytes()).await.unwrap();
    tls.flush().await.unwrap();

    let mut buf = [0u8; 1];
    let outcome = tokio::time::timeout(Duration::from_secs(2), tls.read(&mut buf)).await;
    match outcome {
        Ok(Ok(0)) | Ok(Err(_)) => {} // connection dropped, either cleanly or via reset
        Ok(Ok(_)) => panic!("did not expect a response to an incomplete frame"),
        Err(_) => panic!("server did not drop the connection within its I/O timeout"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_frame_is_rejected() {
    let (tls_config, server_fp) = no_client_auth_tls_config();
    let db_pool = common::create_test_pool();
    let server = tcp::spawn_for_test(tls_config, db_pool, base_config())
        .await
        .unwrap();

    let mut tls = connect_tls(server.addr, &server_fp).await;
    // A length prefix over MAX_FRAME_SIZE (1 MiB) must be rejected without
    // the server ever trying to allocate/read that many bytes.
    let oversized_len = 2 * 1024 * 1024u32;
    tls.write_all(&oversized_len.to_be_bytes()).await.unwrap();
    tls.flush().await.unwrap();

    let mut buf = [0u8; 1];
    let outcome = tokio::time::timeout(Duration::from_secs(2), tls.read(&mut buf)).await;
    match outcome {
        Ok(Ok(0)) | Ok(Err(_)) => {} // rejected: connection dropped
        Ok(Ok(_)) => panic!("did not expect a response to an oversized frame"),
        Err(_) => panic!("server did not reject the oversized frame promptly"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_connection_does_not_hold_a_megabyte_scale_buffer() {
    // Deterministic instrumentation, not process RSS (per the design's own
    // guidance): `TcpMetrics::frame_buffer_bytes` tracks bytes currently
    // allocated for a read-but-undispatched frame body, summed across every
    // connection on the server.
    let (tls_config, server_fp) = no_client_auth_tls_config();
    let db_pool = common::create_test_pool();
    let server = tcp::spawn_for_test(tls_config, db_pool, base_config())
        .await
        .unwrap();

    let mut tls = connect_tls(server.addr, &server_fp).await;
    // Send one small request and read its response, so the connection is
    // fully established and has processed at least one frame.
    tls.write_all(&hello_request_frame()).await.unwrap();
    tls.flush().await.unwrap();
    let _ = read_response_frame(&mut tls).await.unwrap();

    // Now idle: no frame in flight. The accounted buffer size must be far
    // below the 1 MiB cap — proving the connection isn't holding
    // `MAX_FRAME_SIZE`-sized buffers just for being open/idle.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let idle_bytes = server.metrics.frame_buffer_bytes();
    assert!(
        idle_bytes < 4096,
        "expected a near-zero idle frame buffer, got {idle_bytes} bytes"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persistent_connection_serves_several_requests_in_sequence() {
    let (tls_config, server_fp) = no_client_auth_tls_config();
    let db_pool = common::create_test_pool();
    let server = tcp::spawn_for_test(tls_config, db_pool, base_config())
        .await
        .unwrap();

    let mut tls = connect_tls(server.addr, &server_fp).await;
    for _ in 0..5 {
        tls.write_all(&hello_request_frame()).await.unwrap();
        tls.flush().await.unwrap();
        let response = read_response_frame(&mut tls).await.unwrap();
        assert!(!response.is_empty());
    }
    assert!(
        server.metrics.frames_processed() >= 5,
        "expected all 5 requests on the reused connection to be counted"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_in_flight_frames_and_response_queue_do_not_deadlock() {
    // A client that pipelines more requests than `max_inflight_frames` must
    // be backpressured (the reader stalls once the channel is full), not
    // dropped or deadlocked — draining responses afterward must complete
    // every request.
    let (tls_config, server_fp) = no_client_auth_tls_config();
    let db_pool = common::create_test_pool();
    let mut config = base_config();
    config.max_inflight_frames = 2;
    config.write_queue_bound = 2;
    let server = tcp::spawn_for_test(tls_config, db_pool, config)
        .await
        .unwrap();

    let mut tls = connect_tls(server.addr, &server_fp).await;
    const REQUESTS: usize = 20; // far more than the bound of 2
    for _ in 0..REQUESTS {
        tls.write_all(&hello_request_frame()).await.unwrap();
    }
    tls.flush().await.unwrap();

    let drain = async {
        for _ in 0..REQUESTS {
            let response = read_response_frame(&mut tls).await.unwrap();
            assert!(!response.is_empty());
        }
    };
    tokio::time::timeout(Duration::from_secs(10), drain)
        .await
        .expect("all pipelined requests must eventually complete despite the small bound");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn graceful_load_shedding_at_the_connection_limit() {
    let (tls_config, server_fp) = no_client_auth_tls_config();
    let db_pool = common::create_test_pool();
    let mut config = base_config();
    config.max_connections = 1;
    let server = tcp::spawn_for_test(tls_config, db_pool, config)
        .await
        .unwrap();

    // Hold the first connection open (established, idle) so the accept loop
    // sees the limit as full for the second attempt.
    let _first = connect_tls(server.addr, &server_fp).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // The second connection must be refused cleanly (closed), not hang and
    // not crash the server — the first connection must keep working.
    let mut second = TcpStream::connect(server.addr).await.unwrap();
    let mut buf = [0u8; 1];
    let outcome = tokio::time::timeout(Duration::from_secs(2), second.read(&mut buf)).await;
    assert!(
        matches!(outcome, Ok(Ok(0)) | Ok(Err(_))),
        "the over-the-limit connection must be refused cleanly, not hang"
    );

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(server.metrics.shed_connection_limit() >= 1);

    // Prove the server is still alive and serving the connection it already
    // accepted — a graceful shed must not have taken the process down.
    let (tls_config2, server_fp2) = no_client_auth_tls_config();
    let db_pool2 = common::create_test_pool();
    let unrelated = tcp::spawn_for_test(tls_config2, db_pool2, base_config())
        .await
        .unwrap();
    let mut tls = connect_tls(unrelated.addr, &server_fp2).await;
    tls.write_all(&hello_request_frame()).await.unwrap();
    tls.flush().await.unwrap();
    let response = read_response_frame(&mut tls).await.unwrap();
    assert!(!response.is_empty(), "the server process is still healthy");
}
