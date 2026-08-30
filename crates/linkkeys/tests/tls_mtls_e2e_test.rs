//! Multi-domain mutual-TLS end-to-end test exercising the REAL asynchronous
//! rustls handshake (`tokio_rustls::TlsAcceptor`) and the REAL
//! `FingerprintClientCertVerifier` — the verifier that, mid-handshake, pins
//! the connecting client's certificate to its domain's DNS `fp=` set. The DNS
//! lookup goes through the injected `DnsResolver` seam (a static fake here),
//! so this covers the TLS path that `dispatch_for_test` deliberately
//! bypasses.
//!
//! The verifier is synchronous (rustls's trait) but now consults an in-memory
//! `DnsPinCache` instead of blocking on DNS directly (see
//! `crate::tcp::dns_pin_cache` module docs):
//!
//! - Hit: answered immediately, no I/O.
//! - Miss, and the `sync_fallback` semaphore has a free permit: a BOUNDED
//!   synchronous DNS lookup runs right there, so first contact with a domain
//!   still gets a correct answer on the FIRST attempt — this is the
//!   regression fix over the earlier cache-only design (there is no retry
//!   anywhere in `linkkeys-rpc-client`, so a guaranteed-fail-once first
//!   contact would surface as a failed login/verification with no automatic
//!   recovery).
//! - Miss, and `sync_fallback` is exhausted: fails THIS attempt closed and
//!   fires a background `tokio::spawn` refresh for next time.
//!
//! That requires an ambient Tokio runtime around the server side of the
//! handshake (unlike the earlier purely-synchronous implementation, which
//! ran the server on a plain `std::thread`), so every test here runs under
//! `#[tokio::test(flavor = "multi_thread")]` with both client and server as
//! async tasks on loopback.

mod common;

use common::net::StaticDns;
use liblinkkeys::crypto;
use linkkeys::net::DnsResolver;
use linkkeys::tcp::dns_pin_cache::{DnsPinCache, DnsPinCacheConfig};
use linkkeys::tcp::tls;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const SERVER_DOMAIN: &str = "idp-a.test";
const CLIENT_DOMAIN: &str = "idp-b.test";

struct Domain {
    fp: String,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
}

fn make_domain(name: &str) -> Domain {
    let (vk, sk) = crypto::generate_ed25519_keypair();
    let fp = crypto::fingerprint(vk.as_bytes());
    let seed = sk.to_bytes();
    let (cert_der, key_der) = tls::generate_domain_tls_cert(name, &seed).unwrap();
    Domain {
        fp,
        cert_der,
        key_der,
    }
}

/// Generous, test-friendly cache bounds — the entry-cap/refresh-concurrency
/// behavior under attack has its own dedicated unit tests in
/// `tcp::dns_pin_cache`; these values just need to be large enough not to be
/// the bottleneck for the handful of domains a test in this file touches.
fn test_cache() -> Arc<DnsPinCache> {
    Arc::new(DnsPinCache::new(DnsPinCacheConfig {
        positive_ttl: Duration::from_secs(300),
        negative_ttl: Duration::from_secs(30),
        max_entries: 100,
        max_concurrent_refreshes: 8,
    }))
}

/// Normal (non-exhausted) synchronous-fallback concurrency for tests that
/// aren't specifically about the fallback-exhausted path.
fn normal_sync_fallback() -> Arc<Semaphore> {
    Arc::new(Semaphore::new(4))
}

/// Run one mTLS exchange over loopback, using the real async accept/connect
/// paths. The server pins the client via `cache` and `sync_fallback`
/// (backing its real verifier) — falling back to `dns` on a cache miss,
/// exactly as production does — then sends back the domain it proved for the
/// client. Returns the string the client read back, or an error if the
/// handshake or exchange failed.
async fn exchange(
    server: &Domain,
    client: &Domain,
    dns: Arc<dyn DnsResolver>,
    cache: Arc<DnsPinCache>,
    sync_fallback: Arc<Semaphore>,
) -> std::io::Result<String> {
    let verifier = Arc::new(tls::FingerprintClientCertVerifier::new(
        dns,
        cache,
        sync_fallback,
    ));
    let server_config =
        tls::build_server_config(server.cert_der.clone(), server.key_der.clone(), verifier)
            .unwrap();
    let acceptor = TlsAcceptor::from(server_config);

    // The client pins the server by a pre-resolved fp list (no DNS-in-handshake
    // on the client side, mirroring how the real client resolves first).
    let client_config = tls::build_client_config_with_cert(
        vec![server.fp.clone()],
        client.cert_der.clone(),
        client.key_der.clone(),
    )
    .unwrap();
    let connector = TlsConnector::from(client_config);

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let server_task = tokio::spawn(async move {
        let (sock, _) = listener.accept().await?;
        let mut tls = acceptor.accept(sock).await?;
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await?;
        let (_, server_conn) = tls.get_ref();
        let domain = server_conn
            .peer_certificates()
            .and_then(|c| c.first())
            .and_then(tls::verified_client_domain)
            .unwrap_or_default();
        tls.write_all(domain.as_bytes()).await?;
        tls.shutdown().await?;
        Ok::<(), std::io::Error>(())
    });

    let result = async {
        let sock = TcpStream::connect(addr).await?;
        let name = ServerName::try_from(SERVER_DOMAIN).unwrap();
        let mut tls = connector.connect(name, sock).await?;
        tls.write_all(b"ping").await?;
        let mut out = String::new();
        tls.read_to_string(&mut out).await?;
        Ok::<String, std::io::Error>(out)
    }
    .await;

    // The server task's result is informational; the client outcome is what
    // we assert on (on a rejected handshake the server side also fails).
    let _ = server_task.await;
    result
}

/// Small, deterministic retry helper: attempt `exchange` up to `attempts`
/// times with a short delay between, returning the first success (or the
/// last error). Only used for the fallback-exhausted scenario, where success
/// depends on a background refresh completing.
async fn exchange_until_ok(
    server: &Domain,
    client: &Domain,
    dns: Arc<dyn DnsResolver>,
    cache: Arc<DnsPinCache>,
    sync_fallback: Arc<Semaphore>,
    attempts: u32,
) -> std::io::Result<String> {
    let mut last_err = None;
    for _ in 0..attempts {
        match exchange(
            server,
            client,
            dns.clone(),
            cache.clone(),
            sync_fallback.clone(),
        )
        .await
        {
            Ok(value) => return Ok(value),
            Err(e) => last_err = Some(e),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(last_err.unwrap())
}

fn dns_with_correct_fingerprint(client: &Domain) -> Arc<dyn DnsResolver> {
    Arc::new(StaticDns::new().with(
        &liblinkkeys::dns::linkkeys_dns_name(CLIENT_DOMAIN),
        &[&format!("v=lk1 fp={}", client.fp)],
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_handshake_pins_client_domain_via_dns_once_cache_is_warm() {
    let server = make_domain(SERVER_DOMAIN);
    let client = make_domain(CLIENT_DOMAIN);
    let dns = dns_with_correct_fingerprint(&client);
    let cache = test_cache();
    // Simulate the steady-state (warm cache) case deterministically: the
    // cache already holds the client's correct fingerprint, so the verifier
    // never needs any DNS work at all, sync or background.
    cache.insert_positive(CLIENT_DOMAIN, vec![client.fp.clone()]);

    let proven = exchange(&server, &client, dns, cache, normal_sync_fallback())
        .await
        .expect("mTLS handshake succeeds with a warm, correct cache entry");
    assert_eq!(
        proven, CLIENT_DOMAIN,
        "server proves the connecting client's domain"
    );
}

/// The regression this whole change fixes: a domain LinkKeys has never seen
/// (cold cache) must still succeed on the FIRST attempt, not fail once and
/// require a caller-driven retry that doesn't exist anywhere in the stack.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_handshake_succeeds_on_first_contact_via_bounded_sync_fallback() {
    let server = make_domain(SERVER_DOMAIN);
    let client = make_domain(CLIENT_DOMAIN);
    let dns = dns_with_correct_fingerprint(&client);
    let cache = test_cache();
    assert_eq!(cache.len(), 0, "cache starts genuinely cold");

    let proven = exchange(&server, &client, dns, cache.clone(), normal_sync_fallback())
        .await
        .expect(
            "first contact with a domain must succeed immediately via the bounded synchronous \
             DNS fallback, not fail closed",
        );
    assert_eq!(proven, CLIENT_DOMAIN);
    assert_eq!(
        cache.len(),
        1,
        "the synchronous fallback should have warmed the cache as a side effect"
    );
}

/// When the bounded synchronous fallback is fully busy (here: given zero
/// permits, so it is ALWAYS busy), a cold-cache miss must still fail closed
/// rather than block the caller, and must fall back to the background
/// refresh path — which eventually succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_handshake_falls_back_to_background_refresh_when_sync_fallback_exhausted() {
    let server = make_domain(SERVER_DOMAIN);
    let client = make_domain(CLIENT_DOMAIN);
    let dns = dns_with_correct_fingerprint(&client);
    let cache = test_cache();
    // Zero permits: `try_acquire` always fails, deterministically forcing the
    // "fully busy" branch every time, no timing/concurrency race needed.
    let exhausted_sync_fallback = Arc::new(Semaphore::new(0));

    let first = exchange(
        &server,
        &client,
        dns.clone(),
        cache.clone(),
        exhausted_sync_fallback.clone(),
    )
    .await;
    assert!(
        first.is_err(),
        "a cold cache miss with no synchronous-fallback permit available must fail closed"
    );
    assert!(
        cache.refreshes_started() >= 1,
        "it must fire a background refresh instead"
    );

    let proven = exchange_until_ok(&server, &client, dns, cache, exhausted_sync_fallback, 20)
        .await
        .expect("a retry succeeds once the background refresh has populated the cache");
    assert_eq!(proven, CLIENT_DOMAIN);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_handshake_rejected_when_dns_fingerprint_wrong() {
    let server = make_domain(SERVER_DOMAIN);
    let client = make_domain(CLIENT_DOMAIN);
    // DNS for the client domain publishes a DIFFERENT fingerprint than the
    // client actually presents.
    let dns: Arc<dyn DnsResolver> = Arc::new(StaticDns::new().with(
        &liblinkkeys::dns::linkkeys_dns_name(CLIENT_DOMAIN),
        &["v=lk1 fp=0000000000000000000000000000000000000000000000000000000000000000"],
    ));
    let cache = test_cache();
    // Pre-warm with that same wrong fingerprint so this test proves the
    // FINGERPRINT CHECK rejects it (not merely a cold-cache miss).
    cache.insert_positive(
        CLIENT_DOMAIN,
        vec!["0000000000000000000000000000000000000000000000000000000000000000".to_string()],
    );

    for _ in 0..3 {
        let result = exchange(
            &server,
            &client,
            dns.clone(),
            cache.clone(),
            normal_sync_fallback(),
        )
        .await;
        assert!(
            result.is_err(),
            "an unpinned client cert must fail the mTLS handshake, warm cache or not"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_handshake_rejected_when_dns_missing() {
    let server = make_domain(SERVER_DOMAIN);
    let client = make_domain(CLIENT_DOMAIN);
    // No DNS record at all for the client domain — even the synchronous
    // fallback (a permit is available here) gets a genuine resolution
    // failure, so every attempt fails closed deterministically, not just the
    // first cold one.
    let dns: Arc<dyn DnsResolver> = Arc::new(StaticDns::new());
    let cache = test_cache();

    for attempt in 0..5 {
        let result = exchange(
            &server,
            &client,
            dns.clone(),
            cache.clone(),
            normal_sync_fallback(),
        )
        .await;
        assert!(
            result.is_err(),
            "absent DNS => fail closed, handshake rejected (attempt {attempt})"
        );
    }
}
