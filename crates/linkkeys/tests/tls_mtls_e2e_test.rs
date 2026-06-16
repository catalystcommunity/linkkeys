//! Multi-domain mutual-TLS end-to-end test exercising the REAL rustls handshake
//! and the REAL `FingerprintClientCertVerifier` — the verifier that, mid-
//! handshake, pins the connecting client's certificate to its domain's DNS
//! `fp=` set. The DNS lookup goes through the injected `DnsResolver` seam (a
//! static fake here), so this covers the TLS path that `dispatch_for_test`
//! deliberately bypasses.
//!
//! Limitation, by construction: TLS is a byte protocol between two live
//! endpoints, so unlike the pure in-process seams this needs a real stream — we
//! use loopback. The verifier's DNS is blocking (rustls's trait is sync), so the
//! server side runs on a plain std::thread (no tokio runtime around `block_on`).

mod common;

use common::net::StaticDns;
use liblinkkeys::crypto;
use linkkeys::net::DnsResolver;
use linkkeys::tcp::tls;
use rustls::pki_types::ServerName;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

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

fn runtime() -> Arc<tokio::runtime::Runtime> {
    Arc::new(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap(),
    )
}

/// Run one mTLS exchange over loopback. The server pins the client via `dns`
/// (its real verifier), then sends back the domain it proved for the client.
/// Returns the string the client read back, or an error if the handshake failed.
fn exchange(server: &Domain, client: &Domain, dns: StaticDns) -> std::io::Result<String> {
    let verifier = Arc::new(tls::FingerprintClientCertVerifier::new(
        runtime(),
        Arc::new(dns) as Arc<dyn DnsResolver>,
    ));
    let server_config =
        tls::build_server_config(server.cert_der.clone(), server.key_der.clone(), verifier)
            .unwrap();
    // The client pins the server by a pre-resolved fp list (no DNS-in-handshake
    // on the client side, mirroring how the real client resolves first).
    let client_config = tls::build_client_config_with_cert(
        vec![server.fp.clone()],
        client.cert_der.clone(),
        client.key_der.clone(),
    )
    .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    // Server runs on a plain thread: the verifier's DNS block_on must not be
    // inside a tokio worker.
    let server_thread = std::thread::spawn(move || -> std::io::Result<()> {
        let (sock, _) = listener.accept()?;
        let conn = rustls::ServerConnection::new(server_config).map_err(std::io::Error::other)?;
        let mut tls = rustls::StreamOwned::new(conn, sock);
        // Reading drives the handshake to completion (or fails it).
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf)?;
        let domain = tls
            .conn
            .peer_certificates()
            .and_then(|c| c.first())
            .and_then(tls::verified_client_domain)
            .unwrap_or_default();
        tls.write_all(domain.as_bytes())?;
        // Graceful TLS shutdown so the client's read_to_string sees a clean EOF
        // (rustls treats a missing close_notify as an error otherwise).
        tls.conn.send_close_notify();
        tls.flush()
    });

    let result = (|| -> std::io::Result<String> {
        let sock = TcpStream::connect(addr)?;
        let name = ServerName::try_from(SERVER_DOMAIN).unwrap();
        let conn =
            rustls::ClientConnection::new(client_config, name).map_err(std::io::Error::other)?;
        let mut tls = rustls::StreamOwned::new(conn, sock);
        tls.write_all(b"ping")?;
        tls.flush()?;
        let mut out = String::new();
        tls.read_to_string(&mut out)?;
        Ok(out)
    })();

    // The server thread result is informational; the client outcome is what we
    // assert on. (On a rejected handshake the server read also fails.)
    let _ = server_thread.join();
    result
}

#[test]
fn mtls_handshake_pins_client_domain_via_dns() {
    let server = make_domain(SERVER_DOMAIN);
    let client = make_domain(CLIENT_DOMAIN);

    // DNS publishes the client's real fingerprint => the verifier pins it and
    // the connecting domain is proven.
    let dns = StaticDns::new().with(
        &liblinkkeys::dns::linkkeys_dns_name(CLIENT_DOMAIN),
        &[&format!("v=lk1 fp={}", client.fp)],
    );
    let proven = exchange(&server, &client, dns).expect("mTLS handshake succeeds");
    assert_eq!(
        proven, CLIENT_DOMAIN,
        "server proves the connecting client's domain"
    );
}

#[test]
fn mtls_handshake_rejected_when_dns_fingerprint_absent() {
    let server = make_domain(SERVER_DOMAIN);
    let client = make_domain(CLIENT_DOMAIN);

    // DNS for the client domain publishes a DIFFERENT fingerprint, so the
    // client's presented cert does not pin => the handshake must fail.
    let dns = StaticDns::new().with(
        &liblinkkeys::dns::linkkeys_dns_name(CLIENT_DOMAIN),
        &["v=lk1 fp=0000000000000000000000000000000000000000000000000000000000000000"],
    );
    let result = exchange(&server, &client, dns);
    assert!(
        result.is_err(),
        "an unpinned client cert must fail the mTLS handshake"
    );
}

#[test]
fn mtls_handshake_rejected_when_dns_missing() {
    let server = make_domain(SERVER_DOMAIN);
    let client = make_domain(CLIENT_DOMAIN);

    // No DNS record at all for the client domain => verifier resolution fails
    // closed => handshake rejected.
    let result = exchange(&server, &client, StaticDns::new());
    assert!(
        result.is_err(),
        "absent DNS => fail closed, handshake rejected"
    );
}
