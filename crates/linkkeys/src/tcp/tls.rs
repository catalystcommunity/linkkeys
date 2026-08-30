use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::danger::ClientCertVerified;
use rustls::SignatureScheme;
use std::sync::Arc;

use crate::tcp::dns_pin_cache::{DnsPinCache, PinLookup};

// Client-side TLS (cert generation from a domain key, server-cert fingerprint
// pinning, client config builders) lives in the shared `linkkeys-rpc-client`
// crate so the CLI, the demo site, and the server's own outbound paths share one
// implementation. Re-exported here so existing `tcp::tls::` call sites keep
// working.
pub use linkkeys_rpc_client::tls::{
    build_client_config, build_client_config_with_cert, generate_domain_tls_cert,
    FingerprintVerifier,
};

/// Build a rustls ServerConfig with the domain certificate and mutual TLS.
/// The server presents its domain cert and requires clients to present theirs.
/// Client certs are verified via DNS-published fingerprints.
pub fn build_server_config(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    client_verifier: Arc<FingerprintClientCertVerifier>,
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error>> {
    let certs = vec![CertificateDer::from(cert_der)];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key)?;

    Ok(Arc::new(config))
}

// ---------------------------------------------------------------------------
// Server-side: verify the connecting client's certificate via DNS fingerprints
// ---------------------------------------------------------------------------

/// Custom ClientCertVerifier that verifies the client's certificate public key
/// fingerprint against the client domain's DNS-published fingerprints.
/// The domain is extracted from the certificate's SAN (dNSName) or CN.
#[derive(Debug)]
pub struct FingerprintClientCertVerifier {
    dns: Arc<dyn crate::net::DnsResolver>,
    /// Bounded, TTL'd cache of DNS-resolved fingerprint sets — see
    /// `tcp::dns_pin_cache` module docs for why this exists: it is what keeps
    /// this synchronous rustls callback from blocking the async connection
    /// task's thread on network I/O in the common (warm-cache) case.
    cache: Arc<DnsPinCache>,
    /// Small, SEPARATE semaphore (not `TCP_HANDSHAKE_CONCURRENCY`) bounding
    /// how many handshakes may, at once, fall back to a synchronous DNS
    /// lookup on a cache miss. This is what turns "first contact with a
    /// domain" from a guaranteed-fail-once into a correct answer on the
    /// first attempt in the common case (no retry exists anywhere in
    /// `linkkeys-rpc-client`/`net::TcpRpcClient`, so a spurious first-attempt
    /// failure would otherwise surface as a failed login/verification with
    /// no automatic recovery) — while still bounding the worst case (a flood
    /// of distinct unknown domains) to a handful of blocked threads rather
    /// than blocking the async runtime without limit.
    sync_fallback: Arc<tokio::sync::Semaphore>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl FingerprintClientCertVerifier {
    /// `dns` is the resolver used for BOTH the bounded synchronous fallback
    /// (directly, gated by `sync_fallback`) and a cache-miss background
    /// refresh (via `DnsPinCache::spawn_refresh`, gated by the cache's own
    /// `max_concurrent_refreshes`) — real in production, a static fake in
    /// tests. This constructor itself does no I/O and needs no ambient Tokio
    /// context; only `verify_client_cert` does (see its doc comment).
    pub fn new(
        dns: Arc<dyn crate::net::DnsResolver>,
        cache: Arc<DnsPinCache>,
        sync_fallback: Arc<tokio::sync::Semaphore>,
    ) -> Self {
        Self {
            dns,
            cache,
            sync_fallback,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }
}

impl rustls::server::danger::ClientCertVerifier for FingerprintClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        // Request client certs — server-to-server connections will present them.
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        // Client auth is optional. Clients that don't have a domain key (e.g.,
        // external API consumers) won't present a cert. They authenticate via
        // API key in the application protocol instead. Server-to-server connections
        // present a cert for domain-level trust verification.
        false
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        // No CA chain — we use DNS fingerprints, not root CAs.
        // Empty list tells the client to present any cert it has.
        &[]
    }

    /// Synchronous by rustls's trait contract, and invoked from inside the
    /// async `TlsAcceptor::accept` future on whichever Tokio task is driving
    /// this connection's handshake. On a cache HIT this does no I/O at all.
    /// On a cache MISS it takes a bounded, permit-gated synchronous DNS
    /// fallback (`dns::resolve_fingerprints_via`'s `block_in_place` path) so
    /// first contact with a domain gets a correct answer immediately in the
    /// common case — see `sync_fallback`'s field doc for why that matters
    /// (no retry exists anywhere in the callers of this server). Only when
    /// that small semaphore is exhausted does it fall back to failing this
    /// attempt closed and handing the lookup to a background task via
    /// `DnsPinCache::spawn_refresh` (see that module's docs).
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let (_, cert) = x509_parser::parse_x509_certificate(end_entity.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;

        // Check certificate validity period
        let validity = &cert.tbs_certificate.validity;
        let now_secs = now.as_secs();
        let not_before = validity.not_before.timestamp() as u64;
        let not_after = validity.not_after.timestamp() as u64;
        if now_secs < not_before || now_secs > not_after {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Expired,
            ));
        }

        // Extract the client's domain from SAN (dNSName) or CN
        let domain = extract_domain_from_cert(&cert).ok_or_else(|| {
            log::warn!("Client certificate has no domain in SAN or CN");
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )
        })?;

        let expected_fingerprints = match self.cache.get(&domain) {
            PinLookup::Hit(fingerprints) => fingerprints,
            PinLookup::NegativeHit => {
                log::warn!("Client cert verification for {domain}: cached DNS resolution failure");
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ));
            }
            PinLookup::Miss => match self.sync_fallback.try_acquire() {
                Ok(_permit) => {
                    // Bounded synchronous fallback: a small, fixed number of
                    // concurrent slots (never `TCP_HANDSHAKE_CONCURRENCY`),
                    // so a flood of unknown domains cannot tie up the
                    // blocking pool. `resolve_fingerprints_via` picks the
                    // same `block_in_place`-on-a-multi-thread-runtime path
                    // `cli/tcp_client.rs` relies on — always safe here since
                    // this callback only ever runs on an async connection
                    // task inside an ambient multi-thread runtime.
                    match crate::dns::resolve_fingerprints_via(self.dns.clone(), &domain) {
                        Ok(fingerprints) => {
                            self.cache.insert_positive(&domain, fingerprints.clone());
                            fingerprints
                        }
                        Err(error) => {
                            log::warn!(
                                "Client cert verification for {domain}: synchronous DNS \
                                 fallback failed: {error}"
                            );
                            self.cache.insert_negative(&domain);
                            return Err(rustls::Error::InvalidCertificate(
                                rustls::CertificateError::ApplicationVerificationFailure,
                            ));
                        }
                    }
                }
                Err(_) => {
                    // The bounded fallback is fully busy: don't pile more
                    // blocking work onto the runtime. Fail this attempt
                    // closed and let the (separately bounded) background
                    // refresh populate the cache for the next attempt.
                    self.cache.spawn_refresh(self.dns.clone(), domain.clone());
                    log::debug!(
                        "Client cert verification for {domain}: DNS pin cache miss and the \
                         synchronous fallback is fully busy; refreshing in the background and \
                         failing this attempt closed"
                    );
                    return Err(rustls::Error::InvalidCertificate(
                        rustls::CertificateError::ApplicationVerificationFailure,
                    ));
                }
            },
        };

        // Extract public key and compute fingerprint
        let spki = cert.tbs_certificate.subject_pki;
        let public_key_bytes = spki.subject_public_key.data;
        let fp = liblinkkeys::crypto::fingerprint(&public_key_bytes);

        if expected_fingerprints.contains(&fp) {
            log::debug!("Client cert verified for domain {}", domain);
            Ok(ClientCertVerified::assertion())
        } else {
            log::warn!(
                "Client cert fingerprint {} does not match any DNS fingerprint for {}",
                fp,
                domain
            );
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Extract the verified client domain from a peer certificate presented during
/// the mTLS handshake.
///
/// The handshake only succeeds (via [`FingerprintClientCertVerifier`]) when the
/// cert's public key is pinned to this domain's DNS `fp=` set, so the SAN/CN
/// domain recovered here is the *proven* identity of the connecting domain —
/// safe to use for audience binding (tcp-03). Returns `None` if the cert is
/// unparseable or carries no domain (which cannot happen for a cert that
/// already passed verification, but we fail closed anyway).
pub fn verified_client_domain(cert: &CertificateDer<'_>) -> Option<String> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref()).ok()?;
    extract_domain_from_cert(&parsed)
}

/// Extract the domain name from a parsed X.509 certificate.
/// Checks SAN (dNSName) first, falls back to CN.
fn extract_domain_from_cert(cert: &x509_parser::certificate::X509Certificate) -> Option<String> {
    use x509_parser::extensions::{GeneralName, ParsedExtension};

    // Check Subject Alternative Names first
    if let Ok(Some(san_ext)) = cert
        .tbs_certificate
        .get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
    {
        if let ParsedExtension::SubjectAlternativeName(san) = san_ext.parsed_extension() {
            for name in &san.general_names {
                if let GeneralName::DNSName(dns) = name {
                    return Some(dns.to_string());
                }
            }
        }
    }

    // Fall back to Common Name
    for attr in cert.tbs_certificate.subject.iter_common_name() {
        if let Ok(cn) = attr.as_str() {
            return Some(cn.to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use liblinkkeys::crypto;
    use rustls::pki_types::ServerName;

    #[test]
    fn test_extract_domain_from_cert() {
        let (_, sk) = crypto::generate_ed25519_keypair();
        let seed = sk.to_bytes();
        let (cert_der, _) = generate_domain_tls_cert("test.example.com", &seed).unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(&cert_der).unwrap();

        let domain = extract_domain_from_cert(&cert);
        assert_eq!(domain, Some("test.example.com".to_string()));
    }

    #[test]
    fn test_client_cert_verifier_extracts_and_fingerprints() {
        // The full client-cert verifier path does a DNS lookup, which a unit
        // test can't drive. Here we confirm the two pieces it relies on: domain
        // extraction from the cert and fingerprint computation matching the key.
        let (vk, sk) = crypto::generate_ed25519_keypair();
        let seed = sk.to_bytes();
        let fp = crypto::fingerprint(vk.as_bytes());

        let (cert_der, _) = generate_domain_tls_cert("test.example.com", &seed).unwrap();

        let (_, cert) = x509_parser::parse_x509_certificate(&cert_der).unwrap();
        let domain = extract_domain_from_cert(&cert);
        assert_eq!(domain, Some("test.example.com".to_string()));

        let spki = cert.tbs_certificate.subject_pki;
        let public_key_bytes = spki.subject_public_key.data;
        let cert_fp = crypto::fingerprint(&public_key_bytes);
        assert_eq!(fp, cert_fp);
    }

    #[test]
    fn test_build_server_config_succeeds() {
        let (_, sk) = crypto::generate_ed25519_keypair();
        let seed = sk.to_bytes();
        let (cert_der, key_der) = generate_domain_tls_cert("test.example.com", &seed).unwrap();

        let cache = Arc::new(DnsPinCache::new(
            crate::tcp::dns_pin_cache::DnsPinCacheConfig {
                positive_ttl: std::time::Duration::from_secs(300),
                negative_ttl: std::time::Duration::from_secs(30),
                max_entries: 100,
                max_concurrent_refreshes: 4,
            },
        ));
        let verifier = Arc::new(FingerprintClientCertVerifier::new(
            crate::net::Net::production().dns,
            cache,
            Arc::new(tokio::sync::Semaphore::new(4)),
        ));
        let config = build_server_config(cert_der, key_der, verifier);
        assert!(config.is_ok(), "Server config should build successfully");
    }

    #[test]
    fn test_tls_handshake_roundtrip() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let (vk, sk) = crypto::generate_ed25519_keypair();
        let seed = sk.to_bytes();
        let fp = crypto::fingerprint(vk.as_bytes());

        let (cert_der, key_der) = generate_domain_tls_cert("localhost", &seed).unwrap();

        // Build server config without mutual TLS for this basic roundtrip
        let certs = vec![CertificateDer::from(cert_der.clone())];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
        let server_config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap(),
        );
        let client_config = build_client_config(vec![fp]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_thread = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(server_config).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, stream);

            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"hello");
            tls.write_all(b"world").unwrap();
            tls.flush().unwrap();
        });

        let stream = std::net::TcpStream::connect(addr).unwrap();
        let server_name = ServerName::try_from("localhost").unwrap();
        let conn = rustls::ClientConnection::new(client_config, server_name).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, stream);

        tls.write_all(b"hello").unwrap();
        tls.flush().unwrap();
        let mut buf = [0u8; 5];
        tls.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"world");

        server_thread.join().unwrap();
    }

    #[test]
    fn test_mutual_tls_handshake_roundtrip() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        // Generate server key
        let (server_vk, server_sk) = crypto::generate_ed25519_keypair();
        let server_seed = server_sk.to_bytes();
        let server_fp = crypto::fingerprint(server_vk.as_bytes());
        let (server_cert_der, server_key_der) =
            generate_domain_tls_cert("localhost", &server_seed).unwrap();

        // Generate client key (simulating a different domain)
        let (client_vk, client_sk) = crypto::generate_ed25519_keypair();
        let client_seed = client_sk.to_bytes();
        let client_fp = crypto::fingerprint(client_vk.as_bytes());
        let (client_cert_der, client_key_der) =
            generate_domain_tls_cert("client.example.com", &client_seed).unwrap();

        // Server config: expects client fingerprint directly (bypassing DNS for test)
        let server_certs = vec![CertificateDer::from(server_cert_der)];
        let server_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key_der));

        // For this test, we use a simple verifier that has known fingerprints
        // rather than DNS lookup. The FingerprintClientCertVerifier does DNS,
        // which won't work in a unit test. We test domain extraction + fingerprint
        // matching separately.
        let test_verifier = Arc::new(TestClientCertVerifier {
            expected_fingerprints: vec![client_fp],
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        });
        let server_config = Arc::new(
            rustls::ServerConfig::builder()
                .with_client_cert_verifier(test_verifier)
                .with_single_cert(server_certs, server_key)
                .unwrap(),
        );

        // Client config: presents cert, verifies server fingerprint
        let client_config =
            build_client_config_with_cert(vec![server_fp], client_cert_der, client_key_der)
                .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_thread = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(server_config).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, stream);

            let mut buf = [0u8; 6];
            tls.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"mutual");
            tls.write_all(b"tls-ok").unwrap();
            tls.flush().unwrap();
        });

        let stream = std::net::TcpStream::connect(addr).unwrap();
        let server_name = ServerName::try_from("localhost").unwrap();
        let conn = rustls::ClientConnection::new(client_config, server_name).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, stream);

        tls.write_all(b"mutual").unwrap();
        tls.flush().unwrap();
        let mut buf = [0u8; 6];
        tls.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"tls-ok");

        server_thread.join().unwrap();
    }

    /// Test-only ClientCertVerifier with hardcoded fingerprints (no DNS).
    #[derive(Debug)]
    struct TestClientCertVerifier {
        expected_fingerprints: Vec<String>,
        provider: Arc<rustls::crypto::CryptoProvider>,
    }

    impl rustls::server::danger::ClientCertVerifier for TestClientCertVerifier {
        fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
            &[]
        }

        fn verify_client_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            now: UnixTime,
        ) -> Result<ClientCertVerified, rustls::Error> {
            let (_, cert) =
                x509_parser::parse_x509_certificate(end_entity.as_ref()).map_err(|_| {
                    rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
                })?;

            let validity = &cert.tbs_certificate.validity;
            let now_secs = now.as_secs();
            let not_before = validity.not_before.timestamp() as u64;
            let not_after = validity.not_after.timestamp() as u64;
            if now_secs < not_before || now_secs > not_after {
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::Expired,
                ));
            }

            let spki = cert.tbs_certificate.subject_pki;
            let public_key_bytes = spki.subject_public_key.data;
            let fp = liblinkkeys::crypto::fingerprint(&public_key_bytes);

            if self.expected_fingerprints.contains(&fp) {
                Ok(ClientCertVerified::assertion())
            } else {
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ))
            }
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.provider
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}
