use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::danger::ClientCertVerified;
use rustls::SignatureScheme;
use std::sync::Arc;

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
    runtime: Arc<tokio::runtime::Runtime>,
    dns: Arc<dyn crate::net::DnsResolver>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl FingerprintClientCertVerifier {
    /// `dns` is the resolver the verifier consults *inside the handshake* to pin
    /// the connecting client's cert to its domain's DNS `fp=` set — real in
    /// production, a static fake in tests. The lookup is blocking (rustls's
    /// verifier trait is synchronous), driven on `runtime`.
    pub fn new(
        runtime: Arc<tokio::runtime::Runtime>,
        dns: Arc<dyn crate::net::DnsResolver>,
    ) -> Self {
        Self {
            runtime,
            dns,
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

        // Resolve the client domain's fingerprints from DNS (through the seam).
        let expected_fingerprints =
            crate::dns::resolve_fingerprints_with(&self.runtime, self.dns.as_ref(), &domain)
                .map_err(|e| {
                    log::warn!("DNS fingerprint resolution failed for {}: {}", domain, e);
                    rustls::Error::InvalidCertificate(
                        rustls::CertificateError::ApplicationVerificationFailure,
                    )
                })?;

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

        let runtime = Arc::new(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
        let verifier = Arc::new(FingerprintClientCertVerifier::new(
            runtime,
            crate::net::Net::production().dns,
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
