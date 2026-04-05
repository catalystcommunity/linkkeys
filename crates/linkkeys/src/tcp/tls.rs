use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::SignatureScheme;
use std::sync::Arc;

/// PKCS8 v1 DER prefix for Ed25519 private keys (RFC 8410).
/// This is the fixed ASN.1 encoding: SEQUENCE { version=0, algorithm=Ed25519, OCTET STRING { seed } }
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, // SEQUENCE, 46 bytes total
    0x02, 0x01, 0x00, // INTEGER version = 0
    0x30, 0x05, // SEQUENCE (AlgorithmIdentifier)
    0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
    0x04, 0x22, // OCTET STRING, 34 bytes
    0x04, 0x20, // OCTET STRING, 32 bytes (the seed)
];

/// Wrap a 32-byte Ed25519 seed in PKCS8 v1 DER format.
fn ed25519_seed_to_pkcs8_der(seed: &[u8; 32]) -> Vec<u8> {
    let mut der = Vec::with_capacity(48);
    der.extend_from_slice(&ED25519_PKCS8_PREFIX);
    der.extend_from_slice(seed);
    der
}

/// Generate a self-signed TLS certificate from a domain Ed25519 key.
/// The certificate's public key will match the domain key, so its fingerprint
/// is already published in DNS.
pub fn generate_domain_tls_cert(
    domain_name: &str,
    ed25519_seed: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let pkcs8_der = ed25519_seed_to_pkcs8_der(ed25519_seed);
    let key_pair = rcgen::KeyPair::try_from(pkcs8_der.as_slice())?;

    let mut params = rcgen::CertificateParams::new(vec![domain_name.to_string()])?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, domain_name);

    let cert = params.self_signed(&key_pair)?;

    Ok((cert.der().to_vec(), pkcs8_der))
}

/// Build a rustls ServerConfig with the domain certificate.
pub fn build_server_config(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error>> {
    let certs = vec![CertificateDer::from(cert_der)];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(Arc::new(config))
}

/// Custom ServerCertVerifier that checks the certificate's public key fingerprint
/// against expected fingerprints (from DNS TXT records).
/// This replaces CA chain verification — trust is rooted in DNS-published fingerprints.
#[derive(Debug)]
pub struct FingerprintVerifier {
    expected_fingerprints: Vec<String>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl FingerprintVerifier {
    pub fn new(expected_fingerprints: Vec<String>) -> Self {
        Self {
            expected_fingerprints,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Parse the certificate to extract the public key and validity period
        let (_, cert) = x509_parser::parse_x509_certificate(end_entity.as_ref())
            .map_err(|_| {
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

        // Extract the raw public key bytes from SubjectPublicKeyInfo
        let spki = cert.tbs_certificate.subject_pki;
        let public_key_bytes = spki.subject_public_key.data;

        // Compute fingerprint (SHA-256 hex)
        let fp = liblinkkeys::crypto::fingerprint(&public_key_bytes);

        if self.expected_fingerprints.contains(&fp) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            log::warn!(
                "Certificate fingerprint {} does not match any expected fingerprint",
                fp
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

/// Build a rustls ClientConfig that uses fingerprint-based verification
/// instead of CA chain verification.
pub fn build_client_config(
    expected_fingerprints: Vec<String>,
) -> Result<Arc<rustls::ClientConfig>, Box<dyn std::error::Error>> {
    let verifier = FingerprintVerifier::new(expected_fingerprints);

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use liblinkkeys::crypto;
    use rustls::client::danger::ServerCertVerifier;

    #[test]
    fn test_ed25519_seed_to_pkcs8_roundtrip() {
        let (_, sk) = crypto::generate_ed25519_keypair();
        let seed = sk.to_bytes();
        let pkcs8 = ed25519_seed_to_pkcs8_der(&seed);
        // Verify rcgen can parse it
        let key_pair = rcgen::KeyPair::try_from(pkcs8.as_slice());
        assert!(key_pair.is_ok(), "rcgen should accept PKCS8 DER");
    }

    #[test]
    fn test_generate_cert_fingerprint_matches() {
        let (vk, sk) = crypto::generate_ed25519_keypair();
        let seed = sk.to_bytes();
        let expected_fp = crypto::fingerprint(vk.as_bytes());

        let (cert_der, _key_der) =
            generate_domain_tls_cert("test.example.com", &seed).unwrap();

        // Parse the cert and extract the public key
        let (_, cert) = x509_parser::parse_x509_certificate(&cert_der).unwrap();
        let spki = cert.tbs_certificate.subject_pki;
        let pub_key_bytes = spki.subject_public_key.data;
        let cert_fp = crypto::fingerprint(&pub_key_bytes);

        assert_eq!(
            expected_fp, cert_fp,
            "Cert public key fingerprint must match domain key fingerprint"
        );
    }

    #[test]
    fn test_fingerprint_verifier_accepts_matching() {
        let (vk, sk) = crypto::generate_ed25519_keypair();
        let seed = sk.to_bytes();
        let fp = crypto::fingerprint(vk.as_bytes());

        let (cert_der, _) = generate_domain_tls_cert("test.example.com", &seed).unwrap();
        let cert = CertificateDer::from(cert_der);

        let verifier = FingerprintVerifier::new(vec![fp]);
        let result = verifier.verify_server_cert(
            &cert,
            &[],
            &ServerName::try_from("test.example.com").unwrap(),
            &[],
            UnixTime::now(),
        );
        assert!(result.is_ok(), "Should accept matching fingerprint");
    }

    #[test]
    fn test_fingerprint_verifier_rejects_wrong() {
        let (_, sk) = crypto::generate_ed25519_keypair();
        let seed = sk.to_bytes();

        let (cert_der, _) = generate_domain_tls_cert("test.example.com", &seed).unwrap();
        let cert = CertificateDer::from(cert_der);

        let verifier = FingerprintVerifier::new(vec!["wrong_fingerprint".to_string()]);
        let result = verifier.verify_server_cert(
            &cert,
            &[],
            &ServerName::try_from("test.example.com").unwrap(),
            &[],
            UnixTime::now(),
        );
        assert!(result.is_err(), "Should reject wrong fingerprint");
    }

    #[test]
    fn test_fingerprint_verifier_rejects_empty() {
        let (_, sk) = crypto::generate_ed25519_keypair();
        let seed = sk.to_bytes();

        let (cert_der, _) = generate_domain_tls_cert("test.example.com", &seed).unwrap();
        let cert = CertificateDer::from(cert_der);

        let verifier = FingerprintVerifier::new(vec![]);
        let result = verifier.verify_server_cert(
            &cert,
            &[],
            &ServerName::try_from("test.example.com").unwrap(),
            &[],
            UnixTime::now(),
        );
        assert!(result.is_err(), "Should reject with empty fingerprint list");
    }

    #[test]
    fn test_build_server_config_succeeds() {
        let (_, sk) = crypto::generate_ed25519_keypair();
        let seed = sk.to_bytes();
        let (cert_der, key_der) = generate_domain_tls_cert("test.example.com", &seed).unwrap();
        let config = build_server_config(cert_der, key_der);
        assert!(config.is_ok(), "Server config should build successfully");
    }

    #[test]
    fn test_tls_handshake_roundtrip() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let (vk, sk) = crypto::generate_ed25519_keypair();
        let seed = sk.to_bytes();
        let fp = crypto::fingerprint(vk.as_bytes());

        let (cert_der, key_der) =
            generate_domain_tls_cert("localhost", &seed).unwrap();
        let server_config = build_server_config(cert_der, key_der).unwrap();
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
}
