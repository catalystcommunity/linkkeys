use crate::crypto::{self, CryptoError, SigningAlgorithm};
use crate::generated::types::{DomainPublicKey, IdentityAssertion, SignedIdentityAssertion};
use chrono::Utc;
use std::fmt;

#[derive(Debug)]
pub enum VerifyError {
    KeyNotFound(String),
    SignatureInvalid,
    UnsupportedAlgorithm(String),
    Expired,
    DeserializationFailed(String),
    Crypto(CryptoError),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::KeyNotFound(id) => write!(f, "signing key not found: {}", id),
            VerifyError::SignatureInvalid => write!(f, "signature verification failed"),
            VerifyError::UnsupportedAlgorithm(alg) => {
                write!(f, "unsupported signing algorithm: {}", alg)
            }
            VerifyError::Expired => write!(f, "assertion has expired"),
            VerifyError::DeserializationFailed(msg) => {
                write!(f, "failed to deserialize assertion: {}", msg)
            }
            VerifyError::Crypto(e) => write!(f, "crypto error: {}", e),
        }
    }
}

impl std::error::Error for VerifyError {}

impl From<CryptoError> for VerifyError {
    fn from(e: CryptoError) -> Self {
        VerifyError::Crypto(e)
    }
}

pub fn build_assertion(
    user_id: &str,
    domain: &str,
    audience: &str,
    nonce: &str,
    display_name: Option<&str>,
    ttl_seconds: u64,
) -> IdentityAssertion {
    let now = Utc::now();
    let expires = now + chrono::Duration::seconds(ttl_seconds as i64);
    IdentityAssertion {
        user_id: user_id.to_string(),
        domain: domain.to_string(),
        audience: audience.to_string(),
        nonce: nonce.to_string(),
        issued_at: now.to_rfc3339(),
        expires_at: expires.to_rfc3339(),
        display_name: display_name.map(|s| s.to_string()),
    }
}

/// Sign an identity assertion with a domain key.
/// The assertion is CBOR-encoded, then signed. The raw CBOR bytes become
/// the `assertion` field in the signed envelope.
pub fn sign_assertion(
    assertion: &IdentityAssertion,
    key_id: &str,
    algorithm: SigningAlgorithm,
    private_key_bytes: &[u8],
) -> Result<SignedIdentityAssertion, CryptoError> {
    let mut assertion_bytes = Vec::new();
    ciborium::ser::into_writer(assertion, &mut assertion_bytes)
        .map_err(|e| CryptoError::SigningFailed(format!("CBOR encode failed: {}", e)))?;

    let signature = crypto::sign_with_algorithm(algorithm, &assertion_bytes, private_key_bytes)?;

    Ok(SignedIdentityAssertion {
        assertion: assertion_bytes,
        signing_key_id: key_id.to_string(),
        signature,
    })
}

/// Verify a signed identity assertion against a set of domain public keys.
/// Returns the deserialized assertion if the signature is valid and the
/// assertion has not expired. The caller should additionally check
/// the nonce and audience fields.
pub fn verify_assertion(
    signed: &SignedIdentityAssertion,
    public_keys: &[DomainPublicKey],
) -> Result<IdentityAssertion, VerifyError> {
    let key = public_keys
        .iter()
        .find(|k| k.key_id == signed.signing_key_id)
        .ok_or_else(|| VerifyError::KeyNotFound(signed.signing_key_id.clone()))?;

    crypto::resolve_and_verify(
        &key.algorithm,
        &signed.assertion,
        &signed.signature,
        &key.public_key,
    )
    .map_err(|e| match e {
        CryptoError::UnsupportedAlgorithm(alg) => VerifyError::UnsupportedAlgorithm(alg),
        _ => VerifyError::SignatureInvalid,
    })?;

    let assertion: IdentityAssertion =
        ciborium::de::from_reader(signed.assertion.as_slice()).map_err(|e| {
            VerifyError::DeserializationFailed(format!("CBOR decode failed: {}", e))
        })?;

    let expires_at = chrono::DateTime::parse_from_rfc3339(&assertion.expires_at)
        .map_err(|e| VerifyError::DeserializationFailed(format!("invalid expires_at: {}", e)))?;

    if Utc::now() > expires_at {
        return Err(VerifyError::Expired);
    }

    Ok(assertion)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{fingerprint, generate_keypair, ALGORITHM_ED25519};

    fn make_domain_key(key_id: &str, pk_bytes: &[u8]) -> DomainPublicKey {
        DomainPublicKey {
            key_id: key_id.to_string(),
            public_key: pk_bytes.to_vec(),
            fingerprint: fingerprint(pk_bytes),
            algorithm: ALGORITHM_ED25519.to_string(),
            created_at: Utc::now().to_rfc3339(),
            expires_at: (Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
            revoked_at: None,
        }
    }

    #[test]
    fn test_assertion_sign_verify_roundtrip() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let domain_key = make_domain_key("key-1", &pk);

        let assertion =
            build_assertion("user-123", "example.com", "app.example.com", "nonce-abc", Some("Alice"), 300);

        let signed = sign_assertion(&assertion, "key-1", SigningAlgorithm::Ed25519, &sk).unwrap();
        let verified = verify_assertion(&signed, &[domain_key]).unwrap();

        assert_eq!(verified.user_id, "user-123");
        assert_eq!(verified.domain, "example.com");
        assert_eq!(verified.audience, "app.example.com");
        assert_eq!(verified.nonce, "nonce-abc");
        assert_eq!(verified.display_name.as_deref(), Some("Alice"));
    }

    #[test]
    fn test_assertion_expired_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let domain_key = make_domain_key("key-1", &pk);

        let assertion = build_assertion("user-123", "example.com", "app.example.com", "nonce", None, 0);
        let signed = sign_assertion(&assertion, "key-1", SigningAlgorithm::Ed25519, &sk).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(10));

        let result = verify_assertion(&signed, &[domain_key]);
        assert!(matches!(result, Err(VerifyError::Expired)));
    }

    #[test]
    fn test_assertion_wrong_key_rejected() {
        let (_pk1, sk1) = generate_keypair(SigningAlgorithm::Ed25519);
        let (pk2, _sk2) = generate_keypair(SigningAlgorithm::Ed25519);
        let domain_key = make_domain_key("key-2", &pk2);

        let assertion = build_assertion("user-123", "example.com", "app.example.com", "nonce", None, 300);
        let signed = sign_assertion(&assertion, "key-1", SigningAlgorithm::Ed25519, &sk1).unwrap();

        let result = verify_assertion(&signed, &[domain_key]);
        assert!(matches!(result, Err(VerifyError::KeyNotFound(_))));
    }

    #[test]
    fn test_assertion_tampered_signature_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let domain_key = make_domain_key("key-1", &pk);

        let assertion = build_assertion("user-123", "example.com", "app.example.com", "nonce", None, 300);
        let mut signed = sign_assertion(&assertion, "key-1", SigningAlgorithm::Ed25519, &sk).unwrap();

        if let Some(byte) = signed.assertion.first_mut() {
            *byte ^= 0xff;
        }

        let result = verify_assertion(&signed, &[domain_key]);
        assert!(matches!(result, Err(VerifyError::SignatureInvalid)));
    }

    #[test]
    fn test_assertion_unsupported_algorithm_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let mut domain_key = make_domain_key("key-1", &pk);
        domain_key.algorithm = "dilithium3".to_string();

        let assertion = build_assertion("user-123", "example.com", "app.example.com", "nonce", None, 300);
        let signed = sign_assertion(&assertion, "key-1", SigningAlgorithm::Ed25519, &sk).unwrap();

        let result = verify_assertion(&signed, &[domain_key]);
        assert!(matches!(result, Err(VerifyError::UnsupportedAlgorithm(_))));
    }
}
