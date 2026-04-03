use crate::crypto::{self, CryptoError, SigningAlgorithm};
use crate::generated::types::{Claim, DomainPublicKey};
use chrono::Utc;
use std::fmt;

#[derive(Debug)]
pub enum ClaimError {
    SignatureInvalid,
    UnsupportedAlgorithm(String),
    KeyNotFound(String),
    Crypto(CryptoError),
}

impl fmt::Display for ClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClaimError::SignatureInvalid => write!(f, "claim signature verification failed"),
            ClaimError::UnsupportedAlgorithm(alg) => {
                write!(f, "unsupported signing algorithm: {}", alg)
            }
            ClaimError::KeyNotFound(id) => write!(f, "signing key not found: {}", id),
            ClaimError::Crypto(e) => write!(f, "crypto error: {}", e),
        }
    }
}

impl std::error::Error for ClaimError {}

/// Build the canonical bytes that get signed for a claim.
/// Uses CBOR encoding for an unambiguous, deterministic payload
/// even when claim_value contains arbitrary bytes (including nulls).
fn claim_sign_payload(claim_type: &str, claim_value: &[u8], user_id: &str) -> Vec<u8> {
    // Use a tuple for deterministic CBOR encoding
    let payload = (claim_type, serde_bytes::Bytes::new(claim_value), user_id);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&payload, &mut out)
        .expect("CBOR serialization of claim payload cannot fail");
    out
}

pub fn sign_claim(
    claim_id: &str,
    claim_type: &str,
    claim_value: &[u8],
    user_id: &str,
    key_id: &str,
    algorithm: SigningAlgorithm,
    private_key_bytes: &[u8],
    expires_at: Option<&str>,
) -> Result<Claim, CryptoError> {
    let payload = claim_sign_payload(claim_type, claim_value, user_id);
    let signature = crypto::sign_with_algorithm(algorithm, &payload, private_key_bytes)?;

    Ok(Claim {
        claim_id: claim_id.to_string(),
        user_id: user_id.to_string(),
        claim_type: claim_type.to_string(),
        claim_value: claim_value.to_vec(),
        signed_by_key_id: key_id.to_string(),
        signature,
        created_at: Utc::now().to_rfc3339(),
        expires_at: expires_at.map(|s| s.to_string()),
        revoked_at: None,
    })
}

pub fn verify_claim(claim: &Claim, public_keys: &[DomainPublicKey]) -> Result<(), ClaimError> {
    let key = public_keys
        .iter()
        .find(|k| k.key_id == claim.signed_by_key_id)
        .ok_or_else(|| ClaimError::KeyNotFound(claim.signed_by_key_id.clone()))?;

    let payload = claim_sign_payload(&claim.claim_type, &claim.claim_value, &claim.user_id);
    crypto::resolve_and_verify(&key.algorithm, &payload, &claim.signature, &key.public_key)
        .map_err(|e| match e {
            CryptoError::UnsupportedAlgorithm(alg) => ClaimError::UnsupportedAlgorithm(alg),
            _ => ClaimError::SignatureInvalid,
        })
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
    fn test_claim_sign_verify_roundtrip() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let domain_key = make_domain_key("key-1", &pk);

        let claim = sign_claim(
            "claim-1", "email", b"alice@example.com", "user-123", "key-1",
            SigningAlgorithm::Ed25519, &sk, None,
        ).unwrap();

        assert!(verify_claim(&claim, &[domain_key]).is_ok());
    }

    #[test]
    fn test_claim_tampered_value_fails() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let domain_key = make_domain_key("key-1", &pk);

        let mut claim = sign_claim(
            "claim-1", "email", b"alice@example.com", "user-123", "key-1",
            SigningAlgorithm::Ed25519, &sk, None,
        ).unwrap();

        claim.claim_value = b"eve@evil.com".to_vec();
        assert!(matches!(verify_claim(&claim, &[domain_key]), Err(ClaimError::SignatureInvalid)));
    }

    #[test]
    fn test_claim_wrong_key_fails() {
        let (_pk1, sk1) = generate_keypair(SigningAlgorithm::Ed25519);
        let (pk2, _sk2) = generate_keypair(SigningAlgorithm::Ed25519);
        let domain_key = make_domain_key("key-2", &pk2);

        let claim = sign_claim(
            "claim-1", "role", b"admin", "user-123", "key-1",
            SigningAlgorithm::Ed25519, &sk1, None,
        ).unwrap();

        assert!(matches!(verify_claim(&claim, &[domain_key]), Err(ClaimError::KeyNotFound(_))));
    }

    #[test]
    fn test_claim_tampered_type_fails() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let domain_key = make_domain_key("key-1", &pk);

        let mut claim = sign_claim(
            "claim-1", "role", b"admin", "user-123", "key-1",
            SigningAlgorithm::Ed25519, &sk, None,
        ).unwrap();

        claim.claim_type = "email".to_string();
        assert!(matches!(verify_claim(&claim, &[domain_key]), Err(ClaimError::SignatureInvalid)));
    }

    #[test]
    fn test_claim_unsupported_algorithm_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let mut domain_key = make_domain_key("key-1", &pk);
        domain_key.algorithm = "unknown-alg".to_string();

        let claim = sign_claim(
            "claim-1", "role", b"admin", "user-123", "key-1",
            SigningAlgorithm::Ed25519, &sk, None,
        ).unwrap();

        assert!(matches!(verify_claim(&claim, &[domain_key]), Err(ClaimError::UnsupportedAlgorithm(_))));
    }
}
