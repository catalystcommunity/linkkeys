use crate::crypto::{self, CryptoError, SigningAlgorithm};
use crate::generated::types::{Claim, DomainPublicKey};
use chrono::Utc;
use std::fmt;

#[derive(Debug)]
pub enum ClaimError {
    SignatureInvalid,
    UnsupportedAlgorithm(String),
    KeyNotFound(String),
    /// The domain key that signed the claim is revoked.
    KeyRevoked(String),
    /// The domain key that signed the claim is expired / has bad expiry.
    KeyExpired(String),
    /// The claim itself has been revoked.
    Revoked,
    /// The claim itself has expired (past its signed `expires_at`).
    Expired,
    /// The claim's `expires_at` could not be parsed.
    BadExpiry,
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
            ClaimError::KeyRevoked(id) => write!(f, "signing key has been revoked: {}", id),
            ClaimError::KeyExpired(id) => write!(f, "signing key has expired: {}", id),
            ClaimError::Revoked => write!(f, "claim has been revoked"),
            ClaimError::Expired => write!(f, "claim has expired"),
            ClaimError::BadExpiry => write!(f, "claim has an invalid expires_at"),
            ClaimError::Crypto(e) => write!(f, "crypto error: {}", e),
        }
    }
}

impl std::error::Error for ClaimError {}

/// Domain-separation tag + version for the claim signature payload. Bumping
/// this invalidates old signatures by design (versioned construction).
const CLAIM_PAYLOAD_TAG: &str = "linkkeys-claim-v1";

/// Build the canonical bytes that get signed for a claim.
///
/// Uses CBOR encoding for an unambiguous, deterministic payload even when
/// `claim_value` contains arbitrary bytes (including nulls). The signed payload
/// binds `claim_id` and `expires_at` in addition to the core (type/value/user)
/// so expiry and identity are tamper-evident — an attacker cannot extend a
/// claim's life or re-id it without breaking the signature.
///
/// `expires_at` must be stored and served byte-identical to what was signed
/// (the caller normalizes it to whole-second RFC3339 so it round-trips through
/// both Postgres timestamptz and SQLite text). `created_at` is deliberately NOT
/// signed — it is assigned by the database on insert, so signing it would make
/// the stored claim unverifiable.
///
/// Note: the issuing *domain* is bound implicitly via `signed_by_key_id` →
/// key → domain ownership at fetch time. An explicit issuer-domain field is a
/// CSIL/schema change deferred to the key-model work (see sec-explore/db-02).
fn claim_sign_payload(
    claim_id: &str,
    claim_type: &str,
    claim_value: &[u8],
    user_id: &str,
    expires_at: Option<&str>,
) -> Vec<u8> {
    // Use a tuple for deterministic CBOR encoding.
    let payload = (
        CLAIM_PAYLOAD_TAG,
        claim_id,
        claim_type,
        serde_bytes::Bytes::new(claim_value),
        user_id,
        expires_at,
    );
    let mut out = Vec::new();
    ciborium::ser::into_writer(&payload, &mut out)
        .expect("CBOR serialization of claim payload cannot fail");
    out
}

/// What is being claimed: the borrowed pieces that go into a `Claim`
/// independent of *who* is signing it.
pub struct ClaimSpec<'a> {
    pub claim_id: &'a str,
    pub claim_type: &'a str,
    pub claim_value: &'a [u8],
    pub user_id: &'a str,
    pub expires_at: Option<&'a str>,
}

pub fn sign_claim(
    spec: &ClaimSpec<'_>,
    key_id: &str,
    algorithm: SigningAlgorithm,
    private_key_bytes: &[u8],
) -> Result<Claim, CryptoError> {
    let payload = claim_sign_payload(
        spec.claim_id,
        spec.claim_type,
        spec.claim_value,
        spec.user_id,
        spec.expires_at,
    );
    let signature = crypto::sign_with_algorithm(algorithm, &payload, private_key_bytes)?;

    Ok(Claim {
        claim_id: spec.claim_id.to_string(),
        user_id: spec.user_id.to_string(),
        claim_type: spec.claim_type.to_string(),
        claim_value: spec.claim_value.to_vec(),
        signed_by_key_id: key_id.to_string(),
        signature,
        created_at: Utc::now().to_rfc3339(),
        expires_at: spec.expires_at.map(|s| s.to_string()),
        revoked_at: None,
    })
}

/// Verify a claim: signing-key validity, signature over the bound payload, and
/// the claim's own revocation/expiry. All four must pass.
pub fn verify_claim(claim: &Claim, public_keys: &[DomainPublicKey]) -> Result<(), ClaimError> {
    let key = public_keys
        .iter()
        .find(|k| k.key_id == claim.signed_by_key_id)
        .ok_or_else(|| ClaimError::KeyNotFound(claim.signed_by_key_id.clone()))?;

    // Reject claims signed by a revoked/expired domain key.
    match crypto::signing_key_validity(&key.expires_at, key.revoked_at.as_deref()) {
        crypto::KeyValidity::Valid => {}
        crypto::KeyValidity::Revoked => return Err(ClaimError::KeyRevoked(key.key_id.clone())),
        crypto::KeyValidity::Expired | crypto::KeyValidity::BadExpiry => {
            return Err(ClaimError::KeyExpired(key.key_id.clone()))
        }
    }

    let payload = claim_sign_payload(
        &claim.claim_id,
        &claim.claim_type,
        &claim.claim_value,
        &claim.user_id,
        claim.expires_at.as_deref(),
    );
    crypto::resolve_and_verify(&key.algorithm, &payload, &claim.signature, &key.public_key)
        .map_err(|e| match e {
            CryptoError::UnsupportedAlgorithm(alg) => ClaimError::UnsupportedAlgorithm(alg),
            _ => ClaimError::SignatureInvalid,
        })?;

    // Enforce the claim's own revocation and expiry (now tamper-evident,
    // since expires_at is part of the signed payload).
    if claim.revoked_at.is_some() {
        return Err(ClaimError::Revoked);
    }
    if let Some(exp) = claim.expires_at.as_deref() {
        let expires = chrono::DateTime::parse_from_rfc3339(exp).map_err(|_| ClaimError::BadExpiry)?;
        if Utc::now() > expires {
            return Err(ClaimError::Expired);
        }
    }

    Ok(())
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
            key_usage: "sign".to_string(),
            signed_by_key_id: None,
            key_signature: None,
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
            &ClaimSpec {
                claim_id: "claim-1",
                claim_type: "email",
                claim_value: b"alice@example.com",
                user_id: "user-123",
                expires_at: None,
            },
            "key-1",
            SigningAlgorithm::Ed25519,
            &sk,
        )
        .unwrap();

        assert!(verify_claim(&claim, &[domain_key]).is_ok());
    }

    #[test]
    fn test_claim_tampered_value_fails() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let domain_key = make_domain_key("key-1", &pk);

        let mut claim = sign_claim(
            &ClaimSpec {
                claim_id: "claim-1",
                claim_type: "email",
                claim_value: b"alice@example.com",
                user_id: "user-123",
                expires_at: None,
            },
            "key-1",
            SigningAlgorithm::Ed25519,
            &sk,
        )
        .unwrap();

        claim.claim_value = b"eve@evil.com".to_vec();
        assert!(matches!(verify_claim(&claim, &[domain_key]), Err(ClaimError::SignatureInvalid)));
    }

    #[test]
    fn test_claim_wrong_key_fails() {
        let (_pk1, sk1) = generate_keypair(SigningAlgorithm::Ed25519);
        let (pk2, _sk2) = generate_keypair(SigningAlgorithm::Ed25519);
        let domain_key = make_domain_key("key-2", &pk2);

        let claim = sign_claim(
            &ClaimSpec {
                claim_id: "claim-1",
                claim_type: "role",
                claim_value: b"admin",
                user_id: "user-123",
                expires_at: None,
            },
            "key-1",
            SigningAlgorithm::Ed25519,
            &sk1,
        )
        .unwrap();

        assert!(matches!(verify_claim(&claim, &[domain_key]), Err(ClaimError::KeyNotFound(_))));
    }

    #[test]
    fn test_claim_tampered_type_fails() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let domain_key = make_domain_key("key-1", &pk);

        let mut claim = sign_claim(
            &ClaimSpec {
                claim_id: "claim-1",
                claim_type: "role",
                claim_value: b"admin",
                user_id: "user-123",
                expires_at: None,
            },
            "key-1",
            SigningAlgorithm::Ed25519,
            &sk,
        )
        .unwrap();

        claim.claim_type = "email".to_string();
        assert!(matches!(verify_claim(&claim, &[domain_key]), Err(ClaimError::SignatureInvalid)));
    }

    fn signed_claim(sk: &[u8], expires_at: Option<&str>) -> Claim {
        sign_claim(
            &ClaimSpec {
                claim_id: "claim-1",
                claim_type: "over-21",
                claim_value: b"true",
                user_id: "user-123",
                expires_at,
            },
            "key-1",
            SigningAlgorithm::Ed25519,
            sk,
        )
        .unwrap()
    }

    #[test]
    fn test_claim_expired_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let domain_key = make_domain_key("key-1", &pk);
        let past = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let claim = signed_claim(&sk, Some(&past));
        assert!(matches!(verify_claim(&claim, &[domain_key]), Err(ClaimError::Expired)));
    }

    #[test]
    fn test_claim_not_yet_expired_ok() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let domain_key = make_domain_key("key-1", &pk);
        let future = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let claim = signed_claim(&sk, Some(&future));
        assert!(verify_claim(&claim, &[domain_key]).is_ok());
    }

    #[test]
    fn test_claim_revoked_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let domain_key = make_domain_key("key-1", &pk);
        let mut claim = signed_claim(&sk, None);
        claim.revoked_at = Some(Utc::now().to_rfc3339());
        assert!(matches!(verify_claim(&claim, &[domain_key]), Err(ClaimError::Revoked)));
    }

    #[test]
    fn test_claim_tampered_expiry_rejected() {
        // expires_at is part of the signed payload, so extending it breaks the signature.
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let domain_key = make_domain_key("key-1", &pk);
        let soon = (Utc::now() + chrono::Duration::minutes(1)).to_rfc3339();
        let mut claim = signed_claim(&sk, Some(&soon));
        claim.expires_at = Some((Utc::now() + chrono::Duration::weeks(520)).to_rfc3339());
        assert!(matches!(verify_claim(&claim, &[domain_key]), Err(ClaimError::SignatureInvalid)));
    }

    #[test]
    fn test_claim_signed_by_revoked_key_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let mut domain_key = make_domain_key("key-1", &pk);
        let claim = signed_claim(&sk, None);
        domain_key.revoked_at = Some(Utc::now().to_rfc3339());
        assert!(matches!(verify_claim(&claim, &[domain_key]), Err(ClaimError::KeyRevoked(_))));
    }

    #[test]
    fn test_claim_signed_by_expired_key_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let mut domain_key = make_domain_key("key-1", &pk);
        let claim = signed_claim(&sk, None);
        domain_key.expires_at = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        assert!(matches!(verify_claim(&claim, &[domain_key]), Err(ClaimError::KeyExpired(_))));
    }

    #[test]
    fn test_claim_unsupported_algorithm_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let mut domain_key = make_domain_key("key-1", &pk);
        domain_key.algorithm = "unknown-alg".to_string();

        let claim = sign_claim(
            &ClaimSpec {
                claim_id: "claim-1",
                claim_type: "role",
                claim_value: b"admin",
                user_id: "user-123",
                expires_at: None,
            },
            "key-1",
            SigningAlgorithm::Ed25519,
            &sk,
        )
        .unwrap();

        assert!(matches!(verify_claim(&claim, &[domain_key]), Err(ClaimError::UnsupportedAlgorithm(_))));
    }
}
