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
    /// The signing key has been revoked.
    KeyRevoked(String),
    /// The signing key has expired (past its `expires_at`) or has an
    /// unparseable `expires_at`.
    KeyExpired(String),
    DeserializationFailed(String),
    Crypto(CryptoError),
}

/// Reject a signing key that is revoked or expired at verification time.
/// Shared by every verify path that resolves a key by id.
pub fn check_signing_key_valid(key: &DomainPublicKey) -> Result<(), VerifyError> {
    // SEC-13b: only a signing key may authenticate signed protocol data. An
    // encryption key that happens to share a key_id must never be accepted as a
    // signer. Today algorithm binding also catches this (an x25519 key fails
    // resolve_and_verify), but that is an implicit invariant; gate it explicitly
    // here so every verify path that consults key validity is protected.
    if key.key_usage != "sign" {
        return Err(VerifyError::SignatureInvalid);
    }
    match crypto::signing_key_validity(&key.expires_at, key.revoked_at.as_deref()) {
        crypto::KeyValidity::Valid => Ok(()),
        crypto::KeyValidity::Revoked => Err(VerifyError::KeyRevoked(key.key_id.clone())),
        crypto::KeyValidity::Expired | crypto::KeyValidity::BadExpiry => {
            Err(VerifyError::KeyExpired(key.key_id.clone()))
        }
    }
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
            VerifyError::KeyRevoked(id) => write!(f, "signing key has been revoked: {}", id),
            VerifyError::KeyExpired(id) => write!(f, "signing key has expired: {}", id),
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

/// Domain-separation tag for the identity-assertion signature payload. The
/// `-v1alpha` suffix is the pre-alpha protocol EPOCH, not a per-change counter —
/// same convention as every other signed structure (see `claims`, `revocation`).
/// `pub` so conformance-vector generation and consumers can reference the exact
/// tag string rather than retyping it.
pub const ASSERTION_PAYLOAD_TAG: &str = "linkkeys-identity-assertion-v1alpha";

/// The canonical bytes an assertion signature covers: the domain-separation tag
/// and the assertion's CBOR bytes, as a deterministic two-element CBOR array.
///
/// The assertion itself stays an opaque byte string inside the payload rather
/// than being re-encoded structurally, so a verifier signs and checks over the
/// exact bytes it received — decoding happens only after the signature holds.
///
/// `pub` so conformance-vector generation and consumer-zero tests can compute
/// the exact signed bytes without duplicating this construction.
pub fn assertion_sign_payload(assertion_bytes: &[u8]) -> Vec<u8> {
    let payload = (
        ASSERTION_PAYLOAD_TAG,
        serde_bytes::Bytes::new(assertion_bytes),
    );
    let mut out = Vec::new();
    ciborium::ser::into_writer(&payload, &mut out)
        .expect("CBOR serialization of assertion payload cannot fail");
    out
}

pub fn build_assertion(
    user_id: &str,
    domain: &str,
    audience: &str,
    nonce: &str,
    display_name: Option<&str>,
    ttl_seconds: u64,
    authorized_claims: Vec<String>,
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
        authorized_claims,
        display_name: display_name.map(|s| s.to_string()),
    }
}

/// Sign an identity assertion with a domain key.
/// The assertion is CBOR-encoded and its bytes become the `assertion` field in
/// the signed envelope; the signature covers the tagged payload built from those
/// bytes by [`assertion_sign_payload`].
pub fn sign_assertion(
    assertion: &IdentityAssertion,
    key_id: &str,
    algorithm: SigningAlgorithm,
    private_key_bytes: &[u8],
) -> Result<SignedIdentityAssertion, CryptoError> {
    let assertion_bytes = crate::generated::encode_identity_assertion(assertion);

    let payload = assertion_sign_payload(&assertion_bytes);
    let signature = crypto::sign_with_algorithm(algorithm, &payload, private_key_bytes)?;

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

    // Reject revoked/expired keys before trusting anything they signed.
    check_signing_key_valid(key)?;

    // Verify over the tagged payload built from the bytes AS RECEIVED; decoding
    // happens only after the signature holds.
    let payload = assertion_sign_payload(&signed.assertion);
    crypto::resolve_and_verify(&key.algorithm, &payload, &signed.signature, &key.public_key)
        .map_err(|e| match e {
            CryptoError::UnsupportedAlgorithm(alg) => VerifyError::UnsupportedAlgorithm(alg),
            _ => VerifyError::SignatureInvalid,
        })?;

    let assertion = crate::generated::decode_identity_assertion(signed.assertion.as_slice())
        .map_err(|e| VerifyError::DeserializationFailed(format!("CBOR decode failed: {}", e)))?;

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
            key_usage: "sign".to_string(),
            signed_by_key_id: None,
            key_signature: None,
            created_at: Utc::now().to_rfc3339(),
            expires_at: (Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
            revoked_at: None,
        }
    }

    #[test]
    fn test_assertion_sign_verify_roundtrip() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let domain_key = make_domain_key("key-1", &pk);

        let assertion = build_assertion(
            "user-123",
            "example.com",
            "app.example.com",
            "nonce-abc",
            Some("Alice"),
            300,
            vec!["email".to_string()],
        );

        let signed = sign_assertion(&assertion, "key-1", SigningAlgorithm::Ed25519, &sk).unwrap();
        let verified = verify_assertion(&signed, &[domain_key]).unwrap();

        assert_eq!(verified.user_id, "user-123");
        assert_eq!(verified.domain, "example.com");
        assert_eq!(verified.audience, "app.example.com");
        assert_eq!(verified.nonce, "nonce-abc");
        assert_eq!(verified.display_name.as_deref(), Some("Alice"));
        assert_eq!(verified.authorized_claims, vec!["email".to_string()]);
    }

    #[test]
    fn test_assertion_expired_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let domain_key = make_domain_key("key-1", &pk);

        let assertion = build_assertion(
            "user-123",
            "example.com",
            "app.example.com",
            "nonce",
            None,
            0,
            vec![],
        );
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

        let assertion = build_assertion(
            "user-123",
            "example.com",
            "app.example.com",
            "nonce",
            None,
            300,
            vec![],
        );
        let signed = sign_assertion(&assertion, "key-1", SigningAlgorithm::Ed25519, &sk1).unwrap();

        let result = verify_assertion(&signed, &[domain_key]);
        assert!(matches!(result, Err(VerifyError::KeyNotFound(_))));
    }

    #[test]
    fn test_assertion_tampered_signature_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let domain_key = make_domain_key("key-1", &pk);

        let assertion = build_assertion(
            "user-123",
            "example.com",
            "app.example.com",
            "nonce",
            None,
            300,
            vec![],
        );
        let mut signed =
            sign_assertion(&assertion, "key-1", SigningAlgorithm::Ed25519, &sk).unwrap();

        if let Some(byte) = signed.assertion.first_mut() {
            *byte ^= 0xff;
        }

        let result = verify_assertion(&signed, &[domain_key]);
        assert!(matches!(result, Err(VerifyError::SignatureInvalid)));
    }

    #[test]
    fn test_assertion_revoked_key_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let mut domain_key = make_domain_key("key-1", &pk);
        domain_key.revoked_at = Some(Utc::now().to_rfc3339());

        let assertion = build_assertion(
            "user-123",
            "example.com",
            "app.example.com",
            "nonce",
            None,
            300,
            vec![],
        );
        let signed = sign_assertion(&assertion, "key-1", SigningAlgorithm::Ed25519, &sk).unwrap();

        let result = verify_assertion(&signed, &[domain_key]);
        assert!(matches!(result, Err(VerifyError::KeyRevoked(_))));
    }

    #[test]
    fn test_assertion_expired_key_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let mut domain_key = make_domain_key("key-1", &pk);
        domain_key.expires_at = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();

        let assertion = build_assertion(
            "user-123",
            "example.com",
            "app.example.com",
            "nonce",
            None,
            300,
            vec![],
        );
        let signed = sign_assertion(&assertion, "key-1", SigningAlgorithm::Ed25519, &sk).unwrap();

        let result = verify_assertion(&signed, &[domain_key]);
        assert!(matches!(result, Err(VerifyError::KeyExpired(_))));
    }

    #[test]
    fn test_assertion_unsupported_algorithm_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let mut domain_key = make_domain_key("key-1", &pk);
        domain_key.algorithm = "dilithium3".to_string();

        let assertion = build_assertion(
            "user-123",
            "example.com",
            "app.example.com",
            "nonce",
            None,
            300,
            vec![],
        );
        let signed = sign_assertion(&assertion, "key-1", SigningAlgorithm::Ed25519, &sk).unwrap();

        let result = verify_assertion(&signed, &[domain_key]);
        assert!(matches!(result, Err(VerifyError::UnsupportedAlgorithm(_))));
    }

    /// Domain separation is enforced, not incidental: a signature over the bare
    /// assertion CBOR — the pre-tag format — must NOT verify. This is the
    /// regression guard against silently reverting to an untagged payload.
    #[test]
    fn untagged_signature_is_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let domain_key = make_domain_key("key-1", &pk);

        let assertion = build_assertion(
            "user-123",
            "example.com",
            "app.example.com",
            "nonce",
            None,
            300,
            vec![],
        );
        let assertion_bytes = crate::generated::encode_identity_assertion(&assertion);

        // Sign the raw bytes directly, bypassing the tagged payload.
        let signature =
            crypto::sign_with_algorithm(SigningAlgorithm::Ed25519, &assertion_bytes, &sk).unwrap();
        let forged = SignedIdentityAssertion {
            assertion: assertion_bytes,
            signing_key_id: "key-1".to_string(),
            signature,
        };

        assert!(matches!(
            verify_assertion(&forged, &[domain_key]),
            Err(VerifyError::SignatureInvalid)
        ));
    }

    /// The signed payload actually carries the tag, so a consumer in another
    /// language can reproduce the exact bytes.
    #[test]
    fn assertion_payload_carries_the_tag() {
        let payload = assertion_sign_payload(b"opaque-assertion-bytes");
        let (tag, body): (String, serde_bytes::ByteBuf) =
            ciborium::de::from_reader(payload.as_slice()).unwrap();
        assert_eq!(tag, ASSERTION_PAYLOAD_TAG);
        assert_eq!(body.as_ref(), b"opaque-assertion-bytes");
    }
}
