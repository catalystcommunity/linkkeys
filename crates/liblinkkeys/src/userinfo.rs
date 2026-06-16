//! Signed claims-fetch (proof-of-possession) for the /userinfo exchange.
//!
//! A leaked assertion token is a bearer credential: anyone holding it could
//! redeem it at the IDP's /userinfo endpoint. To bind redemption to the
//! relying party named in the assertion's `audience`, the RP wraps the token
//! in a [`UserInfoRequest`] and signs it with its own domain signing key,
//! producing a [`SignedUserInfoRequest`]. The IDP verifies the signature
//! against the RP's DNS-pinned signing keys and requires
//! `relying_party == assertion.audience` before returning any claims.
//!
//! This module is pure protocol: it builds, signs, and verifies the PoP
//! envelope. Resolving the RP's trusted keys (DNS pin / vouch / cache),
//! enforcing the audience match, and single-use nonce burning are the
//! caller's responsibility on the server side.

use crate::assertions::VerifyError;
use crate::crypto::{self, CryptoError, SigningAlgorithm};
use crate::generated::types::{DomainPublicKey, SignedUserInfoRequest, UserInfoRequest};
use chrono::Utc;

/// Build an unsigned user-info request with the current timestamp.
///
/// `token` is the URL-param-encoded sealed assertion the RP received on its
/// callback; `relying_party` is the RP's own domain (must equal the
/// assertion's audience for the IDP to honor the request); `nonce` makes the
/// request single-use at the IDP.
pub fn build_user_info_request(
    token: Vec<u8>,
    relying_party: &str,
    nonce: &str,
) -> UserInfoRequest {
    UserInfoRequest {
        token,
        relying_party: relying_party.to_string(),
        timestamp: Utc::now().to_rfc3339(),
        nonce: nonce.to_string(),
    }
}

/// Sign a user-info request with the RP's domain signing key.
///
/// The request is CBOR-encoded, then signed; the raw CBOR bytes become the
/// `request` field of the envelope. `public_keys`, when present, inlines the
/// RP's published keys so a first-contact IDP can fingerprint-check them
/// against DNS without a separate fetch — they are a hint, never a trust
/// anchor (the IDP still pins them to the RP's DNS `fp=`).
pub fn sign_user_info_request(
    request: &UserInfoRequest,
    key_id: &str,
    algorithm: SigningAlgorithm,
    private_key_bytes: &[u8],
    public_keys: Option<Vec<DomainPublicKey>>,
) -> Result<SignedUserInfoRequest, CryptoError> {
    let mut request_bytes = Vec::new();
    ciborium::ser::into_writer(request, &mut request_bytes)
        .map_err(|e| CryptoError::SigningFailed(format!("CBOR encode failed: {}", e)))?;

    let signature = crypto::sign_with_algorithm(algorithm, &request_bytes, private_key_bytes)?;

    Ok(SignedUserInfoRequest {
        request: request_bytes,
        signing_key_id: key_id.to_string(),
        signature,
        public_keys,
    })
}

/// Verify a signed user-info request against the RP's trusted signing keys.
///
/// Checks: the named key exists among `rp_signing_keys` and is a signing key,
/// the key is not revoked/expired, the signature is valid, and the embedded
/// timestamp is within `max_age_seconds` of now. Returns the deserialized
/// [`UserInfoRequest`] on success.
///
/// The caller MUST additionally enforce `request.relying_party ==
/// assertion.audience` and burn `request.nonce` for single use — this function
/// proves only that the request was produced by a holder of the RP's signing
/// key, not that it targets the right assertion.
pub fn verify_user_info_request(
    signed: &SignedUserInfoRequest,
    rp_signing_keys: &[DomainPublicKey],
    max_age_seconds: i64,
) -> Result<UserInfoRequest, VerifyError> {
    let key = rp_signing_keys
        .iter()
        .find(|k| k.key_id == signed.signing_key_id)
        .ok_or_else(|| VerifyError::KeyNotFound(signed.signing_key_id.clone()))?;

    // Only a signing key can authenticate a request; an encryption key that
    // happens to share the id must never be accepted as a PoP key.
    if key.key_usage != "sign" {
        return Err(VerifyError::SignatureInvalid);
    }

    // Reject revoked/expired keys before trusting anything they signed.
    crate::assertions::check_signing_key_valid(key)?;

    crypto::resolve_and_verify(
        &key.algorithm,
        &signed.request,
        &signed.signature,
        &key.public_key,
    )
    .map_err(|e| match e {
        CryptoError::UnsupportedAlgorithm(alg) => VerifyError::UnsupportedAlgorithm(alg),
        _ => VerifyError::SignatureInvalid,
    })?;

    let request: UserInfoRequest = ciborium::de::from_reader(signed.request.as_slice())
        .map_err(|e| VerifyError::DeserializationFailed(format!("CBOR decode failed: {}", e)))?;

    let timestamp = chrono::DateTime::parse_from_rfc3339(&request.timestamp)
        .map_err(|e| VerifyError::DeserializationFailed(format!("invalid timestamp: {}", e)))?;

    let age = Utc::now().signed_duration_since(timestamp);
    if age.num_seconds() > max_age_seconds || age.num_seconds() < 0 {
        return Err(VerifyError::Expired);
    }

    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{fingerprint, generate_keypair, ALGORITHM_ED25519};

    fn make_signing_key(key_id: &str, pk_bytes: &[u8]) -> DomainPublicKey {
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
    fn test_user_info_request_sign_verify_roundtrip() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let key = make_signing_key("rp-key-1", &pk);

        let request =
            build_user_info_request(b"token-bytes".to_vec(), "app.example.com", "nonce-123");
        let signed =
            sign_user_info_request(&request, "rp-key-1", SigningAlgorithm::Ed25519, &sk, None)
                .unwrap();

        let verified = verify_user_info_request(&signed, &[key], 300).unwrap();
        assert_eq!(verified.relying_party, "app.example.com");
        assert_eq!(verified.token, b"token-bytes");
        assert_eq!(verified.nonce, "nonce-123");
    }

    #[test]
    fn test_user_info_request_expired_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let key = make_signing_key("rp-key-1", &pk);

        let request = UserInfoRequest {
            token: b"token".to_vec(),
            relying_party: "app.example.com".to_string(),
            timestamp: (Utc::now() - chrono::Duration::seconds(120)).to_rfc3339(),
            nonce: "nonce".to_string(),
        };
        let signed =
            sign_user_info_request(&request, "rp-key-1", SigningAlgorithm::Ed25519, &sk, None)
                .unwrap();

        let result = verify_user_info_request(&signed, &[key], 60);
        assert!(matches!(result, Err(VerifyError::Expired)));
    }

    #[test]
    fn test_user_info_request_wrong_key_rejected() {
        let (_pk1, sk1) = generate_keypair(SigningAlgorithm::Ed25519);
        let (pk2, _sk2) = generate_keypair(SigningAlgorithm::Ed25519);
        let key = make_signing_key("rp-key-2", &pk2);

        let request = build_user_info_request(b"token".to_vec(), "app.example.com", "nonce");
        let signed =
            sign_user_info_request(&request, "rp-key-1", SigningAlgorithm::Ed25519, &sk1, None)
                .unwrap();

        let result = verify_user_info_request(&signed, &[key], 300);
        assert!(matches!(result, Err(VerifyError::KeyNotFound(_))));
    }

    #[test]
    fn test_user_info_request_tampered_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let key = make_signing_key("rp-key-1", &pk);

        let request = build_user_info_request(b"token".to_vec(), "app.example.com", "nonce");
        let mut signed =
            sign_user_info_request(&request, "rp-key-1", SigningAlgorithm::Ed25519, &sk, None)
                .unwrap();

        if let Some(byte) = signed.request.first_mut() {
            *byte ^= 0xff;
        }

        let result = verify_user_info_request(&signed, &[key], 300);
        assert!(matches!(result, Err(VerifyError::SignatureInvalid)));
    }

    #[test]
    fn test_user_info_request_encryption_key_rejected() {
        // A key with the right id but key_usage="encrypt" must not be accepted
        // as a PoP key, even though the bytes are a valid Ed25519 verifier.
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let mut key = make_signing_key("rp-key-1", &pk);
        key.key_usage = "encrypt".to_string();

        let request = build_user_info_request(b"token".to_vec(), "app.example.com", "nonce");
        let signed =
            sign_user_info_request(&request, "rp-key-1", SigningAlgorithm::Ed25519, &sk, None)
                .unwrap();

        let result = verify_user_info_request(&signed, &[key], 300);
        assert!(matches!(result, Err(VerifyError::SignatureInvalid)));
    }
}
