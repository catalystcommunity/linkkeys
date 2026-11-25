// LINKKEYS-TRUST-CRITICAL: a change to this file needs a trust approval. See docs/trust-change-control.md.
use crate::assertions::VerifyError;
use crate::crypto::{self, CryptoError, SigningAlgorithm};
use crate::generated::types::{
    AuthFlowContext, AuthRequest, ClaimRequest, DomainPublicKey, RelyingPartyApplication,
    SignedAuthRequest,
};
use time::OffsetDateTime;

/// Build an unsigned auth request with the current timestamp. `requested_claims`
/// advertises the claims the RP wants released for this login or later
/// claims-update flow; pass `None` for authentication-only.
pub fn build_auth_request(
    relying_party: &str,
    callback_url: &str,
    nonce: &str,
    signing_key_id: &str,
    requested_claims: Option<ClaimRequest>,
    flow_context: Option<AuthFlowContext>,
    application: RelyingPartyApplication,
) -> AuthRequest {
    AuthRequest {
        relying_party: relying_party.to_string(),
        callback_url: callback_url.to_string(),
        nonce: nonce.to_string(),
        timestamp: OffsetDateTime::now_utc(),
        signing_key_id: signing_key_id.to_string(),
        requested_claims,
        authentication_requirements: None,
        flow_context,
        // The caller sets `relying_party_claims` on the returned request if it
        // wants to assert claims about itself (signed self/third-party).
        relying_party_claims: None,
        application,
    }
}

/// Sign an auth request with a domain key.
/// The request is CBOR-encoded, then signed. The raw CBOR bytes become
/// the `request` field in the signed envelope.
pub fn sign_auth_request(
    request: &AuthRequest,
    key_id: &str,
    algorithm: SigningAlgorithm,
    private_key_bytes: &[u8],
) -> Result<SignedAuthRequest, CryptoError> {
    let request_bytes = crate::generated::encode_auth_request(request)?;

    let signature = crypto::sign_with_algorithm(algorithm, &request_bytes, private_key_bytes)?;

    Ok(SignedAuthRequest {
        request: request_bytes,
        signing_key_id: key_id.to_string(),
        signature,
    })
}

/// Verify a signed auth request against a set of public keys.
/// Checks: key exists, signature valid, timestamp within max_age_seconds of now.
/// Returns the deserialized AuthRequest if valid.
pub fn verify_auth_request(
    signed: &SignedAuthRequest,
    public_keys: &[DomainPublicKey],
    max_age_seconds: i64,
) -> Result<AuthRequest, VerifyError> {
    let key = public_keys
        .iter()
        .find(|k| k.key_id == signed.signing_key_id)
        .ok_or_else(|| VerifyError::KeyNotFound(signed.signing_key_id.clone()))?;

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

    let request = crate::generated::decode_auth_request(signed.request.as_slice())
        .map_err(|e| VerifyError::DeserializationFailed(format!("CBOR decode failed: {}", e)))?;

    let age = OffsetDateTime::now_utc() - request.timestamp;
    if age.whole_seconds() > max_age_seconds || age.whole_seconds() < 0 {
        return Err(VerifyError::Expired);
    }

    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{fingerprint, generate_keypair};

    fn make_domain_key(key_id: &str, pk_bytes: &[u8]) -> DomainPublicKey {
        DomainPublicKey {
            key_id: key_id.to_string(),
            public_key: pk_bytes.to_vec(),
            fingerprint: fingerprint(pk_bytes),
            algorithm: crate::generated::types::KeyAlgorithm::Ed25519,
            key_usage: crate::generated::types::KeyUsage::Sign,
            signed_by_key_id: None,
            key_signature: None,
            created_at: OffsetDateTime::now_utc(),
            expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
            revoked_at: None,
        }
    }

    #[test]
    fn test_auth_request_sign_verify_roundtrip() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let domain_key = make_domain_key("key-1", &pk);

        let mut request = build_auth_request(
            "linkidspec.com",
            "https://linkidspec.com/callback",
            "nonce-123",
            "key-1",
            None,
            None,
            crate::test_support::rp_app(),
        );
        request.authentication_requirements =
            Some(crate::generated::types::AuthenticationRequirements {
                minimum_factor_count: 2,
            });

        let signed = sign_auth_request(&request, "key-1", SigningAlgorithm::Ed25519, &sk).unwrap();
        let verified = verify_auth_request(&signed, &[domain_key], 300).unwrap();

        assert_eq!(verified.relying_party, "linkidspec.com");
        assert_eq!(verified.callback_url, "https://linkidspec.com/callback");
        assert_eq!(verified.nonce, "nonce-123");
        assert_eq!(
            verified
                .authentication_requirements
                .unwrap()
                .minimum_factor_count,
            2
        );
    }

    #[test]
    fn test_auth_request_expired_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let domain_key = make_domain_key("key-1", &pk);

        // Build a request with a timestamp in the past by constructing it manually
        let request = AuthRequest {
            relying_party: "linkidspec.com".to_string(),
            callback_url: "https://linkidspec.com/callback".to_string(),
            nonce: "nonce".to_string(),
            timestamp: OffsetDateTime::now_utc() - time::Duration::seconds(120),
            signing_key_id: "key-1".to_string(),
            requested_claims: None,
            authentication_requirements: None,
            flow_context: None,
            relying_party_claims: None,
            application: crate::test_support::rp_app(),
        };

        let signed = sign_auth_request(&request, "key-1", SigningAlgorithm::Ed25519, &sk).unwrap();

        // max_age of 60 seconds, but request is 120 seconds old
        let result = verify_auth_request(&signed, &[domain_key], 60);
        assert!(matches!(result, Err(VerifyError::Expired)));
    }

    #[test]
    fn test_auth_request_wrong_key_rejected() {
        let (_pk1, sk1) = generate_keypair(SigningAlgorithm::Ed25519);
        let (pk2, _sk2) = generate_keypair(SigningAlgorithm::Ed25519);
        let domain_key = make_domain_key("key-2", &pk2);

        let request = build_auth_request(
            "linkidspec.com",
            "https://linkidspec.com/callback",
            "nonce",
            "key-1",
            None,
            None,
            crate::test_support::rp_app(),
        );

        let signed = sign_auth_request(&request, "key-1", SigningAlgorithm::Ed25519, &sk1).unwrap();

        let result = verify_auth_request(&signed, &[domain_key], 300);
        assert!(matches!(result, Err(VerifyError::KeyNotFound(_))));
    }

    #[test]
    fn test_auth_request_tampered_signature_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let domain_key = make_domain_key("key-1", &pk);

        let request = build_auth_request(
            "linkidspec.com",
            "https://linkidspec.com/callback",
            "nonce",
            "key-1",
            None,
            None,
            crate::test_support::rp_app(),
        );

        let mut signed =
            sign_auth_request(&request, "key-1", SigningAlgorithm::Ed25519, &sk).unwrap();

        if let Some(byte) = signed.request.first_mut() {
            *byte ^= 0xff;
        }

        let result = verify_auth_request(&signed, &[domain_key], 300);
        assert!(matches!(result, Err(VerifyError::SignatureInvalid)));
    }
}
