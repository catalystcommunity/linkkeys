//! User-initiated signing requests: a home-domain-attested envelope asking a
//! third-party issuer to sign claim(s) about the user (see the CSIL
//! `SigningRequest`). Pure: signing/verification only, no I/O. The producing
//! side (the user's IDP) signs with its domain keys; the consuming side (the
//! issuer's server) verifies against the user's DNS-pinned keys before issuing.
//!
//! Mirrors `consent`: domain-separated CBOR payload, signature LIST, reusing the
//! shared `claims::verify_signature_quorum` so it can't drift from claim/consent
//! verification.

use chrono::Utc;

use crate::claims::{verify_signature_quorum, ClaimError, ClaimSigner, DomainKeySet};
use crate::crypto::CryptoError;
use crate::generated::types::{ClaimSignature, SignedSigningRequest, SigningRequest};

/// Domain-separation tag + version for the signing-request signature payload.
const SIGNING_REQUEST_TAG: &str = "linkkeys-signing-request-v1";

/// What can go wrong verifying a [`SignedSigningRequest`].
#[derive(Debug)]
pub enum SigningRequestError {
    /// The request bytes are not a valid CBOR-encoded [`SigningRequest`].
    Malformed,
    /// No signatures present.
    Unsigned,
    /// The request's subject_domain / issuer_domain don't match the verifier's
    /// authoritative context.
    ContextMismatch,
    /// The per-domain signature quorum failed.
    Signature(ClaimError),
    /// `expires_at` is not a valid RFC3339 timestamp.
    BadExpiry,
    /// The request has expired.
    Expired,
}

impl std::fmt::Display for SigningRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigningRequestError::Malformed => write!(f, "malformed signing request"),
            SigningRequestError::Unsigned => write!(f, "signing request is unsigned"),
            SigningRequestError::ContextMismatch => {
                write!(f, "signing request subject/issuer does not match context")
            }
            SigningRequestError::Signature(e) => write!(f, "signature verification failed: {}", e),
            SigningRequestError::BadExpiry => write!(f, "signing request has a bad expiry"),
            SigningRequestError::Expired => write!(f, "signing request has expired"),
        }
    }
}

impl std::error::Error for SigningRequestError {}

/// Sorted/deduped claim types for a stable signed payload.
fn canonical_types(types: &[String]) -> Vec<String> {
    let mut v: Vec<String> = types.to_vec();
    v.sort();
    v.dedup();
    v
}

#[allow(clippy::too_many_arguments)]
fn signing_request_payload(
    request_id: &str,
    subject_user_id: &str,
    subject_domain: &str,
    issuer_domain: &str,
    requested_claim_types: &[String],
    nonce: &str,
    issued_at: &str,
    expires_at: &str,
    signing_domain: &str,
    callback: Option<&str>,
) -> Vec<u8> {
    let subject = format!("{}@{}", subject_user_id, subject_domain);
    // SEC-13a: `callback` is bound into the signed payload so an intercepted
    // request cannot have its delivery/callback target rewritten while still
    // verifying. Appended last to keep the tuple's existing prefix stable.
    let payload = (
        SIGNING_REQUEST_TAG,
        request_id,
        subject.as_str(),
        issuer_domain,
        requested_claim_types,
        nonce,
        issued_at,
        expires_at,
        signing_domain,
        callback,
    );
    let mut out = Vec::new();
    ciborium::ser::into_writer(&payload, &mut out)
        .expect("CBOR serialization of signing-request payload cannot fail");
    out
}

/// The terms of a signing request, independent of who attests it.
/// `requested_claim_types` is canonicalized (sorted/deduped) before signing.
pub struct SigningRequestSpec<'a> {
    pub request_id: &'a str,
    pub subject_user_id: &'a str,
    pub subject_domain: &'a str,
    pub issuer_domain: &'a str,
    pub requested_claim_types: &'a [String],
    pub nonce: &'a str,
    pub issued_at: &'a str,
    pub expires_at: &'a str,
    pub callback: Option<&'a str>,
}

/// Sign a signing request with one or more domain keys (the user's home domain
/// attests it). An empty signer set yields an unsigned request, which
/// [`verify_signing_request`] rejects.
pub fn sign_signing_request(
    spec: &SigningRequestSpec<'_>,
    signers: &[ClaimSigner<'_>],
) -> Result<SignedSigningRequest, CryptoError> {
    let requested_claim_types = canonical_types(spec.requested_claim_types);

    let request = SigningRequest {
        request_id: spec.request_id.to_string(),
        subject_user_id: spec.subject_user_id.to_string(),
        subject_domain: spec.subject_domain.to_string(),
        issuer_domain: spec.issuer_domain.to_string(),
        requested_claim_types: requested_claim_types.clone(),
        nonce: spec.nonce.to_string(),
        issued_at: spec.issued_at.to_string(),
        expires_at: spec.expires_at.to_string(),
        callback: spec.callback.map(str::to_string),
    };

    let request_bytes = crate::generated::encode_signing_request(&request);

    let mut signatures = Vec::with_capacity(signers.len());
    for signer in signers {
        let payload = signing_request_payload(
            spec.request_id,
            spec.subject_user_id,
            spec.subject_domain,
            spec.issuer_domain,
            &requested_claim_types,
            spec.nonce,
            spec.issued_at,
            spec.expires_at,
            signer.domain,
            spec.callback,
        );
        let signature = crate::crypto::sign_with_algorithm(
            signer.algorithm,
            &payload,
            signer.private_key_bytes,
        )?;
        signatures.push(ClaimSignature {
            domain: signer.domain.to_string(),
            signed_by_key_id: signer.key_id.to_string(),
            signature,
        });
    }

    Ok(SignedSigningRequest {
        request: request_bytes,
        signatures,
    })
}

/// Verify a signed signing request and return the decoded [`SigningRequest`].
///
/// `subject_domain` is where the verifier fetched the user's keys from (the
/// request's home domain) and `issuer_domain` is the verifier's own domain — both
/// authoritative context, never attacker input. The request's fields must match
/// them, the per-domain signature quorum must pass, and it must not be expired.
/// `domain_keys` supplies candidate keys per signing domain; performs no I/O.
pub fn verify_signing_request(
    signed: &SignedSigningRequest,
    subject_domain: &str,
    issuer_domain: &str,
    domain_keys: &[DomainKeySet],
) -> Result<SigningRequest, SigningRequestError> {
    let request = crate::generated::decode_signing_request(&signed.request[..])
        .map_err(|_| SigningRequestError::Malformed)?;

    if signed.signatures.is_empty() {
        return Err(SigningRequestError::Unsigned);
    }

    if request.subject_domain != subject_domain || request.issuer_domain != issuer_domain {
        return Err(SigningRequestError::ContextMismatch);
    }

    let requested_claim_types = canonical_types(&request.requested_claim_types);
    verify_signature_quorum(&signed.signatures, domain_keys, |signing_domain| {
        signing_request_payload(
            &request.request_id,
            &request.subject_user_id,
            subject_domain,
            issuer_domain,
            &requested_claim_types,
            &request.nonce,
            &request.issued_at,
            &request.expires_at,
            signing_domain,
            request.callback.as_deref(),
        )
    })
    .map_err(SigningRequestError::Signature)?;

    let expires = chrono::DateTime::parse_from_rfc3339(&request.expires_at)
        .map_err(|_| SigningRequestError::BadExpiry)?;
    if Utc::now() > expires {
        return Err(SigningRequestError::Expired);
    }

    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{fingerprint, generate_ed25519_keypair, SigningAlgorithm};
    use crate::generated::types::DomainPublicKey;

    fn keyset(domain: &str, key_id: &str, pk: &[u8]) -> DomainKeySet {
        DomainKeySet {
            domain: domain.to_string(),
            keys: vec![DomainPublicKey {
                key_id: key_id.to_string(),
                public_key: pk.to_vec(),
                fingerprint: fingerprint(pk),
                algorithm: "ed25519".to_string(),
                key_usage: "sign".to_string(),
                created_at: String::new(),
                expires_at: (Utc::now() + chrono::Duration::days(365)).to_rfc3339(),
                revoked_at: None,
                signed_by_key_id: None,
                key_signature: None,
            }],
        }
    }

    fn spec_signed(expires_at: &str) -> (SignedSigningRequest, Vec<u8>, String) {
        let (vk, sk) = generate_ed25519_keypair();
        let pk = vk.as_bytes().to_vec();
        let types = vec!["age_over_21".to_string()];
        let signed = sign_signing_request(
            &SigningRequestSpec {
                request_id: "req-1",
                subject_user_id: "user-1",
                subject_domain: "home.test",
                issuer_domain: "dmv.test",
                requested_claim_types: &types,
                nonce: "nonce-1",
                issued_at: &Utc::now().to_rfc3339(),
                expires_at,
                callback: Some("https://home.test/deposit"),
            },
            &[ClaimSigner {
                domain: "home.test",
                key_id: "k1",
                algorithm: SigningAlgorithm::parse_str("ed25519").unwrap(),
                private_key_bytes: &sk.to_bytes(),
            }],
        )
        .unwrap();
        (signed, pk, "k1".to_string())
    }

    #[test]
    fn round_trips_and_verifies() {
        let exp = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let (signed, pk, kid) = spec_signed(&exp);
        let keys = vec![keyset("home.test", &kid, &pk)];
        let req = verify_signing_request(&signed, "home.test", "dmv.test", &keys).unwrap();
        assert_eq!(req.subject_user_id, "user-1");
        assert_eq!(req.requested_claim_types, vec!["age_over_21".to_string()]);
        assert_eq!(req.callback.as_deref(), Some("https://home.test/deposit"));
    }

    #[test]
    fn wrong_issuer_is_rejected() {
        let exp = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let (signed, pk, kid) = spec_signed(&exp);
        let keys = vec![keyset("home.test", &kid, &pk)];
        // A request addressed to dmv.test must not verify at another issuer.
        assert!(matches!(
            verify_signing_request(&signed, "home.test", "evil.test", &keys),
            Err(SigningRequestError::ContextMismatch)
        ));
    }

    #[test]
    fn expired_is_rejected() {
        let exp = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let (signed, pk, kid) = spec_signed(&exp);
        let keys = vec![keyset("home.test", &kid, &pk)];
        assert!(matches!(
            verify_signing_request(&signed, "home.test", "dmv.test", &keys),
            Err(SigningRequestError::Expired)
        ));
    }

    #[test]
    fn tampered_payload_fails_quorum() {
        let exp = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let (mut signed, pk, kid) = spec_signed(&exp);
        // Flip a byte in the encoded request → decoded fields no longer match the
        // signed payload.
        let mut req = crate::generated::decode_signing_request(&signed.request[..]).unwrap();
        req.subject_user_id = "user-2".to_string();
        let bytes = crate::generated::encode_signing_request(&req);
        signed.request = bytes;
        let keys = vec![keyset("home.test", &kid, &pk)];
        assert!(matches!(
            verify_signing_request(&signed, "home.test", "dmv.test", &keys),
            Err(SigningRequestError::Signature(_))
        ));
    }
}
