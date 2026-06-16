//! Claims *about a domain* (e.g. a relying party asserting something about
//! itself), as opposed to [`crate::claims`] which are about a user.
//!
//! A [`DomainClaim`] is structurally a `Claim` without a `user_id`: the subject
//! is a domain, supplied by the verifier from authoritative context and bound
//! into every signature (tag `"linkkeys-domain-claim-v1"`) so a claim about
//! domain A cannot be replayed as one about domain B. It is signed by one or
//! more domains via the shared [`ClaimSignature`] list, so third parties can
//! attest — `us.gov` can sign a `government_entity` claim about
//! `us-forestry-service.example`, or a relying party can self-sign a
//! `privacy_policy` claim naming a standard it agrees to.
//!
//! Verification reuses [`crate::claims::verify_signature_quorum`] so it cannot
//! drift from claim/consent verification. Pure: no I/O. The caller resolves each
//! signing domain's keys before verifying.

use crate::claims::{verify_signature_quorum, ClaimError, ClaimSigner, DomainKeySet};
use crate::crypto::CryptoError;
use crate::generated::types::{ClaimSignature, DomainClaim};
use chrono::Utc;

/// Domain-separation tag + version for the domain-claim signature payload.
const DOMAIN_CLAIM_PAYLOAD_TAG: &str = "linkkeys-domain-claim-v1";

/// Build the canonical bytes a single signature covers for a domain claim.
///
/// `subject_domain` is the domain the claim is *about*; `signing_domain` is the
/// attestor for this signature. Both are bound so a claim cannot be re-subjected
/// to a different domain, nor a signature relabelled to a different attestor.
fn domain_claim_sign_payload(
    claim_type: &str,
    claim_value: &[u8],
    subject_domain: &str,
    signing_domain: &str,
    expires_at: Option<&str>,
) -> Vec<u8> {
    let payload = (
        DOMAIN_CLAIM_PAYLOAD_TAG,
        claim_type,
        serde_bytes::Bytes::new(claim_value),
        subject_domain,
        signing_domain,
        expires_at,
    );
    let mut out = Vec::new();
    ciborium::ser::into_writer(&payload, &mut out)
        .expect("CBOR serialization of domain claim payload cannot fail");
    out
}

/// What is being claimed about a domain, independent of *who* signs it.
pub struct DomainClaimSpec<'a> {
    pub claim_type: &'a str,
    pub claim_value: &'a [u8],
    /// The domain the claim is about. Bound into every signature.
    pub subject_domain: &'a str,
    pub expires_at: Option<&'a str>,
}

/// Sign a domain claim with one or more keys, producing a [`DomainClaim`] with
/// one [`ClaimSignature`] per signer. Each signer may belong to a different
/// domain (self-attestation or third-party attestation). An empty signer set
/// yields an unsigned claim, which [`verify_domain_claim`] rejects.
pub fn sign_domain_claim(
    spec: &DomainClaimSpec<'_>,
    signers: &[ClaimSigner<'_>],
) -> Result<DomainClaim, CryptoError> {
    let mut signatures = Vec::with_capacity(signers.len());
    for signer in signers {
        let payload = domain_claim_sign_payload(
            spec.claim_type,
            spec.claim_value,
            spec.subject_domain,
            signer.domain,
            spec.expires_at,
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

    Ok(DomainClaim {
        claim_type: spec.claim_type.to_string(),
        claim_value: spec.claim_value.to_vec(),
        signatures,
        expires_at: spec.expires_at.map(|s| s.to_string()),
    })
}

/// Verify a domain claim about `subject_domain`: every distinct signing domain
/// must contribute a valid signature (the shared quorum), and the claim must not
/// be expired. `subject_domain` is supplied by the caller from authoritative
/// context (e.g. the relying party it is talking to), never from attacker input.
/// `domain_keys` supplies candidate keys per signing domain; a missing domain
/// yields [`ClaimError::DomainKeysUnavailable`] so the caller can fetch and
/// retry. Performs no I/O.
pub fn verify_domain_claim(
    claim: &DomainClaim,
    subject_domain: &str,
    domain_keys: &[DomainKeySet],
) -> Result<(), ClaimError> {
    verify_signature_quorum(&claim.signatures, domain_keys, |signing_domain| {
        domain_claim_sign_payload(
            &claim.claim_type,
            &claim.claim_value,
            subject_domain,
            signing_domain,
            claim.expires_at.as_deref(),
        )
    })?;

    if let Some(exp) = claim.expires_at.as_deref() {
        let expires =
            chrono::DateTime::parse_from_rfc3339(exp).map_err(|_| ClaimError::BadExpiry)?;
        if Utc::now() > expires {
            return Err(ClaimError::Expired);
        }
    }
    Ok(())
}

/// The distinct domains that have attested a domain claim, in stable order. This
/// is *who signed*, independent of whether the signatures verify — callers
/// should pair it with [`verify_domain_claim`] for trust decisions.
pub fn attesting_domains(claim: &DomainClaim) -> Vec<String> {
    use std::collections::BTreeSet;
    claim
        .signatures
        .iter()
        .map(|s| s.domain.clone())
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{fingerprint, generate_keypair, SigningAlgorithm, ALGORITHM_ED25519};
    use crate::generated::types::DomainPublicKey;

    const RP: &str = "us-forestry-service.example";
    const GOV: &str = "us.gov";

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
            expires_at: (Utc::now() + chrono::Duration::days(400)).to_rfc3339(),
            revoked_at: None,
        }
    }

    fn signer<'a>(domain: &'a str, key_id: &'a str, sk: &'a [u8]) -> ClaimSigner<'a> {
        ClaimSigner {
            domain,
            key_id,
            algorithm: SigningAlgorithm::Ed25519,
            private_key_bytes: sk,
        }
    }

    #[test]
    fn test_self_signed_privacy_policy_roundtrip() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let claim = sign_domain_claim(
            &DomainClaimSpec {
                claim_type: "privacy_policy",
                claim_value: b"GDPR-strict-v1",
                subject_domain: RP,
                expires_at: None,
            },
            &[signer(RP, "rp-1", &sk)],
        )
        .unwrap();

        let keys = vec![DomainKeySet {
            domain: RP.to_string(),
            keys: vec![make_domain_key("rp-1", &pk)],
        }];
        assert!(verify_domain_claim(&claim, RP, &keys).is_ok());
        assert_eq!(attesting_domains(&claim), vec![RP.to_string()]);
    }

    #[test]
    fn test_third_party_attestation_roundtrip() {
        // us.gov signs a government_entity claim ABOUT the forestry service.
        let (gov_pk, gov_sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let claim = sign_domain_claim(
            &DomainClaimSpec {
                claim_type: "government_entity",
                claim_value: b"true",
                subject_domain: RP,
                expires_at: None,
            },
            &[signer(GOV, "gov-1", &gov_sk)],
        )
        .unwrap();

        let keys = vec![DomainKeySet {
            domain: GOV.to_string(),
            keys: vec![make_domain_key("gov-1", &gov_pk)],
        }];
        assert!(verify_domain_claim(&claim, RP, &keys).is_ok());
        assert_eq!(attesting_domains(&claim), vec![GOV.to_string()]);
    }

    #[test]
    fn test_subject_domain_replay_rejected() {
        // A claim us.gov signed about the forestry service can't be presented as
        // being about a different (attacker) domain: subject is bound.
        let (gov_pk, gov_sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let claim = sign_domain_claim(
            &DomainClaimSpec {
                claim_type: "government_entity",
                claim_value: b"true",
                subject_domain: RP,
                expires_at: None,
            },
            &[signer(GOV, "gov-1", &gov_sk)],
        )
        .unwrap();
        let keys = vec![DomainKeySet {
            domain: GOV.to_string(),
            keys: vec![make_domain_key("gov-1", &gov_pk)],
        }];
        assert!(matches!(
            verify_domain_claim(&claim, "evil.example", &keys),
            Err(ClaimError::SignatureInvalid)
        ));
    }

    #[test]
    fn test_tampered_value_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let mut claim = sign_domain_claim(
            &DomainClaimSpec {
                claim_type: "government_entity",
                claim_value: b"false",
                subject_domain: RP,
                expires_at: None,
            },
            &[signer(GOV, "gov-1", &sk)],
        )
        .unwrap();
        claim.claim_value = b"true".to_vec();
        let keys = vec![DomainKeySet {
            domain: GOV.to_string(),
            keys: vec![make_domain_key("gov-1", &pk)],
        }];
        assert!(matches!(
            verify_domain_claim(&claim, RP, &keys),
            Err(ClaimError::SignatureInvalid)
        ));
    }

    #[test]
    fn test_unsigned_rejected() {
        let claim = sign_domain_claim(
            &DomainClaimSpec {
                claim_type: "x",
                claim_value: b"y",
                subject_domain: RP,
                expires_at: None,
            },
            &[],
        )
        .unwrap();
        assert!(matches!(
            verify_domain_claim(&claim, RP, &[]),
            Err(ClaimError::Unsigned)
        ));
    }

    #[test]
    fn test_expired_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let past = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let claim = sign_domain_claim(
            &DomainClaimSpec {
                claim_type: "privacy_policy",
                claim_value: b"v1",
                subject_domain: RP,
                expires_at: Some(&past),
            },
            &[signer(RP, "rp-1", &sk)],
        )
        .unwrap();
        let keys = vec![DomainKeySet {
            domain: RP.to_string(),
            keys: vec![make_domain_key("rp-1", &pk)],
        }];
        assert!(matches!(
            verify_domain_claim(&claim, RP, &keys),
            Err(ClaimError::Expired)
        ));
    }

    #[test]
    fn test_missing_signer_keys_unavailable() {
        let (_pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let claim = sign_domain_claim(
            &DomainClaimSpec {
                claim_type: "government_entity",
                claim_value: b"true",
                subject_domain: RP,
                expires_at: None,
            },
            &[signer(GOV, "gov-1", &sk)],
        )
        .unwrap();
        // No keys supplied for us.gov.
        assert!(matches!(
            verify_domain_claim(&claim, RP, &[]),
            Err(ClaimError::DomainKeysUnavailable(_))
        ));
    }
}
