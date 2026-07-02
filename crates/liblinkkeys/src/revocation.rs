//! Sibling-signed key revocation certificates (SEC-08).
//!
//! A domain's signing keys are equal peers (≥3 by design). When one is
//! compromised, the OTHER keys can co-sign a revocation of it — a portable,
//! cryptographic proof "key K is revoked as of T" that a peer can verify against
//! the domain's DNS-pinned key set, without waiting for a DNS edit to propagate.
//! This is the in-band, authenticated revocation lever the design calls for.
//!
//! The signing/verifying logic is hand-written here (following the same
//! canonical-tuple-over-a-domain-separation-tag pattern as `claims`,
//! `assertions`, and `signing_request`); the wire type is mirrored in
//! `csil/linkkeys.csil` for the spec. Verification requires a quorum of at least
//! two DISTINCT, currently-valid signing keys of the domain — and the revoked key
//! may never authorize its own revocation.

use crate::assertions::check_signing_key_valid;
use crate::claims::ClaimSigner;
use crate::crypto::{self, CryptoError};
use crate::generated::types::{ClaimSignature, DomainPublicKey};
use std::collections::HashSet;
use std::fmt;

/// Minimum number of distinct sibling signatures required to revoke a key.
pub const REVOCATION_QUORUM: usize = 2;

/// Domain-separation tag / version for the signed revocation payload.
const REVOCATION_TAG: &str = "linkkeys-key-revocation-v1";

/// A sibling-signed assertion that a domain key is revoked. `signatures` are from
/// OTHER keys of the same domain.
#[derive(Debug, Clone, PartialEq)]
pub struct RevocationCertificate {
    /// The key being revoked.
    pub target_key_id: String,
    /// The revoked key's fingerprint (binds the id to specific key material).
    pub target_fingerprint: String,
    /// UTC RFC3339 instant of revocation. Messages after this are suspect.
    pub revoked_at: String,
    /// Co-signatures from sibling signing keys of the domain.
    pub signatures: Vec<ClaimSignature>,
}

#[derive(Debug)]
pub enum RevocationError {
    /// Fewer than `REVOCATION_QUORUM` distinct valid sibling signatures verified.
    InsufficientSignatures { got: usize, need: usize },
}

impl fmt::Display for RevocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RevocationError::InsufficientSignatures { got, need } => write!(
                f,
                "revocation certificate has {got} valid sibling signatures; {need} required"
            ),
        }
    }
}

impl std::error::Error for RevocationError {}

/// The terms of a revocation, independent of who signs it.
pub struct RevocationSpec<'a> {
    pub target_key_id: &'a str,
    pub target_fingerprint: &'a str,
    pub revoked_at: &'a str,
}

/// Canonical signed bytes: the tag, the target key id + fingerprint, the
/// revocation instant, and the signing sibling's domain (bound per-signature to
/// stop cross-domain reuse of a signature).
fn revocation_payload(
    target_key_id: &str,
    target_fingerprint: &str,
    revoked_at: &str,
    signing_domain: &str,
) -> Vec<u8> {
    let payload = (
        REVOCATION_TAG,
        target_key_id,
        target_fingerprint,
        revoked_at,
        signing_domain,
    );
    let mut out = Vec::new();
    ciborium::ser::into_writer(&payload, &mut out)
        .expect("CBOR serialization of revocation payload cannot fail");
    out
}

/// Build a revocation certificate signed by one or more sibling keys. The caller
/// must NOT include the target key among `signers` (a key cannot authorize its
/// own revocation); `verify_revocation_certificate` enforces that regardless.
pub fn build_revocation_certificate(
    spec: &RevocationSpec<'_>,
    signers: &[ClaimSigner<'_>],
) -> Result<RevocationCertificate, CryptoError> {
    let mut signatures = Vec::with_capacity(signers.len());
    for signer in signers {
        let payload = revocation_payload(
            spec.target_key_id,
            spec.target_fingerprint,
            spec.revoked_at,
            signer.domain,
        );
        let signature =
            crypto::sign_with_algorithm(signer.algorithm, &payload, signer.private_key_bytes)?;
        signatures.push(ClaimSignature {
            domain: signer.domain.to_string(),
            signed_by_key_id: signer.key_id.to_string(),
            signature,
        });
    }
    Ok(RevocationCertificate {
        target_key_id: spec.target_key_id.to_string(),
        target_fingerprint: spec.target_fingerprint.to_string(),
        revoked_at: spec.revoked_at.to_string(),
        signatures,
    })
}

/// Verify a revocation certificate against a domain's public key set. Requires at
/// least [`REVOCATION_QUORUM`] DISTINCT signing keys of `domain`, each currently
/// valid and NOT the target key, to have signed the canonical payload. Returns
/// `Ok(())` when the quorum is met.
pub fn verify_revocation_certificate(
    cert: &RevocationCertificate,
    domain_keys: &[DomainPublicKey],
    domain: &str,
) -> Result<(), RevocationError> {
    let mut valid_signers: HashSet<&str> = HashSet::new();

    for sig in &cert.signatures {
        // A key can never authorize its own revocation.
        if sig.signed_by_key_id == cert.target_key_id {
            continue;
        }
        // The signature must be bound to this domain.
        if sig.domain != domain {
            continue;
        }
        let Some(key) = domain_keys
            .iter()
            .find(|k| k.key_id == sig.signed_by_key_id)
        else {
            continue;
        };
        // Only a currently-valid signing key counts toward the quorum.
        if check_signing_key_valid(key).is_err() {
            continue;
        }
        let payload = revocation_payload(
            &cert.target_key_id,
            &cert.target_fingerprint,
            &cert.revoked_at,
            &sig.domain,
        );
        if crypto::resolve_and_verify(&key.algorithm, &payload, &sig.signature, &key.public_key)
            .is_ok()
        {
            valid_signers.insert(sig.signed_by_key_id.as_str());
        }
    }

    if valid_signers.len() >= REVOCATION_QUORUM {
        Ok(())
    } else {
        Err(RevocationError::InsufficientSignatures {
            got: valid_signers.len(),
            need: REVOCATION_QUORUM,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{fingerprint, generate_ed25519_keypair, SigningAlgorithm};
    use chrono::Utc;

    struct Sibling {
        key_id: String,
        public_key: Vec<u8>,
        private_key: Vec<u8>,
    }

    fn make_sibling(id: &str) -> Sibling {
        let (vk, sk) = generate_ed25519_keypair();
        Sibling {
            key_id: id.to_string(),
            public_key: vk.as_bytes().to_vec(),
            private_key: sk.to_bytes().to_vec(),
        }
    }

    fn pubkey(domain_active: &Sibling) -> DomainPublicKey {
        DomainPublicKey {
            key_id: domain_active.key_id.clone(),
            public_key: domain_active.public_key.clone(),
            fingerprint: fingerprint(&domain_active.public_key),
            algorithm: "ed25519".to_string(),
            key_usage: "sign".to_string(),
            created_at: String::new(),
            expires_at: (Utc::now() + chrono::Duration::days(365)).to_rfc3339(),
            revoked_at: None,
            signed_by_key_id: None,
            key_signature: None,
        }
    }

    fn signer<'a>(s: &'a Sibling, domain: &'a str) -> ClaimSigner<'a> {
        ClaimSigner {
            domain,
            key_id: &s.key_id,
            algorithm: SigningAlgorithm::Ed25519,
            private_key_bytes: &s.private_key,
        }
    }

    #[test]
    fn two_siblings_revoke_a_third() {
        let domain = "d.test";
        let (a, b, target) = (make_sibling("a"), make_sibling("b"), make_sibling("t"));
        let keys = vec![pubkey(&a), pubkey(&b), pubkey(&target)];
        let spec = RevocationSpec {
            target_key_id: "t",
            target_fingerprint: &fingerprint(&target.public_key),
            revoked_at: &Utc::now().to_rfc3339(),
        };
        let cert =
            build_revocation_certificate(&spec, &[signer(&a, domain), signer(&b, domain)]).unwrap();
        assert!(verify_revocation_certificate(&cert, &keys, domain).is_ok());
    }

    #[test]
    fn one_signature_is_insufficient() {
        let domain = "d.test";
        let (a, target) = (make_sibling("a"), make_sibling("t"));
        let keys = vec![pubkey(&a), pubkey(&target)];
        let spec = RevocationSpec {
            target_key_id: "t",
            target_fingerprint: &fingerprint(&target.public_key),
            revoked_at: &Utc::now().to_rfc3339(),
        };
        let cert = build_revocation_certificate(&spec, &[signer(&a, domain)]).unwrap();
        assert!(verify_revocation_certificate(&cert, &keys, domain).is_err());
    }

    #[test]
    fn target_cannot_sign_its_own_revocation() {
        let domain = "d.test";
        let (a, target) = (make_sibling("a"), make_sibling("t"));
        let keys = vec![pubkey(&a), pubkey(&target)];
        let spec = RevocationSpec {
            target_key_id: "t",
            target_fingerprint: &fingerprint(&target.public_key),
            revoked_at: &Utc::now().to_rfc3339(),
        };
        // One real sibling + the target trying to self-authorize: still only 1
        // valid distinct signer -> insufficient.
        let cert =
            build_revocation_certificate(&spec, &[signer(&a, domain), signer(&target, domain)])
                .unwrap();
        assert!(verify_revocation_certificate(&cert, &keys, domain).is_err());
    }

    #[test]
    fn tampered_revoked_at_fails() {
        let domain = "d.test";
        let (a, b, target) = (make_sibling("a"), make_sibling("b"), make_sibling("t"));
        let keys = vec![pubkey(&a), pubkey(&b), pubkey(&target)];
        let spec = RevocationSpec {
            target_key_id: "t",
            target_fingerprint: &fingerprint(&target.public_key),
            revoked_at: &Utc::now().to_rfc3339(),
        };
        let mut cert =
            build_revocation_certificate(&spec, &[signer(&a, domain), signer(&b, domain)]).unwrap();
        cert.revoked_at = (Utc::now() + chrono::Duration::days(1)).to_rfc3339();
        assert!(verify_revocation_certificate(&cert, &keys, domain).is_err());
    }

    #[test]
    fn wrong_domain_binding_fails() {
        let domain = "d.test";
        let (a, b, target) = (make_sibling("a"), make_sibling("b"), make_sibling("t"));
        let keys = vec![pubkey(&a), pubkey(&b), pubkey(&target)];
        let spec = RevocationSpec {
            target_key_id: "t",
            target_fingerprint: &fingerprint(&target.public_key),
            revoked_at: &Utc::now().to_rfc3339(),
        };
        let cert =
            build_revocation_certificate(&spec, &[signer(&a, domain), signer(&b, domain)]).unwrap();
        // Verifying under a different domain context must fail (signatures are
        // bound to the signing domain).
        assert!(verify_revocation_certificate(&cert, &keys, "evil.test").is_err());
    }
}
