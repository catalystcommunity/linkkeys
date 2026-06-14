use crate::crypto::{self, CryptoError, SigningAlgorithm};
use crate::generated::types::{Claim, ClaimSignature, DomainPublicKey};
use chrono::Utc;
use std::collections::BTreeSet;
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
    /// The claim carries no signatures at all.
    Unsigned,
    /// A domain signed the claim but its public keys were not supplied to the
    /// verifier. The caller is expected to resolve/fetch that domain's keys and
    /// retry — `verify_claim` itself performs no I/O.
    DomainKeysUnavailable(String),
    /// A signing domain had keys supplied but none of its signatures verified
    /// against a currently-valid key of that domain.
    DomainUnverified(String),
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
            ClaimError::Unsigned => write!(f, "claim has no signatures"),
            ClaimError::DomainKeysUnavailable(d) => {
                write!(f, "no public keys available for signing domain: {}", d)
            }
            ClaimError::DomainUnverified(d) => {
                write!(f, "no valid signature for signing domain: {}", d)
            }
            ClaimError::Crypto(e) => write!(f, "crypto error: {}", e),
        }
    }
}

impl std::error::Error for ClaimError {}

/// Domain-separation tag + version for the claim signature payload. Bumping
/// this invalidates old signatures by design (versioned construction).
const CLAIM_PAYLOAD_TAG: &str = "linkkeys-claim-v1";

/// Build the canonical bytes that get signed for a claim by `domain`.
///
/// Uses CBOR encoding for an unambiguous, deterministic payload even when
/// `claim_value` contains arbitrary bytes (including nulls). The signed payload
/// binds `claim_id`, `expires_at`, and the issuing `domain` in addition to the
/// core (type/value/user) so expiry, identity, and the vouching domain are all
/// tamper-evident — an attacker cannot extend a claim's life, re-id it, or
/// re-attribute it to a more-trusted domain without breaking the signature.
///
/// `domain` is bound per-signature: every signature carries the domain it was
/// produced for, and a verifier checks the signature against *that* domain's
/// keys. A signature from domain A therefore cannot satisfy a claim presented as
/// signed by domain B — the payloads differ.
///
/// `expires_at` must be stored and served byte-identical to what was signed
/// (the caller normalizes it to whole-second RFC3339 so it round-trips through
/// both Postgres timestamptz and SQLite text). `created_at` is deliberately NOT
/// signed — it is assigned by the database on insert, so signing it would make
/// the stored claim unverifiable.
fn claim_sign_payload(
    claim_id: &str,
    claim_type: &str,
    claim_value: &[u8],
    user_id: &str,
    domain: &str,
    expires_at: Option<&str>,
) -> Vec<u8> {
    // Use a tuple for deterministic CBOR encoding.
    let payload = (
        CLAIM_PAYLOAD_TAG,
        claim_id,
        claim_type,
        serde_bytes::Bytes::new(claim_value),
        user_id,
        domain,
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

/// One signer of a claim: a single key, owned by `domain`, used to produce one
/// `ClaimSignature`. A claim is signed by passing several of these — typically
/// the >=3 active keys of the issuing domain.
pub struct ClaimSigner<'a> {
    pub domain: &'a str,
    pub key_id: &'a str,
    pub algorithm: SigningAlgorithm,
    pub private_key_bytes: &'a [u8],
}

/// Sign a claim with one or more keys, producing a `Claim` carrying one
/// `ClaimSignature` per signer. Each signature binds its signer's domain into
/// the signed payload. Callers must supply at least one signer; an empty signer
/// set yields an unsigned claim, which `verify_claim` rejects.
pub fn sign_claim(spec: &ClaimSpec<'_>, signers: &[ClaimSigner<'_>]) -> Result<Claim, CryptoError> {
    let mut signatures = Vec::with_capacity(signers.len());
    for signer in signers {
        let payload = claim_sign_payload(
            spec.claim_id,
            spec.claim_type,
            spec.claim_value,
            spec.user_id,
            signer.domain,
            spec.expires_at,
        );
        let signature =
            crypto::sign_with_algorithm(signer.algorithm, &payload, signer.private_key_bytes)?;
        signatures.push(ClaimSignature {
            domain: signer.domain.to_string(),
            signed_by_key_id: signer.key_id.to_string(),
            signature,
        });
    }

    Ok(Claim {
        claim_id: spec.claim_id.to_string(),
        user_id: spec.user_id.to_string(),
        claim_type: spec.claim_type.to_string(),
        claim_value: spec.claim_value.to_vec(),
        signatures,
        created_at: Utc::now().to_rfc3339(),
        expires_at: spec.expires_at.map(|s| s.to_string()),
        revoked_at: None,
    })
}

/// A domain and the set of its currently-known public keys, as supplied to
/// `verify_claim`. The caller (the server) resolves these before verifying —
/// from its local DB for its own domain, or by fetching another domain's keys
/// over the network — so that `verify_claim` stays pure and performs no I/O.
pub struct DomainKeySet {
    pub domain: String,
    pub keys: Vec<DomainPublicKey>,
}

/// Verify one signature against a set of candidate keys for its domain: the
/// referenced key must exist, be currently valid, and the signature must check
/// out over `payload`.
fn verify_one_signature(
    sig: &ClaimSignature,
    payload: &[u8],
    keys: &[DomainPublicKey],
) -> Result<(), ClaimError> {
    let key = keys
        .iter()
        .find(|k| k.key_id == sig.signed_by_key_id)
        .ok_or_else(|| ClaimError::KeyNotFound(sig.signed_by_key_id.clone()))?;

    match crypto::signing_key_validity(&key.expires_at, key.revoked_at.as_deref()) {
        crypto::KeyValidity::Valid => {}
        crypto::KeyValidity::Revoked => return Err(ClaimError::KeyRevoked(key.key_id.clone())),
        crypto::KeyValidity::Expired | crypto::KeyValidity::BadExpiry => {
            return Err(ClaimError::KeyExpired(key.key_id.clone()))
        }
    }

    crypto::resolve_and_verify(&key.algorithm, payload, &sig.signature, &key.public_key).map_err(
        |e| match e {
            CryptoError::UnsupportedAlgorithm(alg) => ClaimError::UnsupportedAlgorithm(alg),
            _ => ClaimError::SignatureInvalid,
        },
    )
}

/// Verify a claim under the per-domain quorum rule: **every** domain that signed
/// the claim must contribute at least one signature from a currently-valid key
/// of that domain. The claim's own revocation/expiry are also enforced (both are
/// tamper-evident, being bound into each signed payload).
///
/// `domain_keys` supplies the candidate keys grouped by domain. If a signing
/// domain has no entry, verification returns [`ClaimError::DomainKeysUnavailable`]
/// so the caller can fetch that domain's keys and retry; this function never
/// performs I/O. Trust *policy* (which domains are acceptable, how many, etc.)
/// is intentionally out of scope — that belongs to the consuming policy engine.
pub fn verify_claim(claim: &Claim, domain_keys: &[DomainKeySet]) -> Result<(), ClaimError> {
    if claim.signatures.is_empty() {
        return Err(ClaimError::Unsigned);
    }

    // Distinct signing domains, in stable order for deterministic errors.
    let domains: BTreeSet<&str> = claim.signatures.iter().map(|s| s.domain.as_str()).collect();

    for domain in domains {
        let set = domain_keys
            .iter()
            .find(|s| s.domain == domain)
            .ok_or_else(|| ClaimError::DomainKeysUnavailable(domain.to_string()))?;

        let payload = claim_sign_payload(
            &claim.claim_id,
            &claim.claim_type,
            &claim.claim_value,
            &claim.user_id,
            domain,
            claim.expires_at.as_deref(),
        );

        // The domain is satisfied as soon as one of its signatures verifies. If
        // none do, surface the most recent concrete reason (a single-signature
        // domain therefore yields its exact error: KeyNotFound, KeyRevoked, …).
        let mut last_err = ClaimError::DomainUnverified(domain.to_string());
        let mut satisfied = false;
        for sig in claim.signatures.iter().filter(|s| s.domain == domain) {
            match verify_one_signature(sig, &payload, &set.keys) {
                Ok(()) => {
                    satisfied = true;
                    break;
                }
                Err(e) => last_err = e,
            }
        }
        if !satisfied {
            return Err(last_err);
        }
    }

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

    const DOMAIN: &str = "example.com";

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

    /// One signer on `DOMAIN` for `key_id`/`sk`.
    fn signer<'a>(key_id: &'a str, sk: &'a [u8]) -> ClaimSigner<'a> {
        ClaimSigner {
            domain: DOMAIN,
            key_id,
            algorithm: SigningAlgorithm::Ed25519,
            private_key_bytes: sk,
        }
    }

    /// Wrap a flat key list as a single-domain key set on `DOMAIN`.
    fn keyset(keys: Vec<DomainPublicKey>) -> Vec<DomainKeySet> {
        vec![DomainKeySet {
            domain: DOMAIN.to_string(),
            keys,
        }]
    }

    /// Sign a default single-key claim on `DOMAIN`.
    fn signed_claim(key_id: &str, sk: &[u8], expires_at: Option<&str>) -> Claim {
        sign_claim(
            &ClaimSpec {
                claim_id: "claim-1",
                claim_type: "over-21",
                claim_value: b"true",
                user_id: "user-123",
                expires_at,
            },
            &[signer(key_id, sk)],
        )
        .unwrap()
    }

    #[test]
    fn test_claim_sign_verify_roundtrip() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let claim = signed_claim("key-1", &sk, None);
        assert!(verify_claim(&claim, &keyset(vec![make_domain_key("key-1", &pk)])).is_ok());
    }

    #[test]
    fn test_claim_tampered_value_fails() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let mut claim = signed_claim("key-1", &sk, None);
        claim.claim_value = b"eve@evil.com".to_vec();
        assert!(matches!(
            verify_claim(&claim, &keyset(vec![make_domain_key("key-1", &pk)])),
            Err(ClaimError::SignatureInvalid)
        ));
    }

    #[test]
    fn test_claim_wrong_key_fails() {
        let (_pk1, sk1) = generate_keypair(SigningAlgorithm::Ed25519);
        let (pk2, _sk2) = generate_keypair(SigningAlgorithm::Ed25519);
        // Claim references key-1, but only key-2 is supplied for the domain.
        let claim = signed_claim("key-1", &sk1, None);
        assert!(matches!(
            verify_claim(&claim, &keyset(vec![make_domain_key("key-2", &pk2)])),
            Err(ClaimError::KeyNotFound(_))
        ));
    }

    #[test]
    fn test_claim_tampered_type_fails() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let mut claim = signed_claim("key-1", &sk, None);
        claim.claim_type = "email".to_string();
        assert!(matches!(
            verify_claim(&claim, &keyset(vec![make_domain_key("key-1", &pk)])),
            Err(ClaimError::SignatureInvalid)
        ));
    }

    #[test]
    fn test_claim_expired_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let past = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let claim = signed_claim("key-1", &sk, Some(&past));
        assert!(matches!(
            verify_claim(&claim, &keyset(vec![make_domain_key("key-1", &pk)])),
            Err(ClaimError::Expired)
        ));
    }

    #[test]
    fn test_claim_not_yet_expired_ok() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let future = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let claim = signed_claim("key-1", &sk, Some(&future));
        assert!(verify_claim(&claim, &keyset(vec![make_domain_key("key-1", &pk)])).is_ok());
    }

    #[test]
    fn test_claim_revoked_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let mut claim = signed_claim("key-1", &sk, None);
        claim.revoked_at = Some(Utc::now().to_rfc3339());
        assert!(matches!(
            verify_claim(&claim, &keyset(vec![make_domain_key("key-1", &pk)])),
            Err(ClaimError::Revoked)
        ));
    }

    #[test]
    fn test_claim_tampered_expiry_rejected() {
        // expires_at is part of the signed payload, so extending it breaks the signature.
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let soon = (Utc::now() + chrono::Duration::minutes(1)).to_rfc3339();
        let mut claim = signed_claim("key-1", &sk, Some(&soon));
        claim.expires_at = Some((Utc::now() + chrono::Duration::weeks(520)).to_rfc3339());
        assert!(matches!(
            verify_claim(&claim, &keyset(vec![make_domain_key("key-1", &pk)])),
            Err(ClaimError::SignatureInvalid)
        ));
    }

    #[test]
    fn test_claim_signed_by_revoked_key_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let mut domain_key = make_domain_key("key-1", &pk);
        let claim = signed_claim("key-1", &sk, None);
        domain_key.revoked_at = Some(Utc::now().to_rfc3339());
        assert!(matches!(
            verify_claim(&claim, &keyset(vec![domain_key])),
            Err(ClaimError::KeyRevoked(_))
        ));
    }

    #[test]
    fn test_claim_signed_by_expired_key_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let mut domain_key = make_domain_key("key-1", &pk);
        let claim = signed_claim("key-1", &sk, None);
        domain_key.expires_at = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        assert!(matches!(
            verify_claim(&claim, &keyset(vec![domain_key])),
            Err(ClaimError::KeyExpired(_))
        ));
    }

    #[test]
    fn test_claim_unsupported_algorithm_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let mut domain_key = make_domain_key("key-1", &pk);
        domain_key.algorithm = "unknown-alg".to_string();
        let claim = signed_claim("key-1", &sk, None);
        assert!(matches!(
            verify_claim(&claim, &keyset(vec![domain_key])),
            Err(ClaimError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn test_claim_unsigned_rejected() {
        let claim = sign_claim(
            &ClaimSpec {
                claim_id: "claim-1",
                claim_type: "over-21",
                claim_value: b"true",
                user_id: "user-123",
                expires_at: None,
            },
            &[],
        )
        .unwrap();
        assert!(matches!(verify_claim(&claim, &keyset(vec![])), Err(ClaimError::Unsigned)));
    }

    #[test]
    fn test_claim_domain_keys_unavailable() {
        let (_pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let claim = signed_claim("key-1", &sk, None);
        // No key set supplied for the signing domain at all.
        match verify_claim(&claim, &[]) {
            Err(ClaimError::DomainKeysUnavailable(d)) => assert_eq!(d, DOMAIN),
            other => panic!("expected DomainKeysUnavailable, got {:?}", other),
        }
    }

    #[test]
    fn test_claim_quorum_one_of_three_keys_valid() {
        // A domain signs with three keys; two later go revoked/expired but the
        // claim still verifies because one signature remains valid.
        let (pk1, sk1) = generate_keypair(SigningAlgorithm::Ed25519);
        let (pk2, sk2) = generate_keypair(SigningAlgorithm::Ed25519);
        let (pk3, sk3) = generate_keypair(SigningAlgorithm::Ed25519);
        let claim = sign_claim(
            &ClaimSpec {
                claim_id: "claim-1",
                claim_type: "role",
                claim_value: b"admin",
                user_id: "user-123",
                expires_at: None,
            },
            &[signer("key-1", &sk1), signer("key-2", &sk2), signer("key-3", &sk3)],
        )
        .unwrap();
        assert_eq!(claim.signatures.len(), 3);

        let mut k1 = make_domain_key("key-1", &pk1);
        k1.revoked_at = Some(Utc::now().to_rfc3339());
        let mut k2 = make_domain_key("key-2", &pk2);
        k2.expires_at = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let k3 = make_domain_key("key-3", &pk3); // still valid

        assert!(verify_claim(&claim, &keyset(vec![k1, k2, k3])).is_ok());
    }

    #[test]
    fn test_claim_quorum_all_keys_invalid_fails() {
        let (pk1, sk1) = generate_keypair(SigningAlgorithm::Ed25519);
        let (pk2, sk2) = generate_keypair(SigningAlgorithm::Ed25519);
        let claim = sign_claim(
            &ClaimSpec {
                claim_id: "claim-1",
                claim_type: "role",
                claim_value: b"admin",
                user_id: "user-123",
                expires_at: None,
            },
            &[signer("key-1", &sk1), signer("key-2", &sk2)],
        )
        .unwrap();

        let mut k1 = make_domain_key("key-1", &pk1);
        k1.revoked_at = Some(Utc::now().to_rfc3339());
        let mut k2 = make_domain_key("key-2", &pk2);
        k2.revoked_at = Some(Utc::now().to_rfc3339());
        assert!(matches!(
            verify_claim(&claim, &keyset(vec![k1, k2])),
            Err(ClaimError::KeyRevoked(_))
        ));
    }

    #[test]
    fn test_claim_multi_domain_each_must_verify() {
        // Two domains co-sign. Both must contribute a valid signature.
        let (pk_a, sk_a) = generate_keypair(SigningAlgorithm::Ed25519);
        let (pk_b, sk_b) = generate_keypair(SigningAlgorithm::Ed25519);
        let claim = sign_claim(
            &ClaimSpec {
                claim_id: "claim-1",
                claim_type: "citizen",
                claim_value: b"yes",
                user_id: "user-123",
                expires_at: None,
            },
            &[
                ClaimSigner {
                    domain: "gov.example",
                    key_id: "gov-1",
                    algorithm: SigningAlgorithm::Ed25519,
                    private_key_bytes: &sk_a,
                },
                ClaimSigner {
                    domain: "bank.example",
                    key_id: "bank-1",
                    algorithm: SigningAlgorithm::Ed25519,
                    private_key_bytes: &sk_b,
                },
            ],
        )
        .unwrap();

        let gov = DomainKeySet {
            domain: "gov.example".to_string(),
            keys: vec![make_domain_key("gov-1", &pk_a)],
        };
        let bank = DomainKeySet {
            domain: "bank.example".to_string(),
            keys: vec![make_domain_key("bank-1", &pk_b)],
        };

        // Both domains resolvable and valid -> ok.
        assert!(verify_claim(&claim, &[gov.clone_for_test(), bank.clone_for_test()]).is_ok());

        // Missing one domain's keys -> DomainKeysUnavailable for it.
        match verify_claim(&claim, &[gov.clone_for_test()]) {
            Err(ClaimError::DomainKeysUnavailable(d)) => assert_eq!(d, "bank.example"),
            other => panic!("expected DomainKeysUnavailable(bank.example), got {:?}", other),
        }
    }

    #[test]
    fn test_claim_cross_domain_signature_rejected() {
        // A signature produced for one domain cannot be re-labelled as another:
        // the domain is bound into the signed payload.
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let mut claim = signed_claim("key-1", &sk, None);
        claim.signatures[0].domain = "evil.example".to_string();

        // Supply the same key under the spoofed domain; the payload recomputed
        // with "evil.example" no longer matches the signature.
        let spoof = DomainKeySet {
            domain: "evil.example".to_string(),
            keys: vec![make_domain_key("key-1", &pk)],
        };
        assert!(matches!(verify_claim(&claim, &[spoof]), Err(ClaimError::SignatureInvalid)));
    }

    // Small helper so multi-domain tests can reuse a key set across two
    // verify_claim calls without re-deriving keys.
    impl DomainKeySet {
        fn clone_for_test(&self) -> DomainKeySet {
            DomainKeySet {
                domain: self.domain.clone(),
                keys: self.keys.clone(),
            }
        }
    }
}
