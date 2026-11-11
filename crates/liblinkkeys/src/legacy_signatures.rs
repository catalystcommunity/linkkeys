//! Signed payload formats from before the `-v1alpha` epoch, and the
//! provenance checks that use them.
//!
//! Commit ded0471 (v0.14.1, 2026-07-16) renamed every domain-separation tag
//! to the `-v1alpha` epoch. During alpha the rule is "re-sign, do not accept
//! old formats", so current verifiers accept only the current format, and every
//! stored signature made before that release stopped verifying. This module
//! lets the server prove that a stored signature is its own work in a known
//! older format before it re-signs the record in the current format.
//!
//! Nothing in the verify path uses this module. It is compiled only with the
//! `legacy-formats` feature (the server's re-sign transform) and in tests.
//!
//! A provenance check passes only when **every** signature of the local
//! domain on the record verifies, under one format, with a key of the local
//! domain. A record that fails is not re-signed: re-signing it would launder a
//! tampered row into a valid one.
//!
//! Pure: no I/O. The caller supplies all of its domain keys, including revoked
//! and expired ones, so that signatures of retired keys can be checked.

use crate::claims::claim_sign_payload;
use crate::consent::{canonical_types, consent_sign_payload};
use crate::crypto;
use crate::dns::key_vouch_payload;
use crate::generated::types::{
    Claim, ClaimSignature, ConsentGrant, DomainPublicKey, RevocationCertificate, SignedConsentGrant,
};
use crate::revocation::revocation_payload;

const CLAIM_V1_TAG: &str = "linkkeys-claim-v1";
const CLAIM_V2_TAG: &str = "linkkeys-claim-v2";
const CONSENT_V1_TAG: &str = "linkkeys-consent-v1";
const REVOCATION_V1_TAG: &str = "linkkeys-key-revocation-v1";
const KEY_VOUCH_V1_TAG: &str = "linkkeys-key-vouch-v1";

/// The format a stored signature verified under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// The current format. The record may still need a re-sign, for example
    /// when its signing key is revoked now.
    Current,
    /// A known older format, by name.
    Legacy(&'static str),
}

/// Claim payload formats that were stored in `claim_signatures`.
///
/// Older formats exist (dcdeacb, cdd5009) but the `claim_signatures`
/// migration (05b7588) dropped their single-signature column, so no stored
/// signature uses them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyClaimFormat {
    /// 05b7588 (2026-06-14): `("linkkeys-claim-v1", id, type, value, user_id,
    /// signing_domain, expires_at)`.
    V1SigningDomain,
    /// 54b4873 (2026-06-14): `("linkkeys-claim-v1", id, type, value,
    /// "user_id@subject_domain", signing_domain, expires_at)`.
    V1Subject,
    /// 59428af (2026-07-02): `("linkkeys-claim-v2", id, type, value,
    /// "user_id@subject_domain", signing_domain, expires_at, attested_at)`.
    V2,
}

impl LegacyClaimFormat {
    /// Every legacy claim format, newest first.
    pub const ALL: [LegacyClaimFormat; 3] = [
        LegacyClaimFormat::V2,
        LegacyClaimFormat::V1Subject,
        LegacyClaimFormat::V1SigningDomain,
    ];

    pub fn name(self) -> &'static str {
        match self {
            LegacyClaimFormat::V1SigningDomain => "claim-v1 (user_id, signing domain)",
            LegacyClaimFormat::V1Subject => "claim-v1 (user@domain subject)",
            LegacyClaimFormat::V2 => "claim-v2",
        }
    }
}

fn cbor<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out)
        .expect("CBOR serialization of a legacy payload cannot fail");
    out
}

/// The bytes a signature in `format` covered for `claim`.
pub fn legacy_claim_payload(
    format: LegacyClaimFormat,
    claim: &Claim,
    subject_domain: &str,
    signing_domain: &str,
) -> Vec<u8> {
    let value = serde_bytes::Bytes::new(&claim.claim_value);
    let subject = format!("{}@{}", claim.user_id, subject_domain);
    let expires_at = claim.expires_at.as_deref();
    match format {
        LegacyClaimFormat::V1SigningDomain => cbor(&(
            CLAIM_V1_TAG,
            claim.claim_id.as_str(),
            claim.claim_type.as_str(),
            value,
            claim.user_id.as_str(),
            signing_domain,
            expires_at,
        )),
        LegacyClaimFormat::V1Subject => cbor(&(
            CLAIM_V1_TAG,
            claim.claim_id.as_str(),
            claim.claim_type.as_str(),
            value,
            subject.as_str(),
            signing_domain,
            expires_at,
        )),
        LegacyClaimFormat::V2 => cbor(&(
            CLAIM_V2_TAG,
            claim.claim_id.as_str(),
            claim.claim_type.as_str(),
            value,
            subject.as_str(),
            signing_domain,
            expires_at,
            claim.attested_at.as_str(),
        )),
    }
}

/// The bytes a `linkkeys-consent-v1` signature covered (0026221 to ded0471).
/// That format had no application element.
pub fn legacy_consent_payload(grant: &ConsentGrant, signing_domain: &str) -> Vec<u8> {
    let subject = format!("{}@{}", grant.user_id, grant.subject_domain);
    cbor(&(
        CONSENT_V1_TAG,
        grant.grant_id.as_str(),
        subject.as_str(),
        grant.audience.as_str(),
        canonical_types(&grant.claim_types),
        grant.issued_at.as_str(),
        grant.expires_at.as_str(),
        signing_domain,
    ))
}

/// The bytes a `linkkeys-key-revocation-v1` signature covered (4a8b759 to
/// ded0471).
pub fn legacy_revocation_payload(
    target_key_id: &str,
    target_fingerprint: &str,
    revoked_at: &str,
    signing_domain: &str,
) -> Vec<u8> {
    cbor(&(
        REVOCATION_V1_TAG,
        target_key_id,
        target_fingerprint,
        revoked_at,
        signing_domain,
    ))
}

/// The bytes a `linkkeys-key-vouch-v1` vouch covered (cdd5009 to ded0471).
pub fn legacy_key_vouch_payload(enc_fingerprint: &str, enc_expires_at: &str) -> Vec<u8> {
    cbor(&(KEY_VOUCH_V1_TAG, enc_fingerprint, enc_expires_at))
}

/// Whether `key` can stand behind a signature made at `signed_at`: it is a
/// signing key, and it was not revoked at that time. Expiry does not matter:
/// a key that expired after it signed is retired, not compromised. A revoked
/// key with an unreadable `signed_at` fails, because the order is unknown.
fn key_usable(key: &DomainPublicKey, signed_at: Option<&str>) -> bool {
    if key.key_usage != "sign" {
        return false;
    }
    let Some(revoked_at) = key.revoked_at.as_deref() else {
        return true;
    };
    let signed = signed_at.and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok());
    let revoked = chrono::DateTime::parse_from_rfc3339(revoked_at).ok();
    matches!((signed, revoked), (Some(s), Some(r)) if s < r)
}

/// True when `signatures` is not empty and every one verifies over `payload`
/// with the key it names in `keys`.
fn all_verify(
    signatures: &[&ClaimSignature],
    keys: &[DomainPublicKey],
    signed_at: Option<&str>,
    payload: &[u8],
) -> bool {
    !signatures.is_empty()
        && signatures.iter().all(|sig| {
            keys.iter()
                .find(|k| k.key_id == sig.signed_by_key_id)
                .is_some_and(|key| {
                    key_usable(key, signed_at)
                        && crypto::resolve_and_verify(
                            &key.algorithm,
                            payload,
                            &sig.signature,
                            &key.public_key,
                        )
                        .is_ok()
                })
        })
}

fn local_signatures<'a>(signatures: &'a [ClaimSignature], domain: &str) -> Vec<&'a ClaimSignature> {
    signatures.iter().filter(|s| s.domain == domain).collect()
}

/// The format under which every `local_domain` signature of `claim` verifies
/// with a key in `keys`, or `None`. The claim is about a user of
/// `local_domain`. Signatures of other domains are ignored.
pub fn claim_provenance(
    claim: &Claim,
    local_domain: &str,
    keys: &[DomainPublicKey],
) -> Option<Provenance> {
    let local = local_signatures(&claim.signatures, local_domain);
    let signed_at = Some(claim.attested_at.as_str());
    let current = claim_sign_payload(
        &claim.claim_id,
        &claim.claim_type,
        &claim.claim_value,
        &claim.user_id,
        local_domain,
        local_domain,
        claim.expires_at.as_deref(),
        &claim.attested_at,
    );
    if all_verify(&local, keys, signed_at, &current) {
        return Some(Provenance::Current);
    }
    LegacyClaimFormat::ALL.into_iter().find_map(|format| {
        let payload = legacy_claim_payload(format, claim, local_domain, local_domain);
        all_verify(&local, keys, signed_at, &payload).then_some(Provenance::Legacy(format.name()))
    })
}

/// The format under which every `local_domain` signature of a consent grant
/// verifies with a key in `keys`, or `None`. `grant` is the decoded
/// `signed.grant`.
pub fn consent_provenance(
    signed: &SignedConsentGrant,
    grant: &ConsentGrant,
    local_domain: &str,
    keys: &[DomainPublicKey],
) -> Option<Provenance> {
    let local = local_signatures(&signed.signatures, local_domain);
    let signed_at = Some(grant.issued_at.as_str());
    let current = consent_sign_payload(
        &grant.grant_id,
        &grant.user_id,
        &grant.subject_domain,
        &grant.audience,
        &canonical_types(&grant.claim_types),
        &grant.issued_at,
        &grant.expires_at,
        local_domain,
        grant.application.as_ref(),
    );
    if all_verify(&local, keys, signed_at, &current) {
        return Some(Provenance::Current);
    }
    // The v1 format had no application, so a grant that names one is not v1.
    if grant.application.is_none()
        && all_verify(
            &local,
            keys,
            signed_at,
            &legacy_consent_payload(grant, local_domain),
        )
    {
        return Some(Provenance::Legacy("consent-v1"));
    }
    None
}

/// The format under which every `local_domain` signature of a revocation
/// certificate verifies with a sibling key in `keys`, or `None`. A signature
/// by the revoked key itself never counts.
pub fn revocation_provenance(
    cert: &RevocationCertificate,
    local_domain: &str,
    keys: &[DomainPublicKey],
) -> Option<Provenance> {
    let local = local_signatures(&cert.signatures, local_domain);
    if local
        .iter()
        .any(|s| s.signed_by_key_id == cert.target_key_id)
    {
        return None;
    }
    let signed_at = Some(cert.revoked_at.as_str());
    let current = revocation_payload(
        &cert.target_key_id,
        &cert.target_fingerprint,
        &cert.revoked_at,
        local_domain,
    );
    if all_verify(&local, keys, signed_at, &current) {
        return Some(Provenance::Current);
    }
    let legacy = legacy_revocation_payload(
        &cert.target_key_id,
        &cert.target_fingerprint,
        &cert.revoked_at,
        local_domain,
    );
    all_verify(&local, keys, signed_at, &legacy).then_some(Provenance::Legacy("key-revocation-v1"))
}

/// The format under which the stored vouch of `enc_key` verifies with
/// `signer`, the signing key it names, or `None`. The fingerprint is
/// recomputed from the public key, as verifiers do.
pub fn vouch_provenance(enc_key: &DomainPublicKey, signer: &DomainPublicKey) -> Option<Provenance> {
    if enc_key.signed_by_key_id.as_deref() != Some(signer.key_id.as_str()) {
        return None;
    }
    let signature = enc_key.key_signature.as_deref()?;
    if !key_usable(signer, Some(&enc_key.created_at)) {
        return None;
    }
    let fingerprint = crypto::fingerprint(&enc_key.public_key);
    let verifies = |payload: &[u8]| {
        crypto::resolve_and_verify(&signer.algorithm, payload, signature, &signer.public_key)
            .is_ok()
    };
    if verifies(&key_vouch_payload(&fingerprint, &enc_key.expires_at)) {
        Some(Provenance::Current)
    } else if verifies(&legacy_key_vouch_payload(&fingerprint, &enc_key.expires_at)) {
        Some(Provenance::Legacy("key-vouch-v1"))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::{
        sign_claim, verify_claim_signatures, ClaimSigner, ClaimSpec, DomainKeySet,
    };
    use crate::crypto::{fingerprint, generate_keypair, SigningAlgorithm, ALGORITHM_ED25519};
    use chrono::Utc;

    const DOMAIN: &str = "example.com";

    fn public_key(key_id: &str, pk: &[u8]) -> DomainPublicKey {
        DomainPublicKey {
            key_id: key_id.to_string(),
            public_key: pk.to_vec(),
            fingerprint: fingerprint(pk),
            algorithm: ALGORITHM_ED25519.to_string(),
            key_usage: "sign".to_string(),
            signed_by_key_id: None,
            key_signature: None,
            created_at: "2026-01-01T00:00:00+00:00".to_string(),
            expires_at: (Utc::now() + chrono::Duration::days(30)).to_rfc3339(),
            revoked_at: None,
        }
    }

    fn base_claim() -> Claim {
        Claim {
            claim_id: "019d6ac9-da5e-7073-a43c-351cd7aba003".to_string(),
            user_id: "019d6ac9-58bf-7303-8a5a-e60fba633239".to_string(),
            claim_type: "email".to_string(),
            claim_value: b"user@example.com".to_vec(),
            signatures: Vec::new(),
            attested_at: "2026-04-08T01:51:46.799297+00:00".to_string(),
            created_at: "2026-04-08T01:51:46.799297+00:00".to_string(),
            expires_at: None,
            revoked_at: None,
        }
    }

    fn sign_legacy(claim: &mut Claim, format: LegacyClaimFormat, key_id: &str, sk: &[u8]) {
        let payload = legacy_claim_payload(format, claim, DOMAIN, DOMAIN);
        claim.signatures.push(ClaimSignature {
            domain: DOMAIN.to_string(),
            signed_by_key_id: key_id.to_string(),
            signature: crypto::sign_with_algorithm(SigningAlgorithm::Ed25519, &payload, sk)
                .unwrap(),
        });
    }

    #[test]
    fn each_legacy_claim_format_is_recognized_and_not_accepted_by_the_verifier() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let keys = vec![public_key("k1", &pk)];
        let keysets = [DomainKeySet {
            domain: DOMAIN.to_string(),
            keys: keys.clone(),
        }];
        for format in LegacyClaimFormat::ALL {
            let mut claim = base_claim();
            sign_legacy(&mut claim, format, "k1", &sk);
            assert!(
                verify_claim_signatures(&claim, DOMAIN, &keysets).is_err(),
                "{format:?} must not verify under the current format"
            );
            assert_eq!(
                claim_provenance(&claim, DOMAIN, &keys),
                Some(Provenance::Legacy(format.name()))
            );

            // Re-signed with the same fields, it verifies under the current format.
            let resigned = sign_claim(
                &ClaimSpec {
                    claim_id: &claim.claim_id,
                    claim_type: &claim.claim_type,
                    claim_value: &claim.claim_value,
                    user_id: &claim.user_id,
                    subject_domain: DOMAIN,
                    expires_at: claim.expires_at.as_deref(),
                    attested_at: &claim.attested_at,
                },
                &[ClaimSigner {
                    domain: DOMAIN,
                    key_id: "k1",
                    algorithm: SigningAlgorithm::Ed25519,
                    private_key_bytes: &sk,
                }],
            )
            .unwrap();
            verify_claim_signatures(&resigned, DOMAIN, &keysets).unwrap();
            assert_eq!(
                claim_provenance(&resigned, DOMAIN, &keys),
                Some(Provenance::Current)
            );
        }
    }

    #[test]
    fn tampered_or_mixed_claims_have_no_provenance() {
        let (pk1, sk1) = generate_keypair(SigningAlgorithm::Ed25519);
        let (pk2, sk2) = generate_keypair(SigningAlgorithm::Ed25519);
        let keys = vec![public_key("k1", &pk1), public_key("k2", &pk2)];

        let mut tampered = base_claim();
        sign_legacy(&mut tampered, LegacyClaimFormat::V1Subject, "k1", &sk1);
        tampered.claim_value = b"attacker@example.net".to_vec();
        assert_eq!(claim_provenance(&tampered, DOMAIN, &keys), None);

        // One good signature and one bad one: not all verify, so no provenance.
        let mut mixed = base_claim();
        sign_legacy(&mut mixed, LegacyClaimFormat::V2, "k1", &sk1);
        sign_legacy(&mut mixed, LegacyClaimFormat::V2, "k2", &sk2);
        mixed.signatures[1].signature[0] ^= 0xff;
        assert_eq!(claim_provenance(&mixed, DOMAIN, &keys), None);

        // A key that is not this domain's.
        let (_, stranger_sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let mut stranger = base_claim();
        sign_legacy(&mut stranger, LegacyClaimFormat::V2, "k9", &stranger_sk);
        assert_eq!(claim_provenance(&stranger, DOMAIN, &keys), None);

        // No local signature at all.
        assert_eq!(claim_provenance(&base_claim(), DOMAIN, &keys), None);
    }

    #[test]
    fn a_key_revoked_before_the_attestation_does_not_count() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let mut key = public_key("k1", &pk);
        let mut claim = base_claim();
        sign_legacy(&mut claim, LegacyClaimFormat::V2, "k1", &sk);

        key.revoked_at = Some("2026-04-01T00:00:00+00:00".to_string());
        assert_eq!(claim_provenance(&claim, DOMAIN, &[key.clone()]), None);

        // Revoked after the claim was attested: the signature was good.
        key.revoked_at = Some("2026-05-01T00:00:00+00:00".to_string());
        assert_eq!(
            claim_provenance(&claim, DOMAIN, &[key]),
            Some(Provenance::Legacy(LegacyClaimFormat::V2.name()))
        );
    }

    #[test]
    fn legacy_consent_grant_is_recognized() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let keys = vec![public_key("k1", &pk)];
        let grant = ConsentGrant {
            grant_id: "g1".to_string(),
            user_id: "u1".to_string(),
            subject_domain: DOMAIN.to_string(),
            audience: "rp.example".to_string(),
            claim_types: vec!["email".to_string(), "handle".to_string()],
            issued_at: "2026-06-20T00:00:00+00:00".to_string(),
            expires_at: "2027-06-20T00:00:00+00:00".to_string(),
            revoked_at: None,
            application: None,
        };
        let payload = legacy_consent_payload(&grant, DOMAIN);
        let mut signed = SignedConsentGrant {
            grant: crate::generated::encode_consent_grant(&grant),
            signatures: vec![ClaimSignature {
                domain: DOMAIN.to_string(),
                signed_by_key_id: "k1".to_string(),
                signature: crypto::sign_with_algorithm(SigningAlgorithm::Ed25519, &payload, &sk)
                    .unwrap(),
            }],
        };
        assert_eq!(
            consent_provenance(&signed, &grant, DOMAIN, &keys),
            Some(Provenance::Legacy("consent-v1"))
        );
        signed.signatures[0].signature[0] ^= 0xff;
        assert_eq!(consent_provenance(&signed, &grant, DOMAIN, &keys), None);
    }

    #[test]
    fn legacy_revocation_is_recognized_and_self_signature_is_refused() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let keys = vec![public_key("sibling", &pk)];
        let mut cert = RevocationCertificate {
            target_key_id: "target".to_string(),
            target_fingerprint: "fp".to_string(),
            revoked_at: "2026-07-05T00:00:00+00:00".to_string(),
            signatures: Vec::new(),
        };
        let payload = legacy_revocation_payload("target", "fp", &cert.revoked_at, DOMAIN);
        cert.signatures.push(ClaimSignature {
            domain: DOMAIN.to_string(),
            signed_by_key_id: "sibling".to_string(),
            signature: crypto::sign_with_algorithm(SigningAlgorithm::Ed25519, &payload, &sk)
                .unwrap(),
        });
        assert_eq!(
            revocation_provenance(&cert, DOMAIN, &keys),
            Some(Provenance::Legacy("key-revocation-v1"))
        );

        cert.signatures[0].signed_by_key_id = "target".to_string();
        let keys = vec![public_key("target", &pk)];
        assert_eq!(revocation_provenance(&cert, DOMAIN, &keys), None);
    }

    #[test]
    fn legacy_vouch_is_recognized() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let signer = public_key("signer", &pk);
        let (enc_pub, _) = crypto::generate_x25519_keypair();
        let expires_at = "2027-01-01T00:00:00+00:00";
        let payload = legacy_key_vouch_payload(&fingerprint(&enc_pub), expires_at);
        let mut enc = DomainPublicKey {
            key_id: "enc".to_string(),
            public_key: enc_pub.to_vec(),
            fingerprint: fingerprint(&enc_pub),
            algorithm: "x25519".to_string(),
            key_usage: "encrypt".to_string(),
            signed_by_key_id: Some("signer".to_string()),
            key_signature: Some(
                crypto::sign_with_algorithm(SigningAlgorithm::Ed25519, &payload, &sk).unwrap(),
            ),
            created_at: "2026-06-02T00:00:00+00:00".to_string(),
            expires_at: expires_at.to_string(),
            revoked_at: None,
        };
        assert_eq!(
            vouch_provenance(&enc, &signer),
            Some(Provenance::Legacy("key-vouch-v1"))
        );

        // A swapped public key no longer matches the vouched fingerprint.
        let (other_pub, _) = crypto::generate_x25519_keypair();
        enc.public_key = other_pub.to_vec();
        assert_eq!(vouch_provenance(&enc, &signer), None);
    }
}
