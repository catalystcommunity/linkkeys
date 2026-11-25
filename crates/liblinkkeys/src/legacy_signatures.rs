// LINKKEYS-TRUST-CRITICAL: a change to this file needs a trust approval. See docs/trust-change-control.md.
//! Signed payload and record formats of older releases, and the provenance
//! checks that use them.
//!
//! During alpha the rule is "re-sign, do not accept old formats": current
//! verifiers accept only the current format, so every stored signature made in
//! an older format stops verifying when the format changes. This module lets
//! the server prove that a stored signature is its own work in a known older
//! format before it re-signs the record in the current format.
//!
//! The formats, newest first:
//!
//! - **v1alpha text** (v0.14.1 to the release that typed CSIL timestamps):
//!   the current `-v1alpha` tags, with timestamps as RFC 3339 text in the
//!   signed tuples, and stored CBOR records with timestamps as text and enum
//!   fields as text labels. [`upgrade_legacy_record`] rewrites such a record
//!   into the current encoding.
//! - **v1 / v2** (before v0.14.1, ded0471): the old tags.
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

use ciborium::value::Value;
use time::OffsetDateTime;

use crate::application_keys::attestation_signature_input;
use crate::claims::{claim_sign_payload, signed_times, CLAIM_PAYLOAD_TAG};
use crate::consent::canonical_types;
use crate::crypto;
use crate::dns::key_vouch_payload;
use crate::generated::types::{
    AeadSuite, ApplicationKeyAttestation, Claim, ClaimSignature, ClaimValueType, ConsentGrant,
    DomainPublicKey, KeyAlgorithm, KeyUsage, RevocationCertificate,
    SignedApplicationKeyAttestation,
};
use crate::revocation::{revocation_payload, REVOCATION_TAG};
use crate::timestamp::{Rfc3339 as _, SignedTime};

const CLAIM_V1_TAG: &str = "linkkeys-claim-v1";
const CLAIM_V2_TAG: &str = "linkkeys-claim-v2";
pub const CONSENT_V1_TAG: &str = "linkkeys-consent-v1";
pub const CONSENT_V1ALPHA_TAG: &str = "linkkeys-consent-v1alpha";
pub const REVOCATION_V1_TAG: &str = "linkkeys-key-revocation-v1";
pub const KEY_VOUCH_V1_TAG: &str = "linkkeys-key-vouch-v1";
pub const KEY_VOUCH_V1ALPHA_TAG: &str = "linkkeys-key-vouch-v1alpha";

/// The name of the v1alpha text format of every record kind.
pub const V1ALPHA_TEXT: &str = "v1alpha text";

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
    /// ded0471 (v0.14.1) until typed timestamps: the current tuple with
    /// `expires_at` and `attested_at` as RFC 3339 text.
    V1AlphaText,
}

impl LegacyClaimFormat {
    /// Every legacy claim format, newest first.
    pub const ALL: [LegacyClaimFormat; 4] = [
        LegacyClaimFormat::V1AlphaText,
        LegacyClaimFormat::V2,
        LegacyClaimFormat::V1Subject,
        LegacyClaimFormat::V1SigningDomain,
    ];

    pub fn name(self) -> &'static str {
        match self {
            LegacyClaimFormat::V1SigningDomain => "claim-v1 (user_id, signing domain)",
            LegacyClaimFormat::V1Subject => "claim-v1 (user@domain subject)",
            LegacyClaimFormat::V2 => "claim-v2",
            LegacyClaimFormat::V1AlphaText => V1ALPHA_TEXT,
        }
    }
}

fn cbor<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out)
        .expect("CBOR serialization of a legacy payload cannot fail");
    out
}

/// The RFC 3339 text that every format before typed timestamps signed. The
/// server wrote it with [`crate::timestamp::Rfc3339::to_rfc3339`] and served
/// stored times in the same form, so this rebuilds the signed text.
fn text(t: &OffsetDateTime) -> String {
    t.to_rfc3339()
}

/// The bytes a signature in `format` covered for `claim`.
pub fn legacy_claim_payload(
    format: LegacyClaimFormat,
    claim: &Claim,
    subject_domain: &str,
    signing_domain: &str,
) -> Vec<u8> {
    legacy_claim_payload_with(
        format,
        claim,
        subject_domain,
        signing_domain,
        &text(&claim.attested_at),
    )
}

/// The `YYYY-MM-DD HH:MM:SS` text that SQLite's `datetime('now')` wrote.
/// SQLite claims from before 2026-07-02 had this as `attested_at`, and the
/// server signed it as stored.
pub fn sqlite_datetime_text(t: &OffsetDateTime) -> String {
    let t = t.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// [`legacy_claim_payload`] with the attestation time as the given text.
pub fn legacy_claim_payload_with(
    format: LegacyClaimFormat,
    claim: &Claim,
    subject_domain: &str,
    signing_domain: &str,
    attested_text: &str,
) -> Vec<u8> {
    let value = serde_bytes::Bytes::new(&claim.claim_value);
    let subject = format!("{}@{}", claim.user_id, subject_domain);
    let expires_at = claim.expires_at.as_ref().map(text);
    let attested_at = attested_text;
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
            attested_at,
        )),
        LegacyClaimFormat::V1AlphaText => cbor(&(
            CLAIM_PAYLOAD_TAG,
            claim.claim_id.as_str(),
            claim.claim_type.as_str(),
            value,
            subject.as_str(),
            signing_domain,
            expires_at,
            attested_at,
        )),
    }
}

/// The text form of a consent grant's two signed times, as the old grant
/// bytes carried them.
pub struct LegacyGrantTimes {
    pub issued_at: String,
    pub expires_at: String,
}

/// The bytes a consent signature covered in the `format` named by `tag`, with
/// the times as text. The v1 format (0026221 to ded0471) had no application
/// element; the v1alpha text format appends it when the grant names one.
pub fn legacy_consent_payload(
    tag: &str,
    grant: &ConsentGrant,
    times: &LegacyGrantTimes,
    signing_domain: &str,
) -> Vec<u8> {
    let subject = format!("{}@{}", grant.user_id, grant.subject_domain);
    let types = canonical_types(&grant.claim_types);
    match (&grant.application, tag == CONSENT_V1_TAG) {
        (Some(app), false) => cbor(&(
            tag,
            grant.grant_id.as_str(),
            subject.as_str(),
            grant.audience.as_str(),
            types,
            times.issued_at.as_str(),
            times.expires_at.as_str(),
            signing_domain,
            (
                app.subject_user_id.as_str(),
                app.subject_domain.as_str(),
                app.application_id.as_str(),
            ),
        )),
        _ => cbor(&(
            tag,
            grant.grant_id.as_str(),
            subject.as_str(),
            grant.audience.as_str(),
            types,
            times.issued_at.as_str(),
            times.expires_at.as_str(),
            signing_domain,
        )),
    }
}

/// The bytes a key revocation signature covered: the v1 tag or the v1alpha
/// tag, with `revoked_at` as text.
pub fn legacy_revocation_payload(
    tag: &str,
    target_key_id: &str,
    target_fingerprint: &str,
    revoked_at: &str,
    signing_domain: &str,
) -> Vec<u8> {
    cbor(&(
        tag,
        target_key_id,
        target_fingerprint,
        revoked_at,
        signing_domain,
    ))
}

/// The bytes an encryption-key vouch covered: the v1 tag or the v1alpha tag,
/// with the expiry as text.
pub fn legacy_key_vouch_payload(tag: &str, enc_fingerprint: &str, enc_expires_at: &str) -> Vec<u8> {
    cbor(&(tag, enc_fingerprint, enc_expires_at))
}

// ---------------------------------------------------------------------------
// Stored CBOR records of the v1alpha text format
// ---------------------------------------------------------------------------

/// Why an old stored record could not be rewritten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyRecordError(pub String);

impl std::fmt::Display for LegacyRecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LegacyRecordError {}

fn is_time_key(key: &str) -> bool {
    key.ends_with("_at") || matches!(key, "timestamp" | "renewable_until" | "since")
}

fn enum_number(key: &str, label: &str) -> Option<Result<i64, LegacyRecordError>> {
    let unknown = || LegacyRecordError(format!("unknown {key} label {label:?}"));
    let number = match key {
        "algorithm" => KeyAlgorithm::from_label(label).map(|v| v.to_number()),
        "key_usage" => KeyUsage::from_label(label).map(|v| v.to_number()),
        "datatype" | "value_type" => ClaimValueType::from_label(label).map(|v| v.to_number()),
        "suite" | "supported_suites" => match label {
            "aes-256-gcm" => Some(AeadSuite::Aes256Gcm.to_number()),
            "chacha20-poly1305" => Some(AeadSuite::Chacha20Poly1305.to_number()),
            _ => None,
        },
        _ => return None,
    };
    Some(number.ok_or_else(unknown))
}

fn csil_timestamp_text(t: &OffsetDateTime) -> Result<String, LegacyRecordError> {
    t.to_offset(time::UtcOffset::UTC)
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| LegacyRecordError(format!("timestamp out of range: {e}")))
}

fn upgrade_value(key: Option<&str>, value: Value) -> Result<Value, LegacyRecordError> {
    match (key, value) {
        (Some(k), Value::Text(s)) if is_time_key(k) => {
            let t = crate::timestamp::parse_rfc3339(&s)
                .map_err(|e| LegacyRecordError(format!("{k}: {e}")))?;
            Ok(Value::Tag(
                0,
                Box::new(Value::Text(csil_timestamp_text(&t)?)),
            ))
        }
        (Some(k), Value::Text(s)) => match enum_number(k, &s) {
            Some(n) => Ok(Value::Integer(n?.into())),
            None => Ok(Value::Text(s)),
        },
        (key, Value::Array(items)) => items
            .into_iter()
            .map(|v| upgrade_value(key, v))
            .collect::<Result<_, _>>()
            .map(Value::Array),
        (_, Value::Map(entries)) => entries
            .into_iter()
            .map(|(k, v)| {
                let name = k.as_text().map(str::to_string);
                Ok((k, upgrade_value(name.as_deref(), v)?))
            })
            .collect::<Result<_, LegacyRecordError>>()
            .map(Value::Map),
        (_, other) => Ok(other),
    }
}

/// Rewrite one stored CBOR record of the v1alpha text format into the current
/// encoding: a time field (`*_at`, `timestamp`, `renewable_until`, `since`)
/// that holds RFC 3339 text becomes a CBOR tag 0 timestamp, and an
/// `algorithm`, `key_usage`, `datatype`, `value_type`, `suite`, or
/// `supported_suites` text label becomes its CSIL number. Nested maps and
/// arrays are rewritten; byte strings (for example embedded signed bytes) are
/// not. A record already in the current encoding comes back unchanged.
///
/// The caller decodes the result with the generated decoder, so a record with
/// any other difference fails there.
pub fn upgrade_legacy_record(bytes: &[u8]) -> Result<Vec<u8>, LegacyRecordError> {
    let value: Value = ciborium::de::from_reader(bytes)
        .map_err(|e| LegacyRecordError(format!("not CBOR: {e}")))?;
    Ok(cbor(&upgrade_value(None, value)?))
}

/// Rewrite a record in the current encoding into the v1alpha text encoding:
/// a tag 0 timestamp becomes the RFC 3339 text that the server wrote, and an
/// enum number in one of the fields that [`upgrade_legacy_record`] knows
/// becomes its old text label. The inverse of [`upgrade_legacy_record`]; it
/// exists to build old records in tests.
pub fn downgrade_to_v1alpha_text(bytes: &[u8]) -> Result<Vec<u8>, LegacyRecordError> {
    fn walk(key: Option<&str>, v: Value) -> Result<Value, LegacyRecordError> {
        Ok(match (key, v) {
            (_, Value::Tag(0, inner)) => match *inner {
                Value::Text(t) => Value::Text(
                    crate::timestamp::parse_rfc3339(&t)
                        .map_err(|e| LegacyRecordError(e.to_string()))?
                        .to_rfc3339(),
                ),
                other => Value::Tag(0, Box::new(other)),
            },
            (Some(k), Value::Integer(n)) => {
                let n = i64::try_from(i128::from(n))
                    .map_err(|_| LegacyRecordError("integer out of range".into()))?;
                let label = match k {
                    "algorithm" => KeyAlgorithm::from_number(n).map(|v| v.as_str()),
                    "key_usage" => KeyUsage::from_number(n).map(|v| v.as_str()),
                    "datatype" | "value_type" => ClaimValueType::from_number(n).map(|v| v.as_str()),
                    "suite" | "supported_suites" => {
                        AeadSuite::from_number(n).map(|v| v.kdf_label())
                    }
                    _ => None,
                };
                match label {
                    Some(l) => Value::Text(l.to_string()),
                    None => Value::Integer(n.into()),
                }
            }
            (key, Value::Array(items)) => Value::Array(
                items
                    .into_iter()
                    .map(|v| walk(key, v))
                    .collect::<Result<_, _>>()?,
            ),
            (_, Value::Map(entries)) => Value::Map(
                entries
                    .into_iter()
                    .map(|(k, v)| {
                        let name = k.as_text().map(str::to_string);
                        Ok((k, walk(name.as_deref(), v)?))
                    })
                    .collect::<Result<_, LegacyRecordError>>()?,
            ),
            (_, other) => other,
        })
    }
    let value: Value = ciborium::de::from_reader(bytes)
        .map_err(|e| LegacyRecordError(format!("not CBOR: {e}")))?;
    Ok(cbor(&walk(None, value)?))
}

/// The text of field `key` in a stored CBOR map, if it is text.
fn text_field(bytes: &[u8], key: &str) -> Option<String> {
    let value: Value = ciborium::de::from_reader(bytes).ok()?;
    value.as_map()?.iter().find_map(|(k, v)| {
        (k.as_text() == Some(key))
            .then(|| v.as_text().map(str::to_string))
            .flatten()
    })
}

// ---------------------------------------------------------------------------
// Provenance checks
// ---------------------------------------------------------------------------

/// Whether `key` can stand behind a signature made at `signed_at`: it is a
/// signing key, and it was not revoked at that time. Expiry does not matter:
/// a key that expired after it signed is retired, not compromised.
fn key_usable(key: &DomainPublicKey, signed_at: &OffsetDateTime) -> bool {
    key.key_usage == KeyUsage::Sign && key.revoked_at.is_none_or(|r| *signed_at < r)
}

/// True when `signatures` is not empty and every one verifies over `payload`
/// with the key it names in `keys`.
fn all_verify(
    signatures: &[&ClaimSignature],
    keys: &[DomainPublicKey],
    signed_at: &OffsetDateTime,
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
    let signed_at = &claim.attested_at;
    if let Ok((expires_at, attested_at)) =
        signed_times(claim.expires_at.as_ref(), &claim.attested_at)
    {
        let current = claim_sign_payload(
            &claim.claim_id,
            &claim.claim_type,
            &claim.claim_value,
            &claim.user_id,
            local_domain,
            local_domain,
            expires_at,
            attested_at,
        );
        if all_verify(&local, keys, signed_at, &current) {
            return Some(Provenance::Current);
        }
    }
    // The attestation text as the server served it: RFC 3339, or, for an old
    // SQLite row, SQLite's own form.
    let mut texts = vec![text(&claim.attested_at)];
    if claim.attested_at.nanosecond() == 0 {
        texts.push(sqlite_datetime_text(&claim.attested_at));
    }
    LegacyClaimFormat::ALL.into_iter().find_map(|format| {
        texts.iter().find_map(|attested| {
            let payload =
                legacy_claim_payload_with(format, claim, local_domain, local_domain, attested);
            all_verify(&local, keys, signed_at, &payload)
                .then_some(Provenance::Legacy(format.name()))
        })
    })
}

/// A stored consent grant, decoded in the current or an older encoding.
pub struct StoredConsentGrant {
    /// The grant in the current types.
    pub grant: ConsentGrant,
    /// The stored signatures.
    pub signatures: Vec<ClaimSignature>,
    /// The text times, when the stored grant used the v1alpha text encoding.
    pub legacy_times: Option<LegacyGrantTimes>,
}

/// Decode a stored `SignedConsentGrant` in the current encoding or the
/// v1alpha text encoding.
pub fn decode_stored_consent_grant(stored: &[u8]) -> Result<StoredConsentGrant, LegacyRecordError> {
    let decode_err = |e: crate::generated::CsilCborError| LegacyRecordError(e.to_string());
    let signed = crate::generated::decode_signed_consent_grant(stored).map_err(decode_err)?;
    if let Ok(grant) = crate::generated::decode_consent_grant(&signed.grant) {
        return Ok(StoredConsentGrant {
            grant,
            signatures: signed.signatures,
            legacy_times: None,
        });
    }
    let times = match (
        text_field(&signed.grant, "issued_at"),
        text_field(&signed.grant, "expires_at"),
    ) {
        (Some(issued_at), Some(expires_at)) => LegacyGrantTimes {
            issued_at,
            expires_at,
        },
        _ => return Err(LegacyRecordError("grant times are not text".into())),
    };
    let upgraded = upgrade_legacy_record(&signed.grant)?;
    let grant = crate::generated::decode_consent_grant(&upgraded).map_err(decode_err)?;
    Ok(StoredConsentGrant {
        grant,
        signatures: signed.signatures,
        legacy_times: Some(times),
    })
}

/// The format under which every `local_domain` signature of a stored consent
/// grant verifies with a key in `keys`, or `None`.
pub fn consent_provenance(
    stored: &StoredConsentGrant,
    local_domain: &str,
    keys: &[DomainPublicKey],
) -> Option<Provenance> {
    let grant = &stored.grant;
    let local = local_signatures(&stored.signatures, local_domain);
    let signed_at = &grant.issued_at;
    let Some(times) = &stored.legacy_times else {
        let (issued_at, expires_at) =
            crate::consent::signed_times(&grant.issued_at, &grant.expires_at).ok()?;
        let current = crate::consent::consent_sign_payload(
            &grant.grant_id,
            &grant.user_id,
            &grant.subject_domain,
            &grant.audience,
            &canonical_types(&grant.claim_types),
            issued_at,
            expires_at,
            local_domain,
            grant.application.as_ref(),
        );
        return all_verify(&local, keys, signed_at, &current).then_some(Provenance::Current);
    };
    let v1alpha = legacy_consent_payload(CONSENT_V1ALPHA_TAG, grant, times, local_domain);
    if all_verify(&local, keys, signed_at, &v1alpha) {
        return Some(Provenance::Legacy(V1ALPHA_TEXT));
    }
    // The v1 format had no application, so a grant that names one is not v1.
    if grant.application.is_none()
        && all_verify(
            &local,
            keys,
            signed_at,
            &legacy_consent_payload(CONSENT_V1_TAG, grant, times, local_domain),
        )
    {
        return Some(Provenance::Legacy("consent-v1"));
    }
    None
}

/// A stored key revocation certificate, decoded in the current or the
/// v1alpha text encoding.
pub struct StoredRevocation {
    pub cert: RevocationCertificate,
    /// The text `revoked_at`, when the stored certificate used the v1alpha
    /// text encoding.
    pub legacy_revoked_at: Option<String>,
}

/// Decode a stored `RevocationCertificate` in the current encoding or the
/// v1alpha text encoding.
pub fn decode_stored_revocation(stored: &[u8]) -> Result<StoredRevocation, LegacyRecordError> {
    if let Ok(cert) = crate::generated::decode_revocation_certificate(stored) {
        return Ok(StoredRevocation {
            cert,
            legacy_revoked_at: None,
        });
    }
    let revoked_at = text_field(stored, "revoked_at")
        .ok_or_else(|| LegacyRecordError("revoked_at is not text".into()))?;
    let upgraded = upgrade_legacy_record(stored)?;
    let cert = crate::generated::decode_revocation_certificate(&upgraded)
        .map_err(|e| LegacyRecordError(e.to_string()))?;
    Ok(StoredRevocation {
        cert,
        legacy_revoked_at: Some(revoked_at),
    })
}

/// The format under which every `local_domain` signature of a stored
/// revocation certificate verifies with a sibling key in `keys`, or `None`. A
/// signature by the revoked key itself never counts.
pub fn revocation_provenance(
    stored: &StoredRevocation,
    local_domain: &str,
    keys: &[DomainPublicKey],
) -> Option<Provenance> {
    let cert = &stored.cert;
    let local = local_signatures(&cert.signatures, local_domain);
    if local
        .iter()
        .any(|s| s.signed_by_key_id == cert.target_key_id)
    {
        return None;
    }
    let signed_at = &cert.revoked_at;
    let Some(revoked_text) = &stored.legacy_revoked_at else {
        let revoked_at = SignedTime::new(&cert.revoked_at).ok()?;
        let current = revocation_payload(
            &cert.target_key_id,
            &cert.target_fingerprint,
            revoked_at,
            local_domain,
        );
        return all_verify(&local, keys, signed_at, &current).then_some(Provenance::Current);
    };
    [
        (REVOCATION_TAG, V1ALPHA_TEXT),
        (REVOCATION_V1_TAG, "key-revocation-v1"),
    ]
    .into_iter()
    .find_map(|(tag, name)| {
        let payload = legacy_revocation_payload(
            tag,
            &cert.target_key_id,
            &cert.target_fingerprint,
            revoked_text,
            local_domain,
        );
        all_verify(&local, keys, signed_at, &payload).then_some(Provenance::Legacy(name))
    })
}

/// The format under which the stored vouch of `enc_key` verifies with
/// `signer`, the signing key it names, or `None`. The fingerprint is
/// recomputed from the public key, as verifiers do.
pub fn vouch_provenance(enc_key: &DomainPublicKey, signer: &DomainPublicKey) -> Option<Provenance> {
    if enc_key.signed_by_key_id.as_deref() != Some(signer.key_id.as_str()) {
        return None;
    }
    let signature = enc_key.key_signature.as_deref()?;
    if !key_usable(signer, &enc_key.created_at) {
        return None;
    }
    let fingerprint = crypto::fingerprint(&enc_key.public_key);
    let verifies = |payload: &[u8]| {
        crypto::resolve_and_verify(&signer.algorithm, payload, signature, &signer.public_key)
            .is_ok()
    };
    if SignedTime::new(&enc_key.expires_at)
        .is_ok_and(|expires| verifies(&key_vouch_payload(&fingerprint, expires)))
    {
        return Some(Provenance::Current);
    }
    let expires_text = text(&enc_key.expires_at);
    [
        (KEY_VOUCH_V1ALPHA_TAG, V1ALPHA_TEXT),
        (KEY_VOUCH_V1_TAG, "key-vouch-v1"),
    ]
    .into_iter()
    .find_map(|(tag, name)| {
        verifies(&legacy_key_vouch_payload(tag, &fingerprint, &expires_text))
            .then_some(Provenance::Legacy(name))
    })
}

/// A stored application-key attestation whose local signatures verify, with
/// the attestation in the current types.
pub struct StoredAttestation {
    pub attestation: ApplicationKeyAttestation,
    pub provenance: Provenance,
}

/// Decode a stored `SignedApplicationKeyAttestation` and check that every
/// `local_domain` signature verifies over its stored bytes with a key in
/// `keys`. The signatures cover the attestation bytes, so an attestation in
/// the v1alpha text encoding still verifies as stored; its fields are then
/// rewritten with [`upgrade_legacy_record`]. `None` when a signature does not
/// verify or the record does not decode.
pub fn attestation_provenance(
    stored: &[u8],
    local_domain: &str,
    keys: &[DomainPublicKey],
) -> Option<StoredAttestation> {
    let signed: SignedApplicationKeyAttestation =
        crate::generated::decode_signed_application_key_attestation(stored).ok()?;
    let (attestation, provenance) =
        match crate::generated::decode_application_key_attestation(&signed.attestation) {
            Ok(a) => (a, Provenance::Current),
            Err(_) => {
                let upgraded = upgrade_legacy_record(&signed.attestation).ok()?;
                let a = crate::generated::decode_application_key_attestation(&upgraded).ok()?;
                (a, Provenance::Legacy(V1ALPHA_TEXT))
            }
        };
    let local = local_signatures(&signed.signatures, local_domain);
    let message = attestation_signature_input(&signed.attestation);
    all_verify(&local, keys, &attestation.attested_at, &message).then_some(StoredAttestation {
        attestation,
        provenance,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::{
        sign_claim, verify_claim_signatures, ClaimSigner, ClaimSpec, DomainKeySet,
    };
    use crate::consent::{sign_consent, verify_consent, ConsentSpec};
    use crate::crypto::{fingerprint, generate_keypair, SigningAlgorithm};
    use crate::revocation::{build_revocation_certificate, RevocationSpec};
    use crate::timestamp::parse_rfc3339;

    const DOMAIN: &str = "example.com";

    fn at(s: &str) -> OffsetDateTime {
        parse_rfc3339(s).unwrap()
    }

    fn public_key(key_id: &str, pk: &[u8]) -> DomainPublicKey {
        DomainPublicKey {
            key_id: key_id.to_string(),
            public_key: pk.to_vec(),
            fingerprint: fingerprint(pk),
            algorithm: KeyAlgorithm::Ed25519,
            key_usage: KeyUsage::Sign,
            signed_by_key_id: None,
            key_signature: None,
            created_at: at("2026-01-01T00:00:00+00:00"),
            expires_at: OffsetDateTime::now_utc() + time::Duration::days(30),
            revoked_at: None,
        }
    }

    fn signer<'a>(key_id: &'a str, sk: &'a [u8]) -> ClaimSigner<'a> {
        ClaimSigner {
            domain: DOMAIN,
            key_id,
            algorithm: SigningAlgorithm::Ed25519,
            private_key_bytes: sk,
        }
    }

    fn signature(key_id: &str, sk: &[u8], payload: &[u8]) -> ClaimSignature {
        ClaimSignature {
            domain: DOMAIN.to_string(),
            signed_by_key_id: key_id.to_string(),
            signature: crypto::sign_with_algorithm(SigningAlgorithm::Ed25519, payload, sk).unwrap(),
        }
    }

    fn downgrade(bytes: &[u8]) -> Vec<u8> {
        downgrade_to_v1alpha_text(bytes).unwrap()
    }

    fn base_claim() -> Claim {
        Claim {
            claim_id: "019d6ac9-da5e-7073-a43c-351cd7aba003".to_string(),
            user_id: "019d6ac9-58bf-7303-8a5a-e60fba633239".to_string(),
            claim_type: "email".to_string(),
            claim_value: b"user@example.com".to_vec(),
            signatures: Vec::new(),
            attested_at: at("2026-04-08T01:51:46.799297+00:00"),
            created_at: at("2026-04-08T01:51:46.799297+00:00"),
            expires_at: None,
            revoked_at: None,
        }
    }

    fn sign_legacy(claim: &mut Claim, format: LegacyClaimFormat, key_id: &str, sk: &[u8]) {
        let payload = legacy_claim_payload(format, claim, DOMAIN, DOMAIN);
        claim.signatures.push(signature(key_id, sk, &payload));
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

            // Re-signed at whole seconds, it verifies under the current format.
            let resigned = sign_claim(
                &ClaimSpec {
                    claim_id: &claim.claim_id,
                    claim_type: &claim.claim_type,
                    claim_value: &claim.claim_value,
                    user_id: &claim.user_id,
                    subject_domain: DOMAIN,
                    expires_at: claim.expires_at,
                    attested_at: crate::timestamp::whole_seconds(claim.attested_at),
                },
                &[signer("k1", &sk)],
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
    fn the_v1alpha_text_claim_payload_differs_from_the_current_one_only_in_its_times() {
        let mut claim = base_claim();
        claim.attested_at = at("2026-04-08T01:51:46+00:00");
        let current = claim_sign_payload(
            &claim.claim_id,
            &claim.claim_type,
            &claim.claim_value,
            &claim.user_id,
            DOMAIN,
            DOMAIN,
            None,
            SignedTime::new(&claim.attested_at).unwrap(),
        );
        let legacy = legacy_claim_payload(LegacyClaimFormat::V1AlphaText, &claim, DOMAIN, DOMAIN);
        assert_ne!(current, legacy);
        let text = b"2026-04-08T01:51:46+00:00";
        assert!(legacy.windows(text.len()).any(|w| w == text));
    }

    #[test]
    fn tampered_or_mixed_claims_have_no_provenance() {
        let (pk1, sk1) = generate_keypair(SigningAlgorithm::Ed25519);
        let (pk2, sk2) = generate_keypair(SigningAlgorithm::Ed25519);
        let keys = vec![public_key("k1", &pk1), public_key("k2", &pk2)];

        let mut tampered = base_claim();
        sign_legacy(&mut tampered, LegacyClaimFormat::V1AlphaText, "k1", &sk1);
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
        sign_legacy(&mut claim, LegacyClaimFormat::V1AlphaText, "k1", &sk);

        key.revoked_at = Some(at("2026-04-01T00:00:00+00:00"));
        assert_eq!(claim_provenance(&claim, DOMAIN, &[key.clone()]), None);

        // Revoked after the claim was attested: the signature was good.
        key.revoked_at = Some(at("2026-05-01T00:00:00+00:00"));
        assert_eq!(
            claim_provenance(&claim, DOMAIN, &[key]),
            Some(Provenance::Legacy(V1ALPHA_TEXT))
        );
    }

    fn grant(application: Option<crate::generated::types::ApplicationRef>) -> ConsentGrant {
        ConsentGrant {
            grant_id: "g1".to_string(),
            user_id: "u1".to_string(),
            subject_domain: DOMAIN.to_string(),
            audience: "rp.example".to_string(),
            claim_types: vec!["email".to_string(), "handle".to_string()],
            issued_at: at("2026-06-20T00:00:00.250+00:00"),
            expires_at: at("2027-06-20T00:00:00+00:00"),
            revoked_at: None,
            application,
        }
    }

    /// A stored grant in the v1alpha text encoding, signed under `tag`.
    fn legacy_stored_grant(grant: &ConsentGrant, tag: &str, key_id: &str, sk: &[u8]) -> Vec<u8> {
        let times = LegacyGrantTimes {
            issued_at: grant.issued_at.to_rfc3339(),
            expires_at: grant.expires_at.to_rfc3339(),
        };
        let payload = legacy_consent_payload(tag, grant, &times, DOMAIN);
        crate::generated::encode_signed_consent_grant(
            &crate::generated::types::SignedConsentGrant {
                grant: downgrade(&crate::generated::encode_consent_grant(grant).unwrap()),
                signatures: vec![signature(key_id, sk, &payload)],
            },
        )
        .unwrap()
    }

    #[test]
    fn legacy_consent_grants_are_recognized_and_decoded() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let keys = vec![public_key("k1", &pk)];
        let app = crate::generated::types::ApplicationRef {
            subject_user_id: "owner".to_string(),
            subject_domain: "rp.example".to_string(),
            application_id: "app".to_string(),
        };
        for (g, tag, name) in [
            (grant(None), CONSENT_V1ALPHA_TAG, V1ALPHA_TEXT),
            (grant(Some(app.clone())), CONSENT_V1ALPHA_TAG, V1ALPHA_TEXT),
            (grant(None), CONSENT_V1_TAG, "consent-v1"),
        ] {
            let bytes = legacy_stored_grant(&g, tag, "k1", &sk);
            let mut stored = decode_stored_consent_grant(&bytes).unwrap();
            assert_eq!(
                stored.grant, g,
                "the old encoding decodes to the same grant"
            );
            assert!(stored.legacy_times.is_some());
            assert_eq!(
                consent_provenance(&stored, DOMAIN, &keys),
                Some(Provenance::Legacy(name))
            );
            stored.signatures[0].signature[0] ^= 0xff;
            assert_eq!(consent_provenance(&stored, DOMAIN, &keys), None);
        }
        // A grant that names an application was never v1.
        let bytes = legacy_stored_grant(&grant(Some(app)), CONSENT_V1_TAG, "k1", &sk);
        let stored = decode_stored_consent_grant(&bytes).unwrap();
        assert_eq!(consent_provenance(&stored, DOMAIN, &keys), None);
    }

    #[test]
    fn a_current_consent_grant_is_current() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let keys = vec![public_key("k1", &pk)];
        let g = grant(None);
        let signed = sign_consent(
            &ConsentSpec {
                grant_id: &g.grant_id,
                user_id: &g.user_id,
                subject_domain: DOMAIN,
                audience: &g.audience,
                claim_types: &g.claim_types,
                issued_at: crate::timestamp::whole_seconds(g.issued_at),
                expires_at: g.expires_at,
                application: None,
            },
            &[signer("k1", &sk)],
        )
        .unwrap();
        let keysets = [DomainKeySet {
            domain: DOMAIN.to_string(),
            keys: keys.clone(),
        }];
        verify_consent(&signed, DOMAIN, &g.audience, None, &keysets).unwrap();
        let stored = decode_stored_consent_grant(
            &crate::generated::encode_signed_consent_grant(&signed).unwrap(),
        )
        .unwrap();
        assert!(stored.legacy_times.is_none());
        assert_eq!(
            consent_provenance(&stored, DOMAIN, &keys),
            Some(Provenance::Current)
        );
    }

    #[test]
    fn legacy_revocations_are_recognized_and_self_signature_is_refused() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let keys = vec![public_key("sibling", &pk)];
        for (tag, name) in [
            (REVOCATION_TAG, V1ALPHA_TEXT),
            (REVOCATION_V1_TAG, "key-revocation-v1"),
        ] {
            let revoked_at = at("2026-07-05T00:00:00+00:00");
            let payload =
                legacy_revocation_payload(tag, "target", "fp", &revoked_at.to_rfc3339(), DOMAIN);
            let cert = RevocationCertificate {
                target_key_id: "target".to_string(),
                target_fingerprint: "fp".to_string(),
                revoked_at,
                signatures: vec![signature("sibling", &sk, &payload)],
            };
            let bytes = downgrade(&crate::generated::encode_revocation_certificate(&cert).unwrap());
            let stored = decode_stored_revocation(&bytes).unwrap();
            assert_eq!(stored.cert, cert);
            assert_eq!(
                revocation_provenance(&stored, DOMAIN, &keys),
                Some(Provenance::Legacy(name))
            );
        }

        // Current format.
        let cert = build_revocation_certificate(
            &RevocationSpec {
                target_key_id: "target",
                target_fingerprint: "fp",
                revoked_at: at("2026-07-05T00:00:00+00:00"),
            },
            &[signer("sibling", &sk)],
        )
        .unwrap();
        let stored = decode_stored_revocation(
            &crate::generated::encode_revocation_certificate(&cert).unwrap(),
        )
        .unwrap();
        assert_eq!(
            revocation_provenance(&stored, DOMAIN, &keys),
            Some(Provenance::Current)
        );

        // A key can never authorize its own revocation.
        let mut own = stored;
        own.cert.signatures[0].signed_by_key_id = "target".to_string();
        let keys = vec![public_key("target", &pk)];
        assert_eq!(revocation_provenance(&own, DOMAIN, &keys), None);
    }

    #[test]
    fn legacy_vouches_are_recognized() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let signer_key = public_key("signer", &pk);
        let (enc_pub, _) = crypto::generate_x25519_keypair();
        let expires_at = at("2027-01-01T00:00:00+00:00");
        for (tag, name) in [
            (KEY_VOUCH_V1ALPHA_TAG, V1ALPHA_TEXT),
            (KEY_VOUCH_V1_TAG, "key-vouch-v1"),
        ] {
            let payload =
                legacy_key_vouch_payload(tag, &fingerprint(&enc_pub), &expires_at.to_rfc3339());
            let mut enc = DomainPublicKey {
                key_id: "enc".to_string(),
                public_key: enc_pub.to_vec(),
                fingerprint: fingerprint(&enc_pub),
                algorithm: KeyAlgorithm::X25519,
                key_usage: KeyUsage::Encrypt,
                signed_by_key_id: Some("signer".to_string()),
                key_signature: Some(
                    crypto::sign_with_algorithm(SigningAlgorithm::Ed25519, &payload, &sk).unwrap(),
                ),
                created_at: at("2026-06-02T00:00:00+00:00"),
                expires_at,
                revoked_at: None,
            };
            assert!(!crate::dns::verify_key_vouch(&enc, &signer_key));
            assert_eq!(
                vouch_provenance(&enc, &signer_key),
                Some(Provenance::Legacy(name))
            );

            // A swapped public key no longer matches the vouched fingerprint.
            let (other_pub, _) = crypto::generate_x25519_keypair();
            enc.public_key = other_pub.to_vec();
            assert_eq!(vouch_provenance(&enc, &signer_key), None);
        }
    }

    fn attestation() -> ApplicationKeyAttestation {
        let (pk, _) = generate_keypair(SigningAlgorithm::Ed25519);
        ApplicationKeyAttestation {
            subject_user_id: "owner".to_string(),
            subject_domain: DOMAIN.to_string(),
            application_id: "app".to_string(),
            instance_id: "i1".to_string(),
            key_id: "ak1".to_string(),
            key_usage: KeyUsage::Sign,
            algorithm: KeyAlgorithm::Ed25519,
            fingerprint: fingerprint(&pk),
            public_key: pk,
            key_created_at: at("2026-06-01T00:00:00.123+00:00"),
            key_expires_at: at("2027-06-01T00:00:00+00:00"),
            attested_at: at("2026-06-01T00:00:00.123+00:00"),
            attestation_expires_at: at("2026-06-02T00:00:00.123+00:00"),
        }
    }

    #[test]
    fn a_legacy_attestation_verifies_as_stored_and_decodes_after_the_upgrade() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let keys = vec![public_key("k1", &pk)];
        let a = attestation();
        let old_bytes =
            downgrade(&crate::generated::encode_application_key_attestation(&a).unwrap());
        assert!(crate::generated::decode_application_key_attestation(&old_bytes).is_err());
        let message = attestation_signature_input(&old_bytes);
        let stored = crate::generated::encode_signed_application_key_attestation(
            &SignedApplicationKeyAttestation {
                attestation: old_bytes,
                signatures: vec![signature("k1", &sk, &message)],
            },
        )
        .unwrap();
        let found = attestation_provenance(&stored, DOMAIN, &keys).unwrap();
        assert_eq!(found.provenance, Provenance::Legacy(V1ALPHA_TEXT));
        assert_eq!(found.attestation, a);

        // A signature that does not cover the stored bytes is refused.
        let mut tampered: SignedApplicationKeyAttestation =
            crate::generated::decode_signed_application_key_attestation(&stored).unwrap();
        tampered.signatures[0].signature[0] ^= 0xff;
        let tampered =
            crate::generated::encode_signed_application_key_attestation(&tampered).unwrap();
        assert!(attestation_provenance(&tampered, DOMAIN, &keys).is_none());

        // Re-signed in the current encoding, it is current.
        let resigned = crate::application_keys::sign_attestation(&a, &[signer("k1", &sk)]).unwrap();
        let bytes = crate::generated::encode_signed_application_key_attestation(&resigned).unwrap();
        assert_eq!(
            attestation_provenance(&bytes, DOMAIN, &keys)
                .unwrap()
                .provenance,
            Provenance::Current
        );
    }

    #[test]
    fn upgrade_legacy_record_reverses_the_text_encoding() {
        let a = attestation();
        let current = crate::generated::encode_application_key_attestation(&a).unwrap();
        let old = downgrade(&current);
        assert_ne!(old, current);
        let upgraded = upgrade_legacy_record(&old).unwrap();
        assert_eq!(
            crate::generated::decode_application_key_attestation(&upgraded).unwrap(),
            a
        );
        // A current record comes back with the same content.
        let again = upgrade_legacy_record(&current).unwrap();
        assert_eq!(
            crate::generated::decode_application_key_attestation(&again).unwrap(),
            a
        );
    }

    #[test]
    fn upgrade_legacy_record_refuses_unknown_labels_and_bad_times() {
        let map = |k: &str, v: Value| cbor(&Value::Map(vec![(Value::Text(k.into()), v)]));
        assert!(upgrade_legacy_record(&map("key_usage", Value::Text("fly".into()))).is_err());
        assert!(upgrade_legacy_record(&map("issued_at", Value::Text("soon".into()))).is_err());
        assert!(upgrade_legacy_record(b"\xff").is_err());
        // Other text fields are left alone.
        let other = map("label", Value::Text("2026".into()));
        assert_eq!(upgrade_legacy_record(&other).unwrap(), other);
    }
}
