//! Application keys: enrollment, attestation, renewal, and revocation.
//!
//! An application (Tinku is the first) generates and holds its own key pairs
//! and signs its own messages. The home domain never sees an application
//! private key and never signs an application message. It only attests that a
//! public key belongs to one canonical account, application, and application
//! instance, for a short and renewable period. Home-domain work then scales
//! with key enrollment and attestation renewal instead of with messages and
//! peers — the useful Kerberos property of establishing short-lived trust
//! material and then leaving the message path.
//!
//! This module is the pure half of that design: deterministic encoding,
//! signature construction, signature verification, quorum rules, attestation
//! validity, and revocation validity. It has no database, no network, and no
//! clock of its own — every temporal function takes `now` explicitly, so the
//! crate stays WASM-viable and every rule is directly testable.
//!
//! The wire types are generated from `csil/linkkeys.csil`; only the
//! signing/verifying LOGIC lives here, the same split as [`crate::revocation`]
//! and [`crate::local_rp`].
//!
//! # The rules, in one place
//!
//! - Two DISTINCT, currently valid application signing keys authorize adding a
//!   key. The new key never counts toward that quorum and must separately
//!   prove possession.
//! - Two DISTINCT, currently valid SIBLING signing keys authorize a revocation.
//!   The target key never signs or counts toward its own revocation — which is
//!   why an instance should hold three signing keys and not two.
//! - Initial enrollment is the one bootstrap exception: the account owner
//!   authenticates, at least two signing keys enroll together, and each proves
//!   its own possession.
//! - Ed25519 keys sign. X25519 keys do key agreement, cannot sign, and never
//!   count toward a quorum.
//! - All valid keys of the same use are equal. There is no preferred key, and
//!   array order carries no meaning anywhere in this module.

use crate::assertions::check_signing_key_valid;
use crate::claims::ClaimSigner;
use crate::crypto::{self, CryptoError, SigningAlgorithm};
use crate::generated::types::{
    ApplicationKeyAddition, ApplicationKeyAttestation, ApplicationKeyRenewal,
    ApplicationKeyRevocation, ApplicationKeySignature, ClaimSignature, DomainPublicKey,
    SignedApplicationKeyAddition, SignedApplicationKeyAttestation, SignedApplicationKeyRenewal,
};
use crate::local_rp::envelope_signature_input;
use chrono::{DateTime, Duration, Utc};
use std::collections::{BTreeSet, HashSet};
use std::fmt;
use x25519_dalek::StaticSecret as X25519StaticSecret;

// ---------------------------------------------------------------------------
// Domain-separation tags
// ---------------------------------------------------------------------------

/// Signature context for the home domain's attestation over one application
/// public key.
///
/// The `-v1alpha` suffix is an EPOCH marker, not a version counter. It marks
/// the pre-alpha protocol epoch and changes only when the protocol leaves
/// alpha — the point at which invalidating every earlier signature becomes a
/// deliberate act. An attestation is a stored signature, the case where a tag
/// change is most expensive, so it keeps the suffix in order to take part in
/// one coordinated epoch change instead of needing its own. Within an epoch
/// this tag MUST NOT change for this structure.
pub const ATTESTATION_TAG: &str = "linkkeys-application-key-attestation-v1alpha";

/// Signature context for a quorum signature over an addition request.
pub const ADDITION_TAG: &str = "linkkeys-application-key-addition-v1alpha";

/// Signature context for a key's proof that it holds its own private key.
///
/// Distinct from [`ADDITION_TAG`] and [`RENEWAL_TAG`] on purpose: the same
/// bytes are signed by the new key and by the authorizing quorum, and a shared
/// tag would let one signature be presented as the other.
pub const POSSESSION_TAG: &str = "linkkeys-application-key-possession-v1alpha";

/// Signature context for a sibling signature over a renewal request.
pub const RENEWAL_TAG: &str = "linkkeys-application-key-renewal-v1alpha";

/// Signature context for a sibling signature over an application-key
/// revocation.
pub const REVOCATION_TAG: &str = "linkkeys-application-key-revocation-v1alpha";

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// Distinct valid signing keys that must authorize adding a key.
pub const ADDITION_QUORUM: usize = 2;

/// Distinct valid sibling signing keys that must authorize a revocation.
pub const REVOCATION_QUORUM: usize = 2;

/// Distinct valid sibling signing keys that must authorize renewing the
/// attestation of a key that cannot sign for itself.
pub const RENEWAL_QUORUM: usize = 1;

/// An instance MUST hold at least this many valid signing keys after initial
/// enrollment.
pub const MIN_SIGNING_KEYS: usize = 2;

/// An instance SHOULD hold at least this many. Three keys permit ordinary
/// sibling revocation: with only two, both keys can authorize a third, but
/// neither can be revoked through sibling quorum, because the target may not
/// sign its own revocation.
pub const RECOMMENDED_SIGNING_KEYS: usize = 3;

/// Default attestation lifetime. This value IS the revocation propagation
/// window: a verifier can accept a revoked key until its current attestation
/// expires. Lower it to shorten that window; it must stay larger than the
/// permitted clock skew by a wide margin.
pub const DEFAULT_ATTESTATION_LIFETIME_SECONDS: i64 = 86_400;

/// Default look-back for the application-key revocation read.
pub const DEFAULT_REVOCATION_WINDOW_SECONDS: i64 = 3 * 365 * 86_400;

/// Key use: an Ed25519 signing key.
pub const KEY_USAGE_SIGN: &str = "sign";
/// Key use: an X25519 key-agreement key.
pub const KEY_USAGE_AGREE: &str = "agree";

/// Challenge purpose: enrolling or adding a key.
pub const PURPOSE_ADD: &str = "add";
/// Challenge purpose: renewing an existing key's attestation.
pub const PURPOSE_RENEW: &str = "renew";

const ALG_ED25519: &str = "ed25519";
const ALG_X25519: &str = "x25519";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum ApplicationKeyError {
    /// The embedded CBOR payload did not decode.
    Decode(String),
    /// A timestamp field was not RFC3339.
    BadTimestamp(String),
    /// The signed payload names a different subject, domain, application, or
    /// instance than the one being operated on. A signature for one instance
    /// can never be used for another.
    IdentityMismatch {
        field: &'static str,
    },
    /// The request's own validity window does not contain `now`.
    RequestExpired,
    /// Fewer than the required number of DISTINCT valid signatures verified.
    InsufficientSignatures {
        got: usize,
        need: usize,
    },
    /// The new or target key proved nothing about its private key.
    MissingPossessionProof,
    /// A possession proof was supplied where none is possible (an X25519 key
    /// cannot sign) or it did not verify.
    BadPossessionProof,
    /// `key_usage` and `algorithm` do not agree, or do not match the operation.
    UsageMismatch {
        expected: String,
        got: String,
    },
    /// The stated fingerprint is not the fingerprint of the stated public key.
    FingerprintMismatch,
    /// The named key is not a key of this instance.
    UnknownKey(String),
    /// The key is revoked, and revocation is permanent.
    KeyRevoked(String),
    /// The key's own validity window has passed.
    KeyExpired(String),
    /// The attestation's validity window has passed. This is NOT a revocation:
    /// a renewed attestation can make the same unrevoked key acceptable again.
    AttestationExpired,
    /// No signature from a currently valid domain signing key verified.
    UntrustedAttestation,
    /// Initial enrollment carried fewer signing keys than the protocol permits.
    TooFewSigningKeys {
        got: usize,
        need: usize,
    },
    /// The same key appeared twice where distinct keys are required.
    DuplicateKey(String),
    /// A configured bound is self-defeating (see
    /// [`validate_revocation_window`]).
    BadConfiguration(String),
    Crypto(String),
}

impl fmt::Display for ApplicationKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ApplicationKeyError::*;
        match self {
            Decode(e) => write!(f, "could not decode application key payload: {e}"),
            BadTimestamp(e) => write!(f, "bad timestamp: {e}"),
            IdentityMismatch { field } => {
                write!(f, "application key request is bound to a different {field}")
            }
            RequestExpired => write!(f, "application key request is outside its validity window"),
            InsufficientSignatures { got, need } => write!(
                f,
                "{got} distinct valid application key signatures; {need} required"
            ),
            MissingPossessionProof => write!(f, "no proof of possession for the key"),
            BadPossessionProof => write!(f, "proof of possession did not verify"),
            UsageMismatch { expected, got } => {
                write!(f, "key use mismatch: expected {expected}, got {got}")
            }
            FingerprintMismatch => write!(f, "fingerprint does not match the public key"),
            UnknownKey(id) => write!(f, "unknown application key {id}"),
            KeyRevoked(id) => write!(f, "application key {id} is revoked"),
            KeyExpired(id) => write!(f, "application key {id} has expired"),
            AttestationExpired => write!(f, "the attestation has expired"),
            UntrustedAttestation => {
                write!(f, "no valid home-domain signature over the attestation")
            }
            TooFewSigningKeys { got, need } => write!(
                f,
                "enrollment carried {got} signing keys; at least {need} required"
            ),
            DuplicateKey(id) => write!(f, "duplicate application key {id}"),
            BadConfiguration(m) => write!(f, "unusable application key configuration: {m}"),
            Crypto(e) => write!(f, "crypto error: {e}"),
        }
    }
}

impl std::error::Error for ApplicationKeyError {}

impl From<CryptoError> for ApplicationKeyError {
    fn from(e: CryptoError) -> Self {
        ApplicationKeyError::Crypto(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Identity and key references
// ---------------------------------------------------------------------------

/// The canonical identity an application key is bound to. `subject_user_id` is
/// always the account's one canonical UUID; a profile is a presentation
/// persona, never a second identity, so it never appears here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstanceRef<'a> {
    pub subject_user_id: &'a str,
    pub subject_domain: &'a str,
    pub application_id: &'a str,
    pub instance_id: &'a str,
}

/// One application public key as the verifying side knows it. The home domain
/// builds these from its own rows; a peer builds them from verified
/// attestations. There is no private key here and never will be.
#[derive(Debug, Clone, PartialEq)]
pub struct ApplicationKeyRef {
    pub key_id: String,
    pub key_usage: String,
    pub algorithm: String,
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    pub created_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
}

impl ApplicationKeyRef {
    /// A key that can currently make a quorum signature: a signing key, not
    /// revoked, and inside its own validity window.
    pub fn is_valid_signing_key(&self, now: DateTime<Utc>) -> bool {
        self.key_usage == KEY_USAGE_SIGN && self.is_valid(now)
    }

    /// Not revoked and inside its own validity window at `now`.
    pub fn is_valid(&self, now: DateTime<Utc>) -> bool {
        if let Some(r) = &self.revoked_at {
            match parse_time(r) {
                Ok(t) if t <= now => return false,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
        match parse_time(&self.expires_at) {
            Ok(exp) => exp > now,
            Err(_) => false,
        }
    }

    /// Was this key able to authorize something at `at`? Used when checking a
    /// revocation long after the fact: a signer that was valid when it signed
    /// authorized the revocation, and a verifier must still be able to confirm
    /// that after the signer itself expires.
    pub fn was_valid_at(&self, at: DateTime<Utc>) -> bool {
        if let Ok(created) = parse_time(&self.created_at) {
            if created > at {
                return false;
            }
        }
        if let Ok(exp) = parse_time(&self.expires_at) {
            if exp <= at {
                return false;
            }
        } else {
            return false;
        }
        if let Some(r) = &self.revoked_at {
            if let Ok(rev) = parse_time(r) {
                if rev <= at {
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    }
}

/// An application's own signing material. The mirror of
/// [`crate::claims::ClaimSigner`] for keys the APPLICATION holds — this crate
/// never sees a domain's copy of one, because there is none.
pub struct ApplicationSigner<'a> {
    pub key_id: &'a str,
    pub algorithm: SigningAlgorithm,
    pub private_key_bytes: &'a [u8],
}

// ---------------------------------------------------------------------------
// Canonical signature inputs
// ---------------------------------------------------------------------------

/// Bytes a home-domain signature over an attestation covers.
///
/// `pub` so conformance-vector generation and SDK authors can compute the
/// exact bytes without duplicating the construction.
pub fn attestation_signature_input(attestation_bytes: &[u8]) -> Vec<u8> {
    envelope_signature_input(ATTESTATION_TAG, attestation_bytes)
}

/// Bytes a quorum signature over an addition request covers.
pub fn addition_signature_input(addition_bytes: &[u8]) -> Vec<u8> {
    envelope_signature_input(ADDITION_TAG, addition_bytes)
}

/// Bytes a key's own proof of possession covers. The same payload bytes as the
/// addition or renewal, under a DIFFERENT tag, so a possession proof can never
/// be replayed as a quorum signature or the reverse.
pub fn possession_signature_input(payload_bytes: &[u8]) -> Vec<u8> {
    envelope_signature_input(POSSESSION_TAG, payload_bytes)
}

/// Bytes a sibling signature over a renewal request covers.
pub fn renewal_signature_input(renewal_bytes: &[u8]) -> Vec<u8> {
    envelope_signature_input(RENEWAL_TAG, renewal_bytes)
}

/// Bytes a sibling signature over a revocation covers.
///
/// Unlike the attestation and the requests, a revocation is verified from its
/// FIELDS rather than from a stored byte string, so its canonical payload is
/// built here — the tuple-with-the-tag-first pattern of
/// [`crate::revocation::revocation_payload`]. Every identifier is bound, so a
/// revocation cannot move between subjects, applications, or instances.
pub fn revocation_payload(
    subject_user_id: &str,
    subject_domain: &str,
    application_id: &str,
    instance_id: &str,
    target_key_id: &str,
    target_fingerprint: &str,
    revoked_at: &str,
) -> Vec<u8> {
    let tuple = (
        REVOCATION_TAG,
        subject_user_id,
        subject_domain,
        application_id,
        instance_id,
        target_key_id,
        target_fingerprint,
        revoked_at,
    );
    let mut out = Vec::new();
    ciborium::ser::into_writer(&tuple, &mut out)
        .expect("CBOR serialization of application key revocation payload cannot fail");
    out
}

fn revocation_payload_of(rev: &ApplicationKeyRevocation) -> Vec<u8> {
    revocation_payload(
        &rev.subject_user_id,
        &rev.subject_domain,
        &rev.application_id,
        &rev.instance_id,
        &rev.target_key_id,
        &rev.target_fingerprint,
        &rev.revoked_at,
    )
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn parse_time(s: &str) -> Result<DateTime<Utc>, ApplicationKeyError> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| ApplicationKeyError::BadTimestamp(e.to_string()))
}

/// The algorithm a key use requires. Ed25519 keys sign; X25519 keys do key
/// agreement and can do nothing else.
fn expected_algorithm(key_usage: &str) -> Option<&'static str> {
    match key_usage {
        KEY_USAGE_SIGN => Some(ALG_ED25519),
        KEY_USAGE_AGREE => Some(ALG_X25519),
        _ => None,
    }
}

/// Check that a key's stated use, algorithm, and fingerprint are internally
/// consistent before anything trusts them.
pub fn check_key_shape(
    key_usage: &str,
    algorithm: &str,
    public_key: &[u8],
    fingerprint: &str,
) -> Result<(), ApplicationKeyError> {
    let Some(expected) = expected_algorithm(key_usage) else {
        return Err(ApplicationKeyError::UsageMismatch {
            expected: format!("{KEY_USAGE_SIGN} or {KEY_USAGE_AGREE}"),
            got: key_usage.to_string(),
        });
    };
    if algorithm != expected {
        return Err(ApplicationKeyError::UsageMismatch {
            expected: expected.to_string(),
            got: algorithm.to_string(),
        });
    }
    if public_key.len() != 32 {
        return Err(ApplicationKeyError::Crypto(format!(
            "{algorithm} public key must be 32 bytes, got {}",
            public_key.len()
        )));
    }
    if crypto::fingerprint(public_key) != fingerprint {
        return Err(ApplicationKeyError::FingerprintMismatch);
    }
    Ok(())
}

fn check_identity(
    expected: &InstanceRef<'_>,
    subject_user_id: &str,
    subject_domain: &str,
    application_id: &str,
    instance_id: &str,
) -> Result<(), ApplicationKeyError> {
    if subject_user_id != expected.subject_user_id {
        return Err(ApplicationKeyError::IdentityMismatch {
            field: "subject_user_id",
        });
    }
    if subject_domain != expected.subject_domain {
        return Err(ApplicationKeyError::IdentityMismatch {
            field: "subject_domain",
        });
    }
    if application_id != expected.application_id {
        return Err(ApplicationKeyError::IdentityMismatch {
            field: "application_id",
        });
    }
    if instance_id != expected.instance_id {
        return Err(ApplicationKeyError::IdentityMismatch {
            field: "instance_id",
        });
    }
    Ok(())
}

fn check_window(
    requested_at: &str,
    expires_at: &str,
    now: DateTime<Utc>,
    skew_seconds: i64,
) -> Result<(), ApplicationKeyError> {
    let start = parse_time(requested_at)?;
    let end = parse_time(expires_at)?;
    if end <= start {
        return Err(ApplicationKeyError::RequestExpired);
    }
    let skew = Duration::seconds(skew_seconds);
    if now + skew < start || now - skew > end {
        return Err(ApplicationKeyError::RequestExpired);
    }
    Ok(())
}

/// Count DISTINCT valid application signing keys that signed `message`.
///
/// A key never counts twice, `excluded_key_id` never counts at all (the new key
/// in an addition, the target in a revocation), and only a key that
/// `valid_at` accepts is eligible.
fn count_distinct_signers<F>(
    signatures: &[ApplicationKeySignature],
    keys: &[ApplicationKeyRef],
    message: &[u8],
    excluded_key_id: Option<&str>,
    valid_at: F,
) -> BTreeSet<String>
where
    F: Fn(&ApplicationKeyRef) -> bool,
{
    let mut accepted: BTreeSet<String> = BTreeSet::new();
    for sig in signatures {
        if Some(sig.signed_by_key_id.as_str()) == excluded_key_id {
            continue;
        }
        if accepted.contains(&sig.signed_by_key_id) {
            continue;
        }
        let Some(key) = keys.iter().find(|k| k.key_id == sig.signed_by_key_id) else {
            continue;
        };
        if key.key_usage != KEY_USAGE_SIGN || !valid_at(key) {
            continue;
        }
        if crypto::resolve_and_verify(&key.algorithm, message, &sig.signature, &key.public_key)
            .is_ok()
        {
            accepted.insert(sig.signed_by_key_id.clone());
        }
    }
    accepted
}

// ---------------------------------------------------------------------------
// Attestations: build and verify
// ---------------------------------------------------------------------------

/// Build the attestation record for one key. The caller supplies the clock and
/// the two lifetimes, so this stays deterministic and testable.
#[allow(clippy::too_many_arguments)]
pub fn build_attestation(
    instance: &InstanceRef<'_>,
    key: &ApplicationKeyRef,
    attested_at: DateTime<Utc>,
    attestation_lifetime_seconds: i64,
) -> ApplicationKeyAttestation {
    ApplicationKeyAttestation {
        subject_user_id: instance.subject_user_id.to_string(),
        subject_domain: instance.subject_domain.to_string(),
        application_id: instance.application_id.to_string(),
        instance_id: instance.instance_id.to_string(),
        key_id: key.key_id.clone(),
        key_usage: key.key_usage.clone(),
        algorithm: key.algorithm.clone(),
        public_key: key.public_key.clone(),
        fingerprint: key.fingerprint.clone(),
        key_created_at: key.created_at.clone(),
        key_expires_at: key.expires_at.clone(),
        attested_at: attested_at.to_rfc3339(),
        attestation_expires_at: (attested_at + Duration::seconds(attestation_lifetime_seconds))
            .to_rfc3339(),
    }
}

/// Sign an attestation with one or more of the home domain's valid signing
/// keys. The signed bytes are returned inside the record and are what the
/// server must store and later serve VERBATIM — it must not re-encode or
/// re-sign on read.
pub fn sign_attestation(
    attestation: &ApplicationKeyAttestation,
    signers: &[ClaimSigner<'_>],
) -> Result<SignedApplicationKeyAttestation, CryptoError> {
    let bytes = crate::generated::encode_application_key_attestation(attestation);
    let message = attestation_signature_input(&bytes);
    let mut signatures = Vec::with_capacity(signers.len());
    for signer in signers {
        let signature =
            crypto::sign_with_algorithm(signer.algorithm, &message, signer.private_key_bytes)?;
        signatures.push(ClaimSignature {
            domain: signer.domain.to_string(),
            signed_by_key_id: signer.key_id.to_string(),
            signature,
        });
    }
    Ok(SignedApplicationKeyAttestation {
        attestation: bytes,
        signatures,
    })
}

/// Verify a home-domain attestation and return what it says.
///
/// Requires at least one signature from a currently valid signing key of
/// `expected_domain`. This is a domain assertion, not a peer quorum: the
/// domain's own key set is already pinned in DNS, so one valid signature over
/// the exact stored bytes is the proof. The domain may include several.
///
/// Checking that the attestation is CURRENT is a separate step — see
/// [`classify_key`] — because an expired attestation is a missing proof, not a
/// revocation.
pub fn verify_attestation_signature(
    signed: &SignedApplicationKeyAttestation,
    domain_keys: &[DomainPublicKey],
    expected_domain: &str,
) -> Result<ApplicationKeyAttestation, ApplicationKeyError> {
    let attestation = crate::generated::decode_application_key_attestation(&signed.attestation)
        .map_err(|e| ApplicationKeyError::Decode(e.to_string()))?;

    if attestation.subject_domain != expected_domain {
        return Err(ApplicationKeyError::IdentityMismatch {
            field: "subject_domain",
        });
    }
    check_key_shape(
        &attestation.key_usage,
        &attestation.algorithm,
        &attestation.public_key,
        &attestation.fingerprint,
    )?;

    let message = attestation_signature_input(&signed.attestation);
    for sig in &signed.signatures {
        if sig.domain != expected_domain {
            continue;
        }
        let Some(key) = domain_keys
            .iter()
            .find(|k| k.key_id == sig.signed_by_key_id)
        else {
            continue;
        };
        if check_signing_key_valid(key).is_err() {
            continue;
        }
        if crypto::resolve_and_verify(&key.algorithm, &message, &sig.signature, &key.public_key)
            .is_ok()
        {
            return Ok(attestation);
        }
    }
    Err(ApplicationKeyError::UntrustedAttestation)
}

// ---------------------------------------------------------------------------
// The verifier's view of a key set
// ---------------------------------------------------------------------------

/// Why a key is or is not acceptable for current use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStatus {
    /// Every condition holds: the attestation verifies and is current, the key
    /// is inside its own window, no accepted revocation applies.
    Usable,
    /// The key is fine but the proof is stale. A renewed attestation can make
    /// the same unrevoked key acceptable again.
    AttestationExpired,
    /// The key's own lifetime has passed. Renewal cannot help.
    KeyExpired,
    /// Permanently revoked as of the recorded effective time.
    Revoked { revoked_at: String },
}

/// One attestation-verified key, with the reason it is or is not usable.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedApplicationKey {
    pub attestation: ApplicationKeyAttestation,
    pub status: KeyStatus,
}

impl VerifiedApplicationKey {
    pub fn is_usable(&self) -> bool {
        self.status == KeyStatus::Usable
    }
}

/// A record that did not survive verification, and why. Kept rather than
/// silently dropped so a caller can log or surface a real problem instead of
/// seeing an unexplained empty set.
#[derive(Debug, Clone, PartialEq)]
pub struct RejectedRecord {
    pub what: String,
    pub reason: String,
}

/// The verified result of one `get-application-keys` (or RP-cached) response.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct VerifiedApplicationKeySet {
    /// Attestation-verified keys, in no meaningful order. A key id identifies
    /// one key; there is no preferred key.
    pub keys: Vec<VerifiedApplicationKey>,
    /// Key ids with an accepted revocation that applies at the evaluated time.
    pub revoked_key_ids: BTreeSet<String>,
    /// Records that failed verification, with the reason.
    pub rejected: Vec<RejectedRecord>,
}

impl VerifiedApplicationKeySet {
    /// Look up one key by id and confirm it is acceptable for a specific
    /// operation. This is the call a peer makes before it verifies a message:
    /// it fails closed on an unknown, expired, unattested, mismatched, or
    /// revoked key.
    pub fn key_for_use(
        &self,
        key_id: &str,
        key_usage: &str,
        algorithm: &str,
    ) -> Result<&ApplicationKeyAttestation, ApplicationKeyError> {
        if self.revoked_key_ids.contains(key_id) {
            return Err(ApplicationKeyError::KeyRevoked(key_id.to_string()));
        }
        let Some(found) = self.keys.iter().find(|k| k.attestation.key_id == key_id) else {
            return Err(ApplicationKeyError::UnknownKey(key_id.to_string()));
        };
        match &found.status {
            KeyStatus::Usable => {}
            KeyStatus::AttestationExpired => return Err(ApplicationKeyError::AttestationExpired),
            KeyStatus::KeyExpired => {
                return Err(ApplicationKeyError::KeyExpired(key_id.to_string()))
            }
            KeyStatus::Revoked { .. } => {
                return Err(ApplicationKeyError::KeyRevoked(key_id.to_string()))
            }
        }
        if found.attestation.key_usage != key_usage {
            return Err(ApplicationKeyError::UsageMismatch {
                expected: key_usage.to_string(),
                got: found.attestation.key_usage.clone(),
            });
        }
        if found.attestation.algorithm != algorithm {
            return Err(ApplicationKeyError::UsageMismatch {
                expected: algorithm.to_string(),
                got: found.attestation.algorithm.clone(),
            });
        }
        Ok(&found.attestation)
    }

    /// Every currently usable key of one use. All such keys are equal: a
    /// caller may pick any of them, and the returned order carries no meaning.
    pub fn usable_keys(&self, key_usage: &str) -> Vec<&ApplicationKeyAttestation> {
        self.keys
            .iter()
            .filter(|k| k.is_usable() && k.attestation.key_usage == key_usage)
            .map(|k| &k.attestation)
            .collect()
    }
}

/// Decide the status of one verified attestation at `now`.
pub fn classify_key(
    attestation: &ApplicationKeyAttestation,
    revoked_at: Option<&str>,
    now: DateTime<Utc>,
    skew_seconds: i64,
) -> Result<KeyStatus, ApplicationKeyError> {
    if let Some(r) = revoked_at {
        let effective = parse_time(r)?;
        if effective <= now + Duration::seconds(skew_seconds) {
            return Ok(KeyStatus::Revoked {
                revoked_at: r.to_string(),
            });
        }
    }
    let skew = Duration::seconds(skew_seconds);
    if parse_time(&attestation.key_expires_at)? + skew <= now {
        return Ok(KeyStatus::KeyExpired);
    }
    if parse_time(&attestation.attestation_expires_at)? + skew <= now {
        return Ok(KeyStatus::AttestationExpired);
    }
    Ok(KeyStatus::Usable)
}

/// Verify a whole application-key response the way a peer or an SDK must.
///
/// Order of work matters and is deliberate:
/// 1. Verify every attestation against the home domain's pinned key set. Only
///    attested keys exist as far as this function is concerned.
/// 2. Verify every revocation against those attested SIBLING keys, requiring
///    the quorum, excluding the target, and judging each signer by whether it
///    was valid AT THE REVOCATION TIME — a revocation must stay verifiable
///    after its signers themselves expire.
/// 3. Classify each key against the accepted revocations and `now`.
///
/// Nothing here fails the whole set because one record is bad: a rejected
/// record is recorded with its reason, so a caller sees a real problem instead
/// of an unexplained empty result. A caller that requires completeness must
/// check `rejected` is empty.
pub fn verify_application_key_set(
    signed_attestations: &[SignedApplicationKeyAttestation],
    revocations: &[ApplicationKeyRevocation],
    domain_keys: &[DomainPublicKey],
    instance: &InstanceRef<'_>,
    now: DateTime<Utc>,
    skew_seconds: i64,
) -> VerifiedApplicationKeySet {
    let mut set = VerifiedApplicationKeySet::default();
    let mut attested: Vec<ApplicationKeyAttestation> = Vec::new();

    for signed in signed_attestations {
        match verify_attestation_signature(signed, domain_keys, instance.subject_domain) {
            Ok(a) => {
                if let Err(e) = check_identity(
                    instance,
                    &a.subject_user_id,
                    &a.subject_domain,
                    &a.application_id,
                    &a.instance_id,
                ) {
                    set.rejected.push(RejectedRecord {
                        what: format!("attestation {}", a.key_id),
                        reason: e.to_string(),
                    });
                    continue;
                }
                if attested.iter().any(|x| x.key_id == a.key_id) {
                    set.rejected.push(RejectedRecord {
                        what: format!("attestation {}", a.key_id),
                        reason: ApplicationKeyError::DuplicateKey(a.key_id.clone()).to_string(),
                    });
                    continue;
                }
                attested.push(a);
            }
            Err(e) => set.rejected.push(RejectedRecord {
                what: "attestation".to_string(),
                reason: e.to_string(),
            }),
        }
    }

    // The attested keys are the only sibling authority a revocation can draw
    // on, so this set is built first and used as-is below.
    let key_refs: Vec<ApplicationKeyRef> = attested.iter().map(attested_key_ref).collect();

    let mut revoked: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for rev in revocations {
        match verify_revocation(rev, &key_refs, instance) {
            Ok(()) => {
                // Revocation is permanent, so the earliest accepted effective
                // time wins if several records name the same key.
                revoked
                    .entry(rev.target_key_id.clone())
                    .and_modify(|existing| {
                        if rev.revoked_at < *existing {
                            *existing = rev.revoked_at.clone();
                        }
                    })
                    .or_insert_with(|| rev.revoked_at.clone());
            }
            Err(e) => set.rejected.push(RejectedRecord {
                what: format!("revocation of {}", rev.target_key_id),
                reason: e.to_string(),
            }),
        }
    }

    for a in attested {
        let revoked_at = revoked.get(&a.key_id).cloned();
        match classify_key(&a, revoked_at.as_deref(), now, skew_seconds) {
            Ok(status) => {
                if let KeyStatus::Revoked { .. } = status {
                    set.revoked_key_ids.insert(a.key_id.clone());
                }
                set.keys.push(VerifiedApplicationKey {
                    attestation: a,
                    status,
                });
            }
            Err(e) => set.rejected.push(RejectedRecord {
                what: format!("attestation {}", a.key_id),
                reason: e.to_string(),
            }),
        }
    }

    set
}

fn attested_key_ref(a: &ApplicationKeyAttestation) -> ApplicationKeyRef {
    ApplicationKeyRef {
        key_id: a.key_id.clone(),
        key_usage: a.key_usage.clone(),
        algorithm: a.algorithm.clone(),
        public_key: a.public_key.clone(),
        fingerprint: a.fingerprint.clone(),
        created_at: a.key_created_at.clone(),
        expires_at: a.key_expires_at.clone(),
        revoked_at: None,
    }
}

// ---------------------------------------------------------------------------
// Additions
// ---------------------------------------------------------------------------

/// Build and sign an addition request. `quorum_signers` must be two DISTINCT
/// currently valid signing keys of the instance, and must not include the new
/// key. `new_key_signer` is the new key itself for a signing key, and `None`
/// for a key-agreement key (which cannot sign — it proves possession by
/// returning the sealed challenge plaintext in `addition.challenge`).
pub fn sign_addition(
    addition: &ApplicationKeyAddition,
    quorum_signers: &[ApplicationSigner<'_>],
    new_key_signer: Option<&ApplicationSigner<'_>>,
) -> Result<SignedApplicationKeyAddition, CryptoError> {
    let bytes = crate::generated::encode_application_key_addition(addition);
    let quorum_message = addition_signature_input(&bytes);
    let mut signatures = Vec::with_capacity(quorum_signers.len());
    for signer in quorum_signers {
        signatures.push(ApplicationKeySignature {
            signed_by_key_id: signer.key_id.to_string(),
            signature: crypto::sign_with_algorithm(
                signer.algorithm,
                &quorum_message,
                signer.private_key_bytes,
            )?,
        });
    }
    let possession_proof = match new_key_signer {
        Some(s) => Some(crypto::sign_with_algorithm(
            s.algorithm,
            &possession_signature_input(&bytes),
            s.private_key_bytes,
        )?),
        None => None,
    };
    Ok(SignedApplicationKeyAddition {
        addition: bytes,
        signatures,
        possession_proof,
    })
}

/// Verify an addition request against the instance's current key set.
///
/// The caller still owns two things this function cannot know: that
/// `addition.challenge` matches the single-use nonce the home domain issued
/// under `addition.challenge_id`, and that `addition.key_id` is not already
/// taken. Both need server state.
pub fn verify_addition(
    signed: &SignedApplicationKeyAddition,
    existing_keys: &[ApplicationKeyRef],
    instance: &InstanceRef<'_>,
    now: DateTime<Utc>,
    skew_seconds: i64,
) -> Result<ApplicationKeyAddition, ApplicationKeyError> {
    let addition = decode_addition(signed, instance, now, skew_seconds)?;

    // The new key must prove it holds its own private key, and that proof can
    // never double as one of the two authorizing signatures.
    check_addition_possession(signed, &addition)?;

    let message = addition_signature_input(&signed.addition);
    let accepted = count_distinct_signers(
        &signed.signatures,
        existing_keys,
        &message,
        Some(&addition.key_id),
        |k| k.is_valid_signing_key(now),
    );
    if accepted.len() < ADDITION_QUORUM {
        return Err(ApplicationKeyError::InsufficientSignatures {
            got: accepted.len(),
            need: ADDITION_QUORUM,
        });
    }
    Ok(addition)
}

/// Verify the bootstrap enrollment batch: at least [`MIN_SIGNING_KEYS`]
/// signing keys, every key proving its own possession, no quorum requirement
/// (there is no prior key to form one), and no duplicate key ids.
///
/// This is the ONLY path that skips quorum, and it is reachable only after the
/// account owner authenticates. Losing quorum later means coming back through
/// here, which is a visible trust reset rather than a silent bypass.
pub fn verify_initial_enrollment(
    keys: &[SignedApplicationKeyAddition],
    instance: &InstanceRef<'_>,
    now: DateTime<Utc>,
    skew_seconds: i64,
) -> Result<Vec<ApplicationKeyAddition>, ApplicationKeyError> {
    let mut out: Vec<ApplicationKeyAddition> = Vec::with_capacity(keys.len());
    let mut seen: HashSet<String> = HashSet::new();
    for signed in keys {
        let addition = decode_addition(signed, instance, now, skew_seconds)?;
        check_addition_possession(signed, &addition)?;
        if !seen.insert(addition.key_id.clone()) {
            return Err(ApplicationKeyError::DuplicateKey(addition.key_id));
        }
        out.push(addition);
    }
    let signing = out.iter().filter(|a| a.key_usage == KEY_USAGE_SIGN).count();
    if signing < MIN_SIGNING_KEYS {
        return Err(ApplicationKeyError::TooFewSigningKeys {
            got: signing,
            need: MIN_SIGNING_KEYS,
        });
    }
    Ok(out)
}

fn decode_addition(
    signed: &SignedApplicationKeyAddition,
    instance: &InstanceRef<'_>,
    now: DateTime<Utc>,
    skew_seconds: i64,
) -> Result<ApplicationKeyAddition, ApplicationKeyError> {
    let addition = crate::generated::decode_application_key_addition(&signed.addition)
        .map_err(|e| ApplicationKeyError::Decode(e.to_string()))?;
    check_identity(
        instance,
        &addition.subject_user_id,
        &addition.subject_domain,
        &addition.application_id,
        &addition.instance_id,
    )?;
    check_key_shape(
        &addition.key_usage,
        &addition.algorithm,
        &addition.public_key,
        &addition.fingerprint,
    )?;
    check_window(
        &addition.requested_at,
        &addition.expires_at,
        now,
        skew_seconds,
    )?;
    if addition.requested_key_lifetime_seconds <= 0 {
        return Err(ApplicationKeyError::BadConfiguration(
            "requested key lifetime must be positive".to_string(),
        ));
    }
    Ok(addition)
}

fn check_addition_possession(
    signed: &SignedApplicationKeyAddition,
    addition: &ApplicationKeyAddition,
) -> Result<(), ApplicationKeyError> {
    match addition.key_usage.as_str() {
        KEY_USAGE_SIGN => {
            let Some(proof) = &signed.possession_proof else {
                return Err(ApplicationKeyError::MissingPossessionProof);
            };
            let message = possession_signature_input(&signed.addition);
            crypto::resolve_and_verify(&addition.algorithm, &message, proof, &addition.public_key)
                .map_err(|_| ApplicationKeyError::BadPossessionProof)
        }
        KEY_USAGE_AGREE => {
            // An X25519 key cannot sign, so a signature here proves nothing
            // about it and must not be accepted as if it did. Possession is
            // proven by the sealed-challenge plaintext the server checks.
            if signed.possession_proof.is_some() {
                return Err(ApplicationKeyError::BadPossessionProof);
            }
            Ok(())
        }
        other => Err(ApplicationKeyError::UsageMismatch {
            expected: format!("{KEY_USAGE_SIGN} or {KEY_USAGE_AGREE}"),
            got: other.to_string(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Renewal
// ---------------------------------------------------------------------------

/// Sign a renewal request. For an Ed25519 target the key signs for itself in
/// `possession_proof`, which is both the proof and the authentication. For an
/// X25519 target, pass sibling `signers` — it cannot sign for itself.
pub fn sign_renewal(
    renewal: &ApplicationKeyRenewal,
    signers: &[ApplicationSigner<'_>],
    target_signer: Option<&ApplicationSigner<'_>>,
) -> Result<SignedApplicationKeyRenewal, CryptoError> {
    let bytes = crate::generated::encode_application_key_renewal(renewal);
    let message = renewal_signature_input(&bytes);
    let mut signatures = Vec::with_capacity(signers.len());
    for signer in signers {
        signatures.push(ApplicationKeySignature {
            signed_by_key_id: signer.key_id.to_string(),
            signature: crypto::sign_with_algorithm(
                signer.algorithm,
                &message,
                signer.private_key_bytes,
            )?,
        });
    }
    let possession_proof = match target_signer {
        Some(s) => Some(crypto::sign_with_algorithm(
            s.algorithm,
            &possession_signature_input(&bytes),
            s.private_key_bytes,
        )?),
        None => None,
    };
    Ok(SignedApplicationKeyRenewal {
        renewal: bytes,
        signatures,
        possession_proof,
    })
}

/// Verify a renewal request for `target`.
///
/// Renewal creates a new attestation for the SAME key. It never creates a key
/// and never changes key equality. A revoked key can never be renewed, and
/// revocation is permanent, so this is checked before anything else.
///
/// As with additions, the caller must separately confirm that
/// `renewal.challenge` matches the single-use nonce it issued.
pub fn verify_renewal(
    signed: &SignedApplicationKeyRenewal,
    target: &ApplicationKeyRef,
    sibling_keys: &[ApplicationKeyRef],
    instance: &InstanceRef<'_>,
    now: DateTime<Utc>,
    skew_seconds: i64,
) -> Result<ApplicationKeyRenewal, ApplicationKeyError> {
    let renewal = crate::generated::decode_application_key_renewal(&signed.renewal)
        .map_err(|e| ApplicationKeyError::Decode(e.to_string()))?;
    check_identity(
        instance,
        &renewal.subject_user_id,
        &renewal.subject_domain,
        &renewal.application_id,
        &renewal.instance_id,
    )?;
    check_window(
        &renewal.requested_at,
        &renewal.expires_at,
        now,
        skew_seconds,
    )?;

    if renewal.key_id != target.key_id {
        return Err(ApplicationKeyError::IdentityMismatch { field: "key_id" });
    }
    if target.revoked_at.is_some() {
        return Err(ApplicationKeyError::KeyRevoked(target.key_id.clone()));
    }
    if !target.is_valid(now) {
        return Err(ApplicationKeyError::KeyExpired(target.key_id.clone()));
    }

    match target.key_usage.as_str() {
        KEY_USAGE_SIGN => {
            let Some(proof) = &signed.possession_proof else {
                return Err(ApplicationKeyError::MissingPossessionProof);
            };
            crypto::resolve_and_verify(
                &target.algorithm,
                &possession_signature_input(&signed.renewal),
                proof,
                &target.public_key,
            )
            .map_err(|_| ApplicationKeyError::BadPossessionProof)?;
        }
        KEY_USAGE_AGREE => {
            if signed.possession_proof.is_some() {
                return Err(ApplicationKeyError::BadPossessionProof);
            }
            // The key cannot sign, so a sibling must say who is asking. The
            // proof of possession itself is the sealed-challenge plaintext the
            // server checks against the nonce it issued.
            let message = renewal_signature_input(&signed.renewal);
            let accepted = count_distinct_signers(
                &signed.signatures,
                sibling_keys,
                &message,
                Some(&target.key_id),
                |k| k.is_valid_signing_key(now),
            );
            if accepted.len() < RENEWAL_QUORUM {
                return Err(ApplicationKeyError::InsufficientSignatures {
                    got: accepted.len(),
                    need: RENEWAL_QUORUM,
                });
            }
        }
        other => {
            return Err(ApplicationKeyError::UsageMismatch {
                expected: format!("{KEY_USAGE_SIGN} or {KEY_USAGE_AGREE}"),
                got: other.to_string(),
            })
        }
    }
    Ok(renewal)
}

/// Should the home domain make a NEW signature for this renewal, or return the
/// attestation bytes it already holds?
///
/// Renewal is idempotent: while the current attestation keeps more than half
/// of its lifetime, the stored bytes are returned and no signature is made.
/// This is a load control, not a convenience. It turns the common renewal into
/// a stored-bytes read and absorbs retry storms, restart storms, and clients
/// with a skewed clock — a misbehaving instance in a tight loop gets a cache
/// hit instead of an Argon2id derivation and a signature.
///
/// Applications renew when less than half of the lifetime remains, so the
/// honest client and this rule agree.
pub fn needs_new_attestation(
    attested_at: &str,
    attestation_expires_at: &str,
    now: DateTime<Utc>,
) -> Result<bool, ApplicationKeyError> {
    let start = parse_time(attested_at)?;
    let end = parse_time(attestation_expires_at)?;
    if end <= start {
        return Ok(true);
    }
    let half = start + (end - start) / 2;
    Ok(now >= half)
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

/// Build a revocation co-signed by sibling keys. The caller must not include
/// the target among `signers`; [`verify_revocation`] rejects it regardless.
pub fn sign_revocation(
    instance: &InstanceRef<'_>,
    target_key_id: &str,
    target_fingerprint: &str,
    revoked_at: &str,
    signers: &[ApplicationSigner<'_>],
) -> Result<ApplicationKeyRevocation, CryptoError> {
    let message = revocation_payload(
        instance.subject_user_id,
        instance.subject_domain,
        instance.application_id,
        instance.instance_id,
        target_key_id,
        target_fingerprint,
        revoked_at,
    );
    let mut signatures = Vec::with_capacity(signers.len());
    for signer in signers {
        signatures.push(ApplicationKeySignature {
            signed_by_key_id: signer.key_id.to_string(),
            signature: crypto::sign_with_algorithm(
                signer.algorithm,
                &message,
                signer.private_key_bytes,
            )?,
        });
    }
    Ok(ApplicationKeyRevocation {
        subject_user_id: instance.subject_user_id.to_string(),
        subject_domain: instance.subject_domain.to_string(),
        application_id: instance.application_id.to_string(),
        instance_id: instance.instance_id.to_string(),
        target_key_id: target_key_id.to_string(),
        target_fingerprint: target_fingerprint.to_string(),
        revoked_at: revoked_at.to_string(),
        signatures,
    })
}

/// Verify a revocation against the instance's key set.
///
/// Requires [`REVOCATION_QUORUM`] distinct signing keys that were valid AT THE
/// REVOCATION TIME. Judging signers at `revoked_at` rather than at "now" is
/// deliberate: revocation is permanent, so the record must stay verifiable
/// long after its signers have themselves expired or been rotated out. A
/// signer that was valid when it signed authorized the revocation.
///
/// The target never signs and never counts. Whether `revoked_at` is
/// acceptable in the first place is a submission-time question — see
/// [`check_revocation_effective_time`] — because a verifier reading a stored
/// record years later has no basis to re-judge it.
pub fn verify_revocation(
    rev: &ApplicationKeyRevocation,
    keys: &[ApplicationKeyRef],
    instance: &InstanceRef<'_>,
) -> Result<(), ApplicationKeyError> {
    check_identity(
        instance,
        &rev.subject_user_id,
        &rev.subject_domain,
        &rev.application_id,
        &rev.instance_id,
    )?;
    let effective = parse_time(&rev.revoked_at)?;

    let Some(target) = keys.iter().find(|k| k.key_id == rev.target_key_id) else {
        return Err(ApplicationKeyError::UnknownKey(rev.target_key_id.clone()));
    };
    if target.fingerprint != rev.target_fingerprint {
        return Err(ApplicationKeyError::FingerprintMismatch);
    }

    let message = revocation_payload_of(rev);
    let accepted = count_distinct_signers(
        &rev.signatures,
        keys,
        &message,
        Some(&rev.target_key_id),
        |k| k.was_valid_at(effective),
    );
    if accepted.len() < REVOCATION_QUORUM {
        return Err(ApplicationKeyError::InsufficientSignatures {
            got: accepted.len(),
            need: REVOCATION_QUORUM,
        });
    }
    Ok(())
}

/// The submission-time check the home domain adds on top of
/// [`verify_revocation`]: a domain must not accept a revocation dated in the
/// future beyond the permitted skew.
pub fn check_revocation_effective_time(
    revoked_at: &str,
    now: DateTime<Utc>,
    skew_seconds: i64,
) -> Result<(), ApplicationKeyError> {
    let effective = parse_time(revoked_at)?;
    if effective > now + Duration::seconds(skew_seconds) {
        return Err(ApplicationKeyError::BadConfiguration(
            "revocation effective time is in the future".to_string(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The sealed challenge (X25519 proof of possession)
// ---------------------------------------------------------------------------

/// The AEAD suite the sealed challenge uses. Fixed rather than negotiated:
/// this is a one-shot box from the home domain to the application with no
/// handshake in which to agree anything. The id still travels inside the
/// encoding so a future change is detectable rather than silent.
pub const CHALLENGE_SEAL_SUITE: crate::crypto::AeadSuite =
    crate::crypto::AeadSuite::ChaCha20Poly1305;

/// Seal a challenge nonce to a claimed X25519 public key.
///
/// This is the other half of proof of possession. An Ed25519 key proves it
/// holds its private key by signing; an X25519 key cannot sign, and a
/// signature by some OTHER key in the same request proves nothing about it —
/// the signing keys and the key-agreement keys are independent. Without this
/// exchange an instance could enrol a public key that a different party holds.
///
/// The application decrypts and returns the plaintext inside the
/// quorum-signed addition request, which binds control of the X25519 private
/// key to the signing quorum in one structure.
///
/// This proof is defence in depth. The primary control against a misattributed
/// key-agreement key is the handshake itself: bind the attested canonical
/// identity into the transcript, through the Noise prologue or the HPKE `info`
/// string, so a peer detects a key that does not belong to the identity it
/// expects. Do not rely on enrolment proof alone.
pub fn seal_challenge(
    nonce: &[u8],
    recipient_x25519_public: &[u8; 32],
) -> Result<Vec<u8>, ApplicationKeyError> {
    let sealed = crypto::sealed_box_encrypt(nonce, recipient_x25519_public, CHALLENGE_SEAL_SUITE)?;
    encode_sealed_challenge(&sealed)
}

/// [`seal_challenge`]'s seam for deterministic conformance-vector generation
/// and tests: the ephemeral X25519 secret and the AEAD nonce are supplied
/// explicitly instead of drawn from the OS RNG. Mirrors
/// [`crate::local_rp::seal_local_rp_callback_with_randomness`], which solves
/// the identical problem for the local-RP callback box. Production code MUST
/// use [`seal_challenge`]; this function exists for reproducible test/vector
/// output only.
pub fn seal_challenge_with_randomness(
    nonce: &[u8],
    recipient_x25519_public: &[u8; 32],
    ephemeral_private_key: &[u8; 32],
    aead_nonce: &[u8; 12],
) -> Result<Vec<u8>, ApplicationKeyError> {
    let ephemeral_secret = X25519StaticSecret::from(*ephemeral_private_key);
    let sealed = crypto::sealed_box_encrypt_with_randomness(
        nonce,
        recipient_x25519_public,
        CHALLENGE_SEAL_SUITE,
        ephemeral_secret,
        *aead_nonce,
    )?;
    encode_sealed_challenge(&sealed)
}

/// A four-element CBOR array, not a bare concatenation: CBOR framing removes
/// any question about where each field ends, and needs no canonical
/// re-serialization in any target language. Shared by [`seal_challenge`] and
/// [`seal_challenge_with_randomness`].
fn encode_sealed_challenge(sealed: &crypto::SealedBox) -> Result<Vec<u8>, ApplicationKeyError> {
    let tuple = (
        CHALLENGE_SEAL_SUITE.as_str(),
        serde_bytes::Bytes::new(&sealed.ephemeral_public_key),
        serde_bytes::Bytes::new(&sealed.nonce),
        serde_bytes::Bytes::new(&sealed.ciphertext),
    );
    let mut out = Vec::new();
    ciborium::ser::into_writer(&tuple, &mut out)
        .map_err(|e| ApplicationKeyError::Decode(e.to_string()))?;
    Ok(out)
}

/// Open a sealed challenge with the X25519 private key the application holds.
/// The SDK side of [`seal_challenge`].
///
/// The recovered nonce IS the proof-of-possession secret for a key-agreement
/// key, so it comes back in a `Zeroizing` guard rather than a bare `Vec`.
pub fn open_challenge(
    sealed: &[u8],
    recipient_x25519_private: &[u8; 32],
) -> Result<zeroize::Zeroizing<Vec<u8>>, ApplicationKeyError> {
    let (suite_id, ephemeral, nonce, ciphertext): (
        String,
        serde_bytes::ByteBuf,
        serde_bytes::ByteBuf,
        serde_bytes::ByteBuf,
    ) = ciborium::de::from_reader(sealed)
        .map_err(|e| ApplicationKeyError::Decode(e.to_string()))?;
    let suite = crypto::AeadSuite::parse_str(&suite_id).ok_or_else(|| {
        ApplicationKeyError::Crypto(format!("unknown sealed challenge suite {suite_id}"))
    })?;
    Ok(crypto::sealed_box_decrypt(
        &ephemeral,
        &nonce,
        &ciphertext,
        recipient_x25519_private,
        suite,
    )?)
}

// ---------------------------------------------------------------------------
// Configuration bounds
// ---------------------------------------------------------------------------

/// Refuse a configuration in which a revoked, unexpired key could verify clean.
///
/// The revocation look-back only needs to exceed the maximum key lifetime plus
/// the maximum attestation lifetime plus the permitted skew: a record older
/// than that cannot change the answer for any key a verifier can still accept,
/// and an expired key needs no revocation record at all. A SHORTER window
/// would silently drop a record that still matters, which is the one failure
/// this design refuses to have — so the server checks this at startup rather
/// than discovering it in the field.
pub fn validate_revocation_window(
    revocation_window_seconds: i64,
    max_key_lifetime_seconds: i64,
    max_attestation_lifetime_seconds: i64,
    skew_seconds: i64,
) -> Result<(), ApplicationKeyError> {
    let required = max_key_lifetime_seconds
        .saturating_add(max_attestation_lifetime_seconds)
        .saturating_add(skew_seconds);
    if revocation_window_seconds < required {
        return Err(ApplicationKeyError::BadConfiguration(format!(
            "revocation look-back of {revocation_window_seconds}s is shorter than the \
             {required}s a revoked but unexpired key can survive (max key lifetime \
             {max_key_lifetime_seconds}s + max attestation lifetime \
             {max_attestation_lifetime_seconds}s + clock skew {skew_seconds}s); a revoked key \
             could verify clean"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{fingerprint, generate_ed25519_keypair, generate_x25519_keypair};

    const SUBJECT: &str = "018f0000-0000-7000-8000-000000000001";
    const DOMAIN: &str = "home.test";
    const APP: &str = "tinku";
    const INSTANCE: &str = "instance-a";

    fn instance() -> InstanceRef<'static> {
        InstanceRef {
            subject_user_id: SUBJECT,
            subject_domain: DOMAIN,
            application_id: APP,
            instance_id: INSTANCE,
        }
    }

    struct AppKey {
        key_id: String,
        public_key: Vec<u8>,
        private_key: Vec<u8>,
        usage: String,
        algorithm: String,
    }

    fn make_signing_key(id: &str) -> AppKey {
        let (vk, sk) = generate_ed25519_keypair();
        AppKey {
            key_id: id.to_string(),
            public_key: vk.as_bytes().to_vec(),
            private_key: sk.to_bytes().to_vec(),
            usage: KEY_USAGE_SIGN.to_string(),
            algorithm: ALG_ED25519.to_string(),
        }
    }

    fn make_agree_key(id: &str) -> AppKey {
        let (public_key, private_key) = generate_x25519_keypair();
        AppKey {
            key_id: id.to_string(),
            public_key,
            private_key,
            usage: KEY_USAGE_AGREE.to_string(),
            algorithm: ALG_X25519.to_string(),
        }
    }

    fn key_ref(k: &AppKey) -> ApplicationKeyRef {
        ApplicationKeyRef {
            key_id: k.key_id.clone(),
            key_usage: k.usage.clone(),
            algorithm: k.algorithm.clone(),
            public_key: k.public_key.clone(),
            fingerprint: fingerprint(&k.public_key),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2027-01-01T00:00:00Z".to_string(),
            revoked_at: None,
        }
    }

    fn signer(k: &AppKey) -> ApplicationSigner<'_> {
        ApplicationSigner {
            key_id: &k.key_id,
            algorithm: SigningAlgorithm::Ed25519,
            private_key_bytes: &k.private_key,
        }
    }

    fn now() -> DateTime<Utc> {
        parse_time("2026-06-01T00:00:00Z").unwrap()
    }

    fn addition_for(k: &AppKey) -> ApplicationKeyAddition {
        ApplicationKeyAddition {
            subject_user_id: SUBJECT.to_string(),
            subject_domain: DOMAIN.to_string(),
            application_id: APP.to_string(),
            instance_id: INSTANCE.to_string(),
            key_id: k.key_id.clone(),
            key_usage: k.usage.clone(),
            algorithm: k.algorithm.clone(),
            public_key: k.public_key.clone(),
            fingerprint: fingerprint(&k.public_key),
            requested_key_lifetime_seconds: 31_536_000,
            challenge_id: "chal-1".to_string(),
            challenge: vec![7u8; 32],
            requested_at: "2026-05-31T23:59:00Z".to_string(),
            expires_at: "2026-06-01T00:05:00Z".to_string(),
        }
    }

    // --- key shape -------------------------------------------------------

    #[test]
    fn sign_use_requires_ed25519_and_agree_use_requires_x25519() {
        let sign = make_signing_key("k1");
        let agree = make_agree_key("k2");
        assert!(check_key_shape(
            KEY_USAGE_SIGN,
            ALG_ED25519,
            &sign.public_key,
            &fingerprint(&sign.public_key)
        )
        .is_ok());
        // An X25519 key presented as a signing key is refused: it cannot sign,
        // so accepting it would create a key that can never make a quorum.
        assert!(matches!(
            check_key_shape(
                KEY_USAGE_SIGN,
                ALG_X25519,
                &agree.public_key,
                &fingerprint(&agree.public_key)
            ),
            Err(ApplicationKeyError::UsageMismatch { .. })
        ));
    }

    #[test]
    fn a_lying_fingerprint_is_refused() {
        let k = make_signing_key("k1");
        assert_eq!(
            check_key_shape(KEY_USAGE_SIGN, ALG_ED25519, &k.public_key, "00"),
            Err(ApplicationKeyError::FingerprintMismatch)
        );
    }

    // --- addition quorum -------------------------------------------------

    #[test]
    fn two_distinct_valid_keys_authorize_an_addition() {
        let (a, b, new) = (
            make_signing_key("a"),
            make_signing_key("b"),
            make_signing_key("c"),
        );
        let existing = vec![key_ref(&a), key_ref(&b)];
        let signed = sign_addition(
            &addition_for(&new),
            &[signer(&a), signer(&b)],
            Some(&signer(&new)),
        )
        .unwrap();
        let out = verify_addition(&signed, &existing, &instance(), now(), 300).unwrap();
        assert_eq!(out.key_id, "c");
    }

    #[test]
    fn one_signature_is_not_a_quorum() {
        let (a, new) = (make_signing_key("a"), make_signing_key("c"));
        let existing = vec![key_ref(&a)];
        let signed =
            sign_addition(&addition_for(&new), &[signer(&a)], Some(&signer(&new))).unwrap();
        assert_eq!(
            verify_addition(&signed, &existing, &instance(), now(), 300),
            Err(ApplicationKeyError::InsufficientSignatures { got: 1, need: 2 })
        );
    }

    #[test]
    fn the_same_key_signing_twice_is_still_one_signer() {
        let (a, new) = (make_signing_key("a"), make_signing_key("c"));
        let existing = vec![key_ref(&a)];
        let signed = sign_addition(
            &addition_for(&new),
            &[signer(&a), signer(&a)],
            Some(&signer(&new)),
        )
        .unwrap();
        assert_eq!(
            verify_addition(&signed, &existing, &instance(), now(), 300),
            Err(ApplicationKeyError::InsufficientSignatures { got: 1, need: 2 })
        );
    }

    #[test]
    fn the_new_key_cannot_count_toward_its_own_authorization() {
        // The new key is presented as an existing key too (as a compromised
        // server or a confused client might). It still must not count.
        let (a, new) = (make_signing_key("a"), make_signing_key("c"));
        let existing = vec![key_ref(&a), key_ref(&new)];
        let signed = sign_addition(
            &addition_for(&new),
            &[signer(&a), signer(&new)],
            Some(&signer(&new)),
        )
        .unwrap();
        assert_eq!(
            verify_addition(&signed, &existing, &instance(), now(), 300),
            Err(ApplicationKeyError::InsufficientSignatures { got: 1, need: 2 })
        );
    }

    #[test]
    fn a_key_agreement_key_never_counts_toward_a_quorum() {
        let (a, agree, new) = (
            make_signing_key("a"),
            make_agree_key("x"),
            make_signing_key("c"),
        );
        // The X25519 key is a real, valid key of the instance -- but it is not
        // a signing key, so it contributes nothing. (It cannot even produce a
        // signature; we assert on the key set, which is the rule that matters.)
        let existing = vec![key_ref(&a), key_ref(&agree)];
        let signed =
            sign_addition(&addition_for(&new), &[signer(&a)], Some(&signer(&new))).unwrap();
        assert_eq!(
            verify_addition(&signed, &existing, &instance(), now(), 300),
            Err(ApplicationKeyError::InsufficientSignatures { got: 1, need: 2 })
        );
    }

    #[test]
    fn an_expired_or_revoked_sibling_does_not_count() {
        let (a, b, new) = (
            make_signing_key("a"),
            make_signing_key("b"),
            make_signing_key("c"),
        );
        let mut expired = key_ref(&b);
        expired.expires_at = "2026-02-01T00:00:00Z".to_string();
        let existing = vec![key_ref(&a), expired];
        let signed = sign_addition(
            &addition_for(&new),
            &[signer(&a), signer(&b)],
            Some(&signer(&new)),
        )
        .unwrap();
        assert_eq!(
            verify_addition(&signed, &existing, &instance(), now(), 300),
            Err(ApplicationKeyError::InsufficientSignatures { got: 1, need: 2 })
        );

        let mut revoked = key_ref(&b);
        revoked.revoked_at = Some("2026-03-01T00:00:00Z".to_string());
        let existing = vec![key_ref(&a), revoked];
        assert_eq!(
            verify_addition(&signed, &existing, &instance(), now(), 300),
            Err(ApplicationKeyError::InsufficientSignatures { got: 1, need: 2 })
        );
    }

    #[test]
    fn signature_order_carries_no_meaning() {
        let (a, b, new) = (
            make_signing_key("a"),
            make_signing_key("b"),
            make_signing_key("c"),
        );
        let existing = vec![key_ref(&a), key_ref(&b)];
        let forward = sign_addition(
            &addition_for(&new),
            &[signer(&a), signer(&b)],
            Some(&signer(&new)),
        )
        .unwrap();
        let mut reversed = forward.clone();
        reversed.signatures.reverse();
        assert!(verify_addition(&forward, &existing, &instance(), now(), 300).is_ok());
        assert!(verify_addition(&reversed, &existing, &instance(), now(), 300).is_ok());
        // Key-set order is equally meaningless.
        let reversed_keys = vec![key_ref(&b), key_ref(&a)];
        assert!(verify_addition(&forward, &reversed_keys, &instance(), now(), 300).is_ok());
    }

    // --- possession ------------------------------------------------------

    #[test]
    fn a_signing_key_without_a_possession_proof_is_refused() {
        let (a, b, new) = (
            make_signing_key("a"),
            make_signing_key("b"),
            make_signing_key("c"),
        );
        let existing = vec![key_ref(&a), key_ref(&b)];
        let signed = sign_addition(&addition_for(&new), &[signer(&a), signer(&b)], None).unwrap();
        assert_eq!(
            verify_addition(&signed, &existing, &instance(), now(), 300),
            Err(ApplicationKeyError::MissingPossessionProof)
        );
    }

    #[test]
    fn a_possession_proof_by_the_wrong_key_is_refused() {
        // The attack this stops: enrolling a public key you do not hold, by
        // borrowing a proof made with a key you do.
        let (a, b, new, impostor) = (
            make_signing_key("a"),
            make_signing_key("b"),
            make_signing_key("c"),
            make_signing_key("evil"),
        );
        let existing = vec![key_ref(&a), key_ref(&b)];
        let signed = sign_addition(
            &addition_for(&new),
            &[signer(&a), signer(&b)],
            Some(&signer(&impostor)),
        )
        .unwrap();
        assert_eq!(
            verify_addition(&signed, &existing, &instance(), now(), 300),
            Err(ApplicationKeyError::BadPossessionProof)
        );
    }

    #[test]
    fn a_quorum_signature_cannot_be_replayed_as_a_possession_proof() {
        // The two signatures cover the same bytes under DIFFERENT tags, so a
        // signature made for one purpose must not verify for the other.
        let (a, b, new) = (
            make_signing_key("a"),
            make_signing_key("b"),
            make_signing_key("c"),
        );
        let existing = vec![key_ref(&a), key_ref(&b)];
        let mut signed = sign_addition(
            &addition_for(&new),
            &[signer(&a), signer(&b)],
            Some(&signer(&new)),
        )
        .unwrap();
        // Take the new key's own quorum-tagged signature and offer it as the
        // possession proof.
        let quorum_style = crypto::sign_with_algorithm(
            SigningAlgorithm::Ed25519,
            &addition_signature_input(&signed.addition),
            &new.private_key,
        )
        .unwrap();
        signed.possession_proof = Some(quorum_style);
        assert_eq!(
            verify_addition(&signed, &existing, &instance(), now(), 300),
            Err(ApplicationKeyError::BadPossessionProof)
        );
    }

    #[test]
    fn a_key_agreement_key_may_not_carry_a_possession_signature() {
        // An X25519 key cannot sign, so any signature offered here proves
        // nothing about it. Accepting one would let a party enrol a public key
        // it does not hold -- the exact misattribution this rule prevents.
        let (a, b) = (make_signing_key("a"), make_signing_key("b"));
        let agree = make_agree_key("x");
        let existing = vec![key_ref(&a), key_ref(&b)];
        let bogus = make_signing_key("bogus");
        let signed = sign_addition(
            &addition_for(&agree),
            &[signer(&a), signer(&b)],
            Some(&signer(&bogus)),
        )
        .unwrap();
        assert_eq!(
            verify_addition(&signed, &existing, &instance(), now(), 300),
            Err(ApplicationKeyError::BadPossessionProof)
        );
    }

    #[test]
    fn a_key_agreement_key_enrolls_on_quorum_alone() {
        // Its possession proof is the sealed-challenge plaintext in
        // `challenge`, which only the server (holding the nonce) can check.
        let (a, b) = (make_signing_key("a"), make_signing_key("b"));
        let agree = make_agree_key("x");
        let existing = vec![key_ref(&a), key_ref(&b)];
        let signed = sign_addition(&addition_for(&agree), &[signer(&a), signer(&b)], None).unwrap();
        let out = verify_addition(&signed, &existing, &instance(), now(), 300).unwrap();
        assert_eq!(out.key_usage, KEY_USAGE_AGREE);
        assert_eq!(out.challenge, vec![7u8; 32]);
    }

    // --- identity binding ------------------------------------------------

    #[test]
    fn a_request_for_another_subject_application_or_instance_is_refused() {
        let (a, b, new) = (
            make_signing_key("a"),
            make_signing_key("b"),
            make_signing_key("c"),
        );
        let existing = vec![key_ref(&a), key_ref(&b)];
        let signed = sign_addition(
            &addition_for(&new),
            &[signer(&a), signer(&b)],
            Some(&signer(&new)),
        )
        .unwrap();

        for (field, other) in [
            (
                "subject_user_id",
                InstanceRef {
                    subject_user_id: "someone-else",
                    ..instance()
                },
            ),
            (
                "subject_domain",
                InstanceRef {
                    subject_domain: "evil.test",
                    ..instance()
                },
            ),
            (
                "application_id",
                InstanceRef {
                    application_id: "other-app",
                    ..instance()
                },
            ),
            (
                "instance_id",
                InstanceRef {
                    instance_id: "instance-b",
                    ..instance()
                },
            ),
        ] {
            assert_eq!(
                verify_addition(&signed, &existing, &other, now(), 300),
                Err(ApplicationKeyError::IdentityMismatch { field }),
                "{field} must be bound"
            );
        }
    }

    #[test]
    fn a_stale_request_is_refused() {
        let (a, b, new) = (
            make_signing_key("a"),
            make_signing_key("b"),
            make_signing_key("c"),
        );
        let existing = vec![key_ref(&a), key_ref(&b)];
        let signed = sign_addition(
            &addition_for(&new),
            &[signer(&a), signer(&b)],
            Some(&signer(&new)),
        )
        .unwrap();
        let much_later = parse_time("2026-06-02T00:00:00Z").unwrap();
        assert_eq!(
            verify_addition(&signed, &existing, &instance(), much_later, 300),
            Err(ApplicationKeyError::RequestExpired)
        );
    }

    // --- initial enrollment ----------------------------------------------

    #[test]
    fn enrollment_needs_two_signing_keys_each_proving_possession() {
        let (a, b, c) = (
            make_signing_key("a"),
            make_signing_key("b"),
            make_signing_key("c"),
        );
        let batch: Vec<_> = [&a, &b, &c]
            .iter()
            .map(|k| sign_addition(&addition_for(k), &[], Some(&signer(k))).unwrap())
            .collect();
        let out = verify_initial_enrollment(&batch, &instance(), now(), 300).unwrap();
        assert_eq!(out.len(), 3);

        // One key alone is not enough to bootstrap.
        let single = vec![batch[0].clone()];
        assert_eq!(
            verify_initial_enrollment(&single, &instance(), now(), 300),
            Err(ApplicationKeyError::TooFewSigningKeys { got: 1, need: 2 })
        );
    }

    #[test]
    fn enrollment_still_requires_each_key_to_prove_possession() {
        let (a, b) = (make_signing_key("a"), make_signing_key("b"));
        let batch = vec![
            sign_addition(&addition_for(&a), &[], Some(&signer(&a))).unwrap(),
            sign_addition(&addition_for(&b), &[], None).unwrap(),
        ];
        assert_eq!(
            verify_initial_enrollment(&batch, &instance(), now(), 300),
            Err(ApplicationKeyError::MissingPossessionProof)
        );
    }

    #[test]
    fn enrollment_refuses_a_duplicate_key_id() {
        let a = make_signing_key("a");
        let b = make_signing_key("b");
        let mut dup = addition_for(&b);
        dup.key_id = "a".to_string();
        let batch = vec![
            sign_addition(&addition_for(&a), &[], Some(&signer(&a))).unwrap(),
            sign_addition(&dup, &[], Some(&signer(&b))).unwrap(),
        ];
        assert_eq!(
            verify_initial_enrollment(&batch, &instance(), now(), 300),
            Err(ApplicationKeyError::DuplicateKey("a".to_string()))
        );
    }

    #[test]
    fn a_key_agreement_key_alone_cannot_bootstrap_an_instance() {
        let agree = make_agree_key("x");
        let agree2 = make_agree_key("y");
        let batch = vec![
            sign_addition(&addition_for(&agree), &[], None).unwrap(),
            sign_addition(&addition_for(&agree2), &[], None).unwrap(),
        ];
        assert_eq!(
            verify_initial_enrollment(&batch, &instance(), now(), 300),
            Err(ApplicationKeyError::TooFewSigningKeys { got: 0, need: 2 })
        );
    }

    // --- renewal ---------------------------------------------------------

    fn renewal_for(key_id: &str) -> ApplicationKeyRenewal {
        ApplicationKeyRenewal {
            subject_user_id: SUBJECT.to_string(),
            subject_domain: DOMAIN.to_string(),
            application_id: APP.to_string(),
            instance_id: INSTANCE.to_string(),
            key_id: key_id.to_string(),
            challenge_id: "chal-2".to_string(),
            challenge: vec![9u8; 32],
            requested_at: "2026-05-31T23:59:00Z".to_string(),
            expires_at: "2026-06-01T00:05:00Z".to_string(),
        }
    }

    #[test]
    fn a_signing_key_renews_by_signing_for_itself() {
        let a = make_signing_key("a");
        let signed = sign_renewal(&renewal_for("a"), &[], Some(&signer(&a))).unwrap();
        let out = verify_renewal(&signed, &key_ref(&a), &[], &instance(), now(), 300).unwrap();
        assert_eq!(out.key_id, "a");
    }

    #[test]
    fn renewal_without_current_possession_is_refused() {
        let a = make_signing_key("a");
        let impostor = make_signing_key("evil");
        let signed = sign_renewal(&renewal_for("a"), &[], Some(&signer(&impostor))).unwrap();
        assert_eq!(
            verify_renewal(&signed, &key_ref(&a), &[], &instance(), now(), 300),
            Err(ApplicationKeyError::BadPossessionProof)
        );
    }

    #[test]
    fn a_revoked_key_can_never_be_renewed() {
        let a = make_signing_key("a");
        let mut target = key_ref(&a);
        target.revoked_at = Some("2026-03-01T00:00:00Z".to_string());
        let signed = sign_renewal(&renewal_for("a"), &[], Some(&signer(&a))).unwrap();
        assert_eq!(
            verify_renewal(&signed, &target, &[], &instance(), now(), 300),
            Err(ApplicationKeyError::KeyRevoked("a".to_string()))
        );
    }

    #[test]
    fn a_key_agreement_key_renews_on_a_sibling_signature() {
        let agree = make_agree_key("x");
        let a = make_signing_key("a");
        let siblings = vec![key_ref(&a)];
        let signed = sign_renewal(&renewal_for("x"), &[signer(&a)], None).unwrap();
        assert!(verify_renewal(
            &signed,
            &key_ref(&agree),
            &siblings,
            &instance(),
            now(),
            300
        )
        .is_ok());

        // With no sibling vouching for it, there is nothing to attribute the
        // request to.
        let unsigned = sign_renewal(&renewal_for("x"), &[], None).unwrap();
        assert_eq!(
            verify_renewal(
                &unsigned,
                &key_ref(&agree),
                &siblings,
                &instance(),
                now(),
                300
            ),
            Err(ApplicationKeyError::InsufficientSignatures { got: 0, need: 1 })
        );
    }

    #[test]
    fn renewal_for_a_different_key_is_refused() {
        let a = make_signing_key("a");
        let b = make_signing_key("b");
        let signed = sign_renewal(&renewal_for("b"), &[], Some(&signer(&b))).unwrap();
        assert_eq!(
            verify_renewal(&signed, &key_ref(&a), &[], &instance(), now(), 300),
            Err(ApplicationKeyError::IdentityMismatch { field: "key_id" })
        );
    }

    // --- idempotent renewal ----------------------------------------------

    #[test]
    fn renewal_above_the_half_life_returns_the_stored_bytes() {
        let start = "2026-06-01T00:00:00Z";
        let end = "2026-06-02T00:00:00Z";
        // Just after issue: more than half the lifetime remains, so no new
        // signature. This is what absorbs a retry or restart storm.
        assert!(
            !needs_new_attestation(start, end, parse_time("2026-06-01T01:00:00Z").unwrap())
                .unwrap()
        );
        assert!(
            !needs_new_attestation(start, end, parse_time("2026-06-01T11:59:59Z").unwrap())
                .unwrap()
        );
        // At and past the half-life, a new signature is made.
        assert!(
            needs_new_attestation(start, end, parse_time("2026-06-01T12:00:00Z").unwrap()).unwrap()
        );
        assert!(
            needs_new_attestation(start, end, parse_time("2026-06-01T18:00:00Z").unwrap()).unwrap()
        );
    }

    #[test]
    fn a_clock_skewed_client_asking_early_still_gets_a_cache_hit() {
        // A client whose clock runs hours fast asks immediately after issue.
        // The server judges by ITS clock, so it returns stored bytes.
        let start = "2026-06-01T00:00:00Z";
        let end = "2026-06-02T00:00:00Z";
        assert!(!needs_new_attestation(start, end, parse_time(start).unwrap()).unwrap());
    }

    #[test]
    fn a_degenerate_attestation_window_always_re_signs() {
        assert!(
            needs_new_attestation("2026-06-02T00:00:00Z", "2026-06-01T00:00:00Z", now()).unwrap()
        );
    }

    // --- revocation ------------------------------------------------------

    fn revoke(
        target: &AppKey,
        signers: &[ApplicationSigner<'_>],
        at: &str,
    ) -> ApplicationKeyRevocation {
        sign_revocation(
            &instance(),
            &target.key_id,
            &fingerprint(&target.public_key),
            at,
            signers,
        )
        .unwrap()
    }

    #[test]
    fn two_siblings_revoke_a_third() {
        let (a, b, t) = (
            make_signing_key("a"),
            make_signing_key("b"),
            make_signing_key("t"),
        );
        let keys = vec![key_ref(&a), key_ref(&b), key_ref(&t)];
        let rev = revoke(&t, &[signer(&a), signer(&b)], "2026-06-01T00:00:00Z");
        assert!(verify_revocation(&rev, &keys, &instance()).is_ok());
    }

    #[test]
    fn the_target_may_not_sign_its_own_revocation() {
        let (a, t) = (make_signing_key("a"), make_signing_key("t"));
        let keys = vec![key_ref(&a), key_ref(&t)];
        // One real sibling plus the target trying to authorize itself. This is
        // why two signing keys are not enough to run an instance safely.
        let rev = revoke(&t, &[signer(&a), signer(&t)], "2026-06-01T00:00:00Z");
        assert_eq!(
            verify_revocation(&rev, &keys, &instance()),
            Err(ApplicationKeyError::InsufficientSignatures { got: 1, need: 2 })
        );
    }

    #[test]
    fn a_revocation_stays_verifiable_after_its_signers_expire() {
        // Revocation is permanent, so a verifier reading the record later must
        // still be able to check it. Signers are judged at the revocation time.
        let (a, b, t) = (
            make_signing_key("a"),
            make_signing_key("b"),
            make_signing_key("t"),
        );
        let rev = revoke(&t, &[signer(&a), signer(&b)], "2026-06-01T00:00:00Z");
        let mut keys = vec![key_ref(&a), key_ref(&b), key_ref(&t)];
        for k in keys.iter_mut() {
            k.expires_at = "2026-07-01T00:00:00Z".to_string();
        }
        assert!(verify_revocation(&rev, &keys, &instance()).is_ok());
    }

    #[test]
    fn a_signer_that_was_not_yet_valid_does_not_count() {
        let (a, b, t) = (
            make_signing_key("a"),
            make_signing_key("b"),
            make_signing_key("t"),
        );
        let rev = revoke(&t, &[signer(&a), signer(&b)], "2026-06-01T00:00:00Z");
        let mut keys = vec![key_ref(&a), key_ref(&b), key_ref(&t)];
        keys[1].created_at = "2026-08-01T00:00:00Z".to_string();
        assert_eq!(
            verify_revocation(&rev, &keys, &instance()),
            Err(ApplicationKeyError::InsufficientSignatures { got: 1, need: 2 })
        );
    }

    #[test]
    fn a_tampered_revocation_time_breaks_the_signatures() {
        let (a, b, t) = (
            make_signing_key("a"),
            make_signing_key("b"),
            make_signing_key("t"),
        );
        let keys = vec![key_ref(&a), key_ref(&b), key_ref(&t)];
        let mut rev = revoke(&t, &[signer(&a), signer(&b)], "2026-06-01T00:00:00Z");
        rev.revoked_at = "2026-05-01T00:00:00Z".to_string();
        assert!(verify_revocation(&rev, &keys, &instance()).is_err());
    }

    #[test]
    fn a_revocation_cannot_be_moved_to_another_instance() {
        let (a, b, t) = (
            make_signing_key("a"),
            make_signing_key("b"),
            make_signing_key("t"),
        );
        let keys = vec![key_ref(&a), key_ref(&b), key_ref(&t)];
        let rev = revoke(&t, &[signer(&a), signer(&b)], "2026-06-01T00:00:00Z");
        let other = InstanceRef {
            instance_id: "instance-b",
            ..instance()
        };
        assert_eq!(
            verify_revocation(&rev, &keys, &other),
            Err(ApplicationKeyError::IdentityMismatch {
                field: "instance_id"
            })
        );
    }

    #[test]
    fn a_key_agreement_key_is_revoked_by_two_signing_siblings() {
        let (a, b) = (make_signing_key("a"), make_signing_key("b"));
        let agree = make_agree_key("x");
        let keys = vec![key_ref(&a), key_ref(&b), key_ref(&agree)];
        let rev = revoke(&agree, &[signer(&a), signer(&b)], "2026-06-01T00:00:00Z");
        assert!(verify_revocation(&rev, &keys, &instance()).is_ok());
    }

    #[test]
    fn a_future_dated_revocation_is_refused_at_submission() {
        assert!(check_revocation_effective_time("2026-06-01T00:01:00Z", now(), 300).is_ok());
        assert!(check_revocation_effective_time("2026-06-01T01:00:00Z", now(), 300).is_err());
    }

    // --- attestations and the verifier's view ----------------------------

    struct DomainKey {
        key_id: String,
        public_key: Vec<u8>,
        private_key: Vec<u8>,
    }

    fn make_domain_key(id: &str) -> DomainKey {
        let (vk, sk) = generate_ed25519_keypair();
        DomainKey {
            key_id: id.to_string(),
            public_key: vk.as_bytes().to_vec(),
            private_key: sk.to_bytes().to_vec(),
        }
    }

    fn domain_public(d: &DomainKey) -> DomainPublicKey {
        DomainPublicKey {
            key_id: d.key_id.clone(),
            public_key: d.public_key.clone(),
            fingerprint: fingerprint(&d.public_key),
            algorithm: ALG_ED25519.to_string(),
            key_usage: "sign".to_string(),
            created_at: String::new(),
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            revoked_at: None,
            signed_by_key_id: None,
            key_signature: None,
        }
    }

    fn domain_signer(d: &DomainKey) -> ClaimSigner<'_> {
        ClaimSigner {
            domain: DOMAIN,
            key_id: &d.key_id,
            algorithm: SigningAlgorithm::Ed25519,
            private_key_bytes: &d.private_key,
        }
    }

    fn attest(d: &DomainKey, k: &AppKey, expires: &str) -> SignedApplicationKeyAttestation {
        let mut key = key_ref(k);
        key.expires_at = "2027-01-01T00:00:00Z".to_string();
        let mut a = build_attestation(
            &instance(),
            &key,
            now(),
            DEFAULT_ATTESTATION_LIFETIME_SECONDS,
        );
        a.attestation_expires_at = expires.to_string();
        sign_attestation(&a, &[domain_signer(d)]).unwrap()
    }

    #[test]
    fn an_attestation_round_trips_and_verifies() {
        let d = make_domain_key("dk1");
        let k = make_signing_key("a");
        let signed = attest(&d, &k, "2026-06-02T00:00:00Z");
        let out = verify_attestation_signature(&signed, &[domain_public(&d)], DOMAIN).unwrap();
        assert_eq!(out.key_id, "a");
        assert_eq!(out.public_key, k.public_key);
    }

    #[test]
    fn an_attestation_signed_by_an_unknown_domain_key_is_untrusted() {
        let d = make_domain_key("dk1");
        let other = make_domain_key("dk2");
        let k = make_signing_key("a");
        let signed = attest(&d, &k, "2026-06-02T00:00:00Z");
        assert_eq!(
            verify_attestation_signature(&signed, &[domain_public(&other)], DOMAIN),
            Err(ApplicationKeyError::UntrustedAttestation)
        );
    }

    #[test]
    fn an_attestation_signature_is_bound_to_its_domain_separation_tag() {
        let d = make_domain_key("dk1");
        let k = make_signing_key("a");
        let mut signed = attest(&d, &k, "2026-06-02T00:00:00Z");
        // Re-sign the SAME attestation bytes under a different tag. Nothing
        // else changes; only the domain separator does.
        signed.signatures[0].signature = crypto::sign_with_algorithm(
            SigningAlgorithm::Ed25519,
            &envelope_signature_input("linkkeys-claim-v1alpha", &signed.attestation),
            &d.private_key,
        )
        .unwrap();
        assert_eq!(
            verify_attestation_signature(&signed, &[domain_public(&d)], DOMAIN),
            Err(ApplicationKeyError::UntrustedAttestation)
        );
    }

    #[test]
    fn an_attestation_for_another_domain_is_refused() {
        let d = make_domain_key("dk1");
        let k = make_signing_key("a");
        let signed = attest(&d, &k, "2026-06-02T00:00:00Z");
        assert_eq!(
            verify_attestation_signature(&signed, &[domain_public(&d)], "evil.test"),
            Err(ApplicationKeyError::IdentityMismatch {
                field: "subject_domain"
            })
        );
    }

    #[test]
    fn tampering_with_the_attestation_bytes_breaks_the_signature() {
        let d = make_domain_key("dk1");
        let k = make_signing_key("a");
        let signed = attest(&d, &k, "2026-06-02T00:00:00Z");
        let mut decoded =
            crate::generated::decode_application_key_attestation(&signed.attestation).unwrap();
        decoded.key_expires_at = "2099-01-01T00:00:00Z".to_string();
        let tampered = SignedApplicationKeyAttestation {
            attestation: crate::generated::encode_application_key_attestation(&decoded),
            signatures: signed.signatures.clone(),
        };
        assert_eq!(
            verify_attestation_signature(&tampered, &[domain_public(&d)], DOMAIN),
            Err(ApplicationKeyError::UntrustedAttestation)
        );
    }

    #[test]
    fn an_expired_attestation_is_a_missing_proof_not_a_revocation() {
        let d = make_domain_key("dk1");
        let k = make_signing_key("a");
        let stale = attest(&d, &k, "2026-05-01T00:00:00Z");
        let set = verify_application_key_set(
            &[stale],
            &[],
            &[domain_public(&d)],
            &instance(),
            now(),
            300,
        );
        assert_eq!(set.keys.len(), 1);
        assert_eq!(set.keys[0].status, KeyStatus::AttestationExpired);
        assert!(set.revoked_key_ids.is_empty());
        assert_eq!(
            set.key_for_use("a", KEY_USAGE_SIGN, ALG_ED25519),
            Err(ApplicationKeyError::AttestationExpired)
        );

        // A renewed attestation for the SAME unrevoked key makes it usable
        // again -- the key never went anywhere.
        let d2 = make_domain_key("dk1");
        let fresh = attest(&d2, &k, "2026-06-02T00:00:00Z");
        let set = verify_application_key_set(
            &[fresh],
            &[],
            &[domain_public(&d2)],
            &instance(),
            now(),
            300,
        );
        assert!(set.keys[0].is_usable());
    }

    #[test]
    fn a_revoked_key_fails_after_its_effective_time() {
        let d = make_domain_key("dk1");
        let (a, b, t) = (
            make_signing_key("a"),
            make_signing_key("b"),
            make_signing_key("t"),
        );
        let attestations = vec![
            attest(&d, &a, "2027-01-01T00:00:00Z"),
            attest(&d, &b, "2027-01-01T00:00:00Z"),
            attest(&d, &t, "2027-01-01T00:00:00Z"),
        ];
        let rev = revoke(&t, &[signer(&a), signer(&b)], "2026-06-15T00:00:00Z");

        // Before the effective time the key still verifies.
        let revocations = [rev];
        let before = verify_application_key_set(
            &attestations,
            &revocations,
            &[domain_public(&d)],
            &instance(),
            parse_time("2026-06-10T00:00:00Z").unwrap(),
            300,
        );
        assert!(before.rejected.is_empty(), "{:?}", before.rejected);
        assert!(before.key_for_use("t", KEY_USAGE_SIGN, ALG_ED25519).is_ok());

        // After it, the key is refused and stays refused.
        let after = verify_application_key_set(
            &attestations,
            &revocations,
            &[domain_public(&d)],
            &instance(),
            parse_time("2026-06-20T00:00:00Z").unwrap(),
            300,
        );
        assert!(after.revoked_key_ids.contains("t"));
        assert_eq!(
            after.key_for_use("t", KEY_USAGE_SIGN, ALG_ED25519),
            Err(ApplicationKeyError::KeyRevoked("t".to_string()))
        );
        // The siblings are unaffected.
        assert!(after.key_for_use("a", KEY_USAGE_SIGN, ALG_ED25519).is_ok());
    }

    #[test]
    fn a_revocation_without_quorum_does_not_revoke_anything() {
        let d = make_domain_key("dk1");
        let (a, t) = (make_signing_key("a"), make_signing_key("t"));
        let attestations = vec![
            attest(&d, &a, "2027-01-01T00:00:00Z"),
            attest(&d, &t, "2027-01-01T00:00:00Z"),
        ];
        let rev = revoke(&t, &[signer(&a)], "2026-06-01T00:00:00Z");
        let set = verify_application_key_set(
            &attestations,
            &[rev],
            &[domain_public(&d)],
            &instance(),
            now(),
            300,
        );
        assert!(set.revoked_key_ids.is_empty());
        assert_eq!(set.rejected.len(), 1);
        assert!(set.key_for_use("t", KEY_USAGE_SIGN, ALG_ED25519).is_ok());
    }

    #[test]
    fn asking_for_the_wrong_use_or_algorithm_fails_closed() {
        let d = make_domain_key("dk1");
        let a = make_signing_key("a");
        let set = verify_application_key_set(
            &[attest(&d, &a, "2027-01-01T00:00:00Z")],
            &[],
            &[domain_public(&d)],
            &instance(),
            now(),
            300,
        );
        assert!(matches!(
            set.key_for_use("a", KEY_USAGE_AGREE, ALG_X25519),
            Err(ApplicationKeyError::UsageMismatch { .. })
        ));
        assert!(matches!(
            set.key_for_use("a", KEY_USAGE_SIGN, ALG_X25519),
            Err(ApplicationKeyError::UsageMismatch { .. })
        ));
        assert_eq!(
            set.key_for_use("nope", KEY_USAGE_SIGN, ALG_ED25519),
            Err(ApplicationKeyError::UnknownKey("nope".to_string()))
        );
    }

    #[test]
    fn an_attestation_from_another_instance_never_enters_the_set() {
        // A cache entry must not cross an instance boundary. Even correctly
        // signed by the right domain, an attestation for instance-b is not an
        // answer about instance-a.
        let d = make_domain_key("dk1");
        let k = make_signing_key("a");
        let other = InstanceRef {
            instance_id: "instance-b",
            ..instance()
        };
        let mut key = key_ref(&k);
        key.expires_at = "2027-01-01T00:00:00Z".to_string();
        let a = build_attestation(&other, &key, now(), DEFAULT_ATTESTATION_LIFETIME_SECONDS);
        let signed = sign_attestation(&a, &[domain_signer(&d)]).unwrap();

        let set = verify_application_key_set(
            &[signed],
            &[],
            &[domain_public(&d)],
            &instance(),
            now(),
            300,
        );
        assert!(set.keys.is_empty());
        assert_eq!(set.rejected.len(), 1);
    }

    #[test]
    fn rotation_works_while_old_and_new_keys_overlap() {
        let d = make_domain_key("dk1");
        let (old, new) = (make_signing_key("old"), make_signing_key("new"));
        let set = verify_application_key_set(
            &[
                attest(&d, &old, "2027-01-01T00:00:00Z"),
                attest(&d, &new, "2027-01-01T00:00:00Z"),
            ],
            &[],
            &[domain_public(&d)],
            &instance(),
            now(),
            300,
        );
        // Both are equal and both are usable. There is no preferred key.
        let usable = set.usable_keys(KEY_USAGE_SIGN);
        assert_eq!(usable.len(), 2);
        assert!(set.key_for_use("old", KEY_USAGE_SIGN, ALG_ED25519).is_ok());
        assert!(set.key_for_use("new", KEY_USAGE_SIGN, ALG_ED25519).is_ok());
    }

    #[test]
    fn key_set_order_does_not_change_the_answer() {
        let d = make_domain_key("dk1");
        let (a, b) = (make_signing_key("a"), make_signing_key("b"));
        let forward = vec![
            attest(&d, &a, "2027-01-01T00:00:00Z"),
            attest(&d, &b, "2027-01-01T00:00:00Z"),
        ];
        let mut reversed = forward.clone();
        reversed.reverse();
        let dk = [domain_public(&d)];
        let one = verify_application_key_set(&forward, &[], &dk, &instance(), now(), 300);
        let two = verify_application_key_set(&reversed, &[], &dk, &instance(), now(), 300);
        assert_eq!(one.revoked_key_ids, two.revoked_key_ids);
        assert_eq!(one.usable_keys(KEY_USAGE_SIGN).len(), 2);
        assert_eq!(two.usable_keys(KEY_USAGE_SIGN).len(), 2);
    }

    #[test]
    fn a_duplicate_attestation_for_one_key_id_is_refused() {
        let d = make_domain_key("dk1");
        let a = make_signing_key("a");
        let one = attest(&d, &a, "2027-01-01T00:00:00Z");
        let set = verify_application_key_set(
            &[one.clone(), one],
            &[],
            &[domain_public(&d)],
            &instance(),
            now(),
            300,
        );
        assert_eq!(set.keys.len(), 1);
        assert_eq!(set.rejected.len(), 1);
    }

    // --- configuration ---------------------------------------------------

    #[test]
    fn a_revocation_window_shorter_than_a_key_can_live_is_refused() {
        // The default 3-year look-back covers a 1-year key with a 24h
        // attestation comfortably.
        assert!(validate_revocation_window(
            DEFAULT_REVOCATION_WINDOW_SECONDS,
            31_536_000,
            DEFAULT_ATTESTATION_LIFETIME_SECONDS,
            300
        )
        .is_ok());
        // A 30-day look-back against a 1-year key would silently drop a
        // revocation that still decides the answer.
        assert!(matches!(
            validate_revocation_window(
                30 * 86_400,
                31_536_000,
                DEFAULT_ATTESTATION_LIFETIME_SECONDS,
                300
            ),
            Err(ApplicationKeyError::BadConfiguration(_))
        ));
    }

    #[test]
    fn a_sealed_challenge_opens_only_with_the_claimed_private_key() {
        let holder = make_agree_key("x");
        let other = make_agree_key("y");
        let nonce = vec![42u8; 32];
        let pubkey: [u8; 32] = holder.public_key.clone().try_into().unwrap();
        let sealed = seal_challenge(&nonce, &pubkey).unwrap();

        let holder_secret: [u8; 32] = holder.private_key.clone().try_into().unwrap();
        assert_eq!(
            open_challenge(&sealed, &holder_secret).unwrap().as_slice(),
            &nonce[..]
        );

        // The exact attack this closes: enrolling a public key someone else
        // holds. Without the private key the challenge cannot be recovered, so
        // the addition request cannot carry the plaintext the server expects.
        let other_secret: [u8; 32] = other.private_key.clone().try_into().unwrap();
        assert!(open_challenge(&sealed, &other_secret).is_err());
    }

    #[test]
    fn a_corrupted_sealed_challenge_is_refused() {
        let holder = make_agree_key("x");
        let pubkey: [u8; 32] = holder.public_key.clone().try_into().unwrap();
        let secret: [u8; 32] = holder.private_key.clone().try_into().unwrap();
        let mut sealed = seal_challenge(&[1u8; 32], &pubkey).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;
        assert!(open_challenge(&sealed, &secret).is_err());
        assert!(open_challenge(b"not cbor at all", &secret).is_err());
    }

    #[test]
    fn every_tag_in_this_module_is_distinct() {
        let tags = [
            ATTESTATION_TAG,
            ADDITION_TAG,
            POSSESSION_TAG,
            RENEWAL_TAG,
            REVOCATION_TAG,
        ];
        let unique: BTreeSet<&str> = tags.iter().copied().collect();
        assert_eq!(unique.len(), tags.len());
        for t in tags {
            assert!(
                t.starts_with("linkkeys-"),
                "{t} must carry the house prefix"
            );
            assert!(t.ends_with("-v1alpha"), "{t} must carry the epoch suffix");
        }
    }
}
