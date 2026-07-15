//! DNS-less local RP identity: pure protocol helpers.
//!
//! See `dns-less-local-rp-design.md` at the repo root — in particular the
//! "Wire Precision (Normative)" section, which this module implements
//! byte-for-byte. Summary of the shape:
//!
//! - Every signed structure uses the envelope pattern already established by
//!   [`crate::assertions`] / [`crate::auth_request`]: the payload is
//!   CBOR-encoded once, and the signature covers
//!   `CBOR([context: tstr, payload: bstr])` — a two-element CBOR array, never
//!   a bare `context || payload` concatenation (see [`envelope_signature_input`]
//!   and the domain-separation-tag precedent in [`crate::revocation`]).
//! - Four mandatory, structure-specific context strings
//!   ([`CTX_LOCAL_RP_DESCRIPTOR`], [`CTX_LOCAL_RP_LOGIN_REQUEST`],
//!   [`CTX_LOCAL_RP_CALLBACK`], [`CTX_LOCAL_RP_TICKET_REDEMPTION`]) stop a
//!   signature over one structure from ever verifying as another.
//! - The descriptor, login request, and ticket-redemption envelopes verify
//!   against the local RP's own signing key (self-asserted identity, SSH-host
//!   style). The callback payload envelope verifies against DOMAIN public
//!   keys via the existing `check_signing_key_valid`/`resolve_and_verify`
//!   pattern, keyed by `signing_key_id` — a domain holds several signing
//!   keys, so unlike the local-RP-signed envelopes, this one needs a key id.
//! - The callback ciphertext is a variant of the existing sealed-box
//!   construction ([`crate::crypto::sealed_box_encrypt`] /
//!   `sealed_box_decrypt`), extended with negotiated-suite selection and
//!   cleartext-header AAD binding. See [`seal_local_rp_callback`] /
//!   [`open_local_rp_callback`] for the exact KDF/AAD layout.
//!
//! This module performs no I/O: every "current time" is an explicit `now`
//! parameter, never `Utc::now()`, so verification stays deterministic and
//! WASM-viable.

use crate::assertions::{check_signing_key_valid, VerifyError};
use crate::crypto::{self, AeadSuite, CryptoError, SigningAlgorithm};
use crate::generated::types::{
    DomainPublicKey, LocalRpCallbackHeader, LocalRpCallbackPayload, LocalRpDescriptor,
    LocalRpEncryptedCallback, LocalRpLoginRequest, LocalRpTicketRedemptionRequest,
    SignedLocalRpCallbackPayload, SignedLocalRpDescriptor, SignedLocalRpLoginRequest,
    SignedLocalRpTicketRedemptionRequest,
};
use aes_gcm::aead::OsRng;
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use sha2::Sha256;
use std::fmt;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

/// Signature context for [`SignedLocalRpDescriptor`].
pub const CTX_LOCAL_RP_DESCRIPTOR: &str = "linkkeys-local-rp-descriptor";
/// Signature context for [`SignedLocalRpLoginRequest`].
pub const CTX_LOCAL_RP_LOGIN_REQUEST: &str = "linkkeys-local-rp-login-request";
/// Signature context for [`SignedLocalRpCallbackPayload`].
pub const CTX_LOCAL_RP_CALLBACK: &str = "linkkeys-local-rp-callback";
/// Signature context for [`SignedLocalRpTicketRedemptionRequest`].
pub const CTX_LOCAL_RP_TICKET_REDEMPTION: &str = "linkkeys-local-rp-ticket-redemption";

/// Default bounded clock-skew tolerance (seconds) for timestamp checks, per
/// the design doc's "expiry checking helpers with explicit clock-skew
/// tolerance parameter" (default ±300 seconds).
pub const DEFAULT_CLOCK_SKEW_SECONDS: i64 = 300;

/// Domain-separation tag for the local-RP callback sealed box (Wire
/// Precision). Distinct from [`crate::crypto`]'s generic sealed-box tag: this
/// construction additionally binds the negotiated suite id into the KDF
/// context, and binds the cleartext header into the AEAD associated data, so
/// it is its own construction rather than a call-site of the generic one.
const LOCAL_RP_CALLBACK_BOX_TAG: &[u8] = b"linkkeys-local-rp-callback-box";

#[derive(Debug)]
pub enum LocalRpError {
    /// A domain-signature envelope check failed (callback payload path),
    /// reusing the existing [`VerifyError`] taxonomy (key not found, revoked,
    /// expired, unsupported algorithm, bad signature).
    Verify(VerifyError),
    /// A local-RP-signed envelope's signature/crypto operation failed
    /// (descriptor, login request, ticket redemption, callback sealed box).
    Crypto(CryptoError),
    /// CBOR decoding of an embedded payload failed.
    Decode(String),
    /// A raw key/nonce field was not the expected fixed length.
    InvalidKeyLength,
    /// The structure's `fingerprint` field does not equal
    /// `crypto::fingerprint` of the signing public key it is bound to.
    FingerprintMismatch,
    /// A timestamp is further in the future than `now + skew` allows.
    NotYetValid,
    /// A timestamp is further in the past than `now - skew` allows.
    Expired,
    /// A `created_at`/`issued_at`/`expires_at` field could not be parsed as
    /// RFC3339.
    BadTimestamp(String),
    /// Nonce did not match the caller-supplied expected value (pending-login
    /// state, or protocol nonce echoed in a callback).
    NonceMismatch,
    /// State did not match the caller-supplied expected value.
    StateMismatch,
    /// Callback audience (fingerprint) did not match the local RP's own
    /// fingerprint.
    AudienceMismatch,
    /// Callback `user_domain` did not match the domain the login was begun
    /// with.
    IssuerMismatch,
    /// Callback `callback_url` did not match the URL the callback actually
    /// arrived at.
    CallbackUrlMismatch,
    /// The callback header advertises a suite id outside the AEAD suite
    /// registry entirely (not even a recognized id).
    UnsupportedSuite(String),
    /// The callback header advertises a suite id that IS in the registry but
    /// was not in the caller's own advertised/allowed list — decrypting with
    /// it would trust a suite the local RP never offered.
    SuiteNotAdvertised(String),
    /// A field inside the decrypted, signature-verified payload did not match
    /// its cleartext-header twin. The header is already bound as AEAD
    /// associated data (so it cannot be tampered independently of the
    /// ciphertext it accompanies), but callers must still check the
    /// authoritative in-payload copy rather than trusting the header alone.
    HeaderPayloadMismatch(&'static str),
}

impl fmt::Display for LocalRpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LocalRpError::Verify(e) => write!(f, "{}", e),
            LocalRpError::Crypto(e) => write!(f, "{}", e),
            LocalRpError::Decode(msg) => write!(f, "CBOR decode failed: {}", msg),
            LocalRpError::InvalidKeyLength => write!(f, "invalid key or nonce length"),
            LocalRpError::FingerprintMismatch => {
                write!(f, "fingerprint does not match the signing public key")
            }
            LocalRpError::NotYetValid => write!(f, "timestamp is not yet valid"),
            LocalRpError::Expired => write!(f, "timestamp has expired"),
            LocalRpError::BadTimestamp(msg) => write!(f, "invalid timestamp: {}", msg),
            LocalRpError::NonceMismatch => write!(f, "nonce does not match"),
            LocalRpError::StateMismatch => write!(f, "state does not match"),
            LocalRpError::AudienceMismatch => write!(f, "audience fingerprint does not match"),
            LocalRpError::IssuerMismatch => write!(f, "issuing domain does not match"),
            LocalRpError::CallbackUrlMismatch => write!(f, "callback URL does not match"),
            LocalRpError::UnsupportedSuite(id) => write!(f, "unsupported AEAD suite: {}", id),
            LocalRpError::SuiteNotAdvertised(id) => {
                write!(f, "AEAD suite was not advertised/allowed: {}", id)
            }
            LocalRpError::HeaderPayloadMismatch(field) => write!(
                f,
                "callback header does not match signed payload field: {}",
                field
            ),
        }
    }
}

impl std::error::Error for LocalRpError {}

impl From<VerifyError> for LocalRpError {
    fn from(e: VerifyError) -> Self {
        LocalRpError::Verify(e)
    }
}

impl From<CryptoError> for LocalRpError {
    fn from(e: CryptoError) -> Self {
        LocalRpError::Crypto(e)
    }
}

/// The signature input for every new local-RP signed structure:
/// `CBOR([context, payload_bytes])`, a two-element array with the
/// domain-separation context string first and the exact payload bytes second
/// (encoded as a CBOR byte string, never re-serialized). This is the house
/// pattern already used by `revocation_payload` in [`crate::revocation`] and
/// `claim_sign_payload` in [`crate::claims`] — a tuple with the tag first —
/// applied here with exactly two elements per Wire Precision. Deliberately
/// NOT a bare `context || payload` concatenation: CBOR array framing removes
/// any ambiguity between the two fields and needs no canonical
/// re-serialization in any target language.
///
/// `pub` so conformance-vector generation (`examples/generate_conformance_vectors.rs`)
/// and other verification/debugging callers can compute the exact bytes a
/// signature covers without duplicating this construction.
pub fn envelope_signature_input(context: &str, payload_bytes: &[u8]) -> Vec<u8> {
    let tuple = (context, serde_bytes::Bytes::new(payload_bytes));
    let mut out = Vec::new();
    ciborium::ser::into_writer(&tuple, &mut out)
        .expect("CBOR serialization of envelope signature input cannot fail");
    out
}

fn parse_timestamp(s: &str) -> Result<DateTime<Utc>, LocalRpError> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| LocalRpError::BadTimestamp(e.to_string()))
}

/// Check a `(issued_at, expires_at)` pair against `now`, tolerant of
/// `skew_seconds` of clock skew in either direction. Boundaries are
/// inclusive: exactly `now - skew == expires_at` still passes, and exactly
/// one second past either boundary fails.
pub fn check_timestamps(
    issued_at: &str,
    expires_at: &str,
    now: DateTime<Utc>,
    skew_seconds: i64,
) -> Result<(), LocalRpError> {
    let issued = parse_timestamp(issued_at)?;
    let expires = parse_timestamp(expires_at)?;
    let skew = chrono::Duration::seconds(skew_seconds);

    if now + skew < issued {
        return Err(LocalRpError::NotYetValid);
    }
    if now - skew > expires {
        return Err(LocalRpError::Expired);
    }
    Ok(())
}

/// Warning level returned by [`check_expirations`], per the design doc's
/// "Expiration Helper": `notice` at 180 days remaining, `warning` at 90,
/// `critical` at 30, `expired` once `now >= expires_at`. Every SDK mirrors
/// these exact thresholds, which is why the boundaries are exact (inclusive
/// at the threshold) rather than approximate — see `expirations.json` in
/// `sdks/local-rp/conformance/` for boundary vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpirationLevel {
    /// More than 180 days remain until expiry.
    Ok,
    /// 180 days or fewer remain (and more than 90).
    Notice,
    /// 90 days or fewer remain (and more than 30).
    Warning,
    /// 30 days or fewer remain (and expiry has not yet passed).
    Critical,
    /// `now >= expires_at`.
    Expired,
}

impl ExpirationLevel {
    /// Wire-stable lowercase name, matching `expirations.json`'s
    /// `expected_level` values.
    pub fn as_str(&self) -> &'static str {
        match self {
            ExpirationLevel::Ok => "ok",
            ExpirationLevel::Notice => "notice",
            ExpirationLevel::Warning => "warning",
            ExpirationLevel::Critical => "critical",
            ExpirationLevel::Expired => "expired",
        }
    }
}

impl fmt::Display for ExpirationLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Facts about a local RP identity's expiry as of `now`: the exact parsed
/// expiry datetime, `now` itself, and the resulting [`ExpirationLevel`]. Per
/// the design doc, the SDK reports facts; the app decides whether to warn
/// admins, warn users, block login, renew, or ignore.
#[derive(Debug, Clone, PartialEq)]
pub struct ExpirationStatus {
    pub level: ExpirationLevel,
    pub expires_at: DateTime<Utc>,
    pub now: DateTime<Utc>,
}

/// `check_expirations(identity, now) -> ExpirationStatus` from the design
/// doc's "Expiration Helper" and "SDK API Shape" sections. Takes the local RP
/// identity's `expires_at` (RFC3339) directly rather than a full identity
/// struct, since that is the only field this pure check needs — callers pass
/// `descriptor.expires_at` (or the signing/encryption key's own expiry, for
/// SDKs that track them separately).
///
/// This does NOT apply clock-skew tolerance (unlike [`check_timestamps`]):
/// expiry warnings are advisory, multi-day-granularity facts, not a
/// replay/freshness security boundary, so a few seconds of clock drift at a
/// day-scale threshold is immaterial and skew tolerance would only add
/// surprising boundary behavior for no benefit.
pub fn check_expirations(
    expires_at: &str,
    now: DateTime<Utc>,
) -> Result<ExpirationStatus, LocalRpError> {
    let expires = parse_timestamp(expires_at)?;
    let remaining = expires - now;
    let level = if now >= expires {
        ExpirationLevel::Expired
    } else if remaining <= chrono::Duration::days(30) {
        ExpirationLevel::Critical
    } else if remaining <= chrono::Duration::days(90) {
        ExpirationLevel::Warning
    } else if remaining <= chrono::Duration::days(180) {
        ExpirationLevel::Notice
    } else {
        ExpirationLevel::Ok
    };
    Ok(ExpirationStatus {
        level,
        expires_at: expires,
        now,
    })
}

/// Verify a nonce/state pair against the caller-supplied expected values
/// (typically the pending-login state the app persisted from `begin`). Pure
/// equality — replay protection at the app boundary is the caller's job
/// (treat the pending state as single-use); this only checks the values
/// match.
pub fn verify_nonce_state(
    expected_nonce: &[u8],
    expected_state: &[u8],
    actual_nonce: &[u8],
    actual_state: &[u8],
) -> Result<(), LocalRpError> {
    if !constant_time_eq(expected_nonce, actual_nonce) {
        return Err(LocalRpError::NonceMismatch);
    }
    if !constant_time_eq(expected_state, actual_state) {
        return Err(LocalRpError::StateMismatch);
    }
    Ok(())
}

/// Timing-safe byte equality (security review). A length mismatch is an
/// immediate non-match (lengths are not secret); equal-length contents are
/// compared in constant time so comparison latency doesn't leak how much of
/// a nonce/state prefix an attacker guessed correctly.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && a.ct_eq(b).into()
}

/// Verify the callback's audience (fingerprint) equals the local RP's own
/// fingerprint.
pub fn verify_audience(
    payload_audience_fingerprint: &str,
    local_rp_fingerprint: &str,
) -> Result<(), LocalRpError> {
    if payload_audience_fingerprint != local_rp_fingerprint {
        return Err(LocalRpError::AudienceMismatch);
    }
    Ok(())
}

/// Verify issuer binding: the callback payload's `user_domain` must equal the
/// domain the login was begun with (from the caller's pending-login state),
/// not merely whichever domain's keys happened to verify the signature.
pub fn verify_issuer(payload_user_domain: &str, expected_domain: &str) -> Result<(), LocalRpError> {
    if payload_user_domain != expected_domain {
        return Err(LocalRpError::IssuerMismatch);
    }
    Ok(())
}

/// Verify the callback payload's `callback_url` equals the URL the callback
/// actually arrived at (not merely the URL originally requested — a
/// redirect or proxy rewrite must not be trusted silently).
pub fn verify_callback_url(
    payload_callback_url: &str,
    arrived_url: &str,
) -> Result<(), LocalRpError> {
    if payload_callback_url != arrived_url {
        return Err(LocalRpError::CallbackUrlMismatch);
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Descriptor
// ---------------------------------------------------------------------

/// Build an unsigned [`LocalRpDescriptor`]. `fingerprint` is always derived
/// from `signing_public_key` via [`crate::crypto::fingerprint`] — callers
/// cannot set it directly, so it can never drift from the key it names.
#[allow(clippy::too_many_arguments)]
pub fn build_local_rp_descriptor(
    app_name: &str,
    local_domain_hint: Option<&str>,
    signing_public_key: &[u8; 32],
    encryption_public_key: &[u8; 32],
    supported_suites: Vec<String>,
    created_at: &str,
    expires_at: &str,
) -> LocalRpDescriptor {
    LocalRpDescriptor {
        app_name: app_name.to_string(),
        local_domain_hint: local_domain_hint.map(|s| s.to_string()),
        signing_public_key: signing_public_key.to_vec(),
        encryption_public_key: encryption_public_key.to_vec(),
        fingerprint: crypto::fingerprint(signing_public_key),
        supported_suites,
        created_at: created_at.to_string(),
        expires_at: expires_at.to_string(),
    }
}

/// Sign a [`LocalRpDescriptor`] with the local RP's own signing key. The
/// descriptor is CBOR-encoded once; those exact bytes become the `descriptor`
/// field of the envelope, and the signature covers
/// `CBOR([`[`CTX_LOCAL_RP_DESCRIPTOR`]`, descriptor_bytes])`.
pub fn sign_local_rp_descriptor(
    descriptor: &LocalRpDescriptor,
    private_key_bytes: &[u8],
) -> Result<SignedLocalRpDescriptor, CryptoError> {
    let descriptor_bytes = crate::generated::encode_local_rp_descriptor(descriptor);
    let signature_input = envelope_signature_input(CTX_LOCAL_RP_DESCRIPTOR, &descriptor_bytes);
    let signature = crypto::sign_with_algorithm(
        SigningAlgorithm::Ed25519,
        &signature_input,
        private_key_bytes,
    )?;
    Ok(SignedLocalRpDescriptor {
        descriptor: descriptor_bytes,
        signature,
    })
}

/// Verify a signed local RP descriptor: decode it, check its `fingerprint`
/// field truly is `crypto::fingerprint(signing_public_key)`, verify the
/// envelope signature against ITS OWN embedded signing key (a local RP
/// descriptor is self-asserted identity, SSH-host style — there is no
/// external key list to consult), and check `created_at`/`expires_at` bounds.
///
/// Decoding necessarily happens before signature verification here (unlike
/// [`crate::assertions::verify_assertion`], which looks up an externally
/// supplied key first): the verifying key is only discoverable by decoding
/// the very structure it signed.
pub fn verify_local_rp_descriptor(
    signed: &SignedLocalRpDescriptor,
    now: DateTime<Utc>,
    skew_seconds: i64,
) -> Result<LocalRpDescriptor, LocalRpError> {
    let descriptor = crate::generated::decode_local_rp_descriptor(&signed.descriptor)
        .map_err(|e| LocalRpError::Decode(e.to_string()))?;

    if descriptor.signing_public_key.len() != 32 {
        return Err(LocalRpError::InvalidKeyLength);
    }
    // Defense in depth: the encryption key is only ever consumed later, as a
    // `[u8; 32]` via `try_into` (e.g. `finalize_local_rp_login`'s
    // `enc_pk: [u8; 32] = descriptor.encryption_public_key...try_into()`), so
    // a malformed length would previously surface as a generic conversion
    // failure far from verification. Reject it here instead, at the single
    // point every descriptor is required to pass through, mirroring the
    // signing-key check immediately above.
    if descriptor.encryption_public_key.len() != 32 {
        return Err(LocalRpError::InvalidKeyLength);
    }

    let expected_fingerprint = crypto::fingerprint(&descriptor.signing_public_key);
    if descriptor.fingerprint != expected_fingerprint {
        return Err(LocalRpError::FingerprintMismatch);
    }

    let signature_input = envelope_signature_input(CTX_LOCAL_RP_DESCRIPTOR, &signed.descriptor);
    crypto::verify_with_algorithm(
        SigningAlgorithm::Ed25519,
        &signature_input,
        &signed.signature,
        &descriptor.signing_public_key,
    )?;

    check_timestamps(
        &descriptor.created_at,
        &descriptor.expires_at,
        now,
        skew_seconds,
    )?;

    Ok(descriptor)
}

// ---------------------------------------------------------------------
// Login request
// ---------------------------------------------------------------------

/// Build an unsigned [`LocalRpLoginRequest`] around an already-signed
/// descriptor.
#[allow(clippy::too_many_arguments)]
pub fn build_local_rp_login_request(
    descriptor: SignedLocalRpDescriptor,
    callback_url: &str,
    nonce: Vec<u8>,
    state: Vec<u8>,
    requested_claims: Vec<String>,
    required_claims: Vec<String>,
    issued_at: &str,
    expires_at: &str,
) -> LocalRpLoginRequest {
    LocalRpLoginRequest {
        descriptor,
        callback_url: callback_url.to_string(),
        nonce,
        state,
        requested_claims,
        required_claims,
        issued_at: issued_at.to_string(),
        expires_at: expires_at.to_string(),
    }
}

/// Sign a [`LocalRpLoginRequest`] with the local RP's signing key (the same
/// key embedded in the request's own descriptor).
pub fn sign_local_rp_login_request(
    request: &LocalRpLoginRequest,
    private_key_bytes: &[u8],
) -> Result<SignedLocalRpLoginRequest, CryptoError> {
    let request_bytes = crate::generated::encode_local_rp_login_request(request);
    let signature_input = envelope_signature_input(CTX_LOCAL_RP_LOGIN_REQUEST, &request_bytes);
    let signature = crypto::sign_with_algorithm(
        SigningAlgorithm::Ed25519,
        &signature_input,
        private_key_bytes,
    )?;
    Ok(SignedLocalRpLoginRequest {
        request: request_bytes,
        signature,
    })
}

/// Verify a signed local RP login request end to end: decode it, fully
/// verify the nested descriptor (envelope signature, fingerprint binding,
/// timestamp bounds — see [`verify_local_rp_descriptor`]), then verify the
/// outer envelope signature against the descriptor's signing key, then check
/// the request's own `issued_at`/`expires_at` bounds.
pub fn verify_local_rp_login_request(
    signed: &SignedLocalRpLoginRequest,
    now: DateTime<Utc>,
    skew_seconds: i64,
) -> Result<LocalRpLoginRequest, LocalRpError> {
    let request = crate::generated::decode_local_rp_login_request(&signed.request)
        .map_err(|e| LocalRpError::Decode(e.to_string()))?;

    let descriptor = verify_local_rp_descriptor(&request.descriptor, now, skew_seconds)?;

    let signature_input = envelope_signature_input(CTX_LOCAL_RP_LOGIN_REQUEST, &signed.request);
    crypto::verify_with_algorithm(
        SigningAlgorithm::Ed25519,
        &signature_input,
        &signed.signature,
        &descriptor.signing_public_key,
    )?;

    check_timestamps(&request.issued_at, &request.expires_at, now, skew_seconds)?;

    Ok(request)
}

// ---------------------------------------------------------------------
// Ticket redemption
// ---------------------------------------------------------------------

/// Build an unsigned [`LocalRpTicketRedemptionRequest`].
pub fn build_local_rp_ticket_redemption_request(
    claim_ticket: Vec<u8>,
    fingerprint: &str,
    issued_at: &str,
) -> LocalRpTicketRedemptionRequest {
    LocalRpTicketRedemptionRequest {
        claim_ticket,
        fingerprint: fingerprint.to_string(),
        issued_at: issued_at.to_string(),
    }
}

/// Sign a [`LocalRpTicketRedemptionRequest`] with the local RP's signing key,
/// so a stolen ticket is useless without the matching private key.
pub fn sign_local_rp_ticket_redemption_request(
    request: &LocalRpTicketRedemptionRequest,
    private_key_bytes: &[u8],
) -> Result<SignedLocalRpTicketRedemptionRequest, CryptoError> {
    let request_bytes = crate::generated::encode_local_rp_ticket_redemption_request(request);
    let signature_input = envelope_signature_input(CTX_LOCAL_RP_TICKET_REDEMPTION, &request_bytes);
    let signature = crypto::sign_with_algorithm(
        SigningAlgorithm::Ed25519,
        &signature_input,
        private_key_bytes,
    )?;
    Ok(SignedLocalRpTicketRedemptionRequest {
        request: request_bytes,
        signature,
    })
}

/// Verify a ticket-redemption request's possession proof: `signing_public_key`
/// is the key the caller resolved for `expected_fingerprint` (e.g. from
/// approved local-RP storage) — the signature must verify against it, AND
/// that key's own fingerprint plus the request's embedded `fingerprint` field
/// must both equal `expected_fingerprint`, so a request cannot ride in on a
/// signature from an unrelated key or claim a fingerprint it does not own.
///
/// This does not check ticket expiry/multi-use/RP-revocation — those require
/// server-side ticket and approval state and belong to the server crate.
pub fn verify_local_rp_ticket_redemption_request(
    signed: &SignedLocalRpTicketRedemptionRequest,
    signing_public_key: &[u8],
    expected_fingerprint: &str,
) -> Result<LocalRpTicketRedemptionRequest, LocalRpError> {
    let signature_input = envelope_signature_input(CTX_LOCAL_RP_TICKET_REDEMPTION, &signed.request);
    crypto::verify_with_algorithm(
        SigningAlgorithm::Ed25519,
        &signature_input,
        &signed.signature,
        signing_public_key,
    )?;

    let request = crate::generated::decode_local_rp_ticket_redemption_request(&signed.request)
        .map_err(|e| LocalRpError::Decode(e.to_string()))?;

    let key_fingerprint = crypto::fingerprint(signing_public_key);
    if key_fingerprint != expected_fingerprint || request.fingerprint != expected_fingerprint {
        return Err(LocalRpError::FingerprintMismatch);
    }

    Ok(request)
}

// ---------------------------------------------------------------------
// Callback payload (domain-signed envelope)
// ---------------------------------------------------------------------

/// Build an unsigned [`LocalRpCallbackPayload`].
#[allow(clippy::too_many_arguments)]
pub fn build_local_rp_callback_payload(
    user_id: &str,
    user_domain: &str,
    claim_ticket: Vec<u8>,
    audience_fingerprint: &str,
    callback_url: &str,
    nonce: Vec<u8>,
    state: Vec<u8>,
    issued_at: &str,
    expires_at: &str,
) -> LocalRpCallbackPayload {
    LocalRpCallbackPayload {
        user_id: user_id.to_string(),
        user_domain: user_domain.to_string(),
        claim_ticket,
        audience_fingerprint: audience_fingerprint.to_string(),
        callback_url: callback_url.to_string(),
        nonce,
        state,
        issued_at: issued_at.to_string(),
        expires_at: expires_at.to_string(),
    }
}

/// Sign a [`LocalRpCallbackPayload`] with one of the issuing domain's signing
/// keys (`key_id` identifies which one, like [`crate::assertions`]'s
/// `SignedIdentityAssertion` — a domain holds several signing keys).
pub fn sign_local_rp_callback_payload(
    payload: &LocalRpCallbackPayload,
    key_id: &str,
    algorithm: SigningAlgorithm,
    private_key_bytes: &[u8],
) -> Result<SignedLocalRpCallbackPayload, CryptoError> {
    let payload_bytes = crate::generated::encode_local_rp_callback_payload(payload);
    let signature_input = envelope_signature_input(CTX_LOCAL_RP_CALLBACK, &payload_bytes);
    let signature = crypto::sign_with_algorithm(algorithm, &signature_input, private_key_bytes)?;
    Ok(SignedLocalRpCallbackPayload {
        payload: payload_bytes,
        signing_key_id: key_id.to_string(),
        signature,
    })
}

/// Verify a domain-signed callback payload envelope against a set of domain
/// public keys, following the existing
/// `check_signing_key_valid`/`resolve_and_verify` pattern used by
/// [`crate::assertions::verify_assertion`]: resolve `signing_key_id`, reject
/// a revoked/expired/non-signing key, verify the envelope signature, decode,
/// then check `issued_at`/`expires_at` bounds.
pub fn verify_local_rp_callback_payload(
    signed: &SignedLocalRpCallbackPayload,
    domain_public_keys: &[DomainPublicKey],
    now: DateTime<Utc>,
    skew_seconds: i64,
) -> Result<LocalRpCallbackPayload, LocalRpError> {
    let key = domain_public_keys
        .iter()
        .find(|k| k.key_id == signed.signing_key_id)
        .ok_or_else(|| VerifyError::KeyNotFound(signed.signing_key_id.clone()))?;

    check_signing_key_valid(key)?;

    let signature_input = envelope_signature_input(CTX_LOCAL_RP_CALLBACK, &signed.payload);
    crypto::resolve_and_verify(
        &key.algorithm,
        &signature_input,
        &signed.signature,
        &key.public_key,
    )
    .map_err(|e| match e {
        CryptoError::UnsupportedAlgorithm(alg) => {
            LocalRpError::Verify(VerifyError::UnsupportedAlgorithm(alg))
        }
        _ => LocalRpError::Verify(VerifyError::SignatureInvalid),
    })?;

    let payload = crate::generated::decode_local_rp_callback_payload(&signed.payload)
        .map_err(|e| LocalRpError::Decode(e.to_string()))?;

    check_timestamps(&payload.issued_at, &payload.expires_at, now, skew_seconds)?;

    Ok(payload)
}

/// Cross-check the cleartext callback header's routing fields against the
/// authoritative copies inside the decrypted, domain-signature-verified
/// payload. The header is already bound as AEAD associated data (so it
/// cannot be tampered independently of the ciphertext it accompanies), but a
/// verifier must still consult the signed copies rather than trusting the
/// header on its own — this makes that check explicit and mandatory to call.
pub fn check_callback_header_matches_payload(
    header: &LocalRpCallbackHeader,
    payload: &LocalRpCallbackPayload,
) -> Result<(), LocalRpError> {
    if header.fingerprint != payload.audience_fingerprint {
        return Err(LocalRpError::HeaderPayloadMismatch("fingerprint"));
    }
    if header.nonce != payload.nonce {
        return Err(LocalRpError::HeaderPayloadMismatch("nonce"));
    }
    if header.state != payload.state {
        return Err(LocalRpError::HeaderPayloadMismatch("state"));
    }
    if header.issued_at != payload.issued_at {
        return Err(LocalRpError::HeaderPayloadMismatch("issued_at"));
    }
    if header.expires_at != payload.expires_at {
        return Err(LocalRpError::HeaderPayloadMismatch("expires_at"));
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Callback sealed box (Wire Precision: "Callback sealed box")
// ---------------------------------------------------------------------

/// Derive the AEAD key and construct the KDF `info`/AAD-prefix context for
/// the local-RP callback sealed box:
/// `tag || suite_id_utf8 || ephemeral_public(32) || recipient_public(32)`,
/// raw concatenation, matching `crate::crypto`'s `sealed_box_kdf` layout with
/// the suite id inserted after the tag. HKDF-SHA256 with no salt, expanded to
/// 32 bytes.
fn local_rp_callback_kdf(
    suite: AeadSuite,
    ephemeral_public: &[u8; 32],
    recipient_public: &[u8; 32],
    shared_secret: &[u8],
) -> Result<([u8; 32], Vec<u8>), CryptoError> {
    let suite_id = suite.as_str().as_bytes();
    let mut context = Vec::with_capacity(LOCAL_RP_CALLBACK_BOX_TAG.len() + suite_id.len() + 64);
    context.extend_from_slice(LOCAL_RP_CALLBACK_BOX_TAG);
    context.extend_from_slice(suite_id);
    context.extend_from_slice(ephemeral_public);
    context.extend_from_slice(recipient_public);

    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hk.expand(&context, &mut key)
        .map_err(|_| CryptoError::EncryptionFailed("HKDF expand failed".to_string()))?;
    Ok((key, context))
}

// AEAD dispatch (encrypt/decrypt per suite) lives in `crate::crypto`
// (`aead_encrypt`/`aead_decrypt`), shared with the generic sealed box in
// `crypto::sealed_box_encrypt`/`sealed_box_decrypt` — one dispatch point per
// direction for every negotiated-suite AEAD use in this crate.

/// Seal a [`SignedLocalRpCallbackPayload`] (the exact bytes to encrypt — the
/// domain-signed envelope, per Wire Precision) into a
/// [`LocalRpEncryptedCallback`] for `recipient_encryption_public_key`, using
/// `suite`.
///
/// Steps (Wire Precision, "Callback sealed box"):
/// 1. Generate an ephemeral X25519 keypair; ECDH with the recipient key;
///    reject an all-zero (low-order) shared secret.
/// 2. Build the header (which contains the ephemeral public key and AEAD
///    nonce — both exist before encryption) and encode it to its exact CBOR
///    bytes.
/// 3. Derive the AEAD key via HKDF-SHA256 over the shared secret
///    ([`local_rp_callback_kdf`]).
/// 4. Encrypt with the negotiated suite, random 12-byte nonce.
/// 5. AAD = kdf context || header bytes, so the header cannot be swapped
///    without invalidating the ciphertext.
#[allow(clippy::too_many_arguments)]
pub fn seal_local_rp_callback(
    signed_payload: &SignedLocalRpCallbackPayload,
    suite: AeadSuite,
    recipient_encryption_public_key: &[u8; 32],
    fingerprint: &str,
    nonce: Vec<u8>,
    state: Vec<u8>,
    issued_at: &str,
    expires_at: &str,
) -> Result<LocalRpEncryptedCallback, LocalRpError> {
    let ephemeral_secret = X25519StaticSecret::random_from_rng(OsRng);
    let aead_nonce: [u8; 12] = rand::random();
    seal_local_rp_callback_inner(
        signed_payload,
        suite,
        recipient_encryption_public_key,
        fingerprint,
        nonce,
        state,
        issued_at,
        expires_at,
        ephemeral_secret,
        aead_nonce,
    )
}

/// Deterministic variant of [`seal_local_rp_callback`]: the caller supplies
/// the ephemeral X25519 private key and AEAD nonce instead of sourcing them
/// from the OS RNG.
///
/// Production code must always use [`seal_local_rp_callback`] — real
/// ephemeral keys and nonces must be unpredictable. This variant exists
/// solely so conformance-vector generation
/// (`examples/generate_conformance_vectors.rs`) can produce byte-identical
/// ciphertexts on every regeneration, per the design doc's Phase 8
/// requirement that "randomness" inputs be injected as fixed constants for
/// checked-in vectors.
#[allow(clippy::too_many_arguments)]
pub fn seal_local_rp_callback_with_randomness(
    signed_payload: &SignedLocalRpCallbackPayload,
    suite: AeadSuite,
    recipient_encryption_public_key: &[u8; 32],
    fingerprint: &str,
    nonce: Vec<u8>,
    state: Vec<u8>,
    issued_at: &str,
    expires_at: &str,
    ephemeral_private_key: &[u8; 32],
    aead_nonce: &[u8; 12],
) -> Result<LocalRpEncryptedCallback, LocalRpError> {
    let ephemeral_secret = X25519StaticSecret::from(*ephemeral_private_key);
    seal_local_rp_callback_inner(
        signed_payload,
        suite,
        recipient_encryption_public_key,
        fingerprint,
        nonce,
        state,
        issued_at,
        expires_at,
        ephemeral_secret,
        *aead_nonce,
    )
}

/// Shared core of [`seal_local_rp_callback`] and
/// [`seal_local_rp_callback_with_randomness`]: everything except where the
/// ephemeral secret and AEAD nonce come from.
#[allow(clippy::too_many_arguments)]
fn seal_local_rp_callback_inner(
    signed_payload: &SignedLocalRpCallbackPayload,
    suite: AeadSuite,
    recipient_encryption_public_key: &[u8; 32],
    fingerprint: &str,
    nonce: Vec<u8>,
    state: Vec<u8>,
    issued_at: &str,
    expires_at: &str,
    ephemeral_secret: X25519StaticSecret,
    aead_nonce: [u8; 12],
) -> Result<LocalRpEncryptedCallback, LocalRpError> {
    let plaintext = crate::generated::encode_signed_local_rp_callback_payload(signed_payload);

    let recipient_pk = X25519PublicKey::from(*recipient_encryption_public_key);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pk);
    crypto::reject_low_order(shared_secret.as_bytes())?;

    let header = LocalRpCallbackHeader {
        fingerprint: fingerprint.to_string(),
        nonce,
        state,
        suite: suite.as_str().to_string(),
        ephemeral_public_key: ephemeral_public.as_bytes().to_vec(),
        aead_nonce: aead_nonce.to_vec(),
        issued_at: issued_at.to_string(),
        expires_at: expires_at.to_string(),
    };
    let header_bytes = crate::generated::encode_local_rp_callback_header(&header);

    let (aead_key, kdf_context) = local_rp_callback_kdf(
        suite,
        ephemeral_public.as_bytes(),
        recipient_encryption_public_key,
        shared_secret.as_bytes(),
    )?;

    let mut aad = kdf_context;
    aad.extend_from_slice(&header_bytes);

    let ciphertext = crypto::aead_encrypt(suite, &aead_key, &aead_nonce, &aad, &plaintext)?;

    Ok(LocalRpEncryptedCallback {
        header: header_bytes,
        ciphertext,
    })
}

/// Open a [`LocalRpEncryptedCallback`] with the local RP's encryption private
/// key. `allowed_suites` is the local RP's own supported-suite list (from its
/// descriptor): a header advertising a suite NOT in that list is rejected
/// even if it is otherwise a valid registry id, per Wire Precision ("The SDK
/// must decrypt only with a suite listed in its own descriptor").
///
/// Returns the decoded header (cleartext routing metadata) and the still-
/// domain-signature-unverified [`SignedLocalRpCallbackPayload`] — callers
/// must still call [`verify_local_rp_callback_payload`] against fetched
/// domain keys, and then [`check_callback_header_matches_payload`], before
/// trusting the result.
pub fn open_local_rp_callback(
    encrypted: &LocalRpEncryptedCallback,
    recipient_encryption_private_key: &[u8; 32],
    allowed_suites: &[AeadSuite],
) -> Result<(LocalRpCallbackHeader, SignedLocalRpCallbackPayload), LocalRpError> {
    let header = crate::generated::decode_local_rp_callback_header(&encrypted.header)
        .map_err(|e| LocalRpError::Decode(e.to_string()))?;

    let suite = AeadSuite::parse_str(&header.suite)
        .ok_or_else(|| LocalRpError::UnsupportedSuite(header.suite.clone()))?;
    if !allowed_suites.contains(&suite) {
        return Err(LocalRpError::SuiteNotAdvertised(header.suite.clone()));
    }

    let ephemeral_pk_bytes: [u8; 32] = header
        .ephemeral_public_key
        .as_slice()
        .try_into()
        .map_err(|_| LocalRpError::InvalidKeyLength)?;
    let ephemeral_pk = X25519PublicKey::from(ephemeral_pk_bytes);

    let aead_nonce: [u8; 12] = header
        .aead_nonce
        .as_slice()
        .try_into()
        .map_err(|_| LocalRpError::InvalidKeyLength)?;

    let recipient_secret = X25519StaticSecret::from(*recipient_encryption_private_key);
    let recipient_public = X25519PublicKey::from(&recipient_secret);

    let shared_secret = recipient_secret.diffie_hellman(&ephemeral_pk);
    crypto::reject_low_order(shared_secret.as_bytes())?;

    let (aead_key, kdf_context) = local_rp_callback_kdf(
        suite,
        &ephemeral_pk_bytes,
        recipient_public.as_bytes(),
        shared_secret.as_bytes(),
    )?;

    let mut aad = kdf_context;
    aad.extend_from_slice(&encrypted.header);

    let plaintext =
        crypto::aead_decrypt(suite, &aead_key, &aead_nonce, &aad, &encrypted.ciphertext)?;

    let signed_payload = crate::generated::decode_signed_local_rp_callback_payload(&plaintext)
        .map_err(|e| LocalRpError::Decode(e.to_string()))?;

    Ok((header, signed_payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{fingerprint, generate_ed25519_keypair, generate_x25519_keypair};
    use chrono::Duration;

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    fn rfc3339(dt: DateTime<Utc>) -> String {
        dt.to_rfc3339()
    }

    fn make_domain_key(key_id: &str, pk_bytes: &[u8]) -> DomainPublicKey {
        DomainPublicKey {
            key_id: key_id.to_string(),
            public_key: pk_bytes.to_vec(),
            fingerprint: fingerprint(pk_bytes),
            algorithm: "ed25519".to_string(),
            key_usage: "sign".to_string(),
            signed_by_key_id: None,
            key_signature: None,
            created_at: Utc::now().to_rfc3339(),
            expires_at: (Utc::now() + Duration::hours(1)).to_rfc3339(),
            revoked_at: None,
        }
    }

    fn make_descriptor_signed(
        signing_pk: &[u8],
        signing_sk: &[u8],
        enc_pk: &[u8],
        suites: Vec<String>,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> SignedLocalRpDescriptor {
        let signing_pk_arr: [u8; 32] = signing_pk.try_into().unwrap();
        let enc_pk_arr: [u8; 32] = enc_pk.try_into().unwrap();
        let descriptor = build_local_rp_descriptor(
            "Test App",
            None,
            &signing_pk_arr,
            &enc_pk_arr,
            suites,
            &rfc3339(created_at),
            &rfc3339(expires_at),
        );
        sign_local_rp_descriptor(&descriptor, signing_sk).unwrap()
    }

    fn make_callback_signed_payload(
        domain_sk: &[u8],
        key_id: &str,
        n: DateTime<Utc>,
        audience_fp: &str,
    ) -> SignedLocalRpCallbackPayload {
        let payload = build_local_rp_callback_payload(
            "user-1",
            "example.com",
            vec![7u8; 32],
            audience_fp,
            "http://localhost/callback",
            b"nonce".to_vec(),
            b"state".to_vec(),
            &rfc3339(n),
            &rfc3339(n + Duration::minutes(5)),
        );
        sign_local_rp_callback_payload(&payload, key_id, SigningAlgorithm::Ed25519, domain_sk)
            .unwrap()
    }

    // -----------------------------------------------------------------
    // Context / domain-separation
    // -----------------------------------------------------------------

    #[test]
    fn context_binding_wrong_context_fails_against_every_other_structure() {
        let (pk, sk) = generate_ed25519_keypair();
        let payload = b"some payload bytes".to_vec();
        let sig_input = envelope_signature_input(CTX_LOCAL_RP_DESCRIPTOR, &payload);
        let signature =
            crypto::sign_with_algorithm(SigningAlgorithm::Ed25519, &sig_input, &sk.to_bytes())
                .unwrap();

        for wrong_ctx in [
            CTX_LOCAL_RP_LOGIN_REQUEST,
            CTX_LOCAL_RP_CALLBACK,
            CTX_LOCAL_RP_TICKET_REDEMPTION,
        ] {
            let wrong_input = envelope_signature_input(wrong_ctx, &payload);
            assert!(crypto::verify_with_algorithm(
                SigningAlgorithm::Ed25519,
                &wrong_input,
                &signature,
                pk.as_bytes()
            )
            .is_err());
        }

        // Sanity: the correct context still verifies.
        assert!(crypto::verify_with_algorithm(
            SigningAlgorithm::Ed25519,
            &sig_input,
            &signature,
            pk.as_bytes()
        )
        .is_ok());
    }

    // -----------------------------------------------------------------
    // check_timestamps
    // -----------------------------------------------------------------

    #[test]
    fn check_timestamps_skew_boundaries_are_exact() {
        let n = now();
        let skew = DEFAULT_CLOCK_SKEW_SECONDS;
        let issued = rfc3339(n - Duration::minutes(10));
        let far_expires = rfc3339(n + Duration::days(1));

        // Expired exactly at the skew boundary: allowed.
        let expires_at_boundary = rfc3339(n - Duration::seconds(skew));
        assert!(check_timestamps(&issued, &expires_at_boundary, n, skew).is_ok());

        // One second past the boundary: rejected.
        let expires_at_past = rfc3339(n - Duration::seconds(skew + 1));
        assert!(matches!(
            check_timestamps(&issued, &expires_at_past, n, skew),
            Err(LocalRpError::Expired)
        ));

        // Not-yet-valid exactly at the boundary: allowed.
        let issued_at_boundary = rfc3339(n + Duration::seconds(skew));
        assert!(check_timestamps(&issued_at_boundary, &far_expires, n, skew).is_ok());

        // One second past the not-yet-valid boundary: rejected.
        let issued_at_future = rfc3339(n + Duration::seconds(skew + 1));
        assert!(matches!(
            check_timestamps(&issued_at_future, &far_expires, n, skew),
            Err(LocalRpError::NotYetValid)
        ));
    }

    #[test]
    fn check_timestamps_bad_rfc3339_fails() {
        let n = now();
        assert!(matches!(
            check_timestamps("not-a-timestamp", &rfc3339(n), n, 300),
            Err(LocalRpError::BadTimestamp(_))
        ));
    }

    // -----------------------------------------------------------------
    // check_expirations
    // -----------------------------------------------------------------

    #[test]
    fn check_expirations_thresholds_are_exact() {
        let expires = now();

        let cases: &[(chrono::Duration, ExpirationLevel)] = &[
            (Duration::days(181), ExpirationLevel::Ok),
            (Duration::days(180), ExpirationLevel::Notice),
            (Duration::days(179), ExpirationLevel::Notice),
            (Duration::days(91), ExpirationLevel::Notice),
            (Duration::days(90), ExpirationLevel::Warning),
            (Duration::days(89), ExpirationLevel::Warning),
            (Duration::days(31), ExpirationLevel::Warning),
            (Duration::days(30), ExpirationLevel::Critical),
            (Duration::seconds(1), ExpirationLevel::Critical),
            (Duration::seconds(0), ExpirationLevel::Expired),
            (Duration::seconds(-1), ExpirationLevel::Expired),
        ];

        for (remaining, expected) in cases {
            let n = expires - *remaining;
            let status = check_expirations(&rfc3339(expires), n).unwrap();
            assert_eq!(
                status.level, *expected,
                "remaining={remaining:?} now={n} expires={expires}"
            );
            assert_eq!(status.expires_at, expires);
            assert_eq!(status.now, n);
        }
    }

    #[test]
    fn check_expirations_bad_rfc3339_fails() {
        assert!(matches!(
            check_expirations("not-a-timestamp", now()),
            Err(LocalRpError::BadTimestamp(_))
        ));
    }

    // -----------------------------------------------------------------
    // Descriptor
    // -----------------------------------------------------------------

    #[test]
    fn descriptor_sign_verify_roundtrip() {
        let (pk, sk) = generate_ed25519_keypair();
        let (enc_pk, _enc_sk) = generate_x25519_keypair();
        let n = now();
        let signed = make_descriptor_signed(
            pk.as_bytes(),
            &sk.to_bytes(),
            &enc_pk,
            vec!["aes-256-gcm".to_string()],
            n - Duration::minutes(1),
            n + Duration::days(3650),
        );
        let verified = verify_local_rp_descriptor(&signed, n, DEFAULT_CLOCK_SKEW_SECONDS).unwrap();
        assert_eq!(verified.app_name, "Test App");
        assert_eq!(verified.fingerprint, fingerprint(pk.as_bytes()));
    }

    #[test]
    fn fingerprint_matches_crypto_fingerprint_exactly() {
        let (pk, sk) = generate_ed25519_keypair();
        let (enc_pk, _) = generate_x25519_keypair();
        let n = now();
        let signed = make_descriptor_signed(
            pk.as_bytes(),
            &sk.to_bytes(),
            &enc_pk,
            vec!["aes-256-gcm".to_string()],
            n - Duration::minutes(1),
            n + Duration::days(3650),
        );
        let descriptor = crate::generated::decode_local_rp_descriptor(&signed.descriptor).unwrap();
        assert_eq!(descriptor.fingerprint, fingerprint(pk.as_bytes()));
        assert_eq!(descriptor.fingerprint.len(), 64);
    }

    #[test]
    fn descriptor_tampered_signature_fails() {
        let (pk, sk) = generate_ed25519_keypair();
        let (enc_pk, _) = generate_x25519_keypair();
        let n = now();
        let mut signed = make_descriptor_signed(
            pk.as_bytes(),
            &sk.to_bytes(),
            &enc_pk,
            vec!["aes-256-gcm".to_string()],
            n - Duration::minutes(1),
            n + Duration::days(3650),
        );
        if let Some(b) = signed.signature.first_mut() {
            *b ^= 0xff;
        }
        assert!(verify_local_rp_descriptor(&signed, n, DEFAULT_CLOCK_SKEW_SECONDS).is_err());
    }

    #[test]
    fn descriptor_tampered_payload_fails() {
        let (pk, sk) = generate_ed25519_keypair();
        let (enc_pk, _) = generate_x25519_keypair();
        let n = now();
        let mut signed = make_descriptor_signed(
            pk.as_bytes(),
            &sk.to_bytes(),
            &enc_pk,
            vec!["aes-256-gcm".to_string()],
            n - Duration::minutes(1),
            n + Duration::days(3650),
        );
        if let Some(b) = signed.descriptor.last_mut() {
            *b ^= 0xff;
        }
        assert!(verify_local_rp_descriptor(&signed, n, DEFAULT_CLOCK_SKEW_SECONDS).is_err());
    }

    #[test]
    fn descriptor_encryption_key_is_bound_by_signature() {
        let (pk, sk) = generate_ed25519_keypair();
        let (enc_pk, _) = generate_x25519_keypair();
        let (other_enc_pk, _) = generate_x25519_keypair();
        let n = now();
        let mut signed = make_descriptor_signed(
            pk.as_bytes(),
            &sk.to_bytes(),
            &enc_pk,
            vec!["aes-256-gcm".to_string()],
            n - Duration::minutes(1),
            n + Duration::days(3650),
        );

        // Swap in a re-encoded descriptor with a DIFFERENT encryption key but
        // keep the ORIGINAL signature: the signature no longer matches these
        // bytes, proving the encryption key is bound by the descriptor
        // signature rather than free-floating alongside it.
        let mut descriptor =
            crate::generated::decode_local_rp_descriptor(&signed.descriptor).unwrap();
        descriptor.encryption_public_key = other_enc_pk;
        signed.descriptor = crate::generated::encode_local_rp_descriptor(&descriptor);

        assert!(verify_local_rp_descriptor(&signed, n, DEFAULT_CLOCK_SKEW_SECONDS).is_err());
    }

    #[test]
    fn descriptor_expired_rejected() {
        let (pk, sk) = generate_ed25519_keypair();
        let (enc_pk, _) = generate_x25519_keypair();
        let n = now();
        let signed = make_descriptor_signed(
            pk.as_bytes(),
            &sk.to_bytes(),
            &enc_pk,
            vec!["aes-256-gcm".to_string()],
            n - Duration::days(400),
            n - Duration::seconds(DEFAULT_CLOCK_SKEW_SECONDS + 1),
        );
        assert!(matches!(
            verify_local_rp_descriptor(&signed, n, DEFAULT_CLOCK_SKEW_SECONDS),
            Err(LocalRpError::Expired)
        ));
    }

    #[test]
    fn descriptor_fingerprint_mismatch_rejected() {
        let (pk, sk) = generate_ed25519_keypair();
        let (enc_pk, _) = generate_x25519_keypair();
        let n = now();
        let mut signed = make_descriptor_signed(
            pk.as_bytes(),
            &sk.to_bytes(),
            &enc_pk,
            vec!["aes-256-gcm".to_string()],
            n - Duration::minutes(1),
            n + Duration::days(3650),
        );
        let mut descriptor =
            crate::generated::decode_local_rp_descriptor(&signed.descriptor).unwrap();
        descriptor.fingerprint = "0".repeat(64);
        // Re-sign over the tampered descriptor bytes so the signature itself
        // is valid — isolating the fingerprint-binding check specifically.
        signed = sign_local_rp_descriptor(&descriptor, &sk.to_bytes()).unwrap();
        assert!(matches!(
            verify_local_rp_descriptor(&signed, n, DEFAULT_CLOCK_SKEW_SECONDS),
            Err(LocalRpError::FingerprintMismatch)
        ));
    }

    /// Defense in depth: a malformed `encryption_public_key` length must fail
    /// verification explicitly, not defer to a later `try_into` elsewhere in
    /// the stack. Re-signs over the tampered descriptor so the signature
    /// itself stays valid, isolating the length check.
    #[test]
    fn descriptor_malformed_encryption_key_length_rejected() {
        let (pk, sk) = generate_ed25519_keypair();
        let (enc_pk, _) = generate_x25519_keypair();
        let n = now();
        let signed = make_descriptor_signed(
            pk.as_bytes(),
            &sk.to_bytes(),
            &enc_pk,
            vec!["aes-256-gcm".to_string()],
            n - Duration::minutes(1),
            n + Duration::days(3650),
        );
        let mut descriptor =
            crate::generated::decode_local_rp_descriptor(&signed.descriptor).unwrap();
        descriptor.encryption_public_key = vec![1u8; 31]; // one byte short
        let re_signed = sign_local_rp_descriptor(&descriptor, &sk.to_bytes()).unwrap();
        assert!(matches!(
            verify_local_rp_descriptor(&re_signed, n, DEFAULT_CLOCK_SKEW_SECONDS),
            Err(LocalRpError::InvalidKeyLength)
        ));
    }

    // -----------------------------------------------------------------
    // Login request
    // -----------------------------------------------------------------

    fn make_login_request_signed(
        signing_pk: &[u8],
        signing_sk: &[u8],
        enc_pk: &[u8],
        n: DateTime<Utc>,
    ) -> SignedLocalRpLoginRequest {
        let descriptor_signed = make_descriptor_signed(
            signing_pk,
            signing_sk,
            enc_pk,
            vec!["aes-256-gcm".to_string()],
            n - Duration::minutes(1),
            n + Duration::days(3650),
        );
        let request = build_local_rp_login_request(
            descriptor_signed,
            "http://localhost:8080/callback",
            b"nonce123".to_vec(),
            b"state456".to_vec(),
            vec!["email".to_string()],
            vec!["handle".to_string()],
            &rfc3339(n),
            &rfc3339(n + Duration::minutes(5)),
        );
        sign_local_rp_login_request(&request, signing_sk).unwrap()
    }

    #[test]
    fn login_request_sign_verify_roundtrip() {
        let (pk, sk) = generate_ed25519_keypair();
        let (enc_pk, _) = generate_x25519_keypair();
        let n = now();
        let signed = make_login_request_signed(pk.as_bytes(), &sk.to_bytes(), &enc_pk, n);
        let verified =
            verify_local_rp_login_request(&signed, n, DEFAULT_CLOCK_SKEW_SECONDS).unwrap();
        assert_eq!(verified.callback_url, "http://localhost:8080/callback");
        assert_eq!(verified.required_claims, vec!["handle".to_string()]);
    }

    #[test]
    fn login_request_tampered_signature_fails() {
        let (pk, sk) = generate_ed25519_keypair();
        let (enc_pk, _) = generate_x25519_keypair();
        let n = now();
        let mut signed = make_login_request_signed(pk.as_bytes(), &sk.to_bytes(), &enc_pk, n);
        if let Some(b) = signed.signature.first_mut() {
            *b ^= 0xff;
        }
        assert!(verify_local_rp_login_request(&signed, n, DEFAULT_CLOCK_SKEW_SECONDS).is_err());
    }

    #[test]
    fn login_request_tampered_payload_fails() {
        let (pk, sk) = generate_ed25519_keypair();
        let (enc_pk, _) = generate_x25519_keypair();
        let n = now();
        let mut signed = make_login_request_signed(pk.as_bytes(), &sk.to_bytes(), &enc_pk, n);
        if let Some(b) = signed.request.last_mut() {
            *b ^= 0xff;
        }
        assert!(verify_local_rp_login_request(&signed, n, DEFAULT_CLOCK_SKEW_SECONDS).is_err());
    }

    #[test]
    fn login_request_expired_rejected() {
        let (pk, sk) = generate_ed25519_keypair();
        let (enc_pk, _) = generate_x25519_keypair();
        let n = now();
        let descriptor_signed = make_descriptor_signed(
            pk.as_bytes(),
            &sk.to_bytes(),
            &enc_pk,
            vec!["aes-256-gcm".to_string()],
            n - Duration::minutes(1),
            n + Duration::days(3650),
        );
        let request = build_local_rp_login_request(
            descriptor_signed,
            "http://localhost:8080/callback",
            b"nonce".to_vec(),
            b"state".to_vec(),
            vec![],
            vec![],
            &rfc3339(n - Duration::minutes(10)),
            &rfc3339(n - Duration::seconds(DEFAULT_CLOCK_SKEW_SECONDS + 1)),
        );
        let signed = sign_local_rp_login_request(&request, &sk.to_bytes()).unwrap();
        assert!(matches!(
            verify_local_rp_login_request(&signed, n, DEFAULT_CLOCK_SKEW_SECONDS),
            Err(LocalRpError::Expired)
        ));
    }

    // -----------------------------------------------------------------
    // Ticket redemption
    // -----------------------------------------------------------------

    #[test]
    fn ticket_redemption_sign_verify_roundtrip() {
        let (pk, sk) = generate_ed25519_keypair();
        let fp = fingerprint(pk.as_bytes());
        let request = build_local_rp_ticket_redemption_request(vec![1u8; 32], &fp, &rfc3339(now()));
        let signed = sign_local_rp_ticket_redemption_request(&request, &sk.to_bytes()).unwrap();
        let verified =
            verify_local_rp_ticket_redemption_request(&signed, pk.as_bytes(), &fp).unwrap();
        assert_eq!(verified.fingerprint, fp);
    }

    #[test]
    fn ticket_redemption_tampered_signature_fails() {
        let (pk, sk) = generate_ed25519_keypair();
        let fp = fingerprint(pk.as_bytes());
        let request = build_local_rp_ticket_redemption_request(vec![1u8; 32], &fp, &rfc3339(now()));
        let mut signed = sign_local_rp_ticket_redemption_request(&request, &sk.to_bytes()).unwrap();
        if let Some(b) = signed.signature.first_mut() {
            *b ^= 0xff;
        }
        assert!(verify_local_rp_ticket_redemption_request(&signed, pk.as_bytes(), &fp).is_err());
    }

    #[test]
    fn ticket_redemption_possession_proof_wrong_key_fails() {
        let (pk1, sk1) = generate_ed25519_keypair();
        let (pk2, _sk2) = generate_ed25519_keypair();
        let fp = fingerprint(pk1.as_bytes());
        let request = build_local_rp_ticket_redemption_request(vec![1u8; 32], &fp, &rfc3339(now()));
        let signed = sign_local_rp_ticket_redemption_request(&request, &sk1.to_bytes()).unwrap();
        // A stolen request cannot be "redeemed" against a different key: the
        // signature was produced by sk1, so verifying against pk2 must fail.
        assert!(verify_local_rp_ticket_redemption_request(&signed, pk2.as_bytes(), &fp).is_err());
    }

    #[test]
    fn ticket_redemption_fingerprint_mismatch_fails() {
        let (pk, sk) = generate_ed25519_keypair();
        let fp = fingerprint(pk.as_bytes());
        let other_fp = "0".repeat(64);
        let request = build_local_rp_ticket_redemption_request(vec![1u8; 32], &fp, &rfc3339(now()));
        let signed = sign_local_rp_ticket_redemption_request(&request, &sk.to_bytes()).unwrap();
        // signing_public_key matches the signature, but the caller resolved
        // it under a DIFFERENT fingerprint than the request claims.
        assert!(matches!(
            verify_local_rp_ticket_redemption_request(&signed, pk.as_bytes(), &other_fp),
            Err(LocalRpError::FingerprintMismatch)
        ));
    }

    // -----------------------------------------------------------------
    // Callback payload envelope (domain-signed)
    // -----------------------------------------------------------------

    #[test]
    fn callback_payload_sign_verify_roundtrip() {
        let (domain_pk, domain_sk) = generate_ed25519_keypair();
        let n = now();
        let signed =
            make_callback_signed_payload(&domain_sk.to_bytes(), "key-1", n, "rp-fingerprint");
        let domain_key = make_domain_key("key-1", domain_pk.as_bytes());
        let payload =
            verify_local_rp_callback_payload(&signed, &[domain_key], n, DEFAULT_CLOCK_SKEW_SECONDS)
                .unwrap();
        assert_eq!(payload.user_id, "user-1");
        assert_eq!(payload.audience_fingerprint, "rp-fingerprint");
    }

    #[test]
    fn callback_payload_tampered_signature_fails() {
        let (domain_pk, domain_sk) = generate_ed25519_keypair();
        let n = now();
        let mut signed = make_callback_signed_payload(&domain_sk.to_bytes(), "key-1", n, "rp-fp");
        if let Some(b) = signed.signature.first_mut() {
            *b ^= 0xff;
        }
        let domain_key = make_domain_key("key-1", domain_pk.as_bytes());
        assert!(matches!(
            verify_local_rp_callback_payload(&signed, &[domain_key], n, DEFAULT_CLOCK_SKEW_SECONDS),
            Err(LocalRpError::Verify(VerifyError::SignatureInvalid))
        ));
    }

    #[test]
    fn callback_payload_wrong_key_not_found() {
        let (_domain_pk, domain_sk) = generate_ed25519_keypair();
        let (other_pk, _other_sk) = generate_ed25519_keypair();
        let n = now();
        let signed = make_callback_signed_payload(&domain_sk.to_bytes(), "key-1", n, "rp-fp");
        // Only a DIFFERENT key id is supplied for verification.
        let domain_key = make_domain_key("key-2", other_pk.as_bytes());
        assert!(matches!(
            verify_local_rp_callback_payload(&signed, &[domain_key], n, DEFAULT_CLOCK_SKEW_SECONDS),
            Err(LocalRpError::Verify(VerifyError::KeyNotFound(_)))
        ));
    }

    #[test]
    fn callback_payload_expired_rejected() {
        let (domain_pk, domain_sk) = generate_ed25519_keypair();
        let n = now();
        let payload = build_local_rp_callback_payload(
            "user-1",
            "example.com",
            vec![7u8; 32],
            "rp-fp",
            "http://localhost/callback",
            b"nonce".to_vec(),
            b"state".to_vec(),
            &rfc3339(n - Duration::minutes(10)),
            &rfc3339(n - Duration::seconds(DEFAULT_CLOCK_SKEW_SECONDS + 1)),
        );
        let signed = sign_local_rp_callback_payload(
            &payload,
            "key-1",
            SigningAlgorithm::Ed25519,
            &domain_sk.to_bytes(),
        )
        .unwrap();
        let domain_key = make_domain_key("key-1", domain_pk.as_bytes());
        assert!(matches!(
            verify_local_rp_callback_payload(&signed, &[domain_key], n, DEFAULT_CLOCK_SKEW_SECONDS),
            Err(LocalRpError::Expired)
        ));
    }

    // -----------------------------------------------------------------
    // Nonce/state/audience/issuer/callback-url helpers
    // -----------------------------------------------------------------

    #[test]
    fn nonce_state_match_ok_mismatch_fails() {
        assert!(verify_nonce_state(b"n", b"s", b"n", b"s").is_ok());
        assert!(matches!(
            verify_nonce_state(b"n", b"s", b"different", b"s"),
            Err(LocalRpError::NonceMismatch)
        ));
        assert!(matches!(
            verify_nonce_state(b"n", b"s", b"n", b"different"),
            Err(LocalRpError::StateMismatch)
        ));
    }

    #[test]
    fn audience_mismatch_fails() {
        assert!(verify_audience("fp-a", "fp-a").is_ok());
        assert!(matches!(
            verify_audience("fp-a", "fp-b"),
            Err(LocalRpError::AudienceMismatch)
        ));
    }

    #[test]
    fn issuer_binding_wrong_domain_fails() {
        assert!(verify_issuer("example.com", "example.com").is_ok());
        assert!(matches!(
            verify_issuer("evil.example", "example.com"),
            Err(LocalRpError::IssuerMismatch)
        ));
    }

    #[test]
    fn callback_url_binding_mismatch_fails() {
        assert!(verify_callback_url("http://localhost/cb", "http://localhost/cb").is_ok());
        assert!(matches!(
            verify_callback_url("http://localhost/cb", "http://localhost/different"),
            Err(LocalRpError::CallbackUrlMismatch)
        ));
    }

    // -----------------------------------------------------------------
    // Callback sealed box
    // -----------------------------------------------------------------

    fn seal_for_test(
        suite: AeadSuite,
        domain_sk: &[u8],
        enc_pk: &[u8; 32],
        n: DateTime<Utc>,
    ) -> LocalRpEncryptedCallback {
        let signed_payload = make_callback_signed_payload(domain_sk, "key-1", n, "rp-fp");
        seal_local_rp_callback(
            &signed_payload,
            suite,
            enc_pk,
            "rp-fp",
            b"nonce".to_vec(),
            b"state".to_vec(),
            &rfc3339(n),
            &rfc3339(n + Duration::minutes(5)),
        )
        .unwrap()
    }

    #[test]
    fn callback_seal_open_roundtrip_both_suites() {
        for suite in [AeadSuite::Aes256Gcm, AeadSuite::ChaCha20Poly1305] {
            let (domain_pk, domain_sk) = generate_ed25519_keypair();
            let (enc_pk, enc_sk) = generate_x25519_keypair();
            let n = now();
            let enc_pk_arr: [u8; 32] = enc_pk.try_into().unwrap();
            let enc_sk_arr: [u8; 32] = enc_sk.try_into().unwrap();

            let sealed = seal_for_test(suite, &domain_sk.to_bytes(), &enc_pk_arr, n);

            let (header, opened_signed_payload) = open_local_rp_callback(
                &sealed,
                &enc_sk_arr,
                &[AeadSuite::Aes256Gcm, AeadSuite::ChaCha20Poly1305],
            )
            .unwrap();
            assert_eq!(header.suite, suite.as_str());

            let domain_key = make_domain_key("key-1", domain_pk.as_bytes());
            let payload = verify_local_rp_callback_payload(
                &opened_signed_payload,
                &[domain_key],
                n,
                DEFAULT_CLOCK_SKEW_SECONDS,
            )
            .unwrap();
            assert_eq!(payload.user_id, "user-1");
            check_callback_header_matches_payload(&header, &payload).unwrap();
        }
    }

    #[test]
    fn callback_decrypts_only_with_right_key() {
        let (_domain_pk, domain_sk) = generate_ed25519_keypair();
        let (enc_pk, _enc_sk) = generate_x25519_keypair();
        let (_, wrong_enc_sk) = generate_x25519_keypair();
        let n = now();
        let enc_pk_arr: [u8; 32] = enc_pk.try_into().unwrap();
        let wrong_sk_arr: [u8; 32] = wrong_enc_sk.try_into().unwrap();

        let sealed = seal_for_test(AeadSuite::Aes256Gcm, &domain_sk.to_bytes(), &enc_pk_arr, n);

        assert!(open_local_rp_callback(&sealed, &wrong_sk_arr, &[AeadSuite::Aes256Gcm]).is_err());
    }

    #[test]
    fn callback_ciphertext_tamper_fails() {
        let (_domain_pk, domain_sk) = generate_ed25519_keypair();
        let (enc_pk, enc_sk) = generate_x25519_keypair();
        let n = now();
        let enc_pk_arr: [u8; 32] = enc_pk.try_into().unwrap();
        let enc_sk_arr: [u8; 32] = enc_sk.try_into().unwrap();

        let mut sealed = seal_for_test(AeadSuite::Aes256Gcm, &domain_sk.to_bytes(), &enc_pk_arr, n);
        if let Some(b) = sealed.ciphertext.first_mut() {
            *b ^= 0xff;
        }
        assert!(open_local_rp_callback(&sealed, &enc_sk_arr, &[AeadSuite::Aes256Gcm]).is_err());
    }

    /// Reseal with a fresh keypair, apply `mutate` to the decoded header, then
    /// re-encode and attempt to open with `allowed_suites`. Returns the
    /// `open_local_rp_callback` result so callers can assert on the specific
    /// error variant they expect.
    fn open_with_tampered_header(
        mutate: impl FnOnce(&mut LocalRpCallbackHeader),
        allowed_suites: &[AeadSuite],
    ) -> Result<(LocalRpCallbackHeader, SignedLocalRpCallbackPayload), LocalRpError> {
        let (_domain_pk, domain_sk) = generate_ed25519_keypair();
        let (enc_pk, enc_sk) = generate_x25519_keypair();
        let n = now();
        let enc_pk_arr: [u8; 32] = enc_pk.try_into().unwrap();
        let enc_sk_arr: [u8; 32] = enc_sk.try_into().unwrap();

        let sealed = seal_for_test(AeadSuite::Aes256Gcm, &domain_sk.to_bytes(), &enc_pk_arr, n);

        let mut header = crate::generated::decode_local_rp_callback_header(&sealed.header).unwrap();
        mutate(&mut header);
        let mut tampered = sealed;
        tampered.header = crate::generated::encode_local_rp_callback_header(&header);

        open_local_rp_callback(&tampered, &enc_sk_arr, allowed_suites)
    }

    #[test]
    fn callback_header_fingerprint_swap_fails_aad() {
        let result = open_with_tampered_header(
            |h| h.fingerprint = "swapped-fingerprint".to_string(),
            &[AeadSuite::Aes256Gcm],
        );
        assert!(result.is_err());
    }

    #[test]
    fn callback_header_nonce_swap_fails_aad() {
        let result = open_with_tampered_header(
            |h| h.nonce = b"swapped-nonce".to_vec(),
            &[AeadSuite::Aes256Gcm],
        );
        assert!(result.is_err());
    }

    #[test]
    fn callback_header_state_swap_fails_aad() {
        let result = open_with_tampered_header(
            |h| h.state = b"swapped-state".to_vec(),
            &[AeadSuite::Aes256Gcm],
        );
        assert!(result.is_err());
    }

    #[test]
    fn callback_header_suite_swap_fails_aad() {
        // The suite id is part of the KDF context (not just the AAD), so
        // swapping it changes the derived key too — this proves the chosen
        // suite is cryptographically bound, not merely advisory metadata.
        let result = open_with_tampered_header(
            |h| h.suite = crypto::AEAD_SUITE_CHACHA20_POLY1305.to_string(),
            &[AeadSuite::Aes256Gcm, AeadSuite::ChaCha20Poly1305],
        );
        assert!(result.is_err());
    }

    #[test]
    fn callback_open_rejects_unadvertised_suite() {
        let (_domain_pk, domain_sk) = generate_ed25519_keypair();
        let (enc_pk, enc_sk) = generate_x25519_keypair();
        let n = now();
        let enc_pk_arr: [u8; 32] = enc_pk.try_into().unwrap();
        let enc_sk_arr: [u8; 32] = enc_sk.try_into().unwrap();

        let sealed = seal_for_test(
            AeadSuite::ChaCha20Poly1305,
            &domain_sk.to_bytes(),
            &enc_pk_arr,
            n,
        );

        // The SDK's own descriptor only advertised aes-256-gcm; a callback
        // that arrives using chacha20-poly1305 (however validly encrypted)
        // must be rejected rather than silently decrypted.
        assert!(matches!(
            open_local_rp_callback(&sealed, &enc_sk_arr, &[AeadSuite::Aes256Gcm]),
            Err(LocalRpError::SuiteNotAdvertised(_))
        ));
    }

    #[test]
    fn callback_open_rejects_unrecognized_suite_id() {
        let result = open_with_tampered_header(
            |h| h.suite = "made-up-suite".to_string(),
            &[AeadSuite::Aes256Gcm, AeadSuite::ChaCha20Poly1305],
        );
        assert!(matches!(result, Err(LocalRpError::UnsupportedSuite(_))));
    }

    #[test]
    fn callback_open_rejects_low_order_ephemeral_key() {
        let result = open_with_tampered_header(
            |h| h.ephemeral_public_key = vec![0u8; 32],
            &[AeadSuite::Aes256Gcm],
        );
        assert!(result.is_err());
    }

    #[test]
    fn callback_header_matches_payload_detects_drift() {
        let header = LocalRpCallbackHeader {
            fingerprint: "fp-a".to_string(),
            nonce: b"n".to_vec(),
            state: b"s".to_vec(),
            suite: crypto::AEAD_SUITE_AES_256_GCM.to_string(),
            ephemeral_public_key: vec![1u8; 32],
            aead_nonce: vec![2u8; 12],
            issued_at: "2020-01-01T00:00:00+00:00".to_string(),
            expires_at: "2020-01-01T00:05:00+00:00".to_string(),
        };
        let mut payload = LocalRpCallbackPayload {
            user_id: "u".to_string(),
            user_domain: "example.com".to_string(),
            claim_ticket: vec![],
            audience_fingerprint: "fp-a".to_string(),
            callback_url: "http://localhost/cb".to_string(),
            nonce: b"n".to_vec(),
            state: b"s".to_vec(),
            issued_at: "2020-01-01T00:00:00+00:00".to_string(),
            expires_at: "2020-01-01T00:05:00+00:00".to_string(),
        };
        assert!(check_callback_header_matches_payload(&header, &payload).is_ok());

        payload.audience_fingerprint = "fp-b".to_string();
        assert!(matches!(
            check_callback_header_matches_payload(&header, &payload),
            Err(LocalRpError::HeaderPayloadMismatch("fingerprint"))
        ));
    }
}
