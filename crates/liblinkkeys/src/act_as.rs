//! Act-as grants: a user lets one application (the grantee) act as the user at
//! a second application (the audience).
//!
//! The user's home domain signs the user's decision. It does not interpret the
//! scope: the audience defines the scope strings, signs the set it offers, and
//! enforces them in its own policy. No party is in the request path between the
//! grantee and the audience. The audience verifies a credential with public,
//! cacheable material only. See `docs/spec/reserved/act-as-grants.md`.
//!
//! This module is the pure half: deterministic encoding, signature
//! construction and verification, the issued-terms calculation, the refresh
//! decision, and the audience's verification checklist. It has no database,
//! no network, and no clock of its own. Every temporal function takes `now`.
//!
//! The one exception, shared with [`crate::application_keys`], is a DOMAIN
//! signing key's validity, which [`crate::assertions::check_signing_key_valid`]
//! checks against wall-clock time.

use crate::application_keys::{ApplicationKeyRef, ApplicationSigner, KEY_USAGE_SIGN};
use crate::assertions::check_signing_key_valid;
use crate::claims::ClaimSigner;
use crate::crypto::{self, CryptoError};
use crate::generated::types::{
    ActAsCredential, ActAsGrant, ActAsGrantRequest, ActAsGrantRevocation, ActAsPresentation,
    ActAsRefreshRequest, ActAsScopeSet, ApplicationKeySignature, ApplicationRef, ClaimSignature,
    DomainPublicKey, GranteeProof, GranteeRef, SignedActAsGrant, SignedActAsGrantRequest,
    SignedActAsGrantRevocation, SignedActAsPresentation, SignedActAsRefreshRequest,
    SignedActAsScopeSet, SignedLocalRpDescriptor,
};
use crate::local_rp::envelope_signature_input;
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;

// ---------------------------------------------------------------------------
// Domain-separation tags
// ---------------------------------------------------------------------------

/// The audience's signature over the scope set it offers one grantee.
pub const SCOPE_SET_TAG: &str = "linkkeys-act-as-scope-set-v1alpha";
/// The home domain's signature over a grant.
pub const GRANT_TAG: &str = "linkkeys-act-as-grant-v1alpha";
/// The grantee's signature over a grant request.
pub const GRANT_REQUEST_TAG: &str = "linkkeys-act-as-grant-request-v1alpha";
/// The grantee's signature over a refresh request.
pub const REFRESH_REQUEST_TAG: &str = "linkkeys-act-as-refresh-request-v1alpha";
/// The grantee's signature over one presentation to the audience.
pub const PRESENTATION_TAG: &str = "linkkeys-act-as-presentation-v1alpha";
/// The home domain's signature over a grant revocation.
pub const GRANT_REVOCATION_TAG: &str = "linkkeys-act-as-grant-revocation-v1alpha";

// ---------------------------------------------------------------------------
// Defaults and bounds
// ---------------------------------------------------------------------------

/// Default grant lifetime: one hour.
pub const DEFAULT_LIFETIME_SECONDS: i64 = 3_600;
/// Default largest lifetime a user can choose: one day.
pub const DEFAULT_MAX_LIFETIME_SECONDS: i64 = 86_400;
/// Default renewal window: no renewal.
pub const DEFAULT_RENEWAL_WINDOW_SECONDS: i64 = 0;
/// Default largest renewal window a user can choose: 30 days.
pub const DEFAULT_MAX_RENEWAL_WINDOW_SECONDS: i64 = 30 * 86_400;
/// Most grant ids one public revocation read accepts.
pub const MAX_REVOCATION_LOOKUP_IDS: usize = 100;
/// Most entries one scope set can carry. The consent screen must show every
/// entry, so the set stays bounded.
pub const MAX_SCOPE_ENTRIES: usize = 64;
/// Longest scope string, in bytes.
pub const MAX_SCOPE_BYTES: usize = 256;
/// Longest scope description, in bytes.
pub const MAX_DESCRIPTION_BYTES: usize = 1_024;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum ActAsError {
    /// An embedded CBOR payload did not decode.
    Decode(String),
    /// A timestamp field was not RFC3339.
    BadTimestamp(String),
    /// A GranteeRef or GranteeProof did not carry exactly one form.
    MalformedGrantee,
    /// The proof's form does not match the grantee's form.
    ProofDoesNotMatchGrantee,
    /// The signing key is not a valid key of the expected party.
    UntrustedSigner,
    /// A signature did not verify.
    BadSignature,
    /// No signature on a multi-signed structure came from an acceptable key.
    /// The text names each signing key and why it was refused.
    NoValidSignature(String),
    /// A handle claim is malformed, about another account, or did not verify.
    BadHandleClaim(String),
    /// A field did not equal the value the verifier expected.
    Mismatch(&'static str),
    /// A scope set is empty, too large, or repeats a scope.
    BadScopeSet(String),
    /// The approved scope is empty, repeats a scope, or names a scope outside
    /// the scope set.
    BadApprovedScope(String),
    /// A request or presentation is outside its time window.
    RequestExpired,
    /// The scope set has expired. Applies only at approval.
    ScopeSetExpired,
    /// The grant has expired.
    GrantExpired,
    /// The grant is revoked.
    GrantRevoked,
    /// A lifetime or renewal window is not positive, or exceeds a bound.
    BadTerms(String),
    /// The grant carries a device binding. Device keys are Reserved, so no
    /// verifier can check one yet.
    DeviceBindingUnsupported,
    /// A cryptographic primitive failed.
    Crypto(String),
}

impl fmt::Display for ActAsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "act-as payload did not decode: {e}"),
            Self::BadTimestamp(e) => write!(f, "act-as timestamp is not RFC3339: {e}"),
            Self::MalformedGrantee => write!(f, "grantee must name exactly one form"),
            Self::ProofDoesNotMatchGrantee => write!(f, "grantee proof does not match the grantee"),
            Self::UntrustedSigner => {
                write!(f, "signing key is not a valid key of the expected party")
            }
            Self::BadSignature => write!(f, "signature did not verify"),
            Self::NoValidSignature(e) => write!(f, "no acceptable signature: {e}"),
            Self::BadHandleClaim(e) => write!(f, "handle claim is invalid: {e}"),
            Self::Mismatch(field) => write!(f, "{field} does not match the expected value"),
            Self::BadScopeSet(e) => write!(f, "scope set is invalid: {e}"),
            Self::BadApprovedScope(e) => write!(f, "approved scope is invalid: {e}"),
            Self::RequestExpired => write!(f, "request is outside its time window"),
            Self::ScopeSetExpired => write!(f, "scope set has expired"),
            Self::GrantExpired => write!(f, "act-as grant has expired"),
            Self::GrantRevoked => write!(f, "act-as grant is revoked"),
            Self::BadTerms(e) => write!(f, "act-as terms are invalid: {e}"),
            Self::DeviceBindingUnsupported => write!(f, "device-bound grants are not supported"),
            Self::Crypto(e) => write!(f, "act-as crypto error: {e}"),
        }
    }
}

impl std::error::Error for ActAsError {}

impl From<CryptoError> for ActAsError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn parse_time(s: &str) -> Result<DateTime<Utc>, ActAsError> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| ActAsError::BadTimestamp(e.to_string()))
}

/// Whole-second RFC3339 in UTC, so a timestamp survives storage unchanged.
pub fn format_time(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn check_window(
    starts_at: &str,
    ends_at: &str,
    now: DateTime<Utc>,
    skew_seconds: i64,
) -> Result<(), ActAsError> {
    let start = parse_time(starts_at)?;
    let end = parse_time(ends_at)?;
    if end <= start {
        return Err(ActAsError::RequestExpired);
    }
    let skew = Duration::seconds(skew_seconds);
    if now + skew < start || now - skew > end {
        return Err(ActAsError::RequestExpired);
    }
    Ok(())
}

/// SHA-256 of a grant's signed bytes. A presentation binds this value.
pub fn grant_hash(grant_bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(grant_bytes).to_vec()
}

/// Two application references name the same application.
pub fn same_application(a: &ApplicationRef, b: &ApplicationRef) -> bool {
    a.subject_user_id == b.subject_user_id
        && a.subject_domain == b.subject_domain
        && a.application_id == b.application_id
}

/// Two grantee references name the same grantee.
pub fn same_grantee(a: &GranteeRef, b: &GranteeRef) -> bool {
    match (
        &a.application,
        &a.local_rp_descriptor_fingerprint,
        &b.application,
        &b.local_rp_descriptor_fingerprint,
    ) {
        (Some(x), None, Some(y), None) => same_application(x, y),
        (None, Some(x), None, Some(y)) => x == y,
        _ => false,
    }
}

/// A GranteeRef must carry exactly one form.
pub fn check_grantee(grantee: &GranteeRef) -> Result<(), ActAsError> {
    match (
        &grantee.application,
        &grantee.local_rp_descriptor_fingerprint,
    ) {
        (Some(app), None) => {
            if app.subject_user_id.is_empty()
                || app.subject_domain.is_empty()
                || app.application_id.is_empty()
            {
                return Err(ActAsError::MalformedGrantee);
            }
            Ok(())
        }
        (None, Some(fp)) if !fp.is_empty() => Ok(()),
        _ => Err(ActAsError::MalformedGrantee),
    }
}

// ---------------------------------------------------------------------------
// Grantee keys and proofs
// ---------------------------------------------------------------------------

/// A grantee's signing material, as the grantee holds it.
pub enum GranteeSigner<'a> {
    /// An enrolled application instance signs with one of its attested keys.
    Application {
        instance_id: &'a str,
        signer: ApplicationSigner<'a>,
    },
    /// A local RP signs with its descriptor signing key.
    LocalRp {
        descriptor: &'a SignedLocalRpDescriptor,
        fingerprint: &'a str,
        signing_private_key: &'a [u8],
    },
}

impl GranteeSigner<'_> {
    /// Sign `message` and wrap the signature in a proof.
    pub fn prove(&self, message: &[u8]) -> Result<GranteeProof, ActAsError> {
        match self {
            Self::Application {
                instance_id,
                signer,
            } => Ok(GranteeProof {
                application_instance_id: Some((*instance_id).to_string()),
                local_rp_descriptor: None,
                signature: ApplicationKeySignature {
                    signed_by_key_id: signer.key_id.to_string(),
                    signature: crypto::sign_with_algorithm(
                        signer.algorithm,
                        message,
                        signer.private_key_bytes,
                    )?,
                },
            }),
            Self::LocalRp {
                descriptor,
                fingerprint,
                signing_private_key,
            } => Ok(GranteeProof {
                application_instance_id: None,
                local_rp_descriptor: Some((*descriptor).clone()),
                signature: ApplicationKeySignature {
                    signed_by_key_id: (*fingerprint).to_string(),
                    signature: crypto::sign_with_algorithm(
                        crypto::SigningAlgorithm::Ed25519,
                        message,
                        signing_private_key,
                    )?,
                },
            }),
        }
    }
}

/// Who signed a proof, once the proof is verified.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedGranteeSigner {
    /// The application instance, for an application grantee.
    pub instance_id: Option<String>,
    /// The key id or descriptor fingerprint that signed.
    pub key_id: String,
}

/// The application instance a proof names, for an application grantee. The
/// caller resolves that instance's attested keys and passes them to
/// [`verify_grantee_proof`].
pub fn proof_instance_id(proof: &GranteeProof) -> Option<&str> {
    proof.application_instance_id.as_deref()
}

/// Verify that a grantee key signed `message`.
///
/// For an application grantee, `instance_keys` are the attested keys of the
/// instance that [`proof_instance_id`] names. The caller MUST have verified
/// those attestations against the grantee's home domain, for the grantee's
/// `ApplicationRef`. The signing key must be a signing key that is valid at
/// `now`.
///
/// For a local-RP grantee, `instance_keys` is ignored. The descriptor in the
/// proof must verify, its fingerprint must equal the grantee's, and its
/// signing key must have signed.
pub fn verify_grantee_proof(
    proof: &GranteeProof,
    message: &[u8],
    grantee: &GranteeRef,
    instance_keys: &[ApplicationKeyRef],
    now: DateTime<Utc>,
    skew_seconds: i64,
) -> Result<VerifiedGranteeSigner, ActAsError> {
    check_grantee(grantee)?;
    match (
        &grantee.application,
        &grantee.local_rp_descriptor_fingerprint,
        &proof.application_instance_id,
        &proof.local_rp_descriptor,
    ) {
        (Some(_), None, Some(instance_id), None) => {
            let key = instance_keys
                .iter()
                .find(|k| k.key_id == proof.signature.signed_by_key_id)
                .ok_or(ActAsError::UntrustedSigner)?;
            if key.key_usage != KEY_USAGE_SIGN || !key.is_valid_signing_key(now) {
                return Err(ActAsError::UntrustedSigner);
            }
            crypto::resolve_and_verify(
                &key.algorithm,
                message,
                &proof.signature.signature,
                &key.public_key,
            )
            .map_err(|_| ActAsError::BadSignature)?;
            Ok(VerifiedGranteeSigner {
                instance_id: Some(instance_id.clone()),
                key_id: key.key_id.clone(),
            })
        }
        (None, Some(fingerprint), None, Some(signed_descriptor)) => {
            let descriptor =
                crate::local_rp::verify_local_rp_descriptor(signed_descriptor, now, skew_seconds)
                    .map_err(|_| ActAsError::UntrustedSigner)?;
            if &descriptor.fingerprint != fingerprint
                || proof.signature.signed_by_key_id != descriptor.fingerprint
            {
                return Err(ActAsError::Mismatch("local_rp_descriptor_fingerprint"));
            }
            crypto::verify_with_algorithm(
                crypto::SigningAlgorithm::Ed25519,
                message,
                &proof.signature.signature,
                &descriptor.signing_public_key,
            )
            .map_err(|_| ActAsError::BadSignature)?;
            Ok(VerifiedGranteeSigner {
                instance_id: None,
                key_id: descriptor.fingerprint,
            })
        }
        _ => Err(ActAsError::ProofDoesNotMatchGrantee),
    }
}

// ---------------------------------------------------------------------------
// Revoked-key policy
// ---------------------------------------------------------------------------

/// How a verifier treats a signature whose key was revoked after it signed.
///
/// Revocation invalidates one key, never the others. The protocol does not
/// require a verifier to trust a revoked key's earlier signatures, so each
/// party chooses. The default follows invariant I-7: a signature made before
/// the key's revocation time stays valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RevokedKeyPolicy {
    /// Accept a revoked key's signature made before its revocation time.
    #[default]
    AcceptBeforeRevocation,
    /// Refuse any signature by a key that is now revoked.
    RefuseRevoked,
}

/// The clock skew allowed between a signer and the home domain that recorded
/// its key's creation time. A key created up to this long after a structure's
/// signing time still counts, so an audience whose clock trails its home
/// domain can sign right after it enrolls.
pub const KEY_CLOCK_SKEW_SECONDS: i64 = 300;

/// The key could vouch at `signed_at`, allowing [`KEY_CLOCK_SKEW_SECONDS`] for
/// a key the home domain recorded as created slightly later.
fn valid_at_with_skew(key: &ApplicationKeyRef, signed_at: DateTime<Utc>) -> bool {
    if key.was_valid_at(signed_at) {
        return true;
    }
    let Ok(created) = parse_time(&key.created_at) else {
        return false;
    };
    created > signed_at
        && created <= signed_at + Duration::seconds(KEY_CLOCK_SKEW_SECONDS)
        && key.was_valid_at(created)
}

/// Why `key` cannot vouch for something signed at `signed_at`, or None.
fn key_refusal(
    key: &ApplicationKeyRef,
    signed_at: DateTime<Utc>,
    policy: RevokedKeyPolicy,
) -> Option<String> {
    if key.key_usage != KEY_USAGE_SIGN {
        return Some("not a signing key".into());
    }
    if let (RevokedKeyPolicy::RefuseRevoked, Some(revoked_at)) = (policy, &key.revoked_at) {
        return Some(format!(
            "revoked at {revoked_at}; this verifier refuses revoked keys"
        ));
    }
    if !valid_at_with_skew(key, signed_at) {
        return Some(match &key.revoked_at {
            Some(revoked_at) => format!("revoked at {revoked_at}, before it signed"),
            None => "not inside its validity window when it signed".into(),
        });
    }
    None
}

// ---------------------------------------------------------------------------
// Scope sets
// ---------------------------------------------------------------------------

/// Check a scope set's shape: bounded, non-empty, no repeated scope.
pub fn check_scope_set_shape(set: &ActAsScopeSet) -> Result<(), ActAsError> {
    check_grantee(&set.grantee)?;
    if set.entries.is_empty() {
        return Err(ActAsError::BadScopeSet("no entries".into()));
    }
    if set.entries.len() > MAX_SCOPE_ENTRIES {
        return Err(ActAsError::BadScopeSet(format!(
            "more than {MAX_SCOPE_ENTRIES} entries"
        )));
    }
    let mut seen = HashSet::new();
    for entry in &set.entries {
        if entry.scope.is_empty() || entry.scope.len() > MAX_SCOPE_BYTES {
            return Err(ActAsError::BadScopeSet("scope length out of range".into()));
        }
        if entry
            .description
            .as_ref()
            .is_some_and(|d| d.len() > MAX_DESCRIPTION_BYTES)
        {
            return Err(ActAsError::BadScopeSet("description too long".into()));
        }
        if !seen.insert(entry.scope.as_str()) {
            return Err(ActAsError::BadScopeSet(format!(
                "scope {:?} repeats",
                entry.scope
            )));
        }
    }
    if let Some(claim) = &set.audience_handle_claim {
        check_handle_claim_subject(claim, &set.audience)?;
    }
    parse_time(&set.issued_at)?;
    parse_time(&set.expires_at)?;
    Ok(())
}

/// The audience signs the scope set it offers one grantee, with every current
/// signing key of the instance. A verifier needs one signature from a valid
/// key, so one expired or revoked key does not break the set.
pub fn sign_scope_set(
    set: &ActAsScopeSet,
    signer_instance_id: &str,
    signers: &[ApplicationSigner<'_>],
) -> Result<SignedActAsScopeSet, ActAsError> {
    check_scope_set_shape(set)?;
    if signers.is_empty() {
        return Err(ActAsError::NoValidSignature("no signing key given".into()));
    }
    let mut seen = HashSet::new();
    if !signers.iter().all(|s| seen.insert(s.key_id)) {
        return Err(ActAsError::NoValidSignature("a key is listed twice".into()));
    }
    let bytes = crate::generated::encode_act_as_scope_set(set);
    let message = envelope_signature_input(SCOPE_SET_TAG, &bytes);
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
    Ok(SignedActAsScopeSet {
        scope_set: bytes,
        signer_instance_id: signer_instance_id.to_string(),
        signatures,
    })
}

/// Verify a scope set's signatures and shape.
///
/// `audience_keys` are the attested keys of the instance that
/// `signed.signer_instance_id` names, INCLUDING keys that expired or were
/// revoked since, each with its `revoked_at`. The caller MUST have verified
/// them for `expected_audience`. One signature by a key that was valid when
/// the set was issued, and that `policy` accepts, is enough.
///
/// This does not check the set's expiry. Only approval does that, with
/// [`check_scope_set_current`].
pub fn verify_scope_set(
    signed: &SignedActAsScopeSet,
    expected_audience: &ApplicationRef,
    audience_keys: &[ApplicationKeyRef],
    policy: RevokedKeyPolicy,
) -> Result<ActAsScopeSet, ActAsError> {
    let set = crate::generated::decode_act_as_scope_set(&signed.scope_set)
        .map_err(|e| ActAsError::Decode(e.to_string()))?;
    if !same_application(&set.audience, expected_audience) {
        return Err(ActAsError::Mismatch("scope_set.audience"));
    }
    check_scope_set_shape(&set)?;
    if signed.signatures.is_empty() {
        return Err(ActAsError::NoValidSignature(
            "the scope set is unsigned".into(),
        ));
    }
    let issued_at = parse_time(&set.issued_at)?;
    let message = envelope_signature_input(SCOPE_SET_TAG, &signed.scope_set);
    let mut refusals = Vec::new();
    for sig in &signed.signatures {
        let Some(key) = audience_keys
            .iter()
            .find(|k| k.key_id == sig.signed_by_key_id)
        else {
            refusals.push(format!(
                "{}: not a key of the audience",
                sig.signed_by_key_id
            ));
            continue;
        };
        if let Some(reason) = key_refusal(key, issued_at, policy) {
            refusals.push(format!("{}: {reason}", key.key_id));
            continue;
        }
        match crypto::resolve_and_verify(&key.algorithm, &message, &sig.signature, &key.public_key)
        {
            Ok(()) => return Ok(set),
            Err(_) => refusals.push(format!("{}: signature did not verify", key.key_id)),
        }
    }
    Err(ActAsError::NoValidSignature(refusals.join("; ")))
}

// ---------------------------------------------------------------------------
// Handle claims
// ---------------------------------------------------------------------------

/// The claim type a handle claim carries.
pub const HANDLE_CLAIM_TYPE: &str = "handle";

/// A handle claim must be about the party's own account.
fn check_handle_claim_subject(
    claim: &crate::generated::types::Claim,
    party: &ApplicationRef,
) -> Result<(), ActAsError> {
    if claim.claim_type != HANDLE_CLAIM_TYPE {
        return Err(ActAsError::BadHandleClaim(format!(
            "claim type is {:?}, not {HANDLE_CLAIM_TYPE:?}",
            claim.claim_type
        )));
    }
    if claim.user_id != party.subject_user_id {
        return Err(ActAsError::BadHandleClaim(
            "the claim is about another account".into(),
        ));
    }
    Ok(())
}

/// Verify a handle claim about `party`'s enrolling account and return the
/// handle. Only signatures by the party's own domain count: a handle is that
/// domain's statement. `domain_keys` are that domain's signing keys.
pub fn verify_handle_claim(
    claim: &crate::generated::types::Claim,
    party: &ApplicationRef,
    domain_keys: &[DomainPublicKey],
) -> Result<String, ActAsError> {
    check_handle_claim_subject(claim, party)?;
    let mut own = claim.clone();
    own.signatures.retain(|s| s.domain == party.subject_domain);
    crate::claims::verify_claim(
        &own,
        &party.subject_domain,
        &[crate::claims::DomainKeySet {
            domain: party.subject_domain.clone(),
            keys: domain_keys.to_vec(),
        }],
    )
    .map_err(|e| ActAsError::BadHandleClaim(e.to_string()))?;
    String::from_utf8(claim.claim_value.clone())
        .map_err(|_| ActAsError::BadHandleClaim("the handle is not UTF-8".into()))
}

/// At approval only: the scope set has not expired.
pub fn check_scope_set_current(
    set: &ActAsScopeSet,
    now: DateTime<Utc>,
    skew_seconds: i64,
) -> Result<(), ActAsError> {
    check_window(&set.issued_at, &set.expires_at, now, skew_seconds)
        .map_err(|_| ActAsError::ScopeSetExpired)
}

/// The approved scope is a non-empty subset of the set, with no repeats.
pub fn check_approved_scope(set: &ActAsScopeSet, approved: &[String]) -> Result<(), ActAsError> {
    if approved.is_empty() {
        return Err(ActAsError::BadApprovedScope("no scope approved".into()));
    }
    let offered: HashSet<&str> = set.entries.iter().map(|e| e.scope.as_str()).collect();
    let mut seen = HashSet::new();
    for scope in approved {
        if !offered.contains(scope.as_str()) {
            return Err(ActAsError::BadApprovedScope(format!(
                "{scope:?} is not in the scope set"
            )));
        }
        if !seen.insert(scope.as_str()) {
            return Err(ActAsError::BadApprovedScope(format!("{scope:?} repeats")));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Grant requests
// ---------------------------------------------------------------------------

/// The grantee signs a grant request.
pub fn sign_grant_request(
    request: &ActAsGrantRequest,
    signer: &GranteeSigner<'_>,
) -> Result<SignedActAsGrantRequest, ActAsError> {
    check_grantee(&request.grantee)?;
    // Refuse a handle claim the home domain would refuse, before sending.
    if let Some(claim) = &request.grantee_handle_claim {
        let Some(app) = &request.grantee.application else {
            return Err(ActAsError::BadHandleClaim(
                "a local-RP grantee has no account to name".into(),
            ));
        };
        check_handle_claim_subject(claim, app)?;
    }
    let bytes = crate::generated::encode_act_as_grant_request(request);
    let proof = signer.prove(&envelope_signature_input(GRANT_REQUEST_TAG, &bytes))?;
    Ok(SignedActAsGrantRequest {
        request: bytes,
        proof,
    })
}

/// Decode a grant request without verifying it, so the caller can find the
/// grantee's keys. Never trust the result before [`verify_grant_request`].
pub fn decode_grant_request(
    signed: &SignedActAsGrantRequest,
) -> Result<ActAsGrantRequest, ActAsError> {
    crate::generated::decode_act_as_grant_request(&signed.request)
        .map_err(|e| ActAsError::Decode(e.to_string()))
}

/// The home domain verifies a grant request's signature, window, and shape.
///
/// The caller still owns three checks that need state or the network: that
/// the scope set verifies against the audience's keys
/// ([`verify_scope_set`]), that the set is current, and that the nonce is
/// single-use.
pub fn verify_grant_request(
    signed: &SignedActAsGrantRequest,
    grantee_instance_keys: &[ApplicationKeyRef],
    now: DateTime<Utc>,
    skew_seconds: i64,
) -> Result<ActAsGrantRequest, ActAsError> {
    let request = decode_grant_request(signed)?;
    check_grantee(&request.grantee)?;
    check_window(
        &request.requested_at,
        &request.expires_at,
        now,
        skew_seconds,
    )?;
    if request.requested_lifetime_seconds.is_some_and(|v| v <= 0) {
        return Err(ActAsError::BadTerms(
            "requested lifetime must be positive".into(),
        ));
    }
    if request
        .requested_renewal_window_seconds
        .is_some_and(|v| v < 0)
    {
        return Err(ActAsError::BadTerms(
            "requested renewal window must not be negative".into(),
        ));
    }
    if let Some(claim) = &request.grantee_handle_claim {
        let Some(app) = &request.grantee.application else {
            return Err(ActAsError::BadHandleClaim(
                "a local-RP grantee has no account to name".into(),
            ));
        };
        check_handle_claim_subject(claim, app)?;
    }
    if request.nonce.is_empty() || request.callback_url.is_empty() {
        return Err(ActAsError::Decode(
            "nonce and callback_url are required".into(),
        ));
    }
    verify_grantee_proof(
        &signed.proof,
        &envelope_signature_input(GRANT_REQUEST_TAG, &signed.request),
        &request.grantee,
        grantee_instance_keys,
        now,
        skew_seconds,
    )?;
    Ok(request)
}

// ---------------------------------------------------------------------------
// Issued terms
// ---------------------------------------------------------------------------

/// The home domain's bounds for one grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainTermBounds {
    pub default_lifetime_seconds: i64,
    pub max_lifetime_seconds: i64,
    pub max_renewal_window_seconds: i64,
}

impl Default for DomainTermBounds {
    fn default() -> Self {
        Self {
            default_lifetime_seconds: DEFAULT_LIFETIME_SECONDS,
            max_lifetime_seconds: DEFAULT_MAX_LIFETIME_SECONDS,
            max_renewal_window_seconds: DEFAULT_MAX_RENEWAL_WINDOW_SECONDS,
        }
    }
}

impl DomainTermBounds {
    /// Refuse a configuration in which the default exceeds the maximum, or a
    /// value is out of range.
    pub fn validate(&self) -> Result<(), ActAsError> {
        if self.default_lifetime_seconds <= 0 || self.max_lifetime_seconds <= 0 {
            return Err(ActAsError::BadTerms("lifetimes must be positive".into()));
        }
        if self.default_lifetime_seconds > self.max_lifetime_seconds {
            return Err(ActAsError::BadTerms(
                "default lifetime exceeds the maximum".into(),
            ));
        }
        if self.max_renewal_window_seconds < 0 {
            return Err(ActAsError::BadTerms(
                "maximum renewal window must not be negative".into(),
            ));
        }
        Ok(())
    }
}

/// What the consent screen offers: starting values and the most the user can
/// choose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfferedTerms {
    pub default_lifetime_seconds: i64,
    pub max_lifetime_seconds: i64,
    pub default_renewal_window_seconds: i64,
    pub max_renewal_window_seconds: i64,
}

/// The consent screen's starting values and limits.
///
/// The grantee's request is a ceiling, never a floor. An absent requested
/// lifetime sets no ceiling, and the screen starts at the domain default. An
/// absent renewal window means 0.
pub fn offered_terms(
    requested_lifetime_seconds: Option<i64>,
    requested_renewal_window_seconds: Option<i64>,
    bounds: &DomainTermBounds,
) -> OfferedTerms {
    let max_lifetime = requested_lifetime_seconds
        .map_or(bounds.max_lifetime_seconds, |r| {
            r.min(bounds.max_lifetime_seconds)
        })
        .max(1);
    let default_lifetime = requested_lifetime_seconds
        .unwrap_or(bounds.default_lifetime_seconds)
        .min(max_lifetime)
        .max(1);
    let max_window = requested_renewal_window_seconds
        .unwrap_or(0)
        .min(bounds.max_renewal_window_seconds)
        .max(0);
    OfferedTerms {
        default_lifetime_seconds: default_lifetime,
        max_lifetime_seconds: max_lifetime,
        default_renewal_window_seconds: max_window,
        max_renewal_window_seconds: max_window,
    }
}

/// The issued lifetime and renewal window: the user's choice, never above the
/// offered maximum. A choice above the maximum is an error, not a silent cap,
/// so a tampered form fails visibly.
pub fn issued_terms(
    offered: &OfferedTerms,
    chosen_lifetime_seconds: i64,
    chosen_renewal_window_seconds: i64,
) -> Result<(i64, i64), ActAsError> {
    if chosen_lifetime_seconds <= 0 || chosen_lifetime_seconds > offered.max_lifetime_seconds {
        return Err(ActAsError::BadTerms(
            "lifetime is outside the offered range".into(),
        ));
    }
    if chosen_renewal_window_seconds < 0
        || chosen_renewal_window_seconds > offered.max_renewal_window_seconds
    {
        return Err(ActAsError::BadTerms(
            "renewal window is outside the offered range".into(),
        ));
    }
    Ok((chosen_lifetime_seconds, chosen_renewal_window_seconds))
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

/// Everything the home domain needs to build a first grant.
pub struct NewGrant<'a> {
    pub grant_id: &'a str,
    pub user_id: &'a str,
    pub subject_domain: &'a str,
    pub grantee: &'a GranteeRef,
    pub audience: &'a ApplicationRef,
    pub scope_set: &'a SignedActAsScopeSet,
    pub approved_scope: &'a [String],
    pub lifetime_seconds: i64,
    pub renewal_window_seconds: i64,
    pub now: DateTime<Utc>,
}

/// Build the first grant of a series.
pub fn build_grant(new: &NewGrant<'_>) -> Result<ActAsGrant, ActAsError> {
    if new.lifetime_seconds <= 0 || new.renewal_window_seconds < 0 {
        return Err(ActAsError::BadTerms("terms out of range".into()));
    }
    let issued_at = format_time(new.now);
    let expires = new.now + Duration::seconds(new.lifetime_seconds);
    let renewable_until = expires + Duration::seconds(new.renewal_window_seconds);
    Ok(ActAsGrant {
        grant_id: new.grant_id.to_string(),
        user_id: new.user_id.to_string(),
        subject_domain: new.subject_domain.to_string(),
        grantee: new.grantee.clone(),
        audience: new.audience.clone(),
        scope_set: new.scope_set.clone(),
        approved_scope: new.approved_scope.to_vec(),
        issued_at: issued_at.clone(),
        expires_at: format_time(expires),
        series_issued_at: issued_at,
        renewable_until: format_time(renewable_until),
        device_fingerprint: None,
    })
}

/// The home domain signs a grant with one or more of its signing keys.
pub fn sign_grant(
    grant: &ActAsGrant,
    signers: &[ClaimSigner<'_>],
) -> Result<SignedActAsGrant, ActAsError> {
    let bytes = crate::generated::encode_act_as_grant(grant);
    let message = envelope_signature_input(GRANT_TAG, &bytes);
    let mut signatures = Vec::with_capacity(signers.len());
    for signer in signers {
        signatures.push(ClaimSignature {
            domain: signer.domain.to_string(),
            signed_by_key_id: signer.key_id.to_string(),
            signature: crypto::sign_with_algorithm(
                signer.algorithm,
                &message,
                signer.private_key_bytes,
            )?,
        });
    }
    Ok(SignedActAsGrant {
        grant: bytes,
        signatures,
    })
}

/// Decode a grant without verifying it.
pub fn decode_grant(signed: &SignedActAsGrant) -> Result<ActAsGrant, ActAsError> {
    crate::generated::decode_act_as_grant(&signed.grant)
        .map_err(|e| ActAsError::Decode(e.to_string()))
}

fn verify_domain_signature(
    message: &[u8],
    signatures: &[ClaimSignature],
    domain_keys: &[DomainPublicKey],
    domain: &str,
) -> Result<(), ActAsError> {
    for sig in signatures {
        if sig.domain != domain {
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
        if crypto::resolve_and_verify(&key.algorithm, message, &sig.signature, &key.public_key)
            .is_ok()
        {
            return Ok(());
        }
    }
    Err(ActAsError::UntrustedSigner)
}

/// Verify a grant's home-domain signature and internal consistency.
///
/// `domain_keys` are the keys of the grant's `subject_domain`, from that
/// domain's anchor. This does not check expiry, revocation, the audience, or
/// the scope set's signature. [`verify_credential`] does all of those.
pub fn verify_grant_signature(
    signed: &SignedActAsGrant,
    domain_keys: &[DomainPublicKey],
) -> Result<ActAsGrant, ActAsError> {
    let grant = decode_grant(signed)?;
    check_grantee(&grant.grantee)?;
    if grant.device_fingerprint.is_some() {
        return Err(ActAsError::DeviceBindingUnsupported);
    }
    verify_domain_signature(
        &envelope_signature_input(GRANT_TAG, &signed.grant),
        &signed.signatures,
        domain_keys,
        &grant.subject_domain,
    )?;
    Ok(grant)
}

// ---------------------------------------------------------------------------
// Refresh and renewal
// ---------------------------------------------------------------------------

/// What a refresh should return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshDecision {
    /// Return the stored grant bytes. No new signature.
    Stored,
    /// Sign a renewed grant with these times.
    Renew {
        issued_at: String,
        expires_at: String,
    },
}

/// Decide whether a refresh renews the grant.
///
/// The current grant must not have expired: an expired grant cannot be
/// renewed, and the grantee must ask the user again. While the grant keeps
/// more than one half of its life, the stored bytes are returned. A renewal
/// happens only before `renewable_until`, and only when it would extend the
/// expiry. Otherwise the stored grant is returned. A renewed grant expires at
/// `min(now + lifetime, renewable_until)`.
pub fn refresh_decision(
    grant: &ActAsGrant,
    lifetime_seconds: i64,
    now: DateTime<Utc>,
) -> Result<RefreshDecision, ActAsError> {
    let issued = parse_time(&grant.issued_at)?;
    let expires = parse_time(&grant.expires_at)?;
    let renewable_until = parse_time(&grant.renewable_until)?;
    if now >= expires {
        return Err(ActAsError::GrantExpired);
    }
    if expires <= issued {
        return Ok(RefreshDecision::Stored);
    }
    let half = issued + (expires - issued) / 2;
    if now < half || now >= renewable_until {
        return Ok(RefreshDecision::Stored);
    }
    let new_expires = (now + Duration::seconds(lifetime_seconds)).min(renewable_until);
    if new_expires <= expires {
        return Ok(RefreshDecision::Stored);
    }
    Ok(RefreshDecision::Renew {
        issued_at: format_time(now),
        expires_at: format_time(new_expires),
    })
}

/// A renewal changes only `issued_at` and `expires_at`.
pub fn renewed_grant(grant: &ActAsGrant, issued_at: String, expires_at: String) -> ActAsGrant {
    ActAsGrant {
        issued_at,
        expires_at,
        ..grant.clone()
    }
}

/// The grantee signs a refresh request.
pub fn sign_refresh_request(
    request: &ActAsRefreshRequest,
    signer: &GranteeSigner<'_>,
) -> Result<SignedActAsRefreshRequest, ActAsError> {
    check_grantee(&request.grantee)?;
    let bytes = crate::generated::encode_act_as_refresh_request(request);
    let proof = signer.prove(&envelope_signature_input(REFRESH_REQUEST_TAG, &bytes))?;
    Ok(SignedActAsRefreshRequest {
        request: bytes,
        proof,
    })
}

/// Decode a refresh request without verifying it.
pub fn decode_refresh_request(
    signed: &SignedActAsRefreshRequest,
) -> Result<ActAsRefreshRequest, ActAsError> {
    crate::generated::decode_act_as_refresh_request(&signed.request)
        .map_err(|e| ActAsError::Decode(e.to_string()))
}

/// The home domain verifies a refresh request against the stored grant's
/// grantee. The request's grantee must equal the grant's.
pub fn verify_refresh_request(
    signed: &SignedActAsRefreshRequest,
    grant_grantee: &GranteeRef,
    grantee_instance_keys: &[ApplicationKeyRef],
    now: DateTime<Utc>,
    skew_seconds: i64,
) -> Result<ActAsRefreshRequest, ActAsError> {
    let request = decode_refresh_request(signed)?;
    if !same_grantee(&request.grantee, grant_grantee) {
        return Err(ActAsError::Mismatch("grantee"));
    }
    check_window(
        &request.requested_at,
        &request.expires_at,
        now,
        skew_seconds,
    )?;
    verify_grantee_proof(
        &signed.proof,
        &envelope_signature_input(REFRESH_REQUEST_TAG, &signed.request),
        grant_grantee,
        grantee_instance_keys,
        now,
        skew_seconds,
    )?;
    Ok(request)
}

// ---------------------------------------------------------------------------
// Presentations and audience verification
// ---------------------------------------------------------------------------

/// The grantee builds the credential for one call to the audience.
pub fn present(
    grant: &SignedActAsGrant,
    audience: &ApplicationRef,
    request_digest: &[u8],
    presented_at: DateTime<Utc>,
    nonce: &[u8],
    signer: &GranteeSigner<'_>,
) -> Result<ActAsCredential, ActAsError> {
    let presentation = ActAsPresentation {
        grant_hash: grant_hash(&grant.grant),
        audience: audience.clone(),
        request_digest: request_digest.to_vec(),
        presented_at: format_time(presented_at),
        nonce: nonce.to_vec(),
    };
    let bytes = crate::generated::encode_act_as_presentation(&presentation);
    let proof = signer.prove(&envelope_signature_input(PRESENTATION_TAG, &bytes))?;
    Ok(ActAsCredential {
        grant: grant.clone(),
        presentation: SignedActAsPresentation {
            presentation: bytes,
            proof,
        },
    })
}

/// What the audience supplies to verify a credential. Every key list is
/// already verified by the caller: domain keys from the issuer's anchor, and
/// application keys from verified attestations.
pub struct AudienceContext<'a> {
    /// The verifier's own application. Never read from the request.
    pub own_application: &'a ApplicationRef,
    /// The verifier's own attested keys, for the instance that signed the
    /// scope set. Resolve with [`credential_scope_set_signer`].
    pub own_scope_set_keys: &'a [ApplicationKeyRef],
    /// Signing keys of the grant's `subject_domain`.
    pub issuer_domain_keys: &'a [DomainPublicKey],
    /// Attested keys of the grantee instance that signed the presentation.
    /// Resolve with [`credential_signer_instance`]. Ignored for a local-RP
    /// grantee.
    pub grantee_instance_keys: &'a [ApplicationKeyRef],
    /// The digest of this request, as the audience's protocol defines it.
    pub expected_request_digest: &'a [u8],
    /// Grant ids the verifier holds a valid revocation for.
    pub revoked_grant_ids: &'a [String],
    /// Largest accepted age of a presentation, in seconds.
    pub max_presentation_age_seconds: i64,
    pub now: DateTime<Utc>,
    pub skew_seconds: i64,
    /// How to treat scope-set signatures by keys revoked since.
    pub revoked_key_policy: RevokedKeyPolicy,
}

/// A credential the audience accepted.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedActAs {
    pub grant_id: String,
    /// `user_id@subject_domain`.
    pub user_id: String,
    pub subject_domain: String,
    pub grantee: GranteeRef,
    pub signer: VerifiedGranteeSigner,
    /// The only scope the audience's policy may act on.
    pub approved_scope: Vec<String>,
    pub expires_at: String,
    /// The presentation nonce. The audience owns replay protection.
    pub nonce: Vec<u8>,
}

/// The grantee instance whose key signed a credential's presentation, so the
/// audience can resolve its attested keys before [`verify_credential`]. None
/// for a local-RP grantee.
pub fn credential_signer_instance(credential: &ActAsCredential) -> Option<&str> {
    credential
        .presentation
        .proof
        .application_instance_id
        .as_deref()
}

/// The audience instance whose key signed the embedded scope set.
pub fn credential_scope_set_signer(credential: &ActAsCredential) -> Result<String, ActAsError> {
    Ok(decode_grant(&credential.grant)?
        .scope_set
        .signer_instance_id)
}

/// The audience's verification checklist. Every step must pass:
///
/// 1. The grant's home-domain signature verifies.
/// 2. The grant's audience is the verifier.
/// 3. The grant is inside its validity window.
/// 4. The presentation was signed by a key of the grantee.
/// 5. The presentation binds this grant, this audience, and this request,
///    and is fresh.
/// 6. The embedded scope set was signed by the verifier, names the same
///    grantee, and contains every approved scope. Its expiry is NOT checked.
/// 7. The verifier holds no revocation for the grant.
pub fn verify_credential(
    credential: &ActAsCredential,
    ctx: &AudienceContext<'_>,
) -> Result<VerifiedActAs, ActAsError> {
    // 1
    let grant = verify_grant_signature(&credential.grant, ctx.issuer_domain_keys)?;
    // 2
    if !same_application(&grant.audience, ctx.own_application) {
        return Err(ActAsError::Mismatch("audience"));
    }
    // 3
    let issued = parse_time(&grant.issued_at)?;
    let expires = parse_time(&grant.expires_at)?;
    let skew = Duration::seconds(ctx.skew_seconds);
    if ctx.now + skew < issued {
        return Err(ActAsError::RequestExpired);
    }
    if ctx.now - skew >= expires {
        return Err(ActAsError::GrantExpired);
    }
    // 4
    let signed = &credential.presentation;
    let signer = verify_grantee_proof(
        &signed.proof,
        &envelope_signature_input(PRESENTATION_TAG, &signed.presentation),
        &grant.grantee,
        ctx.grantee_instance_keys,
        ctx.now,
        ctx.skew_seconds,
    )?;
    // 5
    let presentation = crate::generated::decode_act_as_presentation(&signed.presentation)
        .map_err(|e| ActAsError::Decode(e.to_string()))?;
    if presentation.grant_hash != grant_hash(&credential.grant.grant) {
        return Err(ActAsError::Mismatch("grant_hash"));
    }
    if !same_application(&presentation.audience, ctx.own_application) {
        return Err(ActAsError::Mismatch("presentation.audience"));
    }
    if presentation.request_digest != ctx.expected_request_digest {
        return Err(ActAsError::Mismatch("request_digest"));
    }
    let presented_at = parse_time(&presentation.presented_at)?;
    if presented_at > ctx.now + skew
        || presented_at + Duration::seconds(ctx.max_presentation_age_seconds) + skew < ctx.now
    {
        return Err(ActAsError::RequestExpired);
    }
    // 6
    let set = verify_scope_set(
        &grant.scope_set,
        ctx.own_application,
        ctx.own_scope_set_keys,
        ctx.revoked_key_policy,
    )?;
    if !same_grantee(&set.grantee, &grant.grantee) {
        return Err(ActAsError::Mismatch("scope_set.grantee"));
    }
    check_approved_scope(&set, &grant.approved_scope)?;
    // 7
    if ctx.revoked_grant_ids.iter().any(|id| id == &grant.grant_id) {
        return Err(ActAsError::GrantRevoked);
    }
    Ok(VerifiedActAs {
        user_id: format!("{}@{}", grant.user_id, grant.subject_domain),
        grant_id: grant.grant_id,
        subject_domain: grant.subject_domain,
        grantee: grant.grantee,
        signer,
        approved_scope: grant.approved_scope,
        expires_at: grant.expires_at,
        nonce: presentation.nonce,
    })
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

/// The home domain signs a grant revocation.
pub fn sign_grant_revocation(
    revocation: &ActAsGrantRevocation,
    signers: &[ClaimSigner<'_>],
) -> Result<SignedActAsGrantRevocation, ActAsError> {
    let bytes = crate::generated::encode_act_as_grant_revocation(revocation);
    let message = envelope_signature_input(GRANT_REVOCATION_TAG, &bytes);
    let mut signatures = Vec::with_capacity(signers.len());
    for signer in signers {
        signatures.push(ClaimSignature {
            domain: signer.domain.to_string(),
            signed_by_key_id: signer.key_id.to_string(),
            signature: crypto::sign_with_algorithm(
                signer.algorithm,
                &message,
                signer.private_key_bytes,
            )?,
        });
    }
    Ok(SignedActAsGrantRevocation {
        revocation: bytes,
        signatures,
    })
}

/// Verify a grant revocation against the issuing domain's keys.
pub fn verify_grant_revocation(
    signed: &SignedActAsGrantRevocation,
    domain_keys: &[DomainPublicKey],
    expected_domain: &str,
) -> Result<ActAsGrantRevocation, ActAsError> {
    let revocation = crate::generated::decode_act_as_grant_revocation(&signed.revocation)
        .map_err(|e| ActAsError::Decode(e.to_string()))?;
    if revocation.subject_domain != expected_domain {
        return Err(ActAsError::Mismatch("subject_domain"));
    }
    parse_time(&revocation.revoked_at)?;
    verify_domain_signature(
        &envelope_signature_input(GRANT_REVOCATION_TAG, &signed.revocation),
        &signed.signatures,
        domain_keys,
        expected_domain,
    )?;
    Ok(revocation)
}

/// The grant ids that a set of revocations validly revokes. Records that fail
/// verification are ignored.
pub fn revoked_grant_ids(
    revocations: &[SignedActAsGrantRevocation],
    domain_keys: &[DomainPublicKey],
    expected_domain: &str,
) -> Vec<String> {
    revocations
        .iter()
        .filter_map(|r| verify_grant_revocation(r, domain_keys, expected_domain).ok())
        .map(|r| r.grant_id)
        .collect()
}

#[cfg(test)]
mod tests;
