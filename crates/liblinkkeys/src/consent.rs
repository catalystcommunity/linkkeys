//! Consent (claim-release) grants.
//!
//! A consent grant is a user's standing authorization for one relying party
//! (the `audience`) to receive a specific set of claim types. It is the scoped,
//! signed object that turns "release everything" into "release exactly what the
//! user agreed to for this audience".
//!
//! Structurally it is a sibling of [`crate::claims::Claim`]: same domain-signed
//! envelope, same `user_id@subject_domain` subject binding, plus an `audience`.
//! It reuses the claim signing primitives ([`ClaimSigner`], [`DomainKeySet`],
//! and the shared signature quorum) so consent verification cannot drift from
//! claim verification.
//!
//! This module is pure: no I/O, no clock authority beyond `Utc::now()` for
//! expiry (mirroring [`crate::claims`]). The server is responsible for
//! persisting grants, resolving keys, and applying the result.

use crate::claims::{verify_signature_quorum, ClaimError, ClaimSigner, DomainKeySet};
use crate::crypto::CryptoError;
use crate::generated::types::{
    Claim, ClaimRequest, ClaimSignature, ConsentGrant, SignedConsentGrant,
};
use chrono::Utc;
use std::collections::BTreeSet;
use std::fmt;

/// Default lifetime of a consent grant: one year. The server may override this
/// (see `CONSENT_GRANT_TTL_SECONDS`); consent is re-affirmed when a login finds
/// the standing grant expired.
pub const DEFAULT_CONSENT_TTL_SECONDS: i64 = 365 * 24 * 60 * 60;

/// Domain-separation tag + version for the consent grant signature payload.
/// Bumping this invalidates old grant signatures by design.
const CONSENT_PAYLOAD_TAG: &str = "linkkeys-consent-v1alpha";

/// What can go wrong verifying a [`SignedConsentGrant`].
#[derive(Debug)]
pub enum ConsentError {
    /// The grant bytes are not a valid CBOR-encoded [`ConsentGrant`].
    Malformed,
    /// The grant carries no signatures.
    Unsigned,
    /// The grant's own `subject_domain`/`audience` do not match the
    /// authoritative context the verifier supplied. (Tampering is also caught
    /// cryptographically, but this yields a precise error and prevents using an
    /// otherwise-valid grant in the wrong context.)
    ContextMismatch,
    /// The grant has been revoked.
    Revoked,
    /// The grant has expired (past its signed `expires_at`).
    Expired,
    /// The grant's `expires_at` could not be parsed.
    BadExpiry,
    /// A signing domain failed the cryptographic quorum (key missing/revoked/
    /// expired, unsupported algorithm, or bad signature).
    Signature(ClaimError),
}

impl fmt::Display for ConsentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConsentError::Malformed => write!(f, "consent grant is not valid CBOR"),
            ConsentError::Unsigned => write!(f, "consent grant has no signatures"),
            ConsentError::ContextMismatch => {
                write!(f, "consent grant subject/audience does not match context")
            }
            ConsentError::Revoked => write!(f, "consent grant has been revoked"),
            ConsentError::Expired => write!(f, "consent grant has expired"),
            ConsentError::BadExpiry => write!(f, "consent grant has an invalid expires_at"),
            ConsentError::Signature(e) => write!(f, "consent grant signature: {}", e),
        }
    }
}

impl std::error::Error for ConsentError {}

/// Canonicalize a set of claim types: deduplicated and sorted, so the signed
/// payload is independent of input order and multiplicity.
fn canonical_types(types: &[String]) -> Vec<String> {
    types
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<&str>>()
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// Build the canonical bytes a single signature covers for a consent grant.
///
/// Deterministic CBOR over a domain-separated tuple. The subject is the full
/// identity `user_id@subject_domain` (a uuid is only unique within its home
/// domain), and `audience` is bound so a grant authorizing RP-X cannot be
/// replayed to authorize RP-Y. `claim_types` must be canonical (sorted/deduped).
/// `signing_domain` — the attestor for *this* signature — is bound per-signature.
/// `revoked_at` is deliberately NOT signed: it is a mutable post-issuance field.
#[allow(clippy::too_many_arguments)]
fn consent_sign_payload(
    grant_id: &str,
    user_id: &str,
    subject_domain: &str,
    audience: &str,
    claim_types: &[String],
    issued_at: &str,
    expires_at: &str,
    signing_domain: &str,
) -> Vec<u8> {
    let subject = format!("{}@{}", user_id, subject_domain);
    let payload = (
        CONSENT_PAYLOAD_TAG,
        grant_id,
        subject.as_str(),
        audience,
        claim_types,
        issued_at,
        expires_at,
        signing_domain,
    );
    let mut out = Vec::new();
    ciborium::ser::into_writer(&payload, &mut out)
        .expect("CBOR serialization of consent payload cannot fail");
    out
}

/// The terms of a consent grant: what the user authorized, independent of *who*
/// attests it. `claim_types` is canonicalized (sorted/deduped) before signing.
pub struct ConsentSpec<'a> {
    pub grant_id: &'a str,
    pub user_id: &'a str,
    /// The subject's home domain — `user_id@subject_domain` is the full identity.
    pub subject_domain: &'a str,
    /// The relying party authorized to receive these claims.
    pub audience: &'a str,
    pub claim_types: &'a [String],
    pub issued_at: &'a str,
    pub expires_at: &'a str,
}

/// Sign a consent grant with one or more domain keys, producing a
/// [`SignedConsentGrant`] carrying one [`ClaimSignature`] per signer. The home
/// domain attests it; under key-based auth a user key may co-sign by passing an
/// additional signer. An empty signer set yields an unsigned grant, which
/// [`verify_consent`] rejects.
pub fn sign_consent(
    spec: &ConsentSpec<'_>,
    signers: &[ClaimSigner<'_>],
) -> Result<SignedConsentGrant, CryptoError> {
    let claim_types = canonical_types(spec.claim_types);

    let grant = ConsentGrant {
        grant_id: spec.grant_id.to_string(),
        user_id: spec.user_id.to_string(),
        subject_domain: spec.subject_domain.to_string(),
        audience: spec.audience.to_string(),
        claim_types: claim_types.clone(),
        issued_at: spec.issued_at.to_string(),
        expires_at: spec.expires_at.to_string(),
        revoked_at: None,
    };

    let grant_bytes = crate::generated::encode_consent_grant(&grant);

    let mut signatures = Vec::with_capacity(signers.len());
    for signer in signers {
        let payload = consent_sign_payload(
            spec.grant_id,
            spec.user_id,
            spec.subject_domain,
            spec.audience,
            &claim_types,
            spec.issued_at,
            spec.expires_at,
            signer.domain,
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

    Ok(SignedConsentGrant {
        grant: grant_bytes,
        signatures,
    })
}

/// Verify a signed consent grant and return the decoded [`ConsentGrant`].
///
/// `subject_domain` and `audience` are the authoritative context the verifier
/// holds (its own domain; the RP it is releasing claims to) — never taken from
/// attacker-controlled input. The grant's own fields must match them, and the
/// per-domain signature quorum must pass over the reconstructed payload, and the
/// grant must be neither revoked nor expired. `domain_keys` supplies candidate
/// keys per signing domain; a missing domain yields
/// [`ConsentError::Signature`]`(`[`ClaimError::DomainKeysUnavailable`]`)` so the
/// caller can fetch and retry. Performs no I/O.
pub fn verify_consent(
    signed: &SignedConsentGrant,
    subject_domain: &str,
    audience: &str,
    domain_keys: &[DomainKeySet],
) -> Result<ConsentGrant, ConsentError> {
    let grant = crate::generated::decode_consent_grant(&signed.grant[..])
        .map_err(|_| ConsentError::Malformed)?;

    if signed.signatures.is_empty() {
        return Err(ConsentError::Unsigned);
    }

    if grant.subject_domain != subject_domain || grant.audience != audience {
        return Err(ConsentError::ContextMismatch);
    }

    let claim_types = canonical_types(&grant.claim_types);
    verify_signature_quorum(&signed.signatures, domain_keys, |signing_domain| {
        consent_sign_payload(
            &grant.grant_id,
            &grant.user_id,
            subject_domain,
            audience,
            &claim_types,
            &grant.issued_at,
            &grant.expires_at,
            signing_domain,
        )
    })
    .map_err(ConsentError::Signature)?;

    if grant.revoked_at.is_some() {
        return Err(ConsentError::Revoked);
    }
    let expires = chrono::DateTime::parse_from_rfc3339(&grant.expires_at)
        .map_err(|_| ConsentError::BadExpiry)?;
    if Utc::now() > expires {
        return Err(ConsentError::Expired);
    }

    Ok(grant)
}

/// Home-domain policy that overrides user choice for an audience. `forced_allow`
/// claim types are released whenever requested even if the user would decline;
/// `forced_deny` are never released regardless of user choice. Deny wins over
/// allow. Both hold claim_type strings. The user is shown these (locked) rows by
/// a spec-compliant IDP, but cannot toggle them.
#[derive(Debug, Default, Clone)]
pub struct DomainPolicy {
    pub forced_allow: Vec<String>,
    pub forced_deny: Vec<String>,
}

/// Where a row's locked disposition comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDisposition {
    /// User decides freely.
    User,
    /// Home domain forces release; the user cannot opt out.
    ForcedAllow,
    /// Home domain forbids release; the user cannot opt in.
    ForcedDeny,
}

/// One row of a consent screen: a single requested claim type, annotated with
/// everything a UI needs to render and default it. UI-agnostic — any transport
/// (browser, native agent, …) renders the same rows however it wishes.
#[derive(Debug, Clone)]
pub struct ConsentScreenRow {
    pub claim_type: String,
    /// Datatype the RP expects (advisory; from the request).
    pub datatype: String,
    /// The RP marked this claim required for the app to function.
    pub required: bool,
    /// The user actually holds a claim of this type (releasable).
    pub available: bool,
    /// This type was in a prior standing grant for this audience (pre-check it).
    pub previously_granted: bool,
    /// Home-domain policy fixes this row; the user cannot change it.
    pub locked: bool,
    pub policy: PolicyDisposition,
}

impl ConsentScreenRow {
    /// The checkbox state a compliant UI should start with: policy decides when
    /// locked, otherwise default to a previously-granted choice. Required rows
    /// are NOT auto-granted — consent must be an affirmative act. The RP/app
    /// decides whether a missing required claim rejects or degrades the session.
    pub fn default_granted(&self) -> bool {
        match self.policy {
            PolicyDisposition::ForcedAllow => true,
            PolicyDisposition::ForcedDeny => false,
            PolicyDisposition::User => self.previously_granted,
        }
    }
}

/// The full set of rows to render for a first-contact (or re-consent) screen.
pub struct ConsentScreen {
    pub rows: Vec<ConsentScreenRow>,
}

/// Compute the consent screen for an RP's request, given what the user holds, an
/// optional prior standing grant for this audience, and home-domain policy. Rows
/// are the union of requested (required ∪ optional) claim types, sorted, each
/// annotated. Policy-forced rows are marked `locked`.
pub fn resolve_consent_screen(
    req: &ClaimRequest,
    available: &[Claim],
    prior: Option<&ConsentGrant>,
    policy: &DomainPolicy,
) -> ConsentScreen {
    let required: BTreeSet<&str> = req.required.iter().map(|r| r.claim_type.as_str()).collect();
    let forced_allow: BTreeSet<&str> = policy.forced_allow.iter().map(String::as_str).collect();
    let forced_deny: BTreeSet<&str> = policy.forced_deny.iter().map(String::as_str).collect();
    let prior_types: BTreeSet<&str> = prior
        .map(|g| g.claim_types.iter().map(String::as_str).collect())
        .unwrap_or_default();
    let available_types: BTreeSet<&str> = available.iter().map(|c| c.claim_type.as_str()).collect();

    // Datatype per requested claim type. If a type appears in both required and
    // optional, required's datatype wins (looked up first).
    let mut datatypes: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
    for r in req.optional.iter().chain(req.required.iter()) {
        datatypes.insert(r.claim_type.as_str(), r.datatype.as_str());
    }

    let rows = datatypes
        .iter()
        .map(|(&claim_type, &datatype)| {
            let policy_disp = if forced_deny.contains(claim_type) {
                PolicyDisposition::ForcedDeny
            } else if forced_allow.contains(claim_type) {
                PolicyDisposition::ForcedAllow
            } else {
                PolicyDisposition::User
            };
            ConsentScreenRow {
                claim_type: claim_type.to_string(),
                datatype: datatype.to_string(),
                required: required.contains(claim_type),
                available: available_types.contains(claim_type),
                previously_granted: prior_types.contains(claim_type),
                locked: policy_disp != PolicyDisposition::User,
                policy: policy_disp,
            }
        })
        .collect();

    ConsentScreen { rows }
}

/// Compute the effective authorized claim-type set to record in a grant, from
/// the user's choices and home-domain policy, bounded by what the RP requested:
///
/// `authorized = ((user_choices ∪ forced_allow) ∩ requested) − forced_deny`
///
/// Choices outside the requested set are ignored (defensive); deny always wins
/// over allow and over user choice. Result is canonical (sorted/deduped).
pub fn compute_authorized_claims(
    req: &ClaimRequest,
    user_choices: &[String],
    policy: &DomainPolicy,
) -> Vec<String> {
    let requested: BTreeSet<&str> = req
        .required
        .iter()
        .chain(req.optional.iter())
        .map(|r| r.claim_type.as_str())
        .collect();
    let forced_deny: BTreeSet<&str> = policy.forced_deny.iter().map(String::as_str).collect();

    let mut authorized: BTreeSet<&str> = BTreeSet::new();
    for c in user_choices.iter().map(String::as_str) {
        if requested.contains(c) && !forced_deny.contains(c) {
            authorized.insert(c);
        }
    }
    for a in policy.forced_allow.iter().map(String::as_str) {
        if requested.contains(a) && !forced_deny.contains(a) {
            authorized.insert(a);
        }
    }

    authorized.into_iter().map(str::to_string).collect()
}

/// Filter a set of claims to those whose `claim_type` is in `authorized`. Applied
/// at every claim-release boundary (TCP `get-user-info`, HTTP userinfo) so
/// scoping is identical everywhere. An empty `authorized` releases nothing.
pub fn scope_claims(claims: &[Claim], authorized: &[String]) -> Vec<Claim> {
    let allow: BTreeSet<&str> = authorized.iter().map(String::as_str).collect();
    claims
        .iter()
        .filter(|c| allow.contains(c.claim_type.as_str()))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{fingerprint, generate_keypair, SigningAlgorithm, ALGORITHM_ED25519};
    use crate::generated::types::{DomainPublicKey, RequestedClaim};

    const HOME: &str = "todandlorna.com";
    const RP: &str = "app.example";
    const USER: &str = "user-123";

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

    fn signer<'a>(key_id: &'a str, sk: &'a [u8]) -> ClaimSigner<'a> {
        ClaimSigner {
            domain: HOME,
            key_id,
            algorithm: SigningAlgorithm::Ed25519,
            private_key_bytes: sk,
        }
    }

    fn keyset(keys: Vec<DomainPublicKey>) -> Vec<DomainKeySet> {
        vec![DomainKeySet {
            domain: HOME.to_string(),
            keys,
        }]
    }

    fn types(ts: &[&str]) -> Vec<String> {
        ts.iter().map(|s| s.to_string()).collect()
    }

    fn issued_and_expiry() -> (String, String) {
        let now = Utc::now();
        (
            now.to_rfc3339(),
            (now + chrono::Duration::seconds(DEFAULT_CONSENT_TTL_SECONDS)).to_rfc3339(),
        )
    }

    fn signed_grant(
        key_id: &str,
        sk: &[u8],
        claim_types: &[String],
        audience: &str,
    ) -> SignedConsentGrant {
        let (issued_at, expires_at) = issued_and_expiry();
        sign_consent(
            &ConsentSpec {
                grant_id: "grant-1",
                user_id: USER,
                subject_domain: HOME,
                audience,
                claim_types,
                issued_at: &issued_at,
                expires_at: &expires_at,
            },
            &[signer(key_id, sk)],
        )
        .unwrap()
    }

    #[test]
    fn test_consent_sign_verify_roundtrip() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let signed = signed_grant("key-1", &sk, &types(&["email", "display_name"]), RP);
        let grant = verify_consent(
            &signed,
            HOME,
            RP,
            &keyset(vec![make_domain_key("key-1", &pk)]),
        )
        .unwrap();
        assert_eq!(grant.audience, RP);
        // Canonicalized order.
        assert_eq!(grant.claim_types, types(&["display_name", "email"]));
    }

    #[test]
    fn test_consent_wrong_audience_context_mismatch() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let signed = signed_grant("key-1", &sk, &types(&["email"]), RP);
        // Verifier expects a different audience than the grant authorizes.
        assert!(matches!(
            verify_consent(
                &signed,
                HOME,
                "other.example",
                &keyset(vec![make_domain_key("key-1", &pk)])
            ),
            Err(ConsentError::ContextMismatch)
        ));
    }

    #[test]
    fn test_consent_wrong_subject_domain_context_mismatch() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let signed = signed_grant("key-1", &sk, &types(&["email"]), RP);
        assert!(matches!(
            verify_consent(
                &signed,
                "evil.example",
                RP,
                &keyset(vec![make_domain_key("key-1", &pk)])
            ),
            Err(ConsentError::ContextMismatch)
        ));
    }

    #[test]
    fn test_consent_tampered_claim_types_fails() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let signed = signed_grant("key-1", &sk, &types(&["email"]), RP);
        // Decode, widen the authorized set, re-encode the grant bytes. The
        // signature is over the original set, so verification must fail.
        let mut grant = crate::generated::decode_consent_grant(&signed.grant[..]).unwrap();
        grant.claim_types = types(&["email", "ssn"]);
        let grant_bytes = crate::generated::encode_consent_grant(&grant);
        let tampered = SignedConsentGrant {
            grant: grant_bytes,
            signatures: signed.signatures,
        };
        assert!(matches!(
            verify_consent(
                &tampered,
                HOME,
                RP,
                &keyset(vec![make_domain_key("key-1", &pk)])
            ),
            Err(ConsentError::Signature(ClaimError::SignatureInvalid))
        ));
    }

    #[test]
    fn test_consent_cross_audience_replay_rejected() {
        // A grant authorizing RP cannot be re-presented to authorize another RP,
        // even by an attacker who also flips the grant's audience field: audience
        // is bound into the signature.
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let signed = signed_grant("key-1", &sk, &types(&["email"]), RP);
        let mut grant = crate::generated::decode_consent_grant(&signed.grant[..]).unwrap();
        grant.audience = "other.example".to_string();
        let grant_bytes = crate::generated::encode_consent_grant(&grant);
        let tampered = SignedConsentGrant {
            grant: grant_bytes,
            signatures: signed.signatures,
        };
        // Now context matches the flipped audience, but the signature was made
        // over RP, so the quorum fails.
        assert!(matches!(
            verify_consent(
                &tampered,
                HOME,
                "other.example",
                &keyset(vec![make_domain_key("key-1", &pk)])
            ),
            Err(ConsentError::Signature(ClaimError::SignatureInvalid))
        ));
    }

    #[test]
    fn test_consent_expired_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let past = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let issued = (Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
        let signed = sign_consent(
            &ConsentSpec {
                grant_id: "grant-1",
                user_id: USER,
                subject_domain: HOME,
                audience: RP,
                claim_types: &types(&["email"]),
                issued_at: &issued,
                expires_at: &past,
            },
            &[signer("key-1", &sk)],
        )
        .unwrap();
        assert!(matches!(
            verify_consent(
                &signed,
                HOME,
                RP,
                &keyset(vec![make_domain_key("key-1", &pk)])
            ),
            Err(ConsentError::Expired)
        ));
    }

    #[test]
    fn test_consent_revoked_rejected() {
        let (pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let signed = signed_grant("key-1", &sk, &types(&["email"]), RP);
        let mut grant = crate::generated::decode_consent_grant(&signed.grant[..]).unwrap();
        grant.revoked_at = Some(Utc::now().to_rfc3339());
        let grant_bytes = crate::generated::encode_consent_grant(&grant);
        let revoked = SignedConsentGrant {
            grant: grant_bytes,
            signatures: signed.signatures,
        };
        // revoked_at is not signed, so the signature still verifies; the grant is
        // rejected on the revocation check.
        assert!(matches!(
            verify_consent(
                &revoked,
                HOME,
                RP,
                &keyset(vec![make_domain_key("key-1", &pk)])
            ),
            Err(ConsentError::Revoked)
        ));
    }

    #[test]
    fn test_consent_unsigned_rejected() {
        let (issued_at, expires_at) = issued_and_expiry();
        let signed = sign_consent(
            &ConsentSpec {
                grant_id: "grant-1",
                user_id: USER,
                subject_domain: HOME,
                audience: RP,
                claim_types: &types(&["email"]),
                issued_at: &issued_at,
                expires_at: &expires_at,
            },
            &[],
        )
        .unwrap();
        assert!(matches!(
            verify_consent(&signed, HOME, RP, &keyset(vec![])),
            Err(ConsentError::Unsigned)
        ));
    }

    #[test]
    fn test_consent_domain_keys_unavailable() {
        let (_pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let signed = signed_grant("key-1", &sk, &types(&["email"]), RP);
        assert!(matches!(
            verify_consent(&signed, HOME, RP, &[]),
            Err(ConsentError::Signature(ClaimError::DomainKeysUnavailable(
                _
            )))
        ));
    }

    #[test]
    fn test_consent_malformed_rejected() {
        let signed = SignedConsentGrant {
            grant: vec![0xff, 0x00, 0x13, 0x37],
            signatures: vec![],
        };
        assert!(matches!(
            verify_consent(&signed, HOME, RP, &[]),
            Err(ConsentError::Malformed)
        ));
    }

    // ---- pure policy / selection logic ----

    fn req(required: &[(&str, &str)], optional: &[(&str, &str)]) -> ClaimRequest {
        let mk = |xs: &[(&str, &str)]| {
            xs.iter()
                .map(|(ct, dt)| RequestedClaim {
                    claim_type: ct.to_string(),
                    datatype: dt.to_string(),
                })
                .collect()
        };
        ClaimRequest {
            required: mk(required),
            optional: mk(optional),
        }
    }

    #[test]
    fn test_compute_authorized_user_choices_bounded_by_request() {
        let r = req(&[("email", "email")], &[("display_name", "text")]);
        let policy = DomainPolicy::default();
        // User picks display_name plus an un-requested type, which is dropped.
        let out = compute_authorized_claims(&r, &types(&["display_name", "ssn"]), &policy);
        assert_eq!(out, types(&["display_name"]));
    }

    #[test]
    fn test_compute_authorized_forced_allow_added_deny_removed() {
        let r = req(
            &[("email", "email")],
            &[("display_name", "text"), ("avatar", "url")],
        );
        let policy = DomainPolicy {
            forced_allow: types(&["avatar"]),
            forced_deny: types(&["email"]),
        };
        // User grants email + display_name; policy forces avatar in, email out.
        let out = compute_authorized_claims(&r, &types(&["email", "display_name"]), &policy);
        assert_eq!(out, types(&["avatar", "display_name"]));
    }

    #[test]
    fn test_compute_authorized_deny_beats_forced_allow() {
        let r = req(&[], &[("x", "text")]);
        let policy = DomainPolicy {
            forced_allow: types(&["x"]),
            forced_deny: types(&["x"]),
        };
        assert!(compute_authorized_claims(&r, &types(&["x"]), &policy).is_empty());
    }

    #[test]
    fn test_resolve_screen_annotates_rows() {
        let r = req(
            &[("email", "email")],
            &[("display_name", "text"), ("avatar", "url")],
        );
        let policy = DomainPolicy {
            forced_deny: types(&["avatar"]),
            ..Default::default()
        };
        // User already granted email before; holds email + display_name claims.
        let prior = ConsentGrant {
            grant_id: "g0".into(),
            user_id: USER.into(),
            subject_domain: HOME.into(),
            audience: RP.into(),
            claim_types: types(&["email"]),
            issued_at: Utc::now().to_rfc3339(),
            expires_at: Utc::now().to_rfc3339(),
            revoked_at: None,
        };
        let available = vec![
            Claim {
                claim_id: "c1".into(),
                user_id: USER.into(),
                claim_type: "email".into(),
                claim_value: b"a@b.com".to_vec(),
                signatures: vec![],
                attested_at: Utc::now().to_rfc3339(),
                created_at: Utc::now().to_rfc3339(),
                expires_at: None,
                revoked_at: None,
            },
            Claim {
                claim_id: "c2".into(),
                user_id: USER.into(),
                claim_type: "display_name".into(),
                claim_value: b"Tod".to_vec(),
                signatures: vec![],
                attested_at: Utc::now().to_rfc3339(),
                created_at: Utc::now().to_rfc3339(),
                expires_at: None,
                revoked_at: None,
            },
        ];
        let screen = resolve_consent_screen(&r, &available, Some(&prior), &policy);
        let row = |ct: &str| {
            screen
                .rows
                .iter()
                .find(|r| r.claim_type == ct)
                .unwrap()
                .clone()
        };

        let email = row("email");
        assert!(email.required && email.available && email.previously_granted && !email.locked);
        assert!(email.default_granted());

        let avatar = row("avatar");
        assert!(avatar.locked && avatar.policy == PolicyDisposition::ForcedDeny);
        assert!(!avatar.default_granted());
        assert!(!avatar.available); // user holds no avatar claim

        let dn = row("display_name");
        assert!(!dn.required && dn.available && !dn.previously_granted);
        assert!(!dn.default_granted());
    }

    #[test]
    fn test_scope_claims_filters_by_type() {
        let mk = |ct: &str| Claim {
            claim_id: format!("c-{ct}"),
            user_id: USER.into(),
            claim_type: ct.into(),
            claim_value: b"v".to_vec(),
            signatures: vec![],
            attested_at: Utc::now().to_rfc3339(),
            created_at: Utc::now().to_rfc3339(),
            expires_at: None,
            revoked_at: None,
        };
        let claims = vec![mk("email"), mk("ssn"), mk("display_name")];
        let scoped = scope_claims(&claims, &types(&["email", "display_name"]));
        let got: BTreeSet<&str> = scoped.iter().map(|c| c.claim_type.as_str()).collect();
        assert_eq!(got, ["display_name", "email"].into_iter().collect());

        assert!(scope_claims(&claims, &[]).is_empty());
    }
}
