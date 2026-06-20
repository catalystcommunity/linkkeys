//! Attested (lane-C) claims: claims signed by a THIRD-PARTY issuer about one of
//! our accounts. Per docs/claim-trust-verification.md the issuer's signature is
//! kept and exposed — we never strip it and re-attest in our own name — so any
//! verifier can check it against the issuer's public keys (trust but verify).
//!
//! This module holds the synchronous primitives: build the key sets for a
//! claim's signer domains (our own keys for our domain, the append-only peer-key
//! cache for others), verify a stored claim, and gate-then-store an externally
//! signed claim. Resolving a brand-new issuer's keys over the network (and
//! caching them) is the deposit layer that sits on top of these.

use std::collections::BTreeSet;

use liblinkkeys::claims::{ClaimSigner, DomainKeySet};
use liblinkkeys::generated::services::ServiceError;
use liblinkkeys::generated::types::{Claim, DomainPublicKey, SignedSigningRequest};
use liblinkkeys::signing_request::{sign_signing_request, SigningRequestSpec};

use crate::conversions::get_domain_name;
use crate::db::{models, DbPool};

/// Default max validity for a minted signing request: 2 days. Generous on
/// purpose — a user without a portable device might print a QR at a library and
/// physically carry it to the issuer (e.g. a DMV), so a 1-hour window would be
/// hostile to people in low-device contexts. Override with
/// `SIGNING_REQUEST_TTL_SECONDS`.
const DEFAULT_SIGNING_REQUEST_TTL_SECONDS: i64 = 2 * 24 * 60 * 60;

fn signing_request_ttl_seconds() -> i64 {
    std::env::var("SIGNING_REQUEST_TTL_SECONDS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_SIGNING_REQUEST_TTL_SECONDS)
}

fn svc_err(code: i32, msg: &str) -> ServiceError {
    ServiceError {
        code,
        message: msg.to_string(),
    }
}

fn db_err(e: diesel::result::Error) -> ServiceError {
    log::error!("Database error: {}", e);
    svc_err(500, "Internal database error")
}

/// A claim's verification result for display — what it asserts, who signed it,
/// and whether every signer's signature checks out against that signer's keys.
#[derive(Debug, Clone)]
pub struct ClaimVerification {
    pub claim_type: String,
    pub value: String,
    pub signed_by: Vec<String>,
    pub verified: bool,
}

fn peer_to_public(p: &models::PeerKey) -> DomainPublicKey {
    DomainPublicKey {
        key_id: p.key_id.clone(),
        public_key: p.public_key.clone(),
        fingerprint: p.fingerprint.clone(),
        algorithm: p.algorithm.clone(),
        key_usage: p.key_usage.clone(),
        created_at: String::new(),
        expires_at: p.expires_at.clone(),
        revoked_at: p.revoked_at.clone(),
        signed_by_key_id: None,
        key_signature: None,
    }
}

/// The distinct domains that signed a claim.
fn signer_domains(claim: &Claim) -> Vec<String> {
    let mut set: BTreeSet<&str> = BTreeSet::new();
    for s in &claim.signatures {
        set.insert(s.domain.as_str());
    }
    set.into_iter().map(str::to_string).collect()
}

/// Resolve candidate keys for every domain that signed `claim`: our own active
/// domain keys for our domain, the peer-key cache for any other. A domain with
/// no resolvable keys yields an empty set, so its signatures read as unverified
/// (fail closed) rather than erroring.
fn build_keysets(pool: &DbPool, claim: &Claim) -> Vec<DomainKeySet> {
    let our = get_domain_name();
    signer_domains(claim)
        .into_iter()
        .map(|d| {
            let keys: Vec<DomainPublicKey> = if d == our {
                pool.list_active_domain_keys()
                    .unwrap_or_default()
                    .iter()
                    .map(DomainPublicKey::from)
                    .collect()
            } else {
                pool.list_peer_keys_for_domain(&d)
                    .unwrap_or_default()
                    .iter()
                    .map(peer_to_public)
                    .collect()
            };
            DomainKeySet { domain: d, keys }
        })
        .collect()
}

/// Base URL used to tell an issuer where to deposit the resulting signed claim.
fn public_origin() -> String {
    std::env::var("PUBLIC_ORIGIN").unwrap_or_else(|_| format!("https://{}", get_domain_name()))
}

/// Mint a home-domain-signed [`SignedSigningRequest`] for `subject_user_id`,
/// addressed to `issuer_domain`, asking it to attest `requested_types`. The user
/// pulls this from the API and conveys it to the issuer however they like
/// (base64 in a QR, a file, an HTTP POST). Signed with the domain's active keys.
pub fn mint_signing_request(
    pool: &DbPool,
    subject_user_id: &str,
    issuer_domain: &str,
    requested_types: &[String],
) -> Result<SignedSigningRequest, ServiceError> {
    let passphrase = std::env::var("DOMAIN_KEY_PASSPHRASE")
        .map_err(|_| svc_err(500, "DOMAIN_KEY_PASSPHRASE not set"))?;
    let domain_keys = pool.list_active_domain_keys().map_err(db_err)?;
    let signers = crate::claim_signing::active_signers(&domain_keys, passphrase.as_bytes())
        .map_err(|e| svc_err(500, &e.to_string()))?;

    let our = get_domain_name();
    let claim_signers: Vec<ClaimSigner> = signers
        .iter()
        .map(|s| ClaimSigner {
            domain: &our,
            key_id: &s.key_id,
            algorithm: s.algorithm,
            private_key_bytes: &s.private_key,
        })
        .collect();

    let request_id = uuid::Uuid::now_v7().to_string();
    let nonce = uuid::Uuid::now_v7().to_string();
    let issued_at = chrono::Utc::now().to_rfc3339();
    let expires_at = (chrono::Utc::now()
        + chrono::Duration::seconds(signing_request_ttl_seconds()))
    .to_rfc3339();
    // Where the issuer deposits the resulting claim: this domain's CBOR-RPC
    // carrier. The issuer normally resolves this from DNS, but we include it for
    // convenience / out-of-band issuers.
    let callback = format!("{}/csil/v1/rpc", public_origin());

    sign_signing_request(
        &SigningRequestSpec {
            request_id: &request_id,
            subject_user_id,
            subject_domain: &our,
            issuer_domain,
            requested_claim_types: requested_types,
            nonce: &nonce,
            issued_at: &issued_at,
            expires_at: &expires_at,
            callback: Some(&callback),
        },
        &claim_signers,
    )
    .map_err(|e| svc_err(500, &e.to_string()))
}

/// Issue (sign) a claim about a subject as THIS domain acting as the issuer.
/// Used by the receive/accept flow: after verifying a signing request, an
/// authorized operator signs the requested claim about `subject_user_id@subject_domain`
/// with our domain keys. The subject may be remote — `subject_domain` comes from
/// the (verified) request, bound into the signature. The result is handed back /
/// deposited at the subject's domain.
pub fn issue_attested_claim(
    pool: &DbPool,
    subject_user_id: &str,
    subject_domain: &str,
    claim_type: &str,
    value: &[u8],
) -> Result<Claim, ServiceError> {
    let passphrase = std::env::var("DOMAIN_KEY_PASSPHRASE")
        .map_err(|_| svc_err(500, "DOMAIN_KEY_PASSPHRASE not set"))?;
    let domain_keys = pool.list_active_domain_keys().map_err(db_err)?;
    let signers = crate::claim_signing::active_signers(&domain_keys, passphrase.as_bytes())
        .map_err(|e| svc_err(500, &e.to_string()))?;
    let our = get_domain_name();
    let claim_signers: Vec<ClaimSigner> = signers
        .iter()
        .map(|s| ClaimSigner {
            domain: &our,
            key_id: &s.key_id,
            algorithm: s.algorithm,
            private_key_bytes: &s.private_key,
        })
        .collect();
    let claim_id = uuid::Uuid::now_v7().to_string();
    liblinkkeys::claims::sign_claim(
        &liblinkkeys::claims::ClaimSpec {
            claim_id: &claim_id,
            claim_type,
            claim_value: value,
            user_id: subject_user_id,
            subject_domain,
            expires_at: None,
        },
        &claim_signers,
    )
    .map_err(|e| svc_err(500, &e.to_string()))
}

/// Verify a claim we hold: every signing domain must contribute a valid
/// signature from a currently-valid key of that domain (resolved from our keys /
/// the peer cache), and the claim itself must not be revoked/expired. The
/// "one-click verify" a viewer's IDP performs.
pub fn verify_stored_claim(pool: &DbPool, claim: &Claim) -> ClaimVerification {
    let our = get_domain_name();
    let sets = build_keysets(pool, claim);
    let verified = liblinkkeys::claims::verify_claim(claim, &our, &sets).is_ok();
    ClaimVerification {
        claim_type: claim.claim_type.clone(),
        value: String::from_utf8_lossy(&claim.claim_value).to_string(),
        signed_by: signer_domains(claim),
        verified,
    }
}

/// Accept an externally-signed claim about `subject_id` (an account UUID) and
/// store it verbatim (issuer signatures intact). Gated: at least one signing
/// domain must be a trusted issuer for the claim type, the signatures must
/// verify against keys already cached (caller resolves/caches them first for a
/// new issuer), and the claim's subject must match `subject_id`.
pub fn verify_and_store_attested(
    pool: &DbPool,
    subject_id: &str,
    claim: &Claim,
) -> Result<(), ServiceError> {
    if claim.user_id != subject_id {
        return Err(svc_err(400, "claim subject does not match the account"));
    }
    if claim.signatures.is_empty() {
        return Err(svc_err(400, "an attested claim must carry a signature"));
    }

    // Trust gate: we only admit an attestation from a domain the admin has
    // marked as a trusted issuer for this claim type.
    let trusted = pool
        .list_trusted_issuers_for(&claim.claim_type)
        .map_err(db_err)?;
    let trusted_set: BTreeSet<&str> = trusted.iter().map(String::as_str).collect();
    let from_trusted = signer_domains(claim)
        .iter()
        .any(|d| trusted_set.contains(d.as_str()));
    if !from_trusted {
        return Err(svc_err(
            403,
            &liblinkkeys::claim_policy::RejectionReason::SetterNotAuthorized.to_string(),
        ));
    }

    // Cryptographic verification against the resolved (cached) issuer keys.
    let our = get_domain_name();
    let sets = build_keysets(pool, claim);
    liblinkkeys::claims::verify_claim(claim, &our, &sets)
        .map_err(|_| svc_err(400, "the issuer signature did not verify"))?;

    let expires = claim
        .expires_at
        .as_deref()
        .map(|s| chrono::DateTime::parse_from_rfc3339(s).map(|dt| dt.with_timezone(&chrono::Utc)))
        .transpose()
        .map_err(|_| svc_err(400, "invalid expires_at"))?;

    pool.create_claim(
        &claim.claim_id,
        subject_id,
        &claim.claim_type,
        &claim.claim_value,
        &claim.signatures,
        expires,
    )
    .map_err(db_err)?;
    Ok(())
}
