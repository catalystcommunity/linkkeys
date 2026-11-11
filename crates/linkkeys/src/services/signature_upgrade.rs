//! Upgrade stored signatures to the current payload format.
//!
//! Release 0.14.1 (ded0471) moved every domain-separation tag to the
//! `-v1alpha` epoch, and earlier releases changed the claim payload twice. The
//! alpha rule is "re-sign, do not accept old formats", so verifiers accept only
//! the current format. Signatures stored before those changes stopped
//! verifying, and nothing re-signed them. A relying party that verifies claim
//! signatures then rejects the claims with `signature_invalid`.
//!
//! This module checks every stored record that this domain signed:
//!
//! - claims about local users (`claim_signatures`), active only;
//! - consent grants (`consent_grants.signed_grant`), active only;
//! - issued key revocation certificates (`issued_revocations.cert`).
//!
//! Encryption-key vouches have their own repair,
//! [`crate::services::domain_keys::revouch_encryption_keys`].
//!
//! For each record:
//!
//! 1. If the current verifier accepts the local signatures, it is **current**.
//! 2. Else, if every local signature verifies with a key of this domain
//!    (active or retired) under the current or a known older format, it is
//!    **stale**. With a passphrase, it is re-signed with the active signing
//!    keys. All signed fields stay the same.
//! 3. Else it is **unverifiable** and is not changed. Re-signing it would make
//!    a tampered row valid.
//!
//! Signatures of other domains cannot be re-signed here. They stay as they
//! are, and the record is counted as **foreign**.
//!
//! The pass is idempotent: after a repair, a second pass finds every repaired
//! record current. Two replicas that start together can both re-sign a claim;
//! the claim then has two sets of valid signatures, which is harmless. The pass
//! verifies every signature of every active record, so start-up time grows
//! with the number of claims.

use std::fmt;

use liblinkkeys::claims::{verify_claim_signatures, ClaimSigner, ClaimSpec, DomainKeySet};
use liblinkkeys::consent::{sign_consent, verify_consent, ConsentSpec};
use liblinkkeys::generated::types::{
    ApplicationRef, Claim, ClaimSignature, DomainPublicKey, SignedConsentGrant,
};
use liblinkkeys::legacy_signatures::{claim_provenance, consent_provenance, revocation_provenance};
use liblinkkeys::revocation::{
    build_revocation_certificate, verify_revocation_certificate, RevocationSpec, REVOCATION_QUORUM,
};

use crate::claim_signing::{active_signers, sign_with_active, ActiveSigner};
use crate::conversions::get_domain_name;
use crate::db::DbPool;

/// The result of one pass for one kind of record.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct KindReport {
    /// Records looked at.
    pub checked: usize,
    /// Records the current verifier accepts.
    pub current: usize,
    /// Records this domain signed in an older format, or with a key that no
    /// longer verifies. A repair re-signs them.
    pub stale: Vec<String>,
    /// Stale records that this pass re-signed.
    pub resigned: Vec<String>,
    /// Records with no proof that this domain signed them. Not changed.
    pub unverifiable: Vec<String>,
    /// Records that carry signatures of other domains. Those signatures are
    /// left as they are.
    pub foreign: Vec<String>,
    /// Claims whose stored `attested_at` was not RFC3339, so the re-sign
    /// recorded a new attestation time.
    pub reattested: Vec<String>,
    /// Stale records that could not be re-signed, with the reason.
    pub failed: Vec<(String, String)>,
}

impl KindReport {
    /// True when nothing needs an operator: every record that this domain
    /// signed verifies under the current format.
    pub fn is_clean(&self) -> bool {
        self.stale.len() == self.resigned.len()
            && self.unverifiable.is_empty()
            && self.failed.is_empty()
    }
}

impl fmt::Display for KindReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "checked {}, current {}, stale {}, re-signed {}, unverifiable {}, foreign {}",
            self.checked,
            self.current,
            self.stale.len(),
            self.resigned.len(),
            self.unverifiable.len(),
            self.foreign.len()
        )?;
        if !self.reattested.is_empty() {
            write!(f, ", new attestation time {}", self.reattested.len())?;
        }
        if !self.failed.is_empty() {
            write!(f, ", failed {}", self.failed.len())?;
        }
        Ok(())
    }
}

/// The result of one pass over every kind of record.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UpgradeReport {
    pub claims: KindReport,
    pub consent_grants: KindReport,
    pub revocations: KindReport,
}

impl UpgradeReport {
    pub fn is_clean(&self) -> bool {
        self.claims.is_clean() && self.consent_grants.is_clean() && self.revocations.is_clean()
    }

    /// `(name, report)` for each kind, in a fixed order.
    pub fn kinds(&self) -> [(&'static str, &KindReport); 3] {
        [
            ("claims", &self.claims),
            ("consent grants", &self.consent_grants),
            ("key revocations", &self.revocations),
        ]
    }
}

/// Decrypts the active signing keys on first use, so a pass that finds
/// nothing stale never touches private keys.
struct Signers<'a> {
    pool: &'a DbPool,
    passphrase: Option<&'a str>,
    loaded: Option<Result<Vec<ActiveSigner>, String>>,
}

impl<'a> Signers<'a> {
    /// The active signers, or `None` in a check-only pass. A failure to load
    /// them is recorded against `id` in `report`, and also gives `None`.
    fn for_resign(&mut self, report: &mut KindReport, id: &str) -> Option<&[ActiveSigner]> {
        let passphrase = self.passphrase?;
        let pool = self.pool;
        let loaded = self.loaded.get_or_insert_with(|| {
            let keys = pool
                .list_active_domain_keys()
                .map_err(|e| format!("could not list active domain keys: {e}"))?;
            active_signers(&keys, passphrase.as_bytes()).map_err(|e| e.to_string())
        });
        match loaded {
            Ok(signers) => Some(signers),
            Err(e) => {
                report.failed.push((id.to_string(), e.clone()));
                None
            }
        }
    }
}

fn claim_signers<'a>(domain: &'a str, signers: &'a [ActiveSigner]) -> Vec<ClaimSigner<'a>> {
    signers
        .iter()
        .map(|s| ClaimSigner {
            domain,
            key_id: &s.key_id,
            algorithm: s.algorithm,
            private_key_bytes: &s.private_key,
        })
        .collect()
}

/// Check every stored signed record, and re-sign the stale ones when
/// `passphrase` is given. `None` only reports (`linkkeys domain
/// verify-signatures`). Errors only when the records cannot be listed.
pub fn run(pool: &DbPool, passphrase: Option<&str>) -> Result<UpgradeReport, String> {
    let domain = get_domain_name();
    let keys: Vec<DomainPublicKey> = pool
        .list_all_domain_keys()
        .map_err(|e| format!("could not list domain keys: {e}"))?
        .iter()
        .map(Into::into)
        .collect();
    let mut signers = Signers {
        pool,
        passphrase,
        loaded: None,
    };
    Ok(UpgradeReport {
        claims: upgrade_claims(pool, &domain, &keys, &mut signers)?,
        consent_grants: upgrade_consent_grants(pool, &domain, &keys, &mut signers)?,
        revocations: upgrade_revocations(pool, &domain, &keys, &mut signers)?,
    })
}

/// Split signatures into this domain's and other domains'.
fn split_signatures(
    signatures: &[ClaimSignature],
    domain: &str,
) -> (Vec<ClaimSignature>, Vec<ClaimSignature>) {
    signatures.iter().cloned().partition(|s| s.domain == domain)
}

fn is_active(revoked_at: Option<&str>, expires_at: Option<&str>) -> bool {
    revoked_at.is_none()
        && expires_at
            .and_then(|e| chrono::DateTime::parse_from_rfc3339(e).ok())
            .is_none_or(|e| e > chrono::Utc::now())
}

fn upgrade_claims(
    pool: &DbPool,
    domain: &str,
    keys: &[DomainPublicKey],
    signers: &mut Signers<'_>,
) -> Result<KindReport, String> {
    let keysets = [DomainKeySet {
        domain: domain.to_string(),
        keys: keys.to_vec(),
    }];
    let rows = pool
        .list_all_claims()
        .map_err(|e| format!("could not list claims: {e}"))?;
    let mut report = KindReport::default();

    for row in rows
        .iter()
        .filter(|r| is_active(r.revoked_at.as_deref(), r.expires_at.as_deref()))
    {
        report.checked += 1;
        let claim: Claim = row.into();
        let (local, foreign) = split_signatures(&claim.signatures, domain);
        if !foreign.is_empty() {
            report.foreign.push(row.id.clone());
        }
        if local.is_empty() {
            continue;
        }
        let local_claim = Claim {
            signatures: local,
            ..claim.clone()
        };
        if verify_claim_signatures(&local_claim, domain, &keysets).is_ok() {
            report.current += 1;
            continue;
        }
        let Some(provenance) = claim_provenance(&local_claim, domain, keys) else {
            report.unverifiable.push(row.id.clone());
            continue;
        };
        log::debug!("claim {} is signed in format {:?}", row.id, provenance);
        report.stale.push(row.id.clone());

        let Some(active) = signers.for_resign(&mut report, &row.id) else {
            continue;
        };

        // `attested_at` is signed and is served exactly as stored. A value
        // that is not RFC3339 (SQLite rows from before 2026-07-02 copied
        // `created_at`, "YYYY-MM-DD HH:MM:SS") fails every verifier's key
        // check, so the re-sign makes a new attestation at whole seconds.
        let new_attested_at = chrono::DateTime::parse_from_rfc3339(&claim.attested_at)
            .is_err()
            .then(|| {
                use chrono::Timelike;
                chrono::Utc::now()
                    .with_nanosecond(0)
                    .expect("zeroing nanoseconds cannot fail")
                    .to_rfc3339()
            });
        let attested_at = new_attested_at.as_deref().unwrap_or(&claim.attested_at);

        let signed = match sign_with_active(
            &ClaimSpec {
                claim_id: &claim.claim_id,
                claim_type: &claim.claim_type,
                claim_value: &claim.claim_value,
                user_id: &claim.user_id,
                subject_domain: domain,
                expires_at: claim.expires_at.as_deref(),
                attested_at,
            },
            active,
        ) {
            Ok(c) => c,
            Err(e) => {
                report.failed.push((row.id.clone(), e.to_string()));
                continue;
            }
        };
        if let Err(e) = verify_claim_signatures(&signed, domain, &keysets) {
            report.failed.push((
                row.id.clone(),
                format!("re-signed claim does not verify: {e}"),
            ));
            continue;
        }

        let mut signatures = signed.signatures;
        signatures.extend(foreign);
        if let Err(e) = pool.resign_claim(&row.id, new_attested_at.as_deref(), &signatures) {
            report
                .failed
                .push((row.id.clone(), format!("could not store signatures: {e}")));
            continue;
        }
        if new_attested_at.is_some() {
            let _ = pool.write_audit(
                "claim.reattested",
                Some(&row.id),
                Some("signature-upgrade"),
                Some("stored attested_at was not RFC3339; re-signed with a new attestation time"),
            );
            report.reattested.push(row.id.clone());
        }
        report.resigned.push(row.id.clone());
    }
    Ok(report)
}

fn upgrade_consent_grants(
    pool: &DbPool,
    domain: &str,
    keys: &[DomainPublicKey],
    signers: &mut Signers<'_>,
) -> Result<KindReport, String> {
    let keysets = [DomainKeySet {
        domain: domain.to_string(),
        keys: keys.to_vec(),
    }];
    let rows = pool
        .list_all_active_consent_grants()
        .map_err(|e| format!("could not list consent grants: {e}"))?;
    let mut report = KindReport::default();

    for row in &rows {
        report.checked += 1;
        let decoded = liblinkkeys::generated::decode_signed_consent_grant(&row.signed_grant)
            .ok()
            .and_then(|signed| {
                let grant = liblinkkeys::generated::decode_consent_grant(&signed.grant).ok()?;
                Some((signed, grant))
            });
        let Some((signed, grant)) = decoded else {
            report.unverifiable.push(row.id.clone());
            continue;
        };
        let application = match (&row.app_subject_user_id, &row.app_application_id) {
            (Some(subject_user_id), Some(application_id)) => Some(ApplicationRef {
                subject_user_id: subject_user_id.clone(),
                subject_domain: row.audience.clone(),
                application_id: application_id.clone(),
            }),
            _ => None,
        };
        // The signed grant must be the grant this row stands for.
        if grant.user_id != row.user_id
            || grant.subject_domain != domain
            || grant.audience != row.audience
            || grant.application != application
        {
            report.unverifiable.push(row.id.clone());
            continue;
        }

        let (local, foreign) = split_signatures(&signed.signatures, domain);
        if !foreign.is_empty() {
            report.foreign.push(row.id.clone());
        }
        if local.is_empty() {
            continue;
        }
        let local_signed = SignedConsentGrant {
            grant: signed.grant.clone(),
            signatures: local,
        };
        if verify_consent(
            &local_signed,
            domain,
            &row.audience,
            application.as_ref(),
            &keysets,
        )
        .is_ok()
        {
            report.current += 1;
            continue;
        }
        if consent_provenance(&local_signed, &grant, domain, keys).is_none() {
            report.unverifiable.push(row.id.clone());
            continue;
        }
        report.stale.push(row.id.clone());

        let Some(active) = signers.for_resign(&mut report, &row.id) else {
            continue;
        };
        let mut resigned = match sign_consent(
            &ConsentSpec {
                grant_id: &grant.grant_id,
                user_id: &grant.user_id,
                subject_domain: domain,
                audience: &grant.audience,
                claim_types: &grant.claim_types,
                issued_at: &grant.issued_at,
                expires_at: &grant.expires_at,
                application: application.as_ref(),
            },
            &claim_signers(domain, active),
        ) {
            Ok(s) => s,
            Err(e) => {
                report.failed.push((row.id.clone(), e.to_string()));
                continue;
            }
        };
        if let Err(e) = verify_consent(
            &resigned,
            domain,
            &row.audience,
            application.as_ref(),
            &keysets,
        ) {
            report.failed.push((
                row.id.clone(),
                format!("re-signed grant does not verify: {e}"),
            ));
            continue;
        }
        resigned.signatures.extend(foreign);
        let bytes = liblinkkeys::generated::encode_signed_consent_grant(&resigned);
        if let Err(e) = pool.update_consent_grant_signature(&row.id, &bytes) {
            report
                .failed
                .push((row.id.clone(), format!("could not store grant: {e}")));
            continue;
        }
        report.resigned.push(row.id.clone());
    }
    Ok(report)
}

fn upgrade_revocations(
    pool: &DbPool,
    domain: &str,
    keys: &[DomainPublicKey],
    signers: &mut Signers<'_>,
) -> Result<KindReport, String> {
    let rows = pool
        .list_issued_revocations_since(None)
        .map_err(|e| format!("could not list issued revocations: {e}"))?;
    let mut report = KindReport::default();

    for row in &rows {
        report.checked += 1;
        let Ok(cert) = liblinkkeys::generated::decode_revocation_certificate(&row.cert) else {
            report.unverifiable.push(row.id.clone());
            continue;
        };
        if cert.target_key_id != row.target_key_id
            || cert.target_fingerprint != row.target_fingerprint
        {
            report.unverifiable.push(row.id.clone());
            continue;
        }
        if cert.signatures.iter().any(|s| s.domain != domain) {
            report.foreign.push(row.id.clone());
        }
        if verify_revocation_certificate(&cert, keys, domain).is_ok() {
            report.current += 1;
            continue;
        }
        if revocation_provenance(&cert, domain, keys).is_none() {
            report.unverifiable.push(row.id.clone());
            continue;
        }
        report.stale.push(row.id.clone());

        let Some(active) = signers.for_resign(&mut report, &row.id) else {
            continue;
        };
        let siblings: Vec<ClaimSigner> = claim_signers(domain, active)
            .into_iter()
            .filter(|s| s.key_id != cert.target_key_id)
            .collect();
        if siblings.len() < REVOCATION_QUORUM {
            report.failed.push((
                row.id.clone(),
                format!(
                    "only {} active sibling signing key(s); a certificate needs {}",
                    siblings.len(),
                    REVOCATION_QUORUM
                ),
            ));
            continue;
        }
        let resigned = match build_revocation_certificate(
            &RevocationSpec {
                target_key_id: &cert.target_key_id,
                target_fingerprint: &cert.target_fingerprint,
                revoked_at: &cert.revoked_at,
            },
            &siblings,
        ) {
            Ok(c) => c,
            Err(e) => {
                report.failed.push((row.id.clone(), e.to_string()));
                continue;
            }
        };
        if let Err(e) = verify_revocation_certificate(&resigned, keys, domain) {
            report.failed.push((
                row.id.clone(),
                format!("re-signed certificate does not verify: {e}"),
            ));
            continue;
        }
        let bytes = liblinkkeys::generated::encode_revocation_certificate(&resigned);
        if let Err(e) = pool.update_issued_revocation_cert(&row.id, &bytes) {
            report
                .failed
                .push((row.id.clone(), format!("could not store certificate: {e}")));
            continue;
        }
        report.resigned.push(row.id.clone());
    }
    Ok(report)
}

/// Startup transform: run a repair pass and log the result. Never fatal. Without
/// `DOMAIN_KEY_PASSPHRASE` the pass only reports.
pub fn upgrade_on_startup(pool: &DbPool) {
    let passphrase = std::env::var("DOMAIN_KEY_PASSPHRASE").ok();
    let report = match run(pool, passphrase.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            log::error!("signature upgrade failed: {e}");
            return;
        }
    };
    for (kind, r) in report.kinds() {
        for id in &r.unverifiable {
            log::warn!(
                "signature upgrade: {kind} {id}: no signature of this domain verifies in a \
                 known format; not re-signed"
            );
        }
        for id in &r.foreign {
            log::info!(
                "signature upgrade: {kind} {id}: carries signatures of other domains; \
                 left as they are"
            );
        }
        for id in &r.reattested {
            log::warn!(
                "signature upgrade: {kind} {id}: stored attested_at was not RFC3339; \
                 re-signed with a new attestation time"
            );
        }
        for (id, reason) in &r.failed {
            log::error!("signature upgrade: {kind} {id}: not re-signed: {reason}");
        }
        let waiting = r.stale.len() - r.resigned.len();
        if passphrase.is_none() && waiting > 0 {
            log::warn!(
                "signature upgrade: {waiting} {kind} need a re-sign but DOMAIN_KEY_PASSPHRASE \
                 is not set; they do not verify until a server with the passphrase starts"
            );
        }
        if r.checked > 0 {
            log::info!("signature upgrade: {kind}: {r}");
        }
    }
}
