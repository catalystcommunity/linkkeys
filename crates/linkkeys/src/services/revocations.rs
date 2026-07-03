//! Inter-domain revocation exchange (SEC-08).
//!
//! Issuer side: `recent_revocations_available` sets the signal on
//! `get-domain-keys`; `serve` answers `get-revocations`. Verifier side: `apply`
//! verifies fetched certs against the domain's current key set and records the
//! revocation on any cached peer key — at the DOMAIN'S asserted `revoked_at`
//! (which may be months before we asked), because that is the domain saying "do
//! not trust this key's signatures dated after this instant".
//!
//! Because a cert is self-authenticating (≥2 sibling signatures), fetching it
//! over an untrusted channel is safe: an attacker can only withhold one, never
//! forge one. Applying a revocation only ever REMOVES trust, so it needs no
//! human gate — but if a single fetch would revoke two or more of the domain's
//! *currently-active* keys, that is anomalous (with three equal keys you cannot
//! even sign two revocations), so it is additionally raised for human review.

use crate::db::DbPool;
use liblinkkeys::generated::types::{DomainPublicKey, RevocationCertificate};
use liblinkkeys::revocation::verify_revocation_certificate;

/// Issuer's "recent" window (days) for the get-domain-keys signal. Admin-tunable.
fn recent_window_days() -> i64 {
    std::env::var("LINKKEYS_REVOCATION_RECENT_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(14)
}

/// Verifier's default look-back (days) when it asks get-revocations with no
/// explicit `since`. Default ~6 months.
pub fn fetch_default_days() -> i64 {
    std::env::var("LINKKEYS_REVOCATION_FETCH_DEFAULT_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(180)
}

/// Whether this domain issued any revocation inside its recent window — the
/// `recent_revocations_available` signal on get-domain-keys.
pub fn recent_revocations_available(pool: &DbPool) -> bool {
    let since = chrono::Utc::now() - chrono::Duration::days(recent_window_days());
    pool.has_issued_revocations_since(since).unwrap_or(false)
}

/// Serve issued revocation certs for get-revocations. `since` (RFC3339) bounds
/// the result; when absent, defaults to the last `fetch_default_days()`.
pub fn serve(pool: &DbPool, since: Option<&str>) -> Vec<RevocationCertificate> {
    let cutoff = match since {
        Some(s) => chrono::DateTime::parse_from_rfc3339(s)
            .map(|d| d.with_timezone(&chrono::Utc))
            .ok(),
        None => Some(chrono::Utc::now() - chrono::Duration::days(fetch_default_days())),
    };
    let rows = pool
        .list_issued_revocations_since(cutoff)
        .unwrap_or_default();
    rows.iter()
        .filter_map(|r| liblinkkeys::generated::decode_revocation_certificate(&r.cert).ok())
        .collect()
}

/// Verify fetched revocation certs against `domain`'s current key set and record
/// each valid one on any cached peer key (at the cert's asserted `revoked_at`).
/// Returns the set of `key_id`s that were provably revoked, so the caller can
/// drop them from the freshly-trusted set for this interaction. If two or more
/// currently-active keys are revoked at once, a human review item is enqueued.
pub fn apply(
    pool: &DbPool,
    domain: &str,
    active_keys: &[DomainPublicKey],
    certs: &[RevocationCertificate],
) -> Vec<String> {
    let active_ids: std::collections::HashSet<&str> =
        active_keys.iter().map(|k| k.key_id.as_str()).collect();
    let mut revoked_ids: Vec<String> = Vec::new();

    for cert in certs {
        if verify_revocation_certificate(cert, active_keys, domain).is_err() {
            continue;
        }
        // Record on the cached peer key (SEC-02) at the domain's asserted time.
        let _ = pool.revoke_peer_key_by_key_id_at(domain, &cert.target_key_id, &cert.revoked_at);
        let _ = pool.write_audit(
            "revocation.applied",
            Some(domain),
            Some("system"),
            Some(&format!(
                "key {} revoked_at {}",
                cert.target_key_id, cert.revoked_at
            )),
        );
        if !revoked_ids.contains(&cert.target_key_id) {
            revoked_ids.push(cert.target_key_id.clone());
        }
    }

    // How many of the domain's CURRENTLY-active keys were just revoked? Two or
    // more is anomalous (you can't sign two revocations with three equal keys),
    // so flag it for a human even though the certs verified.
    let active_revoked = revoked_ids
        .iter()
        .filter(|id| active_ids.contains(id.as_str()))
        .count();
    if active_revoked >= 2 {
        let detail =
            format!("{active_revoked} currently-active keys revoked at once: {revoked_ids:?}");
        let _ = pool.enqueue_review("key_mismatch", Some(domain), Some(&detail));
        let _ = pool.write_audit(
            "revocation.mass",
            Some(domain),
            Some("system"),
            Some(&detail),
        );
        log::warn!("revocation MASS event for {domain}: {detail}");
    }

    revoked_ids
}
