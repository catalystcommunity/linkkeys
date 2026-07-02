//! TOFU pin policy (SEC-01/02): compare a peer domain's freshly-resolved DNS
//! fingerprint set against the pinned set and apply the rotation / mismatch
//! rules. Because the trust anchor is unauthenticated DNS (no DNSSEC by design),
//! this is what turns "any attacker who wins DNS at any moment" into "an attacker
//! must win first contact and sustain it": once a domain is pinned, an unexpected
//! change is refused.
//!
//! Rules (per design):
//! - No pin yet -> pin now (first-seen) and trust.
//! - Fresh set == pinned set -> trust (touch last-checked).
//! - Exactly one pinned fingerprint gone (single-key rotation) -> accept: re-pin
//!   to the new set, retire the old cached key, audit it, and trust.
//! - More than one pinned fingerprint gone -> refuse (fail closed), enqueue an
//!   admin review item, and audit it. A human decides.

use crate::db::DbPool;

/// Outcome of a pin check. `is_trusted()` tells the caller whether it may go on
/// to trust the freshly-fetched keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinOutcome {
    /// No prior pin; the set was pinned now.
    FirstSeen,
    /// Fresh set matches the pin.
    Unchanged,
    /// A single-key rotation was accepted and re-pinned.
    Rotated,
    /// More than one key changed — refused; a review item was enqueued.
    Mismatch,
}

impl PinOutcome {
    pub fn is_trusted(self) -> bool {
        !matches!(self, PinOutcome::Mismatch)
    }
}

/// Normalize a fingerprint list into the canonical pinned form: unique, sorted,
/// comma-joined. Order/duplication in DNS must not change the pin identity.
fn canonicalize(fingerprints: &[String]) -> (Vec<String>, String) {
    let mut set: Vec<String> = fingerprints.to_vec();
    set.sort();
    set.dedup();
    let joined = set.join(",");
    (set, joined)
}

/// Compare `fresh` against the stored pin for `domain` and apply the policy,
/// writing pin/audit/review rows as needed. `fresh` is the DNS-resolved `fp=`
/// set. Never returns an error for a policy decision — a DB error is logged and
/// treated as Unchanged-trust only when there was already a matching pin;
/// otherwise it fails closed to Mismatch.
pub fn check_and_update_pin(pool: &DbPool, domain: &str, fresh: &[String]) -> PinOutcome {
    let (fresh_set, fresh_joined) = canonicalize(fresh);

    let existing = match pool.find_domain_pin(domain) {
        Ok(p) => p,
        Err(e) => {
            log::error!("pin lookup for {domain} failed: {e}");
            return PinOutcome::Mismatch; // fail closed
        }
    };

    let Some(pin) = existing else {
        // First contact: trust-on-first-use.
        if let Err(e) = pool.create_domain_pin(domain, &fresh_joined) {
            log::error!("pinning {domain} failed: {e}");
            return PinOutcome::Mismatch;
        }
        let _ = pool.write_audit(
            "pin.first_seen",
            Some(domain),
            Some("system"),
            Some(&fresh_joined),
        );
        return PinOutcome::FirstSeen;
    };

    let pinned_set: Vec<String> = pin
        .fingerprints
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();

    if pinned_set == fresh_set {
        let _ = pool.touch_domain_pin(domain);
        return PinOutcome::Unchanged;
    }

    // Which pinned fingerprints are no longer advertised? That is the dangerous
    // direction — additions alone are harmless key introductions.
    let removed: Vec<&String> = pinned_set
        .iter()
        .filter(|f| !fresh_set.contains(f))
        .collect();

    if removed.len() <= 1 {
        // Single-key rotation (or pure addition): accept and re-pin.
        if let Err(e) = pool.rotate_domain_pin(domain, &fresh_joined) {
            log::error!("re-pinning {domain} failed: {e}");
            return PinOutcome::Mismatch;
        }
        for fp in &removed {
            // Best-effort: retire any cached copy of the rotated-away key so it
            // is no longer honored for attested-claim verification (SEC-02).
            let _ = pool.revoke_peer_key_by_fingerprint(domain, fp);
        }
        let detail = format!("pinned=[{}] observed=[{}]", pin.fingerprints, fresh_joined);
        let _ = pool.write_audit("pin.rotated", Some(domain), Some("system"), Some(&detail));
        return PinOutcome::Rotated;
    }

    // More than one pinned key vanished at once: refuse and escalate to a human.
    let detail = format!("pinned=[{}] observed=[{}]", pin.fingerprints, fresh_joined);
    let _ = pool.enqueue_review("key_mismatch", Some(domain), Some(&detail));
    let _ = pool.write_audit("pin.mismatch", Some(domain), Some("system"), Some(&detail));
    log::warn!(
        "pin MISMATCH for {domain}: {} pinned fingerprints changed; refusing and queuing review",
        removed.len()
    );
    PinOutcome::Mismatch
}

/// Resolve a domain's current DNS `fp=` set and run the pin policy against it.
/// This is the reusable recheck entry point behind the lazy fetch-time hook, the
/// `linkkeys pins recheck` CLI command (cron-friendly), and the admin RPC op.
pub async fn recheck_domain(
    pool: &DbPool,
    net: &crate::net::Net,
    domain: &str,
) -> Result<PinOutcome, String> {
    let fps = crate::web::rp::fetch_dns_fingerprints(net, domain)
        .await
        .map_err(|e| format!("resolving _linkkeys for {domain} failed: {e}"))?;
    Ok(check_and_update_pin(pool, domain, &fps))
}

/// Recheck every currently-pinned domain. Returns per-domain outcomes (or the
/// resolution error). Intended to be driven on an interval (e.g. a 14-day cron).
pub async fn recheck_all(
    pool: &DbPool,
    net: &crate::net::Net,
) -> Vec<(String, Result<PinOutcome, String>)> {
    let domains: Vec<String> = match pool.list_domain_pins() {
        Ok(pins) => pins.into_iter().map(|p| p.domain).collect(),
        Err(e) => {
            log::error!("listing domain pins failed: {e}");
            return Vec::new();
        }
    };
    let mut out = Vec::with_capacity(domains.len());
    for d in domains {
        let r = recheck_domain(pool, net, &d).await;
        out.push((d, r));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::canonicalize;

    #[test]
    fn canonicalize_is_order_and_dup_independent() {
        let (_, a) = canonicalize(&["b".into(), "a".into(), "b".into()]);
        let (_, b) = canonicalize(&["a".into(), "b".into()]);
        assert_eq!(a, b);
        assert_eq!(a, "a,b");
    }
}
