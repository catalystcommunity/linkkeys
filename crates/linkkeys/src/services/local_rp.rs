//! DNS-less local RP identity: the decision layer over `crate::db::local_rp`'s
//! pure storage (see `dns-less-local-rp-design.md` at the repo root, Phase 4 —
//! server persistence). Three responsibilities:
//!
//! - The pending-queue guard: create-or-refresh a pending approval entry only
//!   from an authenticated domain user's login attempt (anonymous requests
//!   must never create queue entries — enforced by API shape below, not by a
//!   runtime flag), deduped by fingerprint, capped per domain.
//! - The status-transition matrix: pending to approved/denied, approved to
//!   revoked, denied to approved (an admin changed their mind); every other
//!   transition, including un-revoking, is rejected.
//! - Claim-get ticket issue/redeem/purge: redemption checks expiry and that
//!   the bound local RP is still `approved` (revocation kills outstanding
//!   tickets); tickets are multi-use within their window, so redemption never
//!   deletes the row.
//!
//! This mirrors the `crate::db::domain_pins` / `crate::services::pins` split:
//! `db::local_rp` is pure storage, this module is the policy.

use crate::db::models::LocalRp;
use crate::db::{local_rp as db, DbPool};

/// Per-domain cap on PENDING local RP entries (design doc: "cap pending
/// entries per domain so the queue cannot be flooded"). A deployment serves a
/// single domain, so this is simply a cap on the whole `local_rps` table's
/// pending count. Chosen as a generous but bounded ceiling for a
/// human-reviewed admin queue.
pub const MAX_PENDING_LOCAL_RPS: i64 = 100;

/// Per-user cap on PENDING local RP entries a single authenticated account
/// may have attributed to it (SEC M3: without this, one authenticated user
/// could occupy the entire global queue by itself, drowning out other
/// users' legitimate pending entries even though the global cap has room).
/// Deliberately much smaller than [`MAX_PENDING_LOCAL_RPS`] — a real user
/// trying a handful of local apps is normal; dozens from one account is not.
pub const MAX_PENDING_LOCAL_RPS_PER_USER: i64 = 5;

/// A single changed display/audit metadata field on an already-known
/// fingerprint. Metadata is never identity (approval keys on fingerprint
/// alone) — this is purely a signal for admins to notice, e.g. in an audit
/// log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataDrift {
    pub field: &'static str,
    pub previous: String,
    pub reported: String,
}

/// Result of a login-attempt-driven pending-queue touch.
#[derive(Debug, Clone)]
pub enum PendingAttemptOutcome {
    /// The fingerprint was never seen before; a new `pending` row was created.
    Created(LocalRp),
    /// The fingerprint was already known (any status); `last_seen_at` was
    /// refreshed and the latest reported metadata stored. `drift` is empty
    /// when nothing changed.
    Refreshed {
        local_rp: LocalRp,
        drift: Vec<MetadataDrift>,
    },
}

#[derive(Debug)]
pub enum PendingAttemptError {
    /// `authenticated_user_id` did not resolve to an active user. This is the
    /// enforcement point for "anonymous requests never create queue entries":
    /// the function requires a real, active user id — there is no code path
    /// that accepts an absent/unauthenticated caller.
    NotAuthenticated,
    /// The fingerprint is unseen and the per-domain pending cap
    /// (`MAX_PENDING_LOCAL_RPS`) has already been reached.
    PendingCapReached,
    /// The fingerprint is unseen and this authenticated user has already
    /// reached their own per-user pending cap
    /// (`MAX_PENDING_LOCAL_RPS_PER_USER`), even though the global cap still
    /// has room. Stops one authenticated account from occupying the whole
    /// pending-approval queue by itself.
    PerUserPendingCapReached,
    Db(diesel::result::Error),
}

impl From<diesel::result::Error> for PendingAttemptError {
    fn from(e: diesel::result::Error) -> Self {
        PendingAttemptError::Db(e)
    }
}

impl std::fmt::Display for PendingAttemptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PendingAttemptError::NotAuthenticated => {
                write!(f, "login attempt was not from an authenticated user")
            }
            PendingAttemptError::PendingCapReached => {
                write!(f, "pending local RP queue is at capacity")
            }
            PendingAttemptError::PerUserPendingCapReached => {
                write!(f, "this user's pending local RP queue is at capacity")
            }
            PendingAttemptError::Db(e) => write!(f, "database error: {}", e),
        }
    }
}

fn diff_metadata(
    existing: &LocalRp,
    app_name: &str,
    local_domain_hint: Option<&str>,
) -> Vec<MetadataDrift> {
    let mut drift = Vec::new();
    if existing.app_name != app_name {
        drift.push(MetadataDrift {
            field: "app_name",
            previous: existing.app_name.clone(),
            reported: app_name.to_string(),
        });
    }
    let existing_hint = existing.local_domain_hint.as_deref();
    if existing_hint != local_domain_hint {
        drift.push(MetadataDrift {
            field: "local_domain_hint",
            previous: existing_hint.unwrap_or_default().to_string(),
            reported: local_domain_hint.unwrap_or_default().to_string(),
        });
    }
    drift
}

/// Record a login attempt through an unknown-or-known local RP fingerprint.
/// Only ever called after the caller has authenticated `authenticated_user_id`
/// against this domain — the design's "a pending approval entry is created
/// only when an authenticated user of the domain actually attempts a login
/// through the unknown local RP" is enforced here by requiring a real,
/// active, non-empty user id: there is no way to call this on behalf of an
/// anonymous request short of fabricating a valid user id, which a caller
/// that hasn't authenticated anyone cannot do.
///
/// - Unseen fingerprint, room under both caps: creates a `pending` row,
///   attributed to `authenticated_user_id` for the per-user cap. The
///   global-cap check, per-user-cap check, and insert all happen inside one
///   DB transaction (SEC M3), so concurrent attempts cannot both observe
///   "room available" and both insert, overshooting either cap.
/// - Unseen fingerprint, global cap reached: `PendingCapReached` (no row
///   created).
/// - Unseen fingerprint, global cap has room but this user is already at
///   their own per-user cap: `PerUserPendingCapReached` (no row created) —
///   stops one authenticated account from occupying the whole queue.
/// - Known fingerprint (any status): refreshes `last_seen_at` and the
///   reported metadata, returning any drift for the caller to surface/audit.
///   Cap checks do not apply here — dedupe never blocks a repeat attempt.
#[allow(clippy::too_many_arguments)]
pub fn record_login_attempt(
    pool: &DbPool,
    authenticated_user_id: &str,
    fingerprint: &str,
    signing_public_key: &[u8],
    encryption_public_key: &[u8],
    app_name: &str,
    local_domain_hint: Option<&str>,
) -> Result<PendingAttemptOutcome, PendingAttemptError> {
    match pool.find_user_by_id(authenticated_user_id) {
        Ok(u) if u.is_active => {}
        Ok(_) => return Err(PendingAttemptError::NotAuthenticated),
        Err(diesel::result::Error::NotFound) => return Err(PendingAttemptError::NotAuthenticated),
        Err(e) => return Err(e.into()),
    }

    match pool.find_local_rp(fingerprint)? {
        Some(existing) => {
            let drift = diff_metadata(&existing, app_name, local_domain_hint);
            let local_rp =
                pool.touch_local_rp_last_seen(fingerprint, app_name, local_domain_hint)?;
            Ok(PendingAttemptOutcome::Refreshed { local_rp, drift })
        }
        None => match pool.insert_pending_local_rp_with_caps(
            fingerprint,
            signing_public_key,
            encryption_public_key,
            app_name,
            local_domain_hint,
            authenticated_user_id,
            MAX_PENDING_LOCAL_RPS,
            MAX_PENDING_LOCAL_RPS_PER_USER,
        )? {
            db::PendingInsertOutcome::Created(rp) => Ok(PendingAttemptOutcome::Created(*rp)),
            db::PendingInsertOutcome::GlobalCapReached => {
                Err(PendingAttemptError::PendingCapReached)
            }
            db::PendingInsertOutcome::PerUserCapReached => {
                Err(PendingAttemptError::PerUserPendingCapReached)
            }
        },
    }
}

/// Error for [`record_allow_by_default_login`]. Distinct from
/// [`PendingAttemptError`] because there is no pending-queue cap in the
/// allow-by-default path (the domain has explicitly accepted that risk) — a
/// shared error type would carry an unreachable `PendingCapReached` variant.
#[derive(Debug)]
pub enum AllowByDefaultError {
    /// Same enforcement point as [`PendingAttemptError::NotAuthenticated`]:
    /// this function requires a real, active, authenticated user id.
    NotAuthenticated,
    Db(diesel::result::Error),
}

impl From<diesel::result::Error> for AllowByDefaultError {
    fn from(e: diesel::result::Error) -> Self {
        AllowByDefaultError::Db(e)
    }
}

impl std::fmt::Display for AllowByDefaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AllowByDefaultError::NotAuthenticated => {
                write!(f, "login attempt was not from an authenticated user")
            }
            AllowByDefaultError::Db(e) => write!(f, "database error: {}", e),
        }
    }
}

/// Record a first-contact local RP under the `allow-by-default` domain
/// policy: an unseen fingerprint is admitted as `approved` immediately,
/// rather than queued for admin review (design doc: "optionally
/// allow-by-default for domains that explicitly choose that risk").
///
/// Still requires a real, active, authenticated user (same rationale as
/// [`record_login_attempt`]'s pending-queue guard: no code path here accepts
/// an anonymous caller). There is no cap: the domain has opted into this
/// risk, so flooding protection is not this function's job.
///
/// An already-known fingerprint (any status — pending from a prior policy,
/// approved, denied, or revoked) is returned as-is and NOT overwritten: an
/// admin's denial or revocation must never be silently promoted to approved
/// by a policy change, and a fingerprint already mid-review under a prior
/// `admin-approval-required` policy should not skip that review just because
/// the domain later switched policies. Auto-approval applies to first
/// contact only.
pub fn record_allow_by_default_login(
    pool: &DbPool,
    authenticated_user_id: &str,
    fingerprint: &str,
    signing_public_key: &[u8],
    encryption_public_key: &[u8],
    app_name: &str,
    local_domain_hint: Option<&str>,
) -> Result<LocalRp, AllowByDefaultError> {
    match pool.find_user_by_id(authenticated_user_id) {
        Ok(u) if u.is_active => {}
        Ok(_) => return Err(AllowByDefaultError::NotAuthenticated),
        Err(diesel::result::Error::NotFound) => return Err(AllowByDefaultError::NotAuthenticated),
        Err(e) => return Err(e.into()),
    }

    match pool.find_local_rp(fingerprint)? {
        Some(existing) => Ok(existing),
        None => Ok(pool.insert_local_rp(
            fingerprint,
            signing_public_key,
            encryption_public_key,
            app_name,
            local_domain_hint,
            db::STATUS_APPROVED,
            None,
        )?),
    }
}

/// Valid `from` statuses for a transition INTO `to` (design doc's matrix):
/// - -> approved: from pending or denied (an admin changed their mind)
/// - -> denied: from pending only
/// - -> revoked: from approved only
/// - anything else (including "-> pending", which would imply un-denying/
///   un-revoking back to the queue, and "-> revoked" from anywhere but
///   approved) is not a recognised transition. `revoked` is terminal: the
///   design treats revocation as final (rotate the key for a new identity).
fn valid_from_statuses(to: &str) -> Option<&'static [&'static str]> {
    match to {
        db::STATUS_APPROVED => Some(&[db::STATUS_PENDING, db::STATUS_DENIED]),
        db::STATUS_DENIED => Some(&[db::STATUS_PENDING]),
        db::STATUS_REVOKED => Some(&[db::STATUS_APPROVED]),
        _ => None,
    }
}

#[derive(Debug)]
pub enum StatusTransitionError {
    NotFound,
    /// `from` is the row's actual current status (or empty if `to` itself is
    /// not a recognised transition target at all).
    Invalid {
        from: String,
        to: String,
    },
    Db(diesel::result::Error),
}

impl From<diesel::result::Error> for StatusTransitionError {
    fn from(e: diesel::result::Error) -> Self {
        StatusTransitionError::Db(e)
    }
}

impl std::fmt::Display for StatusTransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StatusTransitionError::NotFound => write!(f, "local RP not found"),
            StatusTransitionError::Invalid { from, to } => {
                write!(f, "invalid local RP status transition: {} -> {}", from, to)
            }
            StatusTransitionError::Db(e) => write!(f, "database error: {}", e),
        }
    }
}

/// Transition a local RP's approval status, enforcing the matrix documented
/// on [`valid_from_statuses`]. Re-fetches and validates against the current
/// row before attempting a guarded update, so a nonsensical transition (e.g.
/// `denied -> denied`, `revoked -> approved`, `pending -> revoked`) is
/// rejected with the current status rather than silently no-opping.
pub fn transition_status(
    pool: &DbPool,
    fingerprint: &str,
    to: &str,
    admin_notes: Option<&str>,
) -> Result<LocalRp, StatusTransitionError> {
    let Some(allowed_from) = valid_from_statuses(to) else {
        return Err(StatusTransitionError::Invalid {
            from: String::new(),
            to: to.to_string(),
        });
    };

    let current = pool
        .find_local_rp(fingerprint)?
        .ok_or(StatusTransitionError::NotFound)?;

    if !allowed_from.contains(&current.status.as_str()) {
        return Err(StatusTransitionError::Invalid {
            from: current.status,
            to: to.to_string(),
        });
    }

    let affected = pool.set_local_rp_status(fingerprint, &current.status, to, admin_notes)?;
    if affected == 0 {
        // Raced: status changed between the read above and the guarded update.
        let now_status = pool
            .find_local_rp(fingerprint)?
            .map(|r| r.status)
            .unwrap_or(current.status);
        return Err(StatusTransitionError::Invalid {
            from: now_status,
            to: to.to_string(),
        });
    }

    if to == db::STATUS_REVOKED {
        // Revocation kills outstanding claim tickets (design doc). The
        // approval-status check in `redeem_ticket` already blocks a revoked
        // RP's tickets at redemption time (the enforcement point); deleting
        // the rows here is cheap-and-unambiguous belt-and-suspenders cleanup,
        // so a failure here is logged, not propagated — the status change
        // above has already committed and is authoritative on its own.
        if let Err(e) = pool.delete_local_rp_claim_tickets_by_fingerprint(fingerprint) {
            log::warn!(
                "revoked local RP {} but failed to delete its outstanding claim tickets: {}",
                fingerprint,
                e
            );
        }
    }

    pool.find_local_rp(fingerprint)?
        .ok_or(StatusTransitionError::NotFound)
}

#[derive(Debug)]
pub enum TicketRedeemError {
    NotFound,
    Expired,
    /// The bound local RP's current approval status (never `approved`, since
    /// that is the only status that redeems successfully).
    RpNotApproved(String),
    /// The ticket exists, has not expired, and its bound RP is still
    /// `approved` — but it is bound to a DIFFERENT local RP than the one that
    /// authenticated this redemption (the possession-proven caller
    /// fingerprint). This is the enforcement point for "a stolen ticket is
    /// useless without the RP's private key": knowing another RP's ticket
    /// bytes is not enough, because only the RP the ticket was actually
    /// issued to may redeem it. Callers must map this to the same opaque
    /// response as `NotFound` so it is not distinguishable as an oracle.
    FingerprintMismatch,
    Db(diesel::result::Error),
}

impl From<diesel::result::Error> for TicketRedeemError {
    fn from(e: diesel::result::Error) -> Self {
        TicketRedeemError::Db(e)
    }
}

impl std::fmt::Display for TicketRedeemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TicketRedeemError::NotFound => write!(f, "claim ticket not found"),
            TicketRedeemError::Expired => write!(f, "claim ticket has expired"),
            TicketRedeemError::RpNotApproved(status) => {
                write!(f, "local RP is not approved (status: {})", status)
            }
            TicketRedeemError::FingerprintMismatch => {
                write!(f, "claim ticket is not bound to this local RP")
            }
            TicketRedeemError::Db(e) => write!(f, "database error: {}", e),
        }
    }
}

/// Issue a claim-get ticket. `ticket_hash` is the SHA-256 hex of the 32
/// random ticket bytes (`liblinkkeys::crypto::fingerprint` over those bytes) —
/// callers must never pass the raw ticket itself; only its hash is stored.
pub fn issue_ticket(
    pool: &DbPool,
    ticket_hash: &str,
    fingerprint: &str,
    user_id: &str,
    user_domain: &str,
    granted_claims: &[String],
    expires_at: chrono::DateTime<chrono::Utc>,
) -> diesel::result::QueryResult<crate::db::models::LocalRpClaimTicket> {
    let granted_claims_json = serde_json::to_string(granted_claims).unwrap_or_else(|e| {
        log::warn!(
            "failed to serialize granted_claims ({}); storing empty set",
            e
        );
        "[]".to_string()
    });
    pool.issue_local_rp_claim_ticket(
        ticket_hash,
        fingerprint,
        user_id,
        user_domain,
        &granted_claims_json,
        expires_at,
    )
}

fn parse_rfc3339(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

/// Redeem a claim-get ticket by its hash: checks it exists, is bound to
/// `authenticated_fingerprint` (the caller's possession-proven identity —
/// see [`TicketRedeemError::FingerprintMismatch`]), has not expired, and that
/// the bound local RP's approval status is still `approved` (revocation
/// kills outstanding tickets — design doc). Does not delete the row: tickets
/// are multi-use within their window, so a valid redemption may be called
/// again later (the caller re-fetches claim values fresh each time). Returns
/// the ticket row (fingerprint binding + consent-frozen `granted_claims`)
/// for the caller to fetch current claim values with.
///
/// `authenticated_fingerprint` must be a value the caller has already proven
/// possession of (e.g. `rp.fingerprint` after a verified signature) — never
/// a value taken from the unverified request. Without this check, anyone who
/// obtains a ticket's raw bytes (not just the RP it was issued to) could
/// redeem it by signing a redemption request with any other approved local
/// RP's own key, since the ticket lookup is keyed purely by the ticket hash.
pub fn redeem_ticket(
    pool: &DbPool,
    ticket_hash: &str,
    authenticated_fingerprint: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<crate::db::models::LocalRpClaimTicket, TicketRedeemError> {
    let ticket = pool
        .find_local_rp_claim_ticket(ticket_hash)?
        .ok_or(TicketRedeemError::NotFound)?;

    if ticket.fingerprint != authenticated_fingerprint {
        return Err(TicketRedeemError::FingerprintMismatch);
    }

    let expires_at =
        parse_rfc3339(&ticket.expires_at).unwrap_or(chrono::DateTime::<chrono::Utc>::MIN_UTC);
    if now > expires_at {
        return Err(TicketRedeemError::Expired);
    }

    let rp = pool
        .find_local_rp(&ticket.fingerprint)?
        .ok_or(TicketRedeemError::NotFound)?;
    if rp.status != db::STATUS_APPROVED {
        return Err(TicketRedeemError::RpNotApproved(rp.status));
    }

    Ok(ticket)
}

/// Delete every expired claim ticket. Intended to be driven on an interval
/// (mirrors `services::pins::recheck_all`'s cron-friendly shape).
pub fn purge_expired_tickets(
    pool: &DbPool,
    now: chrono::DateTime<chrono::Utc>,
) -> diesel::result::QueryResult<usize> {
    pool.purge_expired_local_rp_claim_tickets(now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_matrix_pending_to_approved_or_denied() {
        assert_eq!(
            valid_from_statuses(db::STATUS_APPROVED),
            Some(&[db::STATUS_PENDING, db::STATUS_DENIED][..])
        );
        assert_eq!(
            valid_from_statuses(db::STATUS_DENIED),
            Some(&[db::STATUS_PENDING][..])
        );
        assert_eq!(
            valid_from_statuses(db::STATUS_REVOKED),
            Some(&[db::STATUS_APPROVED][..])
        );
    }

    #[test]
    fn transition_matrix_rejects_unrecognised_targets() {
        assert_eq!(valid_from_statuses(db::STATUS_PENDING), None);
        assert_eq!(valid_from_statuses("not-a-status"), None);
    }

    #[test]
    fn metadata_drift_detects_app_name_and_hint_changes() {
        let existing = LocalRp {
            fingerprint: "fp".to_string(),
            signing_public_key: vec![],
            encryption_public_key: vec![],
            app_name: "Old Name".to_string(),
            local_domain_hint: Some("old.local".to_string()),
            status: db::STATUS_PENDING.to_string(),
            created_at: String::new(),
            updated_at: String::new(),
            expires_at: None,
            last_seen_at: None,
            admin_notes: None,
            first_seen_by_user_id: None,
        };
        let drift = diff_metadata(&existing, "New Name", Some("new.local"));
        assert_eq!(drift.len(), 2);
        assert!(drift.iter().any(|d| d.field == "app_name"));
        assert!(drift.iter().any(|d| d.field == "local_domain_hint"));

        let no_drift = diff_metadata(&existing, "Old Name", Some("old.local"));
        assert!(no_drift.is_empty());
    }
}
