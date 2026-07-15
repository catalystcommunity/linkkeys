//! Persistence for DNS-less local RP identity (see `dns-less-local-rp-design.md`
//! at the repo root, Phase 4 — server persistence): this domain's admission
//! policy for local RP logins, the local RP approval registry, and claim-get
//! ticket storage. Pure storage only — the pending-queue guard, drift
//! detection, status-transition matrix, and ticket redemption decision all
//! live in `crate::services::local_rp`, matching the split already used by
//! `domain_pins`/`crate::services::pins`.

/// Local RP admission policy vocabulary (CSIL `LocalRpPolicy`, a registry of
/// exact strings, not free text).
pub const POLICY_DISABLED: &str = "disabled";
pub const POLICY_ADMIN_APPROVAL_REQUIRED: &str = "admin-approval-required";
pub const POLICY_ALLOW_BY_DEFAULT: &str = "allow-by-default";

/// The default policy applied when a domain has never set one explicitly
/// (design doc: "the default should be admin approval").
pub const DEFAULT_POLICY: &str = POLICY_ADMIN_APPROVAL_REQUIRED;

const VALID_POLICIES: &[&str] = &[
    POLICY_DISABLED,
    POLICY_ADMIN_APPROVAL_REQUIRED,
    POLICY_ALLOW_BY_DEFAULT,
];

/// Whether `policy` is one of the recognised vocabulary values.
pub fn is_valid_policy(policy: &str) -> bool {
    VALID_POLICIES.contains(&policy)
}

/// Local RP approval status vocabulary.
pub const STATUS_PENDING: &str = "pending";
pub const STATUS_APPROVED: &str = "approved";
pub const STATUS_DENIED: &str = "denied";
pub const STATUS_REVOKED: &str = "revoked";

/// Outcome of [`pg::insert_pending_with_caps`] / [`sqlite::insert_pending_with_caps`]:
/// the global and per-user pending caps are checked, and the row is inserted
/// if room remains, ALL inside one DB transaction — so two concurrent login
/// attempts can never both observe "room available" and both insert,
/// overshooting the cap (the TOCTOU the separate count-then-insert calls
/// this replaces were vulnerable to). Cap-reached is a normal, expected
/// outcome of an authenticated login attempt (not a database failure), so it
/// is an `Ok` variant here rather than an `Err` — `QueryResult` is reserved
/// for actual database errors.
#[derive(Debug)]
pub enum PendingInsertOutcome {
    // Boxed: `LocalRp` is far larger than the other, data-free variants
    // (clippy::large_enum_variant) — indirection keeps this enum small to
    // pass/return by value.
    Created(Box<crate::db::models::LocalRp>),
    /// The domain-wide pending cap (`MAX_PENDING_LOCAL_RPS`) is already at
    /// capacity.
    GlobalCapReached,
    /// The domain-wide cap has room, but `first_seen_by_user_id` already has
    /// `MAX_PENDING_LOCAL_RPS_PER_USER` pending entries of their own.
    PerUserCapReached,
}

#[cfg(feature = "postgres")]
pub mod pg {
    use diesel::prelude::*;

    use crate::db::models::pg::{
        LocalRpClaimTicketRow, LocalRpDomainPolicyRow, LocalRpRow, NewLocalRpClaimTicketRow,
        NewLocalRpRow,
    };
    use crate::db::models::{LocalRp, LocalRpClaimTicket, LocalRpDomainPolicy};
    use crate::schema::pg::{local_rp_claim_tickets, local_rp_domain_policy, local_rps};

    // -- Domain policy --

    pub fn get_domain_policy(
        conn: &mut diesel::PgConnection,
        domain: &str,
    ) -> QueryResult<Option<LocalRpDomainPolicy>> {
        local_rp_domain_policy::table
            .find(domain)
            .select(LocalRpDomainPolicyRow::as_select())
            .first::<LocalRpDomainPolicyRow>(conn)
            .optional()
            .map(|o| o.map(Into::into))
    }

    pub fn set_domain_policy(
        conn: &mut diesel::PgConnection,
        domain: &str,
        policy: &str,
    ) -> QueryResult<usize> {
        let row = LocalRpDomainPolicyRow {
            domain: domain.to_string(),
            policy: policy.to_string(),
        };
        diesel::insert_into(local_rp_domain_policy::table)
            .values(&row)
            .on_conflict(local_rp_domain_policy::domain)
            .do_update()
            .set(local_rp_domain_policy::policy.eq(policy))
            .execute(conn)
    }

    // -- Local RP registry --

    pub fn find_by_fingerprint(
        conn: &mut diesel::PgConnection,
        fingerprint: &str,
    ) -> QueryResult<Option<LocalRp>> {
        local_rps::table
            .find(fingerprint)
            .select(LocalRpRow::as_select())
            .first::<LocalRpRow>(conn)
            .optional()
            .map(|o| o.map(Into::into))
    }

    pub fn list_by_status(
        conn: &mut diesel::PgConnection,
        status: Option<&str>,
    ) -> QueryResult<Vec<LocalRp>> {
        let mut query = local_rps::table.into_boxed();
        if let Some(status) = status {
            query = query.filter(local_rps::status.eq(status.to_string()));
        }
        query
            .order(local_rps::created_at.asc())
            .select(LocalRpRow::as_select())
            .load::<LocalRpRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn count_by_status(conn: &mut diesel::PgConnection, status: &str) -> QueryResult<i64> {
        local_rps::table
            .filter(local_rps::status.eq(status))
            .count()
            .get_result(conn)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert(
        conn: &mut diesel::PgConnection,
        fingerprint: &str,
        signing_public_key: &[u8],
        encryption_public_key: &[u8],
        app_name: &str,
        local_domain_hint: Option<&str>,
        status: &str,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> QueryResult<LocalRp> {
        let new_row = NewLocalRpRow {
            fingerprint: fingerprint.to_string(),
            signing_public_key: signing_public_key.to_vec(),
            encryption_public_key: encryption_public_key.to_vec(),
            app_name: app_name.to_string(),
            local_domain_hint: local_domain_hint.map(str::to_string),
            status: status.to_string(),
            expires_at,
            first_seen_by_user_id: None,
        };
        diesel::insert_into(local_rps::table)
            .values(&new_row)
            .get_result::<LocalRpRow>(conn)
            .map(Into::into)
    }

    /// Atomically check the global and per-user pending caps and insert a new
    /// `pending` row, all inside one transaction (SEC M3: replaces a
    /// count-then-insert pair of separate pooled calls, which raced under
    /// concurrent login attempts). `first_seen_by_user_id` is the
    /// authenticated user whose login attempt is creating this row; both
    /// caps are inclusive (a count equal to the cap blocks the insert).
    #[allow(clippy::too_many_arguments)]
    pub fn insert_pending_with_caps(
        conn: &mut diesel::PgConnection,
        fingerprint: &str,
        signing_public_key: &[u8],
        encryption_public_key: &[u8],
        app_name: &str,
        local_domain_hint: Option<&str>,
        first_seen_by_user_id: uuid::Uuid,
        global_cap: i64,
        per_user_cap: i64,
    ) -> QueryResult<super::PendingInsertOutcome> {
        conn.transaction(|conn| {
            let global_count: i64 = local_rps::table
                .filter(local_rps::status.eq(super::STATUS_PENDING))
                .count()
                .get_result(conn)?;
            if global_count >= global_cap {
                return Ok(super::PendingInsertOutcome::GlobalCapReached);
            }

            let user_count: i64 = local_rps::table
                .filter(local_rps::status.eq(super::STATUS_PENDING))
                .filter(local_rps::first_seen_by_user_id.eq(Some(first_seen_by_user_id)))
                .count()
                .get_result(conn)?;
            if user_count >= per_user_cap {
                return Ok(super::PendingInsertOutcome::PerUserCapReached);
            }

            let new_row = NewLocalRpRow {
                fingerprint: fingerprint.to_string(),
                signing_public_key: signing_public_key.to_vec(),
                encryption_public_key: encryption_public_key.to_vec(),
                app_name: app_name.to_string(),
                local_domain_hint: local_domain_hint.map(str::to_string),
                status: super::STATUS_PENDING.to_string(),
                expires_at: None,
                first_seen_by_user_id: Some(first_seen_by_user_id),
            };
            diesel::insert_into(local_rps::table)
                .values(&new_row)
                .get_result::<LocalRpRow>(conn)
                .map(|r| super::PendingInsertOutcome::Created(Box::new(r.into())))
        })
    }

    /// Refresh `last_seen_at` (to now) and the display/audit metadata
    /// (`app_name`/`local_domain_hint`) for an already-known fingerprint.
    /// Drift detection (comparing old vs. new metadata) is the caller's job —
    /// this only writes the latest reported values.
    pub fn touch_last_seen(
        conn: &mut diesel::PgConnection,
        fingerprint: &str,
        app_name: &str,
        local_domain_hint: Option<&str>,
    ) -> QueryResult<LocalRp> {
        diesel::update(local_rps::table.find(fingerprint))
            .set((
                local_rps::last_seen_at.eq(Some(chrono::Utc::now())),
                local_rps::app_name.eq(app_name),
                local_rps::local_domain_hint.eq(local_domain_hint),
            ))
            .get_result::<LocalRpRow>(conn)
            .map(Into::into)
    }

    /// Guarded status update: only applies if the row's current status is
    /// still `expected_from` (the caller has already validated the transition
    /// is in the allowed matrix). Returns rows affected (0 = raced/changed
    /// since the caller's read).
    pub fn set_status(
        conn: &mut diesel::PgConnection,
        fingerprint: &str,
        expected_from: &str,
        to: &str,
        admin_notes: Option<&str>,
    ) -> QueryResult<usize> {
        diesel::update(
            local_rps::table
                .filter(local_rps::fingerprint.eq(fingerprint))
                .filter(local_rps::status.eq(expected_from)),
        )
        .set((
            local_rps::status.eq(to),
            local_rps::admin_notes.eq(admin_notes),
        ))
        .execute(conn)
    }

    // -- Claim tickets --

    #[allow(clippy::too_many_arguments)]
    pub fn insert_ticket(
        conn: &mut diesel::PgConnection,
        ticket_hash: &str,
        fingerprint: &str,
        user_id: uuid::Uuid,
        user_domain: &str,
        granted_claims_json: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<LocalRpClaimTicket> {
        let new_row = NewLocalRpClaimTicketRow {
            ticket_hash: ticket_hash.to_string(),
            fingerprint: fingerprint.to_string(),
            user_id,
            user_domain: user_domain.to_string(),
            granted_claims: granted_claims_json.to_string(),
            expires_at,
        };
        diesel::insert_into(local_rp_claim_tickets::table)
            .values(&new_row)
            .get_result::<LocalRpClaimTicketRow>(conn)
            .map(Into::into)
    }

    pub fn find_ticket(
        conn: &mut diesel::PgConnection,
        ticket_hash: &str,
    ) -> QueryResult<Option<LocalRpClaimTicket>> {
        local_rp_claim_tickets::table
            .find(ticket_hash)
            .select(LocalRpClaimTicketRow::as_select())
            .first::<LocalRpClaimTicketRow>(conn)
            .optional()
            .map(|o| o.map(Into::into))
    }

    /// Delete every ticket whose `expires_at` is at or before `now`. Returns
    /// rows deleted.
    pub fn delete_expired_tickets(
        conn: &mut diesel::PgConnection,
        now: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<usize> {
        diesel::delete(
            local_rp_claim_tickets::table.filter(local_rp_claim_tickets::expires_at.le(now)),
        )
        .execute(conn)
    }

    /// Delete every outstanding ticket bound to `fingerprint`. Used when a
    /// local RP is revoked: `crate::services::local_rp::transition_status`
    /// already blocks redemption of a revoked RP's tickets at redemption
    /// time, so this is cheap-and-unambiguous belt-and-suspenders cleanup,
    /// not the enforcement point.
    pub fn delete_tickets_by_fingerprint(
        conn: &mut diesel::PgConnection,
        fingerprint: &str,
    ) -> QueryResult<usize> {
        diesel::delete(
            local_rp_claim_tickets::table
                .filter(local_rp_claim_tickets::fingerprint.eq(fingerprint)),
        )
        .execute(conn)
    }

    /// Delete every outstanding ticket issued to `user_id`. Used on user
    /// purge: purge minimizes the `users` row rather than deleting it, so the
    /// ticket's foreign key to that row never cascades away on its own
    /// (design doc / Phase 4 finding).
    pub fn delete_tickets_by_user_id(
        conn: &mut diesel::PgConnection,
        user_id: uuid::Uuid,
    ) -> QueryResult<usize> {
        diesel::delete(
            local_rp_claim_tickets::table.filter(local_rp_claim_tickets::user_id.eq(user_id)),
        )
        .execute(conn)
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use diesel::prelude::*;

    use crate::db::models::sqlite::{
        LocalRpClaimTicketRow, LocalRpDomainPolicyRow, LocalRpRow, NewLocalRpClaimTicketRow,
        NewLocalRpRow,
    };
    use crate::db::models::{LocalRp, LocalRpClaimTicket, LocalRpDomainPolicy};
    use crate::schema::sqlite::{local_rp_claim_tickets, local_rp_domain_policy, local_rps};

    // -- Domain policy --

    pub fn get_domain_policy(
        conn: &mut diesel::SqliteConnection,
        domain: &str,
    ) -> QueryResult<Option<LocalRpDomainPolicy>> {
        local_rp_domain_policy::table
            .find(domain)
            .select(LocalRpDomainPolicyRow::as_select())
            .first::<LocalRpDomainPolicyRow>(conn)
            .optional()
            .map(|o| o.map(Into::into))
    }

    pub fn set_domain_policy(
        conn: &mut diesel::SqliteConnection,
        domain: &str,
        policy: &str,
    ) -> QueryResult<usize> {
        let row = LocalRpDomainPolicyRow {
            domain: domain.to_string(),
            policy: policy.to_string(),
        };
        diesel::insert_into(local_rp_domain_policy::table)
            .values(&row)
            .on_conflict(local_rp_domain_policy::domain)
            .do_update()
            .set(local_rp_domain_policy::policy.eq(policy))
            .execute(conn)
    }

    // -- Local RP registry --

    pub fn find_by_fingerprint(
        conn: &mut diesel::SqliteConnection,
        fingerprint: &str,
    ) -> QueryResult<Option<LocalRp>> {
        local_rps::table
            .find(fingerprint)
            .select(LocalRpRow::as_select())
            .first::<LocalRpRow>(conn)
            .optional()
            .map(|o| o.map(Into::into))
    }

    pub fn list_by_status(
        conn: &mut diesel::SqliteConnection,
        status: Option<&str>,
    ) -> QueryResult<Vec<LocalRp>> {
        let mut query = local_rps::table.into_boxed();
        if let Some(status) = status {
            query = query.filter(local_rps::status.eq(status.to_string()));
        }
        query
            .order(local_rps::created_at.asc())
            .select(LocalRpRow::as_select())
            .load::<LocalRpRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn count_by_status(conn: &mut diesel::SqliteConnection, status: &str) -> QueryResult<i64> {
        local_rps::table
            .filter(local_rps::status.eq(status))
            .count()
            .get_result(conn)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert(
        conn: &mut diesel::SqliteConnection,
        fingerprint: &str,
        signing_public_key: &[u8],
        encryption_public_key: &[u8],
        app_name: &str,
        local_domain_hint: Option<&str>,
        status: &str,
        expires_at: Option<&str>,
    ) -> QueryResult<LocalRp> {
        let new_row = NewLocalRpRow {
            fingerprint: fingerprint.to_string(),
            signing_public_key: signing_public_key.to_vec(),
            encryption_public_key: encryption_public_key.to_vec(),
            app_name: app_name.to_string(),
            local_domain_hint: local_domain_hint.map(str::to_string),
            status: status.to_string(),
            expires_at: expires_at.map(str::to_string),
            first_seen_by_user_id: None,
        };
        diesel::insert_into(local_rps::table)
            .values(&new_row)
            .execute(conn)?;

        local_rps::table
            .find(fingerprint)
            .select(LocalRpRow::as_select())
            .first::<LocalRpRow>(conn)
            .map(Into::into)
    }

    /// See the postgres variant — atomically checks the global and per-user
    /// pending caps and inserts, all inside one transaction (SEC M3).
    #[allow(clippy::too_many_arguments)]
    pub fn insert_pending_with_caps(
        conn: &mut diesel::SqliteConnection,
        fingerprint: &str,
        signing_public_key: &[u8],
        encryption_public_key: &[u8],
        app_name: &str,
        local_domain_hint: Option<&str>,
        first_seen_by_user_id: &str,
        global_cap: i64,
        per_user_cap: i64,
    ) -> QueryResult<super::PendingInsertOutcome> {
        conn.transaction(|conn| {
            let global_count: i64 = local_rps::table
                .filter(local_rps::status.eq(super::STATUS_PENDING))
                .count()
                .get_result(conn)?;
            if global_count >= global_cap {
                return Ok(super::PendingInsertOutcome::GlobalCapReached);
            }

            let user_count: i64 = local_rps::table
                .filter(local_rps::status.eq(super::STATUS_PENDING))
                .filter(local_rps::first_seen_by_user_id.eq(Some(first_seen_by_user_id)))
                .count()
                .get_result(conn)?;
            if user_count >= per_user_cap {
                return Ok(super::PendingInsertOutcome::PerUserCapReached);
            }

            let new_row = NewLocalRpRow {
                fingerprint: fingerprint.to_string(),
                signing_public_key: signing_public_key.to_vec(),
                encryption_public_key: encryption_public_key.to_vec(),
                app_name: app_name.to_string(),
                local_domain_hint: local_domain_hint.map(str::to_string),
                status: super::STATUS_PENDING.to_string(),
                expires_at: None,
                first_seen_by_user_id: Some(first_seen_by_user_id.to_string()),
            };
            diesel::insert_into(local_rps::table)
                .values(&new_row)
                .execute(conn)?;

            local_rps::table
                .find(fingerprint)
                .select(LocalRpRow::as_select())
                .first::<LocalRpRow>(conn)
                .map(|r| super::PendingInsertOutcome::Created(Box::new(r.into())))
        })
    }

    /// See the postgres variant — writes the latest reported metadata plus a
    /// fresh `last_seen_at`; drift detection is the caller's job.
    pub fn touch_last_seen(
        conn: &mut diesel::SqliteConnection,
        fingerprint: &str,
        app_name: &str,
        local_domain_hint: Option<&str>,
    ) -> QueryResult<LocalRp> {
        let now = chrono::Utc::now().to_rfc3339();
        diesel::update(local_rps::table.find(fingerprint))
            .set((
                local_rps::last_seen_at.eq(Some(now)),
                local_rps::app_name.eq(app_name),
                local_rps::local_domain_hint.eq(local_domain_hint),
            ))
            .execute(conn)?;

        local_rps::table
            .find(fingerprint)
            .select(LocalRpRow::as_select())
            .first::<LocalRpRow>(conn)
            .map(Into::into)
    }

    /// See the postgres variant — guarded on the expected current status.
    pub fn set_status(
        conn: &mut diesel::SqliteConnection,
        fingerprint: &str,
        expected_from: &str,
        to: &str,
        admin_notes: Option<&str>,
    ) -> QueryResult<usize> {
        diesel::update(
            local_rps::table
                .filter(local_rps::fingerprint.eq(fingerprint))
                .filter(local_rps::status.eq(expected_from)),
        )
        .set((
            local_rps::status.eq(to),
            local_rps::admin_notes.eq(admin_notes),
        ))
        .execute(conn)
    }

    // -- Claim tickets --

    #[allow(clippy::too_many_arguments)]
    pub fn insert_ticket(
        conn: &mut diesel::SqliteConnection,
        ticket_hash: &str,
        fingerprint: &str,
        user_id: &str,
        user_domain: &str,
        granted_claims_json: &str,
        expires_at: &str,
    ) -> QueryResult<LocalRpClaimTicket> {
        let new_row = NewLocalRpClaimTicketRow {
            ticket_hash: ticket_hash.to_string(),
            fingerprint: fingerprint.to_string(),
            user_id: user_id.to_string(),
            user_domain: user_domain.to_string(),
            granted_claims: granted_claims_json.to_string(),
            expires_at: expires_at.to_string(),
        };
        diesel::insert_into(local_rp_claim_tickets::table)
            .values(&new_row)
            .execute(conn)?;

        local_rp_claim_tickets::table
            .find(ticket_hash)
            .select(LocalRpClaimTicketRow::as_select())
            .first::<LocalRpClaimTicketRow>(conn)
            .map(Into::into)
    }

    pub fn find_ticket(
        conn: &mut diesel::SqliteConnection,
        ticket_hash: &str,
    ) -> QueryResult<Option<LocalRpClaimTicket>> {
        local_rp_claim_tickets::table
            .find(ticket_hash)
            .select(LocalRpClaimTicketRow::as_select())
            .first::<LocalRpClaimTicketRow>(conn)
            .optional()
            .map(|o| o.map(Into::into))
    }

    /// `now` is an RFC3339 string; comparison is lexicographic, which is
    /// correct for RFC3339 timestamps stored as text (see `consent_grants`).
    pub fn delete_expired_tickets(
        conn: &mut diesel::SqliteConnection,
        now: &str,
    ) -> QueryResult<usize> {
        diesel::delete(
            local_rp_claim_tickets::table.filter(local_rp_claim_tickets::expires_at.le(now)),
        )
        .execute(conn)
    }

    /// See the postgres variant — deletes every outstanding ticket bound to
    /// `fingerprint` (revocation cleanup).
    pub fn delete_tickets_by_fingerprint(
        conn: &mut diesel::SqliteConnection,
        fingerprint: &str,
    ) -> QueryResult<usize> {
        diesel::delete(
            local_rp_claim_tickets::table
                .filter(local_rp_claim_tickets::fingerprint.eq(fingerprint)),
        )
        .execute(conn)
    }

    /// See the postgres variant — deletes every outstanding ticket issued to
    /// `user_id` (purge cleanup).
    pub fn delete_tickets_by_user_id(
        conn: &mut diesel::SqliteConnection,
        user_id: &str,
    ) -> QueryResult<usize> {
        diesel::delete(
            local_rp_claim_tickets::table.filter(local_rp_claim_tickets::user_id.eq(user_id)),
        )
        .execute(conn)
    }
}
