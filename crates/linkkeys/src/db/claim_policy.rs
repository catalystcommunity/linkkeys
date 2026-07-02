//! Persistence for the claim-signing policy registry and the per-user /
//! per-audience policy tables built on top of it: the claim-type registry,
//! trusted issuers, per-profile auto-sign preferences, release policies, and the
//! admin approval queue. The lane semantics these encode live in
//! `liblinkkeys::claim_policy`; this module is purely storage.

use crate::db::models::ClaimTypePolicy;

/// The starter registry shipped on first boot — sane, non-technical defaults so
/// a fresh domain works out of the box and the admin only edits to deviate.
/// Seeded idempotently (insert-if-absent), so an admin's later edits are never
/// overwritten on restart.
///
/// Lanes (see `liblinkkeys::claim_policy`):
/// - `self_signed` (A): a CSIL primitive the IDP validates and signs on set.
/// - `verified` (B): the IDP signs only after a built-in verification flow.
/// - `attested` (C): the IDP does not self-sign; it admits an external signature
///   from a trusted issuer (configured per type in `trusted_issuers`).
pub fn default_registry() -> Vec<ClaimTypePolicy> {
    let lane_a = |claim_type: &str, label: &str, value_type: &str| ClaimTypePolicy {
        claim_type: claim_type.to_string(),
        label: label.to_string(),
        description: String::new(),
        value_type: value_type.to_string(),
        max_bytes: 33792,
        set_rule: "user_self".to_string(),
        signing_rule: "self_signed".to_string(),
        requires_approval: false,
        user_settable: true,
        default_auto_sign: true,
        suggested: true,
    };
    let lane_c = |claim_type: &str, label: &str, value_type: &str| ClaimTypePolicy {
        claim_type: claim_type.to_string(),
        label: label.to_string(),
        description: String::new(),
        value_type: value_type.to_string(),
        max_bytes: 33792,
        set_rule: "trusted_issuer_only".to_string(),
        signing_rule: "attested".to_string(),
        requires_approval: false,
        user_settable: false,
        default_auto_sign: false,
        suggested: true,
    };
    vec![
        // Lane A — self-asserted, IDP validates the primitive and signs on set so
        // the value is domain-attested, not merely in-payload.
        lane_a("display_name", "Display name", "text"),
        lane_a("handle", "Handle", "text"),
        lane_a("website", "Website", "url"),
        lane_a("avatar_url", "Avatar URL", "url"),
        // Lane B — signed only after the built-in email round-trip.
        ClaimTypePolicy {
            claim_type: "email".to_string(),
            label: "Email address".to_string(),
            description: "Verified by a confirmation link sent to the address.".to_string(),
            value_type: "email".to_string(),
            max_bytes: 33792,
            set_rule: "user_self".to_string(),
            signing_rule: "verified".to_string(),
            requires_approval: false,
            user_settable: true,
            default_auto_sign: true,
            suggested: true,
        },
        // The IDP sets this as a side effect of a successful email verification;
        // the user cannot self-assert it.
        ClaimTypePolicy {
            claim_type: "email_verified".to_string(),
            label: "Email verified".to_string(),
            description: "Set automatically once an email address is verified.".to_string(),
            value_type: "bool".to_string(),
            max_bytes: 16,
            set_rule: "idp_on_request".to_string(),
            signing_rule: "verified".to_string(),
            requires_approval: false,
            user_settable: false,
            default_auto_sign: true,
            suggested: true,
        },
        // Lane C — attested by a recognised third party (e.g. a government
        // entity); the IDP signs nothing here, it admits a trusted issuer's
        // signature. No issuers are trusted by default — an admin adds the
        // domains they recognise in `trusted_issuers`.
        lane_c("legal_name", "Legal name", "text"),
        lane_c("date_of_birth", "Date of birth", "date"),
        lane_c("age_over_21", "Age over 21", "bool"),
        lane_c("linkidspec_signed", "LinkID Spec signed", "date"),
    ]
}

#[cfg(feature = "postgres")]
pub mod pg {
    use diesel::prelude::*;

    use crate::db::models::pg::{
        AdminReviewRow, AuditLogRow, ClaimTypePolicyRow, NewAdminReviewRow, NewAuditLogRow,
        NewClaimApprovalRow, ProfileClaimPrefRow, ReleasePolicyRow, TrustedIssuerRow,
    };
    use crate::db::models::{
        AdminReview, AuditEntry, ClaimApproval, ClaimTypePolicy, ProfileClaimPref, ReleasePolicy,
        TrustedIssuer,
    };
    use crate::schema::pg::{
        admin_review_queue, audit_log, claim_type_policies, profile_claim_prefs, release_policies,
        trusted_issuers,
    };

    // -- Claim-type policy registry --

    pub fn list_policies(conn: &mut diesel::PgConnection) -> QueryResult<Vec<ClaimTypePolicy>> {
        claim_type_policies::table
            .order(claim_type_policies::claim_type.asc())
            .select(ClaimTypePolicyRow::as_select())
            .load::<ClaimTypePolicyRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn find_policy(
        conn: &mut diesel::PgConnection,
        claim_type: &str,
    ) -> QueryResult<Option<ClaimTypePolicy>> {
        claim_type_policies::table
            .find(claim_type)
            .select(ClaimTypePolicyRow::as_select())
            .first::<ClaimTypePolicyRow>(conn)
            .optional()
            .map(|o| o.map(Into::into))
    }

    pub fn upsert_policy(
        conn: &mut diesel::PgConnection,
        policy: ClaimTypePolicy,
    ) -> QueryResult<usize> {
        let row: ClaimTypePolicyRow = policy.into();
        diesel::insert_into(claim_type_policies::table)
            .values(&row)
            .on_conflict(claim_type_policies::claim_type)
            .do_update()
            .set(&row)
            .execute(conn)
    }

    /// Insert a default policy only if the claim type is not already present.
    /// Returns rows inserted (0 = already present). Used by idempotent seeding.
    pub fn insert_policy_if_absent(
        conn: &mut diesel::PgConnection,
        policy: ClaimTypePolicy,
    ) -> QueryResult<usize> {
        let row: ClaimTypePolicyRow = policy.into();
        diesel::insert_into(claim_type_policies::table)
            .values(&row)
            .on_conflict_do_nothing()
            .execute(conn)
    }

    pub fn delete_policy(conn: &mut diesel::PgConnection, claim_type: &str) -> QueryResult<usize> {
        diesel::delete(claim_type_policies::table.find(claim_type)).execute(conn)
    }

    // -- Trusted issuers --

    pub fn list_trusted_issuers_for(
        conn: &mut diesel::PgConnection,
        claim_type: &str,
    ) -> QueryResult<Vec<String>> {
        trusted_issuers::table
            .filter(trusted_issuers::claim_type.eq(claim_type))
            .select(trusted_issuers::issuer_domain)
            .load::<String>(conn)
    }

    pub fn list_all_trusted_issuers(
        conn: &mut diesel::PgConnection,
    ) -> QueryResult<Vec<TrustedIssuer>> {
        trusted_issuers::table
            .order((
                trusted_issuers::claim_type.asc(),
                trusted_issuers::issuer_domain.asc(),
            ))
            .select(TrustedIssuerRow::as_select())
            .load::<TrustedIssuerRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn add_trusted_issuer(
        conn: &mut diesel::PgConnection,
        claim_type: &str,
        issuer_domain: &str,
    ) -> QueryResult<usize> {
        diesel::insert_into(trusted_issuers::table)
            .values(TrustedIssuerRow {
                claim_type: claim_type.to_string(),
                issuer_domain: issuer_domain.to_string(),
            })
            .on_conflict_do_nothing()
            .execute(conn)
    }

    pub fn remove_trusted_issuer(
        conn: &mut diesel::PgConnection,
        claim_type: &str,
        issuer_domain: &str,
    ) -> QueryResult<usize> {
        diesel::delete(
            trusted_issuers::table
                .filter(trusted_issuers::claim_type.eq(claim_type))
                .filter(trusted_issuers::issuer_domain.eq(issuer_domain)),
        )
        .execute(conn)
    }

    // -- Per-profile auto-sign preferences --

    pub fn get_pref(
        conn: &mut diesel::PgConnection,
        profile_id: &str,
        claim_type: &str,
    ) -> QueryResult<Option<bool>> {
        profile_claim_prefs::table
            .find((profile_id, claim_type))
            .select(profile_claim_prefs::auto_sign)
            .first::<bool>(conn)
            .optional()
    }

    pub fn list_prefs_for_profile(
        conn: &mut diesel::PgConnection,
        profile_id: &str,
    ) -> QueryResult<Vec<ProfileClaimPref>> {
        profile_claim_prefs::table
            .filter(profile_claim_prefs::profile_id.eq(profile_id))
            .select(ProfileClaimPrefRow::as_select())
            .load::<ProfileClaimPrefRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn upsert_pref(
        conn: &mut diesel::PgConnection,
        profile_id: &str,
        claim_type: &str,
        auto_sign: bool,
    ) -> QueryResult<usize> {
        let row = ProfileClaimPrefRow {
            profile_id: profile_id.to_string(),
            claim_type: claim_type.to_string(),
            auto_sign,
        };
        diesel::insert_into(profile_claim_prefs::table)
            .values(&row)
            .on_conflict((
                profile_claim_prefs::profile_id,
                profile_claim_prefs::claim_type,
            ))
            .do_update()
            .set(profile_claim_prefs::auto_sign.eq(auto_sign))
            .execute(conn)
    }

    // -- Release policies --

    pub fn list_release_policies(
        conn: &mut diesel::PgConnection,
    ) -> QueryResult<Vec<ReleasePolicy>> {
        release_policies::table
            .order((
                release_policies::audience.asc(),
                release_policies::claim_type.asc(),
            ))
            .select(ReleasePolicyRow::as_select())
            .load::<ReleasePolicyRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    /// Rows that apply to `audience`: that audience's explicit rows plus the
    /// global `*` defaults.
    pub fn list_release_policies_for_audience(
        conn: &mut diesel::PgConnection,
        audience: &str,
    ) -> QueryResult<Vec<ReleasePolicy>> {
        release_policies::table
            .filter(
                release_policies::audience
                    .eq(audience)
                    .or(release_policies::audience.eq("*")),
            )
            .select(ReleasePolicyRow::as_select())
            .load::<ReleasePolicyRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn count_release_policies(conn: &mut diesel::PgConnection) -> QueryResult<i64> {
        release_policies::table.count().get_result(conn)
    }

    pub fn upsert_release_policy(
        conn: &mut diesel::PgConnection,
        audience: &str,
        claim_type: &str,
        disposition: &str,
    ) -> QueryResult<usize> {
        let row = ReleasePolicyRow {
            audience: audience.to_string(),
            claim_type: claim_type.to_string(),
            disposition: disposition.to_string(),
        };
        diesel::insert_into(release_policies::table)
            .values(&row)
            .on_conflict((release_policies::audience, release_policies::claim_type))
            .do_update()
            .set(release_policies::disposition.eq(disposition))
            .execute(conn)
    }

    pub fn delete_release_policy(
        conn: &mut diesel::PgConnection,
        audience: &str,
        claim_type: &str,
    ) -> QueryResult<usize> {
        diesel::delete(
            release_policies::table
                .filter(release_policies::audience.eq(audience))
                .filter(release_policies::claim_type.eq(claim_type)),
        )
        .execute(conn)
    }

    // -- Approval queue --

    pub fn enqueue_approval(
        conn: &mut diesel::PgConnection,
        id: uuid::Uuid,
        user_id: uuid::Uuid,
        claim_type: &str,
        claim_value: &[u8],
    ) -> QueryResult<usize> {
        diesel::insert_into(admin_review_queue::table)
            .values(NewClaimApprovalRow {
                id,
                kind: "claim_approval".to_string(),
                user_id,
                claim_type: claim_type.to_string(),
                claim_value: claim_value.to_vec(),
            })
            .execute(conn)
    }

    /// Enqueue a non-claim admin review item (e.g. a key-mismatch that needs a
    /// human). `subject` is a human target (a domain); `detail` is JSON context.
    pub fn enqueue_review(
        conn: &mut diesel::PgConnection,
        id: uuid::Uuid,
        kind: &str,
        subject: Option<&str>,
        detail: Option<&str>,
    ) -> QueryResult<usize> {
        diesel::insert_into(admin_review_queue::table)
            .values(NewAdminReviewRow {
                id,
                kind: kind.to_string(),
                subject: subject.map(str::to_string),
                detail: detail.map(str::to_string),
            })
            .execute(conn)
    }

    pub fn list_pending_approvals(
        conn: &mut diesel::PgConnection,
    ) -> QueryResult<Vec<ClaimApproval>> {
        admin_review_queue::table
            .filter(admin_review_queue::status.eq("pending"))
            .filter(admin_review_queue::kind.eq("claim_approval"))
            .order(admin_review_queue::created_at.asc())
            .select(AdminReviewRow::as_select())
            .load::<AdminReviewRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    /// List pending review items of any `kind` (e.g. "key_mismatch").
    pub fn list_pending_reviews(
        conn: &mut diesel::PgConnection,
        kind: &str,
    ) -> QueryResult<Vec<AdminReview>> {
        admin_review_queue::table
            .filter(admin_review_queue::status.eq("pending"))
            .filter(admin_review_queue::kind.eq(kind.to_string()))
            .order(admin_review_queue::created_at.asc())
            .select(AdminReviewRow::as_select())
            .load::<AdminReviewRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn find_approval(
        conn: &mut diesel::PgConnection,
        id: uuid::Uuid,
    ) -> QueryResult<ClaimApproval> {
        admin_review_queue::table
            .find(id)
            .select(AdminReviewRow::as_select())
            .first::<AdminReviewRow>(conn)
            .map(Into::into)
    }

    /// Resolve a still-pending review item. Guarded on `status = 'pending'`, so a
    /// concurrent or repeat resolve affects 0 rows (caller treats 0 as
    /// already-resolved) rather than overwriting the prior resolution.
    pub fn resolve_approval(
        conn: &mut diesel::PgConnection,
        id: uuid::Uuid,
        status: &str,
        resolved_by: &str,
    ) -> QueryResult<usize> {
        diesel::update(
            admin_review_queue::table
                .filter(admin_review_queue::id.eq(id))
                .filter(admin_review_queue::status.eq("pending")),
        )
        .set((
            admin_review_queue::status.eq(status),
            admin_review_queue::resolved_by.eq(resolved_by),
            admin_review_queue::resolved_at.eq(chrono::Utc::now()),
        ))
        .execute(conn)
    }

    // -- Audit log --

    pub fn write_audit(
        conn: &mut diesel::PgConnection,
        id: uuid::Uuid,
        event: &str,
        subject: Option<&str>,
        actor: Option<&str>,
        detail: Option<&str>,
    ) -> QueryResult<usize> {
        diesel::insert_into(audit_log::table)
            .values(NewAuditLogRow {
                id,
                event: event.to_string(),
                subject: subject.map(str::to_string),
                actor: actor.map(str::to_string),
                detail: detail.map(str::to_string),
            })
            .execute(conn)
    }

    pub fn list_audit(conn: &mut diesel::PgConnection, limit: i64) -> QueryResult<Vec<AuditEntry>> {
        audit_log::table
            .order(audit_log::created_at.desc())
            .limit(limit)
            .select(AuditLogRow::as_select())
            .load::<AuditLogRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use diesel::prelude::*;

    use crate::db::models::sqlite::{
        AdminReviewRow, AuditLogRow, ClaimTypePolicyRow, NewAdminReviewRow, NewAuditLogRow,
        NewClaimApprovalRow, ProfileClaimPrefRow, ReleasePolicyRow, TrustedIssuerRow,
    };
    use crate::db::models::{
        AdminReview, AuditEntry, ClaimApproval, ClaimTypePolicy, ProfileClaimPref, ReleasePolicy,
        TrustedIssuer,
    };
    use crate::schema::sqlite::{
        admin_review_queue, audit_log, claim_type_policies, profile_claim_prefs, release_policies,
        trusted_issuers,
    };

    // -- Claim-type policy registry --

    pub fn list_policies(conn: &mut diesel::SqliteConnection) -> QueryResult<Vec<ClaimTypePolicy>> {
        claim_type_policies::table
            .order(claim_type_policies::claim_type.asc())
            .select(ClaimTypePolicyRow::as_select())
            .load::<ClaimTypePolicyRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn find_policy(
        conn: &mut diesel::SqliteConnection,
        claim_type: &str,
    ) -> QueryResult<Option<ClaimTypePolicy>> {
        claim_type_policies::table
            .find(claim_type)
            .select(ClaimTypePolicyRow::as_select())
            .first::<ClaimTypePolicyRow>(conn)
            .optional()
            .map(|o| o.map(Into::into))
    }

    pub fn upsert_policy(
        conn: &mut diesel::SqliteConnection,
        policy: ClaimTypePolicy,
    ) -> QueryResult<usize> {
        let row: ClaimTypePolicyRow = policy.into();
        diesel::insert_into(claim_type_policies::table)
            .values(&row)
            .on_conflict(claim_type_policies::claim_type)
            .do_update()
            .set(&row)
            .execute(conn)
    }

    pub fn insert_policy_if_absent(
        conn: &mut diesel::SqliteConnection,
        policy: ClaimTypePolicy,
    ) -> QueryResult<usize> {
        let row: ClaimTypePolicyRow = policy.into();
        diesel::insert_into(claim_type_policies::table)
            .values(&row)
            .on_conflict_do_nothing()
            .execute(conn)
    }

    pub fn delete_policy(
        conn: &mut diesel::SqliteConnection,
        claim_type: &str,
    ) -> QueryResult<usize> {
        diesel::delete(claim_type_policies::table.find(claim_type)).execute(conn)
    }

    // -- Trusted issuers --

    pub fn list_trusted_issuers_for(
        conn: &mut diesel::SqliteConnection,
        claim_type: &str,
    ) -> QueryResult<Vec<String>> {
        trusted_issuers::table
            .filter(trusted_issuers::claim_type.eq(claim_type))
            .select(trusted_issuers::issuer_domain)
            .load::<String>(conn)
    }

    pub fn list_all_trusted_issuers(
        conn: &mut diesel::SqliteConnection,
    ) -> QueryResult<Vec<TrustedIssuer>> {
        trusted_issuers::table
            .order((
                trusted_issuers::claim_type.asc(),
                trusted_issuers::issuer_domain.asc(),
            ))
            .select(TrustedIssuerRow::as_select())
            .load::<TrustedIssuerRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn add_trusted_issuer(
        conn: &mut diesel::SqliteConnection,
        claim_type: &str,
        issuer_domain: &str,
    ) -> QueryResult<usize> {
        diesel::insert_into(trusted_issuers::table)
            .values(TrustedIssuerRow {
                claim_type: claim_type.to_string(),
                issuer_domain: issuer_domain.to_string(),
            })
            .on_conflict_do_nothing()
            .execute(conn)
    }

    pub fn remove_trusted_issuer(
        conn: &mut diesel::SqliteConnection,
        claim_type: &str,
        issuer_domain: &str,
    ) -> QueryResult<usize> {
        diesel::delete(
            trusted_issuers::table
                .filter(trusted_issuers::claim_type.eq(claim_type))
                .filter(trusted_issuers::issuer_domain.eq(issuer_domain)),
        )
        .execute(conn)
    }

    // -- Per-profile auto-sign preferences --

    pub fn get_pref(
        conn: &mut diesel::SqliteConnection,
        profile_id: &str,
        claim_type: &str,
    ) -> QueryResult<Option<bool>> {
        profile_claim_prefs::table
            .find((profile_id, claim_type))
            .select(profile_claim_prefs::auto_sign)
            .first::<i32>(conn)
            .optional()
            .map(|o| o.map(|v| v != 0))
    }

    pub fn list_prefs_for_profile(
        conn: &mut diesel::SqliteConnection,
        profile_id: &str,
    ) -> QueryResult<Vec<ProfileClaimPref>> {
        profile_claim_prefs::table
            .filter(profile_claim_prefs::profile_id.eq(profile_id))
            .select(ProfileClaimPrefRow::as_select())
            .load::<ProfileClaimPrefRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn upsert_pref(
        conn: &mut diesel::SqliteConnection,
        profile_id: &str,
        claim_type: &str,
        auto_sign: bool,
    ) -> QueryResult<usize> {
        let row = ProfileClaimPrefRow {
            profile_id: profile_id.to_string(),
            claim_type: claim_type.to_string(),
            auto_sign: i32::from(auto_sign),
        };
        diesel::insert_into(profile_claim_prefs::table)
            .values(&row)
            .on_conflict((
                profile_claim_prefs::profile_id,
                profile_claim_prefs::claim_type,
            ))
            .do_update()
            .set(profile_claim_prefs::auto_sign.eq(i32::from(auto_sign)))
            .execute(conn)
    }

    // -- Release policies --

    pub fn list_release_policies(
        conn: &mut diesel::SqliteConnection,
    ) -> QueryResult<Vec<ReleasePolicy>> {
        release_policies::table
            .order((
                release_policies::audience.asc(),
                release_policies::claim_type.asc(),
            ))
            .select(ReleasePolicyRow::as_select())
            .load::<ReleasePolicyRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn list_release_policies_for_audience(
        conn: &mut diesel::SqliteConnection,
        audience: &str,
    ) -> QueryResult<Vec<ReleasePolicy>> {
        release_policies::table
            .filter(
                release_policies::audience
                    .eq(audience)
                    .or(release_policies::audience.eq("*")),
            )
            .select(ReleasePolicyRow::as_select())
            .load::<ReleasePolicyRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn count_release_policies(conn: &mut diesel::SqliteConnection) -> QueryResult<i64> {
        release_policies::table.count().get_result(conn)
    }

    pub fn upsert_release_policy(
        conn: &mut diesel::SqliteConnection,
        audience: &str,
        claim_type: &str,
        disposition: &str,
    ) -> QueryResult<usize> {
        let row = ReleasePolicyRow {
            audience: audience.to_string(),
            claim_type: claim_type.to_string(),
            disposition: disposition.to_string(),
        };
        diesel::insert_into(release_policies::table)
            .values(&row)
            .on_conflict((release_policies::audience, release_policies::claim_type))
            .do_update()
            .set(release_policies::disposition.eq(disposition))
            .execute(conn)
    }

    pub fn delete_release_policy(
        conn: &mut diesel::SqliteConnection,
        audience: &str,
        claim_type: &str,
    ) -> QueryResult<usize> {
        diesel::delete(
            release_policies::table
                .filter(release_policies::audience.eq(audience))
                .filter(release_policies::claim_type.eq(claim_type)),
        )
        .execute(conn)
    }

    // -- Approval queue --

    pub fn enqueue_approval(
        conn: &mut diesel::SqliteConnection,
        id: &str,
        user_id: &str,
        claim_type: &str,
        claim_value: &[u8],
    ) -> QueryResult<usize> {
        diesel::insert_into(admin_review_queue::table)
            .values(NewClaimApprovalRow {
                id: id.to_string(),
                kind: "claim_approval".to_string(),
                user_id: user_id.to_string(),
                claim_type: claim_type.to_string(),
                claim_value: claim_value.to_vec(),
            })
            .execute(conn)
    }

    /// Enqueue a non-claim admin review item (e.g. a key-mismatch).
    pub fn enqueue_review(
        conn: &mut diesel::SqliteConnection,
        id: &str,
        kind: &str,
        subject: Option<&str>,
        detail: Option<&str>,
    ) -> QueryResult<usize> {
        diesel::insert_into(admin_review_queue::table)
            .values(NewAdminReviewRow {
                id: id.to_string(),
                kind: kind.to_string(),
                subject: subject.map(str::to_string),
                detail: detail.map(str::to_string),
            })
            .execute(conn)
    }

    pub fn list_pending_approvals(
        conn: &mut diesel::SqliteConnection,
    ) -> QueryResult<Vec<ClaimApproval>> {
        admin_review_queue::table
            .filter(admin_review_queue::status.eq("pending"))
            .filter(admin_review_queue::kind.eq("claim_approval"))
            .order(admin_review_queue::created_at.asc())
            .select(AdminReviewRow::as_select())
            .load::<AdminReviewRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    /// List pending review items of any `kind` (e.g. "key_mismatch").
    pub fn list_pending_reviews(
        conn: &mut diesel::SqliteConnection,
        kind: &str,
    ) -> QueryResult<Vec<AdminReview>> {
        admin_review_queue::table
            .filter(admin_review_queue::status.eq("pending"))
            .filter(admin_review_queue::kind.eq(kind.to_string()))
            .order(admin_review_queue::created_at.asc())
            .select(AdminReviewRow::as_select())
            .load::<AdminReviewRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn find_approval(
        conn: &mut diesel::SqliteConnection,
        id: &str,
    ) -> QueryResult<ClaimApproval> {
        admin_review_queue::table
            .find(id)
            .select(AdminReviewRow::as_select())
            .first::<AdminReviewRow>(conn)
            .map(Into::into)
    }

    /// See the postgres variant — guarded on `status = 'pending'`.
    pub fn resolve_approval(
        conn: &mut diesel::SqliteConnection,
        id: &str,
        status: &str,
        resolved_by: &str,
    ) -> QueryResult<usize> {
        diesel::update(
            admin_review_queue::table
                .filter(admin_review_queue::id.eq(id))
                .filter(admin_review_queue::status.eq("pending")),
        )
        .set((
            admin_review_queue::status.eq(status),
            admin_review_queue::resolved_by.eq(resolved_by),
            admin_review_queue::resolved_at.eq(chrono::Utc::now().to_rfc3339()),
        ))
        .execute(conn)
    }

    // -- Audit log --

    pub fn write_audit(
        conn: &mut diesel::SqliteConnection,
        id: &str,
        event: &str,
        subject: Option<&str>,
        actor: Option<&str>,
        detail: Option<&str>,
    ) -> QueryResult<usize> {
        diesel::insert_into(audit_log::table)
            .values(NewAuditLogRow {
                id: id.to_string(),
                event: event.to_string(),
                subject: subject.map(str::to_string),
                actor: actor.map(str::to_string),
                detail: detail.map(str::to_string),
            })
            .execute(conn)
    }

    pub fn list_audit(
        conn: &mut diesel::SqliteConnection,
        limit: i64,
    ) -> QueryResult<Vec<AuditEntry>> {
        audit_log::table
            .order(audit_log::created_at.desc())
            .limit(limit)
            .select(AuditLogRow::as_select())
            .load::<AuditLogRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }
}
