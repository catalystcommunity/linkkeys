//! Persistence for the RP's own cache of REMOTE key material
//! (signing-things-request.md, step 6: "RP cache" / "RP-facing operations").
//!
//! This is the reader side: what a regular RP server durably remembers about
//! OTHER domains' signing keys and OTHER applications' attested keys, so a
//! restart does not lose useful cache state and so a home-domain outage can
//! still be answered with the last verified material, explicitly marked
//! stale. It is deliberately the mirror image of `db::application_keys`
//! (which is the home domain's storage of its OWN subjects' keys) — pure
//! storage here too, no verification, no discovery, no dispatch.
//!
//! Domain-key material itself keeps living in `db::peer_keys`; this module
//! only adds the domain-key freshness record. Application-key attestations
//! and revocations have no pre-existing durable home, so this module stores
//! the SIGNED records verbatim plus per-entry freshness metadata, keyed on
//! the canonical (subject_user_id, subject_domain, application_id,
//! instance_id) tuple — never a handle.

#[cfg(feature = "postgres")]
pub mod pg {
    use diesel::prelude::*;

    use crate::db::models::pg::{
        NewRpApplicationKeyCacheEntryRow, RpApplicationKeyAttestationRow,
        RpApplicationKeyCacheEntryRow, RpApplicationKeyRevocationRow, RpDomainKeyCacheRow,
    };
    use crate::db::models::{
        RpApplicationKeyAttestationCache, RpApplicationKeyCacheEntry,
        RpApplicationKeyRevocationCache, RpDomainKeyCacheMeta,
    };
    use crate::schema::pg::{
        rp_application_key_attestations, rp_application_key_cache_entries,
        rp_application_key_revocations, rp_domain_key_cache,
    };

    fn parse_uuid(s: &str) -> QueryResult<uuid::Uuid> {
        s.parse().map_err(|_| diesel::result::Error::NotFound)
    }

    // -- Domain-key freshness --

    pub fn get_domain_meta(
        conn: &mut diesel::PgConnection,
        domain: &str,
    ) -> QueryResult<Option<RpDomainKeyCacheMeta>> {
        rp_domain_key_cache::table
            .filter(rp_domain_key_cache::domain.eq(domain))
            .select(RpDomainKeyCacheRow::as_select())
            .first::<RpDomainKeyCacheRow>(conn)
            .optional()
            .map(|o| o.map(Into::into))
    }

    pub fn upsert_domain_meta(
        conn: &mut diesel::PgConnection,
        domain: &str,
        fetched_at: chrono::DateTime<chrono::Utc>,
        revocations_checked_at: chrono::DateTime<chrono::Utc>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<usize> {
        diesel::insert_into(rp_domain_key_cache::table)
            .values((
                rp_domain_key_cache::domain.eq(domain),
                rp_domain_key_cache::fetched_at.eq(fetched_at),
                rp_domain_key_cache::revocations_checked_at.eq(revocations_checked_at),
                rp_domain_key_cache::last_used_at.eq(now),
            ))
            .on_conflict(rp_domain_key_cache::domain)
            .do_update()
            .set((
                rp_domain_key_cache::fetched_at.eq(fetched_at),
                rp_domain_key_cache::revocations_checked_at.eq(revocations_checked_at),
                rp_domain_key_cache::last_used_at.eq(now),
                rp_domain_key_cache::updated_at.eq(now),
            ))
            .execute(conn)
    }

    pub fn touch_domain_meta(
        conn: &mut diesel::PgConnection,
        domain: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<usize> {
        diesel::update(rp_domain_key_cache::table.filter(rp_domain_key_cache::domain.eq(domain)))
            .set(rp_domain_key_cache::last_used_at.eq(now))
            .execute(conn)
    }

    pub fn count_domain_meta(conn: &mut diesel::PgConnection) -> QueryResult<i64> {
        rp_domain_key_cache::table.count().get_result(conn)
    }

    /// Bounded eviction: delete the least-recently-used domain entries beyond
    /// `max_entries`. A plain select-then-delete (not `DELETE ... LIMIT`,
    /// which is not portable) — cheap, since this only runs after an insert
    /// that might have pushed the cache over budget.
    pub fn evict_oldest_domain_meta(
        conn: &mut diesel::PgConnection,
        max_entries: i64,
    ) -> QueryResult<usize> {
        let total = count_domain_meta(conn)?;
        let over = total - max_entries;
        if over <= 0 {
            return Ok(0);
        }
        let victims: Vec<String> = rp_domain_key_cache::table
            .order(rp_domain_key_cache::last_used_at.asc())
            .limit(over)
            .select(rp_domain_key_cache::domain)
            .load(conn)?;
        diesel::delete(
            rp_domain_key_cache::table.filter(rp_domain_key_cache::domain.eq_any(&victims)),
        )
        .execute(conn)
    }

    // -- Application-key cache entries --

    pub fn find_entry(
        conn: &mut diesel::PgConnection,
        subject_user_id: &str,
        subject_domain: &str,
        application_id: &str,
        instance_id: &str,
    ) -> QueryResult<Option<RpApplicationKeyCacheEntry>> {
        rp_application_key_cache_entries::table
            .filter(rp_application_key_cache_entries::subject_user_id.eq(subject_user_id))
            .filter(rp_application_key_cache_entries::subject_domain.eq(subject_domain))
            .filter(rp_application_key_cache_entries::application_id.eq(application_id))
            .filter(rp_application_key_cache_entries::instance_id.eq(instance_id))
            .select(RpApplicationKeyCacheEntryRow::as_select())
            .first::<RpApplicationKeyCacheEntryRow>(conn)
            .optional()
            .map(|o| o.map(Into::into))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_entry(
        conn: &mut diesel::PgConnection,
        subject_user_id: &str,
        subject_domain: &str,
        application_id: &str,
        instance_id: &str,
        fetched_at: chrono::DateTime<chrono::Utc>,
        revocations_checked_at: chrono::DateTime<chrono::Utc>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<RpApplicationKeyCacheEntry> {
        conn.transaction(|conn| {
            diesel::insert_into(rp_application_key_cache_entries::table)
                .values(NewRpApplicationKeyCacheEntryRow {
                    id: uuid::Uuid::now_v7(),
                    subject_user_id: subject_user_id.to_string(),
                    subject_domain: subject_domain.to_string(),
                    application_id: application_id.to_string(),
                    instance_id: instance_id.to_string(),
                    fetched_at,
                    revocations_checked_at,
                    last_used_at: now,
                })
                .on_conflict((
                    rp_application_key_cache_entries::subject_user_id,
                    rp_application_key_cache_entries::subject_domain,
                    rp_application_key_cache_entries::application_id,
                    rp_application_key_cache_entries::instance_id,
                ))
                .do_update()
                .set((
                    rp_application_key_cache_entries::fetched_at.eq(fetched_at),
                    rp_application_key_cache_entries::revocations_checked_at
                        .eq(revocations_checked_at),
                    rp_application_key_cache_entries::last_used_at.eq(now),
                    rp_application_key_cache_entries::updated_at.eq(now),
                ))
                .execute(conn)?;

            rp_application_key_cache_entries::table
                .filter(rp_application_key_cache_entries::subject_user_id.eq(subject_user_id))
                .filter(rp_application_key_cache_entries::subject_domain.eq(subject_domain))
                .filter(rp_application_key_cache_entries::application_id.eq(application_id))
                .filter(rp_application_key_cache_entries::instance_id.eq(instance_id))
                .select(RpApplicationKeyCacheEntryRow::as_select())
                .first::<RpApplicationKeyCacheEntryRow>(conn)
                .map(Into::into)
        })
    }

    pub fn touch_entry(
        conn: &mut diesel::PgConnection,
        entry_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<usize> {
        let id = parse_uuid(entry_id)?;
        diesel::update(rp_application_key_cache_entries::table.find(id))
            .set(rp_application_key_cache_entries::last_used_at.eq(now))
            .execute(conn)
    }

    pub fn count_entries(conn: &mut diesel::PgConnection) -> QueryResult<i64> {
        rp_application_key_cache_entries::table
            .count()
            .get_result(conn)
    }

    /// Bounded eviction of the least-recently-used entries beyond
    /// `max_entries`, deleting each victim's child attestation/revocation
    /// rows first (no `ON DELETE CASCADE`; kept explicit and testable).
    pub fn evict_oldest_entries(
        conn: &mut diesel::PgConnection,
        max_entries: i64,
    ) -> QueryResult<usize> {
        let total = count_entries(conn)?;
        let over = total - max_entries;
        if over <= 0 {
            return Ok(0);
        }
        let victims: Vec<uuid::Uuid> = rp_application_key_cache_entries::table
            .order(rp_application_key_cache_entries::last_used_at.asc())
            .limit(over)
            .select(rp_application_key_cache_entries::id)
            .load(conn)?;
        conn.transaction(|conn| {
            diesel::delete(
                rp_application_key_attestations::table
                    .filter(rp_application_key_attestations::cache_entry_id.eq_any(&victims)),
            )
            .execute(conn)?;
            diesel::delete(
                rp_application_key_revocations::table
                    .filter(rp_application_key_revocations::cache_entry_id.eq_any(&victims)),
            )
            .execute(conn)?;
            diesel::delete(
                rp_application_key_cache_entries::table
                    .filter(rp_application_key_cache_entries::id.eq_any(&victims)),
            )
            .execute(conn)
        })
    }

    // -- Cached attestations --

    pub fn upsert_attestation(
        conn: &mut diesel::PgConnection,
        cache_entry_id: &str,
        key_id: &str,
        signed_attestation: &[u8],
        attestation_expires_at: chrono::DateTime<chrono::Utc>,
        verified_by_key_ids: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<usize> {
        let entry_uuid = parse_uuid(cache_entry_id)?;
        diesel::insert_into(rp_application_key_attestations::table)
            .values((
                rp_application_key_attestations::id.eq(uuid::Uuid::now_v7()),
                rp_application_key_attestations::cache_entry_id.eq(entry_uuid),
                rp_application_key_attestations::key_id.eq(key_id),
                rp_application_key_attestations::signed_attestation.eq(signed_attestation),
                rp_application_key_attestations::attestation_expires_at.eq(attestation_expires_at),
                rp_application_key_attestations::verified_by_key_ids.eq(verified_by_key_ids),
            ))
            .on_conflict((
                rp_application_key_attestations::cache_entry_id,
                rp_application_key_attestations::key_id,
            ))
            .do_update()
            .set((
                rp_application_key_attestations::signed_attestation.eq(signed_attestation),
                rp_application_key_attestations::attestation_expires_at.eq(attestation_expires_at),
                rp_application_key_attestations::verified_by_key_ids.eq(verified_by_key_ids),
                rp_application_key_attestations::updated_at.eq(now),
            ))
            .execute(conn)
    }

    pub fn list_attestations(
        conn: &mut diesel::PgConnection,
        cache_entry_id: &str,
    ) -> QueryResult<Vec<RpApplicationKeyAttestationCache>> {
        let entry_uuid = parse_uuid(cache_entry_id)?;
        rp_application_key_attestations::table
            .filter(rp_application_key_attestations::cache_entry_id.eq(entry_uuid))
            .select(RpApplicationKeyAttestationRow::as_select())
            .load::<RpApplicationKeyAttestationRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    // -- Cached revocations --

    pub fn upsert_revocation(
        conn: &mut diesel::PgConnection,
        cache_entry_id: &str,
        target_key_id: &str,
        revocation: &[u8],
        revoked_at: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<usize> {
        let entry_uuid = parse_uuid(cache_entry_id)?;
        diesel::insert_into(rp_application_key_revocations::table)
            .values((
                rp_application_key_revocations::id.eq(uuid::Uuid::now_v7()),
                rp_application_key_revocations::cache_entry_id.eq(entry_uuid),
                rp_application_key_revocations::target_key_id.eq(target_key_id),
                rp_application_key_revocations::revocation.eq(revocation),
                rp_application_key_revocations::revoked_at.eq(revoked_at),
            ))
            .on_conflict((
                rp_application_key_revocations::cache_entry_id,
                rp_application_key_revocations::target_key_id,
            ))
            .do_update()
            .set((
                rp_application_key_revocations::revocation.eq(revocation),
                rp_application_key_revocations::revoked_at.eq(revoked_at),
            ))
            .execute(conn)
    }

    pub fn list_revocations(
        conn: &mut diesel::PgConnection,
        cache_entry_id: &str,
    ) -> QueryResult<Vec<RpApplicationKeyRevocationCache>> {
        let entry_uuid = parse_uuid(cache_entry_id)?;
        rp_application_key_revocations::table
            .filter(rp_application_key_revocations::cache_entry_id.eq(entry_uuid))
            .select(RpApplicationKeyRevocationRow::as_select())
            .load::<RpApplicationKeyRevocationRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use diesel::prelude::*;

    use crate::db::models::sqlite::{
        NewRpApplicationKeyCacheEntryRow, RpApplicationKeyAttestationRow,
        RpApplicationKeyCacheEntryRow, RpApplicationKeyRevocationRow, RpDomainKeyCacheRow,
    };
    use crate::db::models::{
        RpApplicationKeyAttestationCache, RpApplicationKeyCacheEntry,
        RpApplicationKeyRevocationCache, RpDomainKeyCacheMeta,
    };
    use crate::schema::sqlite::{
        rp_application_key_attestations, rp_application_key_cache_entries,
        rp_application_key_revocations, rp_domain_key_cache,
    };

    // -- Domain-key freshness --

    pub fn get_domain_meta(
        conn: &mut diesel::SqliteConnection,
        domain: &str,
    ) -> QueryResult<Option<RpDomainKeyCacheMeta>> {
        rp_domain_key_cache::table
            .filter(rp_domain_key_cache::domain.eq(domain))
            .select(RpDomainKeyCacheRow::as_select())
            .first::<RpDomainKeyCacheRow>(conn)
            .optional()
            .map(|o| o.map(Into::into))
    }

    pub fn upsert_domain_meta(
        conn: &mut diesel::SqliteConnection,
        domain: &str,
        fetched_at: chrono::DateTime<chrono::Utc>,
        revocations_checked_at: chrono::DateTime<chrono::Utc>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<usize> {
        let fetched_at_str = fetched_at.to_rfc3339();
        let revocations_checked_at_str = revocations_checked_at.to_rfc3339();
        let now_str = now.to_rfc3339();
        diesel::insert_into(rp_domain_key_cache::table)
            .values((
                rp_domain_key_cache::domain.eq(domain),
                rp_domain_key_cache::fetched_at.eq(&fetched_at_str),
                rp_domain_key_cache::revocations_checked_at.eq(&revocations_checked_at_str),
                rp_domain_key_cache::last_used_at.eq(&now_str),
            ))
            .on_conflict(rp_domain_key_cache::domain)
            .do_update()
            .set((
                rp_domain_key_cache::fetched_at.eq(&fetched_at_str),
                rp_domain_key_cache::revocations_checked_at.eq(&revocations_checked_at_str),
                rp_domain_key_cache::last_used_at.eq(&now_str),
                rp_domain_key_cache::updated_at.eq(&now_str),
            ))
            .execute(conn)
    }

    pub fn touch_domain_meta(
        conn: &mut diesel::SqliteConnection,
        domain: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<usize> {
        diesel::update(rp_domain_key_cache::table.filter(rp_domain_key_cache::domain.eq(domain)))
            .set(rp_domain_key_cache::last_used_at.eq(now.to_rfc3339()))
            .execute(conn)
    }

    pub fn count_domain_meta(conn: &mut diesel::SqliteConnection) -> QueryResult<i64> {
        rp_domain_key_cache::table.count().get_result(conn)
    }

    pub fn evict_oldest_domain_meta(
        conn: &mut diesel::SqliteConnection,
        max_entries: i64,
    ) -> QueryResult<usize> {
        let total = count_domain_meta(conn)?;
        let over = total - max_entries;
        if over <= 0 {
            return Ok(0);
        }
        let victims: Vec<String> = rp_domain_key_cache::table
            .order(rp_domain_key_cache::last_used_at.asc())
            .limit(over)
            .select(rp_domain_key_cache::domain)
            .load(conn)?;
        diesel::delete(
            rp_domain_key_cache::table.filter(rp_domain_key_cache::domain.eq_any(&victims)),
        )
        .execute(conn)
    }

    // -- Application-key cache entries --

    pub fn find_entry(
        conn: &mut diesel::SqliteConnection,
        subject_user_id: &str,
        subject_domain: &str,
        application_id: &str,
        instance_id: &str,
    ) -> QueryResult<Option<RpApplicationKeyCacheEntry>> {
        rp_application_key_cache_entries::table
            .filter(rp_application_key_cache_entries::subject_user_id.eq(subject_user_id))
            .filter(rp_application_key_cache_entries::subject_domain.eq(subject_domain))
            .filter(rp_application_key_cache_entries::application_id.eq(application_id))
            .filter(rp_application_key_cache_entries::instance_id.eq(instance_id))
            .select(RpApplicationKeyCacheEntryRow::as_select())
            .first::<RpApplicationKeyCacheEntryRow>(conn)
            .optional()
            .map(|o| o.map(Into::into))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_entry(
        conn: &mut diesel::SqliteConnection,
        subject_user_id: &str,
        subject_domain: &str,
        application_id: &str,
        instance_id: &str,
        fetched_at: chrono::DateTime<chrono::Utc>,
        revocations_checked_at: chrono::DateTime<chrono::Utc>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<RpApplicationKeyCacheEntry> {
        let fetched_at_str = fetched_at.to_rfc3339();
        let revocations_checked_at_str = revocations_checked_at.to_rfc3339();
        let now_str = now.to_rfc3339();
        conn.transaction(|conn| {
            diesel::insert_into(rp_application_key_cache_entries::table)
                .values(NewRpApplicationKeyCacheEntryRow {
                    id: uuid::Uuid::now_v7().to_string(),
                    subject_user_id: subject_user_id.to_string(),
                    subject_domain: subject_domain.to_string(),
                    application_id: application_id.to_string(),
                    instance_id: instance_id.to_string(),
                    fetched_at: fetched_at_str.clone(),
                    revocations_checked_at: revocations_checked_at_str.clone(),
                    last_used_at: now_str.clone(),
                })
                .on_conflict((
                    rp_application_key_cache_entries::subject_user_id,
                    rp_application_key_cache_entries::subject_domain,
                    rp_application_key_cache_entries::application_id,
                    rp_application_key_cache_entries::instance_id,
                ))
                .do_update()
                .set((
                    rp_application_key_cache_entries::fetched_at.eq(&fetched_at_str),
                    rp_application_key_cache_entries::revocations_checked_at
                        .eq(&revocations_checked_at_str),
                    rp_application_key_cache_entries::last_used_at.eq(&now_str),
                    rp_application_key_cache_entries::updated_at.eq(&now_str),
                ))
                .execute(conn)?;

            rp_application_key_cache_entries::table
                .filter(rp_application_key_cache_entries::subject_user_id.eq(subject_user_id))
                .filter(rp_application_key_cache_entries::subject_domain.eq(subject_domain))
                .filter(rp_application_key_cache_entries::application_id.eq(application_id))
                .filter(rp_application_key_cache_entries::instance_id.eq(instance_id))
                .select(RpApplicationKeyCacheEntryRow::as_select())
                .first::<RpApplicationKeyCacheEntryRow>(conn)
                .map(Into::into)
        })
    }

    pub fn touch_entry(
        conn: &mut diesel::SqliteConnection,
        entry_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<usize> {
        diesel::update(
            rp_application_key_cache_entries::table
                .filter(rp_application_key_cache_entries::id.eq(entry_id)),
        )
        .set(rp_application_key_cache_entries::last_used_at.eq(now.to_rfc3339()))
        .execute(conn)
    }

    pub fn count_entries(conn: &mut diesel::SqliteConnection) -> QueryResult<i64> {
        rp_application_key_cache_entries::table
            .count()
            .get_result(conn)
    }

    pub fn evict_oldest_entries(
        conn: &mut diesel::SqliteConnection,
        max_entries: i64,
    ) -> QueryResult<usize> {
        let total = count_entries(conn)?;
        let over = total - max_entries;
        if over <= 0 {
            return Ok(0);
        }
        let victims: Vec<String> = rp_application_key_cache_entries::table
            .order(rp_application_key_cache_entries::last_used_at.asc())
            .limit(over)
            .select(rp_application_key_cache_entries::id)
            .load(conn)?;
        conn.transaction(|conn| {
            diesel::delete(
                rp_application_key_attestations::table
                    .filter(rp_application_key_attestations::cache_entry_id.eq_any(&victims)),
            )
            .execute(conn)?;
            diesel::delete(
                rp_application_key_revocations::table
                    .filter(rp_application_key_revocations::cache_entry_id.eq_any(&victims)),
            )
            .execute(conn)?;
            diesel::delete(
                rp_application_key_cache_entries::table
                    .filter(rp_application_key_cache_entries::id.eq_any(&victims)),
            )
            .execute(conn)
        })
    }

    // -- Cached attestations --

    pub fn upsert_attestation(
        conn: &mut diesel::SqliteConnection,
        cache_entry_id: &str,
        key_id: &str,
        signed_attestation: &[u8],
        attestation_expires_at: chrono::DateTime<chrono::Utc>,
        verified_by_key_ids: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<usize> {
        let expires_str = attestation_expires_at.to_rfc3339();
        let now_str = now.to_rfc3339();
        diesel::insert_into(rp_application_key_attestations::table)
            .values((
                rp_application_key_attestations::id.eq(uuid::Uuid::now_v7().to_string()),
                rp_application_key_attestations::cache_entry_id.eq(cache_entry_id),
                rp_application_key_attestations::key_id.eq(key_id),
                rp_application_key_attestations::signed_attestation.eq(signed_attestation),
                rp_application_key_attestations::attestation_expires_at.eq(&expires_str),
                rp_application_key_attestations::verified_by_key_ids.eq(verified_by_key_ids),
            ))
            .on_conflict((
                rp_application_key_attestations::cache_entry_id,
                rp_application_key_attestations::key_id,
            ))
            .do_update()
            .set((
                rp_application_key_attestations::signed_attestation.eq(signed_attestation),
                rp_application_key_attestations::attestation_expires_at.eq(&expires_str),
                rp_application_key_attestations::verified_by_key_ids.eq(verified_by_key_ids),
                rp_application_key_attestations::updated_at.eq(&now_str),
            ))
            .execute(conn)
    }

    pub fn list_attestations(
        conn: &mut diesel::SqliteConnection,
        cache_entry_id: &str,
    ) -> QueryResult<Vec<RpApplicationKeyAttestationCache>> {
        rp_application_key_attestations::table
            .filter(rp_application_key_attestations::cache_entry_id.eq(cache_entry_id))
            .select(RpApplicationKeyAttestationRow::as_select())
            .load::<RpApplicationKeyAttestationRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    // -- Cached revocations --

    pub fn upsert_revocation(
        conn: &mut diesel::SqliteConnection,
        cache_entry_id: &str,
        target_key_id: &str,
        revocation: &[u8],
        revoked_at: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<usize> {
        let revoked_at_str = revoked_at.to_rfc3339();
        diesel::insert_into(rp_application_key_revocations::table)
            .values((
                rp_application_key_revocations::id.eq(uuid::Uuid::now_v7().to_string()),
                rp_application_key_revocations::cache_entry_id.eq(cache_entry_id),
                rp_application_key_revocations::target_key_id.eq(target_key_id),
                rp_application_key_revocations::revocation.eq(revocation),
                rp_application_key_revocations::revoked_at.eq(&revoked_at_str),
            ))
            .on_conflict((
                rp_application_key_revocations::cache_entry_id,
                rp_application_key_revocations::target_key_id,
            ))
            .do_update()
            .set((
                rp_application_key_revocations::revocation.eq(revocation),
                rp_application_key_revocations::revoked_at.eq(&revoked_at_str),
            ))
            .execute(conn)
    }

    pub fn list_revocations(
        conn: &mut diesel::SqliteConnection,
        cache_entry_id: &str,
    ) -> QueryResult<Vec<RpApplicationKeyRevocationCache>> {
        rp_application_key_revocations::table
            .filter(rp_application_key_revocations::cache_entry_id.eq(cache_entry_id))
            .select(RpApplicationKeyRevocationRow::as_select())
            .load::<RpApplicationKeyRevocationRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }
}
