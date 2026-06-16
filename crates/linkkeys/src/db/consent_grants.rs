//! Persistence for consent grants. One active grant per (user, audience):
//! `upsert` replaces any existing grant for the pair within a transaction, and
//! `find_active` returns the current non-revoked, non-expired grant if any.

#[cfg(feature = "postgres")]
pub mod pg {
    use diesel::prelude::*;

    use crate::db::models::pg::{ConsentGrantDbRow, NewConsentGrantDbRow};
    use crate::db::models::ConsentGrantRow;
    use crate::schema::pg::consent_grants;

    /// Replace any existing grant for (user_id, audience) with this one.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert(
        conn: &mut diesel::PgConnection,
        id: uuid::Uuid,
        user_id: uuid::Uuid,
        subject_domain: &str,
        audience: &str,
        claim_types_json: &str,
        requested_types_json: &str,
        signed_grant: &[u8],
        offered_claims: Option<&[u8]>,
        issued_at: chrono::DateTime<chrono::Utc>,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<()> {
        conn.transaction(|conn| {
            diesel::delete(
                consent_grants::table
                    .filter(consent_grants::user_id.eq(user_id))
                    .filter(consent_grants::audience.eq(audience)),
            )
            .execute(conn)?;
            let new_row = NewConsentGrantDbRow {
                id,
                user_id,
                subject_domain: subject_domain.to_string(),
                audience: audience.to_string(),
                claim_types: claim_types_json.to_string(),
                requested_types: requested_types_json.to_string(),
                signed_grant: signed_grant.to_vec(),
                offered_claims: offered_claims.map(|b| b.to_vec()),
                issued_at,
                expires_at,
            };
            diesel::insert_into(consent_grants::table)
                .values(&new_row)
                .execute(conn)?;
            Ok(())
        })
    }

    /// The current valid grant for (user_id, audience): not revoked, not expired.
    pub fn find_active(
        conn: &mut diesel::PgConnection,
        user_id: uuid::Uuid,
        audience: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<Option<ConsentGrantRow>> {
        let row = consent_grants::table
            .filter(consent_grants::user_id.eq(user_id))
            .filter(consent_grants::audience.eq(audience))
            .filter(consent_grants::revoked_at.is_null())
            .filter(consent_grants::expires_at.gt(now))
            .select(ConsentGrantDbRow::as_select())
            .first::<ConsentGrantDbRow>(conn)
            .optional()?;
        Ok(row.map(Into::into))
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use diesel::prelude::*;

    use crate::db::models::sqlite::{ConsentGrantDbRow, NewConsentGrantDbRow};
    use crate::db::models::ConsentGrantRow;
    use crate::schema::sqlite::consent_grants;

    #[allow(clippy::too_many_arguments)]
    pub fn upsert(
        conn: &mut diesel::SqliteConnection,
        id: &str,
        user_id: &str,
        subject_domain: &str,
        audience: &str,
        claim_types_json: &str,
        requested_types_json: &str,
        signed_grant: &[u8],
        offered_claims: Option<&[u8]>,
        issued_at: &str,
        expires_at: &str,
    ) -> QueryResult<()> {
        conn.transaction(|conn| {
            diesel::delete(
                consent_grants::table
                    .filter(consent_grants::user_id.eq(user_id))
                    .filter(consent_grants::audience.eq(audience)),
            )
            .execute(conn)?;
            let new_row = NewConsentGrantDbRow {
                id: id.to_string(),
                user_id: user_id.to_string(),
                subject_domain: subject_domain.to_string(),
                audience: audience.to_string(),
                claim_types: claim_types_json.to_string(),
                requested_types: requested_types_json.to_string(),
                signed_grant: signed_grant.to_vec(),
                offered_claims: offered_claims.map(|b| b.to_vec()),
                issued_at: issued_at.to_string(),
                expires_at: expires_at.to_string(),
            };
            diesel::insert_into(consent_grants::table)
                .values(&new_row)
                .execute(conn)?;
            Ok(())
        })
    }

    /// `now` is an RFC3339 string; expiry comparison is lexicographic, which is
    /// correct for RFC3339 timestamps stored as text.
    pub fn find_active(
        conn: &mut diesel::SqliteConnection,
        user_id: &str,
        audience: &str,
        now: &str,
    ) -> QueryResult<Option<ConsentGrantRow>> {
        let row = consent_grants::table
            .filter(consent_grants::user_id.eq(user_id))
            .filter(consent_grants::audience.eq(audience))
            .filter(consent_grants::revoked_at.is_null())
            .filter(consent_grants::expires_at.gt(now))
            .select(ConsentGrantDbRow::as_select())
            .first::<ConsentGrantDbRow>(conn)
            .optional()?;
        Ok(row.map(Into::into))
    }
}
