//! Persistence for consent grants. One active grant per (user, audience,
//! application): `upsert` replaces any existing grant for that key within a
//! transaction, and `find_active` returns the current non-revoked,
//! non-expired grant if any.
//!
//! `app` is `(subject_user_id, application_id)` of the audience's application,
//! or `None` for a grant that covers requests with no application. `None`
//! matches only rows whose application columns are NULL: a no-application
//! grant never stands in for an application, and the reverse.

/// The application key of a grant: `(subject_user_id, application_id)`.
pub type GrantApp<'a> = Option<(&'a str, &'a str)>;

#[cfg(feature = "postgres")]
pub mod pg {
    use diesel::pg::Pg;
    use diesel::prelude::*;

    use super::GrantApp;
    use crate::db::models::pg::{ConsentGrantDbRow, NewConsentGrantDbRow};
    use crate::db::models::ConsentGrantRow;
    use crate::schema::pg::consent_grants;

    fn for_key<'a>(
        user_id: uuid::Uuid,
        audience: &'a str,
        app: GrantApp<'a>,
    ) -> consent_grants::BoxedQuery<'a, Pg> {
        let query = consent_grants::table
            .filter(consent_grants::user_id.eq(user_id))
            .filter(consent_grants::audience.eq(audience))
            .into_boxed();
        match app {
            Some((subject_user_id, application_id)) => query
                .filter(consent_grants::app_subject_user_id.eq(subject_user_id))
                .filter(consent_grants::app_application_id.eq(application_id)),
            None => query
                .filter(consent_grants::app_subject_user_id.is_null())
                .filter(consent_grants::app_application_id.is_null()),
        }
    }

    /// Replace any existing grant for (user_id, audience, app) with this one.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert(
        conn: &mut diesel::PgConnection,
        id: uuid::Uuid,
        user_id: uuid::Uuid,
        subject_domain: &str,
        audience: &str,
        app: GrantApp<'_>,
        claim_types_json: &str,
        requested_types_json: &str,
        signed_grant: &[u8],
        offered_claims: Option<&[u8]>,
        issued_at: chrono::DateTime<chrono::Utc>,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<()> {
        conn.transaction(|conn| {
            let existing: Vec<uuid::Uuid> = for_key(user_id, audience, app)
                .select(consent_grants::id)
                .load(conn)?;
            diesel::delete(consent_grants::table.filter(consent_grants::id.eq_any(existing)))
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
                app_subject_user_id: app.map(|(s, _)| s.to_string()),
                app_application_id: app.map(|(_, a)| a.to_string()),
            };
            diesel::insert_into(consent_grants::table)
                .values(&new_row)
                .execute(conn)?;
            Ok(())
        })
    }

    /// The current valid grant for (user_id, audience, app): not revoked, not
    /// expired.
    pub fn find_active(
        conn: &mut diesel::PgConnection,
        user_id: uuid::Uuid,
        audience: &str,
        app: GrantApp<'_>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<Option<ConsentGrantRow>> {
        let row = for_key(user_id, audience, app)
            .filter(consent_grants::revoked_at.is_null())
            .filter(consent_grants::expires_at.gt(now))
            .select(ConsentGrantDbRow::as_select())
            .first::<ConsentGrantDbRow>(conn)
            .optional()?;
        Ok(row.map(Into::into))
    }

    /// True when any current grant exists for (user_id, audience), for any
    /// application or none.
    pub fn any_active(
        conn: &mut diesel::PgConnection,
        user_id: uuid::Uuid,
        audience: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<bool> {
        diesel::select(diesel::dsl::exists(
            consent_grants::table
                .filter(consent_grants::user_id.eq(user_id))
                .filter(consent_grants::audience.eq(audience))
                .filter(consent_grants::revoked_at.is_null())
                .filter(consent_grants::expires_at.gt(now)),
        ))
        .get_result(conn)
    }

    /// Every current grant of every user: not revoked, not expired.
    pub fn list_active_all(
        conn: &mut diesel::PgConnection,
        now: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<Vec<ConsentGrantRow>> {
        consent_grants::table
            .filter(consent_grants::revoked_at.is_null())
            .filter(consent_grants::expires_at.gt(now))
            .order(consent_grants::issued_at.asc())
            .select(ConsentGrantDbRow::as_select())
            .load::<ConsentGrantDbRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    /// Replace the stored `CBOR(SignedConsentGrant)` of one grant.
    pub fn update_signed_grant(
        conn: &mut diesel::PgConnection,
        id: uuid::Uuid,
        signed_grant: &[u8],
    ) -> QueryResult<usize> {
        diesel::update(consent_grants::table.find(id))
            .set(consent_grants::signed_grant.eq(signed_grant.to_vec()))
            .execute(conn)
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use diesel::prelude::*;
    use diesel::sqlite::Sqlite;

    use super::GrantApp;
    use crate::db::models::sqlite::{ConsentGrantDbRow, NewConsentGrantDbRow};
    use crate::db::models::ConsentGrantRow;
    use crate::schema::sqlite::consent_grants;

    fn for_key<'a>(
        user_id: &'a str,
        audience: &'a str,
        app: GrantApp<'a>,
    ) -> consent_grants::BoxedQuery<'a, Sqlite> {
        let query = consent_grants::table
            .filter(consent_grants::user_id.eq(user_id))
            .filter(consent_grants::audience.eq(audience))
            .into_boxed();
        match app {
            Some((subject_user_id, application_id)) => query
                .filter(consent_grants::app_subject_user_id.eq(subject_user_id))
                .filter(consent_grants::app_application_id.eq(application_id)),
            None => query
                .filter(consent_grants::app_subject_user_id.is_null())
                .filter(consent_grants::app_application_id.is_null()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert(
        conn: &mut diesel::SqliteConnection,
        id: &str,
        user_id: &str,
        subject_domain: &str,
        audience: &str,
        app: GrantApp<'_>,
        claim_types_json: &str,
        requested_types_json: &str,
        signed_grant: &[u8],
        offered_claims: Option<&[u8]>,
        issued_at: &str,
        expires_at: &str,
    ) -> QueryResult<()> {
        conn.transaction(|conn| {
            let existing: Vec<String> = for_key(user_id, audience, app)
                .select(consent_grants::id)
                .load(conn)?;
            diesel::delete(consent_grants::table.filter(consent_grants::id.eq_any(existing)))
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
                app_subject_user_id: app.map(|(s, _)| s.to_string()),
                app_application_id: app.map(|(_, a)| a.to_string()),
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
        app: GrantApp<'_>,
        now: &str,
    ) -> QueryResult<Option<ConsentGrantRow>> {
        let row = for_key(user_id, audience, app)
            .filter(consent_grants::revoked_at.is_null())
            .filter(consent_grants::expires_at.gt(now))
            .select(ConsentGrantDbRow::as_select())
            .first::<ConsentGrantDbRow>(conn)
            .optional()?;
        Ok(row.map(Into::into))
    }

    pub fn any_active(
        conn: &mut diesel::SqliteConnection,
        user_id: &str,
        audience: &str,
        now: &str,
    ) -> QueryResult<bool> {
        diesel::select(diesel::dsl::exists(
            consent_grants::table
                .filter(consent_grants::user_id.eq(user_id))
                .filter(consent_grants::audience.eq(audience))
                .filter(consent_grants::revoked_at.is_null())
                .filter(consent_grants::expires_at.gt(now)),
        ))
        .get_result(conn)
    }

    pub fn list_active_all(
        conn: &mut diesel::SqliteConnection,
        now: &str,
    ) -> QueryResult<Vec<ConsentGrantRow>> {
        consent_grants::table
            .filter(consent_grants::revoked_at.is_null())
            .filter(consent_grants::expires_at.gt(now))
            .order(consent_grants::issued_at.asc())
            .select(ConsentGrantDbRow::as_select())
            .load::<ConsentGrantDbRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn update_signed_grant(
        conn: &mut diesel::SqliteConnection,
        id: &str,
        signed_grant: &[u8],
    ) -> QueryResult<usize> {
        diesel::update(consent_grants::table.find(id))
            .set(consent_grants::signed_grant.eq(signed_grant.to_vec()))
            .execute(conn)
    }
}
