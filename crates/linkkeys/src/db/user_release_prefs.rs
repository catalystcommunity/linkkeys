//! Persistence for a user's standing release preferences — claim types they
//! pre-authorize for an audience (or `*` = any domain), set from their own
//! profile editor. Surfaced as pre-checked rows at consent.

#[cfg(feature = "postgres")]
pub mod pg {
    use diesel::prelude::*;

    use crate::schema::pg::user_release_prefs as t;

    pub fn add(
        conn: &mut diesel::PgConnection,
        user_id: uuid::Uuid,
        audience: &str,
        claim_type: &str,
    ) -> QueryResult<usize> {
        diesel::insert_into(t::table)
            .values((
                t::user_id.eq(user_id),
                t::audience.eq(audience),
                t::claim_type.eq(claim_type),
            ))
            .on_conflict_do_nothing()
            .execute(conn)
    }

    pub fn remove(
        conn: &mut diesel::PgConnection,
        user_id: uuid::Uuid,
        audience: &str,
        claim_type: &str,
    ) -> QueryResult<usize> {
        diesel::delete(
            t::table
                .filter(t::user_id.eq(user_id))
                .filter(t::audience.eq(audience))
                .filter(t::claim_type.eq(claim_type)),
        )
        .execute(conn)
    }

    /// Claim types this user pre-allows for `audience`, including their global
    /// `*` (any domain) preferences.
    pub fn list_allows(
        conn: &mut diesel::PgConnection,
        user_id: uuid::Uuid,
        audience: &str,
    ) -> QueryResult<Vec<String>> {
        t::table
            .filter(t::user_id.eq(user_id))
            .filter(t::audience.eq(audience).or(t::audience.eq("*")))
            .select(t::claim_type)
            .load::<String>(conn)
    }

    /// All (audience, claim_type) standing prefs for the user, for the editor.
    pub fn list_all(
        conn: &mut diesel::PgConnection,
        user_id: uuid::Uuid,
    ) -> QueryResult<Vec<(String, String)>> {
        t::table
            .filter(t::user_id.eq(user_id))
            .select((t::audience, t::claim_type))
            .load::<(String, String)>(conn)
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use diesel::prelude::*;

    use crate::schema::sqlite::user_release_prefs as t;

    pub fn add(
        conn: &mut diesel::SqliteConnection,
        user_id: &str,
        audience: &str,
        claim_type: &str,
    ) -> QueryResult<usize> {
        diesel::insert_into(t::table)
            .values((
                t::user_id.eq(user_id),
                t::audience.eq(audience),
                t::claim_type.eq(claim_type),
            ))
            .on_conflict_do_nothing()
            .execute(conn)
    }

    pub fn remove(
        conn: &mut diesel::SqliteConnection,
        user_id: &str,
        audience: &str,
        claim_type: &str,
    ) -> QueryResult<usize> {
        diesel::delete(
            t::table
                .filter(t::user_id.eq(user_id))
                .filter(t::audience.eq(audience))
                .filter(t::claim_type.eq(claim_type)),
        )
        .execute(conn)
    }

    pub fn list_allows(
        conn: &mut diesel::SqliteConnection,
        user_id: &str,
        audience: &str,
    ) -> QueryResult<Vec<String>> {
        t::table
            .filter(t::user_id.eq(user_id))
            .filter(t::audience.eq(audience).or(t::audience.eq("*")))
            .select(t::claim_type)
            .load::<String>(conn)
    }

    pub fn list_all(
        conn: &mut diesel::SqliteConnection,
        user_id: &str,
    ) -> QueryResult<Vec<(String, String)>> {
        t::table
            .filter(t::user_id.eq(user_id))
            .select((t::audience, t::claim_type))
            .load::<(String, String)>(conn)
    }
}
