//! Durable single-use / replay-prevention store for auth nonces.
//!
//! A nonce row exists iff that nonce has been consumed. Recording uses an atomic
//! `INSERT ... ON CONFLICT DO NOTHING`: 1 row inserted ⇒ first use; 0 rows ⇒ the
//! nonce was already present, i.e. a replay. We deliberately do NOT rely on
//! catching a unique-violation error, because on Postgres a constraint error
//! aborts the surrounding transaction — which breaks any caller (notably the
//! test harness) that runs multiple operations in one transaction. ON CONFLICT
//! DO NOTHING is a clean no-op on both backends and is race-free. Expired rows
//! are opportunistically cleaned up on each record so the table stays small.

#[cfg(feature = "postgres")]
pub mod pg {
    use diesel::prelude::*;

    use crate::schema::pg::used_nonces;

    #[derive(Insertable)]
    #[diesel(table_name = used_nonces)]
    struct NewUsedNonce<'a> {
        nonce: &'a str,
        expires_at: chrono::DateTime<chrono::Utc>,
    }

    /// Returns Ok(true) on first use, Ok(false) on replay.
    pub fn record(
        conn: &mut diesel::PgConnection,
        nonce: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<bool> {
        let now = chrono::Utc::now();
        diesel::delete(used_nonces::table.filter(used_nonces::expires_at.lt(now))).execute(conn)?;
        let inserted = diesel::insert_into(used_nonces::table)
            .values(NewUsedNonce { nonce, expires_at })
            .on_conflict_do_nothing()
            .execute(conn)?;
        Ok(inserted == 1)
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use diesel::prelude::*;

    use crate::schema::sqlite::used_nonces;

    #[derive(Insertable)]
    #[diesel(table_name = used_nonces)]
    struct NewUsedNonce<'a> {
        nonce: &'a str,
        expires_at: &'a str,
    }

    /// Returns Ok(true) on first use, Ok(false) on replay. `expires_at` is
    /// RFC3339 UTC text; lexicographic comparison is valid for cleanup as long
    /// as all timestamps share that format.
    pub fn record(
        conn: &mut diesel::SqliteConnection,
        nonce: &str,
        expires_at: &str,
    ) -> QueryResult<bool> {
        let now = chrono::Utc::now().to_rfc3339();
        diesel::delete(used_nonces::table.filter(used_nonces::expires_at.lt(now))).execute(conn)?;
        let inserted = diesel::insert_into(used_nonces::table)
            .values(NewUsedNonce { nonce, expires_at })
            .on_conflict_do_nothing()
            .execute(conn)?;
        Ok(inserted == 1)
    }
}
