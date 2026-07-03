//! Persistence for revocation certificates this domain has ISSUED (SEC-08).
//! Written when `domain revoke-key` produces a sibling-signed cert; read by
//! DomainKeys/get-revocations to serve peers and by get-domain-keys to set the
//! `recent_revocations_available` signal. Pure storage.

#[cfg(feature = "postgres")]
pub mod pg {
    use diesel::prelude::*;

    use crate::db::models::pg::{IssuedRevocationRow, NewIssuedRevocationRow};
    use crate::db::models::IssuedRevocation;
    use crate::schema::pg::issued_revocations;

    /// Store an issued revocation. First revocation of a given key wins
    /// (`target_key_id` is unique); a repeat is a no-op. Returns rows inserted.
    pub fn insert(
        conn: &mut diesel::PgConnection,
        target_key_id: &str,
        target_fingerprint: &str,
        revoked_at: chrono::DateTime<chrono::Utc>,
        cert: &[u8],
    ) -> QueryResult<usize> {
        diesel::insert_into(issued_revocations::table)
            .values(NewIssuedRevocationRow {
                id: uuid::Uuid::now_v7(),
                target_key_id: target_key_id.to_string(),
                target_fingerprint: target_fingerprint.to_string(),
                revoked_at,
                cert: cert.to_vec(),
            })
            .on_conflict(issued_revocations::target_key_id)
            .do_nothing()
            .execute(conn)
    }

    /// List issued revocations with `revoked_at >= since` (all if `None`),
    /// newest first.
    pub fn list_since(
        conn: &mut diesel::PgConnection,
        since: Option<chrono::DateTime<chrono::Utc>>,
    ) -> QueryResult<Vec<IssuedRevocation>> {
        let mut q = issued_revocations::table.into_boxed();
        if let Some(s) = since {
            q = q.filter(issued_revocations::revoked_at.ge(s));
        }
        q.order(issued_revocations::revoked_at.desc())
            .select(IssuedRevocationRow::as_select())
            .load::<IssuedRevocationRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    /// Whether any revocation was issued with `revoked_at >= since`.
    pub fn exists_since(
        conn: &mut diesel::PgConnection,
        since: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<bool> {
        diesel::select(diesel::dsl::exists(
            issued_revocations::table.filter(issued_revocations::revoked_at.ge(since)),
        ))
        .get_result(conn)
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use diesel::prelude::*;

    use crate::db::models::sqlite::{IssuedRevocationRow, NewIssuedRevocationRow};
    use crate::db::models::IssuedRevocation;
    use crate::schema::sqlite::issued_revocations;

    pub fn insert(
        conn: &mut diesel::SqliteConnection,
        target_key_id: &str,
        target_fingerprint: &str,
        revoked_at: chrono::DateTime<chrono::Utc>,
        cert: &[u8],
    ) -> QueryResult<usize> {
        diesel::insert_into(issued_revocations::table)
            .values(NewIssuedRevocationRow {
                id: uuid::Uuid::now_v7().to_string(),
                target_key_id: target_key_id.to_string(),
                target_fingerprint: target_fingerprint.to_string(),
                revoked_at: revoked_at.to_rfc3339(),
                cert: cert.to_vec(),
            })
            .on_conflict(issued_revocations::target_key_id)
            .do_nothing()
            .execute(conn)
    }

    pub fn list_since(
        conn: &mut diesel::SqliteConnection,
        since: Option<chrono::DateTime<chrono::Utc>>,
    ) -> QueryResult<Vec<IssuedRevocation>> {
        // RFC3339 UTC strings compare lexicographically in chronological order,
        // matching how the domain_keys/user_keys expiry filters work.
        let mut q = issued_revocations::table.into_boxed();
        if let Some(s) = since {
            q = q.filter(issued_revocations::revoked_at.ge(s.to_rfc3339()));
        }
        q.order(issued_revocations::revoked_at.desc())
            .select(IssuedRevocationRow::as_select())
            .load::<IssuedRevocationRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn exists_since(
        conn: &mut diesel::SqliteConnection,
        since: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<bool> {
        diesel::select(diesel::dsl::exists(
            issued_revocations::table.filter(issued_revocations::revoked_at.ge(since.to_rfc3339())),
        ))
        .get_result(conn)
    }
}
