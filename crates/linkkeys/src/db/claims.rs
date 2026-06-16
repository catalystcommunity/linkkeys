#[cfg(feature = "postgres")]
pub mod pg {
    use diesel::prelude::*;
    use std::collections::HashMap;

    use crate::db::models::pg::{
        ClaimDbRow, ClaimSignatureDbRow, NewClaimDbRow, NewClaimSignatureDbRow,
    };
    use crate::db::models::{ClaimRow, ClaimSignatureRow};
    use crate::schema::pg::{claim_signatures, claims};
    use liblinkkeys::generated::types::ClaimSignature;

    /// Insert a claim and its signatures atomically, returning the stored claim
    /// with its signatures attached.
    pub fn create(
        conn: &mut diesel::PgConnection,
        id: uuid::Uuid,
        user_id: uuid::Uuid,
        claim_type: &str,
        claim_value: &[u8],
        signatures: &[ClaimSignature],
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> QueryResult<ClaimRow> {
        conn.transaction(|conn| {
            let new_row = NewClaimDbRow {
                id,
                user_id,
                claim_type: claim_type.to_string(),
                claim_value: claim_value.to_vec(),
                expires_at,
            };
            diesel::insert_into(claims::table)
                .values(&new_row)
                .execute(conn)?;
            insert_signatures(conn, id, signatures)?;
            load_with_signatures(conn, id)
        })
    }

    /// Replace every signature on a claim. Used by the pre-alpha re-sign backfill.
    pub fn replace_signatures(
        conn: &mut diesel::PgConnection,
        claim_id: uuid::Uuid,
        signatures: &[ClaimSignature],
    ) -> QueryResult<()> {
        conn.transaction(|conn| {
            diesel::delete(claim_signatures::table.filter(claim_signatures::claim_id.eq(claim_id)))
                .execute(conn)?;
            insert_signatures(conn, claim_id, signatures)
        })
    }

    fn insert_signatures(
        conn: &mut diesel::PgConnection,
        claim_id: uuid::Uuid,
        signatures: &[ClaimSignature],
    ) -> QueryResult<()> {
        let mut rows = Vec::with_capacity(signatures.len());
        for s in signatures {
            let key_id: uuid::Uuid = s
                .signed_by_key_id
                .parse()
                .map_err(|_| diesel::result::Error::NotFound)?;
            rows.push(NewClaimSignatureDbRow {
                id: uuid::Uuid::now_v7(),
                claim_id,
                domain: s.domain.clone(),
                signed_by_key_id: key_id,
                signature: s.signature.clone(),
            });
        }
        if !rows.is_empty() {
            diesel::insert_into(claim_signatures::table)
                .values(&rows)
                .execute(conn)?;
        }
        Ok(())
    }

    fn load_signatures(
        conn: &mut diesel::PgConnection,
        claim_id: uuid::Uuid,
    ) -> QueryResult<Vec<ClaimSignatureRow>> {
        claim_signatures::table
            .filter(claim_signatures::claim_id.eq(claim_id))
            .order(claim_signatures::created_at.asc())
            .load::<ClaimSignatureDbRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    fn load_with_signatures(
        conn: &mut diesel::PgConnection,
        claim_id: uuid::Uuid,
    ) -> QueryResult<ClaimRow> {
        let mut row: ClaimRow = claims::table
            .find(claim_id)
            .first::<ClaimDbRow>(conn)?
            .into();
        row.signatures = load_signatures(conn, claim_id)?;
        Ok(row)
    }

    /// Attach signatures to a batch of claim rows in a single extra query.
    fn attach_signatures(
        conn: &mut diesel::PgConnection,
        db_rows: Vec<ClaimDbRow>,
    ) -> QueryResult<Vec<ClaimRow>> {
        let ids: Vec<uuid::Uuid> = db_rows.iter().map(|r| r.id).collect();
        let sigs = claim_signatures::table
            .filter(claim_signatures::claim_id.eq_any(ids))
            .order(claim_signatures::created_at.asc())
            .load::<ClaimSignatureDbRow>(conn)?;
        let mut by_claim: HashMap<uuid::Uuid, Vec<ClaimSignatureRow>> = HashMap::new();
        for s in sigs {
            by_claim.entry(s.claim_id).or_default().push(s.into());
        }
        Ok(db_rows
            .into_iter()
            .map(|r| {
                let cid = r.id;
                let mut row: ClaimRow = r.into();
                row.signatures = by_claim.remove(&cid).unwrap_or_default();
                row
            })
            .collect())
    }

    pub fn list_active_for_user(
        conn: &mut diesel::PgConnection,
        user_id_str: &str,
    ) -> QueryResult<Vec<ClaimRow>> {
        let uid: uuid::Uuid = user_id_str
            .parse()
            .map_err(|_| diesel::result::Error::NotFound)?;
        // Active = not revoked AND (no expiry OR expiry in the future).
        let now = chrono::Utc::now();
        let db_rows = claims::table
            .filter(claims::user_id.eq(uid))
            .filter(claims::revoked_at.is_null())
            .filter(claims::expires_at.is_null().or(claims::expires_at.gt(now)))
            .order(claims::created_at.asc())
            .load::<ClaimDbRow>(conn)?;
        attach_signatures(conn, db_rows)
    }

    /// All claims with signatures attached, regardless of revocation/expiry.
    /// Used by the pre-alpha re-sign backfill.
    pub fn list_all(conn: &mut diesel::PgConnection) -> QueryResult<Vec<ClaimRow>> {
        let db_rows = claims::table
            .order(claims::created_at.asc())
            .load::<ClaimDbRow>(conn)?;
        attach_signatures(conn, db_rows)
    }

    pub fn find_by_id(conn: &mut diesel::PgConnection, claim_id: &str) -> QueryResult<ClaimRow> {
        let id: uuid::Uuid = claim_id
            .parse()
            .map_err(|_| diesel::result::Error::NotFound)?;
        load_with_signatures(conn, id)
    }

    pub fn remove(conn: &mut diesel::PgConnection, claim_id: &str) -> QueryResult<ClaimRow> {
        let id: uuid::Uuid = claim_id
            .parse()
            .map_err(|_| diesel::result::Error::NotFound)?;
        diesel::update(claims::table.find(id))
            .set((
                claims::revoked_at.eq(Some(chrono::Utc::now())),
                claims::updated_at.eq(chrono::Utc::now()),
            ))
            .execute(conn)?;
        load_with_signatures(conn, id)
    }

    /// Claims with no signature rows — legacy claims left unsigned by the
    /// claim_signatures migration. Used by the pre-alpha re-sign backfill. The
    /// returned rows intentionally carry empty `signatures`.
    pub fn list_missing_signatures(conn: &mut diesel::PgConnection) -> QueryResult<Vec<ClaimRow>> {
        let signed: Vec<uuid::Uuid> = claim_signatures::table
            .select(claim_signatures::claim_id)
            .distinct()
            .load(conn)?;
        let db_rows = claims::table
            .filter(claims::id.ne_all(signed))
            .order(claims::created_at.asc())
            .load::<ClaimDbRow>(conn)?;
        Ok(db_rows.into_iter().map(Into::into).collect())
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use diesel::prelude::*;
    use std::collections::HashMap;

    use crate::db::models::sqlite::{
        ClaimDbRow, ClaimSignatureDbRow, NewClaimDbRow, NewClaimSignatureDbRow,
    };
    use crate::db::models::{ClaimRow, ClaimSignatureRow};
    use crate::schema::sqlite::{claim_signatures, claims};
    use liblinkkeys::generated::types::ClaimSignature;

    /// Insert a claim and its signatures atomically, returning the stored claim
    /// with its signatures attached.
    pub fn create(
        conn: &mut diesel::SqliteConnection,
        id: &str,
        user_id: &str,
        claim_type: &str,
        claim_value: &[u8],
        signatures: &[ClaimSignature],
        expires_at: Option<&str>,
    ) -> QueryResult<ClaimRow> {
        conn.transaction(|conn| {
            let new_row = NewClaimDbRow {
                id: id.to_string(),
                user_id: user_id.to_string(),
                claim_type: claim_type.to_string(),
                claim_value: claim_value.to_vec(),
                expires_at: expires_at.map(|s| s.to_string()),
            };
            diesel::insert_into(claims::table)
                .values(&new_row)
                .execute(conn)?;
            insert_signatures(conn, id, signatures)?;
            load_with_signatures(conn, id)
        })
    }

    /// Replace every signature on a claim. Used by the pre-alpha re-sign backfill.
    pub fn replace_signatures(
        conn: &mut diesel::SqliteConnection,
        claim_id: &str,
        signatures: &[ClaimSignature],
    ) -> QueryResult<()> {
        conn.transaction(|conn| {
            diesel::delete(claim_signatures::table.filter(claim_signatures::claim_id.eq(claim_id)))
                .execute(conn)?;
            insert_signatures(conn, claim_id, signatures)
        })
    }

    fn insert_signatures(
        conn: &mut diesel::SqliteConnection,
        claim_id: &str,
        signatures: &[ClaimSignature],
    ) -> QueryResult<()> {
        let rows: Vec<NewClaimSignatureDbRow> = signatures
            .iter()
            .map(|s| NewClaimSignatureDbRow {
                id: uuid::Uuid::now_v7().to_string(),
                claim_id: claim_id.to_string(),
                domain: s.domain.clone(),
                signed_by_key_id: s.signed_by_key_id.clone(),
                signature: s.signature.clone(),
            })
            .collect();
        if !rows.is_empty() {
            diesel::insert_into(claim_signatures::table)
                .values(&rows)
                .execute(conn)?;
        }
        Ok(())
    }

    fn load_signatures(
        conn: &mut diesel::SqliteConnection,
        claim_id: &str,
    ) -> QueryResult<Vec<ClaimSignatureRow>> {
        claim_signatures::table
            .filter(claim_signatures::claim_id.eq(claim_id))
            .order(claim_signatures::created_at.asc())
            .load::<ClaimSignatureDbRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    fn load_with_signatures(
        conn: &mut diesel::SqliteConnection,
        claim_id: &str,
    ) -> QueryResult<ClaimRow> {
        let mut row: ClaimRow = claims::table
            .find(claim_id)
            .first::<ClaimDbRow>(conn)?
            .into();
        row.signatures = load_signatures(conn, claim_id)?;
        Ok(row)
    }

    /// Attach signatures to a batch of claim rows in a single extra query.
    fn attach_signatures(
        conn: &mut diesel::SqliteConnection,
        db_rows: Vec<ClaimDbRow>,
    ) -> QueryResult<Vec<ClaimRow>> {
        let ids: Vec<String> = db_rows.iter().map(|r| r.id.clone()).collect();
        let sigs = claim_signatures::table
            .filter(claim_signatures::claim_id.eq_any(ids))
            .order(claim_signatures::created_at.asc())
            .load::<ClaimSignatureDbRow>(conn)?;
        let mut by_claim: HashMap<String, Vec<ClaimSignatureRow>> = HashMap::new();
        for s in sigs {
            by_claim
                .entry(s.claim_id.clone())
                .or_default()
                .push(s.into());
        }
        Ok(db_rows
            .into_iter()
            .map(|r| {
                let cid = r.id.clone();
                let mut row: ClaimRow = r.into();
                row.signatures = by_claim.remove(&cid).unwrap_or_default();
                row
            })
            .collect())
    }

    pub fn list_active_for_user(
        conn: &mut diesel::SqliteConnection,
        user_id: &str,
    ) -> QueryResult<Vec<ClaimRow>> {
        // Active = not revoked AND (no expiry OR expiry in the future).
        // expires_at is stored as RFC3339 UTC text; lexicographic comparison is
        // correct as long as all timestamps use the same UTC format (they do,
        // via chrono to_rfc3339).
        let now = chrono::Utc::now().to_rfc3339();
        let db_rows = claims::table
            .filter(claims::user_id.eq(user_id))
            .filter(claims::revoked_at.is_null())
            .filter(claims::expires_at.is_null().or(claims::expires_at.gt(now)))
            .order(claims::created_at.asc())
            .load::<ClaimDbRow>(conn)?;
        attach_signatures(conn, db_rows)
    }

    /// All claims with signatures attached, regardless of revocation/expiry.
    /// Used by the pre-alpha re-sign backfill.
    pub fn list_all(conn: &mut diesel::SqliteConnection) -> QueryResult<Vec<ClaimRow>> {
        let db_rows = claims::table
            .order(claims::created_at.asc())
            .load::<ClaimDbRow>(conn)?;
        attach_signatures(conn, db_rows)
    }

    pub fn find_by_id(
        conn: &mut diesel::SqliteConnection,
        claim_id: &str,
    ) -> QueryResult<ClaimRow> {
        load_with_signatures(conn, claim_id)
    }

    pub fn remove(conn: &mut diesel::SqliteConnection, claim_id: &str) -> QueryResult<ClaimRow> {
        let now = chrono::Utc::now().to_rfc3339();
        diesel::update(claims::table.find(claim_id))
            .set((
                claims::revoked_at.eq(Some(&now)),
                claims::updated_at.eq(&now),
            ))
            .execute(conn)?;
        load_with_signatures(conn, claim_id)
    }

    /// Claims with no signature rows — legacy claims left unsigned by the
    /// claim_signatures migration. Used by the pre-alpha re-sign backfill. The
    /// returned rows intentionally carry empty `signatures`.
    pub fn list_missing_signatures(
        conn: &mut diesel::SqliteConnection,
    ) -> QueryResult<Vec<ClaimRow>> {
        let signed: Vec<String> = claim_signatures::table
            .select(claim_signatures::claim_id)
            .distinct()
            .load(conn)?;
        let db_rows = claims::table
            .filter(claims::id.ne_all(signed))
            .order(claims::created_at.asc())
            .load::<ClaimDbRow>(conn)?;
        Ok(db_rows.into_iter().map(Into::into).collect())
    }
}
