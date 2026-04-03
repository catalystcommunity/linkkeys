#[cfg(feature = "postgres")]
pub mod pg {
    use diesel::prelude::*;

    use crate::db::models::pg::{ClaimDbRow, NewClaimDbRow};
    use crate::db::models::ClaimRow;
    use crate::schema::pg::claims;

    pub fn create(
        conn: &mut diesel::PgConnection,
        user_id: uuid::Uuid,
        claim_type: &str,
        claim_value: &[u8],
        signed_by_key_id: uuid::Uuid,
        signature: &[u8],
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> QueryResult<ClaimRow> {
        let new_row = NewClaimDbRow {
            id: uuid::Uuid::now_v7(),
            user_id,
            claim_type: claim_type.to_string(),
            claim_value: claim_value.to_vec(),
            signed_by_key_id,
            signature: signature.to_vec(),
            expires_at,
        };

        diesel::insert_into(claims::table)
            .values(&new_row)
            .get_result::<ClaimDbRow>(conn)
            .map(Into::into)
    }

    pub fn list_active_for_user(
        conn: &mut diesel::PgConnection,
        user_id_str: &str,
    ) -> QueryResult<Vec<ClaimRow>> {
        let uid: uuid::Uuid = user_id_str
            .parse()
            .map_err(|_| diesel::result::Error::NotFound)?;
        claims::table
            .filter(claims::user_id.eq(uid))
            .filter(claims::revoked_at.is_null())
            .order(claims::created_at.asc())
            .load::<ClaimDbRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use diesel::prelude::*;

    use crate::db::models::sqlite::{ClaimDbRow, NewClaimDbRow};
    use crate::db::models::ClaimRow;
    use crate::schema::sqlite::claims;

    pub fn create(
        conn: &mut diesel::SqliteConnection,
        user_id: &str,
        claim_type: &str,
        claim_value: &[u8],
        signed_by_key_id: &str,
        signature: &[u8],
        expires_at: Option<&str>,
    ) -> QueryResult<ClaimRow> {
        let new_row = NewClaimDbRow {
            id: uuid::Uuid::now_v7().to_string(),
            user_id: user_id.to_string(),
            claim_type: claim_type.to_string(),
            claim_value: claim_value.to_vec(),
            signed_by_key_id: signed_by_key_id.to_string(),
            signature: signature.to_vec(),
            expires_at: expires_at.map(|s| s.to_string()),
        };
        let id = new_row.id.clone();

        diesel::insert_into(claims::table)
            .values(&new_row)
            .execute(conn)?;

        claims::table
            .filter(claims::id.eq(&id))
            .first::<ClaimDbRow>(conn)
            .map(Into::into)
    }

    pub fn list_active_for_user(
        conn: &mut diesel::SqliteConnection,
        user_id: &str,
    ) -> QueryResult<Vec<ClaimRow>> {
        claims::table
            .filter(claims::user_id.eq(user_id))
            .filter(claims::revoked_at.is_null())
            .order(claims::created_at.asc())
            .load::<ClaimDbRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }
}
