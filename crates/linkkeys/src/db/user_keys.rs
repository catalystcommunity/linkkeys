#[cfg(feature = "postgres")]
pub mod pg {
    use diesel::prelude::*;

    use crate::db::models::pg::{NewUserKeyRow, UserKeyRow};
    use crate::db::models::UserKey;
    use crate::schema::pg::user_keys;

    pub fn create(
        conn: &mut diesel::PgConnection,
        user_id: uuid::Uuid,
        public_key: &[u8],
        private_key_encrypted: &[u8],
        fingerprint: &str,
        algorithm: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<UserKey> {
        let new_row = NewUserKeyRow {
            id: uuid::Uuid::now_v7(),
            user_id,
            public_key: public_key.to_vec(),
            private_key_encrypted: private_key_encrypted.to_vec(),
            fingerprint: fingerprint.to_string(),
            algorithm: algorithm.to_string(),
            expires_at,
        };

        diesel::insert_into(user_keys::table)
            .values(&new_row)
            .get_result::<UserKeyRow>(conn)
            .map(Into::into)
    }

    pub fn list_active_for_user(
        conn: &mut diesel::PgConnection,
        user_id_str: &str,
    ) -> QueryResult<Vec<UserKey>> {
        let uid: uuid::Uuid = user_id_str
            .parse()
            .map_err(|_| diesel::result::Error::NotFound)?;
        let now = chrono::Utc::now();
        user_keys::table
            .filter(user_keys::user_id.eq(uid))
            .filter(user_keys::expires_at.gt(now))
            .filter(user_keys::revoked_at.is_null())
            .order(user_keys::created_at.asc())
            .load::<UserKeyRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use diesel::prelude::*;

    use crate::db::models::sqlite::{NewUserKeyRow, UserKeyRow};
    use crate::db::models::UserKey;
    use crate::schema::sqlite::user_keys;

    pub fn create(
        conn: &mut diesel::SqliteConnection,
        user_id: &str,
        public_key: &[u8],
        private_key_encrypted: &[u8],
        fingerprint: &str,
        algorithm: &str,
        expires_at: &str,
    ) -> QueryResult<UserKey> {
        let new_row = NewUserKeyRow {
            id: uuid::Uuid::now_v7().to_string(),
            user_id: user_id.to_string(),
            public_key: public_key.to_vec(),
            private_key_encrypted: private_key_encrypted.to_vec(),
            fingerprint: fingerprint.to_string(),
            algorithm: algorithm.to_string(),
            expires_at: expires_at.to_string(),
        };
        let id = new_row.id.clone();

        diesel::insert_into(user_keys::table)
            .values(&new_row)
            .execute(conn)?;

        user_keys::table
            .filter(user_keys::id.eq(&id))
            .first::<UserKeyRow>(conn)
            .map(Into::into)
    }

    pub fn list_active_for_user(
        conn: &mut diesel::SqliteConnection,
        user_id: &str,
    ) -> QueryResult<Vec<UserKey>> {
        let now = chrono::Utc::now().to_rfc3339();
        user_keys::table
            .filter(user_keys::user_id.eq(user_id))
            .filter(user_keys::expires_at.gt(&now))
            .filter(user_keys::revoked_at.is_null())
            .order(user_keys::created_at.asc())
            .load::<UserKeyRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }
}
