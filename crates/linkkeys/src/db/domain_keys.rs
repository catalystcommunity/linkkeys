#[cfg(feature = "postgres")]
pub mod pg {
    use diesel::prelude::*;

    use crate::db::models::pg::{DomainKeyRow, NewDomainKeyRow};
    use crate::db::models::DomainKey;
    use crate::schema::pg::domain_keys;

    /// Create a signing (Ed25519) domain key.
    pub fn create(
        conn: &mut diesel::PgConnection,
        public_key: &[u8],
        private_key_encrypted: &[u8],
        fingerprint: &str,
        algorithm: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<DomainKey> {
        let new_row = NewDomainKeyRow {
            id: uuid::Uuid::now_v7(),
            public_key: public_key.to_vec(),
            private_key_encrypted: private_key_encrypted.to_vec(),
            fingerprint: fingerprint.to_string(),
            algorithm: algorithm.to_string(),
            key_usage: "sign".to_string(),
            expires_at,
            signed_by_key_id: None,
            key_signature: None,
        };

        diesel::insert_into(domain_keys::table)
            .values(&new_row)
            .get_result::<DomainKeyRow>(conn)
            .map(Into::into)
    }

    /// Create an encryption (X25519) domain key vouched for by a signing key.
    #[allow(clippy::too_many_arguments)]
    pub fn create_encryption_key(
        conn: &mut diesel::PgConnection,
        public_key: &[u8],
        private_key_encrypted: &[u8],
        fingerprint: &str,
        signed_by_key_id: &str,
        key_signature: &[u8],
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<DomainKey> {
        let new_row = NewDomainKeyRow {
            id: uuid::Uuid::now_v7(),
            public_key: public_key.to_vec(),
            private_key_encrypted: private_key_encrypted.to_vec(),
            fingerprint: fingerprint.to_string(),
            algorithm: "x25519".to_string(),
            key_usage: "encrypt".to_string(),
            expires_at,
            signed_by_key_id: Some(signed_by_key_id.to_string()),
            key_signature: Some(key_signature.to_vec()),
        };

        diesel::insert_into(domain_keys::table)
            .values(&new_row)
            .get_result::<DomainKeyRow>(conn)
            .map(Into::into)
    }

    pub fn list_active(conn: &mut diesel::PgConnection) -> QueryResult<Vec<DomainKey>> {
        let now = chrono::Utc::now();
        domain_keys::table
            .filter(domain_keys::expires_at.gt(now))
            .filter(domain_keys::revoked_at.is_null())
            .order(domain_keys::created_at.asc())
            .load::<DomainKeyRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn list_all(conn: &mut diesel::PgConnection) -> QueryResult<Vec<DomainKey>> {
        domain_keys::table
            .order(domain_keys::created_at.asc())
            .load::<DomainKeyRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn find_by_id(conn: &mut diesel::PgConnection, key_id: &str) -> QueryResult<DomainKey> {
        let id: uuid::Uuid = key_id
            .parse()
            .map_err(|_| diesel::result::Error::NotFound)?;
        domain_keys::table
            .find(id)
            .first::<DomainKeyRow>(conn)
            .map(Into::into)
    }

    /// Mark a domain key revoked as of now, preserving an earlier revocation
    /// timestamp if one is already set (revocation time is load-bearing: messages
    /// before it stay valid). Returns the resulting row.
    pub fn revoke(conn: &mut diesel::PgConnection, key_id: &str) -> QueryResult<DomainKey> {
        let id: uuid::Uuid = key_id
            .parse()
            .map_err(|_| diesel::result::Error::NotFound)?;
        diesel::update(domain_keys::table.find(id))
            .filter(domain_keys::revoked_at.is_null())
            .set(domain_keys::revoked_at.eq(chrono::Utc::now()))
            .execute(conn)?;
        domain_keys::table
            .find(id)
            .first::<DomainKeyRow>(conn)
            .map(Into::into)
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use diesel::prelude::*;

    use crate::db::models::sqlite::{DomainKeyRow, NewDomainKeyRow};
    use crate::db::models::DomainKey;
    use crate::schema::sqlite::domain_keys;

    /// Create a signing (Ed25519) domain key.
    pub fn create(
        conn: &mut diesel::SqliteConnection,
        public_key: &[u8],
        private_key_encrypted: &[u8],
        fingerprint: &str,
        algorithm: &str,
        expires_at: &str,
    ) -> QueryResult<DomainKey> {
        let new_row = NewDomainKeyRow {
            id: uuid::Uuid::now_v7().to_string(),
            public_key: public_key.to_vec(),
            private_key_encrypted: private_key_encrypted.to_vec(),
            fingerprint: fingerprint.to_string(),
            algorithm: algorithm.to_string(),
            key_usage: "sign".to_string(),
            expires_at: expires_at.to_string(),
            signed_by_key_id: None,
            key_signature: None,
        };
        let id = new_row.id.clone();

        diesel::insert_into(domain_keys::table)
            .values(&new_row)
            .execute(conn)?;

        domain_keys::table
            .filter(domain_keys::id.eq(&id))
            .first::<DomainKeyRow>(conn)
            .map(Into::into)
    }

    /// Create an encryption (X25519) domain key vouched for by a signing key.
    #[allow(clippy::too_many_arguments)]
    pub fn create_encryption_key(
        conn: &mut diesel::SqliteConnection,
        public_key: &[u8],
        private_key_encrypted: &[u8],
        fingerprint: &str,
        signed_by_key_id: &str,
        key_signature: &[u8],
        expires_at: &str,
    ) -> QueryResult<DomainKey> {
        let new_row = NewDomainKeyRow {
            id: uuid::Uuid::now_v7().to_string(),
            public_key: public_key.to_vec(),
            private_key_encrypted: private_key_encrypted.to_vec(),
            fingerprint: fingerprint.to_string(),
            algorithm: "x25519".to_string(),
            key_usage: "encrypt".to_string(),
            expires_at: expires_at.to_string(),
            signed_by_key_id: Some(signed_by_key_id.to_string()),
            key_signature: Some(key_signature.to_vec()),
        };
        let id = new_row.id.clone();

        diesel::insert_into(domain_keys::table)
            .values(&new_row)
            .execute(conn)?;

        domain_keys::table
            .filter(domain_keys::id.eq(&id))
            .first::<DomainKeyRow>(conn)
            .map(Into::into)
    }

    pub fn list_active(conn: &mut diesel::SqliteConnection) -> QueryResult<Vec<DomainKey>> {
        let now = chrono::Utc::now().to_rfc3339();
        domain_keys::table
            .filter(domain_keys::expires_at.gt(&now))
            .filter(domain_keys::revoked_at.is_null())
            .order(domain_keys::created_at.asc())
            .load::<DomainKeyRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn list_all(conn: &mut diesel::SqliteConnection) -> QueryResult<Vec<DomainKey>> {
        domain_keys::table
            .order(domain_keys::created_at.asc())
            .load::<DomainKeyRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn find_by_id(conn: &mut diesel::SqliteConnection, key_id: &str) -> QueryResult<DomainKey> {
        domain_keys::table
            .find(key_id)
            .first::<DomainKeyRow>(conn)
            .map(Into::into)
    }

    /// Mark a domain key revoked as of now, preserving an earlier revocation
    /// timestamp if already set. Returns the resulting row.
    pub fn revoke(conn: &mut diesel::SqliteConnection, key_id: &str) -> QueryResult<DomainKey> {
        diesel::update(domain_keys::table.find(key_id))
            .filter(domain_keys::revoked_at.is_null())
            .set(domain_keys::revoked_at.eq(chrono::Utc::now().to_rfc3339()))
            .execute(conn)?;
        domain_keys::table
            .find(key_id)
            .first::<DomainKeyRow>(conn)
            .map(Into::into)
    }
}
