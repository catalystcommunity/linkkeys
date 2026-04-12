#[cfg(feature = "postgres")]
pub mod pg {
    use diesel::prelude::*;

    use crate::db::models::pg::{AuthCredentialRow, NewAuthCredentialRow};
    use crate::db::models::AuthCredential;
    use crate::schema::pg::auth_credentials;

    pub fn create(
        conn: &mut diesel::PgConnection,
        user_id: uuid::Uuid,
        credential_type: &str,
        credential_hash: &str,
    ) -> QueryResult<AuthCredential> {
        let new_row = NewAuthCredentialRow {
            id: uuid::Uuid::now_v7(),
            user_id,
            credential_type: credential_type.to_string(),
            credential_hash: credential_hash.to_string(),
        };

        diesel::insert_into(auth_credentials::table)
            .values(&new_row)
            .get_result::<AuthCredentialRow>(conn)
            .map(Into::into)
    }

    pub fn find_for_user(
        conn: &mut diesel::PgConnection,
        user_id_str: &str,
        cred_type: &str,
    ) -> QueryResult<Vec<AuthCredential>> {
        let uid: uuid::Uuid = user_id_str
            .parse()
            .map_err(|_| diesel::result::Error::NotFound)?;
        auth_credentials::table
            .filter(auth_credentials::user_id.eq(uid))
            .filter(auth_credentials::credential_type.eq(cred_type))
            .filter(auth_credentials::revoked_at.is_null())
            .filter(
                auth_credentials::expires_at
                    .is_null()
                    .or(auth_credentials::expires_at.gt(chrono::Utc::now())),
            )
            .load::<AuthCredentialRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn find_by_id(
        conn: &mut diesel::PgConnection,
        credential_id: &str,
    ) -> QueryResult<AuthCredential> {
        let id: uuid::Uuid = credential_id
            .parse()
            .map_err(|_| diesel::result::Error::NotFound)?;
        auth_credentials::table
            .find(id)
            .first::<AuthCredentialRow>(conn)
            .map(Into::into)
    }

    pub fn revoke_all_for_user(
        conn: &mut diesel::PgConnection,
        user_id_str: &str,
    ) -> QueryResult<usize> {
        let uid: uuid::Uuid = user_id_str
            .parse()
            .map_err(|_| diesel::result::Error::NotFound)?;
        diesel::update(
            auth_credentials::table
                .filter(auth_credentials::user_id.eq(uid))
                .filter(auth_credentials::revoked_at.is_null()),
        )
        .set((
            auth_credentials::revoked_at.eq(Some(chrono::Utc::now())),
            auth_credentials::updated_at.eq(chrono::Utc::now()),
        ))
        .execute(conn)
    }

    pub fn remove(
        conn: &mut diesel::PgConnection,
        credential_id: &str,
    ) -> QueryResult<AuthCredential> {
        let id: uuid::Uuid = credential_id
            .parse()
            .map_err(|_| diesel::result::Error::NotFound)?;
        diesel::update(auth_credentials::table.find(id))
            .set((
                auth_credentials::revoked_at.eq(Some(chrono::Utc::now())),
                auth_credentials::updated_at.eq(chrono::Utc::now()),
            ))
            .get_result::<AuthCredentialRow>(conn)
            .map(Into::into)
    }

    pub fn update_hash(
        conn: &mut diesel::PgConnection,
        credential_id: &str,
        new_hash: &str,
    ) -> QueryResult<AuthCredential> {
        let id: uuid::Uuid = credential_id
            .parse()
            .map_err(|_| diesel::result::Error::NotFound)?;
        diesel::update(auth_credentials::table.find(id))
            .set((
                auth_credentials::credential_hash.eq(new_hash),
                auth_credentials::updated_at.eq(chrono::Utc::now()),
            ))
            .get_result::<AuthCredentialRow>(conn)
            .map(Into::into)
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use diesel::prelude::*;

    use crate::db::models::sqlite::{AuthCredentialRow, NewAuthCredentialRow};
    use crate::db::models::AuthCredential;
    use crate::schema::sqlite::auth_credentials;

    pub fn create(
        conn: &mut diesel::SqliteConnection,
        user_id: &str,
        credential_type: &str,
        credential_hash: &str,
    ) -> QueryResult<AuthCredential> {
        let new_row = NewAuthCredentialRow {
            id: uuid::Uuid::now_v7().to_string(),
            user_id: user_id.to_string(),
            credential_type: credential_type.to_string(),
            credential_hash: credential_hash.to_string(),
        };
        let id = new_row.id.clone();

        diesel::insert_into(auth_credentials::table)
            .values(&new_row)
            .execute(conn)?;

        auth_credentials::table
            .filter(auth_credentials::id.eq(&id))
            .first::<AuthCredentialRow>(conn)
            .map(Into::into)
    }

    pub fn find_for_user(
        conn: &mut diesel::SqliteConnection,
        user_id: &str,
        cred_type: &str,
    ) -> QueryResult<Vec<AuthCredential>> {
        let now_rfc3339 = chrono::Utc::now().to_rfc3339();
        auth_credentials::table
            .filter(auth_credentials::user_id.eq(user_id))
            .filter(auth_credentials::credential_type.eq(cred_type))
            .filter(auth_credentials::revoked_at.is_null())
            .filter(
                auth_credentials::expires_at
                    .is_null()
                    .or(auth_credentials::expires_at.gt(now_rfc3339)),
            )
            .load::<AuthCredentialRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn find_by_id(
        conn: &mut diesel::SqliteConnection,
        credential_id: &str,
    ) -> QueryResult<AuthCredential> {
        auth_credentials::table
            .find(credential_id)
            .first::<AuthCredentialRow>(conn)
            .map(Into::into)
    }

    pub fn revoke_all_for_user(
        conn: &mut diesel::SqliteConnection,
        user_id: &str,
    ) -> QueryResult<usize> {
        let now = chrono::Utc::now().to_rfc3339();
        diesel::update(
            auth_credentials::table
                .filter(auth_credentials::user_id.eq(user_id))
                .filter(auth_credentials::revoked_at.is_null()),
        )
        .set((
            auth_credentials::revoked_at.eq(Some(&now)),
            auth_credentials::updated_at.eq(&now),
        ))
        .execute(conn)
    }

    pub fn remove(
        conn: &mut diesel::SqliteConnection,
        credential_id: &str,
    ) -> QueryResult<AuthCredential> {
        let now = chrono::Utc::now().to_rfc3339();
        diesel::update(auth_credentials::table.find(credential_id))
            .set((
                auth_credentials::revoked_at.eq(Some(&now)),
                auth_credentials::updated_at.eq(&now),
            ))
            .execute(conn)?;

        auth_credentials::table
            .find(credential_id)
            .first::<AuthCredentialRow>(conn)
            .map(Into::into)
    }

    pub fn update_hash(
        conn: &mut diesel::SqliteConnection,
        credential_id: &str,
        new_hash: &str,
    ) -> QueryResult<AuthCredential> {
        let now = chrono::Utc::now().to_rfc3339();
        diesel::update(auth_credentials::table.find(credential_id))
            .set((
                auth_credentials::credential_hash.eq(new_hash),
                auth_credentials::updated_at.eq(&now),
            ))
            .execute(conn)?;

        auth_credentials::table
            .find(credential_id)
            .first::<AuthCredentialRow>(conn)
            .map(Into::into)
    }
}
