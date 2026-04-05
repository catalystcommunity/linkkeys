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
            .load::<AuthCredentialRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
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
        auth_credentials::table
            .filter(auth_credentials::user_id.eq(user_id))
            .filter(auth_credentials::credential_type.eq(cred_type))
            .filter(auth_credentials::revoked_at.is_null())
            .load::<AuthCredentialRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }
}
