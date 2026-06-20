//! Persistence for pending email-verification challenges. Single-use tokens that
//! expire; on confirmation the server signs the `email` / `email_verified`
//! claims and deletes the row.

#[cfg(feature = "postgres")]
pub mod pg {
    use diesel::prelude::*;

    use crate::db::models::pg::EmailVerificationRow;
    use crate::db::models::EmailVerification;
    use crate::schema::pg::email_verifications;

    pub fn create(
        conn: &mut diesel::PgConnection,
        token: &str,
        user_id: uuid::Uuid,
        email: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<usize> {
        diesel::insert_into(email_verifications::table)
            .values(EmailVerificationRow {
                token: token.to_string(),
                user_id,
                email: email.to_string(),
                expires_at,
            })
            .execute(conn)
    }

    pub fn find(
        conn: &mut diesel::PgConnection,
        token: &str,
    ) -> QueryResult<Option<EmailVerification>> {
        email_verifications::table
            .find(token)
            .select(EmailVerificationRow::as_select())
            .first::<EmailVerificationRow>(conn)
            .optional()
            .map(|o| o.map(Into::into))
    }

    pub fn delete(conn: &mut diesel::PgConnection, token: &str) -> QueryResult<usize> {
        diesel::delete(email_verifications::table.find(token)).execute(conn)
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use diesel::prelude::*;

    use crate::db::models::sqlite::EmailVerificationRow;
    use crate::db::models::EmailVerification;
    use crate::schema::sqlite::email_verifications;

    pub fn create(
        conn: &mut diesel::SqliteConnection,
        token: &str,
        user_id: &str,
        email: &str,
        expires_at: &str,
    ) -> QueryResult<usize> {
        diesel::insert_into(email_verifications::table)
            .values(EmailVerificationRow {
                token: token.to_string(),
                user_id: user_id.to_string(),
                email: email.to_string(),
                expires_at: expires_at.to_string(),
            })
            .execute(conn)
    }

    pub fn find(
        conn: &mut diesel::SqliteConnection,
        token: &str,
    ) -> QueryResult<Option<EmailVerification>> {
        email_verifications::table
            .find(token)
            .select(EmailVerificationRow::as_select())
            .first::<EmailVerificationRow>(conn)
            .optional()
            .map(|o| o.map(Into::into))
    }

    pub fn delete(conn: &mut diesel::SqliteConnection, token: &str) -> QueryResult<usize> {
        diesel::delete(email_verifications::table.find(token)).execute(conn)
    }
}
