//! Persistence for this domain's sign-in length (`sign_in_policy`). Pure
//! storage only; the default and the allowed range live in
//! `crate::services::browser_session`.

#[cfg(feature = "postgres")]
pub mod pg {
    use crate::db::models::pg::SignInPolicyRow;
    use crate::schema::pg::sign_in_policy;
    use diesel::prelude::*;

    pub fn get(conn: &mut diesel::PgConnection, domain: &str) -> QueryResult<Option<i32>> {
        sign_in_policy::table
            .find(domain)
            .select(sign_in_policy::sign_in_hours)
            .first::<i32>(conn)
            .optional()
    }

    pub fn set(conn: &mut diesel::PgConnection, domain: &str, hours: i32) -> QueryResult<usize> {
        diesel::insert_into(sign_in_policy::table)
            .values(&SignInPolicyRow {
                domain: domain.to_string(),
                sign_in_hours: hours,
            })
            .on_conflict(sign_in_policy::domain)
            .do_update()
            .set(sign_in_policy::sign_in_hours.eq(hours))
            .execute(conn)
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use crate::db::models::sqlite::SignInPolicyRow;
    use crate::schema::sqlite::sign_in_policy;
    use diesel::prelude::*;

    pub fn get(conn: &mut diesel::SqliteConnection, domain: &str) -> QueryResult<Option<i32>> {
        sign_in_policy::table
            .find(domain)
            .select(sign_in_policy::sign_in_hours)
            .first::<i32>(conn)
            .optional()
    }

    pub fn set(
        conn: &mut diesel::SqliteConnection,
        domain: &str,
        hours: i32,
    ) -> QueryResult<usize> {
        diesel::insert_into(sign_in_policy::table)
            .values(&SignInPolicyRow {
                domain: domain.to_string(),
                sign_in_hours: hours,
            })
            .on_conflict(sign_in_policy::domain)
            .do_update()
            .set(sign_in_policy::sign_in_hours.eq(hours))
            .execute(conn)
    }
}
