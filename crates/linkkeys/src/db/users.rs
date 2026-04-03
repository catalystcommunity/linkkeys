#[cfg(feature = "postgres")]
pub mod pg {
    use diesel::prelude::*;

    use crate::db::models::pg::{NewUserRow, UserRow};
    use crate::db::models::User;
    use crate::schema::pg::users;

    pub fn create(
        conn: &mut diesel::PgConnection,
        username: &str,
        display_name: &str,
        password_hash: &str,
    ) -> QueryResult<User> {
        let new_row = NewUserRow {
            id: uuid::Uuid::now_v7(),
            username: username.to_string(),
            display_name: display_name.to_string(),
            password_hash: password_hash.to_string(),
        };

        diesel::insert_into(users::table)
            .values(&new_row)
            .get_result::<UserRow>(conn)
            .map(Into::into)
    }

    pub fn find_by_id(conn: &mut diesel::PgConnection, user_id: &str) -> QueryResult<User> {
        let id: uuid::Uuid = user_id
            .parse()
            .map_err(|_| diesel::result::Error::NotFound)?;
        users::table.find(id).first::<UserRow>(conn).map(Into::into)
    }

    pub fn find_by_username(
        conn: &mut diesel::PgConnection,
        username: &str,
    ) -> QueryResult<User> {
        users::table
            .filter(users::username.eq(username))
            .first::<UserRow>(conn)
            .map(Into::into)
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use diesel::prelude::*;

    use crate::db::models::sqlite::{NewUserRow, UserRow};
    use crate::db::models::User;
    use crate::schema::sqlite::users;

    pub fn create(
        conn: &mut diesel::SqliteConnection,
        username: &str,
        display_name: &str,
        password_hash: &str,
    ) -> QueryResult<User> {
        let new_row = NewUserRow {
            id: uuid::Uuid::now_v7().to_string(),
            username: username.to_string(),
            display_name: display_name.to_string(),
            password_hash: password_hash.to_string(),
        };
        let id = new_row.id.clone();

        diesel::insert_into(users::table)
            .values(&new_row)
            .execute(conn)?;

        users::table
            .filter(users::id.eq(&id))
            .first::<UserRow>(conn)
            .map(Into::into)
    }

    pub fn find_by_id(conn: &mut diesel::SqliteConnection, user_id: &str) -> QueryResult<User> {
        users::table
            .find(user_id)
            .first::<UserRow>(conn)
            .map(Into::into)
    }

    pub fn find_by_username(
        conn: &mut diesel::SqliteConnection,
        username: &str,
    ) -> QueryResult<User> {
        users::table
            .filter(users::username.eq(username))
            .first::<UserRow>(conn)
            .map(Into::into)
    }
}
