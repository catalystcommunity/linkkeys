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
    ) -> QueryResult<User> {
        let new_row = NewUserRow {
            id: uuid::Uuid::now_v7(),
            username: username.to_string(),
            display_name: display_name.to_string(),
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

    pub fn list_all(conn: &mut diesel::PgConnection) -> QueryResult<Vec<User>> {
        users::table
            .order(users::created_at.asc())
            .load::<UserRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn update_display_name(
        conn: &mut diesel::PgConnection,
        user_id: &str,
        new_display_name: &str,
    ) -> QueryResult<User> {
        let id: uuid::Uuid = user_id
            .parse()
            .map_err(|_| diesel::result::Error::NotFound)?;
        diesel::update(users::table.find(id))
            .set((
                users::display_name.eq(new_display_name),
                users::updated_at.eq(chrono::Utc::now()),
            ))
            .get_result::<UserRow>(conn)
            .map(Into::into)
    }

    pub fn deactivate(conn: &mut diesel::PgConnection, user_id: &str) -> QueryResult<User> {
        let id: uuid::Uuid = user_id
            .parse()
            .map_err(|_| diesel::result::Error::NotFound)?;
        diesel::update(users::table.find(id))
            .set((
                users::is_active.eq(false),
                users::updated_at.eq(chrono::Utc::now()),
            ))
            .get_result::<UserRow>(conn)
            .map(Into::into)
    }

    pub fn activate(conn: &mut diesel::PgConnection, user_id: &str) -> QueryResult<User> {
        let id: uuid::Uuid = user_id
            .parse()
            .map_err(|_| diesel::result::Error::NotFound)?;
        diesel::update(users::table.find(id))
            .set((
                users::is_active.eq(true),
                users::updated_at.eq(chrono::Utc::now()),
            ))
            .get_result::<UserRow>(conn)
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
    ) -> QueryResult<User> {
        let new_row = NewUserRow {
            id: uuid::Uuid::now_v7().to_string(),
            username: username.to_string(),
            display_name: display_name.to_string(),
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

    pub fn list_all(conn: &mut diesel::SqliteConnection) -> QueryResult<Vec<User>> {
        users::table
            .order(users::created_at.asc())
            .load::<UserRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn update_display_name(
        conn: &mut diesel::SqliteConnection,
        user_id: &str,
        new_display_name: &str,
    ) -> QueryResult<User> {
        let now = chrono::Utc::now().to_rfc3339();
        diesel::update(users::table.find(user_id))
            .set((
                users::display_name.eq(new_display_name),
                users::updated_at.eq(&now),
            ))
            .execute(conn)?;

        users::table
            .find(user_id)
            .first::<UserRow>(conn)
            .map(Into::into)
    }

    pub fn deactivate(conn: &mut diesel::SqliteConnection, user_id: &str) -> QueryResult<User> {
        let now = chrono::Utc::now().to_rfc3339();
        diesel::update(users::table.find(user_id))
            .set((
                users::is_active.eq(0),
                users::updated_at.eq(&now),
            ))
            .execute(conn)?;

        users::table
            .find(user_id)
            .first::<UserRow>(conn)
            .map(Into::into)
    }

    pub fn activate(conn: &mut diesel::SqliteConnection, user_id: &str) -> QueryResult<User> {
        let now = chrono::Utc::now().to_rfc3339();
        diesel::update(users::table.find(user_id))
            .set((
                users::is_active.eq(1),
                users::updated_at.eq(&now),
            ))
            .execute(conn)?;

        users::table
            .find(user_id)
            .first::<UserRow>(conn)
            .map(Into::into)
    }
}
