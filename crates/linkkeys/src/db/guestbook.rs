#[cfg(feature = "postgres")]
pub mod pg {
    use diesel::prelude::*;

    use crate::db::models::pg::{GuestbookEntryRow, NewGuestbookEntryRow};
    use crate::db::models::GuestbookEntry;
    use crate::schema::pg::guestbook_entries;

    pub fn create(conn: &mut diesel::PgConnection, name: &str) -> QueryResult<GuestbookEntry> {
        let new_entry = NewGuestbookEntryRow {
            id: uuid::Uuid::now_v7(),
            name: name.to_string(),
        };

        diesel::insert_into(guestbook_entries::table)
            .values(&new_entry)
            .get_result::<GuestbookEntryRow>(conn)
            .map(Into::into)
    }

    pub fn list(
        conn: &mut diesel::PgConnection,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> QueryResult<Vec<GuestbookEntry>> {
        let mut query = guestbook_entries::table
            .order(guestbook_entries::created_at.desc())
            .into_boxed();

        if let Some(off) = offset.filter(|&o| o >= 0) {
            query = query.offset(off);
        }
        if let Some(lim) = limit.filter(|&l| l >= 0) {
            query = query.limit(lim);
        }

        query
            .load::<GuestbookEntryRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn update(
        conn: &mut diesel::PgConnection,
        entry_id: &str,
        new_name: &str,
    ) -> QueryResult<GuestbookEntry> {
        let id: uuid::Uuid = entry_id
            .parse()
            .map_err(|_| diesel::result::Error::NotFound)?;

        diesel::update(guestbook_entries::table.find(id))
            .set(guestbook_entries::name.eq(new_name))
            .get_result::<GuestbookEntryRow>(conn)
            .map(Into::into)
    }

    pub fn delete(conn: &mut diesel::PgConnection, entry_id: &str) -> QueryResult<usize> {
        let id: uuid::Uuid = entry_id
            .parse()
            .map_err(|_| diesel::result::Error::NotFound)?;

        diesel::delete(guestbook_entries::table.find(id)).execute(conn)
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use diesel::prelude::*;

    use crate::db::models::sqlite::{GuestbookEntryRow, NewGuestbookEntryRow};
    use crate::db::models::GuestbookEntry;
    use crate::schema::sqlite::guestbook_entries;

    pub fn create(conn: &mut diesel::SqliteConnection, name: &str) -> QueryResult<GuestbookEntry> {
        let new_entry = NewGuestbookEntryRow {
            id: uuid::Uuid::now_v7().to_string(),
            name: name.to_string(),
        };
        let id = new_entry.id.clone();

        diesel::insert_into(guestbook_entries::table)
            .values(&new_entry)
            .execute(conn)?;

        guestbook_entries::table
            .filter(guestbook_entries::id.eq(&id))
            .first::<GuestbookEntryRow>(conn)
            .map(Into::into)
    }

    pub fn list(
        conn: &mut diesel::SqliteConnection,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> QueryResult<Vec<GuestbookEntry>> {
        let mut query = guestbook_entries::table
            .order(guestbook_entries::created_at.desc())
            .into_boxed();

        if let Some(off) = offset.filter(|&o| o >= 0) {
            query = query.offset(off);
        }
        if let Some(lim) = limit.filter(|&l| l >= 0) {
            query = query.limit(lim);
        }

        query
            .load::<GuestbookEntryRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn update(
        conn: &mut diesel::SqliteConnection,
        entry_id: &str,
        new_name: &str,
    ) -> QueryResult<GuestbookEntry> {
        diesel::update(guestbook_entries::table.find(entry_id))
            .set(guestbook_entries::name.eq(new_name))
            .execute(conn)?;

        guestbook_entries::table
            .find(entry_id)
            .first::<GuestbookEntryRow>(conn)
            .map(Into::into)
    }

    pub fn delete(conn: &mut diesel::SqliteConnection, entry_id: &str) -> QueryResult<usize> {
        diesel::delete(guestbook_entries::table.find(entry_id)).execute(conn)
    }
}
