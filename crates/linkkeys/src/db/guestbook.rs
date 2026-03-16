use diesel::prelude::*;

use super::models::{GuestbookEntryRow, NewGuestbookEntryRow};
use crate::schema::guestbook_entries;

#[cfg(feature = "postgres")]
pub fn create(conn: &mut super::DbConn, name: &str) -> QueryResult<GuestbookEntryRow> {
    let new_entry = NewGuestbookEntryRow {
        id: uuid::Uuid::now_v7(),
        name: name.to_string(),
    };

    diesel::insert_into(guestbook_entries::table)
        .values(&new_entry)
        .get_result(conn)
}

#[cfg(feature = "sqlite")]
pub fn create(conn: &mut super::DbConn, name: &str) -> QueryResult<GuestbookEntryRow> {
    let new_entry = NewGuestbookEntryRow {
        id: uuid::Uuid::now_v7().to_string(),
        name: name.to_string(),
    };

    diesel::insert_into(guestbook_entries::table)
        .values(&new_entry)
        .execute(conn)?;

    // SQLite doesn't support RETURNING, so query it back
    guestbook_entries::table
        .filter(guestbook_entries::id.eq(&new_entry.id))
        .first(conn)
}

pub fn list(
    conn: &mut super::DbConn,
    offset: Option<i64>,
    limit: Option<i64>,
) -> QueryResult<Vec<GuestbookEntryRow>> {
    let mut query = guestbook_entries::table
        .order(guestbook_entries::created_at.desc())
        .into_boxed();

    if let Some(off) = offset.filter(|&o| o >= 0) {
        query = query.offset(off);
    }
    if let Some(lim) = limit.filter(|&l| l >= 0) {
        query = query.limit(lim);
    }

    query.load(conn)
}

#[cfg(feature = "postgres")]
pub fn update(conn: &mut super::DbConn, entry_id: uuid::Uuid, new_name: &str) -> QueryResult<GuestbookEntryRow> {
    diesel::update(guestbook_entries::table.find(entry_id))
        .set(guestbook_entries::name.eq(new_name))
        .get_result(conn)
}

#[cfg(feature = "sqlite")]
pub fn update(conn: &mut super::DbConn, entry_id: &str, new_name: &str) -> QueryResult<GuestbookEntryRow> {
    diesel::update(guestbook_entries::table.find(entry_id))
        .set(guestbook_entries::name.eq(new_name))
        .execute(conn)?;

    guestbook_entries::table
        .find(entry_id)
        .first(conn)
}

#[cfg(feature = "postgres")]
pub fn delete(conn: &mut super::DbConn, entry_id: uuid::Uuid) -> QueryResult<usize> {
    diesel::delete(guestbook_entries::table.find(entry_id))
        .execute(conn)
}

#[cfg(feature = "sqlite")]
pub fn delete(conn: &mut super::DbConn, entry_id: &str) -> QueryResult<usize> {
    diesel::delete(guestbook_entries::table.find(entry_id))
        .execute(conn)
}
