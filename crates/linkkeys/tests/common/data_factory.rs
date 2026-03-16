use diesel::prelude::*;
use serde_json::Value;
use std::collections::HashMap;

use linkkeys::db::models::{GuestbookEntryRow, NewGuestbookEntryRow};
use linkkeys::schema::guestbook_entries;

pub type DataMap = HashMap<String, Value>;

#[cfg(feature = "postgres")]
pub fn create_guestbook_entry(
    conn: &mut super::TestConn,
    overrides: &DataMap,
) -> GuestbookEntryRow {
    let name = extract_name(overrides);

    let new_entry = NewGuestbookEntryRow {
        id: uuid::Uuid::now_v7(),
        name,
    };

    diesel::insert_into(guestbook_entries::table)
        .values(&new_entry)
        .get_result(conn)
        .expect("Failed to create test guestbook entry")
}

#[cfg(feature = "sqlite")]
pub fn create_guestbook_entry(
    conn: &mut super::TestConn,
    overrides: &DataMap,
) -> GuestbookEntryRow {
    let name = extract_name(overrides);

    let new_entry = NewGuestbookEntryRow {
        id: uuid::Uuid::now_v7().to_string(),
        name,
    };

    diesel::insert_into(guestbook_entries::table)
        .values(&new_entry)
        .execute(conn)
        .expect("Failed to create test guestbook entry");

    guestbook_entries::table
        .filter(guestbook_entries::id.eq(&new_entry.id))
        .first(conn)
        .expect("Failed to read back test guestbook entry")
}

fn extract_name(overrides: &DataMap) -> String {
    overrides
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("test-guest-{}", rand_suffix()))
}

fn rand_suffix() -> String {
    use rand::Rng;
    let n: u32 = rand::rng().random();
    format!("{:08x}", n)
}
