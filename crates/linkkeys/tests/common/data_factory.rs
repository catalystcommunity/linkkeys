use serde_json::Value;
use std::collections::HashMap;

use linkkeys::db::models::GuestbookEntry;
use super::TestDb;

pub type DataMap = HashMap<String, Value>;

pub fn create_guestbook_entry(db: &mut TestDb, overrides: &DataMap) -> GuestbookEntry {
    let name = extract_name(overrides);

    match db {
        #[cfg(feature = "postgres")]
        TestDb::Postgres(conn) => {
            linkkeys::db::guestbook::pg::create(conn, &name)
                .expect("Failed to create test guestbook entry")
        }
        #[cfg(feature = "sqlite")]
        TestDb::Sqlite(conn) => {
            linkkeys::db::guestbook::sqlite::create(conn, &name)
                .expect("Failed to create test guestbook entry")
        }
    }
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
    let n: u32 = rand::thread_rng().gen();
    format!("{:08x}", n)
}
