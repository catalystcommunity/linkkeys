mod common;

use common::data_factory::{create_guestbook_entry, DataMap};
use common::TestDb;
use serde_json::Value;

#[test]
fn test_create_guestbook_entry() {
    let mut db = TestDb::new();
    let entry = create_guestbook_entry(
        db.conn(),
        &DataMap::from([("name".into(), Value::String("Alice".into()))]),
    );
    assert_eq!(entry.name, "Alice");
    assert!(!entry.id.to_string().is_empty());
}

#[test]
fn test_create_guestbook_entry_default_name() {
    let mut db = TestDb::new();
    let entry = create_guestbook_entry(db.conn(), &DataMap::new());
    assert!(entry.name.starts_with("test-guest-"));
}

#[test]
fn test_list_guestbook_entries() {
    let mut db = TestDb::new();
    create_guestbook_entry(db.conn(), &DataMap::new());
    create_guestbook_entry(db.conn(), &DataMap::new());

    let entries = linkkeys::db::guestbook::list(db.conn(), None, None).unwrap();
    assert_eq!(entries.len(), 2);
}

#[test]
fn test_list_guestbook_entries_with_limit() {
    let mut db = TestDb::new();
    create_guestbook_entry(db.conn(), &DataMap::new());
    create_guestbook_entry(db.conn(), &DataMap::new());
    create_guestbook_entry(db.conn(), &DataMap::new());

    let entries = linkkeys::db::guestbook::list(db.conn(), None, Some(2)).unwrap();
    assert_eq!(entries.len(), 2);
}

#[cfg(feature = "postgres")]
#[test]
fn test_update_guestbook_entry() {
    let mut db = TestDb::new();
    let entry = create_guestbook_entry(
        db.conn(),
        &DataMap::from([("name".into(), Value::String("Before".into()))]),
    );

    let updated = linkkeys::db::guestbook::update(db.conn(), entry.id, "After").unwrap();
    assert_eq!(updated.name, "After");
    assert_eq!(updated.id, entry.id);
}

#[cfg(feature = "sqlite")]
#[test]
fn test_update_guestbook_entry() {
    let mut db = TestDb::new();
    let entry = create_guestbook_entry(
        db.conn(),
        &DataMap::from([("name".into(), Value::String("Before".into()))]),
    );

    let updated = linkkeys::db::guestbook::update(db.conn(), &entry.id, "After").unwrap();
    assert_eq!(updated.name, "After");
    assert_eq!(updated.id, entry.id);
}

#[cfg(feature = "postgres")]
#[test]
fn test_delete_guestbook_entry() {
    let mut db = TestDb::new();
    let entry = create_guestbook_entry(db.conn(), &DataMap::new());

    let deleted = linkkeys::db::guestbook::delete(db.conn(), entry.id).unwrap();
    assert_eq!(deleted, 1);

    let entries = linkkeys::db::guestbook::list(db.conn(), None, None).unwrap();
    assert!(entries.is_empty());
}

#[cfg(feature = "sqlite")]
#[test]
fn test_delete_guestbook_entry() {
    let mut db = TestDb::new();
    let entry = create_guestbook_entry(db.conn(), &DataMap::new());

    let deleted = linkkeys::db::guestbook::delete(db.conn(), &entry.id).unwrap();
    assert_eq!(deleted, 1);

    let entries = linkkeys::db::guestbook::list(db.conn(), None, None).unwrap();
    assert!(entries.is_empty());
}

#[test]
fn test_migrations_run_successfully() {
    let mut db = TestDb::new();
    use diesel::prelude::*;
    let count: i64 = linkkeys::schema::guestbook_entries::table
        .count()
        .get_result(db.conn())
        .expect("guestbook_entries table should exist");
    assert_eq!(count, 0);
}
