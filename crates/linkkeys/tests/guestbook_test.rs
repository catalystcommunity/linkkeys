mod common;

use common::data_factory::{create_guestbook_entry, DataMap};
use common::TestDb;
use serde_json::Value;

#[test]
fn test_create_guestbook_entry() {
    let mut db = TestDb::new();
    let entry = create_guestbook_entry(
        &mut db,
        &DataMap::from([("name".into(), Value::String("Alice".into()))]),
    );
    assert_eq!(entry.name, "Alice");
    assert!(!entry.id.is_empty());
}

#[test]
fn test_create_guestbook_entry_default_name() {
    let mut db = TestDb::new();
    let entry = create_guestbook_entry(&mut db, &DataMap::new());
    assert!(entry.name.starts_with("test-guest-"));
}

#[test]
fn test_list_guestbook_entries() {
    let mut db = TestDb::new();
    create_guestbook_entry(&mut db, &DataMap::new());
    create_guestbook_entry(&mut db, &DataMap::new());

    let entries = common::guestbook_list(&mut db, None, None);
    assert_eq!(entries.len(), 2);
}

#[test]
fn test_list_guestbook_entries_with_limit() {
    let mut db = TestDb::new();
    create_guestbook_entry(&mut db, &DataMap::new());
    create_guestbook_entry(&mut db, &DataMap::new());
    create_guestbook_entry(&mut db, &DataMap::new());

    let entries = common::guestbook_list(&mut db, None, Some(2));
    assert_eq!(entries.len(), 2);
}

#[test]
fn test_update_guestbook_entry() {
    let mut db = TestDb::new();
    let entry = create_guestbook_entry(
        &mut db,
        &DataMap::from([("name".into(), Value::String("Before".into()))]),
    );

    let updated = common::guestbook_update(&mut db, &entry.id, "After");
    assert_eq!(updated.name, "After");
    assert_eq!(updated.id, entry.id);
}

#[test]
fn test_delete_guestbook_entry() {
    let mut db = TestDb::new();
    let entry = create_guestbook_entry(&mut db, &DataMap::new());

    let deleted = common::guestbook_delete(&mut db, &entry.id);
    assert_eq!(deleted, 1);

    let entries = common::guestbook_list(&mut db, None, None);
    assert!(entries.is_empty());
}

#[test]
fn test_migrations_run_successfully() {
    let mut db = TestDb::new();
    // If we got here, migrations ran. Verify the table exists by listing entries.
    let entries = common::guestbook_list(&mut db, None, None);
    assert_eq!(entries.len(), 0);
}
