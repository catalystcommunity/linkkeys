mod common;

use common::data_factory::{create_guestbook_entry, DataMap};
use serde_json::Value;

#[test]
fn test_create_guestbook_entry() {
    let pool = common::create_test_pool();
    let entry = create_guestbook_entry(
        &pool,
        &DataMap::from([("name".into(), Value::String("Alice".into()))]),
    );
    assert_eq!(entry.name, "Alice");
    assert!(!entry.id.is_empty());
}

#[test]
fn test_create_guestbook_entry_default_name() {
    let pool = common::create_test_pool();
    let entry = create_guestbook_entry(&pool, &DataMap::new());
    assert!(entry.name.starts_with("test-guest-"));
}

#[test]
fn test_list_guestbook_entries() {
    let pool = common::create_test_pool();
    create_guestbook_entry(&pool, &DataMap::new());
    create_guestbook_entry(&pool, &DataMap::new());

    let entries = pool.guestbook_list(None, None).unwrap();
    assert_eq!(entries.len(), 2);
}

#[test]
fn test_list_guestbook_entries_with_limit() {
    let pool = common::create_test_pool();
    create_guestbook_entry(&pool, &DataMap::new());
    create_guestbook_entry(&pool, &DataMap::new());
    create_guestbook_entry(&pool, &DataMap::new());

    let entries = pool.guestbook_list(None, Some(2)).unwrap();
    assert_eq!(entries.len(), 2);
}

#[test]
fn test_update_guestbook_entry() {
    let pool = common::create_test_pool();
    let entry = create_guestbook_entry(
        &pool,
        &DataMap::from([("name".into(), Value::String("Before".into()))]),
    );

    let updated = pool.guestbook_update(&entry.id, "After").unwrap();
    assert_eq!(updated.name, "After");
    assert_eq!(updated.id, entry.id);
}

#[test]
fn test_delete_guestbook_entry() {
    let pool = common::create_test_pool();
    let entry = create_guestbook_entry(&pool, &DataMap::new());

    let deleted = pool.guestbook_delete(&entry.id).unwrap();
    assert_eq!(deleted, 1);

    let entries = pool.guestbook_list(None, None).unwrap();
    assert!(entries.is_empty());
}

#[test]
fn test_migrations_run_successfully() {
    let pool = common::create_test_pool();
    // If we got here, migrations ran. Verify the table exists by listing entries.
    let entries = pool.guestbook_list(None, None).unwrap();
    assert_eq!(entries.len(), 0);
}
