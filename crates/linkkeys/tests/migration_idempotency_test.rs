//! The migration runner must be idempotent: re-running it on a database that
//! already has the schema (the production case the single-file switch broke —
//! existing schema, no tracking state) must SUCCEED, skipping already-applied
//! migrations rather than erroring on "table already exists". Every other test
//! starts from a fresh DB, which is exactly why this class of bug slipped
//! through, so this guards it directly.

#![cfg(feature = "sqlite")]

use diesel::Connection;

#[test]
fn migrations_are_idempotent_on_an_existing_db() {
    let mut conn = diesel::SqliteConnection::establish(":memory:").expect("connect");

    // First boot: builds the schema from scratch.
    let applied = linkkeys::db::migrate_sqlite(&mut conn).expect("first migrate");
    assert!(applied > 0, "first run applies migrations");

    // Second boot on the SAME, already-migrated DB: must not error. The
    // CREATE/ALTER migrations hit "already exists" and are skipped, so fewer run
    // than the first time. (The key regression assertion is simply that this
    // returns Ok rather than crashing the server, as it did in production.)
    let again = linkkeys::db::migrate_sqlite(&mut conn).expect("re-migrate is idempotent");
    assert!(
        again < applied,
        "re-run skips already-applied migrations (applied={}, again={})",
        applied,
        again
    );
}
