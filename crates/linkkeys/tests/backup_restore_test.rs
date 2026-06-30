// Encrypted backup/restore feature tests. v1 targets the SQLite backend, so
// these skip cleanly when the suite runs against Postgres (the pool won't be
// the Sqlite variant).

mod common;

use common::data_factory::{create_domain_key, create_user, DataMap};
use linkkeys::backup::{
    create_backup, key_from_hex, restore_backup, snapshot_table_names, BackupOptions,
    RestoreOptions,
};
use linkkeys::db::DbPool;

const PASS: &str = "test-passphrase";

/// Build a test pool; return None (skip) unless it's the SQLite backend.
fn sqlite_pool() -> Option<DbPool> {
    let pool = common::create_test_pool();
    match &pool {
        DbPool::Sqlite(_) => Some(pool),
        #[allow(unreachable_patterns)]
        _ => None,
    }
}

fn signing_fingerprints(pool: &DbPool) -> Vec<String> {
    let mut fps: Vec<String> = pool
        .list_active_domain_keys()
        .expect("list domain keys")
        .into_iter()
        .filter(|k| k.key_usage == "sign")
        .map(|k| k.fingerprint)
        .collect();
    fps.sort();
    fps
}

#[test]
fn backup_restore_round_trip_replaces_state() {
    let Some(pool) = sqlite_pool() else { return };

    // Seed a domain (signing key) + a user that should survive the round-trip.
    let dk = create_domain_key(&pool);
    let user_a = create_user(&pool, &DataMap::new());
    let fps_before = signing_fingerprints(&pool);
    assert!(fps_before.contains(&dk.fingerprint));

    // Back up the current state.
    let backup = create_backup(
        &pool,
        PASS,
        BackupOptions {
            rotate: false,
            include_passphrase: true,
        },
    )
    .expect("backup");
    let key = backup.new_key.expect("first backup generates a key");

    // Mutate AFTER the backup: a user that must NOT survive the restore.
    let user_b = create_user(&pool, &DataMap::new());
    assert!(pool
        .list_all_users()
        .unwrap()
        .iter()
        .any(|u| u.id == user_b.id));

    // Restore replaces live state with the snapshot.
    let result = restore_backup(
        &pool,
        &backup.ciphertext,
        RestoreOptions { key, force: true },
    )
    .expect("restore");

    let users = pool.list_all_users().unwrap();
    assert!(users.iter().any(|u| u.id == user_a.id), "user A restored");
    assert!(
        !users.iter().any(|u| u.id == user_b.id),
        "post-backup user B is gone after restore"
    );
    assert_eq!(
        signing_fingerprints(&pool),
        fps_before,
        "domain signing fingerprints are byte-identical after restore"
    );
    assert!(result.fingerprints.contains(&dk.fingerprint));
    assert_eq!(result.passphrase_in_bundle.as_deref(), Some(PASS));
}

#[test]
fn backup_key_generated_once_then_reused() {
    let Some(pool) = sqlite_pool() else { return };
    create_domain_key(&pool);

    let first = create_backup(
        &pool,
        PASS,
        BackupOptions {
            rotate: false,
            include_passphrase: true,
        },
    )
    .expect("first backup");
    let k1 = first.new_key.expect("first backup generates a key");

    let second = create_backup(
        &pool,
        PASS,
        BackupOptions {
            rotate: false,
            include_passphrase: true,
        },
    )
    .expect("second backup");
    assert!(
        second.new_key.is_none(),
        "second backup reuses the stored key silently"
    );

    // The reused key still decrypts the second artifact.
    restore_backup(
        &pool,
        &second.ciphertext,
        RestoreOptions {
            key: k1,
            force: true,
        },
    )
    .expect("restore second backup with original key");
}

#[test]
fn rotation_changes_the_key() {
    let Some(pool) = sqlite_pool() else { return };
    create_domain_key(&pool);

    let first = create_backup(
        &pool,
        PASS,
        BackupOptions {
            rotate: false,
            include_passphrase: true,
        },
    )
    .expect("first backup");
    let k1 = first.new_key.unwrap();

    let rotated = create_backup(
        &pool,
        PASS,
        BackupOptions {
            rotate: true,
            include_passphrase: true,
        },
    )
    .expect("rotated backup");
    let k2 = rotated.new_key.expect("rotation yields a new key");
    assert_ne!(k1, k2, "rotation produces a different key");

    // The old key cannot decrypt the rotated backup; the new one can.
    assert!(restore_backup(
        &pool,
        &rotated.ciphertext,
        RestoreOptions {
            key: k1,
            force: true,
        },
    )
    .is_err());
    restore_backup(
        &pool,
        &rotated.ciphertext,
        RestoreOptions {
            key: k2,
            force: true,
        },
    )
    .expect("new key decrypts rotated backup");
}

#[test]
fn restore_with_wrong_key_fails() {
    let Some(pool) = sqlite_pool() else { return };
    create_domain_key(&pool);
    let backup = create_backup(
        &pool,
        PASS,
        BackupOptions {
            rotate: false,
            include_passphrase: true,
        },
    )
    .expect("backup");

    let wrong = key_from_hex(&"ab".repeat(32)).unwrap();
    assert!(restore_backup(
        &pool,
        &backup.ciphertext,
        RestoreOptions {
            key: wrong,
            force: true,
        },
    )
    .is_err());
}

#[test]
fn restore_refuses_nonempty_db_without_force() {
    let Some(pool) = sqlite_pool() else { return };
    create_domain_key(&pool);
    create_user(&pool, &DataMap::new());
    let backup = create_backup(
        &pool,
        PASS,
        BackupOptions {
            rotate: false,
            include_passphrase: true,
        },
    )
    .expect("backup");
    let key = backup.new_key.unwrap();

    // DB still has the user → restore without --force must refuse.
    assert!(restore_backup(
        &pool,
        &backup.ciphertext,
        RestoreOptions { key, force: false },
    )
    .is_err());
}

/// Drift guard: every application table in the database must be covered by the
/// snapshot registry, or a future table would be silently omitted from backups.
#[test]
fn snapshot_covers_every_table() {
    use diesel::prelude::*;
    let Some(pool) = sqlite_pool() else { return };

    #[derive(diesel::QueryableByName)]
    struct TableName {
        #[diesel(sql_type = diesel::sql_types::Text)]
        name: String,
    }

    let DbPool::Sqlite(p) = &pool else {
        return;
    };
    let mut conn = p.get().unwrap();
    let rows: Vec<TableName> = diesel::sql_query(
        "SELECT name FROM sqlite_master WHERE type='table' \
         AND name NOT LIKE 'sqlite_%' AND name != '__diesel_schema_migrations'",
    )
    .load(&mut conn)
    .expect("list tables");

    let covered: std::collections::BTreeSet<&str> =
        snapshot_table_names().iter().copied().collect();
    let missing: Vec<String> = rows
        .into_iter()
        .map(|r| r.name)
        .filter(|name| !covered.contains(name.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "tables present in the DB but missing from the backup snapshot registry: {missing:?}"
    );
}
