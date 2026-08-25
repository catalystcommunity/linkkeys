use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

#[cfg(feature = "postgres")]
const POSTGRES_MIGRATIONS: EmbeddedMigrations = embed_migrations!("../../migrations/postgres");
#[cfg(feature = "sqlite")]
const SQLITE_MIGRATIONS: EmbeddedMigrations = embed_migrations!("../../migrations/sqlite");

#[test]
fn latest_two_migrations_can_revert_and_run_again() {
    let backend = std::env::var("TEST_DATABASE_BACKEND").unwrap_or_else(|_| "sqlite".to_string());
    match backend.as_str() {
        #[cfg(feature = "sqlite")]
        "sqlite" => {
            let mut connection = diesel::SqliteConnection::establish(":memory:").unwrap();
            connection.batch_execute("PRAGMA foreign_keys=ON;").unwrap();
            connection
                .run_pending_migrations(SQLITE_MIGRATIONS)
                .unwrap();
            connection.revert_last_migration(SQLITE_MIGRATIONS).unwrap();
            connection.revert_last_migration(SQLITE_MIGRATIONS).unwrap();
            connection
                .run_pending_migrations(SQLITE_MIGRATIONS)
                .unwrap();
        }
        #[cfg(feature = "postgres")]
        "postgres" => {
            let url = std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
                "postgres://devuser:devpass@localhost/linkkeys_test".to_string()
            });
            let schema = format!("migration_test_{}", uuid::Uuid::now_v7().simple());
            let mut connection = diesel::PgConnection::establish(&url).unwrap();
            connection
                .batch_execute(&format!(
                    "CREATE SCHEMA {schema}; SET search_path TO {schema};"
                ))
                .unwrap();
            connection
                .run_pending_migrations(POSTGRES_MIGRATIONS)
                .unwrap();
            connection
                .revert_last_migration(POSTGRES_MIGRATIONS)
                .unwrap();
            connection
                .revert_last_migration(POSTGRES_MIGRATIONS)
                .unwrap();
            connection
                .run_pending_migrations(POSTGRES_MIGRATIONS)
                .unwrap();
            connection
                .batch_execute("SET search_path TO public;")
                .unwrap();
            connection
                .batch_execute(&format!("DROP SCHEMA {schema} CASCADE;"))
                .unwrap();
        }
        other => panic!("Unsupported TEST_DATABASE_BACKEND: {other}"),
    }
}
