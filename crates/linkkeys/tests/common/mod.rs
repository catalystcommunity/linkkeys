pub mod data_factory;

use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use linkkeys::db::DbPool;

#[cfg(feature = "postgres")]
const PG_MIGRATIONS: EmbeddedMigrations = embed_migrations!("../../migrations/postgres");

#[cfg(feature = "sqlite")]
const SQLITE_MIGRATIONS: EmbeddedMigrations = embed_migrations!("../../migrations/sqlite");

/// Create a test DbPool backed by a single connection in a test transaction.
///
/// The pool has `max_size=1` and `test_on_check_out=false` so the same
/// physical connection (with its test transaction) is reused for every
/// `pool.get()` call. When the pool is dropped at the end of the test,
/// the connection is dropped and the transaction rolls back automatically.
pub fn create_test_pool() -> DbPool {
    let backend =
        std::env::var("TEST_DATABASE_BACKEND").unwrap_or_else(|_| "postgres".to_string());
    let url = std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| default_test_url(&backend));

    match backend.as_str() {
        #[cfg(feature = "postgres")]
        "postgres" => {
            // Run migrations exactly once per process (handles in-process parallelism),
            // with an advisory lock (handles cross-process parallelism from multiple
            // test binaries hitting the same Postgres database).
            use std::sync::Once;
            static PG_MIGRATE: Once = Once::new();
            PG_MIGRATE.call_once(|| {
                let mut migration_conn = diesel::PgConnection::establish(&url)
                    .expect("Failed to connect for migrations");
                const LOCK_KEY: i64 = 0x6c6b5f74657374; // "lk_test"
                diesel::sql_query(format!("SELECT pg_advisory_lock({})", LOCK_KEY))
                    .execute(&mut migration_conn)
                    .expect("Failed to acquire advisory lock");
                migration_conn
                    .run_pending_migrations(PG_MIGRATIONS)
                    .expect("Failed to run test migrations");
                diesel::sql_query(format!("SELECT pg_advisory_unlock({})", LOCK_KEY))
                    .execute(&mut migration_conn)
                    .expect("Failed to release advisory lock");
            });

            let manager = ConnectionManager::<diesel::PgConnection>::new(&url);
            let pool = r2d2::Pool::builder()
                .max_size(1)
                .test_on_check_out(false)
                .build(manager)
                .expect("Failed to create test pool");

            {
                let mut conn = pool.get().expect("Failed to get test connection");
                conn.begin_test_transaction()
                    .expect("Failed to begin test transaction");
            }

            DbPool::Postgres(pool)
        }
        #[cfg(feature = "sqlite")]
        "sqlite" => {
            // SQLite :memory: databases are per-connection, so no race.
            // Migrations and test transaction can happen on the same connection.
            let manager = ConnectionManager::<diesel::SqliteConnection>::new(&url);
            let pool = r2d2::Pool::builder()
                .max_size(1)
                .test_on_check_out(false)
                .build(manager)
                .expect("Failed to create test pool");

            {
                let mut conn = pool.get().expect("Failed to get test connection");
                conn.run_pending_migrations(SQLITE_MIGRATIONS)
                    .expect("Failed to run test migrations");
                conn.begin_test_transaction()
                    .expect("Failed to begin test transaction");
            }

            DbPool::Sqlite(pool)
        }
        other => panic!(
            "Unsupported TEST_DATABASE_BACKEND: '{}'. Use 'postgres' or 'sqlite'.",
            other
        ),
    }
}

fn default_test_url(backend: &str) -> String {
    match backend {
        "postgres" => "postgres://devuser:devpass@localhost/linkkeys_test".to_string(),
        _ => ":memory:".to_string(),
    }
}
