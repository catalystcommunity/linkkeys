pub mod models;
pub mod guestbook;

use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(feature = "postgres")]
pub type DbConn = diesel::PgConnection;
#[cfg(feature = "sqlite")]
pub type DbConn = diesel::SqliteConnection;

pub type DbPool = r2d2::Pool<ConnectionManager<DbConn>>;

#[cfg(feature = "postgres")]
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
#[cfg(feature = "postgres")]
const MIGRATIONS: EmbeddedMigrations = embed_migrations!("../../migrations/postgres");

#[cfg(feature = "sqlite")]
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
#[cfg(feature = "sqlite")]
const MIGRATIONS: EmbeddedMigrations = embed_migrations!("../../migrations/sqlite");

pub fn create_pool() -> DbPool {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| default_database_url().to_string());

    let manager = ConnectionManager::<DbConn>::new(database_url);

    r2d2::Pool::builder()
        .max_size(15)
        .min_idle(Some(5))
        .test_on_check_out(true)
        .build(manager)
        .expect("Failed to create database pool")
}

#[cfg(feature = "postgres")]
fn default_database_url() -> &'static str {
    "postgres://devuser:devpass@localhost/linkkeys"
}

#[cfg(feature = "sqlite")]
fn default_database_url() -> &'static str {
    "linkkeys.db"
}

/// Run pending migrations with backend-appropriate locking.
///
/// For Postgres: uses advisory locks so concurrent pods don't race.
/// For SQLite: uses WAL mode + busy timeout for serialized writes.
///
/// Sets `ready_flag` to true once migrations complete.
pub fn run_migrations_with_locking(pool: &DbPool, ready_flag: Arc<AtomicBool>) {
    let mut conn = pool.get().expect("Failed to get connection for migrations");

    #[cfg(feature = "postgres")]
    {
        // Advisory lock hash for "linkkeys_migrations"
        const LOCK_KEY: i64 = 0x6c696e6b6b657973; // "linkkeys" as bytes, truncated to i64
        diesel::sql_query(format!("SELECT pg_advisory_lock({})", LOCK_KEY))
            .execute(&mut conn)
            .expect("Failed to acquire advisory lock");

        let migration_result = conn
            .run_pending_migrations(MIGRATIONS)
            .map(|v| v.len())
            .map_err(|e| e.to_string());

        diesel::sql_query(format!("SELECT pg_advisory_unlock({})", LOCK_KEY))
            .execute(&mut conn)
            .expect("Failed to release advisory lock");

        match migration_result {
            Ok(count) if count > 0 => log::info!("Ran {} pending migration(s)", count),
            Ok(_) => {}
            Err(e) => {
                log::error!("Migration failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    #[cfg(feature = "sqlite")]
    {
        diesel::sql_query("PRAGMA journal_mode=WAL")
            .execute(&mut conn)
            .expect("Failed to set WAL mode");
        diesel::sql_query("PRAGMA busy_timeout=5000")
            .execute(&mut conn)
            .expect("Failed to set busy timeout");

        match conn.run_pending_migrations(MIGRATIONS) {
            Ok(versions) => {
                if !versions.is_empty() {
                    log::info!("Ran {} pending migration(s)", versions.len());
                }
            }
            Err(e) => {
                log::error!("Migration failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    ready_flag.store(true, Ordering::SeqCst);
    log::info!("Migrations complete, server ready");
}
