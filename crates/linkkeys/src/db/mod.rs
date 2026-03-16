pub mod guestbook;
pub mod models;

use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(feature = "postgres")]
const PG_MIGRATIONS: EmbeddedMigrations = embed_migrations!("../../migrations/postgres");

#[cfg(feature = "sqlite")]
const SQLITE_MIGRATIONS: EmbeddedMigrations = embed_migrations!("../../migrations/sqlite");

pub enum DbPool {
    #[cfg(feature = "postgres")]
    Postgres(r2d2::Pool<ConnectionManager<diesel::PgConnection>>),
    #[cfg(feature = "sqlite")]
    Sqlite(r2d2::Pool<ConnectionManager<diesel::SqliteConnection>>),
}

impl Clone for DbPool {
    fn clone(&self) -> Self {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => DbPool::Postgres(p.clone()),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => DbPool::Sqlite(p.clone()),
        }
    }
}

pub fn create_pool() -> DbPool {
    let backend = env::var("DATABASE_BACKEND").unwrap_or_else(|_| "postgres".to_string());
    let url = env::var("DATABASE_URL").unwrap_or_else(|_| default_database_url(&backend).to_string());

    match backend.as_str() {
        #[cfg(feature = "postgres")]
        "postgres" => {
            let manager = ConnectionManager::<diesel::PgConnection>::new(url);
            let pool = r2d2::Pool::builder()
                .max_size(15)
                .min_idle(Some(5))
                .test_on_check_out(true)
                .build(manager)
                .expect("Failed to create postgres pool");
            DbPool::Postgres(pool)
        }
        #[cfg(feature = "sqlite")]
        "sqlite" => {
            let manager = ConnectionManager::<diesel::SqliteConnection>::new(url);
            let pool = r2d2::Pool::builder()
                .max_size(15)
                .min_idle(Some(5))
                .test_on_check_out(true)
                .build(manager)
                .expect("Failed to create sqlite pool");
            DbPool::Sqlite(pool)
        }
        other => panic!(
            "Unsupported DATABASE_BACKEND: '{}'. Use 'postgres' or 'sqlite'.",
            other
        ),
    }
}

fn default_database_url(backend: &str) -> &'static str {
    match backend {
        "postgres" => "postgres://devuser:devpass@localhost/linkkeys",
        "sqlite" => "linkkeys.db",
        _ => "postgres://devuser:devpass@localhost/linkkeys",
    }
}

/// Run pending migrations with backend-appropriate locking.
///
/// For Postgres: uses advisory locks so concurrent pods don't race.
/// For SQLite: uses WAL mode + busy timeout for serialized writes.
///
/// Sets `ready_flag` to true once migrations complete.
pub fn run_migrations_with_locking(pool: &DbPool, ready_flag: Arc<AtomicBool>) {
    match pool {
        #[cfg(feature = "postgres")]
        DbPool::Postgres(pool) => {
            let mut conn = pool.get().expect("Failed to get connection for migrations");

            // Advisory lock hash for "linkkeys_migrations"
            const LOCK_KEY: i64 = 0x6c696e6b6b657973;
            diesel::sql_query(format!("SELECT pg_advisory_lock({})", LOCK_KEY))
                .execute(&mut *conn)
                .expect("Failed to acquire advisory lock");

            let migration_result = conn
                .run_pending_migrations(PG_MIGRATIONS)
                .map(|v| v.len())
                .map_err(|e| e.to_string());

            diesel::sql_query(format!("SELECT pg_advisory_unlock({})", LOCK_KEY))
                .execute(&mut *conn)
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
        DbPool::Sqlite(pool) => {
            let mut conn = pool.get().expect("Failed to get connection for migrations");

            diesel::sql_query("PRAGMA journal_mode=WAL")
                .execute(&mut *conn)
                .expect("Failed to set WAL mode");
            diesel::sql_query("PRAGMA busy_timeout=5000")
                .execute(&mut *conn)
                .expect("Failed to set busy timeout");

            match conn.run_pending_migrations(SQLITE_MIGRATIONS) {
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
    }

    ready_flag.store(true, Ordering::SeqCst);
    log::info!("Migrations complete, server ready");
}
