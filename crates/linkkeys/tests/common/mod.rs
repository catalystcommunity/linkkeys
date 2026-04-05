pub mod data_factory;

use diesel::prelude::*;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use linkkeys::db::models::{AuthCredential, GuestbookEntry, User};

#[cfg(feature = "postgres")]
const PG_MIGRATIONS: EmbeddedMigrations = embed_migrations!("../../migrations/postgres");

#[cfg(feature = "sqlite")]
const SQLITE_MIGRATIONS: EmbeddedMigrations = embed_migrations!("../../migrations/sqlite");

pub enum TestDb {
    #[cfg(feature = "postgres")]
    Postgres(diesel::PgConnection),
    #[cfg(feature = "sqlite")]
    Sqlite(diesel::SqliteConnection),
}

impl TestDb {
    pub fn new() -> Self {
        let backend =
            std::env::var("TEST_DATABASE_BACKEND").unwrap_or_else(|_| "postgres".to_string());
        let url =
            std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| default_test_url(&backend));

        match backend.as_str() {
            #[cfg(feature = "postgres")]
            "postgres" => {
                let mut conn =
                    diesel::PgConnection::establish(&url).expect("Failed to connect to test db");
                conn.begin_test_transaction()
                    .expect("Failed to begin test transaction");
                conn.run_pending_migrations(PG_MIGRATIONS)
                    .expect("Failed to run test migrations");
                TestDb::Postgres(conn)
            }
            #[cfg(feature = "sqlite")]
            "sqlite" => {
                let mut conn = diesel::SqliteConnection::establish(&url)
                    .expect("Failed to connect to test db");
                conn.begin_test_transaction()
                    .expect("Failed to begin test transaction");
                conn.run_pending_migrations(SQLITE_MIGRATIONS)
                    .expect("Failed to run test migrations");
                TestDb::Sqlite(conn)
            }
            other => panic!(
                "Unsupported TEST_DATABASE_BACKEND: '{}'. Use 'postgres' or 'sqlite'.",
                other
            ),
        }
    }
}

fn default_test_url(backend: &str) -> String {
    match backend {
        "postgres" => "postgres://devuser:devpass@localhost/linkkeys_test".to_string(),
        _ => ":memory:".to_string(),
    }
}

// Dispatch helpers for guestbook operations in tests.

pub fn guestbook_list(
    db: &mut TestDb,
    offset: Option<i64>,
    limit: Option<i64>,
) -> Vec<GuestbookEntry> {
    match db {
        #[cfg(feature = "postgres")]
        TestDb::Postgres(conn) => {
            linkkeys::db::guestbook::pg::list(conn, offset, limit).unwrap()
        }
        #[cfg(feature = "sqlite")]
        TestDb::Sqlite(conn) => {
            linkkeys::db::guestbook::sqlite::list(conn, offset, limit).unwrap()
        }
    }
}

pub fn guestbook_update(db: &mut TestDb, id: &str, name: &str) -> GuestbookEntry {
    match db {
        #[cfg(feature = "postgres")]
        TestDb::Postgres(conn) => {
            linkkeys::db::guestbook::pg::update(conn, id, name).unwrap()
        }
        #[cfg(feature = "sqlite")]
        TestDb::Sqlite(conn) => {
            linkkeys::db::guestbook::sqlite::update(conn, id, name).unwrap()
        }
    }
}

pub fn guestbook_delete(db: &mut TestDb, id: &str) -> usize {
    match db {
        #[cfg(feature = "postgres")]
        TestDb::Postgres(conn) => linkkeys::db::guestbook::pg::delete(conn, id).unwrap(),
        #[cfg(feature = "sqlite")]
        TestDb::Sqlite(conn) => linkkeys::db::guestbook::sqlite::delete(conn, id).unwrap(),
    }
}

pub fn find_user_by_username(db: &mut TestDb, username: &str) -> User {
    match db {
        #[cfg(feature = "postgres")]
        TestDb::Postgres(conn) => linkkeys::db::users::pg::find_by_username(conn, username).unwrap(),
        #[cfg(feature = "sqlite")]
        TestDb::Sqlite(conn) => linkkeys::db::users::sqlite::find_by_username(conn, username).unwrap(),
    }
}

pub fn find_credentials_for_user(
    db: &mut TestDb,
    user_id: &str,
    credential_type: &str,
) -> Vec<AuthCredential> {
    match db {
        #[cfg(feature = "postgres")]
        TestDb::Postgres(conn) => {
            linkkeys::db::auth_credentials::pg::find_for_user(conn, user_id, credential_type)
                .unwrap()
        }
        #[cfg(feature = "sqlite")]
        TestDb::Sqlite(conn) => {
            linkkeys::db::auth_credentials::sqlite::find_for_user(conn, user_id, credential_type)
                .unwrap()
        }
    }
}
