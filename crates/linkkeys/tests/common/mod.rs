pub mod data_factory;

use diesel::prelude::*;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

#[cfg(feature = "postgres")]
const MIGRATIONS: EmbeddedMigrations = embed_migrations!("../../migrations/postgres");

#[cfg(feature = "sqlite")]
const MIGRATIONS: EmbeddedMigrations = embed_migrations!("../../migrations/sqlite");

#[cfg(feature = "postgres")]
type TestConn = diesel::PgConnection;
#[cfg(feature = "sqlite")]
type TestConn = diesel::SqliteConnection;

pub struct TestDb {
    conn: TestConn,
}

impl TestDb {
    pub fn new() -> Self {
        let url = std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| default_test_url());
        let mut conn = TestConn::establish(&url).expect("Failed to connect to test database");
        conn.begin_test_transaction()
            .expect("Failed to begin test transaction");
        conn.run_pending_migrations(MIGRATIONS)
            .expect("Failed to run test migrations");
        Self { conn }
    }

    pub fn conn(&mut self) -> &mut TestConn {
        &mut self.conn
    }
}

#[cfg(feature = "postgres")]
fn default_test_url() -> String {
    "postgres://devuser:devpass@localhost/linkkeys_test".to_string()
}

#[cfg(feature = "sqlite")]
fn default_test_url() -> String {
    ":memory:".to_string()
}
