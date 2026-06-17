pub mod auth_credentials;
pub mod claims;
pub mod consent_grants;
pub mod domain_keys;
pub mod guestbook;
pub mod models;
pub mod nonces;
pub mod profiles;
pub mod relations;
pub mod user_keys;
pub mod users;

use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use std::env;

// Single-file, forward-only migrations: each entry is (version, SQL), applied in
// array order. A `__lk_migrations` table records which versions have run. No
// rollback by design (no down migrations). Adding a migration = drop one `.sql`
// file under migrations/<backend>/ and add a line here.
#[cfg(feature = "postgres")]
const PG_MIGRATIONS: &[(&str, &str)] = &[
    (
        "00000000000000_diesel_initial_setup",
        include_str!("../../../../migrations/postgres/00000000000000_diesel_initial_setup.sql"),
    ),
    (
        "2026-03-15-000001_create_guestbook",
        include_str!("../../../../migrations/postgres/2026-03-15-000001_create_guestbook.sql"),
    ),
    (
        "2026-04-02-000001_create_identity_tables",
        include_str!(
            "../../../../migrations/postgres/2026-04-02-000001_create_identity_tables.sql"
        ),
    ),
    (
        "2026-04-09-000001_create_relations_and_extensions",
        include_str!(
            "../../../../migrations/postgres/2026-04-09-000001_create_relations_and_extensions.sql"
        ),
    ),
    (
        "2026-04-09-000002_add_relations_unique_index",
        include_str!(
            "../../../../migrations/postgres/2026-04-09-000002_add_relations_unique_index.sql"
        ),
    ),
    (
        "2026-05-30-000001_create_used_nonces",
        include_str!("../../../../migrations/postgres/2026-05-30-000001_create_used_nonces.sql"),
    ),
    (
        "2026-06-01-000001_add_key_usage",
        include_str!("../../../../migrations/postgres/2026-06-01-000001_add_key_usage.sql"),
    ),
    (
        "2026-06-14-000001_claim_signatures",
        include_str!("../../../../migrations/postgres/2026-06-14-000001_claim_signatures.sql"),
    ),
    (
        "2026-06-14-000002_create_consent_grants",
        include_str!("../../../../migrations/postgres/2026-06-14-000002_create_consent_grants.sql"),
    ),
    (
        "2026-06-15-000001_create_profiles",
        include_str!("../../../../migrations/postgres/2026-06-15-000001_create_profiles.sql"),
    ),
    (
        "2026-06-16-000001_admin_accounts",
        include_str!("../../../../migrations/postgres/2026-06-16-000001_admin_accounts.sql"),
    ),
];

#[cfg(feature = "sqlite")]
const SQLITE_MIGRATIONS: &[(&str, &str)] = &[
    (
        "00000000000000_diesel_initial_setup",
        include_str!("../../../../migrations/sqlite/00000000000000_diesel_initial_setup.sql"),
    ),
    (
        "2026-03-15-000001_create_guestbook",
        include_str!("../../../../migrations/sqlite/2026-03-15-000001_create_guestbook.sql"),
    ),
    (
        "2026-04-02-000001_create_identity_tables",
        include_str!("../../../../migrations/sqlite/2026-04-02-000001_create_identity_tables.sql"),
    ),
    (
        "2026-04-09-000001_create_relations_and_extensions",
        include_str!(
            "../../../../migrations/sqlite/2026-04-09-000001_create_relations_and_extensions.sql"
        ),
    ),
    (
        "2026-04-09-000002_add_relations_unique_index",
        include_str!(
            "../../../../migrations/sqlite/2026-04-09-000002_add_relations_unique_index.sql"
        ),
    ),
    (
        "2026-05-30-000001_create_used_nonces",
        include_str!("../../../../migrations/sqlite/2026-05-30-000001_create_used_nonces.sql"),
    ),
    (
        "2026-06-01-000001_add_key_usage",
        include_str!("../../../../migrations/sqlite/2026-06-01-000001_add_key_usage.sql"),
    ),
    (
        "2026-06-14-000001_claim_signatures",
        include_str!("../../../../migrations/sqlite/2026-06-14-000001_claim_signatures.sql"),
    ),
    (
        "2026-06-14-000002_create_consent_grants",
        include_str!("../../../../migrations/sqlite/2026-06-14-000002_create_consent_grants.sql"),
    ),
    (
        "2026-06-15-000001_create_profiles",
        include_str!("../../../../migrations/sqlite/2026-06-15-000001_create_profiles.sql"),
    ),
    (
        "2026-06-16-000001_admin_accounts",
        include_str!("../../../../migrations/sqlite/2026-06-16-000001_admin_accounts.sql"),
    ),
];

/// True for the benign "this object already exists" class of DB errors that
/// means a migration was already applied (so we skip it), as opposed to a real
/// failure (which propagates). Covers both Postgres ("... already exists") and
/// SQLite ("table ... already exists", "duplicate column name", ...).
fn is_already_applied(e: &diesel::result::Error) -> bool {
    if let diesel::result::Error::DatabaseError(_, info) = e {
        let msg = info.message().to_lowercase();
        msg.contains("already exists") || msg.contains("duplicate column")
    } else {
        false
    }
}

/// Apply forward-only, single-file migrations on a concrete connection. There is
/// NO migration-tracking table — the runner is idempotent: it runs every
/// migration on each boot and treats an "already exists / duplicate column"
/// failure as "already applied, skip". This works because each migration's first
/// statement is a uniquely-named CREATE/ALTER, so a previously-applied migration
/// fails on that first statement (rolling back its transaction untouched) and is
/// skipped wholesale, while a genuinely-new migration applies. Any OTHER error
/// is a real failure and propagates. Each migration runs in its own transaction,
/// so a partial/failed apply rolls back cleanly.
///
/// SOUND ONLY FOR DDL migrations (the convention here): a data statement would
/// not error on re-run and would silently execute every boot. Data backfills
/// must be idempotent startup hooks instead (see `backfill_profiles` /
/// `split_admins`), never SQL migrations.
macro_rules! apply_migrations {
    ($conn:expr, $migrations:expr) => {{
        // Migrations apply in array order, which must be strictly ascending so a
        // fresh DB builds the schema in the right sequence.
        debug_assert!(
            $migrations.windows(2).all(|w| w[0].0 < w[1].0),
            "migrations must be listed in strictly ascending version order"
        );
        let mut count = 0usize;
        for (name, sql) in $migrations.iter() {
            match $conn.transaction::<(), diesel::result::Error, _>(|c| c.batch_execute(sql)) {
                Ok(()) => {
                    log::info!("applied migration {}", name);
                    count += 1;
                }
                Err(e) if is_already_applied(&e) => {
                    log::debug!("migration {} already applied; skipping", name);
                }
                Err(e) => return Err(format!("migration {} failed: {}", name, e)),
            }
        }
        Ok::<usize, String>(count)
    }};
}

/// Apply pending migrations on a Postgres connection. Returns the number run.
#[cfg(feature = "postgres")]
pub fn migrate_pg(conn: &mut diesel::PgConnection) -> Result<usize, String> {
    apply_migrations!(conn, PG_MIGRATIONS)
}

/// Apply pending migrations on a SQLite connection. Returns the number run.
#[cfg(feature = "sqlite")]
pub fn migrate_sqlite(conn: &mut diesel::SqliteConnection) -> Result<usize, String> {
    apply_migrations!(conn, SQLITE_MIGRATIONS)
}

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
    let url =
        env::var("DATABASE_URL").unwrap_or_else(|_| default_database_url(&backend).to_string());

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

/// Per-account cap on presentable profiles (`MAX_PROFILES_PER_ACCOUNT`, default
/// 1 — keeps the system single-identity and the multi-profile UI hidden until an
/// operator opts in). The root anchor is separate and not counted.
fn max_profiles_per_account() -> i64 {
    std::env::var("MAX_PROFILES_PER_ACCOUNT")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|n| *n >= 1)
        .unwrap_or(1)
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
/// Runs all pending migrations under a cross-process lock (advisory lock on
/// Postgres, WAL on SQLite). Does not signal readiness — the caller sets the
/// ready flag once *all* startup DB writes (migrations + data backfills) are
/// done, so nothing contends on the SQLite lock while reading domain keys.
pub fn run_migrations_with_locking(pool: &DbPool) {
    match pool {
        #[cfg(feature = "postgres")]
        DbPool::Postgres(pool) => {
            let mut conn = pool.get().expect("Failed to get connection for migrations");

            // Advisory lock hash for "linkkeys_migrations"
            const LOCK_KEY: i64 = 0x6c696e6b6b657973;
            diesel::sql_query(format!("SELECT pg_advisory_lock({})", LOCK_KEY))
                .execute(&mut *conn)
                .expect("Failed to acquire advisory lock");

            let migration_result = migrate_pg(&mut conn);

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

            match migrate_sqlite(&mut conn) {
                Ok(count) if count > 0 => log::info!("Ran {} pending migration(s)", count),
                Ok(_) => {}
                Err(e) => {
                    log::error!("Migration failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }

    log::info!("Migrations complete");
}

// -- Convenience methods to eliminate match-on-DbPool boilerplate --

impl DbPool {
    pub fn list_active_domain_keys(&self) -> QueryResult<Vec<models::DomainKey>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                domain_keys::pg::list_active(&mut conn)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                domain_keys::sqlite::list_active(&mut conn)
            }
        }
    }

    pub fn list_all_domain_keys(&self) -> QueryResult<Vec<models::DomainKey>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                domain_keys::pg::list_all(&mut conn)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                domain_keys::sqlite::list_all(&mut conn)
            }
        }
    }

    pub fn find_user_by_id(&self, user_id: &str) -> QueryResult<models::User> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                users::pg::find_by_id(&mut conn, user_id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                users::sqlite::find_by_id(&mut conn, user_id)
            }
        }
    }

    pub fn list_active_user_keys(&self, user_id: &str) -> QueryResult<Vec<models::UserKey>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                user_keys::pg::list_active_for_user(&mut conn, user_id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                user_keys::sqlite::list_active_for_user(&mut conn, user_id)
            }
        }
    }

    pub fn find_credentials_for_user(
        &self,
        user_id: &str,
        credential_type: &str,
    ) -> QueryResult<Vec<models::AuthCredential>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                auth_credentials::pg::find_for_user(&mut conn, user_id, credential_type)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                auth_credentials::sqlite::find_for_user(&mut conn, user_id, credential_type)
            }
        }
    }

    /// All claims (any user, regardless of revocation/expiry), signatures
    /// attached. Used by the pre-alpha re-sign backfill.
    pub fn list_all_claims(&self) -> QueryResult<Vec<models::ClaimRow>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                claims::pg::list_all(&mut conn)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                claims::sqlite::list_all(&mut conn)
            }
        }
    }

    pub fn list_active_claims(&self, user_id: &str) -> QueryResult<Vec<models::ClaimRow>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                claims::pg::list_active_for_user(&mut conn, user_id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                claims::sqlite::list_active_for_user(&mut conn, user_id)
            }
        }
    }

    pub fn create_relation(
        &self,
        subject_type: &str,
        subject_id: &str,
        relation: &str,
        object_type: &str,
        object_id: &str,
    ) -> QueryResult<models::Relation> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                relations::pg::create(
                    &mut conn,
                    subject_type,
                    subject_id,
                    relation,
                    object_type,
                    object_id,
                )
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                relations::sqlite::create(
                    &mut conn,
                    subject_type,
                    subject_id,
                    relation,
                    object_type,
                    object_id,
                )
            }
        }
    }

    pub fn remove_relation(&self, id: &str) -> QueryResult<models::Relation> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                relations::pg::remove(&mut conn, id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                relations::sqlite::remove(&mut conn, id)
            }
        }
    }

    pub fn list_relations_for_subject(
        &self,
        subject_type: &str,
        subject_id: &str,
    ) -> QueryResult<Vec<models::Relation>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                relations::pg::list_for_subject(&mut conn, subject_type, subject_id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                relations::sqlite::list_for_subject(&mut conn, subject_type, subject_id)
            }
        }
    }

    pub fn list_relations_for_object(
        &self,
        object_type: &str,
        object_id: &str,
    ) -> QueryResult<Vec<models::Relation>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                relations::pg::list_for_object(&mut conn, object_type, object_id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                relations::sqlite::list_for_object(&mut conn, object_type, object_id)
            }
        }
    }

    pub fn check_permission(
        &self,
        user_id: &str,
        relation: &str,
        object_type: &str,
        object_id: &str,
    ) -> QueryResult<bool> {
        // Normalize the same way grant_relation does on the store side (db-05):
        // the id fields are whitespace-trimmed so the compare path matches stored
        // grants byte-for-byte. (Types/relation are canonical via VALID_*.)
        let user_id = user_id.trim();
        let object_id = object_id.trim();

        // A deactivated or non-existent user holds no permissions, even if stale
        // relation grants still reference them (db-06). Deactivation thus revokes
        // access without requiring the grant graph to be cleaned up first.
        match self.find_user_by_id(user_id) {
            Ok(u) if u.is_active => {}
            Ok(_) => return Ok(false),
            Err(diesel::result::Error::NotFound) => return Ok(false),
            Err(e) => return Err(e),
        }

        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                // 1. Direct check
                if relations::pg::check_direct(
                    &mut conn,
                    "user",
                    user_id,
                    relation,
                    object_type,
                    object_id,
                )? {
                    return Ok(true);
                }
                // 2. Admin override
                if relations::pg::check_direct(
                    &mut conn,
                    "user",
                    user_id,
                    "admin",
                    object_type,
                    object_id,
                )? {
                    return Ok(true);
                }
                // 3. Check via group memberships
                let user_relations = relations::pg::list_for_subject(&mut conn, "user", user_id)?;
                for rel in &user_relations {
                    if rel.relation == "member" && rel.object_type == "group" {
                        // 4. Group direct check
                        if relations::pg::check_direct(
                            &mut conn,
                            "group",
                            &rel.object_id,
                            relation,
                            object_type,
                            object_id,
                        )? {
                            return Ok(true);
                        }
                        // 5. Group admin override
                        if relations::pg::check_direct(
                            &mut conn,
                            "group",
                            &rel.object_id,
                            "admin",
                            object_type,
                            object_id,
                        )? {
                            return Ok(true);
                        }
                    }
                }
                Ok(false)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                // 1. Direct check
                if relations::sqlite::check_direct(
                    &mut conn,
                    "user",
                    user_id,
                    relation,
                    object_type,
                    object_id,
                )? {
                    return Ok(true);
                }
                // 2. Admin override
                if relations::sqlite::check_direct(
                    &mut conn,
                    "user",
                    user_id,
                    "admin",
                    object_type,
                    object_id,
                )? {
                    return Ok(true);
                }
                // 3. Check via group memberships
                let user_relations =
                    relations::sqlite::list_for_subject(&mut conn, "user", user_id)?;
                for rel in &user_relations {
                    if rel.relation == "member" && rel.object_type == "group" {
                        // 4. Group direct check
                        if relations::sqlite::check_direct(
                            &mut conn,
                            "group",
                            &rel.object_id,
                            relation,
                            object_type,
                            object_id,
                        )? {
                            return Ok(true);
                        }
                        // 5. Group admin override
                        if relations::sqlite::check_direct(
                            &mut conn,
                            "group",
                            &rel.object_id,
                            "admin",
                            object_type,
                            object_id,
                        )? {
                            return Ok(true);
                        }
                    }
                }
                Ok(false)
            }
        }
    }

    pub fn list_all_users(&self) -> QueryResult<Vec<models::User>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                users::pg::list_all(&mut conn)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                users::sqlite::list_all(&mut conn)
            }
        }
    }

    pub fn activate_user(&self, user_id: &str) -> QueryResult<models::User> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                users::pg::activate(&mut conn, user_id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                users::sqlite::activate(&mut conn, user_id)
            }
        }
    }

    pub fn deactivate_user(&self, user_id: &str) -> QueryResult<models::User> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                users::pg::deactivate(&mut conn, user_id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                users::sqlite::deactivate(&mut conn, user_id)
            }
        }
    }

    pub fn find_credential_by_id(&self, id: &str) -> QueryResult<models::AuthCredential> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                auth_credentials::pg::find_by_id(&mut conn, id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                auth_credentials::sqlite::find_by_id(&mut conn, id)
            }
        }
    }

    pub fn find_claim_by_id(&self, id: &str) -> QueryResult<models::ClaimRow> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                claims::pg::find_by_id(&mut conn, id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                claims::sqlite::find_by_id(&mut conn, id)
            }
        }
    }

    pub fn revoke_all_credentials_for_user(&self, user_id: &str) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                auth_credentials::pg::revoke_all_for_user(&mut conn, user_id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                auth_credentials::sqlite::revoke_all_for_user(&mut conn, user_id)
            }
        }
    }

    pub fn remove_credential(&self, credential_id: &str) -> QueryResult<models::AuthCredential> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                auth_credentials::pg::remove(&mut conn, credential_id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                auth_credentials::sqlite::remove(&mut conn, credential_id)
            }
        }
    }

    pub fn remove_claim(&self, claim_id: &str) -> QueryResult<models::ClaimRow> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                claims::pg::remove(&mut conn, claim_id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                claims::sqlite::remove(&mut conn, claim_id)
            }
        }
    }

    /// Create a user (human account) and provision its profiles atomically: a
    /// default presentable profile whose id REUSES the account id (so existing
    /// claims/assertions that reference the account id keep resolving — the
    /// migration to profiles is value-preserving), plus a fresh never-leaked
    /// root anchor profile.
    pub fn create_user(&self, username: &str, display_name: &str) -> QueryResult<models::User> {
        let domain = crate::conversions::get_domain_name();
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                conn.transaction(|conn| {
                    let user = users::pg::create(conn, username, display_name)?;
                    let account_id: uuid::Uuid = user
                        .id
                        .parse()
                        .map_err(|_| diesel::result::Error::NotFound)?;
                    profiles::pg::create(conn, account_id, account_id, &domain, false, None)?;
                    profiles::pg::create(
                        conn,
                        uuid::Uuid::now_v7(),
                        account_id,
                        &domain,
                        true,
                        Some("root"),
                    )?;
                    Ok(user)
                })
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                conn.transaction(|conn| {
                    let user = users::sqlite::create(conn, username, display_name)?;
                    profiles::sqlite::create(conn, &user.id, &user.id, &domain, false, None)?;
                    profiles::sqlite::create(
                        conn,
                        &uuid::Uuid::now_v7().to_string(),
                        &user.id,
                        &domain,
                        true,
                        Some("root"),
                    )?;
                    Ok(user)
                })
            }
        }
    }

    /// All profiles for an account (root + presentable), oldest first.
    pub fn list_profiles_for_account(&self, account_id: &str) -> QueryResult<Vec<models::Profile>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                let aid: uuid::Uuid = account_id
                    .parse()
                    .map_err(|_| diesel::result::Error::NotFound)?;
                profiles::pg::list_for_account(&mut conn, aid)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                profiles::sqlite::list_for_account(&mut conn, account_id)
            }
        }
    }

    /// The presentable (non-root) profiles for an account — the personas a login
    /// may present. The root anchor is excluded (it is never leaked).
    pub fn list_presentable_profiles_for_account(
        &self,
        account_id: &str,
    ) -> QueryResult<Vec<models::Profile>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                let aid: uuid::Uuid = account_id
                    .parse()
                    .map_err(|_| diesel::result::Error::NotFound)?;
                profiles::pg::list_presentable_for_account(&mut conn, aid)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                profiles::sqlite::list_presentable_for_account(&mut conn, account_id)
            }
        }
    }

    /// Create a presentable profile, enforcing the per-account cap on TOTAL
    /// presentable profiles (`MAX_PROFILES_PER_ACCOUNT`, default 1). NB: the
    /// default profile created at account creation already counts, so at the
    /// default of 1 this always rejects — additional personas require raising
    /// the cap. `Err` when the cap is reached. (Count-then-create is not atomic;
    /// a concurrent racer could exceed the cap by one — acceptable pre-alpha.)
    ///
    /// NOT YET SAFE to use beyond the default profile: claims and `find_user_by_id`
    /// are still keyed by the account id, so a non-default persona resolves no
    /// claims and its userinfo redemption 404s (fail-closed, not a leak). Raising
    /// the cap and using extra personas must wait for per-profile claim keying +
    /// threading the resolved subject through the consent grant.
    pub fn create_presentable_profile(
        &self,
        account_id: &str,
        label: Option<&str>,
    ) -> Result<models::Profile, String> {
        let domain = crate::conversions::get_domain_name();
        let limit = max_profiles_per_account();
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| e.to_string())?;
                let aid: uuid::Uuid = account_id
                    .parse()
                    .map_err(|_| "invalid account id".to_string())?;
                let n = profiles::pg::count_presentable_for_account(&mut conn, aid)
                    .map_err(|e| e.to_string())?;
                if n >= limit {
                    return Err("profile limit reached".to_string());
                }
                profiles::pg::create(&mut conn, uuid::Uuid::now_v7(), aid, &domain, false, label)
                    .map_err(|e| e.to_string())
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| e.to_string())?;
                let n = profiles::sqlite::count_presentable_for_account(&mut conn, account_id)
                    .map_err(|e| e.to_string())?;
                if n >= limit {
                    return Err("profile limit reached".to_string());
                }
                profiles::sqlite::create(
                    &mut conn,
                    &uuid::Uuid::now_v7().to_string(),
                    account_id,
                    &domain,
                    false,
                    label,
                )
                .map_err(|e| e.to_string())
            }
        }
    }

    /// Provision root + default profiles for any pre-existing account that has
    /// none (one-time data normalization after the profiles migration). Run at
    /// startup. Returns how many accounts were backfilled.
    pub fn backfill_profiles(&self) -> QueryResult<usize> {
        let domain = crate::conversions::get_domain_name();
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                profiles::pg::backfill(&mut conn, &domain)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                profiles::sqlite::backfill(&mut conn, &domain)
            }
        }
    }

    /// Create a domain administrator account: a user with `is_admin_account`
    /// set, a password credential, and the `admin` relation on the domain — and
    /// crucially NO profiles, so it cannot be presented to a relying party. All
    /// in one transaction. This is the "admin that doesn't go elsewhere".
    pub fn create_admin_account(
        &self,
        username: &str,
        display_name: &str,
        password_hash: &str,
    ) -> QueryResult<models::User> {
        let domain = crate::conversions::get_domain_name();
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                conn.transaction(|conn| {
                    let mut user = users::pg::create(conn, username, display_name)?;
                    let uid: uuid::Uuid = user
                        .id
                        .parse()
                        .map_err(|_| diesel::result::Error::NotFound)?;
                    diesel::update(crate::schema::pg::users::table.find(uid))
                        .set(crate::schema::pg::users::is_admin_account.eq(true))
                        .execute(conn)?;
                    auth_credentials::pg::create(conn, uid, "password", password_hash)?;
                    relations::pg::create(conn, "user", &user.id, "admin", "domain", &domain)?;
                    user.is_admin_account = true;
                    Ok(user)
                })
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                conn.transaction(|conn| {
                    let mut user = users::sqlite::create(conn, username, display_name)?;
                    diesel::update(crate::schema::sqlite::users::table.find(user.id.as_str()))
                        .set(crate::schema::sqlite::users::is_admin_account.eq(1))
                        .execute(conn)?;
                    auth_credentials::sqlite::create(conn, &user.id, "password", password_hash)?;
                    relations::sqlite::create(conn, "user", &user.id, "admin", "domain", &domain)?;
                    user.is_admin_account = true;
                    Ok(user)
                })
            }
        }
    }

    /// Split existing administrators into a normal user + a separate
    /// `<username>_admin` admin account (with a copy of the user's password), and
    /// demote the original to a normal user. Idempotent: an account that is
    /// already an admin account, or whose `_admin` twin already exists, is
    /// skipped; demoted originals no longer match. Best-effort per admin (logs +
    /// skips on error) so one bad account can't abort the pass. Returns how many
    /// admins were split.
    pub fn split_admins(&self) -> QueryResult<usize> {
        // Relations that confer administrative power on the domain.
        const ADMIN_RELATIONS: &[&str] = &["admin", "manage_users", "manage_claims", "api_access"];
        let domain = crate::conversions::get_domain_name();
        let rels = self.list_relations_for_object("domain", &domain)?;

        let admin_ids: std::collections::BTreeSet<String> = rels
            .iter()
            .filter(|r| {
                r.subject_type == "user" && (r.relation == "admin" || r.relation == "manage_users")
            })
            .map(|r| r.subject_id.clone())
            .collect();

        let mut count = 0;
        for uid in admin_ids {
            let user = match self.find_user_by_id(&uid) {
                Ok(u) => u,
                Err(_) => continue,
            };
            if user.is_admin_account {
                continue; // already a separated admin account
            }
            let target = format!("{}_admin", user.username);
            if self.find_user_by_username(&target).is_ok() {
                continue; // already split
            }
            let hash = match self
                .find_credentials_for_user(&uid, "password")
                .ok()
                .and_then(|c| c.into_iter().next())
            {
                Some(cred) => cred.credential_hash,
                None => {
                    log::warn!(
                        "admin split skipped {}: no password credential to copy",
                        user.username
                    );
                    continue;
                }
            };
            if let Err(e) = self.create_admin_account(&target, &user.display_name, &hash) {
                log::warn!("admin split: creating {} failed: {:?}", target, e);
                continue;
            }
            // Demote the original: drop its administrative relations on the domain.
            for r in rels.iter().filter(|r| {
                r.subject_type == "user"
                    && r.subject_id == uid
                    && r.object_type == "domain"
                    && r.object_id == domain
                    && ADMIN_RELATIONS.contains(&r.relation.as_str())
            }) {
                let _ = self.remove_relation(&r.id);
            }
            count += 1;
        }
        Ok(count)
    }

    pub fn update_display_name(
        &self,
        user_id: &str,
        new_display_name: &str,
    ) -> QueryResult<models::User> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                users::pg::update_display_name(&mut conn, user_id, new_display_name)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                users::sqlite::update_display_name(&mut conn, user_id, new_display_name)
            }
        }
    }

    pub fn create_auth_credential(
        &self,
        user_id: &str,
        credential_type: &str,
        credential_hash: &str,
    ) -> QueryResult<models::AuthCredential> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                let uid: uuid::Uuid = user_id
                    .parse()
                    .map_err(|_| diesel::result::Error::NotFound)?;
                auth_credentials::pg::create(&mut conn, uid, credential_type, credential_hash)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                auth_credentials::sqlite::create(
                    &mut conn,
                    user_id,
                    credential_type,
                    credential_hash,
                )
            }
        }
    }

    /// Replace a credential's stored hash in place. Used to transparently
    /// upgrade a legacy bcrypt password hash to Argon2id after a successful
    /// login, without changing the credential's identity or timestamps beyond
    /// `updated_at`.
    pub fn update_credential_hash(
        &self,
        credential_id: &str,
        new_hash: &str,
    ) -> QueryResult<models::AuthCredential> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                auth_credentials::pg::update_hash(&mut conn, credential_id, new_hash)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                auth_credentials::sqlite::update_hash(&mut conn, credential_id, new_hash)
            }
        }
    }

    pub fn create_user_key(
        &self,
        user_id: &str,
        public_key: &[u8],
        private_key_encrypted: &[u8],
        fingerprint: &str,
        algorithm: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<models::UserKey> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                let uid: uuid::Uuid = user_id
                    .parse()
                    .map_err(|_| diesel::result::Error::NotFound)?;
                user_keys::pg::create(
                    &mut conn,
                    uid,
                    public_key,
                    private_key_encrypted,
                    fingerprint,
                    algorithm,
                    expires_at,
                )
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                user_keys::sqlite::create(
                    &mut conn,
                    user_id,
                    public_key,
                    private_key_encrypted,
                    fingerprint,
                    algorithm,
                    &expires_at.to_rfc3339(),
                )
            }
        }
    }

    /// Persist a claim under a caller-supplied `claim_id`. The id MUST be the
    /// same one bound into the claim's signed payload (the signature covers
    /// claim_id), otherwise the stored claim won't verify — so the signer owns
    /// the id rather than letting the DB mint one.
    #[allow(clippy::too_many_arguments)]
    pub fn create_claim(
        &self,
        claim_id: &str,
        user_id: &str,
        claim_type: &str,
        claim_value: &[u8],
        signatures: &[liblinkkeys::generated::types::ClaimSignature],
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> QueryResult<models::ClaimRow> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                let id: uuid::Uuid = claim_id
                    .parse()
                    .map_err(|_| diesel::result::Error::NotFound)?;
                let uid: uuid::Uuid = user_id
                    .parse()
                    .map_err(|_| diesel::result::Error::NotFound)?;
                claims::pg::create(
                    &mut conn,
                    id,
                    uid,
                    claim_type,
                    claim_value,
                    signatures,
                    expires_at,
                )
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                claims::sqlite::create(
                    &mut conn,
                    claim_id,
                    user_id,
                    claim_type,
                    claim_value,
                    signatures,
                    expires_at.map(|e| e.to_rfc3339()).as_deref(),
                )
            }
        }
    }

    /// Store a consent grant, replacing any prior grant for the same
    /// (user, audience). `claim_types`/`requested_types` are persisted as JSON
    /// arrays; `signed_grant` is CBOR(SignedConsentGrant). `issued_at` and
    /// `expires_at` are RFC3339 strings.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_consent_grant(
        &self,
        grant_id: &str,
        user_id: &str,
        subject_domain: &str,
        audience: &str,
        claim_types: &[String],
        requested_types: &[String],
        signed_grant: &[u8],
        offered_claims: Option<&[u8]>,
        issued_at: &str,
        expires_at: &str,
    ) -> QueryResult<()> {
        let claim_types_json = serde_json::to_string(claim_types)
            .map_err(|_| diesel::result::Error::RollbackTransaction)?;
        let requested_types_json = serde_json::to_string(requested_types)
            .map_err(|_| diesel::result::Error::RollbackTransaction)?;
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                let id: uuid::Uuid = grant_id
                    .parse()
                    .map_err(|_| diesel::result::Error::NotFound)?;
                let uid: uuid::Uuid = user_id
                    .parse()
                    .map_err(|_| diesel::result::Error::NotFound)?;
                let issued = chrono::DateTime::parse_from_rfc3339(issued_at)
                    .map_err(|_| diesel::result::Error::NotFound)?
                    .with_timezone(&chrono::Utc);
                let expires = chrono::DateTime::parse_from_rfc3339(expires_at)
                    .map_err(|_| diesel::result::Error::NotFound)?
                    .with_timezone(&chrono::Utc);
                consent_grants::pg::upsert(
                    &mut conn,
                    id,
                    uid,
                    subject_domain,
                    audience,
                    &claim_types_json,
                    &requested_types_json,
                    signed_grant,
                    offered_claims,
                    issued,
                    expires,
                )
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                consent_grants::sqlite::upsert(
                    &mut conn,
                    grant_id,
                    user_id,
                    subject_domain,
                    audience,
                    &claim_types_json,
                    &requested_types_json,
                    signed_grant,
                    offered_claims,
                    issued_at,
                    expires_at,
                )
            }
        }
    }

    /// The current valid consent grant for (user, audience), if any (not revoked,
    /// not expired).
    pub fn find_active_consent_grant(
        &self,
        user_id: &str,
        audience: &str,
    ) -> QueryResult<Option<models::ConsentGrantRow>> {
        let now = chrono::Utc::now();
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                let uid: uuid::Uuid = user_id
                    .parse()
                    .map_err(|_| diesel::result::Error::NotFound)?;
                consent_grants::pg::find_active(&mut conn, uid, audience, now)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                consent_grants::sqlite::find_active(&mut conn, user_id, audience, &now.to_rfc3339())
            }
        }
    }

    /// Claims that have no signature rows — legacy claims the claim_signatures
    /// migration left unsigned. Used by the pre-alpha re-sign backfill.
    pub fn list_claims_missing_signatures(&self) -> QueryResult<Vec<models::ClaimRow>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                claims::pg::list_missing_signatures(&mut conn)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                claims::sqlite::list_missing_signatures(&mut conn)
            }
        }
    }

    /// Replace every signature on a claim. Used by the pre-alpha re-sign backfill.
    pub fn replace_claim_signatures(
        &self,
        claim_id: &str,
        signatures: &[liblinkkeys::generated::types::ClaimSignature],
    ) -> QueryResult<()> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                let id: uuid::Uuid = claim_id
                    .parse()
                    .map_err(|_| diesel::result::Error::NotFound)?;
                claims::pg::replace_signatures(&mut conn, id, signatures)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                claims::sqlite::replace_signatures(&mut conn, claim_id, signatures)
            }
        }
    }

    /// Record a nonce as used (durable, shared replay protection).
    /// Returns Ok(true) on first use, Ok(false) if already used (replay).
    pub fn record_nonce(&self, nonce: &str, ttl: std::time::Duration) -> QueryResult<bool> {
        let expires_at = chrono::Utc::now()
            + chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::seconds(300));
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                nonces::pg::record(&mut conn, nonce, expires_at)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                nonces::sqlite::record(&mut conn, nonce, &expires_at.to_rfc3339())
            }
        }
    }

    pub fn find_user_by_username(&self, username: &str) -> QueryResult<models::User> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                users::pg::find_by_username(&mut conn, username)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                users::sqlite::find_by_username(&mut conn, username)
            }
        }
    }

    pub fn guestbook_create(&self, name: &str) -> QueryResult<models::GuestbookEntry> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                guestbook::pg::create(&mut conn, name)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                guestbook::sqlite::create(&mut conn, name)
            }
        }
    }

    pub fn guestbook_list(
        &self,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> QueryResult<Vec<models::GuestbookEntry>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                guestbook::pg::list(&mut conn, offset, limit)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                guestbook::sqlite::list(&mut conn, offset, limit)
            }
        }
    }

    pub fn guestbook_update(
        &self,
        entry_id: &str,
        new_name: &str,
    ) -> QueryResult<models::GuestbookEntry> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                guestbook::pg::update(&mut conn, entry_id, new_name)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                guestbook::sqlite::update(&mut conn, entry_id, new_name)
            }
        }
    }

    pub fn guestbook_delete(&self, entry_id: &str) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                guestbook::pg::delete(&mut conn, entry_id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                guestbook::sqlite::delete(&mut conn, entry_id)
            }
        }
    }

    pub fn create_domain_key(
        &self,
        public_key: &[u8],
        private_key_encrypted: &[u8],
        fingerprint: &str,
        algorithm: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<models::DomainKey> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                domain_keys::pg::create(
                    &mut conn,
                    public_key,
                    private_key_encrypted,
                    fingerprint,
                    algorithm,
                    expires_at,
                )
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                domain_keys::sqlite::create(
                    &mut conn,
                    public_key,
                    private_key_encrypted,
                    fingerprint,
                    algorithm,
                    &expires_at.to_rfc3339(),
                )
            }
        }
    }

    /// Create an X25519 encryption domain key vouched for by a signing key.
    #[allow(clippy::too_many_arguments)]
    pub fn create_domain_encryption_key(
        &self,
        public_key: &[u8],
        private_key_encrypted: &[u8],
        fingerprint: &str,
        signed_by_key_id: &str,
        key_signature: &[u8],
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<models::DomainKey> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                domain_keys::pg::create_encryption_key(
                    &mut conn,
                    public_key,
                    private_key_encrypted,
                    fingerprint,
                    signed_by_key_id,
                    key_signature,
                    expires_at,
                )
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                domain_keys::sqlite::create_encryption_key(
                    &mut conn,
                    public_key,
                    private_key_encrypted,
                    fingerprint,
                    signed_by_key_id,
                    key_signature,
                    &expires_at.to_rfc3339(),
                )
            }
        }
    }

    /// Set expires_at on a credential (test utility for testing expired credential filtering).
    pub fn set_credential_expires_at(
        &self,
        credential_id: &str,
        expires_at: &str,
    ) -> QueryResult<()> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                use crate::schema::pg::auth_credentials;
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                let id: uuid::Uuid = credential_id
                    .parse()
                    .map_err(|_| diesel::result::Error::NotFound)?;
                let dt = chrono::DateTime::parse_from_rfc3339(expires_at)
                    .map_err(|_| diesel::result::Error::NotFound)?
                    .with_timezone(&chrono::Utc);
                diesel::update(auth_credentials::table.find(id))
                    .set(auth_credentials::expires_at.eq(Some(dt)))
                    .execute(&mut *conn)?;
                Ok(())
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                use crate::schema::sqlite::auth_credentials;
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                diesel::update(auth_credentials::table.find(credential_id))
                    .set(auth_credentials::expires_at.eq(Some(expires_at)))
                    .execute(&mut *conn)?;
                Ok(())
            }
        }
    }
}
