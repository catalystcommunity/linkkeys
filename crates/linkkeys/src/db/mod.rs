pub mod auth_credentials;
pub mod claim_policy;
pub mod claims;
pub mod consent_grants;
pub mod domain_keys;
pub mod domain_pins;
pub mod email_verification;
pub mod guestbook;
pub mod issued_revocations;
pub mod models;
pub mod nonces;
pub mod peer_keys;
pub mod profiles;
pub mod relations;
pub mod user_keys;
pub mod user_release_prefs;
pub mod users;

use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use std::env;

use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

// Schema migrations are tracked by diesel (the `__diesel_schema_migrations`
// table); diesel runs only the pending ones. Migrations are pure SCHEMA DDL,
// living under migrations/<backend>/<version>_<name>/up.sql. Idempotent DATA
// backfills are NOT migrations — they are "transforms" run separately at
// startup (see main.rs). Paths are relative to this crate's manifest dir; the
// migrations tree is at the workspace root.
#[cfg(feature = "postgres")]
const PG_MIGRATIONS: EmbeddedMigrations = embed_migrations!("../../migrations/postgres");
#[cfg(feature = "sqlite")]
const SQLITE_MIGRATIONS: EmbeddedMigrations = embed_migrations!("../../migrations/sqlite");

#[derive(diesel::QueryableByName)]
struct MigCount {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    n: i64,
}

/// ONE-TIME diesel-tracking baseline (2026-06-18 migration-system transition).
///
/// Deployed DBs were originally diesel-migrated through `20260614000001`
/// (`claim_signatures`), then the interim custom runner applied
/// `create_consent_grants`, `create_profiles`, and `admin_accounts` WITHOUT
/// recording them in `__diesel_schema_migrations`. Now that diesel tracks
/// migrations again, those three would be seen as pending and re-run → "already
/// exists" crash. Record them as applied (they exist) so diesel skips them and
/// runs only genuinely-new migrations (e.g. `claim_policy`).
///
/// Guarded + idempotent: acts only when diesel's table exists AND carries the
/// pre-transition cutoff version (so a fresh DB — table absent — is untouched and
/// diesel builds the whole schema normally). `ON CONFLICT DO NOTHING` makes
/// re-runs no-ops. The version strings are compile-time constants, not input.
/// Safe to delete once every deployment has booted on diesel tracking.
const LEGACY_APPLIED_UNTRACKED: &[&str] = &["20260614000002", "20260615000001", "20260616000001"];
const LEGACY_TRACKING_CUTOFF: &str = "20260614000001";

/// Run pending schema migrations on a Postgres connection. Returns the number run.
#[cfg(feature = "postgres")]
pub fn migrate_pg(conn: &mut diesel::PgConnection) -> Result<usize, String> {
    let applied = diesel::sql_query(format!(
        "SELECT count(*) AS n FROM __diesel_schema_migrations WHERE version = '{}'",
        LEGACY_TRACKING_CUTOFF
    ))
    .get_result::<MigCount>(conn)
    .map(|c| c.n > 0)
    .unwrap_or(false); // table absent (fresh DB) → nothing to baseline
    if applied {
        for v in LEGACY_APPLIED_UNTRACKED {
            diesel::sql_query(format!(
                "INSERT INTO __diesel_schema_migrations (version) VALUES ('{}') ON CONFLICT (version) DO NOTHING",
                v
            ))
            .execute(conn)
            .map_err(|e| e.to_string())?;
        }
    }
    conn.run_pending_migrations(PG_MIGRATIONS)
        .map(|v| v.len())
        .map_err(|e| e.to_string())
}

/// Run pending schema migrations on a SQLite connection. Returns the number run.
#[cfg(feature = "sqlite")]
pub fn migrate_sqlite(conn: &mut diesel::SqliteConnection) -> Result<usize, String> {
    let applied = diesel::sql_query(format!(
        "SELECT count(*) AS n FROM __diesel_schema_migrations WHERE version = '{}'",
        LEGACY_TRACKING_CUTOFF
    ))
    .get_result::<MigCount>(conn)
    .map(|c| c.n > 0)
    .unwrap_or(false);
    if applied {
        for v in LEGACY_APPLIED_UNTRACKED {
            diesel::sql_query(format!(
                "INSERT INTO __diesel_schema_migrations (version) VALUES ('{}') ON CONFLICT (version) DO NOTHING",
                v
            ))
            .execute(conn)
            .map_err(|e| e.to_string())?;
        }
    }
    conn.run_pending_migrations(SQLITE_MIGRATIONS)
        .map(|v| v.len())
        .map_err(|e| e.to_string())
}

/// Fetch a pooled connection, mapping the r2d2 checkout error into a diesel
/// error so call sites stay `QueryResult`-shaped.
#[cfg(feature = "postgres")]
fn pg_conn(
    p: &r2d2::Pool<ConnectionManager<diesel::PgConnection>>,
) -> QueryResult<r2d2::PooledConnection<ConnectionManager<diesel::PgConnection>>> {
    p.get().map_err(|e| {
        diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::Unknown,
            Box::new(e.to_string()),
        )
    })
}

#[cfg(feature = "sqlite")]
fn sqlite_conn(
    p: &r2d2::Pool<ConnectionManager<diesel::SqliteConnection>>,
) -> QueryResult<r2d2::PooledConnection<ConnectionManager<diesel::SqliteConnection>>> {
    p.get().map_err(|e| {
        diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::Unknown,
            Box::new(e.to_string()),
        )
    })
}

pub enum DbPool {
    #[cfg(feature = "postgres")]
    Postgres(r2d2::Pool<ConnectionManager<diesel::PgConnection>>),
    #[cfg(feature = "sqlite")]
    Sqlite(r2d2::Pool<ConnectionManager<diesel::SqliteConnection>>),
}

fn parse_release_policy_env() -> Vec<(String, String, String)> {
    std::env::var("CONSENT_RELEASE_POLICIES")
        .unwrap_or_default()
        .split(';')
        .filter_map(|entry| {
            let mut parts = entry.split('|').map(str::trim);
            let audience = parts.next()?;
            let claim_type = parts.next()?;
            let disposition = parts.next()?;
            if parts.next().is_some()
                || audience.is_empty()
                || claim_type.is_empty()
                || !matches!(disposition, "forced_allow" | "forced_deny")
            {
                log::warn!(
                    "Ignoring malformed CONSENT_RELEASE_POLICIES entry: {}",
                    entry
                );
                return None;
            }
            Some((
                audience.to_string(),
                claim_type.to_string(),
                disposition.to_string(),
            ))
        })
        .collect()
}

fn parse_release_policy_delete_env() -> Vec<(String, String)> {
    std::env::var("CONSENT_RELEASE_POLICY_DELETES")
        .unwrap_or_default()
        .split(';')
        .filter_map(|entry| {
            let mut parts = entry.split('|').map(str::trim);
            let audience = parts.next()?;
            let claim_type = parts.next()?;
            if parts.next().is_some() || audience.is_empty() || claim_type.is_empty() {
                log::warn!(
                    "Ignoring malformed CONSENT_RELEASE_POLICY_DELETES entry: {}",
                    entry
                );
                return None;
            }
            Some((audience.to_string(), claim_type.to_string()))
        })
        .collect()
}

fn parse_trusted_issuers_env() -> Vec<(String, String)> {
    std::env::var("TRUSTED_ISSUERS")
        .unwrap_or_default()
        .split(';')
        .filter_map(|entry| {
            let mut parts = entry.split('|').map(str::trim);
            let claim_type = parts.next()?;
            let issuer_domain = parts.next()?;
            if parts.next().is_some() || claim_type.is_empty() || issuer_domain.is_empty() {
                log::warn!("Ignoring malformed TRUSTED_ISSUERS entry: {}", entry);
                return None;
            }
            Some((claim_type.to_string(), issuer_domain.to_string()))
        })
        .collect()
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
pub fn max_profiles_per_account() -> i64 {
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

    /// Revoke a domain key by id (SEC-08). Verification already rejects revoked
    /// keys via `signing_key_validity`; peers stop honoring it after their next
    /// pin recheck / DNS re-resolve.
    pub fn revoke_domain_key(&self, key_id: &str) -> QueryResult<models::DomainKey> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => domain_keys::pg::revoke(&mut *pg_conn(p)?, key_id),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => domain_keys::sqlite::revoke(&mut *sqlite_conn(p)?, key_id),
        }
    }

    /// Revoke a user key by id (SEC-08). The only revocation lever for user keys,
    /// which have no DNS anchor.
    pub fn revoke_user_key(&self, key_id: &str) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => user_keys::pg::revoke(&mut *pg_conn(p)?, key_id),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => user_keys::sqlite::revoke(&mut *sqlite_conn(p)?, key_id),
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

    /// Idempotently seed the claim-type policy registry with the starter
    /// defaults (insert-if-absent, so admin edits are never overwritten) and, on
    /// first boot only, seed the per-audience release policy from the deprecated
    /// `CONSENT_FORCED_ALLOW` / `CONSENT_FORCED_DENY` env vars into the global
    /// `*` audience. Run at startup after migrations. Returns how many registry
    /// entries were newly inserted.
    pub fn seed_default_policies(&self) -> QueryResult<usize> {
        // TODO(later-session): remove the env-var seed once all deployments have
        // migrated their release policy into the database. `release_policies` is
        // the source of truth; the env vars are a one-time bootstrap.
        let parse_env = |var: &str| {
            std::env::var(var)
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<String>>()
        };
        let forced_allow = parse_env("CONSENT_FORCED_ALLOW");
        let forced_deny = parse_env("CONSENT_FORCED_DENY");
        let release_policy_deletes = parse_release_policy_delete_env();
        let release_policies = parse_release_policy_env();
        let trusted_issuers = parse_trusted_issuers_env();

        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                let mut inserted = 0;
                for policy in claim_policy::default_registry() {
                    inserted += claim_policy::pg::insert_policy_if_absent(&mut conn, policy)?;
                }
                if claim_policy::pg::count_release_policies(&mut conn)? == 0 {
                    for ct in &forced_allow {
                        claim_policy::pg::upsert_release_policy(
                            &mut conn,
                            "*",
                            ct,
                            "forced_allow",
                        )?;
                    }
                    for ct in &forced_deny {
                        claim_policy::pg::upsert_release_policy(&mut conn, "*", ct, "forced_deny")?;
                    }
                }
                for (audience, claim_type) in &release_policy_deletes {
                    claim_policy::pg::delete_release_policy(&mut conn, audience, claim_type)?;
                }
                for (audience, claim_type, disposition) in &release_policies {
                    claim_policy::pg::upsert_release_policy(
                        &mut conn,
                        audience,
                        claim_type,
                        disposition,
                    )?;
                }
                for (claim_type, issuer_domain) in &trusted_issuers {
                    claim_policy::pg::add_trusted_issuer(&mut conn, claim_type, issuer_domain)?;
                }
                Ok(inserted)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::Unknown,
                        Box::new(e.to_string()),
                    )
                })?;
                let mut inserted = 0;
                for policy in claim_policy::default_registry() {
                    inserted += claim_policy::sqlite::insert_policy_if_absent(&mut conn, policy)?;
                }
                if claim_policy::sqlite::count_release_policies(&mut conn)? == 0 {
                    for ct in &forced_allow {
                        claim_policy::sqlite::upsert_release_policy(
                            &mut conn,
                            "*",
                            ct,
                            "forced_allow",
                        )?;
                    }
                    for ct in &forced_deny {
                        claim_policy::sqlite::upsert_release_policy(
                            &mut conn,
                            "*",
                            ct,
                            "forced_deny",
                        )?;
                    }
                }
                for (audience, claim_type) in &release_policy_deletes {
                    claim_policy::sqlite::delete_release_policy(&mut conn, audience, claim_type)?;
                }
                for (audience, claim_type, disposition) in &release_policies {
                    claim_policy::sqlite::upsert_release_policy(
                        &mut conn,
                        audience,
                        claim_type,
                        disposition,
                    )?;
                }
                for (claim_type, issuer_domain) in &trusted_issuers {
                    claim_policy::sqlite::add_trusted_issuer(&mut conn, claim_type, issuer_domain)?;
                }
                Ok(inserted)
            }
        }
    }

    // ---- Claim-type policy registry & related policy tables ----
    //
    // Thin DbPool wrappers over `claim_policy::{pg,sqlite}`, dispatching on the
    // backend. The pure set/sign decision lives in `liblinkkeys::claim_policy`;
    // these are storage only.

    pub fn list_claim_policies(&self) -> QueryResult<Vec<models::ClaimTypePolicy>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => claim_policy::pg::list_policies(&mut *pg_conn(p)?),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => claim_policy::sqlite::list_policies(&mut *sqlite_conn(p)?),
        }
    }

    pub fn find_claim_policy(
        &self,
        claim_type: &str,
    ) -> QueryResult<Option<models::ClaimTypePolicy>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => claim_policy::pg::find_policy(&mut *pg_conn(p)?, claim_type),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                claim_policy::sqlite::find_policy(&mut *sqlite_conn(p)?, claim_type)
            }
        }
    }

    pub fn upsert_claim_policy(&self, policy: models::ClaimTypePolicy) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => claim_policy::pg::upsert_policy(&mut *pg_conn(p)?, policy),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => claim_policy::sqlite::upsert_policy(&mut *sqlite_conn(p)?, policy),
        }
    }

    pub fn delete_claim_policy(&self, claim_type: &str) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => claim_policy::pg::delete_policy(&mut *pg_conn(p)?, claim_type),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                claim_policy::sqlite::delete_policy(&mut *sqlite_conn(p)?, claim_type)
            }
        }
    }

    pub fn get_profile_pref(
        &self,
        profile_id: &str,
        claim_type: &str,
    ) -> QueryResult<Option<bool>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                claim_policy::pg::get_pref(&mut *pg_conn(p)?, profile_id, claim_type)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                claim_policy::sqlite::get_pref(&mut *sqlite_conn(p)?, profile_id, claim_type)
            }
        }
    }

    pub fn list_profile_prefs(
        &self,
        profile_id: &str,
    ) -> QueryResult<Vec<models::ProfileClaimPref>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                claim_policy::pg::list_prefs_for_profile(&mut *pg_conn(p)?, profile_id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                claim_policy::sqlite::list_prefs_for_profile(&mut *sqlite_conn(p)?, profile_id)
            }
        }
    }

    pub fn upsert_profile_pref(
        &self,
        profile_id: &str,
        claim_type: &str,
        auto_sign: bool,
    ) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                claim_policy::pg::upsert_pref(&mut *pg_conn(p)?, profile_id, claim_type, auto_sign)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => claim_policy::sqlite::upsert_pref(
                &mut *sqlite_conn(p)?,
                profile_id,
                claim_type,
                auto_sign,
            ),
        }
    }

    pub fn list_trusted_issuers_for(&self, claim_type: &str) -> QueryResult<Vec<String>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                claim_policy::pg::list_trusted_issuers_for(&mut *pg_conn(p)?, claim_type)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                claim_policy::sqlite::list_trusted_issuers_for(&mut *sqlite_conn(p)?, claim_type)
            }
        }
    }

    pub fn list_all_trusted_issuers(&self) -> QueryResult<Vec<models::TrustedIssuer>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => claim_policy::pg::list_all_trusted_issuers(&mut *pg_conn(p)?),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                claim_policy::sqlite::list_all_trusted_issuers(&mut *sqlite_conn(p)?)
            }
        }
    }

    pub fn add_trusted_issuer(&self, claim_type: &str, issuer_domain: &str) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                claim_policy::pg::add_trusted_issuer(&mut *pg_conn(p)?, claim_type, issuer_domain)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => claim_policy::sqlite::add_trusted_issuer(
                &mut *sqlite_conn(p)?,
                claim_type,
                issuer_domain,
            ),
        }
    }

    pub fn remove_trusted_issuer(
        &self,
        claim_type: &str,
        issuer_domain: &str,
    ) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => claim_policy::pg::remove_trusted_issuer(
                &mut *pg_conn(p)?,
                claim_type,
                issuer_domain,
            ),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => claim_policy::sqlite::remove_trusted_issuer(
                &mut *sqlite_conn(p)?,
                claim_type,
                issuer_domain,
            ),
        }
    }

    pub fn list_release_policies(&self) -> QueryResult<Vec<models::ReleasePolicy>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => claim_policy::pg::list_release_policies(&mut *pg_conn(p)?),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => claim_policy::sqlite::list_release_policies(&mut *sqlite_conn(p)?),
        }
    }

    pub fn list_release_policies_for_audience(
        &self,
        audience: &str,
    ) -> QueryResult<Vec<models::ReleasePolicy>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                claim_policy::pg::list_release_policies_for_audience(&mut *pg_conn(p)?, audience)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => claim_policy::sqlite::list_release_policies_for_audience(
                &mut *sqlite_conn(p)?,
                audience,
            ),
        }
    }

    pub fn upsert_release_policy(
        &self,
        audience: &str,
        claim_type: &str,
        disposition: &str,
    ) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => claim_policy::pg::upsert_release_policy(
                &mut *pg_conn(p)?,
                audience,
                claim_type,
                disposition,
            ),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => claim_policy::sqlite::upsert_release_policy(
                &mut *sqlite_conn(p)?,
                audience,
                claim_type,
                disposition,
            ),
        }
    }

    pub fn delete_release_policy(&self, audience: &str, claim_type: &str) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                claim_policy::pg::delete_release_policy(&mut *pg_conn(p)?, audience, claim_type)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => claim_policy::sqlite::delete_release_policy(
                &mut *sqlite_conn(p)?,
                audience,
                claim_type,
            ),
        }
    }

    pub fn list_pending_approvals(&self) -> QueryResult<Vec<models::ClaimApproval>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => claim_policy::pg::list_pending_approvals(&mut *pg_conn(p)?),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                claim_policy::sqlite::list_pending_approvals(&mut *sqlite_conn(p)?)
            }
        }
    }

    pub fn find_approval(&self, id: &str) -> QueryResult<models::ClaimApproval> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let uid: uuid::Uuid = id.parse().map_err(|_| diesel::result::Error::NotFound)?;
                claim_policy::pg::find_approval(&mut *pg_conn(p)?, uid)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => claim_policy::sqlite::find_approval(&mut *sqlite_conn(p)?, id),
        }
    }

    pub fn enqueue_approval(
        &self,
        user_id: &str,
        claim_type: &str,
        claim_value: &[u8],
    ) -> QueryResult<String> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let id = uuid::Uuid::now_v7();
                let uid: uuid::Uuid = user_id
                    .parse()
                    .map_err(|_| diesel::result::Error::NotFound)?;
                claim_policy::pg::enqueue_approval(
                    &mut *pg_conn(p)?,
                    id,
                    uid,
                    claim_type,
                    claim_value,
                )?;
                Ok(id.to_string())
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let id = uuid::Uuid::now_v7().to_string();
                claim_policy::sqlite::enqueue_approval(
                    &mut *sqlite_conn(p)?,
                    &id,
                    user_id,
                    claim_type,
                    claim_value,
                )?;
                Ok(id)
            }
        }
    }

    pub fn resolve_approval(
        &self,
        id: &str,
        status: &str,
        resolved_by: &str,
    ) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let uid: uuid::Uuid = id.parse().map_err(|_| diesel::result::Error::NotFound)?;
                claim_policy::pg::resolve_approval(&mut *pg_conn(p)?, uid, status, resolved_by)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => claim_policy::sqlite::resolve_approval(
                &mut *sqlite_conn(p)?,
                id,
                status,
                resolved_by,
            ),
        }
    }

    /// Enqueue a non-claim admin review item (e.g. a key-mismatch needing human
    /// review). Returns the new review id.
    pub fn enqueue_review(
        &self,
        kind: &str,
        subject: Option<&str>,
        detail: Option<&str>,
    ) -> QueryResult<String> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let id = uuid::Uuid::now_v7();
                claim_policy::pg::enqueue_review(&mut *pg_conn(p)?, id, kind, subject, detail)?;
                Ok(id.to_string())
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let id = uuid::Uuid::now_v7().to_string();
                claim_policy::sqlite::enqueue_review(
                    &mut *sqlite_conn(p)?,
                    &id,
                    kind,
                    subject,
                    detail,
                )?;
                Ok(id)
            }
        }
    }

    pub fn list_pending_reviews(&self, kind: &str) -> QueryResult<Vec<models::AdminReview>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => claim_policy::pg::list_pending_reviews(&mut *pg_conn(p)?, kind),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                claim_policy::sqlite::list_pending_reviews(&mut *sqlite_conn(p)?, kind)
            }
        }
    }

    /// Append an audit-log event. Best-effort context; never carries secrets.
    pub fn write_audit(
        &self,
        event: &str,
        subject: Option<&str>,
        actor: Option<&str>,
        detail: Option<&str>,
    ) -> QueryResult<String> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let id = uuid::Uuid::now_v7();
                claim_policy::pg::write_audit(
                    &mut *pg_conn(p)?,
                    id,
                    event,
                    subject,
                    actor,
                    detail,
                )?;
                Ok(id.to_string())
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let id = uuid::Uuid::now_v7().to_string();
                claim_policy::sqlite::write_audit(
                    &mut *sqlite_conn(p)?,
                    &id,
                    event,
                    subject,
                    actor,
                    detail,
                )?;
                Ok(id)
            }
        }
    }

    pub fn list_audit(&self, limit: i64) -> QueryResult<Vec<models::AuditEntry>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => claim_policy::pg::list_audit(&mut *pg_conn(p)?, limit),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => claim_policy::sqlite::list_audit(&mut *sqlite_conn(p)?, limit),
        }
    }

    // -- Domain fingerprint pins (SEC-01 TOFU) --

    pub fn find_domain_pin(&self, domain: &str) -> QueryResult<Option<models::DomainKeyPin>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => domain_pins::pg::find(&mut *pg_conn(p)?, domain),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => domain_pins::sqlite::find(&mut *sqlite_conn(p)?, domain),
        }
    }

    pub fn create_domain_pin(&self, domain: &str, fingerprints: &str) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => domain_pins::pg::create(&mut *pg_conn(p)?, domain, fingerprints),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                domain_pins::sqlite::create(&mut *sqlite_conn(p)?, domain, fingerprints)
            }
        }
    }

    pub fn rotate_domain_pin(&self, domain: &str, fingerprints: &str) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => domain_pins::pg::rotate(&mut *pg_conn(p)?, domain, fingerprints),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                domain_pins::sqlite::rotate(&mut *sqlite_conn(p)?, domain, fingerprints)
            }
        }
    }

    pub fn touch_domain_pin(&self, domain: &str) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => domain_pins::pg::touch(&mut *pg_conn(p)?, domain),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => domain_pins::sqlite::touch(&mut *sqlite_conn(p)?, domain),
        }
    }

    pub fn list_domain_pins(&self) -> QueryResult<Vec<models::DomainKeyPin>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => domain_pins::pg::list_all(&mut *pg_conn(p)?),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => domain_pins::sqlite::list_all(&mut *sqlite_conn(p)?),
        }
    }

    // -- Issued revocation certificates (SEC-08) --

    pub fn insert_issued_revocation(
        &self,
        target_key_id: &str,
        target_fingerprint: &str,
        revoked_at: chrono::DateTime<chrono::Utc>,
        cert: &[u8],
    ) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => issued_revocations::pg::insert(
                &mut *pg_conn(p)?,
                target_key_id,
                target_fingerprint,
                revoked_at,
                cert,
            ),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => issued_revocations::sqlite::insert(
                &mut *sqlite_conn(p)?,
                target_key_id,
                target_fingerprint,
                revoked_at,
                cert,
            ),
        }
    }

    pub fn list_issued_revocations_since(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
    ) -> QueryResult<Vec<models::IssuedRevocation>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => issued_revocations::pg::list_since(&mut *pg_conn(p)?, since),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                issued_revocations::sqlite::list_since(&mut *sqlite_conn(p)?, since)
            }
        }
    }

    pub fn has_issued_revocations_since(
        &self,
        since: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<bool> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => issued_revocations::pg::exists_since(&mut *pg_conn(p)?, since),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                issued_revocations::sqlite::exists_since(&mut *sqlite_conn(p)?, since)
            }
        }
    }

    /// Revoke a cached peer key by fingerprint (pin recheck retiring an old key).
    pub fn revoke_peer_key_by_fingerprint(
        &self,
        domain: &str,
        fingerprint: &str,
    ) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                peer_keys::pg::revoke_by_fingerprint(&mut *pg_conn(p)?, domain, fingerprint)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                peer_keys::sqlite::revoke_by_fingerprint(&mut *sqlite_conn(p)?, domain, fingerprint)
            }
        }
    }

    /// Revoke a cached peer key by (domain, key_id) at the domain's asserted
    /// timestamp from a verified revocation certificate (SEC-08).
    pub fn revoke_peer_key_by_key_id_at(
        &self,
        domain: &str,
        key_id: &str,
        revoked_at: &str,
    ) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                peer_keys::pg::revoke_by_key_id_at(&mut *pg_conn(p)?, domain, key_id, revoked_at)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => peer_keys::sqlite::revoke_by_key_id_at(
                &mut *sqlite_conn(p)?,
                domain,
                key_id,
                revoked_at,
            ),
        }
    }

    pub fn revoke_active_claims_of_type(
        &self,
        user_id: &str,
        claim_type: &str,
    ) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                claims::pg::revoke_active_of_type(&mut *pg_conn(p)?, user_id, claim_type)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                claims::sqlite::revoke_active_of_type(&mut *sqlite_conn(p)?, user_id, claim_type)
            }
        }
    }

    pub fn create_email_verification(
        &self,
        token: &str,
        user_id: &str,
        email: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let uid: uuid::Uuid = user_id
                    .parse()
                    .map_err(|_| diesel::result::Error::NotFound)?;
                email_verification::pg::create(&mut *pg_conn(p)?, token, uid, email, expires_at)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => email_verification::sqlite::create(
                &mut *sqlite_conn(p)?,
                token,
                user_id,
                email,
                &expires_at.to_rfc3339(),
            ),
        }
    }

    pub fn find_email_verification(
        &self,
        token: &str,
    ) -> QueryResult<Option<models::EmailVerification>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => email_verification::pg::find(&mut *pg_conn(p)?, token),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => email_verification::sqlite::find(&mut *sqlite_conn(p)?, token),
        }
    }

    pub fn delete_email_verification(&self, token: &str) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => email_verification::pg::delete(&mut *pg_conn(p)?, token),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => email_verification::sqlite::delete(&mut *sqlite_conn(p)?, token),
        }
    }

    /// Append a peer domain's public key to the cache (no-op if already cached).
    pub fn cache_peer_key(&self, key: &models::PeerKey) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => peer_keys::pg::cache(&mut *pg_conn(p)?, key),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => peer_keys::sqlite::cache(&mut *sqlite_conn(p)?, key),
        }
    }

    /// All cached public keys for a peer domain (for verifying stored external
    /// signatures).
    pub fn list_peer_keys_for_domain(&self, domain: &str) -> QueryResult<Vec<models::PeerKey>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => peer_keys::pg::list_for_domain(&mut *pg_conn(p)?, domain),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => peer_keys::sqlite::list_for_domain(&mut *sqlite_conn(p)?, domain),
        }
    }

    pub fn add_user_release_pref(
        &self,
        user_id: &str,
        audience: &str,
        claim_type: &str,
    ) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let uid: uuid::Uuid = user_id
                    .parse()
                    .map_err(|_| diesel::result::Error::NotFound)?;
                user_release_prefs::pg::add(&mut *pg_conn(p)?, uid, audience, claim_type)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => user_release_prefs::sqlite::add(
                &mut *sqlite_conn(p)?,
                user_id,
                audience,
                claim_type,
            ),
        }
    }

    pub fn remove_user_release_pref(
        &self,
        user_id: &str,
        audience: &str,
        claim_type: &str,
    ) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let uid: uuid::Uuid = user_id
                    .parse()
                    .map_err(|_| diesel::result::Error::NotFound)?;
                user_release_prefs::pg::remove(&mut *pg_conn(p)?, uid, audience, claim_type)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => user_release_prefs::sqlite::remove(
                &mut *sqlite_conn(p)?,
                user_id,
                audience,
                claim_type,
            ),
        }
    }

    /// Claim types the user pre-allows for `audience` (plus their global `*`).
    pub fn list_user_release_allows(
        &self,
        user_id: &str,
        audience: &str,
    ) -> QueryResult<Vec<String>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let uid: uuid::Uuid = user_id
                    .parse()
                    .map_err(|_| diesel::result::Error::NotFound)?;
                user_release_prefs::pg::list_allows(&mut *pg_conn(p)?, uid, audience)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                user_release_prefs::sqlite::list_allows(&mut *sqlite_conn(p)?, user_id, audience)
            }
        }
    }

    /// All (audience, claim_type) standing prefs for the user.
    pub fn list_user_release_prefs(&self, user_id: &str) -> QueryResult<Vec<(String, String)>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let uid: uuid::Uuid = user_id
                    .parse()
                    .map_err(|_| diesel::result::Error::NotFound)?;
                user_release_prefs::pg::list_all(&mut *pg_conn(p)?, uid)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                user_release_prefs::sqlite::list_all(&mut *sqlite_conn(p)?, user_id)
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
        attested_at: chrono::DateTime<chrono::Utc>,
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
                    attested_at,
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
                    &attested_at.to_rfc3339(),
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
