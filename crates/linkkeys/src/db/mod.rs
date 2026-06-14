pub mod auth_credentials;
pub mod claims;
pub mod domain_keys;
pub mod guestbook;
pub mod models;
pub mod nonces;
pub mod relations;
pub mod user_keys;
pub mod users;

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

// -- Convenience methods to eliminate match-on-DbPool boilerplate --

impl DbPool {
    pub fn list_active_domain_keys(&self) -> QueryResult<Vec<models::DomainKey>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                domain_keys::pg::list_active(&mut conn)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                domain_keys::sqlite::list_active(&mut conn)
            }
        }
    }

    pub fn list_all_domain_keys(&self) -> QueryResult<Vec<models::DomainKey>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                domain_keys::pg::list_all(&mut conn)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                domain_keys::sqlite::list_all(&mut conn)
            }
        }
    }

    pub fn find_user_by_id(&self, user_id: &str) -> QueryResult<models::User> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                users::pg::find_by_id(&mut conn, user_id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                users::sqlite::find_by_id(&mut conn, user_id)
            }
        }
    }

    pub fn list_active_user_keys(&self, user_id: &str) -> QueryResult<Vec<models::UserKey>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                user_keys::pg::list_active_for_user(&mut conn, user_id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
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
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                auth_credentials::pg::find_for_user(&mut conn, user_id, credential_type)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                auth_credentials::sqlite::find_for_user(&mut conn, user_id, credential_type)
            }
        }
    }

    pub fn list_active_claims(&self, user_id: &str) -> QueryResult<Vec<models::ClaimRow>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                claims::pg::list_active_for_user(&mut conn, user_id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
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
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                relations::pg::create(&mut conn, subject_type, subject_id, relation, object_type, object_id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                relations::sqlite::create(&mut conn, subject_type, subject_id, relation, object_type, object_id)
            }
        }
    }

    pub fn remove_relation(&self, id: &str) -> QueryResult<models::Relation> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                relations::pg::remove(&mut conn, id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
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
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                relations::pg::list_for_subject(&mut conn, subject_type, subject_id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
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
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                relations::pg::list_for_object(&mut conn, object_type, object_id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
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
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                // 1. Direct check
                if relations::pg::check_direct(&mut conn, "user", user_id, relation, object_type, object_id)? {
                    return Ok(true);
                }
                // 2. Admin override
                if relations::pg::check_direct(&mut conn, "user", user_id, "admin", object_type, object_id)? {
                    return Ok(true);
                }
                // 3. Check via group memberships
                let user_relations = relations::pg::list_for_subject(&mut conn, "user", user_id)?;
                for rel in &user_relations {
                    if rel.relation == "member" && rel.object_type == "group" {
                        // 4. Group direct check
                        if relations::pg::check_direct(&mut conn, "group", &rel.object_id, relation, object_type, object_id)? {
                            return Ok(true);
                        }
                        // 5. Group admin override
                        if relations::pg::check_direct(&mut conn, "group", &rel.object_id, "admin", object_type, object_id)? {
                            return Ok(true);
                        }
                    }
                }
                Ok(false)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                // 1. Direct check
                if relations::sqlite::check_direct(&mut conn, "user", user_id, relation, object_type, object_id)? {
                    return Ok(true);
                }
                // 2. Admin override
                if relations::sqlite::check_direct(&mut conn, "user", user_id, "admin", object_type, object_id)? {
                    return Ok(true);
                }
                // 3. Check via group memberships
                let user_relations = relations::sqlite::list_for_subject(&mut conn, "user", user_id)?;
                for rel in &user_relations {
                    if rel.relation == "member" && rel.object_type == "group" {
                        // 4. Group direct check
                        if relations::sqlite::check_direct(&mut conn, "group", &rel.object_id, relation, object_type, object_id)? {
                            return Ok(true);
                        }
                        // 5. Group admin override
                        if relations::sqlite::check_direct(&mut conn, "group", &rel.object_id, "admin", object_type, object_id)? {
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
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                users::pg::list_all(&mut conn)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                users::sqlite::list_all(&mut conn)
            }
        }
    }

    pub fn activate_user(&self, user_id: &str) -> QueryResult<models::User> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                users::pg::activate(&mut conn, user_id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                users::sqlite::activate(&mut conn, user_id)
            }
        }
    }

    pub fn deactivate_user(&self, user_id: &str) -> QueryResult<models::User> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                users::pg::deactivate(&mut conn, user_id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                users::sqlite::deactivate(&mut conn, user_id)
            }
        }
    }

    pub fn find_credential_by_id(&self, id: &str) -> QueryResult<models::AuthCredential> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                auth_credentials::pg::find_by_id(&mut conn, id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                auth_credentials::sqlite::find_by_id(&mut conn, id)
            }
        }
    }

    pub fn find_claim_by_id(&self, id: &str) -> QueryResult<models::ClaimRow> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                claims::pg::find_by_id(&mut conn, id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                claims::sqlite::find_by_id(&mut conn, id)
            }
        }
    }

    pub fn revoke_all_credentials_for_user(&self, user_id: &str) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                auth_credentials::pg::revoke_all_for_user(&mut conn, user_id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                auth_credentials::sqlite::revoke_all_for_user(&mut conn, user_id)
            }
        }
    }

    pub fn remove_credential(&self, credential_id: &str) -> QueryResult<models::AuthCredential> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                auth_credentials::pg::remove(&mut conn, credential_id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                auth_credentials::sqlite::remove(&mut conn, credential_id)
            }
        }
    }

    pub fn remove_claim(&self, claim_id: &str) -> QueryResult<models::ClaimRow> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                claims::pg::remove(&mut conn, claim_id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                claims::sqlite::remove(&mut conn, claim_id)
            }
        }
    }

    pub fn create_user(&self, username: &str, display_name: &str) -> QueryResult<models::User> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                users::pg::create(&mut conn, username, display_name)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                users::sqlite::create(&mut conn, username, display_name)
            }
        }
    }

    pub fn update_display_name(&self, user_id: &str, new_display_name: &str) -> QueryResult<models::User> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                users::pg::update_display_name(&mut conn, user_id, new_display_name)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
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
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                let uid: uuid::Uuid = user_id
                    .parse()
                    .map_err(|_| diesel::result::Error::NotFound)?;
                auth_credentials::pg::create(&mut conn, uid, credential_type, credential_hash)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                auth_credentials::sqlite::create(&mut conn, user_id, credential_type, credential_hash)
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
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                auth_credentials::pg::update_hash(&mut conn, credential_id, new_hash)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
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
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                let uid: uuid::Uuid = user_id
                    .parse()
                    .map_err(|_| diesel::result::Error::NotFound)?;
                user_keys::pg::create(&mut conn, uid, public_key, private_key_encrypted, fingerprint, algorithm, expires_at)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
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
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                let id: uuid::Uuid = claim_id
                    .parse()
                    .map_err(|_| diesel::result::Error::NotFound)?;
                let uid: uuid::Uuid = user_id
                    .parse()
                    .map_err(|_| diesel::result::Error::NotFound)?;
                claims::pg::create(&mut conn, id, uid, claim_type, claim_value, signatures, expires_at)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
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

    /// Claims that have no signature rows — legacy claims the claim_signatures
    /// migration left unsigned. Used by the pre-alpha re-sign backfill.
    pub fn list_claims_missing_signatures(&self) -> QueryResult<Vec<models::ClaimRow>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                claims::pg::list_missing_signatures(&mut conn)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
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
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                let id: uuid::Uuid = claim_id
                    .parse()
                    .map_err(|_| diesel::result::Error::NotFound)?;
                claims::pg::replace_signatures(&mut conn, id, signatures)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
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
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                nonces::pg::record(&mut conn, nonce, expires_at)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                nonces::sqlite::record(&mut conn, nonce, &expires_at.to_rfc3339())
            }
        }
    }

    pub fn find_user_by_username(&self, username: &str) -> QueryResult<models::User> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                users::pg::find_by_username(&mut conn, username)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                users::sqlite::find_by_username(&mut conn, username)
            }
        }
    }

    pub fn guestbook_create(&self, name: &str) -> QueryResult<models::GuestbookEntry> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                guestbook::pg::create(&mut conn, name)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
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
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                guestbook::pg::list(&mut conn, offset, limit)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                guestbook::sqlite::list(&mut conn, offset, limit)
            }
        }
    }

    pub fn guestbook_update(&self, entry_id: &str, new_name: &str) -> QueryResult<models::GuestbookEntry> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                guestbook::pg::update(&mut conn, entry_id, new_name)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                guestbook::sqlite::update(&mut conn, entry_id, new_name)
            }
        }
    }

    pub fn guestbook_delete(&self, entry_id: &str) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                guestbook::pg::delete(&mut conn, entry_id)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
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
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                domain_keys::pg::create(&mut conn, public_key, private_key_encrypted, fingerprint, algorithm, expires_at)
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
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
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                domain_keys::pg::create_encryption_key(
                    &mut conn, public_key, private_key_encrypted, fingerprint, signed_by_key_id, key_signature, expires_at,
                )
            }
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => {
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
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
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
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
                let mut conn = p.get().map_err(|e| diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::Unknown,
                    Box::new(e.to_string()),
                ))?;
                diesel::update(auth_credentials::table.find(credential_id))
                    .set(auth_credentials::expires_at.eq(Some(expires_at)))
                    .execute(&mut *conn)?;
                Ok(())
            }
        }
    }
}
