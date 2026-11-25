//! Persistence for application accounts on a relying party
//! (request-app-management.md): account renames, application ids, named API
//! keys, per-account limits, the keyed-hash register of the users an
//! application served, and daily `Rp` usage counts. Pure storage: no policy,
//! no hashing, no counting rules.

use time::{Date, OffsetDateTime};

use super::models::{AuthCredential, User};
use super::{DbPool, QueryResult};

/// Limits an administrator set on one account. `None` means no limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountLimitsRecord {
    pub max_api_keys: Option<i32>,
    pub max_distinct_users: Option<i32>,
    pub distinct_user_window_days: i32,
    pub requests_per_minute: Option<i32>,
    pub request_burst: Option<i32>,
}

/// The default rolling window of the distinct-user count.
pub const DEFAULT_DISTINCT_USER_WINDOW_DAYS: i32 = 30;

impl Default for AccountLimitsRecord {
    fn default() -> Self {
        AccountLimitsRecord {
            max_api_keys: None,
            max_distinct_users: None,
            distinct_user_window_days: DEFAULT_DISTINCT_USER_WINDOW_DAYS,
            requests_per_minute: None,
            request_burst: None,
        }
    }
}

/// Counts of one `Rp` operation by one account on one UTC day.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageDayRecord {
    pub day: Date,
    pub operation: String,
    pub succeeded: i64,
    pub failed: i64,
}

/// The minimum time between two `last_used_at` writes for one API key.
pub const LAST_USED_RESOLUTION_SECONDS: i64 = 60;

#[cfg(feature = "postgres")]
pub mod pg {
    use super::*;
    use crate::db::models::pg::{AuthCredentialRow, UserRow};
    use crate::schema::pg::{
        account_limits, application_users, auth_credentials, rp_usage_days, users,
    };
    use diesel::prelude::*;
    use diesel::PgConnection;

    fn uuid(s: &str) -> QueryResult<uuid::Uuid> {
        s.parse().map_err(|_| diesel::result::Error::NotFound)
    }

    pub fn rename(conn: &mut PgConnection, user_id: &str, username: &str) -> QueryResult<User> {
        diesel::update(users::table.find(uuid(user_id)?))
            .set(users::username.eq(username))
            .get_result::<UserRow>(conn)
            .map(Into::into)
    }

    pub fn set_application_id(
        conn: &mut PgConnection,
        user_id: &str,
        application_id: &str,
    ) -> QueryResult<User> {
        diesel::update(
            users::table
                .find(uuid(user_id)?)
                .filter(users::kind.eq("application")),
        )
        .set(users::application_id.eq(Some(application_id)))
        .get_result::<UserRow>(conn)
        .map(Into::into)
    }

    pub fn list_api_keys(
        conn: &mut PgConnection,
        user_id: &str,
    ) -> QueryResult<Vec<AuthCredential>> {
        auth_credentials::table
            .filter(auth_credentials::user_id.eq(uuid(user_id)?))
            .filter(auth_credentials::credential_type.eq("api_key"))
            .filter(auth_credentials::revoked_at.is_null())
            .order((
                auth_credentials::created_at.asc(),
                auth_credentials::id.asc(),
            ))
            .load::<AuthCredentialRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn revoke_api_key(
        conn: &mut PgConnection,
        user_id: &str,
        key_id: &str,
        now: OffsetDateTime,
    ) -> QueryResult<usize> {
        let Ok(key_uuid) = key_id.parse::<uuid::Uuid>() else {
            return Ok(0);
        };
        diesel::update(
            auth_credentials::table
                .find(key_uuid)
                .filter(auth_credentials::user_id.eq(uuid(user_id)?))
                .filter(auth_credentials::credential_type.eq("api_key"))
                .filter(auth_credentials::revoked_at.is_null()),
        )
        .set((
            auth_credentials::revoked_at.eq(Some(now)),
            auth_credentials::updated_at.eq(now),
        ))
        .execute(conn)
    }

    pub fn touch_api_key(
        conn: &mut PgConnection,
        key_id: &str,
        now: OffsetDateTime,
    ) -> QueryResult<usize> {
        let cutoff = now - time::Duration::seconds(LAST_USED_RESOLUTION_SECONDS);
        diesel::update(
            auth_credentials::table.find(uuid(key_id)?).filter(
                auth_credentials::last_used_at
                    .is_null()
                    .or(auth_credentials::last_used_at.lt(cutoff)),
            ),
        )
        .set(auth_credentials::last_used_at.eq(Some(now)))
        .execute(conn)
    }

    pub fn get_limits(
        conn: &mut PgConnection,
        user_id: &str,
    ) -> QueryResult<Option<AccountLimitsRecord>> {
        account_limits::table
            .find(uuid(user_id)?)
            .select((
                account_limits::max_api_keys,
                account_limits::max_distinct_users,
                account_limits::distinct_user_window_days,
                account_limits::requests_per_minute,
                account_limits::request_burst,
            ))
            .first::<(Option<i32>, Option<i32>, i32, Option<i32>, Option<i32>)>(conn)
            .optional()
            .map(|row| {
                row.map(|(a, b, c, d, e)| AccountLimitsRecord {
                    max_api_keys: a,
                    max_distinct_users: b,
                    distinct_user_window_days: c,
                    requests_per_minute: d,
                    request_burst: e,
                })
            })
    }

    pub fn set_limits(
        conn: &mut PgConnection,
        user_id: &str,
        limits: &AccountLimitsRecord,
    ) -> QueryResult<usize> {
        let id = uuid(user_id)?;
        let values = (
            account_limits::user_id.eq(id),
            account_limits::max_api_keys.eq(limits.max_api_keys),
            account_limits::max_distinct_users.eq(limits.max_distinct_users),
            account_limits::distinct_user_window_days.eq(limits.distinct_user_window_days),
            account_limits::requests_per_minute.eq(limits.requests_per_minute),
            account_limits::request_burst.eq(limits.request_burst),
        );
        diesel::insert_into(account_limits::table)
            .values(values)
            .on_conflict(account_limits::user_id)
            .do_update()
            .set((
                account_limits::max_api_keys.eq(limits.max_api_keys),
                account_limits::max_distinct_users.eq(limits.max_distinct_users),
                account_limits::distinct_user_window_days.eq(limits.distinct_user_window_days),
                account_limits::requests_per_minute.eq(limits.requests_per_minute),
                account_limits::request_burst.eq(limits.request_burst),
            ))
            .execute(conn)
    }

    pub fn user_seen_since(
        conn: &mut PgConnection,
        account_id: &str,
        user_hash: &[u8],
        since: OffsetDateTime,
    ) -> QueryResult<bool> {
        diesel::select(diesel::dsl::exists(
            application_users::table
                .filter(application_users::account_id.eq(uuid(account_id)?))
                .filter(application_users::user_hash.eq(user_hash))
                .filter(application_users::last_seen_at.ge(since)),
        ))
        .get_result(conn)
    }

    pub fn count_users_since(
        conn: &mut PgConnection,
        account_id: &str,
        since: OffsetDateTime,
    ) -> QueryResult<i64> {
        application_users::table
            .filter(application_users::account_id.eq(uuid(account_id)?))
            .filter(application_users::last_seen_at.ge(since))
            .count()
            .get_result(conn)
    }

    pub fn record_user(
        conn: &mut PgConnection,
        account_id: &str,
        user_hash: &[u8],
        now: OffsetDateTime,
    ) -> QueryResult<usize> {
        diesel::insert_into(application_users::table)
            .values((
                application_users::account_id.eq(uuid(account_id)?),
                application_users::user_hash.eq(user_hash),
                application_users::last_seen_at.eq(now),
            ))
            .on_conflict((application_users::account_id, application_users::user_hash))
            .do_update()
            .set(application_users::last_seen_at.eq(now))
            .execute(conn)
    }

    pub fn prune_users(conn: &mut PgConnection, before: OffsetDateTime) -> QueryResult<usize> {
        diesel::delete(application_users::table.filter(application_users::last_seen_at.lt(before)))
            .execute(conn)
    }

    pub fn add_usage(
        conn: &mut PgConnection,
        account_id: &str,
        day: Date,
        operation: &str,
        succeeded: i64,
        failed: i64,
    ) -> QueryResult<usize> {
        diesel::insert_into(rp_usage_days::table)
            .values((
                rp_usage_days::account_id.eq(uuid(account_id)?),
                rp_usage_days::day.eq(day),
                rp_usage_days::operation.eq(operation),
                rp_usage_days::succeeded.eq(succeeded),
                rp_usage_days::failed.eq(failed),
            ))
            .on_conflict((
                rp_usage_days::account_id,
                rp_usage_days::day,
                rp_usage_days::operation,
            ))
            .do_update()
            .set((
                rp_usage_days::succeeded.eq(rp_usage_days::succeeded + succeeded),
                rp_usage_days::failed.eq(rp_usage_days::failed + failed),
            ))
            .execute(conn)
    }

    pub fn list_usage(
        conn: &mut PgConnection,
        account_id: &str,
        first: Date,
        last: Date,
    ) -> QueryResult<Vec<UsageDayRecord>> {
        rp_usage_days::table
            .filter(rp_usage_days::account_id.eq(uuid(account_id)?))
            .filter(rp_usage_days::day.ge(first))
            .filter(rp_usage_days::day.le(last))
            .order((rp_usage_days::day.asc(), rp_usage_days::operation.asc()))
            .select((
                rp_usage_days::day,
                rp_usage_days::operation,
                rp_usage_days::succeeded,
                rp_usage_days::failed,
            ))
            .load::<(Date, String, i64, i64)>(conn)
            .map(|rows| {
                rows.into_iter()
                    .map(|(day, operation, succeeded, failed)| UsageDayRecord {
                        day,
                        operation,
                        succeeded,
                        failed,
                    })
                    .collect()
            })
    }

    pub fn insert_login_nonce(
        conn: &mut PgConnection,
        account_id: &str,
        nonce_hash: &[u8],
        expires_at: OffsetDateTime,
    ) -> QueryResult<usize> {
        use crate::schema::pg::rp_login_nonces;
        diesel::insert_into(rp_login_nonces::table)
            .values((
                rp_login_nonces::account_id.eq(uuid(account_id)?),
                rp_login_nonces::nonce_hash.eq(nonce_hash),
                rp_login_nonces::expires_at.eq(expires_at),
            ))
            .on_conflict((rp_login_nonces::account_id, rp_login_nonces::nonce_hash))
            .do_update()
            .set(rp_login_nonces::expires_at.eq(expires_at))
            .execute(conn)
    }

    pub fn login_nonce_open(
        conn: &mut PgConnection,
        account_id: &str,
        nonce_hash: &[u8],
        now: OffsetDateTime,
    ) -> QueryResult<bool> {
        use crate::schema::pg::rp_login_nonces;
        diesel::select(diesel::dsl::exists(
            rp_login_nonces::table
                .filter(rp_login_nonces::account_id.eq(uuid(account_id)?))
                .filter(rp_login_nonces::nonce_hash.eq(nonce_hash))
                .filter(rp_login_nonces::expires_at.gt(now)),
        ))
        .get_result(conn)
    }

    pub fn consume_login_nonce(
        conn: &mut PgConnection,
        account_id: &str,
        nonce_hash: &[u8],
    ) -> QueryResult<usize> {
        use crate::schema::pg::rp_login_nonces;
        diesel::delete(
            rp_login_nonces::table
                .filter(rp_login_nonces::account_id.eq(uuid(account_id)?))
                .filter(rp_login_nonces::nonce_hash.eq(nonce_hash)),
        )
        .execute(conn)
    }

    pub fn prune_login_nonces(conn: &mut PgConnection, now: OffsetDateTime) -> QueryResult<usize> {
        use crate::schema::pg::rp_login_nonces;
        diesel::delete(rp_login_nonces::table.filter(rp_login_nonces::expires_at.le(now)))
            .execute(conn)
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use super::*;
    use crate::db::db_time::store;
    use crate::db::models::sqlite::{AuthCredentialRow, UserRow};
    use crate::schema::sqlite::{
        account_limits, application_users, auth_credentials, rp_usage_days, users,
    };
    use diesel::prelude::*;
    use diesel::SqliteConnection;

    fn day_text(day: Date) -> String {
        format!(
            "{:04}-{:02}-{:02}",
            day.year(),
            u8::from(day.month()),
            day.day()
        )
    }

    pub fn rename(conn: &mut SqliteConnection, user_id: &str, username: &str) -> QueryResult<User> {
        let n = diesel::update(users::table.find(user_id))
            .set(users::username.eq(username))
            .execute(conn)?;
        if n == 0 {
            return Err(diesel::result::Error::NotFound);
        }
        users::table
            .find(user_id)
            .first::<UserRow>(conn)
            .map(Into::into)
    }

    pub fn set_application_id(
        conn: &mut SqliteConnection,
        user_id: &str,
        application_id: &str,
    ) -> QueryResult<User> {
        let n = diesel::update(
            users::table
                .find(user_id)
                .filter(users::kind.eq("application")),
        )
        .set(users::application_id.eq(Some(application_id)))
        .execute(conn)?;
        if n == 0 {
            return Err(diesel::result::Error::NotFound);
        }
        users::table
            .find(user_id)
            .first::<UserRow>(conn)
            .map(Into::into)
    }

    pub fn list_api_keys(
        conn: &mut SqliteConnection,
        user_id: &str,
    ) -> QueryResult<Vec<AuthCredential>> {
        auth_credentials::table
            .filter(auth_credentials::user_id.eq(user_id))
            .filter(auth_credentials::credential_type.eq("api_key"))
            .filter(auth_credentials::revoked_at.is_null())
            .order((
                auth_credentials::created_at.asc(),
                auth_credentials::id.asc(),
            ))
            .load::<AuthCredentialRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn revoke_api_key(
        conn: &mut SqliteConnection,
        user_id: &str,
        key_id: &str,
        now: OffsetDateTime,
    ) -> QueryResult<usize> {
        let now = store(&now);
        diesel::update(
            auth_credentials::table
                .find(key_id)
                .filter(auth_credentials::user_id.eq(user_id))
                .filter(auth_credentials::credential_type.eq("api_key"))
                .filter(auth_credentials::revoked_at.is_null()),
        )
        .set((
            auth_credentials::revoked_at.eq(Some(&now)),
            auth_credentials::updated_at.eq(&now),
        ))
        .execute(conn)
    }

    /// SQLite text times do not compare as instants, so the resolution check
    /// reads the row first.
    pub fn touch_api_key(
        conn: &mut SqliteConnection,
        key_id: &str,
        now: OffsetDateTime,
    ) -> QueryResult<usize> {
        let last: Option<Option<String>> = auth_credentials::table
            .find(key_id)
            .select(auth_credentials::last_used_at)
            .first(conn)
            .optional()?;
        let Some(last) = last else {
            return Ok(0);
        };
        let recent = last
            .as_deref()
            .and_then(crate::db::db_time::parse)
            .is_some_and(|t| now - t < time::Duration::seconds(LAST_USED_RESOLUTION_SECONDS));
        if recent {
            return Ok(0);
        }
        diesel::update(auth_credentials::table.find(key_id))
            .set(auth_credentials::last_used_at.eq(Some(store(&now))))
            .execute(conn)
    }

    pub fn get_limits(
        conn: &mut SqliteConnection,
        user_id: &str,
    ) -> QueryResult<Option<AccountLimitsRecord>> {
        account_limits::table
            .find(user_id)
            .select((
                account_limits::max_api_keys,
                account_limits::max_distinct_users,
                account_limits::distinct_user_window_days,
                account_limits::requests_per_minute,
                account_limits::request_burst,
            ))
            .first::<(Option<i32>, Option<i32>, i32, Option<i32>, Option<i32>)>(conn)
            .optional()
            .map(|row| {
                row.map(|(a, b, c, d, e)| AccountLimitsRecord {
                    max_api_keys: a,
                    max_distinct_users: b,
                    distinct_user_window_days: c,
                    requests_per_minute: d,
                    request_burst: e,
                })
            })
    }

    pub fn set_limits(
        conn: &mut SqliteConnection,
        user_id: &str,
        limits: &AccountLimitsRecord,
    ) -> QueryResult<usize> {
        let now = store(&liblinkkeys::timestamp::now_whole_milliseconds());
        diesel::insert_into(account_limits::table)
            .values((
                account_limits::user_id.eq(user_id),
                account_limits::max_api_keys.eq(limits.max_api_keys),
                account_limits::max_distinct_users.eq(limits.max_distinct_users),
                account_limits::distinct_user_window_days.eq(limits.distinct_user_window_days),
                account_limits::requests_per_minute.eq(limits.requests_per_minute),
                account_limits::request_burst.eq(limits.request_burst),
                account_limits::updated_at.eq(&now),
            ))
            .on_conflict(account_limits::user_id)
            .do_update()
            .set((
                account_limits::max_api_keys.eq(limits.max_api_keys),
                account_limits::max_distinct_users.eq(limits.max_distinct_users),
                account_limits::distinct_user_window_days.eq(limits.distinct_user_window_days),
                account_limits::requests_per_minute.eq(limits.requests_per_minute),
                account_limits::request_burst.eq(limits.request_burst),
                account_limits::updated_at.eq(&now),
            ))
            .execute(conn)
    }

    /// `last_seen_at` is stored as whole-second `store()` text, which has one
    /// fixed width, so text order is time order and SQL can compare it.
    fn seen_text(t: OffsetDateTime) -> String {
        store(&liblinkkeys::timestamp::whole_seconds(t))
    }

    pub fn user_seen_since(
        conn: &mut SqliteConnection,
        account_id: &str,
        user_hash: &[u8],
        since: OffsetDateTime,
    ) -> QueryResult<bool> {
        diesel::select(diesel::dsl::exists(
            application_users::table
                .filter(application_users::account_id.eq(account_id))
                .filter(application_users::user_hash.eq(user_hash))
                .filter(application_users::last_seen_at.ge(seen_text(since))),
        ))
        .get_result(conn)
    }

    pub fn count_users_since(
        conn: &mut SqliteConnection,
        account_id: &str,
        since: OffsetDateTime,
    ) -> QueryResult<i64> {
        application_users::table
            .filter(application_users::account_id.eq(account_id))
            .filter(application_users::last_seen_at.ge(seen_text(since)))
            .count()
            .get_result(conn)
    }

    pub fn record_user(
        conn: &mut SqliteConnection,
        account_id: &str,
        user_hash: &[u8],
        now: OffsetDateTime,
    ) -> QueryResult<usize> {
        let now = seen_text(now);
        diesel::insert_into(application_users::table)
            .values((
                application_users::account_id.eq(account_id),
                application_users::user_hash.eq(user_hash),
                application_users::last_seen_at.eq(&now),
            ))
            .on_conflict((application_users::account_id, application_users::user_hash))
            .do_update()
            .set(application_users::last_seen_at.eq(&now))
            .execute(conn)
    }

    pub fn prune_users(conn: &mut SqliteConnection, before: OffsetDateTime) -> QueryResult<usize> {
        diesel::delete(
            application_users::table.filter(application_users::last_seen_at.lt(seen_text(before))),
        )
        .execute(conn)
    }

    pub fn add_usage(
        conn: &mut SqliteConnection,
        account_id: &str,
        day: Date,
        operation: &str,
        succeeded: i64,
        failed: i64,
    ) -> QueryResult<usize> {
        diesel::insert_into(rp_usage_days::table)
            .values((
                rp_usage_days::account_id.eq(account_id),
                rp_usage_days::day.eq(day_text(day)),
                rp_usage_days::operation.eq(operation),
                rp_usage_days::succeeded.eq(succeeded),
                rp_usage_days::failed.eq(failed),
            ))
            .on_conflict((
                rp_usage_days::account_id,
                rp_usage_days::day,
                rp_usage_days::operation,
            ))
            .do_update()
            .set((
                rp_usage_days::succeeded.eq(rp_usage_days::succeeded + succeeded),
                rp_usage_days::failed.eq(rp_usage_days::failed + failed),
            ))
            .execute(conn)
    }

    pub fn list_usage(
        conn: &mut SqliteConnection,
        account_id: &str,
        first: Date,
        last: Date,
    ) -> QueryResult<Vec<UsageDayRecord>> {
        // `YYYY-MM-DD` text orders as dates.
        rp_usage_days::table
            .filter(rp_usage_days::account_id.eq(account_id))
            .filter(rp_usage_days::day.ge(day_text(first)))
            .filter(rp_usage_days::day.le(day_text(last)))
            .order((rp_usage_days::day.asc(), rp_usage_days::operation.asc()))
            .select((
                rp_usage_days::day,
                rp_usage_days::operation,
                rp_usage_days::succeeded,
                rp_usage_days::failed,
            ))
            .load::<(String, String, i64, i64)>(conn)
            .map(|rows| {
                rows.into_iter()
                    .filter_map(|(day, operation, succeeded, failed)| {
                        Some(UsageDayRecord {
                            day: liblinkkeys::timestamp::parse_date_ymd(&day).ok()?,
                            operation,
                            succeeded,
                            failed,
                        })
                    })
                    .collect()
            })
    }

    pub fn insert_login_nonce(
        conn: &mut SqliteConnection,
        account_id: &str,
        nonce_hash: &[u8],
        expires_at: OffsetDateTime,
    ) -> QueryResult<usize> {
        use crate::schema::sqlite::rp_login_nonces;
        let expires = seen_text(expires_at);
        diesel::insert_into(rp_login_nonces::table)
            .values((
                rp_login_nonces::account_id.eq(account_id),
                rp_login_nonces::nonce_hash.eq(nonce_hash),
                rp_login_nonces::expires_at.eq(&expires),
            ))
            .on_conflict((rp_login_nonces::account_id, rp_login_nonces::nonce_hash))
            .do_update()
            .set(rp_login_nonces::expires_at.eq(&expires))
            .execute(conn)
    }

    pub fn login_nonce_open(
        conn: &mut SqliteConnection,
        account_id: &str,
        nonce_hash: &[u8],
        now: OffsetDateTime,
    ) -> QueryResult<bool> {
        use crate::schema::sqlite::rp_login_nonces;
        diesel::select(diesel::dsl::exists(
            rp_login_nonces::table
                .filter(rp_login_nonces::account_id.eq(account_id))
                .filter(rp_login_nonces::nonce_hash.eq(nonce_hash))
                .filter(rp_login_nonces::expires_at.gt(seen_text(now))),
        ))
        .get_result(conn)
    }

    pub fn consume_login_nonce(
        conn: &mut SqliteConnection,
        account_id: &str,
        nonce_hash: &[u8],
    ) -> QueryResult<usize> {
        use crate::schema::sqlite::rp_login_nonces;
        diesel::delete(
            rp_login_nonces::table
                .filter(rp_login_nonces::account_id.eq(account_id))
                .filter(rp_login_nonces::nonce_hash.eq(nonce_hash)),
        )
        .execute(conn)
    }

    pub fn prune_login_nonces(
        conn: &mut SqliteConnection,
        now: OffsetDateTime,
    ) -> QueryResult<usize> {
        use crate::schema::sqlite::rp_login_nonces;
        diesel::delete(
            rp_login_nonces::table.filter(rp_login_nonces::expires_at.le(seen_text(now))),
        )
        .execute(conn)
    }
}

macro_rules! dispatch {
    ($self:ident, $f:ident ( $($arg:expr),* )) => {
        match $self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => pg::$f(&mut *super::pg_conn(p)?, $($arg),*),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => sqlite::$f(&mut *super::sqlite_conn(p)?, $($arg),*),
        }
    };
}

impl DbPool {
    /// Change the username of an account. A taken username fails with a
    /// unique-violation error.
    pub fn rename_user(&self, user_id: &str, username: &str) -> QueryResult<User> {
        dispatch!(self, rename(user_id, username))
    }

    /// Set the application id of an application account. `NotFound` when the
    /// account does not exist or is not an application account.
    pub fn set_application_id(&self, user_id: &str, application_id: &str) -> QueryResult<User> {
        dispatch!(self, set_application_id(user_id, application_id))
    }

    /// The active API keys of an account, oldest first.
    pub fn list_api_keys(&self, user_id: &str) -> QueryResult<Vec<AuthCredential>> {
        dispatch!(self, list_api_keys(user_id))
    }

    /// Revoke one API key of an account. Returns rows updated (0: no such
    /// active key of this account).
    pub fn revoke_api_key(
        &self,
        user_id: &str,
        key_id: &str,
        now: OffsetDateTime,
    ) -> QueryResult<usize> {
        dispatch!(self, revoke_api_key(user_id, key_id, now))
    }

    /// Record that an API key authenticated, at most once per
    /// [`LAST_USED_RESOLUTION_SECONDS`].
    pub fn touch_api_key(&self, key_id: &str, now: OffsetDateTime) -> QueryResult<usize> {
        dispatch!(self, touch_api_key(key_id, now))
    }

    /// The limits of an account; the defaults when none are set.
    pub fn account_limits(&self, user_id: &str) -> QueryResult<AccountLimitsRecord> {
        Ok(dispatch!(self, get_limits(user_id))?.unwrap_or_default())
    }

    pub fn set_account_limits(
        &self,
        user_id: &str,
        limits: &AccountLimitsRecord,
    ) -> QueryResult<usize> {
        dispatch!(self, set_limits(user_id, limits))
    }

    /// Whether the user with `user_hash` used the application since `since`.
    pub fn application_user_seen_since(
        &self,
        account_id: &str,
        user_hash: &[u8],
        since: OffsetDateTime,
    ) -> QueryResult<bool> {
        dispatch!(self, user_seen_since(account_id, user_hash, since))
    }

    /// The number of distinct users of the application since `since`.
    pub fn count_application_users_since(
        &self,
        account_id: &str,
        since: OffsetDateTime,
    ) -> QueryResult<i64> {
        dispatch!(self, count_users_since(account_id, since))
    }

    pub fn record_application_user(
        &self,
        account_id: &str,
        user_hash: &[u8],
        now: OffsetDateTime,
    ) -> QueryResult<usize> {
        dispatch!(self, record_user(account_id, user_hash, now))
    }

    /// Remove users not seen since `before`.
    pub fn prune_application_users(&self, before: OffsetDateTime) -> QueryResult<usize> {
        dispatch!(self, prune_users(before))
    }

    pub fn add_rp_usage(
        &self,
        account_id: &str,
        day: Date,
        operation: &str,
        succeeded: i64,
        failed: i64,
    ) -> QueryResult<usize> {
        dispatch!(
            self,
            add_usage(account_id, day, operation, succeeded, failed)
        )
    }

    /// Record the nonce of a login an application account started.
    pub fn insert_rp_login_nonce(
        &self,
        account_id: &str,
        nonce_hash: &[u8],
        expires_at: OffsetDateTime,
    ) -> QueryResult<usize> {
        dispatch!(self, insert_login_nonce(account_id, nonce_hash, expires_at))
    }

    /// Whether the account started a login with this nonce that has not
    /// expired or been used.
    pub fn rp_login_nonce_open(
        &self,
        account_id: &str,
        nonce_hash: &[u8],
        now: OffsetDateTime,
    ) -> QueryResult<bool> {
        dispatch!(self, login_nonce_open(account_id, nonce_hash, now))
    }

    pub fn consume_rp_login_nonce(
        &self,
        account_id: &str,
        nonce_hash: &[u8],
    ) -> QueryResult<usize> {
        dispatch!(self, consume_login_nonce(account_id, nonce_hash))
    }

    pub fn prune_rp_login_nonces(&self, now: OffsetDateTime) -> QueryResult<usize> {
        dispatch!(self, prune_login_nonces(now))
    }

    pub fn list_rp_usage(
        &self,
        account_id: &str,
        first: Date,
        last: Date,
    ) -> QueryResult<Vec<UsageDayRecord>> {
        dispatch!(self, list_usage(account_id, first, last))
    }
}
