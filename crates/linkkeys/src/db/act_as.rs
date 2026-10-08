//! Persistence for act-as grants (docs/spec/reserved/act-as-grants.md). One
//! row per grant series; the row id IS the protocol `grant_id`. Pure storage:
//! no signing, no verification, no policy.
//!
//! `signed_grant` holds the CURRENT `CBOR(SignedActAsGrant)` and is served
//! verbatim. A renewal replaces it. The other columns exist for lookups and
//! the user's grant list.

/// One stored grant series.
#[derive(Debug, Clone, PartialEq)]
pub struct ActAsGrantRecord {
    pub grant_id: String,
    pub user_id: String,
    pub grantee: GranteeColumns,
    pub audience_subject_user_id: String,
    pub audience_subject_domain: String,
    pub audience_application_id: String,
    pub approved_scope: Vec<String>,
    pub lifetime_seconds: i64,
    pub series_issued_at: String,
    pub renewable_until: String,
    pub signed_grant: Vec<u8>,
    pub issued_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
    pub signed_revocation: Option<Vec<u8>>,
}

/// The grantee, as the storage columns hold it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GranteeColumns {
    Application {
        subject_user_id: String,
        subject_domain: String,
        application_id: String,
    },
    LocalRp {
        fingerprint: String,
    },
}

const KIND_APPLICATION: &str = "application";
const KIND_LOCAL_RP: &str = "local_rp";

type GranteeTuple = (
    &'static str,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

impl GranteeColumns {
    fn to_columns(&self) -> GranteeTuple {
        match self {
            Self::Application {
                subject_user_id,
                subject_domain,
                application_id,
            } => (
                KIND_APPLICATION,
                Some(subject_user_id.clone()),
                Some(subject_domain.clone()),
                Some(application_id.clone()),
                None,
            ),
            Self::LocalRp { fingerprint } => {
                (KIND_LOCAL_RP, None, None, None, Some(fingerprint.clone()))
            }
        }
    }

    fn from_columns(
        kind: &str,
        subject_user_id: Option<String>,
        subject_domain: Option<String>,
        application_id: Option<String>,
        fingerprint: Option<String>,
    ) -> Self {
        // The table's CHECK constraint guarantees the shape for each kind.
        match (
            kind,
            subject_user_id,
            subject_domain,
            application_id,
            fingerprint,
        ) {
            (KIND_APPLICATION, Some(u), Some(d), Some(a), None) => Self::Application {
                subject_user_id: u,
                subject_domain: d,
                application_id: a,
            },
            (_, _, _, _, fingerprint) => Self::LocalRp {
                fingerprint: fingerprint.unwrap_or_default(),
            },
        }
    }
}

fn scope_to_json(scope: &[String]) -> String {
    serde_json::to_string(scope).expect("a list of strings always serializes")
}

fn scope_from_json(raw: &str) -> Vec<String> {
    serde_json::from_str(raw).unwrap_or_else(|e| {
        log::warn!("act_as_grants.approved_scope is not valid JSON ({e}); showing it as empty");
        Vec::new()
    })
}

#[cfg(feature = "postgres")]
pub mod pg {
    use super::{scope_from_json, scope_to_json, ActAsGrantRecord, GranteeColumns};
    use crate::schema::pg::act_as_grants;
    use chrono::{DateTime, Utc};
    use diesel::prelude::*;

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = act_as_grants)]
    struct Row {
        id: uuid::Uuid,
        user_id: uuid::Uuid,
        grantee_kind: String,
        grantee_subject_user_id: Option<String>,
        grantee_subject_domain: Option<String>,
        grantee_application_id: Option<String>,
        grantee_local_rp_fingerprint: Option<String>,
        audience_subject_user_id: String,
        audience_subject_domain: String,
        audience_application_id: String,
        approved_scope: String,
        lifetime_seconds: i64,
        series_issued_at: DateTime<Utc>,
        renewable_until: DateTime<Utc>,
        signed_grant: Vec<u8>,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        revoked_at: Option<DateTime<Utc>>,
        signed_revocation: Option<Vec<u8>>,
    }

    fn ts(t: DateTime<Utc>) -> String {
        liblinkkeys::act_as::format_time(t)
    }

    impl From<Row> for ActAsGrantRecord {
        fn from(r: Row) -> Self {
            Self {
                grant_id: r.id.to_string(),
                user_id: r.user_id.to_string(),
                grantee: GranteeColumns::from_columns(
                    &r.grantee_kind,
                    r.grantee_subject_user_id,
                    r.grantee_subject_domain,
                    r.grantee_application_id,
                    r.grantee_local_rp_fingerprint,
                ),
                audience_subject_user_id: r.audience_subject_user_id,
                audience_subject_domain: r.audience_subject_domain,
                audience_application_id: r.audience_application_id,
                approved_scope: scope_from_json(&r.approved_scope),
                lifetime_seconds: r.lifetime_seconds,
                series_issued_at: ts(r.series_issued_at),
                renewable_until: ts(r.renewable_until),
                signed_grant: r.signed_grant,
                issued_at: ts(r.issued_at),
                expires_at: ts(r.expires_at),
                revoked_at: r.revoked_at.map(ts),
                signed_revocation: r.signed_revocation,
            }
        }
    }

    fn uuid(s: &str) -> QueryResult<uuid::Uuid> {
        s.parse().map_err(|_| diesel::result::Error::NotFound)
    }

    fn time(s: &str) -> QueryResult<DateTime<Utc>> {
        DateTime::parse_from_rfc3339(s)
            .map(|t| t.with_timezone(&Utc))
            .map_err(|e| {
                diesel::result::Error::SerializationError(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e.to_string(),
                )))
            })
    }

    pub fn insert(conn: &mut PgConnection, r: &ActAsGrantRecord) -> QueryResult<usize> {
        let (kind, gu, gd, ga, gf) = r.grantee.to_columns();
        diesel::insert_into(act_as_grants::table)
            .values((
                act_as_grants::id.eq(uuid(&r.grant_id)?),
                act_as_grants::user_id.eq(uuid(&r.user_id)?),
                act_as_grants::grantee_kind.eq(kind),
                act_as_grants::grantee_subject_user_id.eq(gu),
                act_as_grants::grantee_subject_domain.eq(gd),
                act_as_grants::grantee_application_id.eq(ga),
                act_as_grants::grantee_local_rp_fingerprint.eq(gf),
                act_as_grants::audience_subject_user_id.eq(&r.audience_subject_user_id),
                act_as_grants::audience_subject_domain.eq(&r.audience_subject_domain),
                act_as_grants::audience_application_id.eq(&r.audience_application_id),
                act_as_grants::approved_scope.eq(scope_to_json(&r.approved_scope)),
                act_as_grants::lifetime_seconds.eq(r.lifetime_seconds),
                act_as_grants::series_issued_at.eq(time(&r.series_issued_at)?),
                act_as_grants::renewable_until.eq(time(&r.renewable_until)?),
                act_as_grants::signed_grant.eq(&r.signed_grant),
                act_as_grants::issued_at.eq(time(&r.issued_at)?),
                act_as_grants::expires_at.eq(time(&r.expires_at)?),
            ))
            .execute(conn)
    }

    pub fn find(conn: &mut PgConnection, grant_id: &str) -> QueryResult<Option<ActAsGrantRecord>> {
        let Ok(id) = grant_id.parse::<uuid::Uuid>() else {
            return Ok(None);
        };
        act_as_grants::table
            .find(id)
            .select(Row::as_select())
            .first(conn)
            .optional()
            .map(|r| r.map(Into::into))
    }

    pub fn list_for_user(
        conn: &mut PgConnection,
        user_id: &str,
    ) -> QueryResult<Vec<ActAsGrantRecord>> {
        act_as_grants::table
            .filter(act_as_grants::user_id.eq(uuid(user_id)?))
            .order(act_as_grants::series_issued_at.desc())
            .select(Row::as_select())
            .load(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    /// Replace the current grant bytes, only if the grant is not revoked and
    /// still has the expiry the caller read. Returns rows updated: 0 means a
    /// concurrent refresh or a revocation won.
    pub fn replace_current(
        conn: &mut PgConnection,
        grant_id: &str,
        signed_grant: &[u8],
        issued_at: &str,
        expires_at: &str,
        expected_expires_at: &str,
    ) -> QueryResult<usize> {
        diesel::update(
            act_as_grants::table
                .find(uuid(grant_id)?)
                .filter(act_as_grants::revoked_at.is_null())
                .filter(act_as_grants::expires_at.eq(time(expected_expires_at)?)),
        )
        .set((
            act_as_grants::signed_grant.eq(signed_grant),
            act_as_grants::issued_at.eq(time(issued_at)?),
            act_as_grants::expires_at.eq(time(expires_at)?),
        ))
        .execute(conn)
    }

    /// Revoke a series the user owns. Returns rows updated: 0 means the grant
    /// does not exist, belongs to another user, or is already revoked.
    pub fn revoke(
        conn: &mut PgConnection,
        grant_id: &str,
        user_id: &str,
        revoked_at: &str,
        signed_revocation: &[u8],
    ) -> QueryResult<usize> {
        let Ok(id) = grant_id.parse::<uuid::Uuid>() else {
            return Ok(0);
        };
        diesel::update(
            act_as_grants::table
                .find(id)
                .filter(act_as_grants::user_id.eq(uuid(user_id)?))
                .filter(act_as_grants::revoked_at.is_null()),
        )
        .set((
            act_as_grants::revoked_at.eq(Some(time(revoked_at)?)),
            act_as_grants::signed_revocation.eq(Some(signed_revocation)),
        ))
        .execute(conn)
    }

    /// The signed revocations among `grant_ids`. Unknown and unrevoked ids
    /// are absent from the result.
    pub fn revocations(conn: &mut PgConnection, grant_ids: &[String]) -> QueryResult<Vec<Vec<u8>>> {
        let ids: Vec<uuid::Uuid> = grant_ids.iter().filter_map(|i| i.parse().ok()).collect();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        act_as_grants::table
            .filter(act_as_grants::id.eq_any(ids))
            .filter(act_as_grants::signed_revocation.is_not_null())
            .select(act_as_grants::signed_revocation)
            .load::<Option<Vec<u8>>>(conn)
            .map(|rows| rows.into_iter().flatten().collect())
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use super::{scope_from_json, scope_to_json, ActAsGrantRecord, GranteeColumns};
    use crate::schema::sqlite::act_as_grants;
    use diesel::prelude::*;

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = act_as_grants)]
    struct Row {
        id: String,
        user_id: String,
        grantee_kind: String,
        grantee_subject_user_id: Option<String>,
        grantee_subject_domain: Option<String>,
        grantee_application_id: Option<String>,
        grantee_local_rp_fingerprint: Option<String>,
        audience_subject_user_id: String,
        audience_subject_domain: String,
        audience_application_id: String,
        approved_scope: String,
        lifetime_seconds: i64,
        series_issued_at: String,
        renewable_until: String,
        signed_grant: Vec<u8>,
        issued_at: String,
        expires_at: String,
        revoked_at: Option<String>,
        signed_revocation: Option<Vec<u8>>,
    }

    impl From<Row> for ActAsGrantRecord {
        fn from(r: Row) -> Self {
            Self {
                grant_id: r.id,
                user_id: r.user_id,
                grantee: GranteeColumns::from_columns(
                    &r.grantee_kind,
                    r.grantee_subject_user_id,
                    r.grantee_subject_domain,
                    r.grantee_application_id,
                    r.grantee_local_rp_fingerprint,
                ),
                audience_subject_user_id: r.audience_subject_user_id,
                audience_subject_domain: r.audience_subject_domain,
                audience_application_id: r.audience_application_id,
                approved_scope: scope_from_json(&r.approved_scope),
                lifetime_seconds: r.lifetime_seconds,
                series_issued_at: r.series_issued_at,
                renewable_until: r.renewable_until,
                signed_grant: r.signed_grant,
                issued_at: r.issued_at,
                expires_at: r.expires_at,
                revoked_at: r.revoked_at,
                signed_revocation: r.signed_revocation,
            }
        }
    }

    pub fn insert(conn: &mut SqliteConnection, r: &ActAsGrantRecord) -> QueryResult<usize> {
        let (kind, gu, gd, ga, gf) = r.grantee.to_columns();
        diesel::insert_into(act_as_grants::table)
            .values((
                act_as_grants::id.eq(&r.grant_id),
                act_as_grants::user_id.eq(&r.user_id),
                act_as_grants::grantee_kind.eq(kind),
                act_as_grants::grantee_subject_user_id.eq(gu),
                act_as_grants::grantee_subject_domain.eq(gd),
                act_as_grants::grantee_application_id.eq(ga),
                act_as_grants::grantee_local_rp_fingerprint.eq(gf),
                act_as_grants::audience_subject_user_id.eq(&r.audience_subject_user_id),
                act_as_grants::audience_subject_domain.eq(&r.audience_subject_domain),
                act_as_grants::audience_application_id.eq(&r.audience_application_id),
                act_as_grants::approved_scope.eq(scope_to_json(&r.approved_scope)),
                act_as_grants::lifetime_seconds.eq(r.lifetime_seconds),
                act_as_grants::series_issued_at.eq(&r.series_issued_at),
                act_as_grants::renewable_until.eq(&r.renewable_until),
                act_as_grants::signed_grant.eq(&r.signed_grant),
                act_as_grants::issued_at.eq(&r.issued_at),
                act_as_grants::expires_at.eq(&r.expires_at),
            ))
            .execute(conn)
    }

    pub fn find(
        conn: &mut SqliteConnection,
        grant_id: &str,
    ) -> QueryResult<Option<ActAsGrantRecord>> {
        act_as_grants::table
            .find(grant_id)
            .select(Row::as_select())
            .first(conn)
            .optional()
            .map(|r| r.map(Into::into))
    }

    pub fn list_for_user(
        conn: &mut SqliteConnection,
        user_id: &str,
    ) -> QueryResult<Vec<ActAsGrantRecord>> {
        act_as_grants::table
            .filter(act_as_grants::user_id.eq(user_id))
            .order(act_as_grants::series_issued_at.desc())
            .select(Row::as_select())
            .load(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn replace_current(
        conn: &mut SqliteConnection,
        grant_id: &str,
        signed_grant: &[u8],
        issued_at: &str,
        expires_at: &str,
        expected_expires_at: &str,
    ) -> QueryResult<usize> {
        diesel::update(
            act_as_grants::table
                .find(grant_id)
                .filter(act_as_grants::revoked_at.is_null())
                .filter(act_as_grants::expires_at.eq(expected_expires_at)),
        )
        .set((
            act_as_grants::signed_grant.eq(signed_grant),
            act_as_grants::issued_at.eq(issued_at),
            act_as_grants::expires_at.eq(expires_at),
        ))
        .execute(conn)
    }

    pub fn revoke(
        conn: &mut SqliteConnection,
        grant_id: &str,
        user_id: &str,
        revoked_at: &str,
        signed_revocation: &[u8],
    ) -> QueryResult<usize> {
        diesel::update(
            act_as_grants::table
                .find(grant_id)
                .filter(act_as_grants::user_id.eq(user_id))
                .filter(act_as_grants::revoked_at.is_null()),
        )
        .set((
            act_as_grants::revoked_at.eq(Some(revoked_at)),
            act_as_grants::signed_revocation.eq(Some(signed_revocation)),
        ))
        .execute(conn)
    }

    pub fn revocations(
        conn: &mut SqliteConnection,
        grant_ids: &[String],
    ) -> QueryResult<Vec<Vec<u8>>> {
        if grant_ids.is_empty() {
            return Ok(Vec::new());
        }
        act_as_grants::table
            .filter(act_as_grants::id.eq_any(grant_ids))
            .filter(act_as_grants::signed_revocation.is_not_null())
            .select(act_as_grants::signed_revocation)
            .load::<Option<Vec<u8>>>(conn)
            .map(|rows| rows.into_iter().flatten().collect())
    }
}

use super::{DbPool, QueryResult};

impl DbPool {
    pub fn insert_act_as_grant(&self, record: &ActAsGrantRecord) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => pg::insert(&mut *super::pg_conn(p)?, record),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => sqlite::insert(&mut *super::sqlite_conn(p)?, record),
        }
    }

    pub fn find_act_as_grant(&self, grant_id: &str) -> QueryResult<Option<ActAsGrantRecord>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => pg::find(&mut *super::pg_conn(p)?, grant_id),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => sqlite::find(&mut *super::sqlite_conn(p)?, grant_id),
        }
    }

    pub fn list_act_as_grants_for_user(&self, user_id: &str) -> QueryResult<Vec<ActAsGrantRecord>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => pg::list_for_user(&mut *super::pg_conn(p)?, user_id),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => sqlite::list_for_user(&mut *super::sqlite_conn(p)?, user_id),
        }
    }

    pub fn replace_current_act_as_grant(
        &self,
        grant_id: &str,
        signed_grant: &[u8],
        issued_at: &str,
        expires_at: &str,
        expected_expires_at: &str,
    ) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => pg::replace_current(
                &mut *super::pg_conn(p)?,
                grant_id,
                signed_grant,
                issued_at,
                expires_at,
                expected_expires_at,
            ),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => sqlite::replace_current(
                &mut *super::sqlite_conn(p)?,
                grant_id,
                signed_grant,
                issued_at,
                expires_at,
                expected_expires_at,
            ),
        }
    }

    pub fn revoke_act_as_grant(
        &self,
        grant_id: &str,
        user_id: &str,
        revoked_at: &str,
        signed_revocation: &[u8],
    ) -> QueryResult<usize> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => pg::revoke(
                &mut *super::pg_conn(p)?,
                grant_id,
                user_id,
                revoked_at,
                signed_revocation,
            ),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => sqlite::revoke(
                &mut *super::sqlite_conn(p)?,
                grant_id,
                user_id,
                revoked_at,
                signed_revocation,
            ),
        }
    }

    pub fn act_as_grant_revocations(&self, grant_ids: &[String]) -> QueryResult<Vec<Vec<u8>>> {
        match self {
            #[cfg(feature = "postgres")]
            DbPool::Postgres(p) => pg::revocations(&mut *super::pg_conn(p)?, grant_ids),
            #[cfg(feature = "sqlite")]
            DbPool::Sqlite(p) => sqlite::revocations(&mut *super::sqlite_conn(p)?, grant_ids),
        }
    }
}
