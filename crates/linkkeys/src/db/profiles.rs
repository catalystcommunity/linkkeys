//! Persistence for profiles (the pseudonymous identities a human account
//! presents). One root profile per account (the never-leaked anchor) plus the
//! presentable personas.

#[cfg(feature = "postgres")]
pub mod pg {
    use diesel::prelude::*;

    use crate::db::models::pg::{NewProfileRow, ProfileRow};
    use crate::db::models::Profile;
    use crate::schema::pg::profiles;

    pub fn create(
        conn: &mut diesel::PgConnection,
        id: uuid::Uuid,
        account_id: uuid::Uuid,
        domain: &str,
        is_root: bool,
        label: Option<&str>,
    ) -> QueryResult<Profile> {
        let row = NewProfileRow {
            id,
            account_id,
            domain: domain.to_string(),
            is_root,
            label: label.map(|s| s.to_string()),
        };
        diesel::insert_into(profiles::table)
            .values(&row)
            .execute(conn)?;
        find(conn, id)
    }

    pub fn find(conn: &mut diesel::PgConnection, id: uuid::Uuid) -> QueryResult<Profile> {
        profiles::table
            .find(id)
            .select(ProfileRow::as_select())
            .first::<ProfileRow>(conn)
            .map(Into::into)
    }

    pub fn list_for_account(
        conn: &mut diesel::PgConnection,
        account_id: uuid::Uuid,
    ) -> QueryResult<Vec<Profile>> {
        profiles::table
            .filter(profiles::account_id.eq(account_id))
            .order(profiles::created_at.asc())
            .select(ProfileRow::as_select())
            .load::<ProfileRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn count_for_account(
        conn: &mut diesel::PgConnection,
        account_id: uuid::Uuid,
    ) -> QueryResult<i64> {
        profiles::table
            .filter(profiles::account_id.eq(account_id))
            .count()
            .get_result(conn)
    }

    /// Count only presentable (non-root) profiles — what the per-account limit
    /// caps (the root anchor is always exactly one and not user-creatable).
    pub fn count_presentable_for_account(
        conn: &mut diesel::PgConnection,
        account_id: uuid::Uuid,
    ) -> QueryResult<i64> {
        profiles::table
            .filter(profiles::account_id.eq(account_id))
            .filter(profiles::is_root.eq(false))
            .count()
            .get_result(conn)
    }

    /// The presentable (non-root) profiles for an account, oldest first.
    pub fn list_presentable_for_account(
        conn: &mut diesel::PgConnection,
        account_id: uuid::Uuid,
    ) -> QueryResult<Vec<Profile>> {
        profiles::table
            .filter(profiles::account_id.eq(account_id))
            .filter(profiles::is_root.eq(false))
            // id tiebreaker: stable selection when created_at collides (SQLite
            // timestamps are second-resolution).
            .order((profiles::created_at.asc(), profiles::id.asc()))
            .select(ProfileRow::as_select())
            .load::<ProfileRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    /// Provision a default presentable profile (id reuses the account id) + a
    /// fresh root anchor for every account that has no profiles yet. Idempotent;
    /// returns how many accounts were backfilled.
    pub fn backfill(conn: &mut diesel::PgConnection, domain: &str) -> QueryResult<usize> {
        use crate::schema::pg::users;
        let user_ids: Vec<uuid::Uuid> = users::table.select(users::id).load(conn)?;
        let existing: Vec<uuid::Uuid> = profiles::table.select(profiles::account_id).load(conn)?;
        let have: std::collections::HashSet<uuid::Uuid> = existing.into_iter().collect();
        let mut count = 0;
        for uid in user_ids {
            if have.contains(&uid) {
                continue;
            }
            // Per-account atomic provisioning. If a concurrent backfiller on
            // another node won the race, our insert hits the PK and rolls back —
            // skip and continue rather than aborting the whole pass.
            if let Err(e) = conn.transaction::<(), diesel::result::Error, _>(|conn| {
                create(conn, uid, uid, domain, false, None)?;
                create(conn, uuid::Uuid::now_v7(), uid, domain, true, Some("root"))?;
                Ok(())
            }) {
                log::warn!("profile backfill skipped account {}: {}", uid, e);
                continue;
            }
            count += 1;
        }
        Ok(count)
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use diesel::prelude::*;

    use crate::db::models::sqlite::{NewProfileRow, ProfileRow};
    use crate::db::models::Profile;
    use crate::schema::sqlite::profiles;

    pub fn create(
        conn: &mut diesel::SqliteConnection,
        id: &str,
        account_id: &str,
        domain: &str,
        is_root: bool,
        label: Option<&str>,
    ) -> QueryResult<Profile> {
        let row = NewProfileRow {
            id: id.to_string(),
            account_id: account_id.to_string(),
            domain: domain.to_string(),
            is_root: i32::from(is_root),
            label: label.map(|s| s.to_string()),
        };
        diesel::insert_into(profiles::table)
            .values(&row)
            .execute(conn)?;
        find(conn, id)
    }

    pub fn find(conn: &mut diesel::SqliteConnection, id: &str) -> QueryResult<Profile> {
        profiles::table
            .find(id)
            .select(ProfileRow::as_select())
            .first::<ProfileRow>(conn)
            .map(Into::into)
    }

    pub fn list_for_account(
        conn: &mut diesel::SqliteConnection,
        account_id: &str,
    ) -> QueryResult<Vec<Profile>> {
        profiles::table
            .filter(profiles::account_id.eq(account_id))
            .order(profiles::created_at.asc())
            .select(ProfileRow::as_select())
            .load::<ProfileRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn count_for_account(
        conn: &mut diesel::SqliteConnection,
        account_id: &str,
    ) -> QueryResult<i64> {
        profiles::table
            .filter(profiles::account_id.eq(account_id))
            .count()
            .get_result(conn)
    }

    pub fn count_presentable_for_account(
        conn: &mut diesel::SqliteConnection,
        account_id: &str,
    ) -> QueryResult<i64> {
        profiles::table
            .filter(profiles::account_id.eq(account_id))
            .filter(profiles::is_root.eq(0))
            .count()
            .get_result(conn)
    }

    pub fn list_presentable_for_account(
        conn: &mut diesel::SqliteConnection,
        account_id: &str,
    ) -> QueryResult<Vec<Profile>> {
        profiles::table
            .filter(profiles::account_id.eq(account_id))
            .filter(profiles::is_root.eq(0))
            .order((profiles::created_at.asc(), profiles::id.asc()))
            .select(ProfileRow::as_select())
            .load::<ProfileRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn backfill(conn: &mut diesel::SqliteConnection, domain: &str) -> QueryResult<usize> {
        use crate::schema::sqlite::users;
        let user_ids: Vec<String> = users::table.select(users::id).load(conn)?;
        let existing: Vec<String> = profiles::table.select(profiles::account_id).load(conn)?;
        let have: std::collections::HashSet<String> = existing.into_iter().collect();
        let mut count = 0;
        for uid in user_ids {
            if have.contains(&uid) {
                continue;
            }
            if let Err(e) = conn.transaction::<(), diesel::result::Error, _>(|conn| {
                create(conn, &uid, &uid, domain, false, None)?;
                create(
                    conn,
                    &uuid::Uuid::now_v7().to_string(),
                    &uid,
                    domain,
                    true,
                    Some("root"),
                )?;
                Ok(())
            }) {
                log::warn!("profile backfill skipped account {}: {}", uid, e);
                continue;
            }
            count += 1;
        }
        Ok(count)
    }
}
