//! Persistence for TOFU domain-fingerprint pins (SEC-01). Stores the sorted,
//! comma-joined `fp=` set first seen for each peer domain so later fetches can
//! detect an unexpected change. Pure storage; the compare/rotate/alarm policy
//! lives in `crate::services::pins`.

#[cfg(feature = "postgres")]
pub mod pg {
    use diesel::prelude::*;

    use crate::db::models::pg::{DomainKeyPinRow, NewDomainKeyPinRow};
    use crate::db::models::DomainKeyPin;
    use crate::schema::pg::domain_key_pins;

    pub fn find(
        conn: &mut diesel::PgConnection,
        domain: &str,
    ) -> QueryResult<Option<DomainKeyPin>> {
        domain_key_pins::table
            .find(domain)
            .select(DomainKeyPinRow::as_select())
            .first::<DomainKeyPinRow>(conn)
            .optional()
            .map(|o| o.map(Into::into))
    }

    /// Create the first-seen pin. Returns rows inserted (0 = already pinned).
    pub fn create(
        conn: &mut diesel::PgConnection,
        domain: &str,
        fingerprints: &str,
    ) -> QueryResult<usize> {
        diesel::insert_into(domain_key_pins::table)
            .values(NewDomainKeyPinRow {
                domain: domain.to_string(),
                fingerprints: fingerprints.to_string(),
            })
            .on_conflict_do_nothing()
            .execute(conn)
    }

    /// Re-pin to a new fingerprint set (accepted rotation) and stamp the check.
    pub fn rotate(
        conn: &mut diesel::PgConnection,
        domain: &str,
        fingerprints: &str,
    ) -> QueryResult<usize> {
        let now = chrono::Utc::now();
        diesel::update(domain_key_pins::table.find(domain))
            .set((
                domain_key_pins::fingerprints.eq(fingerprints),
                domain_key_pins::last_checked_at.eq(now),
            ))
            .execute(conn)
    }

    /// Record that the pin was verified unchanged at this instant.
    pub fn touch(conn: &mut diesel::PgConnection, domain: &str) -> QueryResult<usize> {
        diesel::update(domain_key_pins::table.find(domain))
            .set(domain_key_pins::last_checked_at.eq(chrono::Utc::now()))
            .execute(conn)
    }

    pub fn list_all(conn: &mut diesel::PgConnection) -> QueryResult<Vec<DomainKeyPin>> {
        domain_key_pins::table
            .order(domain_key_pins::domain.asc())
            .select(DomainKeyPinRow::as_select())
            .load::<DomainKeyPinRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use diesel::prelude::*;

    use crate::db::models::sqlite::{DomainKeyPinRow, NewDomainKeyPinRow};
    use crate::db::models::DomainKeyPin;
    use crate::schema::sqlite::domain_key_pins;

    pub fn find(
        conn: &mut diesel::SqliteConnection,
        domain: &str,
    ) -> QueryResult<Option<DomainKeyPin>> {
        domain_key_pins::table
            .find(domain)
            .select(DomainKeyPinRow::as_select())
            .first::<DomainKeyPinRow>(conn)
            .optional()
            .map(|o| o.map(Into::into))
    }

    pub fn create(
        conn: &mut diesel::SqliteConnection,
        domain: &str,
        fingerprints: &str,
    ) -> QueryResult<usize> {
        diesel::insert_into(domain_key_pins::table)
            .values(NewDomainKeyPinRow {
                domain: domain.to_string(),
                fingerprints: fingerprints.to_string(),
            })
            .on_conflict_do_nothing()
            .execute(conn)
    }

    pub fn rotate(
        conn: &mut diesel::SqliteConnection,
        domain: &str,
        fingerprints: &str,
    ) -> QueryResult<usize> {
        let now = chrono::Utc::now().to_rfc3339();
        diesel::update(domain_key_pins::table.find(domain))
            .set((
                domain_key_pins::fingerprints.eq(fingerprints),
                domain_key_pins::last_checked_at.eq(now),
            ))
            .execute(conn)
    }

    pub fn touch(conn: &mut diesel::SqliteConnection, domain: &str) -> QueryResult<usize> {
        diesel::update(domain_key_pins::table.find(domain))
            .set(domain_key_pins::last_checked_at.eq(chrono::Utc::now().to_rfc3339()))
            .execute(conn)
    }

    pub fn list_all(conn: &mut diesel::SqliteConnection) -> QueryResult<Vec<DomainKeyPin>> {
        domain_key_pins::table
            .order(domain_key_pins::domain.asc())
            .select(DomainKeyPinRow::as_select())
            .load::<DomainKeyPinRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }
}
