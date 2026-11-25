//! Timestamps read from SQLite text columns.
//!
//! SQLite has no timestamp type. A column holds the RFC 3339 text that the
//! server wrote, or `YYYY-MM-DD HH:MM:SS[.fff]` (UTC, no offset) from a
//! `DEFAULT (datetime('now'))`. Postgres columns are `timestamptz` and need
//! none of this.

use time::{OffsetDateTime, PrimitiveDateTime};

/// Parse a stored SQLite timestamp. Accepts RFC 3339 and SQLite's own
/// `datetime()` form, which is UTC.
pub fn parse(stored: &str) -> Option<OffsetDateTime> {
    if let Ok(t) = liblinkkeys::timestamp::parse_rfc3339(stored) {
        return Some(t);
    }
    let format = time::macros::format_description!(
        version = 2,
        "[year]-[month]-[day] [hour]:[minute]:[second][optional [.[subsecond]]]"
    );
    PrimitiveDateTime::parse(stored, &format)
        .ok()
        .map(PrimitiveDateTime::assume_utc)
}

/// [`parse`] for a row loader, which cannot fail. A value that does not parse
/// is not a timestamp this server wrote; it loads as the Unix epoch, so an
/// expiry or revocation time read from it fails closed (expired, revoked).
pub fn load(stored: &str) -> OffsetDateTime {
    parse(stored).unwrap_or_else(|| {
        log::error!("a stored SQLite timestamp is not readable; using the Unix epoch");
        OffsetDateTime::UNIX_EPOCH
    })
}

/// [`load`] for a nullable column.
pub fn load_opt(stored: Option<&str>) -> Option<OffsetDateTime> {
    stored.map(load)
}

/// The text to store in a SQLite timestamp column: RFC 3339 at millisecond
/// precision or coarser. A finer value is rounded down. Postgres columns are
/// `timestamptz(3)`, so neither backend sends a timestamp that the generated
/// TypeScript codec rejects.
pub fn store(t: &OffsetDateTime) -> String {
    use liblinkkeys::timestamp::Rfc3339 as _;
    liblinkkeys::timestamp::whole_milliseconds(*t).to_rfc3339()
}

/// [`store`] as a method, for SQLite query code.
pub trait DbText {
    /// The text to store in, or compare with, a SQLite timestamp column.
    fn to_db_text(&self) -> String;
}

impl DbText for OffsetDateTime {
    fn to_db_text(&self) -> String {
        store(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_both_stored_forms() {
        let rfc = parse("2026-11-22T10:00:00+00:00").unwrap();
        assert_eq!(parse("2026-11-22 10:00:00").unwrap(), rfc);
        assert_eq!(
            parse("2026-11-22 10:00:00.250").unwrap(),
            rfc + time::Duration::milliseconds(250)
        );
        assert_eq!(parse("not a time"), None);
        assert_eq!(load("not a time"), OffsetDateTime::UNIX_EPOCH);
        assert_eq!(parse(&store(&rfc)).unwrap(), rfc);
    }
}
