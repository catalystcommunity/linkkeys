//! Every stored timestamp has millisecond precision or coarser.
//!
//! The generated TypeScript codec rejects a finer timestamp, because a
//! JavaScript `Date` holds milliseconds. Postgres keeps microseconds in a
//! plain `timestamptz` column, so each timestamp column must be
//! `timestamptz(3)`. SQLite text is written by `db_time::store`.

mod common;

use liblinkkeys::timestamp::parse_rfc3339;
use linkkeys::db::db_time;

#[test]
fn sqlite_text_is_stored_at_millisecond_precision() {
    let t = parse_rfc3339("2026-04-08T01:51:13.616455789+00:00").unwrap();
    assert_eq!(db_time::store(&t), "2026-04-08T01:51:13.616+00:00");
    let whole = parse_rfc3339("2026-04-08T01:51:13.000455+00:00").unwrap();
    assert_eq!(db_time::store(&whole), "2026-04-08T01:51:13+00:00");
}

#[cfg(feature = "postgres")]
#[test]
fn every_postgres_timestamp_column_has_millisecond_precision() {
    use diesel::prelude::*;
    use diesel::sql_types::Text;

    #[derive(QueryableByName)]
    struct Column {
        #[diesel(sql_type = Text)]
        name: String,
    }

    let linkkeys::db::DbPool::Postgres(pool) = common::create_test_pool() else {
        return;
    };
    let mut conn = pool.get().unwrap();
    let finer: Vec<Column> = diesel::sql_query(
        "SELECT c.table_name || '.' || c.column_name AS name
         FROM information_schema.columns c
         JOIN information_schema.tables t
           ON t.table_schema = c.table_schema AND t.table_name = c.table_name
         WHERE c.table_schema = current_schema()
           AND t.table_type = 'BASE TABLE'
           AND c.table_name <> '__diesel_schema_migrations'
           AND c.data_type LIKE 'timestamp%'
           AND (c.data_type <> 'timestamp with time zone' OR c.datetime_precision <> 3)
         ORDER BY 1",
    )
    .load(&mut conn)
    .unwrap();
    let names: Vec<&str> = finer.iter().map(|c| c.name.as_str()).collect();
    assert!(
        names.is_empty(),
        "these timestamp columns are not timestamptz(3); add a migration: {names:?}"
    );
}
