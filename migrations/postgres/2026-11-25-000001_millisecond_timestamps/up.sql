-- Store every timestamp at millisecond precision.
--
-- A JavaScript `Date` holds milliseconds, and the generated TypeScript codec
-- rejects a finer timestamp. Postgres kept microseconds, so the web UI could
-- not decode a reply that carried a stored time (for example the session and
-- account times after sign-in). A `timestamptz(3)` column rounds each write,
-- so a later write cannot bring microseconds back.
--
-- The loop covers every timestamptz column of every table in this schema. A
-- test checks that new columns also use precision 3.
DO $$
DECLARE
    col record;
BEGIN
    FOR col IN
        SELECT c.table_name, c.column_name
        FROM information_schema.columns c
        JOIN information_schema.tables t
          ON t.table_schema = c.table_schema AND t.table_name = c.table_name
        WHERE c.table_schema = current_schema()
          AND t.table_type = 'BASE TABLE'
          AND c.table_name <> '__diesel_schema_migrations'
          AND c.data_type = 'timestamp with time zone'
          AND c.datetime_precision > 3
        ORDER BY c.table_name, c.column_name
    LOOP
        EXECUTE format(
            'ALTER TABLE %I ALTER COLUMN %I TYPE timestamptz(3) USING date_trunc(''milliseconds'', %I)',
            col.table_name, col.column_name, col.column_name);
    END LOOP;
END
$$;
