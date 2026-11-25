-- Back to the default precision. The sub-millisecond part is not restored.
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
          AND c.datetime_precision = 3
    LOOP
        EXECUTE format('ALTER TABLE %I ALTER COLUMN %I TYPE timestamptz',
            col.table_name, col.column_name);
    END LOOP;
END
$$;
