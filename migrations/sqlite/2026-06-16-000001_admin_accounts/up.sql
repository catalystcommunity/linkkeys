-- See the postgres migration for semantics.
ALTER TABLE users ADD COLUMN is_admin_account INTEGER NOT NULL DEFAULT 0;
