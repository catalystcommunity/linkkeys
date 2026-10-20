-- An admin can lock an account's password. See the postgres migration.
ALTER TABLE users ADD COLUMN password_locked INTEGER NOT NULL DEFAULT 0 CHECK (password_locked IN (0, 1));
