-- An admin can lock an account's password. A locked account cannot change its
-- own password or use password recovery. An admin can still reset it.
ALTER TABLE users ADD COLUMN password_locked BOOLEAN NOT NULL DEFAULT false;
