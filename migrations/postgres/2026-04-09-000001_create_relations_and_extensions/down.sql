ALTER TABLE auth_credentials DROP COLUMN expires_at;
ALTER TABLE users DROP COLUMN is_active;
DROP TABLE relations;
