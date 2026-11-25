DROP TABLE rp_usage_days;
DROP TABLE application_users;
DROP TABLE account_limits;
ALTER TABLE auth_credentials DROP COLUMN last_used_at;
ALTER TABLE auth_credentials DROP COLUMN hint;
ALTER TABLE auth_credentials DROP COLUMN name;
ALTER TABLE users DROP COLUMN application_id;
ALTER TABLE users DROP COLUMN kind;
