-- Application accounts. See the postgres migration for semantics.
ALTER TABLE users ADD COLUMN kind TEXT NOT NULL DEFAULT 'human'
    CHECK (kind IN ('human', 'application'));
ALTER TABLE users ADD COLUMN application_id TEXT
    CHECK ((kind = 'application') = (application_id IS NOT NULL));

UPDATE users SET kind = 'application', application_id = username
WHERE purged_at IS NULL
  AND id IN (SELECT user_id FROM auth_credentials
             WHERE credential_type = 'api_key' AND revoked_at IS NULL)
  AND id NOT IN (SELECT user_id FROM auth_credentials
                 WHERE credential_type = 'password' AND revoked_at IS NULL);

ALTER TABLE auth_credentials ADD COLUMN name TEXT;
ALTER TABLE auth_credentials ADD COLUMN hint TEXT;
ALTER TABLE auth_credentials ADD COLUMN last_used_at TEXT;
UPDATE auth_credentials SET name = 'default' WHERE credential_type = 'api_key';

CREATE TABLE account_limits (
    user_id TEXT PRIMARY KEY REFERENCES users(id),
    max_api_keys INTEGER,
    max_distinct_users INTEGER,
    distinct_user_window_days INTEGER NOT NULL DEFAULT 30,
    requests_per_minute INTEGER,
    request_burst INTEGER,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE application_users (
    account_id TEXT NOT NULL REFERENCES users(id),
    user_hash BLOB NOT NULL,
    last_seen_at TEXT NOT NULL,
    PRIMARY KEY (account_id, user_hash)
);
CREATE INDEX idx_application_users_seen ON application_users (account_id, last_seen_at);

CREATE TABLE rp_usage_days (
    account_id TEXT NOT NULL REFERENCES users(id),
    day TEXT NOT NULL,
    operation TEXT NOT NULL,
    succeeded BIGINT NOT NULL DEFAULT 0,
    failed BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (account_id, day, operation)
);
