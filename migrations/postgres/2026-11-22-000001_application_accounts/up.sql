-- Application accounts (request-app-management.md, "Application identity").
--
-- An account is a `human` or an `application`. An application account is the
-- identity of one application on a relying party: it authenticates with API
-- keys only, and its `application_id` is set by an administrator, never by
-- the application. `Rp/sign-request` names the account's own application.
ALTER TABLE users ADD COLUMN kind VARCHAR NOT NULL DEFAULT 'human';
ALTER TABLE users ADD COLUMN application_id VARCHAR;

-- An account that has an API key and no password was used as an application.
-- It becomes an application account named by its username, which is the id
-- that `Rp/sign-request` used by default, so its users keep their consent.
UPDATE users SET kind = 'application', application_id = username
WHERE purged_at IS NULL
  AND id IN (SELECT user_id FROM auth_credentials
             WHERE credential_type = 'api_key' AND revoked_at IS NULL)
  AND id NOT IN (SELECT user_id FROM auth_credentials
                 WHERE credential_type = 'password' AND revoked_at IS NULL);

ALTER TABLE users ADD CONSTRAINT users_kind_valid CHECK (kind IN ('human', 'application'));
ALTER TABLE users ADD CONSTRAINT users_application_id_iff_application
    CHECK ((kind = 'application') = (application_id IS NOT NULL));

-- Named API keys. `hint` is the last four characters of the secret.
ALTER TABLE auth_credentials ADD COLUMN name VARCHAR;
ALTER TABLE auth_credentials ADD COLUMN hint VARCHAR;
ALTER TABLE auth_credentials ADD COLUMN last_used_at TIMESTAMPTZ;
UPDATE auth_credentials SET name = 'default' WHERE credential_type = 'api_key';

-- Limits an administrator sets on one account. NULL means no limit.
CREATE TABLE account_limits (
    user_id UUID PRIMARY KEY REFERENCES users(id),
    max_api_keys INTEGER,
    max_distinct_users INTEGER,
    distinct_user_window_days INTEGER NOT NULL DEFAULT 30,
    requests_per_minute INTEGER,
    request_burst INTEGER,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT diesel_manage_updated_at('account_limits');

-- The users an application account served, as keyed hashes of the user
-- identity (never the identity itself), with the last time each was seen.
CREATE TABLE application_users (
    account_id UUID NOT NULL REFERENCES users(id),
    user_hash BYTEA NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (account_id, user_hash)
);
CREATE INDEX idx_application_users_seen ON application_users (account_id, last_seen_at);

-- Daily `Rp` operation counts for each account.
CREATE TABLE rp_usage_days (
    account_id UUID NOT NULL REFERENCES users(id),
    day DATE NOT NULL,
    operation VARCHAR NOT NULL,
    succeeded BIGINT NOT NULL DEFAULT 0,
    failed BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (account_id, day, operation)
);
