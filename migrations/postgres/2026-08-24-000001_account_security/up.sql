CREATE TABLE verified_contact_methods (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    channel VARCHAR NOT NULL,
    destination VARCHAR NOT NULL,
    purposes VARCHAR NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX verified_contact_methods_user_id_idx
    ON verified_contact_methods(user_id);

CREATE UNIQUE INDEX verified_contact_methods_active_destination_idx
    ON verified_contact_methods(channel, destination)
    WHERE revoked_at IS NULL;

CREATE TABLE account_challenges (
    id UUID PRIMARY KEY,
    token_digest VARCHAR NOT NULL UNIQUE,
    user_id UUID NOT NULL REFERENCES users(id),
    kind VARCHAR NOT NULL,
    channel VARCHAR NOT NULL,
    destination VARCHAR NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX account_challenges_user_kind_idx
    ON account_challenges(user_id, kind);

CREATE UNIQUE INDEX account_challenges_active_user_kind_idx
    ON account_challenges(user_id, kind)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

CREATE TABLE notification_outbox (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    purpose VARCHAR NOT NULL,
    channel VARCHAR NOT NULL,
    destination VARCHAR NOT NULL,
    encrypted_payload BYTEA,
    state VARCHAR NOT NULL DEFAULT 'pending',
    attempt_count BIGINT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL,
    lease_owner VARCHAR,
    lease_expires_at TIMESTAMPTZ,
    last_error VARCHAR,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX notification_outbox_ready_idx
    ON notification_outbox(state, next_attempt_at);

CREATE TABLE browser_sessions (
    token_digest VARCHAR PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    issued_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    authenticated_at TIMESTAMPTZ NOT NULL,
    authentication_methods VARCHAR NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX browser_sessions_user_id_idx ON browser_sessions(user_id);

WITH ranked_passwords AS (
    SELECT id,
           ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY created_at DESC, id DESC) AS rank
    FROM auth_credentials
    WHERE credential_type = 'password' AND revoked_at IS NULL
)
UPDATE auth_credentials AS credential
SET revoked_at = NOW(), updated_at = NOW()
FROM ranked_passwords
WHERE credential.id = ranked_passwords.id AND ranked_passwords.rank > 1;

CREATE UNIQUE INDEX auth_credentials_active_password_idx
    ON auth_credentials(user_id)
    WHERE credential_type = 'password' AND revoked_at IS NULL;
