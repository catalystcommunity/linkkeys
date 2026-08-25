CREATE TABLE verified_contact_methods (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id),
    channel TEXT NOT NULL,
    destination TEXT NOT NULL,
    purposes TEXT NOT NULL,
    verified_at TEXT NOT NULL,
    revoked_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX verified_contact_methods_user_id_idx
    ON verified_contact_methods(user_id);

CREATE UNIQUE INDEX verified_contact_methods_active_destination_idx
    ON verified_contact_methods(channel, destination)
    WHERE revoked_at IS NULL;

CREATE TABLE account_challenges (
    id TEXT PRIMARY KEY NOT NULL,
    token_digest TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL REFERENCES users(id),
    kind TEXT NOT NULL,
    channel TEXT NOT NULL,
    destination TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    revoked_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX account_challenges_user_kind_idx
    ON account_challenges(user_id, kind);

CREATE UNIQUE INDEX account_challenges_active_user_kind_idx
    ON account_challenges(user_id, kind)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

CREATE TABLE notification_outbox (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id),
    purpose TEXT NOT NULL,
    channel TEXT NOT NULL,
    destination TEXT NOT NULL,
    encrypted_payload BLOB,
    state TEXT NOT NULL DEFAULT 'pending',
    attempt_count BIGINT NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    lease_owner TEXT,
    lease_expires_at TEXT,
    last_error TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX notification_outbox_ready_idx
    ON notification_outbox(state, next_attempt_at);

CREATE TABLE browser_sessions (
    token_digest TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id),
    issued_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    authenticated_at TEXT NOT NULL,
    authentication_methods TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX browser_sessions_user_id_idx ON browser_sessions(user_id);

UPDATE auth_credentials
SET revoked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
WHERE id IN (
    SELECT id FROM (
        SELECT id,
               ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY created_at DESC, id DESC) AS rank
        FROM auth_credentials
        WHERE credential_type = 'password' AND revoked_at IS NULL
    ) AS ranked_passwords
    WHERE rank > 1
);

CREATE UNIQUE INDEX auth_credentials_active_password_idx
    ON auth_credentials(user_id)
    WHERE credential_type = 'password' AND revoked_at IS NULL;
