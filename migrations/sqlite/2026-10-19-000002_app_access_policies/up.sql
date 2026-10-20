-- App access policies. See the postgres migration for semantics.
CREATE TABLE app_access_policies (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE,
    mode TEXT NOT NULL CHECK (mode IN ('allow', 'deny')),
    message TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TRIGGER set_app_access_policies_updated_at
    AFTER UPDATE ON app_access_policies
    FOR EACH ROW
    WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE app_access_policies SET updated_at = datetime('now') WHERE id = NEW.id;
END;

CREATE TABLE app_access_policy_patterns (
    policy_id TEXT NOT NULL REFERENCES app_access_policies(id) ON DELETE CASCADE,
    pattern TEXT NOT NULL,
    PRIMARY KEY (policy_id, pattern)
);

CREATE TABLE app_access_policy_targets (
    id TEXT PRIMARY KEY NOT NULL,
    policy_id TEXT NOT NULL REFERENCES app_access_policies(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    group_name TEXT,
    claim_type TEXT,
    claim_operator TEXT,
    claim_value TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    CHECK (
        (kind = 'everyone' AND user_id IS NULL AND group_name IS NULL
            AND claim_type IS NULL AND claim_operator IS NULL AND claim_value IS NULL)
        OR (kind = 'user' AND user_id IS NOT NULL AND group_name IS NULL
            AND claim_type IS NULL AND claim_operator IS NULL AND claim_value IS NULL)
        OR (kind = 'group' AND user_id IS NULL AND group_name IS NOT NULL
            AND claim_type IS NULL AND claim_operator IS NULL AND claim_value IS NULL)
        OR (kind = 'claim' AND user_id IS NULL AND group_name IS NULL
            AND claim_type IS NOT NULL
            AND claim_operator IN ('present', 'absent', 'equals', 'age_under', 'age_at_least'))
    )
);
CREATE INDEX app_access_policy_targets_policy_id_idx ON app_access_policy_targets(policy_id);
CREATE INDEX app_access_policy_targets_user_id_idx ON app_access_policy_targets(user_id);
