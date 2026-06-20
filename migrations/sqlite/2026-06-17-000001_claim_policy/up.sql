-- See the postgres migration for semantics.

CREATE TABLE claim_type_policies (
    claim_type TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    value_type TEXT NOT NULL,
    max_bytes BIGINT NOT NULL DEFAULT 33792,
    set_rule TEXT NOT NULL,
    signing_rule TEXT NOT NULL,
    requires_approval INTEGER NOT NULL DEFAULT 0,
    user_settable INTEGER NOT NULL DEFAULT 0,
    default_auto_sign INTEGER NOT NULL DEFAULT 0,
    suggested INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TRIGGER set_claim_type_policies_updated_at
    AFTER UPDATE ON claim_type_policies
    FOR EACH ROW
    WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE claim_type_policies SET updated_at = datetime('now') WHERE claim_type = NEW.claim_type;
END;

CREATE TABLE trusted_issuers (
    claim_type TEXT NOT NULL,
    issuer_domain TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (claim_type, issuer_domain)
);

CREATE TABLE profile_claim_prefs (
    profile_id TEXT NOT NULL,
    claim_type TEXT NOT NULL,
    auto_sign INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (profile_id, claim_type)
);

CREATE TRIGGER set_profile_claim_prefs_updated_at
    AFTER UPDATE ON profile_claim_prefs
    FOR EACH ROW
    WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE profile_claim_prefs SET updated_at = datetime('now')
        WHERE profile_id = NEW.profile_id AND claim_type = NEW.claim_type;
END;

CREATE TABLE release_policies (
    audience TEXT NOT NULL,
    claim_type TEXT NOT NULL,
    disposition TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (audience, claim_type)
);

CREATE TRIGGER set_release_policies_updated_at
    AFTER UPDATE ON release_policies
    FOR EACH ROW
    WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE release_policies SET updated_at = datetime('now')
        WHERE audience = NEW.audience AND claim_type = NEW.claim_type;
END;

CREATE TABLE claim_approval_queue (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    claim_type TEXT NOT NULL,
    claim_value BLOB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    resolved_by TEXT,
    resolved_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_claim_approval_queue_status ON claim_approval_queue(status);

CREATE TRIGGER set_claim_approval_queue_updated_at
    AFTER UPDATE ON claim_approval_queue
    FOR EACH ROW
    WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE claim_approval_queue SET updated_at = datetime('now') WHERE id = NEW.id;
END;

-- See the postgres migration for semantics.
CREATE TABLE email_verifications (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_email_verifications_user ON email_verifications(user_id);

CREATE TABLE user_release_prefs (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    audience TEXT NOT NULL,
    claim_type TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user_id, audience, claim_type)
);

CREATE INDEX idx_user_release_prefs_user ON user_release_prefs(user_id);
