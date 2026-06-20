-- See the postgres migration for column semantics.
CREATE TABLE consent_grants (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subject_domain TEXT NOT NULL,
    audience TEXT NOT NULL,
    claim_types TEXT NOT NULL,
    requested_types TEXT NOT NULL,
    signed_grant BLOB NOT NULL,
    -- CBOR([DomainClaim]) the RP asserted about itself at consent time (the
    -- non-repudiable record of what it offered); NULL if it asserted nothing.
    offered_claims BLOB,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE UNIQUE INDEX idx_consent_grants_user_audience ON consent_grants(user_id, audience);

CREATE TRIGGER set_consent_grants_updated_at
    AFTER UPDATE ON consent_grants
    FOR EACH ROW
    WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE consent_grants SET updated_at = datetime('now') WHERE id = NEW.id;
END;
