-- DNS-less local RP identity persistence. See the postgres migration for
-- semantics.

CREATE TABLE local_rp_domain_policy (
    domain TEXT PRIMARY KEY,
    policy TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TRIGGER set_local_rp_domain_policy_updated_at
    AFTER UPDATE ON local_rp_domain_policy
    FOR EACH ROW
    WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE local_rp_domain_policy SET updated_at = datetime('now') WHERE domain = NEW.domain;
END;

CREATE TABLE local_rps (
    fingerprint TEXT PRIMARY KEY,
    signing_public_key BLOB NOT NULL,
    encryption_public_key BLOB NOT NULL,
    app_name TEXT NOT NULL,
    local_domain_hint TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT,
    last_seen_at TEXT,
    admin_notes TEXT
);

CREATE TRIGGER set_local_rps_updated_at
    AFTER UPDATE ON local_rps
    FOR EACH ROW
    WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE local_rps SET updated_at = datetime('now') WHERE fingerprint = NEW.fingerprint;
END;

CREATE INDEX idx_local_rps_status ON local_rps(status);

CREATE TABLE local_rp_claim_tickets (
    ticket_hash TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL REFERENCES local_rps(fingerprint) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_domain TEXT NOT NULL,
    granted_claims TEXT NOT NULL,
    issued_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
);

CREATE INDEX idx_local_rp_claim_tickets_fingerprint ON local_rp_claim_tickets(fingerprint);
CREATE INDEX idx_local_rp_claim_tickets_expires_at ON local_rp_claim_tickets(expires_at);
