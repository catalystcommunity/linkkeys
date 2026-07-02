-- Generalize the claim approval queue into a domain-wide admin review queue and
-- add an append-only audit log. See the postgres migration for semantics.
CREATE TABLE admin_review_queue (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL DEFAULT 'claim_approval',
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    claim_type TEXT,
    claim_value BLOB,
    subject TEXT,
    detail TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    resolved_by TEXT,
    resolved_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO admin_review_queue
    (id, kind, user_id, claim_type, claim_value, status, resolved_by, resolved_at, created_at, updated_at)
SELECT id, 'claim_approval', user_id, claim_type, claim_value, status, resolved_by, resolved_at, created_at, updated_at
FROM claim_approval_queue;

DROP TABLE claim_approval_queue;

CREATE INDEX idx_admin_review_queue_status ON admin_review_queue(status);
CREATE INDEX idx_admin_review_queue_kind ON admin_review_queue(kind);

CREATE TRIGGER set_admin_review_queue_updated_at
    AFTER UPDATE ON admin_review_queue
    FOR EACH ROW
    WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE admin_review_queue SET updated_at = datetime('now') WHERE id = NEW.id;
END;

CREATE TABLE audit_log (
    id TEXT PRIMARY KEY,
    event TEXT NOT NULL,
    subject TEXT,
    actor TEXT,
    detail TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);
