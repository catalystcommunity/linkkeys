-- Reverse: restore claim_approval_queue from the claim-approval rows and drop
-- the generalized tables. Non-claim review items are discarded on downgrade.
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

INSERT INTO claim_approval_queue
    (id, user_id, claim_type, claim_value, status, resolved_by, resolved_at, created_at, updated_at)
SELECT id, user_id, claim_type, claim_value, status, resolved_by, resolved_at, created_at, updated_at
FROM admin_review_queue
WHERE kind = 'claim_approval' AND user_id IS NOT NULL AND claim_type IS NOT NULL AND claim_value IS NOT NULL;

DROP TABLE admin_review_queue;
DROP TABLE audit_log;
