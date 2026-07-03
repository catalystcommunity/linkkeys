-- SEC-08: sibling-signed key-revocation certificates this domain has ISSUED.
-- See the postgres migration for semantics.
CREATE TABLE issued_revocations (
    id TEXT PRIMARY KEY,
    target_key_id TEXT NOT NULL,
    target_fingerprint TEXT NOT NULL,
    revoked_at TEXT NOT NULL,
    cert BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_issued_revocations_revoked_at ON issued_revocations(revoked_at);
CREATE UNIQUE INDEX idx_issued_revocations_target ON issued_revocations(target_key_id);
