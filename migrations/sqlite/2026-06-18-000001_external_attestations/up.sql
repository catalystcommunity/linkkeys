-- See the postgres migration. SQLite already stores signed_by_key_id as TEXT and
-- does not enforce the foreign key, so only the peer-key cache is created here.
CREATE TABLE peer_keys (
    domain TEXT NOT NULL,
    key_id TEXT NOT NULL,
    public_key BLOB NOT NULL,
    algorithm TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    key_usage TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (domain, key_id)
);
