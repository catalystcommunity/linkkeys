-- See the postgres migration for semantics. The 256-bit backup key is stored
-- encrypted at rest with DOMAIN_KEY_PASSPHRASE; a single active row has
-- rotated_at NULL.
CREATE TABLE backup_keys (
    id TEXT PRIMARY KEY,
    key_encrypted BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    rotated_at TEXT
);
