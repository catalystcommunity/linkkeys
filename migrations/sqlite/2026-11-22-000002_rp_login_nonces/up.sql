-- See the postgres migration. `expires_at` is whole-second store() text.
CREATE TABLE rp_login_nonces (
    account_id TEXT NOT NULL REFERENCES users(id),
    nonce_hash BLOB NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (account_id, nonce_hash)
);
CREATE INDEX idx_rp_login_nonces_expires ON rp_login_nonces (expires_at);
