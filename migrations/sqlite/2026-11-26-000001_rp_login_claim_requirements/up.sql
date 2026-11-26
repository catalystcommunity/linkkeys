-- See the postgres migration. `expires_at` is store() text.
CREATE TABLE rp_login_claim_requirements (
    account_id TEXT NOT NULL REFERENCES users(id),
    nonce_hash BLOB NOT NULL,
    required_types TEXT NOT NULL,
    optional_types TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (account_id, nonce_hash)
);
CREATE INDEX idx_rp_login_claim_requirements_expires
    ON rp_login_claim_requirements (expires_at);
