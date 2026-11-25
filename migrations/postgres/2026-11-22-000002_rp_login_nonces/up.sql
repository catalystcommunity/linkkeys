-- The nonces of logins an application account started with `Rp/sign-request`.
-- `Rp/decrypt-token` admits a user only for an assertion that carries one of
-- these nonces, and removes it then. Only the SHA-256 of the nonce is kept.
CREATE TABLE rp_login_nonces (
    account_id UUID NOT NULL REFERENCES users(id),
    nonce_hash BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (account_id, nonce_hash)
);
CREATE INDEX idx_rp_login_nonces_expires ON rp_login_nonces (expires_at);
