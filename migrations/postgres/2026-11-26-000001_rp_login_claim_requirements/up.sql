-- The claims that a login started with `Rp/sign-request` requires a verifier
-- to verify (`RequestedClaim.verified_by`). `Rp/userinfo-fetch` reads the row
-- by the login nonce, enforces it, and removes it. `decrypt-token` removes
-- the nonce itself, so this is a separate table. Each list is a JSON array of
-- claim types.
CREATE TABLE rp_login_claim_requirements (
    account_id UUID NOT NULL REFERENCES users(id),
    nonce_hash BYTEA NOT NULL,
    required_types TEXT NOT NULL,
    optional_types TEXT NOT NULL,
    expires_at TIMESTAMPTZ(3) NOT NULL,
    PRIMARY KEY (account_id, nonce_hash)
);
CREATE INDEX idx_rp_login_claim_requirements_expires
    ON rp_login_claim_requirements (expires_at);
