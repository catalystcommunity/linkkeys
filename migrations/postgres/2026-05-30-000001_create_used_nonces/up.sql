-- Durable single-use / replay-prevention store for auth nonces.
-- A nonce present here has been consumed; re-presenting it is a replay.
CREATE TABLE used_nonces (
    nonce VARCHAR PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_used_nonces_expires_at ON used_nonces(expires_at);
