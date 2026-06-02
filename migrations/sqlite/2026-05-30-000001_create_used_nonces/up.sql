-- Durable single-use / replay-prevention store for auth nonces.
-- A nonce present here has been consumed; re-presenting it is a replay.
CREATE TABLE used_nonces (
    nonce TEXT PRIMARY KEY NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX idx_used_nonces_expires_at ON used_nonces(expires_at);
