CREATE TABLE claim_signatures_new (
    id TEXT PRIMARY KEY,
    claim_id TEXT NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    signed_by_key_id TEXT NOT NULL,
    signature BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO claim_signatures_new
    (id, claim_id, domain, signed_by_key_id, signature, created_at)
SELECT id, claim_id, domain, signed_by_key_id, signature, created_at
FROM claim_signatures;

DROP TABLE claim_signatures;
ALTER TABLE claim_signatures_new RENAME TO claim_signatures;
CREATE INDEX idx_claim_signatures_claim_id ON claim_signatures(claim_id);

CREATE INDEX auth_credentials_active_hash_idx
ON auth_credentials(credential_type, credential_hash)
WHERE revoked_at IS NULL;

CREATE INDEX users_legacy_api_prefix_idx ON users(substr(id, 1, 8));
