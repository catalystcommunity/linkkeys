DROP INDEX users_legacy_api_prefix_idx;
DROP INDEX auth_credentials_active_hash_idx;

CREATE TABLE claim_signatures_old (
    id TEXT PRIMARY KEY,
    claim_id TEXT NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    signed_by_key_id TEXT NOT NULL REFERENCES domain_keys(id),
    signature BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO claim_signatures_old
    (id, claim_id, domain, signed_by_key_id, signature, created_at)
SELECT id, claim_id, domain, signed_by_key_id, signature, created_at
FROM claim_signatures;

DROP TABLE claim_signatures;
ALTER TABLE claim_signatures_old RENAME TO claim_signatures;
CREATE INDEX idx_claim_signatures_claim_id ON claim_signatures(claim_id);
