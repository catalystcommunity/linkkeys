-- Support claims signed by EXTERNAL issuer domains (attested / lane-C claims).
-- An issuer's key id is not one of our domain_keys UUIDs, so drop the FK to
-- domain_keys and widen the column to text. The (domain, signed_by_key_id) pair
-- identifies the signing key, resolved against our domain_keys for our own
-- domain or the peer-key cache for others. The issuer's signature is KEPT and
-- exposed so anyone can verify it (trust but verify).
ALTER TABLE claim_signatures DROP CONSTRAINT IF EXISTS claim_signatures_signed_by_key_id_fkey;
ALTER TABLE claim_signatures ALTER COLUMN signed_by_key_id TYPE VARCHAR USING signed_by_key_id::text;

-- Append-only cache of public keys we've seen for other domains, so stored
-- external signatures stay verifiable even after the issuer rotates or
-- disappears. Never deleted; a rotated key is simply a new (domain, key_id) row.
-- expires_at / revoked_at are captured from the issuer so verification still
-- honours the issuer's own key validity and revocation.
CREATE TABLE peer_keys (
    domain VARCHAR NOT NULL,
    key_id VARCHAR NOT NULL,
    public_key BYTEA NOT NULL,
    algorithm VARCHAR NOT NULL,
    fingerprint VARCHAR NOT NULL,
    key_usage VARCHAR NOT NULL,
    expires_at VARCHAR NOT NULL,
    revoked_at VARCHAR,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (domain, key_id)
);
