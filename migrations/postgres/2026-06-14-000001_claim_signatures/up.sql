-- Claims move from a single embedded signature to a normalized set of
-- signatures, one row per (domain, key) that signed the claim. A domain signs
-- with several of its keys (>=3 by design) for redundancy/rotation, and the
-- signing domain is recorded explicitly so verifiers can key trust on it.
CREATE TABLE claim_signatures (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    claim_id UUID NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    domain VARCHAR NOT NULL,
    signed_by_key_id UUID NOT NULL REFERENCES domain_keys(id),
    signature BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_claim_signatures_claim_id ON claim_signatures(claim_id);

-- The old single-signature columns are superseded. Pre-alpha: existing rows are
-- re-signed into claim_signatures by the server's startup backfill.
ALTER TABLE claims DROP COLUMN signed_by_key_id;
ALTER TABLE claims DROP COLUMN signature;
