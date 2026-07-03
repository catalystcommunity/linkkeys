-- SEC-08: sibling-signed key-revocation certificates this domain has ISSUED, so
-- they can be served to peers via DomainKeys/get-revocations. `revoked_at` is the
-- domain's asserted "not trustworthy after this instant" (may be well before the
-- certificate was requested). `cert` is the canonical CSIL CBOR of the full
-- RevocationCertificate (self-authenticating; a public read).
CREATE TABLE issued_revocations (
    id UUID PRIMARY KEY,
    target_key_id VARCHAR NOT NULL,
    target_fingerprint VARCHAR NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL,
    cert BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_issued_revocations_revoked_at ON issued_revocations(revoked_at);
CREATE UNIQUE INDEX idx_issued_revocations_target ON issued_revocations(target_key_id);
