-- SEC-08: a SIGNED attestation time on each claim (WHEN it was signed), so a
-- verifier can compare it against a signer key's revoked_at. Backfill existing
-- rows from created_at; those pre-existing claims must be re-signed to verify
-- under the new (v2) claim payload, since the signature now also covers
-- attested_at.
ALTER TABLE claims ADD COLUMN attested_at TIMESTAMPTZ;
UPDATE claims SET attested_at = created_at WHERE attested_at IS NULL;
ALTER TABLE claims ALTER COLUMN attested_at SET NOT NULL;
