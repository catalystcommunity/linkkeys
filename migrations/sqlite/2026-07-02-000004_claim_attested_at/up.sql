-- SEC-08: signed attestation time on each claim. See the postgres migration.
ALTER TABLE claims ADD COLUMN attested_at TEXT NOT NULL DEFAULT '';
UPDATE claims SET attested_at = created_at WHERE attested_at = '';
