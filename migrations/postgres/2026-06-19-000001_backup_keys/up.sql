-- Per-domain backup encryption key. A single active row (rotated_at IS NULL)
-- holds the 256-bit key used to encrypt `linkkeys backup` artifacts. The key is
-- itself stored encrypted at rest with DOMAIN_KEY_PASSPHRASE (same scheme as
-- domain_keys.private_key_encrypted), so the DB never holds the raw backup key.
-- Rotation stamps rotated_at on the old row and inserts a new active row.
CREATE TABLE backup_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_encrypted BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at TIMESTAMPTZ
);
