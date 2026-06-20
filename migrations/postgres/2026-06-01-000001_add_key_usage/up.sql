-- Tag each key with its purpose: 'sign' (Ed25519 identity) or 'encrypt'
-- (X25519 sealed-box recipient). Existing keys are signing keys.
ALTER TABLE domain_keys ADD COLUMN key_usage VARCHAR NOT NULL DEFAULT 'sign';
ALTER TABLE user_keys ADD COLUMN key_usage VARCHAR NOT NULL DEFAULT 'sign';

-- Encrypt keys are vouched for by a signing key (not DNS-pinned): signed_by_key_id
-- names the signing key, key_signature is its signature over the encrypt key's
-- fingerprint (+ expiry). NULL for signing keys, which are pinned via DNS fp=.
ALTER TABLE domain_keys ADD COLUMN signed_by_key_id VARCHAR;
ALTER TABLE domain_keys ADD COLUMN key_signature BYTEA;
ALTER TABLE user_keys ADD COLUMN signed_by_key_id VARCHAR;
ALTER TABLE user_keys ADD COLUMN key_signature BYTEA;
