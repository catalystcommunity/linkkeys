ALTER TABLE domain_keys DROP COLUMN key_usage;
ALTER TABLE user_keys DROP COLUMN key_usage;
ALTER TABLE domain_keys DROP COLUMN signed_by_key_id;
ALTER TABLE domain_keys DROP COLUMN key_signature;
ALTER TABLE user_keys DROP COLUMN signed_by_key_id;
ALTER TABLE user_keys DROP COLUMN key_signature;
