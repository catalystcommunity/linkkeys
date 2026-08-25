-- PostgreSQL removed the external-signature foreign key in migration
-- 2026-06-18-000001. Add the API-key digest locator for both backends.
CREATE INDEX auth_credentials_active_hash_idx
ON auth_credentials(credential_type, credential_hash)
WHERE revoked_at IS NULL;

CREATE INDEX users_legacy_api_prefix_idx ON users((LEFT(id::text, 8)));
