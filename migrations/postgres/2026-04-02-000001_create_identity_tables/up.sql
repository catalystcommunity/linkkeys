CREATE TABLE domain_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    public_key BYTEA NOT NULL,
    private_key_encrypted BYTEA NOT NULL,
    fingerprint VARCHAR NOT NULL,
    algorithm VARCHAR NOT NULL DEFAULT 'ed25519',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT diesel_manage_updated_at('domain_keys');

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR NOT NULL UNIQUE,
    display_name VARCHAR NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT diesel_manage_updated_at('users');

CREATE TABLE auth_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    credential_type VARCHAR NOT NULL,
    credential_hash VARCHAR NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT diesel_manage_updated_at('auth_credentials');
CREATE INDEX idx_auth_credentials_user_id ON auth_credentials(user_id);
CREATE INDEX idx_auth_credentials_type ON auth_credentials(credential_type);

CREATE TABLE user_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    public_key BYTEA NOT NULL,
    private_key_encrypted BYTEA NOT NULL,
    fingerprint VARCHAR NOT NULL,
    algorithm VARCHAR NOT NULL DEFAULT 'ed25519',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT diesel_manage_updated_at('user_keys');

CREATE TABLE claims (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    claim_type VARCHAR NOT NULL,
    claim_value BYTEA NOT NULL,
    signed_by_key_id UUID NOT NULL REFERENCES domain_keys(id),
    signature BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT diesel_manage_updated_at('claims');
