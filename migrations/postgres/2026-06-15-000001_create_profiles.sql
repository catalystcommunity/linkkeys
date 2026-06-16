-- Profiles: the pseudonymous identities (UUID@domain) a human account presents.
-- One account has exactly one root profile (the never-leaked anchor) plus zero
-- or more presentable profiles. Claims/assertions are subjected to a profile.
-- Unlinkability between profiles is an operational concern, not enforced here
-- beyond carrying no cross-profile identifier.
CREATE TABLE profiles (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain VARCHAR NOT NULL,
    is_root BOOLEAN NOT NULL DEFAULT FALSE,
    label VARCHAR,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_profiles_account_id ON profiles(account_id);

SELECT diesel_manage_updated_at('profiles');
