-- A user's standing authorization for one relying party (audience) to receive
-- a set of claim types. One active grant per (user, audience); re-consent
-- replaces it. claim_types is the JSON array the user authorized; requested_types
-- is the JSON array the RP asked for at consent time (IDP bookkeeping, not signed)
-- so a later login can skip the prompt unless the RP requests something new.
-- signed_grant is CBOR(SignedConsentGrant) — the home-domain-attested artifact.
CREATE TABLE consent_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subject_domain VARCHAR NOT NULL,
    audience VARCHAR NOT NULL,
    claim_types TEXT NOT NULL,
    requested_types TEXT NOT NULL,
    signed_grant BYTEA NOT NULL,
    -- CBOR([DomainClaim]) the RP asserted about itself at consent time (the
    -- non-repudiable record of what it offered); NULL if it asserted nothing.
    offered_claims BYTEA,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_consent_grants_user_audience ON consent_grants(user_id, audience);

SELECT diesel_manage_updated_at('consent_grants');
