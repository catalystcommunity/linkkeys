-- Claim-signing policy registry and the per-user / per-audience policy tables
-- built on top of it. See liblinkkeys::claim_policy for the lane semantics
-- (self_signed / verified / attested / unsigned) referenced below.

-- The catalogue of recognised claim types and the rules for setting and signing
-- each. A deployment serves a single domain, so claim_type is the natural key.
CREATE TABLE claim_type_policies (
    claim_type VARCHAR PRIMARY KEY,
    label VARCHAR NOT NULL,
    description VARCHAR NOT NULL DEFAULT '',
    -- A CSIL primitive the IDP can validate (text/url/bool/date/email/int/
    -- decimal/timestamp) or 'opaque' (IDP cannot validate the value).
    value_type VARCHAR NOT NULL,
    max_bytes BIGINT NOT NULL DEFAULT 33792,
    -- Who may set a value: user_self | idp_on_request | trusted_issuer_only |
    -- admin_only | deny.
    set_rule VARCHAR NOT NULL,
    -- How a value gets signed (the lanes): self_signed (A) | verified (B) |
    -- attested (C) | unsigned (D).
    signing_rule VARCHAR NOT NULL,
    requires_approval BOOLEAN NOT NULL DEFAULT FALSE,
    user_settable BOOLEAN NOT NULL DEFAULT FALSE,
    default_auto_sign BOOLEAN NOT NULL DEFAULT FALSE,
    suggested BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

SELECT diesel_manage_updated_at('claim_type_policies');

-- Domains whose signature the IDP accepts as attestation for a claim type
-- (lane C) — e.g. a recognised government entity for age_over_21.
CREATE TABLE trusted_issuers (
    claim_type VARCHAR NOT NULL,
    issuer_domain VARCHAR NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (claim_type, issuer_domain)
);

-- A user's per-profile preference for whether the IDP keeps a claim signed
-- automatically. Only meaningful where the registry marks the type user_settable.
CREATE TABLE profile_claim_prefs (
    profile_id VARCHAR NOT NULL,
    claim_type VARCHAR NOT NULL,
    auto_sign BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (profile_id, claim_type)
);

SELECT diesel_manage_updated_at('profile_claim_prefs');

-- Per-audience release policy (forced_allow / forced_deny). The audience '*' is
-- the global default applied to every audience; it seeds from the deprecated
-- CONSENT_FORCED_ALLOW / CONSENT_FORCED_DENY env vars on first boot.
CREATE TABLE release_policies (
    audience VARCHAR NOT NULL,
    claim_type VARCHAR NOT NULL,
    -- forced_allow | forced_deny
    disposition VARCHAR NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (audience, claim_type)
);

SELECT diesel_manage_updated_at('release_policies');

-- Self-asserted claims awaiting admin approval before the IDP signs them
-- (set_rule = idp_on_request with requires_approval).
CREATE TABLE claim_approval_queue (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    claim_type VARCHAR NOT NULL,
    claim_value BYTEA NOT NULL,
    status VARCHAR NOT NULL DEFAULT 'pending',
    resolved_by VARCHAR,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_claim_approval_queue_status ON claim_approval_queue(status);

SELECT diesel_manage_updated_at('claim_approval_queue');

-- Pending email-verification challenges. A row is created when a user asks to
-- verify an email address; on confirmation the IDP signs `email` +
-- `email_verified` and the row is deleted. Tokens are single-use and expire.
CREATE TABLE email_verifications (
    token VARCHAR PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email VARCHAR NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_email_verifications_user ON email_verifications(user_id);

-- A user's standing release preferences: claim types pre-authorized for an
-- audience (audience '*' = any domain), set from their own profile editor.
-- Surfaced as pre-checked rows at consent.
CREATE TABLE user_release_prefs (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    audience VARCHAR NOT NULL,
    claim_type VARCHAR NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, audience, claim_type)
);

CREATE INDEX idx_user_release_prefs_user ON user_release_prefs(user_id);
