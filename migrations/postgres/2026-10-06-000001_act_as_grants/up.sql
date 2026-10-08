-- Act-as grants (docs/spec/reserved/act-as-grants.md). One row per grant
-- series. The id IS the protocol grant_id. signed_grant holds the CURRENT
-- CBOR(SignedActAsGrant); a renewal replaces it and moves issued_at and
-- expires_at. Every other column is bookkeeping for lookups and the user's
-- grant list: the signed bytes are the authoritative record, and the server
-- serves them verbatim.
--
-- approved_scope is the JSON array the user approved. It is a display copy of
-- the value inside signed_grant.
CREATE TABLE act_as_grants (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    grantee_kind VARCHAR NOT NULL,
    grantee_subject_user_id VARCHAR,
    grantee_subject_domain VARCHAR,
    grantee_application_id VARCHAR,
    grantee_local_rp_fingerprint VARCHAR,
    audience_subject_user_id VARCHAR NOT NULL,
    audience_subject_domain VARCHAR NOT NULL,
    audience_application_id VARCHAR NOT NULL,
    approved_scope TEXT NOT NULL,
    lifetime_seconds BIGINT NOT NULL CHECK (lifetime_seconds > 0),
    series_issued_at TIMESTAMPTZ NOT NULL,
    renewable_until TIMESTAMPTZ NOT NULL,
    signed_grant BYTEA NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    -- CBOR(SignedActAsGrantRevocation). Present exactly when revoked_at is.
    signed_revocation BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (
        (grantee_kind = 'application'
            AND grantee_subject_user_id IS NOT NULL
            AND grantee_subject_domain IS NOT NULL
            AND grantee_application_id IS NOT NULL
            AND grantee_local_rp_fingerprint IS NULL)
        OR
        (grantee_kind = 'local_rp'
            AND grantee_subject_user_id IS NULL
            AND grantee_subject_domain IS NULL
            AND grantee_application_id IS NULL
            AND grantee_local_rp_fingerprint IS NOT NULL)
    ),
    CHECK ((revoked_at IS NULL) = (signed_revocation IS NULL)),
    CHECK (expires_at > issued_at),
    CHECK (renewable_until >= expires_at)
);

CREATE INDEX act_as_grants_user_id_idx ON act_as_grants(user_id);

SELECT diesel_manage_updated_at('act_as_grants');
