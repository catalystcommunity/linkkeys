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
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    grantee_kind TEXT NOT NULL,
    grantee_subject_user_id TEXT,
    grantee_subject_domain TEXT,
    grantee_application_id TEXT,
    grantee_local_rp_fingerprint TEXT,
    audience_subject_user_id TEXT NOT NULL,
    audience_subject_domain TEXT NOT NULL,
    audience_application_id TEXT NOT NULL,
    approved_scope TEXT NOT NULL,
    lifetime_seconds BIGINT NOT NULL CHECK (lifetime_seconds > 0),
    series_issued_at TEXT NOT NULL,
    renewable_until TEXT NOT NULL,
    signed_grant BLOB NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    -- CBOR(SignedActAsGrantRevocation). Present exactly when revoked_at is.
    signed_revocation BLOB,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
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
    -- The same time-order rules as the Postgres table. julianday() reads the
    -- RFC3339 text, so the comparison does not depend on string order.
    CHECK (julianday(expires_at) > julianday(issued_at)),
    CHECK (julianday(renewable_until) >= julianday(expires_at))
);

CREATE INDEX act_as_grants_user_id_idx ON act_as_grants(user_id);

CREATE TRIGGER set_act_as_grants_updated_at
    AFTER UPDATE ON act_as_grants
    FOR EACH ROW
    WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE act_as_grants
    SET updated_at = datetime('now')
    WHERE id = NEW.id;
END;
