-- Application-key storage (signing-things-request.md, step 2). Pure storage:
-- an application instance of a canonical account, its enrolled public keys,
-- each key's home-domain attestation, permanent sibling-signed revocations,
-- and single-use enrollment/renewal proof-of-possession challenges.

CREATE TABLE application_instances (
    id UUID PRIMARY KEY,
    subject_user_id UUID NOT NULL REFERENCES users(id),
    application_id VARCHAR NOT NULL,
    instance_id VARCHAR NOT NULL,
    enrolled_at TIMESTAMPTZ NOT NULL,
    trust_reset_count BIGINT NOT NULL DEFAULT 0,
    last_trust_reset_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The composite lookup index the design requires: every anonymous public
-- read and every enrollment op looks up by (subject, application, instance).
CREATE UNIQUE INDEX application_instances_subject_app_instance_idx
    ON application_instances(subject_user_id, application_id, instance_id);

-- Application public keys. Deliberately has no encrypted-private-key column:
-- the application never gives its home domain a private key, so there is
-- nothing here to accidentally leak through a public read projection.
CREATE TABLE application_keys (
    id UUID PRIMARY KEY,
    instance_row_id UUID NOT NULL REFERENCES application_instances(id),
    key_id VARCHAR NOT NULL,
    key_usage VARCHAR NOT NULL,
    algorithm VARCHAR NOT NULL,
    public_key BYTEA NOT NULL,
    fingerprint VARCHAR NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX application_keys_instance_key_id_idx
    ON application_keys(instance_row_id, key_id);

CREATE INDEX application_keys_instance_row_id_idx
    ON application_keys(instance_row_id);

-- Exactly one current attestation per key (application_key_row_id UNIQUE).
-- Renewal replaces this row's bytes; the server never re-signs on read.
CREATE TABLE application_key_attestations (
    id UUID PRIMARY KEY,
    application_key_row_id UUID NOT NULL UNIQUE REFERENCES application_keys(id),
    signed_attestation BYTEA NOT NULL,
    attested_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Permanent, sibling-signed revocation evidence. Idempotent: a repeat
-- revocation of the same key in the same instance is a no-op.
CREATE TABLE application_key_revocations (
    id UUID PRIMARY KEY,
    instance_row_id UUID NOT NULL REFERENCES application_instances(id),
    target_key_id VARCHAR NOT NULL,
    target_fingerprint VARCHAR NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL,
    record BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX application_key_revocations_instance_target_idx
    ON application_key_revocations(instance_row_id, target_key_id);

CREATE INDEX application_key_revocations_instance_revoked_at_idx
    ON application_key_revocations(instance_row_id, revoked_at);

-- Single-use proof-of-possession nonces for key enrollment/renewal.
-- Deliberately NOT FK'd to users or application_instances: the challenge
-- operation must answer identically for a known and an unknown instance.
CREATE TABLE application_key_challenges (
    id UUID PRIMARY KEY,
    challenge_id VARCHAR NOT NULL UNIQUE,
    subject_user_id VARCHAR NOT NULL,
    application_id VARCHAR NOT NULL,
    instance_id VARCHAR NOT NULL,
    purpose VARCHAR NOT NULL,
    key_usage VARCHAR NOT NULL,
    algorithm VARCHAR NOT NULL,
    public_key BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX application_key_challenges_expires_at_idx
    ON application_key_challenges(expires_at);
