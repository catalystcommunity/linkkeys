-- Application-key storage (signing-things-request.md, step 2). Pure storage:
-- an application instance of a canonical account, its enrolled public keys,
-- each key's home-domain attestation, permanent sibling-signed revocations,
-- and single-use enrollment/renewal proof-of-possession challenges.

CREATE TABLE application_instances (
    id TEXT PRIMARY KEY NOT NULL,
    subject_user_id TEXT NOT NULL REFERENCES users(id),
    application_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    enrolled_at TEXT NOT NULL,
    trust_reset_count BIGINT NOT NULL DEFAULT 0,
    last_trust_reset_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- The composite lookup index the design requires: every anonymous public
-- read and every enrollment op looks up by (subject, application, instance).
CREATE UNIQUE INDEX application_instances_subject_app_instance_idx
    ON application_instances(subject_user_id, application_id, instance_id);

-- Application public keys. Deliberately has no encrypted-private-key column:
-- the application never gives its home domain a private key, so there is
-- nothing here to accidentally leak through a public read projection.
CREATE TABLE application_keys (
    id TEXT PRIMARY KEY NOT NULL,
    instance_row_id TEXT NOT NULL REFERENCES application_instances(id),
    key_id TEXT NOT NULL,
    key_usage TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    public_key BLOB NOT NULL,
    fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE UNIQUE INDEX application_keys_instance_key_id_idx
    ON application_keys(instance_row_id, key_id);

CREATE INDEX application_keys_instance_row_id_idx
    ON application_keys(instance_row_id);

-- Exactly one current attestation per key (application_key_row_id UNIQUE).
-- Renewal replaces this row's bytes; the server never re-signs on read.
CREATE TABLE application_key_attestations (
    id TEXT PRIMARY KEY NOT NULL,
    application_key_row_id TEXT NOT NULL UNIQUE REFERENCES application_keys(id),
    signed_attestation BLOB NOT NULL,
    attested_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Permanent, sibling-signed revocation evidence. Idempotent: a repeat
-- revocation of the same key in the same instance is a no-op.
CREATE TABLE application_key_revocations (
    id TEXT PRIMARY KEY NOT NULL,
    instance_row_id TEXT NOT NULL REFERENCES application_instances(id),
    target_key_id TEXT NOT NULL,
    target_fingerprint TEXT NOT NULL,
    revoked_at TEXT NOT NULL,
    record BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX application_key_revocations_instance_target_idx
    ON application_key_revocations(instance_row_id, target_key_id);

CREATE INDEX application_key_revocations_instance_revoked_at_idx
    ON application_key_revocations(instance_row_id, revoked_at);

-- Single-use proof-of-possession nonces for key enrollment/renewal.
-- Deliberately NOT FK'd to users or application_instances: the challenge
-- operation must answer identically for a known and an unknown instance.
CREATE TABLE application_key_challenges (
    id TEXT PRIMARY KEY NOT NULL,
    challenge_id TEXT NOT NULL UNIQUE,
    subject_user_id TEXT NOT NULL,
    application_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    purpose TEXT NOT NULL,
    key_usage TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    public_key BLOB NOT NULL,
    nonce BLOB NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX application_key_challenges_expires_at_idx
    ON application_key_challenges(expires_at);
