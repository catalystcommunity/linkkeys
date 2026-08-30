-- RP-side persistent cache of remote key material (signing-things-request.md,
-- step 6: "RP cache" / "RP-facing operations" / "Public-key caches"). This is
-- OUR reader-side cache of OTHER domains' public material, not the home-domain
-- server-side storage added in 2026-08-29-000001_application_keys.
--
-- Two independent freshness clocks, one per remote-domain-scoped resource:
--
-- 1. Domain keys. The key material itself keeps using the existing
--    `peer_keys` table (already durable); this migration adds only the
--    freshness record so a resolve knows whether `peer_keys` is current
--    enough to serve without a re-fetch.
-- 2. Application-key attestations + revocations. These have no pre-existing
--    durable home, so this migration stores the SIGNED records verbatim
--    (never a re-derived summary) plus per-entry freshness metadata.
--
-- The cache key for application material is the canonical subject identity
-- (subject_user_id + subject_domain) + application_id + instance_id -- never
-- a handle. The unique index below makes an entry crossing a subject,
-- application, or instance boundary a constraint violation, not a bug to
-- catch in review.

CREATE TABLE rp_domain_key_cache (
    domain TEXT PRIMARY KEY NOT NULL,
    fetched_at TEXT NOT NULL,
    revocations_checked_at TEXT NOT NULL,
    last_used_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- One row per (subject, application, instance) this RP has ever resolved.
-- subject_user_id/subject_domain are NOT FK'd to `users`: the subject is a
-- REMOTE account this server does not host.
CREATE TABLE rp_application_key_cache_entries (
    id TEXT PRIMARY KEY NOT NULL,
    subject_user_id TEXT NOT NULL,
    subject_domain TEXT NOT NULL,
    application_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    revocations_checked_at TEXT NOT NULL,
    last_used_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- The structural guarantee the design requires: an entry can never cross a
-- subject, application, or instance boundary, and a handle is never part of
-- this key.
CREATE UNIQUE INDEX rp_application_key_cache_entries_identity_idx
    ON rp_application_key_cache_entries(subject_user_id, subject_domain, application_id, instance_id);

CREATE INDEX rp_application_key_cache_entries_last_used_idx
    ON rp_application_key_cache_entries(last_used_at);

-- Cached SIGNED attestations, stored and served verbatim (never re-derived).
-- Exactly one current row per key_id within an entry; a renewal overwrites it.
CREATE TABLE rp_application_key_attestations (
    id TEXT PRIMARY KEY NOT NULL,
    cache_entry_id TEXT NOT NULL REFERENCES rp_application_key_cache_entries(id),
    key_id TEXT NOT NULL,
    signed_attestation BLOB NOT NULL,
    attestation_expires_at TEXT NOT NULL,
    -- Comma-joined home-domain key ids whose signature verified this
    -- attestation at fetch time (design: "which home-domain keys verified
    -- each attestation"). Informational only -- never re-derives a rule.
    verified_by_key_ids TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX rp_application_key_attestations_entry_key_idx
    ON rp_application_key_attestations(cache_entry_id, key_id);

CREATE INDEX rp_application_key_attestations_expires_at_idx
    ON rp_application_key_attestations(cache_entry_id, attestation_expires_at);

-- Cached SIGNED revocation records, stored and served verbatim.
CREATE TABLE rp_application_key_revocations (
    id TEXT PRIMARY KEY NOT NULL,
    cache_entry_id TEXT NOT NULL REFERENCES rp_application_key_cache_entries(id),
    target_key_id TEXT NOT NULL,
    revocation BLOB NOT NULL,
    revoked_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX rp_application_key_revocations_entry_target_idx
    ON rp_application_key_revocations(cache_entry_id, target_key_id);
