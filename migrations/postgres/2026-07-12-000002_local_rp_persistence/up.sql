-- DNS-less local RP identity persistence (see dns-less-local-rp-design.md,
-- Phase 4 — server persistence). Three tables: this domain's admission policy
-- for local RP logins, the local RP approval registry (keyed by the RP's
-- signing-key fingerprint — its identity, SSH-host-key style), and the
-- claim-get tickets issued at the end of a successful local RP login. See
-- `liblinkkeys::local_rp` for the pure protocol helpers these back; this
-- migration is storage only.

-- Per-domain admission policy for local RP logins. A deployment serves a
-- single domain (see claim_type_policies' precedent comment), so this is
-- effectively one row keyed by that domain's own name — mirrors
-- domain_key_pins' domain-keyed shape. An absent row means the default,
-- "admin-approval-required" (applied in code by
-- DbPool::effective_local_rp_policy); seeding a default row is a data
-- backfill, not migration DDL, per the "migrations are pure schema" rule
-- documented in db/mod.rs.
-- Value vocabulary: "disabled" | "admin-approval-required" | "allow-by-default".
CREATE TABLE local_rp_domain_policy (
    domain VARCHAR PRIMARY KEY,
    policy VARCHAR NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT diesel_manage_updated_at('local_rp_domain_policy');

-- The local RP approval registry. Identity is `fingerprint` alone (sha256 hex
-- of the RP's Ed25519 signing public key, liblinkkeys::crypto::fingerprint) —
-- app_name/local_domain_hint are display/audit metadata only, never identity;
-- a changed value on an already-known fingerprint is a drift warning, not a
-- re-identification (see services::local_rp::record_login_attempt).
-- status: "pending" | "approved" | "denied" | "revoked". Transition matrix is
-- validated in services::local_rp (pending->approved/denied, approved-
-- >revoked, denied->approved; everything else, including un-revoking, is
-- rejected).
CREATE TABLE local_rps (
    fingerprint VARCHAR PRIMARY KEY,
    signing_public_key BYTEA NOT NULL,
    encryption_public_key BYTEA NOT NULL,
    app_name VARCHAR NOT NULL,
    local_domain_hint VARCHAR,
    status VARCHAR NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ,
    admin_notes VARCHAR
);
SELECT diesel_manage_updated_at('local_rps');
CREATE INDEX idx_local_rps_status ON local_rps(status);

-- Claim-get tickets: the browser callback carries a ticket, not claims (Wire
-- Precision: "Claim ticket bytes"). Only the SHA-256 hex of the 32 random
-- ticket bytes is ever stored (`ticket_hash`, via
-- liblinkkeys::crypto::fingerprint) — the raw ticket never touches the
-- database or logs. Redemption looks up by `ticket_hash` (the primary key),
-- then checks expiry and that the bound local RP's approval status is still
-- "approved" (revocation kills outstanding tickets). Multi-use within the
-- window: redemption does not delete the row.
CREATE TABLE local_rp_claim_tickets (
    ticket_hash VARCHAR PRIMARY KEY,
    fingerprint VARCHAR NOT NULL REFERENCES local_rps(fingerprint) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_domain VARCHAR NOT NULL,
    -- JSON array of claim type names, frozen at consent time (design:
    -- "the claim set is frozen to what the user consented to").
    granted_claims TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_local_rp_claim_tickets_fingerprint ON local_rp_claim_tickets(fingerprint);
CREATE INDEX idx_local_rp_claim_tickets_expires_at ON local_rp_claim_tickets(expires_at);
