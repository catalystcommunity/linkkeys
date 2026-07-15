-- SEC M3: attribute a pending local RP entry to the authenticated user whose
-- login attempt first created it, so the pending-queue admission guard
-- (crate::services::local_rp::record_login_attempt) can additionally enforce
-- a PER-USER cap (MAX_PENDING_LOCAL_RPS_PER_USER) on top of the existing
-- global cap (MAX_PENDING_LOCAL_RPS) — one authenticated account can no
-- longer occupy the whole pending-approval queue by itself.
--
-- Nullable: rows inserted via a path that doesn't attribute a user (e.g. test
-- factories inserting directly, or a pre-migration row) simply carry no
-- attribution and are excluded from every user's per-user count — they still
-- count toward the global cap. ON DELETE SET NULL rather than CASCADE: user
-- purge (2026-07-12-000001_user_tombstones) minimizes the `users` row rather
-- than deleting it, so this practically never fires, but a hard delete must
-- not silently delete an unrelated local_rps row.
ALTER TABLE local_rps ADD COLUMN first_seen_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL;
CREATE INDEX idx_local_rps_first_seen_by_user_id ON local_rps(first_seen_by_user_id);
