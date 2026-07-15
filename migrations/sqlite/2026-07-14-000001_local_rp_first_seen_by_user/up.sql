-- SEC M3: see the postgres migration for semantics.
ALTER TABLE local_rps ADD COLUMN first_seen_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL;
CREATE INDEX idx_local_rps_first_seen_by_user_id ON local_rps(first_seen_by_user_id);
