-- TOFU pin of each peer domain's DNS fingerprint SET (SEC-01). See the postgres
-- migration for semantics.
CREATE TABLE domain_key_pins (
    domain TEXT PRIMARY KEY,
    fingerprints TEXT NOT NULL,
    pinned_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_checked_at TEXT NOT NULL DEFAULT (datetime('now'))
);
