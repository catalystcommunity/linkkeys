-- See the postgres migration for semantics.
CREATE TABLE profiles (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    is_root INTEGER NOT NULL DEFAULT 0,
    label TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_profiles_account_id ON profiles(account_id);

CREATE TRIGGER set_profiles_updated_at
    AFTER UPDATE ON profiles
    FOR EACH ROW
    WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE profiles SET updated_at = datetime('now') WHERE id = NEW.id;
END;
