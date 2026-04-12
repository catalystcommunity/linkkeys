-- SQLite doesn't support DROP COLUMN in older versions, but modern SQLite (3.35+) does.
-- For safety, recreate tables without the new columns.

PRAGMA foreign_keys=OFF;

-- Recreate users without is_active
CREATE TABLE users_new (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT INTO users_new (id, username, display_name, created_at, updated_at)
SELECT id, username, display_name, created_at, updated_at FROM users;
DROP TABLE users;
ALTER TABLE users_new RENAME TO users;
CREATE TRIGGER set_users_updated_at
    AFTER UPDATE ON users FOR EACH ROW
    WHEN OLD.updated_at = NEW.updated_at
BEGIN UPDATE users SET updated_at = datetime('now') WHERE id = NEW.id; END;

-- Recreate auth_credentials without expires_at
CREATE TABLE auth_credentials_new (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    credential_type TEXT NOT NULL,
    credential_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    revoked_at TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT INTO auth_credentials_new (id, user_id, credential_type, credential_hash, created_at, revoked_at, updated_at)
SELECT id, user_id, credential_type, credential_hash, created_at, revoked_at, updated_at FROM auth_credentials;
DROP TABLE auth_credentials;
ALTER TABLE auth_credentials_new RENAME TO auth_credentials;
CREATE TRIGGER set_auth_credentials_updated_at
    AFTER UPDATE ON auth_credentials FOR EACH ROW
    WHEN OLD.updated_at = NEW.updated_at
BEGIN UPDATE auth_credentials SET updated_at = datetime('now') WHERE id = NEW.id; END;
CREATE INDEX idx_auth_credentials_user_id ON auth_credentials(user_id);
CREATE INDEX idx_auth_credentials_type ON auth_credentials(credential_type);

PRAGMA foreign_keys=ON;

DROP TABLE relations;
