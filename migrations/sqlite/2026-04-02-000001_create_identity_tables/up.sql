CREATE TABLE domain_keys (
    id TEXT PRIMARY KEY,
    public_key BLOB NOT NULL,
    private_key_encrypted BLOB NOT NULL,
    fingerprint TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'ed25519',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TRIGGER set_domain_keys_updated_at
    AFTER UPDATE ON domain_keys
    FOR EACH ROW
    WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE domain_keys SET updated_at = datetime('now') WHERE id = NEW.id;
END;

CREATE TABLE users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TRIGGER set_users_updated_at
    AFTER UPDATE ON users
    FOR EACH ROW
    WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE users SET updated_at = datetime('now') WHERE id = NEW.id;
END;

CREATE TABLE user_keys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    public_key BLOB NOT NULL,
    private_key_encrypted BLOB NOT NULL,
    fingerprint TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'ed25519',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TRIGGER set_user_keys_updated_at
    AFTER UPDATE ON user_keys
    FOR EACH ROW
    WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE user_keys SET updated_at = datetime('now') WHERE id = NEW.id;
END;

CREATE TABLE claims (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    claim_type TEXT NOT NULL,
    claim_value BLOB NOT NULL,
    signed_by_key_id TEXT NOT NULL REFERENCES domain_keys(id),
    signature BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT,
    revoked_at TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TRIGGER set_claims_updated_at
    AFTER UPDATE ON claims
    FOR EACH ROW
    WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE claims SET updated_at = datetime('now') WHERE id = NEW.id;
END;
