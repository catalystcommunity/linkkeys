CREATE TABLE user_authentication_activity (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    last_authenticated_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    successful_authentication_count INTEGER NOT NULL DEFAULT 1
        CHECK (successful_authentication_count > 0),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TRIGGER set_user_authentication_activity_updated_at
    AFTER UPDATE ON user_authentication_activity
    FOR EACH ROW
    WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE user_authentication_activity
    SET updated_at = datetime('now')
    WHERE user_id = NEW.user_id;
END;
