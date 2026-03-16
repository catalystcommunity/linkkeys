CREATE TABLE guestbook_entries (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TRIGGER set_guestbook_entries_updated_at
    AFTER UPDATE ON guestbook_entries
    FOR EACH ROW
    WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE guestbook_entries SET updated_at = datetime('now') WHERE id = NEW.id;
END;
