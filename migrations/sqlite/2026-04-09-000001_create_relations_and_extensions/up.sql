CREATE TABLE relations (
    id TEXT PRIMARY KEY,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    object_type TEXT NOT NULL,
    object_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    removed_at TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TRIGGER set_relations_updated_at
    AFTER UPDATE ON relations
    FOR EACH ROW
    WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE relations SET updated_at = datetime('now') WHERE id = NEW.id;
END;

CREATE INDEX idx_relations_subject ON relations(subject_type, subject_id);
CREATE INDEX idx_relations_object ON relations(object_type, object_id);
CREATE INDEX idx_relations_lookup ON relations(subject_type, subject_id, relation, object_type, object_id);

ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1;

ALTER TABLE auth_credentials ADD COLUMN expires_at TEXT;
