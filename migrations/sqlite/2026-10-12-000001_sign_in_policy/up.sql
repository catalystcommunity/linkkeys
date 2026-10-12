-- How long a browser sign-in stays valid on this domain. See the postgres
-- migration for semantics.
CREATE TABLE sign_in_policy (
    domain TEXT PRIMARY KEY,
    sign_in_hours INTEGER NOT NULL CHECK (sign_in_hours BETWEEN 1 AND 720),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TRIGGER set_sign_in_policy_updated_at
    AFTER UPDATE ON sign_in_policy
    FOR EACH ROW
    WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE sign_in_policy SET updated_at = datetime('now') WHERE domain = NEW.domain;
END;
