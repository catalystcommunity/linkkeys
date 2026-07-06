-- See the postgres migration for semantics.

CREATE TABLE claim_type_label_i18n (
    claim_type TEXT NOT NULL REFERENCES claim_type_policies(claim_type) ON DELETE CASCADE,
    locale TEXT NOT NULL,
    label TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (claim_type, locale)
);

CREATE TRIGGER set_claim_type_label_i18n_updated_at
    AFTER UPDATE ON claim_type_label_i18n
    FOR EACH ROW
    WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE claim_type_label_i18n SET updated_at = datetime('now')
        WHERE claim_type = NEW.claim_type AND locale = NEW.locale;
END;
