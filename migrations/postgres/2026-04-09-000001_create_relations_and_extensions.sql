CREATE TABLE relations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject_type VARCHAR NOT NULL,
    subject_id VARCHAR NOT NULL,
    relation VARCHAR NOT NULL,
    object_type VARCHAR NOT NULL,
    object_id VARCHAR NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    removed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT diesel_manage_updated_at('relations');
CREATE INDEX idx_relations_subject ON relations(subject_type, subject_id);
CREATE INDEX idx_relations_object ON relations(object_type, object_id);
CREATE INDEX idx_relations_lookup ON relations(subject_type, subject_id, relation, object_type, object_id);

ALTER TABLE users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT true;

ALTER TABLE auth_credentials ADD COLUMN expires_at TIMESTAMPTZ;
