CREATE UNIQUE INDEX idx_relations_unique_active ON relations(subject_type, subject_id, relation, object_type, object_id) WHERE removed_at IS NULL;
