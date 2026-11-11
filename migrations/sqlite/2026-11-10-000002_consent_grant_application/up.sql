-- Standing consent is per application of a relying party. See the postgres
-- migration for semantics.
ALTER TABLE consent_grants ADD COLUMN app_subject_user_id TEXT;
ALTER TABLE consent_grants ADD COLUMN app_application_id TEXT
    CHECK ((app_subject_user_id IS NULL) = (app_application_id IS NULL));

DROP INDEX idx_consent_grants_user_audience;
CREATE UNIQUE INDEX idx_consent_grants_user_audience_app ON consent_grants (
    user_id,
    audience,
    COALESCE(app_subject_user_id, ''),
    COALESCE(app_application_id, '')
);
