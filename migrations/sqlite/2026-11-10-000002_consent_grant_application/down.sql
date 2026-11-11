DROP INDEX idx_consent_grants_user_audience_app;
DELETE FROM consent_grants WHERE app_application_id IS NOT NULL;
ALTER TABLE consent_grants DROP COLUMN app_application_id;
ALTER TABLE consent_grants DROP COLUMN app_subject_user_id;
CREATE UNIQUE INDEX idx_consent_grants_user_audience ON consent_grants(user_id, audience);
