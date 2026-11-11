-- Standing consent is per application of a relying party. A grant names the
-- application (`ApplicationRef` without subject_domain, which always equals
-- `audience`) when the login request named one. Both columns are NULL for a
-- grant that covers requests with no application (local RPs, and regular-RP
-- requests from servers that do not name the application).
ALTER TABLE consent_grants
    ADD COLUMN app_subject_user_id VARCHAR,
    ADD COLUMN app_application_id VARCHAR,
    ADD CONSTRAINT consent_grants_application_complete
        CHECK ((app_subject_user_id IS NULL) = (app_application_id IS NULL));

-- One active grant per (user, audience, application). COALESCE makes the
-- no-application grant unique too (NULLs are otherwise distinct).
DROP INDEX idx_consent_grants_user_audience;
CREATE UNIQUE INDEX idx_consent_grants_user_audience_app ON consent_grants (
    user_id,
    audience,
    COALESCE(app_subject_user_id, ''),
    COALESCE(app_application_id, '')
);
