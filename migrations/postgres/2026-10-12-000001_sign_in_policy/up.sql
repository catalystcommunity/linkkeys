-- How long a browser sign-in stays valid on this domain. One row per domain;
-- no row means the built-in default (services::browser_session).
CREATE TABLE sign_in_policy (
    domain VARCHAR PRIMARY KEY,
    sign_in_hours INTEGER NOT NULL CHECK (sign_in_hours BETWEEN 1 AND 720),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT diesel_manage_updated_at('sign_in_policy');
