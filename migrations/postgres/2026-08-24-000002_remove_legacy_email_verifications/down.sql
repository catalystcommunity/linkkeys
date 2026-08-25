CREATE TABLE email_verifications (
    token VARCHAR PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    email VARCHAR NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_email_verifications_user ON email_verifications(user_id);
