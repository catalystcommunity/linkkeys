-- Generalize the claim approval queue into a domain-wide admin review queue and
-- add an append-only audit log. The review queue now carries a `kind`
-- discriminator so it can hold claim approvals AND security items (e.g. a pin
-- fingerprint-set mismatch that needs human review). Claim-specific columns
-- become nullable; non-claim kinds use `subject` + `detail` (JSON).
CREATE TABLE admin_review_queue (
    id UUID PRIMARY KEY,
    kind VARCHAR NOT NULL DEFAULT 'claim_approval',
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    claim_type VARCHAR,
    claim_value BYTEA,
    subject VARCHAR,
    detail VARCHAR,
    status VARCHAR NOT NULL DEFAULT 'pending',
    resolved_by VARCHAR,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO admin_review_queue
    (id, kind, user_id, claim_type, claim_value, status, resolved_by, resolved_at, created_at, updated_at)
SELECT id, 'claim_approval', user_id, claim_type, claim_value, status, resolved_by, resolved_at, created_at, updated_at
FROM claim_approval_queue;

DROP TABLE claim_approval_queue;

CREATE INDEX idx_admin_review_queue_status ON admin_review_queue(status);
CREATE INDEX idx_admin_review_queue_kind ON admin_review_queue(kind);

CREATE TABLE audit_log (
    id UUID PRIMARY KEY,
    event VARCHAR NOT NULL,
    subject VARCHAR,
    actor VARCHAR,
    detail VARCHAR,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);
