-- App access policies: allow or deny lists of application domain patterns
-- (`*` matches any run of characters), assigned to accounts by targets. See
-- liblinkkeys::app_access for the evaluation rules.
CREATE TABLE app_access_policies (
    id UUID PRIMARY KEY,
    name VARCHAR NOT NULL UNIQUE,
    mode VARCHAR NOT NULL CHECK (mode IN ('allow', 'deny')),
    -- Optional extra text shown to a user that the policy blocks.
    message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT diesel_manage_updated_at('app_access_policies');

-- Canonical patterns (liblinkkeys::app_access::normalize_pattern).
CREATE TABLE app_access_policy_patterns (
    policy_id UUID NOT NULL REFERENCES app_access_policies(id) ON DELETE CASCADE,
    pattern VARCHAR NOT NULL,
    PRIMARY KEY (policy_id, pattern)
);

-- Who a policy applies to: everyone, one account, the members of a group
-- (relation `member` on object type `group`), or the accounts whose active
-- claims satisfy a condition.
CREATE TABLE app_access_policy_targets (
    id UUID PRIMARY KEY,
    policy_id UUID NOT NULL REFERENCES app_access_policies(id) ON DELETE CASCADE,
    kind VARCHAR NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    group_name VARCHAR,
    claim_type VARCHAR,
    claim_operator VARCHAR,
    claim_value VARCHAR,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (
        (kind = 'everyone' AND user_id IS NULL AND group_name IS NULL
            AND claim_type IS NULL AND claim_operator IS NULL AND claim_value IS NULL)
        OR (kind = 'user' AND user_id IS NOT NULL AND group_name IS NULL
            AND claim_type IS NULL AND claim_operator IS NULL AND claim_value IS NULL)
        OR (kind = 'group' AND user_id IS NULL AND group_name IS NOT NULL
            AND claim_type IS NULL AND claim_operator IS NULL AND claim_value IS NULL)
        OR (kind = 'claim' AND user_id IS NULL AND group_name IS NULL
            AND claim_type IS NOT NULL
            AND claim_operator IN ('present', 'absent', 'equals', 'age_under', 'age_at_least'))
    )
);
CREATE INDEX app_access_policy_targets_policy_id_idx ON app_access_policy_targets(policy_id);
CREATE INDEX app_access_policy_targets_user_id_idx ON app_access_policy_targets(user_id);
