-- Operator-supplied per-locale claim-type labels/descriptions. Overrides the
-- built-in liblinkkeys i18n catalog (`claim.<type>.label` /
-- `claim.<type>.description`) for this domain's own claim-type registry, so
-- an operator can localize a custom claim type without a code change. See
-- crate::db::DbPool::resolved_label for the fallback chain (this table ->
-- built-in i18n catalog -> the base ClaimTypePolicy.label/description).
CREATE TABLE claim_type_label_i18n (
    claim_type VARCHAR NOT NULL REFERENCES claim_type_policies(claim_type) ON DELETE CASCADE,
    locale VARCHAR NOT NULL,
    label VARCHAR NOT NULL,
    description VARCHAR,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (claim_type, locale)
);

SELECT diesel_manage_updated_at('claim_type_label_i18n');
