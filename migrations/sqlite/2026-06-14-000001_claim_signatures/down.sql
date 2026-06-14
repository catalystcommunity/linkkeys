-- Forward-only (pre-alpha): the claim_signatures model fully supersedes the old
-- single-signature columns, and we never roll this back. No down migration.
SELECT 1;
