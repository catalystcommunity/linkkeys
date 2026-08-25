ALTER TABLE account_challenges
ADD COLUMN required_credential_id TEXT REFERENCES auth_credentials(id);
