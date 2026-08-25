ALTER TABLE account_challenges
ADD COLUMN required_credential_id UUID REFERENCES auth_credentials(id);
