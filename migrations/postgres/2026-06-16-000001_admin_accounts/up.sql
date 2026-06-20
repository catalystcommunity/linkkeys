-- Admin accounts: a domain administrator that is NOT a real user. Admin accounts
-- have credentials + the admin relation but no presentable profile, and are
-- refused on the RP (app) login path — they administer the domain and "don't go
-- elsewhere". Existing admins are split into a normal user + a `<username>_admin`
-- admin account by a startup hook.
ALTER TABLE users ADD COLUMN is_admin_account BOOLEAN NOT NULL DEFAULT FALSE;
