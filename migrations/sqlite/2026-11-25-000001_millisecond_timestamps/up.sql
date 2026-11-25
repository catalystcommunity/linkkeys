-- Store every timestamp at millisecond precision.
--
-- A JavaScript `Date` holds milliseconds, and the generated TypeScript codec
-- rejects a finer timestamp. The server wrote RFC 3339 text with up to nine
-- fraction digits. This rewrites a value with more than three digits in the
-- form the server now writes (`db_time::store`): three digits, or none when
-- they are all zero, then the original offset. Other values do not change.

UPDATE account_challenges SET expires_at = CASE WHEN substr(expires_at, 21, 3) = '000' THEN substr(expires_at, 1, 19) ELSE substr(expires_at, 1, 23) END
    || CASE WHEN expires_at LIKE '%Z' THEN 'Z' ELSE substr(expires_at, -6) END
WHERE expires_at LIKE '____-__-__T__:__:__.____%' AND (expires_at LIKE '%+00:00' OR expires_at LIKE '%Z');
UPDATE account_challenges SET consumed_at = CASE WHEN substr(consumed_at, 21, 3) = '000' THEN substr(consumed_at, 1, 19) ELSE substr(consumed_at, 1, 23) END
    || CASE WHEN consumed_at LIKE '%Z' THEN 'Z' ELSE substr(consumed_at, -6) END
WHERE consumed_at LIKE '____-__-__T__:__:__.____%' AND (consumed_at LIKE '%+00:00' OR consumed_at LIKE '%Z');
UPDATE account_challenges SET revoked_at = CASE WHEN substr(revoked_at, 21, 3) = '000' THEN substr(revoked_at, 1, 19) ELSE substr(revoked_at, 1, 23) END
    || CASE WHEN revoked_at LIKE '%Z' THEN 'Z' ELSE substr(revoked_at, -6) END
WHERE revoked_at LIKE '____-__-__T__:__:__.____%' AND (revoked_at LIKE '%+00:00' OR revoked_at LIKE '%Z');
UPDATE account_challenges SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE account_limits SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE act_as_grants SET series_issued_at = CASE WHEN substr(series_issued_at, 21, 3) = '000' THEN substr(series_issued_at, 1, 19) ELSE substr(series_issued_at, 1, 23) END
    || CASE WHEN series_issued_at LIKE '%Z' THEN 'Z' ELSE substr(series_issued_at, -6) END
WHERE series_issued_at LIKE '____-__-__T__:__:__.____%' AND (series_issued_at LIKE '%+00:00' OR series_issued_at LIKE '%Z');
UPDATE act_as_grants SET renewable_until = CASE WHEN substr(renewable_until, 21, 3) = '000' THEN substr(renewable_until, 1, 19) ELSE substr(renewable_until, 1, 23) END
    || CASE WHEN renewable_until LIKE '%Z' THEN 'Z' ELSE substr(renewable_until, -6) END
WHERE renewable_until LIKE '____-__-__T__:__:__.____%' AND (renewable_until LIKE '%+00:00' OR renewable_until LIKE '%Z');
UPDATE act_as_grants SET issued_at = CASE WHEN substr(issued_at, 21, 3) = '000' THEN substr(issued_at, 1, 19) ELSE substr(issued_at, 1, 23) END
    || CASE WHEN issued_at LIKE '%Z' THEN 'Z' ELSE substr(issued_at, -6) END
WHERE issued_at LIKE '____-__-__T__:__:__.____%' AND (issued_at LIKE '%+00:00' OR issued_at LIKE '%Z');
UPDATE act_as_grants SET expires_at = CASE WHEN substr(expires_at, 21, 3) = '000' THEN substr(expires_at, 1, 19) ELSE substr(expires_at, 1, 23) END
    || CASE WHEN expires_at LIKE '%Z' THEN 'Z' ELSE substr(expires_at, -6) END
WHERE expires_at LIKE '____-__-__T__:__:__.____%' AND (expires_at LIKE '%+00:00' OR expires_at LIKE '%Z');
UPDATE act_as_grants SET revoked_at = CASE WHEN substr(revoked_at, 21, 3) = '000' THEN substr(revoked_at, 1, 19) ELSE substr(revoked_at, 1, 23) END
    || CASE WHEN revoked_at LIKE '%Z' THEN 'Z' ELSE substr(revoked_at, -6) END
WHERE revoked_at LIKE '____-__-__T__:__:__.____%' AND (revoked_at LIKE '%+00:00' OR revoked_at LIKE '%Z');
UPDATE act_as_grants SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE act_as_grants SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE admin_review_queue SET resolved_at = CASE WHEN substr(resolved_at, 21, 3) = '000' THEN substr(resolved_at, 1, 19) ELSE substr(resolved_at, 1, 23) END
    || CASE WHEN resolved_at LIKE '%Z' THEN 'Z' ELSE substr(resolved_at, -6) END
WHERE resolved_at LIKE '____-__-__T__:__:__.____%' AND (resolved_at LIKE '%+00:00' OR resolved_at LIKE '%Z');
UPDATE admin_review_queue SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE admin_review_queue SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE app_access_policies SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE app_access_policies SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE app_access_policy_targets SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE application_instances SET enrolled_at = CASE WHEN substr(enrolled_at, 21, 3) = '000' THEN substr(enrolled_at, 1, 19) ELSE substr(enrolled_at, 1, 23) END
    || CASE WHEN enrolled_at LIKE '%Z' THEN 'Z' ELSE substr(enrolled_at, -6) END
WHERE enrolled_at LIKE '____-__-__T__:__:__.____%' AND (enrolled_at LIKE '%+00:00' OR enrolled_at LIKE '%Z');
UPDATE application_instances SET last_trust_reset_at = CASE WHEN substr(last_trust_reset_at, 21, 3) = '000' THEN substr(last_trust_reset_at, 1, 19) ELSE substr(last_trust_reset_at, 1, 23) END
    || CASE WHEN last_trust_reset_at LIKE '%Z' THEN 'Z' ELSE substr(last_trust_reset_at, -6) END
WHERE last_trust_reset_at LIKE '____-__-__T__:__:__.____%' AND (last_trust_reset_at LIKE '%+00:00' OR last_trust_reset_at LIKE '%Z');
UPDATE application_instances SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE application_instances SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE application_key_attestations SET attested_at = CASE WHEN substr(attested_at, 21, 3) = '000' THEN substr(attested_at, 1, 19) ELSE substr(attested_at, 1, 23) END
    || CASE WHEN attested_at LIKE '%Z' THEN 'Z' ELSE substr(attested_at, -6) END
WHERE attested_at LIKE '____-__-__T__:__:__.____%' AND (attested_at LIKE '%+00:00' OR attested_at LIKE '%Z');
UPDATE application_key_attestations SET expires_at = CASE WHEN substr(expires_at, 21, 3) = '000' THEN substr(expires_at, 1, 19) ELSE substr(expires_at, 1, 23) END
    || CASE WHEN expires_at LIKE '%Z' THEN 'Z' ELSE substr(expires_at, -6) END
WHERE expires_at LIKE '____-__-__T__:__:__.____%' AND (expires_at LIKE '%+00:00' OR expires_at LIKE '%Z');
UPDATE application_key_attestations SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE application_key_attestations SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE application_key_challenges SET expires_at = CASE WHEN substr(expires_at, 21, 3) = '000' THEN substr(expires_at, 1, 19) ELSE substr(expires_at, 1, 23) END
    || CASE WHEN expires_at LIKE '%Z' THEN 'Z' ELSE substr(expires_at, -6) END
WHERE expires_at LIKE '____-__-__T__:__:__.____%' AND (expires_at LIKE '%+00:00' OR expires_at LIKE '%Z');
UPDATE application_key_challenges SET consumed_at = CASE WHEN substr(consumed_at, 21, 3) = '000' THEN substr(consumed_at, 1, 19) ELSE substr(consumed_at, 1, 23) END
    || CASE WHEN consumed_at LIKE '%Z' THEN 'Z' ELSE substr(consumed_at, -6) END
WHERE consumed_at LIKE '____-__-__T__:__:__.____%' AND (consumed_at LIKE '%+00:00' OR consumed_at LIKE '%Z');
UPDATE application_key_challenges SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE application_key_revocations SET revoked_at = CASE WHEN substr(revoked_at, 21, 3) = '000' THEN substr(revoked_at, 1, 19) ELSE substr(revoked_at, 1, 23) END
    || CASE WHEN revoked_at LIKE '%Z' THEN 'Z' ELSE substr(revoked_at, -6) END
WHERE revoked_at LIKE '____-__-__T__:__:__.____%' AND (revoked_at LIKE '%+00:00' OR revoked_at LIKE '%Z');
UPDATE application_key_revocations SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE application_keys SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE application_keys SET expires_at = CASE WHEN substr(expires_at, 21, 3) = '000' THEN substr(expires_at, 1, 19) ELSE substr(expires_at, 1, 23) END
    || CASE WHEN expires_at LIKE '%Z' THEN 'Z' ELSE substr(expires_at, -6) END
WHERE expires_at LIKE '____-__-__T__:__:__.____%' AND (expires_at LIKE '%+00:00' OR expires_at LIKE '%Z');
UPDATE application_keys SET revoked_at = CASE WHEN substr(revoked_at, 21, 3) = '000' THEN substr(revoked_at, 1, 19) ELSE substr(revoked_at, 1, 23) END
    || CASE WHEN revoked_at LIKE '%Z' THEN 'Z' ELSE substr(revoked_at, -6) END
WHERE revoked_at LIKE '____-__-__T__:__:__.____%' AND (revoked_at LIKE '%+00:00' OR revoked_at LIKE '%Z');
UPDATE application_users SET last_seen_at = CASE WHEN substr(last_seen_at, 21, 3) = '000' THEN substr(last_seen_at, 1, 19) ELSE substr(last_seen_at, 1, 23) END
    || CASE WHEN last_seen_at LIKE '%Z' THEN 'Z' ELSE substr(last_seen_at, -6) END
WHERE last_seen_at LIKE '____-__-__T__:__:__.____%' AND (last_seen_at LIKE '%+00:00' OR last_seen_at LIKE '%Z');
UPDATE audit_log SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE auth_credentials SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE auth_credentials SET expires_at = CASE WHEN substr(expires_at, 21, 3) = '000' THEN substr(expires_at, 1, 19) ELSE substr(expires_at, 1, 23) END
    || CASE WHEN expires_at LIKE '%Z' THEN 'Z' ELSE substr(expires_at, -6) END
WHERE expires_at LIKE '____-__-__T__:__:__.____%' AND (expires_at LIKE '%+00:00' OR expires_at LIKE '%Z');
UPDATE auth_credentials SET revoked_at = CASE WHEN substr(revoked_at, 21, 3) = '000' THEN substr(revoked_at, 1, 19) ELSE substr(revoked_at, 1, 23) END
    || CASE WHEN revoked_at LIKE '%Z' THEN 'Z' ELSE substr(revoked_at, -6) END
WHERE revoked_at LIKE '____-__-__T__:__:__.____%' AND (revoked_at LIKE '%+00:00' OR revoked_at LIKE '%Z');
UPDATE auth_credentials SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE auth_credentials SET last_used_at = CASE WHEN substr(last_used_at, 21, 3) = '000' THEN substr(last_used_at, 1, 19) ELSE substr(last_used_at, 1, 23) END
    || CASE WHEN last_used_at LIKE '%Z' THEN 'Z' ELSE substr(last_used_at, -6) END
WHERE last_used_at LIKE '____-__-__T__:__:__.____%' AND (last_used_at LIKE '%+00:00' OR last_used_at LIKE '%Z');
UPDATE backup_keys SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE backup_keys SET rotated_at = CASE WHEN substr(rotated_at, 21, 3) = '000' THEN substr(rotated_at, 1, 19) ELSE substr(rotated_at, 1, 23) END
    || CASE WHEN rotated_at LIKE '%Z' THEN 'Z' ELSE substr(rotated_at, -6) END
WHERE rotated_at LIKE '____-__-__T__:__:__.____%' AND (rotated_at LIKE '%+00:00' OR rotated_at LIKE '%Z');
UPDATE browser_sessions SET issued_at = CASE WHEN substr(issued_at, 21, 3) = '000' THEN substr(issued_at, 1, 19) ELSE substr(issued_at, 1, 23) END
    || CASE WHEN issued_at LIKE '%Z' THEN 'Z' ELSE substr(issued_at, -6) END
WHERE issued_at LIKE '____-__-__T__:__:__.____%' AND (issued_at LIKE '%+00:00' OR issued_at LIKE '%Z');
UPDATE browser_sessions SET last_seen_at = CASE WHEN substr(last_seen_at, 21, 3) = '000' THEN substr(last_seen_at, 1, 19) ELSE substr(last_seen_at, 1, 23) END
    || CASE WHEN last_seen_at LIKE '%Z' THEN 'Z' ELSE substr(last_seen_at, -6) END
WHERE last_seen_at LIKE '____-__-__T__:__:__.____%' AND (last_seen_at LIKE '%+00:00' OR last_seen_at LIKE '%Z');
UPDATE browser_sessions SET authenticated_at = CASE WHEN substr(authenticated_at, 21, 3) = '000' THEN substr(authenticated_at, 1, 19) ELSE substr(authenticated_at, 1, 23) END
    || CASE WHEN authenticated_at LIKE '%Z' THEN 'Z' ELSE substr(authenticated_at, -6) END
WHERE authenticated_at LIKE '____-__-__T__:__:__.____%' AND (authenticated_at LIKE '%+00:00' OR authenticated_at LIKE '%Z');
UPDATE browser_sessions SET expires_at = CASE WHEN substr(expires_at, 21, 3) = '000' THEN substr(expires_at, 1, 19) ELSE substr(expires_at, 1, 23) END
    || CASE WHEN expires_at LIKE '%Z' THEN 'Z' ELSE substr(expires_at, -6) END
WHERE expires_at LIKE '____-__-__T__:__:__.____%' AND (expires_at LIKE '%+00:00' OR expires_at LIKE '%Z');
UPDATE browser_sessions SET revoked_at = CASE WHEN substr(revoked_at, 21, 3) = '000' THEN substr(revoked_at, 1, 19) ELSE substr(revoked_at, 1, 23) END
    || CASE WHEN revoked_at LIKE '%Z' THEN 'Z' ELSE substr(revoked_at, -6) END
WHERE revoked_at LIKE '____-__-__T__:__:__.____%' AND (revoked_at LIKE '%+00:00' OR revoked_at LIKE '%Z');
UPDATE browser_sessions SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE browser_sessions SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE claim_signatures SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE claim_type_label_i18n SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE claim_type_label_i18n SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE claim_type_policies SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE claim_type_policies SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE claims SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE claims SET expires_at = CASE WHEN substr(expires_at, 21, 3) = '000' THEN substr(expires_at, 1, 19) ELSE substr(expires_at, 1, 23) END
    || CASE WHEN expires_at LIKE '%Z' THEN 'Z' ELSE substr(expires_at, -6) END
WHERE expires_at LIKE '____-__-__T__:__:__.____%' AND (expires_at LIKE '%+00:00' OR expires_at LIKE '%Z');
UPDATE claims SET revoked_at = CASE WHEN substr(revoked_at, 21, 3) = '000' THEN substr(revoked_at, 1, 19) ELSE substr(revoked_at, 1, 23) END
    || CASE WHEN revoked_at LIKE '%Z' THEN 'Z' ELSE substr(revoked_at, -6) END
WHERE revoked_at LIKE '____-__-__T__:__:__.____%' AND (revoked_at LIKE '%+00:00' OR revoked_at LIKE '%Z');
UPDATE claims SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE claims SET attested_at = CASE WHEN substr(attested_at, 21, 3) = '000' THEN substr(attested_at, 1, 19) ELSE substr(attested_at, 1, 23) END
    || CASE WHEN attested_at LIKE '%Z' THEN 'Z' ELSE substr(attested_at, -6) END
WHERE attested_at LIKE '____-__-__T__:__:__.____%' AND (attested_at LIKE '%+00:00' OR attested_at LIKE '%Z');
UPDATE consent_grants SET issued_at = CASE WHEN substr(issued_at, 21, 3) = '000' THEN substr(issued_at, 1, 19) ELSE substr(issued_at, 1, 23) END
    || CASE WHEN issued_at LIKE '%Z' THEN 'Z' ELSE substr(issued_at, -6) END
WHERE issued_at LIKE '____-__-__T__:__:__.____%' AND (issued_at LIKE '%+00:00' OR issued_at LIKE '%Z');
UPDATE consent_grants SET expires_at = CASE WHEN substr(expires_at, 21, 3) = '000' THEN substr(expires_at, 1, 19) ELSE substr(expires_at, 1, 23) END
    || CASE WHEN expires_at LIKE '%Z' THEN 'Z' ELSE substr(expires_at, -6) END
WHERE expires_at LIKE '____-__-__T__:__:__.____%' AND (expires_at LIKE '%+00:00' OR expires_at LIKE '%Z');
UPDATE consent_grants SET revoked_at = CASE WHEN substr(revoked_at, 21, 3) = '000' THEN substr(revoked_at, 1, 19) ELSE substr(revoked_at, 1, 23) END
    || CASE WHEN revoked_at LIKE '%Z' THEN 'Z' ELSE substr(revoked_at, -6) END
WHERE revoked_at LIKE '____-__-__T__:__:__.____%' AND (revoked_at LIKE '%+00:00' OR revoked_at LIKE '%Z');
UPDATE consent_grants SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE consent_grants SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE domain_key_pins SET pinned_at = CASE WHEN substr(pinned_at, 21, 3) = '000' THEN substr(pinned_at, 1, 19) ELSE substr(pinned_at, 1, 23) END
    || CASE WHEN pinned_at LIKE '%Z' THEN 'Z' ELSE substr(pinned_at, -6) END
WHERE pinned_at LIKE '____-__-__T__:__:__.____%' AND (pinned_at LIKE '%+00:00' OR pinned_at LIKE '%Z');
UPDATE domain_key_pins SET last_checked_at = CASE WHEN substr(last_checked_at, 21, 3) = '000' THEN substr(last_checked_at, 1, 19) ELSE substr(last_checked_at, 1, 23) END
    || CASE WHEN last_checked_at LIKE '%Z' THEN 'Z' ELSE substr(last_checked_at, -6) END
WHERE last_checked_at LIKE '____-__-__T__:__:__.____%' AND (last_checked_at LIKE '%+00:00' OR last_checked_at LIKE '%Z');
UPDATE domain_keys SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE domain_keys SET expires_at = CASE WHEN substr(expires_at, 21, 3) = '000' THEN substr(expires_at, 1, 19) ELSE substr(expires_at, 1, 23) END
    || CASE WHEN expires_at LIKE '%Z' THEN 'Z' ELSE substr(expires_at, -6) END
WHERE expires_at LIKE '____-__-__T__:__:__.____%' AND (expires_at LIKE '%+00:00' OR expires_at LIKE '%Z');
UPDATE domain_keys SET revoked_at = CASE WHEN substr(revoked_at, 21, 3) = '000' THEN substr(revoked_at, 1, 19) ELSE substr(revoked_at, 1, 23) END
    || CASE WHEN revoked_at LIKE '%Z' THEN 'Z' ELSE substr(revoked_at, -6) END
WHERE revoked_at LIKE '____-__-__T__:__:__.____%' AND (revoked_at LIKE '%+00:00' OR revoked_at LIKE '%Z');
UPDATE domain_keys SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE guestbook_entries SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE guestbook_entries SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE issued_revocations SET revoked_at = CASE WHEN substr(revoked_at, 21, 3) = '000' THEN substr(revoked_at, 1, 19) ELSE substr(revoked_at, 1, 23) END
    || CASE WHEN revoked_at LIKE '%Z' THEN 'Z' ELSE substr(revoked_at, -6) END
WHERE revoked_at LIKE '____-__-__T__:__:__.____%' AND (revoked_at LIKE '%+00:00' OR revoked_at LIKE '%Z');
UPDATE issued_revocations SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE local_rp_claim_tickets SET issued_at = CASE WHEN substr(issued_at, 21, 3) = '000' THEN substr(issued_at, 1, 19) ELSE substr(issued_at, 1, 23) END
    || CASE WHEN issued_at LIKE '%Z' THEN 'Z' ELSE substr(issued_at, -6) END
WHERE issued_at LIKE '____-__-__T__:__:__.____%' AND (issued_at LIKE '%+00:00' OR issued_at LIKE '%Z');
UPDATE local_rp_claim_tickets SET expires_at = CASE WHEN substr(expires_at, 21, 3) = '000' THEN substr(expires_at, 1, 19) ELSE substr(expires_at, 1, 23) END
    || CASE WHEN expires_at LIKE '%Z' THEN 'Z' ELSE substr(expires_at, -6) END
WHERE expires_at LIKE '____-__-__T__:__:__.____%' AND (expires_at LIKE '%+00:00' OR expires_at LIKE '%Z');
UPDATE local_rp_domain_policy SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE local_rps SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE local_rps SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE local_rps SET expires_at = CASE WHEN substr(expires_at, 21, 3) = '000' THEN substr(expires_at, 1, 19) ELSE substr(expires_at, 1, 23) END
    || CASE WHEN expires_at LIKE '%Z' THEN 'Z' ELSE substr(expires_at, -6) END
WHERE expires_at LIKE '____-__-__T__:__:__.____%' AND (expires_at LIKE '%+00:00' OR expires_at LIKE '%Z');
UPDATE local_rps SET last_seen_at = CASE WHEN substr(last_seen_at, 21, 3) = '000' THEN substr(last_seen_at, 1, 19) ELSE substr(last_seen_at, 1, 23) END
    || CASE WHEN last_seen_at LIKE '%Z' THEN 'Z' ELSE substr(last_seen_at, -6) END
WHERE last_seen_at LIKE '____-__-__T__:__:__.____%' AND (last_seen_at LIKE '%+00:00' OR last_seen_at LIKE '%Z');
UPDATE notification_outbox SET next_attempt_at = CASE WHEN substr(next_attempt_at, 21, 3) = '000' THEN substr(next_attempt_at, 1, 19) ELSE substr(next_attempt_at, 1, 23) END
    || CASE WHEN next_attempt_at LIKE '%Z' THEN 'Z' ELSE substr(next_attempt_at, -6) END
WHERE next_attempt_at LIKE '____-__-__T__:__:__.____%' AND (next_attempt_at LIKE '%+00:00' OR next_attempt_at LIKE '%Z');
UPDATE notification_outbox SET lease_expires_at = CASE WHEN substr(lease_expires_at, 21, 3) = '000' THEN substr(lease_expires_at, 1, 19) ELSE substr(lease_expires_at, 1, 23) END
    || CASE WHEN lease_expires_at LIKE '%Z' THEN 'Z' ELSE substr(lease_expires_at, -6) END
WHERE lease_expires_at LIKE '____-__-__T__:__:__.____%' AND (lease_expires_at LIKE '%+00:00' OR lease_expires_at LIKE '%Z');
UPDATE notification_outbox SET expires_at = CASE WHEN substr(expires_at, 21, 3) = '000' THEN substr(expires_at, 1, 19) ELSE substr(expires_at, 1, 23) END
    || CASE WHEN expires_at LIKE '%Z' THEN 'Z' ELSE substr(expires_at, -6) END
WHERE expires_at LIKE '____-__-__T__:__:__.____%' AND (expires_at LIKE '%+00:00' OR expires_at LIKE '%Z');
UPDATE notification_outbox SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE notification_outbox SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE peer_keys SET first_seen = CASE WHEN substr(first_seen, 21, 3) = '000' THEN substr(first_seen, 1, 19) ELSE substr(first_seen, 1, 23) END
    || CASE WHEN first_seen LIKE '%Z' THEN 'Z' ELSE substr(first_seen, -6) END
WHERE first_seen LIKE '____-__-__T__:__:__.____%' AND (first_seen LIKE '%+00:00' OR first_seen LIKE '%Z');
UPDATE profile_claim_prefs SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE profile_claim_prefs SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE profiles SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE profiles SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE relations SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE relations SET removed_at = CASE WHEN substr(removed_at, 21, 3) = '000' THEN substr(removed_at, 1, 19) ELSE substr(removed_at, 1, 23) END
    || CASE WHEN removed_at LIKE '%Z' THEN 'Z' ELSE substr(removed_at, -6) END
WHERE removed_at LIKE '____-__-__T__:__:__.____%' AND (removed_at LIKE '%+00:00' OR removed_at LIKE '%Z');
UPDATE relations SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE release_policies SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE release_policies SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE rp_application_key_attestations SET attestation_expires_at = CASE WHEN substr(attestation_expires_at, 21, 3) = '000' THEN substr(attestation_expires_at, 1, 19) ELSE substr(attestation_expires_at, 1, 23) END
    || CASE WHEN attestation_expires_at LIKE '%Z' THEN 'Z' ELSE substr(attestation_expires_at, -6) END
WHERE attestation_expires_at LIKE '____-__-__T__:__:__.____%' AND (attestation_expires_at LIKE '%+00:00' OR attestation_expires_at LIKE '%Z');
UPDATE rp_application_key_attestations SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE rp_application_key_attestations SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE rp_application_key_cache_entries SET fetched_at = CASE WHEN substr(fetched_at, 21, 3) = '000' THEN substr(fetched_at, 1, 19) ELSE substr(fetched_at, 1, 23) END
    || CASE WHEN fetched_at LIKE '%Z' THEN 'Z' ELSE substr(fetched_at, -6) END
WHERE fetched_at LIKE '____-__-__T__:__:__.____%' AND (fetched_at LIKE '%+00:00' OR fetched_at LIKE '%Z');
UPDATE rp_application_key_cache_entries SET revocations_checked_at = CASE WHEN substr(revocations_checked_at, 21, 3) = '000' THEN substr(revocations_checked_at, 1, 19) ELSE substr(revocations_checked_at, 1, 23) END
    || CASE WHEN revocations_checked_at LIKE '%Z' THEN 'Z' ELSE substr(revocations_checked_at, -6) END
WHERE revocations_checked_at LIKE '____-__-__T__:__:__.____%' AND (revocations_checked_at LIKE '%+00:00' OR revocations_checked_at LIKE '%Z');
UPDATE rp_application_key_cache_entries SET last_used_at = CASE WHEN substr(last_used_at, 21, 3) = '000' THEN substr(last_used_at, 1, 19) ELSE substr(last_used_at, 1, 23) END
    || CASE WHEN last_used_at LIKE '%Z' THEN 'Z' ELSE substr(last_used_at, -6) END
WHERE last_used_at LIKE '____-__-__T__:__:__.____%' AND (last_used_at LIKE '%+00:00' OR last_used_at LIKE '%Z');
UPDATE rp_application_key_cache_entries SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE rp_application_key_cache_entries SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE rp_application_key_revocations SET revoked_at = CASE WHEN substr(revoked_at, 21, 3) = '000' THEN substr(revoked_at, 1, 19) ELSE substr(revoked_at, 1, 23) END
    || CASE WHEN revoked_at LIKE '%Z' THEN 'Z' ELSE substr(revoked_at, -6) END
WHERE revoked_at LIKE '____-__-__T__:__:__.____%' AND (revoked_at LIKE '%+00:00' OR revoked_at LIKE '%Z');
UPDATE rp_application_key_revocations SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE rp_domain_key_cache SET fetched_at = CASE WHEN substr(fetched_at, 21, 3) = '000' THEN substr(fetched_at, 1, 19) ELSE substr(fetched_at, 1, 23) END
    || CASE WHEN fetched_at LIKE '%Z' THEN 'Z' ELSE substr(fetched_at, -6) END
WHERE fetched_at LIKE '____-__-__T__:__:__.____%' AND (fetched_at LIKE '%+00:00' OR fetched_at LIKE '%Z');
UPDATE rp_domain_key_cache SET revocations_checked_at = CASE WHEN substr(revocations_checked_at, 21, 3) = '000' THEN substr(revocations_checked_at, 1, 19) ELSE substr(revocations_checked_at, 1, 23) END
    || CASE WHEN revocations_checked_at LIKE '%Z' THEN 'Z' ELSE substr(revocations_checked_at, -6) END
WHERE revocations_checked_at LIKE '____-__-__T__:__:__.____%' AND (revocations_checked_at LIKE '%+00:00' OR revocations_checked_at LIKE '%Z');
UPDATE rp_domain_key_cache SET last_used_at = CASE WHEN substr(last_used_at, 21, 3) = '000' THEN substr(last_used_at, 1, 19) ELSE substr(last_used_at, 1, 23) END
    || CASE WHEN last_used_at LIKE '%Z' THEN 'Z' ELSE substr(last_used_at, -6) END
WHERE last_used_at LIKE '____-__-__T__:__:__.____%' AND (last_used_at LIKE '%+00:00' OR last_used_at LIKE '%Z');
UPDATE rp_domain_key_cache SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE rp_domain_key_cache SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE rp_login_nonces SET expires_at = CASE WHEN substr(expires_at, 21, 3) = '000' THEN substr(expires_at, 1, 19) ELSE substr(expires_at, 1, 23) END
    || CASE WHEN expires_at LIKE '%Z' THEN 'Z' ELSE substr(expires_at, -6) END
WHERE expires_at LIKE '____-__-__T__:__:__.____%' AND (expires_at LIKE '%+00:00' OR expires_at LIKE '%Z');
UPDATE sign_in_policy SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE trusted_issuers SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE used_nonces SET expires_at = CASE WHEN substr(expires_at, 21, 3) = '000' THEN substr(expires_at, 1, 19) ELSE substr(expires_at, 1, 23) END
    || CASE WHEN expires_at LIKE '%Z' THEN 'Z' ELSE substr(expires_at, -6) END
WHERE expires_at LIKE '____-__-__T__:__:__.____%' AND (expires_at LIKE '%+00:00' OR expires_at LIKE '%Z');
UPDATE user_authentication_activity SET last_authenticated_at = CASE WHEN substr(last_authenticated_at, 21, 3) = '000' THEN substr(last_authenticated_at, 1, 19) ELSE substr(last_authenticated_at, 1, 23) END
    || CASE WHEN last_authenticated_at LIKE '%Z' THEN 'Z' ELSE substr(last_authenticated_at, -6) END
WHERE last_authenticated_at LIKE '____-__-__T__:__:__.____%' AND (last_authenticated_at LIKE '%+00:00' OR last_authenticated_at LIKE '%Z');
UPDATE user_authentication_activity SET last_seen_at = CASE WHEN substr(last_seen_at, 21, 3) = '000' THEN substr(last_seen_at, 1, 19) ELSE substr(last_seen_at, 1, 23) END
    || CASE WHEN last_seen_at LIKE '%Z' THEN 'Z' ELSE substr(last_seen_at, -6) END
WHERE last_seen_at LIKE '____-__-__T__:__:__.____%' AND (last_seen_at LIKE '%+00:00' OR last_seen_at LIKE '%Z');
UPDATE user_authentication_activity SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE user_authentication_activity SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE user_keys SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE user_keys SET expires_at = CASE WHEN substr(expires_at, 21, 3) = '000' THEN substr(expires_at, 1, 19) ELSE substr(expires_at, 1, 23) END
    || CASE WHEN expires_at LIKE '%Z' THEN 'Z' ELSE substr(expires_at, -6) END
WHERE expires_at LIKE '____-__-__T__:__:__.____%' AND (expires_at LIKE '%+00:00' OR expires_at LIKE '%Z');
UPDATE user_keys SET revoked_at = CASE WHEN substr(revoked_at, 21, 3) = '000' THEN substr(revoked_at, 1, 19) ELSE substr(revoked_at, 1, 23) END
    || CASE WHEN revoked_at LIKE '%Z' THEN 'Z' ELSE substr(revoked_at, -6) END
WHERE revoked_at LIKE '____-__-__T__:__:__.____%' AND (revoked_at LIKE '%+00:00' OR revoked_at LIKE '%Z');
UPDATE user_keys SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE user_release_prefs SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE users SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE users SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
UPDATE users SET purged_at = CASE WHEN substr(purged_at, 21, 3) = '000' THEN substr(purged_at, 1, 19) ELSE substr(purged_at, 1, 23) END
    || CASE WHEN purged_at LIKE '%Z' THEN 'Z' ELSE substr(purged_at, -6) END
WHERE purged_at LIKE '____-__-__T__:__:__.____%' AND (purged_at LIKE '%+00:00' OR purged_at LIKE '%Z');
UPDATE verified_contact_methods SET verified_at = CASE WHEN substr(verified_at, 21, 3) = '000' THEN substr(verified_at, 1, 19) ELSE substr(verified_at, 1, 23) END
    || CASE WHEN verified_at LIKE '%Z' THEN 'Z' ELSE substr(verified_at, -6) END
WHERE verified_at LIKE '____-__-__T__:__:__.____%' AND (verified_at LIKE '%+00:00' OR verified_at LIKE '%Z');
UPDATE verified_contact_methods SET revoked_at = CASE WHEN substr(revoked_at, 21, 3) = '000' THEN substr(revoked_at, 1, 19) ELSE substr(revoked_at, 1, 23) END
    || CASE WHEN revoked_at LIKE '%Z' THEN 'Z' ELSE substr(revoked_at, -6) END
WHERE revoked_at LIKE '____-__-__T__:__:__.____%' AND (revoked_at LIKE '%+00:00' OR revoked_at LIKE '%Z');
UPDATE verified_contact_methods SET created_at = CASE WHEN substr(created_at, 21, 3) = '000' THEN substr(created_at, 1, 19) ELSE substr(created_at, 1, 23) END
    || CASE WHEN created_at LIKE '%Z' THEN 'Z' ELSE substr(created_at, -6) END
WHERE created_at LIKE '____-__-__T__:__:__.____%' AND (created_at LIKE '%+00:00' OR created_at LIKE '%Z');
UPDATE verified_contact_methods SET updated_at = CASE WHEN substr(updated_at, 21, 3) = '000' THEN substr(updated_at, 1, 19) ELSE substr(updated_at, 1, 23) END
    || CASE WHEN updated_at LIKE '%Z' THEN 'Z' ELSE substr(updated_at, -6) END
WHERE updated_at LIKE '____-__-__T__:__:__.____%' AND (updated_at LIKE '%+00:00' OR updated_at LIKE '%Z');
