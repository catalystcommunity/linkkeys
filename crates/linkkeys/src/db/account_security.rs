//! Persistence for browser sessions, verified contacts, account challenges, and
//! durable notification intents.

#[cfg(feature = "postgres")]
pub mod pg {
    use diesel::prelude::*;

    use crate::db::models::pg::{
        AccountChallengeRow, BrowserSessionRow, NotificationOutboxRow, VerifiedContactMethodRow,
    };
    use crate::db::models::{AccountChallenge, BrowserSession, User, VerifiedContactMethod};
    use crate::schema::pg::{
        account_challenges, auth_credentials, browser_sessions, claims, notification_outbox, users,
        verified_contact_methods,
    };

    #[allow(clippy::too_many_arguments)]
    pub fn create_challenge_and_outbox(
        conn: &mut diesel::PgConnection,
        user_id: uuid::Uuid,
        kind: &str,
        channel: &str,
        destination: &str,
        token_digest: &str,
        encrypted_payload: Vec<u8>,
        expires_at: chrono::DateTime<chrono::Utc>,
        required_credential_id: Option<uuid::Uuid>,
    ) -> QueryResult<AccountChallenge> {
        conn.transaction(|conn| {
            let now = chrono::Utc::now();
            // Serialize challenge replacement for one account. Without this
            // lock, two requests can both insert an active challenge.
            let active_user = users::table
                .find(user_id)
                .select((users::is_active, users::purged_at))
                .for_update()
                .first::<(bool, Option<chrono::DateTime<chrono::Utc>>)>(conn)?;
            if !active_user.0 || active_user.1.is_some() {
                return Err(diesel::result::Error::NotFound);
            }
            if kind == "reset_password" {
                let purposes = verified_contact_methods::table
                    .filter(verified_contact_methods::user_id.eq(user_id))
                    .filter(verified_contact_methods::channel.eq(channel))
                    .filter(verified_contact_methods::destination.eq(destination))
                    .filter(verified_contact_methods::revoked_at.is_null())
                    .select(verified_contact_methods::purposes)
                    .first::<String>(conn)?;
                if !purposes.split(',').any(|value| value == "reset_password") {
                    return Err(diesel::result::Error::NotFound);
                }
            }
            if let Some(credential_id) = required_credential_id {
                auth_credentials::table
                    .find(credential_id)
                    .filter(auth_credentials::user_id.eq(user_id))
                    .filter(auth_credentials::credential_type.eq("password"))
                    .filter(auth_credentials::revoked_at.is_null())
                    .filter(
                        auth_credentials::expires_at
                            .is_null()
                            .or(auth_credentials::expires_at.gt(now)),
                    )
                    .select(auth_credentials::id)
                    .first::<uuid::Uuid>(conn)?;
            }
            diesel::update(
                account_challenges::table
                    .filter(account_challenges::user_id.eq(user_id))
                    .filter(account_challenges::kind.eq(kind))
                    .filter(account_challenges::consumed_at.is_null())
                    .filter(account_challenges::revoked_at.is_null()),
            )
            .set(account_challenges::revoked_at.eq(Some(now)))
            .execute(conn)?;
            diesel::update(
                notification_outbox::table
                    .filter(notification_outbox::user_id.eq(user_id))
                    .filter(notification_outbox::purpose.eq(kind))
                    .filter(notification_outbox::state.eq_any(["pending", "leased"])),
            )
            .set((
                notification_outbox::state.eq("superseded"),
                notification_outbox::encrypted_payload.eq::<Option<Vec<u8>>>(None),
                notification_outbox::lease_owner.eq::<Option<String>>(None),
                notification_outbox::lease_expires_at
                    .eq::<Option<chrono::DateTime<chrono::Utc>>>(None),
                notification_outbox::last_error.eq(Some("superseded")),
                notification_outbox::updated_at.eq(now),
            ))
            .execute(conn)?;

            let row = AccountChallengeRow {
                id: uuid::Uuid::now_v7(),
                token_digest: token_digest.to_string(),
                user_id,
                kind: kind.to_string(),
                channel: channel.to_string(),
                destination: destination.to_string(),
                required_credential_id,
                expires_at,
                consumed_at: None,
                revoked_at: None,
                created_at: now,
            };
            diesel::insert_into(account_challenges::table)
                .values(&row)
                .execute(conn)?;
            diesel::insert_into(notification_outbox::table)
                .values(NotificationOutboxRow {
                    id: uuid::Uuid::now_v7(),
                    user_id,
                    purpose: kind.to_string(),
                    channel: channel.to_string(),
                    destination: destination.to_string(),
                    encrypted_payload: Some(encrypted_payload),
                    state: "pending".to_string(),
                    attempt_count: 0,
                    next_attempt_at: now,
                    lease_owner: None,
                    lease_expires_at: None,
                    last_error: None,
                    expires_at,
                    created_at: now,
                    updated_at: now,
                })
                .execute(conn)?;
            Ok(row.into())
        })
    }

    pub fn find_challenge(
        conn: &mut diesel::PgConnection,
        token_digest: &str,
        kind: &str,
    ) -> QueryResult<Option<AccountChallenge>> {
        account_challenges::table
            .filter(account_challenges::token_digest.eq(token_digest))
            .filter(account_challenges::kind.eq(kind))
            .filter(account_challenges::consumed_at.is_null())
            .filter(account_challenges::revoked_at.is_null())
            .filter(account_challenges::expires_at.gt(chrono::Utc::now()))
            .select(AccountChallengeRow::as_select())
            .first(conn)
            .optional()
            .map(|v| v.map(Into::into))
    }

    pub fn confirm_contact(
        conn: &mut diesel::PgConnection,
        challenge_id: &str,
        claims: &[crate::db::models::PreparedClaim],
    ) -> QueryResult<VerifiedContactMethod> {
        let challenge_id: uuid::Uuid = challenge_id
            .parse()
            .map_err(|_| diesel::result::Error::NotFound)?;
        conn.transaction(|conn| {
            let now = chrono::Utc::now();
            let candidate = account_challenges::table
                .find(challenge_id)
                .filter(account_challenges::kind.eq("verify_contact"))
                .filter(account_challenges::consumed_at.is_null())
                .filter(account_challenges::revoked_at.is_null())
                .filter(account_challenges::expires_at.gt(now))
                .select(AccountChallengeRow::as_select())
                .first::<AccountChallengeRow>(conn)?;
            let active_user = users::table
                .find(candidate.user_id)
                .select((users::is_active, users::purged_at))
                .for_update()
                .first::<(bool, Option<chrono::DateTime<chrono::Utc>>)>(conn)?;
            if !active_user.0 || active_user.1.is_some() {
                return Err(diesel::result::Error::NotFound);
            }
            let challenge = account_challenges::table
                .find(challenge_id)
                .filter(account_challenges::kind.eq("verify_contact"))
                .filter(account_challenges::consumed_at.is_null())
                .filter(account_challenges::revoked_at.is_null())
                .filter(account_challenges::expires_at.gt(now))
                .for_update()
                .select(AccountChallengeRow::as_select())
                .first::<AccountChallengeRow>(conn)?;
            if let Some(credential_id) = challenge.required_credential_id {
                auth_credentials::table
                    .find(credential_id)
                    .filter(auth_credentials::user_id.eq(challenge.user_id))
                    .filter(auth_credentials::credential_type.eq("password"))
                    .filter(auth_credentials::revoked_at.is_null())
                    .filter(
                        auth_credentials::expires_at
                            .is_null()
                            .or(auth_credentials::expires_at.gt(now)),
                    )
                    .select(auth_credentials::id)
                    .first::<uuid::Uuid>(conn)?;
            }
            for claim in claims {
                crate::db::claims::pg::replace_active_of_type(
                    conn,
                    claim
                        .id
                        .parse()
                        .map_err(|_| diesel::result::Error::NotFound)?,
                    challenge.user_id,
                    &claim.claim_type,
                    &claim.claim_value,
                    &claim.signatures,
                    None,
                    claim.attested_at,
                )?;
            }
            diesel::update(account_challenges::table.find(challenge_id))
                .set(account_challenges::consumed_at.eq(Some(now)))
                .execute(conn)?;
            diesel::update(
                verified_contact_methods::table
                    .filter(verified_contact_methods::user_id.eq(challenge.user_id))
                    .filter(verified_contact_methods::channel.eq(&challenge.channel))
                    .filter(verified_contact_methods::revoked_at.is_null()),
            )
            .set((
                verified_contact_methods::revoked_at.eq(Some(now)),
                verified_contact_methods::updated_at.eq(now),
            ))
            .execute(conn)?;
            let row = VerifiedContactMethodRow {
                id: uuid::Uuid::now_v7(),
                user_id: challenge.user_id,
                channel: challenge.channel,
                destination: challenge.destination,
                purposes: "verify_contact,reset_password".to_string(),
                verified_at: now,
                revoked_at: None,
                created_at: now,
                updated_at: now,
            };
            diesel::insert_into(verified_contact_methods::table)
                .values(&row)
                .execute(conn)?;
            Ok(row.into())
        })
    }

    pub fn list_contacts(
        conn: &mut diesel::PgConnection,
        user_id: uuid::Uuid,
    ) -> QueryResult<Vec<VerifiedContactMethod>> {
        verified_contact_methods::table
            .filter(verified_contact_methods::user_id.eq(user_id))
            .filter(verified_contact_methods::revoked_at.is_null())
            .order(verified_contact_methods::verified_at.asc())
            .select(VerifiedContactMethodRow::as_select())
            .load(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn revoke_contact(
        conn: &mut diesel::PgConnection,
        user_id: uuid::Uuid,
        contact_id: uuid::Uuid,
        credential_id: uuid::Uuid,
    ) -> QueryResult<usize> {
        conn.transaction(|conn| {
            let now = chrono::Utc::now();
            users::table
                .find(user_id)
                .filter(users::purged_at.is_null())
                .select(users::id)
                .for_update()
                .first::<uuid::Uuid>(conn)?;
            auth_credentials::table
                .find(credential_id)
                .filter(auth_credentials::user_id.eq(user_id))
                .filter(auth_credentials::credential_type.eq("password"))
                .filter(auth_credentials::revoked_at.is_null())
                .filter(
                    auth_credentials::expires_at
                        .is_null()
                        .or(auth_credentials::expires_at.gt(now)),
                )
                .select(auth_credentials::id)
                .first::<uuid::Uuid>(conn)?;
            let contact = verified_contact_methods::table
                .find(contact_id)
                .filter(verified_contact_methods::user_id.eq(user_id))
                .filter(verified_contact_methods::revoked_at.is_null())
                .select(VerifiedContactMethodRow::as_select())
                .first::<VerifiedContactMethodRow>(conn)
                .optional()?;
            let Some(contact) = contact else {
                return Ok(0);
            };
            let changed = diesel::update(
                verified_contact_methods::table
                    .find(contact_id)
                    .filter(verified_contact_methods::user_id.eq(user_id))
                    .filter(verified_contact_methods::revoked_at.is_null()),
            )
            .set((
                verified_contact_methods::revoked_at.eq(Some(now)),
                verified_contact_methods::updated_at.eq(now),
            ))
            .execute(conn)?;
            if changed == 1 {
                diesel::update(
                    account_challenges::table
                        .filter(account_challenges::user_id.eq(user_id))
                        .filter(account_challenges::kind.eq("reset_password"))
                        .filter(account_challenges::consumed_at.is_null())
                        .filter(account_challenges::revoked_at.is_null()),
                )
                .set(account_challenges::revoked_at.eq(Some(now)))
                .execute(conn)?;
                diesel::update(
                    notification_outbox::table
                        .filter(notification_outbox::user_id.eq(user_id))
                        .filter(notification_outbox::purpose.eq("reset_password"))
                        .filter(notification_outbox::state.eq_any(["pending", "leased"])),
                )
                .set((
                    notification_outbox::state.eq("superseded"),
                    notification_outbox::encrypted_payload.eq::<Option<Vec<u8>>>(None),
                    notification_outbox::lease_owner.eq::<Option<String>>(None),
                    notification_outbox::lease_expires_at
                        .eq::<Option<chrono::DateTime<chrono::Utc>>>(None),
                    notification_outbox::last_error.eq(Some("superseded")),
                    notification_outbox::updated_at.eq(now),
                ))
                .execute(conn)?;
                if contact.channel == "email" {
                    diesel::update(
                        claims::table
                            .filter(claims::user_id.eq(user_id))
                            .filter(claims::revoked_at.is_null())
                            .filter(
                                claims::claim_type
                                    .eq("email_verified")
                                    .or(claims::claim_type.eq("email").and(
                                        claims::claim_value.eq(contact.destination.into_bytes()),
                                    )),
                            ),
                    )
                    .set((claims::revoked_at.eq(Some(now)), claims::updated_at.eq(now)))
                    .execute(conn)?;
                }
            }
            Ok(changed)
        })
    }

    pub fn deactivate_account(
        conn: &mut diesel::PgConnection,
        user_id: uuid::Uuid,
    ) -> QueryResult<User> {
        conn.transaction(|conn| {
            let target = users::table
                .find(user_id)
                .for_update()
                .select(crate::db::models::pg::UserRow::as_select())
                .first::<crate::db::models::pg::UserRow>(conn)?;
            if target.is_admin_account {
                let active_admins = users::table
                    .filter(users::is_admin_account.eq(true))
                    .filter(users::is_active.eq(true))
                    .filter(users::purged_at.is_null())
                    .select(users::id)
                    .for_update()
                    .load::<uuid::Uuid>(conn)?;
                if active_admins.len() <= 1 {
                    return Err(diesel::result::Error::NotFound);
                }
            }
            let now = chrono::Utc::now();
            let user = diesel::update(users::table.find(user_id))
                .set((users::is_active.eq(false), users::updated_at.eq(now)))
                .get_result::<crate::db::models::pg::UserRow>(conn)?;
            diesel::update(
                auth_credentials::table
                    .filter(auth_credentials::user_id.eq(user_id))
                    .filter(auth_credentials::revoked_at.is_null()),
            )
            .set((
                auth_credentials::revoked_at.eq(Some(now)),
                auth_credentials::updated_at.eq(now),
            ))
            .execute(conn)?;
            diesel::update(
                browser_sessions::table
                    .filter(browser_sessions::user_id.eq(user_id))
                    .filter(browser_sessions::revoked_at.is_null()),
            )
            .set((
                browser_sessions::revoked_at.eq(Some(now)),
                browser_sessions::updated_at.eq(now),
            ))
            .execute(conn)?;
            diesel::update(
                account_challenges::table
                    .filter(account_challenges::user_id.eq(user_id))
                    .filter(account_challenges::consumed_at.is_null())
                    .filter(account_challenges::revoked_at.is_null()),
            )
            .set(account_challenges::revoked_at.eq(Some(now)))
            .execute(conn)?;
            diesel::update(
                notification_outbox::table
                    .filter(notification_outbox::user_id.eq(user_id))
                    .filter(notification_outbox::state.eq_any(["pending", "leased"])),
            )
            .set((
                notification_outbox::state.eq("superseded"),
                notification_outbox::encrypted_payload.eq::<Option<Vec<u8>>>(None),
                notification_outbox::lease_owner.eq::<Option<String>>(None),
                notification_outbox::lease_expires_at
                    .eq::<Option<chrono::DateTime<chrono::Utc>>>(None),
                notification_outbox::last_error.eq(Some("account_disabled")),
                notification_outbox::updated_at.eq(now),
            ))
            .execute(conn)?;
            Ok(user.into())
        })
    }

    pub fn find_recovery_contact(
        conn: &mut diesel::PgConnection,
        destination: &str,
    ) -> QueryResult<Option<VerifiedContactMethod>> {
        verified_contact_methods::table
            .filter(verified_contact_methods::channel.eq("email"))
            .filter(verified_contact_methods::destination.eq(destination))
            .filter(verified_contact_methods::revoked_at.is_null())
            .order(verified_contact_methods::verified_at.desc())
            .select(VerifiedContactMethodRow::as_select())
            .first(conn)
            .optional()
            .map(|v| v.map(Into::into))
    }

    pub fn create_session(
        conn: &mut diesel::PgConnection,
        row: BrowserSessionRow,
    ) -> QueryResult<BrowserSession> {
        diesel::insert_into(browser_sessions::table)
            .values(&row)
            .execute(conn)?;
        Ok(row.into())
    }

    pub fn create_session_if_password_active(
        conn: &mut diesel::PgConnection,
        row: BrowserSessionRow,
        credential_id: uuid::Uuid,
    ) -> QueryResult<BrowserSession> {
        conn.transaction(|conn| {
            let now = chrono::Utc::now();
            let active_user = users::table
                .find(row.user_id)
                .select((users::is_active, users::purged_at))
                .for_update()
                .first::<(bool, Option<chrono::DateTime<chrono::Utc>>)>(conn)?;
            if !active_user.0 || active_user.1.is_some() {
                return Err(diesel::result::Error::NotFound);
            }
            auth_credentials::table
                .find(credential_id)
                .filter(auth_credentials::user_id.eq(row.user_id))
                .filter(auth_credentials::credential_type.eq("password"))
                .filter(auth_credentials::revoked_at.is_null())
                .filter(
                    auth_credentials::expires_at
                        .is_null()
                        .or(auth_credentials::expires_at.gt(now)),
                )
                .select(auth_credentials::id)
                .first::<uuid::Uuid>(conn)?;
            create_session(conn, row)
        })
    }

    pub fn find_session(
        conn: &mut diesel::PgConnection,
        digest: &str,
    ) -> QueryResult<Option<BrowserSession>> {
        browser_sessions::table
            .find(digest)
            .filter(browser_sessions::revoked_at.is_null())
            .filter(browser_sessions::expires_at.gt(chrono::Utc::now()))
            .select(BrowserSessionRow::as_select())
            .first(conn)
            .optional()
            .map(|v| v.map(Into::into))
    }

    pub fn touch_session(
        conn: &mut diesel::PgConnection,
        digest: &str,
        last_seen: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<usize> {
        diesel::update(
            browser_sessions::table
                .find(digest)
                .filter(browser_sessions::revoked_at.is_null()),
        )
        .set((
            browser_sessions::last_seen_at.eq(last_seen),
            browser_sessions::updated_at.eq(last_seen),
        ))
        .execute(conn)
    }

    pub fn revoke_session(conn: &mut diesel::PgConnection, digest: &str) -> QueryResult<usize> {
        let now = chrono::Utc::now();
        diesel::update(
            browser_sessions::table
                .find(digest)
                .filter(browser_sessions::revoked_at.is_null()),
        )
        .set((
            browser_sessions::revoked_at.eq(Some(now)),
            browser_sessions::updated_at.eq(now),
        ))
        .execute(conn)
    }

    pub fn complete_recovery(
        conn: &mut diesel::PgConnection,
        challenge_id: uuid::Uuid,
        password_hash: &str,
    ) -> QueryResult<()> {
        conn.transaction(|conn| {
            let now = chrono::Utc::now();
            let candidate = account_challenges::table
                .find(challenge_id)
                .filter(account_challenges::kind.eq("reset_password"))
                .filter(account_challenges::consumed_at.is_null())
                .filter(account_challenges::revoked_at.is_null())
                .filter(account_challenges::expires_at.gt(now))
                .select(AccountChallengeRow::as_select())
                .first::<AccountChallengeRow>(conn)?;
            let active_user = users::table
                .find(candidate.user_id)
                .select((users::is_active, users::purged_at))
                .for_update()
                .first::<(bool, Option<chrono::DateTime<chrono::Utc>>)>(conn)?;
            if !active_user.0 || active_user.1.is_some() {
                return Err(diesel::result::Error::NotFound);
            }
            let challenge = account_challenges::table
                .find(challenge_id)
                .filter(account_challenges::kind.eq("reset_password"))
                .filter(account_challenges::consumed_at.is_null())
                .filter(account_challenges::revoked_at.is_null())
                .filter(account_challenges::expires_at.gt(now))
                .for_update()
                .select(AccountChallengeRow::as_select())
                .first::<AccountChallengeRow>(conn)?;
            let purposes = verified_contact_methods::table
                .filter(verified_contact_methods::user_id.eq(challenge.user_id))
                .filter(verified_contact_methods::channel.eq(&challenge.channel))
                .filter(verified_contact_methods::destination.eq(&challenge.destination))
                .filter(verified_contact_methods::revoked_at.is_null())
                .select(verified_contact_methods::purposes)
                .first::<String>(conn)?;
            if !purposes.split(',').any(|value| value == "reset_password") {
                return Err(diesel::result::Error::NotFound);
            }
            diesel::update(
                auth_credentials::table
                    .filter(auth_credentials::user_id.eq(challenge.user_id))
                    .filter(auth_credentials::credential_type.eq("password"))
                    .filter(auth_credentials::revoked_at.is_null()),
            )
            .set((
                auth_credentials::revoked_at.eq(Some(now)),
                auth_credentials::updated_at.eq(now),
            ))
            .execute(conn)?;
            crate::db::auth_credentials::pg::create(
                conn,
                challenge.user_id,
                "password",
                password_hash,
            )?;
            diesel::update(
                browser_sessions::table
                    .filter(browser_sessions::user_id.eq(challenge.user_id))
                    .filter(browser_sessions::revoked_at.is_null()),
            )
            .set((
                browser_sessions::revoked_at.eq(Some(now)),
                browser_sessions::updated_at.eq(now),
            ))
            .execute(conn)?;
            diesel::update(account_challenges::table.find(challenge_id))
                .set(account_challenges::consumed_at.eq(Some(now)))
                .execute(conn)?;
            diesel::update(
                account_challenges::table
                    .filter(account_challenges::user_id.eq(challenge.user_id))
                    .filter(account_challenges::consumed_at.is_null())
                    .filter(account_challenges::revoked_at.is_null()),
            )
            .set(account_challenges::revoked_at.eq(Some(now)))
            .execute(conn)?;
            Ok(())
        })
    }

    pub fn replace_password(
        conn: &mut diesel::PgConnection,
        user_id: uuid::Uuid,
        password_hash: &str,
    ) -> QueryResult<()> {
        conn.transaction(|conn| {
            let now = chrono::Utc::now();
            users::table
                .find(user_id)
                .filter(users::purged_at.is_null())
                .select(users::id)
                .for_update()
                .first::<uuid::Uuid>(conn)?;
            diesel::update(
                auth_credentials::table
                    .filter(auth_credentials::user_id.eq(user_id))
                    .filter(auth_credentials::credential_type.eq("password"))
                    .filter(auth_credentials::revoked_at.is_null()),
            )
            .set((
                auth_credentials::revoked_at.eq(Some(now)),
                auth_credentials::updated_at.eq(now),
            ))
            .execute(conn)?;
            crate::db::auth_credentials::pg::create(conn, user_id, "password", password_hash)?;
            diesel::update(
                browser_sessions::table
                    .filter(browser_sessions::user_id.eq(user_id))
                    .filter(browser_sessions::revoked_at.is_null()),
            )
            .set((
                browser_sessions::revoked_at.eq(Some(now)),
                browser_sessions::updated_at.eq(now),
            ))
            .execute(conn)?;
            diesel::update(
                account_challenges::table
                    .filter(account_challenges::user_id.eq(user_id))
                    .filter(account_challenges::consumed_at.is_null())
                    .filter(account_challenges::revoked_at.is_null()),
            )
            .set(account_challenges::revoked_at.eq(Some(now)))
            .execute(conn)?;
            Ok(())
        })
    }

    pub fn replace_password_if_current(
        conn: &mut diesel::PgConnection,
        user_id: uuid::Uuid,
        credential_id: uuid::Uuid,
        password_hash: &str,
    ) -> QueryResult<()> {
        conn.transaction(|conn| {
            let now = chrono::Utc::now();
            users::table
                .find(user_id)
                .select(users::id)
                .for_update()
                .first::<uuid::Uuid>(conn)?;
            auth_credentials::table
                .find(credential_id)
                .filter(auth_credentials::user_id.eq(user_id))
                .filter(auth_credentials::credential_type.eq("password"))
                .filter(auth_credentials::revoked_at.is_null())
                .filter(
                    auth_credentials::expires_at
                        .is_null()
                        .or(auth_credentials::expires_at.gt(now)),
                )
                .select(auth_credentials::id)
                .first::<uuid::Uuid>(conn)?;
            replace_password(conn, user_id, password_hash)
        })
    }

    pub fn claim_outbox(
        conn: &mut diesel::PgConnection,
        channel: &str,
        worker_id: &str,
        lease_seconds: i64,
    ) -> QueryResult<Option<crate::db::models::NotificationOutboxItem>> {
        conn.transaction(|conn| {
            let now = diesel::select(diesel::dsl::sql::<diesel::sql_types::Timestamptz>(
                "clock_timestamp()",
            ))
            .get_result::<chrono::DateTime<chrono::Utc>>(conn)?;
            let lease_until = diesel::select(
                diesel::dsl::sql::<diesel::sql_types::Timestamptz>("clock_timestamp() + (")
                    .bind::<diesel::sql_types::BigInt, _>(lease_seconds)
                    .sql(" * INTERVAL '1 second')"),
            )
            .get_result::<chrono::DateTime<chrono::Utc>>(conn)?;
            let row = notification_outbox::table
                .filter(notification_outbox::channel.eq(channel))
                .filter(
                    notification_outbox::state
                        .eq("pending")
                        .or(notification_outbox::state.eq("leased").and(
                            notification_outbox::lease_expires_at
                                .is_null()
                                .or(notification_outbox::lease_expires_at.lt(now)),
                        )),
                )
                .filter(notification_outbox::next_attempt_at.le(now))
                .filter(notification_outbox::expires_at.gt(now))
                .order(notification_outbox::created_at.asc())
                .for_update()
                .skip_locked()
                .select(NotificationOutboxRow::as_select())
                .first::<NotificationOutboxRow>(conn)
                .optional()?;
            let Some(row) = row else {
                return Ok(None);
            };
            diesel::update(notification_outbox::table.find(row.id))
                .set((
                    notification_outbox::state.eq("leased"),
                    notification_outbox::attempt_count.eq(row.attempt_count + 1),
                    notification_outbox::lease_owner.eq(Some(worker_id)),
                    notification_outbox::lease_expires_at.eq(Some(lease_until)),
                    notification_outbox::updated_at.eq(now),
                ))
                .execute(conn)?;
            notification_outbox::table
                .find(row.id)
                .select(NotificationOutboxRow::as_select())
                .first(conn)
                .map(|value| Some(value.into()))
        })
    }

    pub fn finish_outbox(
        conn: &mut diesel::PgConnection,
        id: &str,
        worker_id: &str,
        state: &str,
        next_attempt_at: chrono::DateTime<chrono::Utc>,
        error_category: Option<&str>,
        redact_payload: bool,
    ) -> QueryResult<usize> {
        let id = id
            .parse::<uuid::Uuid>()
            .map_err(|_| diesel::result::Error::NotFound)?;
        let now = chrono::Utc::now();
        if redact_payload {
            diesel::update(
                notification_outbox::table
                    .find(id)
                    .filter(notification_outbox::state.eq("leased"))
                    .filter(notification_outbox::lease_owner.eq(worker_id)),
            )
            .set((
                notification_outbox::state.eq(state),
                notification_outbox::encrypted_payload.eq::<Option<Vec<u8>>>(None),
                notification_outbox::next_attempt_at.eq(next_attempt_at),
                notification_outbox::lease_owner.eq::<Option<String>>(None),
                notification_outbox::lease_expires_at
                    .eq::<Option<chrono::DateTime<chrono::Utc>>>(None),
                notification_outbox::last_error.eq(error_category),
                notification_outbox::updated_at.eq(now),
            ))
            .execute(conn)
        } else {
            diesel::update(
                notification_outbox::table
                    .find(id)
                    .filter(notification_outbox::state.eq("leased"))
                    .filter(notification_outbox::lease_owner.eq(worker_id)),
            )
            .set((
                notification_outbox::state.eq(state),
                notification_outbox::next_attempt_at.eq(next_attempt_at),
                notification_outbox::lease_owner.eq::<Option<String>>(None),
                notification_outbox::lease_expires_at
                    .eq::<Option<chrono::DateTime<chrono::Utc>>>(None),
                notification_outbox::last_error.eq(error_category),
                notification_outbox::updated_at.eq(now),
            ))
            .execute(conn)
        }
    }

    pub fn expire_outbox(conn: &mut diesel::PgConnection) -> QueryResult<usize> {
        let now = chrono::Utc::now();
        diesel::update(
            notification_outbox::table
                .filter(notification_outbox::expires_at.le(now))
                .filter(notification_outbox::state.eq_any(["pending", "leased"])),
        )
        .set((
            notification_outbox::state.eq("expired"),
            notification_outbox::encrypted_payload.eq::<Option<Vec<u8>>>(None),
            notification_outbox::lease_owner.eq::<Option<String>>(None),
            notification_outbox::lease_expires_at.eq::<Option<chrono::DateTime<chrono::Utc>>>(None),
            notification_outbox::last_error.eq(Some("expired")),
            notification_outbox::updated_at.eq(now),
        ))
        .execute(conn)
    }

    pub fn find_outbox(
        conn: &mut diesel::PgConnection,
        id: &str,
    ) -> QueryResult<Option<crate::db::models::NotificationOutboxItem>> {
        let id = id
            .parse::<uuid::Uuid>()
            .map_err(|_| diesel::result::Error::NotFound)?;
        notification_outbox::table
            .find(id)
            .select(NotificationOutboxRow::as_select())
            .first(conn)
            .optional()
            .map(|value| value.map(Into::into))
    }

    pub fn latest_outbox(
        conn: &mut diesel::PgConnection,
        user_id: uuid::Uuid,
        purpose: &str,
    ) -> QueryResult<Option<crate::db::models::NotificationOutboxItem>> {
        notification_outbox::table
            .filter(notification_outbox::user_id.eq(user_id))
            .filter(notification_outbox::purpose.eq(purpose))
            .order(notification_outbox::created_at.desc())
            .select(NotificationOutboxRow::as_select())
            .first(conn)
            .optional()
            .map(|value| value.map(Into::into))
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use crate::db::models::sqlite::{
        AccountChallengeRow, BrowserSessionRow, NotificationOutboxRow, VerifiedContactMethodRow,
    };
    use crate::db::models::{AccountChallenge, BrowserSession, User, VerifiedContactMethod};
    use crate::schema::sqlite::{
        account_challenges, auth_credentials, browser_sessions, claims, notification_outbox, users,
        verified_contact_methods,
    };
    use diesel::connection::{AnsiTransactionManager, TransactionManager};
    use diesel::prelude::*;

    fn write_transaction<T, F>(conn: &mut diesel::SqliteConnection, callback: F) -> QueryResult<T>
    where
        F: FnOnce(&mut diesel::SqliteConnection) -> QueryResult<T>,
    {
        let transaction_is_active = <AnsiTransactionManager as TransactionManager<
            diesel::SqliteConnection,
        >>::transaction_manager_status_mut(conn)
        .transaction_depth()?
        .is_some();
        if transaction_is_active {
            conn.transaction(callback)
        } else {
            conn.immediate_transaction(callback)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_challenge_and_outbox(
        conn: &mut diesel::SqliteConnection,
        user_id: &str,
        kind: &str,
        channel: &str,
        destination: &str,
        token_digest: &str,
        encrypted_payload: Vec<u8>,
        expires_at: &str,
        required_credential_id: Option<&str>,
    ) -> QueryResult<AccountChallenge> {
        write_transaction(conn, |conn| {
            let now = chrono::Utc::now().to_rfc3339();
            let active_user = users::table
                .find(user_id)
                .select((users::is_active, users::purged_at))
                .first::<(i32, Option<String>)>(conn)?;
            if active_user.0 == 0 || active_user.1.is_some() {
                return Err(diesel::result::Error::NotFound);
            }
            if kind == "reset_password" {
                let purposes = verified_contact_methods::table
                    .filter(verified_contact_methods::user_id.eq(user_id))
                    .filter(verified_contact_methods::channel.eq(channel))
                    .filter(verified_contact_methods::destination.eq(destination))
                    .filter(verified_contact_methods::revoked_at.is_null())
                    .select(verified_contact_methods::purposes)
                    .first::<String>(conn)?;
                if !purposes.split(',').any(|value| value == "reset_password") {
                    return Err(diesel::result::Error::NotFound);
                }
            }
            if let Some(credential_id) = required_credential_id {
                auth_credentials::table
                    .find(credential_id)
                    .filter(auth_credentials::user_id.eq(user_id))
                    .filter(auth_credentials::credential_type.eq("password"))
                    .filter(auth_credentials::revoked_at.is_null())
                    .filter(
                        auth_credentials::expires_at
                            .is_null()
                            .or(auth_credentials::expires_at.gt(&now)),
                    )
                    .select(auth_credentials::id)
                    .first::<String>(conn)?;
            }
            diesel::update(
                account_challenges::table
                    .filter(account_challenges::user_id.eq(user_id))
                    .filter(account_challenges::kind.eq(kind))
                    .filter(account_challenges::consumed_at.is_null())
                    .filter(account_challenges::revoked_at.is_null()),
            )
            .set(account_challenges::revoked_at.eq(Some(&now)))
            .execute(conn)?;
            diesel::update(
                notification_outbox::table
                    .filter(notification_outbox::user_id.eq(user_id))
                    .filter(notification_outbox::purpose.eq(kind))
                    .filter(notification_outbox::state.eq_any(["pending", "leased"])),
            )
            .set((
                notification_outbox::state.eq("superseded"),
                notification_outbox::encrypted_payload.eq::<Option<Vec<u8>>>(None),
                notification_outbox::lease_owner.eq::<Option<String>>(None),
                notification_outbox::lease_expires_at.eq::<Option<String>>(None),
                notification_outbox::last_error.eq(Some("superseded")),
                notification_outbox::updated_at.eq(&now),
            ))
            .execute(conn)?;
            let row = AccountChallengeRow {
                id: uuid::Uuid::now_v7().to_string(),
                token_digest: token_digest.to_string(),
                user_id: user_id.to_string(),
                kind: kind.to_string(),
                channel: channel.to_string(),
                destination: destination.to_string(),
                required_credential_id: required_credential_id.map(str::to_string),
                expires_at: expires_at.to_string(),
                consumed_at: None,
                revoked_at: None,
                created_at: now.clone(),
            };
            diesel::insert_into(account_challenges::table)
                .values(&row)
                .execute(conn)?;
            diesel::insert_into(notification_outbox::table)
                .values(NotificationOutboxRow {
                    id: uuid::Uuid::now_v7().to_string(),
                    user_id: user_id.to_string(),
                    purpose: kind.to_string(),
                    channel: channel.to_string(),
                    destination: destination.to_string(),
                    encrypted_payload: Some(encrypted_payload),
                    state: "pending".to_string(),
                    attempt_count: 0,
                    next_attempt_at: now.clone(),
                    lease_owner: None,
                    lease_expires_at: None,
                    last_error: None,
                    expires_at: expires_at.to_string(),
                    created_at: now.clone(),
                    updated_at: now,
                })
                .execute(conn)?;
            Ok(row.into())
        })
    }
    pub fn find_challenge(
        conn: &mut diesel::SqliteConnection,
        digest: &str,
        kind: &str,
    ) -> QueryResult<Option<AccountChallenge>> {
        account_challenges::table
            .filter(account_challenges::token_digest.eq(digest))
            .filter(account_challenges::kind.eq(kind))
            .filter(account_challenges::consumed_at.is_null())
            .filter(account_challenges::revoked_at.is_null())
            .filter(account_challenges::expires_at.gt(chrono::Utc::now().to_rfc3339()))
            .select(AccountChallengeRow::as_select())
            .first(conn)
            .optional()
            .map(|v| v.map(Into::into))
    }
    pub fn confirm_contact(
        conn: &mut diesel::SqliteConnection,
        challenge_id: &str,
        claims: &[crate::db::models::PreparedClaim],
    ) -> QueryResult<VerifiedContactMethod> {
        write_transaction(conn, |conn| {
            let now = chrono::Utc::now().to_rfc3339();
            let c = account_challenges::table
                .find(challenge_id)
                .filter(account_challenges::kind.eq("verify_contact"))
                .filter(account_challenges::consumed_at.is_null())
                .filter(account_challenges::revoked_at.is_null())
                .filter(account_challenges::expires_at.gt(&now))
                .select(AccountChallengeRow::as_select())
                .first::<AccountChallengeRow>(conn)?;
            let active_user = users::table
                .find(&c.user_id)
                .select((users::is_active, users::purged_at))
                .first::<(i32, Option<String>)>(conn)?;
            if active_user.0 == 0 || active_user.1.is_some() {
                return Err(diesel::result::Error::NotFound);
            }
            if let Some(credential_id) = c.required_credential_id.as_deref() {
                auth_credentials::table
                    .find(credential_id)
                    .filter(auth_credentials::user_id.eq(&c.user_id))
                    .filter(auth_credentials::credential_type.eq("password"))
                    .filter(auth_credentials::revoked_at.is_null())
                    .filter(
                        auth_credentials::expires_at
                            .is_null()
                            .or(auth_credentials::expires_at.gt(&now)),
                    )
                    .select(auth_credentials::id)
                    .first::<String>(conn)?;
            }
            for claim in claims {
                crate::db::claims::sqlite::replace_active_of_type(
                    conn,
                    &claim.id,
                    &c.user_id,
                    &claim.claim_type,
                    &claim.claim_value,
                    &claim.signatures,
                    None,
                    &claim.attested_at.to_rfc3339(),
                )?;
            }
            diesel::update(account_challenges::table.find(challenge_id))
                .set(account_challenges::consumed_at.eq(Some(&now)))
                .execute(conn)?;
            diesel::update(
                verified_contact_methods::table
                    .filter(verified_contact_methods::user_id.eq(&c.user_id))
                    .filter(verified_contact_methods::channel.eq(&c.channel))
                    .filter(verified_contact_methods::revoked_at.is_null()),
            )
            .set((
                verified_contact_methods::revoked_at.eq(Some(&now)),
                verified_contact_methods::updated_at.eq(&now),
            ))
            .execute(conn)?;
            let row = VerifiedContactMethodRow {
                id: uuid::Uuid::now_v7().to_string(),
                user_id: c.user_id,
                channel: c.channel,
                destination: c.destination,
                purposes: "verify_contact,reset_password".to_string(),
                verified_at: now.clone(),
                revoked_at: None,
                created_at: now.clone(),
                updated_at: now,
            };
            diesel::insert_into(verified_contact_methods::table)
                .values(&row)
                .execute(conn)?;
            Ok(row.into())
        })
    }
    pub fn list_contacts(
        conn: &mut diesel::SqliteConnection,
        user_id: &str,
    ) -> QueryResult<Vec<VerifiedContactMethod>> {
        verified_contact_methods::table
            .filter(verified_contact_methods::user_id.eq(user_id))
            .filter(verified_contact_methods::revoked_at.is_null())
            .order(verified_contact_methods::verified_at.asc())
            .select(VerifiedContactMethodRow::as_select())
            .load(conn)
            .map(|v: Vec<_>| v.into_iter().map(Into::into).collect())
    }
    pub fn revoke_contact(
        conn: &mut diesel::SqliteConnection,
        user_id: &str,
        contact_id: &str,
        credential_id: &str,
    ) -> QueryResult<usize> {
        write_transaction(conn, |conn| {
            let now = chrono::Utc::now().to_rfc3339();
            auth_credentials::table
                .find(credential_id)
                .filter(auth_credentials::user_id.eq(user_id))
                .filter(auth_credentials::credential_type.eq("password"))
                .filter(auth_credentials::revoked_at.is_null())
                .filter(
                    auth_credentials::expires_at
                        .is_null()
                        .or(auth_credentials::expires_at.gt(&now)),
                )
                .select(auth_credentials::id)
                .first::<String>(conn)?;
            let contact = verified_contact_methods::table
                .find(contact_id)
                .filter(verified_contact_methods::user_id.eq(user_id))
                .filter(verified_contact_methods::revoked_at.is_null())
                .select(VerifiedContactMethodRow::as_select())
                .first::<VerifiedContactMethodRow>(conn)
                .optional()?;
            let Some(contact) = contact else {
                return Ok(0);
            };
            let changed = diesel::update(
                verified_contact_methods::table
                    .find(contact_id)
                    .filter(verified_contact_methods::user_id.eq(user_id))
                    .filter(verified_contact_methods::revoked_at.is_null()),
            )
            .set((
                verified_contact_methods::revoked_at.eq(Some(&now)),
                verified_contact_methods::updated_at.eq(&now),
            ))
            .execute(conn)?;
            if changed == 1 {
                diesel::update(
                    account_challenges::table
                        .filter(account_challenges::user_id.eq(user_id))
                        .filter(account_challenges::kind.eq("reset_password"))
                        .filter(account_challenges::consumed_at.is_null())
                        .filter(account_challenges::revoked_at.is_null()),
                )
                .set(account_challenges::revoked_at.eq(Some(&now)))
                .execute(conn)?;
                diesel::update(
                    notification_outbox::table
                        .filter(notification_outbox::user_id.eq(user_id))
                        .filter(notification_outbox::purpose.eq("reset_password"))
                        .filter(notification_outbox::state.eq_any(["pending", "leased"])),
                )
                .set((
                    notification_outbox::state.eq("superseded"),
                    notification_outbox::encrypted_payload.eq::<Option<Vec<u8>>>(None),
                    notification_outbox::lease_owner.eq::<Option<String>>(None),
                    notification_outbox::lease_expires_at.eq::<Option<String>>(None),
                    notification_outbox::last_error.eq(Some("superseded")),
                    notification_outbox::updated_at.eq(&now),
                ))
                .execute(conn)?;
                if contact.channel == "email" {
                    diesel::update(
                        claims::table
                            .filter(claims::user_id.eq(user_id))
                            .filter(claims::revoked_at.is_null())
                            .filter(
                                claims::claim_type
                                    .eq("email_verified")
                                    .or(claims::claim_type.eq("email").and(
                                        claims::claim_value.eq(contact.destination.into_bytes()),
                                    )),
                            ),
                    )
                    .set((
                        claims::revoked_at.eq(Some(&now)),
                        claims::updated_at.eq(&now),
                    ))
                    .execute(conn)?;
                }
            }
            Ok(changed)
        })
    }
    pub fn find_recovery_contact(
        conn: &mut diesel::SqliteConnection,
        destination: &str,
    ) -> QueryResult<Option<VerifiedContactMethod>> {
        verified_contact_methods::table
            .filter(verified_contact_methods::channel.eq("email"))
            .filter(verified_contact_methods::destination.eq(destination))
            .filter(verified_contact_methods::revoked_at.is_null())
            .order(verified_contact_methods::verified_at.desc())
            .select(VerifiedContactMethodRow::as_select())
            .first(conn)
            .optional()
            .map(|v| v.map(Into::into))
    }
    pub fn deactivate_account(
        conn: &mut diesel::SqliteConnection,
        user_id: &str,
    ) -> QueryResult<User> {
        write_transaction(conn, |conn| {
            let target = users::table
                .find(user_id)
                .select(crate::db::models::sqlite::UserRow::as_select())
                .first::<crate::db::models::sqlite::UserRow>(conn)?;
            if target.is_admin_account != 0 {
                let active_admin_count = users::table
                    .filter(users::is_admin_account.eq(1))
                    .filter(users::is_active.eq(1))
                    .filter(users::purged_at.is_null())
                    .count()
                    .get_result::<i64>(conn)?;
                if active_admin_count <= 1 {
                    return Err(diesel::result::Error::NotFound);
                }
            }
            let now = chrono::Utc::now().to_rfc3339();
            diesel::update(users::table.find(user_id))
                .set((users::is_active.eq(0), users::updated_at.eq(&now)))
                .execute(conn)?;
            diesel::update(
                auth_credentials::table
                    .filter(auth_credentials::user_id.eq(user_id))
                    .filter(auth_credentials::revoked_at.is_null()),
            )
            .set((
                auth_credentials::revoked_at.eq(Some(&now)),
                auth_credentials::updated_at.eq(&now),
            ))
            .execute(conn)?;
            diesel::update(
                browser_sessions::table
                    .filter(browser_sessions::user_id.eq(user_id))
                    .filter(browser_sessions::revoked_at.is_null()),
            )
            .set((
                browser_sessions::revoked_at.eq(Some(&now)),
                browser_sessions::updated_at.eq(&now),
            ))
            .execute(conn)?;
            diesel::update(
                account_challenges::table
                    .filter(account_challenges::user_id.eq(user_id))
                    .filter(account_challenges::consumed_at.is_null())
                    .filter(account_challenges::revoked_at.is_null()),
            )
            .set(account_challenges::revoked_at.eq(Some(&now)))
            .execute(conn)?;
            diesel::update(
                notification_outbox::table
                    .filter(notification_outbox::user_id.eq(user_id))
                    .filter(notification_outbox::state.eq_any(["pending", "leased"])),
            )
            .set((
                notification_outbox::state.eq("superseded"),
                notification_outbox::encrypted_payload.eq::<Option<Vec<u8>>>(None),
                notification_outbox::lease_owner.eq::<Option<String>>(None),
                notification_outbox::lease_expires_at.eq::<Option<String>>(None),
                notification_outbox::last_error.eq(Some("account_disabled")),
                notification_outbox::updated_at.eq(&now),
            ))
            .execute(conn)?;
            users::table
                .find(user_id)
                .select(crate::db::models::sqlite::UserRow::as_select())
                .first::<crate::db::models::sqlite::UserRow>(conn)
                .map(Into::into)
        })
    }
    pub fn create_session(
        conn: &mut diesel::SqliteConnection,
        row: BrowserSessionRow,
    ) -> QueryResult<BrowserSession> {
        diesel::insert_into(browser_sessions::table)
            .values(&row)
            .execute(conn)?;
        Ok(row.into())
    }
    pub fn create_session_if_password_active(
        conn: &mut diesel::SqliteConnection,
        row: BrowserSessionRow,
        credential_id: &str,
    ) -> QueryResult<BrowserSession> {
        write_transaction(conn, |conn| {
            let now = chrono::Utc::now().to_rfc3339();
            let active_user = crate::schema::sqlite::users::table
                .find(&row.user_id)
                .select((
                    crate::schema::sqlite::users::is_active,
                    crate::schema::sqlite::users::purged_at,
                ))
                .first::<(i32, Option<String>)>(conn)?;
            if active_user.0 == 0 || active_user.1.is_some() {
                return Err(diesel::result::Error::NotFound);
            }
            auth_credentials::table
                .find(credential_id)
                .filter(auth_credentials::user_id.eq(&row.user_id))
                .filter(auth_credentials::credential_type.eq("password"))
                .filter(auth_credentials::revoked_at.is_null())
                .filter(
                    auth_credentials::expires_at
                        .is_null()
                        .or(auth_credentials::expires_at.gt(&now)),
                )
                .select(auth_credentials::id)
                .first::<String>(conn)?;
            create_session(conn, row)
        })
    }
    pub fn find_session(
        conn: &mut diesel::SqliteConnection,
        digest: &str,
    ) -> QueryResult<Option<BrowserSession>> {
        browser_sessions::table
            .find(digest)
            .filter(browser_sessions::revoked_at.is_null())
            .filter(browser_sessions::expires_at.gt(chrono::Utc::now().to_rfc3339()))
            .select(BrowserSessionRow::as_select())
            .first(conn)
            .optional()
            .map(|v| v.map(Into::into))
    }
    pub fn touch_session(
        conn: &mut diesel::SqliteConnection,
        digest: &str,
        last_seen: &str,
    ) -> QueryResult<usize> {
        diesel::update(
            browser_sessions::table
                .find(digest)
                .filter(browser_sessions::revoked_at.is_null()),
        )
        .set((
            browser_sessions::last_seen_at.eq(last_seen),
            browser_sessions::updated_at.eq(last_seen),
        ))
        .execute(conn)
    }
    pub fn revoke_session(conn: &mut diesel::SqliteConnection, digest: &str) -> QueryResult<usize> {
        let now = chrono::Utc::now().to_rfc3339();
        diesel::update(
            browser_sessions::table
                .find(digest)
                .filter(browser_sessions::revoked_at.is_null()),
        )
        .set((
            browser_sessions::revoked_at.eq(Some(&now)),
            browser_sessions::updated_at.eq(&now),
        ))
        .execute(conn)
    }
    pub fn complete_recovery(
        conn: &mut diesel::SqliteConnection,
        challenge_id: &str,
        password_hash: &str,
    ) -> QueryResult<()> {
        write_transaction(conn, |conn| {
            let now = chrono::Utc::now().to_rfc3339();
            let c = account_challenges::table
                .find(challenge_id)
                .filter(account_challenges::kind.eq("reset_password"))
                .filter(account_challenges::consumed_at.is_null())
                .filter(account_challenges::revoked_at.is_null())
                .filter(account_challenges::expires_at.gt(&now))
                .select(AccountChallengeRow::as_select())
                .first::<AccountChallengeRow>(conn)?;
            let active_user = users::table
                .find(&c.user_id)
                .select((users::is_active, users::purged_at))
                .first::<(i32, Option<String>)>(conn)?;
            if active_user.0 == 0 || active_user.1.is_some() {
                return Err(diesel::result::Error::NotFound);
            }
            let purposes = verified_contact_methods::table
                .filter(verified_contact_methods::user_id.eq(&c.user_id))
                .filter(verified_contact_methods::channel.eq(&c.channel))
                .filter(verified_contact_methods::destination.eq(&c.destination))
                .filter(verified_contact_methods::revoked_at.is_null())
                .select(verified_contact_methods::purposes)
                .first::<String>(conn)?;
            if !purposes.split(',').any(|value| value == "reset_password") {
                return Err(diesel::result::Error::NotFound);
            }
            diesel::update(
                auth_credentials::table
                    .filter(auth_credentials::user_id.eq(&c.user_id))
                    .filter(auth_credentials::credential_type.eq("password"))
                    .filter(auth_credentials::revoked_at.is_null()),
            )
            .set((
                auth_credentials::revoked_at.eq(Some(&now)),
                auth_credentials::updated_at.eq(&now),
            ))
            .execute(conn)?;
            crate::db::auth_credentials::sqlite::create(
                conn,
                &c.user_id,
                "password",
                password_hash,
            )?;
            diesel::update(
                browser_sessions::table
                    .filter(browser_sessions::user_id.eq(&c.user_id))
                    .filter(browser_sessions::revoked_at.is_null()),
            )
            .set((
                browser_sessions::revoked_at.eq(Some(&now)),
                browser_sessions::updated_at.eq(&now),
            ))
            .execute(conn)?;
            diesel::update(account_challenges::table.find(challenge_id))
                .set(account_challenges::consumed_at.eq(Some(&now)))
                .execute(conn)?;
            diesel::update(
                account_challenges::table
                    .filter(account_challenges::user_id.eq(&c.user_id))
                    .filter(account_challenges::consumed_at.is_null())
                    .filter(account_challenges::revoked_at.is_null()),
            )
            .set(account_challenges::revoked_at.eq(Some(&now)))
            .execute(conn)?;
            Ok(())
        })
    }

    pub fn replace_password(
        conn: &mut diesel::SqliteConnection,
        user_id: &str,
        password_hash: &str,
    ) -> QueryResult<()> {
        write_transaction(conn, |conn| {
            let now = chrono::Utc::now().to_rfc3339();
            users::table
                .find(user_id)
                .filter(users::purged_at.is_null())
                .select(users::id)
                .first::<String>(conn)?;
            diesel::update(
                auth_credentials::table
                    .filter(auth_credentials::user_id.eq(user_id))
                    .filter(auth_credentials::credential_type.eq("password"))
                    .filter(auth_credentials::revoked_at.is_null()),
            )
            .set((
                auth_credentials::revoked_at.eq(Some(&now)),
                auth_credentials::updated_at.eq(&now),
            ))
            .execute(conn)?;
            crate::db::auth_credentials::sqlite::create(conn, user_id, "password", password_hash)?;
            diesel::update(
                browser_sessions::table
                    .filter(browser_sessions::user_id.eq(user_id))
                    .filter(browser_sessions::revoked_at.is_null()),
            )
            .set((
                browser_sessions::revoked_at.eq(Some(&now)),
                browser_sessions::updated_at.eq(&now),
            ))
            .execute(conn)?;
            diesel::update(
                account_challenges::table
                    .filter(account_challenges::user_id.eq(user_id))
                    .filter(account_challenges::consumed_at.is_null())
                    .filter(account_challenges::revoked_at.is_null()),
            )
            .set(account_challenges::revoked_at.eq(Some(&now)))
            .execute(conn)?;
            Ok(())
        })
    }

    pub fn replace_password_if_current(
        conn: &mut diesel::SqliteConnection,
        user_id: &str,
        credential_id: &str,
        password_hash: &str,
    ) -> QueryResult<()> {
        write_transaction(conn, |conn| {
            let now = chrono::Utc::now().to_rfc3339();
            auth_credentials::table
                .find(credential_id)
                .filter(auth_credentials::user_id.eq(user_id))
                .filter(auth_credentials::credential_type.eq("password"))
                .filter(auth_credentials::revoked_at.is_null())
                .filter(
                    auth_credentials::expires_at
                        .is_null()
                        .or(auth_credentials::expires_at.gt(&now)),
                )
                .select(auth_credentials::id)
                .first::<String>(conn)?;
            replace_password(conn, user_id, password_hash)
        })
    }

    pub fn claim_outbox(
        conn: &mut diesel::SqliteConnection,
        channel: &str,
        worker_id: &str,
        lease_seconds: i64,
    ) -> QueryResult<Option<crate::db::models::NotificationOutboxItem>> {
        write_transaction(conn, |conn| {
            let now = diesel::select(diesel::dsl::sql::<diesel::sql_types::Text>(
                "strftime('%Y-%m-%dT%H:%M:%fZ','now')",
            ))
            .get_result::<String>(conn)?;
            let lease_until = diesel::select(
                diesel::dsl::sql::<diesel::sql_types::Text>(
                    "strftime('%Y-%m-%dT%H:%M:%fZ','now','+' || ",
                )
                .bind::<diesel::sql_types::BigInt, _>(lease_seconds)
                .sql(" || ' seconds')"),
            )
            .get_result::<String>(conn)?;
            let row = notification_outbox::table
                .filter(notification_outbox::channel.eq(channel))
                .filter(
                    notification_outbox::state
                        .eq("pending")
                        .or(notification_outbox::state.eq("leased").and(
                            notification_outbox::lease_expires_at
                                .is_null()
                                .or(notification_outbox::lease_expires_at.lt(&now)),
                        )),
                )
                .filter(notification_outbox::next_attempt_at.le(&now))
                .filter(notification_outbox::expires_at.gt(&now))
                .order(notification_outbox::created_at.asc())
                .select(NotificationOutboxRow::as_select())
                .first::<NotificationOutboxRow>(conn)
                .optional()?;
            let Some(row) = row else {
                return Ok(None);
            };
            diesel::update(notification_outbox::table.find(&row.id))
                .set((
                    notification_outbox::state.eq("leased"),
                    notification_outbox::attempt_count.eq(row.attempt_count + 1),
                    notification_outbox::lease_owner.eq(Some(worker_id)),
                    notification_outbox::lease_expires_at.eq(Some(&lease_until)),
                    notification_outbox::updated_at.eq(&now),
                ))
                .execute(conn)?;
            notification_outbox::table
                .find(&row.id)
                .select(NotificationOutboxRow::as_select())
                .first(conn)
                .map(|value| Some(value.into()))
        })
    }

    pub fn finish_outbox(
        conn: &mut diesel::SqliteConnection,
        id: &str,
        worker_id: &str,
        state: &str,
        next_attempt_at: &str,
        error_category: Option<&str>,
        redact_payload: bool,
    ) -> QueryResult<usize> {
        let now = chrono::Utc::now().to_rfc3339();
        if redact_payload {
            diesel::update(
                notification_outbox::table
                    .find(id)
                    .filter(notification_outbox::state.eq("leased"))
                    .filter(notification_outbox::lease_owner.eq(worker_id)),
            )
            .set((
                notification_outbox::state.eq(state),
                notification_outbox::encrypted_payload.eq::<Option<Vec<u8>>>(None),
                notification_outbox::next_attempt_at.eq(next_attempt_at),
                notification_outbox::lease_owner.eq::<Option<String>>(None),
                notification_outbox::lease_expires_at.eq::<Option<String>>(None),
                notification_outbox::last_error.eq(error_category),
                notification_outbox::updated_at.eq(&now),
            ))
            .execute(conn)
        } else {
            diesel::update(
                notification_outbox::table
                    .find(id)
                    .filter(notification_outbox::state.eq("leased"))
                    .filter(notification_outbox::lease_owner.eq(worker_id)),
            )
            .set((
                notification_outbox::state.eq(state),
                notification_outbox::next_attempt_at.eq(next_attempt_at),
                notification_outbox::lease_owner.eq::<Option<String>>(None),
                notification_outbox::lease_expires_at.eq::<Option<String>>(None),
                notification_outbox::last_error.eq(error_category),
                notification_outbox::updated_at.eq(&now),
            ))
            .execute(conn)
        }
    }

    pub fn expire_outbox(conn: &mut diesel::SqliteConnection) -> QueryResult<usize> {
        let now = chrono::Utc::now().to_rfc3339();
        diesel::update(
            notification_outbox::table
                .filter(notification_outbox::expires_at.le(&now))
                .filter(notification_outbox::state.eq_any(["pending", "leased"])),
        )
        .set((
            notification_outbox::state.eq("expired"),
            notification_outbox::encrypted_payload.eq::<Option<Vec<u8>>>(None),
            notification_outbox::lease_owner.eq::<Option<String>>(None),
            notification_outbox::lease_expires_at.eq::<Option<String>>(None),
            notification_outbox::last_error.eq(Some("expired")),
            notification_outbox::updated_at.eq(&now),
        ))
        .execute(conn)
    }

    pub fn find_outbox(
        conn: &mut diesel::SqliteConnection,
        id: &str,
    ) -> QueryResult<Option<crate::db::models::NotificationOutboxItem>> {
        notification_outbox::table
            .find(id)
            .select(NotificationOutboxRow::as_select())
            .first(conn)
            .optional()
            .map(|value| value.map(Into::into))
    }

    pub fn latest_outbox(
        conn: &mut diesel::SqliteConnection,
        user_id: &str,
        purpose: &str,
    ) -> QueryResult<Option<crate::db::models::NotificationOutboxItem>> {
        notification_outbox::table
            .filter(notification_outbox::user_id.eq(user_id))
            .filter(notification_outbox::purpose.eq(purpose))
            .order(notification_outbox::created_at.desc())
            .select(NotificationOutboxRow::as_select())
            .first(conn)
            .optional()
            .map(|value| value.map(Into::into))
    }
}
