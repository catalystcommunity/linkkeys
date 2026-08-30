//! Persistence for application-key enrollment (signing-things-request.md,
//! step 2): the application instance identity, its enrolled public keys,
//! each key's home-domain attestation bytes, permanent sibling-signed
//! revocation evidence, and single-use enrollment/renewal proof-of-possession
//! challenges. Pure storage — no quorum verification, no signing, no
//! dispatch, no rate limiting. `application_keys` deliberately has no
//! encrypted-private-key column: the application never gives its home
//! domain a private key, so `load_public_records` (the anonymous public-read
//! projection) can select from it directly without any risk of touching key
//! material that must stay secret.

#[cfg(feature = "postgres")]
pub mod pg {
    use diesel::prelude::*;

    use crate::db::models::pg::{
        ApplicationInstanceRow, ApplicationKeyAttestationRow, ApplicationKeyChallengeRow,
        ApplicationKeyRevocationRow, ApplicationKeyRow, NewApplicationInstanceRow,
        NewApplicationKeyChallengeRow, NewApplicationKeyRevocationRow, NewApplicationKeyRow,
    };
    use crate::db::models::{
        ApplicationInstance, ApplicationKey, ApplicationKeyAttestationRecord,
        ApplicationKeyChallenge, ApplicationKeyRevocationRecord, ApplicationPublicRecords,
    };
    use crate::schema::pg::{
        application_instances, application_key_attestations, application_key_challenges,
        application_key_revocations, application_keys,
    };

    fn parse_uuid(s: &str) -> QueryResult<uuid::Uuid> {
        s.parse().map_err(|_| diesel::result::Error::NotFound)
    }

    /// Insert-or-return-existing, keyed by the composite
    /// (subject_user_id, application_id, instance_id) unique index.
    pub fn upsert_instance(
        conn: &mut diesel::PgConnection,
        subject_user_id: &str,
        application_id: &str,
        instance_id: &str,
        enrolled_at: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<ApplicationInstance> {
        let subject_uuid = parse_uuid(subject_user_id)?;
        conn.transaction(|conn| {
            diesel::insert_into(application_instances::table)
                .values(NewApplicationInstanceRow {
                    id: uuid::Uuid::now_v7(),
                    subject_user_id: subject_uuid,
                    application_id: application_id.to_string(),
                    instance_id: instance_id.to_string(),
                    enrolled_at,
                })
                .on_conflict((
                    application_instances::subject_user_id,
                    application_instances::application_id,
                    application_instances::instance_id,
                ))
                .do_nothing()
                .execute(conn)?;

            application_instances::table
                .filter(application_instances::subject_user_id.eq(subject_uuid))
                .filter(application_instances::application_id.eq(application_id))
                .filter(application_instances::instance_id.eq(instance_id))
                .select(ApplicationInstanceRow::as_select())
                .first::<ApplicationInstanceRow>(conn)
                .map(Into::into)
        })
    }

    pub fn find_instance(
        conn: &mut diesel::PgConnection,
        subject_user_id: &str,
        application_id: &str,
        instance_id: &str,
    ) -> QueryResult<Option<ApplicationInstance>> {
        let subject_uuid = parse_uuid(subject_user_id)?;
        application_instances::table
            .filter(application_instances::subject_user_id.eq(subject_uuid))
            .filter(application_instances::application_id.eq(application_id))
            .filter(application_instances::instance_id.eq(instance_id))
            .select(ApplicationInstanceRow::as_select())
            .first::<ApplicationInstanceRow>(conn)
            .optional()
            .map(|o| o.map(Into::into))
    }

    /// Increment `trust_reset_count` and stamp `last_trust_reset_at`. Used to
    /// make a recovery/instance-reset visible rather than a silent quorum
    /// bypass.
    pub fn record_trust_reset(
        conn: &mut diesel::PgConnection,
        instance_row_id: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<usize> {
        let id = parse_uuid(instance_row_id)?;
        diesel::update(application_instances::table.find(id))
            .set((
                application_instances::trust_reset_count
                    .eq(application_instances::trust_reset_count + 1),
                application_instances::last_trust_reset_at.eq(Some(at)),
                application_instances::updated_at.eq(at),
            ))
            .execute(conn)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_key(
        conn: &mut diesel::PgConnection,
        instance_row_id: &str,
        key_id: &str,
        key_usage: &str,
        algorithm: &str,
        public_key: &[u8],
        fingerprint: &str,
        created_at: chrono::DateTime<chrono::Utc>,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<ApplicationKey> {
        let instance_uuid = parse_uuid(instance_row_id)?;
        diesel::insert_into(application_keys::table)
            .values(NewApplicationKeyRow {
                id: uuid::Uuid::now_v7(),
                instance_row_id: instance_uuid,
                key_id: key_id.to_string(),
                key_usage: key_usage.to_string(),
                algorithm: algorithm.to_string(),
                public_key: public_key.to_vec(),
                fingerprint: fingerprint.to_string(),
                created_at,
                expires_at,
            })
            .get_result::<ApplicationKeyRow>(conn)
            .map(Into::into)
    }

    pub fn find_key(
        conn: &mut diesel::PgConnection,
        instance_row_id: &str,
        key_id: &str,
    ) -> QueryResult<Option<ApplicationKey>> {
        let instance_uuid = parse_uuid(instance_row_id)?;
        application_keys::table
            .filter(application_keys::instance_row_id.eq(instance_uuid))
            .filter(application_keys::key_id.eq(key_id))
            .select(ApplicationKeyRow::as_select())
            .first::<ApplicationKeyRow>(conn)
            .optional()
            .map(|o| o.map(Into::into))
    }

    pub fn list_keys(
        conn: &mut diesel::PgConnection,
        instance_row_id: &str,
    ) -> QueryResult<Vec<ApplicationKey>> {
        let instance_uuid = parse_uuid(instance_row_id)?;
        application_keys::table
            .filter(application_keys::instance_row_id.eq(instance_uuid))
            .select(ApplicationKeyRow::as_select())
            .load::<ApplicationKeyRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    /// Counts only non-revoked keys (the count that matters for quorum size).
    pub fn count_keys(conn: &mut diesel::PgConnection, instance_row_id: &str) -> QueryResult<i64> {
        let instance_uuid = parse_uuid(instance_row_id)?;
        application_keys::table
            .filter(application_keys::instance_row_id.eq(instance_uuid))
            .filter(application_keys::revoked_at.is_null())
            .count()
            .get_result(conn)
    }

    /// Idempotent: only affects a not-already-revoked row.
    pub fn revoke_key(
        conn: &mut diesel::PgConnection,
        instance_row_id: &str,
        key_id: &str,
        revoked_at: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<usize> {
        let instance_uuid = parse_uuid(instance_row_id)?;
        diesel::update(
            application_keys::table
                .filter(application_keys::instance_row_id.eq(instance_uuid))
                .filter(application_keys::key_id.eq(key_id))
                .filter(application_keys::revoked_at.is_null()),
        )
        .set(application_keys::revoked_at.eq(Some(revoked_at)))
        .execute(conn)
    }

    /// Renewal: replace the stored attestation bytes for a key. Exactly one
    /// current attestation per key (`application_key_row_id` is UNIQUE).
    pub fn upsert_attestation(
        conn: &mut diesel::PgConnection,
        application_key_row_id: &str,
        signed_attestation: &[u8],
        attested_at: chrono::DateTime<chrono::Utc>,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<usize> {
        let key_uuid = parse_uuid(application_key_row_id)?;
        let now = chrono::Utc::now();
        diesel::insert_into(application_key_attestations::table)
            .values((
                application_key_attestations::id.eq(uuid::Uuid::now_v7()),
                application_key_attestations::application_key_row_id.eq(key_uuid),
                application_key_attestations::signed_attestation.eq(signed_attestation),
                application_key_attestations::attested_at.eq(attested_at),
                application_key_attestations::expires_at.eq(expires_at),
            ))
            .on_conflict(application_key_attestations::application_key_row_id)
            .do_update()
            .set((
                application_key_attestations::signed_attestation.eq(signed_attestation),
                application_key_attestations::attested_at.eq(attested_at),
                application_key_attestations::expires_at.eq(expires_at),
                application_key_attestations::updated_at.eq(now),
            ))
            .execute(conn)
    }

    pub fn get_attestation(
        conn: &mut diesel::PgConnection,
        application_key_row_id: &str,
    ) -> QueryResult<Option<ApplicationKeyAttestationRecord>> {
        let key_uuid = parse_uuid(application_key_row_id)?;
        application_key_attestations::table
            .filter(application_key_attestations::application_key_row_id.eq(key_uuid))
            .select(ApplicationKeyAttestationRow::as_select())
            .first::<ApplicationKeyAttestationRow>(conn)
            .optional()
            .map(|o| o.map(Into::into))
    }

    /// Permanent and idempotent: a repeat revocation of the same key in the
    /// same instance is a no-op (`(instance_row_id, target_key_id)` unique).
    pub fn insert_revocation(
        conn: &mut diesel::PgConnection,
        instance_row_id: &str,
        target_key_id: &str,
        target_fingerprint: &str,
        revoked_at: chrono::DateTime<chrono::Utc>,
        record: &[u8],
    ) -> QueryResult<usize> {
        let instance_uuid = parse_uuid(instance_row_id)?;
        diesel::insert_into(application_key_revocations::table)
            .values(NewApplicationKeyRevocationRow {
                id: uuid::Uuid::now_v7(),
                instance_row_id: instance_uuid,
                target_key_id: target_key_id.to_string(),
                target_fingerprint: target_fingerprint.to_string(),
                revoked_at,
                record: record.to_vec(),
            })
            .on_conflict((
                application_key_revocations::instance_row_id,
                application_key_revocations::target_key_id,
            ))
            .do_nothing()
            .execute(conn)
    }

    pub fn list_revocations_since(
        conn: &mut diesel::PgConnection,
        instance_row_id: &str,
        since: Option<chrono::DateTime<chrono::Utc>>,
    ) -> QueryResult<Vec<ApplicationKeyRevocationRecord>> {
        let instance_uuid = parse_uuid(instance_row_id)?;
        let mut q = application_key_revocations::table
            .filter(application_key_revocations::instance_row_id.eq(instance_uuid))
            .into_boxed();
        if let Some(s) = since {
            q = q.filter(application_key_revocations::revoked_at.ge(s));
        }
        q.order(application_key_revocations::revoked_at.desc())
            .select(ApplicationKeyRevocationRow::as_select())
            .load::<ApplicationKeyRevocationRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_challenge(
        conn: &mut diesel::PgConnection,
        challenge_id: &str,
        subject_user_id: &str,
        application_id: &str,
        instance_id: &str,
        purpose: &str,
        key_usage: &str,
        algorithm: &str,
        public_key: &[u8],
        nonce: &[u8],
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<usize> {
        diesel::insert_into(application_key_challenges::table)
            .values(NewApplicationKeyChallengeRow {
                id: uuid::Uuid::now_v7(),
                challenge_id: challenge_id.to_string(),
                subject_user_id: subject_user_id.to_string(),
                application_id: application_id.to_string(),
                instance_id: instance_id.to_string(),
                purpose: purpose.to_string(),
                key_usage: key_usage.to_string(),
                algorithm: algorithm.to_string(),
                public_key: public_key.to_vec(),
                nonce: nonce.to_vec(),
                expires_at,
            })
            .execute(conn)
    }

    /// Atomic single-use consumption: one UPDATE guarded by
    /// `consumed_at IS NULL AND expires_at > now`. Returns the row only when
    /// that UPDATE affected exactly one row, so a challenge is never usable
    /// twice, including under concurrency.
    pub fn consume_challenge(
        conn: &mut diesel::PgConnection,
        challenge_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<Option<ApplicationKeyChallenge>> {
        let affected = diesel::update(
            application_key_challenges::table
                .filter(application_key_challenges::challenge_id.eq(challenge_id))
                .filter(application_key_challenges::consumed_at.is_null())
                .filter(application_key_challenges::expires_at.gt(now)),
        )
        .set(application_key_challenges::consumed_at.eq(Some(now)))
        .execute(conn)?;

        if affected != 1 {
            return Ok(None);
        }

        application_key_challenges::table
            .filter(application_key_challenges::challenge_id.eq(challenge_id))
            .select(ApplicationKeyChallengeRow::as_select())
            .first::<ApplicationKeyChallengeRow>(conn)
            .optional()
            .map(|o| o.map(Into::into))
    }

    pub fn delete_expired_challenges(
        conn: &mut diesel::PgConnection,
        now: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<usize> {
        diesel::delete(
            application_key_challenges::table
                .filter(application_key_challenges::expires_at.le(now)),
        )
        .execute(conn)
    }

    /// THE public-read projection: selects only public columns, never an
    /// encrypted-private-key column. `Ok(None)` when the instance does not
    /// exist (identical shape for a known and an unknown instance, as the
    /// anonymous lookup requires).
    ///
    /// A REVOKED key's attestation is still published until the key's own
    /// expiry. That is deliberate and load-bearing: a revocation names its
    /// target by key id and fingerprint, and a verifier checks the sibling
    /// signatures against the attested key set it holds. Drop the revoked
    /// key's attestation and the revocation becomes unverifiable — a peer
    /// holding a still-valid cached attestation for that key would fetch the
    /// revocations, fail to verify them, and go on trusting the revoked key.
    /// Publishing both lets the verifier reach the correct conclusion, which
    /// is what `liblinkkeys::application_keys::classify_key` then does.
    ///
    /// An EXPIRED key is excluded from both: an expired key needs no
    /// revocation record, because nothing can accept it either way.
    pub fn load_public_records(
        conn: &mut diesel::PgConnection,
        subject_user_id: &str,
        application_id: &str,
        instance_id: &str,
        revocation_since: Option<chrono::DateTime<chrono::Utc>>,
    ) -> QueryResult<Option<ApplicationPublicRecords>> {
        let subject_uuid = match subject_user_id.parse::<uuid::Uuid>() {
            Ok(u) => u,
            Err(_) => return Ok(None),
        };
        let now = chrono::Utc::now();

        let instance_row_id = application_instances::table
            .filter(application_instances::subject_user_id.eq(subject_uuid))
            .filter(application_instances::application_id.eq(application_id))
            .filter(application_instances::instance_id.eq(instance_id))
            .select(application_instances::id)
            .first::<uuid::Uuid>(conn)
            .optional()?;

        let Some(instance_row_id) = instance_row_id else {
            return Ok(None);
        };

        let signed_attestations: Vec<Vec<u8>> =
            application_key_attestations::table
                .inner_join(application_keys::table.on(
                    application_key_attestations::application_key_row_id.eq(application_keys::id),
                ))
                .filter(application_keys::instance_row_id.eq(instance_row_id))
                .filter(application_keys::expires_at.gt(now))
                .select(application_key_attestations::signed_attestation)
                .load::<Vec<u8>>(conn)?;

        let mut rev_q = application_key_revocations::table
            .filter(application_key_revocations::instance_row_id.eq(instance_row_id))
            .into_boxed();
        if let Some(since) = revocation_since {
            rev_q = rev_q.filter(application_key_revocations::revoked_at.ge(since));
        }
        let revocation_records: Vec<Vec<u8>> = rev_q
            .select(application_key_revocations::record)
            .load::<Vec<u8>>(conn)?;

        Ok(Some(ApplicationPublicRecords {
            subject_user_id: subject_uuid.to_string(),
            application_id: application_id.to_string(),
            instance_id: instance_id.to_string(),
            signed_attestations,
            revocation_records,
        }))
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use diesel::prelude::*;

    use crate::db::models::sqlite::{
        ApplicationInstanceRow, ApplicationKeyAttestationRow, ApplicationKeyChallengeRow,
        ApplicationKeyRevocationRow, ApplicationKeyRow, NewApplicationInstanceRow,
        NewApplicationKeyChallengeRow, NewApplicationKeyRevocationRow, NewApplicationKeyRow,
    };
    use crate::db::models::{
        ApplicationInstance, ApplicationKey, ApplicationKeyAttestationRecord,
        ApplicationKeyChallenge, ApplicationKeyRevocationRecord, ApplicationPublicRecords,
    };
    use crate::schema::sqlite::{
        application_instances, application_key_attestations, application_key_challenges,
        application_key_revocations, application_keys,
    };

    /// Insert-or-return-existing, keyed by the composite
    /// (subject_user_id, application_id, instance_id) unique index.
    pub fn upsert_instance(
        conn: &mut diesel::SqliteConnection,
        subject_user_id: &str,
        application_id: &str,
        instance_id: &str,
        enrolled_at: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<ApplicationInstance> {
        conn.transaction(|conn| {
            diesel::insert_into(application_instances::table)
                .values(NewApplicationInstanceRow {
                    id: uuid::Uuid::now_v7().to_string(),
                    subject_user_id: subject_user_id.to_string(),
                    application_id: application_id.to_string(),
                    instance_id: instance_id.to_string(),
                    enrolled_at: enrolled_at.to_rfc3339(),
                })
                .on_conflict((
                    application_instances::subject_user_id,
                    application_instances::application_id,
                    application_instances::instance_id,
                ))
                .do_nothing()
                .execute(conn)?;

            application_instances::table
                .filter(application_instances::subject_user_id.eq(subject_user_id))
                .filter(application_instances::application_id.eq(application_id))
                .filter(application_instances::instance_id.eq(instance_id))
                .select(ApplicationInstanceRow::as_select())
                .first::<ApplicationInstanceRow>(conn)
                .map(Into::into)
        })
    }

    pub fn find_instance(
        conn: &mut diesel::SqliteConnection,
        subject_user_id: &str,
        application_id: &str,
        instance_id: &str,
    ) -> QueryResult<Option<ApplicationInstance>> {
        application_instances::table
            .filter(application_instances::subject_user_id.eq(subject_user_id))
            .filter(application_instances::application_id.eq(application_id))
            .filter(application_instances::instance_id.eq(instance_id))
            .select(ApplicationInstanceRow::as_select())
            .first::<ApplicationInstanceRow>(conn)
            .optional()
            .map(|o| o.map(Into::into))
    }

    /// Increment `trust_reset_count` and stamp `last_trust_reset_at`. Used to
    /// make a recovery/instance-reset visible rather than a silent quorum
    /// bypass.
    pub fn record_trust_reset(
        conn: &mut diesel::SqliteConnection,
        instance_row_id: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<usize> {
        let at_str = at.to_rfc3339();
        diesel::update(application_instances::table.find(instance_row_id))
            .set((
                application_instances::trust_reset_count
                    .eq(application_instances::trust_reset_count + 1),
                application_instances::last_trust_reset_at.eq(Some(at_str.clone())),
                application_instances::updated_at.eq(at_str),
            ))
            .execute(conn)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_key(
        conn: &mut diesel::SqliteConnection,
        instance_row_id: &str,
        key_id: &str,
        key_usage: &str,
        algorithm: &str,
        public_key: &[u8],
        fingerprint: &str,
        created_at: chrono::DateTime<chrono::Utc>,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<ApplicationKey> {
        let id = uuid::Uuid::now_v7().to_string();
        diesel::insert_into(application_keys::table)
            .values(NewApplicationKeyRow {
                id: id.clone(),
                instance_row_id: instance_row_id.to_string(),
                key_id: key_id.to_string(),
                key_usage: key_usage.to_string(),
                algorithm: algorithm.to_string(),
                public_key: public_key.to_vec(),
                fingerprint: fingerprint.to_string(),
                created_at: created_at.to_rfc3339(),
                expires_at: expires_at.to_rfc3339(),
            })
            .execute(conn)?;

        application_keys::table
            .filter(application_keys::id.eq(&id))
            .select(ApplicationKeyRow::as_select())
            .first::<ApplicationKeyRow>(conn)
            .map(Into::into)
    }

    pub fn find_key(
        conn: &mut diesel::SqliteConnection,
        instance_row_id: &str,
        key_id: &str,
    ) -> QueryResult<Option<ApplicationKey>> {
        application_keys::table
            .filter(application_keys::instance_row_id.eq(instance_row_id))
            .filter(application_keys::key_id.eq(key_id))
            .select(ApplicationKeyRow::as_select())
            .first::<ApplicationKeyRow>(conn)
            .optional()
            .map(|o| o.map(Into::into))
    }

    pub fn list_keys(
        conn: &mut diesel::SqliteConnection,
        instance_row_id: &str,
    ) -> QueryResult<Vec<ApplicationKey>> {
        application_keys::table
            .filter(application_keys::instance_row_id.eq(instance_row_id))
            .select(ApplicationKeyRow::as_select())
            .load::<ApplicationKeyRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    /// Counts only non-revoked keys (the count that matters for quorum size).
    pub fn count_keys(
        conn: &mut diesel::SqliteConnection,
        instance_row_id: &str,
    ) -> QueryResult<i64> {
        application_keys::table
            .filter(application_keys::instance_row_id.eq(instance_row_id))
            .filter(application_keys::revoked_at.is_null())
            .count()
            .get_result(conn)
    }

    /// Idempotent: only affects a not-already-revoked row.
    pub fn revoke_key(
        conn: &mut diesel::SqliteConnection,
        instance_row_id: &str,
        key_id: &str,
        revoked_at: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<usize> {
        diesel::update(
            application_keys::table
                .filter(application_keys::instance_row_id.eq(instance_row_id))
                .filter(application_keys::key_id.eq(key_id))
                .filter(application_keys::revoked_at.is_null()),
        )
        .set(application_keys::revoked_at.eq(Some(revoked_at.to_rfc3339())))
        .execute(conn)
    }

    /// Renewal: replace the stored attestation bytes for a key. Exactly one
    /// current attestation per key (`application_key_row_id` is UNIQUE).
    pub fn upsert_attestation(
        conn: &mut diesel::SqliteConnection,
        application_key_row_id: &str,
        signed_attestation: &[u8],
        attested_at: chrono::DateTime<chrono::Utc>,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<usize> {
        let now = chrono::Utc::now().to_rfc3339();
        let attested_at_str = attested_at.to_rfc3339();
        let expires_at_str = expires_at.to_rfc3339();
        diesel::insert_into(application_key_attestations::table)
            .values((
                application_key_attestations::id.eq(uuid::Uuid::now_v7().to_string()),
                application_key_attestations::application_key_row_id.eq(application_key_row_id),
                application_key_attestations::signed_attestation.eq(signed_attestation),
                application_key_attestations::attested_at.eq(&attested_at_str),
                application_key_attestations::expires_at.eq(&expires_at_str),
            ))
            .on_conflict(application_key_attestations::application_key_row_id)
            .do_update()
            .set((
                application_key_attestations::signed_attestation.eq(signed_attestation),
                application_key_attestations::attested_at.eq(&attested_at_str),
                application_key_attestations::expires_at.eq(&expires_at_str),
                application_key_attestations::updated_at.eq(&now),
            ))
            .execute(conn)
    }

    pub fn get_attestation(
        conn: &mut diesel::SqliteConnection,
        application_key_row_id: &str,
    ) -> QueryResult<Option<ApplicationKeyAttestationRecord>> {
        application_key_attestations::table
            .filter(application_key_attestations::application_key_row_id.eq(application_key_row_id))
            .select(ApplicationKeyAttestationRow::as_select())
            .first::<ApplicationKeyAttestationRow>(conn)
            .optional()
            .map(|o| o.map(Into::into))
    }

    /// Permanent and idempotent: a repeat revocation of the same key in the
    /// same instance is a no-op (`(instance_row_id, target_key_id)` unique).
    pub fn insert_revocation(
        conn: &mut diesel::SqliteConnection,
        instance_row_id: &str,
        target_key_id: &str,
        target_fingerprint: &str,
        revoked_at: chrono::DateTime<chrono::Utc>,
        record: &[u8],
    ) -> QueryResult<usize> {
        diesel::insert_into(application_key_revocations::table)
            .values(NewApplicationKeyRevocationRow {
                id: uuid::Uuid::now_v7().to_string(),
                instance_row_id: instance_row_id.to_string(),
                target_key_id: target_key_id.to_string(),
                target_fingerprint: target_fingerprint.to_string(),
                revoked_at: revoked_at.to_rfc3339(),
                record: record.to_vec(),
            })
            .on_conflict((
                application_key_revocations::instance_row_id,
                application_key_revocations::target_key_id,
            ))
            .do_nothing()
            .execute(conn)
    }

    pub fn list_revocations_since(
        conn: &mut diesel::SqliteConnection,
        instance_row_id: &str,
        since: Option<chrono::DateTime<chrono::Utc>>,
    ) -> QueryResult<Vec<ApplicationKeyRevocationRecord>> {
        // RFC3339 UTC strings compare lexicographically in chronological
        // order, matching how issued_revocations::sqlite::list_since works.
        let mut q = application_key_revocations::table
            .filter(application_key_revocations::instance_row_id.eq(instance_row_id))
            .into_boxed();
        if let Some(s) = since {
            q = q.filter(application_key_revocations::revoked_at.ge(s.to_rfc3339()));
        }
        q.order(application_key_revocations::revoked_at.desc())
            .select(ApplicationKeyRevocationRow::as_select())
            .load::<ApplicationKeyRevocationRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_challenge(
        conn: &mut diesel::SqliteConnection,
        challenge_id: &str,
        subject_user_id: &str,
        application_id: &str,
        instance_id: &str,
        purpose: &str,
        key_usage: &str,
        algorithm: &str,
        public_key: &[u8],
        nonce: &[u8],
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<usize> {
        diesel::insert_into(application_key_challenges::table)
            .values(NewApplicationKeyChallengeRow {
                id: uuid::Uuid::now_v7().to_string(),
                challenge_id: challenge_id.to_string(),
                subject_user_id: subject_user_id.to_string(),
                application_id: application_id.to_string(),
                instance_id: instance_id.to_string(),
                purpose: purpose.to_string(),
                key_usage: key_usage.to_string(),
                algorithm: algorithm.to_string(),
                public_key: public_key.to_vec(),
                nonce: nonce.to_vec(),
                expires_at: expires_at.to_rfc3339(),
            })
            .execute(conn)
    }

    /// Atomic single-use consumption: one UPDATE guarded by
    /// `consumed_at IS NULL AND expires_at > now`. Returns the row only when
    /// that UPDATE affected exactly one row, so a challenge is never usable
    /// twice, including under concurrency.
    pub fn consume_challenge(
        conn: &mut diesel::SqliteConnection,
        challenge_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<Option<ApplicationKeyChallenge>> {
        let now_str = now.to_rfc3339();
        let affected = diesel::update(
            application_key_challenges::table
                .filter(application_key_challenges::challenge_id.eq(challenge_id))
                .filter(application_key_challenges::consumed_at.is_null())
                .filter(application_key_challenges::expires_at.gt(&now_str)),
        )
        .set(application_key_challenges::consumed_at.eq(Some(now_str.clone())))
        .execute(conn)?;

        if affected != 1 {
            return Ok(None);
        }

        application_key_challenges::table
            .filter(application_key_challenges::challenge_id.eq(challenge_id))
            .select(ApplicationKeyChallengeRow::as_select())
            .first::<ApplicationKeyChallengeRow>(conn)
            .optional()
            .map(|o| o.map(Into::into))
    }

    pub fn delete_expired_challenges(
        conn: &mut diesel::SqliteConnection,
        now: chrono::DateTime<chrono::Utc>,
    ) -> QueryResult<usize> {
        diesel::delete(
            application_key_challenges::table
                .filter(application_key_challenges::expires_at.le(now.to_rfc3339())),
        )
        .execute(conn)
    }

    /// THE public-read projection: selects only public columns, never an
    /// encrypted-private-key column. `Ok(None)` when the instance does not
    /// exist (identical shape for a known and an unknown instance, as the
    /// anonymous lookup requires).
    ///
    /// A REVOKED key's attestation is still published until the key's own
    /// expiry. That is deliberate and load-bearing: a revocation names its
    /// target by key id and fingerprint, and a verifier checks the sibling
    /// signatures against the attested key set it holds. Drop the revoked
    /// key's attestation and the revocation becomes unverifiable — a peer
    /// holding a still-valid cached attestation for that key would fetch the
    /// revocations, fail to verify them, and go on trusting the revoked key.
    /// Publishing both lets the verifier reach the correct conclusion, which
    /// is what `liblinkkeys::application_keys::classify_key` then does.
    ///
    /// An EXPIRED key is excluded from both: an expired key needs no
    /// revocation record, because nothing can accept it either way.
    pub fn load_public_records(
        conn: &mut diesel::SqliteConnection,
        subject_user_id: &str,
        application_id: &str,
        instance_id: &str,
        revocation_since: Option<chrono::DateTime<chrono::Utc>>,
    ) -> QueryResult<Option<ApplicationPublicRecords>> {
        let now = chrono::Utc::now().to_rfc3339();

        let instance_row_id = application_instances::table
            .filter(application_instances::subject_user_id.eq(subject_user_id))
            .filter(application_instances::application_id.eq(application_id))
            .filter(application_instances::instance_id.eq(instance_id))
            .select(application_instances::id)
            .first::<String>(conn)
            .optional()?;

        let Some(instance_row_id) = instance_row_id else {
            return Ok(None);
        };

        let signed_attestations: Vec<Vec<u8>> =
            application_key_attestations::table
                .inner_join(application_keys::table.on(
                    application_key_attestations::application_key_row_id.eq(application_keys::id),
                ))
                .filter(application_keys::instance_row_id.eq(&instance_row_id))
                .filter(application_keys::expires_at.gt(&now))
                .select(application_key_attestations::signed_attestation)
                .load::<Vec<u8>>(conn)?;

        let mut rev_q = application_key_revocations::table
            .filter(application_key_revocations::instance_row_id.eq(&instance_row_id))
            .into_boxed();
        if let Some(since) = revocation_since {
            rev_q = rev_q.filter(application_key_revocations::revoked_at.ge(since.to_rfc3339()));
        }
        let revocation_records: Vec<Vec<u8>> = rev_q
            .select(application_key_revocations::record)
            .load::<Vec<u8>>(conn)?;

        Ok(Some(ApplicationPublicRecords {
            subject_user_id: subject_user_id.to_string(),
            application_id: application_id.to_string(),
            instance_id: instance_id.to_string(),
            signed_attestations,
            revocation_records,
        }))
    }
}
