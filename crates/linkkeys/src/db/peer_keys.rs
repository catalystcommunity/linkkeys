//! Append-only cache of other domains' public keys. We record keys we resolve
//! when accepting an externally-signed (attested) claim, so the claim's
//! signatures stay verifiable later even if the issuer rotates or disappears.
//! Never deleted; a rotated key is a new `(domain, key_id)` row.

#[cfg(feature = "postgres")]
pub mod pg {
    use diesel::prelude::*;

    use crate::db::models::pg::PeerKeyRow;
    use crate::db::models::PeerKey;
    use crate::schema::pg::peer_keys;

    /// Record a key if we haven't seen this `(domain, key_id)` before. Keeps the
    /// first-seen copy (append-only); returns rows inserted (0 = already cached).
    pub fn cache(conn: &mut diesel::PgConnection, key: &PeerKey) -> QueryResult<usize> {
        diesel::insert_into(peer_keys::table)
            .values(PeerKeyRow {
                domain: key.domain.clone(),
                key_id: key.key_id.clone(),
                public_key: key.public_key.clone(),
                algorithm: key.algorithm.clone(),
                fingerprint: key.fingerprint.clone(),
                key_usage: key.key_usage.clone(),
                expires_at: key.expires_at.clone(),
                revoked_at: key.revoked_at.clone(),
            })
            .on_conflict((peer_keys::domain, peer_keys::key_id))
            .do_nothing()
            .execute(conn)
    }

    pub fn list_for_domain(
        conn: &mut diesel::PgConnection,
        domain: &str,
    ) -> QueryResult<Vec<PeerKey>> {
        peer_keys::table
            .filter(peer_keys::domain.eq(domain))
            .select(PeerKeyRow::as_select())
            .load::<PeerKeyRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    /// Mark a cached peer key revoked as of now, identified by its fingerprint
    /// (used when a pin recheck retires a rotated-away key — SEC-02). Only
    /// affects rows not already revoked.
    pub fn revoke_by_fingerprint(
        conn: &mut diesel::PgConnection,
        domain: &str,
        fingerprint: &str,
    ) -> QueryResult<usize> {
        diesel::update(
            peer_keys::table
                .filter(peer_keys::domain.eq(domain))
                .filter(peer_keys::fingerprint.eq(fingerprint))
                .filter(peer_keys::revoked_at.is_null()),
        )
        .set(peer_keys::revoked_at.eq(chrono::Utc::now().to_rfc3339()))
        .execute(conn)
    }

    /// Mark a cached peer key revoked at the DOMAIN'S asserted timestamp (from a
    /// verified revocation certificate, SEC-08) — which may be well before now.
    /// Keyed by (domain, key_id). Only affects not-already-revoked rows.
    pub fn revoke_by_key_id_at(
        conn: &mut diesel::PgConnection,
        domain: &str,
        key_id: &str,
        revoked_at: &str,
    ) -> QueryResult<usize> {
        diesel::update(
            peer_keys::table
                .filter(peer_keys::domain.eq(domain))
                .filter(peer_keys::key_id.eq(key_id))
                .filter(peer_keys::revoked_at.is_null()),
        )
        .set(peer_keys::revoked_at.eq(revoked_at))
        .execute(conn)
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use diesel::prelude::*;

    use crate::db::models::sqlite::PeerKeyRow;
    use crate::db::models::PeerKey;
    use crate::schema::sqlite::peer_keys;

    pub fn cache(conn: &mut diesel::SqliteConnection, key: &PeerKey) -> QueryResult<usize> {
        diesel::insert_into(peer_keys::table)
            .values(PeerKeyRow {
                domain: key.domain.clone(),
                key_id: key.key_id.clone(),
                public_key: key.public_key.clone(),
                algorithm: key.algorithm.clone(),
                fingerprint: key.fingerprint.clone(),
                key_usage: key.key_usage.clone(),
                expires_at: key.expires_at.clone(),
                revoked_at: key.revoked_at.clone(),
            })
            .on_conflict((peer_keys::domain, peer_keys::key_id))
            .do_nothing()
            .execute(conn)
    }

    pub fn list_for_domain(
        conn: &mut diesel::SqliteConnection,
        domain: &str,
    ) -> QueryResult<Vec<PeerKey>> {
        peer_keys::table
            .filter(peer_keys::domain.eq(domain))
            .select(PeerKeyRow::as_select())
            .load::<PeerKeyRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    /// Mark a cached peer key revoked (by fingerprint) when a pin recheck retires
    /// a rotated-away key (SEC-02). Only affects not-already-revoked rows.
    pub fn revoke_by_fingerprint(
        conn: &mut diesel::SqliteConnection,
        domain: &str,
        fingerprint: &str,
    ) -> QueryResult<usize> {
        diesel::update(
            peer_keys::table
                .filter(peer_keys::domain.eq(domain))
                .filter(peer_keys::fingerprint.eq(fingerprint))
                .filter(peer_keys::revoked_at.is_null()),
        )
        .set(peer_keys::revoked_at.eq(chrono::Utc::now().to_rfc3339()))
        .execute(conn)
    }

    /// Mark a cached peer key revoked at the domain's asserted timestamp (from a
    /// verified revocation certificate, SEC-08). Keyed by (domain, key_id).
    pub fn revoke_by_key_id_at(
        conn: &mut diesel::SqliteConnection,
        domain: &str,
        key_id: &str,
        revoked_at: &str,
    ) -> QueryResult<usize> {
        diesel::update(
            peer_keys::table
                .filter(peer_keys::domain.eq(domain))
                .filter(peer_keys::key_id.eq(key_id))
                .filter(peer_keys::revoked_at.is_null()),
        )
        .set(peer_keys::revoked_at.eq(revoked_at))
        .execute(conn)
    }
}
