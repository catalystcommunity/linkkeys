//! Encrypted, storage-agnostic backup & restore.
//!
//! A backup is a logical, point-in-time snapshot of every application table,
//! serialized to CBOR and encrypted **inside the server process** with a
//! per-domain 256-bit key — so plaintext identity material never leaves the
//! host. The single encrypted artifact, plus the separately-stored backup key,
//! is everything an admin needs to rebuild a domain from scratch (even on a
//! different storage backend, even a newer schema) WITHOUT changing public DNS:
//! the domain signing keys come back byte-identical, so their `_linkkeys`
//! fingerprints are unchanged.
//!
//! Key model (see [`backup_keys`](crate::schema::sqlite::backup_keys)):
//! - The backup key is random 256-bit entropy, generated once and persisted
//!   encrypted-at-rest under `DOMAIN_KEY_PASSPHRASE` (same scheme as domain
//!   keys). The admin is shown it only on generation/rotation and stores it
//!   offline; it is the only way to decrypt their backups.
//! - The bundle can also embed `DOMAIN_KEY_PASSPHRASE` for single-artifact
//!   recovery, but this is OFF by default (SEC-09): otherwise a leaked bundle
//!   plus its backup key would decrypt every private key, since the passphrase
//!   that unwraps the at-rest blobs would be sitting inside the same file.
//!   `--embed-passphrase` opts in; the passphrase should normally be stored
//!   separately from the backup key.
//!
//! The format is intentionally backend-neutral (string timestamps/ids, byte
//! blobs). v1 reads/writes the SQLite backend; the same artifact is consumable
//! by a future Postgres path (the migration mechanism for sqlite→postgres).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::db::DbPool;

/// Current bundle format version.
const FORMAT_VERSION: u32 = 1;

#[derive(Debug)]
pub enum BackupError {
    Db(diesel::result::Error),
    Cbor(String),
    Crypto(String),
    Format(String),
    /// Backend not supported by this version (only SQLite for v1).
    Unsupported(String),
}

impl std::fmt::Display for BackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackupError::Db(e) => write!(f, "database error: {e}"),
            BackupError::Cbor(e) => write!(f, "serialization error: {e}"),
            BackupError::Crypto(e) => write!(f, "crypto error: {e}"),
            BackupError::Format(e) => write!(f, "backup format error: {e}"),
            BackupError::Unsupported(e) => write!(f, "unsupported: {e}"),
        }
    }
}

impl std::error::Error for BackupError {}

impl From<diesel::result::Error> for BackupError {
    fn from(e: diesel::result::Error) -> Self {
        BackupError::Db(e)
    }
}

/// The decrypted contents of a backup artifact.
#[derive(Serialize, Deserialize)]
struct BackupBundle {
    format_version: u32,
    domain_name: String,
    created_at: String,
    db_backend: String,
    /// `DOMAIN_KEY_PASSPHRASE` at backup time, included unless `--no-passphrase`.
    domain_key_passphrase: Option<String>,
    /// table name -> CBOR(Vec<Row>) for that table.
    tables: BTreeMap<String, Vec<u8>>,
}

pub struct BackupOptions {
    /// Rotate the backup key before taking this backup.
    pub rotate: bool,
    /// Include `DOMAIN_KEY_PASSPHRASE` in the bundle (single-artifact recovery).
    pub include_passphrase: bool,
}

pub struct BackupResult {
    /// The encrypted artifact to store offline.
    pub ciphertext: Vec<u8>,
    /// The domain this backup is for.
    pub domain: String,
    /// Set when the backup key was just generated or rotated — the admin must be
    /// shown it exactly once. Hex-encoded by the caller via [`key_to_hex`].
    pub new_key: Option<[u8; 32]>,
}

pub struct RestoreOptions {
    /// The 256-bit backup key (decoded from the admin's stored hex).
    pub key: [u8; 32],
    /// Required to overwrite a database that already has data.
    pub force: bool,
}

pub struct RestoreResult {
    pub domain: String,
    /// Signing-key fingerprints recovered — should match the `_linkkeys` record.
    pub fingerprints: Vec<String>,
    /// `DOMAIN_KEY_PASSPHRASE` carried in the bundle, if any. The running server
    /// must use this exact passphrase or the restored domain keys won't decrypt.
    pub passphrase_in_bundle: Option<String>,
}

// --- hex helpers for the backup key (no extra dependency) ---

pub fn key_to_hex(key: &[u8; 32]) -> String {
    use std::fmt::Write;
    key.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

pub fn key_from_hex(s: &str) -> Result<[u8; 32], BackupError> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(BackupError::Format(format!(
            "backup key must be 64 hex chars, got {}",
            s.len()
        )));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| BackupError::Format("backup key is not valid hex".to_string()))?;
    }
    Ok(out)
}

fn to_cbor<T: Serialize>(v: &T) -> Result<Vec<u8>, BackupError> {
    let mut buf = Vec::new();
    ciborium::into_writer(v, &mut buf).map_err(|e| BackupError::Cbor(e.to_string()))?;
    Ok(buf)
}

fn from_cbor<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, BackupError> {
    ciborium::from_reader(bytes).map_err(|e| BackupError::Cbor(e.to_string()))
}

/// Create an encrypted backup. `passphrase` is `DOMAIN_KEY_PASSPHRASE` (needed to
/// access the at-rest backup key). v1 supports the SQLite backend only.
pub fn create_backup(
    pool: &DbPool,
    passphrase: &str,
    opts: BackupOptions,
) -> Result<BackupResult, BackupError> {
    match pool {
        #[cfg(feature = "sqlite")]
        DbPool::Sqlite(p) => {
            let mut conn = p
                .get()
                .map_err(|e| BackupError::Db(diesel::result::Error::QueryBuilderError(e.into())))?;
            sqlite_backend::create_backup(&mut conn, passphrase, opts)
        }
        #[allow(unreachable_patterns)]
        _ => Err(BackupError::Unsupported(
            "backup currently supports the SQLite backend only".to_string(),
        )),
    }
}

/// Restore from an encrypted backup artifact. v1 supports SQLite only.
pub fn restore_backup(
    pool: &DbPool,
    bundle_bytes: &[u8],
    opts: RestoreOptions,
) -> Result<RestoreResult, BackupError> {
    match pool {
        #[cfg(feature = "sqlite")]
        DbPool::Sqlite(p) => {
            let mut conn = p
                .get()
                .map_err(|e| BackupError::Db(diesel::result::Error::QueryBuilderError(e.into())))?;
            sqlite_backend::restore_backup(&mut conn, bundle_bytes, opts)
        }
        #[allow(unreachable_patterns)]
        _ => Err(BackupError::Unsupported(
            "restore currently supports the SQLite backend only".to_string(),
        )),
    }
}

/// The application tables captured by a snapshot, in a stable order. Used by the
/// drift-guard test to assert every table in the DB is covered.
pub fn snapshot_table_names() -> &'static [&'static str] {
    SNAPSHOT_TABLES
}

/// Single source of truth for which tables a snapshot covers. Kept in sync with
/// the SQLite row registry by the `backup_tables!` macro below.
const SNAPSHOT_TABLES: &[&str] = &[
    "guestbook_entries",
    "backup_keys",
    "domain_keys",
    "users",
    "auth_credentials",
    "relations",
    "user_keys",
    "claims",
    "claim_signatures",
    "peer_keys",
    "used_nonces",
    "profiles",
    "consent_grants",
    "claim_type_policies",
    "claim_type_label_i18n",
    "trusted_issuers",
    "profile_claim_prefs",
    "release_policies",
    "admin_review_queue",
    "audit_log",
    "domain_key_pins",
    "issued_revocations",
    "email_verifications",
    "user_release_prefs",
];

#[cfg(feature = "sqlite")]
mod sqlite_backend {
    use super::*;
    use diesel::prelude::*;
    use diesel::SqliteConnection;

    // Backend-neutral row mirrors of the SQLite schema. Field order matches the
    // table column order (required by Queryable). All types are CBOR-neutral
    // (String / Vec<u8> / ints), which is what makes the artifact portable.

    macro_rules! backup_row {
        ($name:ident => $table:ident { $($field:ident : $ty:ty),+ $(,)? }) => {
            #[derive(Queryable, Insertable, Serialize, Deserialize)]
            #[diesel(table_name = crate::schema::sqlite::$table)]
            struct $name {
                $($field: $ty),+
            }
        };
    }

    backup_row!(GuestbookRow => guestbook_entries {
        id: String, name: String, created_at: String, updated_at: String,
    });
    backup_row!(BackupKeyRow => backup_keys {
        id: String, key_encrypted: Vec<u8>, created_at: String, rotated_at: Option<String>,
    });
    backup_row!(DomainKeyRow => domain_keys {
        id: String, public_key: Vec<u8>, private_key_encrypted: Vec<u8>, fingerprint: String,
        algorithm: String, key_usage: String, created_at: String, expires_at: String,
        revoked_at: Option<String>, updated_at: String, signed_by_key_id: Option<String>,
        key_signature: Option<Vec<u8>>,
    });
    backup_row!(UserRow => users {
        id: String, username: String, display_name: String, is_active: i32,
        created_at: String, updated_at: String, is_admin_account: i32,
    });
    backup_row!(AuthCredentialRow => auth_credentials {
        id: String, user_id: String, credential_type: String, credential_hash: String,
        created_at: String, expires_at: Option<String>, revoked_at: Option<String>, updated_at: String,
    });
    backup_row!(RelationRow => relations {
        id: String, subject_type: String, subject_id: String, relation: String,
        object_type: String, object_id: String, created_at: String, removed_at: Option<String>,
        updated_at: String,
    });
    backup_row!(UserKeyRow => user_keys {
        id: String, user_id: String, public_key: Vec<u8>, private_key_encrypted: Vec<u8>,
        fingerprint: String, algorithm: String, key_usage: String, created_at: String,
        expires_at: String, revoked_at: Option<String>, updated_at: String,
        signed_by_key_id: Option<String>, key_signature: Option<Vec<u8>>,
    });
    backup_row!(ClaimRow => claims {
        id: String, user_id: String, claim_type: String, claim_value: Vec<u8>,
        created_at: String, expires_at: Option<String>, revoked_at: Option<String>, updated_at: String,
        attested_at: String,
    });
    backup_row!(ClaimSignatureRow => claim_signatures {
        id: String, claim_id: String, domain: String, signed_by_key_id: String,
        signature: Vec<u8>, created_at: String,
    });
    backup_row!(PeerKeyRow => peer_keys {
        domain: String, key_id: String, public_key: Vec<u8>, algorithm: String,
        fingerprint: String, key_usage: String, expires_at: String, revoked_at: Option<String>,
        first_seen: String,
    });
    backup_row!(UsedNonceRow => used_nonces {
        nonce: String, expires_at: String,
    });
    backup_row!(ProfileRow => profiles {
        id: String, account_id: String, domain: String, is_root: i32, label: Option<String>,
        created_at: String, updated_at: String,
    });
    backup_row!(ConsentGrantRow => consent_grants {
        id: String, user_id: String, subject_domain: String, audience: String,
        claim_types: String, requested_types: String, signed_grant: Vec<u8>,
        offered_claims: Option<Vec<u8>>, issued_at: String, expires_at: String,
        revoked_at: Option<String>, created_at: String, updated_at: String,
    });
    backup_row!(ClaimTypePolicyRow => claim_type_policies {
        claim_type: String, label: String, description: String, value_type: String,
        max_bytes: i64, set_rule: String, signing_rule: String, requires_approval: i32,
        user_settable: i32, default_auto_sign: i32, suggested: i32, created_at: String,
        updated_at: String,
    });
    backup_row!(ClaimLabelI18nRow => claim_type_label_i18n {
        claim_type: String, locale: String, label: String, description: Option<String>,
        created_at: String, updated_at: String,
    });
    backup_row!(TrustedIssuerRow => trusted_issuers {
        claim_type: String, issuer_domain: String, created_at: String,
    });
    backup_row!(ProfileClaimPrefRow => profile_claim_prefs {
        profile_id: String, claim_type: String, auto_sign: i32, created_at: String, updated_at: String,
    });
    backup_row!(ReleasePolicyRow => release_policies {
        audience: String, claim_type: String, disposition: String, created_at: String, updated_at: String,
    });
    backup_row!(AdminReviewBackupRow => admin_review_queue {
        id: String, kind: String, user_id: Option<String>, claim_type: Option<String>,
        claim_value: Option<Vec<u8>>, subject: Option<String>, detail: Option<String>,
        status: String, resolved_by: Option<String>, resolved_at: Option<String>,
        created_at: String, updated_at: String,
    });
    backup_row!(AuditLogBackupRow => audit_log {
        id: String, event: String, subject: Option<String>, actor: Option<String>,
        detail: Option<String>, created_at: String,
    });
    backup_row!(DomainKeyPinBackupRow => domain_key_pins {
        domain: String, fingerprints: String, pinned_at: String, last_checked_at: String,
    });
    backup_row!(IssuedRevocationBackupRow => issued_revocations {
        id: String, target_key_id: String, target_fingerprint: String, revoked_at: String,
        cert: Vec<u8>, created_at: String,
    });
    backup_row!(EmailVerificationRow => email_verifications {
        token: String, user_id: String, email: String, expires_at: String, created_at: String,
    });
    backup_row!(UserReleasePrefRow => user_release_prefs {
        user_id: String, audience: String, claim_type: String, created_at: String,
    });

    /// Apply `$op` to every (table, row-type) pair. Generating dump / wipe /
    /// load from one list keeps them — and `SNAPSHOT_TABLES` — in lockstep.
    macro_rules! for_each_table {
        ($op:ident, $($arg:tt)*) => {
            $op!("guestbook_entries", guestbook_entries, GuestbookRow, $($arg)*);
            $op!("backup_keys", backup_keys, BackupKeyRow, $($arg)*);
            $op!("domain_keys", domain_keys, DomainKeyRow, $($arg)*);
            $op!("users", users, UserRow, $($arg)*);
            $op!("auth_credentials", auth_credentials, AuthCredentialRow, $($arg)*);
            $op!("relations", relations, RelationRow, $($arg)*);
            $op!("user_keys", user_keys, UserKeyRow, $($arg)*);
            $op!("claims", claims, ClaimRow, $($arg)*);
            $op!("claim_signatures", claim_signatures, ClaimSignatureRow, $($arg)*);
            $op!("peer_keys", peer_keys, PeerKeyRow, $($arg)*);
            $op!("used_nonces", used_nonces, UsedNonceRow, $($arg)*);
            $op!("profiles", profiles, ProfileRow, $($arg)*);
            $op!("consent_grants", consent_grants, ConsentGrantRow, $($arg)*);
            $op!("claim_type_policies", claim_type_policies, ClaimTypePolicyRow, $($arg)*);
            $op!("claim_type_label_i18n", claim_type_label_i18n, ClaimLabelI18nRow, $($arg)*);
            $op!("trusted_issuers", trusted_issuers, TrustedIssuerRow, $($arg)*);
            $op!("profile_claim_prefs", profile_claim_prefs, ProfileClaimPrefRow, $($arg)*);
            $op!("release_policies", release_policies, ReleasePolicyRow, $($arg)*);
            $op!("admin_review_queue", admin_review_queue, AdminReviewBackupRow, $($arg)*);
            $op!("audit_log", audit_log, AuditLogBackupRow, $($arg)*);
            $op!("domain_key_pins", domain_key_pins, DomainKeyPinBackupRow, $($arg)*);
            $op!("issued_revocations", issued_revocations, IssuedRevocationBackupRow, $($arg)*);
            $op!("email_verifications", email_verifications, EmailVerificationRow, $($arg)*);
            $op!("user_release_prefs", user_release_prefs, UserReleasePrefRow, $($arg)*);
        };
    }

    fn dump_tables(conn: &mut SqliteConnection) -> Result<BTreeMap<String, Vec<u8>>, BackupError> {
        use crate::schema::sqlite::*;
        let mut out = BTreeMap::new();
        macro_rules! dump_one {
            ($name:literal, $table:ident, $row:ident, $out:ident, $conn:ident) => {
                let rows: Vec<$row> = $table::table.load($conn)?;
                $out.insert($name.to_string(), to_cbor(&rows)?);
            };
        }
        for_each_table!(dump_one, out, conn);
        Ok(out)
    }

    fn wipe_tables(conn: &mut SqliteConnection) -> Result<(), BackupError> {
        use crate::schema::sqlite::*;
        macro_rules! wipe_one {
            ($name:literal, $table:ident, $row:ident, $conn:ident) => {
                diesel::delete($table::table).execute($conn)?;
            };
        }
        for_each_table!(wipe_one, conn);
        Ok(())
    }

    fn load_tables(
        conn: &mut SqliteConnection,
        tables: &BTreeMap<String, Vec<u8>>,
    ) -> Result<(), BackupError> {
        use crate::schema::sqlite::*;
        macro_rules! load_one {
            ($name:literal, $table:ident, $row:ident, $conn:ident, $tables:ident) => {
                if let Some(bytes) = $tables.get($name) {
                    let rows: Vec<$row> = from_cbor(bytes)?;
                    // Chunk to stay well under SQLite's bound-parameter limit.
                    for chunk in rows.chunks(50) {
                        diesel::insert_into($table::table)
                            .values(chunk)
                            .execute($conn)?;
                    }
                }
            };
        }
        for_each_table!(load_one, conn, tables);
        Ok(())
    }

    // --- backup key management ---

    fn active_backup_key(
        conn: &mut SqliteConnection,
        passphrase: &str,
    ) -> Result<Option<[u8; 32]>, BackupError> {
        use crate::schema::sqlite::backup_keys::dsl as bk;
        let row: Option<BackupKeyRow> = bk::backup_keys
            .filter(bk::rotated_at.is_null())
            .order(bk::created_at.desc())
            .first::<BackupKeyRow>(conn)
            .optional()?;
        match row {
            None => Ok(None),
            Some(r) => {
                let raw = liblinkkeys::crypto::decrypt_private_key(
                    &r.key_encrypted,
                    passphrase.as_bytes(),
                )
                .map_err(|e| BackupError::Crypto(format!("cannot decrypt backup key: {e}")))?;
                let key: [u8; 32] = raw.try_into().map_err(|_| {
                    BackupError::Format("stored backup key is not 32 bytes".to_string())
                })?;
                Ok(Some(key))
            }
        }
    }

    fn store_new_backup_key(
        conn: &mut SqliteConnection,
        passphrase: &str,
    ) -> Result<[u8; 32], BackupError> {
        use crate::schema::sqlite::backup_keys;
        let key: [u8; 32] = rand::random();
        let enc = liblinkkeys::crypto::encrypt_private_key(&key, passphrase.as_bytes())
            .map_err(|e| BackupError::Crypto(e.to_string()))?;
        let row = BackupKeyRow {
            id: uuid::Uuid::now_v7().to_string(),
            key_encrypted: enc,
            created_at: chrono::Utc::now().to_rfc3339(),
            rotated_at: None,
        };
        diesel::insert_into(backup_keys::table)
            .values(&row)
            .execute(conn)?;
        Ok(key)
    }

    fn rotate_backup_key(
        conn: &mut SqliteConnection,
        passphrase: &str,
    ) -> Result<[u8; 32], BackupError> {
        use crate::schema::sqlite::backup_keys::dsl as bk;
        diesel::update(bk::backup_keys.filter(bk::rotated_at.is_null()))
            .set(bk::rotated_at.eq(Some(chrono::Utc::now().to_rfc3339())))
            .execute(conn)?;
        store_new_backup_key(conn, passphrase)
    }

    pub(super) fn create_backup(
        conn: &mut SqliteConnection,
        passphrase: &str,
        opts: BackupOptions,
    ) -> Result<BackupResult, BackupError> {
        let domain = crate::conversions::get_domain_name();
        conn.transaction::<_, BackupError, _>(|conn| {
            // Acquire the backup key (inside the txn so a freshly-generated key
            // row is part of this same consistent snapshot).
            let (key, new_key) = if opts.rotate {
                (rotate_backup_key(conn, passphrase)?, true)
            } else {
                match active_backup_key(conn, passphrase)? {
                    Some(k) => (k, false),
                    None => (store_new_backup_key(conn, passphrase)?, true),
                }
            };

            let tables = dump_tables(conn)?;
            let bundle = BackupBundle {
                format_version: FORMAT_VERSION,
                domain_name: domain.clone(),
                created_at: chrono::Utc::now().to_rfc3339(),
                db_backend: "sqlite".to_string(),
                domain_key_passphrase: if opts.include_passphrase {
                    Some(passphrase.to_string())
                } else {
                    None
                },
                tables,
            };
            let plaintext = to_cbor(&bundle)?;
            let ciphertext = liblinkkeys::crypto::encrypt_with_key(&key, &plaintext)
                .map_err(|e| BackupError::Crypto(e.to_string()))?;

            Ok(BackupResult {
                ciphertext,
                domain: domain.clone(),
                new_key: if new_key { Some(key) } else { None },
            })
        })
    }

    pub(super) fn restore_backup(
        conn: &mut SqliteConnection,
        bundle_bytes: &[u8],
        opts: RestoreOptions,
    ) -> Result<RestoreResult, BackupError> {
        let plaintext = liblinkkeys::crypto::decrypt_with_key(&opts.key, bundle_bytes)
            .map_err(|e| BackupError::Crypto(format!("cannot decrypt backup (wrong key?): {e}")))?;
        let bundle: BackupBundle = from_cbor(&plaintext)?;
        if bundle.format_version != FORMAT_VERSION {
            return Err(BackupError::Format(format!(
                "unsupported backup format version {}",
                bundle.format_version
            )));
        }

        let current_domain = crate::conversions::get_domain_name();
        if bundle.domain_name != current_domain && !opts.force {
            return Err(BackupError::Format(format!(
                "backup is for domain '{}' but this server is '{}'; use --force to restore anyway",
                bundle.domain_name, current_domain
            )));
        }

        conn.transaction::<_, BackupError, _>(|conn| {
            // Guard against clobbering a populated database unless forced.
            if !opts.force {
                use crate::schema::sqlite::users::dsl as u;
                let existing: i64 = u::users.count().get_result(conn)?;
                if existing > 0 {
                    return Err(BackupError::Format(
                        "target database is not empty; use --force to overwrite".to_string(),
                    ));
                }
            }
            // Defer FK enforcement to commit: the snapshot is internally
            // consistent, so wipe+reload in any order is valid at commit time.
            diesel::sql_query("PRAGMA defer_foreign_keys = ON").execute(conn)?;
            wipe_tables(conn)?;
            load_tables(conn, &bundle.tables)?;
            Ok(())
        })?;

        // Report recovered signing fingerprints so the admin can confirm DNS.
        use crate::schema::sqlite::domain_keys::dsl as dk;
        let fingerprints: Vec<String> = dk::domain_keys
            .filter(dk::key_usage.eq("sign"))
            .select(dk::fingerprint)
            .load(conn)?;

        Ok(RestoreResult {
            domain: bundle.domain_name,
            fingerprints,
            passphrase_in_bundle: bundle.domain_key_passphrase,
        })
    }
}
