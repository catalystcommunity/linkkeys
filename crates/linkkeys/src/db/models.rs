use serde::{Deserialize, Serialize};

/// Backend-agnostic domain model for guestbook entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestbookEntry {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Domain key model. NOT Serialize — contains encrypted private key material.
/// Use conversions::From<&DomainKey> for DomainPublicKey to get the public-safe type.
#[derive(Debug, Clone)]
pub struct DomainKey {
    pub id: String,
    pub public_key: Vec<u8>,
    pub private_key_encrypted: Vec<u8>,
    pub fingerprint: String,
    pub algorithm: String,
    pub key_usage: String,
    pub created_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
    pub updated_at: String,
    /// Encrypt keys only: signing key that vouches + its signature (else None).
    pub signed_by_key_id: Option<String>,
    pub key_signature: Option<Vec<u8>>,
}

/// User model. Identity only — auth credentials are stored separately.
#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Auth credential model. Stores hashed credentials per user per auth method.
#[derive(Debug, Clone)]
pub struct AuthCredential {
    pub id: String,
    pub user_id: String,
    pub credential_type: String,
    pub credential_hash: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub updated_at: String,
}

/// Relation model for ReBAC authorization tuples.
#[derive(Debug, Clone)]
pub struct Relation {
    pub id: String,
    pub subject_type: String,
    pub subject_id: String,
    pub relation: String,
    pub object_type: String,
    pub object_id: String,
    pub created_at: String,
    pub removed_at: Option<String>,
    pub updated_at: String,
}

/// User key model. NOT Serialize — contains encrypted private key material.
#[derive(Debug, Clone)]
pub struct UserKey {
    pub id: String,
    pub user_id: String,
    pub public_key: Vec<u8>,
    pub private_key_encrypted: Vec<u8>,
    pub fingerprint: String,
    pub algorithm: String,
    pub key_usage: String,
    pub created_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
    pub updated_at: String,
    /// Encrypt keys only: signing key that vouches + its signature (else None).
    pub signed_by_key_id: Option<String>,
    pub key_signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct ClaimRow {
    pub id: String,
    pub user_id: String,
    pub claim_type: String,
    pub claim_value: Vec<u8>,
    /// Signatures over this claim, one per (domain, key). Populated by the query
    /// layer after the claim row is loaded; a freshly-converted `ClaimDbRow`
    /// starts empty until signatures are attached.
    pub signatures: Vec<ClaimSignatureRow>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct ClaimSignatureRow {
    pub id: String,
    pub claim_id: String,
    pub domain: String,
    pub signed_by_key_id: String,
    pub signature: Vec<u8>,
    pub created_at: String,
}

/// A persisted consent grant: the user's standing authorization for one
/// `audience` to receive `claim_types`. `claim_types` and `requested_types` are
/// the decoded JSON arrays; `signed_grant` is CBOR(SignedConsentGrant), the
/// home-domain-attested artifact, kept so it can be re-verified or re-served.
#[derive(Debug, Clone)]
pub struct ConsentGrantRow {
    pub id: String,
    pub user_id: String,
    pub subject_domain: String,
    pub audience: String,
    pub claim_types: Vec<String>,
    pub requested_types: Vec<String>,
    pub signed_grant: Vec<u8>,
    /// CBOR([DomainClaim]) the RP asserted about itself, if any.
    pub offered_claims: Option<Vec<u8>>,
    pub issued_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
}

/// A pseudonymous identity (UUID@domain) belonging to a human account. One
/// profile per account is the never-leaked `is_root` anchor; the rest are the
/// presentable personas.
#[derive(Debug, Clone)]
pub struct Profile {
    pub id: String,
    pub account_id: String,
    pub domain: String,
    pub is_root: bool,
    pub label: Option<String>,
}

/// Parse a JSON `[String]` column. A parse failure (only reachable via DB
/// corruption — the writer always emits valid JSON) yields an empty set, which
/// is fail-safe (empty claim_types under-releases; empty requested_types
/// re-prompts), but is logged so it isn't silent.
fn parse_json_types(field: &str, raw: &str) -> Vec<String> {
    serde_json::from_str(raw).unwrap_or_else(|e| {
        log::warn!(
            "consent_grant.{} is not valid JSON ({}); treating as empty",
            field,
            e
        );
        Vec::new()
    })
}

#[cfg(feature = "postgres")]
pub mod pg {
    use diesel::prelude::*;

    // -- Guestbook --

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::pg::guestbook_entries)]
    pub struct GuestbookEntryRow {
        pub id: uuid::Uuid,
        pub name: String,
        pub created_at: chrono::DateTime<chrono::Utc>,
        pub updated_at: chrono::DateTime<chrono::Utc>,
    }

    impl From<GuestbookEntryRow> for super::GuestbookEntry {
        fn from(row: GuestbookEntryRow) -> Self {
            Self {
                id: row.id.to_string(),
                name: row.name,
                created_at: row.created_at.to_rfc3339(),
                updated_at: row.updated_at.to_rfc3339(),
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::pg::guestbook_entries)]
    pub struct NewGuestbookEntryRow {
        pub id: uuid::Uuid,
        pub name: String,
    }

    // -- Domain Keys --

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::pg::domain_keys)]
    pub struct DomainKeyRow {
        pub id: uuid::Uuid,
        pub public_key: Vec<u8>,
        pub private_key_encrypted: Vec<u8>,
        pub fingerprint: String,
        pub algorithm: String,
        pub key_usage: String,
        pub created_at: chrono::DateTime<chrono::Utc>,
        pub expires_at: chrono::DateTime<chrono::Utc>,
        pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
        pub updated_at: chrono::DateTime<chrono::Utc>,
        pub signed_by_key_id: Option<String>,
        pub key_signature: Option<Vec<u8>>,
    }

    impl From<DomainKeyRow> for super::DomainKey {
        fn from(row: DomainKeyRow) -> Self {
            Self {
                id: row.id.to_string(),
                public_key: row.public_key,
                private_key_encrypted: row.private_key_encrypted,
                fingerprint: row.fingerprint,
                algorithm: row.algorithm,
                key_usage: row.key_usage,
                created_at: row.created_at.to_rfc3339(),
                expires_at: row.expires_at.to_rfc3339(),
                revoked_at: row.revoked_at.map(|t| t.to_rfc3339()),
                updated_at: row.updated_at.to_rfc3339(),
                signed_by_key_id: row.signed_by_key_id,
                key_signature: row.key_signature,
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::pg::domain_keys)]
    pub struct NewDomainKeyRow {
        pub id: uuid::Uuid,
        pub public_key: Vec<u8>,
        pub private_key_encrypted: Vec<u8>,
        pub fingerprint: String,
        pub algorithm: String,
        pub key_usage: String,
        pub expires_at: chrono::DateTime<chrono::Utc>,
        pub signed_by_key_id: Option<String>,
        pub key_signature: Option<Vec<u8>>,
    }

    // -- Users --

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::pg::users)]
    pub struct UserRow {
        pub id: uuid::Uuid,
        pub username: String,
        pub display_name: String,
        pub is_active: bool,
        pub created_at: chrono::DateTime<chrono::Utc>,
        pub updated_at: chrono::DateTime<chrono::Utc>,
    }

    impl From<UserRow> for super::User {
        fn from(row: UserRow) -> Self {
            Self {
                id: row.id.to_string(),
                username: row.username,
                display_name: row.display_name,
                is_active: row.is_active,
                created_at: row.created_at.to_rfc3339(),
                updated_at: row.updated_at.to_rfc3339(),
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::pg::users)]
    pub struct NewUserRow {
        pub id: uuid::Uuid,
        pub username: String,
        pub display_name: String,
    }

    // -- Auth Credentials --

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::pg::auth_credentials)]
    pub struct AuthCredentialRow {
        pub id: uuid::Uuid,
        pub user_id: uuid::Uuid,
        pub credential_type: String,
        pub credential_hash: String,
        pub created_at: chrono::DateTime<chrono::Utc>,
        pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
        pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
        pub updated_at: chrono::DateTime<chrono::Utc>,
    }

    impl From<AuthCredentialRow> for super::AuthCredential {
        fn from(row: AuthCredentialRow) -> Self {
            Self {
                id: row.id.to_string(),
                user_id: row.user_id.to_string(),
                credential_type: row.credential_type,
                credential_hash: row.credential_hash,
                created_at: row.created_at.to_rfc3339(),
                expires_at: row.expires_at.map(|t| t.to_rfc3339()),
                revoked_at: row.revoked_at.map(|t| t.to_rfc3339()),
                updated_at: row.updated_at.to_rfc3339(),
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::pg::auth_credentials)]
    pub struct NewAuthCredentialRow {
        pub id: uuid::Uuid,
        pub user_id: uuid::Uuid,
        pub credential_type: String,
        pub credential_hash: String,
    }

    // -- User Keys --

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::pg::user_keys)]
    pub struct UserKeyRow {
        pub id: uuid::Uuid,
        pub user_id: uuid::Uuid,
        pub public_key: Vec<u8>,
        pub private_key_encrypted: Vec<u8>,
        pub fingerprint: String,
        pub algorithm: String,
        pub key_usage: String,
        pub created_at: chrono::DateTime<chrono::Utc>,
        pub expires_at: chrono::DateTime<chrono::Utc>,
        pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
        pub updated_at: chrono::DateTime<chrono::Utc>,
        pub signed_by_key_id: Option<String>,
        pub key_signature: Option<Vec<u8>>,
    }

    impl From<UserKeyRow> for super::UserKey {
        fn from(row: UserKeyRow) -> Self {
            Self {
                id: row.id.to_string(),
                user_id: row.user_id.to_string(),
                public_key: row.public_key,
                private_key_encrypted: row.private_key_encrypted,
                fingerprint: row.fingerprint,
                algorithm: row.algorithm,
                key_usage: row.key_usage,
                created_at: row.created_at.to_rfc3339(),
                expires_at: row.expires_at.to_rfc3339(),
                revoked_at: row.revoked_at.map(|t| t.to_rfc3339()),
                updated_at: row.updated_at.to_rfc3339(),
                signed_by_key_id: row.signed_by_key_id,
                key_signature: row.key_signature,
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::pg::user_keys)]
    pub struct NewUserKeyRow {
        pub id: uuid::Uuid,
        pub user_id: uuid::Uuid,
        pub public_key: Vec<u8>,
        pub private_key_encrypted: Vec<u8>,
        pub fingerprint: String,
        pub algorithm: String,
        pub expires_at: chrono::DateTime<chrono::Utc>,
    }

    // -- Claims --

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::pg::claims)]
    pub struct ClaimDbRow {
        pub id: uuid::Uuid,
        pub user_id: uuid::Uuid,
        pub claim_type: String,
        pub claim_value: Vec<u8>,
        pub created_at: chrono::DateTime<chrono::Utc>,
        pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
        pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
        pub updated_at: chrono::DateTime<chrono::Utc>,
    }

    impl From<ClaimDbRow> for super::ClaimRow {
        fn from(row: ClaimDbRow) -> Self {
            Self {
                id: row.id.to_string(),
                user_id: row.user_id.to_string(),
                claim_type: row.claim_type,
                claim_value: row.claim_value,
                signatures: Vec::new(),
                created_at: row.created_at.to_rfc3339(),
                expires_at: row.expires_at.map(|t| t.to_rfc3339()),
                revoked_at: row.revoked_at.map(|t| t.to_rfc3339()),
                updated_at: row.updated_at.to_rfc3339(),
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::pg::claims)]
    pub struct NewClaimDbRow {
        pub id: uuid::Uuid,
        pub user_id: uuid::Uuid,
        pub claim_type: String,
        pub claim_value: Vec<u8>,
        pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    }

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::pg::claim_signatures)]
    pub struct ClaimSignatureDbRow {
        pub id: uuid::Uuid,
        pub claim_id: uuid::Uuid,
        pub domain: String,
        pub signed_by_key_id: uuid::Uuid,
        pub signature: Vec<u8>,
        pub created_at: chrono::DateTime<chrono::Utc>,
    }

    impl From<ClaimSignatureDbRow> for super::ClaimSignatureRow {
        fn from(row: ClaimSignatureDbRow) -> Self {
            Self {
                id: row.id.to_string(),
                claim_id: row.claim_id.to_string(),
                domain: row.domain,
                signed_by_key_id: row.signed_by_key_id.to_string(),
                signature: row.signature,
                created_at: row.created_at.to_rfc3339(),
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::pg::claim_signatures)]
    pub struct NewClaimSignatureDbRow {
        pub id: uuid::Uuid,
        pub claim_id: uuid::Uuid,
        pub domain: String,
        pub signed_by_key_id: uuid::Uuid,
        pub signature: Vec<u8>,
    }

    // -- Relations --

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::pg::relations)]
    pub struct RelationRow {
        pub id: uuid::Uuid,
        pub subject_type: String,
        pub subject_id: String,
        pub relation: String,
        pub object_type: String,
        pub object_id: String,
        pub created_at: chrono::DateTime<chrono::Utc>,
        pub removed_at: Option<chrono::DateTime<chrono::Utc>>,
        pub updated_at: chrono::DateTime<chrono::Utc>,
    }

    impl From<RelationRow> for super::Relation {
        fn from(row: RelationRow) -> Self {
            Self {
                id: row.id.to_string(),
                subject_type: row.subject_type,
                subject_id: row.subject_id,
                relation: row.relation,
                object_type: row.object_type,
                object_id: row.object_id,
                created_at: row.created_at.to_rfc3339(),
                removed_at: row.removed_at.map(|t| t.to_rfc3339()),
                updated_at: row.updated_at.to_rfc3339(),
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::pg::relations)]
    pub struct NewRelationRow {
        pub id: uuid::Uuid,
        pub subject_type: String,
        pub subject_id: String,
        pub relation: String,
        pub object_type: String,
        pub object_id: String,
    }

    // -- Consent grants --

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::pg::consent_grants)]
    pub struct ConsentGrantDbRow {
        pub id: uuid::Uuid,
        pub user_id: uuid::Uuid,
        pub subject_domain: String,
        pub audience: String,
        pub claim_types: String,
        pub requested_types: String,
        pub signed_grant: Vec<u8>,
        pub offered_claims: Option<Vec<u8>>,
        pub issued_at: chrono::DateTime<chrono::Utc>,
        pub expires_at: chrono::DateTime<chrono::Utc>,
        pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    }

    impl From<ConsentGrantDbRow> for super::ConsentGrantRow {
        fn from(row: ConsentGrantDbRow) -> Self {
            Self {
                id: row.id.to_string(),
                user_id: row.user_id.to_string(),
                subject_domain: row.subject_domain,
                audience: row.audience,
                claim_types: super::parse_json_types("claim_types", &row.claim_types),
                requested_types: super::parse_json_types("requested_types", &row.requested_types),
                signed_grant: row.signed_grant,
                offered_claims: row.offered_claims,
                issued_at: row.issued_at.to_rfc3339(),
                expires_at: row.expires_at.to_rfc3339(),
                revoked_at: row.revoked_at.map(|t| t.to_rfc3339()),
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::pg::consent_grants)]
    pub struct NewConsentGrantDbRow {
        pub id: uuid::Uuid,
        pub user_id: uuid::Uuid,
        pub subject_domain: String,
        pub audience: String,
        pub claim_types: String,
        pub requested_types: String,
        pub signed_grant: Vec<u8>,
        pub offered_claims: Option<Vec<u8>>,
        pub issued_at: chrono::DateTime<chrono::Utc>,
        pub expires_at: chrono::DateTime<chrono::Utc>,
    }

    // -- Profiles --

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::pg::profiles)]
    pub struct ProfileRow {
        pub id: uuid::Uuid,
        pub account_id: uuid::Uuid,
        pub domain: String,
        pub is_root: bool,
        pub label: Option<String>,
    }

    impl From<ProfileRow> for super::Profile {
        fn from(row: ProfileRow) -> Self {
            Self {
                id: row.id.to_string(),
                account_id: row.account_id.to_string(),
                domain: row.domain,
                is_root: row.is_root,
                label: row.label,
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::pg::profiles)]
    pub struct NewProfileRow {
        pub id: uuid::Uuid,
        pub account_id: uuid::Uuid,
        pub domain: String,
        pub is_root: bool,
        pub label: Option<String>,
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use diesel::prelude::*;

    // -- Guestbook --

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::sqlite::guestbook_entries)]
    pub struct GuestbookEntryRow {
        pub id: String,
        pub name: String,
        pub created_at: String,
        pub updated_at: String,
    }

    impl From<GuestbookEntryRow> for super::GuestbookEntry {
        fn from(row: GuestbookEntryRow) -> Self {
            Self {
                id: row.id,
                name: row.name,
                created_at: row.created_at,
                updated_at: row.updated_at,
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::sqlite::guestbook_entries)]
    pub struct NewGuestbookEntryRow {
        pub id: String,
        pub name: String,
    }

    // -- Domain Keys --

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::sqlite::domain_keys)]
    pub struct DomainKeyRow {
        pub id: String,
        pub public_key: Vec<u8>,
        pub private_key_encrypted: Vec<u8>,
        pub fingerprint: String,
        pub algorithm: String,
        pub key_usage: String,
        pub created_at: String,
        pub expires_at: String,
        pub revoked_at: Option<String>,
        pub updated_at: String,
        pub signed_by_key_id: Option<String>,
        pub key_signature: Option<Vec<u8>>,
    }

    impl From<DomainKeyRow> for super::DomainKey {
        fn from(row: DomainKeyRow) -> Self {
            Self {
                id: row.id,
                public_key: row.public_key,
                private_key_encrypted: row.private_key_encrypted,
                fingerprint: row.fingerprint,
                algorithm: row.algorithm,
                key_usage: row.key_usage,
                created_at: row.created_at,
                expires_at: row.expires_at,
                revoked_at: row.revoked_at,
                updated_at: row.updated_at,
                signed_by_key_id: row.signed_by_key_id,
                key_signature: row.key_signature,
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::sqlite::domain_keys)]
    pub struct NewDomainKeyRow {
        pub id: String,
        pub public_key: Vec<u8>,
        pub private_key_encrypted: Vec<u8>,
        pub fingerprint: String,
        pub algorithm: String,
        pub key_usage: String,
        pub expires_at: String,
        pub signed_by_key_id: Option<String>,
        pub key_signature: Option<Vec<u8>>,
    }

    // -- Users --

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::sqlite::users)]
    pub struct UserRow {
        pub id: String,
        pub username: String,
        pub display_name: String,
        pub is_active: i32,
        pub created_at: String,
        pub updated_at: String,
    }

    impl From<UserRow> for super::User {
        fn from(row: UserRow) -> Self {
            Self {
                id: row.id,
                username: row.username,
                display_name: row.display_name,
                is_active: row.is_active != 0,
                created_at: row.created_at,
                updated_at: row.updated_at,
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::sqlite::users)]
    pub struct NewUserRow {
        pub id: String,
        pub username: String,
        pub display_name: String,
    }

    // -- Auth Credentials --

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::sqlite::auth_credentials)]
    pub struct AuthCredentialRow {
        pub id: String,
        pub user_id: String,
        pub credential_type: String,
        pub credential_hash: String,
        pub created_at: String,
        pub expires_at: Option<String>,
        pub revoked_at: Option<String>,
        pub updated_at: String,
    }

    impl From<AuthCredentialRow> for super::AuthCredential {
        fn from(row: AuthCredentialRow) -> Self {
            Self {
                id: row.id,
                user_id: row.user_id,
                credential_type: row.credential_type,
                credential_hash: row.credential_hash,
                created_at: row.created_at,
                expires_at: row.expires_at,
                revoked_at: row.revoked_at,
                updated_at: row.updated_at,
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::sqlite::auth_credentials)]
    pub struct NewAuthCredentialRow {
        pub id: String,
        pub user_id: String,
        pub credential_type: String,
        pub credential_hash: String,
    }

    // -- User Keys --

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::sqlite::user_keys)]
    pub struct UserKeyRow {
        pub id: String,
        pub user_id: String,
        pub public_key: Vec<u8>,
        pub private_key_encrypted: Vec<u8>,
        pub fingerprint: String,
        pub algorithm: String,
        pub key_usage: String,
        pub created_at: String,
        pub expires_at: String,
        pub revoked_at: Option<String>,
        pub updated_at: String,
        pub signed_by_key_id: Option<String>,
        pub key_signature: Option<Vec<u8>>,
    }

    impl From<UserKeyRow> for super::UserKey {
        fn from(row: UserKeyRow) -> Self {
            Self {
                id: row.id,
                user_id: row.user_id,
                public_key: row.public_key,
                private_key_encrypted: row.private_key_encrypted,
                fingerprint: row.fingerprint,
                algorithm: row.algorithm,
                key_usage: row.key_usage,
                created_at: row.created_at,
                expires_at: row.expires_at,
                revoked_at: row.revoked_at,
                updated_at: row.updated_at,
                signed_by_key_id: row.signed_by_key_id,
                key_signature: row.key_signature,
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::sqlite::user_keys)]
    pub struct NewUserKeyRow {
        pub id: String,
        pub user_id: String,
        pub public_key: Vec<u8>,
        pub private_key_encrypted: Vec<u8>,
        pub fingerprint: String,
        pub algorithm: String,
        pub expires_at: String,
    }

    // -- Claims --

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::sqlite::claims)]
    pub struct ClaimDbRow {
        pub id: String,
        pub user_id: String,
        pub claim_type: String,
        pub claim_value: Vec<u8>,
        pub created_at: String,
        pub expires_at: Option<String>,
        pub revoked_at: Option<String>,
        pub updated_at: String,
    }

    impl From<ClaimDbRow> for super::ClaimRow {
        fn from(row: ClaimDbRow) -> Self {
            Self {
                id: row.id,
                user_id: row.user_id,
                claim_type: row.claim_type,
                claim_value: row.claim_value,
                signatures: Vec::new(),
                created_at: row.created_at,
                expires_at: row.expires_at,
                revoked_at: row.revoked_at,
                updated_at: row.updated_at,
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::sqlite::claims)]
    pub struct NewClaimDbRow {
        pub id: String,
        pub user_id: String,
        pub claim_type: String,
        pub claim_value: Vec<u8>,
        pub expires_at: Option<String>,
    }

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::sqlite::claim_signatures)]
    pub struct ClaimSignatureDbRow {
        pub id: String,
        pub claim_id: String,
        pub domain: String,
        pub signed_by_key_id: String,
        pub signature: Vec<u8>,
        pub created_at: String,
    }

    impl From<ClaimSignatureDbRow> for super::ClaimSignatureRow {
        fn from(row: ClaimSignatureDbRow) -> Self {
            Self {
                id: row.id,
                claim_id: row.claim_id,
                domain: row.domain,
                signed_by_key_id: row.signed_by_key_id,
                signature: row.signature,
                created_at: row.created_at,
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::sqlite::claim_signatures)]
    pub struct NewClaimSignatureDbRow {
        pub id: String,
        pub claim_id: String,
        pub domain: String,
        pub signed_by_key_id: String,
        pub signature: Vec<u8>,
    }

    // -- Relations --

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::sqlite::relations)]
    pub struct RelationRow {
        pub id: String,
        pub subject_type: String,
        pub subject_id: String,
        pub relation: String,
        pub object_type: String,
        pub object_id: String,
        pub created_at: String,
        pub removed_at: Option<String>,
        pub updated_at: String,
    }

    impl From<RelationRow> for super::Relation {
        fn from(row: RelationRow) -> Self {
            Self {
                id: row.id,
                subject_type: row.subject_type,
                subject_id: row.subject_id,
                relation: row.relation,
                object_type: row.object_type,
                object_id: row.object_id,
                created_at: row.created_at,
                removed_at: row.removed_at,
                updated_at: row.updated_at,
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::sqlite::relations)]
    pub struct NewRelationRow {
        pub id: String,
        pub subject_type: String,
        pub subject_id: String,
        pub relation: String,
        pub object_type: String,
        pub object_id: String,
    }

    // -- Consent grants --

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::sqlite::consent_grants)]
    pub struct ConsentGrantDbRow {
        pub id: String,
        pub user_id: String,
        pub subject_domain: String,
        pub audience: String,
        pub claim_types: String,
        pub requested_types: String,
        pub signed_grant: Vec<u8>,
        pub offered_claims: Option<Vec<u8>>,
        pub issued_at: String,
        pub expires_at: String,
        pub revoked_at: Option<String>,
    }

    impl From<ConsentGrantDbRow> for super::ConsentGrantRow {
        fn from(row: ConsentGrantDbRow) -> Self {
            Self {
                id: row.id,
                user_id: row.user_id,
                subject_domain: row.subject_domain,
                audience: row.audience,
                claim_types: super::parse_json_types("claim_types", &row.claim_types),
                requested_types: super::parse_json_types("requested_types", &row.requested_types),
                signed_grant: row.signed_grant,
                offered_claims: row.offered_claims,
                issued_at: row.issued_at,
                expires_at: row.expires_at,
                revoked_at: row.revoked_at,
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::sqlite::consent_grants)]
    pub struct NewConsentGrantDbRow {
        pub id: String,
        pub user_id: String,
        pub subject_domain: String,
        pub audience: String,
        pub claim_types: String,
        pub requested_types: String,
        pub signed_grant: Vec<u8>,
        pub offered_claims: Option<Vec<u8>>,
        pub issued_at: String,
        pub expires_at: String,
    }

    // -- Profiles --

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::sqlite::profiles)]
    pub struct ProfileRow {
        pub id: String,
        pub account_id: String,
        pub domain: String,
        pub is_root: i32,
        pub label: Option<String>,
    }

    impl From<ProfileRow> for super::Profile {
        fn from(row: ProfileRow) -> Self {
            Self {
                id: row.id,
                account_id: row.account_id,
                domain: row.domain,
                is_root: row.is_root != 0,
                label: row.label,
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::sqlite::profiles)]
    pub struct NewProfileRow {
        pub id: String,
        pub account_id: String,
        pub domain: String,
        pub is_root: i32,
        pub label: Option<String>,
    }
}
