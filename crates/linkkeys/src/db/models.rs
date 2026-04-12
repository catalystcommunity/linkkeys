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
    pub created_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
    pub updated_at: String,
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
    pub created_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct ClaimRow {
    pub id: String,
    pub user_id: String,
    pub claim_type: String,
    pub claim_value: Vec<u8>,
    pub signed_by_key_id: String,
    pub signature: Vec<u8>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub updated_at: String,
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
        pub created_at: chrono::DateTime<chrono::Utc>,
        pub expires_at: chrono::DateTime<chrono::Utc>,
        pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
        pub updated_at: chrono::DateTime<chrono::Utc>,
    }

    impl From<DomainKeyRow> for super::DomainKey {
        fn from(row: DomainKeyRow) -> Self {
            Self {
                id: row.id.to_string(),
                public_key: row.public_key,
                private_key_encrypted: row.private_key_encrypted,
                fingerprint: row.fingerprint,
                algorithm: row.algorithm,
                created_at: row.created_at.to_rfc3339(),
                expires_at: row.expires_at.to_rfc3339(),
                revoked_at: row.revoked_at.map(|t| t.to_rfc3339()),
                updated_at: row.updated_at.to_rfc3339(),
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
        pub expires_at: chrono::DateTime<chrono::Utc>,
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
        pub created_at: chrono::DateTime<chrono::Utc>,
        pub expires_at: chrono::DateTime<chrono::Utc>,
        pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
        pub updated_at: chrono::DateTime<chrono::Utc>,
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
                created_at: row.created_at.to_rfc3339(),
                expires_at: row.expires_at.to_rfc3339(),
                revoked_at: row.revoked_at.map(|t| t.to_rfc3339()),
                updated_at: row.updated_at.to_rfc3339(),
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
        pub signed_by_key_id: uuid::Uuid,
        pub signature: Vec<u8>,
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
                signed_by_key_id: row.signed_by_key_id.to_string(),
                signature: row.signature,
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
        pub signed_by_key_id: uuid::Uuid,
        pub signature: Vec<u8>,
        pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
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
        pub created_at: String,
        pub expires_at: String,
        pub revoked_at: Option<String>,
        pub updated_at: String,
    }

    impl From<DomainKeyRow> for super::DomainKey {
        fn from(row: DomainKeyRow) -> Self {
            Self {
                id: row.id,
                public_key: row.public_key,
                private_key_encrypted: row.private_key_encrypted,
                fingerprint: row.fingerprint,
                algorithm: row.algorithm,
                created_at: row.created_at,
                expires_at: row.expires_at,
                revoked_at: row.revoked_at,
                updated_at: row.updated_at,
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
        pub expires_at: String,
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
        pub created_at: String,
        pub expires_at: String,
        pub revoked_at: Option<String>,
        pub updated_at: String,
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
                created_at: row.created_at,
                expires_at: row.expires_at,
                revoked_at: row.revoked_at,
                updated_at: row.updated_at,
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
        pub signed_by_key_id: String,
        pub signature: Vec<u8>,
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
                signed_by_key_id: row.signed_by_key_id,
                signature: row.signature,
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
        pub signed_by_key_id: String,
        pub signature: Vec<u8>,
        pub expires_at: Option<String>,
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
}
