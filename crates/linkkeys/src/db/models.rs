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
    /// A domain administrator account — has the admin relation + credentials but
    /// no presentable profile, and is refused on the RP (app) login path.
    pub is_admin_account: bool,
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
    /// Signed attestation time (RFC3339 UTC) — when this claim was signed. Part
    /// of the signed payload (SEC-08).
    pub attested_at: String,
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

/// One entry in the claim-type policy registry: the rules for setting and
/// signing a single claim type. See `liblinkkeys::claim_policy`.
#[derive(Debug, Clone)]
pub struct ClaimTypePolicy {
    pub claim_type: String,
    pub label: String,
    pub description: String,
    pub value_type: String,
    pub max_bytes: i64,
    pub set_rule: String,
    pub signing_rule: String,
    pub requires_approval: bool,
    pub user_settable: bool,
    pub default_auto_sign: bool,
    pub suggested: bool,
}

/// A domain whose signature is accepted as attestation for a claim type (lane C).
#[derive(Debug, Clone)]
pub struct TrustedIssuer {
    pub claim_type: String,
    pub issuer_domain: String,
}

/// A user's per-profile auto-sign preference for one claim type.
#[derive(Debug, Clone)]
pub struct ProfileClaimPref {
    pub profile_id: String,
    pub claim_type: String,
    pub auto_sign: bool,
}

/// A per-audience release-policy row (forced_allow / forced_deny). Audience `*`
/// is the global default.
#[derive(Debug, Clone)]
pub struct ReleasePolicy {
    pub audience: String,
    pub claim_type: String,
    pub disposition: String,
}

/// A self-asserted claim awaiting admin approval before the IDP signs it. This
/// is the claim-approval VIEW of the general `admin_review_queue`
/// (`kind = "claim_approval"`), so its claim fields are always populated.
#[derive(Debug, Clone)]
pub struct ClaimApproval {
    pub id: String,
    pub user_id: String,
    pub claim_type: String,
    pub claim_value: Vec<u8>,
    pub status: String,
    pub resolved_by: Option<String>,
    pub resolved_at: Option<String>,
    pub created_at: String,
}

/// A general item on the domain admin review queue. `kind` discriminates
/// (`claim_approval`, `key_mismatch`, ...); claim fields are only set for
/// claim approvals, while `subject`/`detail` carry security-item context.
#[derive(Debug, Clone)]
pub struct AdminReview {
    pub id: String,
    pub kind: String,
    pub user_id: Option<String>,
    pub claim_type: Option<String>,
    pub claim_value: Option<Vec<u8>>,
    pub subject: Option<String>,
    pub detail: Option<String>,
    pub status: String,
    pub resolved_by: Option<String>,
    pub resolved_at: Option<String>,
    pub created_at: String,
}

/// An append-only audit-log event.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub id: String,
    pub event: String,
    pub subject: Option<String>,
    pub actor: Option<String>,
    pub detail: Option<String>,
    pub created_at: String,
}

/// The pinned DNS fingerprint set for a peer domain (SEC-01 TOFU). `fingerprints`
/// is the sorted, comma-joined set observed on first successful contact.
#[derive(Debug, Clone)]
pub struct DomainKeyPin {
    pub domain: String,
    pub fingerprints: String,
    pub pinned_at: String,
    pub last_checked_at: String,
}

/// A sibling-signed revocation certificate this domain has issued (SEC-08).
/// `cert` is the canonical CSIL CBOR of the full RevocationCertificate; served to
/// peers via DomainKeys/get-revocations. `revoked_at` is the domain's asserted
/// "untrustworthy after this instant".
#[derive(Debug, Clone)]
pub struct IssuedRevocation {
    pub id: String,
    pub target_key_id: String,
    pub target_fingerprint: String,
    pub revoked_at: String,
    pub cert: Vec<u8>,
    pub created_at: String,
}

/// A pending email-verification challenge. `expires_at` is RFC3339 UTC.
#[derive(Debug, Clone)]
pub struct EmailVerification {
    pub token: String,
    pub user_id: String,
    pub email: String,
    pub expires_at: String,
}

/// A cached public key of another domain (append-only). Lets us verify stored
/// external (attested) signatures even after the issuer rotates or disappears.
#[derive(Debug, Clone)]
pub struct PeerKey {
    pub domain: String,
    pub key_id: String,
    pub public_key: Vec<u8>,
    pub algorithm: String,
    pub fingerprint: String,
    pub key_usage: String,
    /// RFC3339; honoured at verify time so an expired issuer key won't verify.
    pub expires_at: String,
    /// RFC3339 if the issuer revoked the key; honoured at verify time.
    pub revoked_at: Option<String>,
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
        pub is_admin_account: bool,
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
                is_admin_account: row.is_admin_account,
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
        pub attested_at: chrono::DateTime<chrono::Utc>,
    }

    impl From<ClaimDbRow> for super::ClaimRow {
        fn from(row: ClaimDbRow) -> Self {
            Self {
                id: row.id.to_string(),
                user_id: row.user_id.to_string(),
                claim_type: row.claim_type,
                claim_value: row.claim_value,
                signatures: Vec::new(),
                attested_at: row.attested_at.to_rfc3339(),
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
        pub attested_at: chrono::DateTime<chrono::Utc>,
    }

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::pg::claim_signatures)]
    pub struct ClaimSignatureDbRow {
        pub id: uuid::Uuid,
        pub claim_id: uuid::Uuid,
        pub domain: String,
        // VARCHAR, not UUID: a signature may come from an external issuer whose
        // key id is not one of our domain_keys UUIDs.
        pub signed_by_key_id: String,
        pub signature: Vec<u8>,
        pub created_at: chrono::DateTime<chrono::Utc>,
    }

    impl From<ClaimSignatureDbRow> for super::ClaimSignatureRow {
        fn from(row: ClaimSignatureDbRow) -> Self {
            Self {
                id: row.id.to_string(),
                claim_id: row.claim_id.to_string(),
                domain: row.domain,
                signed_by_key_id: row.signed_by_key_id,
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
        pub signed_by_key_id: String,
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

    // -- Claim-type policy registry --

    #[derive(Queryable, Selectable, Insertable, AsChangeset)]
    #[diesel(table_name = crate::schema::pg::claim_type_policies)]
    #[diesel(primary_key(claim_type))]
    pub struct ClaimTypePolicyRow {
        pub claim_type: String,
        pub label: String,
        pub description: String,
        pub value_type: String,
        pub max_bytes: i64,
        pub set_rule: String,
        pub signing_rule: String,
        pub requires_approval: bool,
        pub user_settable: bool,
        pub default_auto_sign: bool,
        pub suggested: bool,
    }

    impl From<ClaimTypePolicyRow> for super::ClaimTypePolicy {
        fn from(r: ClaimTypePolicyRow) -> Self {
            Self {
                claim_type: r.claim_type,
                label: r.label,
                description: r.description,
                value_type: r.value_type,
                max_bytes: r.max_bytes,
                set_rule: r.set_rule,
                signing_rule: r.signing_rule,
                requires_approval: r.requires_approval,
                user_settable: r.user_settable,
                default_auto_sign: r.default_auto_sign,
                suggested: r.suggested,
            }
        }
    }

    impl From<super::ClaimTypePolicy> for ClaimTypePolicyRow {
        fn from(p: super::ClaimTypePolicy) -> Self {
            Self {
                claim_type: p.claim_type,
                label: p.label,
                description: p.description,
                value_type: p.value_type,
                max_bytes: p.max_bytes,
                set_rule: p.set_rule,
                signing_rule: p.signing_rule,
                requires_approval: p.requires_approval,
                user_settable: p.user_settable,
                default_auto_sign: p.default_auto_sign,
                suggested: p.suggested,
            }
        }
    }

    #[derive(Queryable, Selectable, Insertable)]
    #[diesel(table_name = crate::schema::pg::trusted_issuers)]
    pub struct TrustedIssuerRow {
        pub claim_type: String,
        pub issuer_domain: String,
    }

    impl From<TrustedIssuerRow> for super::TrustedIssuer {
        fn from(r: TrustedIssuerRow) -> Self {
            Self {
                claim_type: r.claim_type,
                issuer_domain: r.issuer_domain,
            }
        }
    }

    #[derive(Queryable, Selectable, Insertable, AsChangeset)]
    #[diesel(table_name = crate::schema::pg::profile_claim_prefs)]
    #[diesel(primary_key(profile_id, claim_type))]
    pub struct ProfileClaimPrefRow {
        pub profile_id: String,
        pub claim_type: String,
        pub auto_sign: bool,
    }

    impl From<ProfileClaimPrefRow> for super::ProfileClaimPref {
        fn from(r: ProfileClaimPrefRow) -> Self {
            Self {
                profile_id: r.profile_id,
                claim_type: r.claim_type,
                auto_sign: r.auto_sign,
            }
        }
    }

    #[derive(Queryable, Selectable, Insertable)]
    #[diesel(table_name = crate::schema::pg::release_policies)]
    pub struct ReleasePolicyRow {
        pub audience: String,
        pub claim_type: String,
        pub disposition: String,
    }

    impl From<ReleasePolicyRow> for super::ReleasePolicy {
        fn from(r: ReleasePolicyRow) -> Self {
            Self {
                audience: r.audience,
                claim_type: r.claim_type,
                disposition: r.disposition,
            }
        }
    }

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::pg::admin_review_queue)]
    pub struct AdminReviewRow {
        pub id: uuid::Uuid,
        pub kind: String,
        pub user_id: Option<uuid::Uuid>,
        pub claim_type: Option<String>,
        pub claim_value: Option<Vec<u8>>,
        pub subject: Option<String>,
        pub detail: Option<String>,
        pub status: String,
        pub resolved_by: Option<String>,
        pub resolved_at: Option<chrono::DateTime<chrono::Utc>>,
        pub created_at: chrono::DateTime<chrono::Utc>,
        pub updated_at: chrono::DateTime<chrono::Utc>,
    }

    impl From<AdminReviewRow> for super::AdminReview {
        fn from(r: AdminReviewRow) -> Self {
            Self {
                id: r.id.to_string(),
                kind: r.kind,
                user_id: r.user_id.map(|u| u.to_string()),
                claim_type: r.claim_type,
                claim_value: r.claim_value,
                subject: r.subject,
                detail: r.detail,
                status: r.status,
                resolved_by: r.resolved_by,
                resolved_at: r.resolved_at.map(|t| t.to_rfc3339()),
                created_at: r.created_at.to_rfc3339(),
            }
        }
    }

    /// Claim-approval view: only valid for rows with kind = "claim_approval",
    /// where the claim columns are guaranteed present.
    impl From<AdminReviewRow> for super::ClaimApproval {
        fn from(r: AdminReviewRow) -> Self {
            Self {
                id: r.id.to_string(),
                user_id: r.user_id.map(|u| u.to_string()).unwrap_or_default(),
                claim_type: r.claim_type.unwrap_or_default(),
                claim_value: r.claim_value.unwrap_or_default(),
                status: r.status,
                resolved_by: r.resolved_by,
                resolved_at: r.resolved_at.map(|t| t.to_rfc3339()),
                created_at: r.created_at.to_rfc3339(),
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::pg::admin_review_queue)]
    pub struct NewClaimApprovalRow {
        pub id: uuid::Uuid,
        pub kind: String,
        pub user_id: uuid::Uuid,
        pub claim_type: String,
        pub claim_value: Vec<u8>,
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::pg::admin_review_queue)]
    pub struct NewAdminReviewRow {
        pub id: uuid::Uuid,
        pub kind: String,
        pub subject: Option<String>,
        pub detail: Option<String>,
    }

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::pg::audit_log)]
    pub struct AuditLogRow {
        pub id: uuid::Uuid,
        pub event: String,
        pub subject: Option<String>,
        pub actor: Option<String>,
        pub detail: Option<String>,
        pub created_at: chrono::DateTime<chrono::Utc>,
    }

    impl From<AuditLogRow> for super::AuditEntry {
        fn from(r: AuditLogRow) -> Self {
            Self {
                id: r.id.to_string(),
                event: r.event,
                subject: r.subject,
                actor: r.actor,
                detail: r.detail,
                created_at: r.created_at.to_rfc3339(),
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::pg::audit_log)]
    pub struct NewAuditLogRow {
        pub id: uuid::Uuid,
        pub event: String,
        pub subject: Option<String>,
        pub actor: Option<String>,
        pub detail: Option<String>,
    }

    #[derive(Queryable, Selectable, Insertable)]
    #[diesel(table_name = crate::schema::pg::domain_key_pins)]
    pub struct DomainKeyPinRow {
        pub domain: String,
        pub fingerprints: String,
        pub pinned_at: chrono::DateTime<chrono::Utc>,
        pub last_checked_at: chrono::DateTime<chrono::Utc>,
    }

    impl From<DomainKeyPinRow> for super::DomainKeyPin {
        fn from(r: DomainKeyPinRow) -> Self {
            Self {
                domain: r.domain,
                fingerprints: r.fingerprints,
                pinned_at: r.pinned_at.to_rfc3339(),
                last_checked_at: r.last_checked_at.to_rfc3339(),
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::pg::domain_key_pins)]
    pub struct NewDomainKeyPinRow {
        pub domain: String,
        pub fingerprints: String,
    }

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::pg::issued_revocations)]
    pub struct IssuedRevocationRow {
        pub id: uuid::Uuid,
        pub target_key_id: String,
        pub target_fingerprint: String,
        pub revoked_at: chrono::DateTime<chrono::Utc>,
        pub cert: Vec<u8>,
        pub created_at: chrono::DateTime<chrono::Utc>,
    }

    impl From<IssuedRevocationRow> for super::IssuedRevocation {
        fn from(r: IssuedRevocationRow) -> Self {
            Self {
                id: r.id.to_string(),
                target_key_id: r.target_key_id,
                target_fingerprint: r.target_fingerprint,
                revoked_at: r.revoked_at.to_rfc3339(),
                cert: r.cert,
                created_at: r.created_at.to_rfc3339(),
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::pg::issued_revocations)]
    pub struct NewIssuedRevocationRow {
        pub id: uuid::Uuid,
        pub target_key_id: String,
        pub target_fingerprint: String,
        pub revoked_at: chrono::DateTime<chrono::Utc>,
        pub cert: Vec<u8>,
    }

    #[derive(Queryable, Selectable, Insertable)]
    #[diesel(table_name = crate::schema::pg::email_verifications)]
    pub struct EmailVerificationRow {
        pub token: String,
        pub user_id: uuid::Uuid,
        pub email: String,
        pub expires_at: chrono::DateTime<chrono::Utc>,
    }

    impl From<EmailVerificationRow> for super::EmailVerification {
        fn from(r: EmailVerificationRow) -> Self {
            Self {
                token: r.token,
                user_id: r.user_id.to_string(),
                email: r.email,
                expires_at: r.expires_at.to_rfc3339(),
            }
        }
    }

    #[derive(Queryable, Selectable, Insertable)]
    #[diesel(table_name = crate::schema::pg::peer_keys)]
    pub struct PeerKeyRow {
        pub domain: String,
        pub key_id: String,
        pub public_key: Vec<u8>,
        pub algorithm: String,
        pub fingerprint: String,
        pub key_usage: String,
        pub expires_at: String,
        pub revoked_at: Option<String>,
    }

    impl From<PeerKeyRow> for super::PeerKey {
        fn from(r: PeerKeyRow) -> Self {
            Self {
                domain: r.domain,
                key_id: r.key_id,
                public_key: r.public_key,
                algorithm: r.algorithm,
                fingerprint: r.fingerprint,
                key_usage: r.key_usage,
                expires_at: r.expires_at,
                revoked_at: r.revoked_at,
            }
        }
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
        pub is_admin_account: i32,
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
                is_admin_account: row.is_admin_account != 0,
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
        pub attested_at: String,
    }

    impl From<ClaimDbRow> for super::ClaimRow {
        fn from(row: ClaimDbRow) -> Self {
            Self {
                id: row.id,
                user_id: row.user_id,
                claim_type: row.claim_type,
                claim_value: row.claim_value,
                signatures: Vec::new(),
                attested_at: row.attested_at,
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
        pub attested_at: String,
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

    // -- Claim-type policy registry --

    #[derive(Queryable, Selectable, Insertable, AsChangeset)]
    #[diesel(table_name = crate::schema::sqlite::claim_type_policies)]
    #[diesel(primary_key(claim_type))]
    pub struct ClaimTypePolicyRow {
        pub claim_type: String,
        pub label: String,
        pub description: String,
        pub value_type: String,
        pub max_bytes: i64,
        pub set_rule: String,
        pub signing_rule: String,
        pub requires_approval: i32,
        pub user_settable: i32,
        pub default_auto_sign: i32,
        pub suggested: i32,
    }

    impl From<ClaimTypePolicyRow> for super::ClaimTypePolicy {
        fn from(r: ClaimTypePolicyRow) -> Self {
            Self {
                claim_type: r.claim_type,
                label: r.label,
                description: r.description,
                value_type: r.value_type,
                max_bytes: r.max_bytes,
                set_rule: r.set_rule,
                signing_rule: r.signing_rule,
                requires_approval: r.requires_approval != 0,
                user_settable: r.user_settable != 0,
                default_auto_sign: r.default_auto_sign != 0,
                suggested: r.suggested != 0,
            }
        }
    }

    impl From<super::ClaimTypePolicy> for ClaimTypePolicyRow {
        fn from(p: super::ClaimTypePolicy) -> Self {
            Self {
                claim_type: p.claim_type,
                label: p.label,
                description: p.description,
                value_type: p.value_type,
                max_bytes: p.max_bytes,
                set_rule: p.set_rule,
                signing_rule: p.signing_rule,
                requires_approval: i32::from(p.requires_approval),
                user_settable: i32::from(p.user_settable),
                default_auto_sign: i32::from(p.default_auto_sign),
                suggested: i32::from(p.suggested),
            }
        }
    }

    #[derive(Queryable, Selectable, Insertable)]
    #[diesel(table_name = crate::schema::sqlite::trusted_issuers)]
    pub struct TrustedIssuerRow {
        pub claim_type: String,
        pub issuer_domain: String,
    }

    impl From<TrustedIssuerRow> for super::TrustedIssuer {
        fn from(r: TrustedIssuerRow) -> Self {
            Self {
                claim_type: r.claim_type,
                issuer_domain: r.issuer_domain,
            }
        }
    }

    #[derive(Queryable, Selectable, Insertable, AsChangeset)]
    #[diesel(table_name = crate::schema::sqlite::profile_claim_prefs)]
    #[diesel(primary_key(profile_id, claim_type))]
    pub struct ProfileClaimPrefRow {
        pub profile_id: String,
        pub claim_type: String,
        pub auto_sign: i32,
    }

    impl From<ProfileClaimPrefRow> for super::ProfileClaimPref {
        fn from(r: ProfileClaimPrefRow) -> Self {
            Self {
                profile_id: r.profile_id,
                claim_type: r.claim_type,
                auto_sign: r.auto_sign != 0,
            }
        }
    }

    #[derive(Queryable, Selectable, Insertable)]
    #[diesel(table_name = crate::schema::sqlite::release_policies)]
    pub struct ReleasePolicyRow {
        pub audience: String,
        pub claim_type: String,
        pub disposition: String,
    }

    impl From<ReleasePolicyRow> for super::ReleasePolicy {
        fn from(r: ReleasePolicyRow) -> Self {
            Self {
                audience: r.audience,
                claim_type: r.claim_type,
                disposition: r.disposition,
            }
        }
    }

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::sqlite::admin_review_queue)]
    pub struct AdminReviewRow {
        pub id: String,
        pub kind: String,
        pub user_id: Option<String>,
        pub claim_type: Option<String>,
        pub claim_value: Option<Vec<u8>>,
        pub subject: Option<String>,
        pub detail: Option<String>,
        pub status: String,
        pub resolved_by: Option<String>,
        pub resolved_at: Option<String>,
        pub created_at: String,
        pub updated_at: String,
    }

    impl From<AdminReviewRow> for super::AdminReview {
        fn from(r: AdminReviewRow) -> Self {
            Self {
                id: r.id,
                kind: r.kind,
                user_id: r.user_id,
                claim_type: r.claim_type,
                claim_value: r.claim_value,
                subject: r.subject,
                detail: r.detail,
                status: r.status,
                resolved_by: r.resolved_by,
                resolved_at: r.resolved_at,
                created_at: r.created_at,
            }
        }
    }

    /// Claim-approval view: only valid for kind = "claim_approval".
    impl From<AdminReviewRow> for super::ClaimApproval {
        fn from(r: AdminReviewRow) -> Self {
            Self {
                id: r.id,
                user_id: r.user_id.unwrap_or_default(),
                claim_type: r.claim_type.unwrap_or_default(),
                claim_value: r.claim_value.unwrap_or_default(),
                status: r.status,
                resolved_by: r.resolved_by,
                resolved_at: r.resolved_at,
                created_at: r.created_at,
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::sqlite::admin_review_queue)]
    pub struct NewClaimApprovalRow {
        pub id: String,
        pub kind: String,
        pub user_id: String,
        pub claim_type: String,
        pub claim_value: Vec<u8>,
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::sqlite::admin_review_queue)]
    pub struct NewAdminReviewRow {
        pub id: String,
        pub kind: String,
        pub subject: Option<String>,
        pub detail: Option<String>,
    }

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::sqlite::audit_log)]
    pub struct AuditLogRow {
        pub id: String,
        pub event: String,
        pub subject: Option<String>,
        pub actor: Option<String>,
        pub detail: Option<String>,
        pub created_at: String,
    }

    impl From<AuditLogRow> for super::AuditEntry {
        fn from(r: AuditLogRow) -> Self {
            Self {
                id: r.id,
                event: r.event,
                subject: r.subject,
                actor: r.actor,
                detail: r.detail,
                created_at: r.created_at,
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::sqlite::audit_log)]
    pub struct NewAuditLogRow {
        pub id: String,
        pub event: String,
        pub subject: Option<String>,
        pub actor: Option<String>,
        pub detail: Option<String>,
    }

    #[derive(Queryable, Selectable, Insertable)]
    #[diesel(table_name = crate::schema::sqlite::domain_key_pins)]
    pub struct DomainKeyPinRow {
        pub domain: String,
        pub fingerprints: String,
        pub pinned_at: String,
        pub last_checked_at: String,
    }

    impl From<DomainKeyPinRow> for super::DomainKeyPin {
        fn from(r: DomainKeyPinRow) -> Self {
            Self {
                domain: r.domain,
                fingerprints: r.fingerprints,
                pinned_at: r.pinned_at,
                last_checked_at: r.last_checked_at,
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::sqlite::domain_key_pins)]
    pub struct NewDomainKeyPinRow {
        pub domain: String,
        pub fingerprints: String,
    }

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = crate::schema::sqlite::issued_revocations)]
    pub struct IssuedRevocationRow {
        pub id: String,
        pub target_key_id: String,
        pub target_fingerprint: String,
        pub revoked_at: String,
        pub cert: Vec<u8>,
        pub created_at: String,
    }

    impl From<IssuedRevocationRow> for super::IssuedRevocation {
        fn from(r: IssuedRevocationRow) -> Self {
            Self {
                id: r.id,
                target_key_id: r.target_key_id,
                target_fingerprint: r.target_fingerprint,
                revoked_at: r.revoked_at,
                cert: r.cert,
                created_at: r.created_at,
            }
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = crate::schema::sqlite::issued_revocations)]
    pub struct NewIssuedRevocationRow {
        pub id: String,
        pub target_key_id: String,
        pub target_fingerprint: String,
        pub revoked_at: String,
        pub cert: Vec<u8>,
    }

    #[derive(Queryable, Selectable, Insertable)]
    #[diesel(table_name = crate::schema::sqlite::email_verifications)]
    pub struct EmailVerificationRow {
        pub token: String,
        pub user_id: String,
        pub email: String,
        pub expires_at: String,
    }

    impl From<EmailVerificationRow> for super::EmailVerification {
        fn from(r: EmailVerificationRow) -> Self {
            Self {
                token: r.token,
                user_id: r.user_id,
                email: r.email,
                expires_at: r.expires_at,
            }
        }
    }

    #[derive(Queryable, Selectable, Insertable)]
    #[diesel(table_name = crate::schema::sqlite::peer_keys)]
    pub struct PeerKeyRow {
        pub domain: String,
        pub key_id: String,
        pub public_key: Vec<u8>,
        pub algorithm: String,
        pub fingerprint: String,
        pub key_usage: String,
        pub expires_at: String,
        pub revoked_at: Option<String>,
    }

    impl From<PeerKeyRow> for super::PeerKey {
        fn from(r: PeerKeyRow) -> Self {
            Self {
                domain: r.domain,
                key_id: r.key_id,
                public_key: r.public_key,
                algorithm: r.algorithm,
                fingerprint: r.fingerprint,
                key_usage: r.key_usage,
                expires_at: r.expires_at,
                revoked_at: r.revoked_at,
            }
        }
    }
}
