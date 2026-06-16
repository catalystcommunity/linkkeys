// Per-backend schema definitions. Diesel's table! macro produces types tied to
// specific SQL types, so each backend needs its own module.

#[cfg(feature = "postgres")]
pub mod pg {
    diesel::table! {
        guestbook_entries (id) {
            id -> Uuid,
            name -> Varchar,
            created_at -> Timestamptz,
            updated_at -> Timestamptz,
        }
    }

    diesel::table! {
        domain_keys (id) {
            id -> Uuid,
            public_key -> Binary,
            private_key_encrypted -> Binary,
            fingerprint -> Varchar,
            algorithm -> Varchar,
            key_usage -> Varchar,
            created_at -> Timestamptz,
            expires_at -> Timestamptz,
            revoked_at -> Nullable<Timestamptz>,
            updated_at -> Timestamptz,
            signed_by_key_id -> Nullable<Varchar>,
            key_signature -> Nullable<Binary>,
        }
    }

    diesel::table! {
        users (id) {
            id -> Uuid,
            username -> Varchar,
            display_name -> Varchar,
            is_active -> Bool,
            created_at -> Timestamptz,
            updated_at -> Timestamptz,
            is_admin_account -> Bool,
        }
    }

    diesel::table! {
        auth_credentials (id) {
            id -> Uuid,
            user_id -> Uuid,
            credential_type -> Varchar,
            credential_hash -> Varchar,
            created_at -> Timestamptz,
            expires_at -> Nullable<Timestamptz>,
            revoked_at -> Nullable<Timestamptz>,
            updated_at -> Timestamptz,
        }
    }

    diesel::table! {
        relations (id) {
            id -> Uuid,
            subject_type -> Varchar,
            subject_id -> Varchar,
            relation -> Varchar,
            object_type -> Varchar,
            object_id -> Varchar,
            created_at -> Timestamptz,
            removed_at -> Nullable<Timestamptz>,
            updated_at -> Timestamptz,
        }
    }

    diesel::table! {
        user_keys (id) {
            id -> Uuid,
            user_id -> Uuid,
            public_key -> Binary,
            private_key_encrypted -> Binary,
            fingerprint -> Varchar,
            algorithm -> Varchar,
            key_usage -> Varchar,
            created_at -> Timestamptz,
            expires_at -> Timestamptz,
            revoked_at -> Nullable<Timestamptz>,
            updated_at -> Timestamptz,
            signed_by_key_id -> Nullable<Varchar>,
            key_signature -> Nullable<Binary>,
        }
    }

    diesel::table! {
        claims (id) {
            id -> Uuid,
            user_id -> Uuid,
            claim_type -> Varchar,
            claim_value -> Binary,
            created_at -> Timestamptz,
            expires_at -> Nullable<Timestamptz>,
            revoked_at -> Nullable<Timestamptz>,
            updated_at -> Timestamptz,
        }
    }

    diesel::table! {
        claim_signatures (id) {
            id -> Uuid,
            claim_id -> Uuid,
            domain -> Varchar,
            signed_by_key_id -> Uuid,
            signature -> Binary,
            created_at -> Timestamptz,
        }
    }

    diesel::table! {
        used_nonces (nonce) {
            nonce -> Varchar,
            expires_at -> Timestamptz,
        }
    }

    diesel::table! {
        profiles (id) {
            id -> Uuid,
            account_id -> Uuid,
            domain -> Varchar,
            is_root -> Bool,
            label -> Nullable<Varchar>,
            created_at -> Timestamptz,
            updated_at -> Timestamptz,
        }
    }

    diesel::table! {
        consent_grants (id) {
            id -> Uuid,
            user_id -> Uuid,
            subject_domain -> Varchar,
            audience -> Varchar,
            claim_types -> Text,
            requested_types -> Text,
            signed_grant -> Binary,
            offered_claims -> Nullable<Binary>,
            issued_at -> Timestamptz,
            expires_at -> Timestamptz,
            revoked_at -> Nullable<Timestamptz>,
            created_at -> Timestamptz,
            updated_at -> Timestamptz,
        }
    }

    diesel::joinable!(user_keys -> users (user_id));
    diesel::joinable!(claims -> users (user_id));
    diesel::joinable!(claim_signatures -> claims (claim_id));
    diesel::joinable!(claim_signatures -> domain_keys (signed_by_key_id));
    diesel::joinable!(auth_credentials -> users (user_id));
    diesel::joinable!(consent_grants -> users (user_id));
    diesel::joinable!(profiles -> users (account_id));
    diesel::allow_tables_to_appear_in_same_query!(
        guestbook_entries,
        domain_keys,
        users,
        auth_credentials,
        user_keys,
        claims,
        claim_signatures,
        relations,
        consent_grants,
        profiles,
    );
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    diesel::table! {
        guestbook_entries (id) {
            id -> Text,
            name -> Text,
            created_at -> Text,
            updated_at -> Text,
        }
    }

    diesel::table! {
        domain_keys (id) {
            id -> Text,
            public_key -> Binary,
            private_key_encrypted -> Binary,
            fingerprint -> Text,
            algorithm -> Text,
            key_usage -> Text,
            created_at -> Text,
            expires_at -> Text,
            revoked_at -> Nullable<Text>,
            updated_at -> Text,
            signed_by_key_id -> Nullable<Text>,
            key_signature -> Nullable<Binary>,
        }
    }

    diesel::table! {
        users (id) {
            id -> Text,
            username -> Text,
            display_name -> Text,
            is_active -> Integer,
            created_at -> Text,
            updated_at -> Text,
            is_admin_account -> Integer,
        }
    }

    diesel::table! {
        auth_credentials (id) {
            id -> Text,
            user_id -> Text,
            credential_type -> Text,
            credential_hash -> Text,
            created_at -> Text,
            expires_at -> Nullable<Text>,
            revoked_at -> Nullable<Text>,
            updated_at -> Text,
        }
    }

    diesel::table! {
        relations (id) {
            id -> Text,
            subject_type -> Text,
            subject_id -> Text,
            relation -> Text,
            object_type -> Text,
            object_id -> Text,
            created_at -> Text,
            removed_at -> Nullable<Text>,
            updated_at -> Text,
        }
    }

    diesel::table! {
        user_keys (id) {
            id -> Text,
            user_id -> Text,
            public_key -> Binary,
            private_key_encrypted -> Binary,
            fingerprint -> Text,
            algorithm -> Text,
            key_usage -> Text,
            created_at -> Text,
            expires_at -> Text,
            revoked_at -> Nullable<Text>,
            updated_at -> Text,
            signed_by_key_id -> Nullable<Text>,
            key_signature -> Nullable<Binary>,
        }
    }

    diesel::table! {
        claims (id) {
            id -> Text,
            user_id -> Text,
            claim_type -> Text,
            claim_value -> Binary,
            created_at -> Text,
            expires_at -> Nullable<Text>,
            revoked_at -> Nullable<Text>,
            updated_at -> Text,
        }
    }

    diesel::table! {
        claim_signatures (id) {
            id -> Text,
            claim_id -> Text,
            domain -> Text,
            signed_by_key_id -> Text,
            signature -> Binary,
            created_at -> Text,
        }
    }

    diesel::table! {
        used_nonces (nonce) {
            nonce -> Text,
            expires_at -> Text,
        }
    }

    diesel::table! {
        profiles (id) {
            id -> Text,
            account_id -> Text,
            domain -> Text,
            is_root -> Integer,
            label -> Nullable<Text>,
            created_at -> Text,
            updated_at -> Text,
        }
    }

    diesel::table! {
        consent_grants (id) {
            id -> Text,
            user_id -> Text,
            subject_domain -> Text,
            audience -> Text,
            claim_types -> Text,
            requested_types -> Text,
            signed_grant -> Binary,
            offered_claims -> Nullable<Binary>,
            issued_at -> Text,
            expires_at -> Text,
            revoked_at -> Nullable<Text>,
            created_at -> Text,
            updated_at -> Text,
        }
    }

    diesel::joinable!(user_keys -> users (user_id));
    diesel::joinable!(claims -> users (user_id));
    diesel::joinable!(claim_signatures -> claims (claim_id));
    diesel::joinable!(claim_signatures -> domain_keys (signed_by_key_id));
    diesel::joinable!(auth_credentials -> users (user_id));
    diesel::joinable!(consent_grants -> users (user_id));
    diesel::joinable!(profiles -> users (account_id));
    diesel::allow_tables_to_appear_in_same_query!(
        guestbook_entries,
        domain_keys,
        users,
        auth_credentials,
        user_keys,
        claims,
        claim_signatures,
        relations,
        consent_grants,
        profiles,
    );
}
