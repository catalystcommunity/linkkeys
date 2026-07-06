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
        backup_keys (id) {
            id -> Uuid,
            key_encrypted -> Binary,
            created_at -> Timestamptz,
            rotated_at -> Nullable<Timestamptz>,
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
            attested_at -> Timestamptz,
        }
    }

    diesel::table! {
        claim_signatures (id) {
            id -> Uuid,
            claim_id -> Uuid,
            domain -> Varchar,
            signed_by_key_id -> Varchar,
            signature -> Binary,
            created_at -> Timestamptz,
        }
    }

    diesel::table! {
        peer_keys (domain, key_id) {
            domain -> Varchar,
            key_id -> Varchar,
            public_key -> Binary,
            algorithm -> Varchar,
            fingerprint -> Varchar,
            key_usage -> Varchar,
            expires_at -> Varchar,
            revoked_at -> Nullable<Varchar>,
            first_seen -> Timestamptz,
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

    diesel::table! {
        claim_type_policies (claim_type) {
            claim_type -> Varchar,
            label -> Varchar,
            description -> Varchar,
            value_type -> Varchar,
            max_bytes -> BigInt,
            set_rule -> Varchar,
            signing_rule -> Varchar,
            requires_approval -> Bool,
            user_settable -> Bool,
            default_auto_sign -> Bool,
            suggested -> Bool,
            created_at -> Timestamptz,
            updated_at -> Timestamptz,
        }
    }

    diesel::table! {
        claim_type_label_i18n (claim_type, locale) {
            claim_type -> Varchar,
            locale -> Varchar,
            label -> Varchar,
            description -> Nullable<Varchar>,
            created_at -> Timestamptz,
            updated_at -> Timestamptz,
        }
    }

    diesel::table! {
        trusted_issuers (claim_type, issuer_domain) {
            claim_type -> Varchar,
            issuer_domain -> Varchar,
            created_at -> Timestamptz,
        }
    }

    diesel::table! {
        profile_claim_prefs (profile_id, claim_type) {
            profile_id -> Varchar,
            claim_type -> Varchar,
            auto_sign -> Bool,
            created_at -> Timestamptz,
            updated_at -> Timestamptz,
        }
    }

    diesel::table! {
        release_policies (audience, claim_type) {
            audience -> Varchar,
            claim_type -> Varchar,
            disposition -> Varchar,
            created_at -> Timestamptz,
            updated_at -> Timestamptz,
        }
    }

    diesel::table! {
        admin_review_queue (id) {
            id -> Uuid,
            kind -> Varchar,
            user_id -> Nullable<Uuid>,
            claim_type -> Nullable<Varchar>,
            claim_value -> Nullable<Binary>,
            subject -> Nullable<Varchar>,
            detail -> Nullable<Varchar>,
            status -> Varchar,
            resolved_by -> Nullable<Varchar>,
            resolved_at -> Nullable<Timestamptz>,
            created_at -> Timestamptz,
            updated_at -> Timestamptz,
        }
    }

    diesel::table! {
        audit_log (id) {
            id -> Uuid,
            event -> Varchar,
            subject -> Nullable<Varchar>,
            actor -> Nullable<Varchar>,
            detail -> Nullable<Varchar>,
            created_at -> Timestamptz,
        }
    }

    diesel::table! {
        domain_key_pins (domain) {
            domain -> Varchar,
            fingerprints -> Varchar,
            pinned_at -> Timestamptz,
            last_checked_at -> Timestamptz,
        }
    }

    diesel::table! {
        issued_revocations (id) {
            id -> Uuid,
            target_key_id -> Varchar,
            target_fingerprint -> Varchar,
            revoked_at -> Timestamptz,
            cert -> Binary,
            created_at -> Timestamptz,
        }
    }

    diesel::table! {
        email_verifications (token) {
            token -> Varchar,
            user_id -> Uuid,
            email -> Varchar,
            expires_at -> Timestamptz,
            created_at -> Timestamptz,
        }
    }

    diesel::table! {
        user_release_prefs (user_id, audience, claim_type) {
            user_id -> Uuid,
            audience -> Varchar,
            claim_type -> Varchar,
            created_at -> Timestamptz,
        }
    }

    diesel::joinable!(user_keys -> users (user_id));
    diesel::joinable!(claims -> users (user_id));
    diesel::joinable!(claim_signatures -> claims (claim_id));
    diesel::joinable!(auth_credentials -> users (user_id));
    diesel::joinable!(consent_grants -> users (user_id));
    diesel::joinable!(profiles -> users (account_id));
    diesel::joinable!(admin_review_queue -> users (user_id));
    diesel::allow_tables_to_appear_in_same_query!(
        guestbook_entries,
        backup_keys,
        domain_keys,
        users,
        auth_credentials,
        user_keys,
        claims,
        claim_signatures,
        peer_keys,
        relations,
        consent_grants,
        profiles,
        claim_type_policies,
        claim_type_label_i18n,
        trusted_issuers,
        profile_claim_prefs,
        release_policies,
        admin_review_queue,
        audit_log,
        domain_key_pins,
        issued_revocations,
        email_verifications,
        user_release_prefs,
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
        backup_keys (id) {
            id -> Text,
            key_encrypted -> Binary,
            created_at -> Text,
            rotated_at -> Nullable<Text>,
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
            attested_at -> Text,
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
        peer_keys (domain, key_id) {
            domain -> Text,
            key_id -> Text,
            public_key -> Binary,
            algorithm -> Text,
            fingerprint -> Text,
            key_usage -> Text,
            expires_at -> Text,
            revoked_at -> Nullable<Text>,
            first_seen -> Text,
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

    diesel::table! {
        claim_type_policies (claim_type) {
            claim_type -> Text,
            label -> Text,
            description -> Text,
            value_type -> Text,
            max_bytes -> BigInt,
            set_rule -> Text,
            signing_rule -> Text,
            requires_approval -> Integer,
            user_settable -> Integer,
            default_auto_sign -> Integer,
            suggested -> Integer,
            created_at -> Text,
            updated_at -> Text,
        }
    }

    diesel::table! {
        claim_type_label_i18n (claim_type, locale) {
            claim_type -> Text,
            locale -> Text,
            label -> Text,
            description -> Nullable<Text>,
            created_at -> Text,
            updated_at -> Text,
        }
    }

    diesel::table! {
        trusted_issuers (claim_type, issuer_domain) {
            claim_type -> Text,
            issuer_domain -> Text,
            created_at -> Text,
        }
    }

    diesel::table! {
        profile_claim_prefs (profile_id, claim_type) {
            profile_id -> Text,
            claim_type -> Text,
            auto_sign -> Integer,
            created_at -> Text,
            updated_at -> Text,
        }
    }

    diesel::table! {
        release_policies (audience, claim_type) {
            audience -> Text,
            claim_type -> Text,
            disposition -> Text,
            created_at -> Text,
            updated_at -> Text,
        }
    }

    diesel::table! {
        admin_review_queue (id) {
            id -> Text,
            kind -> Text,
            user_id -> Nullable<Text>,
            claim_type -> Nullable<Text>,
            claim_value -> Nullable<Binary>,
            subject -> Nullable<Text>,
            detail -> Nullable<Text>,
            status -> Text,
            resolved_by -> Nullable<Text>,
            resolved_at -> Nullable<Text>,
            created_at -> Text,
            updated_at -> Text,
        }
    }

    diesel::table! {
        audit_log (id) {
            id -> Text,
            event -> Text,
            subject -> Nullable<Text>,
            actor -> Nullable<Text>,
            detail -> Nullable<Text>,
            created_at -> Text,
        }
    }

    diesel::table! {
        domain_key_pins (domain) {
            domain -> Text,
            fingerprints -> Text,
            pinned_at -> Text,
            last_checked_at -> Text,
        }
    }

    diesel::table! {
        issued_revocations (id) {
            id -> Text,
            target_key_id -> Text,
            target_fingerprint -> Text,
            revoked_at -> Text,
            cert -> Binary,
            created_at -> Text,
        }
    }

    diesel::table! {
        email_verifications (token) {
            token -> Text,
            user_id -> Text,
            email -> Text,
            expires_at -> Text,
            created_at -> Text,
        }
    }

    diesel::table! {
        user_release_prefs (user_id, audience, claim_type) {
            user_id -> Text,
            audience -> Text,
            claim_type -> Text,
            created_at -> Text,
        }
    }

    diesel::joinable!(user_keys -> users (user_id));
    diesel::joinable!(claims -> users (user_id));
    diesel::joinable!(claim_signatures -> claims (claim_id));
    diesel::joinable!(auth_credentials -> users (user_id));
    diesel::joinable!(consent_grants -> users (user_id));
    diesel::joinable!(profiles -> users (account_id));
    diesel::joinable!(admin_review_queue -> users (user_id));
    diesel::allow_tables_to_appear_in_same_query!(
        guestbook_entries,
        backup_keys,
        domain_keys,
        users,
        auth_credentials,
        user_keys,
        claims,
        claim_signatures,
        peer_keys,
        relations,
        consent_grants,
        profiles,
        claim_type_policies,
        claim_type_label_i18n,
        trusted_issuers,
        profile_claim_prefs,
        release_policies,
        admin_review_queue,
        audit_log,
        domain_key_pins,
        issued_revocations,
        email_verifications,
        user_release_prefs,
    );
}
