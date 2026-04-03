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
            created_at -> Timestamptz,
            expires_at -> Timestamptz,
            revoked_at -> Nullable<Timestamptz>,
            updated_at -> Timestamptz,
        }
    }

    diesel::table! {
        users (id) {
            id -> Uuid,
            username -> Varchar,
            display_name -> Varchar,
            password_hash -> Varchar,
            created_at -> Timestamptz,
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
            created_at -> Timestamptz,
            expires_at -> Timestamptz,
            revoked_at -> Nullable<Timestamptz>,
            updated_at -> Timestamptz,
        }
    }

    diesel::table! {
        claims (id) {
            id -> Uuid,
            user_id -> Uuid,
            claim_type -> Varchar,
            claim_value -> Binary,
            signed_by_key_id -> Uuid,
            signature -> Binary,
            created_at -> Timestamptz,
            expires_at -> Nullable<Timestamptz>,
            revoked_at -> Nullable<Timestamptz>,
            updated_at -> Timestamptz,
        }
    }

    diesel::joinable!(user_keys -> users (user_id));
    diesel::joinable!(claims -> users (user_id));
    diesel::joinable!(claims -> domain_keys (signed_by_key_id));
    diesel::allow_tables_to_appear_in_same_query!(
        guestbook_entries,
        domain_keys,
        users,
        user_keys,
        claims,
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
            created_at -> Text,
            expires_at -> Text,
            revoked_at -> Nullable<Text>,
            updated_at -> Text,
        }
    }

    diesel::table! {
        users (id) {
            id -> Text,
            username -> Text,
            display_name -> Text,
            password_hash -> Text,
            created_at -> Text,
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
            created_at -> Text,
            expires_at -> Text,
            revoked_at -> Nullable<Text>,
            updated_at -> Text,
        }
    }

    diesel::table! {
        claims (id) {
            id -> Text,
            user_id -> Text,
            claim_type -> Text,
            claim_value -> Binary,
            signed_by_key_id -> Text,
            signature -> Binary,
            created_at -> Text,
            expires_at -> Nullable<Text>,
            revoked_at -> Nullable<Text>,
            updated_at -> Text,
        }
    }

    diesel::joinable!(user_keys -> users (user_id));
    diesel::joinable!(claims -> users (user_id));
    diesel::joinable!(claims -> domain_keys (signed_by_key_id));
    diesel::allow_tables_to_appear_in_same_query!(
        guestbook_entries,
        domain_keys,
        users,
        user_keys,
        claims,
    );
}
