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
}
