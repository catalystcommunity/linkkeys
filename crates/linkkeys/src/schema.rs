// Schema definition for guestbook_entries table.
// Per-backend SQL types differ, so we cfg-gate the table definition.

#[cfg(feature = "postgres")]
diesel::table! {
    guestbook_entries (id) {
        id -> Uuid,
        name -> Varchar,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

#[cfg(feature = "sqlite")]
diesel::table! {
    guestbook_entries (id) {
        id -> Text,
        name -> Text,
        created_at -> Text,
        updated_at -> Text,
    }
}
