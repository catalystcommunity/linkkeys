use serde::{Deserialize, Serialize};

/// Backend-agnostic domain model for guestbook entries.
/// All fields are strings so the same type works regardless of backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestbookEntry {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
}

#[cfg(feature = "postgres")]
pub mod pg {
    use diesel::prelude::*;

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
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use diesel::prelude::*;

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
}
