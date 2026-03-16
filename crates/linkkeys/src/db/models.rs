use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[cfg(feature = "postgres")]
use uuid::Uuid;

#[cfg(feature = "postgres")]
#[derive(Queryable, Selectable, Serialize, Deserialize, Debug)]
#[diesel(table_name = crate::schema::guestbook_entries)]
pub struct GuestbookEntryRow {
    pub id: Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(feature = "postgres")]
#[derive(Insertable)]
#[diesel(table_name = crate::schema::guestbook_entries)]
pub struct NewGuestbookEntryRow {
    pub id: Uuid,
    pub name: String,
}

#[cfg(feature = "sqlite")]
#[derive(Queryable, Selectable, Serialize, Deserialize, Debug)]
#[diesel(table_name = crate::schema::guestbook_entries)]
pub struct GuestbookEntryRow {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
}

#[cfg(feature = "sqlite")]
#[derive(Insertable)]
#[diesel(table_name = crate::schema::guestbook_entries)]
pub struct NewGuestbookEntryRow {
    pub id: String,
    pub name: String,
}
