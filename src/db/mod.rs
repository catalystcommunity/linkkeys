use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use std::env;
use uuid::Uuid;
use serde::{Serialize, Deserialize};

pub type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

#[derive(Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::hello)]
pub struct Hello {
    pub id: Uuid,
    pub name: String,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::hello)]
pub struct NewHello {
    pub id: Uuid,
    pub name: String,
}

pub fn create_pool() -> DbPool {
    let database_url = env::var("DB_URL")
        .unwrap_or_else(|_| "postgres://devuser:devpass@localhost/linkkeys".to_string());
    
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    
    r2d2::Pool::builder()
        .max_size(15)
        .min_idle(Some(5))
        .test_on_check_out(true)
        .build(manager)
        .expect("Failed to create database pool")
}

pub fn noop_query(pool: &DbPool) -> Result<(), diesel::result::Error> {
    use crate::schema::hello::dsl::*;
    
    let mut conn = pool.get()
        .map_err(|e| diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UnableToSendCommand,
            Box::new(e.to_string())
        ))?;
    
    // Perform a simple count query as noop
    let _count: i64 = hello.count().get_result(&mut conn)?;
    Ok(())
}