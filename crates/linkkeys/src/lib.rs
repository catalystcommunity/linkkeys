#[cfg(not(any(feature = "postgres", feature = "sqlite")))]
compile_error!("At least one of `postgres` or `sqlite` feature must be enabled.");

pub mod db;
pub mod schema;
pub mod services;
