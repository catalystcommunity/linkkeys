#[cfg(all(feature = "postgres", feature = "sqlite"))]
compile_error!("Features `postgres` and `sqlite` are mutually exclusive. Enable only one.");

#[cfg(not(any(feature = "postgres", feature = "sqlite")))]
compile_error!("Either `postgres` or `sqlite` feature must be enabled.");

pub mod db;
pub mod schema;
pub mod services;
