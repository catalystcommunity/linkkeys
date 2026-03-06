use rocket::{State, Config};
use std::env;
use serde::{Serialize, Deserialize};
use crate::db::{DbPool, noop_query};
use log::info;

#[derive(Serialize, Deserialize)]
struct HelloResponse {
    hello: String,
}

#[rocket::get("/hello")]
fn hello_endpoint(db_pool: &State<DbPool>) -> Result<Vec<u8>, rocket::http::Status> {
    // Perform noop query to database
    match noop_query(db_pool) {
        Ok(_) => {
            let response = HelloResponse {
                hello: "world".to_string(),
            };
            
            // Serialize to CBOR
            let mut cbor_data = Vec::new();
            match ciborium::ser::into_writer(&response, &mut cbor_data) {
                Ok(_) => Ok(cbor_data),
                Err(_) => Err(rocket::http::Status::InternalServerError),
            }
        }
        Err(_) => Err(rocket::http::Status::InternalServerError),
    }
}

pub async fn launch_rocket(db_pool: DbPool) {
    let port: u16 = env::var("HTTP_PORT")
        .unwrap_or_else(|_| "5080".to_string())
        .parse()
        .unwrap_or(5080);
    
    info!("Starting Rocket web server on port {}", port);
    
    let config = Config {
        port,
        address: "0.0.0.0".parse().unwrap(),
        ..Config::default()
    };
    
    let _ = rocket::custom(config)
        .mount("/", rocket::routes![hello_endpoint])
        .manage(db_pool)
        .launch()
        .await;
}