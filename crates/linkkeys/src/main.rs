extern crate rocket;

mod schema;
mod cli;
mod db;
mod tcp;
mod web;

use clap::Parser;
use cli::{Cli, Commands};
use std::thread;

#[rocket::main]
async fn main() {
    // Initialize logger with LOG_LEVEL env var or default to warn
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("warn")
    ).init();

    // Parse CLI arguments
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve => {
            log::info!("Starting linkkeys server...");

            // Create database connection pool
            let db_pool = db::create_pool();
            let db_pool_web = db_pool.clone();

            // Start TCP server in a separate thread
            thread::spawn(|| {
                match tcp::TcpServer::new() {
                    Ok(server) => {
                        log::info!("TCP server started on port 4987");
                        server.run();
                    }
                    Err(e) => {
                        log::error!("Failed to start TCP server: {}", e);
                    }
                }
            });

            // Start Rocket web server (this will block)
            web::launch_rocket(db_pool_web).await;
        }
    }
}
