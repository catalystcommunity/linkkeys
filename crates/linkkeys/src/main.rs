extern crate rocket;

mod cli;
mod tcp;
mod web;

use clap::Parser;
use cli::{Cli, Commands};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;

#[rocket::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Serve => {
            log::info!("Starting linkkeys server...");

            let db_pool = linkkeys::db::create_pool();
            let ready_flag = Arc::new(AtomicBool::new(false));

            // Run migrations in a background thread
            {
                let pool = db_pool.clone();
                let flag = ready_flag.clone();
                thread::spawn(move || {
                    linkkeys::db::run_migrations_with_locking(&pool, flag);
                });
            }

            // Start TCP server in a separate thread
            {
                let flag = ready_flag.clone();
                thread::spawn(move || match tcp::TcpServer::new(flag) {
                    Ok(server) => server.run(),
                    Err(e) => log::error!("Failed to start TCP server: {}", e),
                });
            }

            // Start Rocket HTTPS server (blocks)
            web::launch_rocket(db_pool, ready_flag).await;
        }
    }
}
