//! LinkKeys connection/handshake/cache/DDoS load-test harness
//! (signing-things-request.md, "Connection scalability" and step 9 of the
//! implementation order).
//!
//! This is a diagnostic tool, not a test suite: it drives the REAL async TCP
//! server (`linkkeys::tcp::spawn_for_test`, the same code path
//! `tests/tcp_async_connection_test.rs` exercises) at whatever scale the
//! operator asks for, and prints honest numbers. See `docs/load-testing.md`
//! for the reproducible profile and the honesty rules this tool exists to
//! serve: it never extrapolates a measured small run into a claimed large
//! one.
//!
//! Two-process design: `server` runs standalone so its process RSS reflects
//! only server-side memory, not a load generator sharing its address space.
//! Every other subcommand is a client process that reads the server's
//! `--info-file` (host, port, TLS fingerprint) and drives load against it.

mod client;
mod server;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "linkkeys-loadtest",
    about = "Connection/handshake/cache/DDoS load-test harness for the LinkKeys async TCP server"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a real async TCP server for the other subcommands to load. Prints
    /// periodic metrics snapshots and writes an info file the client
    /// subcommands read to find it.
    Server(server::ServerArgs),
    /// Open and hold N established, mostly-idle TLS connections. Reports how
    /// many were actually established and why the rest failed.
    Connections(client::ConnectionsArgs),
    /// Measure TLS handshake rate in isolation: connect, handshake, close,
    /// repeat — a separate number from established-connection count.
    HandshakeBench(client::HandshakeBenchArgs),
    /// Measure request throughput (e.g. `DomainKeys/get-domain-keys`) over
    /// persistent connections — a separate number from handshake rate.
    RequestBench(client::RequestBenchArgs),
    /// Exercise the distinct-source DDoS protection controls: many simulated
    /// sources via distinct loopback addresses.
    Ddos(client::DdosArgs),
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    env_logger::init();
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Server(args) => server::run(args).await,
        Command::Connections(args) => client::run_connections(args).await,
        Command::HandshakeBench(args) => client::run_handshake_bench(args).await,
        Command::RequestBench(args) => client::run_request_bench(args).await,
        Command::Ddos(args) => client::run_ddos(args).await,
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
