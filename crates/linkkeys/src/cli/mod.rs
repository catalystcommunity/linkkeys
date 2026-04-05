use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "linkkeys")]
#[command(about = "An IDP server with TCP and HTTP interfaces", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the server with TCP and HTTP listeners
    Serve,

    /// Domain management commands
    #[command(subcommand)]
    Domain(DomainCommands),

    /// User management commands
    #[command(subcommand)]
    User(UserCommands),

    /// Claim management commands
    #[command(subcommand)]
    Claim(ClaimCommands),
}

#[derive(Subcommand)]
pub enum DomainCommands {
    /// Initialize domain keys (generates 3 Ed25519 keypairs with staggered expiration)
    Init,
    /// Check DNS TXT records for this domain — shows expected vs actual state
    DnsCheck,
}

#[derive(Subcommand)]
pub enum UserCommands {
    /// Create a new user with 3 keypairs
    Create {
        /// Username (must be unique)
        username: String,
        /// Display name
        display_name: String,
        /// Password (reads from stdin if not provided)
        #[arg(long)]
        password: Option<String>,
        /// Generate an API key instead of prompting for a password
        #[arg(long)]
        api_key: bool,
    },
}

#[derive(Subcommand)]
pub enum ClaimCommands {
    /// Set a claim on a user
    Set {
        /// User UUID
        user_id: String,
        /// Claim type (e.g., "email", "role")
        claim_type: String,
        /// Claim value
        claim_value: String,
        /// Optional expiration (RFC 3339 timestamp)
        #[arg(long)]
        expires: Option<String>,
    },
}
