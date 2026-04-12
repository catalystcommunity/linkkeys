pub mod tcp_client;

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

    /// Relation management commands
    #[command(subcommand)]
    Relation(RelationCommands),

    /// Account self-service commands
    #[command(subcommand)]
    Account(AccountCommands),
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
    /// Create a new user with 3 keypairs (DB-direct, break-glass)
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
        /// Grant admin relation on this domain (bootstrap)
        #[arg(long)]
        admin: bool,
    },
    /// List all users (via TCP)
    List {
        #[arg(long)]
        server: Option<String>,
    },
    /// Update a user (via TCP)
    Update {
        /// User UUID
        user_id: String,
        #[arg(long)]
        display_name: Option<String>,
        #[arg(long)]
        server: Option<String>,
    },
    /// Deactivate a user (via TCP)
    Deactivate {
        /// User UUID
        user_id: String,
        #[arg(long)]
        server: Option<String>,
    },
    /// Reset a user's password (via TCP)
    ResetPassword {
        /// User UUID
        user_id: String,
        #[arg(long)]
        server: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum ClaimCommands {
    /// Set a claim on a user (DB-direct, break-glass)
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
    /// Remove a claim (via TCP)
    Remove {
        /// Claim UUID
        claim_id: String,
        #[arg(long)]
        server: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum RelationCommands {
    /// Grant a relation (via TCP)
    Grant {
        /// Subject type (e.g., "user")
        subject_type: String,
        /// Subject UUID
        subject_id: String,
        /// Relation name (e.g., "admin", "member")
        relation: String,
        /// Object type (e.g., "domain")
        object_type: String,
        /// Object ID
        object_id: String,
        #[arg(long)]
        server: Option<String>,
    },
    /// Remove a relation (via TCP)
    Remove {
        /// Relation UUID
        relation_id: String,
        #[arg(long)]
        server: Option<String>,
    },
    /// List relations (via TCP)
    List {
        #[arg(long)]
        subject_type: Option<String>,
        #[arg(long)]
        subject_id: Option<String>,
        #[arg(long)]
        object_type: Option<String>,
        #[arg(long)]
        object_id: Option<String>,
        #[arg(long)]
        server: Option<String>,
    },
    /// Check if a user has a permission (via TCP)
    Check {
        /// User UUID
        user_id: String,
        /// Relation/permission to check (e.g., "admin")
        relation: String,
        /// Object type (e.g., "domain")
        object_type: String,
        /// Object ID
        object_id: String,
        #[arg(long)]
        server: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum AccountCommands {
    /// Change your own password (via TCP)
    ChangePassword {
        #[arg(long)]
        server: Option<String>,
    },
    /// Get your own account info (via TCP)
    MyInfo {
        #[arg(long)]
        server: Option<String>,
    },
}
