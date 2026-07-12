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

    /// TOFU domain fingerprint pin commands
    #[command(subcommand)]
    Pins(PinCommands),

    /// Create an encrypted, storage-agnostic backup of the whole database.
    ///
    /// The artifact is encrypted in-process with a per-domain 256-bit backup key
    /// (shown once on first use / rotation — store it offline). Restoring it
    /// rebuilds the domain with identical signing keys, so public DNS is
    /// unaffected.
    Backup {
        /// Write the encrypted artifact here (default: stdout).
        #[arg(long, short)]
        out: Option<String>,
        /// Rotate the backup key before backing up (prints the new key).
        #[arg(long)]
        rotate: bool,
        /// Embed DOMAIN_KEY_PASSPHRASE in the bundle for single-artifact
        /// recovery. Off by default (SEC-09): a leaked bundle + backup key then
        /// still cannot decrypt the private keys without the separately-held
        /// passphrase. Only pass this if you deliberately want the convenience.
        #[arg(long)]
        embed_passphrase: bool,
    },

    /// Restore the database from an encrypted backup artifact.
    Restore {
        /// Read the encrypted artifact from here (default: stdin).
        #[arg(long = "in", short = 'i')]
        in_file: Option<String>,
        /// The backup key (64 hex chars). Falls back to LINKKEYS_BACKUP_KEY.
        #[arg(long)]
        key: Option<String>,
        /// Overwrite a non-empty database / restore across domains.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub enum DomainCommands {
    /// Initialize domain keys (generates 3 Ed25519 keypairs with staggered expiration)
    Init,
    /// Check DNS TXT records for this domain — shows expected vs actual state
    DnsCheck,
    /// List this domain's keys with their ids, usage, fingerprint, and status
    ListKeys,
    /// Revoke a domain key by id (SEC-08). Verification stops honoring it; remove
    /// its fingerprint from DNS so peers drop it on their next pin recheck.
    RevokeKey {
        /// The key id to revoke (see `domain list-keys`)
        key_id: String,
    },
}

#[derive(Subcommand)]
pub enum PinCommands {
    /// Re-resolve DNS and recheck TOFU fingerprint pins (SEC-01). Cron-friendly:
    /// run on an interval (e.g. every 14 days). With no domain, rechecks all
    /// pinned domains. A single-key rotation is accepted; a larger change is
    /// refused and queued for admin review.
    Recheck {
        /// Recheck only this domain (default: all pinned domains)
        domain: Option<String>,
    },
    /// List the currently pinned domains and their fingerprint sets.
    List,
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
        /// Grant a specific relation on this domain (repeatable). Least-privilege
        /// alternative to --admin for service keys, e.g. `--relation api_access`
        /// for an RP delegate or `--relation manage_users --relation manage_claims`
        /// for an app-driven IDP. Valid: admin, manage_users, manage_claims,
        /// api_access, issue_claims.
        #[arg(long = "relation")]
        relation: Vec<String>,
    },
    /// List all users (via TCP)
    List {
        /// Read directly from the local database instead of TCP.
        #[arg(long)]
        local: bool,
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
    /// Deactivate a user by username or UUID, writing directly to the DB.
    DeactivateLocal {
        /// User: username or UUID
        user: String,
    },
    /// Reset a user's password (via TCP)
    ResetPassword {
        /// User UUID
        user_id: String,
        #[arg(long)]
        server: Option<String>,
    },
    /// Reset a user's password by username or UUID, writing directly to the DB.
    ResetPasswordLocal {
        /// User: username or UUID
        user: String,
        /// New password. Reads from stdin if omitted and --generate is not set.
        #[arg(long)]
        password: Option<String>,
        /// Generate and print a fresh password.
        #[arg(long)]
        generate: bool,
    },
    /// Irreversibly minimize a user while keeping its UUID tombstoned forever.
    PurgeLocal {
        /// User: username or UUID
        user: String,
        /// Required confirmation for irreversible data minimization.
        #[arg(long)]
        force: bool,
        /// Required when purging a protected admin account.
        #[arg(long)]
        force_admin: bool,
        /// Operator-visible audit reason.
        #[arg(long)]
        reason: String,
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
    /// Grant a relation to a user on this domain, writing directly to the DB
    /// (DB-direct, break-glass — no server/API key needed). Resolves bootstrap's
    /// chicken-and-egg: `relation grant` (via TCP) needs an admin key, but the
    /// first api_access/manage_users key has to be granted before one exists.
    /// Idempotent. Run where the DB lives (e.g. inside the server pod).
    GrantLocal {
        /// User: username or UUID
        user: String,
        /// Relation name: admin, manage_users, manage_claims, api_access, issue_claims
        relation: String,
    },
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
