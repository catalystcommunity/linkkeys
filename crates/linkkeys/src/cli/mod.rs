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

    /// DNS-less local RP identity admin commands (list/inspect/approve/deny/
    /// revoke). See dns-less-local-rp-design.md.
    #[command(subcommand)]
    LocalRp(LocalRpCommands),

    /// Claim-type registry admin commands (list/set/remove claim types and
    /// their per-locale name translations). CSIL-RPC parity for what the
    /// `policy-admin` web UI's registry/translation forms do, for a
    /// controller holding an admin-relation API key.
    #[command(subcommand)]
    Policy(PolicyCommands),

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
    /// Revoke a domain key by id (SEC-08), writing directly to the DB.
    /// Verification stops honoring it; remove its fingerprint from DNS so
    /// peers drop it on their next pin recheck.
    RevokeKey {
        /// The key id to revoke (see `domain list-keys`)
        key_id: String,
    },
    /// Revoke a domain key by id (via TCP, admin-relation API key required).
    /// CSIL-RPC parity for `revoke-key`, for a controller that isn't running
    /// on the box holding the domain's own DB/passphrase.
    RevokeKeyRemote {
        /// The key id to revoke (see `domain list-keys`)
        key_id: String,
        #[arg(long)]
        server: Option<String>,
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
    /// Reactivate a previously deactivated user (via TCP)
    Activate {
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
    /// Irreversibly minimize a user while keeping its UUID tombstoned forever
    /// (via TCP, admin-relation API key required). CSIL-RPC parity for
    /// `purge-local`: refuses an already-purged user or a protected admin
    /// account, with no override lever over the wire (unlike `purge-local`'s
    /// `--force-admin`).
    Purge {
        /// User UUID
        user_id: String,
        /// Operator-visible audit reason, stored on the tombstoned user row.
        #[arg(long)]
        reason: Option<String>,
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
pub enum LocalRpCommands {
    /// List DNS-less local RP identities (via TCP), optionally filtered to
    /// one status: pending, approved, denied, revoked.
    List {
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        offset: Option<i64>,
        #[arg(long)]
        limit: Option<i64>,
        #[arg(long)]
        server: Option<String>,
    },
    /// Show one local RP identity by its full fingerprint (via TCP)
    Get {
        /// Full fingerprint (hex)
        fingerprint: String,
        #[arg(long)]
        server: Option<String>,
    },
    /// Approve a pending, or previously-denied, local RP fingerprint (via TCP)
    Approve {
        /// Full fingerprint (hex)
        fingerprint: String,
        /// Optional admin note stored on the record
        #[arg(long)]
        admin_notes: Option<String>,
        #[arg(long)]
        server: Option<String>,
    },
    /// Deny a pending local RP fingerprint (via TCP)
    Deny {
        /// Full fingerprint (hex)
        fingerprint: String,
        /// Optional admin note stored on the record
        #[arg(long)]
        admin_notes: Option<String>,
        #[arg(long)]
        server: Option<String>,
    },
    /// Revoke a previously-approved local RP fingerprint (via TCP). Stops
    /// future logins and deletes its outstanding claim tickets; app sessions
    /// already minted are the app's own to manage. Terminal: there is no
    /// un-revoking.
    Revoke {
        /// Full fingerprint (hex)
        fingerprint: String,
        /// Optional admin note stored on the record
        #[arg(long)]
        admin_notes: Option<String>,
        #[arg(long)]
        server: Option<String>,
    },
    /// Show this domain's local-RP admission policy (via TCP). Returns the
    /// effective policy: the stored value, or "admin-approval-required" if
    /// this domain has never set one explicitly.
    GetPolicy {
        #[arg(long)]
        server: Option<String>,
    },
    /// Set this domain's local-RP admission policy (via TCP). One of:
    /// disabled, admin-approval-required, allow-by-default.
    SetPolicy {
        /// disabled | admin-approval-required | allow-by-default
        policy: String,
        #[arg(long)]
        server: Option<String>,
    },
    /// Delete every expired claim-get ticket (via TCP). Intended to be driven
    /// on a schedule by an external controller holding an admin-relation API
    /// key; the server uses its own clock, so there are no parameters.
    PurgeTickets {
        #[arg(long)]
        server: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum PolicyCommands {
    /// List the domain's full claim-type registry (via TCP). CSIL-RPC
    /// parity for the `policy-admin` web UI's registry table.
    ListClaimTypes {
        #[arg(long)]
        server: Option<String>,
    },
    /// Create or update a claim-type definition (via TCP). CSIL-RPC parity
    /// for the `policy-admin` web UI's "Add / edit a claim type" form.
    SetClaimType {
        /// Claim type id (e.g. "pronouns")
        claim_type: String,
        #[arg(long)]
        label: String,
        #[arg(long)]
        description: Option<String>,
        /// text | url | email | bool | int | float | decimal | date | timestamp | opaque
        #[arg(long)]
        value_type: String,
        #[arg(long, default_value_t = 33792)]
        max_bytes: i64,
        /// user_self | idp_on_request | trusted_issuer_only | admin_only | deny
        #[arg(long)]
        set_rule: String,
        /// self_signed | verified | attested | unsigned
        #[arg(long)]
        signing_rule: String,
        #[arg(long)]
        user_settable: bool,
        #[arg(long)]
        default_auto_sign: bool,
        #[arg(long)]
        requires_approval: bool,
        #[arg(long)]
        suggested: bool,
        #[arg(long)]
        server: Option<String>,
    },
    /// Delete a claim-type definition by id (via TCP).
    RemoveClaimType {
        claim_type: String,
        #[arg(long)]
        server: Option<String>,
    },
    /// Set a claim-type name translation (via TCP). Fails if `claim_type`
    /// is not already registered.
    SetLabel {
        claim_type: String,
        /// e.g. es-ES, pt-BR
        locale: String,
        #[arg(long)]
        label: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        server: Option<String>,
    },
    /// Delete a claim-type name translation (via TCP).
    RemoveLabel {
        claim_type: String,
        locale: String,
        #[arg(long)]
        server: Option<String>,
    },
    /// List every trusted issuer across all claim types (via TCP). CSIL-RPC
    /// parity for the `policy-admin` web UI's trusted-issuers table.
    ListTrustedIssuers {
        #[arg(long)]
        server: Option<String>,
    },
    /// Add a trusted issuer for a claim type (via TCP).
    AddTrustedIssuer {
        claim_type: String,
        issuer_domain: String,
        #[arg(long)]
        server: Option<String>,
    },
    /// Remove a trusted issuer for a claim type (via TCP).
    RemoveTrustedIssuer {
        claim_type: String,
        issuer_domain: String,
        #[arg(long)]
        server: Option<String>,
    },
    /// List every per-audience release rule (via TCP). CSIL-RPC parity for
    /// the `policy-admin` web UI's release-rules table.
    ListReleaseRules {
        #[arg(long)]
        server: Option<String>,
    },
    /// Create or update a release rule (via TCP). Audience `*` is the
    /// global default.
    SetReleaseRule {
        audience: String,
        claim_type: String,
        /// forced_allow | forced_deny
        disposition: String,
        #[arg(long)]
        server: Option<String>,
    },
    /// Delete a release rule (via TCP).
    RemoveReleaseRule {
        audience: String,
        claim_type: String,
        #[arg(long)]
        server: Option<String>,
    },
    /// List claims queued for admin approval (via TCP). CSIL-RPC parity for
    /// the `policy-admin` web UI's approvals table.
    ListPendingApprovals {
        #[arg(long)]
        server: Option<String>,
    },
    /// Approve a queued claim: signs it with the domain's active keys and
    /// stores it for the subject (via TCP).
    ApproveClaim {
        /// Approval queue entry id (see `policy list-pending-approvals`)
        approval_id: String,
        #[arg(long)]
        server: Option<String>,
    },
    /// Reject a queued claim without signing anything (via TCP).
    RejectClaim {
        /// Approval queue entry id (see `policy list-pending-approvals`)
        approval_id: String,
        #[arg(long)]
        server: Option<String>,
    },
    /// Issue a signed attestation for one of this domain's own users (via
    /// TCP). CSIL-RPC parity for the `policy-admin` web UI's "Issue an
    /// attestation" flow — signs `claim_value` with the domain's active keys
    /// and stores it directly for `user_id`.
    IssueAttestation {
        /// Subject user UUID (must be one of this domain's own accounts)
        user_id: String,
        claim_type: String,
        claim_value: String,
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
    /// Set one of your OWN claim values (via TCP), subject to this domain's
    /// set-rule / user-settable policy for the claim type. CSIL-RPC parity
    /// for the web identity editor's "save" button.
    SetClaim {
        claim_type: String,
        claim_value: String,
        #[arg(long)]
        server: Option<String>,
    },
    /// Remove one of your OWN active claims by id (via TCP). Rejected if the
    /// claim belongs to another user.
    RemoveClaim {
        claim_id: String,
        #[arg(long)]
        server: Option<String>,
    },
    /// Create an additional presentable profile on your OWN account (via
    /// TCP), capped by the operator's MAX_PROFILES_PER_ACCOUNT.
    CreateProfile {
        /// Optional display label for the new profile.
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        server: Option<String>,
    },
    /// Pre-approve (or remove pre-approval for) sharing one of your OWN
    /// claim types with ALL audiences (via TCP). This is a STANDING RELEASE
    /// PREFERENCE, not a one-off share: once turned on, matching claims are
    /// released to any relying party without a fresh consent prompt.
    /// CSIL-RPC parity for the web identity editor's "share" toggle.
    ShareClaim {
        claim_type: String,
        /// Turn sharing on.
        #[arg(long, conflicts_with = "off")]
        on: bool,
        /// Turn sharing off.
        #[arg(long, conflicts_with = "on")]
        off: bool,
        #[arg(long)]
        server: Option<String>,
    },
    /// Mint a signing-request bundle for your OWN account (via TCP),
    /// addressed to an issuer, asking it to attest the given claim types.
    /// CSIL-RPC parity for `/account/request-verification`; the printed
    /// base64 is the same bundle the web QR/download offers.
    RequestVerification {
        /// Domain to address the request to (the would-be issuer).
        issuer_domain: String,
        /// Claim type to request attestation for (repeatable), e.g.
        /// `--type age_over_21 --type driver_license_number`.
        #[arg(long = "type")]
        claim_types: Vec<String>,
        #[arg(long)]
        server: Option<String>,
    },
}
