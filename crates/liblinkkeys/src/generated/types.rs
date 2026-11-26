//! Generated types from CSIL specification

#![allow(clippy::large_enum_variant)]

/// Returned by a generated `validate` method when a field violates one of its
/// CSIL constraints. `field` names the offending field; `message` explains.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "validation failed for `{}`: {}",
            self.field, self.message
        )
    }
}

impl std::error::Error for ValidationError {}

/// CheckValue variants
#[derive(Debug, Clone, PartialEq)]
pub enum CheckValue {
    Variant0(String),
    Variant1(i64),
    Variant2(f64),
}

pub type CheckEntries = std::collections::HashMap<String, CheckValue>;

#[derive(Debug, Clone, PartialEq)]
pub struct CheckResult {
    pub result: bool,
    pub entries: CheckEntries,
}

/// KeyAlgorithm variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyAlgorithm {
    Ed25519,
    X25519,
}

impl KeyAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::X25519 => "x25519",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "ed25519" => Some(Self::Ed25519),
            "x25519" => Some(Self::X25519),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::Ed25519 => 1,
            Self::X25519 => 2,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Ed25519),
            2 => Some(Self::X25519),
            _ => None,
        }
    }
}

/// KeyUsage variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyUsage {
    Sign,
    Encrypt,
    Agree,
}

impl KeyUsage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sign => "sign",
            Self::Encrypt => "encrypt",
            Self::Agree => "agree",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "sign" => Some(Self::Sign),
            "encrypt" => Some(Self::Encrypt),
            "agree" => Some(Self::Agree),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::Sign => 1,
            Self::Encrypt => 2,
            Self::Agree => 3,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Sign),
            2 => Some(Self::Encrypt),
            3 => Some(Self::Agree),
            _ => None,
        }
    }
}

/// AeadSuite variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AeadSuite {
    Aes256Gcm,
    Chacha20Poly1305,
}

impl AeadSuite {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes_256_gcm",
            Self::Chacha20Poly1305 => "chacha20_poly1305",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "aes_256_gcm" => Some(Self::Aes256Gcm),
            "chacha20_poly1305" => Some(Self::Chacha20Poly1305),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::Aes256Gcm => 1,
            Self::Chacha20Poly1305 => 2,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Aes256Gcm),
            2 => Some(Self::Chacha20Poly1305),
            _ => None,
        }
    }
}

/// ClaimValueType variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimValueType {
    Text,
    Url,
    Email,
    Bool,
    Int,
    Float,
    Decimal,
    Date,
    Timestamp,
    Opaque,
}

impl ClaimValueType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Url => "url",
            Self::Email => "email",
            Self::Bool => "bool",
            Self::Int => "int",
            Self::Float => "float",
            Self::Decimal => "decimal",
            Self::Date => "date",
            Self::Timestamp => "timestamp",
            Self::Opaque => "opaque",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "text" => Some(Self::Text),
            "url" => Some(Self::Url),
            "email" => Some(Self::Email),
            "bool" => Some(Self::Bool),
            "int" => Some(Self::Int),
            "float" => Some(Self::Float),
            "decimal" => Some(Self::Decimal),
            "date" => Some(Self::Date),
            "timestamp" => Some(Self::Timestamp),
            "opaque" => Some(Self::Opaque),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::Text => 1,
            Self::Url => 2,
            Self::Email => 3,
            Self::Bool => 4,
            Self::Int => 5,
            Self::Float => 6,
            Self::Decimal => 7,
            Self::Date => 8,
            Self::Timestamp => 9,
            Self::Opaque => 10,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Text),
            2 => Some(Self::Url),
            3 => Some(Self::Email),
            4 => Some(Self::Bool),
            5 => Some(Self::Int),
            6 => Some(Self::Float),
            7 => Some(Self::Decimal),
            8 => Some(Self::Date),
            9 => Some(Self::Timestamp),
            10 => Some(Self::Opaque),
            _ => None,
        }
    }
}

/// SetRule variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SetRule {
    UserSelf,
    IdpOnRequest,
    TrustedIssuerOnly,
    AdminOnly,
    Deny,
}

impl SetRule {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UserSelf => "user_self",
            Self::IdpOnRequest => "idp_on_request",
            Self::TrustedIssuerOnly => "trusted_issuer_only",
            Self::AdminOnly => "admin_only",
            Self::Deny => "deny",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "user_self" => Some(Self::UserSelf),
            "idp_on_request" => Some(Self::IdpOnRequest),
            "trusted_issuer_only" => Some(Self::TrustedIssuerOnly),
            "admin_only" => Some(Self::AdminOnly),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::UserSelf => 1,
            Self::IdpOnRequest => 2,
            Self::TrustedIssuerOnly => 3,
            Self::AdminOnly => 4,
            Self::Deny => 5,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::UserSelf),
            2 => Some(Self::IdpOnRequest),
            3 => Some(Self::TrustedIssuerOnly),
            4 => Some(Self::AdminOnly),
            5 => Some(Self::Deny),
            _ => None,
        }
    }
}

/// SigningRule variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigningRule {
    SelfSigned,
    Verified,
    Attested,
    Unsigned,
}

impl SigningRule {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SelfSigned => "self_signed",
            Self::Verified => "verified",
            Self::Attested => "attested",
            Self::Unsigned => "unsigned",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "self_signed" => Some(Self::SelfSigned),
            "verified" => Some(Self::Verified),
            "attested" => Some(Self::Attested),
            "unsigned" => Some(Self::Unsigned),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::SelfSigned => 1,
            Self::Verified => 2,
            Self::Attested => 3,
            Self::Unsigned => 4,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::SelfSigned),
            2 => Some(Self::Verified),
            3 => Some(Self::Attested),
            4 => Some(Self::Unsigned),
            _ => None,
        }
    }
}

/// SetClaimOutcome variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SetClaimOutcome {
    Signed,
    StoredUnsigned,
    VerificationRequired,
    Queued,
}

impl SetClaimOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Signed => "signed",
            Self::StoredUnsigned => "stored_unsigned",
            Self::VerificationRequired => "verification_required",
            Self::Queued => "queued",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "signed" => Some(Self::Signed),
            "stored_unsigned" => Some(Self::StoredUnsigned),
            "verification_required" => Some(Self::VerificationRequired),
            "queued" => Some(Self::Queued),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::Signed => 1,
            Self::StoredUnsigned => 2,
            Self::VerificationRequired => 3,
            Self::Queued => 4,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Signed),
            2 => Some(Self::StoredUnsigned),
            3 => Some(Self::VerificationRequired),
            4 => Some(Self::Queued),
            _ => None,
        }
    }
}

/// ReleaseDisposition variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReleaseDisposition {
    ForcedAllow,
    ForcedDeny,
}

impl ReleaseDisposition {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ForcedAllow => "forced_allow",
            Self::ForcedDeny => "forced_deny",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "forced_allow" => Some(Self::ForcedAllow),
            "forced_deny" => Some(Self::ForcedDeny),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::ForcedAllow => 1,
            Self::ForcedDeny => 2,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::ForcedAllow),
            2 => Some(Self::ForcedDeny),
            _ => None,
        }
    }
}

/// ConsentRowPolicy variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConsentRowPolicy {
    User,
    ForcedAllow,
    ForcedDeny,
}

impl ConsentRowPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::ForcedAllow => "forced_allow",
            Self::ForcedDeny => "forced_deny",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "user" => Some(Self::User),
            "forced_allow" => Some(Self::ForcedAllow),
            "forced_deny" => Some(Self::ForcedDeny),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::User => 1,
            Self::ForcedAllow => 2,
            Self::ForcedDeny => 3,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::User),
            2 => Some(Self::ForcedAllow),
            3 => Some(Self::ForcedDeny),
            _ => None,
        }
    }
}

/// ClaimApprovalStatus variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimApprovalStatus {
    Pending,
    Approved,
    Rejected,
}

impl ClaimApprovalStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::Pending => 1,
            Self::Approved => 2,
            Self::Rejected => 3,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Pending),
            2 => Some(Self::Approved),
            3 => Some(Self::Rejected),
            _ => None,
        }
    }
}

/// PinRecheckOutcome variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PinRecheckOutcome {
    FirstSeen,
    Unchanged,
    Rotated,
    Mismatch,
    Error,
}

impl PinRecheckOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FirstSeen => "first_seen",
            Self::Unchanged => "unchanged",
            Self::Rotated => "rotated",
            Self::Mismatch => "mismatch",
            Self::Error => "error",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "first_seen" => Some(Self::FirstSeen),
            "unchanged" => Some(Self::Unchanged),
            "rotated" => Some(Self::Rotated),
            "mismatch" => Some(Self::Mismatch),
            "error" => Some(Self::Error),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::FirstSeen => 1,
            Self::Unchanged => 2,
            Self::Rotated => 3,
            Self::Mismatch => 4,
            Self::Error => 5,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::FirstSeen),
            2 => Some(Self::Unchanged),
            3 => Some(Self::Rotated),
            4 => Some(Self::Mismatch),
            5 => Some(Self::Error),
            _ => None,
        }
    }
}

/// NotificationPurpose variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NotificationPurpose {
    VerifyContact,
    ResetPassword,
}

impl NotificationPurpose {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::VerifyContact => "verify_contact",
            Self::ResetPassword => "reset_password",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "verify_contact" => Some(Self::VerifyContact),
            "reset_password" => Some(Self::ResetPassword),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::VerifyContact => 1,
            Self::ResetPassword => 2,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::VerifyContact),
            2 => Some(Self::ResetPassword),
            _ => None,
        }
    }
}

/// NotificationChannel variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NotificationChannel {
    Email,
}

impl NotificationChannel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Email => "email",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "email" => Some(Self::Email),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::Email => 1,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Email),
            _ => None,
        }
    }
}

/// DestinationKind variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DestinationKind {
    Email,
}

impl DestinationKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Email => "email",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "email" => Some(Self::Email),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::Email => 1,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Email),
            _ => None,
        }
    }
}

/// LocalRpPolicy variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocalRpPolicy {
    Disabled,
    AdminApprovalRequired,
    AllowByDefault,
}

impl LocalRpPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::AdminApprovalRequired => "admin_approval_required",
            Self::AllowByDefault => "allow_by_default",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "disabled" => Some(Self::Disabled),
            "admin_approval_required" => Some(Self::AdminApprovalRequired),
            "allow_by_default" => Some(Self::AllowByDefault),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::Disabled => 1,
            Self::AdminApprovalRequired => 2,
            Self::AllowByDefault => 3,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Disabled),
            2 => Some(Self::AdminApprovalRequired),
            3 => Some(Self::AllowByDefault),
            _ => None,
        }
    }
}

/// LocalRpStatus variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocalRpStatus {
    Pending,
    Approved,
    Denied,
    Revoked,
}

impl LocalRpStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Revoked => "revoked",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "denied" => Some(Self::Denied),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::Pending => 1,
            Self::Approved => 2,
            Self::Denied => 3,
            Self::Revoked => 4,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Pending),
            2 => Some(Self::Approved),
            3 => Some(Self::Denied),
            4 => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// LocalRpAdmission variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocalRpAdmission {
    Consent,
    Pending,
    Blocked,
}

impl LocalRpAdmission {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Consent => "consent",
            Self::Pending => "pending",
            Self::Blocked => "blocked",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "consent" => Some(Self::Consent),
            "pending" => Some(Self::Pending),
            "blocked" => Some(Self::Blocked),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::Consent => 1,
            Self::Pending => 2,
            Self::Blocked => 3,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Consent),
            2 => Some(Self::Pending),
            3 => Some(Self::Blocked),
            _ => None,
        }
    }
}

/// AppAccessMode variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppAccessMode {
    Allow,
    Deny,
}

impl AppAccessMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "allow" => Some(Self::Allow),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::Allow => 1,
            Self::Deny => 2,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Allow),
            2 => Some(Self::Deny),
            _ => None,
        }
    }
}

/// AppAccessTargetKind variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppAccessTargetKind {
    Everyone,
    User,
    Group,
    Claim,
}

impl AppAccessTargetKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Everyone => "everyone",
            Self::User => "user",
            Self::Group => "group",
            Self::Claim => "claim",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "everyone" => Some(Self::Everyone),
            "user" => Some(Self::User),
            "group" => Some(Self::Group),
            "claim" => Some(Self::Claim),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::Everyone => 1,
            Self::User => 2,
            Self::Group => 3,
            Self::Claim => 4,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Everyone),
            2 => Some(Self::User),
            3 => Some(Self::Group),
            4 => Some(Self::Claim),
            _ => None,
        }
    }
}

/// ClaimOperator variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimOperator {
    Present,
    Absent,
    Equals,
    AgeUnder,
    AgeAtLeast,
}

impl ClaimOperator {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Absent => "absent",
            Self::Equals => "equals",
            Self::AgeUnder => "age_under",
            Self::AgeAtLeast => "age_at_least",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "present" => Some(Self::Present),
            "absent" => Some(Self::Absent),
            "equals" => Some(Self::Equals),
            "age_under" => Some(Self::AgeUnder),
            "age_at_least" => Some(Self::AgeAtLeast),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::Present => 1,
            Self::Absent => 2,
            Self::Equals => 3,
            Self::AgeUnder => 4,
            Self::AgeAtLeast => 5,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Present),
            2 => Some(Self::Absent),
            3 => Some(Self::Equals),
            4 => Some(Self::AgeUnder),
            5 => Some(Self::AgeAtLeast),
            _ => None,
        }
    }
}

/// ApplicationKeyChallengePurpose variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApplicationKeyChallengePurpose {
    Add,
    Renew,
}

impl ApplicationKeyChallengePurpose {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Renew => "renew",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "add" => Some(Self::Add),
            "renew" => Some(Self::Renew),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::Add => 1,
            Self::Renew => 2,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Add),
            2 => Some(Self::Renew),
            _ => None,
        }
    }
}

/// AuthFlow variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthFlow {
    Login,
    ClaimsUpdate,
}

impl AuthFlow {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::ClaimsUpdate => "claims_update",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "login" => Some(Self::Login),
            "claims_update" => Some(Self::ClaimsUpdate),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::Login => 1,
            Self::ClaimsUpdate => 2,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Login),
            2 => Some(Self::ClaimsUpdate),
            _ => None,
        }
    }
}

/// RpCacheStatus variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RpCacheStatus {
    Fresh,
    Refreshed,
    Stale,
}

impl RpCacheStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Refreshed => "refreshed",
            Self::Stale => "stale",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "fresh" => Some(Self::Fresh),
            "refreshed" => Some(Self::Refreshed),
            "stale" => Some(Self::Stale),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::Fresh => 1,
            Self::Refreshed => 2,
            Self::Stale => 3,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Fresh),
            2 => Some(Self::Refreshed),
            3 => Some(Self::Stale),
            _ => None,
        }
    }
}

/// AccountKind variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountKind {
    Human,
    Application,
}

impl AccountKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Application => "application",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "human" => Some(Self::Human),
            "application" => Some(Self::Application),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::Human => 1,
            Self::Application => 2,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Human),
            2 => Some(Self::Application),
            _ => None,
        }
    }
}

/// RpErrorCode variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RpErrorCode {
    NotApplicationAccount,
    ApplicationMismatch,
    ApplicationUserLimit,
    BadRequest,
    UpstreamFailed,
    Internal,
    RequiredClaimUnverified,
}

impl RpErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotApplicationAccount => "not_application_account",
            Self::ApplicationMismatch => "application_mismatch",
            Self::ApplicationUserLimit => "application_user_limit",
            Self::BadRequest => "bad_request",
            Self::UpstreamFailed => "upstream_failed",
            Self::Internal => "internal",
            Self::RequiredClaimUnverified => "required_claim_unverified",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "not_application_account" => Some(Self::NotApplicationAccount),
            "application_mismatch" => Some(Self::ApplicationMismatch),
            "application_user_limit" => Some(Self::ApplicationUserLimit),
            "bad_request" => Some(Self::BadRequest),
            "upstream_failed" => Some(Self::UpstreamFailed),
            "internal" => Some(Self::Internal),
            "required_claim_unverified" => Some(Self::RequiredClaimUnverified),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::NotApplicationAccount => 1,
            Self::ApplicationMismatch => 2,
            Self::ApplicationUserLimit => 3,
            Self::BadRequest => 4,
            Self::UpstreamFailed => 5,
            Self::Internal => 6,
            Self::RequiredClaimUnverified => 7,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::NotApplicationAccount),
            2 => Some(Self::ApplicationMismatch),
            3 => Some(Self::ApplicationUserLimit),
            4 => Some(Self::BadRequest),
            5 => Some(Self::UpstreamFailed),
            6 => Some(Self::Internal),
            7 => Some(Self::RequiredClaimUnverified),
            _ => None,
        }
    }
}

/// IssuedClaimOutcome variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IssuedClaimOutcome {
    Deposited,
    Handoff,
    Skipped,
    Failed,
}

impl IssuedClaimOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Deposited => "deposited",
            Self::Handoff => "handoff",
            Self::Skipped => "skipped",
            Self::Failed => "failed",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "deposited" => Some(Self::Deposited),
            "handoff" => Some(Self::Handoff),
            "skipped" => Some(Self::Skipped),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::Deposited => 1,
            Self::Handoff => 2,
            Self::Skipped => 3,
            Self::Failed => 4,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Deposited),
            2 => Some(Self::Handoff),
            3 => Some(Self::Skipped),
            4 => Some(Self::Failed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HelloRequest {
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HelloResponse {
    pub greeting: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GuestbookEntry {
    pub id: String,
    pub name: String,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CreateGuestbookRequest {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpdateGuestbookRequest {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeleteGuestbookRequest {
    pub id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeleteGuestbookResponse {
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GuestbookListRequest {
    pub offset: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GuestbookListResponse {
    pub entries: Vec<GuestbookEntry>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EmptyRequest {}

#[derive(Debug, Clone, PartialEq)]
pub struct DomainPublicKey {
    pub key_id: String,
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    pub algorithm: KeyAlgorithm,
    pub key_usage: KeyUsage,
    pub created_at: time::OffsetDateTime,
    pub expires_at: time::OffsetDateTime,
    pub revoked_at: Option<time::OffsetDateTime>,
    pub signed_by_key_id: Option<String>,
    pub key_signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetDomainKeysResponse {
    pub domain: String,
    pub keys: Vec<DomainPublicKey>,
    pub recent_revocations_available: Option<bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetRevocationsRequest {
    pub since: Option<time::OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetRevocationsResponse {
    pub revocations: Vec<RevocationCertificate>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RecheckPinsRequest {
    pub domain: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PinRecheckResult {
    pub domain: String,
    pub outcome: PinRecheckOutcome,
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RecheckPinsResponse {
    pub results: Vec<PinRecheckResult>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UserPublicKey {
    pub key_id: String,
    pub user_id: String,
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    pub algorithm: KeyAlgorithm,
    pub key_usage: KeyUsage,
    pub created_at: time::OffsetDateTime,
    pub expires_at: time::OffsetDateTime,
    pub revoked_at: Option<time::OffsetDateTime>,
    pub signed_by_key_id: Option<String>,
    pub key_signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetUserKeysRequest {
    pub user_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetUserKeysResponse {
    pub user_id: String,
    pub domain: String,
    pub keys: Vec<UserPublicKey>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClaimSignature {
    pub domain: String,
    pub signed_by_key_id: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RevocationCertificate {
    pub target_key_id: String,
    pub target_fingerprint: String,
    pub revoked_at: time::OffsetDateTime,
    pub signatures: Vec<ClaimSignature>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Claim {
    pub claim_id: String,
    pub user_id: String,
    pub claim_type: String,
    pub claim_value: Vec<u8>,
    pub signatures: Vec<ClaimSignature>,
    pub attested_at: time::OffsetDateTime,
    pub created_at: time::OffsetDateTime,
    pub expires_at: Option<time::OffsetDateTime>,
    pub revoked_at: Option<time::OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetUserClaimsRequest {
    pub user_id: String,
    pub token: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetUserClaimsResponse {
    pub user_id: String,
    pub domain: String,
    pub claims: Vec<Claim>,
}

/// VerifyingParty variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerifyingParty {
    HomeDomain,
}

impl VerifyingParty {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HomeDomain => "home_domain",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "home_domain" => Some(Self::HomeDomain),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::HomeDomain => 1,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::HomeDomain),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RequestedClaim {
    pub claim_type: String,
    pub datatype: ClaimValueType,
    pub verified_by: Option<VerifyingParty>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClaimRequest {
    pub required: Vec<RequestedClaim>,
    pub optional: Vec<RequestedClaim>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthenticationRequirements {
    pub minimum_factor_count: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthFlowContext {
    pub flow: AuthFlow,
    pub prior_session: Option<String>,
    pub request_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConsentGrant {
    pub grant_id: String,
    pub user_id: String,
    pub subject_domain: String,
    pub audience: String,
    pub claim_types: Vec<String>,
    pub issued_at: time::OffsetDateTime,
    pub expires_at: time::OffsetDateTime,
    pub revoked_at: Option<time::OffsetDateTime>,
    pub application: Option<ApplicationRef>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedConsentGrant {
    pub grant: Vec<u8>,
    pub signatures: Vec<ClaimSignature>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DomainClaim {
    pub claim_type: String,
    pub claim_value: Vec<u8>,
    pub signatures: Vec<ClaimSignature>,
    pub attested_at: time::OffsetDateTime,
    pub expires_at: Option<time::OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SigningRequest {
    pub request_id: String,
    pub subject_user_id: String,
    pub subject_domain: String,
    pub issuer_domain: String,
    pub requested_claim_types: Vec<String>,
    pub nonce: String,
    pub issued_at: time::OffsetDateTime,
    pub expires_at: time::OffsetDateTime,
    pub callback: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedSigningRequest {
    pub request: Vec<u8>,
    pub signatures: Vec<ClaimSignature>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DepositClaimRequest {
    pub claim: Claim,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DepositClaimResponse {
    pub stored: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IdentityAssertion {
    pub user_id: String,
    pub domain: String,
    pub audience: String,
    pub nonce: String,
    pub issued_at: time::OffsetDateTime,
    pub expires_at: time::OffsetDateTime,
    pub authorized_claims: Vec<String>,
    pub display_name: Option<String>,
    pub application: ApplicationRef,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedIdentityAssertion {
    pub assertion: Vec<u8>,
    pub signing_key_id: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetUserInfoRequest {
    pub token: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UserInfoRequest {
    pub token: Vec<u8>,
    pub relying_party: String,
    pub timestamp: time::OffsetDateTime,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedUserInfoRequest {
    pub request: Vec<u8>,
    pub signing_key_id: String,
    pub signature: Vec<u8>,
    pub public_keys: Option<Vec<DomainPublicKey>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UserInfo {
    pub user_id: String,
    pub domain: String,
    pub display_name: String,
    pub claims: Vec<Claim>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RelyingPartyApplication {
    pub application: ApplicationRef,
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthRequest {
    pub relying_party: String,
    pub callback_url: String,
    pub nonce: String,
    pub timestamp: time::OffsetDateTime,
    pub signing_key_id: String,
    pub requested_claims: Option<ClaimRequest>,
    pub authentication_requirements: Option<AuthenticationRequirements>,
    pub flow_context: Option<AuthFlowContext>,
    pub relying_party_claims: Option<Vec<DomainClaim>>,
    pub application: RelyingPartyApplication,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedAuthRequest {
    pub request: Vec<u8>,
    pub signing_key_id: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EncryptedToken {
    pub ephemeral_public_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub suite: Option<AeadSuite>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AlgorithmSupport {
    pub signing: Vec<KeyAlgorithm>,
    pub encryption: Option<Vec<AeadSuite>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HandshakeRequest {
    pub version: String,
    pub algorithms: AlgorithmSupport,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HandshakeResponse {
    pub version: String,
    pub algorithms: AlgorithmSupport,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Relation {
    pub id: String,
    pub subject_type: String,
    pub subject_id: String,
    pub relation: String,
    pub object_type: String,
    pub object_id: String,
    pub created_at: time::OffsetDateTime,
    pub removed_at: Option<time::OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AdminUser {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub kind: AccountKind,
    pub application_id: Option<String>,
    pub is_active: bool,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
    pub purged_at: Option<time::OffsetDateTime>,
    pub purge_reason: Option<String>,
    pub password_locked: Option<bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListUsersRequest {
    pub offset: Option<i64>,
    pub limit: Option<i64>,
    pub include_purged: Option<bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListUsersResponse {
    pub users: Vec<AdminUser>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetUserRequest {
    pub user_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetUserResponse {
    pub user: AdminUser,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UserAuthenticationActivity {
    pub user_id: String,
    pub last_authenticated_at: Option<time::OffsetDateTime>,
    pub last_seen_at: Option<time::OffsetDateTime>,
    pub successful_authentication_count: i64,
    pub active_browser_session_count: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetUserAuthenticationActivityRequest {
    pub user_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetUserAuthenticationActivityResponse {
    pub activity: UserAuthenticationActivity,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CreateUserRequest {
    pub username: String,
    pub display_name: String,
    pub password: Option<String>,
    pub application_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CreateUserResponse {
    pub user: AdminUser,
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RenameUserRequest {
    pub user_id: String,
    pub username: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RenameUserResponse {
    pub user: AdminUser,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetApplicationIdRequest {
    pub user_id: String,
    pub application_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetApplicationIdResponse {
    pub user: AdminUser,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApiKeyInfo {
    pub key_id: String,
    pub name: String,
    pub hint: String,
    pub created_at: time::OffsetDateTime,
    pub last_used_at: Option<time::OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CreateApiKeyRequest {
    pub user_id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CreateApiKeyResponse {
    pub key: ApiKeyInfo,
    pub api_key: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListApiKeysRequest {
    pub user_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListApiKeysResponse {
    pub keys: Vec<ApiKeyInfo>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RevokeApiKeyRequest {
    pub user_id: String,
    pub key_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RevokeApiKeyResponse {
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AccountLimits {
    pub max_api_keys: Option<i64>,
    pub max_distinct_users: Option<i64>,
    pub distinct_user_window_days: i64,
    pub requests_per_minute: Option<i64>,
    pub request_burst: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetAccountLimitsRequest {
    pub user_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetAccountLimitsResponse {
    pub limits: AccountLimits,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetAccountLimitsRequest {
    pub user_id: String,
    pub limits: AccountLimits,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetAccountLimitsResponse {
    pub limits: AccountLimits,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpUsageDay {
    pub day: time::Date,
    pub operation: String,
    pub succeeded: i64,
    pub failed: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetApplicationUsageRequest {
    pub user_id: String,
    pub first_day: time::Date,
    pub last_day: time::Date,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetApplicationUsageResponse {
    pub distinct_users: i64,
    pub distinct_user_window_days: i64,
    pub max_distinct_users: Option<i64>,
    pub days: Vec<RpUsageDay>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpdateUserRequest {
    pub user_id: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpdateUserResponse {
    pub user: AdminUser,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeactivateUserRequest {
    pub user_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeactivateUserResponse {
    pub user: AdminUser,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActivateUserRequest {
    pub user_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActivateUserResponse {
    pub user: AdminUser,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PurgeUserRequest {
    pub user_id: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PurgeUserResponse {
    pub user: AdminUser,
    pub credentials_revoked: i64,
    pub keys_revoked: i64,
    pub claims_revoked: i64,
    pub relations_removed: i64,
    pub profiles_deleted: i64,
    pub consent_grants_deleted: i64,
    pub release_prefs_deleted: i64,
    pub email_verifications_deleted: i64,
    pub reviews_resolved: i64,
    pub local_rp_claim_tickets_deleted: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RevokeDomainKeyRequest {
    pub key_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RevokeDomainKeyResponse {
    pub revoked_key: DomainPublicKey,
    pub certificate_issued: bool,
    pub dns_removal_reminder: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResetPasswordRequest {
    pub user_id: String,
    pub new_password: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResetPasswordResponse {
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthenticateRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthenticateResponse {
    pub user: AdminUser,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoveCredentialRequest {
    pub credential_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoveCredentialResponse {
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetClaimRequest {
    pub user_id: String,
    pub claim_type: String,
    pub claim_value: String,
    pub expires_at: Option<time::OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetClaimResponse {
    pub claim: Claim,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoveClaimRequest {
    pub claim_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoveClaimResponse {
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListUserClaimsRequest {
    pub user_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListUserClaimsResponse {
    pub claim_types: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AdminUserClaimsRequest {
    pub user_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AdminUserClaimsResponse {
    pub claims: Vec<Claim>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetUserClaimRequest {
    pub user_id: String,
    pub claim_type: String,
    pub claim_value: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetUserClaimResponse {
    pub outcome: SetClaimOutcome,
    pub claim: Option<Claim>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SettableClaimPolicy {
    pub claim_type: String,
    pub label: String,
    pub description: String,
    pub datatype: ClaimValueType,
    pub max_bytes: i64,
    pub set_rule: SetRule,
    pub requires_approval: bool,
    pub signing_rule: SigningRule,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListSettablePoliciesResponse {
    pub policies: Vec<SettableClaimPolicy>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClaimTypePolicy {
    pub claim_type: String,
    pub label: String,
    pub description: String,
    pub value_type: ClaimValueType,
    pub max_bytes: i64,
    pub set_rule: SetRule,
    pub signing_rule: SigningRule,
    pub requires_approval: bool,
    pub user_settable: bool,
    pub default_auto_sign: bool,
    pub suggested: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListClaimTypesResponse {
    pub claim_types: Vec<ClaimTypePolicy>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetClaimTypeRequest {
    pub claim_type: String,
    pub label: String,
    pub description: Option<String>,
    pub value_type: ClaimValueType,
    pub max_bytes: i64,
    pub set_rule: SetRule,
    pub signing_rule: SigningRule,
    pub user_settable: bool,
    pub default_auto_sign: bool,
    pub requires_approval: bool,
    pub suggested: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetClaimTypeResponse {
    pub claim_type: ClaimTypePolicy,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoveClaimTypeRequest {
    pub claim_type: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoveClaimTypeResponse {
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClaimTypeLabel {
    pub claim_type: String,
    pub locale: String,
    pub label: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetClaimTypeLabelRequest {
    pub claim_type: String,
    pub locale: String,
    pub label: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetClaimTypeLabelResponse {
    pub label: ClaimTypeLabel,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListClaimTypeLabelsResponse {
    pub labels: Vec<ClaimTypeLabel>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoveClaimTypeLabelRequest {
    pub claim_type: String,
    pub locale: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoveClaimTypeLabelResponse {
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TrustedIssuer {
    pub claim_type: String,
    pub issuer_domain: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListTrustedIssuersResponse {
    pub trusted_issuers: Vec<TrustedIssuer>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AddTrustedIssuerRequest {
    pub claim_type: String,
    pub issuer_domain: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AddTrustedIssuerResponse {
    pub trusted_issuer: TrustedIssuer,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoveTrustedIssuerRequest {
    pub claim_type: String,
    pub issuer_domain: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoveTrustedIssuerResponse {
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReleaseRule {
    pub audience: String,
    pub claim_type: String,
    pub disposition: ReleaseDisposition,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListReleaseRulesResponse {
    pub release_rules: Vec<ReleaseRule>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetReleaseRuleRequest {
    pub audience: String,
    pub claim_type: String,
    pub disposition: ReleaseDisposition,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetReleaseRuleResponse {
    pub release_rule: ReleaseRule,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoveReleaseRuleRequest {
    pub audience: String,
    pub claim_type: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoveReleaseRuleResponse {
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClaimApproval {
    pub id: String,
    pub user_id: String,
    pub claim_type: String,
    pub claim_value: Vec<u8>,
    pub status: ClaimApprovalStatus,
    pub resolved_by: Option<String>,
    pub resolved_at: Option<time::OffsetDateTime>,
    pub created_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListPendingClaimApprovalsResponse {
    pub approvals: Vec<ClaimApproval>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApproveClaimRequest {
    pub approval_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApproveClaimResponse {
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RejectClaimRequest {
    pub approval_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RejectClaimResponse {
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AdminIssueAttestationRequest {
    pub user_id: String,
    pub claim_type: String,
    pub claim_value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AdminIssueAttestationResponse {
    pub claim: Claim,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GrantRelationRequest {
    pub subject_type: String,
    pub subject_id: String,
    pub relation: String,
    pub object_type: String,
    pub object_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GrantRelationResponse {
    pub relation: Relation,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoveRelationRequest {
    pub relation_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoveRelationResponse {
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListRelationsRequest {
    pub subject_type: Option<String>,
    pub subject_id: Option<String>,
    pub object_type: Option<String>,
    pub object_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListRelationsResponse {
    pub relations: Vec<Relation>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CheckPermissionRequest {
    pub user_id: String,
    pub relation: String,
    pub object_type: String,
    pub object_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CheckPermissionResponse {
    pub allowed: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChangePasswordResponse {
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetMyInfoResponse {
    pub user: AdminUser,
    pub relations: Vec<Relation>,
    pub claims: Vec<Claim>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetMyClaimRequest {
    pub claim_type: String,
    pub claim_value: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetMyClaimResponse {
    pub outcome: SetClaimOutcome,
    pub claim: Option<Claim>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoveMyClaimRequest {
    pub claim_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoveMyClaimResponse {
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetMyClaimSharingRequest {
    pub claim_type: String,
    pub share: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetMyClaimSharingResponse {}

#[derive(Debug, Clone, PartialEq)]
pub struct MyClaimSetting {
    pub claim_type: String,
    pub keep_verified: bool,
    pub shared_with_every_app: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MyClaimSettingsResponse {
    pub settings: Vec<MyClaimSetting>,
    pub profiles: Vec<Profile>,
    pub max_profiles: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetMyClaimKeepVerifiedRequest {
    pub claim_type: String,
    pub keep_verified: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetMyClaimKeepVerifiedResponse {}

#[derive(Debug, Clone, PartialEq)]
pub struct Profile {
    pub id: String,
    pub account_id: String,
    pub domain: String,
    pub is_root: bool,
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CreateProfileRequest {
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CreateProfileResponse {
    pub profile: Profile,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RequestVerificationRequest {
    pub issuer_domain: String,
    pub requested_claim_types: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RequestVerificationResponse {
    pub signed_request: SignedSigningRequest,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PasswordPolicy {
    pub min_length: i64,
    pub max_length: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BrowserSessionInfo {
    pub user: AdminUser,
    pub issued_at: time::OffsetDateTime,
    pub authenticated_at: time::OffsetDateTime,
    pub expires_at: time::OffsetDateTime,
    pub authentication_methods: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionPasswordLoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionPasswordLoginResponse {
    pub session: BrowserSessionInfo,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionCurrentResponse {
    pub session: BrowserSessionInfo,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionLogoutResponse {
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IntrospectBrowserSessionRequest {
    pub session_cookie: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IntrospectBrowserSessionResponse {
    pub user_id: String,
    pub user_domain: String,
    pub authenticated_at: time::OffsetDateTime,
    pub expires_at: time::OffsetDateTime,
    pub authentication_methods: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NotificationCapability {
    pub purpose: NotificationPurpose,
    pub channel: NotificationChannel,
    pub destination_kind: DestinationKind,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetNotificationCapabilitiesResponse {
    pub capabilities: Vec<NotificationCapability>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedContactMethod {
    pub id: String,
    pub channel: NotificationChannel,
    pub destination: String,
    pub verified_at: time::OffsetDateTime,
    pub purposes: Vec<NotificationPurpose>,
    pub revoked_at: Option<time::OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListVerifiedContactMethodsResponse {
    pub contact_methods: Vec<VerifiedContactMethod>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RevokeVerifiedContactMethodRequest {
    pub contact_method_id: String,
    pub current_password: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RevokeVerifiedContactMethodResponse {
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RequestContactVerificationRequest {
    pub channel: NotificationChannel,
    pub destination: String,
    pub current_password: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RequestContactVerificationResponse {
    pub expires_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConfirmContactVerificationRequest {
    pub token: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConfirmContactVerificationResponse {
    pub contact_method: VerifiedContactMethod,
    pub claims: Vec<Claim>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RequestPasswordRecoveryRequest {
    pub identifier: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RequestPasswordRecoveryResponse {}

#[derive(Debug, Clone, PartialEq)]
pub struct ValidatePasswordRecoveryRequest {
    pub token: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ValidatePasswordRecoveryResponse {
    pub expires_at: time::OffsetDateTime,
    pub password_policy: PasswordPolicy,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompletePasswordRecoveryRequest {
    pub token: String,
    pub new_password: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompletePasswordRecoveryResponse {
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BrowserAuthorizationInspectRequest {
    pub signed_request: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BrowserConsentClaim {
    pub claim_type: String,
    pub label: String,
    pub datatype: ClaimValueType,
    pub required: bool,
    pub available: bool,
    pub default_granted: bool,
    pub policy: ConsentRowPolicy,
    pub user_settable: bool,
    pub max_bytes: i64,
    pub requires_approval: bool,
    pub newly_requested: Option<bool>,
    pub home_verified: Option<bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BrowserAuthorizationInspectResponse {
    pub relying_party: String,
    pub claims: Vec<BrowserConsentClaim>,
    pub request_reason: Option<String>,
    pub already_consented: Option<bool>,
    pub authorized_claims: Option<Vec<String>>,
    pub access_denied: Option<AppAccessDenial>,
    pub application: Option<RelyingPartyApplication>,
    pub callback_host: Option<String>,
    pub return_host: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BrowserAuthorizationCompleteRequest {
    pub signed_request: String,
    pub authorized_claims: Vec<String>,
    pub claim_types_to_set: Vec<String>,
    pub claim_values_to_set: Vec<String>,
    pub use_standing_grant: Option<bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BrowserAuthorizationCompleteResponse {
    pub redirect_url: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BrowserLocalRpInspectRequest {
    pub signed_request: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BrowserLocalRpInspectResponse {
    pub admission: LocalRpAdmission,
    pub app_name: String,
    pub fingerprint: String,
    pub callback_host: String,
    pub first_seen_at: Option<time::OffsetDateTime>,
    pub claims: Vec<BrowserConsentClaim>,
    pub request_reason: Option<String>,
    pub already_consented: Option<bool>,
    pub authorized_claims: Option<Vec<String>>,
    pub access_denied: Option<AppAccessDenial>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BrowserLocalRpCompleteRequest {
    pub signed_request: String,
    pub authorized_claims: Vec<String>,
    pub claim_types_to_set: Vec<String>,
    pub claim_values_to_set: Vec<String>,
    pub use_standing_grant: Option<bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BrowserLocalRpCompleteResponse {
    pub redirect_url: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UiTheme {
    pub stylesheet_url: Option<String>,
    pub logo_url: Option<String>,
    pub favicon_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UiExtension {
    pub id: String,
    pub module_url: String,
    pub api_version: i64,
    pub stylesheet_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UiDisplaySettings {
    pub site_name: String,
    pub support_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetUiConfigurationResponse {
    pub host_api_version: i64,
    pub domain: String,
    pub public_origin: Option<String>,
    pub capabilities: Vec<String>,
    pub display: UiDisplaySettings,
    pub theme: Option<UiTheme>,
    pub extensions: Vec<UiExtension>,
    pub password_policy: Option<PasswordPolicy>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpSignRequest {
    pub callback_url: String,
    pub nonce: String,
    pub requested_claims: Option<ClaimRequest>,
    pub authentication_requirements: Option<AuthenticationRequirements>,
    pub flow_context: Option<AuthFlowContext>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpSignResponse {
    pub signed_request: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpDecryptRequest {
    pub encrypted_token: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpDecryptResponse {
    pub signed_assertion: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpVerifyRequest {
    pub signed_assertion: String,
    pub expected_domain: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpVerifyResponse {
    pub assertion: IdentityAssertion,
    pub verified: bool,
}

/// ClaimCheckStatus variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimCheckStatus {
    Valid,
    WrongSubject,
    BadTimestamp,
    Unsigned,
    Revoked,
    Expired,
    KeysUnavailable,
    KeyNotValid,
    BadSignature,
}

impl ClaimCheckStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::WrongSubject => "wrong_subject",
            Self::BadTimestamp => "bad_timestamp",
            Self::Unsigned => "unsigned",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::KeysUnavailable => "keys_unavailable",
            Self::KeyNotValid => "key_not_valid",
            Self::BadSignature => "bad_signature",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "valid" => Some(Self::Valid),
            "wrong_subject" => Some(Self::WrongSubject),
            "bad_timestamp" => Some(Self::BadTimestamp),
            "unsigned" => Some(Self::Unsigned),
            "revoked" => Some(Self::Revoked),
            "expired" => Some(Self::Expired),
            "keys_unavailable" => Some(Self::KeysUnavailable),
            "key_not_valid" => Some(Self::KeyNotValid),
            "bad_signature" => Some(Self::BadSignature),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::Valid => 1,
            Self::WrongSubject => 2,
            Self::BadTimestamp => 3,
            Self::Unsigned => 4,
            Self::Revoked => 5,
            Self::Expired => 6,
            Self::KeysUnavailable => 7,
            Self::KeyNotValid => 8,
            Self::BadSignature => 9,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Valid),
            2 => Some(Self::WrongSubject),
            3 => Some(Self::BadTimestamp),
            4 => Some(Self::Unsigned),
            5 => Some(Self::Revoked),
            6 => Some(Self::Expired),
            7 => Some(Self::KeysUnavailable),
            8 => Some(Self::KeyNotValid),
            9 => Some(Self::BadSignature),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DomainSignatureCheck {
    pub domain: String,
    pub status: ClaimCheckStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClaimCheck {
    pub claim_id: String,
    pub claim_type: String,
    pub claim_status: ClaimCheckStatus,
    pub signing_domains: Vec<DomainSignatureCheck>,
    pub verified: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpVerifyClaimsRequest {
    pub subject_domain: String,
    pub user_id: String,
    pub claims: Vec<Claim>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpVerifyClaimsResponse {
    pub checks: Vec<ClaimCheck>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpUserInfoRequest {
    pub token: String,
    pub api_base: String,
    pub domain: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpError {
    pub code: RpErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpIssueAttestationRequest {
    pub signed_request: SignedSigningRequest,
    pub claim_type: String,
    pub claim_value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpIssueAttestationResponse {
    pub claim: Claim,
    pub deposited: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizeValidateRequest {
    pub signed_request: String,
    pub user_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizeValidateResponse {
    pub relying_party: String,
    pub callback_url: String,
    pub requested_claims: Vec<String>,
    pub already_consented: Option<bool>,
    pub authorized_claims: Option<Vec<String>>,
    pub newly_requested_claims: Option<Vec<String>>,
    pub access_denied: Option<AppAccessDenial>,
    pub application: Option<RelyingPartyApplication>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizeFinalizeRequest {
    pub user_id: String,
    pub signed_request: String,
    pub authorized_claims: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizeFinalizeResponse {
    pub redirect_url: String,
}

/// ApiErrorCode variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApiErrorCode {
    RequestAlreadyUsed,
    RpKeyFetchFailed,
    RpEncryptKeyUntrusted,
    SigningFailed,
    StorageFailed,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Internal,
}

impl ApiErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RequestAlreadyUsed => "request_already_used",
            Self::RpKeyFetchFailed => "rp_key_fetch_failed",
            Self::RpEncryptKeyUntrusted => "rp_encrypt_key_untrusted",
            Self::SigningFailed => "signing_failed",
            Self::StorageFailed => "storage_failed",
            Self::BadRequest => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Internal => "internal",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "request_already_used" => Some(Self::RequestAlreadyUsed),
            "rp_key_fetch_failed" => Some(Self::RpKeyFetchFailed),
            "rp_encrypt_key_untrusted" => Some(Self::RpEncryptKeyUntrusted),
            "signing_failed" => Some(Self::SigningFailed),
            "storage_failed" => Some(Self::StorageFailed),
            "bad_request" => Some(Self::BadRequest),
            "unauthorized" => Some(Self::Unauthorized),
            "forbidden" => Some(Self::Forbidden),
            "not_found" => Some(Self::NotFound),
            "internal" => Some(Self::Internal),
            _ => None,
        }
    }

    pub fn to_number(self) -> i64 {
        match self {
            Self::RequestAlreadyUsed => 1,
            Self::RpKeyFetchFailed => 2,
            Self::RpEncryptKeyUntrusted => 3,
            Self::SigningFailed => 4,
            Self::StorageFailed => 5,
            Self::BadRequest => 6,
            Self::Unauthorized => 7,
            Self::Forbidden => 8,
            Self::NotFound => 9,
            Self::Internal => 10,
        }
    }

    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::RequestAlreadyUsed),
            2 => Some(Self::RpKeyFetchFailed),
            3 => Some(Self::RpEncryptKeyUntrusted),
            4 => Some(Self::SigningFailed),
            5 => Some(Self::StorageFailed),
            6 => Some(Self::BadRequest),
            7 => Some(Self::Unauthorized),
            8 => Some(Self::Forbidden),
            9 => Some(Self::NotFound),
            10 => Some(Self::Internal),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApiError {
    pub code: ApiErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LocalRpDescriptor {
    pub app_name: String,
    pub local_domain_hint: Option<String>,
    /// constraint: size == 32
    pub signing_public_key: Vec<u8>,
    /// constraint: size == 32
    pub encryption_public_key: Vec<u8>,
    pub fingerprint: String,
    pub supported_suites: Vec<AeadSuite>,
    pub created_at: time::OffsetDateTime,
    pub expires_at: time::OffsetDateTime,
}

impl LocalRpDescriptor {
    /// Validate this value against the constraints declared in the CSIL spec.
    pub fn validate(&self) -> Result<(), ValidationError> {
        {
            let v = &self.signing_public_key;
            if v.len() != 32usize {
                return Err(ValidationError {
                    field: "signing_public_key".to_string(),
                    message: "length must equal 32".to_string(),
                });
            }
        }
        {
            let v = &self.encryption_public_key;
            if v.len() != 32usize {
                return Err(ValidationError {
                    field: "encryption_public_key".to_string(),
                    message: "length must equal 32".to_string(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedLocalRpDescriptor {
    pub descriptor: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LocalRpLoginRequest {
    pub descriptor: SignedLocalRpDescriptor,
    pub callback_url: String,
    pub nonce: Vec<u8>,
    pub state: Vec<u8>,
    pub requested_claims: Vec<String>,
    pub required_claims: Vec<String>,
    pub authentication_requirements: Option<AuthenticationRequirements>,
    pub flow_context: Option<AuthFlowContext>,
    pub issued_at: time::OffsetDateTime,
    pub expires_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedLocalRpLoginRequest {
    pub request: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LocalRpCallbackHeader {
    pub fingerprint: String,
    pub nonce: Vec<u8>,
    pub state: Vec<u8>,
    pub suite: AeadSuite,
    /// constraint: size == 32
    pub ephemeral_public_key: Vec<u8>,
    /// constraint: size == 12
    pub aead_nonce: Vec<u8>,
    pub issued_at: time::OffsetDateTime,
    pub expires_at: time::OffsetDateTime,
}

impl LocalRpCallbackHeader {
    /// Validate this value against the constraints declared in the CSIL spec.
    pub fn validate(&self) -> Result<(), ValidationError> {
        {
            let v = &self.ephemeral_public_key;
            if v.len() != 32usize {
                return Err(ValidationError {
                    field: "ephemeral_public_key".to_string(),
                    message: "length must equal 32".to_string(),
                });
            }
        }
        {
            let v = &self.aead_nonce;
            if v.len() != 12usize {
                return Err(ValidationError {
                    field: "aead_nonce".to_string(),
                    message: "length must equal 12".to_string(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LocalRpEncryptedCallback {
    pub header: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LocalRpCallbackPayload {
    pub user_id: String,
    pub user_domain: String,
    pub claim_ticket: Vec<u8>,
    pub audience_fingerprint: String,
    pub callback_url: String,
    pub nonce: Vec<u8>,
    pub state: Vec<u8>,
    pub issued_at: time::OffsetDateTime,
    pub expires_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedLocalRpCallbackPayload {
    pub payload: Vec<u8>,
    pub signing_key_id: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LocalRpTicketRedemptionRequest {
    pub claim_ticket: Vec<u8>,
    pub fingerprint: String,
    pub issued_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedLocalRpTicketRedemptionRequest {
    pub request: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LocalRpTicketRedemptionResponse {
    pub user_id: String,
    pub user_domain: String,
    pub claims: Vec<Claim>,
    pub ticket_expires_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AdminLocalRp {
    pub fingerprint: String,
    /// constraint: size == 32
    pub signing_public_key: Vec<u8>,
    /// constraint: size == 32
    pub encryption_public_key: Vec<u8>,
    pub app_name: String,
    pub local_domain_hint: Option<String>,
    pub status: LocalRpStatus,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
    pub expires_at: Option<time::OffsetDateTime>,
    pub last_seen_at: Option<time::OffsetDateTime>,
    pub admin_notes: Option<String>,
}

impl AdminLocalRp {
    /// Validate this value against the constraints declared in the CSIL spec.
    pub fn validate(&self) -> Result<(), ValidationError> {
        {
            let v = &self.signing_public_key;
            if v.len() != 32usize {
                return Err(ValidationError {
                    field: "signing_public_key".to_string(),
                    message: "length must equal 32".to_string(),
                });
            }
        }
        {
            let v = &self.encryption_public_key;
            if v.len() != 32usize {
                return Err(ValidationError {
                    field: "encryption_public_key".to_string(),
                    message: "length must equal 32".to_string(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListLocalRpsRequest {
    pub offset: Option<i64>,
    pub limit: Option<i64>,
    pub status: Option<LocalRpStatus>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListLocalRpsResponse {
    pub local_rps: Vec<AdminLocalRp>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetLocalRpRequest {
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetLocalRpResponse {
    pub local_rp: AdminLocalRp,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApproveLocalRpRequest {
    pub fingerprint: String,
    pub admin_notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApproveLocalRpResponse {
    pub local_rp: AdminLocalRp,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DenyLocalRpRequest {
    pub fingerprint: String,
    pub admin_notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DenyLocalRpResponse {
    pub local_rp: AdminLocalRp,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RevokeLocalRpRequest {
    pub fingerprint: String,
    pub admin_notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RevokeLocalRpResponse {
    pub local_rp: AdminLocalRp,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetLocalRpPolicyRequest {}

#[derive(Debug, Clone, PartialEq)]
pub struct GetLocalRpPolicyResponse {
    pub policy: LocalRpPolicy,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetLocalRpPolicyRequest {
    pub policy: LocalRpPolicy,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetLocalRpPolicyResponse {
    pub policy: LocalRpPolicy,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignInPolicy {
    pub sign_in_hours: i64,
    pub default_sign_in_hours: i64,
    pub min_sign_in_hours: i64,
    pub max_sign_in_hours: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetSignInPolicyRequest {
    pub sign_in_hours: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetUserPasswordLockRequest {
    pub user_id: String,
    pub locked: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetUserPasswordLockResponse {
    pub user: AdminUser,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AppAccessTarget {
    pub kind: AppAccessTargetKind,
    pub user_id: Option<String>,
    pub group_name: Option<String>,
    pub claim_type: Option<String>,
    pub claim_operator: Option<ClaimOperator>,
    pub claim_value: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AppAccessPolicy {
    pub id: String,
    pub name: String,
    pub mode: AppAccessMode,
    pub patterns: Vec<String>,
    pub message: Option<String>,
    pub targets: Vec<AppAccessTarget>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListAppAccessPoliciesResponse {
    pub policies: Vec<AppAccessPolicy>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetAppAccessPolicyRequest {
    pub id: Option<String>,
    pub name: String,
    pub mode: AppAccessMode,
    pub patterns: Vec<String>,
    pub message: Option<String>,
    pub targets: Vec<AppAccessTarget>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetAppAccessPolicyResponse {
    pub policy: AppAccessPolicy,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoveAppAccessPolicyRequest {
    pub id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoveAppAccessPolicyResponse {
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PreviewAppAccessRequest {
    pub user_id: String,
    pub domain: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PreviewAppAccessResponse {
    pub allowed: bool,
    pub applied_policies: Vec<String>,
    pub blocking_policies: Vec<String>,
    pub messages: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AppAccessDenial {
    pub domain: Option<String>,
    pub messages: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PurgeLocalRpTicketsRequest {}

#[derive(Debug, Clone, PartialEq)]
pub struct PurgeLocalRpTicketsResponse {
    pub purged_count: i64,
}

pub type LocaleMessages = std::collections::HashMap<String, String>;

#[derive(Debug, Clone, PartialEq)]
pub struct TranslationsRequest {
    pub locale: Option<String>,
    pub accept_language: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TranslationsResponse {
    pub locale: String,
    pub available_locales: Vec<String>,
    pub messages: LocaleMessages,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListLocalesResponse {
    pub available_locales: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApplicationKeySignature {
    pub signed_by_key_id: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApplicationKeyAttestation {
    pub subject_user_id: String,
    pub subject_domain: String,
    pub application_id: String,
    pub instance_id: String,
    pub key_id: String,
    pub key_usage: KeyUsage,
    pub algorithm: KeyAlgorithm,
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    pub key_created_at: time::OffsetDateTime,
    pub key_expires_at: time::OffsetDateTime,
    pub attested_at: time::OffsetDateTime,
    pub attestation_expires_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedApplicationKeyAttestation {
    pub attestation: Vec<u8>,
    pub signatures: Vec<ClaimSignature>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApplicationKeyAddition {
    pub subject_user_id: String,
    pub subject_domain: String,
    pub application_id: String,
    pub instance_id: String,
    pub key_id: String,
    pub key_usage: KeyUsage,
    pub algorithm: KeyAlgorithm,
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    pub requested_key_lifetime_seconds: i64,
    pub challenge_id: String,
    pub challenge: Vec<u8>,
    pub requested_at: time::OffsetDateTime,
    pub expires_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedApplicationKeyAddition {
    pub addition: Vec<u8>,
    pub signatures: Vec<ApplicationKeySignature>,
    pub possession_proof: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApplicationKeyRenewal {
    pub subject_user_id: String,
    pub subject_domain: String,
    pub application_id: String,
    pub instance_id: String,
    pub key_id: String,
    pub challenge_id: String,
    pub challenge: Vec<u8>,
    pub requested_at: time::OffsetDateTime,
    pub expires_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedApplicationKeyRenewal {
    pub renewal: Vec<u8>,
    pub signatures: Vec<ApplicationKeySignature>,
    pub possession_proof: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApplicationKeyRevocation {
    pub subject_user_id: String,
    pub subject_domain: String,
    pub application_id: String,
    pub instance_id: String,
    pub target_key_id: String,
    pub target_fingerprint: String,
    pub revoked_at: time::OffsetDateTime,
    pub signatures: Vec<ApplicationKeySignature>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StartApplicationKeyChallengeRequest {
    pub subject_user_id: String,
    pub application_id: String,
    pub instance_id: String,
    pub purpose: ApplicationKeyChallengePurpose,
    pub key_usage: KeyUsage,
    pub algorithm: KeyAlgorithm,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StartApplicationKeyChallengeResponse {
    pub challenge_id: String,
    pub challenge: Option<Vec<u8>>,
    pub sealed_challenge: Option<Vec<u8>>,
    pub expires_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AddApplicationKeyRequest {
    pub request: SignedApplicationKeyAddition,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AddApplicationKeyResponse {
    pub attestation: SignedApplicationKeyAttestation,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RenewApplicationKeyAttestationRequest {
    pub request: SignedApplicationKeyRenewal,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RenewApplicationKeyAttestationResponse {
    pub attestation: SignedApplicationKeyAttestation,
    pub signed: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RevokeApplicationKeyRequest {
    pub revocation: ApplicationKeyRevocation,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RevokeApplicationKeyResponse {
    pub revoked_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EnrollApplicationInstanceRequest {
    pub application_id: String,
    pub instance_id: String,
    pub keys: Vec<SignedApplicationKeyAddition>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EnrollApplicationInstanceResponse {
    pub subject_user_id: String,
    pub subject_domain: String,
    pub application_id: String,
    pub instance_id: String,
    pub attestations: Vec<SignedApplicationKeyAttestation>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetApplicationKeysRequest {
    pub subject_user_id: String,
    pub application_id: String,
    pub instance_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetApplicationKeysResponse {
    pub subject_user_id: String,
    pub subject_domain: String,
    pub application_id: String,
    pub instance_id: String,
    pub keys: Vec<SignedApplicationKeyAttestation>,
    pub revocations: Vec<ApplicationKeyRevocation>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpResolveDomainKeysRequest {
    pub domain: String,
    pub max_cache_age_seconds: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpResolveDomainKeysResponse {
    pub domain: String,
    pub keys: Vec<DomainPublicKey>,
    pub revocations: Vec<RevocationCertificate>,
    pub fetched_at: time::OffsetDateTime,
    pub revocations_checked_at: time::OffsetDateTime,
    pub cache_status: RpCacheStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpResolveApplicationKeysRequest {
    pub subject_user_id: String,
    pub subject_domain: String,
    pub application_id: String,
    pub instance_id: String,
    pub max_cache_age_seconds: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpResolveApplicationKeysResponse {
    pub subject_user_id: String,
    pub subject_domain: String,
    pub application_id: String,
    pub instance_id: String,
    pub application_keys: Vec<SignedApplicationKeyAttestation>,
    pub application_key_revocations: Vec<ApplicationKeyRevocation>,
    pub home_domain_keys: Vec<DomainPublicKey>,
    pub home_domain_key_revocations: Vec<RevocationCertificate>,
    pub fetched_at: time::OffsetDateTime,
    pub revocations_checked_at: time::OffsetDateTime,
    pub cache_status: RpCacheStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApplicationRef {
    pub subject_user_id: String,
    pub subject_domain: String,
    pub application_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GranteeRef {
    pub application: Option<ApplicationRef>,
    pub local_rp_descriptor_fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GranteeProof {
    pub application_instance_id: Option<String>,
    pub local_rp_descriptor: Option<SignedLocalRpDescriptor>,
    pub signature: ApplicationKeySignature,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActAsScopeEntry {
    pub scope: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActAsScopeSet {
    pub audience: ApplicationRef,
    pub grantee: GranteeRef,
    pub entries: Vec<ActAsScopeEntry>,
    pub language: Option<String>,
    pub audience_handle_claim: Option<Claim>,
    pub issued_at: time::OffsetDateTime,
    pub expires_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedActAsScopeSet {
    pub scope_set: Vec<u8>,
    pub signer_instance_id: String,
    pub signatures: Vec<ApplicationKeySignature>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActAsScopeSetRequest {
    pub grantee: GranteeRef,
    pub scope: Vec<String>,
    pub locale_preferences: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActAsGrant {
    pub grant_id: String,
    pub user_id: String,
    pub subject_domain: String,
    pub grantee: GranteeRef,
    pub audience: ApplicationRef,
    pub scope_set: SignedActAsScopeSet,
    pub approved_scope: Vec<String>,
    pub issued_at: time::OffsetDateTime,
    pub expires_at: time::OffsetDateTime,
    pub series_issued_at: time::OffsetDateTime,
    pub renewable_until: time::OffsetDateTime,
    pub device_fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedActAsGrant {
    pub grant: Vec<u8>,
    pub signatures: Vec<ClaimSignature>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActAsGrantRequest {
    pub grantee: GranteeRef,
    pub scope_set: SignedActAsScopeSet,
    pub requested_lifetime_seconds: Option<i64>,
    pub requested_renewal_window_seconds: Option<i64>,
    pub grantee_handle_claim: Option<Claim>,
    pub callback_url: String,
    pub nonce: String,
    pub requested_at: time::OffsetDateTime,
    pub expires_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedActAsGrantRequest {
    pub request: Vec<u8>,
    pub proof: GranteeProof,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActAsRefreshRequest {
    pub grant_id: String,
    pub grantee: GranteeRef,
    pub requested_at: time::OffsetDateTime,
    pub expires_at: time::OffsetDateTime,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedActAsRefreshRequest {
    pub request: Vec<u8>,
    pub proof: GranteeProof,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RefreshActAsGrantRequest {
    pub request: SignedActAsRefreshRequest,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RefreshActAsGrantResponse {
    pub grant: SignedActAsGrant,
    pub signed: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActAsPresentation {
    pub grant_hash: Vec<u8>,
    pub audience: ApplicationRef,
    pub request_digest: Vec<u8>,
    pub presented_at: time::OffsetDateTime,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedActAsPresentation {
    pub presentation: Vec<u8>,
    pub proof: GranteeProof,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActAsCredential {
    pub grant: SignedActAsGrant,
    pub presentation: SignedActAsPresentation,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActAsGrantRevocation {
    pub grant_id: String,
    pub user_id: String,
    pub subject_domain: String,
    pub revoked_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedActAsGrantRevocation {
    pub revocation: Vec<u8>,
    pub signatures: Vec<ClaimSignature>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetActAsGrantRevocationsRequest {
    pub grant_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetActAsGrantRevocationsResponse {
    pub revocations: Vec<SignedActAsGrantRevocation>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpActAsRefreshRequest {
    pub subject_domain: String,
    pub request: SignedActAsRefreshRequest,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpResolveActAsRevocationsRequest {
    pub subject_domain: String,
    pub grant_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BrowserActAsInspectRequest {
    pub signed_request: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BrowserActAsScopeEntry {
    pub scope: String,
    pub description: Option<String>,
    pub removed_by_policy: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BrowserActAsParty {
    pub domain: Option<String>,
    pub application_id: Option<String>,
    pub subject_user_id: Option<String>,
    pub handle: Option<String>,
    pub local_rp_name: Option<String>,
    pub local_rp_fingerprint: Option<String>,
    pub own_domain: bool,
    pub user_has_history: bool,
    pub domain_key_pinned: bool,
    pub operator_trusted: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BrowserActAsInspectResponse {
    pub grantee: GranteeRef,
    pub grantee_party: BrowserActAsParty,
    pub audience: ApplicationRef,
    pub audience_party: BrowserActAsParty,
    pub entries: Vec<BrowserActAsScopeEntry>,
    pub language: Option<String>,
    pub default_lifetime_seconds: i64,
    pub max_lifetime_seconds: i64,
    pub default_renewal_window_seconds: i64,
    pub max_renewal_window_seconds: i64,
    pub access_denied: Option<AppAccessDenial>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BrowserActAsCompleteRequest {
    pub signed_request: String,
    pub approved_scope: Vec<String>,
    pub lifetime_seconds: i64,
    pub renewal_window_seconds: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BrowserActAsCompleteResponse {
    pub redirect_url: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActAsGrantSummary {
    pub grant_id: String,
    pub grantee: GranteeRef,
    pub audience: ApplicationRef,
    pub approved_scope: Vec<String>,
    pub issued_at: time::OffsetDateTime,
    pub expires_at: time::OffsetDateTime,
    pub renewable_until: time::OffsetDateTime,
    pub revoked_at: Option<time::OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListActAsGrantsResponse {
    pub grants: Vec<ActAsGrantSummary>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RevokeActAsGrantRequest {
    pub grant_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RevokeActAsGrantResponse {
    pub revoked_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PreviewReleasePolicyRequest {
    pub audience: String,
    pub required_claims: Vec<String>,
    pub optional_claims: Vec<String>,
    pub available_claims: Vec<String>,
    pub user_choices: Vec<String>,
    pub temp_audience: Option<String>,
    pub temp_claim_type: Option<String>,
    pub temp_disposition: Option<ReleaseDisposition>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PreviewReleaseRow {
    pub claim_type: String,
    pub required: bool,
    pub available: bool,
    pub locked: bool,
    pub policy: ConsentRowPolicy,
    pub default_granted: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PreviewReleasePolicyResponse {
    pub forced_allow: Vec<String>,
    pub forced_deny: Vec<String>,
    pub authorized_claims: Vec<String>,
    pub rows: Vec<PreviewReleaseRow>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PreviewIssuerPolicyRequest {
    pub subject_domain: String,
    pub denied_domains: Option<Vec<String>>,
    pub denied_tlds: Option<Vec<String>>,
    pub issuer_user_id: Option<String>,
    pub claim_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PreviewIssuerPolicyResponse {
    pub denied_domains: Vec<String>,
    pub denied_tlds: Vec<String>,
    pub allowed: bool,
    pub reason: String,
    pub user_can_issue: Option<bool>,
    pub attested_claim_ttl_seconds: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InspectSigningRequestRequest {
    pub signed_request: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InspectSigningRequestResponse {
    pub subject_user_id: String,
    pub subject_domain: String,
    pub requested_claim_types: Vec<String>,
    pub expires_at: time::OffsetDateTime,
    pub issuable_claim_types: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IssueForSigningRequestRequest {
    pub signed_request: String,
    pub claim_types: Vec<String>,
    pub claim_values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IssuedClaimResult {
    pub claim_type: String,
    pub outcome: IssuedClaimOutcome,
    pub message: Option<String>,
    pub claim_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IssueForSigningRequestResponse {
    pub results: Vec<IssuedClaimResult>,
}
