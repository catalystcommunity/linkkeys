//! Pure claim-signing policy logic: value validation, the setting/signing lanes,
//! and the rejection taxonomy. This is the heart of "validate anything I can
//! sign" — the IDP only self-signs values it can validate, and the rules for who
//! may set a claim type and how it gets signed are evaluated here.
//!
//! No I/O. The server crate owns the registry storage and maps its DB rows onto
//! the [`ClaimPolicy`] struct, then calls [`evaluate_set`] to decide what to do
//! with a set attempt. Keeping this pure means the same decision is reproducible
//! from any transport (web, a future CLI, a native agent) and is unit-testable
//! without a database.

use std::fmt;

/// The type of a claim's value, which determines whether and how the IDP can
/// validate it. Primitives are validatable (so the IDP may self-sign); `Opaque`
/// is not (so the IDP can only custody an issuer-attested value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    Text,
    Url,
    Email,
    Bool,
    Int,
    Float,
    Decimal,
    /// A calendar date, `YYYY-MM-DD`. Always interpreted as UTC.
    Date,
    /// An RFC3339 timestamp. Always interpreted/stored as UTC.
    Timestamp,
    /// The IDP cannot validate the value; meaning is by convention only.
    Opaque,
}

impl ValueType {
    /// Parse the wire/registry spelling (lowercase) of a value type.
    pub fn parse(s: &str) -> Option<ValueType> {
        Some(match s {
            "text" => ValueType::Text,
            "url" => ValueType::Url,
            "email" => ValueType::Email,
            "bool" => ValueType::Bool,
            "int" => ValueType::Int,
            "float" => ValueType::Float,
            "decimal" => ValueType::Decimal,
            "date" => ValueType::Date,
            "timestamp" => ValueType::Timestamp,
            "opaque" => ValueType::Opaque,
            _ => return None,
        })
    }

    /// The canonical lowercase spelling.
    pub fn as_str(&self) -> &'static str {
        match self {
            ValueType::Text => "text",
            ValueType::Url => "url",
            ValueType::Email => "email",
            ValueType::Bool => "bool",
            ValueType::Int => "int",
            ValueType::Float => "float",
            ValueType::Decimal => "decimal",
            ValueType::Date => "date",
            ValueType::Timestamp => "timestamp",
            ValueType::Opaque => "opaque",
        }
    }

    /// Validate a raw claim value against this type. `Opaque` accepts anything;
    /// every other type requires valid UTF-8 plus a format check. The IDP only
    /// ever self-signs a value that validates here.
    pub fn validate(&self, value: &[u8]) -> Result<(), ValidationError> {
        if *self == ValueType::Opaque {
            return Ok(());
        }
        let s = std::str::from_utf8(value).map_err(|_| ValidationError::NotUtf8)?;
        let ok = match self {
            ValueType::Text => !s.is_empty(),
            ValueType::Url => is_http_url(s),
            ValueType::Email => is_email(s),
            ValueType::Bool => s == "true" || s == "false",
            ValueType::Int => s.parse::<i64>().is_ok(),
            // Reject non-finite (inf/nan) so a domain never self-signs a junk float.
            ValueType::Float => s.parse::<f64>().map(|v| v.is_finite()).unwrap_or(false),
            ValueType::Decimal => is_decimal(s),
            ValueType::Date => chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok(),
            ValueType::Timestamp => chrono::DateTime::parse_from_rfc3339(s).is_ok(),
            ValueType::Opaque => true,
        };
        if ok {
            Ok(())
        } else {
            Err(ValidationError::BadFormat)
        }
    }
}

fn is_http_url(s: &str) -> bool {
    // Deliberately conservative — a real fetch/parse is the consumer's job. We
    // only confirm it looks like an absolute http(s) URL with a host, so the
    // signed value isn't obviously junk. Reject any whitespace/control chars
    // (incl. embedded CR/LF) so a domain-signed URL can't carry an injection
    // payload into a consumer's headers/requests.
    if s.contains(|c: char| c.is_whitespace() || c.is_control()) {
        return false;
    }
    let rest = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"));
    match rest {
        Some(host_and_path) => {
            let host = host_and_path.split(['/', '?', '#']).next().unwrap_or("");
            !host.is_empty() && host.contains('.')
        }
        None => false,
    }
}

fn is_email(s: &str) -> bool {
    // One '@', non-empty local part, a dotted domain, no spaces. Not RFC 5322 —
    // just enough that a self-signed value isn't nonsense. Ownership is proven by
    // the verification flow, not by this check.
    let mut parts = s.split('@');
    let (local, domain) = match (parts.next(), parts.next(), parts.next()) {
        (Some(l), Some(d), None) => (l, d),
        _ => return false,
    };
    !local.is_empty()
        && !domain.is_empty()
        && domain.contains('.')
        && !s.contains(|c: char| c.is_whitespace() || c.is_control())
        && !domain.starts_with('.')
        && !domain.ends_with('.')
}

fn is_decimal(s: &str) -> bool {
    // Optional leading sign, digits, optional single fractional part. No
    // exponent (a decimal is exact). Must contain at least one digit.
    let body = s.strip_prefix(['+', '-']).unwrap_or(s);
    if body.is_empty() {
        return false;
    }
    let mut seen_digit = false;
    let mut seen_dot = false;
    for c in body.chars() {
        match c {
            '0'..='9' => seen_digit = true,
            '.' if !seen_dot => seen_dot = true,
            _ => return false,
        }
    }
    seen_digit
}

/// Why a value failed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    NotUtf8,
    BadFormat,
}

/// How a claim type's value gets signed — the four lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningRule {
    /// Lane A: a validatable primitive the IDP signs itself, on set.
    SelfSigned,
    /// Lane B: the IDP signs only after a built-in verification flow proves the
    /// real-world fact (e.g. an email round-trip).
    Verified,
    /// Lane C: the IDP does not vouch for the value; it admits an external
    /// signature from a trusted issuer.
    Attested,
    /// Lane D: never carries a domain signature.
    Unsigned,
}

impl SigningRule {
    pub fn parse(s: &str) -> Option<SigningRule> {
        Some(match s {
            "self_signed" => SigningRule::SelfSigned,
            "verified" => SigningRule::Verified,
            "attested" => SigningRule::Attested,
            "unsigned" => SigningRule::Unsigned,
            _ => return None,
        })
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SigningRule::SelfSigned => "self_signed",
            SigningRule::Verified => "verified",
            SigningRule::Attested => "attested",
            SigningRule::Unsigned => "unsigned",
        }
    }
}

/// Who may set a value for a claim type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetRule {
    /// The subject may set it themselves (self-asserted lane).
    UserSelf,
    /// The user may request the IDP set it, subject to a validator or approval.
    IdpOnRequest,
    /// Only an attestation from a trusted issuer may set it.
    TrustedIssuerOnly,
    /// Only a domain admin may set it.
    AdminOnly,
    /// No one may set it (effectively retired).
    Deny,
}

impl SetRule {
    pub fn parse(s: &str) -> Option<SetRule> {
        Some(match s {
            "user_self" => SetRule::UserSelf,
            "idp_on_request" => SetRule::IdpOnRequest,
            "trusted_issuer_only" => SetRule::TrustedIssuerOnly,
            "admin_only" => SetRule::AdminOnly,
            "deny" => SetRule::Deny,
            _ => return None,
        })
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SetRule::UserSelf => "user_self",
            SetRule::IdpOnRequest => "idp_on_request",
            SetRule::TrustedIssuerOnly => "trusted_issuer_only",
            SetRule::AdminOnly => "admin_only",
            SetRule::Deny => "deny",
        }
    }
}

/// The principal attempting to set a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Setter {
    /// The subject acting on their own claim (self-service).
    User,
    /// A domain admin (break-glass; bypasses the approval queue).
    Admin,
    /// An external issuer presenting a signed attestation.
    TrustedIssuer,
}

/// A claim type's policy as the evaluator needs it. The server maps its registry
/// row onto this; fields it doesn't carry here (label, description, suggested)
/// don't affect the set/sign decision.
#[derive(Debug, Clone)]
pub struct ClaimPolicy {
    pub claim_type: String,
    pub value_type: ValueType,
    pub max_bytes: u64,
    pub set_rule: SetRule,
    pub signing_rule: SigningRule,
    pub requires_approval: bool,
    pub user_settable: bool,
}

/// What the server should do with an accepted set attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetAction {
    /// Validate (already done) and sign now with the domain's active keys.
    SelfSign,
    /// Start a verification flow; sign on successful completion.
    Verify,
    /// Accept and store the issuer's external signature; the IDP adds none.
    AcceptAttested,
    /// Hold for admin approval before signing.
    Queue,
    /// Store without any domain signature.
    StoreUnsigned,
}

/// The machine-readable rejection taxonomy. Surfaced to callers (and, in
/// interpretable form, to users) so a set attempt fails with a reason, not a
/// generic error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionReason {
    /// The claim type is not in the registry.
    UnknownClaimType,
    /// The value isn't valid for the type's value rule.
    ValueTypeMismatch,
    /// The value exceeds the type's `max_bytes`.
    ValueTooLarge { limit: u64 },
    /// This setter is not permitted to set this type.
    SetterNotAuthorized,
}

impl fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RejectionReason::UnknownClaimType => write!(f, "unknown claim type"),
            RejectionReason::ValueTypeMismatch => {
                write!(f, "value does not match the expected type")
            }
            RejectionReason::ValueTooLarge { limit } => {
                write!(f, "value exceeds the {} byte limit", limit)
            }
            RejectionReason::SetterNotAuthorized => {
                write!(f, "not authorized to set this claim type")
            }
        }
    }
}

/// Decide what to do with an attempt by `setter` to set `value` for a claim type
/// governed by `policy`. Returns the action the server should take, or a
/// machine-readable rejection. Pure: the trusted-issuer signature check and the
/// actual signing/queueing are the server's job; this only decides the lane.
pub fn evaluate_set(
    policy: &ClaimPolicy,
    setter: Setter,
    value: &[u8],
) -> Result<SetAction, RejectionReason> {
    // 1. Authorize the setter against the set rule. Admins may set anything that
    //    isn't explicitly denied (break-glass), mirroring today's admin set-claim.
    let authorized = match policy.set_rule {
        SetRule::Deny => false,
        SetRule::AdminOnly => setter == Setter::Admin,
        SetRule::TrustedIssuerOnly => setter == Setter::TrustedIssuer || setter == Setter::Admin,
        SetRule::UserSelf | SetRule::IdpOnRequest => {
            matches!(setter, Setter::User | Setter::Admin)
        }
    };
    if !authorized {
        return Err(RejectionReason::SetterNotAuthorized);
    }

    // Empty claims are not useful to consumers and are indistinguishable from
    // an absent value in required-claim flows. Disallow them for every lane,
    // including `opaque`, before any type-specific validation.
    if value.is_empty() {
        return Err(RejectionReason::ValueTypeMismatch);
    }

    // 2. Size bound, before any parsing work.
    if value.len() as u64 > policy.max_bytes {
        return Err(RejectionReason::ValueTooLarge {
            limit: policy.max_bytes,
        });
    }

    // 3. Validate the value where the type is validatable. Opaque is a no-op.
    policy
        .value_type
        .validate(value)
        .map_err(|_| RejectionReason::ValueTypeMismatch)?;

    // 4. A user-initiated set of an approval-gated type goes to the queue,
    //    whatever its signing lane. Admins bypass the queue.
    if policy.requires_approval && setter == Setter::User {
        return Ok(SetAction::Queue);
    }

    // 5. Map the signing lane to an action.
    let action = match policy.signing_rule {
        SigningRule::SelfSigned => SetAction::SelfSign,
        SigningRule::Verified => {
            if setter == Setter::Admin {
                // An admin may attest a verified-lane value directly.
                SetAction::SelfSign
            } else {
                SetAction::Verify
            }
        }
        SigningRule::Attested => {
            if setter == Setter::Admin {
                SetAction::SelfSign
            } else {
                SetAction::AcceptAttested
            }
        }
        SigningRule::Unsigned => SetAction::StoreUnsigned,
    };
    Ok(action)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(value_type: ValueType, set_rule: SetRule, signing_rule: SigningRule) -> ClaimPolicy {
        ClaimPolicy {
            claim_type: "t".to_string(),
            value_type,
            max_bytes: 33792,
            set_rule,
            signing_rule,
            requires_approval: false,
            user_settable: true,
        }
    }

    #[test]
    fn value_type_roundtrips() {
        for vt in [
            ValueType::Text,
            ValueType::Url,
            ValueType::Email,
            ValueType::Bool,
            ValueType::Int,
            ValueType::Float,
            ValueType::Decimal,
            ValueType::Date,
            ValueType::Timestamp,
            ValueType::Opaque,
        ] {
            assert_eq!(ValueType::parse(vt.as_str()), Some(vt));
        }
        assert_eq!(ValueType::parse("nonsense"), None);
    }

    #[test]
    fn validates_primitives() {
        assert!(ValueType::Text.validate(b"hi").is_ok());
        assert!(ValueType::Text.validate(b"").is_err());
        assert!(ValueType::Bool.validate(b"true").is_ok());
        assert!(ValueType::Bool.validate(b"True").is_err());
        assert!(ValueType::Int.validate(b"42").is_ok());
        assert!(ValueType::Int.validate(b"4.2").is_err());
        assert!(ValueType::Decimal.validate(b"-3.14").is_ok());
        assert!(ValueType::Decimal.validate(b"3.1.4").is_err());
        assert!(ValueType::Date.validate(b"2026-06-17").is_ok());
        assert!(ValueType::Date.validate(b"2026-13-40").is_err());
        assert!(ValueType::Timestamp
            .validate(b"2026-06-17T00:00:00Z")
            .is_ok());
        assert!(ValueType::Timestamp.validate(b"yesterday").is_err());
    }

    #[test]
    fn evaluate_set_rejects_empty_for_every_lane() {
        let p = policy(ValueType::Opaque, SetRule::UserSelf, SigningRule::Unsigned);
        assert_eq!(
            evaluate_set(&p, Setter::User, b""),
            Err(RejectionReason::ValueTypeMismatch)
        );
    }

    #[test]
    fn validates_urls_and_emails() {
        assert!(ValueType::Url.validate(b"https://example.com").is_ok());
        assert!(ValueType::Url
            .validate(b"https://example.com/path?q=1")
            .is_ok());
        assert!(ValueType::Url.validate(b"ftp://example.com").is_err());
        assert!(ValueType::Url.validate(b"https://nodot").is_err());
        // No embedded whitespace / control chars (CRLF-injection guard).
        assert!(ValueType::Url
            .validate(b"https://example.com\n/evil")
            .is_err());
        assert!(ValueType::Url.validate(b"https://exa mple.com").is_err());
        assert!(ValueType::Email.validate(b"a@b.com").is_ok());
        assert!(ValueType::Email.validate(b"a@b@c.com").is_err());
        assert!(ValueType::Email.validate(b"a@nodot").is_err());
        assert!(ValueType::Email.validate(b"@b.com").is_err());
        // Control characters (e.g. NUL) are rejected, like the URL guard.
        assert!(ValueType::Email.validate(b"a@b\0.com").is_err());
        // Non-finite floats must not be signable.
        assert!(ValueType::Float.validate(b"3.14").is_ok());
        assert!(ValueType::Float.validate(b"nan").is_err());
        assert!(ValueType::Float.validate(b"inf").is_err());
    }

    #[test]
    fn opaque_accepts_anything() {
        assert!(ValueType::Opaque.validate(&[0xff, 0x00, 0x99]).is_ok());
    }

    #[test]
    fn lane_a_self_signs_for_user() {
        let p = policy(ValueType::Text, SetRule::UserSelf, SigningRule::SelfSigned);
        assert_eq!(
            evaluate_set(&p, Setter::User, b"Ada"),
            Ok(SetAction::SelfSign)
        );
    }

    #[test]
    fn lane_b_user_verifies_admin_signs() {
        let p = policy(ValueType::Email, SetRule::UserSelf, SigningRule::Verified);
        assert_eq!(
            evaluate_set(&p, Setter::User, b"a@b.com"),
            Ok(SetAction::Verify)
        );
        assert_eq!(
            evaluate_set(&p, Setter::Admin, b"a@b.com"),
            Ok(SetAction::SelfSign)
        );
    }

    #[test]
    fn lane_c_user_rejected_issuer_accepted() {
        let p = policy(
            ValueType::Bool,
            SetRule::TrustedIssuerOnly,
            SigningRule::Attested,
        );
        assert_eq!(
            evaluate_set(&p, Setter::User, b"true"),
            Err(RejectionReason::SetterNotAuthorized)
        );
        assert_eq!(
            evaluate_set(&p, Setter::TrustedIssuer, b"true"),
            Ok(SetAction::AcceptAttested)
        );
    }

    #[test]
    fn deny_blocks_everyone() {
        let p = policy(ValueType::Text, SetRule::Deny, SigningRule::SelfSigned);
        assert_eq!(
            evaluate_set(&p, Setter::Admin, b"x"),
            Err(RejectionReason::SetterNotAuthorized)
        );
    }

    #[test]
    fn admin_only_rejects_user() {
        let p = policy(ValueType::Text, SetRule::AdminOnly, SigningRule::SelfSigned);
        assert_eq!(
            evaluate_set(&p, Setter::User, b"x"),
            Err(RejectionReason::SetterNotAuthorized)
        );
        assert_eq!(
            evaluate_set(&p, Setter::Admin, b"x"),
            Ok(SetAction::SelfSign)
        );
    }

    #[test]
    fn approval_queue_for_user_only() {
        let mut p = policy(
            ValueType::Text,
            SetRule::IdpOnRequest,
            SigningRule::SelfSigned,
        );
        p.requires_approval = true;
        assert_eq!(evaluate_set(&p, Setter::User, b"x"), Ok(SetAction::Queue));
        // Admin bypasses the queue.
        assert_eq!(
            evaluate_set(&p, Setter::Admin, b"x"),
            Ok(SetAction::SelfSign)
        );
    }

    #[test]
    fn rejects_oversize_and_mismatch() {
        let mut p = policy(ValueType::Text, SetRule::UserSelf, SigningRule::SelfSigned);
        p.max_bytes = 4;
        assert_eq!(
            evaluate_set(&p, Setter::User, b"toolong"),
            Err(RejectionReason::ValueTooLarge { limit: 4 })
        );
        let p = policy(ValueType::Int, SetRule::UserSelf, SigningRule::SelfSigned);
        assert_eq!(
            evaluate_set(&p, Setter::User, b"notanint"),
            Err(RejectionReason::ValueTypeMismatch)
        );
    }
}
