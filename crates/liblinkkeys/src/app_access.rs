//! App access policies: which applications an account may sign in to.
//!
//! An admin writes a policy as an allow list or a deny list of application
//! domain patterns and assigns it to accounts. A pattern is a domain in which
//! `*` matches any run of characters, dots included: `*.ru` covers `shop.ru`
//! and `a.b.ru`, but not `ru`; `*` alone covers every domain.
//!
//! For one sign-in, the server collects the policies that apply to the account
//! and calls [`evaluate`]:
//!
//! - A deny policy with a matching pattern blocks the sign-in. Deny wins.
//! - When at least one allow policy applies, the domain must match a pattern in
//!   one of them.
//! - Otherwise the sign-in may continue.
//!
//! An application without a domain (a local app, known only by its key
//! fingerprint) matches no pattern. A deny list never blocks it; an allow list
//! always does.
//!
//! Policies can apply to accounts by claim value ([`ClaimOperator`]). The
//! condition logic lives here so that every carrier evaluates it the same way.
//! This module is pure: no I/O, and the caller supplies today's date.

use chrono::{Datelike, NaiveDate};
use std::fmt;

/// The longest pattern accepted. It is the longest DNS name.
pub const MAX_PATTERN_LEN: usize = 253;

/// The longest admin message accepted, in bytes.
pub const MAX_MESSAGE_LEN: usize = 1000;

/// The highest age a claim condition can name.
pub const MAX_AGE_YEARS: u32 = 150;

/// Whether a policy lists the permitted domains or the blocked domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    Allow,
    Deny,
}

impl AccessMode {
    pub fn parse(s: &str) -> Option<AccessMode> {
        match s {
            "allow" => Some(AccessMode::Allow),
            "deny" => Some(AccessMode::Deny),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            AccessMode::Allow => "allow",
            AccessMode::Deny => "deny",
        }
    }
}

/// Why a domain pattern was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternError {
    Empty,
    TooLong,
    BadCharacter(char),
    EmptyLabel,
}

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PatternError::Empty => write!(f, "the pattern is empty"),
            PatternError::TooLong => {
                write!(f, "the pattern is longer than {MAX_PATTERN_LEN} characters")
            }
            PatternError::BadCharacter(c) => write!(
                f,
                "the pattern contains {c:?}; use letters, digits, '-', '.', and '*'"
            ),
            PatternError::EmptyLabel => write!(f, "the pattern has an empty domain label"),
        }
    }
}

/// Canonical form of a domain for matching: trimmed, lowercase, no trailing dot.
pub fn normalize_domain(raw: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    lower.strip_suffix('.').unwrap_or(&lower).to_string()
}

/// Validate a pattern and return its canonical form. Runs of `*` collapse to
/// one, since they match the same domains.
pub fn normalize_pattern(raw: &str) -> Result<String, PatternError> {
    let pattern = normalize_domain(raw);
    if pattern.is_empty() {
        return Err(PatternError::Empty);
    }
    if pattern.len() > MAX_PATTERN_LEN {
        return Err(PatternError::TooLong);
    }
    if let Some(c) = pattern
        .chars()
        .find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '.' | '*')))
    {
        return Err(PatternError::BadCharacter(c));
    }
    if pattern.split('.').any(str::is_empty) {
        return Err(PatternError::EmptyLabel);
    }
    let mut collapsed = String::with_capacity(pattern.len());
    for c in pattern.chars() {
        if !(c == '*' && collapsed.ends_with('*')) {
            collapsed.push(c);
        }
    }
    Ok(collapsed)
}

/// Whether a canonical `pattern` matches a canonical `domain`. `*` matches any
/// run of characters, including none and including dots.
pub fn pattern_matches(pattern: &str, domain: &str) -> bool {
    let (p, d) = (pattern.as_bytes(), domain.as_bytes());
    let (mut pi, mut di) = (0, 0);
    // The last `*` seen, and the domain position it is currently matched up to.
    let mut star: Option<(usize, usize)> = None;
    while di < d.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, di));
            pi += 1;
        } else if pi < p.len() && p[pi] == d[di] {
            pi += 1;
            di += 1;
        } else if let Some((star_pi, star_di)) = star {
            pi = star_pi + 1;
            di = star_di + 1;
            star = Some((star_pi, di));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&b| b == b'*')
}

/// One policy that applies to the account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessPolicy {
    pub name: String,
    pub mode: AccessMode,
    /// Canonical patterns (see [`normalize_pattern`]).
    pub patterns: Vec<String>,
    /// Optional extra text the admin wants a blocked user to see.
    pub message: Option<String>,
}

impl AccessPolicy {
    fn matches(&self, domain: Option<&str>) -> bool {
        domain.is_some_and(|domain| self.patterns.iter().any(|p| pattern_matches(p, domain)))
    }
}

/// The result of [`evaluate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessDecision {
    Allowed,
    /// `policies` names the policies that caused the block, for admins and
    /// logs. `messages` holds their admin messages for the user, without
    /// duplicates, in policy order.
    Denied {
        policies: Vec<String>,
        messages: Vec<String>,
    },
}

/// Decide whether an account covered by `policies` may sign in to `domain`.
/// `domain` is canonical (see [`normalize_domain`]); `None` is an application
/// without a domain.
pub fn evaluate(policies: &[AccessPolicy], domain: Option<&str>) -> AccessDecision {
    let denying: Vec<&AccessPolicy> = policies
        .iter()
        .filter(|p| p.mode == AccessMode::Deny && p.matches(domain))
        .collect();
    if !denying.is_empty() {
        return denied(&denying);
    }
    let allowing: Vec<&AccessPolicy> = policies
        .iter()
        .filter(|p| p.mode == AccessMode::Allow)
        .collect();
    if allowing.is_empty() || allowing.iter().any(|p| p.matches(domain)) {
        AccessDecision::Allowed
    } else {
        denied(&allowing)
    }
}

fn denied(policies: &[&AccessPolicy]) -> AccessDecision {
    let mut messages: Vec<String> = Vec::new();
    for message in policies.iter().filter_map(|p| p.message.as_deref()) {
        let message = message.trim();
        if !message.is_empty() && !messages.iter().any(|m| m == message) {
            messages.push(message.to_string());
        }
    }
    AccessDecision::Denied {
        policies: policies.iter().map(|p| p.name.clone()).collect(),
        messages,
    }
}

/// How a claim condition tests an account's values of one claim type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimOperator {
    /// The account has an active value of the claim type.
    Present,
    /// The account has no active value of the claim type.
    Absent,
    /// A value equals the condition value, ignoring ASCII case.
    Equals,
    /// A `YYYY-MM-DD` value is a birth date less than N years ago.
    AgeUnder,
    /// A `YYYY-MM-DD` value is a birth date at least N years ago.
    AgeAtLeast,
}

impl ClaimOperator {
    pub fn parse(s: &str) -> Option<ClaimOperator> {
        match s {
            "present" => Some(ClaimOperator::Present),
            "absent" => Some(ClaimOperator::Absent),
            "equals" => Some(ClaimOperator::Equals),
            "age_under" => Some(ClaimOperator::AgeUnder),
            "age_at_least" => Some(ClaimOperator::AgeAtLeast),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ClaimOperator::Present => "present",
            ClaimOperator::Absent => "absent",
            ClaimOperator::Equals => "equals",
            ClaimOperator::AgeUnder => "age_under",
            ClaimOperator::AgeAtLeast => "age_at_least",
        }
    }

    /// Whether the operator compares against a condition value.
    pub fn takes_value(&self) -> bool {
        !matches!(self, ClaimOperator::Present | ClaimOperator::Absent)
    }
}

/// Why a claim condition was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionError {
    ValueRequired,
    ValueNotAllowed,
    BadAge,
}

impl fmt::Display for ConditionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConditionError::ValueRequired => write!(f, "this condition needs a value"),
            ConditionError::ValueNotAllowed => write!(f, "this condition takes no value"),
            ConditionError::BadAge => {
                write!(
                    f,
                    "the age must be a whole number from 1 to {MAX_AGE_YEARS}"
                )
            }
        }
    }
}

/// Check that a condition is complete. Returns the canonical value: trimmed,
/// or `None` for an operator that takes no value.
pub fn validate_condition(
    operator: ClaimOperator,
    value: Option<&str>,
) -> Result<Option<String>, ConditionError> {
    let value = value.map(str::trim).filter(|v| !v.is_empty());
    match (operator.takes_value(), value) {
        (false, None) => Ok(None),
        (false, Some(_)) => Err(ConditionError::ValueNotAllowed),
        (true, None) => Err(ConditionError::ValueRequired),
        (true, Some(v)) => {
            if matches!(
                operator,
                ClaimOperator::AgeUnder | ClaimOperator::AgeAtLeast
            ) && parse_age(v).is_none()
            {
                return Err(ConditionError::BadAge);
            }
            Ok(Some(v.to_string()))
        }
    }
}

fn parse_age(value: &str) -> Option<u32> {
    value
        .parse::<u32>()
        .ok()
        .filter(|age| (1..=MAX_AGE_YEARS).contains(age))
}

/// Whole years from `birth` to `today`. Negative for a future date.
fn age_in_years(birth: NaiveDate, today: NaiveDate) -> i64 {
    let mut years = i64::from(today.year()) - i64::from(birth.year());
    if (today.month(), today.day()) < (birth.month(), birth.day()) {
        years -= 1;
    }
    years
}

/// Whether an account's active values of one claim type satisfy a condition.
/// `expected` is the canonical value from [`validate_condition`]. A value that
/// does not parse for the operator does not match.
pub fn condition_matches(
    operator: ClaimOperator,
    expected: Option<&str>,
    values: &[&[u8]],
    today: NaiveDate,
) -> bool {
    let texts = || values.iter().filter_map(|v| std::str::from_utf8(v).ok());
    match operator {
        ClaimOperator::Present => !values.is_empty(),
        ClaimOperator::Absent => values.is_empty(),
        ClaimOperator::Equals => {
            let Some(expected) = expected else {
                return false;
            };
            texts().any(|v| v.trim().eq_ignore_ascii_case(expected))
        }
        ClaimOperator::AgeUnder | ClaimOperator::AgeAtLeast => {
            let Some(limit) = expected.and_then(parse_age) else {
                return false;
            };
            texts()
                .filter_map(|v| NaiveDate::parse_from_str(v.trim(), "%Y-%m-%d").ok())
                .any(|birth| {
                    let age = age_in_years(birth, today);
                    if operator == ClaimOperator::AgeUnder {
                        age < i64::from(limit)
                    } else {
                        age >= i64::from(limit)
                    }
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(
        name: &str,
        mode: AccessMode,
        patterns: &[&str],
        message: Option<&str>,
    ) -> AccessPolicy {
        AccessPolicy {
            name: name.to_string(),
            mode,
            patterns: patterns
                .iter()
                .map(|p| normalize_pattern(p).unwrap())
                .collect(),
            message: message.map(str::to_string),
        }
    }

    fn date(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    #[test]
    fn test_pattern_normalization() {
        assert_eq!(
            normalize_pattern(" Shop.EXAMPLE.com. ").unwrap(),
            "shop.example.com"
        );
        assert_eq!(normalize_pattern("**.ru").unwrap(), "*.ru");
        assert_eq!(normalize_pattern("*").unwrap(), "*");
        assert_eq!(normalize_pattern(""), Err(PatternError::Empty));
        assert_eq!(normalize_pattern("a..b"), Err(PatternError::EmptyLabel));
        assert_eq!(normalize_pattern(".ru"), Err(PatternError::EmptyLabel));
        assert_eq!(
            normalize_pattern("a b.com"),
            Err(PatternError::BadCharacter(' '))
        );
        assert_eq!(
            normalize_pattern("x?.com"),
            Err(PatternError::BadCharacter('?'))
        );
        assert_eq!(
            normalize_pattern(&"a".repeat(254)),
            Err(PatternError::TooLong)
        );
    }

    #[test]
    fn test_pattern_matching() {
        assert!(pattern_matches("*.ru", "shop.ru"));
        assert!(pattern_matches("*.ru", "a.b.ru"));
        assert!(!pattern_matches("*.ru", "ru"));
        assert!(!pattern_matches("*.ru", "shop.ru.example.com"));
        assert!(!pattern_matches("*.ru", "guru"));
        assert!(pattern_matches("*", "anything.example"));
        assert!(pattern_matches("example.com", "example.com"));
        assert!(!pattern_matches("example.com", "www.example.com"));
        assert!(pattern_matches("app-*.example.com", "app-1.example.com"));
        assert!(!pattern_matches("app-*.example.com", "web-1.example.com"));
        assert!(pattern_matches("*shop*", "myshopsite.com"));
        assert!(pattern_matches("a*b*c", "aXbYbZc"));
        assert!(!pattern_matches("a*b*c", "aXbYbZ"));
    }

    #[test]
    fn test_no_policies_allows() {
        assert_eq!(evaluate(&[], Some("app.example")), AccessDecision::Allowed);
        assert_eq!(evaluate(&[], None), AccessDecision::Allowed);
    }

    #[test]
    fn test_allow_list_limits_domains() {
        let policies = [policy(
            "demo",
            AccessMode::Allow,
            &["demo.example", "*.demo.example"],
            Some("Demo account."),
        )];
        assert_eq!(
            evaluate(&policies, Some("demo.example")),
            AccessDecision::Allowed
        );
        assert_eq!(
            evaluate(&policies, Some("a.demo.example")),
            AccessDecision::Allowed
        );
        assert_eq!(
            evaluate(&policies, Some("other.example")),
            AccessDecision::Denied {
                policies: vec!["demo".to_string()],
                messages: vec!["Demo account.".to_string()],
            }
        );
    }

    #[test]
    fn test_allow_lists_combine() {
        let policies = [
            policy("a", AccessMode::Allow, &["a.example"], None),
            policy("b", AccessMode::Allow, &["b.example"], None),
        ];
        assert_eq!(
            evaluate(&policies, Some("b.example")),
            AccessDecision::Allowed
        );
        assert!(matches!(
            evaluate(&policies, Some("c.example")),
            AccessDecision::Denied { .. }
        ));
    }

    #[test]
    fn test_deny_wins_over_allow() {
        let policies = [
            policy("all", AccessMode::Allow, &["*"], Some("allow text")),
            policy(
                "no-ru",
                AccessMode::Deny,
                &["*.ru"],
                Some("Blocked region."),
            ),
        ];
        assert_eq!(
            evaluate(&policies, Some("shop.example")),
            AccessDecision::Allowed
        );
        assert_eq!(
            evaluate(&policies, Some("shop.ru")),
            AccessDecision::Denied {
                policies: vec!["no-ru".to_string()],
                messages: vec!["Blocked region.".to_string()],
            }
        );
    }

    #[test]
    fn test_domainless_app() {
        let deny = [policy("no-ru", AccessMode::Deny, &["*.ru"], None)];
        assert_eq!(evaluate(&deny, None), AccessDecision::Allowed);
        let allow = [policy("all", AccessMode::Allow, &["*"], None)];
        assert!(matches!(
            evaluate(&allow, None),
            AccessDecision::Denied { .. }
        ));
    }

    #[test]
    fn test_messages_dedupe_and_skip_blank() {
        let policies = [
            policy("a", AccessMode::Deny, &["*.ru"], Some("Same")),
            policy("b", AccessMode::Deny, &["shop.ru"], Some(" Same ")),
            policy("c", AccessMode::Deny, &["*"], Some("  ")),
            policy("d", AccessMode::Deny, &["*"], None),
        ];
        assert_eq!(
            evaluate(&policies, Some("shop.ru")),
            AccessDecision::Denied {
                policies: vec!["a".into(), "b".into(), "c".into(), "d".into()],
                messages: vec!["Same".to_string()],
            }
        );
    }

    #[test]
    fn test_condition_validation() {
        assert_eq!(validate_condition(ClaimOperator::Present, None), Ok(None));
        assert_eq!(
            validate_condition(ClaimOperator::Absent, Some("  ")),
            Ok(None)
        );
        assert_eq!(
            validate_condition(ClaimOperator::Present, Some("x")),
            Err(ConditionError::ValueNotAllowed)
        );
        assert_eq!(
            validate_condition(ClaimOperator::Equals, None),
            Err(ConditionError::ValueRequired)
        );
        assert_eq!(
            validate_condition(ClaimOperator::Equals, Some(" staff ")),
            Ok(Some("staff".to_string()))
        );
        assert_eq!(
            validate_condition(ClaimOperator::AgeUnder, Some("16")),
            Ok(Some("16".to_string()))
        );
        assert_eq!(
            validate_condition(ClaimOperator::AgeUnder, Some("0")),
            Err(ConditionError::BadAge)
        );
        assert_eq!(
            validate_condition(ClaimOperator::AgeAtLeast, Some("sixteen")),
            Err(ConditionError::BadAge)
        );
        assert_eq!(
            validate_condition(ClaimOperator::AgeAtLeast, Some("151")),
            Err(ConditionError::BadAge)
        );
    }

    #[test]
    fn test_presence_conditions() {
        let today = date("2026-10-19");
        assert!(condition_matches(
            ClaimOperator::Present,
            None,
            &[b"x"],
            today
        ));
        assert!(!condition_matches(ClaimOperator::Present, None, &[], today));
        assert!(condition_matches(ClaimOperator::Absent, None, &[], today));
        assert!(!condition_matches(
            ClaimOperator::Absent,
            None,
            &[b"x"],
            today
        ));
    }

    #[test]
    fn test_equals_condition() {
        let today = date("2026-10-19");
        assert!(condition_matches(
            ClaimOperator::Equals,
            Some("staff"),
            &[b"Staff"],
            today
        ));
        assert!(condition_matches(
            ClaimOperator::Equals,
            Some("staff"),
            &[b"guest", b"staff"],
            today
        ));
        assert!(!condition_matches(
            ClaimOperator::Equals,
            Some("staff"),
            &[b"staffer"],
            today
        ));
        assert!(!condition_matches(
            ClaimOperator::Equals,
            Some("staff"),
            &[],
            today
        ));
    }

    #[test]
    fn test_age_conditions_on_birthday_boundary() {
        let today = date("2026-10-19");
        // Turns 16 today.
        assert!(!condition_matches(
            ClaimOperator::AgeUnder,
            Some("16"),
            &[b"2010-10-19"],
            today
        ));
        assert!(condition_matches(
            ClaimOperator::AgeAtLeast,
            Some("16"),
            &[b"2010-10-19"],
            today
        ));
        // Turns 16 tomorrow.
        assert!(condition_matches(
            ClaimOperator::AgeUnder,
            Some("16"),
            &[b"2010-10-20"],
            today
        ));
        assert!(!condition_matches(
            ClaimOperator::AgeAtLeast,
            Some("16"),
            &[b"2010-10-20"],
            today
        ));
        // A future date counts as age under any limit.
        assert!(condition_matches(
            ClaimOperator::AgeUnder,
            Some("16"),
            &[b"2030-01-01"],
            today
        ));
        // Leap-day birth date, in a year without one.
        assert!(condition_matches(
            ClaimOperator::AgeUnder,
            Some("16"),
            &[b"2008-02-29"],
            date("2024-02-28")
        ));
        assert!(condition_matches(
            ClaimOperator::AgeAtLeast,
            Some("16"),
            &[b"2008-02-29"],
            date("2024-02-29")
        ));
    }

    #[test]
    fn test_age_condition_ignores_unparseable_values() {
        let today = date("2026-10-19");
        assert!(!condition_matches(
            ClaimOperator::AgeUnder,
            Some("16"),
            &[b"not a date"],
            today
        ));
        assert!(!condition_matches(
            ClaimOperator::AgeUnder,
            Some("16"),
            &[&[0xff, 0xfe]],
            today
        ));
        assert!(!condition_matches(
            ClaimOperator::AgeUnder,
            Some("bad"),
            &[b"2020-01-01"],
            today
        ));
        assert!(!condition_matches(
            ClaimOperator::AgeUnder,
            None,
            &[b"2020-01-01"],
            today
        ));
    }
}
