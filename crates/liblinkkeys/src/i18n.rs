//! Pure-data i18n catalog shared by every client (WASM, native, server-rendered
//! HTML). No I/O: locale catalogs are JSON files embedded at compile time via
//! `include_str!`, so this stays viable as a WASM target (see AGENTS.md).
//!
//! Real translations are a community effort; this crate ships the complete
//! `en-US` catalog plus a partial, intentionally-mangled pseudo-locale
//! (`en-XA`) that demonstrates the fallback pipeline end-to-end: any locale
//! missing a key falls back to `en-US`, and any key missing everywhere falls
//! back to the key itself.

use std::collections::{BTreeMap, HashMap};
use std::sync::LazyLock;

/// The complete, canonical catalog. Every other locale falls back to this for
/// any key it doesn't define.
pub const EN_US: &str = "en-US";

const EN_US_JSON: &str = include_str!("../i18n/en-US.json");
const EN_XA_JSON: &str = include_str!("../i18n/en-XA.json");

struct Locale {
    code: &'static str,
    messages: HashMap<String, String>,
}

fn parse_catalog(json: &str) -> HashMap<String, String> {
    serde_json::from_str(json).expect("built-in i18n catalog must be valid flat JSON")
}

static LOCALES: LazyLock<Vec<Locale>> = LazyLock::new(|| {
    vec![
        Locale {
            code: EN_US,
            messages: parse_catalog(EN_US_JSON),
        },
        Locale {
            code: "en-XA",
            messages: parse_catalog(EN_XA_JSON),
        },
    ]
});

/// The primary subtag of a BCP-47-ish locale code (`"pt-BR"` -> `"pt"`).
fn primary_subtag(locale: &str) -> &str {
    locale.split(['-', '_']).next().unwrap_or(locale)
}

fn find_locale(code: &str) -> Option<&'static Locale> {
    LOCALES.iter().find(|l| l.code.eq_ignore_ascii_case(code))
}

/// All locales this build ships a catalog for, in a stable order (`en-US` first).
pub fn available_locales() -> Vec<String> {
    LOCALES.iter().map(|l| l.code.to_string()).collect()
}

/// Exact-locale lookup: `locale` must match a shipped catalog's code exactly
/// (case-insensitively) and that catalog must define `key`. No fallback.
pub fn translate(locale: &str, key: &str) -> Option<&'static str> {
    find_locale(locale)
        .and_then(|l| l.messages.get(key))
        .map(|s| s.as_str())
}

/// Look up `key` for `locale`, falling back per-key: exact locale -> language-only
/// (e.g. `pt-BR` -> `pt`) -> `en-US` -> the key itself. Missing translations
/// always fall back to `en-US`, never to an empty string.
pub fn t<'a>(locale: &str, key: &'a str) -> &'a str {
    if let Some(v) = translate(locale, key) {
        return v;
    }
    let lang = primary_subtag(locale);
    if lang != locale {
        if let Some(v) = translate(lang, key) {
            return v;
        }
    }
    if !locale.eq_ignore_ascii_case(EN_US) {
        if let Some(v) = translate(EN_US, key) {
            return v;
        }
    }
    key
}

/// Substitute `{name}` placeholders in a translated string. Unknown
/// placeholders are left as-is (better a visible `{typo}` than silently
/// dropped text).
pub fn t_with(locale: &str, key: &str, vars: &[(&str, &str)]) -> String {
    let mut out = t(locale, key).to_string();
    for (name, value) in vars {
        out = out.replace(&format!("{{{name}}}"), value);
    }
    out
}

/// The full `en-US` catalog overlaid with whatever `locale` (or its
/// language-only form) defines, so a client fetching a partial locale gets a
/// complete, fallback-filled catalog in one call.
pub fn catalog_for(locale: &str) -> BTreeMap<String, String> {
    let mut map: BTreeMap<String, String> = find_locale(EN_US)
        .map(|l| {
            l.messages
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
        .unwrap_or_default();

    let overlay = find_locale(locale).or_else(|| find_locale(primary_subtag(locale)));
    if let Some(loc) = overlay {
        for (k, v) in &loc.messages {
            map.insert(k.clone(), v.clone());
        }
    }
    map
}

/// Parse an `Accept-Language` header value into locale tags ordered by
/// descending quality (`q`). Tags without a `q` default to `1.0`; malformed
/// segments are skipped. No dependency on a full RFC 4647 implementation —
/// this only needs to rank the small set of tags a browser sends.
fn parse_accept_language(header: &str) -> Vec<String> {
    let mut items: Vec<(String, f32)> = header
        .split(',')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }
            let mut pieces = part.split(';');
            let tag = pieces.next()?.trim();
            if tag.is_empty() || tag == "*" {
                return None;
            }
            let mut q = 1.0f32;
            for p in pieces {
                let p = p.trim();
                if let Some(v) = p.strip_prefix("q=") {
                    q = v.trim().parse().unwrap_or(1.0);
                }
            }
            Some((tag.to_string(), q))
        })
        .collect();
    // Stable sort so equal-quality tags keep the header's original order.
    items.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    items.into_iter().map(|(tag, _)| tag).collect()
}

/// The best available locale a shipped catalog matches, exact then
/// language-only.
fn best_match(requested: &str) -> Option<String> {
    if let Some(l) = find_locale(requested) {
        return Some(l.code.to_string());
    }
    let lang = primary_subtag(requested);
    LOCALES
        .iter()
        .find(|l| primary_subtag(l.code).eq_ignore_ascii_case(lang))
        .map(|l| l.code.to_string())
}

/// Pick the best available locale: an explicit override wins outright,
/// otherwise the highest-quality entry in `accept_language` that this build
/// ships a catalog for, defaulting to `en-US`.
pub fn negotiate(accept_language: &str, override_locale: Option<&str>) -> String {
    if let Some(o) = override_locale {
        if let Some(m) = best_match(o) {
            return m;
        }
    }
    for candidate in parse_accept_language(accept_language) {
        if let Some(m) = best_match(&candidate) {
            return m;
        }
    }
    EN_US.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_exact_hit() {
        assert_eq!(t(EN_US, "consent.cancel"), "Cancel");
    }

    #[test]
    fn t_falls_back_to_en_us_on_missing_key() {
        // en-XA doesn't define this key.
        assert_eq!(t("en-XA", "account.title"), "Account Dashboard");
    }

    #[test]
    fn t_falls_back_through_language_only_tag() {
        // "en-GB" isn't a shipped code, but its language-only form ("en") matches
        // a shipped "en-*" catalog (en-US, the first one registered), so it
        // resolves before falling all the way through to the final en-US tier.
        assert_eq!(best_match("en-GB").as_deref(), Some(EN_US));
        assert_eq!(t("en-GB", "consent.cancel"), "Cancel");
    }

    #[test]
    fn t_returns_key_itself_as_last_resort() {
        assert_eq!(t("fr-FR", "no.such.key"), "no.such.key");
    }

    #[test]
    fn t_with_substitutes_placeholders() {
        let out = t_with(EN_US, "consent.confirmed_by", &[("who", "todandlorna.com")]);
        assert_eq!(out, "Confirmed by todandlorna.com");
    }

    #[test]
    fn catalog_for_en_us_is_the_full_catalog() {
        let cat = catalog_for(EN_US);
        assert_eq!(
            cat.get("consent.cancel").map(String::as_str),
            Some("Cancel")
        );
        assert!(cat.len() >= 40);
    }

    #[test]
    fn catalog_for_partial_locale_is_fallback_filled() {
        let cat = catalog_for("en-XA");
        // en-XA overrides this key...
        assert_eq!(
            cat.get("consent.cancel").map(String::as_str),
            translate("en-XA", "consent.cancel")
        );
        // ...but doesn't define this one, so the full catalog still has it via
        // the en-US overlay base.
        assert_eq!(
            cat.get("account.title").map(String::as_str),
            Some("Account Dashboard")
        );
        // Every en-US key is present (fallback-filled), never missing.
        let en_us = catalog_for(EN_US);
        for key in en_us.keys() {
            assert!(
                cat.contains_key(key),
                "missing key {key} in catalog_for(en-XA)"
            );
        }
    }

    #[test]
    fn negotiate_prefers_override() {
        assert_eq!(negotiate("fr-FR", Some("en-XA")), "en-XA");
    }

    #[test]
    fn negotiate_picks_highest_quality_supported_tag() {
        assert_eq!(negotiate("fr-FR;q=0.9, en-XA;q=0.8", None), "en-XA");
    }

    #[test]
    fn negotiate_falls_back_to_en_us_when_nothing_matches() {
        assert_eq!(negotiate("fr-FR, de-DE", None), EN_US);
    }

    #[test]
    fn negotiate_matches_language_only() {
        // No shipped catalog is literally "en", but "en-US" matches by language.
        assert_eq!(negotiate("en;q=0.9", None), EN_US);
    }

    #[test]
    fn available_locales_lists_both_shipped_catalogs() {
        let locales = available_locales();
        assert!(locales.contains(&EN_US.to_string()));
        assert!(locales.contains(&"en-XA".to_string()));
    }
}
