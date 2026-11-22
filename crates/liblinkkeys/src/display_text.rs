//! Cleaning of human-readable names that another party chose, such as an
//! account display name that a consent screen shows.
//!
//! A display name is not a trust boundary. The protocol never decides
//! anything from it. These functions only stop a name from changing how the
//! text around it looks: control characters, line and paragraph separators,
//! and Unicode bidirectional controls (which can reverse the text that
//! follows them) are removed.

/// The default maximum length of a display name, in Unicode scalar values.
pub const DEFAULT_MAX_DISPLAY_NAME_CHARS: usize = 256;

/// True for a character that a display name must not contain.
pub fn is_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            // Line and paragraph separators.
            '\u{2028}' | '\u{2029}'
            // Arabic letter mark, LRM, RLM.
            | '\u{061C}' | '\u{200E}' | '\u{200F}'
            // LRE, RLE, PDF, LRO, RLO.
            | '\u{202A}'..='\u{202E}'
            // LRI, RLI, FSI, PDI.
            | '\u{2066}'..='\u{2069}'
        )
}

/// Remove unsafe characters (see [`is_unsafe_char`]) and leading and
/// trailing white space.
pub fn strip_unsafe(name: &str) -> String {
    let cleaned: String = name.chars().filter(|c| !is_unsafe_char(*c)).collect();
    cleaned.trim().to_string()
}

/// The length of `name` in Unicode scalar values, the unit that the display
/// name limit uses.
pub fn char_len(name: &str) -> usize {
    name.chars().count()
}

/// A name that is safe to show: [`strip_unsafe`], then shortened to at most
/// `max_chars` characters. A shortened name ends in `…`, which is counted.
pub fn for_display(name: &str, max_chars: usize) -> String {
    let cleaned = strip_unsafe(name);
    if char_len(&cleaned) <= max_chars {
        return cleaned;
    }
    if max_chars == 0 {
        return String::new();
    }
    let mut shortened: String = cleaned.chars().take(max_chars - 1).collect();
    shortened.truncate(shortened.trim_end().len());
    shortened.push('…');
    shortened
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_controls_separators_and_bidi() {
        assert_eq!(strip_unsafe("  Home\u{0007}Grafana\n "), "HomeGrafana");
        assert_eq!(strip_unsafe("abc\u{202E}lmth.exe"), "abclmth.exe");
        assert_eq!(
            strip_unsafe("a\u{2066}b\u{2069}c\u{200F}d\u{2028}e"),
            "abcde"
        );
        assert_eq!(strip_unsafe("\u{061C}"), "");
    }

    #[test]
    fn keeps_ordinary_text() {
        let name = "Gráfana – 家 \u{1F600} (prod)";
        assert_eq!(strip_unsafe(name), name);
        assert_eq!(for_display(name, 256), name);
    }

    #[test]
    fn shortens_by_characters_not_bytes() {
        assert_eq!(for_display("ééééé", 5), "ééééé");
        assert_eq!(for_display("éééééé", 5), "éééé…");
        assert_eq!(char_len(&for_display(&"x".repeat(300), 256)), 256);
        assert_eq!(for_display("ab cd", 4), "ab…");
        assert_eq!(for_display("abc", 0), "");
    }
}
