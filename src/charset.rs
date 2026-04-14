use std::collections::HashSet;

use crate::error::AppError;

// ---------------------------------------------------------------------------
// Character set constants
// ---------------------------------------------------------------------------

/// Lowercase ASCII letters (26 characters).
pub const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";

/// Uppercase ASCII letters (26 characters).
pub const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// ASCII digits (10 characters).
pub const DIGITS: &str = "0123456789";

/// Printable ASCII symbols — all 32 non-alphanumeric printable ASCII characters.
///
/// A raw string literal (`r##"..."##`) is used so that `\`, `"`, and `` ` ``
/// do not require backslash escaping.
pub const SYMBOLS: &str = r##"!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"##;

/// Characters that look alike in common fonts.
///
/// Excluded from the character pool when `--exclude-ambiguous` is active.
/// Each character appears in at most one of the standard categories:
/// - `'0'`, `'1'` → DIGITS
/// - `'O'`, `'I'` → UPPERCASE
/// - `'l'`        → LOWERCASE
/// - `'|'`        → SYMBOLS
pub const AMBIGUOUS: &[char] = &['0', 'O', '1', 'l', 'I', '|'];

// ---------------------------------------------------------------------------
// Charset
// ---------------------------------------------------------------------------

/// The resolved character pools used during password generation.
///
/// `chars` is the combined pool drawn from during the random-fill phase.
/// The per-category vectors are used to satisfy `--min-*` constraints.
/// They are empty when `--charset` (custom mode) is in use.
#[derive(Debug, Clone)]
pub struct Charset {
    /// Full combined pool (all enabled characters).
    pub chars: Vec<char>,
    /// Lowercase subset.
    pub lowercase: Vec<char>,
    /// Uppercase subset.
    pub uppercase: Vec<char>,
    /// Digit subset.
    pub digits: Vec<char>,
    /// Symbol subset.
    pub symbols: Vec<char>,
}

// ---------------------------------------------------------------------------
// CharsetBuilder
// ---------------------------------------------------------------------------

/// Builder that converts CLI flags into a validated [`Charset`].
///
/// All fields default to the most permissive settings (all categories enabled,
/// no ambiguous exclusion, no custom override), matching the tool's defaults.
#[derive(Debug)]
pub struct CharsetBuilder {
    pub include_lowercase: bool,
    pub include_uppercase: bool,
    pub include_digits: bool,
    pub include_symbols: bool,
    pub exclude_ambiguous: bool,
    /// When set, overrides all category include/exclude flags.
    pub custom: Option<String>,
}

impl Default for CharsetBuilder {
    fn default() -> Self {
        Self {
            include_lowercase: true,
            include_uppercase: true,
            include_digits: true,
            include_symbols: true,
            exclude_ambiguous: false,
            custom: None,
        }
    }
}

impl CharsetBuilder {
    /// Build the [`Charset`], validating that at least one character remains.
    ///
    /// # Errors
    ///
    /// - [`AppError::EmptyCustomCharset`] if `--charset` was given but is empty.
    /// - [`AppError::EmptyCharset`] if all standard categories are disabled.
    pub fn build(self) -> Result<Charset, AppError> {
        if let Some(custom) = self.custom {
            return build_from_custom(&custom);
        }
        build_from_categories(
            self.include_lowercase,
            self.include_uppercase,
            self.include_digits,
            self.include_symbols,
            self.exclude_ambiguous,
        )
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Build a `Charset` from a user-supplied custom string.
///
/// Characters are deduplicated while preserving first-occurrence order:
/// `"aaabbb"` → `['a', 'b']`. This uses `HashSet::insert`, which returns
/// `true` only when the value is newly inserted — a neat filter trick.
fn build_from_custom(custom: &str) -> Result<Charset, AppError> {
    let mut seen = HashSet::new();
    let chars: Vec<char> = custom.chars().filter(|c| seen.insert(*c)).collect();

    if chars.is_empty() {
        return Err(AppError::EmptyCustomCharset);
    }

    // Per-category pools are empty in custom mode; min-* constraints cannot
    // be satisfied because there is no category metadata.
    Ok(Charset {
        chars,
        lowercase: Vec::new(),
        uppercase: Vec::new(),
        digits: Vec::new(),
        symbols: Vec::new(),
    })
}

/// Build a `Charset` from the standard category flags.
fn build_from_categories(
    include_lowercase: bool,
    include_uppercase: bool,
    include_digits: bool,
    include_symbols: bool,
    exclude_ambiguous: bool,
) -> Result<Charset, AppError> {
    // A local closure that filters a source string into a Vec<char>,
    // optionally stripping ambiguous characters.
    let filter = |src: &str| -> Vec<char> {
        src.chars()
            .filter(|c| !exclude_ambiguous || !AMBIGUOUS.contains(c))
            .collect()
    };

    let lowercase = if include_lowercase {
        filter(LOWERCASE)
    } else {
        Vec::new()
    };
    let uppercase = if include_uppercase {
        filter(UPPERCASE)
    } else {
        Vec::new()
    };
    let digits = if include_digits {
        filter(DIGITS)
    } else {
        Vec::new()
    };
    let symbols = if include_symbols {
        filter(SYMBOLS)
    } else {
        Vec::new()
    };

    // Concatenate all enabled categories into a single pool.
    let chars: Vec<char> = lowercase
        .iter()
        .chain(&uppercase)
        .chain(&digits)
        .chain(&symbols)
        .copied()
        .collect();

    if chars.is_empty() {
        return Err(AppError::EmptyCharset);
    }

    Ok(Charset {
        chars,
        lowercase,
        uppercase,
        digits,
        symbols,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn full_charset() -> Charset {
        CharsetBuilder::default().build().unwrap()
    }

    #[test]
    fn default_charset_has_94_chars() {
        // 26 lowercase + 26 uppercase + 10 digits + 32 symbols = 94
        let cs = full_charset();
        assert_eq!(cs.chars.len(), 94);
    }

    #[test]
    fn symbols_constant_has_32_chars() {
        assert_eq!(SYMBOLS.chars().count(), 32);
    }

    #[test]
    fn charset_categories_sum_to_total() {
        let cs = full_charset();
        let sum = cs.lowercase.len() + cs.uppercase.len() + cs.digits.len() + cs.symbols.len();
        assert_eq!(sum, cs.chars.len());
    }

    #[test]
    fn exclude_ambiguous_removes_all_ambiguous_chars() {
        let cs = CharsetBuilder {
            exclude_ambiguous: true,
            ..Default::default()
        }
        .build()
        .unwrap();

        for &ch in AMBIGUOUS {
            assert!(
                !cs.chars.contains(&ch),
                "ambiguous char '{ch}' should be excluded"
            );
        }
    }

    #[test]
    fn exclude_ambiguous_reduces_size_by_six() {
        // AMBIGUOUS has exactly 6 entries, each in a different category.
        let cs = CharsetBuilder {
            exclude_ambiguous: true,
            ..Default::default()
        }
        .build()
        .unwrap();
        assert_eq!(cs.chars.len(), 94 - AMBIGUOUS.len());
    }

    #[test]
    fn all_categories_disabled_returns_empty_charset_error() {
        let result = CharsetBuilder {
            include_lowercase: false,
            include_uppercase: false,
            include_digits: false,
            include_symbols: false,
            ..Default::default()
        }
        .build();
        assert!(
            matches!(result, Err(AppError::EmptyCharset)),
            "expected EmptyCharset error"
        );
    }

    #[test]
    fn custom_charset_is_deduplicated() {
        let cs = CharsetBuilder {
            custom: Some("aaabbbccc".into()),
            ..Default::default()
        }
        .build()
        .unwrap();
        assert_eq!(cs.chars, vec!['a', 'b', 'c']);
    }

    #[test]
    fn custom_charset_preserves_first_occurrence_order() {
        let cs = CharsetBuilder {
            custom: Some("zyx".into()),
            ..Default::default()
        }
        .build()
        .unwrap();
        assert_eq!(cs.chars, vec!['z', 'y', 'x']);
    }

    #[test]
    fn empty_custom_charset_returns_error() {
        let result = CharsetBuilder {
            custom: Some(String::new()),
            ..Default::default()
        }
        .build();
        assert!(
            matches!(result, Err(AppError::EmptyCustomCharset)),
            "expected EmptyCustomCharset error"
        );
    }

    #[test]
    fn no_digits_excludes_all_digits() {
        let cs = CharsetBuilder {
            include_digits: false,
            ..Default::default()
        }
        .build()
        .unwrap();
        assert!(cs.digits.is_empty());
        assert!(!cs.chars.iter().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn no_lowercase_excludes_all_lowercase() {
        let cs = CharsetBuilder {
            include_lowercase: false,
            ..Default::default()
        }
        .build()
        .unwrap();
        assert!(cs.lowercase.is_empty());
        assert!(!cs.chars.iter().any(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn custom_mode_has_empty_category_pools() {
        let cs = CharsetBuilder {
            custom: Some("abc".into()),
            ..Default::default()
        }
        .build()
        .unwrap();
        assert!(cs.lowercase.is_empty());
        assert!(cs.uppercase.is_empty());
        assert!(cs.digits.is_empty());
        assert!(cs.symbols.is_empty());
    }
}
