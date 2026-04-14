use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::Rng;

use crate::charset::Charset;
use crate::error::AppError;

/// Parameters controlling password generation.
pub struct GeneratorConfig<'a> {
    /// The resolved character pools.
    pub charset: &'a Charset,
    /// Total password length.
    pub length: usize,
    /// Minimum number of lowercase characters to include.
    pub min_lowercase: usize,
    /// Minimum number of uppercase characters to include.
    pub min_uppercase: usize,
    /// Minimum number of digit characters to include.
    pub min_digits: usize,
    /// Minimum number of symbol characters to include.
    pub min_symbols: usize,
}

/// Generate a single password according to `config`.
///
/// # Algorithm
///
/// 1. **Mandatory phase** — pick the required minimums from each per-category
///    pool using [`OsRng`] + [`Rng::gen_range`] (Lemire's algorithm, no modulo
///    bias).
/// 2. **Fill phase** — draw the remaining characters from the full combined
///    pool.
/// 3. **Shuffle** — apply Fisher-Yates via [`SliceRandom::shuffle`] so that
///    mandatory characters are not always bunched at the front.
///
/// # Errors
///
/// Returns [`AppError::EmptyCharset`] if the combined pool is unexpectedly
/// empty (this should have been caught during argument validation, but is
/// guarded here defensively).
pub fn generate(config: &GeneratorConfig<'_>) -> Result<String, AppError> {
    if config.charset.chars.is_empty() {
        return Err(AppError::EmptyCharset);
    }

    let mut rng = OsRng;
    let mut buf: Vec<char> = Vec::with_capacity(config.length);

    // Phase 1: satisfy --min-* constraints.
    pick_n(
        &config.charset.lowercase,
        config.min_lowercase,
        &mut buf,
        &mut rng,
    );
    pick_n(
        &config.charset.uppercase,
        config.min_uppercase,
        &mut buf,
        &mut rng,
    );
    pick_n(
        &config.charset.digits,
        config.min_digits,
        &mut buf,
        &mut rng,
    );
    pick_n(
        &config.charset.symbols,
        config.min_symbols,
        &mut buf,
        &mut rng,
    );

    // Phase 2: fill remaining positions from the combined pool.
    // `validate()` guarantees buf.len() <= config.length here.
    let remaining = config.length - buf.len();
    for _ in 0..remaining {
        let idx = rng.gen_range(0..config.charset.chars.len());
        buf.push(config.charset.chars[idx]);
    }

    // Phase 3: Fisher-Yates shuffle to distribute mandatory chars evenly.
    buf.shuffle(&mut rng);

    Ok(buf.into_iter().collect())
}

/// Generate `count` independent passwords, short-circuiting on the first error.
///
/// The `collect::<Result<Vec<_>, _>>()` idiom is idiomatic Rust for turning
/// an `Iterator<Item = Result<T, E>>` into a `Result<Vec<T>, E>`.
pub fn generate_many(config: &GeneratorConfig<'_>, count: usize) -> Result<Vec<String>, AppError> {
    (0..count).map(|_| generate(config)).collect()
}

/// Pick `n` random characters from `pool` and append them to `buf`.
///
/// `gen_range` (rand 0.8) uses Lemire's fast algorithm internally, which
/// avoids modulo bias without significant overhead.
///
/// The early return when `pool.is_empty()` is a safety guard: validation
/// ensures `n == 0` whenever a category is disabled, so this branch should
/// never be taken in normal operation.
fn pick_n(pool: &[char], n: usize, buf: &mut Vec<char>, rng: &mut OsRng) {
    if pool.is_empty() {
        return;
    }
    for _ in 0..n {
        let idx = rng.gen_range(0..pool.len());
        buf.push(pool[idx]);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::charset::CharsetBuilder;

    /// Create a minimal config with all minimums zeroed.
    fn make_config(cs: &Charset) -> GeneratorConfig<'_> {
        GeneratorConfig {
            charset: cs,
            length: 16,
            min_lowercase: 0,
            min_uppercase: 0,
            min_digits: 0,
            min_symbols: 0,
        }
    }

    #[test]
    fn generated_password_has_correct_length() {
        let cs = CharsetBuilder::default().build().unwrap();
        let config = GeneratorConfig {
            length: 20,
            ..make_config(&cs)
        };
        let pw = generate(&config).unwrap();
        // Use chars().count(), not len(), because len() counts bytes.
        assert_eq!(pw.chars().count(), 20);
    }

    #[test]
    fn generated_chars_are_subset_of_charset() {
        let cs = CharsetBuilder::default().build().unwrap();
        let config = make_config(&cs);
        for _ in 0..50 {
            let pw = generate(&config).unwrap();
            for ch in pw.chars() {
                assert!(
                    cs.chars.contains(&ch),
                    "unexpected char '{ch}' not in charset"
                );
            }
        }
    }

    #[test]
    fn min_lowercase_is_satisfied() {
        let cs = CharsetBuilder::default().build().unwrap();
        let config = GeneratorConfig {
            min_lowercase: 4,
            ..make_config(&cs)
        };
        for _ in 0..100 {
            let pw = generate(&config).unwrap();
            let count = pw.chars().filter(|c| c.is_ascii_lowercase()).count();
            assert!(count >= 4, "expected ≥4 lowercase, got {count}: {pw}");
        }
    }

    #[test]
    fn min_uppercase_is_satisfied() {
        let cs = CharsetBuilder::default().build().unwrap();
        let config = GeneratorConfig {
            min_uppercase: 3,
            ..make_config(&cs)
        };
        for _ in 0..100 {
            let pw = generate(&config).unwrap();
            let count = pw.chars().filter(|c| c.is_ascii_uppercase()).count();
            assert!(count >= 3, "expected ≥3 uppercase, got {count}: {pw}");
        }
    }

    #[test]
    fn min_digits_is_satisfied() {
        let cs = CharsetBuilder::default().build().unwrap();
        let config = GeneratorConfig {
            min_digits: 3,
            ..make_config(&cs)
        };
        for _ in 0..100 {
            let pw = generate(&config).unwrap();
            let count = pw.chars().filter(|c| c.is_ascii_digit()).count();
            assert!(count >= 3, "expected ≥3 digits, got {count}: {pw}");
        }
    }

    #[test]
    fn min_symbols_is_satisfied() {
        let cs = CharsetBuilder::default().build().unwrap();
        let config = GeneratorConfig {
            min_symbols: 2,
            ..make_config(&cs)
        };
        for _ in 0..100 {
            let pw = generate(&config).unwrap();
            let count = pw.chars().filter(|c| cs.symbols.contains(c)).count();
            assert!(count >= 2, "expected ≥2 symbols, got {count}: {pw}");
        }
    }

    #[test]
    fn all_min_constraints_satisfied_simultaneously() {
        let cs = CharsetBuilder::default().build().unwrap();
        let config = GeneratorConfig {
            charset: &cs,
            length: 20,
            min_lowercase: 2,
            min_uppercase: 2,
            min_digits: 2,
            min_symbols: 2,
        };
        for _ in 0..100 {
            let pw = generate(&config).unwrap();
            assert!(pw.chars().filter(|c| c.is_ascii_lowercase()).count() >= 2);
            assert!(pw.chars().filter(|c| c.is_ascii_uppercase()).count() >= 2);
            assert!(pw.chars().filter(|c| c.is_ascii_digit()).count() >= 2);
            assert!(pw.chars().filter(|c| cs.symbols.contains(c)).count() >= 2);
        }
    }

    #[test]
    fn no_lowercase_password_contains_no_lowercase() {
        let cs = CharsetBuilder {
            include_lowercase: false,
            ..Default::default()
        }
        .build()
        .unwrap();
        let config = make_config(&cs);
        for _ in 0..50 {
            let pw = generate(&config).unwrap();
            assert!(
                !pw.chars().any(|c| c.is_ascii_lowercase()),
                "lowercase found in password: {pw}"
            );
        }
    }

    #[test]
    fn generate_many_returns_correct_count() {
        let cs = CharsetBuilder::default().build().unwrap();
        let config = make_config(&cs);
        let passwords = generate_many(&config, 5).unwrap();
        assert_eq!(passwords.len(), 5);
    }

    #[test]
    fn generate_many_all_correct_length() {
        let cs = CharsetBuilder::default().build().unwrap();
        let config = GeneratorConfig {
            length: 12,
            ..make_config(&cs)
        };
        let passwords = generate_many(&config, 10).unwrap();
        for pw in passwords {
            assert_eq!(pw.chars().count(), 12);
        }
    }
}
