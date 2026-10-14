use clap::Parser;

use crate::error::AppError;

/// Maximum accepted `--length`. Keeps memory use bounded for absurd inputs.
pub const MAX_LENGTH: usize = 4096;

/// Maximum accepted `--count`. Keeps memory use bounded for absurd inputs.
pub const MAX_COUNT: usize = 1000;

const AFTER_HELP: &str = "\
EXAMPLES:
  pwgen                            # 16-character password (all types)
  pwgen -l 24 -c 10               # ten 24-character passwords
  pwgen --no-symbols --min-digits 2
  pwgen --exclude-ambiguous        # easy-to-read (no 0/O/1/l/I/|)
  pwgen --charset 'abc123' -l 8   # custom character pool
  pwgen --json --strength          # JSON output with entropy info
  pwgen --clipboard                # copy result to clipboard";

/// Cryptographically secure CLI password generator.
///
/// Passwords are generated using the operating system's CSPRNG via
/// `rand::rngs::OsRng`, ensuring cryptographic strength on all platforms.
/// Character selection uses rejection sampling (no modulo bias), and the
/// final result is shuffled with Fisher-Yates.
#[derive(Parser, Debug)]
#[command(
    name = "pwgen",
    version,
    about = "A cryptographically secure CLI password generator",
    after_help = AFTER_HELP
)]
pub struct Args {
    /// Password length (1–4096).
    #[arg(short = 'l', long, default_value_t = 16, value_name = "N")]
    pub length: usize,

    /// Number of passwords to generate (1–1000).
    #[arg(short = 'c', long, default_value_t = 1, value_name = "N")]
    pub count: usize,

    /// Exclude lowercase letters (a–z).
    #[arg(long)]
    pub no_lowercase: bool,

    /// Exclude uppercase letters (A–Z).
    #[arg(long)]
    pub no_uppercase: bool,

    /// Exclude digits (0–9).
    #[arg(long)]
    pub no_digits: bool,

    /// Exclude symbols (!@#$ etc.).
    #[arg(long)]
    pub no_symbols: bool,

    /// Exclude visually ambiguous characters: 0 O 1 l I |
    #[arg(long)]
    pub exclude_ambiguous: bool,

    /// Copy the generated password to the clipboard instead of printing it
    /// (requires --count 1). The copy is marked as concealed so clipboard
    /// managers that honor the convention do not record it.
    #[arg(long)]
    pub clipboard: bool,

    /// Require at least N lowercase letters.
    #[arg(long, default_value_t = 0, value_name = "N")]
    pub min_lowercase: usize,

    /// Require at least N uppercase letters.
    #[arg(long, default_value_t = 0, value_name = "N")]
    pub min_uppercase: usize,

    /// Require at least N digits.
    #[arg(long, default_value_t = 0, value_name = "N")]
    pub min_digits: usize,

    /// Require at least N symbols.
    #[arg(long, default_value_t = 0, value_name = "N")]
    pub min_symbols: usize,

    /// Use a fully custom character pool (overrides --no-* flags; cannot be
    /// combined with --min-*).
    #[arg(long, value_name = "STRING")]
    pub charset: Option<String>,

    /// Output results as JSON.
    #[arg(long)]
    pub json: bool,

    /// Display entropy and strength rating alongside the password.
    #[arg(long)]
    pub strength: bool,
}

impl Args {
    /// Validate cross-argument constraints that clap itself cannot express.
    ///
    /// Checks are ordered from cheapest to most specific. Returns `Ok(())`
    /// when all constraints are satisfied.
    ///
    /// # Errors
    ///
    /// Returns the first [`AppError`] violation found.
    pub fn validate(&self) -> Result<(), AppError> {
        if !(1..=MAX_LENGTH).contains(&self.length) {
            return Err(AppError::LengthOutOfRange {
                length: self.length,
                max: MAX_LENGTH,
            });
        }
        if !(1..=MAX_COUNT).contains(&self.count) {
            return Err(AppError::CountOutOfRange {
                count: self.count,
                max: MAX_COUNT,
            });
        }

        // --clipboard is only meaningful with a single password.
        if self.clipboard && self.count > 1 {
            return Err(AppError::ClipboardCountConflict(self.count));
        }

        // --charset overrides all category flags; skip category-level checks.
        // Custom pools have no category metadata, so --min-* cannot be honored.
        if self.charset.is_some() {
            if self.min_lowercase > 0
                || self.min_uppercase > 0
                || self.min_digits > 0
                || self.min_symbols > 0
            {
                return Err(AppError::MinWithCustomCharset);
            }
            return Ok(());
        }

        // At least one category must remain enabled.
        if self.no_lowercase && self.no_uppercase && self.no_digits && self.no_symbols {
            return Err(AppError::EmptyCharset);
        }

        // --min-X cannot coexist with --no-X.
        if self.min_lowercase > 0 && self.no_lowercase {
            return Err(AppError::MinRequiresCategory {
                category: "lowercase",
            });
        }
        if self.min_uppercase > 0 && self.no_uppercase {
            return Err(AppError::MinRequiresCategory {
                category: "uppercase",
            });
        }
        if self.min_digits > 0 && self.no_digits {
            return Err(AppError::MinRequiresCategory { category: "digits" });
        }
        if self.min_symbols > 0 && self.no_symbols {
            return Err(AppError::MinRequiresCategory {
                category: "symbols",
            });
        }

        // Sum of minimums must not exceed the requested length.
        // `saturating_add` prevents wrap-around on absurd inputs in release builds,
        // which would otherwise let a huge total slip past this check.
        let needed = self
            .min_lowercase
            .saturating_add(self.min_uppercase)
            .saturating_add(self.min_digits)
            .saturating_add(self.min_symbols);
        if needed > self.length {
            return Err(AppError::LengthTooShort {
                length: self.length,
                needed,
            });
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Parse from a slice of strings — the idiomatic way to unit-test clap CLIs.
    fn parse(args: &[&str]) -> Args {
        Args::try_parse_from(args).expect("failed to parse test args")
    }

    #[test]
    fn default_args_are_valid() {
        let args = parse(&["pwgen"]);
        assert!(args.validate().is_ok());
    }

    #[test]
    fn clipboard_with_count_greater_than_one_fails() {
        let args = parse(&["pwgen", "--clipboard", "--count", "3"]);
        assert!(matches!(
            args.validate(),
            Err(AppError::ClipboardCountConflict(3))
        ));
    }

    #[test]
    fn clipboard_with_count_one_is_valid() {
        let args = parse(&["pwgen", "--clipboard", "--count", "1"]);
        assert!(args.validate().is_ok());
    }

    #[test]
    fn all_categories_disabled_fails() {
        let args = parse(&[
            "pwgen",
            "--no-lowercase",
            "--no-uppercase",
            "--no-digits",
            "--no-symbols",
        ]);
        assert!(matches!(args.validate(), Err(AppError::EmptyCharset)));
    }

    #[test]
    fn min_lowercase_with_no_lowercase_fails() {
        let args = parse(&["pwgen", "--min-lowercase", "2", "--no-lowercase"]);
        assert!(matches!(
            args.validate(),
            Err(AppError::MinRequiresCategory {
                category: "lowercase"
            })
        ));
    }

    #[test]
    fn min_uppercase_with_no_uppercase_fails() {
        let args = parse(&["pwgen", "--min-uppercase", "2", "--no-uppercase"]);
        assert!(matches!(
            args.validate(),
            Err(AppError::MinRequiresCategory {
                category: "uppercase"
            })
        ));
    }

    #[test]
    fn min_digits_with_no_digits_fails() {
        let args = parse(&["pwgen", "--min-digits", "2", "--no-digits"]);
        assert!(matches!(
            args.validate(),
            Err(AppError::MinRequiresCategory { category: "digits" })
        ));
    }

    #[test]
    fn min_symbols_with_no_symbols_fails() {
        let args = parse(&["pwgen", "--min-symbols", "2", "--no-symbols"]);
        assert!(matches!(
            args.validate(),
            Err(AppError::MinRequiresCategory {
                category: "symbols"
            })
        ));
    }

    #[test]
    fn min_constraints_exceeding_length_fails() {
        let args = parse(&[
            "pwgen",
            "--length",
            "8",
            "--min-lowercase",
            "5",
            "--min-uppercase",
            "5",
        ]);
        assert!(matches!(
            args.validate(),
            Err(AppError::LengthTooShort {
                length: 8,
                needed: 10
            })
        ));
    }

    #[test]
    fn min_constraints_exactly_equal_to_length_is_valid() {
        let args = parse(&[
            "pwgen",
            "--length",
            "8",
            "--min-lowercase",
            "4",
            "--min-uppercase",
            "4",
        ]);
        assert!(args.validate().is_ok());
    }

    #[test]
    fn zero_length_fails() {
        let args = parse(&["pwgen", "--length", "0"]);
        assert!(matches!(
            args.validate(),
            Err(AppError::LengthOutOfRange { length: 0, .. })
        ));
    }

    #[test]
    fn length_above_max_fails() {
        let too_long = (MAX_LENGTH + 1).to_string();
        let args = parse(&["pwgen", "--length", &too_long]);
        assert!(matches!(
            args.validate(),
            Err(AppError::LengthOutOfRange { .. })
        ));
    }

    #[test]
    fn length_at_max_is_valid() {
        let max = MAX_LENGTH.to_string();
        let args = parse(&["pwgen", "--length", &max]);
        assert!(args.validate().is_ok());
    }

    #[test]
    fn zero_count_fails() {
        // Previously `--clipboard --count 0` panicked on `passwords[0]`.
        let args = parse(&["pwgen", "--clipboard", "--count", "0"]);
        assert!(matches!(
            args.validate(),
            Err(AppError::CountOutOfRange { count: 0, .. })
        ));
    }

    #[test]
    fn count_above_max_fails() {
        let too_many = (MAX_COUNT + 1).to_string();
        let args = parse(&["pwgen", "--count", &too_many]);
        assert!(matches!(
            args.validate(),
            Err(AppError::CountOutOfRange { .. })
        ));
    }

    #[test]
    fn overflowing_min_constraints_fail_instead_of_wrapping() {
        let half = (usize::MAX / 2 + 1).to_string();
        let args = parse(&["pwgen", "--min-lowercase", &half, "--min-uppercase", &half]);
        assert!(matches!(
            args.validate(),
            Err(AppError::LengthTooShort {
                needed: usize::MAX,
                ..
            })
        ));
    }

    #[test]
    fn custom_charset_with_min_constraint_fails() {
        let args = parse(&["pwgen", "--charset", "abc", "--min-digits", "1"]);
        assert!(matches!(
            args.validate(),
            Err(AppError::MinWithCustomCharset)
        ));
    }

    #[test]
    fn custom_charset_bypasses_all_category_checks() {
        // Even with all --no-* flags set, --charset overrides them.
        let args = parse(&[
            "pwgen",
            "--charset",
            "abc",
            "--no-lowercase",
            "--no-uppercase",
            "--no-digits",
            "--no-symbols",
        ]);
        assert!(args.validate().is_ok());
    }
}
