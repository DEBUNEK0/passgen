use std::fmt;

use serde_json::{json, Value};

use crate::error::AppError;

// ---------------------------------------------------------------------------
// Strength rating
// ---------------------------------------------------------------------------

/// Qualitative strength label derived from Shannon entropy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrengthLabel {
    Weak,
    Fair,
    Good,
    Strong,
    VeryStrong,
}

impl fmt::Display for StrengthLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Weak => "Weak",
            Self::Fair => "Fair",
            Self::Good => "Good",
            Self::Strong => "Strong",
            Self::VeryStrong => "Very Strong",
        };
        f.write_str(s)
    }
}

/// Entropy and strength metadata for a generated password.
pub struct StrengthInfo {
    /// Conservative entropy estimate in bits (see [`crate::generator::entropy_bits`]).
    pub entropy_bits: f64,
    /// Qualitative strength label.
    pub strength: StrengthLabel,
    /// Number of distinct characters in the pool.
    pub charset_size: usize,
}

/// Build strength metadata from a charset size and an entropy estimate.
///
/// # Entropy thresholds
///
/// | Range (bits) | Label       |
/// |:-------------|:------------|
/// | < 40         | Weak        |
/// | 40 – 59      | Fair        |
/// | 60 – 79      | Good        |
/// | 80 – 119     | Strong      |
/// | ≥ 120        | Very Strong |
pub fn compute_strength(charset_size: usize, entropy_bits: f64) -> StrengthInfo {
    let strength = match entropy_bits as u64 {
        0..=39 => StrengthLabel::Weak,
        40..=59 => StrengthLabel::Fair,
        60..=79 => StrengthLabel::Good,
        80..=119 => StrengthLabel::Strong,
        _ => StrengthLabel::VeryStrong,
    };
    StrengthInfo {
        entropy_bits,
        strength,
        charset_size,
    }
}

// ---------------------------------------------------------------------------
// Plain-text output
// ---------------------------------------------------------------------------

/// Print each password on its own line.
pub fn print_plain(passwords: &[String]) {
    for p in passwords {
        println!("{p}");
    }
}

/// Print each password followed by a strength summary.
///
/// With an empty `passwords` slice (e.g. `--clipboard`), only the summary is printed.
pub fn print_strength(passwords: &[String], info: &StrengthInfo) {
    for p in passwords {
        println!("{p}");
    }
    if !passwords.is_empty() {
        println!();
    }
    println!("Charset size : {} characters", info.charset_size);
    println!("Entropy      : {:.1} bits", info.entropy_bits);
    println!("Strength     : {}", info.strength);
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

/// Build a JSON [`Value`] representing the generation result.
///
/// This function is pure (no I/O), making it easy to unit-test the output
/// structure without capturing stdout.
///
/// - Single password → `{"password": "..."}`.
/// - Multiple passwords → `{"passwords": ["...", ...]}`.
/// - No passwords (e.g. `--clipboard`) → no password field at all.
/// - If `info` is supplied, `charset_size`, `entropy_bits`, and `strength`
///   fields are added to the same object.
pub fn build_json(passwords: &[String], info: Option<&StrengthInfo>) -> Value {
    let mut obj = match passwords {
        [] => json!({}),
        [single] => json!({ "password": single }),
        _ => json!({ "passwords": passwords }),
    };

    if let Some(info) = info {
        let map = obj
            .as_object_mut()
            .expect("json! always produces an object");
        map.insert("charset_size".into(), json!(info.charset_size));
        map.insert("entropy_bits".into(), json!(round2(info.entropy_bits)));
        map.insert("strength".into(), json!(info.strength.to_string()));
    }

    obj
}

/// Serialize and pretty-print the JSON result to stdout.
pub fn print_json(passwords: &[String], info: Option<&StrengthInfo>) -> Result<(), AppError> {
    let value = build_json(passwords, info);
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Round a float to 2 decimal places for stable JSON output.
fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn uniform_bits(charset_size: usize, length: usize) -> f64 {
        (charset_size as f64).log2() * length as f64
    }

    #[test]
    fn weak_password_rated_weak() {
        // 10^6 ≈ 19.9 bits → Weak
        let info = compute_strength(10, uniform_bits(10, 6));
        assert_eq!(info.strength, StrengthLabel::Weak);
    }

    #[test]
    fn fair_password_rated_fair() {
        // 94^8 ≈ 52.4 bits → Fair
        let info = compute_strength(94, uniform_bits(94, 8));
        assert_eq!(info.strength, StrengthLabel::Fair);
    }

    #[test]
    fn good_password_rated_good() {
        // 94^10 ≈ 65.5 bits → Good
        let info = compute_strength(94, uniform_bits(94, 10));
        assert_eq!(info.strength, StrengthLabel::Good);
    }

    #[test]
    fn strong_password_rated_strong() {
        // 94^16 ≈ 104.9 bits → Strong
        let info = compute_strength(94, uniform_bits(94, 16));
        assert_eq!(info.strength, StrengthLabel::Strong);
    }

    #[test]
    fn very_strong_password_rated_very_strong() {
        // 94^20 ≈ 131.1 bits → Very Strong
        let info = compute_strength(94, uniform_bits(94, 20));
        assert_eq!(info.strength, StrengthLabel::VeryStrong);
    }

    #[test]
    fn build_json_single_uses_password_key() {
        let passwords = vec!["abc123".to_string()];
        let v = build_json(&passwords, None);
        assert_eq!(v["password"], "abc123");
        assert!(
            v.get("passwords").is_none(),
            "should not have 'passwords' key"
        );
    }

    #[test]
    fn build_json_multiple_uses_passwords_array() {
        let passwords = vec!["abc".to_string(), "def".to_string()];
        let v = build_json(&passwords, None);
        assert!(v["passwords"].is_array());
        assert_eq!(v["passwords"].as_array().unwrap().len(), 2);
        assert!(
            v.get("password").is_none(),
            "should not have 'password' key"
        );
    }

    #[test]
    fn build_json_with_strength_includes_all_fields() {
        let passwords = vec!["abc123".to_string()];
        let info = compute_strength(94, uniform_bits(94, 16));
        let v = build_json(&passwords, Some(&info));
        assert!(v["entropy_bits"].is_number());
        assert!(v["strength"].is_string());
        assert!(v["charset_size"].is_number());
    }

    #[test]
    fn build_json_without_passwords_omits_password_fields() {
        let info = compute_strength(94, uniform_bits(94, 16));
        let v = build_json(&[], Some(&info));
        assert!(v.get("password").is_none());
        assert!(v.get("passwords").is_none());
        assert!(v["entropy_bits"].is_number());
    }

    #[test]
    fn strength_label_display() {
        assert_eq!(StrengthLabel::Weak.to_string(), "Weak");
        assert_eq!(StrengthLabel::VeryStrong.to_string(), "Very Strong");
    }
}
