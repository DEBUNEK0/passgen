use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

fn pwgen() -> Command {
    Command::cargo_bin("pwgen").unwrap()
}

// ---------------------------------------------------------------------------
// Basic output
// ---------------------------------------------------------------------------

#[test]
fn default_output_is_16_chars() {
    let output = pwgen().output().unwrap();
    assert!(output.status.success());
    let line = String::from_utf8(output.stdout).unwrap();
    let line = line.trim();
    assert_eq!(
        line.chars().count(),
        16,
        "expected 16-char password, got: {line}"
    );
}

#[test]
fn length_flag_is_respected() {
    let output = pwgen().args(["--length", "8"]).output().unwrap();
    assert!(output.status.success());
    let line = String::from_utf8(output.stdout).unwrap();
    assert_eq!(line.trim().chars().count(), 8);
}

#[test]
fn count_produces_correct_number_of_lines() {
    let output = pwgen().args(["-c", "5"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 5);
}

// ---------------------------------------------------------------------------
// Character exclusion
// ---------------------------------------------------------------------------

#[test]
fn no_digits_excludes_digits() {
    // Use a long password to increase the chance of catching violations.
    let output = pwgen()
        .args(["--no-digits", "--length", "100"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let pw = String::from_utf8(output.stdout).unwrap();
    assert!(
        !pw.trim().chars().any(|c| c.is_ascii_digit()),
        "digit found in password: {}",
        pw.trim()
    );
}

#[test]
fn no_symbols_excludes_symbols() {
    let symbols = r##"!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"##;
    let output = pwgen()
        .args(["--no-symbols", "--length", "100"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let pw = String::from_utf8(output.stdout).unwrap();
    assert!(
        !pw.trim().chars().any(|c| symbols.contains(c)),
        "symbol found in password: {}",
        pw.trim()
    );
}

#[test]
fn exclude_ambiguous_removes_ambiguous_chars() {
    let ambiguous = ['0', 'O', '1', 'l', 'I', '|'];
    for _ in 0..30 {
        let output = pwgen()
            .args(["--exclude-ambiguous", "--length", "50"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let pw = String::from_utf8(output.stdout).unwrap();
        for ch in pw.trim().chars() {
            assert!(
                !ambiguous.contains(&ch),
                "ambiguous char '{ch}' found in password"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Error cases
// ---------------------------------------------------------------------------

#[test]
fn clipboard_with_count_2_exits_with_error() {
    pwgen()
        .args(["--clipboard", "--count", "2"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("clipboard"));
}

#[test]
fn all_no_flags_exits_with_error() {
    pwgen()
        .args([
            "--no-lowercase",
            "--no-uppercase",
            "--no-digits",
            "--no-symbols",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("empty character set"));
}

#[test]
fn min_exceeding_length_exits_with_error() {
    pwgen()
        .args([
            "--length",
            "5",
            "--min-lowercase",
            "3",
            "--min-uppercase",
            "3",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("minimum constraints"));
}

#[test]
fn min_with_disabled_category_exits_with_error() {
    pwgen()
        .args(["--no-digits", "--min-digits", "2"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("digits"));
}

// ---------------------------------------------------------------------------
// Custom charset
// ---------------------------------------------------------------------------

#[test]
fn custom_charset_limits_output_characters() {
    for _ in 0..20 {
        let output = pwgen()
            .args(["--charset", "abc", "--length", "10"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let pw = String::from_utf8(output.stdout).unwrap();
        let pw = pw.trim();
        assert_eq!(pw.chars().count(), 10, "wrong length: {pw}");
        assert!(
            pw.chars().all(|c| "abc".contains(c)),
            "unexpected char in password: {pw}"
        );
    }
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

#[test]
fn json_single_has_password_key() {
    let output = pwgen().arg("--json").output().unwrap();
    assert!(output.status.success());
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(v["password"].is_string(), "missing 'password' key");
}

#[test]
fn json_multiple_has_passwords_array() {
    let output = pwgen().args(["--json", "-c", "3"]).output().unwrap();
    assert!(output.status.success());
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(v["passwords"].is_array());
    assert_eq!(v["passwords"].as_array().unwrap().len(), 3);
}

// ---------------------------------------------------------------------------
// Strength output
// ---------------------------------------------------------------------------

#[test]
fn strength_flag_shows_entropy_line() {
    pwgen()
        .arg("--strength")
        .assert()
        .success()
        .stdout(predicate::str::contains("Entropy"));
}

#[test]
fn json_with_strength_has_entropy_bits() {
    let output = pwgen().args(["--json", "--strength"]).output().unwrap();
    assert!(output.status.success());
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(v["entropy_bits"].is_number(), "missing 'entropy_bits'");
    assert!(v["strength"].is_string(), "missing 'strength'");
    assert!(v["charset_size"].is_number(), "missing 'charset_size'");
}

// ---------------------------------------------------------------------------
// Min constraints integration
// ---------------------------------------------------------------------------

#[test]
fn min_constraints_within_length_succeeds() {
    pwgen()
        .args([
            "--length",
            "12",
            "--min-lowercase",
            "2",
            "--min-uppercase",
            "2",
            "--min-digits",
            "2",
            "--min-symbols",
            "2",
        ])
        .assert()
        .success();
}

// ---------------------------------------------------------------------------
// Input bounds and constraint validation
// ---------------------------------------------------------------------------

#[test]
fn length_above_max_exits_with_error() {
    pwgen()
        .args(["--length", "4097"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--length must be between 1 and 4096",
        ));
}

#[test]
fn clipboard_with_count_0_exits_with_error_instead_of_panicking() {
    pwgen()
        .args(["--clipboard", "--count", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--count must be between 1 and 1000",
        ))
        .stderr(predicate::str::contains("panicked").not());
}

#[test]
fn overflowing_min_constraints_exit_with_error() {
    let half = (usize::MAX / 2 + 1).to_string();
    pwgen()
        .args(["--min-lowercase", &half, "--min-uppercase", &half])
        .assert()
        .failure()
        .stderr(predicate::str::contains("minimum constraints total"));
}

#[test]
fn custom_charset_with_min_constraint_exits_with_error() {
    pwgen()
        .args(["--charset", "abc", "--min-digits", "1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with --charset"));
}

#[test]
fn json_entropy_accounts_for_min_constraints() {
    let output = pwgen()
        .args([
            "-l",
            "20",
            "--min-lowercase",
            "1",
            "--min-uppercase",
            "1",
            "--min-digits",
            "1",
            "--min-symbols",
            "1",
            "--json",
            "--strength",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    // log2(26·26·10·32) + 16·log2(94) ≈ 122.60, below the naive 20·log2(94) ≈ 131.09.
    assert_eq!(v["entropy_bits"].as_f64().unwrap(), 122.6);
}
