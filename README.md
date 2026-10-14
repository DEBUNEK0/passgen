# pwgen

A fast, cryptographically secure CLI password generator written in Rust.

Passwords are generated using the operating system's CSPRNG (`OsRng`), character selection uses rejection sampling to avoid modulo bias, and the result is shuffled with Fisher-Yates — so every password is both statistically unbiased and unpredictable.

## Install

### From source (recommended for now)

```sh
git clone https://github.com/DEBUNEK0/passgen
cd passgen
cargo install --path .
```

After installation, the `pwgen` command is available in your shell.

### From crates.io (future)

```sh
cargo install passgen
```

## Usage

```
pwgen [OPTIONS]
```

## Examples

```sh
# Default: 16-character password with all character types
pwgen

# Five 24-character passwords
pwgen -l 24 -c 5

# No symbols, but require at least 2 digits
pwgen --no-symbols --min-digits 2

# Easy to read/transcribe: exclude ambiguous chars (0 O 1 l I |)
pwgen --exclude-ambiguous

# Custom character pool
pwgen --charset 'abc123!@#' -l 12

# JSON output with entropy info
pwgen --json --strength

# Copy to clipboard (silent — password not printed to stdout)
pwgen --clipboard

# JSON, 20 chars, all min constraints
pwgen -l 20 --min-lowercase 2 --min-uppercase 2 --min-digits 2 --min-symbols 2 --json --strength
```

## Options

| Flag | Default | Description |
|:-----|:--------|:------------|
| `-l, --length <N>` | `16` | Password length (1–4096) |
| `-c, --count <N>` | `1` | Number of passwords to generate (1–1000) |
| `--no-lowercase` | — | Exclude lowercase letters (a–z) |
| `--no-uppercase` | — | Exclude uppercase letters (A–Z) |
| `--no-digits` | — | Exclude digits (0–9) |
| `--no-symbols` | — | Exclude symbols (`!@#$` etc.) |
| `--exclude-ambiguous` | — | Exclude visually ambiguous chars: `0 O 1 l I \|` |
| `--clipboard` | — | Copy result to clipboard instead of printing it (requires `--count 1`) |
| `--min-lowercase <N>` | `0` | Require at least N lowercase letters |
| `--min-uppercase <N>` | `0` | Require at least N uppercase letters |
| `--min-digits <N>` | `0` | Require at least N digits |
| `--min-symbols <N>` | `0` | Require at least N symbols |
| `--charset <STRING>` | — | Custom character pool (overrides `--no-*` flags; cannot be combined with `--min-*`) |
| `--json` | — | Output as JSON |
| `--strength` | — | Show entropy and strength rating |
| `-h, --help` | — | Print help |
| `-V, --version` | — | Print version |

## Strength Rating

Entropy is calculated as `log₂(charset_size) × length`.

With `--min-*` constraints, mandatory characters are drawn from their smaller category pools, so each of them contributes `log₂(category_size)` instead. For example, `-l 20` with one of each category is reported as `log₂(26·26·10·32) + 16·log₂(94) ≈ 122.6` bits rather than 131.1. This is a conservative lower bound (the final shuffle is not credited).

| Length | Charset | Entropy | Rating |
|:------:|:-------:|:-------:|:------:|
| 8 | Full (94 chars) | ~52 bits | Fair |
| 12 | Full (94 chars) | ~78 bits | Good |
| 16 | Full (94 chars) | ~105 bits | **Strong** |
| 20 | Full (94 chars) | ~131 bits | **Very Strong** |

| Entropy (bits) | Label |
|:--------------|:------|
| < 40 | Weak |
| 40 – 59 | Fair |
| 60 – 79 | Good |
| 80 – 119 | Strong |
| ≥ 120 | Very Strong |

## Security Notes

- **RNG**: `rand::rngs::OsRng` delegates to `getrandom`, which calls the platform's secure entropy source (`/dev/urandom` on Linux/macOS, `BCryptGenRandom` on Windows). This is cryptographically secure.
- **No modulo bias**: `rand::Rng::gen_range` uses Lemire's fast rejection sampling, ensuring uniform character selection.
- **Fisher-Yates shuffle**: The final password is shuffled so mandatory characters (from `--min-*`) are not predictably placed at the front.
- **Clipboard**: `--clipboard` keeps the password off stdout and marks the copy as concealed (`org.nspasteboard.ConcealedType` on macOS, history/cloud exclusion on Windows, `x-kde-passwordManagerHint` on Linux), so clipboard managers that honor these conventions do not record it. On macOS and Windows, clipboard content persists after the process exits. On Linux (X11/Wayland), it may be cleared when the process ends — use a clipboard manager (`xclip`, `wl-paste`, etc.) if you need persistence.
- **Input bounds**: `--length` and `--count` are capped and the `--min-*` total is overflow-checked, so absurd inputs fail fast instead of exhausting memory.
- **Terminal history**: Passwords printed to stdout may appear in your shell history if you use command substitution (e.g., `export PW=$(pwgen)`). Prefer `--clipboard` or redirect output to a file when this is a concern.

## Character Set

The default character pool contains all 94 printable ASCII non-whitespace characters:

| Category | Count | Characters |
|:---------|:-----:|:-----------|
| Lowercase | 26 | `a–z` |
| Uppercase | 26 | `A–Z` |
| Digits | 10 | `0–9` |
| Symbols | 32 | `!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~` |

Ambiguous characters excluded by `--exclude-ambiguous`: `0 O 1 l I |`

## Development

```sh
# Format
cargo fmt

# Lint (warnings as errors)
cargo clippy -- -D warnings

# Run all tests (unit + integration)
cargo test

# Build optimized binary
cargo build --release
./target/release/pwgen --version
```

## Future Improvements

- `--passphrase` mode: generate word-based passphrases (EFF word list)
- `--entropy-target <bits>`: auto-compute length to hit a desired entropy
- Shell completions (`--completions <shell>`)
- Configurable ambiguous character set
- `--no-repeat`: ensure no character appears more than once
- Publish to crates.io

## License

MIT — see [LICENSE](LICENSE)
