mod charset;
mod cli;
mod error;
mod generator;
mod output;

use std::process::ExitCode;

use arboard::Clipboard;
use clap::Parser;

use crate::charset::CharsetBuilder;
use crate::cli::Args;
use crate::error::AppError;
use crate::generator::{generate_many, GeneratorConfig};
use crate::output::{compute_strength, print_json, print_plain, print_strength};

fn main() -> ExitCode {
    let args = Args::parse();
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Core application logic, separated from `main` to allow clean `?` propagation.
fn run(args: Args) -> Result<(), AppError> {
    // Validate cross-argument constraints first so the user gets a clear error
    // message before any generation work is done.
    args.validate()?;

    let charset = CharsetBuilder {
        include_lowercase: !args.no_lowercase,
        include_uppercase: !args.no_uppercase,
        include_digits: !args.no_digits,
        include_symbols: !args.no_symbols,
        exclude_ambiguous: args.exclude_ambiguous,
        custom: args.charset.clone(),
    }
    .build()?;

    let config = GeneratorConfig {
        charset: &charset,
        length: args.length,
        min_lowercase: args.min_lowercase,
        min_uppercase: args.min_uppercase,
        min_digits: args.min_digits,
        min_symbols: args.min_symbols,
    };

    let passwords = generate_many(&config, args.count)?;

    // --clipboard: copy the first (and only) password to the system clipboard.
    // On macOS/Windows the content persists after the process exits.
    // On Linux (X11/Wayland) the content may be cleared when the process ends;
    // a clipboard manager (e.g. xclip, wl-paste) is recommended for persistence.
    if args.clipboard {
        let mut cb = Clipboard::new()?;
        cb.set_text(passwords[0].clone())?;
        eprintln!("Password copied to clipboard.");
    }

    // `bool::then(|| ...)` is idiomatic for producing an `Option` from a bool.
    // It avoids the verbose `if condition { Some(expr) } else { None }` pattern.
    let strength_info = args
        .strength
        .then(|| compute_strength(charset.chars.len(), args.length));

    if args.json {
        print_json(&passwords, strength_info.as_ref())?;
    } else if let Some(ref info) = strength_info {
        print_strength(&passwords, info);
    } else {
        print_plain(&passwords);
    }

    Ok(())
}
