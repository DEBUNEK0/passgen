use thiserror::Error;

/// Application-level errors.
///
/// Every public function in this crate that can fail returns `Result<_, AppError>`.
/// The `#[from]` attribute on `Clipboard` and `Json` variants lets the `?`
/// operator convert those library errors automatically.
#[derive(Debug, Error)]
pub enum AppError {
    /// All character categories are disabled, leaving an empty pool.
    #[error("empty character set — enable at least one character category")]
    EmptyCharset,

    /// `--charset` was provided but contained no characters after deduplication.
    #[error("custom charset is empty — provide at least one character")]
    EmptyCustomCharset,

    /// The sum of `--min-*` values exceeds `--length`.
    #[error("minimum constraints total {needed} characters but --length is only {length}")]
    LengthTooShort { length: usize, needed: usize },

    /// `--length` is outside the supported range.
    #[error("--length must be between 1 and {max}, but {length} was given")]
    LengthOutOfRange { length: usize, max: usize },

    /// `--count` is outside the supported range.
    #[error("--count must be between 1 and {max}, but {count} was given")]
    CountOutOfRange { count: usize, max: usize },

    /// `--min-*` was combined with `--charset`, which has no category metadata.
    #[error(
        "--min-* options cannot be used with --charset (custom pools have no character categories)"
    )]
    MinWithCustomCharset,

    /// `--clipboard` was combined with `--count > 1`.
    #[error("--clipboard can only be used with --count 1, but --count {0} was given")]
    ClipboardCountConflict(usize),

    /// `--min-X` was set while `--no-X` is also set.
    #[error(
        "--min-{category} requires {category} characters to be enabled \
         (remove --no-{category})"
    )]
    MinRequiresCategory { category: &'static str },

    /// Clipboard I/O error forwarded from `arboard`.
    #[error("clipboard error: {0}")]
    Clipboard(#[from] arboard::Error),

    /// JSON serialization error forwarded from `serde_json`.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
