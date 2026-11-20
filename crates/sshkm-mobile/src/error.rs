//! The one error the bridge throws, with the core's stable code.

use sshkm_core::ErrorCode;

/// What went wrong in the core.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CoreError {
    /// The core refused or failed. The app words `code` in the user's
    /// language; `detail` is English for developers, never shown and never
    /// holding a secret.
    #[error("{code:?}: {detail}")]
    Failed { code: ErrorCode, detail: String },
}

impl From<sshkm_core::Error> for CoreError {
    fn from(error: sshkm_core::Error) -> Self {
        Self::Failed {
            code: error.code(),
            detail: error.to_string(),
        }
    }
}

/// The core's error codes, as Kotlin sees them. UniFFI checks this copy
/// against `sshkm_core::ErrorCode` when it builds, so the two can't drift.
#[uniffi::remote(Enum)]
pub enum ErrorCode {
    NotFound,
    AlreadyExists,
    InvalidInput,
    WrongPassphrase,
    PassphraseRequired,
    AgentUnavailable,
    AgentRefused,
    Unsupported,
    Parse,
    Io,
    PermissionDenied,
    Conflict,
    VaultLocked,
    Cancelled,
    TooManyAttempts,
}
