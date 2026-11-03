//! The single error type of the crate.

use std::{io, path::Path};

use serde::{Serialize, Serializer};

/// Result alias used throughout the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Stable, machine-readable error code.
///
/// The UI localises errors by this code; [`Error`]'s message is English text
/// meant for logs and developers only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum ErrorCode {
    /// A file, key, host or agent identity does not exist.
    NotFound,
    /// The target already exists and is never overwritten.
    AlreadyExists,
    /// The request is malformed (bad file name, newline in a value, …).
    InvalidInput,
    /// The passphrase does not decrypt the key.
    WrongPassphrase,
    /// The key is encrypted and no passphrase was given.
    PassphraseRequired,
    /// No agent is configured, or it cannot be reached.
    AgentUnavailable,
    /// The agent answered with a failure.
    AgentRefused,
    /// The operation is not supported for this input (format, platform, …).
    Unsupported,
    /// A file could not be parsed.
    Parse,
    /// Any other I/O error.
    Io,
    /// The operating system denied access.
    PermissionDenied,
    /// The file changed on disk since it was read (e.g. a synced vault edited
    /// on another computer), so the write was not made.
    Conflict,
    /// The password vault is locked; unlock it and try again.
    VaultLocked,
    /// The user dismissed a system prompt (Touch ID, Windows Hello).
    Cancelled,
}

impl ErrorCode {
    /// The code as the string that is serialised (`"not_found"`, …).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::AlreadyExists => "already_exists",
            Self::InvalidInput => "invalid_input",
            Self::WrongPassphrase => "wrong_passphrase",
            Self::PassphraseRequired => "passphrase_required",
            Self::AgentUnavailable => "agent_unavailable",
            Self::AgentRefused => "agent_refused",
            Self::Unsupported => "unsupported",
            Self::Parse => "parse",
            Self::Io => "io",
            Self::PermissionDenied => "permission_denied",
            Self::Conflict => "conflict",
            Self::VaultLocked => "vault_locked",
            Self::Cancelled => "cancelled",
        }
    }
}

/// The serialised form of an [`Error`]: `{ "code": "...", "message": "..." }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct ErrorInfo {
    /// Machine-readable code.
    pub code: ErrorCode,
    /// English diagnostic text; never contains secrets.
    pub message: String,
}

/// Error returned by every fallible function of the crate.
///
/// Messages never contain passphrases or key material.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// See [`ErrorCode::NotFound`].
    #[error("not found: {0}")]
    NotFound(String),
    /// See [`ErrorCode::AlreadyExists`].
    #[error("already exists: {0}")]
    AlreadyExists(String),
    /// See [`ErrorCode::InvalidInput`].
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// See [`ErrorCode::WrongPassphrase`].
    #[error("wrong passphrase")]
    WrongPassphrase,
    /// See [`ErrorCode::PassphraseRequired`].
    #[error("a passphrase is required")]
    PassphraseRequired,
    /// See [`ErrorCode::AgentUnavailable`].
    #[error("ssh-agent unavailable: {0}")]
    AgentUnavailable(String),
    /// See [`ErrorCode::AgentRefused`].
    #[error("ssh-agent refused the request: {0}")]
    AgentRefused(String),
    /// See [`ErrorCode::Unsupported`].
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// See [`ErrorCode::Parse`].
    #[error("parse error: {0}")]
    Parse(String),
    /// See [`ErrorCode::PermissionDenied`].
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    /// See [`ErrorCode::Conflict`].
    #[error("changed on disk: {0}")]
    Conflict(String),
    /// See [`ErrorCode::Io`].
    #[error("I/O error: {context}: {source}")]
    Io {
        /// What was being done (usually the path).
        context: String,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
}

impl Error {
    /// The stable machine-readable code of this error.
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::NotFound(_) => ErrorCode::NotFound,
            Self::AlreadyExists(_) => ErrorCode::AlreadyExists,
            Self::InvalidInput(_) => ErrorCode::InvalidInput,
            Self::WrongPassphrase => ErrorCode::WrongPassphrase,
            Self::PassphraseRequired => ErrorCode::PassphraseRequired,
            Self::AgentUnavailable(_) => ErrorCode::AgentUnavailable,
            Self::AgentRefused(_) => ErrorCode::AgentRefused,
            Self::Unsupported(_) => ErrorCode::Unsupported,
            Self::Parse(_) => ErrorCode::Parse,
            Self::PermissionDenied(_) => ErrorCode::PermissionDenied,
            Self::Conflict(_) => ErrorCode::Conflict,
            Self::Io { .. } => ErrorCode::Io,
        }
    }

    /// The serialisable `{ code, message }` form.
    pub fn info(&self) -> ErrorInfo {
        ErrorInfo {
            code: self.code(),
            message: self.to_string(),
        }
    }

    /// Wraps an I/O error that happened while working on `path`, mapping the
    /// common kinds (`NotFound`, `PermissionDenied`, `AlreadyExists`) onto the
    /// dedicated codes.
    pub(crate) fn io(err: io::Error, path: &Path) -> Self {
        let context = path.display().to_string();
        match err.kind() {
            io::ErrorKind::NotFound => Self::NotFound(context),
            io::ErrorKind::PermissionDenied => Self::PermissionDenied(context),
            io::ErrorKind::AlreadyExists => Self::AlreadyExists(context),
            _ => Self::Io {
                context,
                source: err,
            },
        }
    }

    /// Shorthand for [`Error::InvalidInput`].
    pub(crate) fn invalid(msg: impl Into<String>) -> Self {
        Self::InvalidInput(msg.into())
    }
}

impl Serialize for Error {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.info().serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_as_code_and_message() {
        let err = Error::NotFound("/tmp/x".into());
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "not_found");
        assert_eq!(json["message"], "not found: /tmp/x");
        assert_eq!(err.code().as_str(), "not_found");
    }

    #[test]
    fn every_code_serializes_to_its_str() {
        let all = [
            ErrorCode::NotFound,
            ErrorCode::AlreadyExists,
            ErrorCode::InvalidInput,
            ErrorCode::WrongPassphrase,
            ErrorCode::PassphraseRequired,
            ErrorCode::AgentUnavailable,
            ErrorCode::AgentRefused,
            ErrorCode::Unsupported,
            ErrorCode::Parse,
            ErrorCode::Io,
            ErrorCode::PermissionDenied,
            ErrorCode::Conflict,
            ErrorCode::VaultLocked,
            ErrorCode::Cancelled,
        ];
        for code in all {
            let json = serde_json::to_value(code).unwrap();
            assert_eq!(json, code.as_str());
        }
    }

    #[test]
    fn io_errors_map_to_specific_codes() {
        let p = Path::new("/x");
        let nf = Error::io(io::Error::from(io::ErrorKind::NotFound), p);
        assert_eq!(nf.code(), ErrorCode::NotFound);
        let pd = Error::io(io::Error::from(io::ErrorKind::PermissionDenied), p);
        assert_eq!(pd.code(), ErrorCode::PermissionDenied);
        let other = Error::io(io::Error::other("boom"), p);
        assert_eq!(other.code(), ErrorCode::Io);
    }
}
