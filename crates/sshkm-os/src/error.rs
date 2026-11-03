//! The single error type of the crate.

/// Result alias used throughout the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Error returned by every fallible function of the crate.
///
/// Messages are English text for logs; they never contain secrets. The app
/// should localise by [`Error::code`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// This platform or desktop environment cannot provide the feature at all
    /// (for example, no way to learn about screen locks).
    #[error("not supported on this platform")]
    Unsupported,
    /// The feature exists but cannot be used right now: no biometric hardware,
    /// nothing enrolled, disabled by policy, no credential store running, …
    #[error("unavailable: {0}")]
    Unavailable(String),
    /// The user dismissed the prompt.
    #[error("cancelled by the user")]
    Cancelled,
    /// The operation ran but did not succeed (for example, a fingerprint was
    /// not recognised too many times).
    #[error("failed: {0}")]
    Failed(String),
    /// The credential store reported an error.
    #[error("credential store error: {0}")]
    Store(String),
    /// A key that should be there is gone (for example, a Windows Hello key
    /// after Windows Hello was reset).
    #[error("not found: {0}")]
    NotFound(String),
}

impl Error {
    /// A stable, machine-readable code: `unsupported`, `unavailable`,
    /// `cancelled`, `failed`, `store` or `not_found`.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Unsupported => "unsupported",
            Self::Unavailable(_) => "unavailable",
            Self::Cancelled => "cancelled",
            Self::Failed(_) => "failed",
            Self::Store(_) => "store",
            Self::NotFound(_) => "not_found",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable() {
        let cases = [
            (Error::Unsupported, "unsupported"),
            (Error::Unavailable("x".into()), "unavailable"),
            (Error::Cancelled, "cancelled"),
            (Error::Failed("x".into()), "failed"),
            (Error::Store("x".into()), "store"),
            (Error::NotFound("x".into()), "not_found"),
        ];
        for (err, code) in cases {
            assert_eq!(err.code(), code);
        }
    }

    #[test]
    fn messages_include_the_detail() {
        assert_eq!(
            Error::Unavailable("no Touch ID".into()).to_string(),
            "unavailable: no Touch ID"
        );
        assert_eq!(Error::Cancelled.to_string(), "cancelled by the user");
    }
}
