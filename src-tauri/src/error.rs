//! The error type every command returns. It serialises as `{ code, message }`,
//! the same shape as [`sshkm_core::ErrorInfo`], so the UI handles both alike.

use serde::{Serialize, Serializer};
use sshkm_core::ErrorCode;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error(transparent)]
    Core(#[from] sshkm_core::Error),
    #[error("{message}")]
    App { code: ErrorCode, message: String },
}

impl AppError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::App {
            code,
            message: message.into(),
        }
    }

    pub fn not_found(what: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, what)
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidInput, message)
    }

    fn code(&self) -> ErrorCode {
        match self {
            Self::Core(error) => error.code(),
            Self::App { code, .. } => *code,
        }
    }
}

impl From<tauri::Error> for AppError {
    fn from(error: tauri::Error) -> Self {
        Self::new(ErrorCode::Io, error.to_string())
    }
}

impl From<std::io::Error> for AppError {
    fn from(error: std::io::Error) -> Self {
        Self::new(ErrorCode::Io, error.to_string())
    }
}

impl Serialize for AppError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            code: ErrorCode,
            message: &'a str,
        }
        let message = self.to_string();
        Wire {
            code: self.code(),
            message: &message,
        }
        .serialize(serializer)
    }
}

pub type AppResult<T> = Result<T, AppError>;
