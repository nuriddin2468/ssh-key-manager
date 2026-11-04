//! What the terminal sends to the UI and receives from it. With `cargo test`
//! these derive `ts_rs::TS` and are written to `src/bindings/`.
//!
//! A session's output reaches the UI over its channel as raw bytes (an
//! `ArrayBuffer` in JavaScript); everything else is a [`TerminalEvent`] (a
//! JSON object) on the same channel, in order.

use serde::{Deserialize, Serialize};
use sshkm_core::{ErrorCode, SecretString};

use crate::askpass::PromptAccount;

/// A session as `terminal_open` and `terminal_list` describe it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct TerminalInfo {
    pub id: u32,
    pub alias: String,
    /// `User` as `ssh -G` resolves it; `None` if `ssh` cannot read its
    /// configuration for the alias.
    pub user: Option<String>,
    /// `HostName` as `ssh -G` resolves it.
    pub host: Option<String>,
    /// `ProxyJump`, if any.
    pub proxy_jump: Option<String>,
    /// RFC 3339, UTC.
    pub started_at: String,
    pub phase: Phase,
}

/// Where a session is, without details (see [`SessionState`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum Phase {
    Connecting,
    Connected,
    Ended,
    Failed,
}

/// Something that happened in a session, other than output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum TerminalEvent {
    /// The session moved on.
    State { state: SessionState },
    /// `ssh` asks something the app cannot answer by itself; answer with
    /// `terminal_answer`. One prompt waits at a time.
    Prompt { prompt: PromptRequest },
    /// The prompt no longer waits.
    PromptClosed { id: u32, reason: PromptClosedReason },
    /// An answer the user chose to save went into the vault, or could not.
    /// Saving waits until the session has signed in, so a wrong password is
    /// never saved.
    Saved {
        target: SavedTarget,
        /// `None` when it was saved.
        error: Option<ErrorCode>,
    },
}

/// A session's state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "phase", rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum SessionState {
    Connecting,
    /// Signed in: the remote session has started.
    Connected {
        #[serde(rename = "signIn")]
        sign_in: SignIn,
    },
    /// `ssh` exited after signing in, or was closed.
    Ended {
        #[serde(rename = "exitCode")]
        exit_code: Option<u32>,
        #[serde(rename = "durationSecs")]
        duration_secs: u32,
    },
    /// `ssh` exited before signing in.
    Failed {
        failure: Failure,
    },
}

impl SessionState {
    pub fn phase(&self) -> Phase {
        match self {
            Self::Connecting => Phase::Connecting,
            Self::Connected { .. } => Phase::Connected,
            Self::Ended { .. } => Phase::Ended,
            Self::Failed { .. } => Phase::Failed,
        }
    }
}

/// Where an answer came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum Source {
    Vault,
    /// The user typed it.
    User,
}

/// What signing in used, for the "Signed in: …" banner. Each field is the
/// last answer of its kind; all `None` means `ssh` asked nothing (a key from
/// the agent or one without a passphrase).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct SignIn {
    pub password: Option<Source>,
    pub one_time_code: Option<Source>,
    /// The key file whose passphrase was asked, as `ssh` named it.
    pub key: Option<String>,
    pub passphrase: Option<Source>,
}

/// Why `ssh` stopped before signing in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct Failure {
    pub reason: FailReason,
    /// For [`FailReason::PasswordRejected`]: the refused password came from
    /// the vault.
    pub saved: bool,
    pub exit_code: Option<u32>,
    /// What `ssh` printed, without terminal escapes. Never holds an answer:
    /// those go through askpass, not the terminal.
    pub output: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum FailReason {
    /// The server refused the password.
    PasswordRejected,
    /// The server refused the 2FA code.
    OneTimeCodeRejected,
    /// A 2FA code was asked and none was given.
    OneTimeCodeMissing,
    /// The server refused the keys and no password was asked.
    NotAccepted,
    /// The user declined a new host key, or `ssh` refused an unknown one.
    HostKeyNotTrusted,
    /// "REMOTE HOST IDENTIFICATION HAS CHANGED": `ssh` stopped.
    HostKeyChanged,
    /// The server could not be reached: no such name, refused, timed out.
    Unreachable,
    /// The user cancelled a password or passphrase prompt.
    Cancelled,
    Other,
}

/// A prompt waiting for the user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct PromptRequest {
    pub id: u32,
    pub ask: PromptAsk,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum PromptAsk {
    Password {
        /// The account the prompt names, if it does.
        account: Option<PromptAccount>,
        why: PasswordWhy,
        save: SaveOffer,
        /// The prompt is for another account than the host's, such as a
        /// `ProxyJump` host's.
        foreign: bool,
    },
    Passphrase {
        /// The key file as `ssh` named it.
        key: String,
        /// A passphrase for this key was given and turned out wrong.
        retry: bool,
        save: SaveOffer,
    },
    OneTimeCode {
        /// The server's question, without the `(user@host)` prefix.
        question: String,
        retry: bool,
        /// The account the prompt names, if it does.
        account: Option<PromptAccount>,
        /// The prompt is for another account than the host's.
        foreign: bool,
    },
    /// `ssh` does not know the server's key yet.
    HostKey {
        /// The host as `ssh` names it in its question: the one whose key it
        /// is, which may be a `ProxyJump` host rather than the tab's.
        host: String,
        /// `ED25519`, `ECDSA`, `RSA`, …
        #[serde(rename = "keyType")]
        key_type: String,
        /// `SHA256:…`
        fingerprint: String,
        /// What `ssh` says besides the plain question (the other names this
        /// key is known by, what DNS says), line by line. Empty for a host
        /// seen for the first time.
        extra: Vec<String>,
        /// A server may have sent the question (OpenSSH before 8.5, with
        /// keyboard-interactive or a proxy), so everything above may be made
        /// up. "Trust" still answers "yes", which trusts a key only if it was
        /// `ssh`'s real question.
        unverified: bool,
    },
    /// Anything else, such as a security key's PIN or a new password, in the
    /// words of whoever sent it: `ssh` or a server, never the app.
    Other {
        /// The question, without the `(user@host)` prefix that `account`
        /// shows.
        text: String,
        /// The account the prompt names, if it does.
        account: Option<PromptAccount>,
        /// The prompt is for another account than the host's.
        foreign: bool,
        /// `ssh` cannot tell which host sent it (OpenSSH before 8.5): it may
        /// be a server's question posing as `ssh`'s own, or another host's.
        /// `text` is then all of it, any account it names included.
        unverified: bool,
    },
}

/// Why a password is asked, which the dialog says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum PasswordWhy {
    /// The server asks for a password.
    Asked,
    /// A key was offered and refused; now the server asks for a password.
    KeyFailed,
    /// The vault's password was given and refused.
    SavedRejected,
    /// The password the user typed was refused, or a 2FA code was.
    Rejected,
}

/// What "Save in the vault" can do for this prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum SaveOffer {
    /// Unlocked, nothing saved yet: save a new entry.
    New,
    /// Unlocked, an entry exists: update it.
    Update,
    /// The vault is locked; unlock it to save.
    Locked,
    /// There is no vault yet.
    NoVault,
    /// Cannot be saved: another account's prompt, a key outside `~/.ssh`, or
    /// a terminal that cannot tell for sure when it signed in (Windows).
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum PromptClosedReason {
    Answered,
    /// Nobody answered for five minutes.
    Timeout,
    /// The session ended or signed in meanwhile.
    Ended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum SavedTarget {
    /// The host entry's password.
    Password,
    /// A key entry's passphrase.
    Passphrase,
}

/// The user's answer to a [`PromptRequest`].
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum PromptAnswer {
    /// A password, code, passphrase or other text.
    Secret {
        #[cfg_attr(test, ts(type = "string"))]
        value: SecretString,
        /// Save it in the vault once signed in (passwords and passphrases).
        #[serde(default)]
        save: bool,
    },
    /// To a host-key question.
    Trust {
        trust: bool,
    },
    Cancel,
}

impl std::fmt::Debug for PromptAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Secret { save, .. } => f.debug_struct("Secret").field("save", save).finish(),
            Self::Trust { trust } => f.debug_struct("Trust").field("trust", trust).finish(),
            Self::Cancel => f.write_str("Cancel"),
        }
    }
}

/// Options of `terminal_open`.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct OpenOptions {
    /// Ask the user for the password instead of giving the saved one (after
    /// the saved one was refused).
    pub ask_password: bool,
}
