//! Why a connection didn't open, or why it ended.

use std::fmt;

/// Why a host can't be reached from the phone, whatever the network does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotAvailable {
    /// A line in effect would make `ssh` run a program on the computer
    /// (`ProxyCommand`, `LocalCommand`, `PermitLocalCommand`,
    /// `KnownHostsCommand`, `Match … exec`, …) or read another file
    /// (`Include`).
    RunsProgram {
        /// The keyword as written (`ProxyCommand`, `Match`, …).
        directive: String,
        /// The line's value as written.
        value: String,
    },
    /// A `Match` line may apply whose criteria only `ssh` can evaluate, or
    /// `CanonicalizeHostname` is on (`ssh` reads the files again with the
    /// name it finds).
    Undecided {
        /// The line as written.
        line: String,
    },
    /// A line of the file `ssh` may read differently from the app (an odd
    /// keyword, a control character): it may start another block, so no
    /// host's settings can be trusted.
    OddLine {
        /// The line as written.
        line: String,
    },
}

impl fmt::Display for NotAvailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RunsProgram { directive, .. } => write!(f, "it uses {directive}"),
            Self::Undecided { line } => write!(f, "only ssh can work out `{line}`"),
            Self::OddLine { .. } => write!(f, "a line ssh may read differently"),
        }
    }
}

/// A server key that differs from the one `known_hosts` has for the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyMismatch {
    /// The name the key is looked up by (`HostName`, or the alias).
    pub host: String,
    pub port: u16,
    /// The type of the key the server sent (`ssh-ed25519`, …).
    pub key_type: String,
    /// The `SHA256:…` fingerprint of the key the server sent.
    pub fingerprint: String,
    /// The `SHA256:…` fingerprints `known_hosts` has for the host, of the
    /// same type.
    pub known: Vec<String>,
}

/// What went wrong. Every variant that is about one machine on the way
/// names it by `alias`: the destination, or a `ProxyJump` hop.
///
/// Nothing here holds a password, an answer or session data.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The host's settings need something only `ssh` on a computer does;
    /// nothing was sent over the network.
    #[error("{alias} is not available on the phone: {reason}")]
    NotAvailable { alias: String, reason: NotAvailable },
    /// The settings can't be used: a bad port or time, a jump that goes
    /// round in a circle, a host name that isn't one.
    #[error("the settings of {alias} can't be used: {detail}")]
    BadSettings { alias: String, detail: String },
    /// Neither the host's settings nor the app give a user name.
    #[error("no user name for {alias}")]
    NoUser { alias: String },
    /// The name has no address.
    #[error("{host} has no address")]
    NameNotFound { alias: String, host: String },
    /// The server refused the connection.
    #[error("{host}:{port} refused the connection")]
    Refused {
        alias: String,
        host: String,
        port: u16,
    },
    /// No answer in time (`ConnectTimeout`).
    #[error("{host}:{port} did not answer in time")]
    TimedOut {
        alias: String,
        host: String,
        port: u16,
    },
    /// The network couldn't reach the server.
    #[error("{host}:{port} can't be reached: {detail}")]
    Unreachable {
        alias: String,
        host: String,
        port: u16,
        detail: String,
    },
    /// A jump host couldn't open the way to the next machine.
    #[error("{jump} couldn't connect to {host}:{port}")]
    JumpFailed {
        jump: String,
        alias: String,
        host: String,
        port: u16,
    },
    /// The server's key is not the one `known_hosts` has for the host: the
    /// connection stops, as on computers. Nothing resolves it automatically.
    #[error("the host key of {alias} has changed")]
    HostKeyChanged {
        alias: String,
        mismatch: Box<KeyMismatch>,
    },
    /// The server's key is marked `@revoked` for the host.
    #[error("the host key of {alias} is revoked")]
    HostKeyRevoked {
        alias: String,
        host: String,
        port: u16,
        fingerprint: String,
    },
    /// The user didn't trust a server key `known_hosts` doesn't have.
    #[error("the host key of {alias} was not accepted")]
    UnknownHostDeclined { alias: String },
    /// No algorithm both sides support (a server that offers only `ssh-rsa`
    /// with SHA-1, or `ssh-dss`).
    #[error("{alias} and the phone have no {kind} in common")]
    Incompatible { alias: String, kind: String },
    /// The server accepted none of the ways to sign in that were tried.
    #[error("{user}@{alias} didn't accept the sign-in")]
    AuthFailed {
        alias: String,
        user: String,
        /// What the server still offered at the end, as SSH names them
        /// (`publickey`, `password`, …).
        methods: Vec<String>,
    },
    /// The app's signer failed (not cancelled): the key is gone, Keystore
    /// refused, or it returned something that isn't a signature by the key.
    #[error("the phone's key couldn't sign: {detail}")]
    Signer { alias: String, detail: String },
    /// The user cancelled (a prompt, the screen lock for the key), or the
    /// app stopped asking.
    #[error("cancelled")]
    Cancelled,
    /// The app failed to answer a question or to store a line.
    #[error("the app failed: {detail}")]
    App { detail: String },
    /// The server refused the terminal or the shell.
    #[error("{alias} refused to open a shell")]
    ShellRefused { alias: String },
    /// The connection broke or the server closed it.
    #[error("the connection ended: {detail}")]
    Disconnected { detail: String },
}

impl Error {
    /// The same error, with `alias` filled in where russh couldn't say
    /// which machine it was about.
    pub(crate) fn about(self, alias: &str) -> Self {
        match self {
            Self::Incompatible { alias: a, kind } if a.is_empty() => Self::Incompatible {
                alias: alias.to_owned(),
                kind,
            },
            other => other,
        }
    }
}

impl From<russh::Error> for Error {
    fn from(error: russh::Error) -> Self {
        use russh::AlgorithmKind;
        match error {
            russh::Error::NoCommonAlgo { kind, .. } => Self::Incompatible {
                alias: String::new(),
                kind: match kind {
                    AlgorithmKind::Kex => "key exchange",
                    AlgorithmKind::Key => "host key type",
                    AlgorithmKind::Cipher => "cipher",
                    AlgorithmKind::Mac => "MAC",
                    AlgorithmKind::Compression => "compression",
                }
                .to_owned(),
            },
            other => Self::Disconnected {
                detail: other.to_string(),
            },
        }
    }
}
