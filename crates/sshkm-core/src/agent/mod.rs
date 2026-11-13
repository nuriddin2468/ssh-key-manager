//! A small synchronous client for the system `ssh-agent`.
//!
//! - Unix: the socket in `SSH_AUTH_SOCK` (or an explicit path), with read and
//!   write timeouts. Nothing is sent until the kernel says the process
//!   serving it runs as this user or as root.
//! - Windows: `SSH_AUTH_SOCK` if it names a pipe, else OpenSSH's
//!   `\\.\pipe\openssh-ssh-agent`. A Unix-socket value (Cygwin, MSYS, Git
//!   Bash) is ignored by [`socket_from_env`]; passed to [`AgentClient::new`]
//!   it fails with [`AgentProblem::Unsupported`]. Nothing is sent over a pipe
//!   until [`set_pipe_check`]'s check has passed.
//!
//! Every call opens a fresh connection. Supported requests: list identities,
//! add (optionally with lifetime / confirm constraints), remove one, remove
//! all.
//!
//! Not supported (yet): `PuTTY`'s Pageant, which uses a different IPC
//! mechanism on Windows (a hidden window and `WM_COPYDATA`; newer versions also
//! offer a named pipe whose name depends on the user). Users of Pageant can
//! enable Pageant's OpenSSH compatibility or point `SSH_AUTH_SOCK` at its pipe.

#[cfg(unix)]
mod peer;
mod proto;
mod transport;

use std::{
    ffi::OsString,
    fs::File,
    io,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::Duration,
};

use serde::{Deserialize, Serialize};

use self::transport::TransportError;
use crate::{
    Error, Result,
    keys::{KeyAlgorithm, UnlockedKey},
    paths::path_string,
};

/// Default read/write timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// The named pipe of the OpenSSH for Windows agent service.
pub const WINDOWS_OPENSSH_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

/// Checks who serves an agent pipe the client has just opened (Windows); an
/// error refuses the pipe. See [`set_pipe_check`].
pub type PipeCheck = fn(&File) -> io::Result<()>;

static PIPE_CHECK: OnceLock<PipeCheck> = OnceLock::new();

/// Sets the check the client runs on every agent pipe it opens, before it
/// sends anything over it (Windows; elsewhere it is never called). The check
/// must pass only for a pipe served by this user or by the system.
///
/// Any local user can create `\\.\pipe\openssh-ssh-agent` while the OpenSSH
/// agent service is stopped, which it is by default, and would then receive
/// the decrypted keys added to the agent. Telling who serves a pipe takes
/// system calls this crate doesn't make, so the app sets the check at
/// startup; until it has, every pipe is refused. Only the first call counts.
pub fn set_pipe_check(check: PipeCheck) {
    let _ = PIPE_CHECK.set(check);
}

#[cfg_attr(not(windows), allow(dead_code))]
fn pipe_check() -> Option<PipeCheck> {
    PIPE_CHECK.get().copied()
}

/// Why the agent cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum AgentProblem {
    /// `SSH_AUTH_SOCK` is not set (and there is no platform default).
    NotConfigured,
    /// The socket or pipe does not exist (agent not running; on Windows the
    /// "OpenSSH Authentication Agent" service is stopped).
    NotFound,
    /// Nothing is listening on the socket.
    ConnectionRefused,
    /// Access to the socket was denied.
    PermissionDenied,
    /// The agent did not answer in time.
    Timeout,
    /// The peer does not speak the agent protocol.
    ProtocolError,
    /// The kind of agent socket is not supported on this platform.
    Unsupported,
    /// Any other error.
    Other,
}

/// Result of [`AgentClient::status`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct AgentStatus {
    /// The agent answered.
    pub available: bool,
    /// Socket or pipe path that was used.
    pub socket: Option<String>,
    /// Number of loaded identities (when available).
    pub identities: Option<u32>,
    /// Why it is not available.
    pub error: Option<AgentProblem>,
}

/// An identity held by the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct AgentIdentity {
    /// `SHA256:…` fingerprint (of the plain key for certificates, like
    /// `ssh-add -l`); matches [`crate::keys::KeyInfo::fingerprint`].
    pub fingerprint: String,
    /// Algorithm.
    pub algorithm: KeyAlgorithm,
    /// Key type as sent by the agent (e.g. `ssh-ed25519`,
    /// `ssh-ed25519-cert-v01@openssh.com`).
    pub key_type: String,
    /// Key size in bits.
    pub bits: Option<u32>,
    /// Comment the key was added with (often the file path).
    pub comment: String,
    /// One-line OpenSSH public key; pass it to [`AgentClient::remove`].
    pub public_key: String,
    /// The identity is a certificate.
    pub certificate: bool,
}

/// Client for one agent socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentClient {
    socket: PathBuf,
    timeout: Duration,
}

impl AgentClient {
    /// The agent of the current session (see [`socket_from_env`]). Fails with
    /// [`Error::AgentUnavailable`] when there is none.
    pub fn from_env() -> Result<Self> {
        socket_from_env()
            .map(Self::new)
            .ok_or_else(|| Error::AgentUnavailable("SSH_AUTH_SOCK is not set".into()))
    }

    /// A client for an explicit socket (Unix) or pipe (Windows) path.
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Sets the per-request timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The socket or pipe path.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Checks that the agent answers and counts its identities.
    pub fn status(&self) -> AgentStatus {
        let socket = Some(path_string(&self.socket));
        match self
            .raw_request(&[proto::REQUEST_IDENTITIES])
            .map(|reply| proto::parse_identities(&reply))
        {
            Ok(Ok(ids)) => AgentStatus {
                available: true,
                socket,
                identities: Some(u32::try_from(ids.len()).unwrap_or(u32::MAX)),
                error: None,
            },
            Ok(Err(Error::AgentRefused(_))) => AgentStatus {
                // The agent is there but locked (`ssh-add -x`) or restricted.
                available: true,
                socket,
                identities: None,
                error: None,
            },
            Ok(Err(_)) => AgentStatus {
                available: false,
                socket,
                identities: None,
                error: Some(AgentProblem::ProtocolError),
            },
            Err(e) => AgentStatus {
                available: false,
                socket,
                identities: None,
                error: Some(e.problem),
            },
        }
    }

    /// Lists the identities (`SSH_AGENTC_REQUEST_IDENTITIES`).
    pub fn list(&self) -> Result<Vec<AgentIdentity>> {
        let reply = self.request(&[proto::REQUEST_IDENTITIES])?;
        proto::parse_identities(&reply)
    }

    /// Adds a decrypted key. `lifetime_secs` limits how long the agent keeps
    /// it (`ssh-add -t`); `confirm` makes the agent ask before each use
    /// (`ssh-add -c`, needs an askpass program). `comment` is what
    /// `ssh-add -l` shows; `ssh-add` uses the key file's path.
    pub fn add(
        &self,
        key: &UnlockedKey,
        comment: &str,
        lifetime_secs: Option<u32>,
        confirm: bool,
    ) -> Result<()> {
        if lifetime_secs == Some(0) {
            return Err(Error::invalid("lifetime must be at least one second"));
        }
        let msg = proto::add_identity(key.keypair(), comment, lifetime_secs, confirm)?;
        let reply = self.request(&msg)?;
        proto::expect_success(&reply, "adding the key")
    }

    /// Removes one identity, given as a one-line OpenSSH public key (e.g.
    /// [`AgentIdentity::public_key`] or a `.pub` file's contents).
    pub fn remove(&self, public_key: &str) -> Result<()> {
        let blob = proto::public_key_blob(public_key)?;
        let reply = self.request(&proto::remove_identity(&blob)?)?;
        proto::expect_success(&reply, "removing the key (it may not be loaded)")
    }

    /// Removes all identities (`ssh-add -D`).
    pub fn remove_all(&self) -> Result<()> {
        let reply = self.request(&[proto::REMOVE_ALL_IDENTITIES])?;
        proto::expect_success(&reply, "removing all keys")
    }

    fn raw_request(&self, msg: &[u8]) -> Result<Vec<u8>, TransportError> {
        transport::request(&self.socket, self.timeout, msg)
    }

    fn request(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.raw_request(msg).map_err(|e| {
            Error::AgentUnavailable(format!("{}: {}", self.socket.display(), e.detail))
        })
    }
}

/// The agent socket of the current session.
///
/// - Unix: `SSH_AUTH_SOCK` if set and non-empty.
/// - Windows: `SSH_AUTH_SOCK` if it names a pipe, else
///   [`WINDOWS_OPENSSH_PIPE`]. Other values, such as the
///   `/tmp/ssh-XXXX/agent.123` of a Cygwin, MSYS or Git Bash `ssh-agent`, are
///   Unix sockets this client cannot reach, so they are ignored.
pub fn socket_from_env() -> Option<PathBuf> {
    socket_for(std::env::var_os("SSH_AUTH_SOCK"), cfg!(windows))
}

/// [`socket_from_env`] for a given `SSH_AUTH_SOCK` value and platform.
fn socket_for(auth_sock: Option<OsString>, windows: bool) -> Option<PathBuf> {
    let from_env = auth_sock.filter(|s| !s.is_empty()).map(PathBuf::from);
    if windows {
        Some(
            from_env
                .filter(|p| transport::is_pipe_path(p))
                .unwrap_or_else(|| PathBuf::from(WINDOWS_OPENSSH_PIPE)),
        )
    } else {
        from_env
    }
}

/// Status of the session's agent (see [`AgentClient::from_env`]).
pub fn status() -> AgentStatus {
    match AgentClient::from_env() {
        Ok(client) => client.status(),
        Err(_) => AgentStatus {
            available: false,
            socket: None,
            identities: None,
            error: Some(AgentProblem::NotConfigured),
        },
    }
}

#[cfg(test)]
mod tests;
