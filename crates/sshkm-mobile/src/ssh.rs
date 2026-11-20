//! SSH for the app: a shell on one of the user's servers, by the host's
//! name, with the host blocks and `known_hosts` the phone carries
//! (`sshkm-ssh`).
//!
//! Kotlin calls [`ssh_open_shell`] with an implementation of
//! [`SshCallbacks`], whose methods are `suspend` functions there: signing
//! with the Keystore key (behind the screen lock), trusting an unknown
//! server key, answering password and one-time-code prompts from the vault
//! or the user. The shell it returns gives output with
//! [`SshShell::next_event`] (one coroutine that keeps asking while the shell
//! is open) and takes input and a new size (in call order), keepalives and
//! `disconnect`.
//!
//! The SSH client runs on a runtime of its own (two threads), so Kotlin's
//! dispatchers never carry it; cancelling a Kotlin call stops the Rust work
//! behind it. Answers and session data are never logged. The Rust copies of
//! answers and of typed bytes are wiped once sent; UniFFI's buffers and
//! Kotlin's strings aren't, and neither are keyboard-interactive answers
//! inside russh (see `sshkm-ssh`'s README).

use std::future::Future;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use sshkm_core::config::SshConfig;
use sshkm_ssh::{self as ssh, Connection, Route};
use tokio::runtime::Runtime;
use zeroize::Zeroizing;

/// The runtime the SSH client runs on.
static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("sshkm-ssh")
        .enable_all()
        .build()
        .expect("the SSH runtime starts")
});

/// Runs `future` on [`RUNTIME`]; dropping the returned future (a cancelled
/// Kotlin coroutine) stops it.
async fn on_runtime<T: Send + 'static>(future: impl Future<Output = T> + Send + 'static) -> T {
    struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);
    impl<T> Drop for AbortOnDrop<T> {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let mut task = AbortOnDrop(RUNTIME.spawn(future));
    match (&mut task.0).await {
        Ok(value) => value,
        // Not cancelled (that drops this future first): the task panicked.
        Err(error) => std::panic::resume_unwind(error.into_panic()),
    }
}

/// What to connect to, and with what.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SshConnectRequest {
    /// The host's name, as the host list shows it.
    pub destination: String,
    /// The host blocks the phone carries (`ssh_config` text).
    pub hosts_config: String,
    /// The `known_hosts` lines the phone carries.
    pub known_hosts: String,
    /// The user for hosts whose settings name none.
    #[uniffi(default = None)]
    pub default_user: Option<String>,
    /// The phone's public key as an OpenSSH line
    /// ([`ssh_public_key_from_spki`]); `None`: prompts and passwords only.
    #[uniffi(default = None)]
    pub public_key: Option<String>,
    /// Keepalive, in seconds, for hosts whose settings set none.
    #[uniffi(default = None)]
    pub keepalive_seconds: Option<u32>,
    /// The terminal's size, in characters.
    pub cols: u32,
    pub rows: u32,
}

/// The data the phone's key must sign.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SshSignRequest {
    /// The machine that asks: the destination or a jump host.
    pub alias: String,
    pub user: String,
    /// What to sign with `SHA256withECDSA`; return the DER signature.
    pub data: Vec<u8>,
}

/// A server key `known_hosts` doesn't have.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SshUnknownHost {
    /// The machine: the destination or a jump host.
    pub alias: String,
    /// The name the key is stored for, and the port.
    pub host: String,
    pub port: u16,
    pub key_type: String,
    /// `SHA256:…`.
    pub fingerprint: String,
    /// Types `known_hosts` has other keys of for this host: when not empty,
    /// the server no longer offers the key computers know.
    pub other_types: Vec<String>,
}

/// What a prompt asks for, so the app can fill it from the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SshPromptKind {
    Password,
    OneTimeCode,
    Other,
}

/// One question.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SshPrompt {
    /// The server's text.
    pub text: String,
    /// Whether the answer may be shown as typed.
    pub echo: bool,
    pub kind: SshPromptKind,
}

/// How the server asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SshAuthMethod {
    Password,
    KeyboardInteractive,
}

/// Questions to answer to sign in.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SshAuthPrompt {
    /// The machine: the destination or a jump host.
    pub alias: String,
    /// The name connected to and port: what the vault's login is matched by.
    pub host: String,
    pub port: u16,
    pub user: String,
    pub method: SshAuthMethod,
    /// The server's title and instructions; may be empty.
    pub name: String,
    pub instructions: String,
    pub prompts: Vec<SshPrompt>,
    /// 1 the first time; more after the server refused the answers.
    pub attempt: u32,
}

/// Why the app didn't sign.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum SshCallbackError {
    /// The user said no (dismissed the screen lock, closed the dialog).
    #[error("cancelled")]
    Cancelled,
    /// Keystore or storage failed; English for developers.
    #[error("{detail}")]
    Failed { detail: String },
}

/// Any other exception a callback throws. A coroutine cancelled under the
/// callback (its dialog's scope closed) cancels the connection; anything
/// else fails it, never panics.
impl From<uniffi::UnexpectedUniFFICallbackError> for SshCallbackError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        if error.reason.contains("CancellationException") {
            Self::Cancelled
        } else {
            Self::Failed {
                detail: error.reason,
            }
        }
    }
}

impl From<SshCallbackError> for ssh::CallbackError {
    fn from(error: SshCallbackError) -> Self {
        match error {
            SshCallbackError::Cancelled => Self::Cancelled,
            SshCallbackError::Failed { detail } => Self::Failed(detail),
        }
    }
}

/// What the app does for the SSH client. The `suspend` methods may take as
/// long as the user does. Every method may throw: `SshCallbackException`
/// (`Cancelled`, `Failed`), or anything else, which fails the connection
/// (a `CancellationException` cancels it).
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait SshCallbacks: Send + Sync {
    /// Signs `request.data` with the phone's key (`SHA256withECDSA`) and
    /// returns the DER signature. Called only once the server has said it
    /// would take the key.
    async fn sign(&self, request: SshSignRequest) -> Result<Vec<u8>, SshCallbackError>;

    /// Whether the user trusts this server key.
    async fn unknown_host(&self, host: SshUnknownHost) -> Result<bool, SshCallbackError>;

    /// After a yes: the `known_hosts` line to store (it syncs to
    /// computers). Called on the connection's own thread: hand the line
    /// over and return at once, never wait for anything here.
    fn host_key_trusted(&self, line: String) -> Result<(), SshCallbackError>;

    /// The answers, one per prompt; `null` cancels.
    async fn answer(&self, prompt: SshAuthPrompt) -> Result<Option<Vec<String>>, SshCallbackError>;
}

/// Hands the client's questions to Kotlin.
struct Bridge(Arc<dyn SshCallbacks>);

#[async_trait::async_trait]
impl ssh::Callbacks for Bridge {
    async fn sign(&self, request: ssh::SignRequest) -> Result<Vec<u8>, ssh::CallbackError> {
        Ok(self
            .0
            .sign(SshSignRequest {
                alias: request.alias,
                user: request.user,
                data: request.data,
            })
            .await?)
    }

    async fn unknown_host(&self, key: ssh::UnknownHostKey) -> Result<bool, ssh::CallbackError> {
        Ok(self
            .0
            .unknown_host(SshUnknownHost {
                alias: key.alias,
                host: key.host,
                port: key.port,
                key_type: key.key_type,
                fingerprint: key.fingerprint,
                other_types: key.other_types,
            })
            .await?)
    }

    fn host_key_trusted(&self, line: String) -> Result<(), ssh::CallbackError> {
        Ok(self.0.host_key_trusted(line)?)
    }

    async fn answer(
        &self,
        prompt: ssh::AuthPrompt,
    ) -> Result<Option<Vec<Zeroizing<String>>>, ssh::CallbackError> {
        let prompt = SshAuthPrompt {
            alias: prompt.alias,
            host: prompt.host,
            port: prompt.port,
            user: prompt.user,
            method: match prompt.method {
                ssh::AuthMethod::Password => SshAuthMethod::Password,
                ssh::AuthMethod::KeyboardInteractive => SshAuthMethod::KeyboardInteractive,
            },
            name: prompt.name,
            instructions: prompt.instructions,
            prompts: prompt
                .prompts
                .into_iter()
                .map(|p| SshPrompt {
                    text: p.text,
                    echo: p.echo,
                    kind: match p.kind {
                        ssh::ServerPrompt::Password => SshPromptKind::Password,
                        ssh::ServerPrompt::OneTimeCode => SshPromptKind::OneTimeCode,
                        ssh::ServerPrompt::Other => SshPromptKind::Other,
                    },
                })
                .collect(),
            attempt: prompt.attempt,
        };
        // The strings move into wiped wrappers. UniFFI's buffer they were
        // read from, and Kotlin's own strings, aren't wiped.
        let answers = self.0.answer(prompt).await?;
        Ok(answers.map(|answers| answers.into_iter().map(Zeroizing::new).collect()))
    }
}

/// Why a host isn't available on the phone.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SshNotAvailable {
    /// A line would make `ssh` run a program (`ProxyCommand`,
    /// `LocalCommand`, `KnownHostsCommand`, `Match … exec`, …).
    RunsProgram { directive: String, value: String },
    /// A `Match` line only `ssh` can evaluate may apply, or
    /// `CanonicalizeHostname` is on.
    Undecided { line: String },
    /// A line of the host blocks `ssh` may read differently from the app.
    OddLine { line: String },
}

/// Why a connection didn't open or a call failed. `alias` names the
/// machine: the destination or a jump host. `detail` is English for
/// developers, never shown, never holding a secret.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum SshError {
    #[error("{alias} is not available on the phone")]
    NotAvailable {
        alias: String,
        reason: SshNotAvailable,
    },
    #[error("bad settings for {alias}: {detail}")]
    BadSettings { alias: String, detail: String },
    #[error("no user name for {alias}")]
    NoUser { alias: String },
    #[error("{host} has no address")]
    NameNotFound { alias: String, host: String },
    #[error("{host}:{port} refused the connection")]
    Refused {
        alias: String,
        host: String,
        port: u16,
    },
    #[error("{host}:{port} did not answer in time")]
    TimedOut {
        alias: String,
        host: String,
        port: u16,
    },
    #[error("{host}:{port} can't be reached: {detail}")]
    Unreachable {
        alias: String,
        host: String,
        port: u16,
        detail: String,
    },
    #[error("{jump} couldn't connect to {host}:{port}")]
    JumpFailed {
        jump: String,
        alias: String,
        host: String,
        port: u16,
    },
    /// The server's key isn't the one `known_hosts` has: never resolved
    /// here.
    #[error("the host key of {alias} has changed")]
    HostKeyChanged {
        alias: String,
        host: String,
        port: u16,
        key_type: String,
        /// The key the server sent.
        fingerprint: String,
        /// The keys `known_hosts` has, of the same type.
        known_fingerprints: Vec<String>,
    },
    #[error("the host key of {alias} is revoked")]
    HostKeyRevoked {
        alias: String,
        host: String,
        port: u16,
        fingerprint: String,
    },
    #[error("the host key of {alias} was not accepted")]
    UnknownHostDeclined { alias: String },
    #[error("{alias} and the phone have no {kind} in common")]
    Incompatible { alias: String, kind: String },
    #[error("{user}@{alias} didn't accept the sign-in")]
    AuthFailed {
        alias: String,
        user: String,
        methods: Vec<String>,
    },
    #[error("the phone's key couldn't sign: {detail}")]
    Signer { alias: String, detail: String },
    #[error("cancelled")]
    Cancelled,
    /// A callback failed (not cancelled); `detail` is what it threw.
    #[error("the app failed: {detail}")]
    App { detail: String },
    #[error("{alias} refused to open a shell")]
    ShellRefused { alias: String },
    #[error("the connection ended: {detail}")]
    Disconnected { detail: String },
    /// Not an OpenSSH `ecdsa-sha2-nistp256` key, or not P-256 DER.
    #[error("not the phone's kind of key")]
    BadKey,
}

impl From<ssh::Error> for SshError {
    fn from(error: ssh::Error) -> Self {
        use ssh::Error as E;
        match error {
            E::NotAvailable { alias, reason } => Self::NotAvailable {
                alias,
                reason: match reason {
                    ssh::NotAvailable::RunsProgram { directive, value } => {
                        SshNotAvailable::RunsProgram { directive, value }
                    }
                    ssh::NotAvailable::Undecided { line } => SshNotAvailable::Undecided { line },
                    ssh::NotAvailable::OddLine { line } => SshNotAvailable::OddLine { line },
                },
            },
            E::BadSettings { alias, detail } => Self::BadSettings { alias, detail },
            E::NoUser { alias } => Self::NoUser { alias },
            E::NameNotFound { alias, host } => Self::NameNotFound { alias, host },
            E::Refused { alias, host, port } => Self::Refused { alias, host, port },
            E::TimedOut { alias, host, port } => Self::TimedOut { alias, host, port },
            E::Unreachable {
                alias,
                host,
                port,
                detail,
            } => Self::Unreachable {
                alias,
                host,
                port,
                detail,
            },
            E::JumpFailed {
                jump,
                alias,
                host,
                port,
            } => Self::JumpFailed {
                jump,
                alias,
                host,
                port,
            },
            E::HostKeyChanged { alias, mismatch } => Self::HostKeyChanged {
                alias,
                host: mismatch.host,
                port: mismatch.port,
                key_type: mismatch.key_type,
                fingerprint: mismatch.fingerprint,
                known_fingerprints: mismatch.known,
            },
            E::HostKeyRevoked {
                alias,
                host,
                port,
                fingerprint,
            } => Self::HostKeyRevoked {
                alias,
                host,
                port,
                fingerprint,
            },
            E::UnknownHostDeclined { alias } => Self::UnknownHostDeclined { alias },
            E::Incompatible { alias, kind } => Self::Incompatible { alias, kind },
            E::AuthFailed {
                alias,
                user,
                methods,
            } => Self::AuthFailed {
                alias,
                user,
                methods,
            },
            E::Signer { alias, detail } => Self::Signer { alias, detail },
            E::Cancelled => Self::Cancelled,
            E::App { detail } => Self::App { detail },
            E::ShellRefused { alias } => Self::ShellRefused { alias },
            E::Disconnected { detail } => Self::Disconnected { detail },
        }
    }
}

/// One machine on the way to a host.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SshHop {
    pub alias: String,
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
}

/// The way to `destination` with the carried host blocks, without
/// connecting: jump hosts first, the destination last. Fails with
/// [`SshError::NotAvailable`] for a host the phone can't connect to, so the
/// host list can say so.
// UniFFI hands arguments over as owned values.
#[allow(clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn ssh_route(hosts_config: String, destination: String) -> Result<Vec<SshHop>, SshError> {
    let route = Route::resolve(&SshConfig::parse(&hosts_config), &destination)?;
    Ok(route
        .hops
        .into_iter()
        .map(|hop| SshHop {
            alias: hop.alias,
            host: hop.host,
            port: hop.port,
            user: hop.user,
        })
        .collect())
}

/// The phone's public key as an OpenSSH line, from what Android's
/// `PublicKey.getEncoded()` gives (X.509 `SubjectPublicKeyInfo`, P-256).
// UniFFI hands arguments over as owned values.
#[allow(clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn ssh_public_key_from_spki(der: Vec<u8>, comment: String) -> Result<String, SshError> {
    let key = ssh::PhoneKey::from_spki_der(&der).map_err(|_| SshError::BadKey)?;
    Ok(key.to_openssh(&comment))
}

/// The `SHA256:…` fingerprint of an OpenSSH public key line.
// UniFFI hands arguments over as owned values.
#[allow(clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn ssh_key_fingerprint(public_key: String) -> Result<String, SshError> {
    let key = ssh::PhoneKey::from_openssh(&public_key).map_err(|_| SshError::BadKey)?;
    Ok(key.fingerprint())
}

/// Connects to `request.destination` and opens a shell on a terminal of
/// `cols` × `rows` (`TERM=xterm-256color`).
#[uniffi::export]
pub async fn ssh_open_shell(
    request: SshConnectRequest,
    callbacks: Arc<dyn SshCallbacks>,
) -> Result<Arc<SshShell>, SshError> {
    let key = request
        .public_key
        .as_deref()
        .map(ssh::PhoneKey::from_openssh)
        .transpose()
        .map_err(|_| SshError::BadKey)?;
    let options = ssh::ConnectOptions {
        default_user: request.default_user,
        key,
        default_keepalive: request
            .keepalive_seconds
            .filter(|s| *s > 0)
            .map(|s| Duration::from_secs(u64::from(s))),
    };
    let size = ssh::PtySize {
        cols: request.cols,
        rows: request.rows,
    };
    let callbacks: Arc<dyn ssh::Callbacks> = Arc::new(Bridge(callbacks));
    let shell = on_runtime(async move {
        let connection = Connection::connect(
            &request.hosts_config,
            &request.known_hosts,
            &request.destination,
            options,
            callbacks,
        )
        .await?;
        connection.open_shell(size).await
    })
    .await?;
    Ok(Arc::new(SshShell::new(shell)))
}

/// Something from the shell.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SshShellEvent {
    /// Bytes for the terminal.
    Output { data: Vec<u8> },
    /// The shell ended; every later call says so again.
    Closed {
        exit_status: Option<u32>,
        exit_signal: Option<String>,
        /// The connection went away before the server closed the shell.
        connection_lost: bool,
    },
}

/// What the user does to the shell, in the order they do it.
enum Input {
    /// Typed or pasted; wiped once sent (it may be a password for `sudo`).
    Data(Zeroizing<Vec<u8>>),
    Resize(ssh::PtySize),
}

/// An open shell. Reading runs on its own; input goes out in the order it
/// is given, through one queue.
#[derive(uniffi::Object)]
pub struct SshShell {
    shell: Arc<ssh::Shell>,
    input: tokio::sync::mpsc::UnboundedSender<Input>,
}

impl SshShell {
    fn new(shell: ssh::Shell) -> Self {
        let shell = Arc::new(shell);
        let (input, mut queue) = tokio::sync::mpsc::unbounded_channel::<Input>();
        let writer = Arc::clone(&shell);
        // Ends when the shell can't take more, or when the object is freed.
        RUNTIME.spawn(async move {
            while let Some(input) = queue.recv().await {
                let sent = match input {
                    Input::Data(data) => writer.write(&data).await,
                    Input::Resize(size) => writer.resize(size).await,
                };
                if sent.is_err() {
                    break;
                }
            }
        });
        Self { shell, input }
    }

    fn send(&self, input: Input) -> Result<(), SshError> {
        self.input.send(input).map_err(|_| SshError::Disconnected {
            detail: "the shell is closed".to_owned(),
        })
    }
}

impl std::fmt::Debug for SshShell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshShell").finish_non_exhaustive()
    }
}

#[uniffi::export]
impl SshShell {
    /// The next thing from the shell. Keep one coroutine asking for as long
    /// as the shell is open, even while the terminal is off screen: while
    /// nobody asks, the whole connection waits, keepalives included.
    pub async fn next_event(&self) -> SshShellEvent {
        let shell = Arc::clone(&self.shell);
        match on_runtime(async move { shell.next_event().await }).await {
            ssh::ShellEvent::Output(data) => SshShellEvent::Output { data },
            ssh::ShellEvent::Closed(closed) => SshShellEvent::Closed {
                exit_status: closed.exit_status,
                exit_signal: closed.exit_signal,
                connection_lost: closed.connection_lost,
            },
        }
    }

    /// Sends what the user typed or pasted. Returns at once; input goes out
    /// in the order of these calls (and of `resize`).
    pub fn write(&self, data: Vec<u8>) -> Result<(), SshError> {
        self.send(Input::Data(Zeroizing::new(data)))
    }

    /// The terminal's new size, in characters, in order with `write`.
    pub fn resize(&self, cols: u32, rows: u32) -> Result<(), SshError> {
        self.send(Input::Resize(ssh::PtySize { cols, rows }))
    }

    /// Asks every machine on the way for an answer now (when the app comes
    /// back to the front, say).
    pub async fn keepalive(&self) -> Result<(), SshError> {
        let shell = Arc::clone(&self.shell);
        Ok(on_runtime(async move { shell.keepalive().await }).await?)
    }

    /// Closes the shell and the connection, jump hosts included. (Not
    /// `close`: Kotlin's `AutoCloseable.close()` frees the object.)
    pub async fn disconnect(&self) {
        let shell = Arc::clone(&self.shell);
        on_runtime(async move { shell.close().await }).await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use russh::keys::PrivateKey;
    use russh::keys::ssh_key::private::Ed25519Keypair;

    use super::*;

    fn block_on<T>(future: impl Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    /// Declines every server key, and remembers what it was asked.
    #[derive(Default)]
    struct Declining {
        asked: StdMutex<Vec<SshUnknownHost>>,
    }

    #[async_trait::async_trait]
    impl SshCallbacks for Declining {
        async fn sign(&self, _request: SshSignRequest) -> Result<Vec<u8>, SshCallbackError> {
            Err(SshCallbackError::Cancelled)
        }
        async fn unknown_host(&self, host: SshUnknownHost) -> Result<bool, SshCallbackError> {
            self.asked.lock().unwrap().push(host);
            Ok(false)
        }
        fn host_key_trusted(&self, _line: String) -> Result<(), SshCallbackError> {
            Ok(())
        }
        async fn answer(
            &self,
            _prompt: SshAuthPrompt,
        ) -> Result<Option<Vec<String>>, SshCallbackError> {
            Ok(None)
        }
    }

    struct Server;
    impl russh::server::Handler for Server {
        type Error = russh::Error;
    }

    /// Lets anyone in and echoes what a shell gets.
    #[derive(Default)]
    struct Echo {
        sessions: Vec<russh::ChannelId>,
    }

    // russh's trait is async; these answer at once.
    #[allow(clippy::unused_async_trait_impl)]
    impl russh::server::Handler for Echo {
        type Error = russh::Error;

        async fn auth_none(&mut self, _user: &str) -> Result<russh::server::Auth, Self::Error> {
            Ok(russh::server::Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            channel: russh::Channel<russh::server::Msg>,
            reply: russh::server::ChannelOpenHandle,
            _session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            self.sessions.push(channel.id());
            reply.accept().await;
            Ok(())
        }

        #[allow(clippy::too_many_arguments)]
        async fn pty_request(
            &mut self,
            channel: russh::ChannelId,
            _term: &str,
            _cols: u32,
            _rows: u32,
            _pix_width: u32,
            _pix_height: u32,
            _modes: &[(russh::Pty, u32)],
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            session.channel_success(channel)
        }

        async fn shell_request(
            &mut self,
            channel: russh::ChannelId,
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            session.channel_success(channel)
        }

        async fn data(
            &mut self,
            channel: russh::ChannelId,
            data: &[u8],
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            if self.sessions.contains(&channel) {
                session.data(channel, data.to_vec())?;
            }
            Ok(())
        }
    }

    /// Trusts every server key.
    struct Trusting;

    #[async_trait::async_trait]
    impl SshCallbacks for Trusting {
        async fn sign(&self, _request: SshSignRequest) -> Result<Vec<u8>, SshCallbackError> {
            Err(SshCallbackError::Cancelled)
        }
        async fn unknown_host(&self, _host: SshUnknownHost) -> Result<bool, SshCallbackError> {
            Ok(true)
        }
        fn host_key_trusted(&self, _line: String) -> Result<(), SshCallbackError> {
            Ok(())
        }
        async fn answer(
            &self,
            _prompt: SshAuthPrompt,
        ) -> Result<Option<Vec<String>>, SshCallbackError> {
            Ok(None)
        }
    }

    /// A server on the bridge's runtime; its port.
    fn serve<H>(handler: impl Fn() -> H + Send + 'static) -> u16
    where
        H: russh::server::Handler + Send + 'static,
    {
        let host_key = PrivateKey::from(Ed25519Keypair::from_seed(&[6; 32]));
        RUNTIME.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let config = Arc::new(russh::server::Config {
                keys: vec![host_key],
                ..russh::server::Config::default()
            });
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let config = Arc::clone(&config);
                    let handler = handler();
                    tokio::spawn(async move {
                        if let Ok(session) =
                            russh::server::run_stream(config, stream, handler).await
                        {
                            let _ = session.await;
                        }
                    });
                }
            });
            port
        })
    }

    fn request(destination: &str, hosts_config: String) -> SshConnectRequest {
        SshConnectRequest {
            destination: destination.to_owned(),
            hosts_config,
            known_hosts: String::new(),
            default_user: Some("alice".into()),
            public_key: None,
            keepalive_seconds: None,
            cols: 80,
            rows: 24,
        }
    }

    #[test]
    fn routes_and_hosts_that_need_ssh() {
        let config = "Host db\n  HostName 10.0.0.9\n  ProxyJump bastion\n\
                      Host bastion\n  User jump\n  Port 2222\n\
                      Host odd\n  ProxyCommand nc %h %p\n";
        assert_eq!(
            ssh_route(config.into(), "db".into()).unwrap(),
            [
                SshHop {
                    alias: "bastion".into(),
                    host: "bastion".into(),
                    port: 2222,
                    user: Some("jump".into()),
                },
                SshHop {
                    alias: "db".into(),
                    host: "10.0.0.9".into(),
                    port: 22,
                    user: None,
                },
            ]
        );
        match ssh_route(config.into(), "odd".into()) {
            Err(SshError::NotAvailable {
                alias,
                reason: SshNotAvailable::RunsProgram { directive, value },
            }) => {
                assert_eq!(alias, "odd");
                assert_eq!(directive, "ProxyCommand");
                assert_eq!(value, "nc %h %p");
            }
            other => panic!("{other:?}"),
        }
        // Opening a shell refuses it the same way, before any network.
        let error = block_on(ssh_open_shell(
            request("odd", config.into()),
            Arc::new(Declining::default()),
        ))
        .unwrap_err();
        assert!(matches!(error, SshError::NotAvailable { .. }), "{error:?}");
    }

    #[test]
    fn keystore_keys_become_openssh_lines() {
        use p256::pkcs8::EncodePublicKey;
        let key = p256::ecdsa::SigningKey::from_bytes(&[9; 32].into()).unwrap();
        let der = key.verifying_key().to_public_key_der().unwrap();
        let line = ssh_public_key_from_spki(der.as_bytes().to_vec(), "phone".into()).unwrap();
        assert!(line.starts_with("ecdsa-sha2-nistp256 "));
        assert!(line.ends_with(" phone"));
        assert!(ssh_key_fingerprint(line).unwrap().starts_with("SHA256:"));
        assert!(matches!(
            ssh_public_key_from_spki(vec![1, 2, 3], String::new()),
            Err(SshError::BadKey)
        ));
        assert!(matches!(
            ssh_key_fingerprint("ssh-ed25519 AAAA".into()),
            Err(SshError::BadKey)
        ));
    }

    #[test]
    fn input_goes_out_in_the_order_given() {
        let port = serve(Echo::default);
        let config = format!("Host echo\n  HostName 127.0.0.1\n  Port {port}\n");
        let shell = block_on(ssh_open_shell(request("echo", config), Arc::new(Trusting))).unwrap();
        // Calls that return at once, as a terminal's key handler makes them.
        let mut expected = Vec::new();
        for i in 0..200u8 {
            let byte = b'a' + i % 26;
            shell.write(vec![byte]).unwrap();
            expected.push(byte);
            if i % 50 == 0 {
                shell.resize(80 + u32::from(i), 24).unwrap();
            }
        }
        let mut echoed = Vec::new();
        block_on(async {
            while echoed.len() < expected.len() {
                match shell.next_event().await {
                    SshShellEvent::Output { data } => echoed.extend(data),
                    SshShellEvent::Closed { .. } => panic!("closed early"),
                }
            }
        });
        assert_eq!(echoed, expected);
        block_on(shell.disconnect());
        assert!(matches!(
            block_on(shell.next_event()),
            SshShellEvent::Closed { .. }
        ));
    }

    #[test]
    fn callback_exceptions_cancel_or_fail() {
        let cancelled = uniffi::UnexpectedUniFFICallbackError::new(
            "kotlinx.coroutines.JobCancellationException: Job was cancelled",
        );
        assert!(matches!(
            SshCallbackError::from(cancelled),
            SshCallbackError::Cancelled
        ));
        let other = uniffi::UnexpectedUniFFICallbackError::new("java.io.IOException: disk full");
        assert!(matches!(
            SshCallbackError::from(other),
            SshCallbackError::Failed { detail } if detail.contains("disk full")
        ));
        assert_eq!(
            ssh::CallbackError::from(SshCallbackError::Cancelled),
            ssh::CallbackError::Cancelled
        );
    }

    #[test]
    fn questions_reach_the_app() {
        let host_key = PrivateKey::from(Ed25519Keypair::from_seed(&[5; 32]));
        let fingerprint = sshkm_ssh::host_keys::fingerprint(host_key.public_key());
        let port = RUNTIME.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let config = Arc::new(russh::server::Config {
                keys: vec![host_key],
                ..russh::server::Config::default()
            });
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let config = Arc::clone(&config);
                    tokio::spawn(async move {
                        if let Ok(session) = russh::server::run_stream(config, stream, Server).await
                        {
                            let _ = session.await;
                        }
                    });
                }
            });
            port
        });
        let app = Arc::new(Declining::default());
        let config = format!("Host web\n  HostName 127.0.0.1\n  Port {port}\n");
        let error = block_on(ssh_open_shell(request("web", config), app.clone())).unwrap_err();
        assert!(
            matches!(&error, SshError::UnknownHostDeclined { alias } if alias == "web"),
            "{error:?}"
        );
        let asked = app.asked.lock().unwrap();
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].fingerprint, fingerprint);
        assert_eq!(asked[0].port, port);
        assert_eq!(asked[0].key_type, "ssh-ed25519");
    }
}
