//! What the client asks the app: a signature from the phone's key, whether
//! to trust a server key, and answers to sign-in prompts.

use sshkm_core::prompt::ServerPrompt;
use zeroize::Zeroizing;

/// The data the phone's key must sign for a server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRequest {
    /// The machine that asks: the destination or a jump host.
    pub alias: String,
    pub user: String,
    /// What to sign with `SHA256withECDSA`: the session's id and the
    /// sign-in request (RFC 4252 §7). Not secret, but only useful to this
    /// server, now.
    pub data: Vec<u8>,
}

/// Why the app didn't sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// The user said no (dismissed the screen lock or the fingerprint).
    Cancelled,
    /// Keystore or the key failed; English for developers.
    Failed(String),
}

/// A server key `known_hosts` doesn't have, for the user to trust or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownHostKey {
    /// The machine: the destination or a jump host.
    pub alias: String,
    /// The name the key would be stored for (`HostName`, or the alias).
    pub host: String,
    pub port: u16,
    /// `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa`, …
    pub key_type: String,
    /// `SHA256:…`, as `ssh-keygen -l` and computers show it.
    pub fingerprint: String,
    /// Types `known_hosts` has other keys of for this host: when not empty,
    /// the server no longer offers the key computers know, which deserves a
    /// stronger warning.
    pub other_types: Vec<String>,
}

/// How the server asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    /// The `password` method: one prompt, the password.
    Password,
    /// `keyboard-interactive`: the server's own prompts (PAM, one-time
    /// codes, …).
    KeyboardInteractive,
}

/// One question in a sign-in prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptItem {
    /// The server's text (for `password`, one the client words).
    pub text: String,
    /// Whether the answer may be shown as typed.
    pub echo: bool,
    /// What it asks for, by the rules desktop and phone share
    /// ([`sshkm_core::prompt`]), so the app can fill it from the vault.
    pub kind: ServerPrompt,
}

/// A set of questions to answer to sign in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthPrompt {
    /// The machine: the destination or a jump host.
    pub alias: String,
    /// The name connected to (`HostName`, or the alias) and port: what the
    /// vault's login for the server is matched by.
    pub host: String,
    pub port: u16,
    pub user: String,
    pub method: AuthMethod,
    /// The server's title and instructions (keyboard-interactive); may be
    /// empty.
    pub name: String,
    pub instructions: String,
    pub prompts: Vec<PromptItem>,
    /// 1 the first time this method asks; more after the server refused
    /// the answers, so an answer filled from the vault isn't sent again
    /// unasked.
    pub attempt: u32,
}

/// What the app does for the client. Every method may take as long as
/// the user does; the connection waits.
#[async_trait::async_trait]
pub trait Callbacks: Send + Sync {
    /// Signs `request.data` with the phone's key (`SHA256withECDSA`) and
    /// returns the signature in DER, as Keystore does. Only called once the
    /// server has said it would accept the key.
    async fn sign(&self, request: SignRequest) -> Result<Vec<u8>, SignError>;

    /// Asks the user whether to trust `key`. `true` connects.
    async fn unknown_host(&self, key: UnknownHostKey) -> bool;

    /// After a yes to [`unknown_host`](Self::unknown_host): the
    /// `known_hosts` line to store, which syncs to computers.
    fn host_key_trusted(&self, line: String);

    /// Answers to `prompt`, one per item, in order; `None` cancels. The
    /// client wipes its copies once they are sent.
    async fn answer(&self, prompt: AuthPrompt) -> Option<Vec<Zeroizing<String>>>;
}
