//! The app as `ssh`'s askpass program, so `ssh` can ask for a password, a
//! one-time code or a key passphrase without a terminal.
//!
//! Two halves of the same executable:
//!
//! - **Server** ([`Server`]), inside the running app. It listens on a Unix
//!   socket in a fresh private (0700) temporary directory, or on Windows on a
//!   named pipe with a random name that rejects remote clients. A caller opens
//!   a [`Session`] with a [`Responder`] that supplies secrets, and lets the
//!   session [configure](Session::configure) the `ssh` command it runs.
//! - **Helper** ([`run_helper_from_env`]). `ssh` runs the app executable with
//!   the prompt as its argument. `main` notices the `SSHKM_ASKPASS_*`
//!   variables, sends the session's token and the prompt to the server, prints
//!   the reply for `ssh` and exits, before Tauri starts.
//!
//! The session decides what is answered, whatever the responder says:
//!
//! - host-key and other yes/no questions are always answered "no", so a host
//!   key is never trusted behind the user's back;
//! - each secret is given at most once per session (a password asked again
//!   means the first one was wrong; answering again would only loop);
//! - prompts naming another account than the one expected (for example a
//!   `ProxyJump` host's password) are refused;
//! - everything is recorded ([`Session::asked`]) so the caller can tell the
//!   user "password rejected", "a 2FA code was asked but none is saved" or
//!   "the host key is not trusted yet".
//!
//! Secrets are [`SecretString`]s, zeroized when dropped and never logged.
//! Tokens are 256-bit random values compared in constant time; a session's
//! token stops working when the session is dropped.

mod helper;
mod prompt;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
mod wire;

use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use rand_core::{OsRng, RngCore};
use serde::Serialize;
use sshkm_core::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;

pub use helper::{ask, run_helper_from_env};
pub use prompt::{Prompt, PromptAccount, PromptKind};

#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
use windows as platform;

/// Where the helper finds the server: a socket path or a pipe name.
pub const ENDPOINT_VAR: &str = "SSHKM_ASKPASS_ENDPOINT";
/// The session token the helper presents.
pub const TOKEN_VAR: &str = "SSHKM_ASKPASS_TOKEN";

/// How long the server waits for a helper to send its request or read the
/// answer.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// What a responder says to a prompt.
pub enum Reply {
    /// Answer with this secret.
    Secret(SecretString),
    /// Answer "no". Only ever sent to a question of kind
    /// [`PromptKind::Other`]; to a secret prompt it counts as [`Reply::Refuse`],
    /// so the word "no" is never sent as a password.
    No,
    /// Do not answer: the helper exits with status 1 and `ssh` treats the
    /// prompt as cancelled (an empty password, or the next key).
    Refuse,
}

/// Supplies secrets for a session's prompts. The session asks it only about
/// passwords, one-time codes, passphrases and unrecognised prompts, never
/// about yes/no questions, and at most once per secret.
pub trait Responder: Send + Sync + 'static {
    fn respond(&self, prompt: &Prompt) -> Reply;
}

impl<F> Responder for F
where
    F: Fn(&Prompt) -> Reply + Send + Sync + 'static,
{
    fn respond(&self, prompt: &Prompt) -> Reply {
        self(prompt)
    }
}

/// A ready-made responder: secrets the caller (such as the vault) has for one
/// connection. Empty strings count as absent.
#[derive(Default)]
pub struct Secrets {
    /// Answers [`PromptKind::Password`].
    pub password: Option<SecretString>,
    /// Answers [`PromptKind::OneTimeCode`].
    pub one_time_code: Option<SecretString>,
    /// Answer [`PromptKind::Passphrase`] for these key files, matched against
    /// the path `ssh` prints (which it cuts to 100 bytes).
    pub passphrases: Vec<(PathBuf, SecretString)>,
}

impl Secrets {
    pub fn new(password: Option<SecretString>, one_time_code: Option<SecretString>) -> Self {
        Self {
            password: password.filter(non_empty),
            one_time_code: one_time_code.filter(non_empty),
            passphrases: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_passphrase(mut self, key: impl Into<PathBuf>, passphrase: SecretString) -> Self {
        if non_empty(&passphrase) {
            self.passphrases.push((key.into(), passphrase));
        }
        self
    }

    /// No secret at all, so there is nothing to answer prompts with.
    pub fn is_empty(&self) -> bool {
        self.password.is_none() && self.one_time_code.is_none() && self.passphrases.is_empty()
    }
}

impl fmt::Debug for Secrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secrets")
            .field("password", &self.password.is_some())
            .field("one_time_code", &self.one_time_code.is_some())
            .field(
                "passphrases",
                &self.passphrases.iter().map(|(k, _)| k).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl Responder for Secrets {
    fn respond(&self, prompt: &Prompt) -> Reply {
        let secret = match &prompt.kind {
            PromptKind::Password => self.password.as_ref(),
            PromptKind::OneTimeCode => self.one_time_code.as_ref(),
            PromptKind::Passphrase { key } => self
                .passphrases
                .iter()
                .find(|(path, _)| names_key(key, path))
                .map(|(_, passphrase)| passphrase),
            _ => None,
        };
        secret.map_or(Reply::Refuse, |s| Reply::Secret(s.clone()))
    }
}

fn non_empty(secret: &SecretString) -> bool {
    !secret.expose_secret().is_empty()
}

/// Whether `ssh`'s `Enter passphrase for key '…'` names `path`; `ssh` prints at
/// most 100 bytes of it.
fn names_key(shown: &str, path: &Path) -> bool {
    let path = path.to_string_lossy();
    shown == path || (shown.len() == 100 && path.as_bytes().get(..100) == Some(shown.as_bytes()))
}

/// What became of a prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum PromptOutcome {
    /// A secret was given.
    Answered,
    /// A yes/no question was answered "no" (host keys are never trusted this
    /// way).
    Declined,
    /// A secret prompt for which no secret was supplied.
    Missing,
    /// The same secret was asked for again after it was given: the server
    /// rejected it.
    Repeated,
    /// Not answered: an unrecognised prompt, or one naming another account.
    Refused,
}

/// A prompt `ssh` showed during a session and what became of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct AskedPrompt {
    #[serde(flatten)]
    #[cfg_attr(test, ts(flatten))]
    pub prompt: Prompt,
    pub outcome: PromptOutcome,
}

/// The server's half of the askpass helper. Dropping it stops listening and
/// removes the socket.
pub struct Server {
    registry: Arc<Registry>,
    program: PathBuf,
    listener: platform::Listener,
}

impl Server {
    /// Starts listening, with this executable as the askpass program.
    pub fn start() -> io::Result<Self> {
        Self::start_with_program(std::env::current_exe()?)
    }

    /// Starts listening, with `program` as the askpass program, for tests that
    /// run the built app.
    pub fn start_with_program(program: impl Into<PathBuf>) -> io::Result<Self> {
        let registry = Arc::new(Registry::default());
        let listener = platform::Listener::start(Arc::clone(&registry))?;
        Ok(Self {
            registry,
            program: program.into(),
            listener,
        })
    }

    /// The socket path or pipe name helpers connect to.
    pub fn endpoint(&self) -> &OsStr {
        self.listener.endpoint()
    }

    /// Opens a session whose prompts `responder` answers.
    pub fn session(&self, responder: impl Responder) -> Session {
        let token = Token::random();
        let state = Arc::new(SessionState {
            responder: Box::new(responder),
            log: Mutex::new(Log::default()),
        });
        self.registry.insert(token.clone(), Arc::clone(&state));
        Session {
            token,
            state,
            registry: Arc::clone(&self.registry),
            endpoint: self.endpoint().to_owned(),
            program: self.program.clone(),
        }
    }
}

/// One `ssh` run's access to the askpass server. Dropping it revokes the
/// token.
pub struct Session {
    token: Token,
    state: Arc<SessionState>,
    registry: Arc<Registry>,
    endpoint: OsString,
    program: PathBuf,
}

impl Session {
    /// Refuses prompts that name an account other than `account` (the `User`
    /// and `HostName`, or `HostKeyAlias`, of the host being connected to).
    /// Prompts that name no account (passphrases; keyboard-interactive before
    /// OpenSSH 8.5) are still answered.
    pub fn expect_account(&self, account: PromptAccount) {
        self.state.log().account = Some(account);
    }

    /// The environment `ssh` needs to use this session, as set by
    /// [`configure`](Self::configure).
    pub fn env(&self) -> Vec<(&'static str, OsString)> {
        let mut env = vec![
            ("SSH_ASKPASS", self.program.clone().into_os_string()),
            // OpenSSH 8.4+: use askpass even with a terminal or without DISPLAY.
            ("SSH_ASKPASS_REQUIRE", "force".into()),
            (ENDPOINT_VAR, self.endpoint.clone()),
            (TOKEN_VAR, self.token.to_hex().into()),
        ];
        // Older OpenSSH uses askpass only when DISPLAY is set.
        if std::env::var_os("DISPLAY").is_none_or(|v| v.is_empty()) {
            env.push(("DISPLAY", ":0".into()));
        }
        env
    }

    /// Sets up `command` (an `ssh` command) to ask this session: the
    /// [environment](Self::env), and stdin closed.
    pub fn configure(&self, command: &mut Command) {
        command.envs(self.env()).stdin(Stdio::null());
    }

    /// Every prompt so far, in order.
    pub fn asked(&self) -> Vec<AskedPrompt> {
        self.state.log().asked.clone()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.registry.remove(&self.token);
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

/// A random 256-bit session token.
#[derive(Clone)]
struct Token([u8; 32]);

impl Token {
    fn random() -> Self {
        let mut bytes = [0; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    fn to_hex(&self) -> String {
        hex(&self.0)
    }

    fn from_hex(hex: &str) -> Option<Self> {
        let hex = hex.as_bytes();
        if hex.len() != 64 {
            return None;
        }
        let mut bytes = [0; 32];
        let (pairs, _) = hex.as_chunks::<2>();
        for (byte, pair) in bytes.iter_mut().zip(pairs) {
            let digits = std::str::from_utf8(pair).ok()?;
            *byte = u8::from_str_radix(digits, 16).ok()?;
        }
        Some(Self(bytes))
    }

    fn matches(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

/// Lowercase hex digits of `bytes`.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut hex, b| {
            let _ = write!(hex, "{b:02x}");
            hex
        })
}

/// The open sessions, by token.
#[derive(Default)]
struct Registry {
    sessions: Mutex<Vec<(Token, Arc<SessionState>)>>,
}

/// The server's reply to a request.
enum Answer {
    /// The token belongs to no session: say nothing.
    Unknown,
    Refuse,
    Text(SecretString),
}

impl Registry {
    fn sessions(&self) -> std::sync::MutexGuard<'_, Vec<(Token, Arc<SessionState>)>> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn insert(&self, token: Token, state: Arc<SessionState>) {
        self.sessions().push((token, state));
    }

    fn remove(&self, token: &Token) {
        self.sessions().retain(|(t, _)| !t.matches(token));
    }

    /// The session with this token. Every token is compared in full, so the
    /// time taken does not tell how much of a guess was right.
    fn find(&self, token: &str) -> Option<Arc<SessionState>> {
        let candidate = Token::from_hex(token)?;
        let mut found = None;
        for (token, state) in self.sessions().iter() {
            if token.matches(&candidate) {
                found = Some(Arc::clone(state));
            }
        }
        found
    }

    fn answer(&self, request: &wire::Request) -> Answer {
        match self.find(&request.token) {
            None => Answer::Unknown,
            Some(session) => session.answer(Prompt::parse(&request.prompt, &request.hint)),
        }
    }
}

struct SessionState {
    responder: Box<dyn Responder>,
    log: Mutex<Log>,
}

#[derive(Default)]
struct Log {
    account: Option<PromptAccount>,
    /// Secrets already given: the prompt kind (by key for passphrases, by
    /// text for other prompts).
    given: HashSet<(PromptKind, String)>,
    asked: Vec<AskedPrompt>,
}

impl SessionState {
    fn log(&self) -> std::sync::MutexGuard<'_, Log> {
        self.log.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Applies the session's rules, asking the responder when they allow. The
    /// log stays locked meanwhile, so prompts of one session are answered one
    /// at a time.
    fn answer(&self, prompt: Prompt) -> Answer {
        let mut log = self.log();
        let slot = (
            prompt.kind.clone(),
            match prompt.kind {
                PromptKind::Other => prompt.text.clone(),
                _ => String::new(),
            },
        );
        let foreign = matches!(
            (&log.account, &prompt.account),
            (Some(expected), Some(named)) if !named.matches(expected)
        );

        let (outcome, answer) = if prompt.kind.is_confirmation() {
            (PromptOutcome::Declined, Answer::Text("no".into()))
        } else if foreign {
            (PromptOutcome::Refused, Answer::Refuse)
        } else if log.given.contains(&slot) {
            (PromptOutcome::Repeated, Answer::Refuse)
        } else {
            match self.responder.respond(&prompt) {
                Reply::Secret(secret) if non_empty(&secret) => {
                    log.given.insert(slot);
                    (PromptOutcome::Answered, Answer::Text(secret))
                }
                Reply::No if prompt.kind == PromptKind::Other => {
                    (PromptOutcome::Declined, Answer::Text("no".into()))
                }
                _ if prompt.kind.is_secret() => (PromptOutcome::Missing, Answer::Refuse),
                _ => (PromptOutcome::Refused, Answer::Refuse),
            }
        };
        log.asked.push(AskedPrompt { prompt, outcome });
        answer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> Server {
        Server::start_with_program("/opt/sshkm/askpass").unwrap()
    }

    fn env_value(session: &Session, name: &str) -> OsString {
        session
            .env()
            .into_iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v)
            .unwrap()
    }

    /// Asks `session` through the server, as the helper would.
    fn ask_session(server: &Server, session: &Session, prompt: &str) -> Option<String> {
        ask_with(server, &env_value(session, TOKEN_VAR), prompt)
    }

    fn ask_with(server: &Server, token: &OsStr, prompt: &str) -> Option<String> {
        ask(server.endpoint(), &token.to_string_lossy(), "", prompt)
            .ok()
            .flatten()
            .map(|s| s.expose_secret().to_owned())
    }

    fn secrets(password: &str, otp: &str) -> Secrets {
        Secrets::new(Some(password.into()), Some(otp.into()))
    }

    #[test]
    fn tokens() {
        let token = Token::random();
        let hex = token.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(Token::from_hex(&hex).unwrap().matches(&token));
        assert!(!Token::random().matches(&token));
        assert!(Token::from_hex(&hex[..63]).is_none());
        assert!(Token::from_hex(&format!("{hex}0")).is_none());
        assert!(Token::from_hex(&format!("{}zz", &hex[..62])).is_none());
        assert!(Token::from_hex("").is_none());
    }

    #[test]
    fn configures_ssh() {
        let server = server();
        let session = server.session(Secrets::default());
        let mut command = Command::new("ssh");
        session.configure(&mut command);
        let envs: Vec<_> = command.get_envs().collect();
        let get = |name: &str| {
            envs.iter()
                .find(|(n, _)| *n == name)
                .and_then(|(_, v)| *v)
                .map(OsStr::to_os_string)
        };
        assert_eq!(get("SSH_ASKPASS"), Some("/opt/sshkm/askpass".into()));
        assert_eq!(get("SSH_ASKPASS_REQUIRE"), Some("force".into()));
        assert_eq!(get(ENDPOINT_VAR), Some(server.endpoint().to_owned()));
        assert_eq!(get(TOKEN_VAR).unwrap().len(), 64);
        if std::env::var_os("DISPLAY").is_none() {
            assert_eq!(get("DISPLAY"), Some(":0".into()));
        }
        // Each session has its own token.
        assert_ne!(
            env_value(&session, TOKEN_VAR),
            env_value(&server.session(Secrets::default()), TOKEN_VAR)
        );
    }

    #[test]
    fn round_trip() {
        let server = server();
        let session = server.session(secrets("hunter2", "123456"));
        assert_eq!(
            ask_session(&server, &session, "alice@example.com's password: ").as_deref(),
            Some("hunter2")
        );
        assert_eq!(
            ask_session(&server, &session, "(alice@example.com) Verification code: ").as_deref(),
            Some("123456")
        );
        let asked = session.asked();
        assert_eq!(asked.len(), 2);
        assert_eq!(asked[0].prompt.kind, PromptKind::Password);
        assert_eq!(asked[0].outcome, PromptOutcome::Answered);
        assert_eq!(asked[1].prompt.kind, PromptKind::OneTimeCode);
    }

    #[test]
    fn secrets_are_given_once() {
        let server = server();
        let session = server.session(secrets("wrong", ""));
        assert!(ask_session(&server, &session, "(alice@h) Password: ").is_some());
        assert!(ask_session(&server, &session, "alice@h's password: ").is_none());
        assert!(ask_session(&server, &session, "(alice@h) Verification code: ").is_none());
        let outcomes: Vec<_> = session.asked().iter().map(|a| a.outcome).collect();
        assert_eq!(
            outcomes,
            [
                PromptOutcome::Answered,
                PromptOutcome::Repeated,
                PromptOutcome::Missing
            ]
        );
    }

    #[test]
    fn passphrases_are_given_once_per_key() {
        let server = server();
        let session = server.session(
            Secrets::default()
                .with_passphrase("/k/one", "first".into())
                .with_passphrase("/k/two", "second".into()),
        );
        let ask = |key: &str| {
            ask_session(
                &server,
                &session,
                &format!("Enter passphrase for key '{key}': "),
            )
        };
        assert_eq!(ask("/k/one").as_deref(), Some("first"));
        assert_eq!(ask("/k/two").as_deref(), Some("second"));
        assert_eq!(ask("/k/one"), None);
        assert_eq!(ask("/k/three"), None);
        let outcomes: Vec<_> = session.asked().iter().map(|a| a.outcome).collect();
        assert_eq!(
            outcomes,
            [
                PromptOutcome::Answered,
                PromptOutcome::Answered,
                PromptOutcome::Repeated,
                PromptOutcome::Missing
            ]
        );
    }

    #[test]
    fn truncated_key_paths_match() {
        let long = format!("/{}/id_ed25519", "d".repeat(120));
        assert!(names_key(&long[..100], Path::new(&long)));
        assert!(names_key(&long, Path::new(&long)));
        assert!(!names_key(&long[..99], Path::new(&long)));
        assert!(!names_key("/k/one", Path::new("/k/one2")));
    }

    #[test]
    fn confirmations_are_always_no() {
        let server = server();
        // Even a responder that would say yes to everything.
        let session = server.session(|_: &Prompt| Reply::Secret("yes".into()));
        let host_key = "The authenticity of host 'h (10.0.0.1)' can't be established.\nED25519 \
                        key fingerprint is SHA256:abc.\nAre you sure you want to continue \
                        connecting (yes/no/[fingerprint])? ";
        assert_eq!(
            ask_session(&server, &session, host_key).as_deref(),
            Some("no")
        );
        assert_eq!(
            ask_with(
                &server,
                &env_value(&session, TOKEN_VAR),
                "Accept updated hostkeys? (yes/no): "
            )
            .as_deref(),
            Some("no")
        );
        assert!(
            session
                .asked()
                .iter()
                .all(|a| a.outcome == PromptOutcome::Declined)
        );
    }

    #[test]
    fn hint_marks_confirmations() {
        let server = server();
        let session = server.session(|_: &Prompt| Reply::Secret("yes".into()));
        let token = env_value(&session, TOKEN_VAR);
        let answer = ask(
            server.endpoint(),
            &token.to_string_lossy(),
            "confirm",
            "Allow use of key /k?\nKey fingerprint SHA256:abc.",
        )
        .unwrap();
        assert_eq!(answer.unwrap().expose_secret(), "no");
        assert_eq!(session.asked()[0].prompt.kind, PromptKind::Confirm);
    }

    #[test]
    fn other_prompts() {
        let server = server();
        let session = server.session(|prompt: &Prompt| match prompt.text.as_str() {
            "Enter PIN for 'token': " => Reply::Secret("0000".into()),
            "Proceed anyway? " => Reply::No,
            _ => Reply::Refuse,
        });
        assert_eq!(
            ask_session(&server, &session, "Enter PIN for 'token': ").as_deref(),
            Some("0000")
        );
        assert_eq!(
            ask_session(&server, &session, "Enter PIN for 'token': "),
            None
        );
        assert_eq!(
            ask_session(&server, &session, "Proceed anyway? ").as_deref(),
            Some("no")
        );
        assert_eq!(ask_session(&server, &session, "Something else: "), None);
        let outcomes: Vec<_> = session.asked().iter().map(|a| a.outcome).collect();
        assert_eq!(
            outcomes,
            [
                PromptOutcome::Answered,
                PromptOutcome::Repeated,
                PromptOutcome::Declined,
                PromptOutcome::Refused
            ]
        );
    }

    #[test]
    fn no_is_never_a_password() {
        let server = server();
        let session = server.session(|_: &Prompt| Reply::No);
        assert_eq!(ask_session(&server, &session, "Password: "), None);
        assert_eq!(session.asked()[0].outcome, PromptOutcome::Missing);
    }

    #[test]
    fn other_accounts_are_refused() {
        let server = server();
        let session = server.session(secrets("target-password", ""));
        session.expect_account(PromptAccount::new("alice", "target.example"));
        assert_eq!(
            ask_session(&server, &session, "bob@jump.example's password: "),
            None
        );
        assert_eq!(
            ask_session(&server, &session, "(alice@jump.example) Password: "),
            None
        );
        assert_eq!(
            ask_session(&server, &session, "(alice@TARGET.example) Password: ").as_deref(),
            Some("target-password")
        );
        let outcomes: Vec<_> = session.asked().iter().map(|a| a.outcome).collect();
        assert_eq!(
            outcomes,
            [
                PromptOutcome::Refused,
                PromptOutcome::Refused,
                PromptOutcome::Answered
            ]
        );
    }

    #[test]
    fn unknown_tokens_get_nothing() {
        let server = server();
        let session = server.session(secrets("hunter2", ""));
        let token = env_value(&session, TOKEN_VAR);

        let wrong = Token::random().to_hex();
        let err = ask(server.endpoint(), &wrong, "", "Password: ");
        assert!(err.is_err(), "the server hangs up without an answer");
        assert!(ask(server.endpoint(), "not-a-token", "", "Password: ").is_err());
        assert_eq!(session.asked(), []);

        drop(session);
        assert!(
            ask(
                server.endpoint(),
                &token.to_string_lossy(),
                "",
                "Password: "
            )
            .is_err()
        );
    }

    #[test]
    fn empty_secrets_are_absent() {
        let secrets = Secrets::new(Some(String::new().into()), None)
            .with_passphrase("/k", String::new().into());
        assert!(secrets.is_empty());
        assert!(!Secrets::new(None, Some("1".into())).is_empty());
        assert!(!format!("{secrets:?}").contains("SecretBox"));
        let debug = format!("{:?}", Secrets::new(Some("hunter2".into()), None));
        assert!(!debug.contains("hunter2"));
    }

    #[test]
    fn concurrent_sessions_are_separate() {
        let server = server();
        let a = server.session(secrets("password-a", ""));
        let b = server.session(secrets("password-b", ""));
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|i| {
                    let session = if i % 2 == 0 { &a } else { &b };
                    let server = &server;
                    scope.spawn(move || {
                        ask_session(server, session, &format!("(u{i}@h) Password: "))
                    })
                })
                .collect();
            for handle in handles {
                handle.join().unwrap();
            }
        });
        // Each session gave its password once and refused the rest.
        for (session, password) in [(&a, "password-a"), (&b, "password-b")] {
            let asked = session.asked();
            assert_eq!(asked.len(), 4);
            assert_eq!(
                asked
                    .iter()
                    .filter(|p| p.outcome == PromptOutcome::Answered)
                    .count(),
                1,
                "{password}"
            );
        }
    }
}
