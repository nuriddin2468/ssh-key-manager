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
//! A session is batch ([`Server::session`]) or interactive
//! ([`Server::interactive_session`]). A batch session is for an `ssh` run
//! nobody watches, and decides what is answered, whatever the responder says:
//!
//! - host-key and other yes/no questions are always answered "no", so a host
//!   key is never trusted behind the user's back;
//! - each secret is given at most once per session (a password asked again
//!   means the first one was wrong; answering again would only loop);
//! - prompts naming another account than the one expected (for example a
//!   `ProxyJump` host's password) are refused.
//!
//! An interactive session is for a terminal the user watches. Its
//! [`Interactive`] responder can ask the user, so it is also asked about host
//! keys, secrets asked again and other accounts' prompts, and told which of
//! these it is. Other yes/no questions are still answered "no".
//!
//! Either way everything is recorded ([`Session::asked`]) so the caller can
//! tell the user "password rejected", "a 2FA code was asked but none is saved"
//! or "the host key is not trusted yet".
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

use std::collections::HashMap;
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
/// How long a helper waits for the answer. A batch session answers in
/// milliseconds; an interactive one may wait up to five minutes for the user,
/// so this is a little longer. (On Windows the helper's pipe read has no
/// timeout.)
#[cfg(unix)]
const HELPER_WAIT: Duration = Duration::from_secs(330);

/// What a responder says to a prompt.
pub enum Reply {
    /// Answer with this secret.
    Secret(SecretString),
    /// Answer "yes" to a host-key question. Only an interactive session sends
    /// it, and only to [`PromptKind::HostKeyConfirm`]; anywhere else it counts
    /// as [`Reply::Refuse`].
    Yes,
    /// Answer "no". Only ever sent to a question of kind
    /// [`PromptKind::Other`] (and, in an interactive session, to a host-key
    /// question); to a secret prompt it counts as [`Reply::Refuse`], so the
    /// word "no" is never sent as a password.
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

/// A prompt of an interactive session and what the session knows about it.
pub struct Ask<'a> {
    pub prompt: &'a Prompt,
    /// The prompt names another account than the one the session expects
    /// (see [`Session::expect_account`]), such as a `ProxyJump` host's.
    pub foreign: bool,
    /// How many times this secret was already given in this session: more
    /// than zero means the server rejected it.
    pub given: u32,
}

/// Answers an interactive session's prompts, usually by asking the user.
///
/// Unlike a [`Responder`] it is asked about host-key questions, secrets given
/// before and prompts naming another account, so it must not answer those
/// with a saved secret by itself: only the user may trust a key, retry a
/// rejected secret or sign in to another host.
pub trait Interactive: Send + Sync + 'static {
    /// Runs on the askpass server's thread and may block while the user
    /// answers; the session's other prompts wait meanwhile.
    fn respond(&self, ask: &Ask<'_>) -> Reply;
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
    /// The same key passphrases without the password and one-time code.
    #[must_use]
    pub fn without_login_secrets(mut self) -> Self {
        self.password = None;
        self.one_time_code = None;
        self
    }

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
pub(crate) fn names_key(shown: &str, path: &Path) -> bool {
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
    /// A host-key question the user answered "yes" (interactive sessions
    /// only).
    Accepted,
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

    /// Opens a batch session whose prompts `responder` answers within the
    /// batch rules (see the [module docs](self)).
    pub fn session(&self, responder: impl Responder) -> Session {
        self.open(Answerer::Batch(Box::new(responder)))
    }

    /// Opens an interactive session, for a terminal the user watches:
    /// host-key questions, secrets asked again and other accounts' prompts go
    /// to `responder` too.
    pub fn interactive_session(&self, responder: impl Interactive) -> Session {
        self.open(Answerer::Interactive(Box::new(responder)))
    }

    fn open(&self, answerer: Answerer) -> Session {
        let token = Token::random();
        let state = Arc::new(SessionState {
            answerer,
            turn: Mutex::new(()),
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
    answerer: Answerer,
    /// Held while a prompt is answered, so prompts of one session are
    /// answered one at a time while the log stays readable.
    turn: Mutex<()>,
    log: Mutex<Log>,
}

enum Answerer {
    Batch(Box<dyn Responder>),
    Interactive(Box<dyn Interactive>),
}

#[derive(Default)]
struct Log {
    account: Option<PromptAccount>,
    /// How often each secret was given, by prompt kind (and key for
    /// passphrases, text for other prompts).
    given: HashMap<(PromptKind, String), u32>,
    asked: Vec<AskedPrompt>,
}

impl SessionState {
    fn log(&self) -> std::sync::MutexGuard<'_, Log> {
        self.log.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Applies the session's rules, asking the responder when they allow.
    fn answer(&self, prompt: Prompt) -> Answer {
        let _turn = self.turn.lock().unwrap_or_else(PoisonError::into_inner);
        let slot = (
            prompt.kind.clone(),
            match prompt.kind {
                PromptKind::Other => prompt.text.clone(),
                _ => String::new(),
            },
        );
        let (foreign, given) = {
            let log = self.log();
            let foreign = matches!(
                (&log.account, &prompt.account),
                (Some(expected), Some(named)) if !named.matches(expected)
            );
            (foreign, log.given.get(&slot).copied().unwrap_or(0))
        };

        let (outcome, answer) = match &self.answerer {
            Answerer::Batch(responder) => batch_rules(responder.as_ref(), &prompt, foreign, given),
            Answerer::Interactive(responder) => interactive_rules(
                responder.as_ref(),
                &Ask {
                    prompt: &prompt,
                    foreign,
                    given,
                },
            ),
        };
        let mut log = self.log();
        if outcome == PromptOutcome::Answered {
            *log.given.entry(slot).or_default() += 1;
        }
        log.asked.push(AskedPrompt { prompt, outcome });
        answer
    }
}

/// A batch session: yes/no questions get "no", other accounts and repeated
/// secrets get nothing, and the responder is asked only about the rest.
fn batch_rules(
    responder: &dyn Responder,
    prompt: &Prompt,
    foreign: bool,
    given: u32,
) -> (PromptOutcome, Answer) {
    if prompt.kind.is_confirmation() {
        (PromptOutcome::Declined, Answer::Text("no".into()))
    } else if foreign {
        (PromptOutcome::Refused, Answer::Refuse)
    } else if given > 0 {
        (PromptOutcome::Repeated, Answer::Refuse)
    } else {
        reply_to(prompt, responder.respond(prompt))
    }
}

/// An interactive session: the responder is asked about everything except
/// yes/no questions other than host keys, which still get "no".
fn interactive_rules(responder: &dyn Interactive, ask: &Ask<'_>) -> (PromptOutcome, Answer) {
    match ask.prompt.kind {
        PromptKind::Confirm => (PromptOutcome::Declined, Answer::Text("no".into())),
        PromptKind::HostKeyConfirm => match responder.respond(ask) {
            Reply::Yes => (PromptOutcome::Accepted, Answer::Text("yes".into())),
            _ => (PromptOutcome::Declined, Answer::Text("no".into())),
        },
        _ => reply_to(ask.prompt, responder.respond(ask)),
    }
}

/// What a reply to anything but a yes/no question comes to.
fn reply_to(prompt: &Prompt, reply: Reply) -> (PromptOutcome, Answer) {
    match reply {
        Reply::Secret(secret) if non_empty(&secret) => {
            (PromptOutcome::Answered, Answer::Text(secret))
        }
        Reply::No if prompt.kind == PromptKind::Other => {
            (PromptOutcome::Declined, Answer::Text("no".into()))
        }
        _ if prompt.kind.is_secret() => (PromptOutcome::Missing, Answer::Refuse),
        _ => (PromptOutcome::Refused, Answer::Refuse),
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

    /// Records what an interactive session asked: (prompt kind, foreign,
    /// given), and replies with `reply`.
    struct Recorder<F> {
        seen: Arc<Mutex<Vec<(PromptKind, bool, u32)>>>,
        reply: F,
    }

    impl<F: Fn(&Ask<'_>) -> Reply + Send + Sync + 'static> Interactive for Recorder<F> {
        fn respond(&self, ask: &Ask<'_>) -> Reply {
            self.seen
                .lock()
                .unwrap()
                .push((ask.prompt.kind.clone(), ask.foreign, ask.given));
            (self.reply)(ask)
        }
    }

    const HOST_KEY: &str = "The authenticity of host 'h (10.0.0.1)' can't be established.\n\
                            ED25519 key fingerprint is SHA256:abc.\nAre you sure you want to \
                            continue connecting (yes/no/[fingerprint])? ";

    #[test]
    fn interactive_sessions_ask_about_host_keys() {
        let server = server();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let trust = Arc::new(Mutex::new(true));
        let session = server.interactive_session(Recorder {
            seen: Arc::clone(&seen),
            reply: {
                let trust = Arc::clone(&trust);
                move |_: &Ask<'_>| {
                    if *trust.lock().unwrap() {
                        Reply::Yes
                    } else {
                        Reply::No
                    }
                }
            },
        });
        assert_eq!(
            ask_session(&server, &session, HOST_KEY).as_deref(),
            Some("yes")
        );
        *trust.lock().unwrap() = false;
        assert_eq!(
            ask_session(&server, &session, HOST_KEY).as_deref(),
            Some("no")
        );
        // Other yes/no questions are not asked about: still "no".
        assert_eq!(
            ask_session(&server, &session, "Accept updated hostkeys? (yes/no): ").as_deref(),
            Some("no")
        );
        let outcomes: Vec<_> = session.asked().iter().map(|a| a.outcome).collect();
        assert_eq!(
            outcomes,
            [
                PromptOutcome::Accepted,
                PromptOutcome::Declined,
                PromptOutcome::Declined
            ]
        );
        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    #[test]
    fn interactive_sessions_ask_again_and_for_other_accounts() {
        let server = server();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let session = server.interactive_session(Recorder {
            seen: Arc::clone(&seen),
            reply: |ask: &Ask<'_>| {
                if ask.prompt.kind == PromptKind::OneTimeCode {
                    Reply::Refuse
                } else {
                    Reply::Secret(format!("try-{}", ask.given).into())
                }
            },
        });
        session.expect_account(PromptAccount::new("alice", "target.example"));
        assert_eq!(
            ask_session(&server, &session, "alice@target.example's password: ").as_deref(),
            Some("try-0")
        );
        assert_eq!(
            ask_session(&server, &session, "(alice@target.example) Password: ").as_deref(),
            Some("try-1")
        );
        assert_eq!(
            ask_session(&server, &session, "bob@jump.example's password: ").as_deref(),
            Some("try-2"),
            "another account's prompt is the responder's to answer"
        );
        assert_eq!(
            ask_session(
                &server,
                &session,
                "(alice@target.example) Verification code: "
            ),
            None
        );
        assert_eq!(
            *seen.lock().unwrap(),
            [
                (PromptKind::Password, false, 0),
                (PromptKind::Password, false, 1),
                (PromptKind::Password, true, 2),
                (PromptKind::OneTimeCode, false, 0),
            ]
        );
        let outcomes: Vec<_> = session.asked().iter().map(|a| a.outcome).collect();
        assert_eq!(
            outcomes,
            [
                PromptOutcome::Answered,
                PromptOutcome::Answered,
                PromptOutcome::Answered,
                PromptOutcome::Missing
            ]
        );
    }

    #[test]
    fn interactive_replies_follow_the_same_rules() {
        let server = server();
        let session = server.interactive_session(Recorder {
            seen: Arc::new(Mutex::new(Vec::new())),
            reply: |ask: &Ask<'_>| match ask.prompt.kind {
                PromptKind::Password => Reply::No,
                PromptKind::Passphrase { .. } => Reply::Yes,
                _ => Reply::Secret(String::new().into()),
            },
        });
        // "no" and "yes" are never sent as secrets; an empty one is none.
        assert_eq!(ask_session(&server, &session, "Password: "), None);
        assert_eq!(
            ask_session(&server, &session, "Enter passphrase for key '/k': "),
            None
        );
        assert_eq!(ask_session(&server, &session, "Verification code: "), None);
        assert!(
            session
                .asked()
                .iter()
                .all(|a| a.outcome == PromptOutcome::Missing)
        );
    }

    #[test]
    fn batch_sessions_never_say_yes() {
        let server = server();
        let session = server.session(|_: &Prompt| Reply::Yes);
        assert_eq!(
            ask_session(&server, &session, HOST_KEY).as_deref(),
            Some("no")
        );
        assert_eq!(ask_session(&server, &session, "Password: "), None);
        assert_eq!(ask_session(&server, &session, "Proceed? "), None);
        let outcomes: Vec<_> = session.asked().iter().map(|a| a.outcome).collect();
        assert_eq!(
            outcomes,
            [
                PromptOutcome::Declined,
                PromptOutcome::Missing,
                PromptOutcome::Refused
            ]
        );
    }

    #[test]
    fn the_log_stays_readable_while_the_user_answers() {
        let server = server();
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let wait = Mutex::new(wait);
        let session = server.interactive_session(Recorder {
            seen: Arc::new(Mutex::new(Vec::new())),
            reply: move |_: &Ask<'_>| {
                let _ = wait.lock().unwrap().recv();
                Reply::Secret("late".into())
            },
        });
        std::thread::scope(|scope| {
            let asking = scope.spawn(|| ask_session(&server, &session, "Password: "));
            std::thread::sleep(Duration::from_millis(100));
            // The responder is still waiting; the log can be read meanwhile.
            assert_eq!(session.asked(), []);
            release.send(()).unwrap();
            assert_eq!(asking.join().unwrap().as_deref(), Some("late"));
        });
        assert_eq!(session.asked()[0].outcome, PromptOutcome::Answered);
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
