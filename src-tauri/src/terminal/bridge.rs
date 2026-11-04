//! The prompt bridge: answers a terminal session's askpass prompts.
//!
//! - A saved secret (the host's password, its current 2FA code, a key's
//!   passphrase) is given automatically, once, and only to prompts for the
//!   host's own account that the session can vouch for.
//! - Anything else becomes a [`TerminalEvent::Prompt`] and waits, up to five
//!   minutes, for the user's [`answer`](Bridge::answer): a secret not saved,
//!   a saved one that was refused, another account's password, a new host
//!   key. A prompt the session cannot vouch for (OpenSSH before 8.5, see
//!   [`crate::askpass::Connection`]) is shown as it is, never as one of the
//!   app's own password or passphrase dialogs.
//! - A host key is offered for trust only when `ssh` asks the plain
//!   question; one of a type the host is not known by, while keys of other
//!   types are, is declined like a changed key. A host-key question the
//!   session cannot vouch for may still be `ssh`'s real one, so it is
//!   offered too, in a dialog that says a server may have sent it.
//! - Answers the user asked to save are kept until the session signs in
//!   ([`Bridge::signed_in`]), then written to the vault
//!   ([`Bridge::save_answers`]); a refused password is never saved. The 2FA
//!   code is never saved. Where signing in cannot be told for sure
//!   (Windows, see [`Options::can_save`]) nothing is offered for saving.
//! - What was used is remembered for the "Signed in: …" banner and for
//!   telling why a session failed ([`Bridge::failure`]).
//!
//! Secrets stay [`SecretString`]s and are never logged.

use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use sshkm_core::SecretString;

use super::Sink;
use super::text::{self, host_key_question};
use super::types::{
    FailReason, Failure, PasswordWhy, PromptAnswer, PromptAsk, PromptClosedReason, PromptRequest,
    SaveOffer, SavedTarget, SignIn, Source, TerminalEvent,
};
use crate::askpass::{Ask, Interactive, PromptKind, Reply};
pub use crate::error::{AppError, AppResult};

/// How long a prompt waits for the user.
pub const ANSWER_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// What a saved answer is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaveTarget {
    /// The host entry's password.
    Password,
    /// The passphrase of this key file (as `ssh` named it).
    Passphrase { key: String },
}

impl SaveTarget {
    fn saved(&self) -> SavedTarget {
        match self {
            Self::Password => SavedTarget::Password,
            Self::Passphrase { .. } => SavedTarget::Passphrase,
        }
    }
}

/// The vault as the bridge sees it. Each call looks again, so a vault locked
/// or unlocked mid-session is noticed at the next prompt.
pub trait Store: Send + Sync + 'static {
    /// The host's saved password, if the vault is unlocked and has one.
    fn password(&self) -> Option<SecretString>;
    /// The host's current 2FA code, if a 2FA secret is saved.
    fn one_time_code(&self) -> Option<SecretString>;
    /// The saved passphrase of the key `ssh` names.
    fn passphrase(&self, key: &str) -> Option<SecretString>;
    /// What "Save in the vault" would do for `target`.
    fn offer(&self, target: &SaveTarget) -> SaveOffer;
    /// Writes `secret` to the entry for `target`, adding one if needed.
    fn save(&self, target: &SaveTarget, secret: &SecretString) -> AppResult<()>;
}

/// Settings of one session's bridge.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// `ssh` offers a key before a password, so a password prompt means the
    /// key was refused.
    pub key_offered: bool,
    /// Do not give the saved password; ask the user (after it was refused).
    pub ask_password: bool,
    /// The session can tell for sure when it signed in (the terminal's raw
    /// mode), so answers may be saved then. Without that (Windows) the first
    /// output only *looks* like the session, and may be the server's banner
    /// before a wrong password: saving is not offered.
    pub can_save: bool,
    pub timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            key_offered: false,
            ask_password: false,
            can_save: true,
            timeout: ANSWER_TIMEOUT,
        }
    }
}

pub struct Bridge {
    store: Box<dyn Store>,
    sink: Arc<dyn Sink>,
    options: Options,
    state: Mutex<State>,
    changed: Condvar,
}

/// A kind of secret, for remembering what was answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Secret {
    Password,
    OneTimeCode,
    Passphrase,
    Other,
}

impl Secret {
    fn of(kind: &PromptKind) -> Self {
        match kind {
            PromptKind::Password => Self::Password,
            PromptKind::OneTimeCode => Self::OneTimeCode,
            PromptKind::Passphrase { .. } => Self::Passphrase,
            _ => Self::Other,
        }
    }
}

#[derive(Default)]
struct State {
    next_id: u32,
    waiting: Option<Waiting>,
    /// The session ended or signed in: prompts get no answer.
    closed: bool,
    sign_in: SignIn,
    /// The last secret given, to tell which one the server refused.
    last_given: Option<Secret>,
    /// The user cancelled (or let time out) a prompt of this kind; later
    /// prompts of the kind are refused without asking again.
    cancelled: Option<Secret>,
    /// `Some(false)` when a host key was declined.
    host_key_trusted: Option<bool>,
    /// A host key was declined because the host is known by keys of other
    /// types.
    host_key_conflict: bool,
    /// Answers to save once signed in.
    to_save: Vec<(SaveTarget, SecretString)>,
    /// Answers to save now: the session signed in.
    ready: Vec<(SaveTarget, SecretString)>,
}

struct Waiting {
    id: u32,
    answer: Option<PromptAnswer>,
}

impl Bridge {
    pub fn new(store: impl Store, sink: Arc<dyn Sink>, options: Options) -> Self {
        Self {
            store: Box::new(store),
            sink,
            options,
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Hands the user's answer to the waiting prompt `id`. Returns false if
    /// that prompt no longer waits.
    pub fn answer(&self, id: u32, answer: PromptAnswer) -> bool {
        let mut state = self.lock();
        match &mut state.waiting {
            Some(waiting) if waiting.id == id && waiting.answer.is_none() => {
                waiting.answer = Some(answer);
                self.changed.notify_all();
                true
            }
            _ => false,
        }
    }

    /// Whether a prompt waits for the user.
    pub fn is_waiting(&self) -> bool {
        self.lock().waiting.is_some()
    }

    /// The session signed in: stops asking and returns what signing in used.
    /// The answers the user chose to save become ready for
    /// [`save_answers`](Self::save_answers).
    pub fn signed_in(&self) -> SignIn {
        let mut state = self.lock();
        state.closed = true;
        self.changed.notify_all();
        let to_save = std::mem::take(&mut state.to_save);
        state.ready.extend(to_save);
        state.sign_in.clone()
    }

    /// The session's output started, and nothing surer tells that it signed
    /// in (Windows): returns what signing in used so far, but keeps answering
    /// prompts and saves nothing, since the output may be the server's banner
    /// or keyboard-interactive text before a password that will be refused.
    pub fn output_started(&self) -> SignIn {
        let mut state = self.lock();
        state.to_save.clear();
        state.sign_in.clone()
    }

    /// Writes the answers ready after signing in to the vault, reporting each
    /// with a [`TerminalEvent::Saved`].
    pub fn save_answers(&self) {
        let ready = std::mem::take(&mut self.lock().ready);
        for (target, secret) in ready {
            let error = match self.store.save(&target, &secret) {
                Ok(()) => None,
                Err(error) => {
                    log::warn!("terminal: could not save an answer in the vault: {error}");
                    Some(error.code())
                }
            };
            self.sink.event(&TerminalEvent::Saved {
                target: target.saved(),
                error,
            });
        }
    }

    /// The session ended: a waiting prompt is cancelled, later ones refused,
    /// and answers to save are dropped.
    pub fn close(&self) {
        let mut state = self.lock();
        state.closed = true;
        state.to_save.clear();
        self.changed.notify_all();
    }

    /// Why a session that exited before signing in failed, from what was
    /// asked and what `ssh` printed (`output`, escapes stripped).
    pub fn failure(&self, output: &str, exit_code: Option<u32>) -> Failure {
        let state = self.lock();
        let reason = fail_reason(&state, output);
        Failure {
            reason,
            saved: reason == FailReason::PasswordRejected
                && state.sign_in.password == Some(Source::Vault),
            exit_code,
            output: output.trim().to_owned(),
        }
    }

    /// Shows `ask` to the user and waits for the answer. `None` when the user
    /// cancelled, nobody answered in time, or the session ended.
    fn ask_user(&self, ask: PromptAsk) -> Option<PromptAnswer> {
        let id = {
            let mut state = self.lock();
            if state.closed {
                return None;
            }
            state.next_id += 1;
            let id = state.next_id;
            state.waiting = Some(Waiting { id, answer: None });
            id
        };
        self.sink.event(&TerminalEvent::Prompt {
            prompt: PromptRequest { id, ask },
        });
        let state = self.lock();
        let (mut state, _) = self
            .changed
            .wait_timeout_while(state, self.options.timeout, |state| {
                !state.closed && state.waiting.as_ref().is_some_and(|w| w.answer.is_none())
            })
            .unwrap_or_else(PoisonError::into_inner);
        let answer = state.waiting.take().and_then(|waiting| waiting.answer);
        let reason = if answer.is_some() {
            PromptClosedReason::Answered
        } else if state.closed {
            PromptClosedReason::Ended
        } else {
            PromptClosedReason::Timeout
        };
        drop(state);
        self.sink.event(&TerminalEvent::PromptClosed { id, reason });
        match answer {
            Some(PromptAnswer::Cancel) | None => None,
            answer => answer,
        }
    }

    /// Asks the user for a secret of kind `secret`; records the answer, and
    /// what to save if the user asked.
    fn ask_secret(&self, secret: Secret, ask: PromptAsk, save: Option<SaveTarget>) -> Reply {
        if self.lock().cancelled == Some(secret) {
            return Reply::Refuse;
        }
        let Some(PromptAnswer::Secret {
            value,
            save: wanted,
        }) = self.ask_user(ask)
        else {
            let mut state = self.lock();
            if !state.closed {
                state.cancelled = Some(secret);
            }
            return Reply::Refuse;
        };
        let mut state = self.lock();
        state.last_given = Some(secret);
        if let Some(target) = save {
            // A new answer replaces one given before for the same thing:
            // that one was wrong.
            state.to_save.retain(|(t, _)| *t != target);
            if wanted {
                state.to_save.push((target, value.clone()));
            }
        }
        Reply::Secret(value)
    }

    fn password(&self, ask: &Ask<'_>) -> Reply {
        let from_vault = self.lock().sign_in.password == Some(Source::Vault);
        if !ask.foreign
            && ask.given == 0
            && !self.options.ask_password
            && let Some(secret) = self.store.password()
        {
            let mut state = self.lock();
            state.sign_in.password = Some(Source::Vault);
            state.last_given = Some(Secret::Password);
            return Reply::Secret(secret);
        }
        let last = self.lock().last_given;
        let why = if ask.given > 0 && from_vault && last == Some(Secret::Password) {
            PasswordWhy::SavedRejected
        } else if ask.given > 0 {
            PasswordWhy::Rejected
        } else if self.options.key_offered && !ask.foreign {
            PasswordWhy::KeyFailed
        } else {
            PasswordWhy::Asked
        };
        let save = (!ask.foreign).then_some(SaveTarget::Password);
        let offer = save
            .as_ref()
            .map_or(SaveOffer::None, |target| self.offer(target));
        let reply = self.ask_secret(
            Secret::Password,
            PromptAsk::Password {
                account: ask.prompt.account.clone(),
                why,
                save: offer,
                foreign: ask.foreign,
            },
            save.filter(|_| matches!(offer, SaveOffer::New | SaveOffer::Update)),
        );
        if matches!(reply, Reply::Secret(_)) && !ask.foreign {
            self.lock().sign_in.password = Some(Source::User);
        }
        reply
    }

    fn one_time_code(&self, ask: &Ask<'_>) -> Reply {
        if !ask.foreign
            && ask.given == 0
            && let Some(code) = self.store.one_time_code()
        {
            let mut state = self.lock();
            state.sign_in.one_time_code = Some(Source::Vault);
            state.last_given = Some(Secret::OneTimeCode);
            return Reply::Secret(code);
        }
        let reply = self.ask_secret(
            Secret::OneTimeCode,
            PromptAsk::OneTimeCode {
                question: ask.prompt.question().to_owned(),
                retry: ask.given > 0,
                account: ask.prompt.account.clone(),
                foreign: ask.foreign,
            },
            None,
        );
        if matches!(reply, Reply::Secret(_)) && !ask.foreign {
            self.lock().sign_in.one_time_code = Some(Source::User);
        }
        reply
    }

    fn passphrase(&self, ask: &Ask<'_>, key: &str) -> Reply {
        // Only `ssh` asks for a key's passphrase, and it names no account.
        if ask.foreign {
            return Reply::Refuse;
        }
        let record = |source| {
            let mut state = self.lock();
            state.sign_in.key = Some(key.to_owned());
            state.sign_in.passphrase = Some(source);
            state.last_given = Some(Secret::Passphrase);
        };
        if ask.given == 0
            && let Some(passphrase) = self.store.passphrase(key)
        {
            record(Source::Vault);
            return Reply::Secret(passphrase);
        }
        let target = SaveTarget::Passphrase {
            key: key.to_owned(),
        };
        let offer = self.offer(&target);
        let reply = self.ask_secret(
            Secret::Passphrase,
            PromptAsk::Passphrase {
                key: key.to_owned(),
                retry: ask.given > 0,
                save: offer,
            },
            matches!(offer, SaveOffer::New | SaveOffer::Update).then_some(target),
        );
        if matches!(reply, Reply::Secret(_)) {
            record(Source::User);
        }
        reply
    }

    /// Shows the prompt's text as it is, for the user to answer: an
    /// unrecognised prompt, or one the session cannot vouch for (`secret`
    /// then says what it claims to ask, for telling why a session failed).
    fn as_it_is(&self, ask: &Ask<'_>, secret: Secret) -> Reply {
        let prompt = ask.prompt;
        let shown = if ask.unverified {
            // Whatever account it names may be made up: show all of it.
            PromptAsk::Other {
                text: prompt.text.trim().to_owned(),
                account: None,
                foreign: false,
                unverified: true,
            }
        } else {
            PromptAsk::Other {
                text: prompt.question().to_owned(),
                account: prompt.account.clone(),
                foreign: ask.foreign,
                unverified: false,
            }
        };
        self.ask_secret(secret, shown, None)
    }

    /// What "Save in the vault" would do for `target`, if saving is possible
    /// at all.
    fn offer(&self, target: &SaveTarget) -> SaveOffer {
        if self.options.can_save {
            self.store.offer(target)
        } else {
            SaveOffer::None
        }
    }

    /// Asks the user whether to trust a new host key. One the session cannot
    /// vouch for is still asked about, since it may be `ssh`'s real question,
    /// but the dialog then says that a server may have sent it.
    fn host_key(&self, ask: &Ask<'_>) -> Reply {
        // Only the "unknown key" question is offered for trust; other
        // warnings (a key that differs from the IP address's) are declined.
        let Some(question) = host_key_question(&ask.prompt.text) else {
            self.lock().host_key_trusted = Some(false);
            return Reply::No;
        };
        // `ssh` prefers the key types it knows for a host, so a known host
        // offers one of another type only once it has dropped those, or when
        // the connection is intercepted. One click must not trust that: it is
        // declined like a changed key, for the user to compare in Known hosts.
        if question.other_types_known {
            let mut state = self.lock();
            state.host_key_trusted = Some(false);
            state.host_key_conflict = true;
            return Reply::No;
        }
        let trusted = matches!(
            self.ask_user(PromptAsk::HostKey {
                host: question.host,
                key_type: question.key_type,
                fingerprint: question.fingerprint,
                extra: question.extra,
                unverified: ask.unverified,
            }),
            Some(PromptAnswer::Trust { trust: true })
        );
        self.lock().host_key_trusted = Some(trusted);
        if trusted { Reply::Yes } else { Reply::No }
    }
}

impl Interactive for Arc<Bridge> {
    fn respond(&self, ask: &Ask<'_>) -> Reply {
        if self.lock().closed {
            return Reply::Refuse;
        }
        match &ask.prompt.kind {
            PromptKind::HostKeyConfirm => self.host_key(ask),
            // The session answers other yes/no questions itself.
            PromptKind::Confirm => Reply::No,
            // It may not be what it says: no saved secret, and not the app's
            // own password or passphrase dialog.
            kind if ask.unverified => self.as_it_is(ask, Secret::of(kind)),
            PromptKind::Password => self.password(ask),
            PromptKind::OneTimeCode => self.one_time_code(ask),
            PromptKind::Passphrase { key } => self.passphrase(ask, key),
            PromptKind::Other => self.as_it_is(ask, Secret::Other),
        }
    }
}

fn fail_reason(state: &State, output: &str) -> FailReason {
    if text::says_host_key_changed(output) || state.host_key_conflict {
        FailReason::HostKeyChanged
    } else if state.host_key_trusted == Some(false) || text::says_host_key_failed(output) {
        FailReason::HostKeyNotTrusted
    } else if text::says_unreachable(output) {
        FailReason::Unreachable
    } else if state.cancelled == Some(Secret::OneTimeCode) {
        FailReason::OneTimeCodeMissing
    } else if state.cancelled.is_some() {
        FailReason::Cancelled
    } else if !text::says_permission_denied(output) {
        FailReason::Other
    } else {
        match state.last_given {
            Some(Secret::OneTimeCode) => FailReason::OneTimeCodeRejected,
            Some(Secret::Password) => FailReason::PasswordRejected,
            _ => FailReason::NotAccepted,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::thread;

    use sshkm_core::{ErrorCode, ExposeSecret};

    use super::*;
    use crate::askpass::{Prompt, PromptAccount};
    use crate::error::AppError;

    /// A vault: saved secrets, the offer it makes and what was saved.
    #[derive(Default)]
    struct FakeStore {
        password: Option<&'static str>,
        code: Option<&'static str>,
        passphrase: Option<&'static str>,
        offer: Option<SaveOffer>,
        fail_saves: bool,
        saved: Arc<Mutex<Vec<(SaveTarget, String)>>>,
    }

    impl Store for FakeStore {
        fn password(&self) -> Option<SecretString> {
            self.password.map(SecretString::from)
        }
        fn one_time_code(&self) -> Option<SecretString> {
            self.code.map(SecretString::from)
        }
        fn passphrase(&self, _key: &str) -> Option<SecretString> {
            self.passphrase.map(SecretString::from)
        }
        fn offer(&self, _target: &SaveTarget) -> SaveOffer {
            self.offer.unwrap_or(SaveOffer::New)
        }
        fn save(&self, target: &SaveTarget, secret: &SecretString) -> AppResult<()> {
            if self.fail_saves {
                return Err(AppError::new(ErrorCode::VaultLocked, "locked"));
            }
            self.saved
                .lock()
                .unwrap()
                .push((target.clone(), secret.expose_secret().to_owned()));
            Ok(())
        }
    }

    /// Collects events; prompts are also sent to `prompts` so a test can
    /// answer them.
    struct Events {
        events: Mutex<Vec<TerminalEvent>>,
        prompts: Mutex<mpsc::Sender<PromptRequest>>,
    }

    impl Sink for Events {
        fn event(&self, event: &TerminalEvent) {
            if let TerminalEvent::Prompt { prompt } = event {
                let _ = self.prompts.lock().unwrap().send(prompt.clone());
            }
            self.events.lock().unwrap().push(event.clone());
        }
        fn output(&self, _bytes: &[u8]) {}
    }

    struct Harness {
        bridge: Arc<Bridge>,
        events: Arc<Events>,
        prompts: mpsc::Receiver<PromptRequest>,
        saved: Arc<Mutex<Vec<(SaveTarget, String)>>>,
    }

    fn harness(store: FakeStore, options: Options) -> Harness {
        let saved = Arc::clone(&store.saved);
        let (tx, prompts) = mpsc::channel();
        let events = Arc::new(Events {
            events: Mutex::new(Vec::new()),
            prompts: Mutex::new(tx),
        });
        let bridge = Arc::new(Bridge::new(
            store,
            Arc::clone(&events) as Arc<dyn Sink>,
            options,
        ));
        Harness {
            bridge,
            events,
            prompts,
            saved,
        }
    }

    impl Harness {
        /// Asks as the session would, answering the user's prompt (if one is
        /// shown) with `answer`.
        fn ask(
            &self,
            text: &str,
            given: u32,
            foreign: bool,
            answer: Option<PromptAnswer>,
        ) -> (Reply, Option<PromptAsk>) {
            self.ask_unverified(text, given, foreign, false, answer)
        }

        /// [`ask`](Self::ask) for a prompt the session may not vouch for.
        fn ask_unverified(
            &self,
            text: &str,
            given: u32,
            foreign: bool,
            unverified: bool,
            answer: Option<PromptAnswer>,
        ) -> (Reply, Option<PromptAsk>) {
            let prompt = Prompt::parse(text, "");
            let bridge = &self.bridge;
            thread::scope(|scope| {
                let asking = scope.spawn(|| {
                    bridge.respond(&Ask {
                        prompt: &prompt,
                        foreign,
                        unverified,
                        given,
                    })
                });
                let shown = match answer {
                    Some(answer) => {
                        let request = self
                            .prompts
                            .recv_timeout(Duration::from_secs(5))
                            .expect("the user is asked");
                        assert!(self.bridge.answer(request.id, answer));
                        Some(request.ask)
                    }
                    None => None,
                };
                (asking.join().unwrap(), shown)
            })
        }

        fn events(&self) -> Vec<TerminalEvent> {
            self.events.events.lock().unwrap().clone()
        }
    }

    fn secret(reply: &Reply) -> Option<&str> {
        match reply {
            Reply::Secret(secret) => Some(secret.expose_secret()),
            _ => None,
        }
    }

    /// The user types `value`: the `answer` argument of [`Harness::ask`].
    #[allow(clippy::unnecessary_wraps, reason = "reads as the answer argument")]
    fn typed(value: &str, save: bool) -> Option<PromptAnswer> {
        Some(PromptAnswer::Secret {
            value: value.to_owned().into(),
            save,
        })
    }

    const PASSWORD: &str = "(ubuntu@10.0.4.12) Password: ";
    const CODE: &str = "(ubuntu@10.0.4.12) Verification code: ";

    #[test]
    fn saved_secrets_are_given_once_then_the_user_is_asked() {
        let h = harness(
            FakeStore {
                password: Some("saved-pw"),
                code: Some("123456"),
                offer: Some(SaveOffer::Update),
                ..FakeStore::default()
            },
            Options::default(),
        );
        let (reply, shown) = h.ask(PASSWORD, 0, false, None);
        assert_eq!(secret(&reply), Some("saved-pw"));
        assert!(shown.is_none(), "answered without asking");
        let (reply, _) = h.ask(CODE, 0, false, None);
        assert_eq!(secret(&reply), Some("123456"));

        // The code was refused, so the password is asked for again: not
        // "the saved password didn't work".
        let (reply, shown) = h.ask(PASSWORD, 1, false, typed("typed-pw", true));
        assert_eq!(secret(&reply), Some("typed-pw"));
        assert_eq!(
            shown,
            Some(PromptAsk::Password {
                account: Some(PromptAccount::new("ubuntu", "10.0.4.12")),
                why: PasswordWhy::Rejected,
                save: SaveOffer::Update,
                foreign: false,
            })
        );
    }

    #[test]
    fn a_refused_saved_password_falls_back_to_the_user() {
        let h = harness(
            FakeStore {
                password: Some("old"),
                offer: Some(SaveOffer::Update),
                ..FakeStore::default()
            },
            Options::default(),
        );
        assert_eq!(secret(&h.ask(PASSWORD, 0, false, None).0), Some("old"));
        let (reply, shown) = h.ask(PASSWORD, 1, false, typed("new", true));
        assert_eq!(secret(&reply), Some("new"));
        assert!(matches!(
            shown,
            Some(PromptAsk::Password {
                why: PasswordWhy::SavedRejected,
                save: SaveOffer::Update,
                ..
            })
        ));
        // Saved only once signed in, and only the answer that worked.
        assert!(h.saved.lock().unwrap().is_empty());
        let sign_in = h.bridge.signed_in();
        h.bridge.save_answers();
        assert_eq!(sign_in.password, Some(Source::User));
        assert_eq!(
            *h.saved.lock().unwrap(),
            [(SaveTarget::Password, "new".to_owned())]
        );
        assert!(h.events().contains(&TerminalEvent::Saved {
            target: SavedTarget::Password,
            error: None
        }));
    }

    #[test]
    fn asks_when_nothing_is_saved_and_says_why() {
        let h = harness(
            FakeStore::default(),
            Options {
                key_offered: true,
                ..Options::default()
            },
        );
        let (reply, shown) = h.ask(
            "ubuntu@10.0.4.12's password: ",
            0,
            false,
            typed("pw", false),
        );
        assert_eq!(secret(&reply), Some("pw"));
        assert!(matches!(
            shown,
            Some(PromptAsk::Password {
                why: PasswordWhy::KeyFailed,
                save: SaveOffer::New,
                ..
            })
        ));
        // A wrong typed password: asked again, and the first is not saved.
        let (_, shown) = h.ask(
            "ubuntu@10.0.4.12's password: ",
            1,
            false,
            typed("pw2", false),
        );
        assert!(matches!(
            shown,
            Some(PromptAsk::Password {
                why: PasswordWhy::Rejected,
                ..
            })
        ));
        h.bridge.signed_in();
        h.bridge.save_answers();
        assert!(h.saved.lock().unwrap().is_empty(), "the user did not ask");
    }

    #[test]
    fn ask_password_skips_the_saved_one() {
        let h = harness(
            FakeStore {
                password: Some("saved"),
                ..FakeStore::default()
            },
            Options {
                ask_password: true,
                ..Options::default()
            },
        );
        let (reply, shown) = h.ask(PASSWORD, 0, false, typed("typed", false));
        assert_eq!(secret(&reply), Some("typed"));
        assert!(shown.is_some());
    }

    #[test]
    fn other_accounts_never_get_saved_secrets() {
        let h = harness(
            FakeStore {
                password: Some("target-pw"),
                code: Some("123456"),
                ..FakeStore::default()
            },
            Options::default(),
        );
        let (reply, shown) = h.ask(
            "bob@jump.example's password: ",
            0,
            true,
            typed("jump-pw", true),
        );
        assert_eq!(secret(&reply), Some("jump-pw"));
        assert_eq!(
            shown,
            Some(PromptAsk::Password {
                account: Some(PromptAccount::new("bob", "jump.example")),
                why: PasswordWhy::Asked,
                save: SaveOffer::None,
                foreign: true,
            })
        );
        let (reply, shown) = h.ask(
            "(bob@jump.example) Verification code: ",
            0,
            true,
            typed("9", false),
        );
        assert_eq!(secret(&reply), Some("9"));
        assert_eq!(
            shown,
            Some(PromptAsk::OneTimeCode {
                question: "Verification code:".into(),
                retry: false,
                account: Some(PromptAccount::new("bob", "jump.example")),
                foreign: true,
            })
        );
        h.bridge.signed_in();
        h.bridge.save_answers();
        assert!(
            h.saved.lock().unwrap().is_empty(),
            "nothing to save for another host"
        );
        assert_eq!(h.bridge.lock().sign_in, SignIn::default());
    }

    #[test]
    fn passphrases_from_the_vault_and_the_user() {
        let key = "Enter passphrase for key '/Users/dev/.ssh/id_ed25519_work': ";
        let h = harness(
            FakeStore {
                passphrase: Some("saved-pp"),
                ..FakeStore::default()
            },
            Options::default(),
        );
        assert_eq!(secret(&h.ask(key, 0, false, None).0), Some("saved-pp"));
        let (reply, shown) = h.ask(key, 1, false, typed("typed-pp", true));
        assert_eq!(secret(&reply), Some("typed-pp"));
        assert_eq!(
            shown,
            Some(PromptAsk::Passphrase {
                key: "/Users/dev/.ssh/id_ed25519_work".into(),
                retry: true,
                save: SaveOffer::New,
            })
        );
        let sign_in = h.bridge.signed_in();
        h.bridge.save_answers();
        assert_eq!(
            sign_in.key.as_deref(),
            Some("/Users/dev/.ssh/id_ed25519_work")
        );
        assert_eq!(sign_in.passphrase, Some(Source::User));
        assert_eq!(
            *h.saved.lock().unwrap(),
            [(
                SaveTarget::Passphrase {
                    key: "/Users/dev/.ssh/id_ed25519_work".into()
                },
                "typed-pp".to_owned()
            )]
        );
    }

    #[test]
    fn a_locked_vault_offers_no_save() {
        let h = harness(
            FakeStore {
                offer: Some(SaveOffer::Locked),
                ..FakeStore::default()
            },
            Options::default(),
        );
        let (_, shown) = h.ask(PASSWORD, 0, false, typed("pw", true));
        assert!(matches!(
            shown,
            Some(PromptAsk::Password {
                save: SaveOffer::Locked,
                ..
            })
        ));
        h.bridge.signed_in();
        h.bridge.save_answers();
        assert!(h.saved.lock().unwrap().is_empty());
    }

    #[test]
    fn failed_saves_are_reported() {
        let h = harness(
            FakeStore {
                fail_saves: true,
                ..FakeStore::default()
            },
            Options::default(),
        );
        h.ask(PASSWORD, 0, false, typed("pw", true));
        h.bridge.signed_in();
        h.bridge.save_answers();
        assert!(h.events().contains(&TerminalEvent::Saved {
            target: SavedTarget::Password,
            error: Some(ErrorCode::VaultLocked)
        }));
    }

    const HOST_KEY: &str = "The authenticity of host 'bastion.example.net (203.0.113.7)' can't \
                            be established.\nED25519 key fingerprint is SHA256:Ka7Sd1Fg5Hj9.\n\
                            Are you sure you want to continue connecting (yes/no/[fingerprint])? ";

    #[test]
    fn host_keys_are_trusted_only_by_the_user() {
        let h = harness(FakeStore::default(), Options::default());
        let (reply, shown) = h.ask(
            HOST_KEY,
            0,
            false,
            Some(PromptAnswer::Trust { trust: true }),
        );
        assert!(matches!(reply, Reply::Yes));
        assert_eq!(
            shown,
            Some(PromptAsk::HostKey {
                host: "bastion.example.net (203.0.113.7)".into(),
                key_type: "ED25519".into(),
                fingerprint: "SHA256:Ka7Sd1Fg5Hj9".into(),
                extra: Vec::new(),
                unverified: false,
            })
        );
        let (reply, _) = h.ask(
            HOST_KEY,
            0,
            false,
            Some(PromptAnswer::Trust { trust: false }),
        );
        assert!(matches!(reply, Reply::No));
        assert_eq!(
            h.bridge.failure("", Some(255)).reason,
            FailReason::HostKeyNotTrusted
        );

        // A question the session cannot vouch for: the dialog says so, and
        // "Trust" still only answers it.
        let (reply, shown) = h.ask_unverified(
            HOST_KEY,
            0,
            false,
            true,
            Some(PromptAnswer::Trust { trust: true }),
        );
        assert!(matches!(reply, Reply::Yes));
        assert!(matches!(
            shown,
            Some(PromptAsk::HostKey {
                unverified: true,
                ..
            })
        ));

        // Not the plain question: declined without asking.
        let h = harness(FakeStore::default(), Options::default());
        let (reply, shown) = h.ask(
            "Warning: the ECDSA host key for 'h' differs from the key for the IP address\nAre \
             you sure you want to continue connecting (yes/no)? ",
            0,
            false,
            None,
        );
        assert!(matches!(reply, Reply::No) && shown.is_none());
    }

    #[test]
    fn unanswered_prompts_time_out() {
        let h = harness(
            FakeStore::default(),
            Options {
                timeout: Duration::from_millis(50),
                ..Options::default()
            },
        );
        let (reply, _) = h.ask(CODE, 0, false, None);
        assert!(matches!(reply, Reply::Refuse));
        let events = h.events();
        assert!(matches!(
            events.as_slice(),
            [
                TerminalEvent::Prompt { .. },
                TerminalEvent::PromptClosed {
                    reason: PromptClosedReason::Timeout,
                    ..
                }
            ]
        ));
        // Not asked again in this session; the session fails for the code.
        let (reply, _) = h.ask(CODE, 0, false, None);
        assert!(matches!(reply, Reply::Refuse));
        assert_eq!(h.events().len(), 2);
        assert_eq!(
            h.bridge
                .failure("Permission denied (keyboard-interactive).", Some(255))
                .reason,
            FailReason::OneTimeCodeMissing
        );
    }

    #[test]
    fn closing_cancels_the_waiting_prompt() {
        let h = harness(FakeStore::default(), Options::default());
        let prompt = Prompt::parse(PASSWORD, "");
        thread::scope(|scope| {
            let asking = scope.spawn(|| {
                h.bridge.respond(&Ask {
                    prompt: &prompt,
                    foreign: false,
                    unverified: false,
                    given: 0,
                })
            });
            let request = h.prompts.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(h.bridge.is_waiting());
            h.bridge.close();
            assert!(matches!(asking.join().unwrap(), Reply::Refuse));
            assert!(
                !h.bridge.answer(request.id, PromptAnswer::Cancel),
                "too late"
            );
        });
        assert!(h.events().contains(&TerminalEvent::PromptClosed {
            id: 1,
            reason: PromptClosedReason::Ended
        }));
        // Closed: nothing more is asked.
        let (reply, _) = h.ask(PASSWORD, 0, false, None);
        assert!(matches!(reply, Reply::Refuse));
    }

    #[test]
    fn answers_go_to_the_waiting_prompt_only() {
        let h = harness(FakeStore::default(), Options::default());
        assert!(!h.bridge.answer(1, PromptAnswer::Cancel), "nothing waits");
        let (reply, _) = h.ask(PASSWORD, 0, false, Some(PromptAnswer::Cancel));
        assert!(matches!(reply, Reply::Refuse));
        // Cancelled: later password prompts are refused without asking.
        let (reply, shown) = h.ask(PASSWORD, 0, false, None);
        assert!(matches!(reply, Reply::Refuse) && shown.is_none());
        assert_eq!(
            h.bridge.failure("Permission denied", Some(255)).reason,
            FailReason::Cancelled
        );
    }

    #[test]
    fn failure_reasons() {
        let h = harness(
            FakeStore {
                password: Some("old"),
                ..FakeStore::default()
            },
            Options::default(),
        );
        let denied = "ubuntu@h: Permission denied (publickey,password).";
        assert_eq!(
            h.bridge.failure(denied, Some(255)).reason,
            FailReason::NotAccepted
        );
        assert_eq!(
            h.bridge
                .failure(
                    "ssh: connect to host h port 22: Connection refused",
                    Some(255)
                )
                .reason,
            FailReason::Unreachable
        );
        assert_eq!(
            h.bridge
                .failure(
                    "@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @\nHost key verification \
                     failed.",
                    Some(255)
                )
                .reason,
            FailReason::HostKeyChanged
        );
        assert_eq!(h.bridge.failure("", Some(1)).reason, FailReason::Other);

        h.ask(PASSWORD, 0, false, None);
        let failure = h.bridge.failure(denied, Some(255));
        assert_eq!(failure.reason, FailReason::PasswordRejected);
        assert!(failure.saved, "the vault's password was refused");
        assert_eq!(failure.exit_code, Some(255));
        assert_eq!(failure.output, denied);

        h.ask(
            CODE,
            0,
            false,
            Some(PromptAnswer::Secret {
                value: "000000".to_owned().into(),
                save: false,
            }),
        );
        assert_eq!(
            h.bridge.failure(denied, Some(255)).reason,
            FailReason::OneTimeCodeRejected
        );
    }

    #[test]
    fn other_prompts_are_shown_as_they_are() {
        let h = harness(FakeStore::default(), Options::default());
        let (reply, shown) = h.ask("Enter PIN for 'token': ", 0, false, typed("0000", true));
        assert_eq!(secret(&reply), Some("0000"));
        assert_eq!(
            shown,
            Some(PromptAsk::Other {
                text: "Enter PIN for 'token':".into(),
                account: None,
                foreign: false,
                unverified: false,
            })
        );
        // A server's question: its account shown apart from the text.
        let (_, shown) = h.ask(
            "(bob@jump.example) Enter the code from the email: ",
            0,
            true,
            typed("4711", false),
        );
        assert_eq!(
            shown,
            Some(PromptAsk::Other {
                text: "Enter the code from the email:".into(),
                account: Some(PromptAccount::new("bob", "jump.example")),
                foreign: true,
                unverified: false,
            })
        );
        h.bridge.signed_in();
        h.bridge.save_answers();
        assert!(
            h.saved.lock().unwrap().is_empty(),
            "only passwords and passphrases"
        );
    }

    const KEY: &str = "/Users/dev/.ssh/id_ed25519";

    /// A vault with everything saved.
    fn full_store() -> FakeStore {
        FakeStore {
            password: Some("saved-pw"),
            code: Some("123456"),
            passphrase: Some("saved-pp"),
            ..FakeStore::default()
        }
    }

    #[test]
    fn server_prompts_get_no_passphrase_or_host_key_dialog() {
        let h = harness(full_store(), Options::default());
        let host_key = format!("(ubuntu@10.0.4.12) {HOST_KEY}");
        for text in [
            format!("(ubuntu@10.0.4.12) Enter passphrase for key '{KEY}': "),
            host_key,
            "(ubuntu@10.0.4.12) Accept updated hostkeys? (yes/no): ".to_owned(),
        ] {
            let (reply, shown) = h.ask(&text, 0, false, Some(PromptAnswer::Cancel));
            assert!(matches!(reply, Reply::Refuse), "{text:?}");
            assert!(
                matches!(
                    &shown,
                    Some(PromptAsk::Other {
                        account: Some(account),
                        unverified: false,
                        ..
                    }) if *account == PromptAccount::new("ubuntu", "10.0.4.12")
                ),
                "{text:?}: {shown:?}"
            );
            // Cancelling one does not stop the next from being asked.
            h.bridge.lock().cancelled = None;
        }
        assert_eq!(h.bridge.lock().sign_in, SignIn::default());
    }

    #[test]
    fn unverified_prompts_are_shown_as_they_are() {
        let h = harness(full_store(), Options::default());
        for (text, quoted) in [
            (
                "ubuntu@10.0.4.12's password: ".to_owned(),
                "ubuntu@10.0.4.12's password:".to_owned(),
            ),
            (
                format!("Enter passphrase for key '{KEY}': "),
                format!("Enter passphrase for key '{KEY}':"),
            ),
            (
                "(ubuntu@10.0.4.12) Verification code: ".to_owned(),
                "(ubuntu@10.0.4.12) Verification code:".to_owned(),
            ),
        ] {
            let (reply, shown) = h.ask_unverified(&text, 0, false, true, typed("typed", true));
            assert_eq!(secret(&reply), Some("typed"), "not the saved one");
            assert_eq!(
                shown,
                Some(PromptAsk::Other {
                    text: quoted,
                    account: None,
                    foreign: false,
                    unverified: true,
                })
            );
        }
        // Another account's password, which before OpenSSH 8.5 and without a
        // proxy only the server can have asked: not "Password for
        // bob@bank.example", but the server's text as it is.
        let (_, shown) = h.ask_unverified(
            "bob@bank.example's password: ",
            0,
            true,
            true,
            typed("typed", false),
        );
        assert_eq!(
            shown,
            Some(PromptAsk::Other {
                text: "bob@bank.example's password:".into(),
                account: None,
                foreign: false,
                unverified: true,
            })
        );
        h.bridge.signed_in();
        h.bridge.save_answers();
        assert!(h.saved.lock().unwrap().is_empty());
        assert_eq!(h.bridge.lock().sign_in, SignIn::default());
    }

    #[test]
    fn foreign_passphrase_prompts_are_refused() {
        let h = harness(full_store(), Options::default());
        let (reply, shown) = h.ask(
            &format!("Enter passphrase for key '{KEY}': "),
            0,
            true,
            None,
        );
        assert!(matches!(reply, Reply::Refuse) && shown.is_none());
    }

    #[test]
    fn keys_of_another_type_are_declined_like_changed_ones() {
        let h = harness(FakeStore::default(), Options::default());
        let (reply, shown) = h.ask(
            "The authenticity of host 'prod.example (10.0.4.12)' can't be established\nbut keys \
             of different type are already known for this host.\nECDSA key fingerprint is \
             SHA256:abc.\nAre you sure you want to continue connecting (yes/no/[fingerprint])? ",
            0,
            false,
            None,
        );
        assert!(matches!(reply, Reply::No) && shown.is_none());
        assert_eq!(
            h.bridge
                .failure("Host key verification failed.", Some(255))
                .reason,
            FailReason::HostKeyChanged
        );
    }

    #[test]
    fn host_key_warnings_are_shown() {
        let h = harness(FakeStore::default(), Options::default());
        let (_, shown) = h.ask(
            "The authenticity of host 'db (10.0.4.20)' can't be established.\nED25519 key \
             fingerprint is SHA256:abc.\nThis host key is known by the following other \
             names/addresses:\n    ~/.ssh/known_hosts:3: db.example\nAre you sure you want to \
             continue connecting (yes/no/[fingerprint])? ",
            0,
            false,
            Some(PromptAnswer::Trust { trust: false }),
        );
        assert_eq!(
            shown,
            Some(PromptAsk::HostKey {
                host: "db (10.0.4.20)".into(),
                key_type: "ED25519".into(),
                fingerprint: "SHA256:abc".into(),
                extra: vec![
                    "This host key is known by the following other names/addresses:".into(),
                    "    ~/.ssh/known_hosts:3: db.example".into(),
                ],
                unverified: false,
            })
        );
    }

    #[test]
    fn without_a_sure_sign_in_nothing_is_saved() {
        let h = harness(
            FakeStore {
                offer: Some(SaveOffer::Update),
                ..FakeStore::default()
            },
            Options {
                can_save: false,
                ..Options::default()
            },
        );
        let (_, shown) = h.ask(PASSWORD, 0, false, typed("pw", true));
        assert!(matches!(
            shown,
            Some(PromptAsk::Password {
                save: SaveOffer::None,
                ..
            })
        ));
        // The server's banner came out: prompts are still answered.
        assert_eq!(h.bridge.output_started().password, Some(Source::User));
        let (reply, shown) = h.ask(PASSWORD, 1, false, typed("pw2", true));
        assert_eq!(secret(&reply), Some("pw2"));
        assert!(shown.is_some());
        h.bridge.output_started();
        h.bridge.save_answers();
        assert!(h.saved.lock().unwrap().is_empty());
        assert!(
            !h.events()
                .iter()
                .any(|e| matches!(e, TerminalEvent::Saved { .. }))
        );
    }

    #[test]
    fn output_alone_saves_nothing_even_where_saving_is_offered() {
        let h = harness(FakeStore::default(), Options::default());
        h.ask(PASSWORD, 0, false, typed("pw", true));
        h.bridge.output_started();
        h.bridge.save_answers();
        assert!(h.saved.lock().unwrap().is_empty());
    }
}
