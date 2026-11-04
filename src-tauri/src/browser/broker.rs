//! Answers the extension's messages ([`sshkm_core::browser::protocol`]).
//!
//! The [`Broker`] knows nothing of Tauri: what it needs from the app — the
//! vault, the pairing dialog, the window — comes through [`Env`], so the
//! whole protocol is tested here against a real vault.
//!
//! Rules:
//!
//! - A pairing needs an unlocked vault and the user's yes in the app; one
//!   pairing waits at a time, for at most [`PAIRING_WAIT`].
//! - A sealed request is answered only if it opens with the keys of a browser
//!   paired with the open vault, was sent in the last two minutes and was not
//!   seen before ([`Seen`]).
//! - Pages are named by origin, and only logins whose address fits that
//!   origin are listed, filled, compared or updated
//!   ([`sshkm_core::browser::origin`]).
//! - The one secret that leaves is the password of the login the user picked,
//!   sealed for that browser. Listing and checking do not count as activity
//!   for the auto-lock; filling and saving do.
//! - A password leaves only once the user allowed that browser to fill that
//!   login on that page, in a prompt the app shows and no other program can
//!   answer ([`Env::confirm_fill`]). The answer lasts for the user's session
//!   ([`Env::session`]), at most [`ALLOWED_FOR`]. So a program that copied
//!   the browser's keys gets no password the user didn't just allow.
//! - A browser may check [`MAX_CHECKS`] typed logins a minute and ask the
//!   user [`MAX_PROMPTS`] times, so whoever holds its keys can neither guess
//!   saved passwords by checking nor wear the user down with prompts.
//! - A browser changes its keys now and then ([`Action::Rekey`]). Its old
//!   keys are kept, retired; a request sealed with one after that shows that
//!   someone else holds a copy, and the pairing is revoked at once
//!   ([`Env::copied`]).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand_core::{OsRng, RngCore};
use serde::Serialize;
use sshkm_core::browser::Origin;
use sshkm_core::browser::channel::{
    self, ChannelKeys, MessageNonce, PROTOCOL, accept_pairing, check_client_id, pairing_code,
};
use sshkm_core::browser::protocol::{
    Action, CheckReply, Envelope, LoginsReply, MAX_MESSAGE, Message, Opened, PairRequest,
    PairedInfo, RekeyReply, Reply, ReplyError, SameSite, SavedReply, SealedRequest, StatusReply,
    VaultLock,
};
use sshkm_core::vault::{KeysUsed, PairedBrowser, Vault};
use sshkm_core::{ErrorCode, ExposeSecret};
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};

/// How long a pairing waits for the user.
pub const PAIRING_WAIT: Duration = Duration::from_secs(120);
/// How long a fill waits for the user before the browser hears it expired.
/// The prompt stays: a yes given later lets the next try fill at once.
pub const FILL_WAIT: Duration = Duration::from_secs(60);
/// How long the user's yes to a fill lasts at most, even in one session.
pub const ALLOWED_FOR: Duration = Duration::from_secs(12 * 60 * 60);
/// What [`MAX_CHECKS`] and [`MAX_PROMPTS`] count over.
const LIMIT_WINDOW: Duration = Duration::from_secs(60);
/// Typed logins a browser may check in [`LIMIT_WINDOW`]: a person signs in
/// a few times a minute at most.
pub const MAX_CHECKS: usize = 10;
/// Times a browser may ask the user about fills in [`LIMIT_WINDOW`].
pub const MAX_PROMPTS: usize = 5;
/// Most characters of a login's title or username shown in a prompt.
const SHOWN_CHARS: usize = 60;
/// How far a request's clock may be from ours.
const MAX_AGE: Duration = Duration::from_secs(120);
/// How long a nonce is remembered, to refuse it again: longer than a request
/// stays fresh on either side of our clock.
const REMEMBER: Duration = Duration::from_secs(300);
/// How many nonces are remembered; past that, the oldest make room.
const MAX_REMEMBERED: usize = 10_000;
const APP_NAME: &str = "SSH Key Manager";

/// A pairing waiting for the user, as the app's dialog shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct PairingRequest {
    /// Names this request when the user answers.
    pub id: String,
    /// The browser's name as the extension reported it.
    pub browser: String,
    /// Six digits the browser shows too.
    pub code: String,
}

/// What the user is asked before a browser fills a login. The texts come
/// from the vault and the app, shortened and on one line; the page only
/// picked the login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FillPrompt {
    /// The paired browser's name, e.g. "Chrome".
    pub browser: String,
    pub title: String,
    pub username: String,
    /// The page: `host[:port]`, with `http://` in front if it isn't https.
    pub site: String,
}

/// The user's answer to a [`FillPrompt`], once they give it.
pub type FillAnswer = Box<dyn FnOnce(bool) + Send>;

/// What changed, for the UI to refetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Changed {
    /// Logins were added or updated.
    Entries,
    /// A browser was paired.
    Browsers,
}

/// What the broker needs from the app.
pub trait Env {
    fn vault_lock(&self) -> VaultLock;
    /// Runs `work` on the unlocked vault. `active` counts as activity for
    /// the auto-lock.
    fn read<T>(&self, active: bool, work: impl FnOnce(&Vault) -> AppResult<T>) -> AppResult<T>;
    /// Runs `work` on the unlocked vault and saves it.
    fn write<T>(&self, work: impl FnOnce(&mut Vault) -> AppResult<T>) -> AppResult<T>;
    /// Like [`Self::write`], without a backup of the previous file: for a
    /// browser's new keys.
    fn write_keys<T>(&self, work: impl FnOnce(&mut Vault) -> AppResult<T>) -> AppResult<T>;
    /// Shows the pairing dialog, or closes it with `None`.
    fn ask(&self, request: Option<&PairingRequest>);
    /// Brings the app forward on the vault, to unlock it.
    fn show(&self);
    fn changed(&self, what: Changed);
    /// This computer's name, recorded with a pairing.
    fn computer(&self) -> String;
    fn version(&self) -> String;
    /// The user's session at the computer, as a number that changes when it
    /// ends: the vault locked by hand, the screen locked, the computer
    /// asleep, the vault changed elsewhere or switched.
    fn session(&self) -> u64;
    /// Asks the user whether to fill a login, in a prompt no other program
    /// can answer, and calls `answer` with their choice once they make it.
    /// Returns at once.
    fn confirm_fill(&self, prompt: FillPrompt, answer: FillAnswer);
    /// Tells the user that someone else used a copy of `browser`'s keys, so
    /// its pairing is gone.
    fn copied(&self, browser: &PairedBrowser);
}

/// An environment shared with its owner.
impl<E: Env> Env for Arc<E> {
    fn vault_lock(&self) -> VaultLock {
        (**self).vault_lock()
    }
    fn read<T>(&self, active: bool, work: impl FnOnce(&Vault) -> AppResult<T>) -> AppResult<T> {
        (**self).read(active, work)
    }
    fn write<T>(&self, work: impl FnOnce(&mut Vault) -> AppResult<T>) -> AppResult<T> {
        (**self).write(work)
    }
    fn write_keys<T>(&self, work: impl FnOnce(&mut Vault) -> AppResult<T>) -> AppResult<T> {
        (**self).write_keys(work)
    }
    fn ask(&self, request: Option<&PairingRequest>) {
        (**self).ask(request);
    }
    fn show(&self) {
        (**self).show();
    }
    fn changed(&self, what: Changed) {
        (**self).changed(what);
    }
    fn computer(&self) -> String {
        (**self).computer()
    }
    fn version(&self) -> String {
        (**self).version()
    }
    fn session(&self) -> u64 {
        (**self).session()
    }
    fn confirm_fill(&self, prompt: FillPrompt, answer: FillAnswer) {
        (**self).confirm_fill(prompt, answer);
    }
    fn copied(&self, browser: &PairedBrowser) {
        (**self).copied(browser);
    }
}

struct Pending {
    request: PairingRequest,
    decision: Option<bool>,
}

pub struct Broker {
    pending: Mutex<Option<Pending>>,
    decided: Condvar,
    seen: Mutex<Seen>,
    pairing_wait: Duration,
    fills: Arc<Fills>,
    fill_wait: Duration,
    checks: Mutex<Limiter>,
}

impl Default for Broker {
    fn default() -> Self {
        Self::new(PAIRING_WAIT)
    }
}

type Answer = Result<Reply, ReplyError>;

impl Broker {
    /// A broker whose pairings wait `pairing_wait` for the user.
    pub fn new(pairing_wait: Duration) -> Self {
        Self {
            pending: Mutex::new(None),
            decided: Condvar::new(),
            seen: Mutex::new(Seen::default()),
            pairing_wait,
            fills: Arc::default(),
            fill_wait: FILL_WAIT,
            checks: Mutex::default(),
        }
    }

    /// The same, with fills waiting `fill_wait` for the user.
    #[must_use]
    pub fn with_fill_wait(self, fill_wait: Duration) -> Self {
        Self { fill_wait, ..self }
    }

    /// Answers one message from the native host with the JSON reply.
    pub fn handle(&self, env: &impl Env, bytes: &[u8]) -> Vec<u8> {
        let reply = match serde_json::from_slice::<Envelope>(bytes) {
            Ok(envelope) => self.answer(env, envelope),
            Err(_) => Err(ReplyError::Invalid),
        };
        let reply = reply.unwrap_or_else(|code| Reply::Error { code });
        serde_json::to_vec(&reply).unwrap_or_default()
    }

    fn answer(&self, env: &impl Env, envelope: Envelope) -> Answer {
        match envelope.message {
            Message::Hello => Ok(Reply::Hello {
                app: APP_NAME,
                version: env.version(),
                protocol: PROTOCOL,
                vault: env.vault_lock(),
            }),
            Message::Show => {
                env.show();
                Ok(Reply::Shown)
            }
            Message::SameSite(sites) => Ok(Reply::SameSite {
                same: same_site(&sites),
            }),
            Message::Pair(request) => self.pair(env, &envelope.caller, &request),
            Message::Request(request) => self.request(env, &request),
        }
    }

    /// The pairing waiting for the user, if any.
    pub fn pending(&self) -> Option<PairingRequest> {
        lock(&self.pending).as_ref().map(|p| p.request.clone())
    }

    /// The user's answer to the pairing `id`. Returns false if it no longer
    /// waits.
    pub fn decide(&self, id: &str, approve: bool) -> bool {
        let mut pending = lock(&self.pending);
        match pending.as_mut() {
            Some(p) if p.request.id == id && p.decision.is_none() => {
                p.decision = Some(approve);
                self.decided.notify_all();
                true
            }
            _ => false,
        }
    }

    fn pair(&self, env: &impl Env, caller: &str, request: &PairRequest) -> Answer {
        check_client_id(&request.client_id).map_err(|_| ReplyError::Invalid)?;
        let client_public =
            channel::decode(&request.public_key, 65).map_err(|_| ReplyError::Invalid)?;
        let nonce = channel::decode_nonce(&request.nonce).map_err(|_| ReplyError::Invalid)?;
        match env.vault_lock() {
            VaultLock::Missing => return Err(ReplyError::NoVault),
            VaultLock::Locked => {
                env.show();
                return Err(ReplyError::Locked);
            }
            VaultLock::Unlocked => {}
        }

        let asked = PairingRequest {
            id: random_id(),
            browser: browser_name(&request.browser),
            code: pairing_code(&request.client_id, &client_public),
        };
        {
            let mut pending = lock(&self.pending);
            if pending.is_some() {
                return Err(ReplyError::Busy);
            }
            *pending = Some(Pending {
                request: asked.clone(),
                decision: None,
            });
        }
        env.ask(Some(&asked));
        let decision = self.wait_for(&asked.id, self.pairing_wait);
        env.ask(None);

        match decision {
            None => return Err(ReplyError::Expired),
            Some(false) => return Err(ReplyError::Denied),
            Some(true) => {}
        }
        let pairing =
            accept_pairing(&request.client_id, &client_public).map_err(|_| ReplyError::Invalid)?;
        let browser = PairedBrowser {
            id: request.client_id.clone(),
            browser: asked.browser,
            computer: env.computer(),
            paired: String::new(),
        };
        env.write(|vault| Ok(vault.add_browser(&browser, caller, &pairing.keys)?))
            .map_err(|e| reply_error(&e))?;
        env.changed(Changed::Browsers);
        let info = serde_json::to_vec(&PairedInfo { paired: true }).unwrap_or_default();
        let (reply_nonce, sealed) = pairing
            .keys
            .seal_response(&request.client_id, &nonce, &info)
            .map_err(|_| ReplyError::Failed)?;
        Ok(Reply::Paired {
            public_key: channel::encode(&pairing.app_public),
            nonce: channel::encode(&reply_nonce),
            payload: channel::encode(&sealed),
        })
    }

    /// Waits for the user's answer to pairing `id`, then forgets the pairing.
    fn wait_for(&self, id: &str, wait: Duration) -> Option<bool> {
        let deadline = Instant::now() + wait;
        let mut pending = lock(&self.pending);
        loop {
            let ours = pending.as_ref().filter(|p| p.request.id == id)?;
            if let Some(decision) = ours.decision {
                *pending = None;
                return Some(decision);
            }
            let now = Instant::now();
            if now >= deadline {
                *pending = None;
                return None;
            }
            pending = self
                .decided
                .wait_timeout(pending, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    fn request(&self, env: &impl Env, request: &SealedRequest) -> Answer {
        check_client_id(&request.client_id).map_err(|_| ReplyError::Invalid)?;
        let nonce = channel::decode_nonce(&request.nonce).map_err(|_| ReplyError::Invalid)?;
        let sealed =
            channel::decode(&request.payload, MAX_MESSAGE).map_err(|_| ReplyError::Invalid)?;
        match env.vault_lock() {
            VaultLock::Missing => return Err(ReplyError::NoVault),
            VaultLock::Locked => return Err(ReplyError::Locked),
            VaultLock::Unlocked => {}
        }
        let client_id = request.client_id.as_str();
        let keys = env
            .read(false, |vault| Ok(vault.browser_keys(client_id)))
            .map_err(|e| reply_error(&e))?
            .ok_or(ReplyError::UnknownClient)?;
        let (plain, used) = keys
            .open_request(client_id, &nonce, &sealed)
            .ok_or(ReplyError::Invalid)?;
        let opened: Opened = serde_json::from_slice(&plain).map_err(|_| ReplyError::Invalid)?;
        drop(plain);
        if !fresh(opened.sent_at) {
            return Err(ReplyError::Expired);
        }
        if !lock(&self.seen).admit(nonce, opened.sent_at, Instant::now()) {
            return Err(ReplyError::Invalid);
        }
        match used {
            // Sealed before the browser changed its keys: a late request of
            // its own, which gets no answer.
            KeysUsed::Retired { retired_at } if opened.sent_at <= retired_at => {
                return Err(ReplyError::Invalid);
            }
            KeysUsed::Retired { .. } => {
                self.revoke_copied(env, client_id);
                return Err(ReplyError::Revoked);
            }
            KeysUsed::Next => {
                env.write_keys(|vault| Ok(vault.promote_browser_keys(client_id, now_millis())?))
                    .map_err(|e| reply_error(&e))?;
            }
            KeysUsed::Current => {}
        }
        let answering = keys.answering(used).ok_or(ReplyError::Invalid)?;
        let answer = self.act(env, client_id, opened.action)?;
        seal(answering, client_id, &nonce, &answer)
    }

    /// Someone else sealed a request with keys `client_id` gave up: forgets
    /// the pairing and tells the user.
    fn revoke_copied(&self, env: &impl Env, client_id: &str) {
        log::warn!("browser: a copy of a paired browser's old keys was used; revoking it");
        let browser = env
            .read(false, |vault| Ok(vault.paired_browser(client_id)))
            .ok()
            .flatten();
        match env.write(|vault| Ok(vault.remove_browser(client_id))) {
            Ok(true) => env.changed(Changed::Browsers),
            Ok(false) => {}
            Err(error) => log::warn!("browser: cannot forget the pairing: {error}"),
        }
        self.fills.forget(client_id);
        if let Some(browser) = browser {
            env.copied(&browser);
        }
    }

    /// Carries out a request; returns the JSON to seal.
    fn act(
        &self,
        env: &impl Env,
        client_id: &str,
        action: Action,
    ) -> Result<Zeroizing<Vec<u8>>, ReplyError> {
        match action {
            Action::Status => Ok(to_json(&StatusReply {
                vault: VaultLock::Unlocked,
            })),
            Action::Disconnect => {
                env.write(|vault| Ok(vault.remove_browser(client_id)))
                    .map_err(|e| reply_error(&e))?;
                self.fills.forget(client_id);
                env.changed(Changed::Browsers);
                Ok(to_json(&StatusReply {
                    vault: VaultLock::Unlocked,
                }))
            }
            Action::Logins { origin } => {
                let page = page(&origin)?;
                let logins = env
                    .read(false, |vault| Ok(vault.logins_for(&page)))
                    .map_err(|e| reply_error(&e))?;
                Ok(to_json(&LoginsReply { logins }))
            }
            Action::Fill { origin, entry_id } => {
                let page = page(&origin)?;
                self.confirm_fill(env, client_id, &page, &entry_id)?;
                let (username, password) = env
                    .read(true, |vault| Ok(vault.fill_for(&page, &entry_id)?))
                    .map_err(|e| reply_error(&e))?;
                Ok(fill_json(&username, password.expose_secret()))
            }
            Action::Check {
                origin,
                username,
                password,
            } => {
                let page = page(&origin)?;
                if !lock(&self.checks).take(client_id, MAX_CHECKS, Instant::now()) {
                    log::warn!("browser: too many logins checked; refusing");
                    return Err(ReplyError::TooMany);
                }
                let check: CheckReply = env
                    .read(false, |vault| {
                        Ok(vault.check_login(&page, &username, &password))
                    })
                    .map_err(|e| reply_error(&e))?;
                Ok(to_json(&check))
            }
            Action::Save {
                origin,
                username,
                password,
            } => {
                let page = page(&origin)?;
                let entry_id = env
                    .write(|vault| Ok(vault.save_login(&page, &username, &password)?))
                    .map_err(|e| reply_error(&e))?;
                env.changed(Changed::Entries);
                Ok(to_json(&SavedReply { entry_id }))
            }
            Action::Update {
                origin,
                entry_id,
                password,
            } => {
                let page = page(&origin)?;
                env.write(|vault| Ok(vault.update_login(&page, &entry_id, &password)?))
                    .map_err(|e| reply_error(&e))?;
                env.changed(Changed::Entries);
                Ok(to_json(&SavedReply { entry_id }))
            }
            Action::Rekey { public_key } => {
                let client_public =
                    channel::decode(&public_key, 65).map_err(|_| ReplyError::Invalid)?;
                let pairing =
                    accept_pairing(client_id, &client_public).map_err(|_| ReplyError::Invalid)?;
                env.write_keys(|vault| Ok(vault.set_next_browser_keys(client_id, &pairing.keys)?))
                    .map_err(|e| reply_error(&e))?;
                Ok(to_json(&RekeyReply {
                    public_key: channel::encode(&pairing.app_public),
                }))
            }
        }
    }

    /// Returns once the user allowed `client_id` to fill `entry_id` on
    /// `page` in this session, asking them if they haven't: `Denied` if they
    /// say no, `Expired` if they don't answer in time, `Busy` while they are
    /// asked about another fill, `TooMany` if the browser asked too often.
    fn confirm_fill(
        &self,
        env: &impl Env,
        client_id: &str,
        page: &Origin,
        entry_id: &str,
    ) -> Result<(), ReplyError> {
        let key = FillKey {
            client: client_id.to_owned(),
            entry: entry_id.to_owned(),
            page: page.to_string(),
        };
        let session = env.session();
        let mut state = lock(&self.fills.state);
        if state.allows(&key, session, Instant::now()) {
            return Ok(());
        }
        match &state.asking {
            Some(asking) if *asking != key => return Err(ReplyError::Busy),
            // Picked again while the user is asked: the same answer will do.
            Some(_) => {}
            None => {
                // Also checks that the login belongs to the page.
                let prompt = fill_prompt(env, client_id, page, entry_id)?;
                if !state.prompts.take(client_id, MAX_PROMPTS, Instant::now()) {
                    log::warn!("browser: too many fills asked about; refusing");
                    return Err(ReplyError::TooMany);
                }
                state.asking = Some(key.clone());
                drop(state);
                let fills = Arc::clone(&self.fills);
                let asked = key.clone();
                env.confirm_fill(
                    prompt,
                    Box::new(move |allowed| fills.answer(&asked, session, allowed)),
                );
                state = lock(&self.fills.state);
            }
        }
        let deadline = Instant::now() + self.fill_wait;
        while state.asking.as_ref() == Some(&key) {
            let now = Instant::now();
            if now >= deadline {
                return Err(ReplyError::Expired);
            }
            state = self
                .fills
                .answered
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        if state.allows(&key, session, Instant::now()) {
            Ok(())
        } else {
            Err(ReplyError::Denied)
        }
    }
}

/// What to ask before `client_id` fills `entry_id` on `page`. Fails with
/// `NotFound` if the login does not belong to the page.
fn fill_prompt(
    env: &impl Env,
    client_id: &str,
    page: &Origin,
    entry_id: &str,
) -> Result<FillPrompt, ReplyError> {
    let (offer, browser) = env
        .read(false, |vault| {
            Ok((
                vault.offer_for(page, entry_id)?,
                vault.paired_browser(client_id),
            ))
        })
        .map_err(|e| reply_error(&e))?;
    let address = page.to_string();
    Ok(FillPrompt {
        browser: browser.map_or_else(|| browser_name(""), |b| browser_name(&b.browser)),
        title: shown(&offer.title),
        username: shown(&offer.username),
        site: address
            .strip_prefix("https://")
            .map_or_else(|| address.clone(), str::to_owned),
    })
}

/// A text from the vault as a prompt shows it: on one line, without control
/// characters, at most [`SHOWN_CHARS`] characters.
fn shown(text: &str) -> String {
    let line: String = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    if line.chars().count() > SHOWN_CHARS {
        let cut: String = line.chars().take(SHOWN_CHARS - 1).collect();
        format!("{}…", cut.trim_end())
    } else {
        line
    }
}

/// A fill the user may allow: a browser, a login, a page.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FillKey {
    client: String,
    entry: String,
    /// The page's origin.
    page: String,
}

/// The fills the user allowed, and the one they are asked about.
#[derive(Default)]
struct Fills {
    state: Mutex<FillState>,
    answered: Condvar,
}

#[derive(Default)]
struct FillState {
    /// In which session, and when, each fill was allowed.
    allowed: HashMap<FillKey, (u64, Instant)>,
    /// The fill the user is asked about now.
    asking: Option<FillKey>,
    /// When each browser asked the user lately.
    prompts: Limiter,
}

impl FillState {
    /// Whether the user allowed `key` in `session`, less than
    /// [`ALLOWED_FOR`] ago. Forgets what no longer counts.
    fn allows(&mut self, key: &FillKey, session: u64, now: Instant) -> bool {
        self.allowed.retain(|_, (at_session, at)| {
            *at_session == session && now.duration_since(*at) < ALLOWED_FOR
        });
        self.allowed.contains_key(key)
    }
}

impl Fills {
    /// Records the user's answer about `key`, asked in `session`.
    fn answer(&self, key: &FillKey, session: u64, allowed: bool) {
        let mut state = lock(&self.state);
        if allowed {
            state.allowed.insert(key.clone(), (session, Instant::now()));
        }
        if state.asking.as_ref() == Some(key) {
            state.asking = None;
        }
        self.answered.notify_all();
    }

    /// Forgets what a browser was allowed: its pairing is gone.
    fn forget(&self, client_id: &str) {
        lock(&self.state)
            .allowed
            .retain(|key, _| key.client != client_id);
    }
}

/// When each browser did something lately, to limit how often it may.
#[derive(Default)]
struct Limiter {
    recent: HashMap<String, VecDeque<Instant>>,
}

impl Limiter {
    /// Counts one more for `client_id`, unless it had `max` in the last
    /// [`LIMIT_WINDOW`] already.
    fn take(&mut self, client_id: &str, max: usize, now: Instant) -> bool {
        let recent = self.recent.entry(client_id.to_owned()).or_default();
        while recent
            .front()
            .is_some_and(|&at| now.duration_since(at) >= LIMIT_WINDOW)
        {
            recent.pop_front();
        }
        if recent.len() >= max {
            return false;
        }
        recent.push_back(now);
        true
    }
}

/// The nonces of the requests answered lately, so that a replay is refused.
///
/// Each is kept for [`REMEMBER`], longer than a request stays [`fresh`]. When
/// [`MAX_REMEMBERED`] are kept, the oldest makes room, rather than every
/// request of every browser being refused until some expire. A nonce that
/// makes room leaves a floor behind: requests sent no later than it are
/// refused for as long as it would have been remembered. Its replay is thus
/// refused as surely as that of one still kept; at worst a request sent
/// during a flood, but delivered after newer ones, is refused too.
#[derive(Default)]
struct Seen {
    /// Oldest first: when each came, its `sent_at` and its nonce.
    order: VecDeque<(Instant, u64, MessageNonce)>,
    nonces: HashSet<MessageNonce>,
    /// Requests sent at or before this `sent_at` are refused until the instant.
    floor: Option<(u64, Instant)>,
}

impl Seen {
    /// Remembers the nonce of a fresh request sent at `sent_at`. False if it
    /// was seen before, or may have been.
    fn admit(&mut self, nonce: MessageNonce, sent_at: u64, now: Instant) -> bool {
        while let Some(&(at, _, old)) = self.order.front()
            && now.duration_since(at) >= REMEMBER
        {
            self.order.pop_front();
            self.nonces.remove(&old);
        }
        if self.floor.is_some_and(|(_, until)| now >= until) {
            self.floor = None;
        }
        if self.floor.is_some_and(|(floor, _)| sent_at <= floor) || self.nonces.contains(&nonce) {
            return false;
        }
        if self.order.len() >= MAX_REMEMBERED
            && let Some((_, old_sent_at, old)) = self.order.pop_front()
        {
            self.nonces.remove(&old);
            let floor = self
                .floor
                .map_or(old_sent_at, |(floor, _)| floor.max(old_sent_at));
            self.floor = Some((floor, now + REMEMBER));
        }
        self.order.push_back((now, sent_at, nonce));
        self.nonces.insert(nonce);
        true
    }
}

fn to_json(value: &impl Serialize) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(serde_json::to_vec(value).unwrap_or_default())
}

/// `{"username":…,"password":…}`, written into a buffer big enough for the
/// worst escaping so it never reallocates and leaves a copy behind.
fn fill_json(username: &str, password: &str) -> Zeroizing<Vec<u8>> {
    #[derive(Serialize)]
    struct Fill<'a> {
        username: &'a str,
        password: &'a str,
    }
    let mut buffer = Zeroizing::new(Vec::with_capacity(
        32 + 6 * (username.len() + password.len()),
    ));
    let _ = serde_json::to_writer(&mut *buffer, &Fill { username, password });
    buffer
}

fn seal(keys: &ChannelKeys, client_id: &str, nonce: &MessageNonce, plain: &[u8]) -> Answer {
    let (reply_nonce, sealed) = keys
        .seal_response(client_id, nonce, plain)
        .map_err(|_| ReplyError::Failed)?;
    Ok(Reply::Response {
        nonce: channel::encode(&reply_nonce),
        payload: channel::encode(&sealed),
    })
}

fn page(origin: &str) -> Result<Origin, ReplyError> {
    Origin::parse(origin).map_err(|_| ReplyError::Invalid)
}

/// Whether a login of `sites.origin` would be offered on `sites.page`.
fn same_site(sites: &SameSite) -> bool {
    match (page(&sites.origin), page(&sites.page)) {
        (Ok(origin), Ok(page)) => page.fits(&origin).is_some(),
        _ => false,
    }
}

fn fresh(sent_at: u64) -> bool {
    let now = now_millis();
    let max = u64::try_from(MAX_AGE.as_millis()).unwrap_or(u64::MAX);
    now != 0 && now.abs_diff(sent_at) <= max
}

/// Milliseconds since 1970, as the extension stamps its requests; 0 if the
/// clock is before then.
fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |now| u64::try_from(now.as_millis()).unwrap_or(u64::MAX))
}

fn reply_error(error: &AppError) -> ReplyError {
    match error.code() {
        ErrorCode::VaultLocked => ReplyError::Locked,
        ErrorCode::NotFound => ReplyError::NotFound,
        ErrorCode::InvalidInput => ReplyError::Invalid,
        _ => ReplyError::Failed,
    }
}

/// A short, printable browser name.
fn browser_name(reported: &str) -> String {
    let name: String = reported
        .chars()
        .filter(|c| !c.is_control())
        .take(40)
        .collect();
    let name = name.trim();
    if name.is_empty() {
        "Browser".to_owned()
    } else {
        name.to_owned()
    }
}

fn random_id() -> String {
    let mut bytes = [0; 16];
    OsRng.fill_bytes(&mut bytes);
    super::hex(&bytes)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests;
