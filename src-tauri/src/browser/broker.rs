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

use std::collections::{HashSet, VecDeque};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand_core::{OsRng, RngCore};
use serde::Serialize;
use sshkm_core::browser::Origin;
use sshkm_core::browser::channel::{
    self, ChannelKeys, MessageNonce, PROTOCOL, accept_pairing, check_client_id, pairing_code,
};
use sshkm_core::browser::protocol::{
    Action, CheckReply, Envelope, LoginsReply, MAX_MESSAGE, Message, Opened, PairRequest,
    PairedInfo, Reply, ReplyError, SameSite, SavedReply, SealedRequest, StatusReply, VaultLock,
};
use sshkm_core::vault::{PairedBrowser, Vault};
use sshkm_core::{ErrorCode, ExposeSecret};
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};

/// How long a pairing waits for the user.
pub const PAIRING_WAIT: Duration = Duration::from_secs(120);
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
    /// Shows the pairing dialog, or closes it with `None`.
    fn ask(&self, request: Option<&PairingRequest>);
    /// Brings the app forward on the vault, to unlock it.
    fn show(&self);
    fn changed(&self, what: Changed);
    /// This computer's name, recorded with a pairing.
    fn computer(&self) -> String;
    fn version(&self) -> String;
}

/// An environment shared with its owner.
impl<E: Env> Env for std::sync::Arc<E> {
    fn vault_lock(&self) -> VaultLock {
        (**self).vault_lock()
    }
    fn read<T>(&self, active: bool, work: impl FnOnce(&Vault) -> AppResult<T>) -> AppResult<T> {
        (**self).read(active, work)
    }
    fn write<T>(&self, work: impl FnOnce(&mut Vault) -> AppResult<T>) -> AppResult<T> {
        (**self).write(work)
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
        }
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
        let keys = env
            .read(false, |vault| Ok(vault.browser_keys(&request.client_id)))
            .map_err(|e| reply_error(&e))?
            .ok_or(ReplyError::UnknownClient)?;
        let plain = keys
            .open_request(&request.client_id, &nonce, &sealed)
            .map_err(|_| ReplyError::Invalid)?;
        let opened: Opened = serde_json::from_slice(&plain).map_err(|_| ReplyError::Invalid)?;
        drop(plain);
        if !fresh(opened.sent_at) {
            return Err(ReplyError::Expired);
        }
        if !lock(&self.seen).admit(nonce, opened.sent_at, Instant::now()) {
            return Err(ReplyError::Invalid);
        }
        let answer = act(env, &request.client_id, opened.action)?;
        seal(&keys, &request.client_id, &nonce, &answer)
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

/// Carries out a request; returns the JSON to seal.
fn act(env: &impl Env, client_id: &str, action: Action) -> Result<Zeroizing<Vec<u8>>, ReplyError> {
    match action {
        Action::Status => Ok(to_json(&StatusReply {
            vault: VaultLock::Unlocked,
        })),
        Action::Disconnect => {
            env.write(|vault| Ok(vault.remove_browser(client_id)))
                .map_err(|e| reply_error(&e))?;
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
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return false;
    };
    let now = u64::try_from(now.as_millis()).unwrap_or(u64::MAX);
    let max = u64::try_from(MAX_AGE.as_millis()).unwrap_or(u64::MAX);
    now.abs_diff(sent_at) <= max
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
