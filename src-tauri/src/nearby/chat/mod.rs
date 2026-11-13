//! Chats with paired computers and the user's own devices (see
//! `docs/p2p-chat.md`).
//!
//! - **Online.** While the vault is unlocked and Nearby is open in a visible
//!   window, and for two minutes after the user leaves it (or hides the
//!   window), the app listens on a port of its own and announces it as
//!   `_sshkm-chat._tcp`, with a tag only each contact recognises
//!   ([`presence`]). Offline, it does none of it.
//! - **Links.** A session with a contact opens when the user sends to it
//!   or opens its chat: a knock, a Noise handshake bound to it, `Hello`s
//!   that both name `chat/1`, then frames both ways ([`link`]). At most 16
//!   at once; they don't take the slot pairing and syncs use.
//! - **History.** Each conversation lives in `chats/<id>.chat` in the app's
//!   data folder, sealed with a key the vault keeps for this computer
//!   ([`sshkm_core::chat`]); in memory only while the vault is unlocked.
//! - **Secrets.** A secret's value, or variables', reaches the page only
//!   when the user asks for it, one at a time, and goes when its term ends.
//! - **Asked natively.** A secret that leaves the vault for another computer
//!   (variables, a login, an environment) and anything received that goes
//!   into the vault are asked about in a system dialog the page can't
//!   answer ([`prompt`]), naming what and to or from whom. Contacts and
//!   their addresses come from the vault and the network, never the page.
//!
//! The UI follows [`CHATS_EVENT`].

mod link;
mod presence;
mod prompt;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sshkm_core::chat::{Body, Conversation, Delivery, Entry, Gone, Line, Outcome, Var, file};
use sshkm_core::p2p::chat::{ChatFrame, MAX_TTL, MIN_TTL, TERMS, new_id};
use sshkm_core::p2p::contact::ContactKey;
use sshkm_core::p2p::protocol::{EnvVariable, Item, ItemSummary, SecretText};
use sshkm_core::p2p::{Identity, PeerKey};
use sshkm_core::vault::envs::{self, EnvInput, risky_variable};
use sshkm_core::{ErrorCode, ExposeSecret, SecretString, fsutil};
use tauri::{Emitter, Manager};
use tauri_plugin_notification::NotificationExt as _;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

use self::link::Link;
use super::Nearby;
use super::items::{self, SendRequest};
use crate::confirm::Localized;
use crate::error::{AppError, AppResult};
use crate::types::CopyResult;

/// Emitted when chats change; `key` names the conversation that did, if one.
pub const CHATS_EVENT: &str = "nearby-chats";
/// How long the app stays online after the user leaves Nearby.
const GRACE: Duration = Duration::from_secs(120);
/// How often the app looks at its chats.
const TICK: Duration = Duration::from_secs(1);
/// How often expired values are looked for, and contacts read again.
const SWEEP: Duration = Duration::from_secs(30);
/// Folder of the conversations, in the app's data folder.
const FOLDER: &str = "chats";

/// What the Chats tab lists.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct ChatList {
    /// This computer is online for chats now.
    pub online: bool,
    pub chats: Vec<ChatSummary>,
}

/// One conversation in the list.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct ChatSummary {
    /// The other device's key.
    pub key: String,
    /// The name the vault keeps for it.
    pub name: String,
    /// One of the user's own devices.
    pub own: bool,
    /// Online for chats now: messages to it go.
    pub online: bool,
    pub unread: u32,
    pub last: Option<ChatPreview>,
}

/// The last thing said in a conversation, as the list shows it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct ChatPreview {
    /// RFC 3339, UTC.
    pub at: String,
    pub mine: bool,
    /// `text`, `secret`, `variables`, `card` or `line`.
    pub kind: String,
    /// A text's words; nothing for the other kinds.
    pub text: Option<String>,
}

/// One entry of a conversation, as the page shows it: never a secret's value.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct ChatEntry {
    pub id: String,
    pub mine: bool,
    /// RFC 3339, UTC.
    pub at: String,
    pub delivery: Delivery,
    pub body: EntryView,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum EntryView {
    Text {
        text: String,
    },
    #[serde(rename_all = "camelCase")]
    Secret {
        label: String,
        /// When the value goes (RFC 3339), while it is there.
        expires: Option<String>,
        gone: Option<Gone>,
    },
    #[serde(rename_all = "camelCase")]
    Variables {
        label: String,
        variables: Vec<VarView>,
        expires: Option<String>,
        gone: Option<Gone>,
    },
    #[serde(rename_all = "camelCase")]
    Card {
        item: ItemSummary,
        outcome: Outcome,
        /// What it was saved as.
        name: Option<String>,
        keys_differ: bool,
        /// A hosts file group waits on the Hosts file page under this id.
        group: Option<u32>,
    },
    Line {
        line: Line,
    },
}

/// A variable of [`EntryView::Variables`]: a secret one's value only when
/// the user asks for it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct VarView {
    pub name: String,
    pub secret: bool,
    /// A plain variable's value, while it is there.
    pub value: Option<String>,
    /// It changes how programs start (`PATH`, `LD_PRELOAD`, …).
    pub risky: bool,
}

/// What adding received variable `name` to an environment would do.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct VarReview {
    pub name: String,
    pub secret: bool,
    pub change: VarChange,
    pub risky: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum VarChange {
    /// The environment has no variable of that name.
    New,
    /// It has one with another value.
    Replaces,
    /// It has one with the same value.
    Same,
}

/// Where received variables go: an environment by id, or a new one in
/// Personal of this name.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum VarTarget {
    #[serde(rename_all = "camelCase")]
    Existing {
        env_id: String,
    },
    New {
        name: String,
    },
}

/// What [`CHATS_EVENT`] carries.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct ChatsChanged {
    /// The conversation that changed, if one did.
    pub key: Option<String>,
}

/// A contact or one of the user's devices, as chats know it while online.
#[derive(Clone)]
struct Known {
    key: PeerKey,
    name: String,
    own: bool,
    contact: Arc<ContactKey>,
}

/// An item this side offered, until the other user answers.
struct Offer {
    peer: PeerKey,
    item: Item,
    since: Instant,
}

/// An item the other side offered, until it is saved or turned down.
struct Incoming {
    peer: PeerKey,
    summary: ItemSummary,
    accepted: bool,
}

#[derive(Default)]
pub(super) struct Chats {
    inner: Mutex<ChatInner>,
}

#[derive(Default)]
struct ChatInner {
    /// The page says Nearby is open.
    page_open: bool,
    /// Online until then after the user left Nearby or hid the window.
    grace_until: Option<Instant>,
    /// Listening and announced, while online.
    online: Option<presence::Online>,
    /// Contacts and the user's devices, read from the vault.
    known: Vec<Known>,
    /// Contacts found on the network, by mDNS name.
    found: BTreeMap<String, Found>,
    links: HashMap<PeerKey, Link>,
    /// Connections waiting at the knock.
    knocking: usize,
    /// The conversations read, while the vault is unlocked.
    conversations: HashMap<PeerKey, Conversation>,
    /// Conversations changed since they were last written.
    dirty: HashSet<PeerKey>,
    /// This computer's chat key, while the vault is unlocked.
    key: Option<Zeroizing<[u8; 32]>>,
    /// Every conversation of a contact has been read since the unlock.
    all_read: bool,
    offers: HashMap<String, Offer>,
    incoming: HashMap<String, Incoming>,
    /// Contacts turned away until then, for sending too much.
    paused: HashMap<PeerKey, Instant>,
    /// When each conversation last notified.
    notified: HashMap<PeerKey, Instant>,
    last_sweep: Option<Instant>,
}

struct Found {
    peer: PeerKey,
    addresses: Vec<SocketAddr>,
}

impl Chats {
    fn lock(&self) -> MutexGuard<'_, ChatInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Nearby {
    fn chats(&self) -> MutexGuard<'_, ChatInner> {
        self.chats.lock()
    }

    /// Starts the thread that keeps chats as they should be. Called once.
    pub(super) fn watch_chats(self: Arc<Self>) {
        thread::spawn(move || {
            loop {
                self.chat_tick();
                thread::sleep(TICK);
            }
        });
    }

    /// The page says whether Nearby is open.
    pub fn chat_set_open(self: &Arc<Self>, open: bool) {
        self.chats().page_open = open;
        let nearby = Arc::clone(self);
        thread::spawn(move || nearby.chat_tick());
    }

    /// One look at chats: online or not, the announcement's window, pings,
    /// links gone quiet, values whose term ended, conversations to write.
    fn chat_tick(self: &Arc<Self>) {
        let Ok(state) = self.state() else {
            return;
        };
        let unlocked = state.vault.is_unlocked();
        if !unlocked {
            self.chats_locked();
            return;
        }
        let visible = self
            .app()
            .ok()
            .and_then(|app| app.get_webview_window("main"))
            .is_some_and(|window| {
                window.is_visible().unwrap_or(false) && !window.is_minimized().unwrap_or(false)
            });
        let now = Instant::now();
        let want = {
            let mut chats = self.chats();
            if chats.page_open && visible {
                chats.grace_until = None;
                true
            } else if chats.online.is_some() {
                let until = *chats.grace_until.get_or_insert(now + GRACE);
                now < until
            } else {
                chats.grace_until = None;
                false
            }
        };
        let sweep = {
            let mut chats = self.chats();
            let due = chats
                .last_sweep
                .is_none_or(|last| now.duration_since(last) >= SWEEP);
            if due {
                chats.last_sweep = Some(now);
            }
            due
        };
        if sweep {
            self.read_known();
            self.read_all_conversations();
            self.wipe_expired();
            self.end_old_offers();
        }
        let online = self.chats().online.is_some();
        match (want, online) {
            (true, false) => {
                if let Err(error) = self.go_online() {
                    log::warn!("nearby: chats could not go online: {error}");
                }
            }
            (false, true) => self.go_offline(),
            (true, true) => self.renew_presence(),
            (false, false) => {}
        }
        self.keep_links_alive();
        self.write_conversations();
    }

    /// The vault locked: write what changed, then forget everything.
    fn chats_locked(self: &Arc<Self>) {
        if self.chats().online.is_some() {
            self.go_offline();
        }
        self.write_conversations();
        let mut chats = self.chats();
        if chats.key.is_none() && chats.conversations.is_empty() {
            return;
        }
        chats.conversations.clear();
        chats.dirty.clear();
        chats.key = None;
        chats.all_read = false;
        chats.known.clear();
        chats.offers.clear();
        chats.incoming.clear();
        drop(chats);
        self.chats_changed(None);
    }

    /// Reads the contacts and the user's devices from the vault.
    fn read_known(&self) {
        let Ok(identity) = self.identity() else {
            return;
        };
        let me = identity.public();
        let Ok(state) = self.state() else {
            return;
        };
        let Ok(app) = self.app() else {
            return;
        };
        let peers = state.vault.with_quietly(app, |vault| {
            let mut peers: Vec<(PeerKey, bool)> = Vec::new();
            for device in vault.own_devices() {
                if let Ok(key) = PeerKey::from_base64(&device.key)
                    && key != me
                {
                    peers.push((key, true));
                }
            }
            for contact in vault.contacts() {
                if let Ok(key) = PeerKey::from_base64(&contact.key)
                    && key != me
                    && !peers.iter().any(|(known, _)| *known == key)
                {
                    peers.push((key, false));
                }
            }
            Ok(peers
                .into_iter()
                .map(|(key, own)| {
                    let name = vault.known_name(&key).unwrap_or_else(|| "?".to_owned());
                    (key, own, name)
                })
                .collect::<Vec<_>>())
        });
        let Ok(peers) = peers else {
            return;
        };
        let known = known_of(&identity, peers);
        let mut chats = self.chats();
        // A contact removed meanwhile: its link goes too.
        let gone: Vec<PeerKey> = chats
            .links
            .keys()
            .filter(|key| !known.iter().any(|known| known.key == **key))
            .copied()
            .collect();
        for key in gone {
            if let Some(link) = chats.links.remove(&key) {
                link.writer.shutdown();
            }
        }
        chats.known = known;
    }

    /// This computer's chat key, if the vault has one: none is made just to
    /// read or delete (making one saves the vault).
    fn existing_chat_key(&self) -> AppResult<Option<Zeroizing<[u8; 32]>>> {
        if let Some(key) = &self.chats().key {
            return Ok(Some(key.clone()));
        }
        let me = self.identity()?.public();
        let state = self.state()?;
        let key = state
            .vault
            .with_quietly(self.app()?, |vault| Ok(vault.chat_key(&me)))?;
        if let Some(key) = &key {
            self.chats().key = Some(key.clone());
        }
        Ok(key)
    }

    /// This computer's chat key, made the first time it goes online.
    fn chat_key(&self) -> AppResult<Zeroizing<[u8; 32]>> {
        if let Some(key) = &self.chats().key {
            return Ok(key.clone());
        }
        let me = self.identity()?.public();
        let state = self.state()?;
        let app = self.app()?;
        let key = state.vault.with_quietly(app, |vault| {
            if vault.chat_key(&me).is_none() {
                vault.make_chat_key(&me, &state.backup_dir)?;
            }
            vault
                .chat_key(&me)
                .ok_or_else(|| AppError::new(ErrorCode::Io, "no chat key"))
        })?;
        self.chats().key = Some(key.clone());
        Ok(key)
    }

    fn folder(&self) -> PathBuf {
        self.data_dir.join(FOLDER)
    }

    fn file_of(&self, key: &[u8; 32], peer: &PeerKey) -> PathBuf {
        self.folder().join(format!(
            "{}.{}",
            file::file_stem(key, peer),
            file::EXTENSION
        ))
    }

    /// Reads the conversation with `peer` into memory, if it isn't there.
    fn load(&self, peer: &PeerKey) -> AppResult<()> {
        if self.chats().conversations.contains_key(peer) {
            return Ok(());
        }
        let Some(key) = self.existing_chat_key()? else {
            // No chat yet on this computer: an empty conversation.
            self.chats().conversations.entry(*peer).or_default();
            return Ok(());
        };
        let me = self.identity()?.public();
        let path = self.file_of(&key, peer);
        let mut conversation = match std::fs::read(&path) {
            Ok(bytes) => file::open(&key, &me, peer, &bytes).unwrap_or_else(|error| {
                // Kept aside, never overwritten: a vault from before its key.
                log::warn!("nearby: a chat file can't be read: {error}");
                let _ = std::fs::rename(&path, path.with_extension("unreadable"));
                Conversation::default()
            }),
            Err(_) => Conversation::default(),
        };
        let wiped = conversation.wipe_expired(unix_now());
        let mut chats = self.chats();
        chats.conversations.entry(*peer).or_insert(conversation);
        if wiped {
            chats.dirty.insert(*peer);
        }
        Ok(())
    }

    /// Reads every contact's conversation once after an unlock, so that
    /// values whose term ended are wiped before anything shows.
    fn read_all_conversations(&self) {
        let (done, peers) = {
            let chats = self.chats();
            (
                chats.all_read,
                chats
                    .known
                    .iter()
                    .map(|known| known.key)
                    .collect::<Vec<_>>(),
            )
        };
        if done || peers.is_empty() {
            return;
        }
        // No key yet means no chat yet: none is made just to look.
        if self.existing_chat_key().ok().flatten().is_some() {
            for peer in &peers {
                let _ = self.load(peer);
            }
        }
        self.chats().all_read = true;
    }

    /// Changes the conversation with `peer`, read first if need be, and
    /// marks it to be written.
    fn edit<T>(&self, peer: &PeerKey, work: impl FnOnce(&mut Conversation) -> T) -> AppResult<T> {
        self.load(peer)?;
        let mut chats = self.chats();
        let conversation = chats
            .conversations
            .get_mut(peer)
            .ok_or_else(|| AppError::not_found("the chat is gone"))?;
        let result = work(conversation);
        chats.dirty.insert(*peer);
        Ok(result)
    }

    /// Reads the conversation with `peer`.
    fn read<T>(&self, peer: &PeerKey, work: impl FnOnce(&Conversation) -> T) -> AppResult<T> {
        self.load(peer)?;
        let chats = self.chats();
        let conversation = chats
            .conversations
            .get(peer)
            .ok_or_else(|| AppError::not_found("the chat is gone"))?;
        Ok(work(conversation))
    }

    /// Writes the conversations that changed.
    fn write_conversations(&self) {
        let (key, dirty) = {
            let mut chats = self.chats();
            let Some(key) = chats.key.clone() else {
                return;
            };
            let dirty: Vec<PeerKey> = chats.dirty.drain().collect();
            (key, dirty)
        };
        if dirty.is_empty() {
            return;
        }
        let Ok(me) = self.identity().map(|identity| identity.public()) else {
            return;
        };
        if fsutil::ensure_private_dir(&self.folder()).is_err() {
            return;
        }
        for peer in dirty {
            let sealed = {
                let mut chats = self.chats();
                let Some(conversation) = chats.conversations.get_mut(&peer) else {
                    continue;
                };
                file::seal(&key, &me, &peer, conversation)
            };
            let written = sealed.map_err(AppError::from).and_then(|bytes| {
                fsutil::atomic_write(&self.file_of(&key, &peer), &bytes, 0o600)
                    .map_err(AppError::from)
            });
            if let Err(error) = written {
                log::warn!("nearby: a chat was not written: {error}");
                self.chats().dirty.insert(peer);
            }
        }
    }

    /// Wipes the values whose term ended.
    fn wipe_expired(&self) {
        let now = unix_now();
        let changed: Vec<PeerKey> = {
            let mut chats = self.chats();
            let mut changed = Vec::new();
            for (peer, conversation) in &mut chats.conversations {
                if conversation.wipe_expired(now) {
                    changed.push(*peer);
                }
            }
            chats.dirty.extend(changed.iter().copied());
            changed
        };
        for peer in changed {
            self.chats_changed(Some(&peer));
        }
    }

    /// Offers nobody answered within ten minutes end.
    fn end_old_offers(&self) {
        let old: Vec<(String, PeerKey)> = {
            let mut chats = self.chats();
            let old: Vec<(String, PeerKey)> = chats
                .offers
                .iter()
                .filter(|(_, offer)| offer.since.elapsed() >= link::OFFER_TIMEOUT)
                .map(|(id, offer)| (id.clone(), offer.peer))
                .collect();
            for (id, _) in &old {
                chats.offers.remove(id);
            }
            old
        };
        for (id, peer) in old {
            let _ = self.edit(&peer, |chat| set_outcome(chat, &id, Outcome::Ended));
            self.chats_changed(Some(&peer));
        }
    }

    /// The conversations, contacts and the user's devices first.
    pub fn chat_list(&self) -> AppResult<ChatList> {
        self.require_vault()?;
        if self.chats().known.is_empty() {
            self.read_known();
        }
        self.read_all_conversations();
        let chats = self.chats();
        let online_peers: HashSet<PeerKey> = chats
            .found
            .values()
            .map(|found| found.peer)
            .chain(chats.links.keys().copied())
            .collect();
        let online = chats.online.is_some();
        let mut list: Vec<ChatSummary> = chats
            .known
            .iter()
            .map(|known| {
                let conversation = chats.conversations.get(&known.key);
                ChatSummary {
                    key: known.key.to_string(),
                    name: known.name.clone(),
                    own: known.own,
                    online: online && online_peers.contains(&known.key),
                    unread: conversation
                        .map_or(0, |chat| u32::try_from(chat.unread()).unwrap_or(u32::MAX)),
                    last: conversation
                        .and_then(|chat| chat.entries().last())
                        .map(preview),
                }
            })
            .collect();
        list.sort_by(|a, b| {
            b.own
                .cmp(&a.own)
                .then(b.online.cmp(&a.online))
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        Ok(ChatList {
            online,
            chats: list,
        })
    }

    /// The conversation with `key`, as the page shows it.
    pub fn chat_history(&self, key: &str) -> AppResult<Vec<ChatEntry>> {
        self.require_vault()?;
        let peer = self.known_peer(key)?;
        self.read(&peer, |chat| chat.entries().iter().map(view).collect())
    }

    /// The user has seen the conversation.
    pub fn chat_mark_read(&self, key: &str) -> AppResult<()> {
        let peer = self.known_peer(key)?;
        if self.edit(&peer, Conversation::mark_read)? {
            self.chats_changed(Some(&peer));
        }
        Ok(())
    }

    pub fn chat_send_text(self: &Arc<Self>, key: &str, text: &str) -> AppResult<()> {
        let text = text.trim_end().to_owned();
        let frame = ChatFrame::Text { id: new_id(), text };
        frame
            .check()
            .map_err(|reason| AppError::invalid(format!("it can't be sent: {reason:?}")))?;
        self.send_new(key, frame)
    }

    pub fn chat_send_secret(
        self: &Arc<Self>,
        key: &str,
        label: &str,
        value: &SecretString,
        ttl: u64,
    ) -> AppResult<()> {
        if !TERMS.contains(&ttl) {
            return Err(AppError::invalid("not a term the app offers"));
        }
        let frame = ChatFrame::Secret {
            id: new_id(),
            label: label.trim().to_owned(),
            value: SecretText::new(value.expose_secret()),
            ttl,
            pad: String::new(),
        };
        frame
            .check()
            .map_err(|reason| AppError::invalid(format!("it can't be sent: {reason:?}")))?;
        self.send_new(key, frame)
    }

    /// Sends variables `names` of environment `env_id`, read from the vault.
    pub fn chat_send_variables(
        self: &Arc<Self>,
        key: &str,
        env_id: &str,
        names: &[String],
        ttl: u64,
    ) -> AppResult<()> {
        if !TERMS.contains(&ttl) {
            return Err(AppError::invalid("not a term the app offers"));
        }
        let peer = self.known_peer(key)?;
        // Online first: nothing is asked that can't go now.
        self.link_to(&peer)?;
        let state = self.state()?;
        let (label, variables) = state.vault.with(self.app()?, |vault| {
            let env = vault.environment(env_id)?;
            let label = envs::label(
                Some(vault.env_label(&env.summary).as_str()).filter(|label| !label.is_empty()),
                &env.summary.name,
            );
            let variables: Vec<EnvVariable> = vault
                .env_variables(env_id)?
                .into_iter()
                .filter(|var| names.contains(&var.name))
                .map(|var| EnvVariable {
                    value: var.value.expose_secret().to_owned(),
                    name: var.name,
                    secret: var.secret,
                    note: var.note,
                })
                .collect();
            Ok((label, variables))
        })?;
        if variables.is_empty() {
            return Err(AppError::invalid("no variables picked"));
        }
        let picked: Vec<String> = variables.iter().map(|var| var.name.clone()).collect();
        self.ask(&prompt::send_variables(
            &self.peer_name(&peer),
            &label,
            &picked,
        ))?;
        let frame = ChatFrame::Variables {
            id: new_id(),
            label,
            variables,
            ttl,
            pad: String::new(),
        };
        frame
            .check()
            .map_err(|reason| AppError::invalid(format!("they can't be sent: {reason:?}")))?;
        self.send_new(key, frame)
    }

    /// Offers an item, read as Nearby reads one to send.
    pub fn chat_send_item(self: &Arc<Self>, key: &str, request: &SendRequest) -> AppResult<()> {
        let peer = self.known_peer(key)?;
        let state = self.state()?;
        let item = items::build(&state, self.app()?, request)?;
        let features = self.link_to(&peer)?;
        if let Some(needed) = item.requires()
            && !features.iter().any(|feature| feature == needed)
        {
            return Err(AppError::new(
                ErrorCode::Unsupported,
                "the other computer can't take this yet: its app needs the new version",
            ));
        }
        let summary = item.summary();
        if let Some(prompt) = prompt::send_item(&self.peer_name(&peer), &summary) {
            self.ask(&prompt)?;
        }
        let id = new_id();
        self.chats().offers.insert(
            id.clone(),
            Offer {
                peer,
                item,
                since: Instant::now(),
            },
        );
        let frame = ChatFrame::Offer { id, item: summary };
        self.send_new(key, frame)
    }

    /// The user's answer to an item offered.
    pub fn chat_answer(self: &Arc<Self>, key: &str, id: &str, accept: bool) -> AppResult<()> {
        let peer = self.known_peer(key)?;
        if accept {
            let summary = self
                .chats()
                .incoming
                .get(id)
                .filter(|incoming| incoming.peer == peer && !incoming.accepted)
                .map(|incoming| incoming.summary.clone())
                .ok_or_else(|| AppError::not_found("the offer has ended"))?;
            // What goes into the vault is said yes to where the page can't.
            if let Some(prompt) = prompt::accept_item(&self.peer_name(&peer), &summary) {
                self.ask(&prompt)?;
            }
        }
        {
            let mut chats = self.chats();
            let incoming = chats
                .incoming
                .get_mut(id)
                .filter(|incoming| incoming.peer == peer && !incoming.accepted)
                .ok_or_else(|| AppError::not_found("the offer has ended"))?;
            incoming.accepted = accept;
            if !accept {
                chats.incoming.remove(id);
            }
        }
        let outcome = if accept {
            Outcome::Accepted
        } else {
            Outcome::Declined
        };
        self.edit(&peer, |chat| set_outcome(chat, id, outcome))?;
        self.chats_changed(Some(&peer));
        self.send_frame(
            &peer,
            &ChatFrame::Reply {
                id: id.to_owned(),
                accepted: accept,
                unsupported: false,
            },
        )
    }

    /// A secret's value, or a variable's (`name`), for the page to show.
    pub fn chat_reveal(&self, key: &str, id: &str, name: Option<&str>) -> AppResult<SecretString> {
        let peer = self.known_peer(key)?;
        self.require_vault()?;
        self.read(&peer, |chat| value_of(chat, id, name))?
    }

    /// Copies a secret's value, or a variable's, as the vault copies a
    /// password: kept out of clipboard history and cleared after a while.
    pub fn chat_copy(&self, key: &str, id: &str, name: Option<&str>) -> AppResult<CopyResult> {
        let value = self.chat_reveal(key, id, name)?;
        let state = self.state()?;
        let clears_in_secs = Arc::clone(&state.vault).copy(&value, true)?;
        Ok(CopyResult { clears_in_secs })
    }

    /// Wipes a secret or variables this user sent before their term. With
    /// `everywhere`, on the other computer too: it must be reachable now (a
    /// link opens if there is none), and the wipe goes there before the
    /// value goes here, so a "wiped on both" is never a "wiped here only".
    /// Without, only here.
    pub fn chat_revoke(self: &Arc<Self>, key: &str, id: &str, everywhere: bool) -> AppResult<()> {
        let peer = self.known_peer(key)?;
        let wipeable = self.read(&peer, |chat| {
            chat.get(id)
                .is_some_and(|entry| entry.mine && entry.body.expires().is_some())
        })?;
        if !wipeable {
            return Err(AppError::not_found("nothing to wipe"));
        }
        if everywhere {
            self.link_to(&peer)?;
            self.send_frame(&peer, &ChatFrame::Revoke { id: id.to_owned() })?;
        }
        self.edit(&peer, |chat| chat.wipe(id, false))?;
        self.chats_changed(Some(&peer));
        Ok(())
    }

    /// How many received messages, in every conversation read, the user
    /// hasn't seen: for the tray menu.
    pub fn chat_unread(&self) -> u32 {
        let chats = self.chats();
        let total: usize = chats
            .known
            .iter()
            .filter_map(|known| chats.conversations.get(&known.key))
            .map(Conversation::unread)
            .sum();
        u32::try_from(total).unwrap_or(u32::MAX)
    }

    /// Sends a message again that didn't arrive, under the same id.
    pub fn chat_retry(self: &Arc<Self>, key: &str, id: &str) -> AppResult<()> {
        let peer = self.known_peer(key)?;
        let frame = self
            .edit(&peer, |chat| {
                let entry = chat.get_mut(id)?;
                if !entry.mine || entry.delivery != Delivery::NotDelivered {
                    return None;
                }
                let frame = frame_of(entry, unix_now())?;
                entry.delivery = Delivery::Sending;
                Some(frame)
            })?
            .ok_or_else(|| AppError::not_found("nothing to send again"))?;
        self.chats_changed(Some(&peer));
        self.send_frame(&peer, &frame).inspect_err(|_| {
            let _ = self.edit(&peer, Conversation::disconnected);
            self.chats_changed(Some(&peer));
        })
    }

    /// What adding received variables to environment `env_id` would do;
    /// every variable is new for a new environment (`None`).
    pub fn chat_review_variables(
        &self,
        key: &str,
        id: &str,
        env_id: Option<&str>,
    ) -> AppResult<Vec<VarReview>> {
        let peer = self.known_peer(key)?;
        let received = self.read(&peer, |chat| received_variables(chat, id))??;
        let state = self.state()?;
        let existing: Vec<envs::EnvVariable> = match env_id {
            Some(env_id) => state
                .vault
                .with(self.app()?, |vault| Ok(vault.env_variables(env_id)?))?,
            None => Vec::new(),
        };
        Ok(received
            .iter()
            .map(|var| {
                let change = match existing.iter().find(|other| other.name == var.name) {
                    None => VarChange::New,
                    Some(other) if other.value.expose_secret() == var.value.expose_secret() => {
                        VarChange::Same
                    }
                    Some(_) => VarChange::Replaces,
                };
                VarReview {
                    name: var.name.clone(),
                    secret: var.secret,
                    change,
                    risky: risky_variable(&var.name),
                }
            })
            .collect())
    }

    /// Adds the received variables `names` to an environment, after the
    /// user reviewed them. Returns the environment's id.
    pub fn chat_add_variables(
        &self,
        key: &str,
        id: &str,
        target: &VarTarget,
        names: &[String],
    ) -> AppResult<String> {
        let peer = self.known_peer(key)?;
        let received = self.read(&peer, |chat| received_variables(chat, id))??;
        let picked: Vec<envs::EnvVariable> = received
            .into_iter()
            .filter(|var| names.contains(&var.name))
            .collect();
        if picked.is_empty() {
            return Err(AppError::invalid("no variables picked"));
        }
        let state = self.state()?;
        let (env_label, review) = match target {
            VarTarget::Existing { env_id } => {
                let label = state.vault.with(self.app()?, |vault| {
                    let env = vault.environment(env_id)?;
                    let project = vault.env_label(&env.summary);
                    Ok(envs::label(
                        Some(project.as_str()).filter(|label| !label.is_empty()),
                        &env.summary.name,
                    ))
                })?;
                (label, self.chat_review_variables(key, id, Some(env_id))?)
            }
            VarTarget::New { name } => (name.trim().to_owned(), Vec::new()),
        };
        let listed = |want: &dyn Fn(&VarReview) -> bool| -> Vec<String> {
            picked
                .iter()
                .filter(|var| {
                    review
                        .iter()
                        .any(|item| item.name == var.name && want(item))
                })
                .map(|var| var.name.clone())
                .collect()
        };
        let replaced = listed(&|item| item.change == VarChange::Replaces);
        let risky: Vec<String> = picked
            .iter()
            .filter(|var| risky_variable(&var.name))
            .map(|var| var.name.clone())
            .collect();
        let all: Vec<String> = picked.iter().map(|var| var.name.clone()).collect();
        self.ask(&prompt::add_variables(
            &self.peer_name(&peer),
            &env_label,
            &all,
            &replaced,
            &risky,
        ))?;
        let env_id = state
            .vault
            .change(self.app()?, &state.backup_dir, |vault| {
                let env_id = match target {
                    VarTarget::Existing { env_id } => {
                        vault.environment(env_id)?;
                        env_id.clone()
                    }
                    VarTarget::New { name } => vault.add_environment(&EnvInput {
                        project: None,
                        part: String::new(),
                        name: name.trim().to_owned(),
                        notes: String::new(),
                    })?,
                };
                vault.import_env_variables(&env_id, &picked)?;
                Ok(env_id)
            })?;
        Ok(env_id)
    }

    /// Deletes the conversation with `key` from this computer.
    pub fn chat_delete(&self, key: &str) -> AppResult<()> {
        let peer = PeerKey::from_base64(key)?;
        let chat_key = self.existing_chat_key()?;
        {
            let mut chats = self.chats();
            chats.conversations.remove(&peer);
            chats.dirty.remove(&peer);
            chats.incoming.retain(|_, incoming| incoming.peer != peer);
            chats.offers.retain(|_, offer| offer.peer != peer);
        }
        if let Some(chat_key) = chat_key {
            match std::fs::remove_file(self.file_of(&chat_key, &peer)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.chats_changed(Some(&peer));
        Ok(())
    }

    /// A contact or device was removed: its link closes, and with
    /// `delete_chat` its conversation goes.
    pub fn chat_forget(self: &Arc<Self>, key: &str, delete_chat: bool) {
        if let Ok(peer) = PeerKey::from_base64(key) {
            let link = self.chats().links.remove(&peer);
            if let Some(link) = link {
                link.writer.shutdown();
            }
        }
        if delete_chat && let Err(error) = self.chat_delete(key) {
            log::warn!("nearby: a removed contact's chat was not deleted: {error}");
        }
        self.read_known();
        self.chats().found.clear();
        self.chats_changed(None);
    }

    /// Asks in a system dialog the page can't answer; a no is an error.
    fn ask(&self, prompt: &prompt::Prompt) -> AppResult<()> {
        crate::confirm::require(self.app()?, &prompt.title, &prompt.body, &prompt.approve)
    }

    /// The name this vault keeps for `peer`.
    fn peer_name(&self, peer: &PeerKey) -> String {
        self.chats()
            .known
            .iter()
            .find(|known| known.key == *peer)
            .map_or_else(|| peer.to_string(), |known| known.name.clone())
    }

    /// The contact or device with this key.
    fn known_peer(&self, key: &str) -> AppResult<PeerKey> {
        let peer = PeerKey::from_base64(key)?;
        if self.chats().known.is_empty() {
            self.read_known();
        }
        if self.chats().known.iter().any(|known| known.key == peer) {
            Ok(peer)
        } else {
            Err(AppError::not_found("that computer is not a contact"))
        }
    }

    /// Stores a new message of this user's and sends it.
    fn send_new(self: &Arc<Self>, key: &str, frame: ChatFrame) -> AppResult<()> {
        let peer = self.known_peer(key)?;
        // Connected first: nothing is stored that can't go now.
        self.link_to(&peer)?;
        let entry =
            entry_of(&frame, true, unix_now()).ok_or_else(|| AppError::invalid("not a message"))?;
        self.edit(&peer, |chat| chat.push(entry))?;
        self.chats_changed(Some(&peer));
        let frame = frame.padded();
        self.send_frame(&peer, &frame).inspect_err(|_| {
            let _ = self.edit(&peer, Conversation::disconnected);
            self.chats_changed(Some(&peer));
        })
    }

    /// Tells the page that chats changed.
    fn chats_changed(&self, peer: Option<&PeerKey>) {
        if let Some(app) = self.app.get() {
            let _ = app.emit(
                CHATS_EVENT,
                ChatsChanged {
                    key: peer.map(ToString::to_string),
                },
            );
        }
    }

    /// Shows a notification for something new from `peer`, if the window
    /// isn't in front, at most one per conversation each half minute. It
    /// never says what came.
    fn notify(&self, peer: &PeerKey) {
        let Ok(app) = self.app() else {
            return;
        };
        let focused = app.get_webview_window("main").is_some_and(|window| {
            window.is_visible().unwrap_or(false) && window.is_focused().unwrap_or(false)
        });
        if focused {
            return;
        }
        let (name, unread) = {
            let mut chats = self.chats();
            if chats
                .notified
                .get(peer)
                .is_some_and(|last| last.elapsed() < link::NOTIFY_EVERY)
            {
                return;
            }
            chats.notified.insert(*peer, Instant::now());
            let name = chats
                .known
                .iter()
                .find(|known| known.key == *peer)
                .map_or_else(String::new, |known| known.name.clone());
            let unread = chats
                .conversations
                .get(peer)
                .map_or(1, Conversation::unread);
            (name, unread)
        };
        let body = if unread > 1 {
            Localized::new(
                format!("{unread} new messages"),
                format!("Новых сообщений: {unread}"),
                format!("{unread} ta yangi xabar"),
            )
        } else {
            Localized::new("New message", "Новое сообщение", "Yangi xabar")
        };
        if let Err(error) = app
            .notification()
            .builder()
            .title(name)
            .body(body.pick())
            .show()
        {
            log::warn!("nearby: no notification: {error}");
        }
    }
}

/// The contact keys of `peers` (key, own, name), own devices first.
fn known_of(identity: &Identity, peers: Vec<(PeerKey, bool, String)>) -> Vec<Known> {
    let mut known: Vec<Known> = peers
        .into_iter()
        .filter_map(|(key, own, name)| {
            let contact = identity.contact_key(&key).ok()?;
            Some(Known {
                key,
                name,
                own,
                contact: Arc::new(contact),
            })
        })
        .collect();
    known.sort_by_key(|known| std::cmp::Reverse(known.own));
    known
}

/// The entry a frame of a message makes, at `now`; `None` for frames that
/// aren't messages.
fn entry_of(frame: &ChatFrame, mine: bool, now: i64) -> Option<Entry> {
    let delivery = if mine {
        Delivery::Sending
    } else {
        Delivery::Received
    };
    let expires = |ttl: u64| now.saturating_add(i64::try_from(ttl).unwrap_or(i64::MAX));
    let (id, body) = match frame {
        ChatFrame::Text { id, text } => (id, Body::Text { text: text.clone() }),
        ChatFrame::Secret {
            id,
            label,
            value,
            ttl,
            ..
        } => (
            id,
            Body::Secret {
                label: label.clone(),
                value: Some(value.clone()),
                expires: expires(*ttl),
                gone: None,
            },
        ),
        ChatFrame::Variables {
            id,
            label,
            variables,
            ttl,
            ..
        } => (
            id,
            Body::Variables {
                label: label.clone(),
                variables: variables
                    .iter()
                    .map(|var| Var {
                        name: var.name.clone(),
                        value: Some(SecretText::new(var.value.as_str())),
                        secret: var.secret,
                        note: var.note.clone(),
                    })
                    .collect(),
                expires: expires(*ttl),
                gone: None,
            },
        ),
        ChatFrame::Offer { id, item } => (
            id,
            Body::Card {
                item: item.clone(),
                outcome: Outcome::Waiting,
                name: None,
                keys_differ: false,
                group: None,
            },
        ),
        _ => return None,
    };
    Some(Entry {
        id: id.clone(),
        mine,
        at: now,
        body,
        delivery,
    })
}

/// The frame that sends a message of this user's again, with what is left
/// of its term; `None` once its value is gone.
fn frame_of(entry: &Entry, now: i64) -> Option<ChatFrame> {
    let ttl = |expires: i64| {
        let left = u64::try_from(expires.saturating_sub(now)).ok()?;
        (left > 0).then(|| left.clamp(MIN_TTL, MAX_TTL))
    };
    let id = entry.id.clone();
    let frame = match &entry.body {
        Body::Text { text } => ChatFrame::Text {
            id,
            text: text.clone(),
        },
        Body::Secret {
            label,
            value: Some(value),
            expires,
            gone: None,
        } => ChatFrame::Secret {
            id,
            label: label.clone(),
            value: value.clone(),
            ttl: ttl(*expires)?,
            pad: String::new(),
        },
        Body::Variables {
            label,
            variables,
            expires,
            gone: None,
        } => ChatFrame::Variables {
            id,
            label: label.clone(),
            variables: variables
                .iter()
                .map(|var| {
                    Some(EnvVariable {
                        name: var.name.clone(),
                        value: var.value.as_ref()?.expose().to_owned(),
                        secret: var.secret,
                        note: var.note.clone(),
                    })
                })
                .collect::<Option<Vec<_>>>()?,
            ttl: ttl(*expires)?,
            pad: String::new(),
        },
        _ => return None,
    };
    Some(frame.padded())
}

fn set_outcome(chat: &mut Conversation, id: &str, outcome: Outcome) {
    if let Some(Entry {
        body: Body::Card { outcome: now, .. },
        ..
    }) = chat.get_mut(id)
    {
        *now = outcome;
    }
}

/// The value of secret `id`, or of its variable `name`.
fn value_of(chat: &Conversation, id: &str, name: Option<&str>) -> AppResult<SecretString> {
    let gone = || AppError::not_found("the value is gone");
    match (&chat.get(id).ok_or_else(gone)?.body, name) {
        (Body::Secret { value, .. }, None) => value
            .as_ref()
            .map(|value| SecretString::from(value.expose()))
            .ok_or_else(gone),
        (Body::Variables { variables, .. }, Some(name)) => variables
            .iter()
            .find(|var| var.name == name)
            .and_then(|var| var.value.as_ref())
            .map(|value| SecretString::from(value.expose()))
            .ok_or_else(gone),
        _ => Err(gone()),
    }
}

/// The variables of received message `id`, while their values are there.
fn received_variables(chat: &Conversation, id: &str) -> AppResult<Vec<envs::EnvVariable>> {
    let gone = || AppError::not_found("the variables are gone");
    let entry = chat.get(id).ok_or_else(gone)?;
    let Body::Variables {
        variables,
        gone: None,
        ..
    } = &entry.body
    else {
        return Err(gone());
    };
    if entry.mine {
        return Err(AppError::invalid("these are the variables you sent"));
    }
    variables
        .iter()
        .map(|var| {
            Ok(envs::EnvVariable {
                name: var.name.clone(),
                value: SecretString::from(var.value.as_ref().ok_or_else(gone)?.expose()),
                secret: var.secret,
                note: var.note.clone(),
            })
        })
        .collect()
}

fn view(entry: &Entry) -> ChatEntry {
    let body = match &entry.body {
        Body::Text { text } => EntryView::Text { text: text.clone() },
        Body::Secret {
            label,
            expires,
            gone,
            ..
        } => EntryView::Secret {
            label: label.clone(),
            expires: gone.is_none().then(|| rfc3339(*expires)),
            gone: *gone,
        },
        Body::Variables {
            label,
            variables,
            expires,
            gone,
        } => EntryView::Variables {
            label: label.clone(),
            variables: variables
                .iter()
                .map(|var| VarView {
                    name: var.name.clone(),
                    secret: var.secret,
                    value: if var.secret {
                        None
                    } else {
                        var.value.as_ref().map(|value| value.expose().to_owned())
                    },
                    risky: risky_variable(&var.name),
                })
                .collect(),
            expires: gone.is_none().then(|| rfc3339(*expires)),
            gone: *gone,
        },
        Body::Card {
            item,
            outcome,
            name,
            keys_differ,
            group,
        } => EntryView::Card {
            item: item.clone(),
            outcome: *outcome,
            name: name.clone(),
            keys_differ: *keys_differ,
            group: *group,
        },
        Body::Line { line } => EntryView::Line { line: *line },
    };
    ChatEntry {
        id: entry.id.clone(),
        mine: entry.mine,
        at: rfc3339(entry.at),
        delivery: entry.delivery,
        body,
    }
}

fn preview(entry: &Entry) -> ChatPreview {
    let (kind, text) = match &entry.body {
        Body::Text { text } => (
            "text",
            Some(text.lines().next().unwrap_or_default().to_owned()),
        ),
        Body::Secret { .. } => ("secret", None),
        Body::Variables { .. } => ("variables", None),
        Body::Card { .. } => ("card", None),
        Body::Line { .. } => ("line", None),
    };
    ChatPreview {
        at: rfc3339(entry.at),
        mine: entry.mine,
        kind: kind.to_owned(),
        text,
    }
}

fn unix_now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn rfc3339(unix: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|time| time.format(&Rfc3339).ok())
        .unwrap_or_default()
}

/// A flag a listener stops on.
type Stop = Arc<AtomicBool>;

#[cfg(test)]
mod tests {
    use super::*;

    fn secret_frame(ttl: u64) -> ChatFrame {
        ChatFrame::Secret {
            id: new_id(),
            label: "db".into(),
            value: SecretText::new("s3cret"),
            ttl,
            pad: String::new(),
        }
    }

    #[test]
    fn a_message_sent_again_keeps_what_is_left_of_its_term() {
        let entry = entry_of(&secret_frame(TERMS[0]), true, 1_000).unwrap();
        let Some(ChatFrame::Secret { ttl, id, .. }) = frame_of(&entry, 1_000 + 600) else {
            panic!("not a secret")
        };
        assert_eq!(ttl, TERMS[0] - 600);
        assert_eq!(id, entry.id);
        // Its term over, it isn't sent again.
        assert!(frame_of(&entry, 1_000 + 3_600).is_none());
        // A little left still makes a term the other side takes.
        let Some(ChatFrame::Secret { ttl, .. }) = frame_of(&entry, 1_000 + 3_590) else {
            panic!("not a secret")
        };
        assert_eq!(ttl, MIN_TTL);
    }

    #[test]
    fn the_page_never_sees_a_secret_value() {
        let secret = entry_of(&secret_frame(TERMS[1]), false, 5).unwrap();
        let json = serde_json::to_string(&view(&secret)).unwrap();
        assert!(!json.contains("s3cret"));
        let variables = entry_of(
            &ChatFrame::Variables {
                id: new_id(),
                label: "shop · prod".into(),
                variables: vec![
                    EnvVariable {
                        name: "API_KEY".into(),
                        value: "hidden-value".into(),
                        secret: true,
                        note: String::new(),
                    },
                    EnvVariable {
                        name: "LD_PRELOAD".into(),
                        value: "/tmp/x.so".into(),
                        secret: false,
                        note: String::new(),
                    },
                ],
                ttl: TERMS[0],
                pad: String::new(),
            },
            false,
            5,
        )
        .unwrap();
        let view = view(&variables);
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("hidden-value"));
        let EntryView::Variables { variables, .. } = view.body else {
            panic!("not variables")
        };
        assert!(variables[1].risky && variables[1].value.as_deref() == Some("/tmp/x.so"));
        assert!(!variables[0].risky);
    }

    #[test]
    fn values_are_read_one_at_a_time_and_not_after_they_go() {
        let mut chat = Conversation::default();
        let entry = entry_of(&secret_frame(TERMS[0]), false, 1).unwrap();
        chat.receive(entry.clone());
        assert_eq!(
            value_of(&chat, &entry.id, None).unwrap().expose_secret(),
            "s3cret"
        );
        assert!(value_of(&chat, &entry.id, Some("X")).is_err());
        chat.wipe_expired(1 + 3_600);
        assert!(value_of(&chat, &entry.id, None).is_err());
    }
}
