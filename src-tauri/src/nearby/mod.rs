//! Nearby: other copies of the app on the local network.
//!
//! - **Visible.** For ten minutes after the user asks, the app listens on a
//!   TCP port and announces it with mDNS as `_sshkm._tcp`, under a random
//!   instance name with the device name in the TXT record. A computer
//!   without a vault can be visible to get one (`join=1` in the record).
//!   It announces nothing otherwise, but to the user's own devices
//!   ([`presence`]).
//! - **Looking.** While the Nearby page is open, the app browses for others.
//! - **Chats.** While Nearby is open, with contacts and the user's devices
//!   online too ([`chat`]); outside the one conversation at a time below.
//! - **Conversations.** One at a time, started from either side: a Noise
//!   session ([`sshkm_core::p2p`]), then [`pairing::conversation`]: pairing
//!   and sending, adding one of the user's devices ([`own`]), or a sync
//!   ([`sync`]). Contacts and devices are kept in the vault, so all of them
//!   need it unlocked, but for a computer being given one.
//!
//! The device key lives in the system's credential store; the device name,
//! and the fingerprints of public keys received from others, in
//! `nearby.json` in the app's data folder. The UI follows [`CHANGED_EVENT`],
//! which carries the whole [`NearbyStatus`].
//!
//! Nearby stays on the local network: it connects only to addresses there
//! and takes connections only from there ([`on_local_network`]). A
//! connection gets a conversation only once its handshake is done, which
//! has a deadline; until then it holds up no other.

pub mod chat;
pub mod items;
pub mod own;
pub mod pairing;
mod presence;
pub mod prompt;
#[cfg(test)]
mod script;
mod store;
pub mod sync;
pub mod transfer;

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sshkm_core::config::SshConfig;
use sshkm_core::known_hosts::KnownHosts;
use sshkm_core::p2p::deadline::Deadline;
use sshkm_core::p2p::protocol::{EntrySync, Intent, Item, SecretText, VaultState, clean_name};
use sshkm_core::p2p::{self, Identity, Message, PeerKey, Session};
use sshkm_core::paths::home_dir;
use sshkm_core::sync::Hasher;
use sshkm_core::sync::host_keys;
use sshkm_core::vault::envs::files::{CloudRoots, CloudService};
use sshkm_core::vault::sync::{
    ENTRY_SYNC_VERSION, Pairs, Party, PeerVault, VaultApplied, VaultBase, VaultChoices, VaultPlan,
    check_moved, digests,
};
use sshkm_core::vault::{self, Vault};
use sshkm_core::{ErrorCode, ExposeSecret, SecretString, fsutil};
use tauri::{AppHandle, Emitter, Listener, Manager};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

use self::items::{ReceivedGroup, SendRequest};
use self::pairing::{
    PairingFailure, PairingPhase, Purpose, Side, Stored, VaultItems, broken, conversation_after,
};
pub use self::presence::OWN_SERVICE_TYPE;
use self::presence::{OwnFound, Presence};
use self::sync::{RiskyChange, RiskyVariables, SyncDecisions, SyncLocal, SyncState, SyncWrite};
use crate::commands::Shared;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// Emitted with the [`NearbyStatus`] whenever it changes.
pub const CHANGED_EVENT: &str = "nearby-changed";
/// Emitted when a contact was added.
pub const CONTACTS_EVENT: &str = "nearby-contacts";
/// Emitted when the user's devices changed.
pub const DEVICES_EVENT: &str = "nearby-devices";

/// The mDNS service type the app announces and looks for.
pub const SERVICE_TYPE: &str = "_sshkm._tcp.local.";
const VISIBLE_FOR: Duration = Duration::from_secs(10 * 60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// For the handshake and `Hello`; comparing codes waits longer.
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a connection has for its first steps (the handshake and, on
/// the side connected to, the other's `Hello`), however slowly its bytes
/// come.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Most connections in their first steps at once, on each port this
/// computer listens on; more are closed at once.
const MAX_HANDSHAKES: usize = 4;
/// Most of those from one address, so one computer can't take them all.
const MAX_HANDSHAKES_PER_ADDRESS: usize = 2;
/// How many times, while this computer is visible, others may hang up
/// after they could work out the code it would show and before it showed
/// it, before it hides: someone may be trying until the code is one they
/// want.
const MAX_BROKEN_OFF: u32 = 3;
/// Most values the user may see in one sync's review, both sides' counted.
const MAX_VALUES_SHOWN: u32 = 200;
const KEY_SERVICE: &str = "SSH Key Manager nearby";
const KEY_ACCOUNT: &str = "device";
const SETTINGS_FILE: &str = "nearby.json";
/// What the hashes of a sync's snapshots are keyed with.
pub const BASE_LABEL: &[u8] = b"sshkm sync base";
/// The same for the vault's snapshots.
pub const VAULT_BASE_LABEL: &[u8] = b"sshkm sync vault base";

/// What the Nearby page shows.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each is one thing the page shows on its own"
)]
pub struct NearbyStatus {
    /// This device's name, as others see it.
    pub name: String,
    /// Visible to others until then (RFC 3339), if it is.
    pub visible_until: Option<String>,
    /// While visible: where others can reach it by address, `ip:port`.
    pub address: Option<String>,
    /// Visible to be given a vault by another of the user's computers.
    pub joining: bool,
    /// It stopped being visible early: other devices broke off pairing
    /// with it too many times before a code showed.
    pub hidden_after_attempts: bool,
    /// Reachable by the user's devices while the vault is unlocked: the
    /// setting.
    pub reachable: bool,
    /// Announced to the user's devices now.
    pub present: bool,
    /// The user's devices found on the network now, by device key.
    pub own_found: Vec<String>,
    /// Devices found on the network, by name.
    pub devices: Vec<NearbyDevice>,
    /// The conversation going on, or just over.
    pub pairing: Option<Pairing>,
}

/// Another copy of the app, visible on the network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct NearbyDevice {
    /// What `nearby_pair` takes to reach it.
    pub id: String,
    pub name: String,
    /// It has no vault and waits to be given one.
    pub joining: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct Pairing {
    pub id: u32,
    /// The other device's name once it said who it is: for a contact or
    /// one of the user's devices the one the vault keeps for it, else the
    /// one it gave.
    pub peer: Option<String>,
    /// This side connected.
    pub outgoing: bool,
    pub kind: ConversationKind,
    pub phase: PairingPhase,
}

/// What a conversation is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum ConversationKind {
    /// Pairing, and maybe sending an item.
    Pair,
    /// Adding one of the user's devices.
    Device,
    Sync,
}

impl ConversationKind {
    fn of(intent: Option<Intent>) -> Self {
        match intent {
            Some(Intent::AddDevice) => Self::Device,
            Some(Intent::Sync) => Self::Sync,
            _ => Self::Pair,
        }
    }
}

/// One of the user's devices, as the Nearby page lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct MyDevice {
    pub key: String,
    pub name: String,
    /// RFC 3339, UTC.
    pub added: String,
    /// It is this computer.
    pub this: bool,
    /// When this computer last synced with it: RFC 3339, UTC.
    pub last_sync: Option<String>,
    /// Found on the network now.
    pub reachable: bool,
    /// The device a sync with which made it one of the user's on this
    /// computer, by its name then; `None` when it was added here.
    pub learned_from: Option<String>,
}

/// What `nearby.json` holds.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Settings {
    /// The device name the user chose.
    name: Option<String>,
    /// Fingerprints of public keys received from others, which the audit
    /// knows have no private key here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    received_keys: Vec<String>,
    /// `false`: not announced to the user's devices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reachable: Option<bool>,
}

pub type SharedNearby = Arc<Nearby>;

pub struct Nearby {
    data_dir: PathBuf,
    app: OnceLock<AppHandle>,
    next_id: AtomicU32,
    /// Connections in their handshake (see [`MAX_HANDSHAKES`]).
    handshakes: Mutex<Pending>,
    inner: Mutex<Inner>,
    chats: chat::Chats,
}

#[derive(Default)]
struct Inner {
    name: String,
    settings: Settings,
    /// The last hosts file group received, until another one comes.
    received_group: Option<ReceivedGroup>,
    identity: Option<Arc<Identity>>,
    mdns: Option<ServiceDaemon>,
    visible: Option<Visible>,
    looking: bool,
    devices: BTreeMap<String, Found>,
    presence: Option<Presence>,
    /// The user's devices found, by mDNS name.
    own_found: BTreeMap<String, OwnFound>,
    pairing: Option<Slot>,
    /// Conversations broken off since this computer was made visible (see
    /// [`MAX_BROKEN_OFF`]).
    broken_off: u32,
    /// Visibility ended because of them.
    hidden_after_attempts: bool,
}

struct Visible {
    until: OffsetDateTime,
    port: u16,
    /// Visible to be given a vault.
    join: bool,
    /// The mDNS name it is announced under.
    fullname: String,
    stop: Arc<AtomicBool>,
}

struct Found {
    name: String,
    joining: bool,
    addresses: Vec<SocketAddr>,
}

/// What the user answered a conversation, and the step it was asked at: an
/// answer meant for an earlier step (a second click on "Codes match") is
/// dropped, never taken for the next question.
struct Answer {
    at: PairingPhase,
    said: Said,
}

enum Said {
    /// Yes or no to the question shown: the codes match, the item is
    /// welcome.
    Yes(bool),
    /// The user confirmed adding the device with Touch ID / Windows Hello
    /// or the master password. Only [`Nearby::authorize`] says it, after
    /// checking; the page can't.
    Authorized,
    /// What to do with the changes of a sync.
    Decided(SyncDecisions),
}

impl Said {
    /// Whether this answers what `phase` asks.
    fn fits(&self, phase: &PairingPhase) -> bool {
        match self {
            Self::Yes(_) => matches!(
                phase,
                PairingPhase::Compare { .. }
                    | PairingPhase::Offered { .. }
                    | PairingPhase::NameMismatch { .. }
            ),
            Self::Authorized => matches!(phase, PairingPhase::Authorize { .. }),
            Self::Decided(_) => matches!(phase, PairingPhase::Decide { .. }),
        }
    }
}

/// A vault another computer gave, until the user sets its master password.
struct PendingVault {
    file: Zeroizing<Vec<u8>>,
    secret: SecretString,
}

struct Slot {
    view: Pairing,
    /// Gives the user's answers to the conversation's thread.
    answer: Option<Sender<Answer>>,
    /// The connection, to end it when the user cancels.
    socket: Option<TcpStream>,
    cancelled: Arc<AtomicBool>,
    pending: Option<PendingVault>,
    /// The name this vault keeps for the other device, if it knows it.
    known: Option<String>,
    /// The code both users compared, for the system dialogs after it.
    code: Option<String>,
    /// The other device's copy of the vault during a sync, for the values
    /// of a conflict the user asks to see; dropped when the sync ends or
    /// the vault locks.
    peer_vault: Option<Arc<PeerVault>>,
    /// How many values the user asked to see in this sync's review.
    values_shown: u32,
}

impl Slot {
    fn active(&self) -> bool {
        !self.view.phase.is_over()
    }
}

impl Nearby {
    pub fn new(data_dir: PathBuf) -> Self {
        let settings: Settings = std::fs::read(data_dir.join(SETTINGS_FILE))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        let name = settings
            .name
            .as_deref()
            .map(clean_name)
            .filter(|name| !name.is_empty())
            .unwrap_or_else(default_name);
        Self {
            data_dir,
            app: OnceLock::new(),
            next_id: AtomicU32::new(1),
            handshakes: Mutex::default(),
            inner: Mutex::new(Inner {
                name,
                settings,
                ..Inner::default()
            }),
            chats: chat::Chats::default(),
        }
    }

    /// Hands over the app, for events and the vault, and starts keeping
    /// this computer announced to the user's devices. Called once at start.
    pub fn attach(self: &Arc<Self>, app: AppHandle) {
        // The other device's copy of the vault goes when the vault locks,
        // as the vault itself does.
        let nearby = Arc::downgrade(self);
        app.listen_any(crate::vault::LOCKED_EVENT, move |_| {
            if let Some(nearby) = nearby.upgrade() {
                nearby.forget_peer_vault();
            }
        });
        let _ = self.app.set(app);
        Arc::clone(self).watch_presence();
        Arc::clone(self).watch_chats();
    }

    /// Drops the other device's copy of the vault, if a sync holds one.
    fn forget_peer_vault(&self) {
        if let Some(slot) = self.lock().pairing.as_mut() {
            slot.peer_vault = None;
        }
    }

    pub fn status(&self) -> NearbyStatus {
        let inner = self.lock();
        let mut own_found: Vec<String> = inner
            .own_found
            .values()
            .map(|found| found.key.to_string())
            .collect();
        own_found.sort();
        own_found.dedup();
        NearbyStatus {
            name: inner.name.clone(),
            visible_until: inner
                .visible
                .as_ref()
                .and_then(|visible| visible.until.format(&Rfc3339).ok()),
            address: inner
                .visible
                .as_ref()
                .and_then(|visible| Some(SocketAddr::new(local_ip()?, visible.port).to_string())),
            joining: inner.visible.as_ref().is_some_and(|visible| visible.join),
            hidden_after_attempts: inner.hidden_after_attempts,
            reachable: inner.settings.reachable != Some(false),
            present: inner.presence.is_some(),
            own_found,
            devices: {
                let mut devices: Vec<NearbyDevice> = inner
                    .devices
                    .iter()
                    .map(|(id, found)| NearbyDevice {
                        id: id.clone(),
                        name: found.name.clone(),
                        joining: found.joining,
                    })
                    .collect();
                devices.sort_by_key(|device| device.name.to_lowercase());
                devices
            },
            pairing: inner.pairing.as_ref().map(|slot| slot.view.clone()),
        }
    }

    pub fn set_name(&self, name: &str) -> AppResult<NearbyStatus> {
        let name = clean_name(name);
        if name.is_empty() {
            return Err(AppError::invalid("a device needs a name"));
        }
        let visible = {
            let mut inner = self.lock();
            let settings = Settings {
                name: Some(name.clone()),
                ..inner.settings.clone()
            };
            self.save(&mut inner, settings)?;
            inner.name = name;
            inner.visible.is_some()
        };
        // Others see the new name once it is announced again.
        if visible {
            self.announce()?;
        }
        Ok(self.changed())
    }

    /// Whether this computer is announced to the user's devices while the
    /// vault is unlocked.
    pub fn set_reachable(self: &Arc<Self>, on: bool) -> AppResult<NearbyStatus> {
        {
            let mut inner = self.lock();
            let settings = Settings {
                reachable: (!on).then_some(false),
                ..inner.settings.clone()
            };
            self.save(&mut inner, settings)?;
        }
        self.reconcile_presence();
        Ok(self.changed())
    }

    /// Fingerprints of the public keys received from others.
    pub fn received_keys(&self) -> Vec<String> {
        self.lock().settings.received_keys.clone()
    }

    /// Remembers a public key received from someone else.
    fn remember_key(&self, fingerprint: &str) -> AppResult<()> {
        let mut inner = self.lock();
        if inner
            .settings
            .received_keys
            .iter()
            .any(|known| known == fingerprint)
        {
            return Ok(());
        }
        let mut settings = inner.settings.clone();
        settings.received_keys.push(fingerprint.to_owned());
        self.save(&mut inner, settings)
    }

    /// The hosts file group that came with pairing `id`, if it is the last
    /// one received.
    pub fn received_group(&self, id: u32) -> Option<ReceivedGroup> {
        self.lock()
            .received_group
            .clone()
            .filter(|group| group.id == id)
    }

    fn keep_group(&self, group: ReceivedGroup) {
        self.lock().received_group = Some(group);
    }

    /// Writes `settings` to `nearby.json`, with the lock held so that two
    /// writes never cross, and keeps them.
    fn save(&self, inner: &mut Inner, settings: Settings) -> AppResult<()> {
        let json = serde_json::to_vec_pretty(&settings)
            .map_err(|e| AppError::new(ErrorCode::Io, e.to_string()))?;
        fsutil::ensure_private_dir(&self.data_dir)?;
        fsutil::atomic_write(&self.data_dir.join(SETTINGS_FILE), &json, 0o600)?;
        inner.settings = settings;
        Ok(())
    }

    /// Makes this device visible for ten minutes, or hides it.
    pub fn set_visible(self: &Arc<Self>, on: bool) -> AppResult<NearbyStatus> {
        self.show(on, false)
    }

    /// Makes this computer, which has no vault, visible for ten minutes to
    /// be given the vault by another of the user's computers; or hides it.
    pub fn join(self: &Arc<Self>, on: bool) -> AppResult<NearbyStatus> {
        self.show(on, true)
    }

    fn show(self: &Arc<Self>, on: bool, join: bool) -> AppResult<NearbyStatus> {
        self.hide();
        {
            let mut inner = self.lock();
            inner.broken_off = 0;
            inner.hidden_after_attempts = false;
        }
        if !on {
            return Ok(self.changed());
        }
        self.identity()?;
        if join {
            let state = self.state()?;
            if state.vault.is_unlocked() || state.vault.paths().database.exists() {
                return Err(AppError::new(
                    ErrorCode::AlreadyExists,
                    "this computer has a vault already",
                ));
            }
        } else {
            self.require_vault()?;
        }
        let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let stop = Arc::new(AtomicBool::new(false));
        let deadline = Instant::now() + VISIBLE_FOR;
        {
            let mut inner = self.lock();
            inner.visible = Some(Visible {
                until: OffsetDateTime::now_utc() + VISIBLE_FOR,
                port,
                join,
                fullname: String::new(),
                stop: Arc::clone(&stop),
            });
        }
        if let Err(error) = self.announce() {
            self.hide();
            return Err(error);
        }
        let nearby = Arc::clone(self);
        thread::spawn(move || nearby.listen(&listener, &stop, deadline));
        Ok(self.changed())
    }

    /// Starts or stops looking for others; the Nearby page looks while open.
    pub fn set_looking(self: &Arc<Self>, on: bool) -> AppResult<NearbyStatus> {
        let mut inner = self.lock();
        if on == inner.looking {
            drop(inner);
            return Ok(self.status());
        }
        let daemon = mdns(&mut inner)?;
        if on {
            let events = daemon.browse(SERVICE_TYPE).map_err(mdns_error)?;
            inner.looking = true;
            drop(inner);
            let nearby = Arc::clone(self);
            thread::spawn(move || {
                while let Ok(event) = events.recv() {
                    if !nearby.found(event) {
                        break;
                    }
                }
            });
        } else {
            let _ = daemon.stop_browse(SERVICE_TYPE);
            inner.looking = false;
            inner.devices.clear();
            drop(inner);
        }
        Ok(self.changed())
    }

    /// Pairs with a device found on the network (its id) or at an address
    /// (`host:port`). The result comes as events.
    pub fn pair(self: &Arc<Self>, target: &str) -> AppResult<u32> {
        self.start(target, Goal::Pair)
    }

    /// Sends what `request` names to a device found on the network, pairing
    /// first if the two don't know each other. The result comes as events.
    pub fn send(self: &Arc<Self>, target: &str, request: &SendRequest) -> AppResult<u32> {
        let state = self.state()?;
        let item = items::build(&state, self.app()?, request)?;
        // The name it was picked under, to hold against the one the vault
        // keeps for the device that answers.
        let to = self
            .lock()
            .devices
            .get(target)
            .map(|found| found.name.clone());
        self.start(
            target,
            Goal::Send {
                item: Box::new(item),
                to,
            },
        )
    }

    /// Makes a device found on the network (or at an address) one of the
    /// user's devices, giving it the vault if it has none. The result comes
    /// as events.
    pub fn add_device(self: &Arc<Self>, target: &str) -> AppResult<u32> {
        // The other computer gets the key own devices share with the vault
        // file, or reads it from the file the two already share.
        self.ensure_own_key()?;
        self.start(target, Goal::AddDevice)
    }

    /// Syncs with one of the user's devices found on the network (`key`),
    /// or with each found, one after another. The results come as events.
    pub fn sync(self: &Arc<Self>, key: Option<&str>) -> AppResult<()> {
        let identity = self.identity()?;
        self.require_vault()?;
        let mut targets: Vec<(PeerKey, Vec<SocketAddr>)> = Vec::new();
        for found in self.lock().own_found.values() {
            if key.is_some_and(|key| key != found.key.to_string()) {
                continue;
            }
            match targets.iter_mut().find(|(k, _)| *k == found.key) {
                Some((_, addresses)) => addresses.extend(&found.addresses),
                None => targets.push((found.key, found.addresses.clone())),
            }
        }
        if targets.is_empty() {
            return Err(AppError::not_found("no device of yours is reachable"));
        }
        let (id, answers, cancelled) = self.claim(true, ConversationKind::Sync)?;
        let nearby = Arc::clone(self);
        thread::spawn(move || {
            let mut slot = Some((id, answers, cancelled));
            for (_, addresses) in targets {
                let Some((id, answers, cancelled)) = slot
                    .take()
                    .or_else(|| nearby.claim(true, ConversationKind::Sync).ok())
                else {
                    break;
                };
                nearby.connect_and_run(id, &addresses, &identity, Goal::Sync, answers, &cancelled);
            }
        });
        Ok(())
    }

    fn start(self: &Arc<Self>, target: &str, goal: Goal) -> AppResult<u32> {
        let identity = self.identity()?;
        self.require_vault()?;
        let found = self
            .lock()
            .devices
            .get(target)
            .map(|found| found.addresses.clone());
        let addresses = match found {
            Some(addresses) => addresses,
            None => target
                .trim()
                .to_socket_addrs()
                .map_err(|_| AppError::invalid("not an address: host:port"))?
                .collect(),
        };
        // Only ever to another computer on this network, whatever a name
        // resolves to or a device announces.
        let subnets = local_subnets();
        let addresses: Vec<SocketAddr> = addresses
            .into_iter()
            .filter(|address| on_local_network(address.ip(), &subnets))
            .collect();
        if addresses.is_empty() {
            return Err(AppError::invalid(
                "Nearby reaches only computers on the local network",
            ));
        }
        let (id, answers, cancelled) = self.claim(true, goal.kind())?;
        let nearby = Arc::clone(self);
        thread::spawn(move || {
            nearby.connect_and_run(id, &addresses, &identity, goal, answers, &cancelled);
        });
        Ok(id)
    }

    fn connect_and_run(
        self: &Arc<Self>,
        id: u32,
        addresses: &[SocketAddr],
        identity: &Identity,
        goal: Goal,
        answers: Receiver<Answer>,
        cancelled: &Arc<AtomicBool>,
    ) {
        let Some(stream) = addresses
            .iter()
            .take_while(|_| !cancelled.load(Ordering::SeqCst))
            .find_map(|address| TcpStream::connect_timeout(address, CONNECT_TIMEOUT).ok())
        else {
            let reason = if cancelled.load(Ordering::SeqCst) {
                PairingFailure::Cancelled
            } else {
                PairingFailure::Unreachable
            };
            self.finish(id, PairingPhase::Failed { reason });
            return;
        };
        self.run(
            id,
            stream,
            identity,
            &Role::Connects(goal),
            answers,
            cancelled,
        );
    }

    /// The user's answer: whether the codes match, or whether to accept an
    /// item. Taken only while the conversation asks one of those.
    pub fn answer(&self, id: u32, matched: bool) -> AppResult<()> {
        self.tell(id, Said::Yes(matched))
    }

    /// The user's decisions on what a sync brings.
    pub fn decide(&self, id: u32, decisions: SyncDecisions) -> AppResult<()> {
        self.tell(id, Said::Decided(decisions))
    }

    /// The user's yes to making the other computer one of their devices,
    /// with the master password or, without one, Touch ID / Windows Hello.
    /// Either names the computer by the code both screens show (and by the
    /// name this vault keeps for it, if it knows it), never by the name it
    /// gives itself; after the master password, which can be typed into
    /// the page, a system dialog asks too.
    pub fn authorize(&self, id: u32, master: Option<&SecretString>) -> AppResult<()> {
        let (known, code, vault) = {
            let mut slot = self.slot(id);
            slot.as_mut()
                .and_then(|slot| match slot.view.phase {
                    PairingPhase::Authorize { vault } => Some((
                        slot.known.clone(),
                        slot.code.clone().unwrap_or_default(),
                        vault,
                    )),
                    _ => None,
                })
                .ok_or_else(|| AppError::not_found("nothing to confirm"))?
        };
        let state = self.state()?;
        let app = self.app()?;
        match master {
            Some(master) => {
                state
                    .vault
                    .with(app, |vault| Ok(vault.verify_master_password(master)?))?;
                let prompt = prompt::add(known.as_deref(), &code, vault);
                crate::confirm::require(app, &prompt.title, &prompt.body, &prompt.approve)?;
            }
            None => crate::device_unlock::authenticate(&prompt::add_reason(
                known.as_deref(),
                &code,
                vault,
            ))?,
        }
        self.tell(id, Said::Authorized)
    }

    /// Sets up the vault another of the user's computers gave, with this
    /// master password, and unlocks it.
    pub fn finish_join(self: &Arc<Self>, id: u32, master: &SecretString) -> AppResult<()> {
        let state = self.state()?;
        let pending = self
            .slot(id)
            .as_mut()
            .filter(|slot| slot.view.phase == PairingPhase::SetMaster)
            .and_then(|slot| slot.pending.take())
            .ok_or_else(|| AppError::not_found("no vault waits here"))?;
        let paths = state.vault.paths();
        let joined = paths
            .database
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .map_err(AppError::from)
            .and_then(|()| Ok(Vault::join(&paths, &pending.file, &pending.secret, master)?));
        match joined {
            Ok(mut vault) => {
                crate::device_unlock::retire_stored_key(state.vault.data_dir(), &mut vault);
                state.vault.set_unlocked(vault);
                self.hide();
                if let Some(slot) = self.slot(id).as_mut() {
                    slot.view.phase = PairingPhase::Joined;
                }
                self.changed();
                if let Some(app) = self.app.get() {
                    let _ = app.emit(DEVICES_EVENT, ());
                }
                self.reconcile_presence();
                Ok(())
            }
            Err(error) => {
                // A master password it didn't take: the user tries another.
                if let Some(slot) = self.slot(id).as_mut() {
                    slot.pending = Some(pending);
                }
                Err(error)
            }
        }
    }

    /// Gives the conversation an answer to the step it is at. One that
    /// doesn't fit the step (a click that came late) is dropped.
    fn tell(&self, id: u32, said: Said) -> AppResult<()> {
        let inner = self.lock();
        let slot = inner
            .pairing
            .as_ref()
            .filter(|slot| slot.view.id == id)
            .ok_or_else(|| AppError::not_found("the pairing has ended"))?;
        let sender = slot
            .answer
            .as_ref()
            .ok_or_else(|| AppError::not_found("the pairing has ended"))?;
        if !said.fits(&slot.view.phase) {
            return Ok(());
        }
        sender
            .send(Answer {
                at: slot.view.phase.clone(),
                said,
            })
            .map_err(|_| AppError::not_found("the pairing has ended"))
    }

    /// Cancels a conversation that is going on, or forgets one that is over.
    pub fn close(&self, id: u32) {
        let mut inner = self.lock();
        let Some(slot) = inner.pairing.as_ref().filter(|slot| slot.view.id == id) else {
            return;
        };
        if slot.active() && slot.view.phase != PairingPhase::SetMaster {
            slot.cancelled.store(true, Ordering::SeqCst);
            if let Some(socket) = &slot.socket {
                let _ = socket.shutdown(std::net::Shutdown::Both);
            } else {
                // Still connecting: nothing to hang up yet, and connecting
                // can take a while. It ends here; the thread stops once
                // connected (see `run`) and finds the slot no longer its own.
                if let Some(slot) = inner.pairing.as_mut() {
                    slot.view.phase = PairingPhase::Failed {
                        reason: PairingFailure::Cancelled,
                    };
                    slot.answer = None;
                }
                drop(inner);
                self.changed();
            }
        } else {
            // A vault given but not set up yet goes with it.
            inner.pairing = None;
            drop(inner);
            self.changed();
        }
    }

    /// The user's devices, this computer among them.
    pub fn my_devices(&self) -> AppResult<Vec<MyDevice>> {
        let state = self.state()?;
        let me = self.identity()?.public().to_string();
        let found = self.status().own_found;
        let devices = state
            .vault
            .with_quietly(self.app()?, |vault| Ok(vault.own_devices()))?;
        let learned = store::learned(&self.data_dir);
        Ok(devices
            .into_iter()
            .map(|device| {
                let last_sync = PeerKey::from_base64(&device.key)
                    .ok()
                    .and_then(|key| store::load(&self.data_dir, &key).synced);
                MyDevice {
                    this: device.key == me,
                    reachable: found.contains(&device.key),
                    learned_from: learned.get(&device.key).map(|learned| learned.from.clone()),
                    key: device.key,
                    name: device.name,
                    added: device.added,
                    last_sync,
                }
            })
            .collect())
    }

    /// Removes one of the user's devices: it is not synced with any more,
    /// and the others learn of it at their next sync.
    pub fn remove_device(self: &Arc<Self>, key: &str) -> AppResult<()> {
        let peer = PeerKey::from_base64(key)?;
        if peer == self.identity()?.public() {
            return Err(AppError::invalid("this computer can't remove itself"));
        }
        let state = self.state()?;
        let removed = state
            .vault
            .change(self.app()?, &state.backup_dir, |vault| {
                Ok(vault.remove_own_device(key)?)
            })?;
        if !removed {
            return Err(AppError::not_found("that device is not one of yours"));
        }
        store::forget(&self.data_dir, &peer);
        if let Some(app) = self.app.get() {
            let _ = app.emit(DEVICES_EVENT, ());
        }
        self.reconcile_presence();
        Ok(())
    }

    /// Stops announcing and listening.
    fn hide(&self) {
        let mut inner = self.lock();
        if let Some(visible) = inner.visible.take() {
            visible.stop.store(true, Ordering::SeqCst);
            if let Some(daemon) = &inner.mdns {
                let _ = daemon.unregister(&visible.fullname);
            }
        }
    }

    /// Announces this device under a new random instance name, replacing
    /// the last announcement.
    fn announce(&self) -> AppResult<()> {
        let mut inner = self.lock();
        let daemon = mdns(&mut inner)?;
        let name = inner.name.clone();
        let Some(visible) = inner.visible.as_mut() else {
            return Ok(());
        };
        if !visible.fullname.is_empty() {
            let _ = daemon.unregister(&visible.fullname);
        }
        let instance = random_hex();
        let mut properties = vec![("v", "1"), ("name", name.as_str())];
        if visible.join {
            properties.push(("join", "1"));
        }
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            &instance,
            &format!("{instance}.local."),
            (),
            visible.port,
            &properties[..],
        )
        .map_err(mdns_error)?
        .enable_addr_auto();
        info.get_fullname().clone_into(&mut visible.fullname);
        daemon.register(info).map_err(mdns_error)
    }

    fn listen(self: Arc<Self>, listener: &TcpListener, stop: &AtomicBool, deadline: Instant) {
        while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
            match listener.accept() {
                Ok((stream, from)) => self.incoming(stream, from, false),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(150));
                }
                Err(error) => {
                    log::warn!("nearby: accept failed: {error}");
                    thread::sleep(Duration::from_millis(500));
                }
            }
        }
        if !stop.load(Ordering::SeqCst) {
            self.hide();
            self.changed();
        }
    }

    /// Someone connected from `from`: talk, unless it is not on the local
    /// network or a conversation is going on (then the connection just
    /// closes). With `only_sync`, only a sync is taken.
    fn incoming(self: &Arc<Self>, stream: TcpStream, from: SocketAddr, only_sync: bool) {
        if from_local_network(from) {
            self.take_call(stream, from.ip(), only_sync);
        }
    }

    /// Takes a connection someone made from `from`, and gives it the slot
    /// only once its first steps are done: the handshake and the other's
    /// `Hello`, in [`HANDSHAKE_TIMEOUT`] in all, with at most
    /// [`MAX_HANDSHAKES`] at once on each port and
    /// [`MAX_HANDSHAKES_PER_ADDRESS`] from one address. With `only_sync`,
    /// only one of the user's devices gets that far: anyone else fails the
    /// handshake, which needs the vault. So a connection that says nothing,
    /// a stranger, or one computer opening many holds up no conversation.
    fn take_call(self: &Arc<Self>, stream: TcpStream, from: IpAddr, only_sync: bool) {
        if self.lock().pairing.as_ref().is_some_and(Slot::active) {
            return;
        }
        let Some(handshaking) = self.handshaking(only_sync, from) else {
            return;
        };
        let nearby = Arc::clone(self);
        thread::spawn(move || {
            // A listener's socket hands on its non-blocking mode on some
            // systems.
            let _ = stream.set_nonblocking(false);
            let Ok(identity) = nearby.identity() else {
                return;
            };
            let role = Role::Answers { only_sync };
            let first = nearby.own_key_for(&role).and_then(|own| {
                handshake_within(
                    stream,
                    &identity,
                    &role,
                    own.as_deref(),
                    HANDSHAKE_TIMEOUT,
                    |session| {
                        if only_sync && !nearby.is_own(session.remote()) {
                            return Err(PairingFailure::NotOwn);
                        }
                        session.recv().map_err(broken)
                    },
                )
            });
            drop(handshaking);
            let Ok((session, hello)) = first else {
                return;
            };
            let kind = if only_sync {
                ConversationKind::Sync
            } else {
                ConversationKind::Pair
            };
            let Ok((id, answers, cancelled)) = nearby.claim(false, kind) else {
                return;
            };
            if let Ok(socket) = session.stream().try_clone()
                && let Some(slot) = nearby.slot(id).as_mut()
            {
                slot.socket = Some(socket);
            }
            nearby.talk(id, session, &role, answers, &cancelled, Some(hello));
        });
    }

    /// A place for a connection from `from` in its first steps on the port
    /// own devices use (`own`) or the other, if one is free.
    fn handshaking(self: &Arc<Self>, own: bool, from: IpAddr) -> Option<Handshaking> {
        self.handshakes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take(own, from)
            .then(|| Handshaking {
                nearby: Arc::clone(self),
                own,
                from,
            })
    }

    /// The key own devices mix into the handshake for `role`, if it is
    /// with one of them; a sync is only ever with one.
    fn own_key_for(&self, role: &Role) -> Result<Option<Zeroizing<[u8; 32]>>, PairingFailure> {
        match role {
            Role::Connects(Goal::Sync) | Role::Answers { only_sync: true } => {
                self.session_key().map(Some).ok_or(PairingFailure::NotOwn)
            }
            _ => Ok(None),
        }
    }

    /// Opens the session on a connection this side made, as `role` says, in
    /// at most [`HANDSHAKE_TIMEOUT`]. A sync is only ever with one of the
    /// user's devices: its handshake mixes in the key own devices have from
    /// the vault, so a computer without it learns nothing from it.
    fn handshake(
        &self,
        stream: TcpStream,
        identity: &Identity,
        role: &Role,
    ) -> Result<Session<TcpStream>, PairingFailure> {
        let own = self.own_key_for(role)?;
        handshake_within(
            stream,
            identity,
            role,
            own.as_deref(),
            HANDSHAKE_TIMEOUT,
            |_| Ok(()),
        )
        .map(|(session, ())| session)
    }

    /// The key own devices mix into their handshake, from the vault.
    fn session_key(&self) -> Option<Zeroizing<[u8; 32]>> {
        let state = self.state().ok()?;
        state
            .vault
            .with_quietly(self.app().ok()?, |vault| {
                Ok(vault.own_key().map(|key| key.session_key()))
            })
            .ok()
            .flatten()
    }

    /// Whether `peer` is one of the user's devices.
    fn is_own(&self, peer: PeerKey) -> bool {
        let (Ok(state), Ok(app)) = (self.state(), self.app()) else {
            return false;
        };
        state
            .vault
            .with_quietly(app, |vault| Ok(vault.is_own_device(&peer)))
            .unwrap_or(false)
    }

    /// Another computer hung up after it could work out the code this one
    /// would show, before this one showed it. After [`MAX_BROKEN_OFF`] of
    /// them, this computer stops being visible and says why.
    fn broke_off(&self) {
        let hide = {
            let mut inner = self.lock();
            inner.broken_off += 1;
            inner.broken_off >= MAX_BROKEN_OFF && inner.visible.is_some()
        };
        if hide {
            log::warn!("nearby: pairing was broken off too often; no longer visible");
            self.hide();
            self.lock().hidden_after_attempts = true;
            self.changed();
        }
    }

    /// Takes the slot for a new conversation; fails if one is going on.
    fn claim(
        &self,
        outgoing: bool,
        kind: ConversationKind,
    ) -> AppResult<(u32, Receiver<Answer>, Arc<AtomicBool>)> {
        let mut inner = self.lock();
        if inner.pairing.as_ref().is_some_and(Slot::active) {
            return Err(AppError::new(
                ErrorCode::Conflict,
                "another pairing is going on",
            ));
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (sender, receiver) = mpsc::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        inner.pairing = Some(Slot {
            view: Pairing {
                id,
                peer: None,
                outgoing,
                kind,
                phase: PairingPhase::Connecting,
            },
            answer: Some(sender),
            socket: None,
            cancelled: Arc::clone(&cancelled),
            pending: None,
            known: None,
            code: None,
            peer_vault: None,
            values_shown: 0,
        });
        drop(inner);
        self.changed();
        Ok((id, receiver, cancelled))
    }

    /// The conversation `id` this side started, on the connection it made.
    fn run(
        self: &Arc<Self>,
        id: u32,
        stream: TcpStream,
        identity: &Identity,
        role: &Role,
        answers: Receiver<Answer>,
        cancelled: &Arc<AtomicBool>,
    ) {
        if let Ok(socket) = stream.try_clone()
            && let Some(slot) = self.slot(id).as_mut()
        {
            slot.socket = Some(socket);
        }
        // Cancelled while connecting, before there was a socket to hang up:
        // stop before saying anything, let alone sending an item. Checked
        // after the socket is in the slot, so a cancel either finds it there
        // or is seen here.
        if cancelled.load(Ordering::SeqCst) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            self.finish(
                id,
                PairingPhase::Failed {
                    reason: PairingFailure::Cancelled,
                },
            );
            return;
        }
        match self.handshake(stream, identity, role) {
            Ok(session) => self.talk(id, session, role, answers, cancelled, None),
            Err(reason) => {
                let reason = if cancelled.load(Ordering::SeqCst) {
                    PairingFailure::Cancelled
                } else {
                    reason
                };
                self.finish(id, PairingPhase::Failed { reason });
            }
        }
    }

    /// Conversation `id`, on an open session.
    fn talk(
        self: &Arc<Self>,
        id: u32,
        mut session: Session<TcpStream>,
        role: &Role,
        answers: Receiver<Answer>,
        cancelled: &Arc<AtomicBool>,
        hello: Option<Message>,
    ) {
        let end = {
            let side = AppSide {
                nearby: self,
                id,
                answers: Mutex::new(answers),
                cancelled,
                only_sync: matches!(role, Role::Answers { only_sync: true }),
            };
            // A sync is only ever with one of the user's devices: anyone
            // else is turned away before the `Hello`, which would carry
            // this vault's proof.
            let sync = side.only_sync || matches!(role, Role::Connects(Goal::Sync));
            match role {
                _ if sync && !side.is_own(session.remote()) => PairingPhase::Failed {
                    reason: PairingFailure::NotOwn,
                },
                Role::Connects(goal) => {
                    conversation_after(&mut session, &side, Some(goal.purpose()), hello)
                }
                Role::Answers { .. } => conversation_after(&mut session, &side, None, hello),
            }
        };
        let end = if cancelled.load(Ordering::SeqCst) && matches!(end, PairingPhase::Failed { .. })
        {
            PairingPhase::Failed {
                reason: PairingFailure::Cancelled,
            }
        } else {
            end
        };
        self.finish(id, end);
    }

    fn finish(&self, id: u32, end: PairingPhase) {
        if let Some(slot) = self.slot(id).as_mut() {
            slot.view.phase = end;
            slot.answer = None;
            slot.socket = None;
            // The other device's copy of the vault goes once the sync ends.
            slot.peer_vault = None;
        }
        self.changed();
    }

    /// One text field of a conflict in the sync `id` under review, as this
    /// computer (`theirs` false) or the other one has it: for the user who
    /// asked to see it.
    pub fn sync_value(
        &self,
        id: u32,
        item: &str,
        field: &str,
        theirs: bool,
    ) -> AppResult<SecretString> {
        let (peer, label) = self.shown_from(id, item, field)?;
        let state = self.state()?;
        let app = self.app()?;
        // A secret goes as anywhere else in the app: past a few a minute,
        // each is asked for in a native dialog, before it is read.
        let secret = state
            .vault
            .with_quietly(app, |vault| Ok(vault.sync_value_secret(&peer, item, field)))?;
        if secret {
            let name = field.strip_prefix("s:").unwrap_or(field);
            let name = name.strip_prefix("env.").unwrap_or(name);
            crate::secret_gate::take_secret(
                app,
                crate::secret_gate::Taking::Show,
                &crate::secret_gate::sync_value(name, &label, theirs),
            )?;
        }
        state.vault.with(app, |vault| {
            Ok(vault.sync_value(&peer, item, field, theirs)?)
        })
    }

    /// The other device's copy, to show `field` of `item` from, and the
    /// item's label: only a field [`sync::Review::may_show`] allows in the
    /// review open in the sync `id`, and at most [`MAX_VALUES_SHOWN`] in one
    /// sync.
    fn shown_from(&self, id: u32, item: &str, field: &str) -> AppResult<(Arc<PeerVault>, String)> {
        let mut slot = self.slot(id);
        let slot = slot
            .as_mut()
            .ok_or_else(|| AppError::invalid("no sync under review"))?;
        let PairingPhase::Decide { review } = &slot.view.phase else {
            return Err(AppError::invalid("no sync under review"));
        };
        let Some(label) = review
            .may_show(item, field)
            .then(|| review.vault.conflicts.iter().find(|c| c.id == item))
            .flatten()
            .map(|conflict| conflict.label.clone())
        else {
            return Err(AppError::invalid("not a field of a conflict under review"));
        };
        if slot.values_shown >= MAX_VALUES_SHOWN {
            return Err(AppError::invalid("no more values in this sync"));
        }
        slot.values_shown += 1;
        let peer = slot
            .peer_vault
            .clone()
            .ok_or_else(|| AppError::invalid("no sync under review"))?;
        Ok((peer, label))
    }

    /// The cloud service whose folder holds the unlocked vault, if one does:
    /// then its entries don't sync with the user's devices here.
    pub fn vault_cloud(&self) -> AppResult<Option<CloudService>> {
        let state = self.state()?;
        let app = self.app()?;
        let paths = state
            .vault
            .with_quietly(app, |vault| Ok(vault.paths().clone()))?;
        Ok(vault_cloud(&paths))
    }

    /// The pairing slot, if it holds pairing `id`.
    fn slot(&self, id: u32) -> SlotGuard<'_> {
        SlotGuard {
            inner: self.lock(),
            id,
        }
    }

    /// An mDNS event while looking; `false` once looking stopped.
    fn found(&self, event: ServiceEvent) -> bool {
        let mut inner = self.lock();
        match event {
            ServiceEvent::ServiceResolved(service) => {
                let own = inner
                    .visible
                    .as_ref()
                    .is_some_and(|visible| visible.fullname == service.fullname);
                let name = service
                    .get_property_val_str("name")
                    .map(clean_name)
                    .filter(|name| !name.is_empty());
                if own || service.get_property_val_str("v") != Some("1") {
                    return true;
                }
                let Some(name) = name else {
                    return true;
                };
                let addresses = addresses_of(&service);
                if addresses.is_empty() {
                    return true;
                }
                let joining = service.get_property_val_str("join") == Some("1");
                inner.devices.insert(
                    service.fullname.clone(),
                    Found {
                        name,
                        joining,
                        addresses,
                    },
                );
            }
            ServiceEvent::ServiceRemoved(_, fullname) => {
                inner.devices.remove(&fullname);
            }
            ServiceEvent::SearchStopped(_) => return false,
            _ => return true,
        }
        drop(inner);
        self.changed();
        true
    }

    /// This device's key: from the credential store, or a new one kept there.
    fn identity(&self) -> AppResult<Arc<Identity>> {
        if let Some(identity) = &self.lock().identity {
            return Ok(Arc::clone(identity));
        }
        let stored = sshkm_os::secret_store::get(KEY_SERVICE, KEY_ACCOUNT).map_err(store_error)?;
        let identity = if let Some(secret) = stored {
            Identity::from_secret(&secret)?
        } else {
            let identity = Identity::generate()?;
            sshkm_os::secret_store::set(KEY_SERVICE, KEY_ACCOUNT, &identity.to_secret())
                .map_err(store_error)?;
            identity
        };
        let identity = Arc::new(identity);
        self.lock().identity = Some(Arc::clone(&identity));
        Ok(identity)
    }

    fn require_vault(&self) -> AppResult<()> {
        let state = self.state()?;
        if state.vault.is_unlocked() {
            Ok(())
        } else {
            Err(AppError::new(ErrorCode::VaultLocked, "the vault is locked"))
        }
    }

    fn state(&self) -> AppResult<Shared> {
        let app = self.app()?;
        app.try_state::<Shared>()
            .map(|state| Arc::clone(&state))
            .ok_or_else(|| AppError::new(ErrorCode::Io, "the app is starting"))
    }

    fn app(&self) -> AppResult<&AppHandle> {
        self.app
            .get()
            .ok_or_else(|| AppError::new(ErrorCode::Io, "the app is starting"))
    }

    /// Tells the UI and returns the new status.
    fn changed(&self) -> NearbyStatus {
        let status = self.status();
        if let Some(app) = self.app.get() {
            let _ = app.emit(CHANGED_EVENT, &status);
        }
        status
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// What the side that connects came for.
enum Goal {
    Pair,
    /// Send `item` to the device picked under the name `to`, or reached by
    /// its address.
    Send {
        item: Box<Item>,
        to: Option<String>,
    },
    AddDevice,
    Sync,
}

impl Goal {
    fn kind(&self) -> ConversationKind {
        match self {
            Self::Pair | Self::Send { .. } => ConversationKind::Pair,
            Self::AddDevice => ConversationKind::Device,
            Self::Sync => ConversationKind::Sync,
        }
    }

    fn purpose(&self) -> Purpose<'_> {
        match self {
            Self::Pair => Purpose::Pair,
            Self::Send { item, to } => Purpose::Send {
                item,
                to: to.as_deref(),
            },
            Self::AddDevice => Purpose::AddDevice,
            Self::Sync => Purpose::Sync,
        }
    }
}

/// Which side of a session this computer is.
enum Role {
    Connects(Goal),
    /// It was connected to; with `only_sync`, on the port announced to the
    /// user's devices.
    Answers {
        only_sync: bool,
    },
}

/// The connections in their first steps: on each port, and from each
/// address.
#[derive(Default)]
struct Pending {
    /// On the port others reach while this computer is visible (`0`), and
    /// on the one the user's devices use (`1`).
    ports: [usize; 2],
    addresses: HashMap<IpAddr, usize>,
}

impl Pending {
    /// Counts one more from `from` on the own devices' port (`own`) or the
    /// other, if neither that port nor that address has all it may.
    fn take(&mut self, own: bool, from: IpAddr) -> bool {
        let port = &mut self.ports[usize::from(own)];
        let address = self.addresses.entry(from).or_default();
        if *port >= MAX_HANDSHAKES || *address >= MAX_HANDSHAKES_PER_ADDRESS {
            if *address == 0 {
                self.addresses.remove(&from);
            }
            return false;
        }
        *port += 1;
        *address += 1;
        true
    }

    /// One fewer, of those [`Self::take`] counted.
    fn release(&mut self, own: bool, from: IpAddr) {
        let port = &mut self.ports[usize::from(own)];
        *port = port.saturating_sub(1);
        if let Some(address) = self.addresses.get_mut(&from) {
            *address = address.saturating_sub(1);
            if *address == 0 {
                self.addresses.remove(&from);
            }
        }
    }
}

/// A connection in its first steps, counted while this lives.
struct Handshaking {
    nearby: Arc<Nearby>,
    own: bool,
    from: IpAddr,
}

impl Drop for Handshaking {
    fn drop(&mut self) {
        self.nearby
            .handshakes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .release(self.own, self.from);
    }
}

/// Whether a connection from `from` is from the local network (see
/// [`on_local_network`]): any other is closed at once.
fn from_local_network(from: SocketAddr) -> bool {
    on_local_network(from.ip(), &local_subnets())
}

/// Opens the session on `stream` as `role` says, with `own`, the key own
/// devices mix in, if it is with one of them, and takes the next step
/// (`then`, such as reading the other's `Hello`); all of it within `limit`
/// ([`Deadline`]), so a peer that sends a byte now and then can't keep it
/// going, as it could a read with a timeout of its own.
fn handshake_within<T>(
    stream: TcpStream,
    identity: &Identity,
    role: &Role,
    own: Option<&[u8; 32]>,
    limit: Duration,
    then: impl FnOnce(&mut Session<Deadline>) -> Result<T, PairingFailure>,
) -> Result<(Session<TcpStream>, T), PairingFailure> {
    let stream = Deadline::new(stream, limit);
    let mut session = match (role, own) {
        (Role::Connects(_), None) => p2p::connect(stream, identity),
        (Role::Connects(_), Some(key)) => p2p::connect_own(stream, identity, key),
        (Role::Answers { .. }, None) => p2p::accept(stream, identity),
        (Role::Answers { .. }, Some(key)) => p2p::accept_own(stream, identity, key),
    }
    .map_err(|_| PairingFailure::Broken)?;
    let next = then(&mut session)?;
    let session = session.map_stream(Deadline::into_inner);
    // The deadline left the timeouts of its last step: the usual ones now.
    let _ = session.stream().set_read_timeout(Some(IO_TIMEOUT));
    let _ = session.stream().set_write_timeout(Some(IO_TIMEOUT));
    Ok((session, next))
}

/// The pairing slot while it holds one pairing; empty for any other.
struct SlotGuard<'a> {
    inner: MutexGuard<'a, Inner>,
    id: u32,
}

impl SlotGuard<'_> {
    fn as_mut(&mut self) -> Option<&mut Slot> {
        let id = self.id;
        self.inner
            .pairing
            .as_mut()
            .filter(|slot| slot.view.id == id)
    }
}

/// [`Side`] for the app: the vault, the device name and the user's answers.
struct AppSide<'a> {
    nearby: &'a Nearby,
    id: u32,
    answers: Mutex<Receiver<Answer>>,
    cancelled: &'a AtomicBool,
    only_sync: bool,
}

impl AppSide<'_> {
    fn context(&self) -> Result<(Shared, &AppHandle), PairingFailure> {
        let state = self.nearby.state().map_err(|_| PairingFailure::Broken)?;
        let app = self.nearby.app().map_err(|_| PairingFailure::Broken)?;
        Ok((state, app))
    }

    /// Reads the unlocked vault without counting as the user's activity.
    fn read<T>(&self, work: impl FnOnce(&Vault) -> T) -> Result<T, PairingFailure> {
        let (state, app) = self.context()?;
        state
            .vault
            .with_quietly(app, |vault| Ok(work(vault)))
            .map_err(|_| PairingFailure::VaultLocked)
    }

    /// Changes the vault and saves it if `work` says something changed.
    fn write(
        &self,
        work: impl FnOnce(&mut Vault) -> sshkm_core::Result<bool>,
    ) -> Result<bool, PairingFailure> {
        let (state, app) = self.context()?;
        let backup_dir = state.backup_dir.clone();
        state
            .vault
            .with_quietly(app, |vault| {
                let before = vault.snapshot();
                let changed = match work(vault) {
                    Ok(changed) => changed,
                    Err(error) => {
                        // Nothing of a merge that failed halfway is kept.
                        vault.restore(before);
                        return Err(error.into());
                    }
                };
                if changed {
                    if let Err(error) = vault.save(&backup_dir) {
                        let _ = vault.refresh();
                        return Err(error.into());
                    }
                    state.vault.remember_projects(vault);
                }
                Ok(changed)
            })
            .map_err(|error| match error.code() {
                ErrorCode::VaultLocked => PairingFailure::VaultLocked,
                _ => PairingFailure::NotSaved,
            })
    }

    /// What this computer keys the vault's snapshots with.
    fn vault_hasher(&self) -> Result<Hasher, PairingFailure> {
        let identity = self.nearby.identity().map_err(|_| PairingFailure::Broken)?;
        Ok(Hasher::new(identity.derive_key(VAULT_BASE_LABEL)))
    }

    fn joining(&self) -> bool {
        self.nearby
            .lock()
            .visible
            .as_ref()
            .is_some_and(|visible| visible.join)
    }

    /// The user's answer to the step the conversation is at, if one comes
    /// within `wait`; one given at another step is dropped.
    fn receive(&self, wait: Duration) -> Result<Option<Said>, PairingFailure> {
        if self.cancelled.load(Ordering::SeqCst) {
            return Err(PairingFailure::Cancelled);
        }
        let answers = self.answers.lock().unwrap_or_else(PoisonError::into_inner);
        let answer = match answers.recv_timeout(wait) {
            Ok(answer) => answer,
            Err(RecvTimeoutError::Timeout) => return Ok(None),
            Err(RecvTimeoutError::Disconnected) => return Err(PairingFailure::Cancelled),
        };
        let now = self
            .nearby
            .slot(self.id)
            .as_mut()
            .map(|slot| slot.view.phase.clone());
        Ok((now.as_ref() == Some(&answer.at)).then_some(answer.said))
    }
}

impl Side for AppSide<'_> {
    fn name(&self) -> String {
        self.nearby.lock().name.clone()
    }

    fn knows(&self, peer: PeerKey) -> Result<Option<String>, PairingFailure> {
        if self.joining() {
            return Ok(None);
        }
        let known = self.read(|vault| vault.known_name(&peer))?;
        if let Some(slot) = self.nearby.slot(self.id).as_mut() {
            slot.known.clone_from(&known);
        }
        Ok(known)
    }

    fn save(&self, peer: PeerKey, name: &str) -> Result<(), PairingFailure> {
        let (state, app) = self.context()?;
        state
            .vault
            .change(app, &state.backup_dir, |vault| {
                Ok(vault.add_contact(&peer, name)?)
            })
            .map_err(|error| match error.code() {
                ErrorCode::VaultLocked => PairingFailure::VaultLocked,
                _ => PairingFailure::Broken,
            })?;
        let _ = app.emit(CONTACTS_EVENT, ());
        Ok(())
    }

    fn show(&self, peer: Option<&str>, phase: &PairingPhase) {
        if let Some(slot) = self.nearby.slot(self.id).as_mut() {
            if peer.is_some() {
                slot.view.peer = peer.map(str::to_owned);
            }
            if let PairingPhase::Compare { code } = phase {
                slot.code = Some(code.clone());
            }
            slot.view.phase = phase.clone();
        }
        self.nearby.changed();
    }

    fn store(&self, item: &Item) -> Result<Stored, PairingFailure> {
        let peer = self
            .nearby
            .slot(self.id)
            .as_mut()
            .and_then(|slot| slot.view.peer.clone());
        items::store(self.nearby, self.id, peer.as_deref(), item)
    }

    fn answer(&self, wait: Duration) -> Result<Option<bool>, PairingFailure> {
        Ok(match self.receive(wait)? {
            Some(Said::Yes(yes)) => Some(yes),
            Some(Said::Authorized | Said::Decided(_)) | None => None,
        })
    }

    fn authorized(&self, wait: Duration) -> Result<bool, PairingFailure> {
        Ok(matches!(self.receive(wait)?, Some(Said::Authorized)))
    }

    fn vault(&self, hash: &[u8], initiator: bool) -> Option<VaultState> {
        if self.joining() {
            return Some(VaultState::Missing);
        }
        // A vault with no key for own devices yet proves nothing: empty.
        Some(
            self.read(|vault| {
                vault
                    .own_key()
                    .map(|key| key.proof(hash, initiator))
                    .unwrap_or_default()
            })
            .map_or(VaultState::Locked, |proof| VaultState::Open { proof }),
        )
    }

    fn same_vault(&self, hash: &[u8], initiator: bool, proof: &str) -> bool {
        self.read(|vault| {
            vault
                .own_key()
                .is_some_and(|key| key.verify(hash, initiator, proof))
        })
        .unwrap_or(false)
    }

    fn is_own(&self, peer: PeerKey) -> bool {
        self.nearby.is_own(peer)
    }

    fn removed(&self, peer: PeerKey) -> bool {
        self.read(|vault| vault.is_removed_device(&peer))
            .unwrap_or(true)
    }

    fn broke_off(&self) {
        self.nearby.broke_off();
    }

    fn allow_send(&self, item: &Item, left_out: &[String]) -> bool {
        let Ok((_, app)) = self.context() else {
            return false;
        };
        let peer = self
            .nearby
            .slot(self.id)
            .as_mut()
            .and_then(|slot| slot.view.peer.clone())
            .unwrap_or_default();
        // The dialog a chat asks in before the same item leaves.
        prompt::send_item(&peer, item, left_out).is_none_or(|prompt| {
            crate::confirm::require(app, &prompt.title, &prompt.body, &prompt.approve).is_ok()
        })
    }

    fn allow_added(&self) -> bool {
        let Ok((_, app)) = self.context() else {
            return false;
        };
        let Some((known, code)) = self
            .nearby
            .slot(self.id)
            .as_mut()
            .map(|slot| (slot.known.clone(), slot.code.clone().unwrap_or_default()))
        else {
            return false;
        };
        let prompt = prompt::added(known.as_deref(), &code);
        crate::confirm::require(app, &prompt.title, &prompt.body, &prompt.approve).is_ok()
    }

    fn takes(&self, intent: Option<Intent>) -> Result<(), PairingFailure> {
        if let Some(slot) = self.nearby.slot(self.id).as_mut() {
            slot.view.kind = ConversationKind::of(intent);
        }
        if self.only_sync && intent != Some(Intent::Sync) {
            return Err(PairingFailure::NotOwn);
        }
        if self.joining() && intent != Some(Intent::AddDevice) {
            return Err(PairingFailure::VaultLocked);
        }
        Ok(())
    }

    fn add_device(&self, peer: PeerKey, name: &str) -> Result<(), PairingFailure> {
        let me = self
            .nearby
            .identity()
            .map_err(|_| PairingFailure::Broken)?
            .public();
        let my_name = self.name();
        self.write(|vault| {
            let mine = vault.add_own_device(&me, &my_name)?;
            Ok(vault.add_own_device(&peer, name)? || mine)
        })?;
        if let Some(app) = self.nearby.app.get() {
            let _ = app.emit(DEVICES_EVENT, ());
        }
        Ok(())
    }

    fn share_vault(&self) -> Result<(Zeroizing<Vec<u8>>, SecretText), PairingFailure> {
        let (state, app) = self.context()?;
        state
            .vault
            .with(app, |vault| {
                let secret = vault.share_secret();
                // Not compressed: the new computer reads it within bounds.
                Ok((vault.moved_copy()?, SecretText::new(secret.expose_secret())))
            })
            .map_err(|_| PairingFailure::NotSaved)
    }

    fn take_vault(
        &self,
        file: Zeroizing<Vec<u8>>,
        secret: SecretText,
    ) -> Result<(), PairingFailure> {
        let secret = SecretString::from(secret.expose().to_owned());
        check_moved(&file, &secret).map_err(|error| match error {
            // Sent compressed: the other computer needs the new version.
            sshkm_core::Error::Unsupported(_) => PairingFailure::Version,
            _ => PairingFailure::NotSaved,
        })?;
        let mut slot = self.nearby.slot(self.id);
        let slot = slot.as_mut().ok_or(PairingFailure::Cancelled)?;
        slot.pending = Some(PendingVault { file, secret });
        Ok(())
    }

    fn sync_load(&self, peer: PeerKey) -> Result<SyncLocal, PairingFailure> {
        let (state, _) = self.context()?;
        let identity = self.nearby.identity().map_err(|_| PairingFailure::Broken)?;
        let config = SshConfig::load(&state.paths.config).map_err(|_| PairingFailure::NotSaved)?;
        let known =
            KnownHosts::load(&state.paths.known_hosts).map_err(|_| PairingFailure::NotSaved)?;
        Ok(SyncLocal {
            config,
            known,
            devices: self.read(Vault::device_records)?,
            projects: self.read(Vault::project_records)?,
            contacts: self.read(Vault::contact_records)?,
            state: store::load(&self.nearby.data_dir, &peer),
            hasher: Hasher::new(identity.derive_key(BASE_LABEL)),
        })
    }

    fn sync_write(&self, _peer: PeerKey, write: &SyncWrite) -> Result<(), PairingFailure> {
        let (state, _) = self.context()?;
        write_files(&state, write).map_err(|error| {
            log::warn!("nearby: a sync was not saved: {error}");
            PairingFailure::NotSaved
        })?;
        // The other device's records, saved as one change.
        let (mut devices, mut projects) = (false, false);
        let mut learned = Vec::new();
        self.write(|vault| {
            learned = vault::learned_devices(&vault.device_records(), &write.devices);
            devices = vault.merge_own_devices(&write.devices)?;
            projects = vault.merge_projects(&write.projects)?;
            let contacts = vault.merge_contacts(&write.contacts)?;
            Ok(devices || projects || contacts)
        })?;
        if !learned.is_empty() {
            let from = self
                .nearby
                .slot(self.id)
                .as_mut()
                .and_then(|slot| slot.view.peer.clone())
                .unwrap_or_default();
            // Best effort: the sync's summary names them too.
            if let Err(error) = store::note_learned(&self.nearby.data_dir, &learned, &from) {
                log::warn!("nearby: devices learned of were not noted: {error}");
            }
        }
        if let Some(app) = self.nearby.app.get() {
            if devices {
                let _ = app.emit(DEVICES_EVENT, ());
            }
            if projects {
                let _ = app.emit(crate::commands::projects::CHANGED_EVENT, ());
            }
        }
        Ok(())
    }

    fn sync_keep(&self, peer: PeerKey, state: &SyncState) -> Result<(), PairingFailure> {
        store::save(&self.nearby.data_dir, &peer, state).map_err(|_| PairingFailure::NotSaved)
    }

    fn sync_unasked(&self, unasked: &[(i64, u32)]) -> Result<(), PairingFailure> {
        store::save_unasked(&self.nearby.data_dir, unasked).map_err(|_| PairingFailure::NotSaved)
    }

    fn allow_risky_variables(&self, changes: &[RiskyVariables]) -> bool {
        let Ok((_, app)) = self.context() else {
            return false;
        };
        let (peer, copy) = self
            .nearby
            .slot(self.id)
            .as_mut()
            .map(|slot| (slot.view.peer.clone(), slot.peer_vault.clone()))
            .unwrap_or_default();
        // The values as the other device's copy has them.
        let value = |change: &RiskyVariables, name: &str| {
            copy.as_ref()?
                .variable(&change.id, name)
                .map(|value| value.expose_secret().to_owned())
        };
        let (title, body, approve) =
            sync::variables_prompt(&peer.unwrap_or_default(), changes, &value);
        crate::confirm::require(app, &title, &body, &approve).is_ok()
    }

    fn entry_sync(&self) -> Option<EntrySync> {
        if self.joining() {
            return None;
        }
        let paths = self.read(|vault| vault.paths().clone()).ok()?;
        Some(match vault_cloud(&paths) {
            Some(service) => EntrySync::Cloud { service },
            None => EntrySync::On {
                version: ENTRY_SYNC_VERSION,
            },
        })
    }

    fn vault_copy(&self) -> Result<Zeroizing<Vec<u8>>, PairingFailure> {
        self.read(Vault::sync_copy)?
            .map_err(|_| PairingFailure::NotSaved)
    }

    fn vault_plan(&self, copy: &[u8], base: &VaultBase) -> Result<VaultPlan, PairingFailure> {
        let hasher = self.vault_hasher()?;
        let mut planned = None;
        // Changed: the file is read again first, as before any change.
        self.write(|vault| {
            vault.refresh()?;
            let peer = vault.open_sync_copy(copy)?;
            planned = Some((vault.plan_sync(&peer, base, &hasher), peer));
            Ok(false)
        })
        .map_err(|_| PairingFailure::Broken)?;
        let (plan, peer) = planned.ok_or(PairingFailure::Broken)?;
        if let Some(slot) = self.nearby.slot(self.id).as_mut() {
            slot.peer_vault = Some(Arc::new(peer));
        }
        Ok(plan)
    }

    fn vault_apply(
        &self,
        plan: &VaultPlan,
        choices: &VaultChoices,
    ) -> Result<VaultApplied, PairingFailure> {
        let (make, theirs) = (&choices.make, &choices.theirs);
        let hasher = self.vault_hasher()?;
        let peer = self
            .nearby
            .slot(self.id)
            .as_mut()
            .and_then(|slot| slot.peer_vault.clone())
            .ok_or(PairingFailure::Broken)?;
        // The vault as it was before the day's first sync deletions
        // outlives the rotation of backups.
        let deletes = plan
            .changes
            .iter()
            .any(|change| change.removal && make.contains(&change.id))
            || plan.conflicts.iter().any(|conflict| {
                (conflict.there == Party::Deleted || conflict.to_bin)
                    && theirs.contains(&conflict.id)
            });
        if deletes {
            let (state, _) = self.context()?;
            let database = self.read(|vault| vault.paths().database.clone())?;
            fsutil::keep_backup(&database, &state.backup_dir)
                .map_err(|_| PairingFailure::NotSaved)?;
        }
        let mut applied = VaultApplied::default();
        let changed = self.write(|vault| {
            applied = vault.apply_sync(&peer, plan, &hasher, choices)?;
            // A version kept in history changes the vault too.
            Ok(applied.changed())
        })?;
        if changed && let Some(app) = self.nearby.app.get() {
            // The page reads the vault again, and the files of environments
            // that changed are written as after any change.
            let _ = app.emit(crate::vault_watcher::EVENT, ());
            let _ = app.emit(crate::commands::projects::CHANGED_EVENT, ());
            if let Some(files) = app.try_state::<Arc<crate::env_files::EnvFiles>>() {
                files.request();
            }
        }
        Ok(applied)
    }

    fn vault_items(&self, pairs: &Pairs) -> Result<VaultItems, PairingFailure> {
        let hasher = self.vault_hasher()?;
        self.read(|vault| {
            let shared = Hasher::new(vault.own_key()?.digest_key());
            Some(VaultItems {
                snapshots: vault.sync_items(pairs, &hasher),
                digests: digests(&vault.sync_items(pairs, &shared)),
            })
        })?
        .ok_or(PairingFailure::NotOwn)
    }

    fn allow_risky(&self, changes: &[RiskyChange]) -> bool {
        let Ok((state, app)) = self.context() else {
            return false;
        };
        let peer = self
            .nearby
            .slot(self.id)
            .as_mut()
            .and_then(|slot| slot.view.peer.clone())
            .unwrap_or_default();
        let file = state.paths.config.display().to_string();
        let (title, body, approve) = sync::risky_prompt(&peer, &file, changes);
        crate::confirm::require(app, &title, &body, &approve).is_ok()
    }

    fn decisions(&self, wait: Duration) -> Result<Option<SyncDecisions>, PairingFailure> {
        Ok(match self.receive(wait)? {
            Some(Said::Decided(decisions)) => Some(decisions),
            Some(Said::Yes(_) | Said::Authorized) | None => None,
        })
    }
}

/// Writes the files a sync changed, each only if it is as the sync found
/// it: an edit made meanwhile is never overwritten.
fn write_files(state: &AppState, write: &SyncWrite) -> AppResult<()> {
    if let Some(config) = &write.config {
        let path = &state.paths.config;
        fsutil::ensure_revision(
            path,
            &SshConfig::load(path)?.revision(),
            &write.config_revision,
        )?;
        // The config as it was before the day's first sync deletions
        // outlives the rotation of backups.
        if write.deletes {
            fsutil::keep_backup(path, &state.backup_dir)?;
        }
        config.save(path, &state.backup_dir)?;
    }
    if let Some(known) = &write.known {
        let path = &state.paths.known_hosts;
        let current = KnownHosts::load(path)?;
        fsutil::ensure_revision(path, &current.revision(), &write.known_revision)?;
        // No key comes in next to one, or a certificate authority, that
        // another file `ssh` reads trusts for the host.
        let mut known = known.clone();
        host_keys::drop_trusted_elsewhere(
            &mut known,
            &current,
            &items::trusted_elsewhere(&state.paths),
        );
        if known != current {
            known.save(path, &state.backup_dir)?;
        }
    }
    Ok(())
}

/// The IPv4 addresses a service was resolved to, on the local network.
fn addresses_of(service: &mdns_sd::ResolvedService) -> Vec<SocketAddr> {
    let subnets = local_subnets();
    let mut addresses: Vec<SocketAddr> = service
        .get_addresses_v4()
        .into_iter()
        .map(|ip| SocketAddr::new(IpAddr::V4(ip), service.port))
        .filter(|address| on_local_network(address.ip(), &subnets))
        .collect();
    addresses.sort();
    addresses
}

/// The networks this computer has an address in: each address and the
/// length of its network's prefix, loopback ones left out.
fn local_subnets() -> Vec<(IpAddr, u8)> {
    if_addrs::get_if_addrs()
        .map(|interfaces| {
            interfaces
                .into_iter()
                .filter(|interface| !interface.is_loopback())
                .map(|interface| match interface.addr {
                    if_addrs::IfAddr::V4(addr) => (IpAddr::V4(addr.ip), addr.prefixlen),
                    if_addrs::IfAddr::V6(addr) => (IpAddr::V6(addr.ip), addr.prefixlen),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Whether `ip` is another computer on the local network: a private
/// (`10/8`, `172.16/12`, `192.168/16`) or link-local IPv4 address, a unique
/// local (`fc00::/7`) or link-local IPv6 one, or one in a network this
/// computer has an address in (`subnets`), as some networks give out
/// public addresses. Never a loopback, unspecified, multicast or broadcast
/// address, nor anything beyond this computer's networks.
fn on_local_network(ip: IpAddr, subnets: &[(IpAddr, u8)]) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        IpAddr::V4(_) => ip,
    };
    match ip {
        IpAddr::V4(v4)
            if v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast() =>
        {
            false
        }
        IpAddr::V6(v6) if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() => false,
        IpAddr::V4(v4) if v4.is_private() || v4.is_link_local() => true,
        IpAddr::V6(v6)
            if v6.segments()[0] & 0xfe00 == 0xfc00 || v6.segments()[0] & 0xffc0 == 0xfe80 =>
        {
            true
        }
        _ => subnets
            .iter()
            .any(|(net, prefix)| same_network(ip, *net, *prefix)),
    }
}

/// Whether `a` and `b` are in one network whose prefix has `prefix` bits.
/// One wider than a `/16` (IPv4) or a `/48` (IPv6) is no local network.
fn same_network(a: IpAddr, b: IpAddr, prefix: u8) -> bool {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) if (16..=32).contains(&prefix) => {
            let mask = u32::MAX << (32 - u32::from(prefix));
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) if (48..=128).contains(&prefix) => {
            let mask = u128::MAX << (128 - u32::from(prefix));
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}

/// The mDNS daemon, started on first use.
fn mdns(inner: &mut Inner) -> AppResult<ServiceDaemon> {
    if let Some(daemon) = &inner.mdns {
        return Ok(daemon.clone());
    }
    let daemon = ServiceDaemon::new().map_err(mdns_error)?;
    inner.mdns = Some(daemon.clone());
    Ok(daemon)
}

#[allow(clippy::needless_pass_by_value, reason = "by value, to fit `map_err`")]
fn mdns_error(error: mdns_sd::Error) -> AppError {
    AppError::new(ErrorCode::Io, format!("local network discovery: {error}"))
}

#[allow(clippy::needless_pass_by_value, reason = "by value, to fit `map_err`")]
fn store_error(error: sshkm_os::Error) -> AppError {
    AppError::new(
        ErrorCode::Unsupported,
        format!("the system's credential store, where the device key is kept: {error}"),
    )
}

/// The computer's name, as the default device name.
fn default_name() -> String {
    let host = gethostname::gethostname().to_string_lossy().into_owned();
    let name = clean_name(host.strip_suffix(".local").unwrap_or(&host));
    if name.is_empty() {
        "SSH Key Manager".to_owned()
    } else {
        name
    }
}

/// The address this computer uses on the local network. Connecting a UDP
/// socket sends nothing; it only picks the route.
/// The cloud service whose folder holds the vault at `paths`, if one does.
fn vault_cloud(paths: &vault::VaultPaths) -> Option<CloudService> {
    vault::cloud_service(paths, &CloudRoots::detect(home_dir().as_deref()))
}

fn local_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).ok()?;
    let ip = socket.local_addr().ok()?.ip();
    (!ip.is_unspecified() && !ip.is_loopback()).then_some(ip)
}

fn random_hex() -> String {
    let mut bytes = [0; 6];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().fold(String::new(), |mut hex, b| {
        let _ = write!(hex, "{b:02x}");
        hex
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The side that reads the answers of conversation `id`, with no app
    /// behind it.
    fn side<'a>(
        nearby: &'a Nearby,
        id: u32,
        answers: Receiver<Answer>,
        cancelled: &'a AtomicBool,
    ) -> AppSide<'a> {
        AppSide {
            nearby,
            id,
            answers: Mutex::new(answers),
            cancelled,
            only_sync: false,
        }
    }

    fn at(nearby: &Nearby, id: u32, phase: PairingPhase) {
        nearby.slot(id).as_mut().unwrap().view.phase = phase;
    }

    const WAIT: Duration = Duration::from_millis(10);

    fn login() -> p2p::protocol::ItemSummary {
        p2p::protocol::ItemSummary::Password {
            title: "Router".into(),
            username: "admin".into(),
            url: String::new(),
            otp: false,
            host: None,
            server: None,
        }
    }

    #[test]
    fn only_computers_on_the_local_network_are_reached() {
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        let none: [(IpAddr, u8); 0] = [];
        for local in [
            "192.168.1.24",
            "10.0.4.12",
            "172.16.0.9",
            "172.31.255.1",
            "169.254.10.1",
            "fd00::7",
            "fe80::1",
            "::ffff:192.168.1.24",
        ] {
            assert!(on_local_network(ip(local), &none), "{local}");
        }
        for beyond in [
            "8.8.8.8",
            "203.0.113.9",
            "172.32.0.1",
            "100.64.0.1",
            "2001:db8::1",
            "::ffff:8.8.8.8",
            // Not another computer.
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "::",
            "224.0.0.251",
            "255.255.255.255",
            "ff02::fb",
        ] {
            assert!(!on_local_network(ip(beyond), &none), "{beyond}");
        }
        // A network with public addresses that this computer is on is local
        // too; one wider than a /16 doesn't count.
        let subnets = [(ip("130.89.4.17"), 22), (ip("2001:db8:5::17"), 64)];
        assert!(on_local_network(ip("130.89.7.200"), &subnets));
        assert!(!on_local_network(ip("130.89.8.1"), &subnets));
        assert!(on_local_network(ip("2001:db8:5::99"), &subnets));
        assert!(!on_local_network(ip("2001:db8:6::99"), &subnets));
        assert!(!on_local_network(
            ip("130.1.2.3"),
            &[(ip("130.89.4.17"), 8)]
        ));
        assert!(!on_local_network(ip("127.0.0.2"), &[(ip("127.0.0.1"), 8)]));
    }

    fn pending(nearby: &Nearby) -> (usize, usize) {
        let pending = nearby.handshakes.lock().unwrap();
        (pending.ports[0], pending.ports[1])
    }

    /// A stand-in for others: connected to, each says nothing at all; the
    /// `n`-th comes from the address `from(n)`.
    fn silent_connections(
        n: usize,
        from: impl Fn(usize) -> IpAddr,
    ) -> (Arc<Nearby>, Vec<TcpStream>) {
        let nearby = Arc::new(Nearby::new(std::env::temp_dir().join("sshkm-no-nearby")));
        nearby.lock().identity = Some(Arc::new(Identity::generate().unwrap()));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut clients = Vec::new();
        for index in 0..n {
            clients.push(TcpStream::connect(listener.local_addr().unwrap()).unwrap());
            let (stream, _) = listener.accept().unwrap();
            nearby.take_call(stream, from(index), false);
        }
        (nearby, clients)
    }

    /// Whether the other end hung up.
    fn closed(client: &mut TcpStream) -> bool {
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        std::io::Read::read(client, &mut [0; 1]).is_ok_and(|n| n == 0)
    }

    #[test]
    fn a_connection_that_says_nothing_holds_up_no_conversation() {
        let address =
            |index: usize| IpAddr::V4(Ipv4Addr::new(192, 168, 1, u8::try_from(index).unwrap()));
        let (nearby, mut clients) = silent_connections(MAX_HANDSHAKES + 2, address);
        thread::sleep(Duration::from_millis(200));
        // None of them took the slot: the user can start one.
        assert_eq!(nearby.status().pairing, None);
        assert!(nearby.claim(true, ConversationKind::Pair).is_ok());
        // Only so many wait for their first steps; the others were closed
        // at once.
        assert_eq!(pending(&nearby), (MAX_HANDSHAKES, 0));
        assert!(closed(clients.last_mut().unwrap()));
    }

    #[test]
    fn one_computer_cant_take_every_place_for_a_handshake() {
        let one = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 66));
        let (nearby, mut clients) = silent_connections(MAX_HANDSHAKES, |_| one);
        thread::sleep(Duration::from_millis(200));
        assert_eq!(pending(&nearby), (MAX_HANDSHAKES_PER_ADDRESS, 0));
        assert!(closed(clients.last_mut().unwrap()));

        // Each port has places of its own, and a place is given back.
        let mut pending = Pending::default();
        let other = |n: u8| IpAddr::V4(Ipv4Addr::new(10, 0, 0, n));
        for n in 0..u8::try_from(MAX_HANDSHAKES).unwrap() {
            assert!(pending.take(false, other(n)));
        }
        assert!(!pending.take(false, other(99)));
        assert!(pending.take(true, other(99)));
        pending.release(false, other(0));
        assert!(pending.take(false, other(99)));
        assert!(!pending.take(false, other(99)), "two from that address");
        assert_eq!(pending.addresses.get(&other(0)), None);
    }

    #[test]
    fn connections_from_beyond_the_local_network_are_closed_at_once() {
        let nearby = Arc::new(Nearby::new(std::env::temp_dir().join("sshkm-no-nearby")));
        nearby.lock().identity = Some(Arc::new(Identity::generate().unwrap()));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        for (from, taken) in [
            ("8.8.8.8:40000", false),
            ("127.0.0.1:40000", false),
            ("192.168.1.24:40000", true),
        ] {
            let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (stream, _) = listener.accept().unwrap();
            nearby.incoming(stream, from.parse().unwrap(), false);
            assert_eq!(pending(&nearby).0 == 1, taken, "{from}");
            if !taken {
                assert!(closed(&mut client), "{from}");
            }
        }
        // As the chats' port takes them.
        assert!(!from_local_network("203.0.113.9:1".parse().unwrap()));
        assert!(from_local_network("[fe80::1]:1".parse().unwrap()));
    }

    /// The answers of a handshake on a loopback connection: the side
    /// connected to runs [`handshake_within`] as `role` with `own`, then
    /// reads the other's first message; the other side runs `connect`.
    fn first_steps<T: Send + 'static>(
        role: &Role,
        own: Option<[u8; 32]>,
        connect: impl FnOnce(TcpStream) -> T + Send + 'static,
    ) -> (Result<Message, PairingFailure>, T, Duration) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let other = thread::spawn(move || connect(client));
        let started = Instant::now();
        let first = handshake_within(
            server,
            &Identity::generate().unwrap(),
            role,
            own.as_ref(),
            Duration::from_millis(300),
            |session| session.recv().map_err(broken),
        )
        .map(|(_, hello)| hello);
        let took = started.elapsed();
        (first, other.join().unwrap(), took)
    }

    #[test]
    fn a_handshake_ends_when_its_time_is_up_however_slowly_bytes_come() {
        // A frame of 65535 bytes announced, then a byte every 100 ms: each
        // read is quick, the whole never ends.
        let (first, (), took) =
            first_steps(&Role::Answers { only_sync: false }, None, |mut client| {
                for _ in 0..50 {
                    if std::io::Write::write_all(&mut client, &[0xff]).is_err() {
                        break;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
            });
        assert!(first.is_err());
        assert!(took < Duration::from_secs(2));

        // A peer that finishes the handshake and then says nothing: its
        // `Hello` falls under the same deadline.
        let (first, _session, took) =
            first_steps(&Role::Answers { only_sync: false }, None, |client| {
                let session = p2p::connect(client, &Identity::generate().unwrap()).unwrap();
                thread::sleep(Duration::from_millis(800));
                session.remote()
            });
        assert!(first.is_err());
        assert!(took < Duration::from_millis(700));

        // One that says hello in time is through.
        let (first, (), _) = first_steps(&Role::Answers { only_sync: false }, None, |client| {
            let mut session = p2p::connect(client, &Identity::generate().unwrap()).unwrap();
            session.send(&hello()).unwrap();
        });
        assert_eq!(first.unwrap(), hello());
    }

    fn hello() -> Message {
        Message::Hello {
            version: p2p::protocol::VERSION,
            name: "peer".into(),
            known: false,
            own: None,
            features: Vec::new(),
        }
    }

    /// The port the user's devices use takes only a handshake that mixes in
    /// the key from the vault.
    #[test]
    fn the_own_devices_port_takes_only_their_handshake() {
        let key = [9; 32];
        let own = Role::Answers { only_sync: true };
        let (first, (), _) = first_steps(&own, Some(key), move |client| {
            let mut session =
                p2p::connect_own(client, &Identity::generate().unwrap(), &key).unwrap();
            session.send(&hello()).unwrap();
        });
        assert_eq!(first.unwrap(), hello());
        for stranger in [None, Some([8; 32])] {
            let own = Role::Answers { only_sync: true };
            let (first, connected, _) = first_steps(&own, Some(key), move |client| {
                let identity = Identity::generate().unwrap();
                match stranger {
                    None => p2p::connect(client, &identity).is_ok(),
                    Some(other) => p2p::connect_own(client, &identity, &other).is_ok(),
                }
            });
            assert!(first.is_err() && !connected);
        }
    }

    /// The deadline holds for the first steps only: what follows on the
    /// own devices' port, such as a copy of the vault in a sync, takes as
    /// long as it needs after it.
    #[test]
    fn the_handshakes_deadline_ends_with_the_first_steps() {
        let key = [9; 32];
        let copy = vec![7_u8; 3 * 1024 * 1024];
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let sent = copy.clone();
        let other = thread::spawn(move || {
            let mut session =
                p2p::connect_own(client, &Identity::generate().unwrap(), &key).unwrap();
            session.send(&hello()).unwrap();
            // Past the deadline of the first steps.
            thread::sleep(Duration::from_millis(600));
            session.send_bytes(&sent, &mut |_, _| {}).unwrap();
            session.recv().unwrap()
        });
        let (mut session, first) = handshake_within(
            server,
            &Identity::generate().unwrap(),
            &Role::Answers { only_sync: true },
            Some(&key),
            Duration::from_millis(300),
            |session| session.recv().map_err(broken),
        )
        .unwrap();
        assert_eq!(first, hello());
        let received = session.recv_bytes(8 * 1024 * 1024, &mut |_, _| {}).unwrap();
        assert_eq!(*received, copy);
        session.send(&hello()).unwrap();
        assert_eq!(other.join().unwrap(), hello());
    }

    #[test]
    fn pairing_broken_off_too_often_hides_this_computer() {
        let nearby = Nearby::new(std::env::temp_dir().join("sshkm-no-nearby"));
        let visible = || Visible {
            until: OffsetDateTime::now_utc() + VISIBLE_FOR,
            port: 1,
            join: false,
            fullname: String::new(),
            stop: Arc::new(AtomicBool::new(false)),
        };
        nearby.lock().visible = Some(visible());
        for _ in 1..MAX_BROKEN_OFF {
            nearby.broke_off();
        }
        assert!(nearby.status().visible_until.is_some());
        assert!(!nearby.status().hidden_after_attempts);
        nearby.broke_off();
        let status = nearby.status();
        assert_eq!(status.visible_until, None);
        assert!(status.hidden_after_attempts);
    }

    #[test]
    fn closing_a_finished_send_ends_it() {
        let nearby = Nearby::new(std::env::temp_dir().join("sshkm-no-nearby"));
        let finished = [
            PairingPhase::Sent { item: login() },
            PairingPhase::Received {
                item: login(),
                name: "Router".into(),
                keys_differ: false,
                left_out: Vec::new(),
            },
        ];
        for phase in finished {
            let (id, _answers, cancelled) = nearby.claim(true, ConversationKind::Pair).unwrap();
            at(&nearby, id, phase);
            // It no longer holds the slot: another device may connect.
            assert!(!nearby.lock().pairing.as_ref().unwrap().active());
            nearby.close(id);
            assert_eq!(nearby.status().pairing, None);
            assert!(!cancelled.load(Ordering::SeqCst));
        }
        // And the next one can start.
        assert!(nearby.claim(true, ConversationKind::Pair).is_ok());
    }

    #[test]
    fn cancelling_while_connecting_ends_at_once() {
        let nearby = Nearby::new(std::env::temp_dir().join("sshkm-no-nearby"));
        let (id, answers, cancelled) = nearby.claim(true, ConversationKind::Pair).unwrap();
        nearby.close(id);
        assert!(cancelled.load(Ordering::SeqCst));
        assert_eq!(
            nearby.status().pairing.map(|pairing| pairing.phase),
            Some(PairingPhase::Failed {
                reason: PairingFailure::Cancelled
            })
        );
        // The thread hears no more answers.
        let side = side(&nearby, id, answers, &cancelled);
        assert_eq!(side.answer(WAIT), Err(PairingFailure::Cancelled));
        // Closing it again lets it go.
        nearby.close(id);
        assert_eq!(nearby.status().pairing, None);
    }

    #[test]
    fn a_cancel_before_the_socket_stops_the_conversation() {
        let nearby = Arc::new(Nearby::new(std::env::temp_dir().join("sshkm-no-nearby")));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let (id, answers, cancelled) = nearby.claim(true, ConversationKind::Pair).unwrap();
        nearby.close(id);
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut other, _) = listener.accept().unwrap();
        let identity = Identity::generate().unwrap();
        nearby.run(
            id,
            stream,
            &identity,
            &Role::Connects(Goal::Pair),
            answers,
            &cancelled,
        );
        assert_eq!(
            nearby.status().pairing.map(|pairing| pairing.phase),
            Some(PairingPhase::Failed {
                reason: PairingFailure::Cancelled
            })
        );
        // Nothing was said to the other side: it only sees the hang-up.
        other
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        assert_eq!(std::io::Read::read(&mut other, &mut [0; 1]).unwrap(), 0);
    }

    #[test]
    fn only_the_app_confirms_adding_a_device() {
        let nearby = Nearby::new(std::env::temp_dir().join("sshkm-no-nearby"));
        let (id, answers, cancelled) = nearby.claim(true, ConversationKind::Device).unwrap();
        let side = side(&nearby, id, answers, &cancelled);
        at(
            &nearby,
            id,
            PairingPhase::Compare {
                code: "123456".into(),
            },
        );
        // "Codes match", clicked twice before the step changed.
        nearby.answer(id, true).unwrap();
        nearby.answer(id, true).unwrap();
        assert_eq!(side.answer(WAIT), Ok(Some(true)));

        at(&nearby, id, PairingPhase::Authorize { vault: true });
        // The second click is dropped, and a yes now is not taken at all.
        nearby.answer(id, true).unwrap();
        assert_eq!(side.authorized(WAIT), Ok(false));
        assert_eq!(side.authorized(WAIT), Ok(false));
        // Decisions don't fit this step either.
        nearby.decide(id, SyncDecisions::default()).unwrap();
        assert_eq!(side.authorized(WAIT), Ok(false));
        // What `authorize` says after its check does.
        nearby.tell(id, Said::Authorized).unwrap();
        assert_eq!(side.authorized(WAIT), Ok(true));
    }

    #[test]
    fn an_answer_counts_only_for_the_step_it_was_given_at() {
        let nearby = Nearby::new(std::env::temp_dir().join("sshkm-no-nearby"));
        let (id, answers, cancelled) = nearby.claim(true, ConversationKind::Sync).unwrap();
        let side = side(&nearby, id, answers, &cancelled);
        // Nothing asked yet: nothing taken.
        nearby.answer(id, true).unwrap();
        assert_eq!(side.answer(WAIT), Ok(None));

        at(
            &nearby,
            id,
            PairingPhase::Compare {
                code: "123456".into(),
            },
        );
        nearby.answer(id, false).unwrap();
        at(
            &nearby,
            id,
            PairingPhase::Compare {
                code: "654321".into(),
            },
        );
        assert_eq!(side.answer(WAIT), Ok(None), "given at another step");

        let review = sync::Review::default();
        at(&nearby, id, PairingPhase::Decide { review });
        nearby.answer(id, false).unwrap();
        nearby.tell(id, Said::Authorized).unwrap();
        assert_eq!(side.decisions(WAIT), Ok(None));
        let decisions = SyncDecisions {
            delete: true,
            ..SyncDecisions::default()
        };
        nearby.decide(id, decisions.clone()).unwrap();
        assert_eq!(side.decisions(WAIT), Ok(Some(decisions)));
    }

    #[test]
    fn a_value_is_shown_only_from_the_review_and_not_without_end() {
        use sshkm_core::vault::VaultPaths;
        use sshkm_core::vault::sync::{ItemKind, Party, VaultConflict};
        let dir = tempfile::tempdir().unwrap();
        let (vault, _) = Vault::create(
            &VaultPaths::new(dir.path().join("vault.kdbx")),
            &SecretString::from("master"),
        )
        .unwrap();
        let copy = vault.open_sync_copy(&vault.sync_copy().unwrap()).unwrap();
        let nearby = Nearby::new(std::env::temp_dir().join("sshkm-no-nearby"));
        let (id, _answers, _cancelled) = nearby.claim(true, ConversationKind::Sync).unwrap();
        nearby.slot(id).as_mut().unwrap().peer_vault = Some(Arc::new(copy));
        // While nothing is under review, nothing is shown.
        assert!(nearby.shown_from(id, "mail", "s:Password").is_err());
        let review = sync::Review {
            vault: sync::VaultReview {
                conflicts: vec![VaultConflict {
                    id: "mail".into(),
                    kind: ItemKind::Login,
                    label: "Mail".into(),
                    here: Party::Changed,
                    there: Party::Changed,
                    fields: vec!["s:Password".into(), "s:TOTP Seed".into()],
                    risky: Vec::new(),
                    to_bin: false,
                }],
                ..sync::VaultReview::default()
            },
            ..sync::Review::default()
        };
        at(&nearby, id, PairingPhase::Decide { review });
        assert!(nearby.shown_from(id, "other", "s:Password").is_err());
        assert!(nearby.shown_from(id, "mail", "s:Notes").is_err());
        assert!(nearby.shown_from(id, "mail", "s:TOTP Seed").is_err());
        // The item's label names it in the dialog past the free secrets.
        assert_eq!(
            nearby.shown_from(id, "mail", "s:Password").unwrap().1,
            "Mail"
        );
        for _ in 1..MAX_VALUES_SHOWN {
            assert!(nearby.shown_from(id, "mail", "s:Password").is_ok());
        }
        assert!(
            nearby.shown_from(id, "mail", "s:Password").is_err(),
            "no more in this sync"
        );
        // The copy goes when the vault locks.
        nearby.forget_peer_vault();
        assert!(nearby.slot(id).as_mut().unwrap().peer_vault.is_none());
    }

    #[test]
    fn instance_names_are_random_hex() {
        let (a, b) = (random_hex(), random_hex());
        assert_eq!(a.len(), 12);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    /// Announces a service the way [`Nearby::announce`] does and finds it
    /// the way looking does. Needs multicast on a network interface:
    /// `cargo test -p sshkm-app -- --ignored announces`.
    #[test]
    #[ignore = "uses the local network"]
    fn announces_and_finds_itself() {
        let daemon = ServiceDaemon::new().unwrap();
        let instance = random_hex();
        let properties = [("v", "1"), ("name", "Test device")];
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            &instance,
            &format!("{instance}.local."),
            (),
            41_234,
            &properties[..],
        )
        .unwrap()
        .enable_addr_auto();
        let fullname = info.get_fullname().to_owned();
        let events = daemon.browse(SERVICE_TYPE).unwrap();
        daemon.register(info).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok(ServiceEvent::ServiceResolved(service)) =
                events.recv_timeout(Duration::from_secs(1))
                && service.fullname == fullname
            {
                assert_eq!(service.get_property_val_str("name"), Some("Test device"));
                assert_eq!(service.port, 41_234);
                assert!(!service.get_addresses_v4().is_empty());
                let _ = daemon.shutdown();
                return;
            }
        }
        panic!("the announcement was not found");
    }
}
