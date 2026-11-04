//! Nearby: other copies of the app on the local network.
//!
//! - **Visible.** For ten minutes after the user asks, the app listens on a
//!   TCP port and announces it with mDNS as `_sshkm._tcp`, under a random
//!   instance name with the device name in the TXT record. A computer
//!   without a vault can be visible to get one (`join=1` in the record).
//!   It announces nothing otherwise, but to the user's own devices
//!   ([`presence`]).
//! - **Looking.** While the Nearby page is open, the app browses for others.
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

pub mod items;
pub mod own;
pub mod pairing;
mod presence;
#[cfg(test)]
mod script;
mod store;
pub mod sync;
pub mod transfer;

use std::collections::BTreeMap;
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
use sshkm_core::p2p::protocol::{Intent, Item, SecretText, VaultState, clean_name};
use sshkm_core::p2p::{self, Identity, PeerKey};
use sshkm_core::sync::Hasher;
use sshkm_core::vault::{self, Vault};
use sshkm_core::{ErrorCode, ExposeSecret, SecretString, fsutil};
use tauri::{AppHandle, Emitter, Manager};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

use self::items::{ReceivedGroup, SendRequest};
use self::pairing::{PairingFailure, PairingPhase, Purpose, Side, conversation};
pub use self::presence::OWN_SERVICE_TYPE;
use self::presence::{OwnFound, Presence};
use self::sync::{SyncDecisions, SyncLocal, SyncState, SyncWrite};
use crate::commands::Shared;
use crate::confirm::Localized;
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
const KEY_SERVICE: &str = "SSH Key Manager nearby";
const KEY_ACCOUNT: &str = "device";
const SETTINGS_FILE: &str = "nearby.json";
/// What the hashes of a sync's snapshots are keyed with.
pub const BASE_LABEL: &[u8] = b"sshkm sync base";

/// What the Nearby page shows.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct NearbyStatus {
    /// This device's name, as others see it.
    pub name: String,
    /// Visible to others until then (RFC 3339), if it is.
    pub visible_until: Option<String>,
    /// While visible: where others can reach it by address, `ip:port`.
    pub address: Option<String>,
    /// Visible to be given a vault by another of the user's computers.
    pub joining: bool,
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
    /// The other device's name, once it said it.
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
    inner: Mutex<Inner>,
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

/// What the user answers a conversation.
enum Answer {
    /// Yes or no: the codes match, the item is welcome, the device added.
    Yes(bool),
    /// What to do with the changes of a sync.
    Decided(SyncDecisions),
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
            inner: Mutex::new(Inner {
                name,
                settings,
                ..Inner::default()
            }),
        }
    }

    /// Hands over the app, for events and the vault, and starts keeping
    /// this computer announced to the user's devices. Called once at start.
    pub fn attach(self: &Arc<Self>, app: AppHandle) {
        let _ = self.app.set(app);
        Arc::clone(self).watch_presence();
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
        self.start(target, Goal::Send(item))
    }

    /// Makes a device found on the network (or at an address) one of the
    /// user's devices, giving it the vault if it has none. The result comes
    /// as events.
    pub fn add_device(self: &Arc<Self>, target: &str) -> AppResult<u32> {
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
        let addresses = {
            let inner = self.lock();
            match inner.devices.get(target) {
                Some(found) => found.addresses.clone(),
                None => target
                    .trim()
                    .to_socket_addrs()
                    .map_err(|_| AppError::invalid("not an address: host:port"))?
                    .collect(),
            }
        };
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
            .find_map(|address| TcpStream::connect_timeout(address, CONNECT_TIMEOUT).ok())
        else {
            self.finish(
                id,
                PairingPhase::Failed {
                    reason: PairingFailure::Unreachable,
                },
            );
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
    /// item.
    pub fn answer(&self, id: u32, matched: bool) -> AppResult<()> {
        self.tell(id, Answer::Yes(matched))
    }

    /// The user's decisions on what a sync brings.
    pub fn decide(&self, id: u32, decisions: SyncDecisions) -> AppResult<()> {
        self.tell(id, Answer::Decided(decisions))
    }

    /// The user's yes to making the other computer one of their devices,
    /// with the master password or, without one, Touch ID / Windows Hello.
    pub fn authorize(&self, id: u32, master: Option<&SecretString>) -> AppResult<()> {
        let peer = {
            let mut slot = self.slot(id);
            let slot = slot
                .as_mut()
                .filter(|slot| matches!(slot.view.phase, PairingPhase::Authorize { .. }))
                .ok_or_else(|| AppError::not_found("nothing to confirm"))?;
            slot.view.peer.clone().unwrap_or_default()
        };
        let state = self.state()?;
        match master {
            Some(master) => state.vault.with(self.app()?, |vault| {
                Ok(vault.verify_master_password(master)?)
            })?,
            None => crate::device_unlock::authenticate(&Localized::new(
                format!("add {peer} to your devices"),
                format!("добавить {peer} в ваши устройства"),
                format!("{peer} qurilmasini qurilmalaringizga qoʻshish"),
            ))?,
        }
        self.answer(id, true)
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

    fn tell(&self, id: u32, answer: Answer) -> AppResult<()> {
        let inner = self.lock();
        let sender = inner
            .pairing
            .as_ref()
            .filter(|slot| slot.view.id == id)
            .and_then(|slot| slot.answer.as_ref())
            .ok_or_else(|| AppError::not_found("the pairing has ended"))?;
        sender
            .send(answer)
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
        Ok(devices
            .into_iter()
            .map(|device| {
                let last_sync = PeerKey::from_base64(&device.key)
                    .ok()
                    .and_then(|key| store::load(&self.data_dir, &key).synced);
                MyDevice {
                    this: device.key == me,
                    reachable: found.contains(&device.key),
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
                Ok((stream, _)) => self.incoming(stream, false),
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

    /// Someone connected: talk, unless a conversation is going on (then the
    /// connection just closes). With `only_sync`, only a sync is taken.
    fn incoming(self: &Arc<Self>, stream: TcpStream, only_sync: bool) {
        // A listener's socket hands on its non-blocking mode on some systems.
        let _ = stream.set_nonblocking(false);
        let Ok(identity) = self.identity() else {
            return;
        };
        let kind = if only_sync {
            ConversationKind::Sync
        } else {
            ConversationKind::Pair
        };
        let Ok((id, answers, cancelled)) = self.claim(false, kind) else {
            return;
        };
        let nearby = Arc::clone(self);
        thread::spawn(move || {
            nearby.run(
                id,
                stream,
                &identity,
                &Role::Answers { only_sync },
                answers,
                &cancelled,
            );
        });
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
        });
        drop(inner);
        self.changed();
        Ok((id, receiver, cancelled))
    }

    fn run(
        self: &Arc<Self>,
        id: u32,
        stream: TcpStream,
        identity: &Identity,
        role: &Role,
        answers: Receiver<Answer>,
        cancelled: &Arc<AtomicBool>,
    ) {
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        if let Ok(socket) = stream.try_clone()
            && let Some(slot) = self.slot(id).as_mut()
        {
            slot.socket = Some(socket);
        }
        let session = if matches!(role, Role::Connects(_)) {
            p2p::connect(stream, identity)
        } else {
            p2p::accept(stream, identity)
        };
        let end = match session {
            Ok(mut session) => {
                let side = AppSide {
                    nearby: self,
                    id,
                    answers: Mutex::new(answers),
                    cancelled,
                    only_sync: matches!(role, Role::Answers { only_sync: true }),
                };
                match role {
                    Role::Connects(goal) => conversation(&mut session, &side, Some(goal.purpose())),
                    Role::Answers { .. } => conversation(&mut session, &side, None),
                }
            }
            Err(_) => PairingPhase::Failed {
                reason: PairingFailure::Broken,
            },
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
        }
        self.changed();
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
    Send(Item),
    AddDevice,
    Sync,
}

impl Goal {
    fn kind(&self) -> ConversationKind {
        match self {
            Self::Pair | Self::Send(_) => ConversationKind::Pair,
            Self::AddDevice => ConversationKind::Device,
            Self::Sync => ConversationKind::Sync,
        }
    }

    fn purpose(&self) -> Purpose<'_> {
        match self {
            Self::Pair => Purpose::Pair,
            Self::Send(item) => Purpose::Send(item),
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
                let changed = work(vault)?;
                if changed && let Err(error) = vault.save(&backup_dir) {
                    let _ = vault.refresh();
                    return Err(error.into());
                }
                Ok(changed)
            })
            .map_err(|error| match error.code() {
                ErrorCode::VaultLocked => PairingFailure::VaultLocked,
                _ => PairingFailure::NotSaved,
            })
    }

    fn joining(&self) -> bool {
        self.nearby
            .lock()
            .visible
            .as_ref()
            .is_some_and(|visible| visible.join)
    }

    fn receive(&self, wait: Duration) -> Result<Option<Answer>, PairingFailure> {
        if self.cancelled.load(Ordering::SeqCst) {
            return Err(PairingFailure::Cancelled);
        }
        let answers = self.answers.lock().unwrap_or_else(PoisonError::into_inner);
        match answers.recv_timeout(wait) {
            Ok(answer) => Ok(Some(answer)),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err(PairingFailure::Cancelled),
        }
    }
}

impl Side for AppSide<'_> {
    fn name(&self) -> String {
        self.nearby.lock().name.clone()
    }

    fn knows(&self, peer: PeerKey) -> Result<bool, PairingFailure> {
        if self.joining() {
            return Ok(false);
        }
        self.read(|vault| vault.contact(&peer).is_some() || vault.is_own_device(&peer))
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
            slot.view.phase = phase.clone();
        }
        self.nearby.changed();
    }

    fn store(&self, item: &Item) -> Result<(String, bool), PairingFailure> {
        let peer = self
            .nearby
            .slot(self.id)
            .as_mut()
            .and_then(|slot| slot.view.peer.clone());
        items::store(self.nearby, self.id, peer.as_deref(), item)
    }

    fn answer(&self, wait: Duration) -> Result<Option<bool>, PairingFailure> {
        Ok(match self.receive(wait)? {
            Some(Answer::Yes(yes)) => Some(yes),
            Some(Answer::Decided(_)) | None => None,
        })
    }

    fn vault(&self, hash: &[u8], initiator: bool) -> Option<VaultState> {
        if self.joining() {
            return Some(VaultState::Missing);
        }
        Some(
            self.read(|vault| vault.own_key().proof(hash, initiator))
                .map_or(VaultState::Locked, |proof| VaultState::Open { proof }),
        )
    }

    fn same_vault(&self, hash: &[u8], initiator: bool, proof: &str) -> bool {
        self.read(|vault| vault.own_key().verify(hash, initiator, proof))
            .unwrap_or(false)
    }

    fn is_own(&self, peer: PeerKey) -> bool {
        self.read(|vault| vault.is_own_device(&peer))
            .unwrap_or(false)
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
                Ok((
                    vault.saved_bytes()?,
                    SecretText::new(secret.expose_secret()),
                ))
            })
            .map_err(|_| PairingFailure::NotSaved)
    }

    fn take_vault(
        &self,
        file: Zeroizing<Vec<u8>>,
        secret: SecretText,
    ) -> Result<(), PairingFailure> {
        let secret = SecretString::from(secret.expose().to_owned());
        vault::check_shared(&file, &secret).map_err(|_| PairingFailure::NotSaved)?;
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
        if self.write(|vault| vault.merge_own_devices(&write.devices))?
            && let Some(app) = self.nearby.app.get()
        {
            let _ = app.emit(DEVICES_EVENT, ());
        }
        Ok(())
    }

    fn sync_keep(&self, peer: PeerKey, state: &SyncState) -> Result<(), PairingFailure> {
        store::save(&self.nearby.data_dir, &peer, state).map_err(|_| PairingFailure::NotSaved)
    }

    fn decisions(&self, wait: Duration) -> Result<Option<SyncDecisions>, PairingFailure> {
        match self.receive(wait)? {
            Some(Answer::Decided(decisions)) => Ok(Some(decisions)),
            Some(Answer::Yes(false)) => Err(PairingFailure::Cancelled),
            Some(Answer::Yes(true)) | None => Ok(None),
        }
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
        config.save(path, &state.backup_dir)?;
    }
    if let Some(known) = &write.known {
        let path = &state.paths.known_hosts;
        fsutil::ensure_revision(
            path,
            &KnownHosts::load(path)?.revision(),
            &write.known_revision,
        )?;
        known.save(path, &state.backup_dir)?;
    }
    Ok(())
}

/// The IPv4 addresses a service was resolved to, but loopback.
fn addresses_of(service: &mdns_sd::ResolvedService) -> Vec<SocketAddr> {
    let mut addresses: Vec<SocketAddr> = service
        .get_addresses_v4()
        .into_iter()
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .map(|ip| SocketAddr::new(IpAddr::V4(ip), service.port))
        .collect();
    addresses.sort();
    addresses
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
