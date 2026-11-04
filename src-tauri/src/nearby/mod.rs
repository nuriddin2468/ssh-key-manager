//! Nearby: other copies of the app on the local network.
//!
//! - **Visible.** For ten minutes after the user asks, the app listens on a
//!   TCP port and announces it with mDNS as `_sshkm._tcp`, under a random
//!   instance name with the device name in the TXT record. It announces
//!   nothing otherwise.
//! - **Looking.** While the Nearby page is open, the app browses for others.
//! - **Pairing.** One at a time, started from either side: a Noise session
//!   ([`sshkm_core::p2p`]), then [`pairing::converse`]. Contacts are kept in
//!   the vault, so pairing needs it unlocked.
//!
//! The device key lives in the system's credential store, the device name in
//! `nearby.json` in the app's data folder. The UI follows [`CHANGED_EVENT`],
//! which carries the whole [`NearbyStatus`].

pub mod pairing;

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
use sshkm_core::p2p::protocol::clean_name;
use sshkm_core::p2p::{self, Identity, PeerKey};
use sshkm_core::{ErrorCode, fsutil};
use tauri::{AppHandle, Emitter, Manager};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use self::pairing::{PairingFailure, PairingPhase, Side, converse};
use crate::commands::Shared;
use crate::error::{AppError, AppResult};

/// Emitted with the [`NearbyStatus`] whenever it changes.
pub const CHANGED_EVENT: &str = "nearby-changed";
/// Emitted when a contact was added.
pub const CONTACTS_EVENT: &str = "nearby-contacts";

/// The mDNS service type the app announces and looks for.
pub const SERVICE_TYPE: &str = "_sshkm._tcp.local.";
const VISIBLE_FOR: Duration = Duration::from_secs(10 * 60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// For the handshake and `Hello`; comparing codes waits longer.
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const KEY_SERVICE: &str = "SSH Key Manager nearby";
const KEY_ACCOUNT: &str = "device";
const SETTINGS_FILE: &str = "nearby.json";

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
    /// Devices found on the network, by name.
    pub devices: Vec<NearbyDevice>,
    /// The pairing going on, or just over.
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
    pub phase: PairingPhase,
}

#[derive(Default, Serialize, Deserialize)]
struct Settings {
    name: Option<String>,
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
    identity: Option<Arc<Identity>>,
    mdns: Option<ServiceDaemon>,
    visible: Option<Visible>,
    looking: bool,
    devices: BTreeMap<String, Found>,
    pairing: Option<Slot>,
}

struct Visible {
    until: OffsetDateTime,
    port: u16,
    /// The mDNS name it is announced under.
    fullname: String,
    stop: Arc<AtomicBool>,
}

struct Found {
    name: String,
    addresses: Vec<SocketAddr>,
}

struct Slot {
    view: Pairing,
    /// Gives the user's answer to the pairing's thread.
    answer: Option<Sender<bool>>,
    /// The connection, to end it when the user cancels.
    socket: Option<TcpStream>,
    cancelled: Arc<AtomicBool>,
}

impl Slot {
    fn active(&self) -> bool {
        !matches!(
            self.view.phase,
            PairingPhase::Paired | PairingPhase::Known | PairingPhase::Failed { .. }
        )
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
            .map(|name| clean_name(&name))
            .filter(|name| !name.is_empty())
            .unwrap_or_else(default_name);
        Self {
            data_dir,
            app: OnceLock::new(),
            next_id: AtomicU32::new(1),
            inner: Mutex::new(Inner {
                name,
                ..Inner::default()
            }),
        }
    }

    /// Hands over the app, for events and the vault. Called once at start.
    pub fn attach(&self, app: AppHandle) {
        let _ = self.app.set(app);
    }

    pub fn status(&self) -> NearbyStatus {
        let inner = self.lock();
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
            devices: {
                let mut devices: Vec<NearbyDevice> = inner
                    .devices
                    .iter()
                    .map(|(id, found)| NearbyDevice {
                        id: id.clone(),
                        name: found.name.clone(),
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
        let settings = Settings {
            name: Some(name.clone()),
        };
        let json = serde_json::to_vec_pretty(&settings)
            .map_err(|e| AppError::new(ErrorCode::Io, e.to_string()))?;
        fsutil::ensure_private_dir(&self.data_dir)?;
        fsutil::atomic_write(&self.data_dir.join(SETTINGS_FILE), &json, 0o600)?;
        let visible = {
            let mut inner = self.lock();
            inner.name = name;
            inner.visible.is_some()
        };
        // Others see the new name once it is announced again.
        if visible {
            self.announce()?;
        }
        Ok(self.changed())
    }

    /// Makes this device visible for ten minutes, or hides it.
    pub fn set_visible(self: &Arc<Self>, on: bool) -> AppResult<NearbyStatus> {
        self.hide();
        if !on {
            return Ok(self.changed());
        }
        self.identity()?;
        self.require_vault()?;
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
        let (id, answers, cancelled) = self.claim(true)?;
        let nearby = Arc::clone(self);
        thread::spawn(move || {
            let Some(stream) = addresses
                .iter()
                .find_map(|address| TcpStream::connect_timeout(address, CONNECT_TIMEOUT).ok())
            else {
                nearby.finish(
                    id,
                    PairingPhase::Failed {
                        reason: PairingFailure::Unreachable,
                    },
                );
                return;
            };
            nearby.run(id, stream, &identity, true, answers, &cancelled);
        });
        Ok(id)
    }

    /// The user's answer to "Do the codes match?".
    pub fn answer(&self, id: u32, matched: bool) -> AppResult<()> {
        let inner = self.lock();
        let sender = inner
            .pairing
            .as_ref()
            .filter(|slot| slot.view.id == id)
            .and_then(|slot| slot.answer.as_ref())
            .ok_or_else(|| AppError::not_found("the pairing has ended"))?;
        sender
            .send(matched)
            .map_err(|_| AppError::not_found("the pairing has ended"))
    }

    /// Cancels a pairing that is going on, or forgets one that is over.
    pub fn close(&self, id: u32) {
        let mut inner = self.lock();
        let Some(slot) = inner.pairing.as_ref().filter(|slot| slot.view.id == id) else {
            return;
        };
        if slot.active() {
            slot.cancelled.store(true, Ordering::SeqCst);
            if let Some(socket) = &slot.socket {
                let _ = socket.shutdown(std::net::Shutdown::Both);
            }
        } else {
            inner.pairing = None;
            drop(inner);
            self.changed();
        }
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
        let properties = [("v", "1"), ("name", name.as_str())];
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
                Ok((stream, _)) => self.incoming(stream),
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

    /// Someone connected: pair, unless a pairing is going on (then the
    /// connection just closes).
    fn incoming(self: &Arc<Self>, stream: TcpStream) {
        let Ok(identity) = self.identity() else {
            return;
        };
        let Ok((id, answers, cancelled)) = self.claim(false) else {
            return;
        };
        let nearby = Arc::clone(self);
        thread::spawn(move || nearby.run(id, stream, &identity, false, answers, &cancelled));
    }

    /// Takes the pairing slot for a new pairing; fails if one is going on.
    fn claim(&self, outgoing: bool) -> AppResult<(u32, Receiver<bool>, Arc<AtomicBool>)> {
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
                phase: PairingPhase::Connecting,
            },
            answer: Some(sender),
            socket: None,
            cancelled: Arc::clone(&cancelled),
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
        outgoing: bool,
        answers: Receiver<bool>,
        cancelled: &Arc<AtomicBool>,
    ) {
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        if let Ok(socket) = stream.try_clone()
            && let Some(slot) = self.slot(id).as_mut()
        {
            slot.socket = Some(socket);
        }
        let session = if outgoing {
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
                };
                converse(&mut session, &side)
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
                let mut addresses: Vec<SocketAddr> = service
                    .get_addresses_v4()
                    .into_iter()
                    .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
                    .map(|ip| SocketAddr::new(IpAddr::V4(ip), service.port))
                    .collect();
                addresses.sort();
                if addresses.is_empty() {
                    return true;
                }
                inner
                    .devices
                    .insert(service.fullname.clone(), Found { name, addresses });
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
    answers: Mutex<Receiver<bool>>,
    cancelled: &'a AtomicBool,
}

impl Side for AppSide<'_> {
    fn name(&self) -> String {
        self.nearby.lock().name.clone()
    }

    fn knows(&self, peer: PeerKey) -> Result<bool, PairingFailure> {
        let state = self.nearby.state().map_err(|_| PairingFailure::Broken)?;
        let app = self.nearby.app().map_err(|_| PairingFailure::Broken)?;
        state
            .vault
            .with_quietly(app, |vault| Ok(vault.contact(&peer).is_some()))
            .map_err(|_| PairingFailure::VaultLocked)
    }

    fn save(&self, peer: PeerKey, name: &str) -> Result<(), PairingFailure> {
        let state = self.nearby.state().map_err(|_| PairingFailure::Broken)?;
        let app = self.nearby.app().map_err(|_| PairingFailure::Broken)?;
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

    fn answer(&self, wait: Duration) -> Result<Option<bool>, PairingFailure> {
        if self.cancelled.load(Ordering::SeqCst) {
            return Err(PairingFailure::Cancelled);
        }
        let answers = self.answers.lock().unwrap_or_else(PoisonError::into_inner);
        match answers.recv_timeout(wait) {
            Ok(matched) => Ok(Some(matched)),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err(PairingFailure::Cancelled),
        }
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
