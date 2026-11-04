//! Being reachable by the user's own devices.
//!
//! While the vault is unlocked, there is another of the user's devices, and
//! the user didn't turn it off, the app listens on a TCP port and announces
//! it as `_sshkm-own._tcp`. The instance name is the device's presence
//! name for the current ten minutes ([`OwnKey::presence_name`]), and the
//! TXT record has nothing but the version. Others see a name that changes
//! and says nothing; the user's devices can tell whose it is. On that port
//! only a sync is taken, and only from one of the user's devices: anyone
//! else is turned away right after the handshake.
//!
//! The app also browses for the same service, to tell the user which of
//! their devices are reachable and to have their addresses for a sync.
//!
//! [`OwnKey::presence_name`]: sshkm_core::p2p::own::OwnKey::presence_name

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mdns_sd::{ServiceEvent, ServiceInfo};
use sshkm_core::p2p::PeerKey;
use sshkm_core::p2p::own::{OwnKey, window};

use super::{Nearby, addresses_of, mdns, mdns_error};
use crate::error::AppResult;

/// The mDNS service type the user's devices announce to each other.
pub const OWN_SERVICE_TYPE: &str = "_sshkm-own._tcp.local.";
/// How often the app checks whether it should be announced.
const CHECK_EVERY: Duration = Duration::from_secs(5);

/// This computer, announced to the user's devices.
pub(super) struct Presence {
    key: OwnKey,
    /// The user's other devices, to recognise.
    devices: Vec<PeerKey>,
    window: u64,
    port: u16,
    fullname: String,
    stop: Arc<AtomicBool>,
}

/// One of the user's devices, found on the network.
pub(super) struct OwnFound {
    pub key: PeerKey,
    pub addresses: Vec<SocketAddr>,
}

/// What this computer should be announced as, read from the vault.
struct Wanted {
    key: OwnKey,
    me: PeerKey,
    devices: Vec<PeerKey>,
}

impl Nearby {
    /// Keeps the announcement as it should be, for the life of the app:
    /// cheaply every few seconds, and with a look into the vault when the
    /// vault was unlocked or the presence name changes.
    pub(super) fn watch_presence(self: Arc<Self>) {
        thread::spawn(move || {
            loop {
                self.reconcile_presence();
                thread::sleep(CHECK_EVERY);
            }
        });
    }

    /// Starts, renews or stops the announcement.
    pub(super) fn reconcile_presence(self: &Arc<Self>) {
        let Ok(state) = self.state() else {
            return;
        };
        let (running, reachable, current_window) = {
            let inner = self.lock();
            (
                inner.presence.as_ref().map(|p| p.window),
                inner.reachable,
                window(now()),
            )
        };
        if !reachable || !state.vault.is_unlocked() {
            if running.is_some() {
                self.stop_presence();
            }
            return;
        }
        if running == Some(current_window) {
            return;
        }
        match self.wanted() {
            Some(wanted) => {
                if let Err(error) = self.start_presence(wanted, current_window) {
                    log::warn!("nearby: could not announce to own devices: {error}");
                }
            }
            None if running.is_some() => self.stop_presence(),
            None => {}
        }
    }

    /// The key and the devices, if this computer is one of the user's
    /// devices and there is another.
    fn wanted(&self) -> Option<Wanted> {
        let me = self.identity().ok()?.public();
        let state = self.state().ok()?;
        let app = self.app().ok()?;
        state
            .vault
            .with_quietly(app, |vault| {
                let devices: Vec<PeerKey> = vault
                    .own_devices()
                    .iter()
                    .filter_map(|device| PeerKey::from_base64(&device.key).ok())
                    .filter(|key| *key != me)
                    .collect();
                Ok(
                    (vault.is_own_device(&me) && !devices.is_empty()).then(|| Wanted {
                        key: vault.own_key(),
                        me,
                        devices,
                    }),
                )
            })
            .ok()
            .flatten()
    }

    /// Announces this computer under the name for `window`: on a new port
    /// the first time, re-announced on the same one after.
    fn start_presence(self: &Arc<Self>, wanted: Wanted, window: u64) -> AppResult<()> {
        let mut inner = self.lock();
        let daemon = mdns(&mut inner)?;
        let instance = wanted.key.presence_name(&wanted.me, window);
        let (port, stop, fresh) = if let Some(old) = inner.presence.take() {
            let _ = daemon.unregister(&old.fullname);
            (old.port, old.stop, false)
        } else {
            let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))?;
            listener.set_nonblocking(true)?;
            let port = listener.local_addr()?.port();
            let stop = Arc::new(AtomicBool::new(false));
            let nearby = Arc::clone(self);
            let flag = Arc::clone(&stop);
            thread::spawn(move || nearby.listen_for_own(&listener, &flag));
            (port, stop, true)
        };
        let info = ServiceInfo::new(
            OWN_SERVICE_TYPE,
            &instance,
            &format!("{instance}.local."),
            (),
            port,
            &[("v", "1")][..],
        )
        .map_err(mdns_error)?
        .enable_addr_auto();
        let fullname = info.get_fullname().to_owned();
        daemon.register(info).map_err(mdns_error)?;
        inner.presence = Some(Presence {
            key: wanted.key,
            devices: wanted.devices,
            window,
            port,
            fullname,
            stop,
        });
        if fresh {
            let events = daemon.browse(OWN_SERVICE_TYPE).map_err(mdns_error)?;
            drop(inner);
            let nearby = Arc::clone(self);
            thread::spawn(move || {
                while let Ok(event) = events.recv() {
                    if !nearby.found_own(event) {
                        break;
                    }
                }
            });
        } else {
            drop(inner);
        }
        self.changed();
        Ok(())
    }

    fn stop_presence(&self) {
        let mut inner = self.lock();
        if let Some(presence) = inner.presence.take() {
            presence.stop.store(true, Ordering::SeqCst);
            if let Some(daemon) = &inner.mdns {
                let _ = daemon.unregister(&presence.fullname);
                let _ = daemon.stop_browse(OWN_SERVICE_TYPE);
            }
        }
        inner.own_found.clear();
        drop(inner);
        self.changed();
    }

    fn listen_for_own(self: Arc<Self>, listener: &TcpListener, stop: &AtomicBool) {
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => self.incoming(stream, true),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(150));
                }
                Err(error) => {
                    log::warn!("nearby: accept failed: {error}");
                    thread::sleep(Duration::from_millis(500));
                }
            }
        }
    }

    /// An mDNS event for the user's devices; `false` once browsing stopped.
    fn found_own(&self, event: ServiceEvent) -> bool {
        let mut inner = self.lock();
        let Some(presence) = inner.presence.as_ref() else {
            return false;
        };
        match event {
            ServiceEvent::ServiceResolved(service) => {
                let instance = service
                    .fullname
                    .strip_suffix(&format!(".{OWN_SERVICE_TYPE}"))
                    .unwrap_or_default();
                if service.fullname == presence.fullname {
                    return true;
                }
                let Some(key) =
                    presence
                        .key
                        .recognize(instance, &presence.devices, presence.window)
                else {
                    return true;
                };
                let addresses = addresses_of(&service);
                if addresses.is_empty() {
                    return true;
                }
                inner
                    .own_found
                    .insert(service.fullname.clone(), OwnFound { key, addresses });
            }
            ServiceEvent::ServiceRemoved(_, fullname) => {
                if inner.own_found.remove(&fullname).is_none() {
                    return true;
                }
            }
            ServiceEvent::SearchStopped(_) => return false,
            _ => return true,
        }
        drop(inner);
        self.changed();
        true
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
