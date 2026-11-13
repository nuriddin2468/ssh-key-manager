//! Being online for chats: a port that takes only chats, announced as
//! `_sshkm-chat._tcp` under a random name that changes every ten minutes,
//! with a tag for each contact that only that contact recognises
//! ([`contact::presence_txt`]); and browsing for the same service, to know
//! which contacts are online and where.

use std::fmt::Write as _;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mdns_sd::{ServiceEvent, ServiceInfo};
use rand_core::{OsRng, RngCore};
use sshkm_core::p2p::PeerKey;
use sshkm_core::p2p::contact::{self, ContactKey};
use sshkm_core::p2p::own::window;

use super::super::{addresses_of, mdns, mdns_error};
use super::{Conversation, Found, Nearby, Stop};
use crate::error::AppResult;

/// The mDNS service type chats are announced as.
pub const CHAT_SERVICE_TYPE: &str = "_sshkm-chat._tcp.local.";
/// TXT strings of tags an announcement may have (`t0`…).
const MAX_TXT: usize = 3;

/// This computer, online for chats.
pub(in crate::nearby) struct Online {
    port: u16,
    stop: Stop,
    /// The mDNS name it is announced under; empty until it is.
    fullname: String,
    window: u64,
}

impl Nearby {
    /// Listens, announces and browses; makes the chat key if there is none.
    pub(super) fn go_online(self: &Arc<Self>) -> AppResult<()> {
        // Online already: never a second listener or announcement beside it.
        if self.chats().online.is_some() {
            return Ok(());
        }
        self.chat_key()?;
        self.read_known();
        self.read_all_conversations();
        let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let stop: Stop = Arc::new(AtomicBool::new(false));
        {
            let nearby = Arc::clone(self);
            let stop = Arc::clone(&stop);
            thread::spawn(move || nearby.listen_chats(&listener, &stop));
        }
        let before = self.chats().online.replace(Online {
            port,
            stop,
            fullname: String::new(),
            window: 0,
        });
        // Should another have come meanwhile, it stops: one port, one name.
        if let Some(before) = before {
            self.stop_online(&before);
        }
        let browse = self.announce_chats().and_then(|()| {
            let daemon = mdns(&mut self.lock())?;
            daemon.browse(CHAT_SERVICE_TYPE).map_err(mdns_error)
        });
        let events = match browse {
            Ok(events) => events,
            Err(error) => {
                self.go_offline();
                return Err(error);
            }
        };
        let nearby = Arc::clone(self);
        thread::spawn(move || {
            while let Ok(event) = events.recv() {
                if !nearby.found_chat(event) {
                    break;
                }
            }
        });
        self.chats_changed(None);
        Ok(())
    }

    /// Stops listening, announcing and browsing, and closes every link.
    pub(super) fn go_offline(&self) {
        let (online, links) = {
            let mut chats = self.chats();
            chats.found.clear();
            chats.grace_until = None;
            chats.offers.clear();
            chats.incoming.clear();
            (chats.online.take(), chats.links.drain().collect::<Vec<_>>())
        };
        if let Some(online) = online {
            self.stop_online(&online);
            if let Some(daemon) = &self.lock().mdns {
                let _ = daemon.stop_browse(CHAT_SERVICE_TYPE);
            }
        }
        self.chats().receipts.clear();
        for (peer, link) in links {
            link.writer.shutdown();
            let _ = self.edit(&peer, Conversation::disconnected);
        }
        self.chats_changed(None);
    }

    /// Stops a listener and takes its name off the network.
    fn stop_online(&self, online: &Online) {
        online.stop.store(true, Ordering::SeqCst);
        if !online.fullname.is_empty()
            && let Some(daemon) = &self.lock().mdns
        {
            let _ = daemon.unregister(&online.fullname);
        }
    }

    /// Announces again now, with the contacts as they are: one added gets a
    /// tag, one removed loses its.
    pub(super) fn reannounce(&self) {
        if let Err(error) = self.announce_chats() {
            log::warn!("nearby: chats could not be announced again: {error}");
        }
    }

    /// Announces again under a new name once the ten-minute window changed.
    pub(super) fn renew_presence(self: &Arc<Self>) {
        let stale = self
            .chats()
            .online
            .as_ref()
            .is_some_and(|online| online.window != window(now()));
        if stale {
            self.read_known();
            if let Err(error) = self.announce_chats() {
                log::warn!("nearby: chats could not be announced again: {error}");
            }
        }
    }

    /// Announces this computer for chats under a new random name, with a
    /// tag for each contact and device: own devices first, then the
    /// contacts chatted with last.
    fn announce_chats(&self) -> AppResult<()> {
        let me = self.identity()?.public();
        let daemon = mdns(&mut self.lock())?;
        let (port, old, contacts) = {
            let chats = self.chats();
            let Some(online) = &chats.online else {
                return Ok(());
            };
            let mut known: Vec<(bool, i64, Arc<ContactKey>)> = chats
                .known
                .iter()
                .map(|known| {
                    let last = chats
                        .conversations
                        .get(&known.key)
                        .and_then(|chat| chat.entries().last())
                        .map_or(0, |entry| entry.at);
                    (known.own, last, Arc::clone(&known.contact))
                })
                .collect();
            known.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
            (
                online.port,
                online.fullname.clone(),
                known.into_iter().map(|(_, _, key)| key).collect::<Vec<_>>(),
            )
        };
        let current = window(now());
        let instance = instance_name();
        let keys: Vec<&ContactKey> = contacts.iter().map(AsRef::as_ref).collect();
        let txt = contact::presence_txt(&me, &keys, &instance, current);
        let names: Vec<String> = (0..txt.len()).map(|i| format!("t{i}")).collect();
        let mut properties: Vec<(&str, &str)> = vec![("v", "1")];
        properties.extend(
            names
                .iter()
                .zip(&txt)
                .take(MAX_TXT)
                .map(|(name, value)| (name.as_str(), value.as_str())),
        );
        if !old.is_empty() {
            let _ = daemon.unregister(&old);
        }
        let info = ServiceInfo::new(
            CHAT_SERVICE_TYPE,
            &instance,
            &format!("{instance}.local."),
            (),
            port,
            &properties[..],
        )
        .map_err(mdns_error)?
        .enable_addr_auto();
        let fullname = info.get_fullname().to_owned();
        daemon.register(info).map_err(mdns_error)?;
        if let Some(online) = self.chats().online.as_mut() {
            online.fullname = fullname;
            online.window = current;
        }
        Ok(())
    }

    fn listen_chats(self: Arc<Self>, listener: &TcpListener, stop: &AtomicBool) {
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let nearby = Arc::clone(&self);
                    thread::spawn(move || nearby.chat_incoming(stream));
                }
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

    /// An mDNS event for chats; `false` once browsing stopped.
    fn found_chat(&self, event: ServiceEvent) -> bool {
        match event {
            ServiceEvent::ServiceResolved(service) => {
                let peer = {
                    let chats = self.chats();
                    let Some(online) = &chats.online else {
                        return false;
                    };
                    if service.fullname == online.fullname {
                        return true;
                    }
                    let instance = service
                        .fullname
                        .strip_suffix(&format!(".{CHAT_SERVICE_TYPE}"))
                        .unwrap_or_default();
                    let names: Vec<String> = (0..MAX_TXT).map(|i| format!("t{i}")).collect();
                    let tags = contact::parse_tags(
                        names
                            .iter()
                            .filter_map(|name| service.get_property_val_str(name)),
                    );
                    let pairs: Vec<(PeerKey, &ContactKey)> = chats
                        .known
                        .iter()
                        .map(|known| (known.key, known.contact.as_ref()))
                        .collect();
                    contact::recognize(&tags, instance, window(now()), &pairs)
                };
                let Some(peer) = peer else {
                    return true;
                };
                let addresses = addresses_of(&service);
                if addresses.is_empty() {
                    return true;
                }
                self.chats()
                    .found
                    .insert(service.fullname.clone(), Found { peer, addresses });
                self.chats_changed(Some(&peer));
            }
            ServiceEvent::ServiceRemoved(_, fullname) => {
                let removed = self.chats().found.remove(&fullname);
                if let Some(found) = removed {
                    self.chats_changed(Some(&found.peer));
                }
            }
            ServiceEvent::SearchStopped(_) => return false,
            _ => {}
        }
        true
    }
}

/// A random instance name: 16 hex digits.
fn instance_name() -> String {
    let mut bytes = [0; 8];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().fold(String::with_capacity(16), |mut hex, b| {
        let _ = write!(hex, "{b:02x}");
        hex
    })
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
