//! Chat sessions ("links"): connecting to a contact found online, taking a
//! contact's connection on the chat port, and what each frame does.
//!
//! A link starts with the knock ([`contact::knock`]), so the chat port says
//! nothing to anyone else, then a Noise handshake bound to it and a `Hello`
//! each way that must name `chat/1`. Then one thread reads while the user's
//! commands send. Of two links two devices open at once, both keep the one
//! the device with the smaller key started. Messages without a receipt go
//! again on a new link, under the same id; the receiver keeps each once.

use std::collections::HashMap;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use sshkm_core::ErrorCode;
use sshkm_core::chat::{Body, Conversation, Entry, Line, Outcome};
use sshkm_core::p2p::chat::{ChatFrame, RateLimit, Refusal, new_id};
use sshkm_core::p2p::contact::{self, ContactKey};
use sshkm_core::p2p::deadline::Deadline;
use sshkm_core::p2p::protocol::{CHAT, Item, ItemSummary, VERSION, features};
use sshkm_core::p2p::session::{Reader, Writer};
use sshkm_core::p2p::{self, Message, PeerKey, Session};

use super::{Incoming, Nearby, entry_of, frame_of, set_outcome, unix_now};
use crate::error::{AppError, AppResult};

/// How long an offer waits for the other user's answer.
pub(super) const OFFER_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// At most one notification per conversation this often.
pub(super) const NOTIFY_EVERY: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// For the knock, the handshake and the `Hello`s.
const KNOCK_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// A link one send has waited on this long is gone: its peer doesn't read,
/// or reads a byte now and then (each write keeps within its timeout).
const STUCK_AFTER: Duration = Duration::from_secs(60);
const PING_EVERY: Duration = Duration::from_secs(30);
/// A link that hears nothing for this long is gone.
const DEAD_AFTER: Duration = Duration::from_secs(90);
/// A link nothing was said on for this long closes; it opens again on demand.
const IDLE_AFTER: Duration = Duration::from_secs(10 * 60);
/// Most links at once, and connections waiting at the knock (in all, and
/// from one address).
const MAX_LINKS: usize = 16;
const MAX_KNOCKING: usize = 8;
const MAX_KNOCKING_PER_ADDRESS: usize = 2;
/// Most offers that wait for this user's answer from one contact.
const MAX_OFFERS: usize = 3;
/// How long a contact that sent too much is turned away.
const PAUSE: Duration = Duration::from_secs(60);

static NEXT_LINK: AtomicU64 = AtomicU64::new(1);

/// A chat session with a contact.
pub(super) struct Link {
    pub writer: Arc<Writer>,
    /// What the other app can do.
    pub features: Vec<String>,
    /// The device that started it.
    initiator: PeerKey,
    id: u64,
    /// When a frame last went: pings count.
    last_out: Instant,
    /// When a message last went either way: pings don't count.
    pub last_use: Instant,
    ping: u64,
    /// A thread is sending its receipts: never a second beside it.
    pub receipting: Arc<AtomicBool>,
}

fn offline() -> AppError {
    AppError::new(
        ErrorCode::NotFound,
        "the other computer is offline: messages go only while Nearby is open on both",
    )
}

impl Nearby {
    /// Links to `peer`, connecting first if there is no link yet. Returns
    /// what the other app can do.
    pub(super) fn link_to(self: &Arc<Self>, peer: &PeerKey) -> AppResult<Vec<String>> {
        let (addresses, key) = {
            let chats = self.chats();
            if let Some(link) = chats.links.get(peer) {
                return Ok(link.features.clone());
            }
            if chats.online.is_none() {
                return Err(offline());
            }
            let addresses: Vec<_> = chats
                .found
                .values()
                .filter(|found| found.peer == *peer)
                .flat_map(|found| found.addresses.iter().copied())
                .collect();
            let key = chats
                .known
                .iter()
                .find(|known| known.key == *peer)
                .map(|known| Arc::clone(&known.contact));
            (addresses, key)
        };
        let key = key.ok_or_else(|| AppError::not_found("that computer is not a contact"))?;
        let identity = self.identity()?;
        let me = identity.public();
        for address in addresses {
            let Ok(stream) = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) else {
                continue;
            };
            // As for one coming in: one deadline for the first steps.
            let mut stream = Deadline::new(stream, KNOCK_TIMEOUT);
            let Ok(prologue) = contact::knock(&mut stream, &key, peer) else {
                continue;
            };
            let Ok(session) = p2p::connect_with(stream, &identity, &prologue) else {
                continue;
            };
            if session.remote() != *peer {
                continue;
            }
            match self.start_link(session, *peer, me, me) {
                Ok(linked) => return Ok(linked),
                Err(error) => log::warn!("nearby: a chat link didn't start: {error}"),
            }
        }
        Err(offline())
    }

    /// A connection to the chat port: a contact's knock, or nothing.
    pub(super) fn chat_incoming(self: &Arc<Self>, stream: TcpStream) {
        let address = stream.peer_addr().ok().map(|address| address.ip());
        {
            let mut chats = self.chats();
            let from = address.map_or(0, |ip| chats.knocking_by.get(&ip).copied().unwrap_or(0));
            if chats.knocking >= MAX_KNOCKING || from >= MAX_KNOCKING_PER_ADDRESS {
                return;
            }
            chats.knocking += 1;
            if let Some(ip) = address {
                *chats.knocking_by.entry(ip).or_default() += 1;
            }
        }
        let result = (|| -> AppResult<()> {
            // A listener's socket hands on its non-blocking mode on some systems.
            stream.set_nonblocking(false)?;
            // One deadline for the knock, the handshake and the Hellos: bytes
            // that trickle in don't keep a place at the knock.
            let mut stream = Deadline::new(stream, KNOCK_TIMEOUT);
            let identity = self.identity()?;
            let me = identity.public();
            let known: Vec<(PeerKey, Arc<ContactKey>)> = self
                .chats()
                .known
                .iter()
                .map(|known| (known.key, Arc::clone(&known.contact)))
                .collect();
            let pairs: Vec<(PeerKey, &ContactKey)> = known
                .iter()
                .map(|(key, contact)| (*key, contact.as_ref()))
                .collect();
            let Some(knocked) = contact::answer_knock(&mut stream, &me, &pairs)? else {
                return Ok(());
            };
            let peer = knocked.peer;
            // Each knock counts against the contact's frames: knocking again
            // and again earns nothing.
            if !self.spend(&peer) {
                self.pause(&peer);
                return Ok(());
            }
            let paused = {
                let mut chats = self.chats();
                let paused = chats
                    .paused
                    .get(&peer)
                    .is_some_and(|until| Instant::now() < *until);
                if !paused {
                    chats.paused.remove(&peer);
                }
                paused
            };
            if paused {
                return Ok(());
            }
            let session = p2p::accept_with(stream, &identity, &knocked.prologue())?;
            if session.remote() != peer {
                return Ok(());
            }
            self.start_link(session, peer, me, peer)?;
            Ok(())
        })();
        if let Err(error) = result {
            log::debug!("nearby: a chat connection ended early: {error}");
        }
        let mut chats = self.chats();
        chats.knocking -= 1;
        if let Some(ip) = address
            && let Some(count) = chats.knocking_by.get_mut(&ip)
        {
            *count -= 1;
            if *count == 0 {
                chats.knocking_by.remove(&ip);
            }
        }
    }

    /// Counts one frame (or knock) from `peer` against its bucket, which
    /// outlives its links; `false` once it sent too many.
    fn spend(&self, peer: &PeerKey) -> bool {
        spend(&mut self.chats().limits, *peer, Instant::now())
    }

    /// The `Hello`s; then the link is kept, read on a thread of its own,
    /// and what waited for a receipt goes again.
    fn start_link(
        self: &Arc<Self>,
        mut session: Session<Deadline>,
        peer: PeerKey,
        me: PeerKey,
        initiator: PeerKey,
    ) -> AppResult<Vec<String>> {
        let name = self.lock().name.clone();
        session.send(&Message::Hello {
            version: VERSION,
            name,
            known: true,
            own: None,
            features: features(),
        })?;
        let Message::Hello {
            version,
            known,
            features: theirs,
            ..
        } = session.recv()?
        else {
            return Err(AppError::invalid("the other computer didn't say hello"));
        };
        if version != VERSION || !known || !theirs.iter().any(|feature| feature == CHAT) {
            return Err(AppError::invalid("the other computer doesn't chat"));
        }
        // Past the first steps: the socket's own timeouts from here on.
        let session = session.map_stream(Deadline::into_inner);
        session.stream().set_read_timeout(Some(DEAD_AFTER))?;
        session.stream().set_write_timeout(Some(WRITE_TIMEOUT))?;
        let (reader, writer) = session.split()?;
        let writer = Arc::new(writer);
        let linked = theirs.clone();
        let id = NEXT_LINK.fetch_add(1, Ordering::SeqCst);
        let pushed_out = {
            let mut chats = self.chats();
            if chats.online.is_none() {
                writer.shutdown();
                return Err(offline());
            }
            let mut pushed_out = None;
            if let Some(old) = chats.links.get(&peer) {
                if keeps_old(&me, &peer, &old.initiator, &initiator) {
                    writer.shutdown();
                    return Ok(old.features.clone());
                }
                old.writer.shutdown();
            } else if chats.links.len() >= MAX_LINKS
                && let Some(oldest) =
                    oldest(chats.links.iter().map(|(key, link)| (*key, link.last_use)))
                && let Some(link) = chats.links.remove(&oldest)
            {
                link.writer.shutdown();
                pushed_out = Some(oldest);
            }
            let now = Instant::now();
            chats.links.insert(
                peer,
                Link {
                    writer,
                    features: theirs,
                    initiator,
                    id,
                    last_out: now,
                    last_use: now,
                    ping: 0,
                    receipting: Arc::new(AtomicBool::new(false)),
                },
            );
            pushed_out
        };
        if let Some(pushed_out) = pushed_out {
            self.link_gone(&pushed_out);
        }
        let nearby = Arc::clone(self);
        thread::spawn(move || nearby.read_link(peer, id, reader));
        self.resend(&peer);
        self.chats_changed(Some(&peer));
        Ok(linked)
    }

    /// Reads a link until it ends.
    fn read_link(self: Arc<Self>, peer: PeerKey, id: u64, mut reader: Reader) {
        while let Ok(message) = reader.recv() {
            if !self.spend(&peer) {
                self.pause(&peer);
                break;
            }
            // Anything but a chat frame on a chat link ends it.
            let Message::Chat { frame } = message else {
                break;
            };
            if !matches!(frame, ChatFrame::Ping { .. } | ChatFrame::Pong { .. })
                && let Some(link) = self
                    .chats()
                    .links
                    .get_mut(&peer)
                    .filter(|link| link.id == id)
            {
                link.last_use = Instant::now();
            }
            self.on_frame(&peer, frame);
        }
        self.link_closed(&peer, id);
    }

    /// A contact sent too much at once: its link closes, and it is turned
    /// away for a minute.
    fn pause(&self, peer: &PeerKey) {
        let now = Instant::now();
        let already = {
            let mut chats = self.chats();
            let already = chats.paused.get(peer).is_some_and(|until| now < *until);
            chats.paused.insert(*peer, now + PAUSE);
            already
        };
        if already {
            return;
        }
        let line = Entry {
            id: new_id(),
            mine: false,
            at: unix_now(),
            body: Body::Line { line: Line::Paused },
            delivery: sshkm_core::chat::Delivery::Received,
        };
        let _ = self.edit(peer, |chat| chat.push(line));
    }

    /// A link ended: unless another took its place, what waited for an
    /// answer ends with it.
    fn link_closed(&self, peer: &PeerKey, id: u64) {
        let closed = {
            let mut chats = self.chats();
            if chats.links.get(peer).is_some_and(|link| link.id == id) {
                if let Some(link) = chats.links.remove(peer) {
                    link.writer.shutdown();
                }
                chats.offers.retain(|_, offer| offer.peer != *peer);
                chats.incoming.retain(|_, incoming| incoming.peer != *peer);
                true
            } else {
                false
            }
        };
        if closed {
            let _ = self.edit(peer, Conversation::disconnected);
            self.chats_changed(Some(peer));
        }
    }

    /// Sends a frame on the link to `peer`.
    pub(super) fn send_frame(&self, peer: &PeerKey, frame: &ChatFrame) -> AppResult<()> {
        let writer = self
            .chats()
            .links
            .get(peer)
            .map(|link| Arc::clone(&link.writer))
            .ok_or_else(offline)?;
        if let Err(error) = writer.send(&Message::Chat {
            frame: frame.clone(),
        }) {
            writer.shutdown();
            return Err(error.into());
        }
        if let Some(link) = self.chats().links.get_mut(peer) {
            link.last_out = Instant::now();
            if !matches!(frame, ChatFrame::Ping { .. } | ChatFrame::Pong { .. }) {
                link.last_use = Instant::now();
            }
        }
        Ok(())
    }

    /// Sends again what waits for a receipt or an answer.
    fn resend(&self, peer: &PeerKey) {
        let now = unix_now();
        let mut frames: Vec<ChatFrame> = self
            .read(peer, |chat| {
                chat.sending()
                    .iter()
                    .filter_map(|id| frame_of(chat.get(id)?, now))
                    .collect()
            })
            .unwrap_or_default();
        frames.extend(
            self.chats()
                .offers
                .iter()
                .filter(|(_, offer)| offer.peer == *peer)
                .map(|(id, offer)| ChatFrame::Offer {
                    id: id.clone(),
                    item: offer.item.summary(),
                }),
        );
        for frame in frames {
            if self.send_frame(peer, &frame).is_err() {
                break;
            }
        }
    }

    /// Pings links that were quiet, and closes those idle for long or
    /// stuck on a send.
    pub(super) fn keep_links_alive(&self) {
        let now = Instant::now();
        let mut pings = Vec::new();
        {
            let mut chats = self.chats();
            for link in chats.links.values_mut() {
                if now.duration_since(link.last_use) >= IDLE_AFTER
                    || link.writer.busy_for() >= STUCK_AFTER
                {
                    link.writer.shutdown();
                } else if now.duration_since(link.last_out) >= PING_EVERY {
                    link.ping += 1;
                    link.last_out = now;
                    pings.push((Arc::clone(&link.writer), link.ping));
                }
            }
        }
        if !pings.is_empty() {
            thread::spawn(move || {
                for (writer, n) in pings {
                    if writer
                        .send(&Message::Chat {
                            frame: ChatFrame::Ping { n },
                        })
                        .is_err()
                    {
                        writer.shutdown();
                    }
                }
            });
        }
    }

    /// What a frame from `peer` does.
    fn on_frame(self: &Arc<Self>, peer: &PeerKey, frame: ChatFrame) {
        match frame {
            ChatFrame::Text { .. } | ChatFrame::Secret { .. } | ChatFrame::Variables { .. } => {
                self.on_message(peer, &frame);
            }
            ChatFrame::Offer { ref id, ref item } => self.on_offer(peer, id, item, &frame),
            ChatFrame::Reply {
                id,
                accepted,
                unsupported,
            } => self.on_reply(peer, &id, accepted, unsupported),
            ChatFrame::Payload { id, item } => self.on_payload(peer, &id, &item),
            ChatFrame::Saved { id, saved } => {
                if self.take_offer(peer, &id) {
                    let outcome = if saved {
                        Outcome::Saved
                    } else {
                        Outcome::NotSaved
                    };
                    let _ = self.edit(peer, |chat| set_outcome(chat, &id, true, outcome));
                    self.chats_changed(Some(peer));
                }
            }
            ChatFrame::Delivered { ref ids } => {
                if frame.check().is_ok()
                    && self.edit(peer, |chat| chat.delivered(ids)).unwrap_or(false)
                {
                    self.chats_changed(Some(peer));
                }
            }
            ChatFrame::Refused { id, reason } => {
                // Only this side's messages, and only its offers to this peer.
                let offered = self.take_offer(peer, &id);
                let changed = self
                    .edit(peer, |chat| {
                        let changed = chat.refused(&id, reason);
                        if offered {
                            set_outcome(chat, &id, true, Outcome::Ended);
                        }
                        changed
                    })
                    .unwrap_or(false);
                if changed {
                    self.chats_changed(Some(peer));
                }
            }
            ChatFrame::Revoke { id } => {
                if self
                    .edit(peer, |chat| chat.wipe(&id, true))
                    .unwrap_or(false)
                {
                    self.chats_changed(Some(peer));
                }
            }
            ChatFrame::Ping { n } => {
                let _ = self.send_frame(peer, &ChatFrame::Pong { n });
            }
            ChatFrame::Pong { .. } | ChatFrame::Unknown => {}
        }
    }

    /// A text, a secret or variables: stored, then the receipt.
    fn on_message(self: &Arc<Self>, peer: &PeerKey, frame: &ChatFrame) {
        let Some(id) = frame.id().map(str::to_owned) else {
            return;
        };
        if let Err(reason) = frame.check() {
            let _ = self.send_frame(peer, &ChatFrame::Refused { id, reason });
            return;
        }
        let Some(entry) = entry_of(frame, false, unix_now()) else {
            return;
        };
        let Ok(new) = self.edit(peer, |chat| chat.receive(entry)) else {
            return;
        };
        // The receipt goes once the conversation is written: stored for good.
        self.receipt(peer, id);
        if new {
            self.chats_changed(Some(peer));
            self.notify(peer);
        }
    }

    /// An item offered: a card for this user to answer.
    fn on_offer(self: &Arc<Self>, peer: &PeerKey, id: &str, item: &ItemSummary, frame: &ChatFrame) {
        match frame.check() {
            Ok(()) => {}
            Err(Refusal::Unsupported) => {
                let _ = self.send_frame(
                    peer,
                    &ChatFrame::Reply {
                        id: id.to_owned(),
                        accepted: false,
                        unsupported: true,
                    },
                );
                return;
            }
            Err(reason) => {
                let _ = self.send_frame(
                    peer,
                    &ChatFrame::Refused {
                        id: id.to_owned(),
                        reason,
                    },
                );
                return;
            }
        }
        let waiting = self
            .chats()
            .incoming
            .values()
            .filter(|incoming| incoming.peer == *peer)
            .count();
        if waiting >= MAX_OFFERS {
            let _ = self.send_frame(
                peer,
                &ChatFrame::Refused {
                    id: id.to_owned(),
                    reason: Refusal::TooMany,
                },
            );
            return;
        }
        let Some(entry) = entry_of(frame, false, unix_now()) else {
            return;
        };
        let Ok(new) = self.edit(peer, |chat| chat.receive(entry)) else {
            return;
        };
        if new {
            self.chats().incoming.insert(
                id.to_owned(),
                Incoming {
                    peer: *peer,
                    summary: item.clone(),
                    accepted: false,
                },
            );
        }
        self.receipt(peer, id.to_owned());
        if new {
            self.chats_changed(Some(peer));
            self.notify(peer);
        }
    }

    /// The other user's answer to an item this side offered.
    fn on_reply(&self, peer: &PeerKey, id: &str, accepted: bool, unsupported: bool) {
        let item = {
            let mut chats = self.chats();
            if !chats
                .offers
                .get(id)
                .is_some_and(|offer| offer.peer == *peer)
            {
                return;
            }
            if accepted {
                chats.offers.get(id).map(|offer| offer.item.clone())
            } else {
                chats.offers.remove(id);
                None
            }
        };
        let outcome = match (accepted, unsupported) {
            (true, _) => Outcome::Accepted,
            (false, true) => Outcome::Unsupported,
            (false, false) => Outcome::Declined,
        };
        let _ = self.edit(peer, |chat| set_outcome(chat, id, true, outcome));
        self.chats_changed(Some(peer));
        if let Some(item) = item {
            let _ = self.send_frame(
                peer,
                &ChatFrame::Payload {
                    id: id.to_owned(),
                    item,
                },
            );
        }
    }

    /// The item of an offer this user accepted: checked against the offer
    /// and saved the way Nearby saves one.
    fn on_payload(self: &Arc<Self>, peer: &PeerKey, id: &str, item: &Item) {
        let summary = {
            let mut chats = self.chats();
            let accepted = chats
                .incoming
                .get(id)
                .is_some_and(|incoming| incoming.peer == *peer && incoming.accepted);
            if !accepted {
                return;
            }
            chats.incoming.remove(id).map(|incoming| incoming.summary)
        };
        let Some(summary) = summary else {
            return;
        };
        let name = self
            .chats()
            .known
            .iter()
            .find(|known| known.key == *peer)
            .map(|known| known.name.clone());
        let saved = if item.summary() == summary && item.check().is_ok() {
            let group = self.next_id.fetch_add(1, Ordering::SeqCst);
            super::items::store(self, group, name.as_deref(), item)
                .map(|stored| {
                    (
                        stored,
                        matches!(item, Item::HostsGroup { .. }).then_some(group),
                    )
                })
                .ok()
        } else {
            None
        };
        let _ = self.edit(peer, |chat| {
            if let Some(Entry {
                body:
                    Body::Card {
                        outcome,
                        name,
                        keys_differ,
                        group,
                        left_out,
                        ..
                    },
                mine: false,
                ..
            }) = chat.get_mut(id)
            {
                match &saved {
                    Some((stored, waiting)) => {
                        *outcome = Outcome::Saved;
                        *name = Some(stored.name.clone());
                        *keys_differ = stored.keys_differ;
                        left_out.clone_from(&stored.left_out);
                        *group = *waiting;
                    }
                    None => *outcome = Outcome::NotSaved,
                }
            }
        });
        self.chats_changed(Some(peer));
        let _ = self.send_frame(
            peer,
            &ChatFrame::Saved {
                id: id.to_owned(),
                saved: saved.is_some(),
            },
        );
    }
}

impl Nearby {
    /// Takes this side's offer `id` if it went to `peer`; `false` for any
    /// other id, or an offer to someone else, which stays.
    fn take_offer(&self, peer: &PeerKey, id: &str) -> bool {
        let mut chats = self.chats();
        if chats
            .offers
            .get(id)
            .is_some_and(|offer| offer.peer == *peer)
        {
            chats.offers.remove(id);
            true
        } else {
            false
        }
    }
}

/// Counts one frame from `peer` in `limits` at `now`; `false` once it sent
/// too many.
fn spend(limits: &mut HashMap<PeerKey, RateLimit>, peer: PeerKey, now: Instant) -> bool {
    limits
        .entry(peer)
        .or_insert_with(|| RateLimit::new(now))
        .take(now)
}

/// Whether a new link with `peer`, started by `initiator`, gives way to the
/// one there, started by `old`: of two at once, both sides keep the one
/// the device with the smaller key started.
fn keeps_old(me: &PeerKey, peer: &PeerKey, old: &PeerKey, initiator: &PeerKey) -> bool {
    let winner = if me.as_bytes() < peer.as_bytes() {
        me
    } else {
        peer
    };
    old == winner && initiator != winner
}

/// The link used least recently: the one to go when there are too many.
fn oldest(links: impl Iterator<Item = (PeerKey, Instant)>) -> Option<PeerKey> {
    links.min_by_key(|(_, used)| *used).map(|(key, _)| key)
}

#[cfg(test)]
mod tests {
    use sshkm_core::p2p::Identity;

    use super::*;

    fn key() -> PeerKey {
        Identity::generate().unwrap().public()
    }

    #[test]
    fn the_rate_limit_outlives_a_link() {
        let (bob, carol) = (key(), key());
        let mut limits = HashMap::new();
        let now = Instant::now();
        for _ in 0..30 {
            assert!(spend(&mut limits, bob, now));
        }
        // Bob hangs up and knocks again: the bucket is his, not the link's.
        assert!(!spend(&mut limits, bob, now));
        assert!(
            spend(&mut limits, carol, now),
            "another contact has its own"
        );
        assert!(spend(&mut limits, bob, now + Duration::from_secs(1)));
    }

    #[test]
    fn of_two_links_both_sides_keep_the_one_the_smaller_key_started() {
        let (a, b) = (key(), key());
        let (small, large) = if a.as_bytes() < b.as_bytes() {
            (a, b)
        } else {
            (b, a)
        };
        // On the smaller key's side: its own link stays, the other's gives way.
        assert!(keeps_old(&small, &large, &small, &large));
        assert!(!keeps_old(&small, &large, &large, &small));
        // On the larger key's side, the same link stays.
        assert!(keeps_old(&large, &small, &small, &large));
        assert!(!keeps_old(&large, &small, &large, &small));
        // A link started again by the winner replaces its old one.
        assert!(!keeps_old(&small, &large, &small, &small));
    }

    #[test]
    fn the_link_used_least_recently_goes_first() {
        let (a, b, c) = (key(), key(), key());
        let start = Instant::now();
        let links = [
            (a, start + Duration::from_secs(60)),
            (b, start),
            (c, start + Duration::from_secs(55)),
        ];
        assert_eq!(oldest(links.into_iter()), Some(b));
        assert_eq!(oldest(std::iter::empty()), None);
    }
}
