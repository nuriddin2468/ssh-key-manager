//! Chat sessions ("links"): connecting to a contact found online, taking a
//! contact's connection on the chat port, and what each frame does.
//!
//! A link starts with the knock ([`contact::knock`]), so the chat port says
//! nothing to anyone else, then a Noise handshake bound to it and a `Hello`
//! each way that must name `chat/1`. Then one thread reads while the user's
//! commands send. Of two links two devices open at once, both keep the one
//! the device with the smaller key started. Messages without a receipt go
//! again on a new link, under the same id; the receiver keeps each once.

use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use sshkm_core::ErrorCode;
use sshkm_core::chat::{Body, Conversation, Entry, Line, Outcome};
use sshkm_core::p2p::chat::{ChatFrame, RateLimit, Refusal, new_id};
use sshkm_core::p2p::contact::{self, ContactKey};
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
const PING_EVERY: Duration = Duration::from_secs(30);
/// A link that hears nothing for this long is gone.
const DEAD_AFTER: Duration = Duration::from_secs(90);
/// A link nothing was said on for this long closes; it opens again on demand.
const IDLE_AFTER: Duration = Duration::from_secs(10 * 60);
/// Most links at once, and connections waiting at the knock.
const MAX_LINKS: usize = 16;
const MAX_KNOCKING: usize = 8;
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
            let Ok(mut stream) = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) else {
                continue;
            };
            let _ = stream.set_read_timeout(Some(KNOCK_TIMEOUT));
            let _ = stream.set_write_timeout(Some(KNOCK_TIMEOUT));
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
    pub(super) fn chat_incoming(self: &Arc<Self>, mut stream: TcpStream) {
        {
            let mut chats = self.chats();
            if chats.knocking >= MAX_KNOCKING {
                return;
            }
            chats.knocking += 1;
        }
        let result = (|| -> AppResult<()> {
            // A listener's socket hands on its non-blocking mode on some systems.
            stream.set_nonblocking(false)?;
            stream.set_read_timeout(Some(KNOCK_TIMEOUT))?;
            stream.set_write_timeout(Some(KNOCK_TIMEOUT))?;
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
        self.chats().knocking -= 1;
    }

    /// The `Hello`s; then the link is kept, read on a thread of its own,
    /// and what waited for a receipt goes again.
    fn start_link(
        self: &Arc<Self>,
        mut session: Session<TcpStream>,
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
        session.stream().set_read_timeout(Some(DEAD_AFTER))?;
        session.stream().set_write_timeout(Some(WRITE_TIMEOUT))?;
        let (reader, writer) = session.split()?;
        let writer = Arc::new(writer);
        let linked = theirs.clone();
        // Of two links at once, both sides keep the one the smaller key started.
        let winner = if me.as_bytes() < peer.as_bytes() {
            me
        } else {
            peer
        };
        let id = NEXT_LINK.fetch_add(1, Ordering::SeqCst);
        {
            let mut chats = self.chats();
            if chats.online.is_none() {
                writer.shutdown();
                return Err(offline());
            }
            if let Some(old) = chats.links.get(&peer) {
                if old.initiator == winner && initiator != winner {
                    writer.shutdown();
                    return Ok(old.features.clone());
                }
                old.writer.shutdown();
            } else if chats.links.len() >= MAX_LINKS
                && let Some(oldest) = chats
                    .links
                    .iter()
                    .min_by_key(|(_, link)| link.last_use)
                    .map(|(key, _)| *key)
                && let Some(link) = chats.links.remove(&oldest)
            {
                link.writer.shutdown();
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
                },
            );
        }
        let nearby = Arc::clone(self);
        thread::spawn(move || nearby.read_link(peer, id, reader));
        self.resend(&peer);
        self.chats_changed(Some(&peer));
        Ok(linked)
    }

    /// Reads a link until it ends.
    fn read_link(self: Arc<Self>, peer: PeerKey, id: u64, mut reader: Reader) {
        let mut limit = RateLimit::new(Instant::now());
        while let Ok(message) = reader.recv() {
            if !limit.take(Instant::now()) {
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
        self.chats().paused.insert(*peer, Instant::now() + PAUSE);
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

    /// Pings links that were quiet, and closes those idle for long.
    pub(super) fn keep_links_alive(&self) {
        let now = Instant::now();
        let mut pings = Vec::new();
        {
            let mut chats = self.chats();
            for link in chats.links.values_mut() {
                if now.duration_since(link.last_use) >= IDLE_AFTER {
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
                let mine = self
                    .chats()
                    .offers
                    .remove(&id)
                    .is_some_and(|offer| offer.peer == *peer);
                if mine {
                    let outcome = if saved {
                        Outcome::Saved
                    } else {
                        Outcome::NotSaved
                    };
                    let _ = self.edit(peer, |chat| set_outcome(chat, &id, outcome));
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
                let changed = self
                    .edit(peer, |chat| {
                        let changed = chat.refused(&id, reason);
                        set_outcome(chat, &id, Outcome::Ended);
                        changed
                    })
                    .unwrap_or(false);
                self.chats().offers.retain(|offer, _| *offer != id);
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
        // Stored for good before the receipt says so.
        self.write_conversations();
        let _ = self.send_frame(peer, &ChatFrame::Delivered { ids: vec![id] });
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
        self.write_conversations();
        let _ = self.send_frame(
            peer,
            &ChatFrame::Delivered {
                ids: vec![id.to_owned()],
            },
        );
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
        let _ = self.edit(peer, |chat| set_outcome(chat, id, outcome));
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
                .map(|(name, keys_differ)| {
                    (
                        name,
                        keys_differ,
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
                        ..
                    },
                ..
            }) = chat.get_mut(id)
            {
                match &saved {
                    Some((saved_as, differ, waiting)) => {
                        *outcome = Outcome::Saved;
                        *name = Some(saved_as.clone());
                        *keys_differ = *differ;
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
