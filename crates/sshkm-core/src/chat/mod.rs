//! A chat's history on this computer: what was said with one paired device
//! or one of the user's own, kept per computer and never synced.
//!
//! A [`Conversation`] is a list of [`Entry`]s in the order this computer
//! saw them, timed by its own clock. It remembers the ids it received, so a
//! message sent again is stored once, and it wipes the value of a secret or
//! of variables once their term ends ([`Conversation::wipe_expired`]),
//! keeping a line that they were there. [`file`] seals it into the file it
//! is kept in, with a key the vault holds.
//!
//! A conversation keeps at most [`MAX_ENTRIES`] entries and [`MAX_BYTES`]
//! of JSON; the oldest go first.

pub mod file;

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use crate::p2p::chat::Refusal;
use crate::p2p::protocol::{ItemSummary, SecretText};

/// Most entries a conversation keeps.
pub const MAX_ENTRIES: usize = 5000;
/// Most bytes of JSON a conversation keeps.
pub const MAX_BYTES: usize = 2 * 1024 * 1024;
/// How many received ids a conversation remembers, to drop duplicates.
const MAX_SEEN: usize = 10_000;

/// The history with one device.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Conversation {
    #[serde(default)]
    entries: Vec<Entry>,
    /// Ids received, oldest first.
    #[serde(default)]
    seen: VecDeque<String>,
    /// How many entries, from the first, the user has seen.
    #[serde(default)]
    read: usize,
}

/// One message, card or line of a conversation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub id: String,
    /// This computer sent it.
    pub mine: bool,
    /// When this computer sent or received it: seconds since 1970.
    pub at: i64,
    pub body: Body,
    #[serde(default)]
    pub delivery: Delivery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Body {
    Text {
        text: String,
    },
    Secret {
        label: String,
        /// `None` once it is gone.
        value: Option<SecretText>,
        /// When it goes: seconds since 1970.
        expires: i64,
        #[serde(default)]
        gone: Option<Gone>,
    },
    Variables {
        label: String,
        variables: Vec<Var>,
        expires: i64,
        #[serde(default)]
        gone: Option<Gone>,
    },
    /// An item offered, by its summary: the item itself is never kept.
    Card {
        item: ItemSummary,
        outcome: Outcome,
        /// What it was saved as on the receiving side.
        #[serde(default)]
        name: Option<String>,
        /// A host came with server keys other than this computer's.
        #[serde(default)]
        keys_differ: bool,
        /// A hosts file group waits on the Hosts file page under this id.
        #[serde(default)]
        group: Option<u32>,
    },
    Line {
        line: Line,
    },
}

/// One variable of [`Body::Variables`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Var {
    pub name: String,
    /// `None` once it is gone.
    pub value: Option<SecretText>,
    pub secret: bool,
    #[serde(default)]
    pub note: String,
}

/// Why a secret's value is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum Gone {
    /// Its term ended.
    Expired,
    /// This user wiped it.
    Wiped,
    /// The other user wiped it.
    WipedByPeer,
}

/// Where a message of this computer's is; a received one is `Received`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum Delivery {
    #[default]
    Received,
    Sending,
    Delivered,
    /// No receipt came before the session ended.
    NotDelivered,
    /// The other side didn't take it.
    Refused {
        reason: Refusal,
    },
}

/// Where an offered item is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum Outcome {
    /// The receiving user hasn't answered.
    Waiting,
    /// The receiving user accepted; the item is on its way.
    Accepted,
    Saved,
    NotSaved,
    Declined,
    /// The receiving app can't take an item of this kind.
    Unsupported,
    /// The session ended, or the offer's time ran out, before an answer.
    Ended,
    /// The item went, and the session ended before the receiver said
    /// whether it saved it.
    NotConfirmed,
}

/// Something that happened in a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum Line {
    /// The other device sent too much at once; it was cut off for a while.
    Paused,
}

impl Body {
    /// When the value goes, if it is a secret or variables that still have it.
    pub fn expires(&self) -> Option<i64> {
        match self {
            Self::Secret {
                expires,
                gone: None,
                ..
            }
            | Self::Variables {
                expires,
                gone: None,
                ..
            } => Some(*expires),
            _ => None,
        }
    }

    /// Wipes the value of a secret or variables; `false` if there was none.
    fn wipe(&mut self, why: Gone) -> bool {
        match self {
            Self::Secret { value, gone, .. } if gone.is_none() => {
                *value = None;
                *gone = Some(why);
                true
            }
            Self::Variables {
                variables, gone, ..
            } if gone.is_none() => {
                for var in variables {
                    var.value = None;
                }
                *gone = Some(why);
                true
            }
            _ => false,
        }
    }
}

impl Conversation {
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn get(&self, id: &str) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.id == id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|entry| entry.id == id)
    }

    /// Adds an entry of this computer's (or a line).
    pub fn push(&mut self, entry: Entry) {
        self.entries.push(entry);
        self.trim(MAX_ENTRIES);
    }

    /// Whether a message with this id was received already.
    pub fn seen(&self, id: &str) -> bool {
        self.seen.iter().any(|seen| seen == id)
    }

    /// Adds a received entry, unless its id was received before; returns
    /// whether it is new.
    pub fn receive(&mut self, entry: Entry) -> bool {
        if self.seen(&entry.id) || self.get(&entry.id).is_some() {
            return false;
        }
        self.seen.push_back(entry.id.clone());
        while self.seen.len() > MAX_SEEN {
            self.seen.pop_front();
        }
        self.push(entry);
        true
    }

    /// Marks these messages of this computer's delivered; returns whether
    /// any changed.
    pub fn delivered(&mut self, ids: &[String]) -> bool {
        let mut changed = false;
        for entry in &mut self.entries {
            if entry.mine
                && matches!(entry.delivery, Delivery::Sending | Delivery::NotDelivered)
                && ids.contains(&entry.id)
            {
                entry.delivery = Delivery::Delivered;
                changed = true;
            }
        }
        changed
    }

    /// Marks a message of this computer's refused.
    pub fn refused(&mut self, id: &str, reason: Refusal) -> bool {
        match self.get_mut(id) {
            Some(entry) if entry.mine && entry.delivery != Delivery::Delivered => {
                entry.delivery = Delivery::Refused { reason };
                true
            }
            _ => false,
        }
    }

    /// The ids of this computer's messages that wait for a receipt.
    pub fn sending(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|entry| entry.mine && entry.delivery == Delivery::Sending)
            .map(|entry| entry.id.clone())
            .collect()
    }

    /// The session ended: messages without a receipt are not delivered,
    /// and offers without an answer end. Returns whether any changed.
    pub fn disconnected(&mut self) -> bool {
        let mut changed = false;
        for entry in &mut self.entries {
            if entry.mine && entry.delivery == Delivery::Sending {
                entry.delivery = Delivery::NotDelivered;
                changed = true;
            }
            if let Body::Card { outcome, .. } = &mut entry.body {
                let next = match (*outcome, entry.mine) {
                    (Outcome::Accepted, true) => Outcome::NotConfirmed,
                    (Outcome::Waiting | Outcome::Accepted, _) => Outcome::Ended,
                    (other, _) => other,
                };
                if next != *outcome {
                    *outcome = next;
                    changed = true;
                }
            }
        }
        changed
    }

    /// Wipes the values whose term ended by `now` (seconds since 1970);
    /// returns whether any did.
    pub fn wipe_expired(&mut self, now: i64) -> bool {
        let mut changed = false;
        for entry in &mut self.entries {
            if entry.body.expires().is_some_and(|expires| expires <= now) {
                changed |= entry.body.wipe(Gone::Expired);
            }
        }
        changed
    }

    /// Wipes secret or variables `id` before its term: this user's own
    /// (`by_peer` false) or, when the other user wipes it, theirs. Returns
    /// whether it did.
    pub fn wipe(&mut self, id: &str, by_peer: bool) -> bool {
        match self.get_mut(id) {
            Some(entry) if entry.mine != by_peer => entry.body.wipe(if by_peer {
                Gone::WipedByPeer
            } else {
                Gone::Wiped
            }),
            _ => false,
        }
    }

    /// When the next value goes, if any is left.
    pub fn next_expiry(&self) -> Option<i64> {
        self.entries
            .iter()
            .filter_map(|entry| entry.body.expires())
            .min()
    }

    /// How many received entries the user hasn't seen.
    pub fn unread(&self) -> usize {
        self.entries
            .iter()
            .skip(self.read)
            .filter(|entry| !entry.mine && !matches!(entry.body, Body::Line { .. }))
            .count()
    }

    /// The user has seen everything; returns whether that changed anything.
    pub fn mark_read(&mut self) -> bool {
        let changed = self.read != self.entries.len();
        self.read = self.entries.len();
        changed
    }

    /// The conversation as the JSON its file holds, the oldest entries left
    /// out until it fits in [`MAX_BYTES`].
    pub fn to_json(&mut self) -> crate::Result<zeroize::Zeroizing<Vec<u8>>> {
        loop {
            let json = zeroize::Zeroizing::new(
                serde_json::to_vec(self).map_err(|e| crate::Error::Parse(format!("chat: {e}")))?,
            );
            if json.len() <= MAX_BYTES || self.entries.len() <= 1 {
                return Ok(json);
            }
            let keep = self.entries.len() - self.entries.len().div_ceil(10);
            self.trim(keep);
        }
    }

    /// Keeps at most `max` entries, the newest.
    fn trim(&mut self, max: usize) {
        if self.entries.len() > max {
            let drop = self.entries.len() - max;
            self.entries.drain(..drop);
            self.read = self.read.saturating_sub(drop);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::chat::new_id;

    fn text(mine: bool, text: &str) -> Entry {
        Entry {
            id: new_id(),
            mine,
            at: 1_000,
            body: Body::Text { text: text.into() },
            delivery: if mine {
                Delivery::Sending
            } else {
                Delivery::Received
            },
        }
    }

    fn secret(mine: bool, expires: i64) -> Entry {
        Entry {
            id: new_id(),
            mine,
            at: 1_000,
            body: Body::Secret {
                label: "db".into(),
                value: Some(SecretText::new("s3cret")),
                expires,
                gone: None,
            },
            delivery: Delivery::Received,
        }
    }

    #[test]
    fn a_message_received_twice_is_stored_once() {
        let mut chat = Conversation::default();
        let message = text(false, "hi");
        assert!(chat.receive(message.clone()));
        assert!(!chat.receive(message.clone()));
        assert_eq!(chat.entries().len(), 1);
        assert!(chat.seen(&message.id));
        assert_eq!(chat.unread(), 1);
        assert!(chat.mark_read());
        assert_eq!(chat.unread(), 0);
        assert!(!chat.mark_read());
    }

    #[test]
    fn receipts_and_a_cut_change_only_this_computers_messages() {
        let mut chat = Conversation::default();
        let (mine, other, theirs) = (text(true, "a"), text(true, "b"), text(false, "c"));
        chat.push(mine.clone());
        chat.push(other.clone());
        chat.receive(theirs.clone());
        assert_eq!(chat.sending(), [mine.id.clone(), other.id.clone()]);
        assert!(chat.delivered(&[mine.id.clone(), theirs.id.clone()]));
        assert_eq!(chat.get(&mine.id).unwrap().delivery, Delivery::Delivered);
        assert_eq!(chat.get(&theirs.id).unwrap().delivery, Delivery::Received);
        assert!(chat.disconnected());
        assert_eq!(
            chat.get(&other.id).unwrap().delivery,
            Delivery::NotDelivered
        );
        // A receipt that comes after all, for a message sent again.
        assert!(chat.delivered(std::slice::from_ref(&other.id)));
        assert!(!chat.refused(&text(true, "x").id, Refusal::Invalid));
    }

    #[test]
    fn values_go_when_their_term_ends_and_a_line_stays() {
        let mut chat = Conversation::default();
        let (soon, later) = (secret(false, 2_000), secret(true, 9_000));
        chat.receive(soon.clone());
        chat.push(later.clone());
        assert_eq!(chat.next_expiry(), Some(2_000));
        assert!(!chat.wipe_expired(1_999));
        assert!(chat.wipe_expired(2_000));
        let Body::Secret { value, gone, .. } = &chat.get(&soon.id).unwrap().body else {
            unreachable!()
        };
        assert_eq!((value, gone), (&None, &Some(Gone::Expired)));
        assert_eq!(chat.next_expiry(), Some(9_000));
        // Once gone, it stays gone, and the JSON has no trace of the value.
        assert!(!chat.wipe_expired(2_000));
        let json = String::from_utf8(chat.clone().to_json().unwrap().to_vec()).unwrap();
        assert_eq!(json.matches("s3cret").count(), 1, "only the later one");
    }

    #[test]
    fn only_the_sender_or_the_other_side_wipes_as_they_may() {
        let mut chat = Conversation::default();
        let (mine, theirs) = (secret(true, 9_000), secret(false, 9_000));
        chat.push(mine.clone());
        chat.receive(theirs.clone());
        // The other side can't wipe a value this computer sent, nor this
        // user one it received, as if the other had.
        assert!(!chat.wipe(&mine.id, true));
        assert!(!chat.wipe(&theirs.id, false));
        assert!(chat.wipe(&theirs.id, true));
        assert!(chat.wipe(&mine.id, false));
        assert!(!chat.wipe(&mine.id, false));
        assert_eq!(chat.next_expiry(), None);
    }

    #[test]
    fn offers_end_with_the_session() {
        let mut chat = Conversation::default();
        let card = |mine: bool, outcome: Outcome| Entry {
            id: new_id(),
            mine,
            at: 1,
            body: Body::Card {
                item: ItemSummary::Unknown,
                outcome,
                name: None,
                keys_differ: false,
                group: None,
            },
            delivery: Delivery::Received,
        };
        let entries = [
            card(true, Outcome::Waiting),
            card(true, Outcome::Accepted),
            card(false, Outcome::Accepted),
            card(true, Outcome::Saved),
        ];
        for entry in &entries {
            chat.push(entry.clone());
        }
        assert!(chat.disconnected());
        let outcome = |entry: &Entry| match chat.get(&entry.id).unwrap().body {
            Body::Card { outcome, .. } => outcome,
            _ => unreachable!(),
        };
        assert_eq!(outcome(&entries[0]), Outcome::Ended);
        assert_eq!(outcome(&entries[1]), Outcome::NotConfirmed);
        assert_eq!(outcome(&entries[2]), Outcome::Ended);
        assert_eq!(outcome(&entries[3]), Outcome::Saved);
    }

    #[test]
    fn a_conversation_keeps_its_newest_entries() {
        let mut chat = Conversation::default();
        for i in 0..MAX_ENTRIES + 10 {
            chat.receive(text(false, &format!("{i}")));
        }
        assert_eq!(chat.entries().len(), MAX_ENTRIES);
        assert_eq!(chat.entries()[0].body, Body::Text { text: "10".into() });
        chat.mark_read();
        let big = "x".repeat(MAX_TEXT_FOR_TEST);
        let mut chat = Conversation::default();
        for _ in 0..200 {
            chat.receive(text(false, &big));
        }
        chat.mark_read();
        let json = chat.to_json().unwrap();
        assert!(json.len() <= MAX_BYTES);
        assert!(chat.entries().len() < 200);
        assert_eq!(chat.unread(), 0);
    }

    const MAX_TEXT_FOR_TEST: usize = 16 * 1024;
}
