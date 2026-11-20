//! One conversation between two devices, from the open session to how it
//! ended. The desktop app and the phone run the same one.
//!
//! Both sides run [`conversation`] over a [`Session`] on any
//! [`Connection`], each with a [`Side`]: what only the device it runs on can
//! do or knows (see [`side`]). Finding the other device and opening the
//! connection come before it and are the app's business, so the tests hold
//! whole conversations over in-memory pipes. Each sends `Hello`, saying
//! what the side that connected came for:
//!
//! - **To pair or to send** (no intent). If both already know each other
//!   there is nothing to agree on. Otherwise they agree on the pairing code,
//!   each user says whether their screen shows the same one, and each side
//!   tells the other. Only when both said yes does each save the other as a
//!   contact. A "no" from either side, a cancel or a hang-up ends it. After
//!   that the side that connected may send one item (see [`transfer`]).
//! - **To add one of the user's devices.** The code is compared always, and
//!   nothing is saved as a contact; the rest is in [`own`].
//! - **To sync** with one of the user's devices: each checks that the other
//!   has the same vault and is one of the user's devices, then [`sync`].
//!
//! Each side shows a device it knows by the name it keeps for it, whatever
//! name the device gives in its `Hello`; only a device it doesn't know yet
//! is shown by its own.

pub mod own;
#[cfg(test)]
mod script;
pub mod side;
pub mod sync;
pub mod transfer;

use std::io::ErrorKind;
use std::time::{Duration, Instant};

use serde::Serialize;

pub use self::side::{Device, Side, Stored, SyncStore, User, VaultItems};
pub use self::sync::{
    MASS_DELETE, Review, RiskyChange, RiskyVariables, SyncDecisions, SyncLocal, SyncState,
    SyncSummary, SyncWrite, VaultOff, VaultReview,
};
use super::connection::Connection;
use super::protocol::{
    EntrySync, Intent, Item, ItemSummary, Own, VERSION, VaultState, clean_name, features,
};
use super::{Message, PeerKey, Session};

/// How long the users have to compare the codes.
pub const ANSWER_TIMEOUT: Duration = Duration::from_secs(180);
/// How often the wait for an answer looks at the connection.
const POLL: Duration = Duration::from_millis(200);
/// How long a read or write waits, but where a step says otherwise. The
/// app's handshake leaves the connection with this too.
pub const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Where a conversation is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum PairingPhase {
    /// Connecting and agreeing on a code.
    Connecting,
    /// Both users compare `code`; this one hasn't answered yet.
    Compare {
        code: String,
    },
    /// This user said the codes match; the other hasn't answered yet.
    Waiting {
        code: String,
    },
    /// Both said the codes match: each is the other's contact now.
    Paired,
    /// Both were each other's contacts already.
    Known,
    /// The device the user picked to send to, under the name `announced`,
    /// is a contact (or one of the user's devices) this vault knows by
    /// another name, the conversation's `peer`: this user says whether to
    /// send it the item all the same. Nothing has gone to it yet, not even
    /// the offer.
    NameMismatch {
        announced: String,
    },
    /// This side offered `item`; the other user hasn't answered yet.
    Offering {
        item: ItemSummary,
    },
    /// The other side offers `item`; this user hasn't answered yet.
    Offered {
        item: ItemSummary,
    },
    /// The other side saved the item this side sent.
    Sent {
        item: ItemSummary,
    },
    /// This side saved the item it got, as `name`: the entry's title, the
    /// host's alias (with a number if it is taken) or the key's file name. A
    /// hosts file group named `name` waits for the user to save it on the
    /// Hosts file page (the app keeps it until then).
    #[serde(rename_all = "camelCase")]
    Received {
        item: ItemSummary,
        name: String,
        /// A host came with server keys other than the ones this computer
        /// has for it; this computer's are kept.
        keys_differ: bool,
        /// An environment's variables left out, as they make programs run
        /// code; the user adds them by hand if they trust them.
        left_out: Vec<String>,
    },
    /// The other computer becomes one of the user's devices once this user
    /// confirms, with Touch ID or the master password. With `vault`, it
    /// gets this computer's vault.
    Authorize {
        vault: bool,
    },
    /// The other computer's user is confirming.
    Approving,
    /// The vault goes over: bytes so far, and in all.
    Transfer {
        #[cfg_attr(feature = "ts", ts(type = "number"))]
        done: u64,
        #[cfg_attr(feature = "ts", ts(type = "number"))]
        total: u64,
    },
    /// The vault came: this user sets a master password for this computer.
    SetMaster,
    /// The two are each other's devices now; with `vault`, this side gave
    /// the other its vault.
    Added {
        vault: bool,
    },
    /// The vault that came is this computer's now, unlocked.
    Joined,
    Syncing,
    /// What this user decides before the sync goes on.
    Decide {
        review: Review,
    },
    Synced {
        summary: SyncSummary,
    },
    Failed {
        reason: PairingFailure,
    },
}

impl PairingPhase {
    /// Whether the conversation is over: nothing more happens but the
    /// user closing it.
    pub fn is_over(&self) -> bool {
        matches!(
            self,
            Self::Paired
                | Self::Known
                | Self::Sent { .. }
                | Self::Received { .. }
                | Self::Added { .. }
                | Self::Joined
                | Self::Synced { .. }
                | Self::Failed { .. }
        )
    }

    /// Whether the conversation waits for this user's answer.
    pub fn asks_user(&self) -> bool {
        matches!(
            self,
            Self::Compare { .. }
                | Self::NameMismatch { .. }
                | Self::Offered { .. }
                | Self::Authorize { .. }
                | Self::SetMaster
                | Self::Decide { .. }
        )
    }
}

/// Why a conversation ended without what it was for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum PairingFailure {
    /// No connection to the device.
    Unreachable,
    /// This user said the codes differ.
    Declined,
    /// The other user said the codes differ, or turned the pairing down.
    PeerDeclined,
    /// This user cancelled.
    Cancelled,
    /// The other device hung up, e.g. because it is pairing with someone else.
    PeerLeft,
    /// Nobody answered in time.
    TimedOut,
    /// The vault, where contacts are kept, is locked or missing.
    VaultLocked,
    /// The other device runs a version of the app that pairs differently.
    Version,
    /// The other device sent something this version doesn't know: this app
    /// needs the new version.
    Unsupported,
    /// The other device can't take what this side sends: its app needs the
    /// new version.
    PeerUnsupported,
    /// The connection broke or the other side broke the protocol.
    Broken,
    /// The other user turned down the item this side offered.
    Refused,
    /// This user turned down the item offered.
    Turned,
    /// The item could not be saved where it goes.
    NotSaved,
    /// The other computer has another vault: two vaults are never merged.
    OtherVault,
    /// The other computer is not one of the user's devices (any more), or
    /// doesn't have this vault.
    NotOwn,
}

/// What the side that connected came for.
#[derive(Debug, Clone, Copy)]
pub enum Purpose<'a> {
    /// To pair only.
    Pair,
    /// To pair if need be, then send `item`; `to` is the name the device
    /// was picked under, when the user picked it from the devices found.
    Send { item: &'a Item, to: Option<&'a str> },
    /// To make the other computer one of the user's devices.
    AddDevice,
    /// To sync with one of the user's devices.
    Sync,
}

/// The whole conversation on one side: `purpose` on the side that
/// connected, `None` on the other. Returns how it ended.
pub fn conversation(
    session: &mut Session<impl Connection>,
    side: &impl Side,
    purpose: Option<Purpose<'_>>,
) -> PairingPhase {
    conversation_after(session, side, purpose, None)
}

/// [`conversation`], the other side's `Hello` read already (`hello`), on
/// the side that was connected to: it reads that before the conversation
/// takes its place, under the deadline of the handshake.
pub fn conversation_after(
    session: &mut Session<impl Connection>,
    side: &impl Side,
    purpose: Option<Purpose<'_>>,
    hello: Option<Message>,
) -> PairingPhase {
    let intent = match purpose {
        Some(Purpose::AddDevice) => Some(Intent::AddDevice),
        Some(Purpose::Sync) => Some(Intent::Sync),
        _ => None,
    };
    let met = match meet(session, side, intent, hello) {
        Ok(met) => met,
        Err(reason) => return PairingPhase::Failed { reason },
    };
    match (met, purpose) {
        (Met::Contacts(_, known, features), Some(Purpose::Send { item, to })) => {
            transfer::send(session, side, item, known.as_deref(), to, &features)
        }
        (Met::Contacts(end, ..), Some(_)) => *end,
        (Met::Contacts(end, ..), None) => transfer::receive(session, side).unwrap_or(*end),
        (Met::AddDevice { peer, name, joins }, _) => own::add(session, side, peer, &name, joins),
        (Met::Sync { peer, entries }, _) => sync::run(session, side, peer, entries),
    }
}

/// How two sides met.
enum Met {
    /// As contacts: `Paired` or `Known`, with the name this side kept for
    /// the other before, if it knew it, and what the other can do.
    Contacts(Box<PairingPhase>, Option<String>, Vec<String>),
    /// To make one the other's device; with `joins`, the side that
    /// answered gets the vault.
    AddDevice {
        peer: PeerKey,
        name: String,
        joins: bool,
    },
    /// To sync, each one of the other's devices; what each said about
    /// syncing the vault's entries.
    Sync { peer: PeerKey, entries: Entries },
}

impl Met {
    fn contacts(end: PairingPhase, known: Option<String>, features: Vec<String>) -> Self {
        Self::Contacts(Box::new(end), known, features)
    }
}

fn meet(
    session: &mut Session<impl Connection>,
    side: &impl Side,
    intent: Option<Intent>,
    hello: Option<Message>,
) -> Result<Met, PairingFailure> {
    let peer_key = session.remote();
    let initiator = session.is_initiator();
    let hash = session.handshake_hash().to_vec();
    let known = side.knows(peer_key)?;
    let mine = hello_own(side, &hash, initiator, intent);
    session
        .send(&Message::Hello {
            version: VERSION,
            name: side.name(),
            known: known.is_some(),
            own: mine.clone(),
            features: features(),
        })
        .map_err(|_| PairingFailure::Broken)?;
    let Hello {
        name,
        known: they_know,
        own: theirs,
        features: their_features,
    } = match hello {
        Some(message) => hello_of(message)?,
        None => hello_of(session.recv().map_err(broken)?)?,
    };
    let announced = Some(clean_name(&name)).filter(|name| !name.is_empty());
    let peer_name = announced.clone().unwrap_or_else(|| "?".to_owned());
    // A device this side knows goes by the name it keeps for it, since any
    // device may give any name; only one it doesn't know yet by its own.
    let peer = known.clone().or(announced);
    side.show(peer.as_deref(), &PairingPhase::Connecting);
    let intent = if initiator {
        intent
    } else {
        theirs.as_ref().and_then(|own| own.intent)
    };
    side.takes(intent)?;

    let Some(intent) = intent else {
        if known.is_some() && they_know {
            return Ok(Met::contacts(PairingPhase::Known, known, their_features));
        }
        compare_codes(session, side, peer.as_deref())?;
        // A device known here already stays as it is, name and all.
        if known.is_none() {
            side.save(peer_key, &peer_name)?;
        }
        return Ok(Met::contacts(PairingPhase::Paired, known, their_features));
    };
    let (Some(mine), Some(theirs)) = (mine, theirs) else {
        return Err(PairingFailure::Version);
    };
    let same = match &theirs.vault {
        VaultState::Open { proof } => side.same_vault(&hash, !initiator, proof),
        _ => false,
    };
    match intent {
        Intent::AddDevice => {
            let joins = match (&mine.vault, &theirs.vault) {
                _ if same => false,
                (VaultState::Open { .. }, VaultState::Missing) if initiator => true,
                (VaultState::Missing, VaultState::Open { .. }) if !initiator => true,
                (VaultState::Locked, _) | (_, VaultState::Locked) => {
                    return Err(PairingFailure::VaultLocked);
                }
                (VaultState::Open { .. }, VaultState::Open { .. }) => {
                    return Err(PairingFailure::OtherVault);
                }
                _ => return Err(PairingFailure::Broken),
            };
            compare_codes(session, side, peer.as_deref())?;
            Ok(Met::AddDevice {
                peer: peer_key,
                name: peer_name,
                joins,
            })
        }
        Intent::Sync => {
            confirm_own(session, same && side.is_own(peer_key))?;
            Ok(Met::Sync {
                peer: peer_key,
                entries: Entries {
                    mine: mine.entries,
                    theirs: theirs.entries,
                },
            })
        }
        Intent::Other => Err(PairingFailure::Version),
    }
}

/// What this side's `Hello` says about the user's own devices.
fn hello_own(
    side: &impl Side,
    hash: &[u8],
    initiator: bool,
    intent: Option<Intent>,
) -> Option<Own> {
    side.vault(hash, initiator).map(|vault| Own {
        intent,
        vault,
        entries: side.entry_sync(),
    })
}

/// Before a sync, each side says whether the other is one of the user's
/// devices (`ok`): the side that answers first, so the side that
/// connected never starts with a device that turned it away.
fn confirm_own(session: &mut Session<impl Connection>, ok: bool) -> Result<(), PairingFailure> {
    if session.is_initiator() {
        if !ok {
            return Err(PairingFailure::NotOwn);
        }
        return match session.recv().map_err(broken)? {
            Message::Confirm { matched: true } => Ok(()),
            Message::Confirm { matched: false } => Err(PairingFailure::NotOwn),
            _ => Err(PairingFailure::Broken),
        };
    }
    session
        .send(&Message::Confirm { matched: ok })
        .map_err(|_| PairingFailure::Broken)?;
    if ok {
        Ok(())
    } else {
        Err(PairingFailure::NotOwn)
    }
}

/// What both sides said about syncing the vault's entries.
#[derive(Debug, Clone, Copy, Default)]
pub struct Entries {
    pub mine: Option<EntrySync>,
    pub theirs: Option<EntrySync>,
}

/// The other side's `Hello`.
struct Hello {
    name: String,
    known: bool,
    own: Option<Own>,
    features: Vec<String>,
}

/// The other side's `Hello`, of this version, from its first message.
fn hello_of(message: Message) -> Result<Hello, PairingFailure> {
    match message {
        Message::Hello {
            version,
            name,
            known,
            own,
            features,
        } if version == VERSION => Ok(Hello {
            name,
            known,
            own,
            features,
        }),
        Message::Hello { .. } => Err(PairingFailure::Version),
        Message::Unknown => Err(PairingFailure::Unsupported),
        _ => Err(PairingFailure::Broken),
    }
}

/// Agrees on the pairing code and has both users compare it; `Ok` only when
/// both said the codes match.
fn compare_codes(
    session: &mut Session<impl Connection>,
    side: &impl Side,
    peer: Option<&str>,
) -> Result<(), PairingFailure> {
    let code = session.pairing_code().map_err(|error| {
        if session.gave_nonce() {
            side.broke_off();
        }
        broken(error)
    })?;
    side.show(peer, &PairingPhase::Compare { code: code.clone() });
    let (matched, mut theirs) = wait_for_answer(session, side)?;
    if !matched {
        let _ = session.send(&Message::Confirm { matched: false });
        return Err(PairingFailure::Declined);
    }
    session
        .send(&Message::Confirm { matched: true })
        .map_err(|_| PairingFailure::Broken)?;
    if theirs.is_none() {
        side.show(peer, &PairingPhase::Waiting { code });
        let _ = session.stream().set_read_timeout(Some(ANSWER_TIMEOUT));
        theirs = match session.recv().map_err(broken)? {
            Message::Confirm { matched } => Some(matched),
            _ => return Err(PairingFailure::Broken),
        };
    }
    if theirs == Some(true) {
        Ok(())
    } else {
        Err(PairingFailure::PeerDeclined)
    }
}

/// Waits for this user's answer while watching the connection, so a "no" or
/// a hang-up from the other side ends the wait. Returns this user's answer
/// and the other's, if it came first.
fn wait_for_answer(
    session: &mut Session<impl Connection>,
    side: &impl Side,
) -> Result<(bool, Option<bool>), PairingFailure> {
    let started = Instant::now();
    let mut theirs = None;
    loop {
        if let Some(matched) = side.answer(POLL)? {
            return Ok((matched, theirs));
        }
        if theirs.is_none()
            && session
                .stream()
                .waiting()
                .map_err(|_| PairingFailure::Broken)?
        {
            match session.recv().map_err(broken)? {
                Message::Confirm { matched: true } => theirs = Some(true),
                Message::Confirm { matched: false } => return Err(PairingFailure::PeerDeclined),
                _ => return Err(PairingFailure::Broken),
            }
        }
        if started.elapsed() > ANSWER_TIMEOUT {
            return Err(PairingFailure::TimedOut);
        }
    }
}

/// A failed read: the peer hung up, took too long, or sent garbage.
pub fn broken(error: crate::Error) -> PairingFailure {
    match error {
        crate::Error::Io { source, .. } => match source.kind() {
            ErrorKind::UnexpectedEof
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted => PairingFailure::PeerLeft,
            ErrorKind::WouldBlock | ErrorKind::TimedOut => PairingFailure::TimedOut,
            _ => PairingFailure::Broken,
        },
        _ => PairingFailure::Broken,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::p2p::Identity;

    use super::script::{Script, codes, pair, peers, talk_as};
    use super::*;

    #[test]
    fn both_yes_saves_each_other() {
        let mut right = Script::new("bob-pc", Some(true));
        right.delay = Duration::from_millis(500);
        let ((left_end, left), (right_end, right)) =
            pair(Script::new("MacBook\nof Alice", Some(true)), right);
        assert_eq!(left_end, PairingPhase::Paired);
        assert_eq!(right_end, PairingPhase::Paired);
        assert_eq!(*left.saved.lock().unwrap(), ["bob-pc"]);
        assert_eq!(*right.saved.lock().unwrap(), ["MacBook of Alice"]);
        assert_eq!(codes(&left), codes(&right));
        // Alice answered first, so she waited for Bob.
        assert!(
            left.shown
                .lock()
                .unwrap()
                .iter()
                .any(|(peer, phase)| peer.as_deref() == Some("bob-pc")
                    && matches!(phase, PairingPhase::Waiting { .. }))
        );
    }

    #[test]
    fn a_no_on_either_side_saves_nothing() {
        let mut right = Script::new("bob-pc", Some(true));
        right.delay = Duration::from_millis(500);
        let ((left_end, left), (right_end, right)) = pair(Script::new("alice", Some(false)), right);
        assert_eq!(
            left_end,
            PairingPhase::Failed {
                reason: PairingFailure::Declined
            }
        );
        // Bob hears the "no" before he answers.
        assert_eq!(
            right_end,
            PairingPhase::Failed {
                reason: PairingFailure::PeerDeclined
            }
        );
        assert!(left.saved.lock().unwrap().is_empty() && right.saved.lock().unwrap().is_empty());
    }

    #[test]
    fn a_cancel_reaches_the_other_side() {
        let mut right = Script::new("bob-pc", Some(true));
        right.delay = Duration::from_millis(500);
        let ((left_end, _), (right_end, right)) = pair(Script::new("alice", None), right);
        assert_eq!(
            left_end,
            PairingPhase::Failed {
                reason: PairingFailure::Cancelled
            }
        );
        assert!(matches!(right_end, PairingPhase::Failed { .. }));
        assert!(right.saved.lock().unwrap().is_empty());
    }

    /// A side that connects, says hello, and hangs up once it got the other
    /// side's nonce, as one would that didn't like the code; or, without
    /// `commits`, right after the hello.
    fn hang_up_after_the_nonce(commits: bool) -> Script {
        use std::thread;

        use crate::p2p::connection::pipe;
        use crate::p2p::{accept, connect};

        let (stream, theirs) = pipe();
        let other = thread::spawn(move || {
            let stream = theirs;
            let mut session = accept(stream, &Identity::generate().unwrap()).unwrap();
            let side = Script::new("bob", Some(true));
            (conversation(&mut session, &side, None), side)
        });
        let mut session = connect(stream, &Identity::generate().unwrap()).unwrap();
        session
            .send(&Message::Hello {
                version: VERSION,
                name: "mallory".into(),
                known: false,
                own: None,
                features: Vec::new(),
            })
            .unwrap();
        assert!(matches!(session.recv().unwrap(), Message::Hello { .. }));
        if commits {
            // What it commits to is only checked when it reveals it.
            session
                .send(&Message::Commit {
                    hash: "a commitment".into(),
                })
                .unwrap();
            assert!(matches!(session.recv().unwrap(), Message::Nonce { .. }));
        }
        drop(session);
        let (end, side) = other.join().unwrap();
        assert!(matches!(end, PairingPhase::Failed { .. }));
        assert_eq!(codes(&side), Vec::<String>::new());
        side
    }

    #[test]
    fn a_side_hears_of_a_hang_up_after_its_nonce() {
        assert_eq!(*hang_up_after_the_nonce(true).broken_off.lock().unwrap(), 1);
        assert_eq!(
            *hang_up_after_the_nonce(false).broken_off.lock().unwrap(),
            0
        );
        // A pairing that went through is no such thing.
        let ((_, left), (_, right)) = pair(
            Script::new("alice", Some(true)),
            Script::new("bob", Some(true)),
        );
        assert_eq!(*left.broken_off.lock().unwrap(), 0);
        assert_eq!(*right.broken_off.lock().unwrap(), 0);
    }

    #[test]
    fn contacts_on_both_sides_skip_the_code() {
        let mut left = Script::new("alice", Some(true));
        left.knows = true;
        let mut right = Script::new("bob", Some(true));
        right.knows = true;
        let ((left_end, left), (right_end, _)) = pair(left, right);
        assert_eq!(
            (left_end, right_end),
            (PairingPhase::Known, PairingPhase::Known)
        );
        assert_eq!(codes(&left), Vec::<String>::new());

        // Known on one side only: they pair again.
        let mut left = Script::new("alice", Some(true));
        left.knows = true;
        let ((left_end, _), (right_end, _)) = pair(left, Script::new("bob", Some(true)));
        assert_eq!(
            (left_end, right_end),
            (PairingPhase::Paired, PairingPhase::Paired)
        );
    }

    #[test]
    fn a_contact_goes_by_the_name_kept_here_not_the_one_it_gives() {
        // Alice has Bob and Carol as contacts; Carol calls herself Bob.
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let carol = Identity::generate().unwrap();
        let mut left = Script::new("Alice", Some(true));
        left.contacts = vec![(bob.public(), "Bob's MacBook"), (carol.public(), "Carol")];
        let mut right = Script::new("Bob's MacBook", Some(true));
        right.contacts = vec![(alice.public(), "Alice")];
        let ((left_end, left), (right_end, right)) =
            talk_as((left, alice), (right, carol), Purpose::Pair);
        assert_eq!(
            (left_end, right_end),
            (PairingPhase::Known, PairingPhase::Known)
        );
        assert_eq!(peers(&left), ["Carol"]);
        assert_eq!(peers(&right), ["Alice"]);

        // Carol, who says she doesn't know Alice, is still Carol there
        // while the two compare the code, and stays Carol after.
        let mut left = Script::new("Alice", Some(true));
        left.knows = true;
        left.known_as = "Carol";
        let ((left_end, left), (right_end, right)) =
            pair(left, Script::new("Bob's MacBook", Some(true)));
        assert_eq!(
            (left_end, right_end),
            (PairingPhase::Paired, PairingPhase::Paired)
        );
        assert_eq!(codes(&left).len(), 1);
        assert_eq!(peers(&left), ["Carol"]);
        assert!(left.saved.lock().unwrap().is_empty());
        assert_eq!(*right.saved.lock().unwrap(), ["Alice"]);
    }
}
