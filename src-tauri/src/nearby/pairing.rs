//! One conversation, from the open session to how it ended.
//!
//! Both sides run [`conversation`] with a [`Side`]: the app's own state in
//! the app, a script in the tests. Each sends `Hello`, saying what the side
//! that connected came for:
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
//! [`transfer`]: super::transfer
//! [`own`]: super::own
//! [`sync`]: super::sync

use std::io::{self, ErrorKind};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use serde::Serialize;
use sshkm_core::p2p::protocol::{
    Intent, Item, ItemSummary, Own, SecretText, VERSION, VaultState, clean_name,
};
use sshkm_core::p2p::{Message, PeerKey, Session};
use zeroize::Zeroizing;

use super::sync::{Review, SyncDecisions, SyncLocal, SyncState, SyncSummary, SyncWrite};
use super::{own, sync, transfer};

/// How long the users have to compare the codes.
pub const ANSWER_TIMEOUT: Duration = Duration::from_secs(180);
/// How often the wait for an answer looks at the connection.
pub(super) const POLL: Duration = Duration::from_millis(200);

/// Where a conversation is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
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
    /// This side saved the item it got, as `name` (the entry's title or the
    /// host's alias, which gets a number if the alias is taken).
    #[serde(rename_all = "camelCase")]
    Received {
        item: ItemSummary,
        name: String,
        /// A host came with server keys other than the ones this computer
        /// has for it; this computer's are kept.
        keys_differ: bool,
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
        #[cfg_attr(test, ts(type = "number"))]
        done: u64,
        #[cfg_attr(test, ts(type = "number"))]
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
                | Self::Added { .. }
                | Self::Joined
                | Self::Synced { .. }
                | Self::Failed { .. }
        )
    }
}

/// Why a conversation ended without what it was for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
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

/// What [`conversation`] needs from the side it runs on. The methods for
/// the user's own devices have defaults for a side that has none, such as
/// `examples/nearby_peer.rs` in its plain modes.
pub trait Side {
    /// This device's name, for the other user to read.
    fn name(&self) -> String;
    /// Whether `peer` is a contact, or one of the user's devices, already.
    fn knows(&self, peer: PeerKey) -> Result<bool, PairingFailure>;
    /// Saves `peer` as a contact named `name`.
    fn save(&self, peer: PeerKey, name: &str) -> Result<(), PairingFailure>;
    /// Shows the user where the conversation is; `peer` once the other
    /// device gave its name.
    fn show(&self, peer: Option<&str>, phase: &PairingPhase);
    /// The user's answer if one comes within `wait`; `Err(Cancelled)` once
    /// the user cancelled.
    fn answer(&self, wait: Duration) -> Result<Option<bool>, PairingFailure>;
    /// Saves an item the user accepted, checked against what was offered.
    /// Returns its name and whether a host's keys differ from the ones here.
    fn store(&self, item: &Item) -> Result<(String, bool), PairingFailure>;

    /// What this side's `Hello` says about its vault in the session with
    /// handshake `hash`; `None` leaves own devices out of it.
    fn vault(&self, _hash: &[u8], _initiator: bool) -> Option<VaultState> {
        None
    }
    /// Whether `proof`, from the peer (the session's initiator or not),
    /// shows it has this side's vault.
    fn same_vault(&self, _hash: &[u8], _initiator: bool, _proof: &str) -> bool {
        false
    }
    /// Whether `peer` is one of the user's devices.
    fn is_own(&self, _peer: PeerKey) -> bool {
        false
    }
    /// Fails unless this side has a conversation for `intent`: one that
    /// waits for a vault is only added, and one announced to the user's
    /// devices only syncs.
    fn takes(&self, _intent: Option<Intent>) -> Result<(), PairingFailure> {
        Ok(())
    }
    /// Records this computer and `peer`, named `name`, as the user's devices.
    fn add_device(&self, _peer: PeerKey, _name: &str) -> Result<(), PairingFailure> {
        Err(PairingFailure::Broken)
    }
    /// The vault file and its secret, for a new device.
    fn share_vault(&self) -> Result<(Zeroizing<Vec<u8>>, SecretText), PairingFailure> {
        Err(PairingFailure::Broken)
    }
    /// Checks and keeps the vault another of the user's computers sent,
    /// until the user sets a master password for it.
    fn take_vault(
        &self,
        _file: Zeroizing<Vec<u8>>,
        _secret: SecretText,
    ) -> Result<(), PairingFailure> {
        Err(PairingFailure::NotSaved)
    }
    /// What a sync with `peer` starts from.
    fn sync_load(&self, _peer: PeerKey) -> Result<SyncLocal, PairingFailure> {
        Err(PairingFailure::NotOwn)
    }
    /// Writes the files a sync changed, unless they changed meanwhile.
    fn sync_write(&self, _peer: PeerKey, _write: &SyncWrite) -> Result<(), PairingFailure> {
        Err(PairingFailure::NotSaved)
    }
    /// Keeps what this side knows after a sync with `peer`.
    fn sync_keep(&self, _peer: PeerKey, _state: &SyncState) -> Result<(), PairingFailure> {
        Err(PairingFailure::NotSaved)
    }
    /// The user's decisions on a review, if they come within `wait`.
    fn decisions(&self, _wait: Duration) -> Result<Option<SyncDecisions>, PairingFailure> {
        Err(PairingFailure::Cancelled)
    }
}

/// What the side that connected came for.
#[derive(Debug, Clone, Copy)]
pub enum Purpose<'a> {
    /// To pair only.
    Pair,
    /// To pair if need be, then send the item.
    Send(&'a Item),
    /// To make the other computer one of the user's devices.
    AddDevice,
    /// To sync with one of the user's devices.
    Sync,
}

/// The whole conversation on one side: `purpose` on the side that
/// connected, `None` on the other. Returns how it ended.
pub fn conversation(
    session: &mut Session<TcpStream>,
    side: &impl Side,
    purpose: Option<Purpose<'_>>,
) -> PairingPhase {
    let intent = match purpose {
        Some(Purpose::AddDevice) => Some(Intent::AddDevice),
        Some(Purpose::Sync) => Some(Intent::Sync),
        _ => None,
    };
    let met = match meet(session, side, intent) {
        Ok(met) => met,
        Err(reason) => return PairingPhase::Failed { reason },
    };
    match (met, purpose) {
        (Met::Contacts(_), Some(Purpose::Send(item))) => transfer::send(session, side, item),
        (Met::Contacts(end), Some(_)) => end,
        (Met::Contacts(end), None) => transfer::receive(session, side).unwrap_or(end),
        (Met::AddDevice { peer, name, joins }, _) => own::add(session, side, peer, &name, joins),
        (Met::Sync { peer }, _) => sync::run(session, side, peer),
    }
}

/// How two sides met.
enum Met {
    /// As contacts: `Paired` or `Known`.
    Contacts(PairingPhase),
    /// To make one the other's device; with `joins`, the side that
    /// answered gets the vault.
    AddDevice {
        peer: PeerKey,
        name: String,
        joins: bool,
    },
    /// To sync, each one of the other's devices.
    Sync { peer: PeerKey },
}

fn meet(
    session: &mut Session<TcpStream>,
    side: &impl Side,
    intent: Option<Intent>,
) -> Result<Met, PairingFailure> {
    let peer_key = session.remote();
    let initiator = session.is_initiator();
    let hash = session.handshake_hash().to_vec();
    let known = side.knows(peer_key)?;
    let mine = side
        .vault(&hash, initiator)
        .map(|vault| Own { intent, vault });
    session
        .send(&Message::Hello {
            version: VERSION,
            name: side.name(),
            known,
            own: mine.clone(),
        })
        .map_err(|_| PairingFailure::Broken)?;
    let Message::Hello {
        version,
        name,
        known: they_know,
        own: theirs,
    } = session.recv().map_err(broken)?
    else {
        return Err(PairingFailure::Broken);
    };
    if version != VERSION {
        return Err(PairingFailure::Version);
    }
    let peer = Some(clean_name(&name)).filter(|name| !name.is_empty());
    let peer_name = peer.clone().unwrap_or_else(|| "?".to_owned());
    side.show(peer.as_deref(), &PairingPhase::Connecting);
    let intent = if initiator {
        intent
    } else {
        theirs.as_ref().and_then(|own| own.intent)
    };
    side.takes(intent)?;

    let Some(intent) = intent else {
        if known && they_know {
            return Ok(Met::Contacts(PairingPhase::Known));
        }
        compare_codes(session, side, peer.as_deref())?;
        side.save(peer_key, &peer_name)?;
        return Ok(Met::Contacts(PairingPhase::Paired));
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
            let ok = same && side.is_own(peer_key);
            if initiator {
                if !ok {
                    return Err(PairingFailure::NotOwn);
                }
                match session.recv().map_err(broken)? {
                    Message::Confirm { matched: true } => Ok(Met::Sync { peer: peer_key }),
                    Message::Confirm { matched: false } => Err(PairingFailure::NotOwn),
                    _ => Err(PairingFailure::Broken),
                }
            } else {
                session
                    .send(&Message::Confirm { matched: ok })
                    .map_err(|_| PairingFailure::Broken)?;
                if ok {
                    Ok(Met::Sync { peer: peer_key })
                } else {
                    Err(PairingFailure::NotOwn)
                }
            }
        }
        Intent::Other => Err(PairingFailure::Version),
    }
}

/// Agrees on the pairing code and has both users compare it; `Ok` only when
/// both said the codes match.
fn compare_codes(
    session: &mut Session<TcpStream>,
    side: &impl Side,
    peer: Option<&str>,
) -> Result<(), PairingFailure> {
    let code = session.pairing_code().map_err(broken)?;
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
pub(super) fn wait_for_answer(
    session: &mut Session<TcpStream>,
    side: &impl Side,
) -> Result<(bool, Option<bool>), PairingFailure> {
    let started = Instant::now();
    let mut theirs = None;
    loop {
        if let Some(matched) = side.answer(POLL)? {
            return Ok((matched, theirs));
        }
        if theirs.is_none() && waiting(session.stream()).map_err(|_| PairingFailure::Broken)? {
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

/// Whether the peer sent something (or hung up: then reading fails).
pub(super) fn waiting(stream: &TcpStream) -> io::Result<bool> {
    stream.set_nonblocking(true)?;
    let peeked = stream.peek(&mut [0; 1]);
    stream.set_nonblocking(false)?;
    match peeked {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(false),
        Err(error) => Err(error),
    }
}

/// A failed read: the peer hung up, took too long, or sent garbage.
pub(super) fn broken(error: sshkm_core::Error) -> PairingFailure {
    match error {
        sshkm_core::Error::Io { source, .. } => match source.kind() {
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

    use super::super::script::{Script, codes, pair};
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
}
