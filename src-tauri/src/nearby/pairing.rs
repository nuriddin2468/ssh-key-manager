//! One pairing, from the open session to a saved contact.
//!
//! Both sides run [`converse`] with a [`Side`]: the app's own state in the
//! app, a script in the tests. Each sends `Hello`; if both already know each
//! other there is nothing to do. Otherwise they agree on the pairing code,
//! each user says whether their screen shows the same one, and each side
//! tells the other. Only when both said yes does each save the other as a
//! contact. A "no" from either side, a cancel or a hang-up ends it.
//!
//! After that the side that connected may send one item (see [`transfer`]).
//!
//! [`transfer`]: super::transfer

use std::io::{self, ErrorKind};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use serde::Serialize;
use sshkm_core::p2p::protocol::{Item, ItemSummary, VERSION, clean_name};
use sshkm_core::p2p::{Message, PeerKey, Session};

/// How long the users have to compare the codes.
pub const ANSWER_TIMEOUT: Duration = Duration::from_secs(180);
/// How often the wait for an answer looks at the connection.
const POLL: Duration = Duration::from_millis(200);

/// Where a pairing is.
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
    Failed {
        reason: PairingFailure,
    },
}

/// Why a pairing ended without one.
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
}

/// What [`converse`] needs from the side it runs on.
pub trait Side {
    /// This device's name, for the other user to read.
    fn name(&self) -> String;
    /// Whether `peer` is a contact already.
    fn knows(&self, peer: PeerKey) -> Result<bool, PairingFailure>;
    /// Saves `peer` as a contact named `name`.
    fn save(&self, peer: PeerKey, name: &str) -> Result<(), PairingFailure>;
    /// Shows the user where the pairing is; `peer` once the other device
    /// gave its name.
    fn show(&self, peer: Option<&str>, phase: &PairingPhase);
    /// The user's answer if one comes within `wait`; `Err(Cancelled)` once
    /// the user cancelled.
    fn answer(&self, wait: Duration) -> Result<Option<bool>, PairingFailure>;
    /// Saves an item the user accepted, checked against what was offered.
    /// Returns its name and whether a host's keys differ from the ones here.
    fn store(&self, item: &Item) -> Result<(String, bool), PairingFailure>;
}

/// Runs a pairing over an open session; returns how it ended, never
/// `Connecting`, `Compare` or `Waiting`.
pub fn converse(session: &mut Session<TcpStream>, side: &impl Side) -> PairingPhase {
    match talk(session, side) {
        Ok(phase) => phase,
        Err(reason) => PairingPhase::Failed { reason },
    }
}

fn talk(
    session: &mut Session<TcpStream>,
    side: &impl Side,
) -> Result<PairingPhase, PairingFailure> {
    let peer_key = session.remote();
    let known = side.knows(peer_key)?;
    session
        .send(&Message::Hello {
            version: VERSION,
            name: side.name(),
            known,
        })
        .map_err(|_| PairingFailure::Broken)?;
    let Message::Hello {
        version,
        name,
        known: they_know,
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
    if known && they_know {
        return Ok(PairingPhase::Known);
    }

    let code = session.pairing_code().map_err(broken)?;
    side.show(
        peer.as_deref(),
        &PairingPhase::Compare { code: code.clone() },
    );
    let (matched, mut theirs) = wait_for_answer(session, side)?;
    if !matched {
        let _ = session.send(&Message::Confirm { matched: false });
        return Err(PairingFailure::Declined);
    }
    session
        .send(&Message::Confirm { matched: true })
        .map_err(|_| PairingFailure::Broken)?;
    if theirs.is_none() {
        side.show(peer.as_deref(), &PairingPhase::Waiting { code });
        let _ = session.stream().set_read_timeout(Some(ANSWER_TIMEOUT));
        theirs = match session.recv().map_err(broken)? {
            Message::Confirm { matched } => Some(matched),
            _ => return Err(PairingFailure::Broken),
        };
    }
    if theirs != Some(true) {
        return Err(PairingFailure::PeerDeclined);
    }
    side.save(peer_key, &peer_name)?;
    Ok(PairingPhase::Paired)
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
fn waiting(stream: &TcpStream) -> io::Result<bool> {
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
