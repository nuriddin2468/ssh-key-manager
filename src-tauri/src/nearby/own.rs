//! Adding one of the user's devices, after both users said the codes match
//! (see [`conversation`]).
//!
//! The side that connected has the vault. Its user confirms with Touch ID
//! or the master password ([`Side::authorized`]: only the app's check of
//! either says so, never the page's yes to the code); then it records both
//! computers as the user's devices and says so ([`Message::Added`]). If the
//! other computer has no vault yet, the vault file follows in parts, then
//! its secret. The other computer checks that the secret opens the file and
//! keeps both in memory until its user sets a master password of its own.
//! If it has the same vault already (a synced folder), it only records both
//! as well; the two tell that by the key own devices share, which is in the
//! file ([`sshkm_core::p2p::own`]).
//!
//! [`conversation`]: super::pairing::conversation

use std::net::TcpStream;
use std::time::Instant;

use sshkm_core::p2p::{Message, PeerKey, Session};
use sshkm_core::vault::MAX_DATABASE_SIZE;

use super::pairing::{ANSWER_TIMEOUT, POLL, PairingFailure, PairingPhase, Side, broken, waiting};
use super::transfer::STEP_TIMEOUT;

/// The rest of the conversation: giving (the side that connected) or
/// being given (the other). With `joins`, the vault goes over.
pub fn add(
    session: &mut Session<TcpStream>,
    side: &impl Side,
    peer: PeerKey,
    name: &str,
    joins: bool,
) -> PairingPhase {
    let result = if session.is_initiator() {
        give(session, side, peer, name, joins)
    } else {
        take(session, side, peer, name, joins)
    };
    result.unwrap_or_else(|reason| PairingPhase::Failed { reason })
}

fn give(
    session: &mut Session<TcpStream>,
    side: &impl Side,
    peer: PeerKey,
    name: &str,
    joins: bool,
) -> Result<PairingPhase, PairingFailure> {
    side.show(None, &PairingPhase::Authorize { vault: joins });
    if let Err(reason) = wait_for_authorization(session, side) {
        let _ = session.send(&Message::Confirm { matched: false });
        return Err(reason);
    }
    side.add_device(peer, name)?;
    session
        .send(&Message::Added)
        .map_err(|_| PairingFailure::Broken)?;
    if joins {
        let (file, secret) = side.share_vault()?;
        let total = u64::try_from(file.len()).unwrap_or(u64::MAX);
        side.show(None, &PairingPhase::Transfer { done: 0, total });
        let _ = session.stream().set_write_timeout(Some(STEP_TIMEOUT));
        session
            .send_bytes(&file, &mut |done, total| {
                side.show(None, &PairingPhase::Transfer { done, total });
            })
            .map_err(broken)?;
        session
            .send(&Message::Secret { key: secret })
            .map_err(broken)?;
    }
    let _ = session.stream().set_read_timeout(Some(STEP_TIMEOUT));
    match session.recv().map_err(broken)? {
        Message::Received { saved: true } => Ok(PairingPhase::Added { vault: joins }),
        Message::Received { saved: false } => Err(PairingFailure::NotSaved),
        _ => Err(PairingFailure::Broken),
    }
}

/// Waits for this user to confirm with Touch ID / Windows Hello or the
/// master password ([`Side::authorized`]); a yes or no meant for the code
/// doesn't count. The other side says nothing meanwhile, so anything from
/// it is it hanging up.
fn wait_for_authorization(
    session: &mut Session<TcpStream>,
    side: &impl Side,
) -> Result<(), PairingFailure> {
    let started = Instant::now();
    loop {
        if side.authorized(POLL)? {
            return Ok(());
        }
        if waiting(session.stream()).map_err(|_| PairingFailure::Broken)? {
            return Err(PairingFailure::PeerLeft);
        }
        if started.elapsed() > ANSWER_TIMEOUT {
            return Err(PairingFailure::TimedOut);
        }
    }
}

fn take(
    session: &mut Session<TcpStream>,
    side: &impl Side,
    peer: PeerKey,
    name: &str,
    joins: bool,
) -> Result<PairingPhase, PairingFailure> {
    side.show(None, &PairingPhase::Approving);
    let _ = session
        .stream()
        .set_read_timeout(Some(ANSWER_TIMEOUT + STEP_TIMEOUT));
    match session.recv().map_err(broken)? {
        Message::Added => {}
        Message::Confirm { matched: false } => return Err(PairingFailure::PeerDeclined),
        _ => return Err(PairingFailure::Broken),
    }
    let _ = session.stream().set_read_timeout(Some(STEP_TIMEOUT));
    let saved = if joins {
        let file = session
            .recv_bytes(MAX_DATABASE_SIZE, &mut |done, total| {
                side.show(None, &PairingPhase::Transfer { done, total });
            })
            .map_err(broken)?;
        let Message::Secret { key } = session.recv().map_err(broken)? else {
            return Err(PairingFailure::Broken);
        };
        side.take_vault(file, key).map(|()| PairingPhase::SetMaster)
    } else {
        side.add_device(peer, name)
            .map(|()| PairingPhase::Added { vault: false })
    };
    let _ = session.send(&Message::Received {
        saved: saved.is_ok(),
    });
    saved
}

#[cfg(test)]
mod tests {
    use super::super::pairing::Purpose;
    use super::super::script::{Script, VAULT_FILE, Vault, codes, talk};
    use super::*;

    fn failed(reason: PairingFailure) -> PairingPhase {
        PairingPhase::Failed { reason }
    }

    /// The computer with the vault: its user says the codes match, then
    /// confirms with Touch ID or the master password (`yes`), or cancels.
    fn giver(yes: bool) -> Script {
        let mut side = Script::new("MacBook", Some(true));
        side.vault = Vault::Open("the secret");
        side.authorizes = yes;
        side
    }

    fn newcomer() -> Script {
        let mut side = Script::new("ThinkPad", Some(true));
        side.vault = Vault::Missing;
        side
    }

    #[test]
    fn a_new_computer_gets_the_vault_and_its_secret() {
        let ((left_end, left), (right_end, right)) =
            talk(giver(true), newcomer(), Purpose::AddDevice);
        assert_eq!(left_end, PairingPhase::Added { vault: true });
        assert_eq!(right_end, PairingPhase::SetMaster);
        assert_eq!(
            *right.taken.lock().unwrap(),
            Some((VAULT_FILE.to_vec(), "the secret".to_owned()))
        );
        assert_eq!(*left.added.lock().unwrap(), ["ThinkPad"]);
        // The code was compared on both, and nobody became a contact.
        assert_eq!(codes(&left).len(), 1);
        assert_eq!(codes(&left), codes(&right));
        assert_eq!(
            left.saved.lock().unwrap().len() + right.saved.lock().unwrap().len(),
            0
        );
        let shown = left.shown.lock().unwrap();
        assert!(
            shown
                .iter()
                .any(|(_, phase)| *phase == PairingPhase::Authorize { vault: true })
        );
    }

    #[test]
    fn computers_with_the_same_vault_record_each_other() {
        let mut other = Script::new("iMac", Some(true));
        other.vault = Vault::Open("the secret");
        // Contacts already: the code is compared all the same.
        other.knows = true;
        let mut left = giver(true);
        left.knows = true;
        let ((left_end, left), (right_end, right)) = talk(left, other, Purpose::AddDevice);
        let added = PairingPhase::Added { vault: false };
        assert_eq!((left_end, right_end), (added.clone(), added));
        assert_eq!(*left.added.lock().unwrap(), ["iMac"]);
        assert_eq!(*right.added.lock().unwrap(), ["MacBook"]);
        assert_eq!(*right.taken.lock().unwrap(), None);
        assert_eq!(codes(&left).len(), 1);
    }

    #[test]
    fn another_vault_is_never_merged() {
        let mut other = Script::new("iMac", Some(true));
        other.vault = Vault::Open("another secret");
        let ((left_end, left), (right_end, _)) = talk(giver(true), other, Purpose::AddDevice);
        assert_eq!(left_end, failed(PairingFailure::OtherVault));
        assert_eq!(right_end, failed(PairingFailure::OtherVault));
        assert_eq!(codes(&left).len(), 0);
    }

    #[test]
    fn a_vault_without_the_key_of_own_devices_is_another_one() {
        // Such as the same file in a synced folder that hasn't synced the
        // key yet: nothing is merged, and adding again later works.
        let mut other = Script::new("iMac", Some(true));
        other.vault = Vault::Open("");
        let ((left_end, left), (right_end, right)) = talk(giver(true), other, Purpose::AddDevice);
        assert_eq!(left_end, failed(PairingFailure::OtherVault));
        assert_eq!(right_end, failed(PairingFailure::OtherVault));
        assert_eq!(codes(&left).len() + codes(&right).len(), 0);
    }

    #[test]
    fn a_locked_vault_or_an_older_version_says_so() {
        let mut locked = Script::new("iMac", Some(true));
        locked.vault = Vault::Locked;
        let ((left_end, _), (right_end, _)) = talk(giver(true), locked, Purpose::AddDevice);
        assert_eq!(left_end, failed(PairingFailure::VaultLocked));
        assert_eq!(right_end, failed(PairingFailure::VaultLocked));

        let older = Script::new("iMac", Some(true));
        let ((left_end, _), _) = talk(giver(true), older, Purpose::AddDevice);
        assert_eq!(left_end, failed(PairingFailure::Version));
    }

    #[test]
    fn without_the_users_confirmation_nothing_is_added_or_given() {
        let ((left_end, left), (right_end, right)) =
            talk(giver(false), newcomer(), Purpose::AddDevice);
        assert_eq!(left_end, failed(PairingFailure::Cancelled));
        assert_eq!(right_end, failed(PairingFailure::PeerDeclined));
        assert_eq!(left.added.lock().unwrap().len(), 0);
        assert_eq!(*right.taken.lock().unwrap(), None);
    }

    #[test]
    fn a_yes_to_the_code_is_not_the_confirmation() {
        // "Codes match" twice, and the yes repeats: still no confirmation.
        let mut left = Script::answering("MacBook", &[Some(true), Some(true), Some(true)]);
        left.vault = Vault::Open("the secret");
        left.authorizes = false;
        let ((left_end, left), (_, right)) = talk(left, newcomer(), Purpose::AddDevice);
        assert_eq!(left_end, failed(PairingFailure::Cancelled));
        assert_eq!(*left.asked_to_authorize.lock().unwrap(), 1);
        assert_eq!(left.added.lock().unwrap().len(), 0);
        assert_eq!(*right.taken.lock().unwrap(), None);

        // The side that is added confirms nothing; the one that adds, once.
        let ((_, left), (_, right)) = talk(giver(true), newcomer(), Purpose::AddDevice);
        assert_eq!(*left.asked_to_authorize.lock().unwrap(), 1);
        assert_eq!(*right.asked_to_authorize.lock().unwrap(), 0);
    }

    #[test]
    fn a_computer_waiting_for_a_vault_only_takes_one() {
        let ((left_end, _), (right_end, _)) = talk(
            Script::new("stranger", Some(true)),
            newcomer(),
            Purpose::Pair,
        );
        assert!(matches!(left_end, PairingPhase::Failed { .. }));
        assert_eq!(right_end, failed(PairingFailure::VaultLocked));
    }
}
