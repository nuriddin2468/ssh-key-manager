//! What a [`conversation`] needs from the device it runs on: the seam
//! between the conversation, which is the same everywhere, and each app.
//!
//! [`Side`] is three traits, by who answers them:
//!
//! - [`User`]: the person at the device. Where the conversation is, the
//!   answers they give on the page (the codes match, an offer, a sync's
//!   review), their confirmation before a device is added, and the system
//!   dialogs a script in the page can't answer (a risky change, a secret
//!   leaving, this computer being added). On a computer the Nearby page
//!   and the system's dialogs; on the phone its screens and the
//!   fingerprint prompt.
//! - [`Device`]: the device itself. Its name, the contacts and own devices
//!   it knows, its vault's proof and state, and what it does on being
//!   added or given a vault.
//! - [`SyncStore`]: what a sync reads and writes here. Host blocks and
//!   server keys (on a computer `~/.ssh/config` and `known_hosts`, with the
//!   rules for writing them; on the phone private text files), the records
//!   of devices, projects and contacts, the snapshot of the last sync with
//!   each device, and the vault's entries.
//!
//! The methods for the user's own devices have defaults for a side that
//! has none, such as `examples/nearby_peer.rs` in its plain modes: no
//! vault, no device of the user's, nothing allowed, nothing kept. Two have
//! none, as no answer is right for every side: whether a device was removed from the
//! user's ([`Device::removed`]), and the deletions this device made without
//! asking ([`SyncStore::unasked`]). Every method that can fail says why in
//! a [`PairingFailure`], which ends the conversation.
//!
//! What stays the conversation's own, whatever the side: a vault that comes
//! for a new device is checked before [`Device::take_vault`] sees it
//! ([`check_moved`]); a sync starts only with one of the user's devices,
//! before either side says anything ([`Device::is_own`]); and deletions from
//! the user's other devices are counted over a day from what
//! [`SyncStore::unasked`] gives, at the limit when that can't be read.
//!
//! [`conversation`]: super::conversation
//! [`check_moved`]: crate::vault::sync::check_moved

use std::collections::BTreeMap;
use std::time::Duration;

use zeroize::Zeroizing;

use super::sync::{RiskyChange, RiskyVariables, SyncDecisions, SyncLocal, SyncState, SyncWrite};
use super::{PairingFailure, PairingPhase};
use crate::p2p::PeerKey;
use crate::p2p::protocol::{EntrySync, Intent, Item, SecretText, VaultState};
use crate::sync::Hashes;
use crate::vault::sync::{Pairs, VaultApplied, VaultBase, VaultChoices, VaultPlan};

/// Everything a conversation needs from the side it runs on.
pub trait Side: User + Device + SyncStore {}

impl<T: User + Device + SyncStore> Side for T {}

/// What the person at this device sees and answers.
pub trait User {
    /// Shows the user where the conversation is; `peer` once the other
    /// device said who it is: the name this side keeps for it, or for a
    /// device it doesn't know, the name it gave.
    fn show(&self, peer: Option<&str>, phase: &PairingPhase);
    /// The user's answer if one comes within `wait`; `Err(Cancelled)` once
    /// the user cancelled.
    fn answer(&self, wait: Duration) -> Result<Option<bool>, PairingFailure>;

    /// Whether this user confirmed, within `wait`, making the other computer
    /// one of their devices: with Touch ID / Windows Hello or the master
    /// password, never with a plain yes. `Err(Cancelled)` once the user
    /// cancelled.
    fn authorized(&self, _wait: Duration) -> Result<bool, PairingFailure> {
        Err(PairingFailure::Cancelled)
    }
    /// The user's decisions on a review, if they come within `wait`.
    fn decisions(&self, _wait: Duration) -> Result<Option<SyncDecisions>, PairingFailure> {
        Err(PairingFailure::Cancelled)
    }
    /// Whether this user allows, in a system dialog that a script in the
    /// page can't answer, sending `item`, which holds a secret, to the
    /// other side, as it goes: without the variables named in `left_out`,
    /// which the other side's version would set without asking.
    fn allow_send(&self, _item: &Item, _left_out: &[String]) -> bool {
        false
    }
    /// On a computer being added that has the vault already: whether this
    /// user allows, in a system dialog, becoming one of their devices with
    /// the computer that adds it.
    fn allow_added(&self) -> bool {
        false
    }
    /// Whether this user allows, in a system dialog that a script in the
    /// page can't answer, the risky changes of a sync they chose to make.
    fn allow_risky(&self, _changes: &[RiskyChange]) -> bool {
        false
    }
    /// Whether this user allows, in a system dialog that a script in the
    /// page can't answer, the variables a sync would add or change that
    /// make programs load code.
    fn allow_risky_variables(&self, _changes: &[RiskyVariables]) -> bool {
        false
    }
}

/// This device: its name, whom it knows, and its vault.
pub trait Device {
    /// This device's name, for the other user to read.
    fn name(&self) -> String;
    /// The name this side keeps for `peer`, if it is a contact or one of
    /// the user's devices already.
    fn knows(&self, peer: PeerKey) -> Result<Option<String>, PairingFailure>;
    /// Saves `peer` as a contact named `name`.
    fn save(&self, peer: PeerKey, name: &str) -> Result<(), PairingFailure>;
    /// Saves an item the user accepted, checked against what was offered,
    /// and says what became of it.
    fn store(&self, item: &Item) -> Result<Stored, PairingFailure>;

    /// Fails unless this side has a conversation for `intent`: one that
    /// waits for a vault is only added, and one announced to the user's
    /// devices only syncs.
    fn takes(&self, _intent: Option<Intent>) -> Result<(), PairingFailure> {
        Ok(())
    }
    /// The other side hung up after this side gave it what it needs to work
    /// out the code this side would show, and before this side showed it:
    /// it may be trying again until the code is one it wants.
    fn broke_off(&self) {}

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
    /// Whether `peer` was one of the user's devices and was removed: such
    /// a device can't add itself back. A side that can't tell (its vault
    /// is locked) says `true`.
    fn removed(&self, peer: PeerKey) -> bool;
    /// What this side's `Hello` says about syncing the vault's entries;
    /// `None` for a side that doesn't.
    fn entry_sync(&self) -> Option<EntrySync> {
        None
    }
    /// Records this computer and `peer`, named `name`, as the user's devices.
    fn add_device(&self, _peer: PeerKey, _name: &str) -> Result<(), PairingFailure> {
        Err(PairingFailure::Broken)
    }
    /// The vault file and its secret, for a new device.
    fn share_vault(&self) -> Result<(Zeroizing<Vec<u8>>, SecretText), PairingFailure> {
        Err(PairingFailure::Broken)
    }
    /// Keeps the vault another of the user's computers sent until the user
    /// sets a master password for it. The conversation checked it already
    /// ([`check_moved`]: within bounds, and opened by `secret`).
    ///
    /// [`check_moved`]: crate::vault::sync::check_moved
    fn take_vault(
        &self,
        _file: Zeroizing<Vec<u8>>,
        _secret: SecretText,
    ) -> Result<(), PairingFailure> {
        Err(PairingFailure::NotSaved)
    }
}

/// What a sync with one of the user's devices reads and writes here.
///
/// What a side must do in each, for a sync to be as safe on it as on a
/// computer:
///
/// - [`sync_write`](Self::sync_write): write the host blocks and the server
///   keys only if they are as the sync read them
///   ([`SyncWrite::config_revision`], [`SyncWrite::known_revision`];
///   [`ensure_revision`]), so an edit made meanwhile is never overwritten;
///   with [`SyncWrite::deletes`], keep a backup that outlives the rotation
///   first ([`keep_backup`]); merge the records as one change. On a
///   computer, also leave out a server key next to one that another file
///   `ssh` reads trusts for the host ([`drop_trusted_elsewhere`]).
/// - [`vault_plan`](Self::vault_plan): read the vault file again first
///   ([`Vault::refresh`]), so the plan is against what is on disk, and keep
///   the other side's copy open until the sync ends.
/// - [`vault_apply`](Self::vault_apply): when the choices delete or move to
///   the recycle bin ([`deletes`]), keep a backup that outlives the rotation
///   first ([`keep_backup`]); nothing of an apply that fails halfway is kept
///   ([`Vault::snapshot`], [`Vault::restore`]); save after a backup.
/// - [`unasked`](Self::unasked) and [`sync_unasked`](Self::sync_unasked):
///   one list for the device, whichever device a sync is with, kept apart
///   from the per-device state that [`sync_keep`](Self::sync_keep) keeps.
///
/// [`ensure_revision`]: crate::fsutil::ensure_revision
/// [`keep_backup`]: crate::fsutil::keep_backup
/// [`drop_trusted_elsewhere`]: crate::sync::host_keys::drop_trusted_elsewhere
/// [`Vault::refresh`]: crate::vault::Vault::refresh
/// [`Vault::snapshot`]: crate::vault::Vault::snapshot
/// [`Vault::restore`]: crate::vault::Vault::restore
/// [`deletes`]: super::sync::deletes
pub trait SyncStore {
    /// What a sync with `peer` starts from. Its state's
    /// [`SyncState::unasked`] is not read: the conversation takes it from
    /// [`unasked`](Self::unasked).
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
    /// Keeps the deletions this computer made without asking, from all the
    /// user's devices ([`SyncState::unasked`]): before a sync writes
    /// anything.
    fn sync_unasked(&self, _unasked: &[(i64, u32)]) -> Result<(), PairingFailure> {
        Err(PairingFailure::NotSaved)
    }
    /// The deletions this device made without asking, from all the user's
    /// devices, as [`sync_unasked`](Self::sync_unasked) kept them: none
    /// when nothing was kept yet. `Err` when they were kept but can't be
    /// read: the conversation then counts them at the limit for a day, and
    /// keeps that.
    fn unasked(&self) -> Result<Vec<(i64, u32)>, PairingFailure>;
    /// This side's copy of the vault for a sync ([`Vault::sync_copy`]).
    ///
    /// [`Vault::sync_copy`]: crate::vault::Vault::sync_copy
    fn vault_copy(&self) -> Result<Zeroizing<Vec<u8>>, PairingFailure> {
        Err(PairingFailure::NotSaved)
    }
    /// Opens the other side's copy and works out what to take from it
    /// against `base`; the copy stays open until the sync ends.
    fn vault_plan(&self, _copy: &[u8], _base: &VaultBase) -> Result<VaultPlan, PairingFailure> {
        Err(PairingFailure::Broken)
    }
    /// Makes the changes of `plan` the `choices` name and settles its
    /// conflicts as they say, then saves the vault after a backup.
    fn vault_apply(
        &self,
        _plan: &VaultPlan,
        _choices: &VaultChoices,
    ) -> Result<VaultApplied, PairingFailure> {
        Err(PairingFailure::NotSaved)
    }
    /// The vault's items now, with the groups paired as `pairs`: their
    /// snapshots (keyed with this device's key) and their digests (keyed
    /// with the key own devices share).
    fn vault_items(&self, _pairs: &Pairs) -> Result<VaultItems, PairingFailure> {
        Err(PairingFailure::Broken)
    }
}

/// What became of an item saved here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stored {
    /// Its name here: the entry's title, the host's alias (with a number if
    /// it is taken), the key's file name, the environment's label.
    pub name: String,
    /// A host came with server keys other than the ones trusted here, which
    /// are kept.
    pub keys_differ: bool,
    /// An environment's variables left out, as they make programs run code.
    pub left_out: Vec<String>,
}

impl Stored {
    /// Saved as `name`, as it came.
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Self::default()
        }
    }
}

/// The vault's items after a sync, as [`SyncStore::vault_items`] gives them.
pub struct VaultItems {
    pub snapshots: BTreeMap<String, Hashes>,
    pub digests: BTreeMap<String, String>,
}
