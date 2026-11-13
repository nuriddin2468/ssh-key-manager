//! Syncing the vault's entries with another of the user's own devices
//! (`docs/vault-sync.md`).
//!
//! Each side sends the other a copy of its database without what never
//! syncs ([`Vault::sync_copy`]): no database custom data (paired browsers,
//! the own-device key, the chat's key, KeePassXC's settings) and nothing
//! marked [`LOCAL`]. The receiver opens it with the vault's secret, checks
//! that it is this vault and within bounds ([`Vault::open_sync_copy`]), and
//! works out what to take ([`Vault::plan_sync`]): entries and groups are
//! items by UUID, each a set of keyed field hashes ([`model`]), merged three
//! ways against this computer's snapshot of the last sync with that device
//! ([`VaultBase`]) by the same rules as hosts ([`crate::sync::plan_hashed`]).
//! [`Vault::apply_sync`] makes the changes the user (or the rules) allow in
//! memory, as one change; the caller saves.
//!
//! The version of an entry this side doesn't keep always stays among the
//! entry's earlier versions, so no choice loses one.

mod apply;
mod copy;
mod model;
mod plan;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub use self::apply::{Counts, VaultApplied, VaultCounts};
pub use self::copy::PeerVault;
pub use self::plan::{ChangeOp, ItemKind, Party, VaultChange, VaultConflict, VaultPlan};
use crate::sync::{Base, Hashes};

/// Custom data that keeps an entry, or a group and everything in it, on
/// this computer: never in a copy, never changed by a sync.
pub const LOCAL: &str = "sshkm.local";
/// The version of entry sync this one speaks.
pub const ENTRY_SYNC_VERSION: u32 = 1;
/// Most entries a copy from another device may hold.
pub const MAX_ENTRIES: usize = 65_536;
/// Most groups a copy may hold.
pub const MAX_GROUPS: usize = 8192;
/// Deepest a group may be in a copy.
pub const MAX_DEPTH: usize = 64;
/// Most removal records a copy may hold.
pub const MAX_DELETED: usize = 262_144;
/// Most earlier versions of an entry taken from a copy: the newest.
pub const MAX_VERSIONS: usize = 64;

/// What this computer keeps about the vault after its last sync with
/// another device: hashes, never values.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultBase {
    /// Each item both had alike: its fields' keyed hashes.
    #[serde(default)]
    pub base: Base,
    /// Groups made separately on each computer for the same thing
    /// (`Environments`, say): this side's UUID → the other's.
    #[serde(default)]
    pub pairs: BTreeMap<String, String>,
}

/// The digest of each item as both sides compare them after a sync: the
/// SHA-256 of its id and its fields' hashes, made with a key both share.
pub fn digests(items: &BTreeMap<String, Hashes>) -> BTreeMap<String, String> {
    use base64ct::{Base64, Encoding};
    use sha2::{Digest, Sha256};
    items
        .iter()
        .map(|(id, fields)| {
            let mut hash = Sha256::new();
            let mut part = |bytes: &[u8]| {
                hash.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
                hash.update(bytes);
            };
            part(id.as_bytes());
            for (key, value) in fields {
                part(key.as_bytes());
                part(value.as_bytes());
            }
            (id.clone(), Base64::encode_string(&hash.finalize()))
        })
        .collect()
}
