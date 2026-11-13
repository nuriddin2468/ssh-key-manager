//! What this computer keeps about each of the user's other devices: the
//! snapshot of its last sync and the changes its user turned down, in
//! `sync/<device>.json` in the app's data folder. And for all of them
//! together: the deletions made from them without asking, in
//! `sync/unasked.json`, and the devices learned of through a sync, in
//! `sync/learned.json`. Hashes, counts and names only, no values.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use sshkm_core::fsutil;
use sshkm_core::p2p::PeerKey;

use serde::{Deserialize, Serialize};
use sshkm_core::vault::OwnDevice;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::sync::SyncState;
use crate::error::AppResult;

const DIR: &str = "sync";
/// Largest state file read: the vault's snapshot is the bulk of it.
const MAX_STATE: u64 = 64 * 1024 * 1024;
/// Largest file of deletions read: a few entries a day.
const MAX_UNASKED: u64 = 64 * 1024;
/// The deletions made without asking, for this computer.
const UNASKED: &str = "unasked.json";
/// The devices learned of through a sync.
const LEARNED: &str = "learned.json";
/// Largest file of devices learned read.
const MAX_LEARNED: u64 = 1024 * 1024;
/// Most devices learned of that are remembered: the newest.
const LEARNED_KEPT: usize = 1024;

fn path(data_dir: &Path, peer: &PeerKey, suffix: &str) -> PathBuf {
    let name = peer.as_bytes().iter().fold(String::new(), |mut hex, b| {
        let _ = write!(hex, "{b:02x}");
        hex
    });
    data_dir.join(DIR).join(format!("{name}{suffix}"))
}

/// `path` as JSON, if it is at most `max` bytes and reads.
fn read<T: serde::de::DeserializeOwned>(path: &Path, max: u64) -> Option<T> {
    std::fs::metadata(path)
        .ok()
        .filter(|meta| meta.len() <= max)
        .and_then(|_| std::fs::read(path).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
}

fn write(path: &Path, value: &impl Serialize) -> AppResult<()> {
    if let Some(dir) = path.parent() {
        fsutil::ensure_private_dir(dir)?;
    }
    let json = serde_json::to_vec_pretty(value)
        .map_err(|e| crate::error::AppError::new(sshkm_core::ErrorCode::Io, e.to_string()))?;
    fsutil::atomic_write(path, &json, 0o600)?;
    Ok(())
}

fn file(data_dir: &Path, name: &str) -> PathBuf {
    data_dir.join(DIR).join(name)
}

/// The state of the last sync with `peer`; empty if there was none or
/// the file can't be read (the next sync then asks about differences).
/// The deletions made without asking are this computer's, from all the
/// user's devices ([`load_unasked`]).
pub fn load(data_dir: &Path, peer: &PeerKey) -> SyncState {
    let mut state: SyncState = read(&path(data_dir, peer, ".json"), MAX_STATE).unwrap_or_default();
    state.unasked = load_unasked(data_dir);
    state
}

/// The deletions this computer made from the user's devices without
/// asking. When the file is there but can't be read, they count as at the
/// limit ([`SyncState::at_the_limit`]), never as none, and the file is
/// written so, to count for a day from now.
fn load_unasked(data_dir: &Path) -> Vec<(i64, u32)> {
    let path = file(data_dir, UNASKED);
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        _ => read(&path, MAX_UNASKED).unwrap_or_else(|| {
            let at_the_limit = SyncState::at_the_limit(OffsetDateTime::now_utc().unix_timestamp());
            // Best effort: when it can't be written, it stays at the limit.
            let _ = write(&path, &at_the_limit);
            at_the_limit
        }),
    }
}

/// Keeps `state`, but for [`SyncState::unasked`] ([`save_unasked`]).
pub fn save(data_dir: &Path, peer: &PeerKey, state: &SyncState) -> AppResult<()> {
    write(&path(data_dir, peer, ".json"), state)
}

/// Keeps the deletions this computer made without asking.
pub fn save_unasked(data_dir: &Path, unasked: &[(i64, u32)]) -> AppResult<()> {
    write(&file(data_dir, UNASKED), &unasked)
}

/// A device this computer learned of through a sync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Learned {
    /// The device the sync was with, by its name then.
    pub from: String,
    /// When: RFC 3339, UTC.
    pub at: String,
}

/// The devices this computer learned of through a sync, by device key.
pub fn learned(data_dir: &Path) -> BTreeMap<String, Learned> {
    read(&file(data_dir, LEARNED), MAX_LEARNED).unwrap_or_default()
}

/// Remembers that a sync with `from` made `devices` the user's here; the
/// [`LEARNED_KEPT`] newest are kept.
pub fn note_learned(data_dir: &Path, devices: &[OwnDevice], from: &str) -> AppResult<()> {
    if devices.is_empty() {
        return Ok(());
    }
    let mut all = learned(data_dir);
    let at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default();
    for device in devices {
        all.insert(
            device.key.clone(),
            Learned {
                from: from.to_owned(),
                at: at.clone(),
            },
        );
    }
    if all.len() > LEARNED_KEPT {
        let mut by_time: Vec<(String, String)> = all
            .iter()
            .map(|(key, learned)| (learned.at.clone(), key.clone()))
            .collect();
        by_time.sort();
        for (_, key) in by_time.into_iter().take(all.len() - LEARNED_KEPT) {
            all.remove(&key);
        }
    }
    write(&file(data_dir, LEARNED), &all)
}

/// Forgets a device that is no longer one of the user's.
pub fn forget(data_dir: &Path, peer: &PeerKey) {
    let _ = std::fs::remove_file(path(data_dir, peer, ".json"));
}

#[cfg(test)]
mod tests {
    use sshkm_core::p2p::Identity;

    use super::*;

    #[test]
    fn states_are_kept_per_device() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (
            Identity::generate().unwrap().public(),
            Identity::generate().unwrap().public(),
        );
        assert_eq!(load(dir.path(), &a), SyncState::default());
        let state = SyncState {
            synced: Some("2026-11-04T12:00:00Z".into()),
            ..SyncState::default()
        };
        save(dir.path(), &a, &state).unwrap();
        assert_eq!(load(dir.path(), &a), state);
        assert_eq!(load(dir.path(), &b), SyncState::default());
        forget(dir.path(), &a);
        assert_eq!(load(dir.path(), &a), SyncState::default());
    }

    #[test]
    fn deletions_are_this_computers_outlive_a_bad_state_and_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (
            Identity::generate().unwrap().public(),
            Identity::generate().unwrap().public(),
        );
        save_unasked(dir.path(), &[(1_000, 3)]).unwrap();
        // Kept apart from each device's state, and the same for all.
        save(dir.path(), &a, &SyncState::default()).unwrap();
        assert_eq!(load(dir.path(), &a).unasked, [(1_000, 3)]);
        assert_eq!(load(dir.path(), &b).unasked, [(1_000, 3)]);
        // A state file that doesn't read leaves them as they are.
        std::fs::write(path(dir.path(), &a, ".json"), "{ not json").unwrap();
        assert_eq!(load(dir.path(), &a).unasked, [(1_000, 3)]);
        forget(dir.path(), &a);
        assert_eq!(load(dir.path(), &b).unasked, [(1_000, 3)]);
        // Their own file unreadable or too large: at the limit, written so
        // that it ends a day from now.
        let unasked = file(dir.path(), UNASKED);
        let at_limit = |state: &SyncState| {
            state.unasked.iter().map(|(_, n)| *n).sum::<u32>()
                == u32::try_from(super::super::sync::MASS_DELETE).unwrap()
        };
        for bad in [b"[[1".to_vec(), vec![b' '; 65 * 1024]] {
            std::fs::write(&unasked, bad).unwrap();
            let state = load(dir.path(), &a);
            assert!(at_limit(&state));
            let kept: Vec<(i64, u32)> = read(&unasked, MAX_UNASKED).unwrap();
            assert_eq!(kept, state.unasked);
        }
    }

    #[test]
    fn devices_learned_of_are_remembered_with_whom_from() {
        let dir = tempfile::tempdir().unwrap();
        let device = |key: &str, name: &str| OwnDevice {
            key: key.into(),
            name: name.into(),
            added: String::new(),
        };
        assert!(learned(dir.path()).is_empty());
        note_learned(dir.path(), &[device("k2", "Phone")], "MacBook").unwrap();
        let all = learned(dir.path());
        assert_eq!(all["k2"].from, "MacBook");
        let many: Vec<OwnDevice> = (0..=LEARNED_KEPT)
            .map(|n| device(&format!("m{n:05}"), "Many"))
            .collect();
        note_learned(dir.path(), &many, "Other").unwrap();
        assert_eq!(learned(dir.path()).len(), LEARNED_KEPT);
    }
}
