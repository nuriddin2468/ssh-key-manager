//! What this computer keeps about each of the user's other devices: the
//! snapshot of its last sync and the changes its user turned down, in
//! `sync/<device>.json` in the app's data folder, and the deletions made
//! from it without asking, in `sync/<device>.unasked.json`. Hashes and
//! counts only, no values.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use sshkm_core::fsutil;
use sshkm_core::p2p::PeerKey;

use super::sync::SyncState;
use crate::error::AppResult;

const DIR: &str = "sync";
/// Largest state file read: the vault's snapshot is the bulk of it.
const MAX_STATE: u64 = 64 * 1024 * 1024;
/// Largest file of deletions read: a few entries a day.
const MAX_UNASKED: u64 = 64 * 1024;

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

fn write(path: &Path, value: &impl serde::Serialize) -> AppResult<()> {
    if let Some(dir) = path.parent() {
        fsutil::ensure_private_dir(dir)?;
    }
    let json = serde_json::to_vec_pretty(value)
        .map_err(|e| crate::error::AppError::new(sshkm_core::ErrorCode::Io, e.to_string()))?;
    fsutil::atomic_write(path, &json, 0o600)?;
    Ok(())
}

/// The state of the last sync with `peer`; empty if there was none or
/// the file can't be read (the next sync then asks about differences).
/// The deletions made from it without asking come from their own file:
/// when that is there but can't be read, they count as at the limit
/// ([`SyncState::at_the_limit`]), never as none.
pub fn load(data_dir: &Path, peer: &PeerKey) -> SyncState {
    let mut state: SyncState = read(&path(data_dir, peer, ".json"), MAX_STATE).unwrap_or_default();
    let unasked = path(data_dir, peer, ".unasked.json");
    state.unasked = match std::fs::symlink_metadata(&unasked) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        _ => read(&unasked, MAX_UNASKED).unwrap_or_else(|| {
            SyncState::at_the_limit(time::OffsetDateTime::now_utc().unix_timestamp())
        }),
    };
    state
}

/// Keeps `state`, but for [`SyncState::unasked`] ([`save_unasked`]).
pub fn save(data_dir: &Path, peer: &PeerKey, state: &SyncState) -> AppResult<()> {
    write(&path(data_dir, peer, ".json"), state)
}

/// Keeps the deletions made from `peer` without asking.
pub fn save_unasked(data_dir: &Path, peer: &PeerKey, unasked: &[(i64, u32)]) -> AppResult<()> {
    write(&path(data_dir, peer, ".unasked.json"), &unasked)
}

/// Forgets a device that is no longer one of the user's.
pub fn forget(data_dir: &Path, peer: &PeerKey) {
    for suffix in [".json", ".unasked.json"] {
        let _ = std::fs::remove_file(path(data_dir, peer, suffix));
    }
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
    fn deletions_outlive_a_state_that_doesnt_read_and_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let peer = Identity::generate().unwrap().public();
        save_unasked(dir.path(), &peer, &[(1_000, 3)]).unwrap();
        // Kept apart from the state, which doesn't hold them.
        save(dir.path(), &peer, &SyncState::default()).unwrap();
        assert_eq!(load(dir.path(), &peer).unasked, [(1_000, 3)]);
        // A state file that doesn't read leaves them as they are.
        std::fs::write(path(dir.path(), &peer, ".json"), "{ not json").unwrap();
        assert_eq!(load(dir.path(), &peer).unasked, [(1_000, 3)]);
        // Their own file unreadable or too large: at the limit.
        let unasked = path(dir.path(), &peer, ".unasked.json");
        let at_limit = |state: SyncState| {
            state.unasked.iter().map(|(_, n)| *n).sum::<u32>()
                == u32::try_from(super::super::sync::MASS_DELETE).unwrap()
        };
        std::fs::write(&unasked, "[[1").unwrap();
        assert!(at_limit(load(dir.path(), &peer)));
        std::fs::write(&unasked, vec![b' '; 65 * 1024]).unwrap();
        assert!(at_limit(load(dir.path(), &peer)));
        forget(dir.path(), &peer);
        assert!(!unasked.exists());
        assert_eq!(load(dir.path(), &peer).unasked, []);
    }
}
