//! What this computer keeps about each of the user's other devices: the
//! snapshot of its last sync and the changes its user turned down, in
//! `sync/<device>.json` in the app's data folder. Hashes only, no values.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use sshkm_core::fsutil;
use sshkm_core::p2p::PeerKey;

use super::sync::SyncState;
use crate::error::AppResult;

const DIR: &str = "sync";
/// Largest state file read: the vault's snapshot is the bulk of it.
const MAX_STATE: u64 = 64 * 1024 * 1024;

fn path(data_dir: &Path, peer: &PeerKey) -> PathBuf {
    let name = peer.as_bytes().iter().fold(String::new(), |mut hex, b| {
        let _ = write!(hex, "{b:02x}");
        hex
    });
    data_dir.join(DIR).join(format!("{name}.json"))
}

/// The state of the last sync with `peer`; empty if there was none or
/// the file can't be read (the next sync then asks about differences).
pub fn load(data_dir: &Path, peer: &PeerKey) -> SyncState {
    let path = path(data_dir, peer);
    std::fs::metadata(&path)
        .ok()
        .filter(|meta| meta.len() <= MAX_STATE)
        .and_then(|_| std::fs::read(&path).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

pub fn save(data_dir: &Path, peer: &PeerKey, state: &SyncState) -> AppResult<()> {
    let path = path(data_dir, peer);
    if let Some(dir) = path.parent() {
        fsutil::ensure_private_dir(dir)?;
    }
    let json = serde_json::to_vec_pretty(state)
        .map_err(|e| crate::error::AppError::new(sshkm_core::ErrorCode::Io, e.to_string()))?;
    fsutil::atomic_write(&path, &json, 0o600)?;
    Ok(())
}

/// Forgets a device that is no longer one of the user's.
pub fn forget(data_dir: &Path, peer: &PeerKey) {
    let _ = std::fs::remove_file(path(data_dir, peer));
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
}
