//! The level-2 files on disk ([`super::FileLevel::WhileUnlocked`]), so they
//! can be removed without the vault: when it locks, when the app quits, and
//! after a crash or a forced quit, by the app's guard process or at the next
//! start.
//!
//! After each round the app keeps a list of the level-2 files that hold what
//! the vault holds, each with what it was on disk then: its identity, size
//! and time of last change ([`Leftover`]). No value, nor a hash of one, is
//! kept. Removing goes by that list: a file still as it was is removed; one
//! that changed since (an edit the vault hasn't taken yet) stays, so nothing
//! the user typed is lost, and the next unlock settles it.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{EnvFileStatus, EnvFilesSynced, FileLevel, FileState};
use crate::{Error, Result, fsutil};

/// Most files a list keeps.
const MAX_LEFTOVERS: usize = 4096;

/// A level-2 file as the app left it, holding what the vault holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leftover {
    /// The file, in its folder with links resolved.
    path: PathBuf,
    stamp: Stamp,
}

/// What a file is on disk: which file (device and inode on Unix, its
/// creation time on Windows), how long, and when its contents last changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Stamp {
    id: String,
    len: u64,
    /// Seconds and nanoseconds since 1970.
    modified: (i64, u32),
}

impl Stamp {
    /// The stamp of the regular file at `path`, not following a link.
    fn of(path: &Path) -> Option<Self> {
        let meta = fs::symlink_metadata(path).ok()?;
        if !meta.is_file() {
            return None;
        }
        let modified = meta
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        Some(Self {
            id: file_id(&meta),
            len: meta.len(),
            modified: (
                i64::try_from(modified.as_secs()).ok()?,
                modified.subsec_nanos(),
            ),
        })
    }
}

#[cfg(unix)]
fn file_id(meta: &fs::Metadata) -> String {
    use std::os::unix::fs::MetadataExt;
    format!("{}:{}", meta.dev(), meta.ino())
}

#[cfg(windows)]
fn file_id(meta: &fs::Metadata) -> String {
    use std::os::windows::fs::MetadataExt;
    meta.creation_time().to_string()
}

#[cfg(not(any(unix, windows)))]
fn file_id(_: &fs::Metadata) -> String {
    String::new()
}

impl Leftover {
    /// The file at `path` as it is now, if it is a regular file.
    pub fn of(path: &Path) -> Option<Self> {
        Some(Self {
            stamp: Stamp::of(path)?,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Removes the file if it is still as it was, with the temporary files
    /// of its writes a crash left next to it. Returns whether it removed
    /// the file.
    pub fn remove(&self) -> bool {
        // Only ever a `.env` file: a list someone else wrote names nothing
        // else that goes.
        let named_so = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(super::is_env_file_name);
        if !named_so {
            return false;
        }
        self.sweep_temporaries();
        if Stamp::of(&self.path).as_ref() != Some(&self.stamp) {
            return false;
        }
        fs::remove_file(&self.path).is_ok()
    }

    /// Removes the temporary files of the file's writes a crash left next
    /// to it: they hold its values in plain text.
    fn sweep_temporaries(&self) {
        let (Some(dir), Some(name)) = (
            self.path.parent(),
            self.path.file_name().and_then(|name| name.to_str()),
        ) else {
            return;
        };
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.filter_map(std::result::Result::ok) {
            let leftover = entry
                .file_name()
                .to_str()
                .is_some_and(|found| fsutil::is_private_temp(found, name));
            if leftover && entry.file_type().is_ok_and(|kind| kind.is_file()) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

/// The level-2 files on disk, as the app keeps them in its data folder.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leftovers {
    #[serde(default)]
    files: Vec<Leftover>,
}

impl Leftovers {
    pub fn new(files: Vec<Leftover>) -> Self {
        let mut files = files;
        files.truncate(MAX_LEFTOVERS);
        Self { files }
    }

    /// The list kept at `path`; empty if there is none or it can't be read.
    pub fn load(path: &Path) -> Self {
        fsutil::read_limited(path, 4 * 1024 * 1024)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .map(|list: Self| Self::new(list.files))
            .unwrap_or_default()
    }

    /// Keeps the list at `path`, readable by this user only; an empty one
    /// removes the file.
    pub fn save(&self, path: &Path) -> Result<()> {
        if self.files.is_empty() {
            return match fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(Error::io(e, path)),
            };
        }
        let json = serde_json::to_vec(self).map_err(|e| Error::Parse(format!("{e}")))?;
        if fs::read(path).is_ok_and(|current| current == json) {
            return Ok(());
        }
        fsutil::atomic_write(path, &json, 0o600)
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Removes every file still as it was, and forgets them all: one that
    /// changed since is the user's now, until the next unlock settles it.
    /// Returns how many it removed.
    pub fn sweep(&mut self) -> usize {
        let removed = self.files.iter().filter(|file| file.remove()).count();
        self.files.clear();
        removed
    }

    /// Removes the files kept at `path` that are still as they were, and
    /// the list with them: after a crash or a forced quit, without the
    /// vault. Returns how many it removed.
    pub fn sweep_at(path: &Path) -> usize {
        let mut list = Self::load(path);
        if list.is_empty() {
            return 0;
        }
        let removed = list.sweep();
        let _ = list.save(path);
        removed
    }
}

/// What putting the level-2 files away did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PutAway {
    /// How many files went.
    pub removed: usize,
    /// The files that stay: the vault couldn't take what they hold (both
    /// sides changed, lines that can't be read) or they changed after the
    /// last round. The next unlock settles them.
    pub kept: Vec<EnvFileStatus>,
}

/// Removes the level-2 files after `synced`, a round just made: each one
/// that holds what the vault holds and is still as the round left it. The
/// others stay, and are named.
pub fn put_away(synced: &EnvFilesSynced) -> PutAway {
    let mut leftovers = Leftovers::new(synced.unlocked.clone());
    let removed = leftovers.sweep();
    let kept = synced
        .files
        .iter()
        .filter(|status| status.level == FileLevel::WhileUnlocked)
        .filter(|status| {
            !matches!(
                status.state,
                FileState::Missing
                    | FileState::FolderMissing
                    | FileState::Inactive { .. }
                    | FileState::Refused { .. }
                    | FileState::Duplicate
            )
        })
        .filter(|status| {
            status
                .location
                .as_deref()
                .is_some_and(|location| fs::symlink_metadata(location).is_ok_and(|m| m.is_file()))
        })
        .cloned()
        .collect();
    PutAway { removed, kept }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_file_as_it_was_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        fs::write(&path, "A=1\n").unwrap();
        let kept = Leftover::of(&path).unwrap();
        let temp = dir.path().join(".env.sshkm-Ab12Cd.tmp");
        fs::write(&temp, "A=1\n").unwrap();
        assert!(kept.remove());
        assert!(!path.exists());
        assert!(!temp.exists());

        // Edited after: it stays.
        fs::write(&path, "A=1\n").unwrap();
        let kept = Leftover::of(&path).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(&path, "A=2\n").unwrap();
        assert!(!kept.remove());
        assert!(path.exists());

        // Replaced by another file of the same size and time: it stays.
        let kept = Leftover::of(&path).unwrap();
        let other = dir.path().join("other");
        fs::write(&other, "A=2\n").unwrap();
        fs::rename(&other, &path).unwrap();
        #[cfg(unix)]
        assert!(!kept.remove());
        assert!(path.exists());
    }

    #[test]
    fn a_list_is_swept_once_and_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let list_path = dir.path().join("list.json");
        let a = dir.path().join(".env");
        let b = dir.path().join(".env.local");
        fs::write(&a, "A=1\n").unwrap();
        fs::write(&b, "B=1\n").unwrap();
        let other = dir.path().join("notes.txt");
        fs::write(&other, "x").unwrap();
        let list = Leftovers::new(vec![
            Leftover::of(&a).unwrap(),
            Leftover::of(&b).unwrap(),
            // Never a file that isn't a `.env` file.
            Leftover::of(&other).unwrap(),
        ]);
        list.save(&list_path).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(&b, "B=2\n").unwrap();
        assert_eq!(Leftovers::sweep_at(&list_path), 1);
        assert!(!a.exists());
        assert!(b.exists());
        assert!(other.exists());
        // The list went with them: nothing is removed later by it.
        assert!(!list_path.exists());
        assert_eq!(Leftovers::sweep_at(&list_path), 0);
        // A list that can't be read is no list.
        fs::write(&list_path, "{").unwrap();
        assert!(Leftovers::load(&list_path).is_empty());
    }
}
