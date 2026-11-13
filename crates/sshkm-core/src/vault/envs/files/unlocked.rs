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
//!
//! A round also lists each write as it makes it, before anything is written
//! (`disk::write`): the file's temporary files, which hold its values while
//! it is written ([`Leftover::temps_of`]), and a level-2 file as it will be,
//! before it takes its place, next to what was listed for it before. So a
//! crash in the middle of a round leaves nothing the guard and the next
//! start don't remove. The round's own list replaces all that at its end.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::folder::{self, Folder};
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
/// An edit changes the time and usually the length; on a file system that
/// keeps times to two seconds (FAT, exFAT), an edit of the same length
/// within those two seconds, followed at once by a crash, isn't told apart.
/// No more is kept, since anything made from the contents (a hash) would
/// let values be guessed from the list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Stamp {
    id: String,
    len: u64,
    /// Seconds and nanoseconds since 1970.
    modified: (i64, u32),
}

impl Stamp {
    /// What no file is: listed, it stands for a file's temporary files
    /// only ([`Leftover::temps_of`]). Every file has an id; this has none.
    fn none() -> Self {
        Self {
            id: String::new(),
            len: 0,
            modified: (0, 0),
        }
    }

    /// The stamp of the regular file at `path`, not following a link.
    fn of(path: &Path) -> Option<Self> {
        Self::of_meta(&fs::symlink_metadata(path).ok()?)
    }

    /// The stamp of the regular file named `name` in `folder`, held, not
    /// following a link.
    #[cfg(unix)]
    fn in_folder(folder: &Folder, name: &str) -> Option<Self> {
        let entry = folder.entry(name).ok()??;
        (entry.kind == folder::Kind::File).then_some(Self {
            id: format!("{}:{}", entry.dev, entry.ino),
            len: entry.len,
            modified: entry.modified?,
        })
    }

    /// By path, which leads nowhere else while the folder is held.
    #[cfg(not(unix))]
    fn in_folder(folder: &Folder, name: &str) -> Option<Self> {
        Self::of(&folder.path().join(name))
    }

    fn of_meta(meta: &fs::Metadata) -> Option<Self> {
        if !meta.is_file() {
            return None;
        }
        let modified = meta
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        Some(Self {
            id: file_id(meta),
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

    /// The file at `path` as `meta` describes it (a file about to take its
    /// place), if it is a regular file.
    pub fn of_meta(path: &Path, meta: &fs::Metadata) -> Option<Self> {
        Some(Self {
            stamp: Stamp::of_meta(meta)?,
            path: path.to_path_buf(),
        })
    }

    /// The temporary files of writes to `path`, and never the file itself:
    /// listed before a write, so what a crash in the middle leaves is
    /// swept.
    pub fn temps_of(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            stamp: Stamp::none(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Removes the file if it is still as it was, with the temporary files
    /// of its writes a crash left next to it. The file is looked at and
    /// removed through its folder, held, so what is removed is what was
    /// looked at. Returns whether it removed the file.
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
        fsutil::sweep_private_temps(&self.path);
        folder::sweep_staging(&self.path);
        if self.stamp.id.is_empty() {
            return false;
        }
        let Ok((folder, name)) = folder::open_parent(&self.path) else {
            return false;
        };
        Stamp::in_folder(&folder, name).as_ref() == Some(&self.stamp) && folder.remove(name).is_ok()
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

    /// Adds `file` to the list kept at `path`, keeping everything listed
    /// there, the same file as it was before included: until a round ends
    /// either may be on disk.
    pub fn add_at(path: &Path, file: Leftover) -> Result<()> {
        let mut list = Self::load(path);
        if !list.files.contains(&file) {
            if list.files.len() >= MAX_LEFTOVERS {
                return Err(Error::invalid("too many files to list"));
            }
            list.files.push(file);
        }
        list.save(path)
    }

    /// Removes every file still as it was, and forgets them all: one that
    /// changed since is the user's now, until the next unlock settles it.
    /// Returns how many it removed.
    pub fn sweep(&mut self) -> usize {
        let removed = self.files.iter().filter(|file| file.remove()).count();
        self.files.clear();
        removed
    }

    /// Removes the files of this list, the one kept before a round, that the
    /// round's list `now` no longer has and that aren't level-1 files
    /// (`always`), if they are still as they were: their binding went (it
    /// was removed here or on another computer, or its environment was
    /// deleted), so nothing would remove them later. Returns how many it
    /// removed.
    pub fn sweep_dropped(&self, now: &Self, always: &[PathBuf]) -> usize {
        self.files
            .iter()
            .filter(|file| !now.files.iter().any(|kept| kept.path == file.path))
            .filter(|file| !always.contains(&file.path))
            .filter(|file| file.remove())
            .count()
    }

    /// Forgets the file at `path`, which the user keeps: no sweep removes
    /// it. Found by its path, or by which file it is on disk, since a path
    /// can name it in another case where the file system ignores case.
    /// Returns whether it was listed.
    pub fn forget(&mut self, path: &Path) -> bool {
        let id = Stamp::of(path).map(|stamp| stamp.id);
        let before = self.files.len();
        self.files
            .retain(|file| file.path != path && Some(&file.stamp.id) != id.as_ref());
        self.files.len() != before
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
    PutAway {
        removed,
        kept: left_on_disk(&synced.files),
    }
}

/// The level-2 files of `files` that are on disk and that a lock leaves
/// there: those the vault couldn't take.
pub fn left_on_disk(files: &[EnvFileStatus]) -> Vec<EnvFileStatus> {
    files
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
        .collect()
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

        // Replaced by another file of the same size: it stays. (Unix tells
        // the files apart by inode; NTFS may give the new one the old one's
        // creation time, and its time of change tells them apart there.)
        #[cfg(unix)]
        {
            let kept = Leftover::of(&path).unwrap();
            let other = dir.path().join("other");
            fs::write(&other, "A=2\n").unwrap();
            fs::rename(&other, &path).unwrap();
            assert!(!kept.remove());
            assert!(path.exists());
        }
    }

    #[test]
    fn a_write_listed_before_it_is_made_leaves_nothing_after_a_crash() {
        let dir = tempfile::tempdir().unwrap();
        let list_path = dir.path().join("list.json");
        let path = dir.path().join(".env");
        fs::write(&path, "A=1\n").unwrap();
        let before = Leftover::of(&path).unwrap();
        Leftovers::add_at(&list_path, before.clone()).unwrap();
        Leftovers::add_at(&list_path, Leftover::temps_of(&path)).unwrap();
        Leftovers::add_at(&list_path, before).unwrap();
        // The new file, about to take its place.
        let new = dir.path().join(".env.sshkm-Ab12Cd.tmp");
        fs::write(&new, "A=2, longer\n").unwrap();
        let meta = fs::metadata(&new).unwrap();
        Leftovers::add_at(&list_path, Leftover::of_meta(&path, &meta).unwrap()).unwrap();
        assert_eq!(Leftovers::load(&list_path).files.len(), 3);
        // The app went before it was renamed: the old file and the
        // temporary one go.
        let mut list = Leftovers::load(&list_path);
        assert_eq!(list.clone().sweep(), 1);
        assert!(!path.exists() && !new.exists());
        // Or after: the new one goes.
        fs::write(&new, "A=2, longer\n").unwrap();
        let meta = fs::metadata(&new).unwrap();
        list.files.push(Leftover::of_meta(&path, &meta).unwrap());
        fs::rename(&new, &path).unwrap();
        assert_eq!(list.sweep(), 1);
        assert!(!path.exists());
        // Temporary files only: the file itself always stays.
        fs::write(&path, "A=3\n").unwrap();
        fs::write(&new, "A=3\n").unwrap();
        assert!(!Leftover::temps_of(&path).remove());
        assert!(path.exists() && !new.exists());
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

    #[test]
    fn files_no_longer_listed_go_unless_bound_otherwise() {
        let dir = tempfile::tempdir().unwrap();
        let [a, b, c] = [".env", ".env.local", ".env.test"].map(|name| dir.path().join(name));
        for path in [&a, &b, &c] {
            fs::write(path, "A=1\n").unwrap();
        }
        let mut before = Leftovers::new(
            [&a, &b, &c]
                .map(|path| Leftover::of(path).unwrap())
                .to_vec(),
        );
        // `b` is still listed; `c` is a level-1 file now.
        let now = Leftovers::new(vec![Leftover::of(&b).unwrap()]);
        assert_eq!(before.sweep_dropped(&now, std::slice::from_ref(&c)), 1);
        assert!(!a.exists());
        assert!(b.exists() && c.exists());
        // One the user keeps is forgotten, and no sweep takes it, however
        // its path is spelt.
        assert!(before.forget(&dir.path().join(".").join(".env.local")));
        assert!(!before.forget(&b));
        assert_eq!(
            before.sweep_dropped(&Leftovers::default(), std::slice::from_ref(&c)),
            0
        );
        assert!(b.exists());
    }
}
