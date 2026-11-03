//! Crash-safe file writes and rotating backups.
//!
//! Writes go to a temporary file in the target's directory, are flushed to disk
//! and then renamed over the target, so readers (including a concurrently
//! running `ssh`) only ever see the old or the new contents. Symbolic links are
//! followed — a `~/.ssh/config` that links into a dotfiles repository stays a
//! link and the repository file is updated.

use std::{
    fmt::Write as _,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::FormatItem, macros::format_description};

use crate::{Error, Result};

/// Number of backups kept per file name; older ones are deleted.
pub const BACKUPS_TO_KEEP: usize = 20;

/// Maximum number of symbolic links followed when resolving a write target.
const MAX_SYMLINKS: usize = 40;

/// Timestamp used in backup file names (UTC, sortable).
const BACKUP_TS: &[FormatItem<'static>] =
    format_description!("[year][month][day]T[hour][minute][second].[subsecond digits:3]Z");

/// Atomically replaces the contents of `path` with `bytes`.
///
/// If the file exists its permission bits are kept; otherwise it is created
/// with `new_file_mode` (Unix only — on Windows the file inherits the ACL of its
/// directory). Symbolic links are followed and the link target is replaced.
pub fn atomic_write(path: &Path, bytes: &[u8], new_file_mode: u32) -> Result<()> {
    let target = resolve_symlinks(path)?;
    let existing = match fs::metadata(&target) {
        Ok(meta) => Some(meta.permissions()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(Error::io(e, &target)),
    };
    let tmp = write_temp(&target, bytes, existing.as_ref(), new_file_mode)?;
    tmp.persist(&target)
        .map_err(|e| Error::io(e.error, &target))?;
    sync_parent(&target);
    Ok(())
}

/// Writes a new file atomically and fails with [`Error::AlreadyExists`] if
/// `path` exists (also when it is created concurrently). The file gets `mode`
/// on Unix.
pub fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    if fs::symlink_metadata(path).is_ok() {
        return Err(Error::AlreadyExists(path.display().to_string()));
    }
    let tmp = write_temp(path, bytes, None, mode)?;
    tmp.persist_noclobber(path)
        .map_err(|e| Error::io(e.error, path))?;
    sync_parent(path);
    Ok(())
}

/// Copies `path` into `backup_dir` as `<file name>.<UTC timestamp>.bak` and
/// deletes all but the newest [`BACKUPS_TO_KEEP`] backups of that file name.
///
/// Returns the backup's path, or `None` if `path` does not exist. The backup
/// directory is created (mode 0700 on Unix) if needed and backups get 0600.
pub fn backup(path: &Path, backup_dir: &Path) -> Result<Option<PathBuf>> {
    if !path.exists() {
        return Ok(None);
    }
    let name = path
        .file_name()
        .ok_or_else(|| Error::invalid(format!("not a file: {}", path.display())))?
        .to_string_lossy()
        .into_owned();
    ensure_private_dir(backup_dir)?;

    let stamp = OffsetDateTime::now_utc()
        .format(BACKUP_TS)
        .map_err(|e| Error::Io {
            context: "formatting backup timestamp".into(),
            source: io::Error::other(e),
        })?;
    let mut dest = backup_dir.join(format!("{name}.{stamp}.bak"));
    let mut n = 1;
    while fs::symlink_metadata(&dest).is_ok() {
        dest = backup_dir.join(format!("{name}.{stamp}-{n}.bak"));
        n += 1;
    }

    let contents = fs::read(path).map_err(|e| Error::io(e, path))?;
    write_new(&dest, &contents, 0o600)?;
    prune_backups(backup_dir, &name, BACKUPS_TO_KEEP);
    Ok(Some(dest))
}

/// Lists the backups of `file_name` in `backup_dir`, oldest first.
pub fn list_backups(backup_dir: &Path, file_name: &str) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(backup_dir) else {
        return Vec::new();
    };
    let mut found: Vec<(String, u32, PathBuf)> = entries
        .filter_map(Result::ok)
        .filter_map(|e| {
            let fname = e.file_name().to_str()?.to_owned();
            let (stamp, seq) = parse_backup_name(&fname, file_name)?;
            Some((stamp.to_owned(), seq, e.path()))
        })
        .collect();
    found.sort();
    found.into_iter().map(|(_, _, p)| p).collect()
}

/// Reads at most `max` bytes; larger files are rejected with
/// [`Error::InvalidInput`] without reading them into memory.
pub(crate) fn read_limited(path: &Path, max: u64) -> Result<Vec<u8>> {
    let file = fs::File::open(path).map_err(|e| Error::io(e, path))?;
    let len = file.metadata().map_err(|e| Error::io(e, path))?.len();
    if len > max {
        return Err(Error::invalid(format!(
            "{} is larger than {max} bytes",
            path.display()
        )));
    }
    let mut buf = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    file.take(max + 1)
        .read_to_end(&mut buf)
        .map_err(|e| Error::io(e, path))?;
    if buf.len() as u64 > max {
        return Err(Error::invalid(format!(
            "{} is larger than {max} bytes",
            path.display()
        )));
    }
    Ok(buf)
}

/// SHA-256 of a file's bytes, in hex: the revision an edit is made against.
pub(crate) fn revision(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Fails with [`Error::Conflict`] unless `current` (the revision of `path`
/// as just read) is the `expected` one an edit was made against.
pub fn ensure_revision(path: &Path, current: &str, expected: &str) -> Result<()> {
    if current == expected {
        Ok(())
    } else {
        Err(Error::Conflict(path.display().to_string()))
    }
}

/// Creates `dir` (and parents) if it does not exist; a directory created here
/// gets mode 0700 on Unix.
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    match fs::metadata(dir) {
        Ok(meta) if meta.is_dir() => return Ok(()),
        Ok(_) => {
            return Err(Error::invalid(format!(
                "{} is not a directory",
                dir.display()
            )));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::io(e, dir)),
    }
    fs::create_dir_all(dir).map_err(|e| Error::io(e, dir))?;
    set_mode(dir, 0o700)?;
    Ok(())
}

/// Sets Unix permission bits (no-op on Windows).
#[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))]
pub(crate) fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|e| Error::io(e, path))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

fn write_temp(
    target: &Path,
    bytes: &[u8],
    keep: Option<&fs::Permissions>,
    mode: u32,
) -> Result<tempfile::NamedTempFile> {
    let dir = match target.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let prefix = format!(
        ".{}.",
        target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    );
    // tempfile creates the file with mode 0600 on Unix, so secrets are never
    // briefly world-readable.
    let mut tmp = tempfile::Builder::new()
        .prefix(&prefix)
        .suffix(".sshkm-tmp")
        .tempfile_in(dir)
        .map_err(|e| Error::io(e, dir))?;
    tmp.write_all(bytes).map_err(|e| Error::io(e, tmp.path()))?;
    tmp.as_file()
        .sync_all()
        .map_err(|e| Error::io(e, tmp.path()))?;
    match keep {
        #[cfg(unix)]
        Some(perms) => {
            fs::set_permissions(tmp.path(), perms.clone()).map_err(|e| Error::io(e, tmp.path()))?;
        }
        #[cfg(not(unix))]
        Some(_) => {}
        None => set_mode(tmp.path(), mode)?,
    }
    Ok(tmp)
}

/// Follows symbolic links so the final file is replaced, not the link.
fn resolve_symlinks(path: &Path) -> Result<PathBuf> {
    let mut current = path.to_path_buf();
    for _ in 0..MAX_SYMLINKS {
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                let link = fs::read_link(&current).map_err(|e| Error::io(e, &current))?;
                current = if link.is_absolute() {
                    link
                } else {
                    current.parent().unwrap_or(Path::new("")).join(link)
                };
            }
            _ => return Ok(current),
        }
    }
    Err(Error::invalid(format!(
        "too many levels of symbolic links: {}",
        path.display()
    )))
}

/// Flushes the directory entry after a rename (best effort, Unix only).
fn sync_parent(path: &Path) {
    #[cfg(unix)]
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty())
        && let Ok(dir) = fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Parses `<file_name>.<stamp>[-<n>].bak`, returning the stamp and sequence.
fn parse_backup_name<'a>(candidate: &'a str, file_name: &str) -> Option<(&'a str, u32)> {
    let rest = candidate
        .strip_prefix(file_name)?
        .strip_prefix('.')?
        .strip_suffix(".bak")?;
    let (stamp, seq) = match rest.split_once('-') {
        Some((stamp, seq)) => (stamp, seq.parse().ok()?),
        None => (rest, 0),
    };
    // 20261102T112700.123Z
    let b = stamp.as_bytes();
    let well_formed = b.len() == 20
        && b[..8].iter().all(u8::is_ascii_digit)
        && b[8] == b'T'
        && b[9..15].iter().all(u8::is_ascii_digit)
        && b[15] == b'.'
        && b[16..19].iter().all(u8::is_ascii_digit)
        && b[19] == b'Z';
    well_formed.then_some((stamp, seq))
}

fn prune_backups(backup_dir: &Path, file_name: &str, keep: usize) {
    let all = list_backups(backup_dir, file_name);
    if all.len() > keep {
        for old in &all[..all.len() - keep] {
            // Best effort: a failed prune must not fail the save it follows.
            let _ = fs::remove_file(old);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_creates_and_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        atomic_write(&path, b"one", 0o600).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"one");
        atomic_write(&path, b"two", 0o600).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        // No temp files left behind.
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_modes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        atomic_write(&path, b"x", 0o640).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o604)).unwrap();
        atomic_write(&path, b"y", 0o600).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o604
        );
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_follows_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("dotfiles-config");
        fs::write(&real, "old").unwrap();
        let link = dir.path().join("config");
        std::os::unix::fs::symlink("dotfiles-config", &link).unwrap();
        atomic_write(&link, b"new", 0o600).unwrap();
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_to_string(&real).unwrap(), "new");
    }

    #[test]
    fn write_new_refuses_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k");
        write_new(&path, b"a", 0o600).unwrap();
        let err = write_new(&path, b"b", 0o600).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::AlreadyExists);
        assert_eq!(fs::read(&path).unwrap(), b"a");
    }

    #[test]
    fn backup_rotates() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("config");
        let backups = dir.path().join("backups");
        assert!(backup(&file, &backups).unwrap().is_none());
        fs::write(&file, "v").unwrap();
        // An unrelated file with a similar prefix must survive pruning.
        fs::create_dir_all(&backups).unwrap();
        fs::write(backups.join("config.d.20200101T000000.000Z.bak"), "x").unwrap();
        for _ in 0..(BACKUPS_TO_KEEP + 5) {
            backup(&file, &backups).unwrap().unwrap();
        }
        assert_eq!(list_backups(&backups, "config").len(), BACKUPS_TO_KEEP);
        assert!(backups.join("config.d.20200101T000000.000Z.bak").exists());
        let newest = list_backups(&backups, "config").pop().unwrap();
        assert_eq!(fs::read_to_string(newest).unwrap(), "v");
    }

    #[test]
    fn backup_name_parsing() {
        assert_eq!(
            parse_backup_name("config.20261102T112700.123Z.bak", "config"),
            Some(("20261102T112700.123Z", 0))
        );
        assert_eq!(
            parse_backup_name("config.20261102T112700.123Z-3.bak", "config"),
            Some(("20261102T112700.123Z", 3))
        );
        assert_eq!(parse_backup_name("config.bak", "config"), None);
        assert_eq!(parse_backup_name("known_hosts.x.bak", "known_hosts"), None);
    }

    #[test]
    fn revisions() {
        assert_eq!(
            revision(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_ne!(revision(b"a"), revision(b"b"));
        let path = Path::new("known_hosts");
        ensure_revision(path, &revision(b"a"), &revision(b"a")).unwrap();
        assert_eq!(
            ensure_revision(path, &revision(b"b"), &revision(b"a"))
                .unwrap_err()
                .code(),
            crate::ErrorCode::Conflict
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_dir_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path().join("home").join(".ssh");
        ensure_private_dir(&ssh).unwrap();
        assert_eq!(
            fs::metadata(&ssh).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let file = dir.path().join("file");
        fs::write(&file, "x").unwrap();
        assert_eq!(
            ensure_private_dir(&file).unwrap_err().code(),
            crate::ErrorCode::InvalidInput
        );
    }

    #[test]
    fn read_limited_rejects_large_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big");
        fs::write(&path, vec![b'a'; 100]).unwrap();
        assert!(read_limited(&path, 100).is_ok());
        assert_eq!(
            read_limited(&path, 99).unwrap_err().code(),
            crate::ErrorCode::InvalidInput
        );
    }
}
