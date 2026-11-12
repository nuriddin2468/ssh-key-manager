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

/// Atomically replaces `path` with `bytes` in a file that only this user,
/// `SYSTEM` and `Administrators` can open (Windows), for secrets in plain
/// text. Unlike [`atomic_write`], whose temporary file has the folder's
/// access list until it is renamed, the temporary file gets its own
/// protected access list as it is created, and no one else can open it
/// while it is written ([`crate::perms::create_private`]). Where the file
/// system can't keep that access list (FAT, exFAT, some network shares),
/// nothing is written and the call fails with [`Error::Unsupported`].
#[cfg(windows)]
pub(crate) fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let target = resolve_symlinks(path)?;
    let (_, prefix) = temp_location(&target);
    write_private_at(&target, bytes, &prefix, ".sshkm-tmp", true, false).map(drop)
}

/// What the temporary file of [`replace_private`] for a file named `name`
/// is called between its prefix and suffix: `.env.sshkm-Ab12Cd.tmp`, so
/// that the rules that keep `.env*` files out of Git and backups keep it
/// out too.
const PRIVATE_TEMP: (&str, &str) = (".sshkm-", ".tmp");

/// Whether `name` is a temporary file [`replace_private`] makes for the file
/// named `of`, which a crash may have left behind.
pub fn is_private_temp(name: &str, of: &str) -> bool {
    name.strip_prefix(of)
        .and_then(|rest| rest.strip_prefix(PRIVATE_TEMP.0))
        .is_some_and(|rest| rest.len() > PRIVATE_TEMP.1.len() && rest.ends_with(PRIVATE_TEMP.1))
}

/// Removes the temporary files of [`replace_private`]'s writes to `path`
/// that a crash left next to it: they may hold its contents in plain text.
/// Only regular files are removed.
pub fn sweep_private_temps(path: &Path) {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) else {
        return;
    };
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(std::result::Result::ok) {
        let leftover = entry
            .file_name()
            .to_str()
            .is_some_and(|found| is_private_temp(found, name));
        if leftover && entry.file_type().is_ok_and(|kind| kind.is_file()) {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// Replaces `path` with a new file that holds `bytes` and that only this
/// user can read: mode 0600 on Unix; on Windows an access list for nobody
/// but the user, `SYSTEM` and `Administrators`, set as the file is made,
/// as [`atomic_write_private`] does. Unlike [`atomic_write`], a symbolic
/// link at `path` is never followed: the new file is renamed over whatever
/// is there, a link included. Without `overwrite`, nothing is written if
/// something is at `path` by then, and the call returns `false`. With
/// `keep_out`, the new file is kept out of backups and cloud folders
/// ([`keep_out_of_copies`]) before it is renamed into place; on Unix before
/// it holds anything.
pub fn replace_private(path: &Path, bytes: &[u8], overwrite: bool, keep_out: bool) -> Result<bool> {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let prefix = format!("{name}{}", PRIVATE_TEMP.0);
    #[cfg(windows)]
    {
        write_private_at(path, bytes, &prefix, PRIVATE_TEMP.1, overwrite, keep_out)
    }
    #[cfg(not(windows))]
    {
        let (dir, _) = temp_location(path);
        let mut tmp = tempfile::Builder::new()
            .prefix(&prefix)
            .suffix(PRIVATE_TEMP.1)
            .tempfile_in(dir)
            .map_err(|e| Error::io(e, dir))?;
        // tempfile makes it 0600; set again in case a umask or ACL differs.
        set_mode(tmp.path(), 0o600)?;
        if keep_out {
            keep_out_of_copies(tmp.as_file());
        }
        tmp.write_all(bytes).map_err(|e| Error::io(e, tmp.path()))?;
        tmp.as_file()
            .sync_all()
            .map_err(|e| Error::io(e, tmp.path()))?;
        let persisted = if overwrite {
            tmp.persist(path).map(drop)
        } else {
            tmp.persist_noclobber(path).map(drop)
        };
        match persisted {
            Ok(()) => {}
            Err(e) if !overwrite && e.error.kind() == io::ErrorKind::AlreadyExists => {
                return Ok(false);
            }
            Err(e) => return Err(Error::io(e.error, path)),
        }
        sync_parent(path);
        Ok(true)
    }
}

/// The private write of [`atomic_write_private`] to `target` as it is,
/// through a temporary file named `<prefix>…<suffix>`. Returns `false`
/// when `overwrite` is off and something is at `target`.
#[cfg(windows)]
fn write_private_at(
    target: &Path,
    bytes: &[u8],
    prefix: &str,
    suffix: &str,
    overwrite: bool,
    keep_out: bool,
) -> Result<bool> {
    let (dir, _) = temp_location(target);
    let created = tempfile::Builder::new()
        .prefix(prefix)
        .suffix(suffix)
        .make_in(dir, crate::perms::create_private);
    let (mut file, tmp) = match created {
        Ok(created) => created.into_parts(),
        Err(e) if e.kind() == io::ErrorKind::Unsupported => {
            return Err(Error::Unsupported(format!("{}: {e}", dir.display())));
        }
        Err(e) => return Err(Error::io(e, dir)),
    };
    // Out of copies before it holds anything, where the stream can be
    // written while the file is open; else once it is closed, below.
    if keep_out {
        keep_out_of_copies_at(&tmp);
    }
    // No one else may open the file while `file` is open, so it is closed
    // before `tmp` renames it, or removes it when dropped on an error.
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    written.map_err(|e| Error::io(e, &tmp))?;
    if keep_out {
        keep_out_of_copies_at(&tmp);
    }
    let persisted = if overwrite {
        tmp.persist(target)
    } else {
        tmp.persist_noclobber(target)
    };
    match persisted {
        Ok(()) => Ok(true),
        Err(e) if !overwrite && e.error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(Error::io(e.error, target)),
    }
}

/// The extended attributes that keep a file out of backups and cloud
/// folders, where the system reads one:
///
/// - macOS: Time Machine's sticky exclusion (what `tmutil addexclusion`
///   sets, a property list naming `com.apple.backupd`), Dropbox's
///   `com.dropbox.ignored`, and `com.apple.fileprovider.ignore#P`, which
///   the folders kept by File Provider (iCloud Drive, Dropbox and `OneDrive`
///   in `~/Library/CloudStorage`) honour;
/// - Linux: Dropbox's `user.com.dropbox.ignored`.
///
/// On Windows Dropbox reads the stream `com.dropbox.ignored` instead
/// (`DROPBOX_STREAM`); `OneDrive` and File History have nothing per file.
#[cfg(target_os = "macos")]
const COPIES_ATTRIBUTES: [(&str, &[u8]); 3] = [
    (
        "com.apple.metadata:com_apple_backup_excludeItem",
        &TIME_MACHINE_EXCLUDED,
    ),
    ("com.dropbox.ignored", b"1"),
    ("com.apple.fileprovider.ignore#P", b"1"),
];
#[cfg(target_os = "linux")]
const COPIES_ATTRIBUTES: [(&str, &[u8]); 1] = [("user.com.dropbox.ignored", b"1")];

/// The binary property list of the string `com.apple.backupd`, as
/// `tmutil addexclusion` writes it.
#[cfg(target_os = "macos")]
const TIME_MACHINE_EXCLUDED: [u8; 61] = {
    let mut plist = [0u8; 61];
    let head = b"bplist00_\x10\x11com.apple.backupd\x08";
    let mut i = 0;
    while i < head.len() {
        plist[i] = head[i];
        i += 1;
    }
    // The trailer: one-byte offsets and references, one object, the top
    // one first, the offset table at 28.
    plist[35] = 1;
    plist[36] = 1;
    plist[44] = 1;
    plist[60] = 0x1c;
    plist
};

/// The alternate data stream Dropbox reads on Windows.
#[cfg(windows)]
const DROPBOX_STREAM: &str = ":com.dropbox.ignored";

/// Keeps the open file out of backups and cloud folders where the system
/// allows it ([`COPIES_ATTRIBUTES`]). Best effort: a file system without
/// extended attributes (FAT, some network shares) keeps none, and nothing
/// fails because of that.
#[cfg(not(windows))]
fn keep_out_of_copies(file: &fs::File) {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use xattr::FileExt as _;
        for (name, value) in COPIES_ATTRIBUTES {
            let _ = file.set_xattr(name, value);
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let _ = file;
}

/// Keeps the file at `path` out of backups and cloud folders, as
/// [`keep_out_of_copies`] does, without following a link at `path`. Only
/// the attributes it lacks are set: setting one is a change the file's
/// watcher reports, and one the file system refuses is not set again and
/// again.
pub fn keep_out_of_copies_at(path: &Path) {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    for (name, value) in COPIES_ATTRIBUTES {
        if xattr::get(path, name).ok().flatten().as_deref() != Some(value) {
            let _ = xattr::set(path, name, value);
        }
    }
    #[cfg(windows)]
    if fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file()) && !is_kept_out_of_copies(path) {
        let mut stream = path.as_os_str().to_owned();
        stream.push(DROPBOX_STREAM);
        let _ = fs::write(PathBuf::from(stream), b"1");
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    let _ = path;
}

/// Lets backups and cloud folders take the file at `path` again: the
/// attributes of [`keep_out_of_copies_at`] removed.
pub fn let_into_copies_at(path: &Path) {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    for (name, _) in COPIES_ATTRIBUTES {
        let _ = xattr::remove(path, name);
    }
    #[cfg(windows)]
    if fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file()) {
        let mut stream = path.as_os_str().to_owned();
        stream.push(DROPBOX_STREAM);
        let _ = fs::remove_file(PathBuf::from(stream));
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    let _ = path;
}

/// Whether the file at `path` has every attribute [`keep_out_of_copies_at`]
/// sets. Where the system has none to set, it is as kept out as it gets.
pub fn is_kept_out_of_copies(path: &Path) -> bool {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        COPIES_ATTRIBUTES
            .iter()
            .all(|(name, value)| xattr::get(path, name).ok().flatten().as_deref() == Some(*value))
    }
    #[cfg(windows)]
    {
        let mut stream = path.as_os_str().to_owned();
        stream.push(DROPBOX_STREAM);
        fs::read(PathBuf::from(stream)).is_ok_and(|value| value == b"1")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        let _ = path;
        true
    }
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
    let (dir, prefix) = temp_location(target);
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

/// Where the temporary file for `target` goes, and how its name starts:
/// next to the target, as `.<file name>.`.
fn temp_location(target: &Path) -> (&Path, String) {
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
    (dir, prefix)
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
    fn files_kept_out_of_copies_are_so_from_the_start() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        assert!(replace_private(&path, b"A=1\n", false, true).unwrap());
        // A temporary folder whose file system keeps no attributes (tmpfs
        // before Linux 6.6) leaves nothing to check; macOS and Windows keep
        // them.
        let kept_out = is_kept_out_of_copies(&path);
        let kept_by_system: bool = cfg!(any(target_os = "macos", windows));
        assert!(kept_out || !kept_by_system);
        if !kept_out {
            return;
        }
        #[cfg(target_os = "macos")]
        {
            let out = std::process::Command::new("tmutil")
                .arg("isexcluded")
                .arg(&path)
                .output()
                .unwrap();
            assert!(String::from_utf8_lossy(&out.stdout).contains("[Excluded]"));
        }
        // Written again, the new file is kept out too.
        assert!(replace_private(&path, b"A=2\n", true, true).unwrap());
        assert!(is_kept_out_of_copies(&path));
        let_into_copies_at(&path);
        assert!(!is_kept_out_of_copies(&path));
        keep_out_of_copies_at(&path);
        assert!(is_kept_out_of_copies(&path));
        // A plain write keeps nothing out.
        assert!(replace_private(&path, b"A=3\n", true, false).unwrap());
        assert!(!is_kept_out_of_copies(&path));
    }

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

    #[cfg(windows)]
    #[test]
    fn private_writes_are_private_from_the_start() {
        use crate::perms::{PermKind, check};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passwords.csv");
        atomic_write_private(&path, b"one").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"one");
        let report = check(&path, PermKind::PrivateKey);
        assert!(report.ok, "{report:?}");
        // A file made the ordinary way is replaced by a private one.
        fs::remove_file(&path).unwrap();
        fs::write(&path, "ordinary").unwrap();
        atomic_write_private(&path, b"two").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        let report = check(&path, PermKind::PrivateKey);
        assert!(report.ok, "{report:?}");
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
    fn private_replacements_are_owner_only_and_never_follow_a_link() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        fs::write(&path, "OLD=1\n").unwrap();
        assert!(replace_private(&path, b"NEW=1\n", true, false).unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"NEW=1\n");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        // Without overwriting, a file that is there stays.
        assert!(!replace_private(&path, b"OTHER=1\n", false, false).unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"NEW=1\n");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        let new = dir.path().join("app.env");
        assert!(replace_private(&new, b"A=1\n", false, false).unwrap());
        assert_eq!(fs::read(&new).unwrap(), b"A=1\n");
        // The temporary file is named like the file, for `.env*` rules.
        assert!(is_private_temp(".env.sshkm-Ab12Cd.tmp", ".env"));
        assert!(is_private_temp("app.env.sshkm-x.tmp", "app.env"));
        assert!(!is_private_temp(".env.local", ".env"));
        assert!(!is_private_temp(".env.sshkm-.tmp", ".env"));
        assert!(!is_private_temp(".env.sshkm-x.tmp", ".env.local"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let elsewhere = dir.path().join("elsewhere");
            fs::write(&elsewhere, "keep").unwrap();
            fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
            replace_private(&path, b"NEW=2\n", true, false).unwrap();
            assert_eq!(fs::read_to_string(&elsewhere).unwrap(), "keep");
            assert!(
                !fs::symlink_metadata(&path)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(fs::read(&path).unwrap(), b"NEW=2\n");
        }
        #[cfg(windows)]
        {
            use crate::perms::{PermKind, check};
            let report = check(&path, PermKind::PrivateKey);
            assert!(report.ok, "{report:?}");
        }
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
