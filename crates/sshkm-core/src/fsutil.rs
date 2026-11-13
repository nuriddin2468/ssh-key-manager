//! Crash-safe file writes and rotating backups.
//!
//! Writes go to a temporary file in the target's directory, are flushed to disk
//! and then renamed over the target, so readers (including a concurrently
//! running `ssh`) only ever see the old or the new contents.
//!
//! - [`atomic_write`] and [`atomic_write_private`], for the app's own files and
//!   those in `~/.ssh`, follow symbolic links: a `~/.ssh/config` that links
//!   into a dotfiles repository stays a link and the repository file is
//!   updated.
//! - [`write_private`] and [`replace_private`], for secrets written where the
//!   user picks (exports, converted keys, `.env` files), never do: the new file
//!   is renamed onto the path itself, and a link there is replaced.
//!
//! A file only this user may read is so from the moment it exists: mode 0600,
//! on macOS made in a new folder of its own whose access list hands nothing
//! down ([`private_folder`]), on Windows with an access list of its own, set
//! as it is created.

use std::{
    fmt::Write as _,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::FormatItem, macros::format_description};

use crate::{Error, Result};

#[cfg(target_os = "macos")]
pub(crate) mod private_folder;

/// Number of backups kept per file name; older ones are deleted.
pub const BACKUPS_TO_KEEP: usize = 20;
/// Days a backup taken before another device's deletions is kept
/// ([`keep_backup`]), whatever backups come after it.
pub const KEPT_DAYS: i64 = 30;

/// Maximum number of symbolic links followed when resolving a write target.
const MAX_SYMLINKS: usize = 40;

/// Timestamp used in backup file names (UTC, sortable).
const BACKUP_TS: &[FormatItem<'static>] =
    format_description!("[year][month][day]T[hour][minute][second].[subsecond digits:3]Z");

/// `C:\…` for `\\?\C:\…`, which [`fs::canonicalize`] returns on Windows and
/// not every tool takes (Command Prompt refuses it as a working folder);
/// other paths are returned unchanged.
pub fn without_verbatim_prefix(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest)
            if rest.as_bytes().get(1) == Some(&b':')
                && rest.as_bytes().first().is_some_and(u8::is_ascii_alphabetic) =>
        {
            PathBuf::from(rest)
        }
        _ => path,
    }
}

/// Atomically replaces the contents of `path` with `bytes`.
///
/// If the file exists its permission bits are kept; otherwise it is created
/// with `new_file_mode` (Unix only — on Windows the file inherits the ACL of its
/// directory). Symbolic links are followed and the link target is replaced.
/// For a file that must stay private, see [`atomic_write_private`].
pub fn atomic_write(path: &Path, bytes: &[u8], new_file_mode: u32) -> Result<()> {
    let target = resolve_symlinks(path)?;
    let existing = match fs::metadata(&target) {
        Ok(meta) => Some(meta.permissions()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(Error::io(e, &target)),
    };
    write_and_rename(&target, bytes, existing.as_ref(), new_file_mode, true)
}

/// [`atomic_write`] for a file only this user may open, such as a private
/// key in `~/.ssh`. A symbolic link at `path` is followed, as there, but
/// the file it replaces never passes on more than its owner's permissions.
///
/// - Unix: the new file gets the old one's mode without the group and other
///   bits (a 0400 key stays 0400, a 0644 one becomes 0600), or 0600 if
///   nothing is there; on macOS it is made in a folder of its own, so it
///   never carries the entries a folder's access list hands down
///   ([`private_folder`]).
/// - Windows: the file is created with an access list for nobody but this
///   user, `SYSTEM` and `Administrators`, and no one else can open it while
///   it is written ([`crate::perms::create_private`]). Where the file system
///   can't keep that list (FAT, exFAT, some network shares), nothing is
///   written and the call fails with [`Error::Unsupported`].
pub fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let target = resolve_symlinks(path)?;
    #[cfg(windows)]
    {
        let (_, prefix) = temp_location(&target);
        write_private_at(&target, bytes, &prefix, TEMP_SUFFIX, true, false).map(drop)
    }
    #[cfg(not(windows))]
    {
        write_and_rename(&target, bytes, None, owner_bits(&target)?, true)
    }
}

/// Writes `bytes` to a new file next to `target`, with `keep`'s mode or
/// else `mode`, and renames it onto `target`: over what is there with
/// `replace`, else only where nothing is ([`Error::AlreadyExists`]). On
/// macOS a file only its owner may open (no group or other bits) is made
/// in a folder of its own ([`write_in_private_folder`]).
fn write_and_rename(
    target: &Path,
    bytes: &[u8],
    keep: Option<&fs::Permissions>,
    mode: u32,
    replace: bool,
) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = keep.map_or(mode, PermissionsExt::mode) & 0o7777;
        let shared = mode & 0o077 != 0;
        if !shared {
            return if write_in_private_folder(target, bytes, mode, replace, false)? {
                Ok(())
            } else {
                Err(Error::AlreadyExists(target.display().to_string()))
            };
        }
    }
    let tmp = write_temp(target, bytes, keep, mode)?;
    let persisted = if replace {
        tmp.persist(target)
    } else {
        tmp.persist_noclobber(target)
    };
    persisted.map_err(|e| Error::io(e.error, target))?;
    sync_parent(target);
    Ok(())
}

/// Makes the new file `target`, holding `bytes` with `mode`, in a new
/// folder of its own next to it first ([`private_folder`]), so that it
/// never carries an entry the folder's access list hands down, not even
/// before it holds anything; then renames it onto `target`: over what is
/// there with `replace` (a link is replaced, not followed), else only where
/// nothing is, returning `false` if something is. With `keep_out`, it is
/// kept out of backups and cloud folders before it holds anything.
#[cfg(target_os = "macos")]
fn write_in_private_folder(
    target: &Path,
    bytes: &[u8],
    mode: u32,
    replace: bool,
    keep_out: bool,
) -> Result<bool> {
    let (dir, _) = temp_location(target);
    let name = target
        .file_name()
        .ok_or_else(|| Error::invalid(format!("not a file path: {}", target.display())))?;
    let folder = private_folder::PrivateFolder::make(dir, name).map_err(|e| Error::io(e, dir))?;
    let mut file = folder.create(name).map_err(|e| Error::io(e, target))?;
    if keep_out {
        keep_out_of_copies(&file);
    }
    file.write_all(bytes).map_err(|e| Error::io(e, target))?;
    file.sync_all().map_err(|e| Error::io(e, target))?;
    set_file_mode(&file, target, mode)?;
    drop(file);
    match folder.place(name, name, replace) {
        Ok(()) => {}
        Err(e) if !replace && e.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
        Err(e) => return Err(Error::io(e, target)),
    }
    sync_parent(target);
    Ok(true)
}

/// The mode of the file at `target` without its group and other bits, or
/// 0600 if nothing is there.
#[cfg(not(windows))]
fn owner_bits(target: &Path) -> Result<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match fs::metadata(target) {
            Ok(meta) => Ok(meta.permissions().mode() & 0o600),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0o600),
            Err(e) => Err(Error::io(e, target)),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = target;
        Ok(0o600)
    }
}

/// Writes `bytes` to `path` in a new file only this user can open, for a
/// secret in plain text written where the user picks: an export, a
/// converted key. It is [`replace_private`] (mode 0600 from the first byte,
/// on Windows the private access list from creation; never written through
/// a link at `path`, which is replaced) after removing what earlier writes
/// to `path` that were cut short left next to it
/// ([`sweep_private_temps`]). Without `overwrite`, nothing is written if
/// something is at `path`, and the call returns `false`.
pub fn write_private(path: &Path, bytes: &[u8], overwrite: bool) -> Result<bool> {
    sweep_private_temps(path);
    replace_private(path, bytes, overwrite, false)
}

/// How the temporary file of [`atomic_write`] for a file named `name` ends:
/// `.name.Ab12Cd.sshkm-tmp`.
const TEMP_SUFFIX: &str = ".sshkm-tmp";

/// What the temporary file of [`replace_private`] for a file named `name`
/// is called between its prefix and suffix: `.env.sshkm-Ab12Cd.tmp`, so
/// that the rules that keep `.env*` files out of Git and backups keep it
/// out too.
pub(crate) const PRIVATE_TEMP: (&str, &str) = (".sshkm-", ".tmp");

/// How long a temporary file must have stayed unchanged before
/// [`sweep_abandoned_temps`] takes it for a leftover: far longer than any
/// write takes.
const ABANDONED_AFTER: Duration = Duration::from_secs(60);

/// Whether `name` is a temporary file [`replace_private`] makes for the file
/// named `of`, which a crash may have left behind.
pub fn is_private_temp(name: &str, of: &str) -> bool {
    name.strip_prefix(of)
        .and_then(|rest| rest.strip_prefix(PRIVATE_TEMP.0))
        .is_some_and(|rest| rest.len() > PRIVATE_TEMP.1.len() && rest.ends_with(PRIVATE_TEMP.1))
}

/// Removes the temporary files of [`replace_private`]'s writes to `path`
/// that a crash left next to it: they may hold its contents in plain text.
/// Only regular files are removed, the pipes a level-3 file is made from
/// next to it (`vault::envs::files::pipes::make_over`), and the private
/// folders such a file or pipe is made in on macOS, with what is in them
/// ([`private_folder`]).
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
        if leftover && let Ok(kind) = entry.file_type() {
            remove_leftover(&entry.path(), kind);
        }
    }
}

/// Removes a temporary file, pipe or private folder (with what is in it)
/// that a crash left at `path`; anything else stays.
fn remove_leftover(path: &Path, kind: fs::FileType) -> bool {
    if kind.is_file() || is_fifo(kind) {
        fs::remove_file(path).is_ok()
    } else if kind.is_dir() {
        fs::remove_dir_all(path).is_ok()
    } else {
        false
    }
}

/// Removes from `dir` the temporary files of this app's writes that a
/// crash, a kill or a power cut left there, which may hold a secret in
/// plain text (a key whose passphrase was being removed, say): regular
/// files named as those of [`atomic_write`] (`.<file>.<random>.sshkm-tmp`)
/// and [`replace_private`] (`<file>.sshkm-<random>.tmp`, also the private
/// folder a file is made in on macOS, with what is in it) that haven't
/// changed for a minute, so that no write under way loses its file. For the
/// folders the app writes into itself (`~/.ssh`, its data folder), at
/// start-up. Returns how many were removed.
pub fn sweep_abandoned_temps(dir: &Path) -> usize {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let now = SystemTime::now();
    let mut removed = 0;
    for entry in entries.filter_map(std::result::Result::ok) {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let written = name.starts_with('.')
            && name
                .strip_suffix(TEMP_SUFFIX)
                .is_some_and(|rest| rest.len() > 1);
        let private = name
            .rsplit_once(PRIVATE_TEMP.0)
            .is_some_and(|(of, _)| !of.is_empty() && is_private_temp(name, of));
        if !written && !private {
            continue;
        }
        // The entry itself, a link not followed.
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let abandoned = meta
            .modified()
            .ok()
            .and_then(|at| now.duration_since(at).ok())
            .is_some_and(|age| age >= ABANDONED_AFTER);
        let kind = meta.file_type();
        let removable = kind.is_file() || (private && kind.is_dir());
        if abandoned && removable && remove_leftover(&entry.path(), kind) {
            removed += 1;
        }
    }
    removed
}

#[cfg(unix)]
fn is_fifo(kind: fs::FileType) -> bool {
    use std::os::unix::fs::FileTypeExt;
    kind.is_fifo()
}

#[cfg(not(unix))]
fn is_fifo(_: fs::FileType) -> bool {
    false
}

/// Replaces `path` with a new file that holds `bytes` and that only this
/// user can read: mode 0600 on Unix, on macOS made in a folder of its own
/// first, so it never carries the entries a folder's access list hands down
/// ([`write_in_private_folder`]); on Windows an access list for nobody but
/// the user, `SYSTEM` and `Administrators`, set as the file is made, as
/// [`atomic_write_private`] does. Both are in place before anything is
/// written. Unlike [`atomic_write`], a symbolic link at `path` is never
/// followed and no mode is taken from what is there: the new file is
/// renamed over whatever is there, a link included. Without `overwrite`,
/// nothing is written if something is at `path` by then, and the call
/// returns `false`. With `keep_out`, the new file is kept out of backups
/// and cloud folders ([`keep_out_of_copies`]) before it is renamed into
/// place; on Unix before it holds anything.
pub fn replace_private(path: &Path, bytes: &[u8], overwrite: bool, keep_out: bool) -> Result<bool> {
    #[cfg(target_os = "macos")]
    {
        write_in_private_folder(path, bytes, 0o600, overwrite, keep_out)
    }
    #[cfg(windows)]
    {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let prefix = format!("{name}{}", PRIVATE_TEMP.0);
        write_private_at(path, bytes, &prefix, PRIVATE_TEMP.1, overwrite, keep_out)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let prefix = format!("{name}{}", PRIVATE_TEMP.0);
        let (dir, _) = temp_location(path);
        let mut tmp = tempfile::Builder::new()
            .prefix(&prefix)
            .suffix(PRIVATE_TEMP.1)
            .tempfile_in(dir)
            .map_err(|e| Error::io(e, dir))?;
        // tempfile makes it 0600; set again, on the open file, in case a
        // umask differs. A POSIX access list a folder hands down (Linux) is
        // masked by the group bits, which are off from the start.
        set_file_mode(tmp.as_file(), tmp.path(), 0o600)?;
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
pub(crate) fn keep_out_of_copies(file: &fs::File) {
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
    write_and_rename(path, bytes, None, mode, false)
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

/// Copies `path` into `backup_dir` as `<file name>.<UTC timestamp>.kept.bak`,
/// a backup the rotation of [`backup`] never removes: taken before each
/// sync that deletes what another device deleted, so that the file as it
/// was stays whatever backups later syncs take. One is skipped only when
/// the newest kept holds the same. Of the older ones, the first of each day
/// stays for [`KEPT_DAYS`] and the [`KEPT_NEWEST`] newest stay too; the
/// rest go.
///
/// Returns the backup's path, or `None` if `path` doesn't exist or the
/// newest kept backup holds the same.
pub fn keep_backup(path: &Path, backup_dir: &Path) -> Result<Option<PathBuf>> {
    if !path.exists() {
        return Ok(None);
    }
    let name = path
        .file_name()
        .ok_or_else(|| Error::invalid(format!("not a file: {}", path.display())))?
        .to_string_lossy()
        .into_owned();
    ensure_private_dir(backup_dir)?;
    let contents = fs::read(path).map_err(|e| Error::io(e, path))?;
    let kept = list_kept_backups(backup_dir, &name);
    if kept
        .last()
        .is_some_and(|newest| fs::read(newest).is_ok_and(|old| old == contents))
    {
        return Ok(None);
    }
    let now = OffsetDateTime::now_utc();
    let stamp = now.format(BACKUP_TS).map_err(|e| Error::Io {
        context: "formatting backup timestamp".into(),
        source: io::Error::other(e),
    })?;
    let mut dest = backup_dir.join(format!("{name}.{stamp}.kept.bak"));
    let mut n = 1;
    while fs::symlink_metadata(&dest).is_ok() {
        dest = backup_dir.join(format!("{name}.{stamp}-{n}.kept.bak"));
        n += 1;
    }
    write_new(&dest, &contents, 0o600)?;
    prune_kept(backup_dir, &name, now);
    Ok(Some(dest))
}

/// Most of the newest kept backups of a file that stay, whatever their day.
pub const KEPT_NEWEST: usize = 16;

/// Removes the kept backups of `name` that [`keep_backup`] no longer keeps.
fn prune_kept(backup_dir: &Path, name: &str, now: OffsetDateTime) {
    let oldest = (now - time::Duration::days(KEPT_DAYS))
        .format(BACKUP_TS)
        .unwrap_or_default();
    let kept = list_kept_backups(backup_dir, name);
    let newest_from = kept.len().saturating_sub(KEPT_NEWEST);
    let mut days = std::collections::BTreeSet::new();
    for (i, path) in kept.iter().enumerate() {
        let stamp = kept_stamp(path, name).map_or("", |(stamp, _)| stamp);
        let first_of_day = days.insert(stamp.get(..8).unwrap_or_default().to_owned());
        let stays = stamp >= oldest.as_str() && (first_of_day || i >= newest_from);
        if !stays {
            // Best effort, as for the rotation.
            let _ = fs::remove_file(path);
        }
    }
}

/// Lists the backups [`keep_backup`] took of `file_name` in `backup_dir`,
/// oldest first.
pub fn list_kept_backups(backup_dir: &Path, file_name: &str) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(backup_dir) else {
        return Vec::new();
    };
    let mut found: Vec<(String, u32, PathBuf)> = entries
        .filter_map(Result::ok)
        .filter_map(|e| {
            let path = e.path();
            let (stamp, seq) = kept_stamp(&path, file_name)?;
            Some((stamp.to_owned(), seq, path))
        })
        .collect();
    found.sort();
    found.into_iter().map(|(_, _, path)| path).collect()
}

/// The timestamp and sequence of a backup [`keep_backup`] took of
/// `file_name`.
fn kept_stamp<'a>(path: &'a Path, file_name: &str) -> Option<(&'a str, u32)> {
    let candidate = path.file_name()?.to_str()?;
    let rest = candidate
        .strip_prefix(file_name)?
        .strip_prefix('.')?
        .strip_suffix(".kept.bak")?;
    let (_, seq) = parse_backup_name(&format!("{file_name}.{rest}.bak"), file_name)?;
    Some((rest.split('-').next()?, seq))
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

/// Opens `path` to read, only if it is a regular file (links followed): a
/// pipe, a device or a folder is refused with [`Error::InvalidInput`]
/// before anything is read. The path is checked before it is opened, and
/// what was opened again after; on Unix it is opened without waiting, so a
/// pipe put there in between can't hold the call until something writes
/// to it.
pub(crate) fn open_regular(path: &Path) -> Result<fs::File> {
    let not_a_file = || Error::invalid(format!("{} is not a file", path.display()));
    if !fs::metadata(path)
        .map_err(|e| Error::io(e, path))?
        .is_file()
    {
        return Err(not_a_file());
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Reads of a regular file don't wait anyway.
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|e| Error::io(e, path))?;
    if !file.metadata().map_err(|e| Error::io(e, path))?.is_file() {
        return Err(not_a_file());
    }
    Ok(file)
}

/// Whether `path` leads to the null device (`/dev/null`), which some link
/// `known_hosts` to: it reads as empty.
fn is_null_device(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        fs::metadata(path).is_ok_and(|meta| {
            meta.file_type().is_char_device()
                && fs::metadata("/dev/null").is_ok_and(|null| null.rdev() == meta.rdev())
        })
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

/// Reads at most `max` bytes of a regular file ([`open_regular`]; the null
/// device reads as empty); larger files are rejected with
/// [`Error::InvalidInput`] without reading them into memory.
pub(crate) fn read_limited(path: &Path, max: u64) -> Result<Vec<u8>> {
    if is_null_device(path) {
        return Ok(Vec::new());
    }
    let file = open_regular(path)?;
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

/// The path with symbolic links resolved, for a file that may not exist yet:
/// the file itself if it exists, else its folder.
pub(crate) fn real_path(path: &Path) -> PathBuf {
    if let Ok(real) = fs::canonicalize(path) {
        return real;
    }
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => {
            fs::canonicalize(parent).map_or_else(|_| path.to_path_buf(), |dir| dir.join(name))
        }
        _ => path.to_path_buf(),
    }
}

/// Which file or folder a path leads to, after links: the device and inode
/// on Unix, the canonical path on Windows (junctions and links resolved,
/// letter case as stored).
#[cfg(unix)]
fn identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path).ok().map(|meta| (meta.dev(), meta.ino()))
}
#[cfg(not(unix))]
fn identity(path: &Path) -> Option<PathBuf> {
    fs::canonicalize(path).ok()
}

/// Whether the file `path` (which need not exist) is in the folder `dir` or
/// in one below it, as the file system sees it: every folder on the way to
/// it, as written and with links resolved, is compared with `dir` by
/// identity, so a symbolic link, `..`, another letter case or a macOS
/// firmlink such as `/System/Volumes/Data/Users/…` doesn't lead around it.
pub fn is_within(path: &Path, dir: &Path) -> bool {
    let real = real_path(path);
    match identity(dir) {
        Some(dir) => [path, &real]
            .into_iter()
            .flat_map(|path| path.ancestors().skip(1))
            .any(|folder| identity(folder).as_ref() == Some(&dir)),
        None => real.starts_with(real_path(dir)),
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

/// Sets Unix permission bits on the open `file`, found at `path`.
#[cfg(not(windows))]
#[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))]
fn set_file_mode(file: &fs::File, path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|e| Error::io(e, path))?;
    }
    #[cfg(not(unix))]
    let _ = (file, path, mode);
    Ok(())
}

/// Makes something new at `path` with `make`, such as a pipe, that only
/// this user may open: mode 0600, and on macOS made in a new folder of its
/// own and renamed into place, so that it never carries an entry the
/// folder's access list hands down, not even before its mode is set
/// ([`private_folder`]). Fails if something is at `path` by then.
pub(crate) fn make_private(path: &Path, make: impl FnOnce(&Path) -> Result<()>) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let (dir, _) = temp_location(path);
        let name = path
            .file_name()
            .ok_or_else(|| Error::invalid(format!("not a file path: {}", path.display())))?;
        let folder =
            private_folder::PrivateFolder::make(dir, name).map_err(|e| Error::io(e, dir))?;
        let inside = folder.path().map_err(|e| Error::io(e, dir))?;
        make(&inside.join(name))?;
        folder.holds(name).map_err(|e| Error::io(e, path))?;
        folder
            .place(name, name, false)
            .map_err(|e| Error::io(e, path))?;
        sync_parent(path);
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        make(path)?;
        set_mode(path, 0o600)
    }
}

/// The temporary file of [`atomic_write`] and the like, holding `bytes`,
/// with `keep`'s mode or else `mode`. On macOS a file only its owner may
/// open is made by [`write_in_private_folder`] instead.
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
        .suffix(TEMP_SUFFIX)
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
    fn a_kept_backup_outlives_the_rotation_and_goes_after_its_days() {
        let dir = tempfile::tempdir().unwrap();
        let (file, backups) = (dir.path().join("config"), dir.path().join("backups"));
        fs::write(&file, "before").unwrap();
        let kept = keep_backup(&file, &backups).unwrap().unwrap();
        // Nothing changed since: no second copy of the same.
        assert_eq!(keep_backup(&file, &backups).unwrap(), None);
        // Another run of deletions the same day: kept too.
        fs::write(&file, "between").unwrap();
        let later = keep_backup(&file, &backups).unwrap().unwrap();
        fs::write(&file, "after").unwrap();
        for _ in 0..BACKUPS_TO_KEEP + 5 {
            backup(&file, &backups).unwrap();
        }
        assert_eq!(list_backups(&backups, "config").len(), BACKUPS_TO_KEEP);
        assert_eq!(fs::read_to_string(&kept).unwrap(), "before");
        assert_eq!(fs::read_to_string(&later).unwrap(), "between");
        assert_eq!(list_kept_backups(&backups, "config"), [kept.clone(), later]);
        // Another file's kept backups aren't this one's.
        assert_eq!(list_kept_backups(&backups, "conf").len(), 0);

        // The first of each day stays; past the newest, the others of a
        // day go; past their days, all go.
        let old = |stamp: &str| backups.join(format!("config.{stamp}.kept.bak"));
        let ancient = old("20000101T000000.000Z");
        fs::write(&ancient, "ancient").unwrap();
        let recent_day = (OffsetDateTime::now_utc() - time::Duration::days(2))
            .format(BACKUP_TS)
            .unwrap();
        let first = old(&recent_day);
        fs::write(&first, "first that day").unwrap();
        let mut same_day = Vec::new();
        for n in 1..=KEPT_NEWEST + 2 {
            let path = old(&format!("{recent_day}-{n}"));
            fs::write(&path, format!("run {n}")).unwrap();
            same_day.push(path);
        }
        fs::write(&file, "now").unwrap();
        assert!(keep_backup(&file, &backups).unwrap().is_some());
        assert!(!ancient.exists());
        assert!(first.exists());
        assert!(kept.exists(), "today's first stays");
        assert!(
            !same_day[0].exists(),
            "an older run of that day, past the newest"
        );
        assert!(same_day.last().unwrap().exists());
    }

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
        // The same for a file written where the user picks.
        fs::remove_file(&path).unwrap();
        fs::write(&path, "ordinary").unwrap();
        assert!(write_private(&path, b"three", true).unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"three");
        let report = check(&path, PermKind::PrivateKey);
        assert!(report.ok, "{report:?}");
        // No temp files left behind.
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    fn set(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    /// A private rewrite follows a link, as `atomic_write` does, but keeps
    /// only the owner's bits of the file it replaces.
    #[cfg(unix)]
    #[test]
    fn private_rewrites_keep_only_the_owners_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("id_ed25519");
        atomic_write_private(&key, b"new").unwrap();
        assert_eq!(mode(&key), 0o600);
        set(&key, 0o644);
        atomic_write_private(&key, b"plain").unwrap();
        assert_eq!(fs::read(&key).unwrap(), b"plain");
        assert_eq!(mode(&key), 0o600);
        set(&key, 0o400);
        atomic_write_private(&key, b"again").unwrap();
        assert_eq!(mode(&key), 0o400);

        let real = dir.path().join("dotfiles-key");
        fs::write(&real, "old").unwrap();
        set(&real, 0o640);
        let link = dir.path().join("id_work");
        std::os::unix::fs::symlink("dotfiles-key", &link).unwrap();
        atomic_write_private(&link, b"key").unwrap();
        assert!(fs::symlink_metadata(&link).unwrap().is_symlink());
        assert_eq!(fs::read(&real).unwrap(), b"key");
        assert_eq!(mode(&real), 0o600);
        // No temp files left behind.
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 3);
    }

    /// A file written where the user picks is 0600 whatever was there, and
    /// never goes through a link to another file or takes its mode.
    #[cfg(unix)]
    #[test]
    fn private_writes_never_take_a_mode_or_follow_a_link() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passwords.csv");
        fs::write(&path, "old").unwrap();
        set(&path, 0o644);
        assert!(write_private(&path, b"secret", true).unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"secret");
        assert_eq!(mode(&path), 0o600);

        let theirs = dir.path().join("collect");
        fs::write(&theirs, "").unwrap();
        set(&theirs, 0o666);
        let link = dir.path().join("deploy.pem");
        std::os::unix::fs::symlink(&theirs, &link).unwrap();
        assert!(write_private(&link, b"key", true).unwrap());
        assert_eq!(fs::read(&theirs).unwrap(), b"");
        assert_eq!(mode(&theirs), 0o666);
        assert!(fs::symlink_metadata(&link).unwrap().is_file());
        assert_eq!(mode(&link), 0o600);

        // Without overwriting, what is there stays.
        assert!(!write_private(&path, b"other", false).unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"secret");
    }

    #[test]
    fn private_writes_remove_what_an_earlier_one_left() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passwords.csv");
        let leftover = dir.path().join("passwords.csv.sshkm-Ab12Cd.tmp");
        fs::write(&leftover, "every password").unwrap();
        let other = dir.path().join("notes.csv.sshkm-Ab12Cd.tmp");
        fs::write(&other, "not this one's").unwrap();
        assert!(write_private(&path, b"new", true).unwrap());
        assert!(!leftover.exists());
        assert!(other.exists());
    }

    #[test]
    fn abandoned_temporary_files_are_swept() {
        let dir = tempfile::tempdir().unwrap();
        let old = SystemTime::now() - Duration::from_secs(3600);
        let make = |name: &str, at: SystemTime| {
            let path = dir.path().join(name);
            fs::File::create(&path).unwrap().set_modified(at).unwrap();
            path
        };
        let left = [
            make(".id_ed25519.Ab12Cd.sshkm-tmp", old),
            make("id_ed25519.pem.sshkm-Ab12Cd.tmp", old),
        ];
        let kept = [
            // A write under way.
            make(".config.Xy34Zw.sshkm-tmp", SystemTime::now()),
            // Not the app's.
            make("notes.tmp", old),
            make(".sshkm-tmp", old),
            make("id_ed25519", old),
        ];
        let folder = dir.path().join(".d.Ab12Cd.sshkm-tmp");
        fs::create_dir(&folder).unwrap();
        // The private folder a write was making a file in (macOS), with
        // the file, and one a write is using now.
        #[cfg(unix)]
        let (abandoned, in_use) = {
            let private = |name: &str, at: SystemTime| {
                let path = dir.path().join(name);
                fs::create_dir(&path).unwrap();
                fs::write(path.join("passwords.csv"), "secret").unwrap();
                fs::File::open(&path).unwrap().set_modified(at).unwrap();
                path
            };
            (
                private("passwords.csv.sshkm-Zz99Yy.tmp", old),
                private("vault.kdbx.sshkm-Qq11Ww.tmp", SystemTime::now()),
            )
        };
        let swept = if cfg!(unix) { 3 } else { 2 };
        assert_eq!(sweep_abandoned_temps(dir.path()), swept);
        assert!(left.iter().all(|path| !path.exists()));
        assert!(kept.iter().all(|path| path.exists()));
        assert!(folder.is_dir());
        #[cfg(unix)]
        {
            assert!(!abandoned.exists());
            assert!(in_use.join("passwords.csv").exists());
        }
        assert_eq!(sweep_abandoned_temps(&dir.path().join("missing")), 0);
    }

    /// Files and pipes only this user may open never carry an entry a
    /// folder's access list hands down (macOS), at no moment: something
    /// opening every file that appears, while they are written over and
    /// over, never finds one with an entry. A file others may read keeps
    /// what the folder hands down.
    #[cfg(target_os = "macos")]
    #[test]
    fn private_files_never_carry_what_a_folder_hands_down() {
        use std::os::unix::fs::OpenOptionsExt;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        use crate::perms::extended_acl::testing::{carries_entries, entries, sharing_folder};

        let dir = sharing_folder();
        let at = |name: &str| dir.path().join(name);
        let public = at("id_ed25519.pub");
        write_new(&public, b"ssh-ed25519 AAAA", 0o644).unwrap();
        assert_eq!(entries(&public), 1);

        let stop = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(AtomicUsize::new(0));
        let carried = Arc::new(Mutex::new(Vec::new()));
        let observer = {
            let (stop, seen, carried) =
                (Arc::clone(&stop), Arc::clone(&seen), Arc::clone(&carried));
            let root = dir.path().to_path_buf();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let mut folders = vec![root.clone()];
                    while let Some(folder) = folders.pop() {
                        let Ok(entries) = fs::read_dir(&folder) else {
                            continue;
                        };
                        for entry in entries.filter_map(std::result::Result::ok) {
                            let path = entry.path();
                            if entry.file_name() == "id_ed25519.pub" {
                                continue;
                            }
                            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                                folders.push(path);
                                continue;
                            }
                            let opened = fs::OpenOptions::new()
                                .read(true)
                                .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
                                .open(&path);
                            if let Ok(file) = opened {
                                seen.fetch_add(1, Ordering::Relaxed);
                                if carries_entries(&file) {
                                    carried.lock().unwrap().push(path);
                                }
                            }
                        }
                    }
                }
            })
        };
        for round in 0..100 {
            let text = format!("A={round}\n");
            let _ = fs::remove_file(at(".env"));
            assert!(replace_private(&at(".env"), text.as_bytes(), false, true).unwrap());
            assert!(write_private(&at("passwords.csv"), text.as_bytes(), true).unwrap());
            atomic_write_private(&at("id_ed25519"), text.as_bytes()).unwrap();
            atomic_write(&at("history.json"), text.as_bytes(), 0o600).unwrap();
            let _ = fs::remove_file(at("vault.kdbx"));
            write_new(&at("vault.kdbx"), text.as_bytes(), 0o600).unwrap();
            if round % 10 == 0 {
                let pipe = at("pipe");
                let _ = fs::remove_file(&pipe);
                make_private(&pipe, |path| {
                    let made = std::process::Command::new("mkfifo")
                        .arg(path)
                        .status()
                        .map_err(|e| Error::io(e, path))?;
                    assert!(made.success());
                    Ok(())
                })
                .unwrap();
            }
        }
        stop.store(true, Ordering::Relaxed);
        observer.join().unwrap();
        assert!(seen.load(Ordering::Relaxed) > 0);
        assert_eq!(*carried.lock().unwrap(), Vec::<PathBuf>::new());

        for name in [
            ".env",
            "passwords.csv",
            "id_ed25519",
            "history.json",
            "vault.kdbx",
            "pipe",
        ] {
            assert_eq!(entries(&at(name)), 0, "{name}");
            assert_eq!(mode(&at(name)), 0o600, "{name}");
        }
        assert!(is_fifo(
            fs::symlink_metadata(at("pipe")).unwrap().file_type()
        ));
        // Nothing else is left in the folder.
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 7);
        // A pipe is never made over something.
        let refused = make_private(&at("pipe"), |path| {
            fs::write(path, "").map_err(|e| Error::io(e, path))
        });
        assert_eq!(refused.unwrap_err().code(), crate::ErrorCode::AlreadyExists);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 7);
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

    /// Only regular files are read: a folder or a pipe is refused at once,
    /// not waited on until something writes to it. The null device reads
    /// as empty.
    #[test]
    fn only_regular_files_are_read() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            read_limited(dir.path(), 100).unwrap_err().code(),
            crate::ErrorCode::InvalidInput
        );
        assert_eq!(
            read_limited(&dir.path().join("missing"), 100)
                .unwrap_err()
                .code(),
            crate::ErrorCode::NotFound
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let pipe = dir.path().join("id_ed25519.pub");
            let made = std::process::Command::new("mkfifo")
                .arg(&pipe)
                .status()
                .unwrap();
            assert!(made.success());
            let (done, finished) = std::sync::mpsc::channel();
            let path = pipe.clone();
            std::thread::spawn(move || {
                let _ = done.send(read_limited(&path, 100).map_err(|e| e.code()));
            });
            let result = finished.recv_timeout(Duration::from_secs(5));
            if result.is_err() {
                // Lets the stuck thread go.
                let _ = fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(&pipe);
            }
            assert_eq!(result, Ok(Err(crate::ErrorCode::InvalidInput)));
            assert_eq!(
                read_limited(Path::new("/dev/zero"), 100)
                    .unwrap_err()
                    .code(),
                crate::ErrorCode::InvalidInput
            );
            let null = dir.path().join("known_hosts");
            std::os::unix::fs::symlink("/dev/null", &null).unwrap();
            assert_eq!(read_limited(&null, 100).unwrap(), b"");
        }
    }

    #[test]
    fn folders_are_compared_by_identity() {
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path().join(".ssh");
        fs::create_dir(&ssh).unwrap();
        fs::create_dir(dir.path().join("x")).unwrap();
        fs::create_dir(dir.path().join(".ssh2")).unwrap();
        assert!(is_within(&ssh.join("id_ed25519"), &ssh));
        assert!(is_within(&ssh.join("sub").join("key"), &ssh));
        assert!(is_within(
            &dir.path().join("x").join("..").join(".ssh").join("key"),
            &ssh
        ));
        assert!(!is_within(&dir.path().join(".ssh2").join("key"), &ssh));
        assert!(!is_within(&dir.path().join("key"), &ssh));
        assert!(!is_within(&ssh, &ssh));
        #[cfg(unix)]
        {
            let link = dir.path().join("dotfiles");
            std::os::unix::fs::symlink(&ssh, &link).unwrap();
            assert!(is_within(&link.join("key"), &ssh));
            // A link in `~/.ssh` to a file elsewhere leads out of it, but
            // the path itself is still in it.
            let elsewhere = dir.path().join("x").join("file");
            fs::write(&elsewhere, "").unwrap();
            std::os::unix::fs::symlink(&elsewhere, ssh.join("out")).unwrap();
            assert!(is_within(&ssh.join("out"), &ssh));
            // And a link elsewhere to a file in it leads in.
            fs::write(ssh.join("id_ed25519"), "").unwrap();
            let into = dir.path().join("x").join("in");
            std::os::unix::fs::symlink(ssh.join("id_ed25519"), &into).unwrap();
            assert!(is_within(&into, &ssh));
        }
        #[cfg(target_os = "macos")]
        {
            // The same folder in another letter case (case-insensitive
            // volumes, macOS's default).
            let upper = dir.path().join(".SSH").join("key");
            if dir.path().join(".SSH").exists() {
                assert!(is_within(&upper, &ssh));
            }
        }
    }
}
