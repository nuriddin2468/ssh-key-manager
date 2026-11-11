//! Finding, reading and writing an environment's files on this computer.
//!
//! A binding's file is looked for in its project folder, with symbolic
//! links on the way resolved, and refused unless the folder it ends up in
//! is that project folder or one inside it (compared by the file system's
//! identity of the folders, so `..`, links and case don't lead around it).
//! The file itself is never a link: it is opened without following one,
//! written by renaming a new file over it (which replaces a link rather
//! than writing through it), and only a regular file is read, so a pipe
//! can't make a read hang. Nothing is written over the vault's own files or
//! into the SSH folder ([`checked_target`]). A folder that isn't there is
//! never made.

use std::fs;
use std::io::{self, Read as _};
use std::path::{Component, Path, PathBuf};

use zeroize::Zeroizing;

use super::{EnvFile, FileState, FilesContext, RefusedReason, check_env_file, is_env_file_name};
use crate::leaks::sources::SKIP_DIRS;
use crate::vault::VaultPaths;
use crate::vault::envs::MAX_FILE_SIZE;
use crate::vault::export::{FileId, checked_target};
use crate::vault::projects;
use crate::{Error, Result, fsutil};

/// Deepest folder below a project folder that unmanaged files are looked
/// for in.
const MAX_DEPTH: usize = 6;
/// Most folder entries one search looks at.
const MAX_ENTRIES: usize = 50_000;

/// Which file a binding names on disk: its folder's identity and its name
/// without case, so two folders that are one on disk (a link, `Code` and
/// `code` on macOS) name one file.
pub(super) type Identity = (FileId, String);

/// A binding's file on this computer.
#[derive(Debug, Clone)]
pub(super) struct Target {
    /// The file, in its folder with links resolved.
    pub real: PathBuf,
    /// The file as the project's folder names it, to show.
    pub display: PathBuf,
    pub identity: Identity,
}

impl Target {
    /// The identity of the file's folder as text, kept with a revision.
    pub fn dir_token(&self) -> String {
        self.identity.0.token()
    }
}

/// Where a binding's file is on this computer, as its project's folder
/// names it, if that folder is a full path here; nothing is checked.
pub(super) fn display(file: &EnvFile, ctx: &FilesContext) -> Option<PathBuf> {
    let mut path = projects::folder_path(&file.folder, ctx.home.as_deref())?;
    path.extend(file.path.split('/'));
    Some(path)
}

/// What reading a file gave.
pub(super) enum Disk {
    Missing,
    Text(Zeroizing<String>),
    Refused(RefusedReason),
    /// What went wrong, without the file's text.
    Failed(String),
}

/// The file `file` names on this computer, checked, or why it can't be
/// used.
pub(super) fn locate(
    file: &EnvFile,
    ctx: &FilesContext,
    vault: &VaultPaths,
) -> std::result::Result<Target, FileState> {
    let failed = |error: &io::Error, path: &Path| FileState::Failed {
        message: Error::io(clone_error(error), path).to_string(),
    };
    // A binding is checked again whenever it is used: one that came from
    // elsewhere may name anything.
    if check_env_file(file).ok().as_ref() != Some(file) {
        return Err(FileState::Refused {
            reason: RefusedReason::Name,
        });
    }
    let Some(folder) = projects::folder_path(&file.folder, ctx.home.as_deref()) else {
        return Err(FileState::FolderMissing);
    };
    let parts: Vec<&str> = file.path.split('/').collect();
    let Some((name, folders)) = parts.split_last() else {
        return Err(FileState::Refused {
            reason: RefusedReason::NotAFile,
        });
    };
    let mut display = folder.clone();
    display.extend(&parts);
    let root = match fs::canonicalize(&folder) {
        Ok(root) if root.is_dir() => root,
        Ok(_) => return Err(FileState::FolderMissing),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(FileState::FolderMissing),
        Err(e) => return Err(failed(&e, &folder)),
    };
    let mut dir = root.clone();
    dir.extend(folders);
    let dir = match fs::canonicalize(&dir) {
        Ok(dir) if dir.is_dir() => dir,
        Ok(_) => return Err(FileState::FolderMissing),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(FileState::FolderMissing),
        Err(e) => return Err(failed(&e, &dir)),
    };
    let root_id = FileId::of(&root);
    let dir_id = FileId::of(&dir);
    let inside = root_id.is_some()
        && dir
            .ancestors()
            .any(|ancestor| FileId::of(ancestor) == root_id);
    let (true, Some(dir_id)) = (inside, dir_id) else {
        return Err(FileState::Refused {
            reason: RefusedReason::Outside,
        });
    };
    let real = dir.join(name);
    if real.parent() != Some(dir.as_path()) || real.file_name() != Some(std::ffi::OsStr::new(name))
    {
        return Err(FileState::Refused {
            reason: RefusedReason::Name,
        });
    }
    match fs::symlink_metadata(&real) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(FileState::Refused {
                reason: RefusedReason::Link,
            });
        }
        Ok(meta) if !meta.is_file() => {
            return Err(FileState::Refused {
                reason: RefusedReason::NotAFile,
            });
        }
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(failed(&e, &real)),
    }
    if checked_target(&real, vault, &ctx.ssh_dir).is_err() {
        return Err(FileState::Refused {
            reason: RefusedReason::Protected,
        });
    }
    Ok(Target {
        real,
        display,
        identity: (dir_id, name.to_lowercase()),
    })
}

/// Reads a `.env` file of at most [`MAX_FILE_SIZE`] bytes, in UTF-8,
/// without following a link and only if it is a regular file.
pub(super) fn read(path: &Path) -> Disk {
    let file = match open_no_follow(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Disk::Missing,
        Err(e) if is_link_error(&e) => return Disk::Refused(RefusedReason::Link),
        Err(e) => return Disk::Failed(Error::io(e, path).to_string()),
    };
    let meta = match file.metadata() {
        Ok(meta) => meta,
        Err(e) => return Disk::Failed(Error::io(e, path).to_string()),
    };
    if meta.file_type().is_symlink() {
        return Disk::Refused(RefusedReason::Link);
    }
    if !meta.is_file() {
        return Disk::Refused(RefusedReason::NotAFile);
    }
    if meta.len() > MAX_FILE_SIZE {
        return Disk::Failed(format!("{} is too large", path.display()));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    if let Err(e) = file.take(MAX_FILE_SIZE + 1).read_to_end(&mut bytes) {
        return Disk::Failed(Error::io(e, path).to_string());
    }
    if bytes.len() as u64 > MAX_FILE_SIZE {
        return Disk::Failed(format!("{} is too large", path.display()));
    }
    match std::str::from_utf8(&bytes) {
        Ok(text) => Disk::Text(Zeroizing::new(text.to_owned())),
        Err(_) => Disk::Failed(format!("{} is not UTF-8 text", path.display())),
    }
}

/// Writes `bytes` to the target, readable by its owner only, by renaming a
/// new file over it, unless it no longer holds `expected` (`None`: unless
/// it exists now) or its folder is no longer the one it was found in.
/// Returns whether it wrote.
pub(super) fn write(target: &Target, expected: Option<&[u8]>, bytes: &[u8]) -> Result<bool> {
    let current = match read(&target.real) {
        Disk::Missing => None,
        Disk::Text(text) => Some(text),
        Disk::Refused(reason) => return Err(refused(reason, &target.display)),
        Disk::Failed(message) => return Err(Error::invalid(message)),
    };
    if current.as_ref().map(|text| text.as_bytes()) != expected || !same_folder(target) {
        return Ok(false);
    }
    fsutil::replace_private(&target.real, bytes, expected.is_some())
}

/// The target's folder is still the folder it was found in, and no link
/// leads to it.
fn same_folder(target: &Target) -> bool {
    target.real.parent().is_some_and(|dir| {
        FileId::of(dir).as_ref() == Some(&target.identity.0)
            && fs::canonicalize(dir).is_ok_and(|real| real == dir)
    })
}

/// Removes the temporary files of the target's writes that a crash left
/// next to it: they hold its values in plain text.
pub(super) fn sweep(target: &Target) {
    let (Some(dir), Some(name)) = (
        target.real.parent(),
        target.real.file_name().and_then(|name| name.to_str()),
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

/// Deletes the target, a regular file.
pub(super) fn remove(target: &Target) -> Result<()> {
    match fs::symlink_metadata(&target.real) {
        Ok(meta) if meta.is_file() => {
            fs::remove_file(&target.real).map_err(|e| Error::io(e, &target.display))
        }
        Ok(_) => Err(Error::invalid("not a regular file")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::io(e, &target.display)),
    }
}

fn refused(reason: RefusedReason, path: &Path) -> Error {
    Error::invalid(format!(
        "{} {}",
        path.display(),
        match reason {
            RefusedReason::Link => "is a symbolic link",
            RefusedReason::NotAFile => "is not a regular file",
            RefusedReason::Outside => "is outside the project's folder",
            RefusedReason::Protected => "is where the app never writes",
            RefusedReason::Name => "is not a file the app writes",
        }
    ))
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    // Non-blocking, so opening a pipe returns at once; its type is checked
    // before anything is read.
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(windows)]
fn open_no_follow(path: &Path) -> io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    // A link (a reparse point) is opened as itself and then refused.
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_no_follow(path: &Path) -> io::Result<fs::File> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(io::Error::other("a symbolic link"));
    }
    fs::File::open(path)
}

/// `open` refused a link (`ELOOP` from `O_NOFOLLOW`).
fn is_link_error(error: &io::Error) -> bool {
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(libc::ELOOP)
    }
    #[cfg(not(unix))]
    {
        let _ = error;
        false
    }
}

fn clone_error(error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), error.to_string())
}

/// The `.env` files in `folder` and the folders in it, down to a few
/// levels, leaving out dependencies and builds ([`SKIP_DIRS`]), the
/// folders in `skip`, links and templates: their paths in the folder with
/// `/` between parts. The second value says the search stopped early.
pub fn find_env_files(folder: &Path, skip: &[PathBuf]) -> (Vec<String>, bool) {
    let mut found = Vec::new();
    let mut seen = 0usize;
    let mut pending: Vec<(PathBuf, Vec<String>)> = vec![(folder.to_path_buf(), Vec::new())];
    while let Some((dir, prefix)) = pending.pop() {
        let Ok(read) = fs::read_dir(&dir) else {
            continue;
        };
        let mut entries: Vec<(String, bool)> = Vec::new();
        for entry in read.filter_map(std::result::Result::ok) {
            seen += 1;
            if seen > MAX_ENTRIES {
                found.sort();
                return (found, true);
            }
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if kind.is_symlink() {
                continue;
            }
            entries.push((name, kind.is_dir()));
        }
        entries.sort();
        for (name, is_dir) in entries {
            if is_dir {
                let path = dir.join(&name);
                if prefix.len() < MAX_DEPTH
                    && !SKIP_DIRS.contains(&name.as_str())
                    && !name.eq_ignore_ascii_case(".git")
                    && !skip.contains(&path)
                {
                    let mut next = prefix.clone();
                    next.push(name.clone());
                    pending.push((path, next));
                }
            } else if is_env_file_name(&name) {
                let mut parts = prefix.clone();
                parts.push(name);
                found.push(parts.join("/"));
            }
        }
    }
    found.sort();
    (found, false)
}

/// The template next to a file (`.env.example`, `.env.sample`,
/// `.env.template`), and the names it sets.
pub(super) fn example_names(dir: &Path) -> Option<(String, Vec<String>)> {
    for name in [".env.example", ".env.sample", ".env.template", ".env.dist"] {
        if let Disk::Text(text) = read(&dir.join(name)) {
            let names = crate::vault::envs::dotenv::parse(&text)
                .vars
                .into_iter()
                .map(|var| var.name)
                .collect();
            return Some((name.to_owned(), names));
        }
    }
    None
}

/// Adds a line that ignores `file` to the `.gitignore` at the top of the
/// Git working tree `repository`, made if there is none: the file's path
/// from there, starting with `/`, so it ignores that one file. A line that
/// says so already is left alone. The `.gitignore` is kept as it is
/// otherwise, and is never written through a link.
///
/// The file's folder may not be made yet (a binding waits for it): the
/// nearest folder on the way that exists, inside `repository`, places it,
/// and the folders still to come follow by name.
pub fn ignore_in_git(repository: &Path, file: &Path) -> Result<()> {
    let root = fs::canonicalize(repository).map_err(|e| Error::io(e, repository))?;
    let folder = file
        .parent()
        .ok_or_else(|| Error::invalid("not a file in a folder"))?;
    let name = file
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::invalid("not a file name"))?;
    let (folder, to_come) = nearest_folder(folder, repository)?;
    let rest = folder
        .strip_prefix(&root)
        .map_err(|_| Error::invalid("the file isn't in that working tree"))?;
    let mut parts: Vec<String> = rest
        .components()
        .map(Component::as_os_str)
        .chain(to_come)
        .map(|part| {
            part.to_str()
                .map(str::to_owned)
                .ok_or_else(|| Error::invalid("not a path in Unicode"))
        })
        .collect::<Result<_>>()?;
    parts.push(name.to_owned());
    let line = format!("/{}", ignore_pattern(&parts.join("/")));
    let gitignore = root.join(".gitignore");
    let text = match fs::symlink_metadata(&gitignore) {
        Ok(meta) if meta.is_file() => {
            let bytes = fsutil::read_limited(&gitignore, MAX_FILE_SIZE)?;
            String::from_utf8(bytes).map_err(|_| Error::invalid(".gitignore is not UTF-8 text"))?
        }
        Ok(_) => return Err(Error::invalid(".gitignore is not a regular file")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(Error::io(e, &gitignore)),
    };
    if text.lines().any(|existing| existing.trim_end() == line) {
        return Ok(());
    }
    let eol = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut out = text;
    if !out.is_empty() && !out.ends_with('\n') {
        out.push_str(eol);
    }
    out.push_str(&line);
    out.push_str(eol);
    fsutil::atomic_write(&gitignore, out.as_bytes(), 0o644)
}

/// `folder` resolved, or the nearest folder on its way that exists, no
/// higher than `top`, with the names of the folders under it still to
/// come, outermost first. Only plain names are taken on faith: not `..`.
fn nearest_folder<'a>(folder: &'a Path, top: &Path) -> Result<(PathBuf, Vec<&'a std::ffi::OsStr>)> {
    let mut to_come = Vec::new();
    let mut at = folder;
    loop {
        match fs::canonicalize(at) {
            Ok(found) if found.is_dir() => {
                to_come.reverse();
                return Ok((found, to_come));
            }
            Ok(_) => return Err(Error::invalid("a folder on the way is a file")),
            Err(e) if e.kind() == io::ErrorKind::NotFound && at != top && at.starts_with(top) => {
                let (Some(parent), Some(Component::Normal(part))) =
                    (at.parent(), at.components().next_back())
                else {
                    return Err(Error::invalid("not a plain path to a folder"));
                };
                to_come.push(part);
                at = parent;
            }
            Err(e) => return Err(Error::io(e, at)),
        }
    }
}

/// A path as a `.gitignore` pattern for that path alone: wildcards and
/// backslashes escaped, as is a space at the end.
fn ignore_pattern(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '\\' | '!' | '#') {
            out.push('\\');
        }
        out.push(c);
    }
    if out.ends_with(' ') {
        out.pop();
        out.push_str("\\ ");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_search_leaves_out_private_folders_and_leftovers() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        for folder in ["code/shop", "Documents/old", "node_modules/x"] {
            fs::create_dir_all(home.join(folder)).unwrap();
        }
        for file in [
            "code/shop/.env",
            "code/shop/.env.sshkm-Ab12Cd.tmp",
            "code/shop/.env.example",
            "Documents/old/.env",
            "node_modules/x/.env",
        ] {
            fs::write(home.join(file), "A=1\n").unwrap();
        }
        let skip = [home.join("Documents")];
        let (found, truncated) = find_env_files(home, &skip);
        assert_eq!(found, ["code/shop/.env"]);
        assert!(!truncated);
        // Searching from inside one of them goes on as asked.
        let (found, _) = find_env_files(&home.join("Documents"), &skip);
        assert_eq!(found, ["old/.env"]);
    }

    #[test]
    fn patterns_name_one_file() {
        assert_eq!(ignore_pattern(".env"), ".env");
        assert_eq!(ignore_pattern("apps/web/.env.local"), "apps/web/.env.local");
        assert_eq!(ignore_pattern("a[1]/*.env"), "a\\[1\\]/\\*.env");
        assert_eq!(ignore_pattern("odd /x "), "odd /x\\ ");
    }
}
