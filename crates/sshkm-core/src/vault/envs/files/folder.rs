//! A managed file's folder, held open while a file in it is read, written,
//! made or removed, so that the folder that was checked is the folder used.
//!
//! On macOS and Linux the folder is opened once, never through a link at its
//! own name, and checked as it was opened ([`Folder::checked`]): that it is
//! the folder the file was found in (its device and inode), and that it is
//! the project's folder or inside it (its parents, walked up through `..`).
//! Every file in it is then read, made, renamed and removed through that
//! descriptor (`openat`, `renameat`, `unlinkat`). Someone who swaps a folder
//! on the way for a link meanwhile, or for a folder of their own, changes
//! nothing: what was opened stays the folder that was checked, wherever its
//! path leads by then.
//!
//! A new file or pipe is made in a staging folder of the app's own inside
//! that folder (`Staging`): mode 0700 and, on macOS, its
//! access list emptied before anything is made in it, so nothing a
//! folder's list hands down (which macOS checks before the mode) is on the
//! file at any moment. It is then renamed into place, and the staging
//! folder removed; one a crash leaves is swept ([`sweep_staging`]).
//!
//! On Windows the folder is held open, without letting it be renamed or
//! deleted, for as long as it is used, and the folder held is checked by
//! the path Windows gives for its handle: the folder found, inside the
//! project's. Files in it are then used by their paths.

use std::fs;
use std::io;
use std::path::Path;

#[cfg(unix)]
use crate::fsutil;

/// What a staging folder of a write to `name` is called: `name` with
/// [`fsutil::PRIVATE_TEMP`] around a random tag (`.env.sshkm-Ab12Cd.tmp`),
/// as the app's temporary files are, so the sweeps of what a crash left
/// find it ([`sweep_staging`]).
#[cfg(unix)]
fn temp_name(name: &str) -> String {
    format!(
        "{name}{}{}{}",
        fsutil::PRIVATE_TEMP.0,
        random_tag(),
        fsutil::PRIVATE_TEMP.1
    )
}

#[cfg(unix)]
fn random_tag() -> String {
    use rand_core::{OsRng, RngCore};
    const LETTERS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut bytes = [0u8; 6];
    OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| char::from(LETTERS[usize::from(*b) % LETTERS.len()]))
        .collect()
}

/// What kind of thing a name in a folder is, not following a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    File,
    Folder,
    Link,
    #[cfg_attr(not(unix), allow(dead_code, reason = "no pipes in folders there"))]
    Pipe,
    Other,
}

#[cfg(unix)]
pub(super) use imp::Staging;
pub(super) use imp::{Folder, sweep_staging};

impl Folder {
    /// The folder `dir`, held, if it is still the folder whose identity
    /// is `id` (as `FileId::token` gives it) and it is the folder whose
    /// identity is `root`, or inside it. `None` when it isn't (it was
    /// swapped, moved or removed since it was found).
    pub(super) fn checked(dir: &Path, id: &str, root: &str) -> Option<Self> {
        let folder = Self::open(dir).ok()?;
        (folder.token().ok()?.as_str() == id && folder.is_within(root)).then_some(folder)
    }

    /// Writes `bytes` to the file `name` in the folder by renaming a new
    /// file over it, readable by its owner only (mode 0600 on Unix, and on
    /// macOS no entries handed down by the folder's access list, dropped
    /// before it holds anything; on Windows an access list for nobody but
    /// the user, `SYSTEM` and `Administrators`, [`fsutil::replace_private`]).
    /// Whatever is at `name`, a link included, is replaced, never written
    /// through; without `overwrite`, nothing is written if something is
    /// there by then, and the call returns `false`. With `keep_out`, the new
    /// file is kept out of backups and cloud folders before it holds
    /// anything (Unix) or before it takes its place (Windows). `placing` is
    /// told what the new file is on disk before it takes its place on Unix,
    /// right after on Windows; an error from it stops the write.
    pub(super) fn write_private(
        &self,
        name: &str,
        bytes: &[u8],
        overwrite: bool,
        keep_out: bool,
        placing: impl FnOnce(&fs::Metadata) -> crate::Result<()>,
    ) -> crate::Result<bool> {
        imp::write_private(self, name, bytes, overwrite, keep_out, placing)
    }
}

#[cfg(unix)]
mod imp {
    use std::fs;
    use std::io::{self, Write as _};
    use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

    use rustix::fs::{AtFlags, Mode, OFlags};
    use rustix::io::Errno;

    use super::{Kind, temp_name};
    use crate::{Error, fsutil};

    /// Most folders walked up from a folder to find the project's.
    const MAX_DEPTH: usize = 256;

    /// A folder, opened.
    pub struct Folder {
        fd: OwnedFd,
        path: PathBuf,
    }

    impl Folder {
        /// The folder at `path` as it is now, opened without following a
        /// link at its own name (links on the way to it are followed).
        pub fn open(path: &Path) -> io::Result<Self> {
            let fd = rustix::fs::open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            Ok(Self {
                fd,
                path: path.to_path_buf(),
            })
        }

        /// The folder by the path it was opened at, to name in messages.
        pub fn path(&self) -> &Path {
            &self.path
        }

        pub fn fd(&self) -> BorrowedFd<'_> {
            self.fd.as_fd()
        }

        /// Which folder it is, as `FileId::token` says it: `device:inode`.
        pub fn token(&self) -> io::Result<String> {
            token(self.fd.as_fd())
        }

        /// Whether `root` (a token) is this folder or one of the folders it
        /// is in, as they are now: walked up through `..`, which no link
        /// redirects.
        pub fn is_within(&self, root: &str) -> bool {
            let mut parent: Option<OwnedFd> = None;
            for _ in 0..MAX_DEPTH {
                let here = parent.as_ref().map_or(self.fd.as_fd(), AsFd::as_fd);
                let Ok(id) = token(here) else {
                    return false;
                };
                if id == root {
                    return true;
                }
                let Ok(up) = rustix::fs::openat(
                    here,
                    "..",
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                ) else {
                    return false;
                };
                // The top of the file system is its own parent.
                if token(up.as_fd()).is_ok_and(|above| above == id) {
                    return false;
                }
                parent = Some(up);
            }
            false
        }

        /// What `name` in the folder is, not following a link, without
        /// opening it (a pipe opened to read is one its server answers);
        /// `None` if nothing is there.
        pub fn entry(&self, name: &str) -> io::Result<Option<Entry>> {
            match Entry::at(self.fd.as_fd(), name) {
                Ok(entry) => Ok(Some(entry)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        }

        /// `name` in the folder opened to read, never through a link and
        /// without waiting: a pipe opens at once, and its type is checked
        /// before anything is read.
        pub fn open_read(&self, name: &str) -> io::Result<fs::File> {
            let fd = rustix::fs::openat(
                &self.fd,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            Ok(fs::File::from(fd))
        }

        /// A staging folder for a new file that is to take the place of
        /// `name` in this folder ([`Staging`]).
        pub fn staging(&self, name: &str) -> io::Result<Staging<'_>> {
            let mut tries = 0;
            let made = loop {
                let made = temp_name(name);
                match rustix::fs::mkdirat(&self.fd, made.as_str(), Mode::from_raw_mode(0o700)) {
                    Ok(()) => break made,
                    Err(Errno::EXIST) if tries < 16 => tries += 1,
                    Err(e) => return Err(e.into()),
                }
            };
            let opened = rustix::fs::openat(
                &self.fd,
                made.as_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            );
            let fd = match opened {
                Ok(fd) => fd,
                Err(e) => {
                    let _ = rustix::fs::unlinkat(&self.fd, made.as_str(), AtFlags::REMOVEDIR);
                    return Err(e.into());
                }
            };
            let staging = Staging {
                folder: Folder {
                    fd,
                    path: self.path.join(&made),
                },
                parent: self,
                name: made,
            };
            // Made 0700; set again in case a umask took more. Then, on
            // macOS, what the folder's access list handed down goes, before
            // anything is made in it. A failure removes it (`Drop`).
            rustix::fs::fchmod(&staging.folder.fd, Mode::from_raw_mode(0o700))?;
            #[cfg(target_os = "macos")]
            crate::perms::extended_acl::clear(&fs::File::from(staging.folder.fd.try_clone()?))?;
            Ok(staging)
        }

        /// Removes `name`, not a folder, from the folder.
        pub fn remove(&self, name: &str) -> io::Result<()> {
            Ok(rustix::fs::unlinkat(&self.fd, name, AtFlags::empty())?)
        }

        /// Flushes the folder's entries (best effort).
        pub fn sync(&self) {
            let _ = rustix::fs::fsync(&self.fd);
        }
    }

    /// A folder of the app's own, made inside a held folder for a new file
    /// to be made in and then renamed into place: mode 0700, and on macOS
    /// with its access list emptied before anything is made in it, so a
    /// file made there gets nothing a folder's list hands down, at no
    /// moment, not even before its own list could be emptied (macOS checks
    /// such entries before the mode, and a descriptor opened in that moment
    /// would stay open). It is named as the app's temporary files are
    /// (`<name>.sshkm-….tmp`), so one a crash leaves is swept
    /// ([`sweep_staging`]), and it goes, with what is left in it, when it
    /// is dropped.
    pub struct Staging<'a> {
        /// The staging folder, opened.
        pub folder: Folder,
        parent: &'a Folder,
        name: String,
    }

    impl Staging<'_> {
        /// Renames `name`, made in the staging folder, to `to` in the
        /// folder it is in. Without `replace`, fails with
        /// [`io::ErrorKind::AlreadyExists`] if something is at `to`.
        pub fn place(&self, name: &str, to: &str, replace: bool) -> io::Result<()> {
            rename_at(self.folder.fd(), name, self.parent.fd(), to, replace)
        }
    }

    impl Drop for Staging<'_> {
        fn drop(&mut self) {
            remove_staging(self.parent, &self.name, &self.folder);
        }
    }

    /// Renames `from` in the folder `from_dir` to `to` in `to_dir`. Without
    /// `replace`, fails with [`io::ErrorKind::AlreadyExists`] if something
    /// is at `to`.
    fn rename_at(
        from_dir: BorrowedFd<'_>,
        from: &str,
        to_dir: BorrowedFd<'_>,
        to: &str,
        replace: bool,
    ) -> io::Result<()> {
        if replace {
            return Ok(rustix::fs::renameat(from_dir, from, to_dir, to)?);
        }
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        match rustix::fs::renameat_with(
            from_dir,
            from,
            to_dir,
            to,
            rustix::fs::RenameFlags::NOREPLACE,
        ) {
            Ok(()) => return Ok(()),
            // Not where the file system can't: a link and an unlink, as
            // `tempfile` does.
            Err(Errno::INVAL | Errno::NOSYS | Errno::NOTSUP) => {}
            Err(e) => return Err(e.into()),
        }
        rustix::fs::linkat(from_dir, from, to_dir, to, AtFlags::empty())?;
        let _ = rustix::fs::unlinkat(from_dir, from, AtFlags::empty());
        Ok(())
    }

    /// Removes the staging folder `name` of `parent`, opened as `staging`,
    /// with what is in it that isn't a folder (nothing else is ever made in
    /// one).
    fn remove_staging(parent: &Folder, name: &str, staging: &Folder) {
        if let Ok(entries) = rustix::fs::Dir::read_from(&staging.fd) {
            let names: Vec<std::ffi::CString> = entries
                .filter_map(Result::ok)
                .map(|entry| entry.file_name().to_owned())
                .filter(|name| !matches!(name.as_bytes(), b"." | b".."))
                .collect();
            for name in names {
                let _ = rustix::fs::unlinkat(&staging.fd, name.as_c_str(), AtFlags::empty());
            }
        }
        let _ = rustix::fs::unlinkat(&parent.fd, name, AtFlags::REMOVEDIR);
    }

    /// Removes the staging folders of writes to `path` that a crash left
    /// next to it ([`Staging`]), with what they hold: a file's values in
    /// plain text, or a pipe. Only folders, never through a link.
    pub fn sweep_staging(path: &Path) {
        let Ok((parent, name)) = super::open_parent(path) else {
            return;
        };
        let Ok(entries) = fs::read_dir(parent.path()) else {
            return;
        };
        for entry in entries.filter_map(Result::ok) {
            let Some(found) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !fsutil::is_private_temp(&found, name) {
                continue;
            }
            let is_folder = parent
                .entry(&found)
                .ok()
                .flatten()
                .is_some_and(|entry| entry.kind == Kind::Folder);
            if !is_folder {
                continue;
            }
            if let Ok(fd) = rustix::fs::openat(
                &parent.fd,
                found.as_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                let staging = Folder {
                    fd,
                    path: parent.path.join(&found),
                };
                remove_staging(&parent, &found, &staging);
            }
        }
    }

    /// `device:inode` of an open file or folder, as the standard library
    /// gives them (the way `FileId` is made).
    fn token(fd: BorrowedFd<'_>) -> io::Result<String> {
        let meta = fs::File::from(fd.try_clone_to_owned()?).metadata()?;
        Ok(format!("{}:{}", meta.dev(), meta.ino()))
    }

    /// What a name in a folder is, not following a link.
    pub struct Entry {
        pub kind: Kind,
        pub dev: u64,
        pub ino: u64,
        pub len: u64,
        /// When its contents last changed, since 1970; `None` before.
        pub modified: Option<(i64, u32)>,
        /// When it was made, where the system says (Linux).
        pub born: Option<(i64, u32)>,
    }

    impl Entry {
        /// On Linux through a descriptor that is only a path (`O_PATH`),
        /// which opens nothing, read as the standard library reads it.
        #[cfg(target_os = "linux")]
        fn at(dir: BorrowedFd<'_>, name: &str) -> io::Result<Self> {
            let fd = rustix::fs::openat(
                dir,
                name,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            let meta = fs::File::from(fd).metadata()?;
            Ok(Self::of(&meta))
        }

        /// Elsewhere from `fstatat`, which opens nothing, with the values
        /// as the standard library gives them.
        #[cfg(not(target_os = "linux"))]
        #[allow(
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation,
            clippy::unnecessary_cast,
            reason = "as std's `MetadataExt` converts them"
        )]
        fn at(dir: BorrowedFd<'_>, name: &str) -> io::Result<Self> {
            use rustix::fs::FileType;
            let stat = rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?;
            let kind = match FileType::from_raw_mode(stat.st_mode as rustix::fs::RawMode) {
                FileType::RegularFile => Kind::File,
                FileType::Directory => Kind::Folder,
                FileType::Symlink => Kind::Link,
                FileType::Fifo => Kind::Pipe,
                _ => Kind::Other,
            };
            Ok(Self {
                kind,
                dev: stat.st_dev as u64,
                ino: stat.st_ino as u64,
                len: stat.st_size as u64,
                modified: (stat.st_mtime >= 0)
                    .then_some((stat.st_mtime as i64, stat.st_mtime_nsec as u32)),
                born: None,
            })
        }

        /// The standard library's metadata of a file, as an entry.
        #[cfg(any(target_os = "linux", test))]
        pub fn of(meta: &fs::Metadata) -> Self {
            use std::os::unix::fs::FileTypeExt as _;
            let kind = meta.file_type();
            let since = |time: io::Result<std::time::SystemTime>| {
                let since = time.ok()?.duration_since(std::time::UNIX_EPOCH).ok()?;
                Some((i64::try_from(since.as_secs()).ok()?, since.subsec_nanos()))
            };
            Self {
                kind: if kind.is_symlink() {
                    Kind::Link
                } else if kind.is_file() {
                    Kind::File
                } else if kind.is_dir() {
                    Kind::Folder
                } else if kind.is_fifo() {
                    Kind::Pipe
                } else {
                    Kind::Other
                },
                dev: meta.dev(),
                ino: meta.ino(),
                len: meta.len(),
                modified: since(meta.modified()),
                born: if cfg!(target_os = "linux") {
                    since(meta.created())
                } else {
                    None
                },
            }
        }
    }

    pub(super) fn write_private(
        folder: &Folder,
        name: &str,
        bytes: &[u8],
        overwrite: bool,
        keep_out: bool,
        placing: impl FnOnce(&fs::Metadata) -> crate::Result<()>,
    ) -> crate::Result<bool> {
        // Made in a staging folder of its own, where nothing is handed down
        // to it, then renamed into place.
        let staging = folder
            .staging(name)
            .map_err(|e| Error::io(e, folder.path()))?;
        let temp_path = staging.folder.path().join(name);
        let mut file = fs::File::from(
            rustix::fs::openat(
                staging.folder.fd(),
                name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|e| Error::io(e.into(), &temp_path))?,
        );
        let written = (|| -> crate::Result<()> {
            // Made 0600; set again in case a umask took more. Its access
            // list is empty already, made where none is handed down; it is
            // emptied once more all the same (macOS).
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| Error::io(e, &temp_path))?;
            #[cfg(target_os = "macos")]
            crate::perms::extended_acl::clear(&file).map_err(|e| Error::io(e, &temp_path))?;
            if keep_out {
                fsutil::keep_out_of_copies(&file);
            }
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|e| Error::io(e, &temp_path))?;
            let meta = file.metadata().map_err(|e| Error::io(e, &temp_path))?;
            placing(&meta)
        })();
        drop(file);
        let placed = written.and_then(|()| match staging.place(name, name, overwrite) {
            Ok(()) => Ok(true),
            Err(e) if !overwrite && e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(Error::io(e, &folder.path().join(name))),
        });
        // The staging folder goes, and what is left in it.
        drop(staging);
        if matches!(placed, Ok(true)) {
            folder.sync();
        }
        placed
    }
}

#[cfg(windows)]
mod imp {
    //! `GetFinalPathNameByHandleW` through `windows`, on a handle the call
    //! borrows.
    #![allow(unsafe_code)]

    use std::ffi::OsString;
    use std::fs;
    use std::io;
    use std::os::windows::ffi::OsStringExt as _;
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use std::path::{Path, PathBuf};

    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_NAME_NORMALIZED,
        FILE_SHARE_READ, FILE_SHARE_WRITE, GetFinalPathNameByHandleW,
    };

    use crate::fsutil;

    /// A folder, held open: as long as it is, no one can rename or delete
    /// it.
    pub struct Folder {
        held: fs::File,
        path: PathBuf,
    }

    impl Folder {
        /// The folder at `path`, held open without letting it be renamed
        /// or deleted, and never a link, junction or mount point itself
        /// (a reparse point that names another place). A folder that is a
        /// reparse point of another kind, such as `OneDrive`'s folders
        /// kept in the cloud, is a folder like any other.
        pub fn open(path: &Path) -> io::Result<Self> {
            let held = fs::OpenOptions::new()
                .read(true)
                .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE).0)
                .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
                .open(path)?;
            let kind = held.metadata()?.file_type();
            // `is_symlink`: a name-surrogate reparse point, as `disk::read`
            // refuses for a file.
            if kind.is_symlink() || !kind.is_dir() {
                return Err(io::Error::other("not a folder"));
            }
            Ok(Self {
                held,
                path: path.to_path_buf(),
            })
        }

        pub fn path(&self) -> &Path {
            &self.path
        }

        /// Which folder it is, as `FileId::token` says it: its full path
        /// with links resolved, without case, from its handle.
        pub fn token(&self) -> io::Result<String> {
            let mut buffer = vec![0u16; 1024];
            loop {
                // SAFETY: the handle is open for the call; the buffer is
                // written up to its length.
                let len = unsafe {
                    GetFinalPathNameByHandleW(
                        HANDLE(self.held.as_raw_handle()),
                        &mut buffer,
                        FILE_NAME_NORMALIZED,
                    )
                } as usize;
                if len == 0 {
                    return Err(io::Error::last_os_error());
                }
                if len < buffer.len() {
                    let path = OsString::from_wide(&buffer[..len]);
                    return Ok(path.to_string_lossy().to_lowercase());
                }
                if buffer.len() >= 1 << 16 {
                    return Err(io::Error::other("a path too long"));
                }
                buffer.resize(len + 1, 0);
            }
        }

        /// Whether `root` (a token) is this folder or a folder it is in.
        pub fn is_within(&self, root: &str) -> bool {
            self.token()
                .is_ok_and(|here| Path::new(&here).starts_with(Path::new(root)))
        }

        pub fn entry(&self, name: &str) -> io::Result<Option<Entry>> {
            match fs::symlink_metadata(self.path.join(name)) {
                Ok(meta) => Ok(Some(Entry::of(&meta))),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        }

        pub fn remove(&self, name: &str) -> io::Result<()> {
            fs::remove_file(self.path.join(name))
        }
    }

    /// No staging folders here: a private file gets its own access list as
    /// it is made ([`fsutil::replace_private`]).
    pub fn sweep_staging(_: &Path) {}

    /// What a name in a folder is, not following a link.
    pub struct Entry {
        pub kind: super::Kind,
    }

    impl Entry {
        pub fn of(meta: &fs::Metadata) -> Self {
            use super::Kind;
            let kind = meta.file_type();
            Self {
                kind: if kind.is_symlink() {
                    Kind::Link
                } else if kind.is_file() {
                    Kind::File
                } else if kind.is_dir() {
                    Kind::Folder
                } else {
                    Kind::Other
                },
            }
        }
    }

    pub(super) fn write_private(
        folder: &Folder,
        name: &str,
        bytes: &[u8],
        overwrite: bool,
        keep_out: bool,
        placing: impl FnOnce(&fs::Metadata) -> crate::Result<()>,
    ) -> crate::Result<bool> {
        // By path, while the folder is held: its path leads nowhere else.
        let path = folder.path.join(name);
        if !fsutil::replace_private(&path, bytes, overwrite, keep_out)? {
            return Ok(false);
        }
        let meta = fs::symlink_metadata(&path).map_err(|e| crate::Error::io(e, &path))?;
        placing(&meta)?;
        Ok(true)
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};

    pub struct Folder {
        path: PathBuf,
    }

    impl Folder {
        pub fn open(path: &Path) -> io::Result<Self> {
            Ok(Self {
                path: path.to_path_buf(),
            })
        }

        pub fn path(&self) -> &Path {
            &self.path
        }

        pub fn token(&self) -> io::Result<String> {
            Err(io::Error::other("not on this system"))
        }

        pub fn is_within(&self, _: &str) -> bool {
            false
        }

        pub fn entry(&self, _: &str) -> io::Result<Option<Entry>> {
            Ok(None)
        }

        pub fn remove(&self, _: &str) -> io::Result<()> {
            Err(io::Error::other("not on this system"))
        }
    }

    pub fn sweep_staging(_: &Path) {}

    pub struct Entry {
        pub kind: super::Kind,
    }

    pub(super) fn write_private(
        _: &Folder,
        _: &str,
        _: &[u8],
        _: bool,
        _: bool,
        _: impl FnOnce(&fs::Metadata) -> crate::Result<()>,
    ) -> crate::Result<bool> {
        Err(crate::Error::Unsupported("not on this system".into()))
    }
}

/// The folder of `path`, opened as [`Folder::open`] does, and the name of
/// `path` in it.
pub(super) fn open_parent(path: &Path) -> io::Result<(Folder, &str)> {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) else {
        return Err(io::Error::other("not a file in a folder"));
    };
    Ok((Folder::open(dir)?, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_folder_is_checked_as_it_was_opened() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let sub = root.join("sub");
        fs::create_dir(&sub).unwrap();
        let token = |path: &Path| Folder::open(path).unwrap().token().unwrap();
        let (root_id, sub_id) = (token(&root), token(&sub));
        assert!(Folder::checked(&sub, &sub_id, &root_id).is_some());
        assert!(Folder::checked(&root, &root_id, &root_id).is_some());
        // Not the folder found, or not inside the project's.
        assert!(Folder::checked(&sub, &root_id, &root_id).is_none());
        let other = tempfile::tempdir().unwrap();
        let other = fs::canonicalize(other.path()).unwrap();
        assert!(Folder::checked(&other, &token(&other), &root_id).is_none());
        assert!(Folder::checked(&root.join("missing"), &sub_id, &root_id).is_none());
        // A link at the folder's own name is never opened.
        #[cfg(unix)]
        {
            let link = root.join("link");
            std::os::unix::fs::symlink(&sub, &link).unwrap();
            assert!(Folder::open(&link).is_err());
            // Held, it stays the folder checked, wherever its path leads.
            let held = Folder::checked(&sub, &sub_id, &root_id).unwrap();
            fs::rename(&sub, root.join("moved")).unwrap();
            std::os::unix::fs::symlink(&other, &sub).unwrap();
            assert!(
                held.write_private(".env", b"A=1\n", false, false, |_| Ok(()))
                    .unwrap()
            );
            assert_eq!(fs::read(root.join("moved").join(".env")).unwrap(), b"A=1\n");
            assert!(!other.join(".env").exists());
        }
    }

    /// A folder whose access list lets everyone read what is made in it
    /// hands nothing down to a file written through it, nor to a pipe
    /// made in it (macOS checks those entries before the mode), at no
    /// moment: they are made in a staging folder that has no entry from
    /// the moment anything can be made in it.
    #[cfg(target_os = "macos")]
    #[test]
    fn files_and_pipes_made_in_a_folder_never_carry_what_it_hands_down() {
        use crate::perms::extended_acl::testing::{entries, sharing_folder};
        let dir = sharing_folder();
        let folder = Folder::open(dir.path()).unwrap();
        // A file made in a staging folder, as it is made: nothing on it,
        // though nothing has emptied its list.
        {
            let staging = folder.staging(".env").unwrap();
            assert_eq!(entries(staging.folder.path()), 0);
            let fd = rustix::fs::openat(
                staging.folder.fd(),
                "made",
                rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CREATE,
                rustix::fs::Mode::from_raw_mode(0o600),
            )
            .unwrap();
            drop(fd);
            assert_eq!(entries(&staging.folder.path().join("made")), 0);
        }
        let leftovers = || {
            fs::read_dir(dir.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .filter(|name| name.to_string_lossy().ends_with(".tmp"))
                .count()
        };
        assert_eq!(leftovers(), 0);
        let mut seen = None;
        assert!(
            folder
                .write_private(".env", b"A=1\n", false, true, |_| {
                    // The staging folder and the new file in it, before it
                    // takes its place.
                    seen = fs::read_dir(dir.path())
                        .unwrap()
                        .map(|entry| entry.unwrap().path())
                        .find(|path| path.to_string_lossy().ends_with(".tmp"))
                        .map(|staging| (entries(&staging), entries(&staging.join(".env"))));
                    Ok(())
                })
                .unwrap()
        );
        assert_eq!(seen, Some((0, 0)));
        assert_eq!(entries(&dir.path().join(".env")), 0);
        assert_eq!(leftovers(), 0);
        // Rewritten, too.
        assert!(
            folder
                .write_private(".env", b"A=2\n", true, false, |_| Ok(()))
                .unwrap()
        );
        assert_eq!(entries(&dir.path().join(".env")), 0);
        // A pipe, made where nothing is, or in a file's place.
        super::super::pipes::make_in(&folder, ".env.local").unwrap();
        assert_eq!(entries(&dir.path().join(".env.local")), 0);
        let made = super::super::pipes::make_over_in(&folder, ".env", b"A=2\n")
            .unwrap()
            .unwrap();
        assert_eq!(
            super::super::pipes::PipeId::of(&dir.path().join(".env")),
            Some(made)
        );
        assert_eq!(entries(&dir.path().join(".env")), 0);
        assert_eq!(leftovers(), 0);
        // A file made the ordinary way there still gets the entry.
        fs::write(dir.path().join("other"), "").unwrap();
        assert_eq!(entries(&dir.path().join("other")), 1);
    }

    /// A junction, which names another place, is never held as the folder;
    /// a plain folder is, by the path Windows gives for it.
    #[cfg(windows)]
    #[test]
    fn a_junction_is_never_held_as_a_folder() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let target = root.join("target");
        fs::create_dir(&target).unwrap();
        let held = Folder::open(&target).unwrap();
        assert_eq!(
            held.token().unwrap(),
            target.to_string_lossy().to_lowercase()
        );
        let junction = root.join("junction");
        let made = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(&junction)
            .arg(&target)
            .output()
            .is_ok_and(|out| out.status.success());
        if made {
            assert!(Folder::open(&junction).is_err());
        }
    }

    /// A staging folder a crash left, with the values in it, is swept;
    /// a folder of the user's is left alone.
    #[cfg(unix)]
    #[test]
    fn staging_folders_a_crash_left_are_swept() {
        let dir = tempfile::tempdir().unwrap();
        let folder = Folder::open(dir.path()).unwrap();
        let staging = folder.staging(".env").unwrap();
        let left = staging.folder.path().to_path_buf();
        fs::write(left.join(".env"), "API_TOKEN=tok-1\n").unwrap();
        // The app went before it could remove it.
        std::mem::forget(staging);
        let mine = dir.path().join("keep.tmp");
        fs::create_dir(&mine).unwrap();
        fs::write(mine.join(".env"), "MINE=1\n").unwrap();
        sweep_staging(&dir.path().join(".env"));
        assert!(!left.exists());
        assert!(mine.join(".env").exists());
        // Nor is the staging folder of another file swept for this one.
        let other = folder.staging(".env.local").unwrap();
        let other_path = other.folder.path().to_path_buf();
        std::mem::forget(other);
        sweep_staging(&dir.path().join(".env"));
        assert!(other_path.exists());
        sweep_staging(&dir.path().join(".env.local"));
        assert!(!other_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn private_writes_through_a_folder_replace_and_leave_no_temporary_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let folder = Folder::open(dir.path()).unwrap();
        assert!(
            folder
                .write_private(".env", b"A=1\n", false, false, |_| Ok(()))
                .unwrap()
        );
        // Without overwriting, what is there stays.
        assert!(
            !folder
                .write_private(".env", b"A=2\n", false, false, |_| Ok(()))
                .unwrap()
        );
        assert_eq!(fs::read(dir.path().join(".env")).unwrap(), b"A=1\n");
        // A link there is replaced, never written through.
        let elsewhere = dir.path().join("elsewhere");
        fs::write(&elsewhere, "keep").unwrap();
        fs::remove_file(dir.path().join(".env")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.path().join(".env")).unwrap();
        let mut seen = None;
        assert!(
            folder
                .write_private(".env", b"A=3\n", true, false, |meta| {
                    seen = Some(imp::Entry::of(meta).len);
                    Ok(())
                })
                .unwrap()
        );
        assert_eq!(seen, Some(4));
        assert_eq!(fs::read_to_string(&elsewhere).unwrap(), "keep");
        let meta = fs::symlink_metadata(dir.path().join(".env")).unwrap();
        assert!(meta.is_file());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        // A write its caller stops leaves nothing.
        let stopped = folder.write_private(".env", b"A=4\n", true, false, |_| {
            Err(crate::Error::invalid("no"))
        });
        assert!(stopped.is_err());
        assert_eq!(fs::read(dir.path().join(".env")).unwrap(), b"A=3\n");
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 2, "{names:?}");
    }
}
