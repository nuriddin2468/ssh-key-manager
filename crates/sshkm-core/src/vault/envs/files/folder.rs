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
//! A new file or pipe is made where it waits before it takes its place
//! (`Making`), then renamed into place: on macOS in a private folder of its
//! own inside that folder (`fsutil::private_folder`), mode 0700 with its
//! access list emptied before anything is made in it, so nothing a folder's
//! list hands down (which macOS checks before the mode) is on the file at
//! any moment; on Linux, which masks a folder's default access list with
//! the mode, under a temporary name in the folder itself. What a crash
//! leaves of either is swept with the file's temporary files
//! ([`fsutil::sweep_private_temps`](crate::fsutil::sweep_private_temps)).
//!
//! On Windows the folder is held open, without letting it be renamed or
//! deleted, for as long as it is used, and the folder held is checked by
//! the path Windows gives for its handle: the folder found, inside the
//! project's. Files in it are then used by their paths.

use std::fs;
use std::io;
use std::path::Path;

/// What a temporary file of a write to `name` is called: `name` with
/// `fsutil::PRIVATE_TEMP` around a random tag (`.env.sshkm-Ab12Cd.tmp`),
/// as the app's other temporary files are, so the sweeps of what a crash
/// left find it.
#[cfg(all(unix, not(target_os = "macos")))]
fn temp_name(name: &str) -> String {
    use rand_core::{OsRng, RngCore};
    const LETTERS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut bytes = [0u8; 6];
    OsRng.fill_bytes(&mut bytes);
    let tag: String = bytes
        .iter()
        .map(|b| char::from(LETTERS[usize::from(*b) % LETTERS.len()]))
        .collect();
    let (before, after) = crate::fsutil::PRIVATE_TEMP;
    format!("{name}{before}{tag}{after}")
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

pub(super) use imp::Folder;
#[cfg(unix)]
pub(super) use imp::{Entry, Making};

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

    #[cfg(target_os = "macos")]
    use std::ffi::OsStr;

    use rustix::fs::{AtFlags, Mode, OFlags};
    #[cfg(not(target_os = "macos"))]
    use rustix::io::Errno;

    use super::Kind;
    #[cfg(target_os = "macos")]
    use crate::fsutil::private_folder::PrivateFolder;
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

        /// Where a new file or pipe that is to take the place of `name` in
        /// this folder is made first ([`Making`]).
        #[cfg_attr(
            not(target_os = "macos"),
            allow(
                clippy::unnecessary_wraps,
                reason = "making the private folder can fail on macOS"
            )
        )]
        pub fn making(&self, name: &str) -> io::Result<Making<'_>> {
            #[cfg(target_os = "macos")]
            let private = PrivateFolder::make_in(self.fd(), OsStr::new(name))?;
            Ok(Making {
                folder: self,
                name: name.to_owned(),
                #[cfg(target_os = "macos")]
                private,
                #[cfg(not(target_os = "macos"))]
                temp: super::temp_name(name),
            })
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

    /// Where a new file or pipe is made before it takes the place of
    /// `name` in a held folder: on macOS a private folder of its own made in
    /// it ([`PrivateFolder`]: mode 0700, its access list emptied before
    /// anything is made in it, so nothing made there carries an entry a
    /// folder's list hands down, at any moment); elsewhere the folder itself,
    /// under a temporary name (`<name>.sshkm-….tmp`; Linux masks a folder's
    /// default access list with the mode). What is left of it goes when it
    /// is dropped; what a crash leaves is swept with the file's temporary
    /// files (`fsutil::sweep_private_temps`).
    pub struct Making<'a> {
        /// The held folder; on macOS the private folder holds its own
        /// descriptor of it.
        #[cfg_attr(target_os = "macos", allow(dead_code, reason = "held by `private`"))]
        folder: &'a Folder,
        name: String,
        #[cfg(target_os = "macos")]
        private: PrivateFolder,
        #[cfg(not(target_os = "macos"))]
        temp: String,
    }

    impl Making<'_> {
        /// The folder and the name a new file or pipe is made at.
        pub fn at(&self) -> (BorrowedFd<'_>, &str) {
            #[cfg(target_os = "macos")]
            {
                (self.private.as_fd(), &self.name)
            }
            #[cfg(not(target_os = "macos"))]
            {
                (self.folder.fd(), &self.temp)
            }
        }

        /// Creates the new file, mode 0600, where nothing was, to write to.
        pub fn create(&self) -> io::Result<fs::File> {
            #[cfg(target_os = "macos")]
            {
                self.private.create(OsStr::new(&self.name))
            }
            #[cfg(not(target_os = "macos"))]
            {
                let fd = rustix::fs::openat(
                    self.folder.fd(),
                    self.temp.as_str(),
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::RUSR | Mode::WUSR,
                )?;
                Ok(fs::File::from(fd))
            }
        }

        /// The path of the new pipe, in the private folder as its path is
        /// now, for `mkfifo`: `mkfifoat` needs macOS 13. What is made there
        /// is then looked at through the folder ([`Self::owner_only`],
        /// [`Self::entry`]).
        #[cfg(target_os = "macos")]
        pub fn path(&self) -> io::Result<PathBuf> {
            Ok(self.private.path()?.join(&self.name))
        }

        /// What was made is this user's (on macOS, looked up through the
        /// private folder, no link followed), and mode 0600.
        pub fn owner_only(&self) -> io::Result<()> {
            #[cfg(target_os = "macos")]
            {
                self.private.holds(OsStr::new(&self.name))
            }
            #[cfg(not(target_os = "macos"))]
            {
                Ok(rustix::fs::chmodat(
                    self.folder.fd(),
                    self.temp.as_str(),
                    Mode::RUSR | Mode::WUSR,
                    AtFlags::empty(),
                )?)
            }
        }

        /// What was made, not following a link, without opening it.
        pub fn entry(&self) -> io::Result<Option<Entry>> {
            let (dir, name) = self.at();
            match Entry::at(dir, name) {
                Ok(entry) => Ok(Some(entry)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        }

        /// Renames what was made to `name` in the held folder: over
        /// whatever is there with `replace` (a link included, replaced, not
        /// followed); else it fails with [`io::ErrorKind::AlreadyExists`]
        /// if something is there.
        pub fn place(&self, replace: bool) -> io::Result<()> {
            #[cfg(target_os = "macos")]
            {
                let name = OsStr::new(&self.name);
                self.private.place(name, name, replace)
            }
            #[cfg(not(target_os = "macos"))]
            {
                let (dir, temp) = (self.folder.fd(), self.temp.as_str());
                if replace {
                    return Ok(rustix::fs::renameat(dir, temp, dir, self.name.as_str())?);
                }
                match rustix::fs::renameat_with(
                    dir,
                    temp,
                    dir,
                    self.name.as_str(),
                    rustix::fs::RenameFlags::NOREPLACE,
                ) {
                    Ok(()) => Ok(()),
                    // Where the file system can't: a second name, which
                    // can't replace one, then the first removed.
                    Err(Errno::INVAL | Errno::NOSYS | Errno::NOTSUP) => {
                        rustix::fs::linkat(dir, temp, dir, self.name.as_str(), AtFlags::empty())?;
                        let _ = rustix::fs::unlinkat(dir, temp, AtFlags::empty());
                        Ok(())
                    }
                    Err(e) => Err(e.into()),
                }
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    impl Drop for Making<'_> {
        fn drop(&mut self) {
            // Gone already once it took its place.
            let _ = rustix::fs::unlinkat(self.folder.fd(), self.temp.as_str(), AtFlags::empty());
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
        // Made where it waits before it takes its place: on macOS a private
        // folder of its own, where nothing is handed down to it.
        let target = folder.path().join(name);
        let making = folder
            .making(name)
            .map_err(|e| Error::io(e, folder.path()))?;
        let mut file = making.create().map_err(|e| Error::io(e, &target))?;
        let written = (|| -> crate::Result<()> {
            // Made 0600; set again in case a umask took more.
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| Error::io(e, &target))?;
            if keep_out {
                fsutil::keep_out_of_copies(&file);
            }
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|e| Error::io(e, &target))?;
            let meta = file.metadata().map_err(|e| Error::io(e, &target))?;
            placing(&meta)
        })();
        drop(file);
        let placed = written.and_then(|()| match making.place(overwrite) {
            Ok(()) => Ok(true),
            Err(e) if !overwrite && e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(Error::io(e, &target)),
        });
        // What is left of it goes.
        drop(making);
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
    #[cfg(unix)]
    use crate::fsutil;

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
    /// moment: they are made in a private folder of their own that has no
    /// entry from the moment anything can be made in it.
    #[cfg(target_os = "macos")]
    #[test]
    fn files_and_pipes_made_in_a_folder_never_carry_what_it_hands_down() {
        use crate::perms::extended_acl::testing::{entries, sharing_folder};
        let dir = sharing_folder();
        let folder = Folder::open(dir.path()).unwrap();
        // A file where it is made, as it is made: nothing on it, though
        // nothing has emptied its list.
        {
            let making = folder.making(".env").unwrap();
            drop(making.create().unwrap());
            let made = making.path().unwrap();
            assert_eq!(entries(made.parent().unwrap()), 0);
            assert_eq!(entries(&made), 0);
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
                    // The private folder and the new file in it, before it
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

    /// What a write that a crash cut short leaves next to the file (a
    /// private folder with the values in it on macOS, a temporary file
    /// elsewhere) goes with the sweep a round and the guard make; a
    /// folder of the user's is left alone.
    #[cfg(unix)]
    #[test]
    fn what_a_crash_leaves_of_a_write_is_swept() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let folder = Folder::open(dir.path()).unwrap();
        let making = folder.making(".env").unwrap();
        making
            .create()
            .unwrap()
            .write_all(b"API_TOKEN=tok-1\n")
            .unwrap();
        // The app went before it could remove it.
        std::mem::forget(making);
        let left = || {
            fs::read_dir(dir.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .filter(|name| fsutil::is_private_temp(&name.to_string_lossy(), ".env"))
                .count()
        };
        assert_eq!(left(), 1);
        let mine = dir.path().join("keep.tmp");
        fs::create_dir(&mine).unwrap();
        fs::write(mine.join(".env"), "MINE=1\n").unwrap();
        fsutil::sweep_private_temps(&dir.path().join(".env"));
        assert_eq!(left(), 0);
        assert!(mine.join(".env").exists());
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
                    seen = Some(Entry::of(meta).len);
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
