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
//! On Windows the folder is held open, without letting it be renamed or
//! deleted, for as long as it is used, and the folder held is checked by
//! the path Windows gives for its handle: the folder found, inside the
//! project's. Files in it are then used by their paths.

use std::fs;
use std::io;
use std::path::Path;

use crate::fsutil;

/// What a temporary file of a write to `name` is called: `name` with
/// [`fsutil::PRIVATE_TEMP`] around a random tag (`.env.sshkm-Ab12Cd.tmp`),
/// so the sweeps of what a crash left find it
/// ([`fsutil::sweep_private_temps`]).
pub(super) fn temp_name(name: &str) -> String {
    format!(
        "{name}{}{}{}",
        fsutil::PRIVATE_TEMP.0,
        random_tag(),
        fsutil::PRIVATE_TEMP.1
    )
}

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
    Pipe,
    Other,
}

pub(super) use imp::Folder;

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
    /// file over it, readable by its owner only (mode 0600 on Unix; on
    /// Windows an access list for nobody but the user, `SYSTEM` and
    /// `Administrators`, [`fsutil::replace_private`]). Whatever is at
    /// `name`, a link included, is replaced, never written through; without
    /// `overwrite`, nothing is written if something is there by then, and
    /// the call returns `false`. With `keep_out`, the new file is kept out
    /// of backups and cloud folders before it holds anything (Unix) or
    /// before it takes its place (Windows). `placing` is told what the new
    /// file is on disk before it takes its place on Unix, right after on
    /// Windows; an error from it stops the write.
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

        /// A new file in the folder for a write to `name`, readable and
        /// writable by its owner only, where nothing was: its name
        /// ([`temp_name`]) and the file.
        pub fn create_temp(&self, name: &str) -> io::Result<(String, fs::File)> {
            let mut tries = 0;
            loop {
                let temp = temp_name(name);
                match rustix::fs::openat(
                    &self.fd,
                    temp.as_str(),
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                ) {
                    Ok(fd) => return Ok((temp, fs::File::from(fd))),
                    Err(Errno::EXIST) if tries < 16 => tries += 1,
                    Err(e) => return Err(e.into()),
                }
            }
        }

        /// Renames `from` to `to` in the folder. Without `replace`, fails
        /// with [`io::ErrorKind::AlreadyExists`] if something is at `to`.
        pub fn rename(&self, from: &str, to: &str, replace: bool) -> io::Result<()> {
            if replace {
                return Ok(rustix::fs::renameat(&self.fd, from, &self.fd, to)?);
            }
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            match rustix::fs::renameat_with(
                &self.fd,
                from,
                &self.fd,
                to,
                rustix::fs::RenameFlags::NOREPLACE,
            ) {
                Ok(()) => return Ok(()),
                // Not where the file system can't: a link and an unlink,
                // as `tempfile` does.
                Err(Errno::INVAL | Errno::NOSYS | Errno::NOTSUP) => {}
                Err(e) => return Err(e.into()),
            }
            rustix::fs::linkat(&self.fd, from, &self.fd, to, AtFlags::empty())?;
            let _ = rustix::fs::unlinkat(&self.fd, from, AtFlags::empty());
            Ok(())
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
        let (temp, mut file) = folder
            .create_temp(name)
            .map_err(|e| Error::io(e, folder.path()))?;
        let temp_path = folder.path().join(&temp);
        let written = (|| -> crate::Result<()> {
            // Made 0600; set again in case a umask took more.
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| Error::io(e, &temp_path))?;
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
        let placed = written.and_then(|()| match folder.rename(&temp, name, overwrite) {
            Ok(()) => Ok(true),
            Err(e) if !overwrite && e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(Error::io(e, &folder.path().join(name))),
        });
        if matches!(placed, Ok(true)) {
            folder.sync();
        } else {
            let _ = folder.remove(&temp);
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
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use std::os::windows::io::AsRawHandle as _;
    use std::path::{Path, PathBuf};

    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_NAME_NORMALIZED, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFinalPathNameByHandleW,
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
        /// or deleted, and never a link or junction itself.
        pub fn open(path: &Path) -> io::Result<Self> {
            let held = fs::OpenOptions::new()
                .read(true)
                .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE).0)
                .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
                .open(path)?;
            let meta = held.metadata()?;
            if !meta.is_dir() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
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

        pub fn rename(&self, from: &str, to: &str, replace: bool) -> io::Result<()> {
            let to = self.path.join(to);
            if !replace && fs::symlink_metadata(&to).is_ok() {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            fs::rename(self.path.join(from), to)
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

        pub fn rename(&self, _: &str, _: &str, _: bool) -> io::Result<()> {
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
