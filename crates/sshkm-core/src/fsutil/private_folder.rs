//! A folder for this user alone, to make a private file in (macOS).
//!
//! A folder's access list can hand its entries down to what is made in it,
//! and macOS checks those entries before the mode: a 0600 file made in a
//! folder that lets everyone read its files is readable by everyone from
//! the moment it exists. Emptying the file's list afterwards comes too late
//! for someone who opened it in between, as access is checked only when a
//! file is opened. So a private file is made in a new folder of its own,
//! next to where it goes: the folder is made 0700 and its list emptied
//! before anything is made in it, so nothing made there inherits an entry.
//! Someone who opened the folder in that moment can list it, but can't open
//! what is made in it later: each name is checked as it is looked up. The
//! file is then renamed into place, which leaves its access list as it is,
//! and the folder removed.
//!
//! The folder is used through descriptors (`openat`, `renameatx_np`,
//! `unlinkat`), so a folder put at its name by someone else changes nothing.
//! Only a pipe is made by path, since `mkfifoat` needs macOS 13; it is then
//! looked up through the folder held before it is used ([`PrivateFolder::holds`]).

use std::ffi::{CString, OsStr};
use std::fs;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags};
use rustix::io::Errno;

use super::PRIVATE_TEMP;

/// Names tried for the folder before giving up.
const ATTEMPTS: usize = 16;

/// A new folder that only this user can enter, in a folder held open; it is
/// removed, with whatever is still in it, when dropped.
pub(crate) struct PrivateFolder {
    parent: OwnedFd,
    fd: OwnedFd,
    name: CString,
}

impl PrivateFolder {
    /// Makes one in the folder at `parent` for a file named `name`.
    pub(crate) fn make(parent: &std::path::Path, name: &OsStr) -> io::Result<Self> {
        let parent = rustix::fs::open(
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Self::make_owned(parent, name)
    }

    /// Makes one in the folder open as `parent`, for a file named `name`.
    /// The folder is held from then on, so the file is placed in it, as it
    /// is, whatever its path leads to by then.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "for writes through a folder held open, such as a managed `.env` file's"
        )
    )]
    pub(crate) fn make_in(parent: BorrowedFd<'_>, name: &OsStr) -> io::Result<Self> {
        Self::make_owned(parent.try_clone_to_owned()?, name)
    }

    /// The folder is named `<name>.sshkm-<random>.tmp`, so that `.env*`
    /// ignore rules cover it and the sweeps of what a crash left find it
    /// (`fsutil::sweep_private_temps`, `fsutil::sweep_abandoned_temps`).
    fn make_owned(parent: OwnedFd, name: &OsStr) -> io::Result<Self> {
        let mut made = None;
        for _ in 0..ATTEMPTS {
            let mut folder = name.as_bytes().to_vec();
            folder.extend_from_slice(PRIVATE_TEMP.0.as_bytes());
            folder.extend_from_slice(random_tag().as_bytes());
            folder.extend_from_slice(PRIVATE_TEMP.1.as_bytes());
            let folder = CString::new(folder).map_err(|_| io::ErrorKind::InvalidInput)?;
            match rustix::fs::mkdirat(&parent, folder.as_c_str(), Mode::RWXU) {
                Ok(()) => {
                    made = Some(folder);
                    break;
                }
                Err(Errno::EXIST) => {}
                Err(e) => return Err(e.into()),
            }
        }
        let name = made.ok_or(io::ErrorKind::AlreadyExists)?;
        let fd = match rustix::fs::openat(
            &parent,
            name.as_c_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(e) => {
                let _ = rustix::fs::unlinkat(&parent, name.as_c_str(), AtFlags::REMOVEDIR);
                return Err(e.into());
            }
        };
        let folder = Self { parent, fd, name };
        // Only its owner may set its mode, so this is the folder just made,
        // not one put at its name meanwhile.
        rustix::fs::fchmod(&folder.fd, Mode::RWXU)?;
        crate::perms::extended_acl::clear(&folder.fd)?;
        Ok(folder)
    }

    /// Creates the new file `name` in the folder, mode 0600, to write to.
    pub(crate) fn create(&self, name: &OsStr) -> io::Result<fs::File> {
        let fd = rustix::fs::openat(
            &self.fd,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?;
        Ok(fs::File::from(fd))
    }

    /// The folder's path as it is now, for what can't be made through a
    /// descriptor (a pipe). What is made there is then checked with
    /// [`Self::holds`].
    pub(crate) fn path(&self) -> io::Result<PathBuf> {
        let path = rustix::fs::getpath(&self.fd)?;
        Ok(PathBuf::from(OsStr::from_bytes(path.as_bytes())))
    }

    /// Fails unless `name`, looked up through the folder held (no link
    /// followed), is there and this user's, and sets its mode to 0600.
    pub(crate) fn holds(&self, name: &OsStr) -> io::Result<()> {
        let owner = rustix::fs::fstat(&self.fd)?.st_uid;
        let found = rustix::fs::statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW)?;
        if found.st_uid != owner {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(rustix::fs::chmodat(
            &self.fd,
            name,
            Mode::RUSR | Mode::WUSR,
            AtFlags::empty(),
        )?)
    }

    /// Renames `name` from the folder to `to` in the folder it was made
    /// in: over whatever is there with `replace` (a link included, which
    /// is replaced, not followed); else it fails with `AlreadyExists` if
    /// something is there.
    pub(crate) fn place(&self, name: &OsStr, to: &OsStr, replace: bool) -> io::Result<()> {
        if replace {
            return Ok(rustix::fs::renameat(&self.fd, name, &self.parent, to)?);
        }
        match rustix::fs::renameat_with(&self.fd, name, &self.parent, to, RenameFlags::NOREPLACE) {
            Ok(()) => Ok(()),
            // A file system that can't refuse an existing name in a rename
            // (some network shares): a second name, which can't replace one,
            // then the first one removed.
            Err(Errno::INVAL | Errno::NOTSUP | Errno::NOSYS) => {
                rustix::fs::linkat(&self.fd, name, &self.parent, to, AtFlags::empty())?;
                let _ = rustix::fs::unlinkat(&self.fd, name, AtFlags::empty());
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }
}

impl AsFd for PrivateFolder {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl Drop for PrivateFolder {
    fn drop(&mut self) {
        // What a write that failed left in it.
        let left: Vec<CString> = rustix::fs::Dir::read_from(&self.fd)
            .map(|dir| {
                dir.filter_map(Result::ok)
                    .map(|entry| entry.file_name().to_owned())
                    .filter(|name| name.as_bytes() != b"." && name.as_bytes() != b"..")
                    .collect()
            })
            .unwrap_or_default();
        for name in left {
            let _ = rustix::fs::unlinkat(&self.fd, name.as_c_str(), AtFlags::empty());
        }
        let _ = rustix::fs::unlinkat(&self.parent, self.name.as_c_str(), AtFlags::REMOVEDIR);
    }
}

/// Six random letters and digits.
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

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::process::Command;

    use super::*;
    use crate::perms::extended_acl::testing::{entries, sharing_folder};

    /// A file and a pipe made through a private folder carry no entry of
    /// the folder's access list at any step, unlike one made there directly.
    #[test]
    fn what_is_made_inside_never_inherits_an_entry() {
        let dir = sharing_folder();
        let direct = dir.path().join("direct");
        fs::write(&direct, "").unwrap();
        assert_eq!(entries(&direct), 1);

        let name = OsStr::new("passwords.csv");
        let folder = PrivateFolder::make(dir.path(), name).unwrap();
        let inside = folder.path().unwrap();
        assert_eq!(entries(&inside), 0);
        assert_eq!(
            inside.parent(),
            Some(fs::canonicalize(dir.path()).unwrap().as_path())
        );
        let mut file = folder.create(name).unwrap();
        // Before anything is written, and never cleared afterwards.
        assert_eq!(entries(&inside.join(name)), 0);
        file.write_all(b"secret").unwrap();
        drop(file);
        folder.place(name, name, false).unwrap();
        let placed = dir.path().join(name);
        assert_eq!(fs::read(&placed).unwrap(), b"secret");
        assert_eq!(entries(&placed), 0);

        let pipe = OsStr::new("pipe");
        let made = Command::new("mkfifo")
            .arg(folder.path().unwrap().join(pipe))
            .status()
            .unwrap();
        assert!(made.success());
        folder.holds(pipe).unwrap();
        assert_eq!(entries(&inside.join(pipe)), 0);
        folder.place(pipe, pipe, false).unwrap();
        assert_eq!(entries(&dir.path().join(pipe)), 0);

        // Never over what is there without `replace`.
        let again = folder.create(name).unwrap();
        drop(again);
        let refused = folder.place(name, name, false).unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&placed).unwrap(), b"secret");
        folder.place(name, name, true).unwrap();
        assert_eq!(fs::read(&placed).unwrap(), b"");

        // Something that isn't there, or isn't in this folder, isn't held.
        assert!(folder.holds(OsStr::new("missing")).is_err());

        // Dropped, the folder goes, with what a failed write left in it.
        drop(folder.create(OsStr::new("left")).unwrap());
        drop(folder);
        assert!(!inside.exists());
        let mut names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(names, ["direct", "passwords.csv", "pipe"]);
    }

    /// Through a folder held open, the file goes into that folder, even
    /// when its path leads elsewhere by then.
    #[test]
    fn a_folder_held_open_is_the_one_written_to() {
        let dir = sharing_folder();
        let held = dir.path().join("project");
        fs::create_dir(&held).unwrap();
        let parent = fs::File::open(&held).unwrap();
        fs::rename(&held, dir.path().join("moved")).unwrap();
        let name = OsStr::new(".env");
        let folder = PrivateFolder::make_in(parent.as_fd(), name).unwrap();
        drop(folder.create(name).unwrap());
        folder.place(name, name, false).unwrap();
        drop(folder);
        let placed = dir.path().join("moved").join(name);
        assert_eq!(entries(&placed), 0);
        assert_eq!(fs::read_dir(dir.path().join("moved")).unwrap().count(), 1);
        assert!(!held.exists());
    }
}
