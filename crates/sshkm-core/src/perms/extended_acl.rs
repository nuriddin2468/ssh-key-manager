//! Emptying an extended access list (macOS).
//!
//! A folder's access list can hand its entries down to every file made in
//! it (`file_inherit`), and macOS checks those entries before the mode: a
//! file made with mode 0600 in a folder whose list lets everyone read what
//! is made in it is readable by everyone. `chmod` leaves the list alone.
//! Emptying a file's list once it exists comes too late for whoever opened
//! it in between, so a private file is made in a folder of its own whose
//! list is emptied here, as `chmod -N` does, before anything is made in it
//! (`fsutil::private_folder`).
//!
//! The functions are those of `<sys/acl.h>` in the system library; every
//! `unsafe` block has a `// SAFETY:` comment.

#![allow(unsafe_code)]

use std::{
    ffi::{c_int, c_void},
    io,
    os::fd::{AsFd, AsRawFd},
    ptr,
};

/// `acl_t`: an access list the system library allocated.
type Acl = *mut c_void;

/// `ACL_TYPE_EXTENDED`, the one kind of access list macOS has.
const ACL_TYPE_EXTENDED: c_int = 0x100;
/// `ACL_FIRST_ENTRY`.
const ACL_FIRST_ENTRY: c_int = 0;

unsafe extern "C" {
    fn acl_init(count: c_int) -> Acl;
    fn acl_free(object: *mut c_void) -> c_int;
    fn acl_get_entry(acl: Acl, entry_id: c_int, entry: *mut *mut c_void) -> c_int;
    fn acl_get_fd_np(fd: c_int, kind: c_int) -> Acl;
    fn acl_set_fd_np(fd: c_int, acl: Acl, kind: c_int) -> c_int;
}

/// Empties the access list of the open file or folder `fd`. Fails only if
/// entries are left that couldn't be removed; a file system without access
/// lists (FAT, some network shares) has none to remove. For a file that
/// must be private from its first moment, empty the list of a folder of
/// its own before the file is made in it (`fsutil::private_folder`).
pub(crate) fn clear(fd: impl AsFd) -> io::Result<()> {
    let fd = fd.as_fd();
    let raw = fd.as_raw_fd();
    // SAFETY: `raw` is open for as long as `fd` is borrowed, and `empty`
    // is a valid list, which the call only reads.
    let cleared = with_empty(|empty| unsafe { acl_set_fd_np(raw, empty, ACL_TYPE_EXTENDED) });
    // SAFETY: as above; the list returned is freed by `has_entries`.
    settle(cleared, || unsafe { acl_get_fd_np(raw, ACL_TYPE_EXTENDED) })
}

/// Runs `set` with a new empty list, freed afterwards.
fn with_empty(set: impl FnOnce(Acl) -> c_int) -> io::Result<()> {
    // SAFETY: no pointers are passed; the list is freed below.
    let empty = unsafe { acl_init(0) };
    if empty.is_null() {
        return Err(io::Error::last_os_error());
    }
    let result = set(empty);
    let error = io::Error::last_os_error();
    // SAFETY: `empty` came from `acl_init` and is freed once, here.
    unsafe { acl_free(empty) };
    if result == 0 { Ok(()) } else { Err(error) }
}

/// A clear that failed is still fine if the file has no entries: `get`
/// reads its list as it is now.
fn settle(cleared: io::Result<()>, get: impl FnOnce() -> Acl) -> io::Result<()> {
    let Err(error) = cleared else {
        return Ok(());
    };
    let acl = get();
    if acl.is_null() {
        // No list at all, or none the file system keeps.
        let none = matches!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOENT | libc::ENOTSUP | libc::EOPNOTSUPP)
        );
        return if none { Ok(()) } else { Err(error) };
    }
    if has_entries(acl) { Err(error) } else { Ok(()) }
}

/// Whether `acl` has an entry; frees it.
fn has_entries(acl: Acl) -> bool {
    let mut entry = ptr::null_mut();
    // SAFETY: `acl` is a valid list and `entry` is writable; the entry
    // belongs to the list and isn't used after it is freed.
    let found = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &raw mut entry) } == 0;
    // SAFETY: `acl` came from the system library and is freed once, here.
    unsafe { acl_free(acl) };
    found
}

/// Folders that hand an entry down to what is made in them, for tests.
#[cfg(test)]
pub(crate) mod testing {
    use std::{
        os::fd::{AsFd, AsRawFd},
        path::Path,
        process::Command,
    };

    /// Whether the open file `fd` has an entry in its access list.
    pub(crate) fn carries_entries(fd: impl AsFd) -> bool {
        // SAFETY: the descriptor is open while borrowed; the list returned
        // is freed by `has_entries`.
        let acl = unsafe { super::acl_get_fd_np(fd.as_fd().as_raw_fd(), super::ACL_TYPE_EXTENDED) };
        !acl.is_null() && super::has_entries(acl)
    }

    /// How many entries `ls -le` lists in `path`'s access list.
    pub(crate) fn entries(path: &Path) -> usize {
        let out = Command::new("/bin/ls")
            .arg("-led")
            .arg(path)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).lines().count() - 1
    }

    /// A folder whose access list lets everyone read what is made in it.
    pub(crate) fn sharing_folder() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let ok = Command::new("/bin/chmod")
            .arg("+a")
            .arg("everyone allow read,file_inherit,directory_inherit")
            .arg(dir.path())
            .status()
            .unwrap()
            .success();
        assert!(ok);
        dir
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{testing::*, *};

    #[test]
    fn inherited_entries_are_removed() {
        let dir = sharing_folder();
        let path = dir.path().join("file");
        let file = fs::File::create(&path).unwrap();
        assert_eq!(entries(&path), 1);
        clear(&file).unwrap();
        assert_eq!(entries(&path), 0);
        // Nothing to remove is fine too.
        clear(&file).unwrap();

        // A folder's list, through its descriptor.
        let folder = dir.path().join("folder");
        fs::create_dir(&folder).unwrap();
        assert_eq!(entries(&folder), 1);
        clear(fs::File::open(&folder).unwrap()).unwrap();
        assert_eq!(entries(&folder), 0);
        // What is made in it now inherits nothing.
        let inside = folder.join("file");
        fs::write(&inside, "").unwrap();
        assert_eq!(entries(&inside), 0);
    }
}
