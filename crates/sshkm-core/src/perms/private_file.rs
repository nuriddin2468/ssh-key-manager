//! Files created with their own access list (Windows).
//!
//! `std` creates a file with the access list it inherits from its folder,
//! which on a drive's root, a folder made under `C:\`, `C:\Users\Public` or a
//! share lets other users read it. Setting a stricter list afterwards comes
//! too late: a handle opened in between keeps working. A file meant for
//! secrets in plain text, such as a CSV export of the vault, is therefore
//! created here with its access list in place from the first moment, and
//! shared with no one while it is open.
//!
//! This is the one module of the crate that calls the OS directly; every
//! `unsafe` block has a `// SAFETY:` comment.

#![allow(unsafe_code)]

use std::{
    fs, io,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
};

use windows::{
    Win32::{
        Foundation::{HANDLE, HLOCAL, LocalFree, WIN32_ERROR},
        Security::{
            Authorization::{
                ConvertSecurityDescriptorToStringSecurityDescriptorW,
                ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
                SDDL_REVISION_1, SE_FILE_OBJECT,
            },
            DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{
            CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_TEMPORARY,
            FILE_GENERIC_WRITE, FILE_SHARE_NONE, GetVolumeInformationByHandleW, READ_CONTROL,
        },
    },
    core::{PCWSTR, PWSTR},
};

/// The volume keeps and enforces access lists (`FILE_PERSISTENT_ACLS`, from
/// the `windows` crate's large `System_SystemServices` feature).
const FILE_PERSISTENT_ACLS: u32 = 0x0000_0008;

/// Creates the new file `path` for writing with the access list `sddl`, in
/// SDDL. Until the returned file is closed, no one else can open it to read,
/// write or delete it (share mode 0). Fails with `AlreadyExists` if `path`
/// exists.
pub(super) fn create(path: &Path, sddl: &str) -> io::Result<fs::File> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    wide.push(0);
    let descriptor = Descriptor::from_sddl(sddl)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
        lpSecurityDescriptor: descriptor.0.0,
        bInheritHandle: false.into(),
    };
    // SAFETY: `wide` is a NUL-terminated UTF-16 path, and `attributes` points
    // at a valid security descriptor; both outlive the call. The handle it
    // returns is owned by the `File` made from it below.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            (FILE_GENERIC_WRITE | READ_CONTROL).0,
            FILE_SHARE_NONE,
            Some(&raw const attributes),
            CREATE_NEW,
            FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY,
            None,
        )
    }
    .map_err(|err| io_error(&err))?;
    // SAFETY: `handle` is a valid file handle that was just opened for
    // synchronous I/O, and nothing else owns it.
    Ok(fs::File::from(unsafe {
        OwnedHandle::from_raw_handle(handle.0)
    }))
}

/// Whether the volume `file` is on keeps access lists. FAT and exFAT don't,
/// and quietly drop the one a file is created with.
pub(super) fn keeps_access_lists(file: &fs::File) -> bool {
    let mut flags = 0;
    // SAFETY: `file` is an open handle and `flags` is writable; no buffers
    // are passed.
    unsafe {
        GetVolumeInformationByHandleW(
            HANDLE(file.as_raw_handle()),
            None,
            None,
            None,
            Some(&raw mut flags),
            None,
        )
    }
    .is_ok_and(|()| flags & FILE_PERSISTENT_ACLS != 0)
}

/// The owner and access list of `file`, as the file system reports them, in
/// SDDL (`O:…D:…`). The file must be open with `READ_CONTROL`, as
/// [`create`] opens it.
pub(super) fn owner_and_access(file: &fs::File) -> io::Result<String> {
    let parts = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut descriptor = Descriptor(PSECURITY_DESCRIPTOR::default());
    // SAFETY: `file` is open with READ_CONTROL and the out pointer is
    // writable. The descriptor is allocated for us and freed by `Descriptor`.
    unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            parts,
            None,
            None,
            None,
            None,
            Some(&raw mut descriptor.0),
        )
    }
    .ok()
    .map_err(|err| io_error(&err))?;
    let mut text = LocalText(PWSTR::null());
    // SAFETY: `descriptor` holds a valid security descriptor and the out
    // pointer is writable. The string is allocated for us and freed by
    // `LocalText`.
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.0,
            SDDL_REVISION_1,
            parts,
            &raw mut text.0,
            None,
        )
    }
    .map_err(|err| io_error(&err))?;
    // SAFETY: the call above succeeded, so `text` is a NUL-terminated
    // UTF-16 string.
    unsafe { text.0.to_string() }.map_err(|_| io::Error::other("unreadable security descriptor"))
}

/// A security descriptor Windows allocated with `LocalAlloc`, freed on drop.
struct Descriptor(PSECURITY_DESCRIPTOR);

impl Descriptor {
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let wide: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
        let mut descriptor = Self(PSECURITY_DESCRIPTOR::default());
        // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the
        // call, and the out pointer is writable; what it receives is freed
        // by `Drop`.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &raw mut descriptor.0,
                None,
            )
        }
        .map_err(|err| io_error(&err))?;
        Ok(descriptor)
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        if !self.0.0.is_null() {
            // SAFETY: Windows allocated the descriptor with `LocalAlloc`; it
            // is freed once, here.
            let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
        }
    }
}

/// A string Windows allocated with `LocalAlloc`, freed on drop.
struct LocalText(PWSTR);

impl Drop for LocalText {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Windows allocated the string with `LocalAlloc`; it is
            // freed once, here.
            let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0.cast()))) };
        }
    }
}

/// The Win32 error behind `err` as `std` reports it, so that its kind
/// (`AlreadyExists`, which `tempfile` retries on, and the like) is right.
fn io_error(err: &windows::core::Error) -> io::Error {
    WIN32_ERROR::from_error(err)
        .and_then(|code| i32::try_from(code.0).ok())
        .map_or_else(
            || io::Error::other(err.message()),
            io::Error::from_raw_os_error,
        )
}
