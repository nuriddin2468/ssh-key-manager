//! Who serves a Unix socket: the user of the process at its other end, as
//! the kernel recorded it when the socket was set up.
#![allow(unsafe_code)]

use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

/// The effective user id of the process serving `stream`.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
        .map_err(|_| io::Error::other("ucred too large"))?;
    // SAFETY: `cred` and `len` are valid for writes of the sizes given, and
    // the descriptor stays open for the call, owned by `stream`.
    let done = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &raw mut len,
        )
    };
    if done != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid)
}

/// The effective user id of the process serving `stream`.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(super) fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `uid` and `gid` are valid for writes, and the descriptor stays
    // open for the call, owned by `stream`.
    let done = unsafe { libc::getpeereid(stream.as_raw_fd(), &raw mut uid, &raw mut gid) };
    if done != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(uid)
}

/// This process's effective user id.
pub(super) fn own_uid() -> u32 {
    // SAFETY: `geteuid` takes nothing and always succeeds.
    unsafe { libc::geteuid() }
}
