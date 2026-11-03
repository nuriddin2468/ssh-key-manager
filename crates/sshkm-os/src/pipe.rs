//! Who serves a named pipe (Windows).
//!
//! A client finds a pipe by its name, and any local user can create a pipe
//! under a name nobody holds. Another user could thus wait under the name of
//! the app's pipe after the app quit, or under OpenSSH's agent pipe while its
//! service is stopped, and read what is sent there: a login, a private key.
//! Before a client sends anything, [`check_server`] makes sure the pipe's
//! server is someone this user has to trust anyway.
//!
//! Two things are checked:
//!
//! - the pipe's owner, its creator: only an administrator can make that
//!   anyone but themselves, so it can't be forged by another user;
//! - the user the server process runs as, read from its token. A standard
//!   user may not read the token of a system service, so this one counts
//!   only when it can be read.

#![allow(unsafe_code)]

use std::os::windows::io::{AsRawHandle, BorrowedHandle};

use windows::Win32::{
    Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree},
    Security::{
        Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT},
        EqualSid, GetTokenInformation, IsWellKnownSid, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER, TokenUser, WELL_KNOWN_SID_TYPE,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    },
    System::{
        Pipes::GetNamedPipeServerProcessId,
        Threading::{
            GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

use crate::{Error, Result};

/// Whom a pipe's server may be, besides an administrator (who could read
/// anything of this user's anyway).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trusted {
    /// This user: the app's own pipes.
    User,
    /// This user or the system (`LocalSystem`): ssh-agent pipes, served by
    /// OpenSSH's agent service or by the user's own agent (1Password,
    /// Pageant and the like).
    UserOrSystem,
}

/// Fails unless the server of `pipe`, the client's end of a named pipe, is
/// [`Trusted`]. Call it before sending anything over the pipe.
pub fn check_server(pipe: BorrowedHandle<'_>, trusted: Trusted) -> Result<()> {
    let pipe = HANDLE(pipe.as_raw_handle());
    // SAFETY: the pseudo handle of this process needs no closing.
    let me = token_user(unsafe { GetCurrentProcess() })
        .map_err(|err| failed("reading this user", &err))?;
    let me = me.sid();
    let system_too = trusted == Trusted::UserOrSystem;

    let owner = PipeOwner::of(pipe).map_err(|err| failed("reading the pipe's owner", &err))?;
    let owner = owner.sid();
    let owner_trusted = same(owner, me)
        || is(owner, WinBuiltinAdministratorsSid)
        || (system_too && is(owner, WinLocalSystemSid));
    if !owner_trusted {
        return Err(untrusted());
    }
    if let Ok(user) = server_user(pipe) {
        let user = user.sid();
        if !(same(user, me) || (system_too && is(user, WinLocalSystemSid))) {
            return Err(untrusted());
        }
    }
    Ok(())
}

fn untrusted() -> Error {
    Error::Failed("the pipe is served by another user".into())
}

fn failed(what: &str, err: &windows::core::Error) -> Error {
    Error::Failed(format!("{what} failed: {err}"))
}

fn same(a: PSID, b: PSID) -> bool {
    // SAFETY: both point at valid SIDs, kept alive by their owners for this
    // call.
    unsafe { EqualSid(a, b) }.is_ok()
}

fn is(sid: PSID, kind: WELL_KNOWN_SID_TYPE) -> bool {
    // SAFETY: `sid` points at a valid SID, kept alive for this call.
    unsafe { IsWellKnownSid(sid, kind) }.as_bool()
}

/// The user that the process serving `pipe` runs as.
fn server_user(pipe: HANDLE) -> windows::core::Result<TokenUserBuffer> {
    let mut pid = 0;
    // SAFETY: `pipe` is a live pipe handle and `pid` is writable.
    unsafe { GetNamedPipeServerProcessId(pipe, &raw mut pid) }?;
    // SAFETY: opening a process by id has no memory-safety preconditions; the
    // handle is closed by `Handle`.
    let process = Handle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }?);
    token_user(process.0)
}

/// The user of the process `process`.
fn token_user(process: HANDLE) -> windows::core::Result<TokenUserBuffer> {
    let mut token = HANDLE::default();
    // SAFETY: `process` is a live process handle (or this process's pseudo
    // handle) and `token` is writable; the token is closed by `Handle`.
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) }?;
    let token = Handle(token);
    let mut len = 0;
    // SAFETY: asks for the size only: no buffer, and `len` is writable. The
    // call fails with ERROR_INSUFFICIENT_BUFFER, as it should.
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &raw mut len) };
    let bytes = usize::try_from(len).unwrap_or(0);
    if bytes < size_of::<TOKEN_USER>() {
        return Err(windows::core::Error::from_thread());
    }
    // `u64`s, so the buffer is aligned for the `TOKEN_USER` at its start.
    let mut buffer = vec![0_u64; bytes.div_ceil(size_of::<u64>())];
    // SAFETY: `buffer` has room for `len` bytes, is aligned for `TOKEN_USER`
    // and outlives the call; `len` is writable.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            len,
            &raw mut len,
        )
    }?;
    Ok(TokenUserBuffer(buffer))
}

/// A `TOKEN_USER` with the SID it points at, in one buffer.
struct TokenUserBuffer(Vec<u64>);

impl TokenUserBuffer {
    fn sid(&self) -> PSID {
        // SAFETY: `GetTokenInformation` filled the buffer with a `TOKEN_USER`
        // at its start, aligned and in bounds; its SID lies inside the buffer,
        // which `self` keeps alive.
        unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }
}

/// The owner of a pipe, inside the security descriptor that holds it.
struct PipeOwner {
    owner: PSID,
    descriptor: PSECURITY_DESCRIPTOR,
}

impl PipeOwner {
    fn of(pipe: HANDLE) -> windows::core::Result<Self> {
        let mut owner = PSID::default();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `pipe` is a live handle opened with read access (which
        // includes READ_CONTROL); the out pointers are writable. The
        // descriptor is allocated for us and freed in `Drop`; `owner` points
        // into it.
        unsafe {
            GetSecurityInfo(
                pipe,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                Some(&raw mut owner),
                None,
                None,
                None,
                Some(&raw mut descriptor),
            )
        }
        .ok()?;
        let found = Self { owner, descriptor };
        if found.owner.is_invalid() {
            return Err(windows::core::Error::from_thread());
        }
        Ok(found)
    }

    fn sid(&self) -> PSID {
        self.owner
    }
}

impl Drop for PipeOwner {
    fn drop(&mut self) {
        if !self.descriptor.0.is_null() {
            // SAFETY: `GetSecurityInfo` allocated the descriptor with
            // `LocalAlloc`; it is freed once, here.
            let _ = unsafe { LocalFree(Some(HLOCAL(self.descriptor.0))) };
        }
    }
}

/// A kernel handle, closed when dropped.
struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle was opened for this `Handle` and is closed once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use std::os::windows::io::AsHandle;

    use windows::{
        Win32::{
            Storage::FileSystem::PIPE_ACCESS_DUPLEX,
            System::Pipes::{CreateNamedPipeW, PIPE_TYPE_BYTE},
        },
        core::HSTRING,
    };

    use super::*;

    #[test]
    fn a_pipe_of_this_user_passes() {
        let name = format!(r"\\.\pipe\sshkm-os-test-{}", std::process::id());
        // SAFETY: a valid name and no security attributes (the default
        // security); the handle is closed by `Handle`.
        let server = Handle(unsafe {
            CreateNamedPipeW(
                &HSTRING::from(name.as_str()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE,
                1,
                0,
                0,
                0,
                None,
            )
        });
        assert!(!server.0.is_invalid());
        let client = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&name)
            .unwrap();
        check_server(client.as_handle(), Trusted::User).unwrap();
        check_server(client.as_handle(), Trusted::UserOrSystem).unwrap();
    }
}
