//! The bridge's socket on macOS and Linux, in a fresh private (0700)
//! directory: under `$XDG_RUNTIME_DIR` on Linux, which nothing cleans while
//! the user is logged in, and in the per-user temporary folder on macOS.

use std::ffi::OsStr;
use std::fs::Permissions;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use tempfile::TempDir;

use super::{HOST_WAIT, Handler, IO_TIMEOUT, frame};

pub struct Listener {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    // Dropped last: removes the socket and its directory.
    _dir: TempDir,
}

impl Listener {
    pub fn start(handler: Handler) -> io::Result<Self> {
        let dir = private_dir()?;
        let path = dir.path().join("browser.sock");
        let listener = UnixListener::bind(&path)?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread = thread::Builder::new().name("browser".into()).spawn({
            let stop = Arc::clone(&stop);
            move || accept(&listener, &handler, &stop)
        })?;
        Ok(Self {
            path,
            stop,
            thread: Some(thread),
            _dir: dir,
        })
    }

    pub fn endpoint(&self) -> &OsStr {
        self.path.as_os_str()
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop so it sees the flag.
        let _ = UnixStream::connect(&self.path);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A new directory only this user can enter, short enough for a socket path
/// (at most 104 bytes on macOS, 108 on Linux).
fn private_dir() -> io::Result<TempDir> {
    let runtime = dirs::runtime_dir().filter(|dir| dir.is_dir());
    let temp = std::env::temp_dir();
    let base = runtime
        .into_iter()
        .chain([temp])
        .find(|dir| dir.as_os_str().len() <= 64)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let dir = tempfile::Builder::new()
        .prefix("sshkm-browser-")
        .permissions(Permissions::from_mode(0o700))
        .tempdir_in(base)?;
    std::fs::set_permissions(dir.path(), Permissions::from_mode(0o700))?;
    Ok(dir)
}

fn accept(listener: &UnixListener, handler: &Handler, stop: &AtomicBool) {
    for stream in listener.incoming() {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        match stream {
            Ok(stream) => {
                let handler = Arc::clone(handler);
                let spawned = thread::Builder::new()
                    .name("browser-request".into())
                    .spawn(move || serve(stream, &handler));
                if let Err(e) = spawned {
                    log::warn!("browser: cannot handle a request: {e}");
                }
            }
            Err(e) => {
                log::warn!("browser: accept failed: {e}");
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn serve(mut stream: UnixStream, handler: &Handler) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let Ok(request) = frame::read(&mut stream) else {
        return;
    };
    let reply = handler(&request);
    let _ = frame::write(&mut stream, &reply);
}

/// The host's side: connects to the app's socket after checking that it is
/// in a directory only this user can enter.
pub fn connect(endpoint: &OsStr) -> io::Result<UnixStream> {
    let path = Path::new(endpoint);
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no socket directory"))?;
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.uid() != nix::unistd::geteuid().as_raw() || meta.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the socket's directory is not private to this user",
        ));
    }
    let stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(HOST_WAIT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echoes_through_a_private_socket() {
        let handler: Handler = Arc::new(|request: &[u8]| {
            let mut reply = b"re:".to_vec();
            reply.extend_from_slice(request);
            reply
        });
        let listener = Listener::start(handler).unwrap();
        let path = PathBuf::from(listener.endpoint());
        assert!(path.as_os_str().len() < 104, "{}", path.display());
        let dir = path.parent().unwrap().to_owned();
        assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);

        let mut stream = connect(listener.endpoint()).unwrap();
        frame::write(&mut stream, b"hello").unwrap();
        assert_eq!(frame::read(&mut stream).unwrap(), b"re:hello");

        drop(listener);
        assert!(!dir.exists(), "dropping the listener removes its directory");
    }

    #[test]
    fn refuses_a_socket_in_a_shared_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), Permissions::from_mode(0o755)).unwrap();
        let path = dir.path().join("browser.sock");
        let _listener = UnixListener::bind(&path).unwrap();
        let error = connect(path.as_os_str()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
}
