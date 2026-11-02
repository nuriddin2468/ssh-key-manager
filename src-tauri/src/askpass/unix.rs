//! The askpass server on macOS and Linux: a Unix socket in a private
//! temporary directory.
//!
//! Only the app's user (and root) can enter the 0700 directory, so no one else
//! can reach the socket; the token then tells sessions apart.

use std::ffi::OsStr;
use std::fs::Permissions;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use tempfile::TempDir;

use super::{Answer, IO_TIMEOUT, Registry, wire};

pub struct Listener {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    // Dropped last: removes the socket and its directory.
    _dir: TempDir,
}

impl Listener {
    pub fn start(registry: Arc<Registry>) -> io::Result<Self> {
        let dir = private_dir()?;
        let path = dir.path().join("askpass.sock");
        let listener = UnixListener::bind(&path)?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread = thread::Builder::new().name("askpass".into()).spawn({
            let stop = Arc::clone(&stop);
            move || accept(&listener, &registry, &stop)
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
    let temp = std::env::temp_dir();
    let base = if temp.as_os_str().len() <= 64 {
        temp
    } else {
        PathBuf::from("/tmp")
    };
    let dir = tempfile::Builder::new()
        .prefix("sshkm-askpass-")
        .permissions(Permissions::from_mode(0o700))
        .tempdir_in(base)?;
    // Whatever the umask did, make sure.
    std::fs::set_permissions(dir.path(), Permissions::from_mode(0o700))?;
    Ok(dir)
}

fn accept(listener: &UnixListener, registry: &Arc<Registry>, stop: &AtomicBool) {
    for stream in listener.incoming() {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        match stream {
            Ok(stream) => {
                let registry = Arc::clone(registry);
                let spawned = thread::Builder::new()
                    .name("askpass-request".into())
                    .spawn(move || serve(stream, &registry));
                if let Err(e) = spawned {
                    log::warn!("askpass: cannot handle a request: {e}");
                }
            }
            Err(e) => {
                log::warn!("askpass: accept failed: {e}");
                // Out of file descriptors, say: do not spin.
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn serve(mut stream: UnixStream, registry: &Registry) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let Ok(request) = wire::read_request(&mut stream) else {
        return;
    };
    let reply = match registry.answer(&request) {
        Answer::Unknown => return,
        Answer::Refuse => None,
        Answer::Text(secret) => Some(secret),
    };
    let _ = wire::write_answer(&mut stream, reply.as_ref());
}

/// The helper's side: connects to the server's socket.
pub fn connect(endpoint: &OsStr) -> io::Result<UnixStream> {
    let stream = UnixStream::connect(Path::new(endpoint))?;
    // `ssh` waits for the helper as long as it takes; the server answers in
    // milliseconds unless it is gone.
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    use super::*;

    #[test]
    fn socket_is_in_a_private_directory() {
        let listener = Listener::start(Arc::new(Registry::default())).unwrap();
        let path = PathBuf::from(listener.endpoint());
        assert!(path.as_os_str().len() < 104, "{}", path.display());
        let dir = path.parent().unwrap().to_owned();
        assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        assert!(std::fs::metadata(&path).unwrap().file_type().is_socket());

        drop(listener);
        assert!(!dir.exists(), "dropping the listener removes its directory");
    }
}
