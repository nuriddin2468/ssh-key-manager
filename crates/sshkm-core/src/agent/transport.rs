//! Connecting to the agent and exchanging one framed message.

use std::{
    io::{self, Read, Write},
    path::Path,
    time::Duration,
};

use super::AgentProblem;

/// Largest reply accepted (OpenSSH's `AGENT_MAX_LEN`).
const MAX_MESSAGE: usize = 256 * 1024;

/// A transport failure with its machine-readable kind.
#[derive(Debug)]
pub(crate) struct TransportError {
    pub(crate) problem: AgentProblem,
    pub(crate) detail: String,
}

impl TransportError {
    fn new(problem: AgentProblem, detail: impl Into<String>) -> Self {
        Self {
            problem,
            detail: detail.into(),
        }
    }

    fn from_io(err: &io::Error) -> Self {
        let problem = match err.kind() {
            io::ErrorKind::NotFound => AgentProblem::NotFound,
            io::ErrorKind::ConnectionRefused => AgentProblem::ConnectionRefused,
            io::ErrorKind::PermissionDenied => AgentProblem::PermissionDenied,
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => AgentProblem::Timeout,
            io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof => {
                AgentProblem::ProtocolError
            }
            _ => AgentProblem::Other,
        };
        Self::new(problem, err.to_string())
    }
}

/// Writes `request` (message type + payload) with its length prefix and reads
/// one reply (message type + payload).
fn exchange_stream<S: Read + Write>(stream: &mut S, request: &[u8]) -> io::Result<Vec<u8>> {
    let len = u32::try_from(request.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "request too large"))?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(request)?;
    stream.flush()?;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = usize::try_from(u32::from_be_bytes(len_buf)).unwrap_or(usize::MAX);
    if len == 0 || len > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid reply length {len}"),
        ));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body)?;
    Ok(body)
}

#[cfg(unix)]
pub(crate) fn request(
    socket: &Path,
    timeout: Duration,
    request: &[u8],
) -> Result<Vec<u8>, TransportError> {
    use std::os::unix::net::UnixStream;
    let mut stream = UnixStream::connect(socket).map_err(|e| TransportError::from_io(&e))?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|e| TransportError::from_io(&e))?;
    exchange_stream(&mut stream, request).map_err(|e| TransportError::from_io(&e))
}

/// Sends `request` over a pipe only once `check` says its server is trusted
/// (see [`super::set_pipe_check`]); without a check, never. Not
/// `cfg(windows)`, so its tests run everywhere.
#[cfg_attr(not(windows), allow(dead_code))]
fn exchange_checked<S: Read + Write>(
    pipe: &mut S,
    check: Option<fn(&S) -> io::Result<()>>,
    request: &[u8],
) -> io::Result<Vec<u8>> {
    let check = check.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "who serves the agent's pipe can't be checked",
        )
    })?;
    check(pipe).map_err(|e| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing the agent's pipe: {e}"),
        )
    })?;
    exchange_stream(pipe, request)
}

/// Windows: OpenSSH's agent listens on a named pipe. Pipes opened through
/// `std::fs` have no timeouts, so the exchange runs on a helper thread and the
/// caller stops waiting after `timeout` (a stuck thread is abandoned). The
/// pipe is opened for identification only, so its server can't act as this
/// user, and its server is checked before anything is sent.
#[cfg(windows)]
pub(crate) fn request(
    socket: &Path,
    timeout: Duration,
    request: &[u8],
) -> Result<Vec<u8>, TransportError> {
    use std::{sync::mpsc, thread};

    use zeroize::Zeroizing;

    if !is_pipe_path(socket) {
        return Err(TransportError::new(
            AgentProblem::Unsupported,
            format!(
                "{} is not a named pipe; Unix-socket agents (Cygwin, MSYS, WSL) are not supported",
                socket.display()
            ),
        ));
    }
    let socket = socket.to_path_buf();
    let request = Zeroizing::new(request.to_vec());
    let check = super::pipe_check();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let result = open_pipe(&socket, timeout)
            .and_then(|mut pipe| exchange_checked(&mut pipe, check, &request));
        let _ = tx.send(result);
    });
    match rx.recv_timeout(timeout) {
        Ok(result) => result.map_err(|e| TransportError::from_io(&e)),
        Err(_) => Err(TransportError::new(
            AgentProblem::Timeout,
            "the agent did not answer",
        )),
    }
}

/// The path names a local Windows named pipe (`\\.\pipe\…`, either slash
/// style, any case). Not `cfg(windows)`: the env-based discovery decides on
/// every platform, so its tests run everywhere.
pub(crate) fn is_pipe_path(path: &Path) -> bool {
    let s = path
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    s.starts_with(r"\\.\pipe\")
}

#[cfg(windows)]
fn open_pipe(path: &Path, timeout: Duration) -> io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::time::Instant;
    /// `ERROR_PIPE_BUSY`: all pipe instances are in use; retry shortly.
    const ERROR_PIPE_BUSY: i32 = 231;
    /// `SecurityIdentification << 16`: the server may learn who the client
    /// is but not act as it.
    const SECURITY_IDENTIFICATION: u32 = 1 << 16;
    let deadline = Instant::now() + timeout;
    loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(path)
        {
            Ok(file) => return Ok(file),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn request(
    _socket: &Path,
    _timeout: Duration,
    _request: &[u8],
) -> Result<Vec<u8>, TransportError> {
    Err(TransportError::new(
        AgentProblem::Unsupported,
        "ssh-agent is not supported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An in-memory duplex stream: reads from `input`, records writes.
    struct Duplex {
        input: io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Read for Duplex {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.output.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn duplex(input: &[u8]) -> Duplex {
        Duplex {
            input: io::Cursor::new(input.to_vec()),
            output: Vec::new(),
        }
    }

    #[test]
    fn frames_request_and_reply() {
        let mut s = duplex(&[0, 0, 0, 1, 6]);
        assert_eq!(exchange_stream(&mut s, &[11]).unwrap(), [6]);
        assert_eq!(s.output, [0, 0, 0, 1, 11]);
    }

    #[test]
    fn sends_nothing_over_a_pipe_until_its_server_is_checked() {
        type Check = fn(&Duplex) -> io::Result<()>;
        let trusted: Check = |_| Ok(());
        let untrusted: Check = |_| Err(io::Error::other("the pipe is served by another user"));
        for check in [None, Some(untrusted)] {
            let mut s = duplex(&[0, 0, 0, 1, 6]);
            let err = exchange_checked(&mut s, check, &[17]).unwrap_err();
            assert_eq!(
                TransportError::from_io(&err).problem,
                AgentProblem::PermissionDenied
            );
            assert!(s.output.is_empty(), "nothing was sent");
        }
        let mut s = duplex(&[0, 0, 0, 1, 6]);
        assert_eq!(exchange_checked(&mut s, Some(trusted), &[17]).unwrap(), [6]);
        assert_eq!(s.output, [0, 0, 0, 1, 17]);
    }

    #[test]
    fn rejects_bad_frames() {
        for input in [
            &[][..],
            &[0, 0],
            &[0, 0, 0, 0],
            &[0xff, 0xff, 0xff, 0xff],
            &[0, 0, 0, 5, 1],
        ] {
            let err = exchange_stream(&mut duplex(input), &[11]).unwrap_err();
            let problem = TransportError::from_io(&err).problem;
            assert_eq!(problem, AgentProblem::ProtocolError, "{input:?}");
        }
    }
}
