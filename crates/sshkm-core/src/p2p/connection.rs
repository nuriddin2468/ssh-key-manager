//! What a [`conversation`] needs of the connection under its session:
//! bytes both ways, a time limit on each read and write, and a look at
//! whether the other side said something (or hung up) without waiting for
//! it, so a wait for the user can watch the connection.
//!
//! The app opens the connection; nothing here does. [`TcpStream`] is one,
//! as the computers' sockets are; [`pipe`] makes two ends in memory, for
//! tests that hold a whole conversation in one process.
//!
//! [`conversation`]: super::conversation

use std::collections::VecDeque;
use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// A connection a conversation runs over.
pub trait Connection: Read + Write {
    /// How long a read waits for bytes before it fails with `WouldBlock`
    /// or `TimedOut`; `None`: as long as it takes.
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    /// How long a write waits for room before it fails.
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    /// Whether the other side sent something or hung up (a read then
    /// fails at once), without waiting.
    fn waiting(&self) -> io::Result<bool>;
}

impl Connection for TcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_write_timeout(self, timeout)
    }

    fn waiting(&self) -> io::Result<bool> {
        self.set_nonblocking(true)?;
        let peeked = self.peek(&mut [0; 1]);
        self.set_nonblocking(false)?;
        match peeked {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(error),
        }
    }
}

/// Two ends of a connection in memory: what one writes, the other reads.
/// Writes never wait; a read waits up to its timeout. Once one end is
/// dropped, the other reads what is left and then the end, and its writes
/// fail, as with a socket the other side closed.
pub fn pipe() -> (PipeEnd, PipeEnd) {
    let (a, b) = (Arc::new(Queue::default()), Arc::new(Queue::default()));
    (
        PipeEnd {
            incoming: Arc::clone(&a),
            outgoing: Arc::clone(&b),
            read_timeout: Mutex::new(None),
        },
        PipeEnd {
            incoming: b,
            outgoing: a,
            read_timeout: Mutex::new(None),
        },
    )
}

/// One end of a [`pipe`]. Dropping it hangs up.
#[derive(Debug)]
pub struct PipeEnd {
    incoming: Arc<Queue>,
    outgoing: Arc<Queue>,
    read_timeout: Mutex<Option<Duration>>,
}

/// The bytes going one way, and whether the end writing them is gone.
#[derive(Debug, Default)]
struct Queue {
    state: Mutex<QueueState>,
    changed: Condvar,
}

#[derive(Debug, Default)]
struct QueueState {
    bytes: VecDeque<u8>,
    closed: bool,
}

impl Queue {
    fn lock(&self) -> MutexGuard<'_, QueueState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn close(&self) {
        self.lock().closed = true;
        self.changed.notify_all();
    }
}

impl Read for PipeEnd {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let timeout = *self
            .read_timeout
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let until = timeout.map(|timeout| Instant::now() + timeout);
        let mut state = self.incoming.lock();
        while state.bytes.is_empty() && !state.closed {
            state = match until {
                None => self
                    .incoming
                    .changed
                    .wait(state)
                    .unwrap_or_else(PoisonError::into_inner),
                Some(until) => {
                    let left = until.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Err(io::Error::new(ErrorKind::TimedOut, "nothing came in time"));
                    }
                    self.incoming
                        .changed
                        .wait_timeout(state, left)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0
                }
            };
        }
        let n = buf.len().min(state.bytes.len());
        for (slot, byte) in buf.iter_mut().zip(state.bytes.drain(..n)) {
            *slot = byte;
        }
        Ok(n)
    }
}

impl Write for PipeEnd {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // A dropped end closes both ways.
        let mut state = self.outgoing.lock();
        if state.closed {
            return Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "the other end is gone",
            ));
        }
        state.bytes.extend(buf);
        drop(state);
        self.outgoing.changed.notify_all();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Connection for PipeEnd {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        if timeout.is_some_and(|timeout| timeout.is_zero()) {
            // As a socket: a zero timeout is refused.
            return Err(io::Error::new(ErrorKind::InvalidInput, "a zero timeout"));
        }
        *self
            .read_timeout
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = timeout;
        Ok(())
    }

    /// Writes never wait.
    fn set_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn waiting(&self) -> io::Result<bool> {
        let state = self.incoming.lock();
        Ok(!state.bytes.is_empty() || state.closed)
    }
}

impl Drop for PipeEnd {
    fn drop(&mut self) {
        // The other end reads the end of what this one wrote, and can't
        // write any more.
        self.outgoing.close();
        self.incoming.close();
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn what_one_end_writes_the_other_reads() {
        let (mut a, mut b) = pipe();
        a.write_all(b"knock knock").unwrap();
        assert!(b.waiting().unwrap());
        assert!(!a.waiting().unwrap());
        let mut buf = [0; 11];
        b.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"knock knock");
        assert!(!b.waiting().unwrap());
        b.write_all(b"who").unwrap();
        let mut answer = [0; 3];
        a.read_exact(&mut answer).unwrap();
        assert_eq!(&answer, b"who");
    }

    #[test]
    fn a_read_waits_for_bytes_up_to_its_timeout() {
        let (mut a, b) = pipe();
        a.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let started = Instant::now();
        let error = a.read(&mut [0; 4]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::TimedOut);
        assert!(started.elapsed() >= Duration::from_millis(100));

        a.set_read_timeout(None).unwrap();
        let writer = thread::spawn(move || {
            let mut b = b;
            thread::sleep(Duration::from_millis(50));
            b.write_all(&[7]).unwrap();
            b
        });
        let mut byte = [0; 1];
        a.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [7]);
        drop(writer.join().unwrap());
    }

    #[test]
    fn a_hang_up_reads_as_the_end_and_fails_writes() {
        let (mut a, mut b) = pipe();
        b.write_all(b"bye").unwrap();
        drop(b);
        // What came before the hang-up is read, then the end.
        assert!(a.waiting().unwrap());
        let mut buf = Vec::new();
        a.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"bye");
        let error = a.read_exact(&mut [0; 1]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
        assert_eq!(
            a.write(b"anyone?").unwrap_err().kind(),
            ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn a_socket_says_whether_the_peer_said_something() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        assert!(!Connection::waiting(&server).unwrap());
        client.write_all(&[1]).unwrap();
        let started = Instant::now();
        while !Connection::waiting(&server).unwrap() {
            assert!(started.elapsed() < Duration::from_secs(5));
            thread::sleep(Duration::from_millis(10));
        }
    }
}
