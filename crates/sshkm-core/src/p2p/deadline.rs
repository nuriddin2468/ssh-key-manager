//! One deadline for the first steps of a connection (the knock, the
//! handshake, the `Hello`s): every read and write waits at most the time
//! left, and none starts once it has passed. A peer that trickles a byte
//! now and then can't stretch it, as it could a timeout per read.
//!
//! It holds without another thread shutting the socket down, which doesn't
//! end a read already waiting on Windows.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// A stream whose reads and writes all end by one deadline.
#[derive(Debug)]
pub struct Deadline {
    stream: TcpStream,
    until: Instant,
}

impl Deadline {
    /// `stream`, whose reads and writes must all end within `after`.
    pub fn new(stream: TcpStream, after: Duration) -> Self {
        Self {
            stream,
            until: Instant::now() + after,
        }
    }

    /// The stream, its timeouts as the last step left them: set them again.
    pub fn into_inner(self) -> TcpStream {
        self.stream
    }

    /// The time left, or `TimedOut` once (almost) none is: a timeout below
    /// a millisecond would be none on Windows, which counts in those.
    fn left(&self) -> io::Result<Duration> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left < Duration::from_millis(1) {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the connection took too long",
            ))
        } else {
            Ok(left)
        }
    }
}

impl Read for Deadline {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.left()?;
        self.stream.set_read_timeout(Some(left))?;
        self.stream.read(buf)
    }
}

impl Write for Deadline {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let left = self.left()?;
        self.stream.set_write_timeout(Some(left))?;
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    fn pipe() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn a_silent_peer_is_given_up_on_at_the_deadline() {
        let (client, server) = pipe();
        let mut stream = Deadline::new(server, Duration::from_millis(300));
        let started = Instant::now();
        let mut buf = [0; 16];
        assert!(stream.read_exact(&mut buf).is_err());
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );
        drop(client);
    }

    #[test]
    fn a_trickling_peer_cant_stretch_the_deadline() {
        let (mut client, server) = pipe();
        // A byte every 100 ms: each read alone would be quick.
        let trickle = thread::spawn(move || {
            for _ in 0..40 {
                if client.write_all(&[7]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
        });
        let mut stream = Deadline::new(server, Duration::from_millis(500));
        let started = Instant::now();
        let mut buf = [0; 32];
        let read = stream.read_exact(&mut buf);
        assert!(read.is_err(), "32 bytes can't come in time");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        drop(stream);
        trickle.join().unwrap();
    }

    #[test]
    fn what_comes_in_time_comes_whole() {
        let (mut client, server) = pipe();
        client.write_all(b"knock knock").unwrap();
        let mut stream = Deadline::new(server, Duration::from_secs(5));
        let mut buf = [0; 11];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"knock knock");
        stream.write_all(b"who").unwrap();
        let mut answer = [0; 3];
        client.read_exact(&mut answer).unwrap();
        assert_eq!(&answer, b"who");
        let _ = stream.into_inner();
    }
}
