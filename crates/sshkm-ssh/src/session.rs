//! An interactive shell on a terminal: bytes in, bytes out, the size of
//! the screen, and the end.
//!
//! Output is read as events ([`Shell::next_event`]). russh widens SSH's
//! window as data arrives, not as the app reads it; what bounds memory is
//! the channel between russh's session task and the reader, 100 messages
//! long. When it is full, the session task waits, and with it everything
//! on the connection, keepalive answers included. So the app must keep
//! asking for the next event for as long as the shell is open (one task or
//! coroutine that does nothing else), even while the terminal isn't on
//! screen. What goes either way is never logged.

use std::collections::VecDeque;
use std::time::Duration;

use russh::client::Msg;
use russh::{Channel, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Pty};
use tokio::sync::Mutex;

use crate::client::Connection;
use crate::error::Error;

/// The terminal type the phone's terminal emulates.
pub const TERM: &str = "xterm-256color";

/// How long the server may take to answer the terminal and shell requests.
const REPLY_TIMEOUT: Duration = Duration::from_secs(30);
/// Output kept while waiting for those answers, at most.
const PENDING_BYTES: usize = 1 << 20;

/// The size of the terminal, in characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtySize {
    pub cols: u32,
    pub rows: u32,
}

/// Something from the shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellEvent {
    /// Bytes for the terminal (standard output and error, as a terminal
    /// shows them).
    Output(Vec<u8>),
    /// The shell has ended; no more events follow.
    Closed(Closed),
}

/// How the shell ended.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Closed {
    /// The shell's exit status, if the server said.
    pub exit_status: Option<u32>,
    /// The signal that ended it (`TERM`, `KILL`, …), if the server said.
    pub exit_signal: Option<String>,
    /// The connection went away (network, keepalives unanswered) before
    /// the server closed the shell.
    pub connection_lost: bool,
}

/// An interactive shell on the destination. Reading, writing and resizing
/// may happen at once, from different tasks: reading waits for the server
/// without holding up what the user types.
pub struct Shell {
    connection: Connection,
    writer: ChannelWriteHalf<Msg>,
    reader: Mutex<Reader>,
}

/// The reading side and what it learnt.
struct Reader {
    half: ChannelReadHalf,
    /// Events read while waiting for the server's answers to the terminal
    /// and shell requests, and their bytes.
    pending: VecDeque<ShellEvent>,
    pending_bytes: usize,
    exit_status: Option<u32>,
    exit_signal: Option<String>,
    closed: bool,
}

impl std::fmt::Debug for Shell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shell")
            .field("connection", &self.connection)
            .finish_non_exhaustive()
    }
}

impl Shell {
    /// Asks for a terminal and a shell on `channel`, a new session channel
    /// of `connection`'s destination.
    pub(crate) async fn start(
        connection: Connection,
        channel: Channel<Msg>,
        size: PtySize,
    ) -> Result<Self, Error> {
        let (half, writer) = channel.split();
        let mut reader = Reader {
            half,
            pending: VecDeque::new(),
            pending_bytes: 0,
            exit_status: None,
            exit_signal: None,
            closed: false,
        };
        let destination = connection.destination();
        let answered = async |reader: &mut Reader| match tokio::time::timeout(
            REPLY_TIMEOUT,
            reader.wait_for_reply(),
        )
        .await
        {
            Ok(true) => Ok(()),
            Ok(false) => Err(Error::ShellRefused {
                alias: destination.alias.clone(),
            }),
            Err(_) => Err(Error::TimedOut {
                alias: destination.alias.clone(),
                host: destination.host.clone(),
                port: destination.port,
            }),
        };
        // Backspace sends DEL, as the terminal view does; the line
        // discipline counts UTF-8 characters when it erases.
        let modes = [(Pty::VERASE, 0x7f), (Pty::IUTF8, 1)];
        writer
            .request_pty(true, TERM, size.cols, size.rows, 0, 0, &modes)
            .await?;
        answered(&mut reader).await?;
        writer.request_shell(true).await?;
        answered(&mut reader).await?;
        Ok(Self {
            connection,
            writer,
            reader: Mutex::new(reader),
        })
    }

    /// The next thing from the shell. After [`ShellEvent::Closed`] it is
    /// `Closed` again. One caller at a time; others wait their turn.
    pub async fn next_event(&self) -> ShellEvent {
        self.reader.lock().await.next_event().await
    }

    /// Sends what the user typed (or pasted). Calls made one after another,
    /// each awaited, go out in that order; calls in flight at once may not.
    pub async fn write(&self, data: &[u8]) -> Result<(), Error> {
        self.writer.data(data).await.map_err(Error::from)
    }

    /// Tells the server the terminal's new size.
    pub async fn resize(&self, size: PtySize) -> Result<(), Error> {
        Ok(self
            .writer
            .window_change(size.cols, size.rows, 0, 0)
            .await?)
    }

    /// Asks every machine on the way for an answer now (see
    /// [`Connection::keepalive`]).
    pub async fn keepalive(&self) -> Result<(), Error> {
        self.connection.keepalive().await
    }

    /// Closes the shell and the connection, jump hosts included.
    pub async fn close(&self) {
        // Already gone, or going: either way nothing more to send.
        let _ = self.writer.eof().await;
        let _ = self.writer.close().await;
        self.connection.disconnect().await;
    }

    /// The destination's settings.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

impl Reader {
    /// Waits for the server's answer to a request, keeping what else comes,
    /// up to [`PENDING_BYTES`]: `true` for yes. A server that sends more
    /// before it answers is taken as a no.
    async fn wait_for_reply(&mut self) -> bool {
        loop {
            match self.half.wait().await {
                Some(ChannelMsg::Success) => return true,
                Some(ChannelMsg::Failure) | None => return false,
                Some(other) => {
                    if let Some(event) = self.event(other) {
                        let ended = match &event {
                            ShellEvent::Output(data) => {
                                self.pending_bytes += data.len();
                                self.pending_bytes > PENDING_BYTES
                            }
                            ShellEvent::Closed(_) => true,
                        };
                        self.pending.push_back(event);
                        if ended {
                            return false;
                        }
                    }
                }
            }
        }
    }

    async fn next_event(&mut self) -> ShellEvent {
        if let Some(event) = self.pending.pop_front() {
            return event;
        }
        loop {
            if self.closed {
                return ShellEvent::Closed(self.closed_event(false));
            }
            let Some(message) = self.half.wait().await else {
                // The channel went without the server closing it.
                self.closed = true;
                return ShellEvent::Closed(self.closed_event(true));
            };
            if let Some(event) = self.event(message) {
                return event;
            }
        }
    }

    /// What a channel message means for the app, if anything.
    fn event(&mut self, message: ChannelMsg) -> Option<ShellEvent> {
        match message {
            ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                Some(ShellEvent::Output(data.to_vec()))
            }
            ChannelMsg::ExitStatus { exit_status } => {
                self.exit_status = Some(exit_status);
                None
            }
            ChannelMsg::ExitSignal { signal_name, .. } => {
                self.exit_signal = Some(format!("{signal_name:?}"));
                None
            }
            ChannelMsg::Close => {
                self.closed = true;
                Some(ShellEvent::Closed(self.closed_event(false)))
            }
            _ => None,
        }
    }

    fn closed_event(&self, connection_lost: bool) -> Closed {
        Closed {
            exit_status: self.exit_status,
            exit_signal: self.exit_signal.clone(),
            connection_lost,
        }
    }
}
