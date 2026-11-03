//! The in-app terminal: interactive `ssh` sessions, one pseudo-terminal each
//! (`ConPTY` on Windows), running `ssh -o ConnectTimeout=10 -- <alias>` with
//! `TERM=xterm-256color`.
//!
//! - Output goes to the UI over the session's channel as raw bytes, at most
//!   [`OUTPUT_RATE`] a second; state changes and prompts go over the same
//!   channel as [`TerminalEvent`]s. Input, resizing, answers and closing are
//!   commands.
//! - `ssh` asks for secrets through an interactive askpass session whose
//!   [`Bridge`] answers from the vault or asks the user (see [`bridge`]).
//! - A session is *connecting* until the remote session starts, then
//!   *connected*, then *ended*; exiting before it connected is *failed*, with
//!   a reason. On macOS and Linux the start is when `ssh` puts the terminal in
//!   raw mode, which it does only once signed in; where the terminal's mode
//!   cannot be read (Windows) it is the first output after the last prompt
//!   that is not one of `ssh`'s own messages. That output may come before
//!   signing in (a server's banner), so there the bridge keeps answering
//!   prompts and answers are never saved in the vault.
//! - Sessions outlive page changes in the UI. They end when the app quits or
//!   the page reloads (their channels die with it); locking the vault does not
//!   end them.
//!
//! Terminal data and answers are never logged.

pub mod bridge;
mod external;
mod store;
mod text;
pub mod types;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use portable_pty::{
    ChildKiller, CommandBuilder, ExitStatus, MasterPty, PtySize, native_pty_system,
};
use sshkm_core::ErrorCode;
use sshkm_core::agent::AgentClient;
use tauri::AppHandle;
use tauri::ipc::{Channel, InvokeResponseBody};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub use self::bridge::Bridge;
pub use self::external::open_external;
use self::store::VaultStore;
use self::text::Resolved;
use self::types::{OpenOptions, Phase, PromptAnswer, SessionState, TerminalEvent, TerminalInfo};
use crate::askpass::{Connection, PromptAccount, Session};
use crate::commands::remote::check_alias;
use crate::error::{AppError, AppResult};
use crate::process;
use crate::state::AppState;

/// Output kept while connecting, to tell why a session failed.
const TAIL: usize = 16 * 1024;
/// How often the terminal's mode is checked while connecting.
const POLL: Duration = Duration::from_millis(100);
/// The terminal's mode can be read here (see [`is_raw`]), so raw mode tells
/// when the session signed in.
const READS_MODE: bool = cfg!(unix);
/// The most output a session passes to the UI per second, after a burst of
/// [`OUTPUT_BURST`]. The channel to the webview queues whatever it is sent,
/// so a server flooding the terminal would otherwise fill the app's memory
/// faster than xterm draws it; past this rate the session stops reading, and
/// `ssh` and then the server wait.
const OUTPUT_RATE: u64 = 4 * 1024 * 1024;
const OUTPUT_BURST: u64 = 1024 * 1024;

/// Where a session's output and events go: the UI's channel, or a test.
pub trait Sink: Send + Sync + 'static {
    fn event(&self, event: &TerminalEvent);
    fn output(&self, bytes: &[u8]);
}

impl Sink for Channel<InvokeResponseBody> {
    fn event(&self, event: &TerminalEvent) {
        if let Ok(json) = serde_json::to_string(event) {
            let _ = self.send(InvokeResponseBody::Json(json));
        }
    }

    fn output(&self, bytes: &[u8]) {
        let _ = self.send(InvokeResponseBody::Raw(bytes.to_vec()));
    }
}

/// The open sessions.
#[derive(Default)]
pub struct Terminals {
    next_id: AtomicU32,
    sessions: Mutex<HashMap<u32, Arc<Terminal>>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Terminals {
    /// Starts `ssh` to `alias` in a `cols`×`rows` terminal.
    pub fn open(
        self: &Arc<Self>,
        state: &Arc<AppState>,
        app: &AppHandle,
        alias: &str,
        size: (u16, u16),
        options: &OpenOptions,
        sink: Arc<dyn Sink>,
    ) -> AppResult<TerminalInfo> {
        check_alias(alias)?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let resolved = resolve(alias);
        let key_offered = resolved.as_ref().is_some_and(|r| {
            r.offers_key(&state.paths.home, || {
                AgentClient::from_env()
                    .ok()
                    .and_then(|agent| agent.with_timeout(Duration::from_millis(500)).list().ok())
                    .is_some_and(|keys| !keys.is_empty())
            })
        });
        let bridge = Arc::new(Bridge::new(
            VaultStore {
                app: app.clone(),
                state: Arc::clone(state),
                alias: alias.to_owned(),
                user: resolved.as_ref().and_then(|r| r.user.clone()),
            },
            Arc::clone(&sink),
            bridge::Options {
                key_offered,
                ask_password: options.ask_password,
                // Only raw mode tells for sure that the session signed in.
                can_save: READS_MODE,
                timeout: bridge::ANSWER_TIMEOUT,
            },
        ));
        let askpass = state.askpass_interactive_session(Arc::clone(&bridge))?;
        if let Some(account) = resolved.as_ref().and_then(account) {
            askpass.expect_account(account);
        }
        // Without `ssh -G` nothing is known about the way: assume the worst.
        askpass.expect_connection(Connection::new(
            state.openssh_version().as_deref(),
            resolved.as_ref().is_none_or(|r| r.keyboard_interactive),
            resolved.as_ref().is_none_or(Resolved::proxied),
        ));

        let info = TerminalInfo {
            id,
            alias: alias.to_owned(),
            user: resolved.as_ref().and_then(|r| r.user.clone()),
            host: resolved.as_ref().and_then(|r| r.host_name.clone()),
            proxy_jump: resolved.as_ref().and_then(|r| r.proxy_jump.clone()),
            started_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            phase: Phase::Connecting,
        };
        let command = ssh_command(alias, &state.paths.home, &askpass);
        // Held until the session is listed, so a session that ends at once
        // is removed after it was added.
        let mut sessions = lock(&self.sessions);
        let terminal = Terminal::spawn(
            info.clone(),
            command,
            size,
            bridge,
            askpass,
            sink,
            Arc::downgrade(self),
        )?;
        sessions.insert(id, terminal);
        Ok(info)
    }

    fn get(&self, id: u32) -> AppResult<Arc<Terminal>> {
        lock(&self.sessions)
            .get(&id)
            .cloned()
            .ok_or_else(|| AppError::not_found("the session has ended"))
    }

    pub fn write(&self, id: u32, data: Vec<u8>) -> AppResult<()> {
        self.get(id)?.write(data);
        Ok(())
    }

    pub fn resize(&self, id: u32, cols: u16, rows: u16) -> AppResult<()> {
        self.get(id)?.resize(cols, rows)
    }

    /// Hands an answer to the session's waiting prompt; false if it no
    /// longer waits.
    pub fn answer(&self, id: u32, prompt: u32, answer: PromptAnswer) -> AppResult<bool> {
        Ok(self.get(id)?.bridge.answer(prompt, answer))
    }

    /// Ends a session (the remote shell gets a hang-up).
    pub fn close(&self, id: u32) {
        if let Ok(terminal) = self.get(id) {
            terminal.close();
        }
    }

    /// The sessions still running.
    pub fn list(&self) -> Vec<TerminalInfo> {
        let mut list: Vec<_> = lock(&self.sessions)
            .values()
            .map(|terminal| lock(&terminal.info).clone())
            .collect();
        list.sort_by_key(|info| info.id);
        list
    }

    /// Ends every session, when the app quits or its page reloads.
    pub fn close_all(&self) {
        let sessions: Vec<_> = lock(&self.sessions).values().cloned().collect();
        for terminal in sessions {
            terminal.close();
        }
    }

    fn remove(&self, id: u32) {
        lock(&self.sessions).remove(&id);
    }
}

/// What `ssh -G` says about `alias`; `None` if it cannot read its
/// configuration (the session then shows `ssh`'s own error).
fn resolve(alias: &str) -> Option<Resolved> {
    let output = process::run("ssh", &["-G", "--", alias], Duration::from_secs(10)).ok()?;
    output.success.then(|| Resolved::parse(&output.stdout))
}

/// The account `ssh`'s prompts name for this host.
fn account(resolved: &Resolved) -> Option<PromptAccount> {
    let host = resolved
        .host_key_alias
        .clone()
        .or_else(|| resolved.host_name.clone())?;
    Some(PromptAccount::new(resolved.user.clone()?, host))
}

/// `ssh -o ConnectTimeout=10 -- <alias>` asking `askpass` for secrets.
fn ssh_command(alias: &str, home: &std::path::Path, askpass: &Session) -> CommandBuilder {
    let mut command = CommandBuilder::new("ssh");
    command.args(["-o", "ConnectTimeout=10", "--", alias]);
    for (name, value) in askpass.env() {
        command.env(name, value);
    }
    command.cwd(home);
    command
}

/// Starts `command` (an `ssh` command set up for `askpass`) in a terminal
/// whose prompts `bridge` answers, outside the app's list of sessions: for
/// the tests that run a local `sshd`.
#[doc(hidden)]
pub fn spawn_detached(
    command: CommandBuilder,
    size: (u16, u16),
    bridge: Arc<Bridge>,
    askpass: Session,
    sink: Arc<dyn Sink>,
) -> AppResult<Arc<Terminal>> {
    let info = TerminalInfo {
        id: 0,
        alias: String::new(),
        user: None,
        host: None,
        proxy_jump: None,
        started_at: String::new(),
        phase: Phase::Connecting,
    };
    Terminal::spawn(
        info,
        command,
        size,
        bridge,
        askpass,
        sink,
        std::sync::Weak::new(),
    )
}

/// One session: `ssh` in a pseudo-terminal and the threads that serve it.
pub struct Terminal {
    info: Mutex<TerminalInfo>,
    bridge: Arc<Bridge>,
    sink: Arc<dyn Sink>,
    /// Keystrokes for the writer thread, in order.
    input: Mutex<Option<Sender<Vec<u8>>>>,
    master: Mutex<Option<Box<dyn MasterPty + Send>>>,
    killer: Mutex<Box<dyn ChildKiller + Send + Sync>>,
    /// The terminal's mode can be read, so raw mode tells when the session
    /// started.
    reads_mode: bool,
    /// Closed by the user: ends as "ended", whatever the exit status.
    closing: AtomicBool,
    progress: Mutex<Progress>,
}

struct Progress {
    phase: Phase,
    connected_at: Option<Instant>,
    /// Output while connecting, at most [`TAIL`] bytes.
    tail: Vec<u8>,
}

impl Terminal {
    fn spawn(
        info: TerminalInfo,
        mut command: CommandBuilder,
        (cols, rows): (u16, u16),
        bridge: Arc<Bridge>,
        askpass: Session,
        sink: Arc<dyn Sink>,
        terminals: std::sync::Weak<Terminals>,
    ) -> AppResult<Arc<Self>> {
        let pair = native_pty_system()
            .openpty(size(cols, rows))
            .map_err(|e| open_error(&e))?;
        command.env("TERM", "xterm-256color");
        command.env("COLORTERM", "truecolor");
        // Apps started from the Dock or a desktop menu often have no locale;
        // without one the server may not show UTF-8.
        let no_locale = ["LC_ALL", "LC_CTYPE", "LANG"]
            .iter()
            .all(|name| std::env::var_os(name).is_none());
        if cfg!(unix) && no_locale {
            command.env("LANG", "en_US.UTF-8");
        }
        let child = pair.slave.spawn_command(command).map_err(|e| {
            let missing = e
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound);
            spawn_error(&e, missing)
        })?;
        drop(pair.slave);
        let reader = pair.master.try_clone_reader().map_err(|e| pty_error(&e))?;
        let writer = pair.master.take_writer().map_err(|e| pty_error(&e))?;
        let reads_mode = is_raw(pair.master.as_ref()).is_some();
        let (input, keystrokes) = mpsc::channel();

        let terminal = Arc::new(Self {
            info: Mutex::new(info),
            bridge,
            sink,
            input: Mutex::new(Some(input)),
            killer: Mutex::new(child.clone_killer()),
            master: Mutex::new(Some(pair.master)),
            reads_mode,
            closing: AtomicBool::new(false),
            progress: Mutex::new(Progress {
                phase: Phase::Connecting,
                connected_at: None,
                tail: Vec::new(),
            }),
        });

        thread::Builder::new()
            .name("terminal-write".into())
            .spawn(move || write_keystrokes(writer, &keystrokes))?;
        let (read_done, reader_finished) = mpsc::channel();
        thread::Builder::new().name("terminal-read".into()).spawn({
            let terminal = Arc::clone(&terminal);
            move || {
                terminal.read(reader);
                let _ = read_done.send(());
            }
        })?;
        thread::Builder::new().name("terminal-wait".into()).spawn({
            let terminal = Arc::clone(&terminal);
            move || {
                let status = terminal.wait(child);
                terminal.finish(status.as_ref(), &reader_finished, askpass);
                if let Some(terminals) = terminals.upgrade() {
                    terminals.remove(lock(&terminal.info).id);
                }
            }
        })?;
        Ok(terminal)
    }

    pub fn phase(&self) -> Phase {
        lock(&self.progress).phase
    }

    pub fn write(&self, data: Vec<u8>) {
        if let Some(input) = lock(&self.input).as_ref() {
            let _ = input.send(data);
        }
    }

    fn resize(&self, cols: u16, rows: u16) -> AppResult<()> {
        if let Some(master) = lock(&self.master).as_ref() {
            master.resize(size(cols, rows)).map_err(|e| pty_error(&e))?;
        }
        Ok(())
    }

    pub fn close(&self) {
        self.closing.store(true, Ordering::SeqCst);
        self.bridge.close();
        let _ = lock(&self.killer).kill();
    }

    /// Passes output to the UI until the terminal closes, at most
    /// [`OUTPUT_RATE`] bytes a second.
    fn read(&self, mut reader: Box<dyn Read + Send>) {
        let mut buffer = vec![0; 32 * 1024];
        let mut throttle = Throttle::new(OUTPUT_RATE, OUTPUT_BURST);
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    self.output(&buffer[..n]);
                    let sent = u64::try_from(n).unwrap_or(u64::MAX);
                    thread::sleep(throttle.take(sent, Instant::now()));
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
    }

    fn output(&self, chunk: &[u8]) {
        let starts_session = {
            let mut progress = lock(&self.progress);
            if progress.phase == Phase::Connecting {
                progress.tail.extend_from_slice(chunk);
                let excess = progress.tail.len().saturating_sub(TAIL);
                progress.tail.drain(..excess);
                !self.reads_mode
                    && !self.bridge.is_waiting()
                    && !text::only_ssh_messages(&String::from_utf8_lossy(chunk))
            } else {
                false
            }
        };
        if starts_session {
            self.connected(false);
        }
        self.sink.output(chunk);
    }

    /// The remote session started: tell the UI what signing in used, then
    /// save the answers the user chose to save. `signed_in` is false when
    /// only output says so (where the terminal's mode cannot be read): that
    /// may be the server's banner before a password it refuses, so prompts
    /// are still answered and nothing is saved.
    fn connected(&self, signed_in: bool) {
        {
            let mut progress = lock(&self.progress);
            if progress.phase != Phase::Connecting {
                return;
            }
            progress.phase = Phase::Connected;
            progress.connected_at = Some(Instant::now());
            progress.tail = Vec::new();
        }
        lock(&self.info).phase = Phase::Connected;
        let sign_in = if signed_in {
            self.bridge.signed_in()
        } else {
            self.bridge.output_started()
        };
        self.sink.event(&TerminalEvent::State {
            state: SessionState::Connected { sign_in },
        });
        if !signed_in {
            return;
        }
        // Writing the vault takes a moment (key derivation); keep it off the
        // output's way.
        let bridge = Arc::clone(&self.bridge);
        let _ = thread::Builder::new()
            .name("terminal-save".into())
            .spawn(move || bridge.save_answers());
    }

    /// Waits for `ssh` to exit, watching for raw mode while connecting.
    fn wait(&self, mut child: Box<dyn portable_pty::Child + Send + Sync>) -> Option<ExitStatus> {
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Some(status),
                Ok(None) => {}
                Err(_) => return None,
            }
            if self.phase() != Phase::Connecting {
                return child.wait().ok();
            }
            let raw = lock(&self.master)
                .as_ref()
                .and_then(|master| is_raw(master.as_ref()));
            if raw == Some(true) {
                self.connected(true);
            } else {
                thread::sleep(POLL);
            }
        }
    }

    fn finish(
        &self,
        status: Option<&ExitStatus>,
        reader_finished: &Receiver<()>,
        askpass: Session,
    ) {
        // Closing the terminal ends the reader on Windows; elsewhere it ends
        // when `ssh` does. Wait for the last output either way.
        drop(lock(&self.master).take());
        let _ = reader_finished.recv_timeout(Duration::from_secs(2));
        self.bridge.close();
        drop(askpass);
        drop(lock(&self.input).take());

        let exit_code = status.and_then(|s| s.signal().is_none().then(|| s.exit_code()));
        let state = {
            let progress = lock(&self.progress);
            let ended = SessionState::Ended {
                exit_code,
                duration_secs: progress.connected_at.map_or(0, |at| {
                    u32::try_from(at.elapsed().as_secs()).unwrap_or(u32::MAX)
                }),
            };
            if progress.phase == Phase::Connected
                || self.closing.load(Ordering::SeqCst)
                || exit_code == Some(0)
            {
                ended
            } else {
                let output = text::strip_escapes(&String::from_utf8_lossy(&progress.tail));
                SessionState::Failed {
                    failure: self.bridge.failure(&output, exit_code),
                }
            }
        };
        lock(&self.progress).phase = state.phase();
        lock(&self.info).phase = state.phase();
        self.sink.event(&TerminalEvent::State { state });
    }
}

/// A token bucket: `rate` bytes a second after a burst of `burst`.
struct Throttle {
    rate: u64,
    burst: u64,
    /// Bytes that may go out without waiting.
    budget: u64,
    /// Until when the budget is counted; in the future while paying off a
    /// wait.
    since: Instant,
}

impl Throttle {
    fn new(rate: u64, burst: u64) -> Self {
        Self {
            rate,
            burst,
            budget: burst,
            since: Instant::now(),
        }
    }

    /// Spends `bytes` sent at `now`; returns how long to wait before sending
    /// more.
    fn take(&mut self, bytes: u64, now: Instant) -> Duration {
        let earned = now.saturating_duration_since(self.since).as_nanos() * u128::from(self.rate)
            / 1_000_000_000;
        self.since = self.since.max(now);
        self.budget = u64::try_from(u128::from(self.budget) + earned)
            .unwrap_or(u64::MAX)
            .min(self.burst);
        if bytes <= self.budget {
            self.budget -= bytes;
            return Duration::ZERO;
        }
        let owed = u128::from(bytes - self.budget);
        self.budget = 0;
        let wait = Duration::from_nanos(
            u64::try_from(owed * 1_000_000_000 / u128::from(self.rate)).unwrap_or(u64::MAX),
        );
        self.since += wait;
        wait
    }
}

fn write_keystrokes(mut writer: Box<dyn Write + Send>, keystrokes: &Receiver<Vec<u8>>) {
    for data in keystrokes {
        if writer
            .write_all(&data)
            .and_then(|()| writer.flush())
            .is_err()
        {
            break;
        }
    }
}

fn size(cols: u16, rows: u16) -> PtySize {
    PtySize {
        rows: rows.max(2),
        cols: cols.max(10),
        pixel_width: 0,
        pixel_height: 0,
    }
}

/// Whether the terminal is in raw mode (no line editing, no echo), as `ssh`
/// sets it once the remote session starts; `None` where the mode cannot be
/// read.
#[cfg(unix)]
fn is_raw(master: &dyn MasterPty) -> Option<bool> {
    use nix::sys::termios::LocalFlags;
    let termios = master.get_termios()?;
    Some(
        !termios
            .local_flags
            .intersects(LocalFlags::ICANON | LocalFlags::ECHO),
    )
}

#[cfg(not(unix))]
fn is_raw(_master: &dyn MasterPty) -> Option<bool> {
    None
}

/// The terminal could not be created. On Windows that means no `ConPTY`.
fn open_error(error: &impl std::fmt::Display) -> AppError {
    if cfg!(windows) {
        AppError::new(
            ErrorCode::Unsupported,
            format!("the terminal needs Windows 10 version 1809 or later (ConPTY): {error}"),
        )
    } else {
        pty_error(error)
    }
}

fn pty_error(error: &impl std::fmt::Display) -> AppError {
    AppError::new(ErrorCode::Io, format!("terminal: {error}"))
}

fn spawn_error(error: &impl std::fmt::Display, missing: bool) -> AppError {
    if missing {
        AppError::not_found("ssh is not installed")
    } else {
        AppError::new(ErrorCode::Io, format!("cannot start ssh: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_throttled_after_a_burst() {
        let start = Instant::now();
        let ms = Duration::from_millis;
        let mut throttle = Throttle::new(1000, 100);
        throttle.since = start;
        // The burst goes out at once; then 1000 bytes a second.
        assert_eq!(throttle.take(100, start), Duration::ZERO);
        assert_eq!(throttle.take(50, start), ms(50));
        // A wait already served is not earned again.
        assert_eq!(throttle.take(10, start + ms(50)), ms(10));
        // 20 ms later 20 bytes are earned.
        assert_eq!(throttle.take(30, start + ms(80)), ms(10));
        // An idle second refills the burst, no more.
        assert_eq!(throttle.take(100, start + ms(2000)), Duration::ZERO);
        assert_eq!(throttle.take(1, start + ms(2000)), ms(1));
    }

    /// The raw-mode check sees what `stty` does to the terminal, as `ssh`
    /// does when the session starts.
    #[cfg(unix)]
    #[test]
    fn sees_raw_mode() {
        let pair = native_pty_system().openpty(size(80, 24)).unwrap();
        assert_eq!(is_raw(pair.master.as_ref()), Some(false));
        let mut command = CommandBuilder::new("/bin/sh");
        command.args(["-c", "stty raw -echo; sleep 5"]);
        let mut child = pair.slave.spawn_command(command).unwrap();
        drop(pair.slave);
        let started = Instant::now();
        while is_raw(pair.master.as_ref()) != Some(true) {
            assert!(
                started.elapsed() < Duration::from_secs(4),
                "raw mode not seen"
            );
            thread::sleep(Duration::from_millis(20));
        }
        let _ = child.kill();
    }
}
