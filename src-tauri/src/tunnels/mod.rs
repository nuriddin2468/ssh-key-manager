//! The Tunnels tool's port forwards while they run: one `ssh -N` child per
//! tunnel that is on (see [`sshkm_core::tunnels`] for its arguments).
//!
//! - `ssh` asks for passwords, passphrases and host keys through an
//!   interactive askpass session whose prompt bridge is the terminal's
//!   ([`crate::terminal::Bridge`]): saved secrets come from the vault, the
//!   rest becomes a prompt on the tunnel for the Tools page to show, and a
//!   new host key is trusted only after the user's yes.
//! - A tunnel is *connecting* until `ssh` logs `Authenticated to …`
//!   (`LogLevel=VERBOSE`), then *up* once the forward had a moment to be
//!   set up: `ExitOnForwardFailure` ends `ssh` if it can't be. That line is
//!   read only from `ssh`'s own log, a private file (`-E`): a server's or
//!   jump host's banner and a `ProxyCommand`'s output go to its stderr, so
//!   they can't make answers count as accepted. Only the server signing in
//!   could write such a line there, and it could just as well let the user
//!   in.
//! - A tunnel that lets others reach something through this computer (one
//!   listening on more than loopback, or any remote tunnel) is saved only
//!   after the user's yes in a native dialog, unless it forwards as it did
//!   when saved before.
//! - When `ssh` ends by itself the tunnel failed, with a reason. With
//!   auto-reconnect on, one that may work later (the network, a busy port,
//!   a server that went away) starts again after 2 seconds, then 5, 10, 20,
//!   30 and 60 at most; a minute up starts the count over.
//! - Tunnels run on while the window is closed to the tray, a page reloads
//!   or the vault locks. They stop when the app quits ([`Tunnels::stop_all`]).
//! - Every change goes to the UI as [`CHANGED_EVENT`], and to the tray menu,
//!   which counts the tunnels that are on.
//!
//! `ssh`'s output and log are kept (the last 16 KiB) to tell why a tunnel
//! failed; they hold no secret, since answers go through askpass. Nothing is
//! logged by the app, and the log file is removed when `ssh` ends.

pub mod failure;

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError, Weak};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;
use sshkm_core::agent::AgentClient;
use sshkm_core::tunnels::{Tunnel, TunnelKind, TunnelStore};
use tauri::{AppHandle, Emitter, Manager};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use self::failure::{TunnelFailReason, TunnelFailure, classify, shown_output};
use crate::askpass::{Connection, Session};
use crate::commands::Shared;
use crate::commands::remote::check_alias;
use crate::error::{AppError, AppResult};
use crate::process::{self, LogFile};
use crate::terminal::bridge::{self, Bridge};
use crate::terminal::store::VaultStore;
use crate::terminal::text::Resolved;
use crate::terminal::types::{PromptAnswer, PromptRequest, TerminalEvent};
use crate::terminal::{Sink, account, resolve};

/// Sent to the page, and the tray, whenever a tunnel changes.
pub const CHANGED_EVENT: &str = "tunnels-changed";
const FILE: &str = "tunnels.json";
const POLL: Duration = Duration::from_millis(100);
/// After signing in, how long `ssh` gets to set up the forward before the
/// tunnel counts as up. A local port is bound at once; a remote one waits
/// for the server's answer.
const SETTLE_LOCAL: Duration = Duration::from_millis(500);
const SETTLE_REMOTE: Duration = Duration::from_secs(2);
/// `ssh`'s output kept to tell why it stopped.
const TAIL: usize = 16 * 1024;
/// Seconds between tries, by how many failed in a row.
const BACKOFF: [u64; 6] = [2, 5, 10, 20, 30, 60];
/// Up this long, a tunnel that drops starts the count of tries over.
const STEADY: Duration = Duration::from_secs(60);

/// Where a tunnel is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum TunnelState {
    Off,
    /// `ssh` is connecting and signing in; `attempt` counts from 1.
    Connecting {
        attempt: u32,
    },
    /// The forward is in place: listening here (local, dynamic), or on the
    /// server (remote).
    Up {
        /// RFC 3339, UTC.
        since: String,
    },
    /// It failed, and starts again at `at` (RFC 3339, UTC).
    Retrying {
        attempt: u32,
        at: String,
        failure: TunnelFailure,
    },
    /// It failed and stays off until started again.
    Failed {
        failure: TunnelFailure,
    },
}

impl TunnelState {
    /// Started and not given up: what the switch shows as on.
    pub fn is_on(&self) -> bool {
        matches!(
            self,
            Self::Connecting { .. } | Self::Up { .. } | Self::Retrying { .. }
        )
    }
}

/// A tunnel as the Tools page shows it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct TunnelView {
    pub tunnel: Tunnel,
    pub state: TunnelState,
    /// What `ssh` asks and waits for; answer with `tunnel_answer`.
    pub prompt: Option<PromptRequest>,
    /// "Open in browser", for a local tunnel.
    pub browser_url: Option<String>,
    /// It listens beyond this computer (or the server): others on the
    /// network can use it.
    pub exposed: bool,
    /// The tunnel as a line of `~/.ssh/config`: `LocalForward …`.
    pub config_line: String,
}

/// A tunnel that is on, for the tray menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Active {
    pub label: String,
    /// A prompt waits for the user.
    pub waiting: bool,
}

pub type SharedTunnels = Arc<Tunnels>;

pub struct Tunnels {
    store: TunnelStore,
    app: OnceLock<AppHandle>,
    runs: Mutex<HashMap<String, Arc<Run>>>,
    /// How tunnels that gave up ended, until they start again.
    ended: Mutex<HashMap<String, TunnelFailure>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn now() -> String {
    OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_default()
}

impl Tunnels {
    /// Tunnels kept in `tunnels.json` in `data_dir`.
    pub fn new(data_dir: &Path) -> Self {
        Self {
            store: TunnelStore::new(data_dir.join(FILE)),
            app: OnceLock::new(),
            runs: Mutex::new(HashMap::new()),
            ended: Mutex::new(HashMap::new()),
        }
    }

    /// Lets tunnels run and tell the page about it; once, at start.
    pub fn attach(&self, app: AppHandle) {
        let _ = self.app.set(app);
    }

    pub fn list(&self) -> AppResult<Vec<TunnelView>> {
        Ok(self.store.load()?.iter().map(|t| self.view(t)).collect())
    }

    fn find(&self, id: &str) -> AppResult<Tunnel> {
        self.store
            .load()?
            .into_iter()
            .find(|t| t.id == id)
            .ok_or_else(|| AppError::not_found("no such tunnel"))
    }

    fn view(&self, tunnel: &Tunnel) -> TunnelView {
        let run = lock(&self.runs).get(&tunnel.id).cloned();
        let (state, prompt) = match run {
            Some(run) => (lock(&run.state).clone(), lock(&run.prompt).clone()),
            None => match lock(&self.ended).get(&tunnel.id) {
                Some(failure) => (
                    TunnelState::Failed {
                        failure: failure.clone(),
                    },
                    None,
                ),
                None => (TunnelState::Off, None),
            },
        };
        let (key, value) = tunnel.config_line();
        TunnelView {
            tunnel: tunnel.clone(),
            state,
            prompt,
            browser_url: tunnel.browser_url(),
            exposed: tunnel.exposed(),
            config_line: format!("{key} {value}"),
        }
    }

    /// Adds or changes a tunnel; one that is on starts again as changed.
    ///
    /// A tunnel that lets others reach something through this computer
    /// ([`Tunnel::opens_to_others`]) is saved only once `approve` says yes,
    /// unless it was saved before forwarding the same way: `approve` is
    /// the native confirmation, which the page can't answer.
    pub fn save(
        self: &Arc<Self>,
        tunnel: Tunnel,
        approve: impl FnOnce(&Tunnel) -> AppResult<()>,
    ) -> AppResult<TunnelView> {
        let tunnel = tunnel.normalized();
        if tunnel.opens_to_others() {
            let unchanged = !tunnel.id.is_empty()
                && self
                    .store
                    .load()?
                    .iter()
                    .any(|saved| saved.id == tunnel.id && saved.same_forward(&tunnel));
            if !unchanged {
                tunnel.validate()?;
                approve(&tunnel)?;
            }
        }
        let saved = self.store.save(tunnel)?;
        if self.stop(&saved.id) {
            self.start(&saved)?;
        }
        lock(&self.ended).remove(&saved.id);
        self.changed();
        Ok(self.view(&saved))
    }

    pub fn delete(&self, id: &str) -> AppResult<()> {
        self.stop(id);
        self.store.remove(id)?;
        lock(&self.ended).remove(id);
        self.changed();
        Ok(())
    }

    /// Starts or stops the tunnel `id`.
    pub fn set_on(self: &Arc<Self>, id: &str, on: bool) -> AppResult<TunnelView> {
        let tunnel = self.find(id)?;
        if on {
            self.start(&tunnel)?;
        } else {
            self.stop(id);
            lock(&self.ended).remove(id);
        }
        self.changed();
        Ok(self.view(&tunnel))
    }

    /// Hands the user's answer to the tunnel's waiting prompt; false if it
    /// no longer waits.
    pub fn answer(&self, id: &str, prompt: u32, answer: PromptAnswer) -> bool {
        let Some(run) = lock(&self.runs).get(id).cloned() else {
            return false;
        };
        let bridge = lock(&run.bridge).clone();
        bridge.is_some_and(|bridge| bridge.answer(prompt, answer))
    }

    /// The tunnels that are on, in the order they were saved.
    pub fn active(&self) -> Vec<Active> {
        let runs = lock(&self.runs).clone();
        let order = self.store.load().unwrap_or_default();
        order
            .iter()
            .filter_map(|t| runs.get(&t.id))
            .filter(|run| lock(&run.state).is_on())
            .map(|run| Active {
                label: run.tunnel.label(),
                waiting: lock(&run.prompt).is_some(),
            })
            .collect()
    }

    /// Stops every tunnel: from the tray menu, and when the app quits.
    pub fn stop_all(&self) {
        let runs: Vec<_> = lock(&self.runs).drain().map(|(_, run)| run).collect();
        for run in &runs {
            run.stop();
        }
        if !runs.is_empty() {
            self.changed();
        }
    }

    fn start(self: &Arc<Self>, tunnel: &Tunnel) -> AppResult<()> {
        check_alias(&tunnel.alias)?;
        let mut runs = lock(&self.runs);
        if runs.contains_key(&tunnel.id) {
            return Ok(());
        }
        let run = Arc::new(Run::new(tunnel.clone()));
        runs.insert(tunnel.id.clone(), Arc::clone(&run));
        drop(runs);
        lock(&self.ended).remove(&tunnel.id);
        let tunnels = Arc::clone(self);
        thread::Builder::new()
            .name("tunnel".into())
            .spawn(move || tunnels.supervise(&run))?;
        Ok(())
    }

    /// Stops the tunnel `id`; whether it was running.
    fn stop(&self, id: &str) -> bool {
        let run = lock(&self.runs).remove(id);
        if let Some(run) = &run {
            run.stop();
        }
        run.is_some()
    }

    fn changed(&self) {
        if let Some(app) = self.app.get() {
            let _ = app.emit(CHANGED_EVENT, ());
        }
    }

    /// Runs `ssh` for `run` until it is stopped or gives up.
    fn supervise(self: &Arc<Self>, run: &Arc<Run>) {
        let mut failed_in_a_row: u32 = 0;
        loop {
            if run.stopping() {
                break;
            }
            failed_in_a_row += 1;
            run.set(TunnelState::Connecting {
                attempt: failed_in_a_row,
            });
            self.changed();
            let (failure, up_for) = self.attempt(run);
            if run.stopping() {
                break;
            }
            if up_for.is_some_and(|up| up >= STEADY) {
                failed_in_a_row = 1;
            }
            if run.tunnel.auto_reconnect && failure.reason.retryable() {
                let index = usize::try_from(failed_in_a_row - 1).unwrap_or(usize::MAX);
                let delay = Duration::from_secs(BACKOFF[index.min(BACKOFF.len() - 1)]);
                let at = OffsetDateTime::now_utc() + delay;
                run.set(TunnelState::Retrying {
                    attempt: failed_in_a_row,
                    at: at
                        .replace_nanosecond(0)
                        .ok()
                        .and_then(|t| t.format(&Rfc3339).ok())
                        .unwrap_or_default(),
                    failure,
                });
                self.changed();
                run.sleep(delay);
                continue;
            }
            lock(&self.ended).insert(run.tunnel.id.clone(), failure);
            break;
        }
        let mut runs = lock(&self.runs);
        if runs
            .get(&run.tunnel.id)
            .is_some_and(|r| Arc::ptr_eq(r, run))
        {
            runs.remove(&run.tunnel.id);
        }
        drop(runs);
        self.changed();
    }

    /// One `ssh` run: how it ended, and how long it was up.
    fn attempt(self: &Arc<Self>, run: &Arc<Run>) -> (TunnelFailure, Option<Duration>) {
        let other = |output: String| {
            (
                TunnelFailure {
                    reason: TunnelFailReason::Other,
                    exit_code: None,
                    output,
                },
                None,
            )
        };
        let Some(app) = self.app.get() else {
            return other("the app is not ready".into());
        };
        let Some(state) = app.try_state::<Shared>().map(|s| Arc::clone(s.inner())) else {
            return other("the app is not ready".into());
        };
        let (bridge, askpass) = match self.prompts(run, app, &state) {
            Ok(opened) => opened,
            Err(e) => return other(format!("could not ask for passwords: {e}")),
        };

        // `ssh`'s own messages, apart from what servers print.
        let opened = LogFile::create().and_then(|log| Ok((LogTail::open(log.path())?, log)));
        let (mut tail, log) = match opened {
            Ok(opened) => opened,
            Err(e) => return other(format!("could not make a log file for ssh: {e}")),
        };
        let mut command = process::command("ssh");
        askpass.configure(&mut command);
        command
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .arg("-E")
            .arg(log.path())
            .args(run.tunnel.ssh_args())
            .current_dir(&state.paths.home);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return other("ssh is not installed".into());
            }
            Err(e) => return other(format!("could not start ssh: {e}")),
        };
        let (lines, received) = mpsc::channel::<String>();
        if let Some(stderr) = child.stderr.take() {
            let _ = thread::Builder::new()
                .name("tunnel-read".into())
                .spawn(move || {
                    for line in BufReader::new(stderr).lines() {
                        let Ok(line) = line else { break };
                        if lines.send(line).is_err() {
                            break;
                        }
                    }
                });
        }
        *lock(&run.child) = Some(child);
        *lock(&run.bridge) = Some(Arc::clone(&bridge));

        let watched = self.watch(run, &bridge, &received, &mut tail);
        lock(&run.child).take();
        lock(&run.bridge).take();
        bridge.close();
        lock(&run.prompt).take();
        drop(askpass);
        drop(tail);
        drop(log);
        let Watched {
            status,
            output,
            signed_in,
            up,
        } = watched;

        let exit_code = status.and_then(|s| s.code());
        let login = bridge.failure(&output, exit_code.and_then(|c| u32::try_from(c).ok()));
        let reason = classify(&output, signed_in, &login);
        (
            TunnelFailure {
                reason,
                exit_code,
                output: shown_output(&output),
            },
            up.map(|at| at.elapsed()),
        )
    }

    /// The prompt bridge and askpass session of one `ssh` run, set up as the
    /// terminal sets up a session's.
    fn prompts(
        self: &Arc<Self>,
        run: &Arc<Run>,
        app: &AppHandle,
        state: &Shared,
    ) -> std::io::Result<(Arc<Bridge>, Session)> {
        let alias = run.tunnel.alias.clone();
        let resolved = resolve(&alias);
        let key_offered = resolved.as_ref().is_some_and(|r| {
            r.offers_key(&state.paths.home, || {
                AgentClient::from_env()
                    .ok()
                    .and_then(|agent| agent.with_timeout(Duration::from_millis(500)).list().ok())
                    .is_some_and(|keys| !keys.is_empty())
            })
        });
        let sink = Arc::new(TunnelSink {
            run: Arc::downgrade(run),
            tunnels: Arc::downgrade(self),
        });
        let bridge = Arc::new(Bridge::new(
            VaultStore {
                app: app.clone(),
                state: Arc::clone(state),
                alias,
                user: resolved.as_ref().and_then(|r| r.user.clone()),
            },
            sink,
            bridge::Options {
                key_offered,
                ask_password: false,
                // `Authenticated to …` in `ssh`'s own log tells for sure when
                // signing in is done.
                can_save: true,
                timeout: bridge::ANSWER_TIMEOUT,
            },
        ));
        let askpass = state.askpass_interactive_session(Arc::clone(&bridge))?;
        if let Some(account) = resolved.as_ref().and_then(account) {
            askpass.expect_account(account);
        }
        // Without `ssh -G` nothing is known about the way: assume the worst.
        askpass.expect_connection(
            Connection::new(
                state.openssh_version().as_deref(),
                resolved.as_ref().is_none_or(|r| r.keyboard_interactive),
                resolved.as_ref().is_none_or(Resolved::proxied),
            )
            .through_command(resolved.as_ref().is_none_or(|r| r.proxy_command.is_some())),
        );
        Ok((bridge, askpass))
    }

    /// Follows a running `ssh` until it exits (or is stopped): its stderr
    /// (`received`) and its log (`log`), signing in, and the forward coming
    /// up. Only the log tells that it signed in.
    fn watch(
        &self,
        run: &Run,
        bridge: &Bridge,
        received: &mpsc::Receiver<String>,
        log: &mut LogTail,
    ) -> Watched {
        let settle = if run.tunnel.kind == TunnelKind::Remote {
            SETTLE_REMOTE
        } else {
            SETTLE_LOCAL
        };
        let mut output = String::new();
        let mut signed_in: Option<Instant> = None;
        let mut up: Option<Instant> = None;
        let status = loop {
            match received.recv_timeout(POLL) {
                Ok(line) => keep(&mut output, &line),
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {}
            }
            for line in log.lines(false) {
                if signed_in.is_none() && line.starts_with("Authenticated to ") {
                    signed_in = Some(Instant::now());
                    bridge.signed_in();
                    bridge.save_answers();
                }
                keep(&mut output, &line);
            }
            if up.is_none() && signed_in.is_some_and(|at| at.elapsed() >= settle) {
                up = Some(Instant::now());
                run.set(TunnelState::Up { since: now() });
                self.changed();
            }
            let mut child = lock(&run.child);
            let Some(process) = child.as_mut() else {
                break None;
            };
            if run.stopping() {
                let _ = process.kill();
            }
            match process.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => {}
                Err(_) => break None,
            }
        };
        // What it printed and logged on the way out.
        let deadline = Instant::now() + Duration::from_millis(300);
        while let Ok(line) =
            received.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            keep(&mut output, &line);
        }
        for line in log.lines(true) {
            keep(&mut output, &line);
        }
        Watched {
            status,
            output,
            signed_in: signed_in.is_some(),
            up,
        }
    }
}

/// What became of one `ssh` run.
struct Watched {
    status: Option<std::process::ExitStatus>,
    /// The last [`TAIL`] bytes or so of what it printed.
    output: String,
    signed_in: bool,
    /// When the forward came up, if it did.
    up: Option<Instant>,
}

/// Adds a line to `output`, keeping about the last [`TAIL`] bytes.
fn keep(output: &mut String, line: &str) {
    output.push_str(line);
    output.push('\n');
    if output.len() > 2 * TAIL {
        let cut = output.len() - TAIL;
        let cut = (cut..output.len())
            .find(|i| output.is_char_boundary(*i))
            .unwrap_or(cut);
        output.drain(..cut);
    }
}

/// Past this size the log file is emptied (Unix, where `ssh` writes at the
/// end of the file, whatever it is): a tunnel up for long may log a line for
/// every connection it can't forward.
#[cfg_attr(not(unix), allow(dead_code))]
const LOG_LIMIT: u64 = 1024 * 1024;

/// `ssh`'s `-E` log, read line by line as it grows.
struct LogTail {
    file: File,
    /// Bytes after the last full line.
    partial: Vec<u8>,
    /// Bytes read since the file was last emptied.
    #[cfg_attr(not(unix), allow(dead_code))]
    read: u64,
}

impl LogTail {
    fn open(path: &Path) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(cfg!(unix))
            .open(path)?;
        Ok(Self {
            file,
            partial: Vec::new(),
            read: 0,
        })
    }

    /// The lines logged since the last call, without line ends; `rest`
    /// takes an unfinished last line too.
    fn lines(&mut self, rest: bool) -> Vec<String> {
        let mut buffer = [0; 8 * 1024];
        loop {
            match self.file.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    self.partial.extend_from_slice(&buffer[..n]);
                    self.read += u64::try_from(n).unwrap_or(u64::MAX);
                }
            }
        }
        #[cfg(unix)]
        if self.read > LOG_LIMIT && self.file.set_len(0).is_ok() {
            use std::io::Seek as _;
            let _ = self.file.rewind();
            self.read = 0;
        }
        let mut lines = Vec::new();
        while let Some(end) = self.partial.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.partial.drain(..=end).collect();
            lines.push(text_line(&line));
        }
        if self.partial.len() > TAIL {
            // A line without end: keep its last part.
            let cut = self.partial.len() - TAIL;
            self.partial.drain(..cut);
        }
        if rest && !self.partial.is_empty() {
            lines.push(text_line(&std::mem::take(&mut self.partial)));
        }
        lines
    }
}

/// A line of the log as text, without its `\r\n`.
fn text_line(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_end_matches(['\r', '\n'])
        .to_owned()
}

/// One tunnel that is on.
struct Run {
    /// As it was when started.
    tunnel: Tunnel,
    state: Mutex<TunnelState>,
    prompt: Mutex<Option<PromptRequest>>,
    /// The running `ssh`'s prompt bridge, for answers.
    bridge: Mutex<Option<Arc<Bridge>>>,
    child: Mutex<Option<Child>>,
    stopping: AtomicBool,
    /// Wakes a wait between tries when the tunnel is stopped.
    wake: Condvar,
    sleeping: Mutex<()>,
}

impl Run {
    fn new(tunnel: Tunnel) -> Self {
        Self {
            tunnel,
            state: Mutex::new(TunnelState::Connecting { attempt: 1 }),
            prompt: Mutex::new(None),
            bridge: Mutex::new(None),
            child: Mutex::new(None),
            stopping: AtomicBool::new(false),
            wake: Condvar::new(),
            sleeping: Mutex::new(()),
        }
    }

    fn stopping(&self) -> bool {
        self.stopping.load(Ordering::Relaxed)
    }

    fn set(&self, state: TunnelState) {
        *lock(&self.state) = state;
    }

    /// Ends `ssh` and any wait: a waiting prompt is cancelled.
    fn stop(&self) {
        self.stopping.store(true, Ordering::Relaxed);
        if let Some(bridge) = lock(&self.bridge).as_ref() {
            bridge.close();
        }
        if let Some(child) = lock(&self.child).as_mut() {
            let _ = child.kill();
        }
        let _sleeping = lock(&self.sleeping);
        self.wake.notify_all();
    }

    fn sleep(&self, delay: Duration) {
        let guard = lock(&self.sleeping);
        let _ = self
            .wake
            .wait_timeout_while(guard, delay, |()| !self.stopping());
    }
}

/// Where a tunnel's prompt bridge reports: a prompt goes on the tunnel for
/// the page to show.
struct TunnelSink {
    run: Weak<Run>,
    tunnels: Weak<Tunnels>,
}

impl Sink for TunnelSink {
    fn event(&self, event: &TerminalEvent) {
        let (Some(run), Some(tunnels)) = (self.run.upgrade(), self.tunnels.upgrade()) else {
            return;
        };
        match event {
            TerminalEvent::Prompt { prompt } => {
                *lock(&run.prompt) = Some(prompt.clone());
            }
            TerminalEvent::PromptClosed { id, .. } => {
                let mut prompt = lock(&run.prompt);
                if prompt.as_ref().is_some_and(|p| p.id == *id) {
                    *prompt = None;
                }
            }
            TerminalEvent::State { .. } | TerminalEvent::Saved { .. } => return,
        }
        tunnels.changed();
    }

    fn output(&self, _bytes: &[u8]) {}
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use sshkm_core::{ErrorCode, ExposeSecret, SecretString};

    use super::*;
    use crate::askpass::{Ask, Interactive, Prompt, Reply};
    use crate::terminal::bridge::{Options, SaveTarget, Store};
    use crate::terminal::types::SaveOffer;

    /// A vault that keeps what the bridge saves.
    #[derive(Default, Clone)]
    struct Saved(Arc<Mutex<Vec<String>>>);

    impl Store for Saved {
        fn password(&self) -> Option<SecretString> {
            None
        }
        fn one_time_code(&self) -> Option<SecretString> {
            None
        }
        fn passphrase(&self, _: &str) -> Option<SecretString> {
            None
        }
        fn offer(&self, _: &SaveTarget) -> SaveOffer {
            SaveOffer::Update
        }
        fn save(&self, _: &SaveTarget, secret: &SecretString) -> AppResult<()> {
            lock(&self.0).push(secret.expose_secret().to_owned());
            Ok(())
        }
    }

    /// Passes on the ids of the prompts the bridge shows.
    struct Prompts(Mutex<mpsc::Sender<u32>>);

    impl Sink for Prompts {
        fn event(&self, event: &TerminalEvent) {
            if let TerminalEvent::Prompt { prompt } = event {
                let _ = lock(&self.0).send(prompt.id);
            }
        }
        fn output(&self, _: &[u8]) {}
    }

    fn local(alias: &str) -> Tunnel {
        Tunnel {
            id: String::new(),
            name: String::new(),
            alias: alias.into(),
            kind: TunnelKind::Local,
            bind_address: None,
            listen_port: 8080,
            target_host: Some("localhost".into()),
            target_port: Some(80),
            auto_reconnect: false,
        }
    }

    /// A bridge whose password prompt the user answered with "typed",
    /// asking to save it.
    fn answered(saved: &Saved) -> Arc<Bridge> {
        let (send, ids) = mpsc::channel();
        let bridge = Arc::new(Bridge::new(
            saved.clone(),
            Arc::new(Prompts(Mutex::new(send))),
            Options::default(),
        ));
        let asking = Arc::clone(&bridge);
        let asked = thread::spawn(move || {
            let prompt = Prompt::parse("alice@10.0.0.5's password: ", "");
            let ask = Ask {
                prompt: &prompt,
                foreign: false,
                unverified: false,
                given: 0,
            };
            matches!(asking.respond(&ask), Reply::Secret(_))
        });
        let id = ids.recv().unwrap();
        assert!(bridge.answer(
            id,
            PromptAnswer::Secret {
                value: "typed".into(),
                save: true,
            }
        ));
        assert!(asked.join().unwrap());
        bridge
    }

    /// What [`Tunnels::watch`] makes of `printed` on stderr and `logged` in
    /// `ssh`'s log: whether it signed in, what was saved, the output kept.
    fn watched(printed: &str, logged: &str) -> (bool, Vec<String>, String) {
        let saved = Saved::default();
        let bridge = answered(&saved);
        let (lines, received) = mpsc::channel();
        for line in printed.lines() {
            lines.send(line.to_owned()).unwrap();
        }
        drop(lines);
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("ssh.log");
        std::fs::write(&log, logged).unwrap();
        let mut tail = LogTail::open(&log).unwrap();
        let tunnels = Tunnels::new(dir.path());
        let watched = tunnels.watch(&Run::new(local("h")), &bridge, &received, &mut tail);
        let saved = lock(&saved.0).clone();
        (watched.signed_in, saved, watched.output)
    }

    #[test]
    fn only_ssh_s_own_log_tells_that_it_signed_in() {
        let line = "Authenticated to h ([10.0.0.5]:22) using \"password\".";
        // A server's banner, or what a jump host or proxy command prints.
        let (signed_in, saved, output) = watched(&format!("Welcome\n{line}\n"), "");
        assert!(!signed_in);
        assert!(saved.is_empty(), "saved before signing in");
        assert!(output.contains("Welcome"));

        let (signed_in, saved, output) = watched("", &format!("{line}\r\n"));
        assert!(signed_in);
        assert_eq!(saved, ["typed"]);
        assert!(output.contains(line), "{output}");
    }

    #[test]
    fn the_log_is_read_as_it_grows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ssh.log");
        let mut file = File::create(&path).unwrap();
        let mut tail = LogTail::open(&path).unwrap();
        assert_eq!(tail.lines(false), Vec::<String>::new());
        file.write_all(b"bind [127.0.0.1]:8080: Address already in use\r\nCould not")
            .unwrap();
        assert_eq!(
            tail.lines(false),
            ["bind [127.0.0.1]:8080: Address already in use"]
        );
        file.write_all(b" request local forwarding.\r\nlast")
            .unwrap();
        assert_eq!(tail.lines(false), ["Could not request local forwarding."]);
        assert_eq!(tail.lines(true), ["last"]);
        assert_eq!(tail.lines(true), Vec::<String>::new());
    }

    #[test]
    fn opening_this_computer_to_others_takes_a_yes() {
        let dir = tempfile::tempdir().unwrap();
        let tunnels = Arc::new(Tunnels::new(dir.path()));
        let asked = Mutex::new(Vec::new());
        let ask = |answer: bool| {
            let asked = &asked;
            move |tunnel: &Tunnel| {
                lock(asked).push(tunnel.forward_spec());
                if answer {
                    Ok(())
                } else {
                    Err(AppError::new(ErrorCode::Cancelled, "not approved"))
                }
            }
        };

        // On loopback: nothing to ask.
        let plain = tunnels.save(local("web"), ask(false)).unwrap().tunnel;
        assert!(lock(&asked).is_empty());

        // On every address: a no saves nothing.
        let open = Tunnel {
            bind_address: Some(" * ".into()),
            ..plain.clone()
        };
        let error = tunnels.save(open.clone(), ask(false)).unwrap_err();
        assert_eq!(error.code(), ErrorCode::Cancelled);
        assert_eq!(*lock(&asked), ["*:8080:localhost:80"]);
        assert_eq!(tunnels.list().unwrap()[0].tunnel, plain);

        // A yes saves it; renaming it later asks nothing, changing where it
        // leads asks again.
        let open = tunnels.save(open, ask(true)).unwrap().tunnel;
        assert_eq!(open.bind_address.as_deref(), Some("*"));
        lock(&asked).clear();
        let renamed = Tunnel {
            name: "Shared".into(),
            auto_reconnect: true,
            ..open
        };
        tunnels.save(renamed.clone(), ask(false)).unwrap();
        assert!(lock(&asked).is_empty());
        let moved = Tunnel {
            target_port: Some(8000),
            ..renamed
        };
        assert!(tunnels.save(moved, ask(false)).is_err());
        assert_eq!(lock(&asked).len(), 1);

        // Every remote tunnel asks, and an invalid one is refused first.
        lock(&asked).clear();
        let remote = Tunnel {
            kind: TunnelKind::Remote,
            listen_port: 2222,
            target_host: Some("127.0.0.1".into()),
            target_port: Some(22),
            ..local("web")
        };
        assert!(tunnels.save(remote.clone(), ask(false)).is_err());
        let invalid = Tunnel {
            alias: "x@-e".into(),
            ..remote
        };
        let error = tunnels.save(invalid, ask(true)).unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert_eq!(*lock(&asked), ["2222:127.0.0.1:22"]);
    }
}
