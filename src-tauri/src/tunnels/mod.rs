//! The Tunnels tool's port forwards while they run: one `ssh -N` child per
//! tunnel that is on (see [`sshkm_core::tunnels`] for its arguments).
//!
//! - `ssh` asks for passwords, passphrases and host keys through an
//!   interactive askpass session whose prompt bridge is the terminal's
//!   ([`crate::terminal::Bridge`]): saved secrets come from the vault, the
//!   rest becomes a prompt on the tunnel for the Tools page to show, and a
//!   new host key is trusted only after the user's yes.
//! - A tunnel is *connecting* until `ssh` prints `Authenticated to …`
//!   (`LogLevel=VERBOSE`), then *up* once the forward had a moment to be
//!   set up: `ExitOnForwardFailure` ends `ssh` if it can't be.
//! - When `ssh` ends by itself the tunnel failed, with a reason. With
//!   auto-reconnect on, one that may work later (the network, a busy port,
//!   a server that went away) starts again after 2 seconds, then 5, 10, 20,
//!   30 and 60 at most; a minute up starts the count over.
//! - Tunnels run on while the window is closed to the tray, a page reloads
//!   or the vault locks. They stop when the app quits ([`Tunnels::stop_all`]).
//! - Every change goes to the UI as [`CHANGED_EVENT`], and to the tray menu,
//!   which counts the tunnels that are on.
//!
//! `ssh`'s output is kept (the last 16 KiB) to tell why a tunnel failed; it
//! holds no secret, since answers go through askpass. Nothing is logged.

pub mod failure;

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
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
use crate::process;
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
    pub fn save(self: &Arc<Self>, tunnel: Tunnel) -> AppResult<TunnelView> {
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

        let mut command = process::command("ssh");
        askpass.configure(&mut command);
        command
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
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

        let watched = self.watch(run, &bridge, &received);
        lock(&run.child).take();
        lock(&run.bridge).take();
        bridge.close();
        lock(&run.prompt).take();
        drop(askpass);
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
                // `Authenticated to …` tells for sure when signing in is done.
                can_save: true,
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
        Ok((bridge, askpass))
    }

    /// Follows a running `ssh` until it exits (or is stopped): its output,
    /// signing in, and the forward coming up.
    fn watch(&self, run: &Run, bridge: &Bridge, received: &mpsc::Receiver<String>) -> Watched {
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
                Ok(line) => {
                    if signed_in.is_none() && line.starts_with("Authenticated to ") {
                        signed_in = Some(Instant::now());
                        bridge.signed_in();
                        bridge.save_answers();
                    }
                    keep(&mut output, &line);
                }
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {}
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
        // What it printed on the way out.
        let deadline = Instant::now() + Duration::from_millis(300);
        while let Ok(line) =
            received.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
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
