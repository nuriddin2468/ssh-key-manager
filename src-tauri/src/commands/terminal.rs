//! The in-app terminal's commands (see [`crate::terminal`]). Input, resizing,
//! answers and closing are synchronous commands: they only hand data to the
//! session's threads, and run in the order the UI sends them.
//!
//! The page drives the terminal, so a script in the page could run commands
//! through it (SECURITY.md, "Locked-down webview"). What it can't do is take
//! an environment's secret values out of the vault in one go by starting a
//! shell with them: that is asked first in a native dialog
//! ([`crate::secret_gate`]).

#![allow(
    clippy::needless_pass_by_value,
    reason = "Tauri passes command arguments by value"
)]

use std::sync::Arc;

use tauri::ipc::{Channel, InvokeResponseBody};
use tauri::{AppHandle, State};

use super::{Shared, blocking};
use crate::error::AppResult;
use crate::terminal::shells::{self, ShellInfo};
use crate::terminal::types::{OpenOptions, PromptAnswer, TerminalInfo};
use crate::terminal::{self, Sink};

/// Starts `ssh` to `alias` in a `cols`×`rows` terminal. Output and events
/// arrive on `events` (see [`crate::terminal::types`]) until the session
/// ends.
#[tauri::command]
pub async fn terminal_open(
    app: AppHandle,
    state: State<'_, Shared>,
    alias: String,
    cols: u16,
    rows: u16,
    options: Option<OpenOptions>,
    events: Channel<InvokeResponseBody>,
) -> AppResult<TerminalInfo> {
    let shared = Arc::clone(&state);
    blocking(&state, move |_| {
        let sink: Arc<dyn Sink> = Arc::new(events);
        shared.terminals.open(
            &shared,
            &app,
            &alias,
            (cols, rows),
            &options.unwrap_or_default(),
            sink,
        )
    })
    .await
}

/// The shells a local session can run, the default first.
#[tauri::command]
pub async fn terminal_shells(state: State<'_, Shared>) -> AppResult<Vec<ShellInfo>> {
    blocking(&state, move |_| {
        Ok(shells::list().into_iter().map(|shell| shell.info).collect())
    })
    .await
}

/// Starts a shell on this computer in a `cols`×`rows` terminal: `shell` (an
/// id from [`terminal_shells`]) or the default one. Output and events arrive
/// on `events`, as for [`terminal_open`].
#[tauri::command]
pub async fn terminal_open_local(
    state: State<'_, Shared>,
    shell: Option<String>,
    cols: u16,
    rows: u16,
    events: Channel<InvokeResponseBody>,
) -> AppResult<TerminalInfo> {
    let shared = Arc::clone(&state);
    blocking(&state, move |state| {
        let shell = shells::find(shell.as_deref())?;
        let sink: Arc<dyn Sink> = Arc::new(events);
        shared.terminals.open_local(
            &shell.info.name,
            &shell,
            &[],
            &state.paths.home,
            (cols, rows),
            sink,
        )
    })
    .await
}

/// Sends keystrokes (or pasted text) to the session.
#[tauri::command]
pub fn terminal_write(state: State<'_, Shared>, id: u32, data: String) -> AppResult<()> {
    state.terminals.write(id, data.into_bytes())
}

#[tauri::command]
pub fn terminal_resize(state: State<'_, Shared>, id: u32, cols: u16, rows: u16) -> AppResult<()> {
    state.terminals.resize(id, cols, rows)
}

/// Answers the session's waiting prompt `prompt`. Returns false if it no
/// longer waits (it timed out, or the session ended).
#[tauri::command]
pub fn terminal_answer(
    state: State<'_, Shared>,
    id: u32,
    prompt: u32,
    answer: PromptAnswer,
) -> AppResult<bool> {
    state.terminals.answer(id, prompt, answer)
}

/// Ends the session; the remote shell gets a hang-up.
#[tauri::command]
pub fn terminal_close(state: State<'_, Shared>, id: u32) {
    state.terminals.close(id);
}

/// The sessions still running.
#[tauri::command]
pub fn terminal_list(state: State<'_, Shared>) -> Vec<TerminalInfo> {
    state.terminals.list()
}

/// Opens the system terminal with `ssh <alias>`.
#[tauri::command]
pub async fn terminal_open_external(state: State<'_, Shared>, alias: String) -> AppResult<()> {
    blocking(&state, move |_| terminal::open_external(&alias)).await
}
