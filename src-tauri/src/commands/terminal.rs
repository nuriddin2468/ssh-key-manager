//! The in-app terminal's commands (see [`crate::terminal`]). Input, resizing,
//! answers and closing are synchronous commands: they only hand data to the
//! session's threads, and run in the order the UI sends them.
//!
//! The page drives the terminal, so a script in the page could run commands
//! through it (SECURITY.md, "Locked-down webview"). What it can't do is take
//! an environment's secret values out of the vault in one go by starting a
//! shell with them: that is asked first in a native dialog
//! ([`confirm_env_secrets`]).

#![allow(
    clippy::needless_pass_by_value,
    reason = "Tauri passes command arguments by value"
)]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, MutexGuard, Once, PoisonError};

use sshkm_core::vault::envs;
use tauri::ipc::{Channel, InvokeResponseBody};
use tauri::{AppHandle, Listener, State};

use super::{Shared, blocking};
use crate::confirm::{self, Localized};
use crate::error::AppResult;
use crate::state::AppState;
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

/// The environments whose secret values the user let into a shell, until
/// the vault locks or unlocks again.
static LET_IN: Mutex<LetIn> = Mutex::new(LetIn::new());
/// Set up the first time an environment is asked for.
static WATCH_LOCK: Once = Once::new();

/// Asks in a native dialog, naming the environment `env` and how many secret
/// values it has, before they go into a shell's environment
/// ([`super::envs::envs_run`], [`super::projects::projects_open_terminal`]).
/// Fails with `cancelled` on a no; an environment without secret values
/// starts without asking.
///
/// Asked once per environment while the vault stays unlocked, not for every
/// shell: once a shell holds the values, page script could type into that
/// shell anyway, so asking again would add clicks, not protection. The next
/// lock or unlock forgets every answer.
pub(crate) fn confirm_env_secrets(app: &AppHandle, state: &AppState, env: &str) -> AppResult<()> {
    let (label, secrets) = state.vault.with(app, |vault| {
        let summary = vault.environment(env)?.summary;
        Ok((
            envs::label(Some(&vault.env_label(&summary)), &summary.name),
            summary.secret_count,
        ))
    })?;
    if secrets == 0 {
        return Ok(());
    }
    WATCH_LOCK.call_once(|| {
        for event in [crate::vault::LOCKED_EVENT, crate::vault::UNLOCKED_EVENT] {
            app.listen_any(event, |_| let_in().forget());
        }
    });
    let Some(asked) = let_in().ask(env) else {
        return Ok(());
    };
    confirm::require(
        app,
        &Localized::new(
            "Open a terminal with secret values?",
            "Открыть терминал с секретными значениями?",
            "Terminal maxfiy qiymatlar bilan ochilsinmi?",
        ),
        &env_secrets_body(&label, secrets),
        &Localized::new("Open terminal", "Открыть терминал", "Terminalni ochish"),
    )?;
    let_in().record(env, asked);
    Ok(())
}

/// The dialog's text: the environment, as its label names it, and how many
/// of its values are secret.
fn env_secrets_body(label: &str, secrets: u32) -> Localized {
    let env = confirm::shown(label, 120);
    let count = if secrets == 1 {
        "1 secret value".to_owned()
    } else {
        format!("{secrets} secret values")
    };
    Localized::new(
        format!(
            "The shell gets the variables of “{env}”, including {count}. Any program you run \
             in it can read them.\n\nYou won’t be asked again for this environment until the \
             vault locks. Continue only if you opened this terminal yourself."
        ),
        format!(
            "Оболочка получит переменные окружения «{env}»; секретных среди них: {secrets}. \
             Любая программа, запущенная в ней, сможет их прочитать.\n\nДля этого окружения \
             вопрос не повторится, пока хранилище не заблокируется. Продолжайте, только если \
             этот терминал открыли вы."
        ),
        format!(
            "Shell «{env}» muhitining oʻzgaruvchilarini oladi, ulardan {secrets} tasi maxfiy. \
             Unda ishga tushirilgan har qanday dastur ularni oʻqiy oladi.\n\nOmbor \
             qulflanmaguncha bu muhit uchun qayta soʻralmaydi. Bu terminalni oʻzingiz ochgan \
             boʻlsangizgina davom eting."
        ),
    )
}

/// Which environments were let in, and how many times the answers were
/// forgotten, so a yes that comes after the vault locked isn't kept.
struct LetIn {
    forgotten: u64,
    envs: BTreeSet<String>,
}

impl LetIn {
    const fn new() -> Self {
        Self {
            forgotten: 0,
            envs: BTreeSet::new(),
        }
    }

    /// `None` if `env` was let in already; otherwise the count to give
    /// [`Self::record`] with the user's yes.
    fn ask(&self, env: &str) -> Option<u64> {
        (!self.envs.contains(env)).then_some(self.forgotten)
    }

    /// Keeps a yes to a question asked at `asked`, unless the answers were
    /// forgotten since.
    fn record(&mut self, env: &str, asked: u64) {
        if asked == self.forgotten {
            self.envs.insert(env.to_owned());
        }
    }

    fn forget(&mut self) {
        self.forgotten += 1;
        self.envs.clear();
    }
}

fn let_in() -> MutexGuard<'static, LetIn> {
    LET_IN.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_environment_is_asked_for_once_until_the_vault_locks() {
        let mut let_in = LetIn::new();
        let asked = let_in.ask("env-1").expect("asked the first time");
        let_in.record("env-1", asked);
        assert_eq!(let_in.ask("env-1"), None);
        assert!(let_in.ask("env-2").is_some());

        // The vault locks: every environment is asked for again.
        let_in.forget();
        assert!(let_in.ask("env-1").is_some());
    }

    #[test]
    fn a_yes_given_after_the_vault_locked_is_not_kept() {
        let mut let_in = LetIn::new();
        let asked = let_in.ask("env-1").unwrap();
        // The vault locks while the dialog is open.
        let_in.forget();
        let_in.record("env-1", asked);
        assert!(let_in.ask("env-1").is_some());
    }

    #[test]
    fn the_dialog_names_the_environment_and_its_secret_values() {
        let body = env_secrets_body("Shop · backend · prod", 3);
        assert!(
            body.en
                .contains("“Shop · backend · prod”, including 3 secret values")
        );
        assert!(
            body.ru
                .contains("«Shop · backend · prod»; секретных среди них: 3")
        );
        assert!(body.uz.contains("ulardan 3 tasi maxfiy"));
        assert!(
            env_secrets_body("dev", 1)
                .en
                .contains("including 1 secret value.")
        );
        // A name received from a contact can't add lines or turn text around.
        let body = env_secrets_body("prod\n\nYou were asked already\u{202E}", 2);
        assert!(
            body.en
                .contains("“prod<U+000A><U+000A>You were asked already<U+202E>”")
        );
    }
}
