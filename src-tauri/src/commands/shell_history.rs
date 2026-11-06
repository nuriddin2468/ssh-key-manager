//! Hosts to add, found in the user's shell history after they said yes
//! ([`sshkm_core::shell_history`]). The history is read here, on demand,
//! and stays in Rust; the UI gets only the suggestions. The answer and the
//! dismissed suggestions are kept in `shell-history.json` in the app's data
//! folder.

#![allow(
    clippy::needless_pass_by_value,
    reason = "Tauri passes command arguments by value"
)]

use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use sshkm_core::config::SshConfig;
use sshkm_core::shell_history::{self, HistoryPrefs, HistoryScan, HistoryStatus};
use tauri::{AppHandle, Manager, State};

use super::{Shared, blocking};
use crate::error::{AppError, AppResult};

const FILE: &str = "shell-history.json";

/// One change of the file at a time.
static PREFS: Mutex<()> = Mutex::new(());

#[tauri::command]
pub async fn shell_history_status(
    app: AppHandle,
    state: State<'_, Shared>,
) -> AppResult<HistoryStatus> {
    let path = prefs_path(&app)?;
    blocking(&state, move |_| Ok(HistoryPrefs::load(&path).status())).await
}

/// The user's answer to "Find hosts in your shell history?", or the
/// switch in Settings.
#[tauri::command]
pub async fn shell_history_set_enabled(
    app: AppHandle,
    state: State<'_, Shared>,
    enabled: bool,
) -> AppResult<HistoryStatus> {
    let path = prefs_path(&app)?;
    blocking(&state, move |_| {
        change(&path, |prefs| {
            prefs.set_enabled(enabled);
            Ok(())
        })
    })
    .await
}

/// Reads the shell history and suggests the hosts it connects to that the
/// config has no block for. Fails with `invalid_input` unless the user
/// turned this on.
#[tauri::command]
pub async fn shell_history_scan(
    app: AppHandle,
    state: State<'_, Shared>,
) -> AppResult<HistoryScan> {
    let path = prefs_path(&app)?;
    blocking(&state, move |state| {
        let prefs = {
            let _guard = PREFS.lock().unwrap_or_else(PoisonError::into_inner);
            let mut prefs = HistoryPrefs::load(&path);
            if !prefs.enabled() {
                return Err(AppError::invalid("shell history suggestions are off"));
            }
            if prefs.ensure_key() {
                prefs.save(&path)?;
            }
            prefs
        };
        let config = SshConfig::load(&state.paths.config)?;
        let files = shell_history::default_history_files(&state.paths.home);
        Ok(shell_history::scan(&files, &config.hosts(), &prefs))
    })
    .await
}

/// Stops suggesting a target, by its suggestion's `id`.
#[tauri::command]
pub async fn shell_history_dismiss(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
) -> AppResult<HistoryStatus> {
    let path = prefs_path(&app)?;
    blocking(&state, move |_| {
        change(&path, |prefs| Ok(prefs.dismiss(&id)?))
    })
    .await
}

/// Suggests the dismissed targets again.
#[tauri::command]
pub async fn shell_history_forget_dismissed(
    app: AppHandle,
    state: State<'_, Shared>,
) -> AppResult<HistoryStatus> {
    let path = prefs_path(&app)?;
    blocking(&state, move |_| {
        change(&path, |prefs| {
            prefs.forget_dismissed();
            Ok(())
        })
    })
    .await
}

fn prefs_path(app: &AppHandle) -> AppResult<PathBuf> {
    Ok(app.path().app_data_dir()?.join(FILE))
}

fn change(
    path: &Path,
    edit: impl FnOnce(&mut HistoryPrefs) -> AppResult<()>,
) -> AppResult<HistoryStatus> {
    let _guard = PREFS.lock().unwrap_or_else(PoisonError::into_inner);
    let mut prefs = HistoryPrefs::load(path);
    edit(&mut prefs)?;
    prefs.save(path)?;
    Ok(prefs.status())
}
