//! Quick search ([`crate::quick`]): its shortcut, as the Settings page sets
//! it, and what the quick search window lists and does.

#![allow(
    clippy::needless_pass_by_value,
    reason = "Tauri passes command arguments by value"
)]

use sshkm_core::ErrorCode;
use sshkm_core::config::SshConfig;
use tauri::{AppHandle, State};

use super::{Shared, blocking};
use crate::error::AppResult;
use crate::quick::items::{self, QuickItems};
use crate::quick::{self as window, QuickStatus, SharedQuick};

#[tauri::command]
pub fn quick_status(quick: State<'_, SharedQuick>) -> QuickStatus {
    quick.status()
}

/// `shortcut`: an accelerator such as `Shift+Super+Space`; `None` for the
/// default.
#[tauri::command]
pub fn quick_set_shortcut(
    app: AppHandle,
    quick: State<'_, SharedQuick>,
    enabled: bool,
    shortcut: Option<String>,
) -> AppResult<QuickStatus> {
    quick.set(&app, enabled, shortcut.as_deref())
}

/// The hosts, and the vault's entries without secrets while it is unlocked.
/// Reading the entries doesn't count as activity, like `vault_entries`.
#[tauri::command]
pub async fn quick_items(app: AppHandle, state: State<'_, Shared>) -> AppResult<QuickItems> {
    blocking(&state, move |state| {
        // A config that can't be read lists no hosts; the main window says why.
        let hosts = SshConfig::load(&state.paths.config)
            .map(|config| items::hosts(&config.view()))
            .unwrap_or_default();
        let entries = match state.vault.with_quietly(&app, |vault| Ok(vault.entries())) {
            Ok(entries) => Some(items::entries(entries)),
            Err(error) if error.code() == ErrorCode::VaultLocked => None,
            Err(error) => return Err(error),
        };
        Ok(QuickItems { hosts, entries })
    })
    .await
}

/// Closes the window and opens a session to `alias` in the main window.
#[tauri::command]
pub fn quick_connect(app: AppHandle, alias: String) -> AppResult<()> {
    window::connect(&app, &alias)
}

/// Closes the window; with `back`, the app the user was in gets the focus.
#[tauri::command]
pub fn quick_close(app: AppHandle, back: bool) {
    window::close(&app, back);
}
