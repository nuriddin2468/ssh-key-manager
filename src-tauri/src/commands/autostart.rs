//! "Open at login", as the Settings page turns it on and off
//! ([`crate::autostart`]).

#![allow(
    clippy::needless_pass_by_value,
    reason = "Tauri passes command arguments by value"
)]

use tauri::{AppHandle, State};

use crate::autostart::{AutostartStatus, LoginEntry, keeps_running_too};
use crate::error::AppResult;
use crate::tray::SharedBackground;

#[tauri::command]
pub fn autostart_status(app: AppHandle) -> AppResult<AutostartStatus> {
    LoginEntry::of(&app)?.status()
}

/// Turns "Open at login" on or off. Turning it on also keeps the app running
/// in the background, so that it starts in the tray.
#[tauri::command]
pub fn autostart_set_enabled(
    app: AppHandle,
    background: State<'_, SharedBackground>,
    enabled: bool,
) -> AppResult<AutostartStatus> {
    let status = LoginEntry::of(&app)?.set_enabled(enabled)?;
    if keeps_running_too(enabled, &background.status()) {
        background.set_enabled(&app, true)?;
    }
    Ok(status)
}
