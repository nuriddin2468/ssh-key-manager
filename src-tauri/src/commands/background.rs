//! Running on with the window closed, as the Settings page turns it on and
//! off ([`crate::tray`]).

#![allow(
    clippy::needless_pass_by_value,
    reason = "Tauri passes command arguments by value"
)]

use tauri::{AppHandle, State};

use crate::error::AppResult;
use crate::tray::{BackgroundStatus, SharedBackground};

#[tauri::command]
pub fn background_status(background: State<'_, SharedBackground>) -> BackgroundStatus {
    background.status()
}

#[tauri::command]
pub fn background_set_enabled(
    app: AppHandle,
    background: State<'_, SharedBackground>,
    enabled: bool,
) -> AppResult<BackgroundStatus> {
    background.set_enabled(&app, enabled)
}
