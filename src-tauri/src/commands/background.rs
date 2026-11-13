//! Running on with the window closed, as the Settings page turns it on and
//! off ([`crate::tray`]).

#![allow(
    clippy::needless_pass_by_value,
    reason = "Tauri passes command arguments by value"
)]

use std::sync::Arc;

use tauri::{AppHandle, Manager, State};

use crate::env_files::EnvFiles;
use crate::error::AppResult;
use crate::tray::{BackgroundStatus, SharedBackground};

#[tauri::command]
pub fn background_status(
    app: AppHandle,
    background: State<'_, SharedBackground>,
) -> BackgroundStatus {
    with_files(&app, background.status())
}

#[tauri::command]
pub fn background_set_enabled(
    app: AppHandle,
    background: State<'_, SharedBackground>,
    enabled: bool,
) -> AppResult<BackgroundStatus> {
    Ok(with_files(&app, background.set_enabled(&app, enabled)?))
}

/// Keeps the app running with the window closed, where the system can, for
/// the virtual `.env` files it serves: they are served only while it runs.
pub(crate) fn keep_running_for_virtual_files(app: &AppHandle) {
    if let Some(background) = app.try_state::<SharedBackground>() {
        let status = background.status();
        if status.available
            && !status.enabled
            && let Err(error) = background.set_enabled(app, true)
        {
            log::warn!("tray: not turned on for virtual files: {error}");
        }
    }
}

/// The status with how many virtual files are served now.
fn with_files(app: &AppHandle, mut status: BackgroundStatus) -> BackgroundStatus {
    status.virtual_files = app
        .try_state::<Arc<EnvFiles>>()
        .map_or(0, |files| u32::try_from(files.served()).unwrap_or(u32::MAX));
    status
}
