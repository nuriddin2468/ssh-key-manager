//! The in-app updater. The page only asks whether a newer release exists and
//! says when to install it; the release server, the public key, headers and
//! proxy all come from `tauri.conf.json`, so script in the page can't point
//! the updater anywhere else.

use std::sync::{Mutex, PoisonError};

use sshkm_core::ErrorCode;
use tauri::AppHandle;
use tauri::ipc::Channel;
use tauri_plugin_updater::{Update, UpdaterExt};

use crate::error::{AppError, AppResult};

/// The release the last check found, until a later check replaces it.
static PENDING: Mutex<Option<Update>> = Mutex::new(None);

/// Asks the release server for a version newer than this one and returns it,
/// or `None` if this is the latest.
#[tauri::command]
pub async fn update_check(app: AppHandle) -> AppResult<Option<String>> {
    let update = app
        .updater()
        .map_err(|e| updater_error(&e))?
        .check()
        .await
        .map_err(|e| updater_error(&e))?;
    let version = update.as_ref().map(|update| update.version.clone());
    *PENDING.lock().unwrap_or_else(PoisonError::into_inner) = update;
    Ok(version)
}

/// Downloads, verifies and installs the release the last check found, then
/// restarts into it. `progress` gets the percentage downloaded whenever it
/// changes, if the server tells the size.
#[tauri::command]
pub async fn update_install(app: AppHandle, progress: Channel<u8>) -> AppResult<()> {
    let update = PENDING
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
        .ok_or_else(|| AppError::not_found("no update to install"))?;
    let mut received: u64 = 0;
    let mut reported = None;
    update
        .download_and_install(
            |chunk, total| {
                received = received.saturating_add(chunk as u64);
                let Some(total) = total.filter(|&total| total > 0) else {
                    return;
                };
                let percent = u8::try_from(received.saturating_mul(100) / total).unwrap_or(100);
                let percent = percent.min(100);
                if reported != Some(percent) {
                    reported = Some(percent);
                    let _ = progress.send(percent);
                }
            },
            || {},
        )
        .await
        .map_err(|e| updater_error(&e))?;
    // Windows has already quit into the installer; macOS and Linux restart here.
    app.request_restart();
    Ok(())
}

fn updater_error(error: &tauri_plugin_updater::Error) -> AppError {
    AppError::new(ErrorCode::Io, error.to_string())
}
