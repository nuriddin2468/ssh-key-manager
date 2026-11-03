//! Browser autofill: turning it on, answering pairings and revoking paired
//! browsers. The extension's own requests never come through here; the
//! bridge answers them ([`crate::browser`]).

use std::sync::Arc;

use serde::Serialize;
use sshkm_core::vault::PairedBrowser;
use tauri::{AppHandle, Emitter, State};

use super::{Shared, blocking};
use crate::browser::broker::PairingRequest;
use crate::browser::manifests::{self, BrowserInstall};
use crate::browser::{Bridge, CHANGED_EVENT, HostProgram, host_program};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// Browser autofill as the settings page shows it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct BrowserStatus {
    pub enabled: bool,
    /// The bridge listens for the extension.
    pub listening: bool,
    /// Why it doesn't, if it should.
    pub problem: Option<String>,
    /// The installed browsers and whether each can start the bridge.
    pub browsers: Vec<BrowserInstall>,
    /// This copy of the app runs from this temporary folder, so no browser
    /// is set up to start it.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(test, ts(optional))]
    pub temporary_location: Option<String>,
    /// Browsers paired with the vault; `None` while it is locked or missing.
    pub paired: Option<Vec<PairedBrowser>>,
    /// A pairing waiting for the user.
    pub pairing: Option<PairingRequest>,
}

type SharedBridge = Arc<Bridge>;

fn status(app: &AppHandle, state: &AppState, bridge: &Bridge) -> BrowserStatus {
    // Registered means: for the program `Bridge::start` registers.
    let (browsers, temporary_location) = match host_program() {
        Ok(HostProgram::At(program)) => (manifests::status(Some(&program)), None),
        Ok(HostProgram::Temporary(program)) => (
            manifests::status(None),
            Some(program.to_string_lossy().into_owned()),
        ),
        Err(_) => (manifests::status(None), None),
    };
    let paired = state
        .vault
        .with_quietly(app, |vault| Ok(vault.paired_browsers()))
        .ok();
    BrowserStatus {
        enabled: bridge.enabled(),
        listening: bridge.listening(),
        problem: bridge.problem(),
        browsers,
        temporary_location,
        paired,
        pairing: bridge.broker().pending(),
    }
}

#[tauri::command]
pub async fn browser_status(
    app: AppHandle,
    state: State<'_, Shared>,
    bridge: State<'_, SharedBridge>,
) -> AppResult<BrowserStatus> {
    let bridge = Arc::clone(&bridge);
    blocking(&state, move |state| Ok(status(&app, state, &bridge))).await
}

/// Turns browser autofill on (registers with the browsers and listens) or
/// off (unregisters and stops listening).
#[tauri::command]
pub async fn browser_set_enabled(
    app: AppHandle,
    state: State<'_, Shared>,
    bridge: State<'_, SharedBridge>,
    enabled: bool,
) -> AppResult<BrowserStatus> {
    let bridge = Arc::clone(&bridge);
    blocking(&state, move |state| {
        bridge.set_enabled(&app, enabled)?;
        Ok(status(&app, state, &bridge))
    })
    .await
}

/// The user's answer to a pairing. Fails if it no longer waits.
#[tauri::command]
pub async fn browser_answer_pairing(
    bridge: State<'_, SharedBridge>,
    id: String,
    approve: bool,
) -> AppResult<()> {
    if bridge.broker().decide(&id, approve) {
        Ok(())
    } else {
        Err(AppError::not_found("the pairing request has ended"))
    }
}

/// Forgets a paired browser; its requests are refused from now on.
#[tauri::command]
pub async fn browser_revoke(app: AppHandle, state: State<'_, Shared>, id: String) -> AppResult<()> {
    blocking(&state, move |state| {
        let removed = state.vault.change(&app, &state.backup_dir, |vault| {
            Ok(vault.remove_browser(&id))
        })?;
        let _ = app.emit(CHANGED_EVENT, ());
        if removed {
            Ok(())
        } else {
            Err(AppError::not_found("that browser is not paired"))
        }
    })
    .await
}
