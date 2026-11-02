use std::fs;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use sshkm_core::ErrorCode;
use sshkm_core::fsutil;
use sshkm_core::hosts_file::{self, HostsChange, HostsFile, InstallOutcome};
use tauri::State;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::{Shared, blocking};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::types::{
    HostsApplyOutcome, HostsApplyResult, HostsBackup, HostsFileInfo, HostsPreview, NameLookup,
};

/// How long a lookup may take before the UI is told there was no answer.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(8);

#[tauri::command]
pub async fn read_hosts_file(state: State<'_, Shared>) -> AppResult<HostsFileInfo> {
    blocking(&state, hosts_file_info).await
}

/// The diff `changes` would make, for the user to review before applying.
#[tauri::command]
pub async fn preview_hosts_changes(
    state: State<'_, Shared>,
    revision: String,
    changes: Vec<HostsChange>,
) -> AppResult<HostsPreview> {
    blocking(&state, move |state| {
        let file = HostsFile::load(&state.hosts_file)?;
        if file.revision() != revision {
            return Ok(HostsPreview {
                stale: true,
                diff: Vec::new(),
            });
        }
        Ok(HostsPreview {
            stale: false,
            diff: file.edited(&changes)?.diff,
        })
    })
    .await
}

/// Applies `changes` with administrator rights. `prompt` is the reason the
/// password dialog gives (macOS).
#[tauri::command]
pub async fn apply_hosts_changes(
    state: State<'_, Shared>,
    revision: String,
    changes: Vec<HostsChange>,
    flush_dns: bool,
    prompt: String,
) -> AppResult<HostsApplyResult> {
    blocking(&state, move |state| {
        let file = writable_hosts_file(state)?;
        if file.revision() != revision {
            return apply_result(state, HostsApplyOutcome::Stale);
        }
        let edited = file.edited(&changes)?;
        install(state, &edited.file.to_string(), flush_dns, &prompt)
    })
    .await
}

/// Backups of the hosts file, newest first.
#[tauri::command]
pub async fn list_hosts_backups(state: State<'_, Shared>) -> AppResult<Vec<HostsBackup>> {
    blocking(&state, |state| {
        Ok(hosts_backups(state)
            .into_iter()
            .rev()
            .map(|path| {
                let saved = fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|time| OffsetDateTime::from(time).format(&Rfc3339).ok());
                let entries = HostsFile::load(&path).map_or(0, |file| file.entries().len());
                HostsBackup {
                    path: path.to_string_lossy().into_owned(),
                    saved,
                    entries: u32::try_from(entries).unwrap_or(u32::MAX),
                }
            })
            .collect())
    })
    .await
}

/// Puts a backup back in place with administrator rights.
#[tauri::command]
pub async fn restore_hosts_backup(
    state: State<'_, Shared>,
    path: String,
    flush_dns: bool,
    prompt: String,
) -> AppResult<HostsApplyResult> {
    blocking(&state, move |state| {
        let path = PathBuf::from(path);
        if !hosts_backups(state).contains(&path) {
            return Err(AppError::invalid("not a backup of the hosts file"));
        }
        writable_hosts_file(state)?;
        let text = String::from_utf8(fs::read(&path)?)
            .map_err(|_| AppError::invalid("the backup is not UTF-8"))?;
        install(state, &text, flush_dns, &prompt)
    })
    .await
}

/// Asks the system resolver (the hosts file, then DNS) for a name's
/// addresses, as `ssh` would. DNS goes over the network, so the UI calls this
/// only when the user asks.
#[tauri::command]
pub async fn lookup_host(state: State<'_, Shared>, name: String) -> AppResult<NameLookup> {
    blocking(&state, move |_| {
        let name = name.trim().to_owned();
        if !hosts_file::is_valid_name(&name) {
            return Err(AppError::invalid("not a host name"));
        }
        // The resolver has no timeout of its own; a stuck lookup is left to
        // finish on its thread.
        let (send, receive) = mpsc::channel();
        thread::spawn(move || {
            let result = (name.as_str(), 0)
                .to_socket_addrs()
                .map(|addrs| addrs.map(|addr| addr.ip().to_string()).collect::<Vec<_>>());
            let _ = send.send(result);
        });
        Ok(match receive.recv_timeout(LOOKUP_TIMEOUT) {
            Ok(Ok(found)) => {
                let mut addresses: Vec<String> = Vec::new();
                for address in found {
                    if !addresses.contains(&address) {
                        addresses.push(address);
                    }
                }
                NameLookup {
                    addresses,
                    error: None,
                }
            }
            Ok(Err(error)) => NameLookup {
                addresses: Vec::new(),
                error: Some(error.to_string()),
            },
            Err(_) => NameLookup {
                addresses: Vec::new(),
                error: Some("no answer".to_owned()),
            },
        })
    })
    .await
}

fn hosts_file_info(state: &AppState) -> AppResult<HostsFileInfo> {
    let file = HostsFile::load(&state.hosts_file)?;
    Ok(HostsFileInfo {
        path: state.hosts_file.to_string_lossy().into_owned(),
        exists: state.hosts_file.exists(),
        revision: file.revision().to_owned(),
        read_only: file.read_only_reason(&state.hosts_file),
        view: file.view(),
    })
}

/// The current file, or an error when the app cannot change it.
fn writable_hosts_file(state: &AppState) -> AppResult<HostsFile> {
    let file = HostsFile::load(&state.hosts_file)?;
    match file.read_only_reason(&state.hosts_file) {
        Some(reason) => Err(AppError::new(
            ErrorCode::Unsupported,
            format!("the hosts file cannot be changed here: {reason:?}"),
        )),
        None => Ok(file),
    }
}

fn hosts_backups(state: &AppState) -> Vec<PathBuf> {
    state
        .hosts_file
        .file_name()
        .map(|name| fsutil::list_backups(&state.backup_dir, &name.to_string_lossy()))
        .unwrap_or_default()
}

/// Backs up the current file, then installs `text`. A cancelled prompt
/// leaves no backup behind.
fn install(
    state: &AppState,
    text: &str,
    flush_dns: bool,
    prompt: &str,
) -> AppResult<HostsApplyResult> {
    let backup = fsutil::backup(&state.hosts_file, &state.backup_dir)?;
    let outcome = hosts_file::install(text, &state.hosts_file, flush_dns, prompt);
    if !matches!(outcome, Ok(InstallOutcome::Installed))
        && let Some(backup) = backup
    {
        let _ = fs::remove_file(backup);
    }
    match outcome? {
        InstallOutcome::Installed => apply_result(state, HostsApplyOutcome::Applied),
        InstallOutcome::Cancelled => apply_result(state, HostsApplyOutcome::Cancelled),
    }
}

fn apply_result(state: &AppState, outcome: HostsApplyOutcome) -> AppResult<HostsApplyResult> {
    Ok(HostsApplyResult {
        outcome,
        file: hosts_file_info(state)?,
    })
}
