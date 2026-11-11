//! Tauri commands. Each one runs its file system, agent or process work on the
//! blocking pool so the UI thread never waits on disk or sockets.

pub mod agent;
pub mod audit;
pub mod audit_checks;
pub mod autostart;
pub mod background;
pub mod browser;
pub mod browser_import;
pub mod config;
pub mod diagnose;
pub mod environment;
pub mod envs;
pub mod hosts_file;
pub mod key_rotation;
pub mod keys;
pub mod known_hosts;
pub mod nearby;
pub mod projects;
pub mod quick;
pub mod remote;
pub mod shell_history;
pub mod ssh_tools;
pub mod terminal;
pub mod tools_net;
pub mod updates;
pub mod vault;
pub mod vault_files;
pub mod vault_hosts;
pub mod vault_links;

use std::sync::Arc;

use sshkm_core::ErrorCode;

use crate::error::{AppError, AppResult};
use crate::state::AppState;

pub type Shared = Arc<AppState>;

pub async fn blocking<T, F>(state: &Shared, work: F) -> AppResult<T>
where
    T: Send + 'static,
    F: FnOnce(&AppState) -> AppResult<T> + Send + 'static,
{
    let state = Arc::clone(state);
    tauri::async_runtime::spawn_blocking(move || work(&state))
        .await
        .map_err(|e| AppError::new(ErrorCode::Io, format!("background task failed: {e}")))?
}
