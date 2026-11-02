use std::fs;
use std::time::Duration;

use sshkm_core::config::{HostEdit, SshConfig};
use sshkm_core::fsutil;
use tauri::State;

use super::{Shared, blocking};
use crate::error::{AppError, AppResult};
use crate::process;
use crate::state::AppState;
use crate::types::{ConfigFile, ConnectionTest, SavedHost};

#[tauri::command]
pub async fn read_config(state: State<'_, Shared>) -> AppResult<ConfigFile> {
    blocking(&state, config_file).await
}

#[tauri::command]
pub async fn save_host(state: State<'_, Shared>, edit: HostEdit) -> AppResult<SavedHost> {
    blocking(&state, move |state| {
        let mut config = SshConfig::load(&state.paths.config)?;
        let id = config.upsert_host(&edit)?;
        config.save(&state.paths.config, &state.backup_dir)?;
        Ok(SavedHost {
            file: config_file(state)?,
            id,
        })
    })
    .await
}

#[tauri::command]
pub async fn delete_host(state: State<'_, Shared>, id: u32) -> AppResult<ConfigFile> {
    blocking(&state, move |state| {
        let mut config = SshConfig::load(&state.paths.config)?;
        config.delete_host(id)?;
        config.save(&state.paths.config, &state.backup_dir)?;
        config_file(state)
    })
    .await
}

#[tauri::command]
pub async fn remove_identity_file(
    state: State<'_, Shared>,
    host_id: Option<u32>,
    value: String,
) -> AppResult<ConfigFile> {
    blocking(&state, move |state| {
        let mut config = SshConfig::load(&state.paths.config)?;
        if config.remove_identity_file(host_id, &value)? {
            config.save(&state.paths.config, &state.backup_dir)?;
        }
        config_file(state)
    })
    .await
}

#[tauri::command]
pub async fn read_config_raw(state: State<'_, Shared>) -> AppResult<String> {
    blocking(&state, |state| {
        match fs::read_to_string(&state.paths.config) {
            Ok(text) => Ok(text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(e) => Err(e.into()),
        }
    })
    .await
}

#[tauri::command]
pub async fn write_config_raw(state: State<'_, Shared>, text: String) -> AppResult<ConfigFile> {
    blocking(&state, move |state| {
        fs::create_dir_all(&state.paths.dir)?;
        fsutil::backup(&state.paths.config, &state.backup_dir)?;
        fsutil::atomic_write(&state.paths.config, text.as_bytes(), 0o600)?;
        config_file(state)
    })
    .await
}

/// Runs `ssh` against a host alias without prompting, so the user sees whether
/// the key, host key and network all work.
#[tauri::command]
pub async fn test_connection(state: State<'_, Shared>, alias: String) -> AppResult<ConnectionTest> {
    blocking(&state, move |_| {
        if alias.is_empty() || alias.starts_with('-') || alias.chars().any(char::is_whitespace) {
            return Err(AppError::invalid("not a host alias"));
        }
        let output = process::run(
            "ssh",
            &[
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=8",
                "-T",
                "--",
                &alias,
                "exit",
            ],
            Duration::from_secs(20),
        )?;
        let text = format!("{}{}", output.stdout, output.stderr)
            .trim()
            .to_owned();
        // Git hosts refuse shell access but confirm the key worked.
        let authenticated = text.contains("successfully authenticated")
            || text.contains("Welcome to GitLab")
            || text.contains("logged in as");
        Ok(ConnectionTest {
            ok: output.success || authenticated,
            output: if output.timed_out {
                format!("{text}\n(timed out)").trim().to_owned()
            } else {
                text
            },
        })
    })
    .await
}

pub fn config_file(state: &AppState) -> AppResult<ConfigFile> {
    let config = SshConfig::load(&state.paths.config)?;
    Ok(ConfigFile {
        path: state.paths.config.to_string_lossy().into_owned(),
        exists: state.paths.config.exists(),
        view: config.view(),
        usage: config.identity_usage(&state.paths),
    })
}
