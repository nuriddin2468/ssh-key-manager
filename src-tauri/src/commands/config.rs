use std::fs;
use std::time::Duration;

use sshkm_core::SecretString;
use sshkm_core::config::{HostEdit, SshConfig};
use sshkm_core::fsutil;
use tauri::State;

use super::remote::{check_alias, combined, run_ssh, with_timeout_note};
use super::{Shared, blocking};
use crate::askpass::Secrets;
use crate::error::AppResult;
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

/// Runs `ssh` against a host alias, so the user sees whether the key, host key
/// and network all work.
///
/// Without `password` and `otp` it never prompts (`BatchMode=yes`). With
/// either, the app answers `ssh`'s password and one-time-code prompts with
/// them through askpass, and `prompts` tells what was asked: a password asked
/// again was rejected, a code asked with none given is missing, a declined
/// host-key question means the host key is not trusted yet.
#[tauri::command]
pub async fn test_connection(
    state: State<'_, Shared>,
    alias: String,
    password: Option<SecretString>,
    otp: Option<SecretString>,
) -> AppResult<ConnectionTest> {
    blocking(&state, move |state| {
        connection_test(state, &alias, Secrets::new(password, otp))
    })
    .await
}

/// [`test_connection`] with the secrets already gathered.
pub fn connection_test(
    state: &AppState,
    alias: &str,
    secrets: Secrets,
) -> AppResult<ConnectionTest> {
    check_alias(alias)?;
    let timeout = Duration::from_secs(if secrets.is_empty() { 20 } else { 30 });
    let run = run_ssh(state, alias, &[], &["exit"], secrets, None, timeout)?;
    let text = combined(&run.output);
    // Git hosts refuse shell access but confirm the key worked.
    let authenticated = text.contains("successfully authenticated")
        || text.contains("Welcome to GitLab")
        || text.contains("logged in as");
    Ok(ConnectionTest {
        ok: run.output.success || authenticated,
        output: with_timeout_note(text, &run.output),
        prompts: run.prompts,
    })
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
