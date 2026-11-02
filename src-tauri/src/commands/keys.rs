use std::collections::HashSet;
use std::path::{Path, PathBuf};

use sshkm_core::SecretString;
use sshkm_core::agent::AgentClient;
use sshkm_core::config::{HostEdit, HostOption, IdentityUsage, SshConfig};
use sshkm_core::keys::{self, KeyInfo};
use tauri::State;

use super::{Shared, blocking};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::types::{GenerateKeyRequest, KeyUsage, KeyView, KeysView};

#[tauri::command]
pub async fn list_keys(state: State<'_, Shared>) -> AppResult<KeysView> {
    blocking(&state, key_views).await
}

#[tauri::command]
pub async fn generate_key(
    state: State<'_, Shared>,
    request: GenerateKeyRequest,
) -> AppResult<KeyView> {
    blocking(&state, move |state| {
        let info = keys::generate(&state.paths.dir, &request.key)?;
        let private = private_path(&info)?;

        if request.add_to_agent {
            let unlocked = keys::load_private(&private, request.key.passphrase.as_ref())?;
            let agent = AgentClient::from_env()?;
            agent.add(
                &unlocked,
                &agent_comment(&info),
                request.agent_lifetime_secs,
                false,
            )?;
            state.record_lifetime(&unlocked.fingerprint(), request.agent_lifetime_secs);
        }

        if let Some(host) = request.host {
            let mut options = Vec::new();
            if let Some(name) = host.host_name.filter(|v| !v.trim().is_empty()) {
                options.push(HostOption::new("HostName", name.trim()));
            }
            if let Some(user) = host.user.filter(|v| !v.trim().is_empty()) {
                options.push(HostOption::new("User", user.trim()));
            }
            options.push(HostOption::new(
                "IdentityFile",
                identity_file_value(state, &private),
            ));
            options.push(HostOption::new("IdentitiesOnly", "yes"));
            let mut config = SshConfig::load(&state.paths.config)?;
            config.upsert_host(&HostEdit {
                id: None,
                patterns: host.alias.split_whitespace().map(str::to_owned).collect(),
                options,
            })?;
            config.save(&state.paths.config, &state.backup_dir)?;
        }

        find_view(state, &info.id)
    })
    .await
}

#[tauri::command]
pub async fn change_passphrase(
    state: State<'_, Shared>,
    key_id: String,
    old: Option<SecretString>,
    new: Option<SecretString>,
) -> AppResult<KeyView> {
    blocking(&state, move |state| {
        let info = find_key(state, &key_id)?;
        let updated = keys::change_passphrase(&private_path(&info)?, old.as_ref(), new.as_ref())?;
        find_view(state, &updated.id)
    })
    .await
}

#[tauri::command]
pub async fn regenerate_public(state: State<'_, Shared>, key_id: String) -> AppResult<KeyView> {
    blocking(&state, move |state| {
        let info = find_key(state, &key_id)?;
        let updated = keys::regenerate_public(&private_path(&info)?)?;
        find_view(state, &updated.id)
    })
    .await
}

#[tauri::command]
pub async fn import_key(
    state: State<'_, Shared>,
    source: String,
    file_name: Option<String>,
) -> AppResult<KeyView> {
    blocking(&state, move |state| {
        let info = keys::import(&state.paths.dir, Path::new(&source), file_name.as_deref())?;
        find_view(state, &info.id)
    })
    .await
}

#[tauri::command]
pub async fn trash_key(state: State<'_, Shared>, key_id: String) -> AppResult<()> {
    blocking(&state, move |state| {
        let info = find_key(state, &key_id)?;
        let files: Vec<PathBuf> = [&info.private_path, &info.public_path]
            .into_iter()
            .flatten()
            .map(PathBuf::from)
            .collect();
        keys::move_to_trash(&files)?;
        Ok(())
    })
    .await
}

pub fn key_views(state: &AppState) -> AppResult<KeysView> {
    let scan = keys::scan(&state.paths.dir)?;
    let in_agent = agent_fingerprints();
    let usage = SshConfig::load(&state.paths.config)
        .map(|config| config.identity_usage(&state.paths))
        .unwrap_or_default();
    let keys = scan
        .keys
        .into_iter()
        .map(|info| view(info, &in_agent, &usage))
        .collect();
    Ok(KeysView {
        keys,
        skipped: scan.skipped,
    })
}

pub fn find_key(state: &AppState, key_id: &str) -> AppResult<KeyInfo> {
    keys::scan(&state.paths.dir)?
        .keys
        .into_iter()
        .find(|key| key.id == key_id)
        .ok_or_else(|| AppError::not_found(format!("key {key_id}")))
}

pub fn private_path(info: &KeyInfo) -> AppResult<PathBuf> {
    info.private_path
        .as_deref()
        .map(PathBuf::from)
        .ok_or_else(|| AppError::invalid(format!("{} has no private key", info.name)))
}

/// What `ssh-add -l` shows for the key: its comment, else its file name.
pub fn agent_comment(info: &KeyInfo) -> String {
    if info.comment.trim().is_empty() {
        info.private_path
            .clone()
            .unwrap_or_else(|| info.name.clone())
    } else {
        info.comment.clone()
    }
}

fn find_view(state: &AppState, key_id: &str) -> AppResult<KeyView> {
    key_views(state)?
        .keys
        .into_iter()
        .find(|key| key.info.id == key_id)
        .ok_or_else(|| AppError::not_found(format!("key {key_id}")))
}

fn agent_fingerprints() -> HashSet<String> {
    AgentClient::from_env()
        .and_then(|agent| agent.list())
        .map(|ids| ids.into_iter().map(|id| id.fingerprint).collect())
        .unwrap_or_default()
}

fn view(info: KeyInfo, in_agent: &HashSet<String>, usage: &[IdentityUsage]) -> KeyView {
    let loaded = info
        .fingerprint
        .as_ref()
        .is_some_and(|fp| in_agent.contains(fp));
    let used_by = usage
        .iter()
        .filter(|u| u.resolved && refers_to(&info, Path::new(&u.path)))
        .map(|u| KeyUsage {
            host_id: u.host_id,
            patterns: u.patterns.clone(),
        })
        .collect();
    KeyView {
        info,
        in_agent: loaded,
        used_by,
    }
}

/// `IdentityFile` may name the private key or its `.pub` (ssh then uses the
/// matching identity from the agent).
fn refers_to(info: &KeyInfo, target: &Path) -> bool {
    let matches = |path: &Option<String>| {
        path.as_deref()
            .is_some_and(|p| same_path(Path::new(p), target))
    };
    if matches(&info.private_path) || matches(&info.public_path) {
        return true;
    }
    info.public_path
        .as_deref()
        .and_then(|p| p.strip_suffix(".pub"))
        .is_some_and(|stem| same_path(Path::new(stem), target))
}

fn same_path(a: &Path, b: &Path) -> bool {
    if cfg!(windows) {
        a.to_string_lossy()
            .eq_ignore_ascii_case(&b.to_string_lossy())
    } else {
        a == b
    }
}

/// `~/.ssh/<name>` for keys in the default directory, the full path otherwise.
fn identity_file_value(state: &AppState, private: &Path) -> String {
    match private.strip_prefix(&state.paths.home) {
        Ok(rest) => format!("~/{}", rest.to_string_lossy().replace('\\', "/")),
        Err(_) => private.to_string_lossy().into_owned(),
    }
}
