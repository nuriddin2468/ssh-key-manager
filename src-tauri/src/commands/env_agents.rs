//! AI tools' ignore rules for a project folder's managed `.env` files
//! (`sshkm_core::vault::envs::files::agents`), added only when the user
//! says so for that folder. The choice is remembered per folder on this
//! computer, in `agent-rules.json`: a folder that said yes gets lines for
//! files bound there later too; one that said no isn't asked again.
//!
//! The page names a folder only as its project keeps it, which the backend
//! checks against the project; the rules files are found from there.

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, PoisonError};

use serde::Serialize;
use sshkm_core::paths::home_dir;
use sshkm_core::vault::Vault;
use sshkm_core::vault::envs::files::agents::{
    self, AgentChoices, AgentRules, AgentTool, FolderChoice,
};
use sshkm_core::vault::projects;
use tauri::AppHandle;

use super::{Shared, blocking};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

const CHOICES_FILE: &str = "agent-rules.json";
/// Held while the choices are read, changed and written.
static CHOICES: Mutex<()> = Mutex::new(());

/// A project folder's AI tools' rules: what each tool's file lacks for the
/// folder's managed files, and what the user said about the folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct AgentRulesView {
    /// The folder as its project keeps it.
    pub folder: String,
    /// The folder on this computer.
    pub location: PathBuf,
    /// The managed files in it, as paths in the folder.
    pub files: Vec<String>,
    pub tools: Vec<AgentRules>,
    /// `None` until the user says.
    pub choice: Option<FolderChoice>,
}

/// What each AI tool's ignore file in a project folder lacks for its
/// managed files, and what the user said about the folder.
#[tauri::command]
pub async fn envs_agents_rules(
    app: AppHandle,
    state: tauri::State<'_, Shared>,
    project: String,
    folder: String,
) -> AppResult<AgentRulesView> {
    blocking(&state, move |state| {
        let (location, files) = state.vault.with_quietly(&app, |vault| {
            Ok((
                located(vault, &project, &folder)?,
                vault.env_files_in_folder(&folder),
            ))
        })?;
        Ok(view(state, folder, location, files))
    })
    .await
}

/// Adds to the ignore files of `tools` in a project folder the lines its
/// managed files need, after the user said to, and remembers it for files
/// bound there later.
#[tauri::command]
pub async fn envs_agents_add(
    app: AppHandle,
    state: tauri::State<'_, Shared>,
    project: String,
    folder: String,
    tools: Vec<AgentTool>,
) -> AppResult<AgentRulesView> {
    blocking(&state, move |state| {
        let (location, files) = state.vault.with(&app, |vault| {
            Ok((
                located(vault, &project, &folder)?,
                vault.env_files_in_folder(&folder),
            ))
        })?;
        let mut tools = tools;
        tools.sort();
        tools.dedup();
        let result = agents::add_agent_rules(&location, &files, &tools);
        // Kept as the user said, even if a file couldn't be changed.
        set_choice(state, &folder, FolderChoice::Added { tools })?;
        result?;
        Ok(view(state, folder, location, files))
    })
    .await
}

/// Remembers that the user doesn't want AI tools' rules in a project
/// folder: they aren't offered there again.
#[tauri::command]
pub async fn envs_agents_decline(
    app: AppHandle,
    state: tauri::State<'_, Shared>,
    project: String,
    folder: String,
) -> AppResult<AgentRulesView> {
    blocking(&state, move |state| {
        let (location, files) = state.vault.with(&app, |vault| {
            Ok((
                located(vault, &project, &folder)?,
                vault.env_files_in_folder(&folder),
            ))
        })?;
        set_choice(state, &folder, FolderChoice::Declined)?;
        Ok(view(state, folder, location, files))
    })
    .await
}

/// After a file is bound in `folder`: if the user said yes to AI tools'
/// rules there, the tools they chose get its line too. Best effort: a file
/// that can't be changed is logged.
pub(crate) fn follow_choice(app: &AppHandle, state: &AppState, folder: &str) {
    let Some(FolderChoice::Added { tools }) = choices(state).get(folder).cloned() else {
        return;
    };
    let Some(location) =
        projects::folder_path(folder, home_dir().as_deref()).filter(|p| p.is_dir())
    else {
        return;
    };
    let Ok(files) = state
        .vault
        .with_quietly(app, |vault| Ok(vault.env_files_in_folder(folder)))
    else {
        return;
    };
    if let Err(error) = agents::add_agent_rules(&location, &files, &tools) {
        log::warn!("agent rules: {error}");
    }
}

/// The folder `folder` of the project `project` on this computer.
fn located(vault: &Vault, project: &str, folder: &str) -> AppResult<PathBuf> {
    if !vault.project(project)?.folders.iter().any(|f| f == folder) {
        return Err(AppError::invalid("the folder isn't in the project"));
    }
    projects::folder_path(folder, home_dir().as_deref())
        .filter(|path| path.is_dir())
        .ok_or_else(|| AppError::invalid("the folder isn't on this computer"))
}

fn view(state: &AppState, folder: String, location: PathBuf, files: Vec<String>) -> AgentRulesView {
    let found = match home_dir() {
        Some(home) => agents::agent_tools_found(&home, dirs::config_dir().as_deref()),
        None => std::collections::BTreeSet::new(),
    };
    AgentRulesView {
        tools: agents::agent_rules(&location, &files, &found),
        choice: choices(state).get(&folder).cloned(),
        folder,
        location,
        files,
    }
}

fn choices_path(state: &AppState) -> PathBuf {
    state.vault.data_dir().join(CHOICES_FILE)
}

fn choices(state: &AppState) -> AgentChoices {
    let _held = held();
    AgentChoices::load(&choices_path(state))
}

fn set_choice(state: &AppState, folder: &str, choice: FolderChoice) -> AppResult<()> {
    let _held = held();
    let path = choices_path(state);
    let mut choices = AgentChoices::load(&path);
    choices.set(folder, choice);
    choices.save(&path)?;
    Ok(())
}

fn held() -> MutexGuard<'static, ()> {
    CHOICES.lock().unwrap_or_else(PoisonError::into_inner)
}
