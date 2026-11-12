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
    self, AgentChoices, AgentRules, AgentTool, FolderChoice, RulesPlaces,
};
use sshkm_core::vault::projects;
use tauri::AppHandle;

use super::{Shared, blocking};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

const CHOICES_FILE: &str = "agent-rules.json";
/// Held while the choices or a tool's rules file are read, changed and
/// written, so two changes don't lose each other's lines.
static HELD: Mutex<()> = Mutex::new(());

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
    /// The tools whose file couldn't be changed just now, passed over.
    pub failed: Vec<AgentTool>,
}

/// What each AI tool's ignore file lacks for a project folder's managed
/// files, and what the user said about the folder.
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
        let _held = held();
        Ok(view(state, folder, location, files, Vec::new()))
    })
    .await
}

/// Adds to the ignore files of `tools` the lines a project folder's managed
/// files need, after the user said to, and remembers it, with the tools
/// chosen before, for files bound there later. A file that can't be changed
/// is passed over and named.
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
        let _held = held();
        let path = choices_path(state);
        let mut choices = AgentChoices::load(&path)?;
        let mut chosen = tools;
        if let Some(FolderChoice::Added { tools: before }) = choices.get(&folder) {
            chosen.extend(before.iter().copied());
        }
        chosen.sort();
        chosen.dedup();
        choices.set(
            &folder,
            FolderChoice::Added {
                tools: chosen.clone(),
            },
        );
        choices.save(&path)?;
        let places = RulesPlaces::of(&location, home_dir().as_deref());
        let added = agents::add_agent_rules(&places, &files, &chosen);
        Ok(view(state, folder, location, files, added.failed))
    })
    .await
}

/// Remembers that the user doesn't want AI tools' rules in a project
/// folder, or no longer: they aren't offered there again, nor added for
/// files bound there later. Lines added before stay.
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
        let _held = held();
        let path = choices_path(state);
        let mut choices = AgentChoices::load(&path)?;
        choices.set(&folder, FolderChoice::Declined);
        choices.save(&path)?;
        Ok(view(state, folder, location, files, Vec::new()))
    })
    .await
}

/// After a file is bound in `folder`: if the user said yes to AI tools'
/// rules there, the tools they chose get its line too. Best effort: a file
/// that can't be changed is logged.
pub(crate) fn follow_choice(app: &AppHandle, state: &AppState, folder: &str) {
    let Some(location) =
        projects::folder_path(folder, home_dir().as_deref()).filter(|path| path.is_dir())
    else {
        return;
    };
    let Ok(files) = state
        .vault
        .with_quietly(app, |vault| Ok(vault.env_files_in_folder(folder)))
    else {
        return;
    };
    let _held = held();
    let Ok(choices) = AgentChoices::load(&choices_path(state)) else {
        return;
    };
    let Some(FolderChoice::Added { tools }) = choices.get(folder) else {
        return;
    };
    let places = RulesPlaces::of(&location, home_dir().as_deref());
    let added = agents::add_agent_rules(&places, &files, tools);
    if !added.failed.is_empty() {
        log::warn!(
            "agent rules: not changed for {:?} in {folder}",
            added.failed
        );
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

/// The view of a folder, with `HELD` held.
fn view(
    state: &AppState,
    folder: String,
    location: PathBuf,
    files: Vec<String>,
    failed: Vec<AgentTool>,
) -> AgentRulesView {
    let home = home_dir();
    let found = match &home {
        Some(home) => agents::agent_tools_found(home, dirs::config_dir().as_deref()),
        None => std::collections::BTreeSet::new(),
    };
    let places = RulesPlaces::of(&location, home.as_deref());
    // Choices that can't be read count as none, and aren't written over.
    let choice = AgentChoices::load(&choices_path(state))
        .ok()
        .and_then(|choices| choices.get(&folder).cloned());
    AgentRulesView {
        tools: agents::agent_rules(&places, &files, &found),
        choice,
        folder,
        location,
        files,
        failed,
    }
}

fn choices_path(state: &AppState) -> PathBuf {
    state.vault.data_dir().join(CHOICES_FILE)
}

fn held() -> MutexGuard<'static, ()> {
    HELD.lock().unwrap_or_else(PoisonError::into_inner)
}
