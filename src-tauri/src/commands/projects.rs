//! Projects (see `sshkm_core::vault::projects`): labels kept in the vault
//! that tie hosts, keys, logins, environments and folders together.
//!
//! While the vault is locked, the list comes from the copy without secrets
//! the vault runtime keeps ([`crate::vault::VaultRuntime::projects_copy`]),
//! so projects still show next to the SSH sections; changing one needs the
//! vault. A folder joins a project only from the system folder dialog this
//! side opens ([`projects_add_folder`]), never by a path the page names.

use std::path::PathBuf;

use sshkm_core::ErrorCode;
use sshkm_core::paths::home_dir;
use sshkm_core::vault::projects::{self, Project, ProjectInput, ProjectMember};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::DialogExt;

use super::{Shared, blocking};
use crate::confirm::Localized;
use crate::error::{AppError, AppResult};

/// Emitted when a sync with one of the user's devices changed the projects.
pub const CHANGED_EVENT: &str = "projects-changed";

/// The projects, by name: from the vault, or while it is locked from the
/// copy kept for then, whose projects have no logins. Quiet: the UI
/// refetches the list by itself.
#[tauri::command]
pub async fn projects_list(app: AppHandle, state: State<'_, Shared>) -> AppResult<Vec<Project>> {
    blocking(&state, move |state| {
        if !state.vault.is_unlocked() {
            return Ok(state.vault.projects_copy());
        }
        match state.vault.with_quietly(&app, |vault| Ok(vault.projects())) {
            Err(error) if error.code() == ErrorCode::VaultLocked => Ok(state.vault.projects_copy()),
            other => other,
        }
    })
    .await
}

#[tauri::command]
pub async fn projects_create(
    app: AppHandle,
    state: State<'_, Shared>,
    input: ProjectInput,
) -> AppResult<Project> {
    blocking(&state, move |state| {
        state.vault.change(&app, &state.backup_dir, |vault| {
            let id = vault.add_project(&input)?;
            Ok(vault.project(&id)?)
        })
    })
    .await
}

/// Renames a project or changes its color.
#[tauri::command]
pub async fn projects_update(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
    input: ProjectInput,
) -> AppResult<Project> {
    blocking(&state, move |state| {
        state.vault.change(&app, &state.backup_dir, |vault| {
            vault.update_project(&id, &input)?;
            Ok(vault.project(&id)?)
        })
    })
    .await
}

/// Removes a project. What it held stays where it is.
#[tauri::command]
pub async fn projects_delete(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
) -> AppResult<()> {
    blocking(&state, move |state| {
        state.vault.change(&app, &state.backup_dir, |vault| {
            Ok(vault.remove_project(&id)?)
        })
    })
    .await
}

/// Puts an item into a project or takes it out. A folder is only taken
/// out here; [`projects_add_folder`] adds one.
#[tauri::command]
pub async fn projects_set_member(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
    member: ProjectMember,
    included: bool,
) -> AppResult<Project> {
    if included && matches!(member, ProjectMember::Folder { .. }) {
        return Err(AppError::invalid("choose the folder in the folder dialog"));
    }
    blocking(&state, move |state| {
        state.vault.change(&app, &state.backup_dir, |vault| {
            vault.set_project_member(&id, &member, included)?;
            Ok(vault.project(&id)?)
        })
    })
    .await
}

/// Asks for a folder in a system dialog and adds it to the project. `None`
/// when the dialog was cancelled.
#[tauri::command]
pub async fn projects_add_folder(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
) -> AppResult<Option<Project>> {
    blocking(&state, move |state| {
        // No dialog while the vault is locked, or for a project that's gone.
        let name = state
            .vault
            .with(&app, |vault| Ok(vault.project(&id)?.name))?;
        let Some(folder) = pick_folder(&app, &name)? else {
            return Ok(None);
        };
        let text = projects::folder_text(&folder, home_dir().as_deref())?;
        let project = state.vault.change(&app, &state.backup_dir, |vault| {
            vault.set_project_member(&id, &ProjectMember::Folder { path: text }, true)?;
            Ok(vault.project(&id)?)
        })?;
        Ok(Some(project))
    })
    .await
}

fn pick_folder(app: &AppHandle, project: &str) -> AppResult<Option<PathBuf>> {
    let mut dialog = app.dialog().file().set_title(
        Localized::new(
            format!("Add a folder to {project}"),
            format!("Добавить папку в {project}"),
            format!("{project} loyihasiga papka qo‘shish"),
        )
        .pick(),
    );
    if let Some(home) = home_dir() {
        dialog = dialog.set_directory(home);
    }
    if let Some(window) = app.get_webview_window("main") {
        dialog = dialog.set_parent(&window);
    }
    let Some(picked) = dialog.blocking_pick_folder() else {
        return Ok(None);
    };
    let path = picked
        .into_path()
        .map_err(|e| AppError::invalid(format!("not a folder path: {e}")))?;
    if !path.is_dir() {
        return Err(AppError::invalid(format!(
            "{} is not a folder",
            path.display()
        )));
    }
    Ok(Some(path))
}
