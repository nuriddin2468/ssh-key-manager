//! Secret environments in the vault (see `sshkm_core::vault::envs`): their
//! list and variables, a value shown or copied one at a time, `.env`
//! imports and exports, comparing two, and running a shell with one.
//!
//! Like passwords, values leave the Rust process only when the user asks to
//! see one ([`envs_reveal`]); copying goes straight to the clipboard
//! ([`envs_copy`]), a shell gets them in its environment ([`envs_run`]),
//! and files get them in plain text. The files read and written here are
//! chosen in system file dialogs this side opens, never named by the page;
//! an export into a Git working tree that doesn't ignore the file waits for
//! the user's go-ahead ([`envs_export_anyway`]).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sshkm_core::paths::home_dir;
use sshkm_core::vault::envs::{
    self, EnvComparison, EnvDetail, EnvFormat, EnvImportPreview, EnvInput, EnvSummary, EnvVarInput,
    ImportChoice, ImportCounts, PartRename, SharedValue,
};
use sshkm_core::vault::projects::{PartFolderChoice, places};
use sshkm_core::{ExposeSecret, SecretString};
use tauri::ipc::{Channel, InvokeResponseBody};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::DialogExt;

use super::projects::{apply_folder_choice, place_path};
use super::{Shared, blocking};
use crate::confirm::Localized;
use crate::error::{AppError, AppResult};
use crate::process;
use crate::terminal::Sink;
use crate::terminal::shells;
use crate::terminal::types::TerminalInfo;
use crate::types::CopyResult;

/// The `.env` file picked in the import's file dialog: the only one
/// [`envs_import`] reads.
static PICKED_IMPORT: Mutex<Option<PathBuf>> = Mutex::new(None);
/// An export that waits for the user's go-ahead: the environment, the
/// format and the file picked for it.
static PENDING_EXPORT: Mutex<Option<(String, EnvFormat, PathBuf)>> = Mutex::new(None);

/// A `.env` file picked for import, and what it holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct EnvImportPick {
    pub path: PathBuf,
    pub preview: EnvImportPreview,
}

/// Where an import goes.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum ImportTarget {
    /// A new environment with that stage, in a project (by id; `None` for
    /// Personal) and part.
    New {
        #[serde(default)]
        project: Option<String>,
        #[serde(default)]
        part: String,
        name: String,
        /// Its notes, if any.
        #[serde(default)]
        #[cfg_attr(test, ts(optional))]
        notes: Option<String>,
    },
    /// An existing one: values of names it has are replaced.
    Existing { id: String },
}

/// What an import did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct EnvImported {
    /// The environment the variables went to.
    pub id: String,
    #[serde(flatten)]
    #[cfg_attr(test, ts(flatten))]
    pub counts: ImportCounts,
}

/// An export: written, or waiting because of a Git working tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct EnvExport {
    pub path: PathBuf,
    /// The file was written; when `false`, it waits for
    /// [`envs_export_anyway`].
    pub written: bool,
    /// How many variables it holds, once written.
    pub count: u32,
    /// The Git working tree the file would be in, without being ignored
    /// there: committing the folder would take the secrets along.
    pub repository: Option<PathBuf>,
}

/// The environments, those in the recycle bin too. Quiet: the UI refetches
/// the list by itself.
#[tauri::command]
pub async fn envs_list(app: AppHandle, state: State<'_, Shared>) -> AppResult<Vec<EnvSummary>> {
    blocking(&state, move |state| {
        state
            .vault
            .with_quietly(&app, |vault| Ok(vault.environments()))
    })
    .await
}

/// One environment's variables, without values. Quiet, like [`envs_list`].
#[tauri::command]
pub async fn envs_get(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
) -> AppResult<EnvDetail> {
    blocking(&state, move |state| {
        state
            .vault
            .with_quietly(&app, |vault| Ok(vault.environment(&id)?))
    })
    .await
}

/// Adds an environment; `rename` names the part its project had, when this
/// gives it a second (in the same change, as do the commands below).
#[tauri::command]
pub async fn envs_create(
    app: AppHandle,
    state: State<'_, Shared>,
    input: EnvInput,
    rename: Option<PartRename>,
    folder: Option<PartFolderChoice>,
) -> AppResult<EnvDetail> {
    blocking(&state, move |state| {
        state.vault.change(&app, &state.backup_dir, |vault| {
            vault.name_first_part(rename.as_ref())?;
            let id = vault.add_environment(&input)?;
            apply_folder_choice(vault, &id, folder.as_ref())?;
            Ok(vault.environment(&id)?)
        })
    })
    .await
}

/// Renames an environment, moves it to another project or changes its notes.
#[tauri::command]
pub async fn envs_update(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
    input: EnvInput,
    rename: Option<PartRename>,
    folder: Option<PartFolderChoice>,
) -> AppResult<EnvDetail> {
    blocking(&state, move |state| {
        state.vault.change(&app, &state.backup_dir, |vault| {
            vault.name_first_part(rename.as_ref())?;
            vault.update_environment(&id, &input)?;
            apply_folder_choice(vault, &id, folder.as_ref())?;
            Ok(vault.environment(&id)?)
        })
    })
    .await
}

/// Gives environments a part (or none): a part renamed, all its stages
/// (those in the recycle bin too).
#[tauri::command]
pub async fn envs_set_part(
    app: AppHandle,
    state: State<'_, Shared>,
    ids: Vec<String>,
    part: String,
) -> AppResult<()> {
    blocking(&state, move |state| {
        state.vault.change(&app, &state.backup_dir, |vault| {
            Ok(vault.set_environment_part(&ids, &part)?)
        })
    })
    .await
}

/// Adds a variable, or changes the one named `previous`.
#[tauri::command]
pub async fn envs_set_var(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
    previous: Option<String>,
    input: EnvVarInput,
) -> AppResult<EnvDetail> {
    blocking(&state, move |state| {
        state.vault.change(&app, &state.backup_dir, |vault| {
            vault.set_env_variable(&id, previous.as_deref(), &input)?;
            Ok(vault.environment(&id)?)
        })
    })
    .await
}

#[tauri::command]
pub async fn envs_remove_var(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
    name: String,
) -> AppResult<EnvDetail> {
    blocking(&state, move |state| {
        state.vault.change(&app, &state.backup_dir, |vault| {
            vault.remove_env_variable(&id, &name)?;
            Ok(vault.environment(&id)?)
        })
    })
    .await
}

/// Every shared value, with the variables that use it; no values.
#[tauri::command]
pub async fn envs_shared_list(
    app: AppHandle,
    state: State<'_, Shared>,
) -> AppResult<Vec<SharedValue>> {
    blocking(&state, move |state| {
        state
            .vault
            .with_quietly(&app, |vault| Ok(vault.shared_values()))
    })
    .await
}

/// Shares the variable `name` of the environment `id` with the
/// environments `others`, which use it under the same name from then on:
/// added where they lack it, their value replaced where they have it.
#[tauri::command]
pub async fn envs_share_var(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
    name: String,
    others: Vec<String>,
) -> AppResult<EnvDetail> {
    blocking(&state, move |state| {
        state.vault.change(&app, &state.backup_dir, |vault| {
            vault.share_env_variable(&id, &name, &others)?;
            Ok(vault.environment(&id)?)
        })
    })
    .await
}

/// Gives a shared variable of an environment a value of its own, the
/// shared value as it is now.
#[tauri::command]
pub async fn envs_unshare_var(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
    name: String,
) -> AppResult<EnvDetail> {
    blocking(&state, move |state| {
        state.vault.change(&app, &state.backup_dir, |vault| {
            vault.unshare_env_variable(&id, &name)?;
            Ok(vault.environment(&id)?)
        })
    })
    .await
}

/// Moves a shared value to the recycle bin, each variable that used it
/// given a value of its own first.
#[tauri::command]
pub async fn envs_shared_delete(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
) -> AppResult<()> {
    blocking(&state, move |state| {
        state.vault.change(&app, &state.backup_dir, |vault| {
            vault.delete_shared_value(&id)?;
            Ok(())
        })
    })
    .await
}

/// One variable's value, for the user to see. Past a few secret ones a
/// minute, each is confirmed in a native dialog ([`crate::secret_gate`]).
#[tauri::command]
pub async fn envs_reveal(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
    name: String,
) -> AppResult<String> {
    blocking(&state, move |state| {
        crate::secret_gate::take_env_value(
            &app,
            state,
            &id,
            &name,
            crate::secret_gate::Taking::Show,
        )?;
        state.vault.with(&app, |vault| {
            Ok(vault.env_value(&id, &name)?.expose_secret().to_owned())
        })
    })
    .await
}

/// Copies one variable's value without it passing through the UI. A secret
/// one is kept out of clipboard history and cleared after a while, like a
/// password, and counts as shown for [`envs_reveal`]'s limit.
#[tauri::command]
pub async fn envs_copy(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
    name: String,
) -> AppResult<CopyResult> {
    blocking(&state, move |state| {
        crate::secret_gate::take_env_value(
            &app,
            state,
            &id,
            &name,
            crate::secret_gate::Taking::Copy,
        )?;
        let (value, secret) = state.vault.with(&app, |vault| {
            let secret = vault
                .environment(&id)?
                .variables
                .iter()
                .any(|var| var.name == name && var.secret);
            Ok((vault.env_value(&id, &name)?, secret))
        })?;
        if value.expose_secret().is_empty() {
            return Err(AppError::not_found("nothing to copy"));
        }
        let clears_in_secs = Arc::clone(&state.vault).copy(&value, secret)?;
        Ok(CopyResult { clears_in_secs })
    })
    .await
}

#[tauri::command]
pub async fn envs_trash(app: AppHandle, state: State<'_, Shared>, id: String) -> AppResult<()> {
    blocking(&state, move |state| {
        state.vault.change(&app, &state.backup_dir, |vault| {
            Ok(vault.trash_environment(&id)?)
        })
    })
    .await
}

#[tauri::command]
pub async fn envs_restore(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
    rename: Option<PartRename>,
) -> AppResult<()> {
    blocking(&state, move |state| {
        state.vault.change(&app, &state.backup_dir, |vault| {
            vault.name_first_part(rename.as_ref())?;
            Ok(vault.restore_environment(&id)?)
        })
    })
    .await
}

/// Deletes an environment in the recycle bin for good.
#[tauri::command]
pub async fn envs_delete(app: AppHandle, state: State<'_, Shared>, id: String) -> AppResult<()> {
    blocking(&state, move |state| {
        state.vault.change(&app, &state.backup_dir, |vault| {
            Ok(vault.delete_environment(&id)?)
        })
    })
    .await
}

/// Which names one environment lacks, adds or has with another value than
/// the other; values are compared here.
#[tauri::command]
pub async fn envs_compare(
    app: AppHandle,
    state: State<'_, Shared>,
    left: String,
    right: String,
) -> AppResult<EnvComparison> {
    blocking(&state, move |state| {
        state
            .vault
            .with(&app, |vault| Ok(vault.compare_environments(&left, &right)?))
    })
    .await
}

/// Asks for a `.env` file in a system file dialog and lists its variables,
/// without values, with the ones that look secret marked. `None` when the
/// dialog was cancelled.
#[tauri::command]
pub async fn envs_import_pick(
    app: AppHandle,
    state: State<'_, Shared>,
) -> AppResult<Option<EnvImportPick>> {
    blocking(&state, move |state| {
        // No dialog while the vault is locked.
        state.vault.with(&app, |_| Ok(()))?;
        let Some(path) = pick_env_file(&app)? else {
            return Ok(None);
        };
        let preview = envs::preview_file(&path)?;
        *picked_import() = Some(path.clone());
        Ok(Some(EnvImportPick { path, preview }))
    })
    .await
}

/// Imports the variables `choices` names from the file picked for it, with
/// the secret flags chosen there, into `target`.
#[tauri::command]
pub async fn envs_import(
    app: AppHandle,
    state: State<'_, Shared>,
    target: ImportTarget,
    choices: Vec<ImportChoice>,
    rename: Option<PartRename>,
) -> AppResult<EnvImported> {
    if choices.is_empty() {
        return Err(AppError::invalid("choose at least one variable to import"));
    }
    blocking(&state, move |state| {
        let path = picked_import()
            .clone()
            .ok_or_else(|| AppError::invalid("choose the file to import again"))?;
        let vars = envs::chosen_variables(envs::read_file(&path)?, &choices);
        let imported = state.vault.change(&app, &state.backup_dir, |vault| {
            vault.name_first_part(rename.as_ref())?;
            let id = match &target {
                ImportTarget::New {
                    project,
                    part,
                    name,
                    notes,
                } => vault.add_environment(&EnvInput {
                    project: project.clone(),
                    part: part.clone(),
                    name: name.clone(),
                    notes: notes.clone().unwrap_or_default(),
                })?,
                ImportTarget::Existing { id } => id.clone(),
            };
            let counts = vault.import_env_variables(&id, &vars)?;
            Ok(EnvImported { id, counts })
        })?;
        *picked_import() = None;
        Ok(imported)
    })
    .await
}

/// Asks where to save the environment in `format` in a system file dialog
/// and writes it there, in plain text, unless the file would be in a Git
/// working tree that doesn't ignore it: then it waits for
/// [`envs_export_anyway`]. `None` when the dialog was cancelled.
#[tauri::command]
pub async fn envs_export(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
    format: EnvFormat,
) -> AppResult<Option<EnvExport>> {
    blocking(&state, move |state| {
        let (env, label) = state.vault.with(&app, |vault| {
            let env = vault.environment(&id)?;
            let label = vault.env_label(&env.summary);
            Ok((env, label))
        })?;
        let Some(path) = pick_export_target(&app, format, &label, &env.summary)? else {
            return Ok(None);
        };
        *pending_export() = None;
        if let Some(repository) = unignored_in_git(&path) {
            *pending_export() = Some((id, format, path.clone()));
            return Ok(Some(EnvExport {
                path,
                written: false,
                count: 0,
                repository: Some(repository),
            }));
        }
        let count = state.vault.with(&app, |vault| {
            Ok(vault.export_environment(&id, format, &path, &state.paths.dir)?)
        })?;
        Ok(Some(EnvExport {
            path,
            written: true,
            count: u32::try_from(count).unwrap_or(u32::MAX),
            repository: None,
        }))
    })
    .await
}

/// Writes the export that waits because of a Git working tree, after the
/// user said to.
#[tauri::command]
pub async fn envs_export_anyway(app: AppHandle, state: State<'_, Shared>) -> AppResult<EnvExport> {
    blocking(&state, move |state| {
        let (id, format, path) = pending_export()
            .take()
            .ok_or_else(|| AppError::invalid("choose where to save again"))?;
        let count = state.vault.with(&app, |vault| {
            Ok(vault.export_environment(&id, format, &path, &state.paths.dir)?)
        })?;
        Ok(EnvExport {
            repository: envs::git_work_tree(path.parent().unwrap_or(&path)),
            path,
            written: true,
            count: u32::try_from(count).unwrap_or(u32::MAX),
        })
    })
    .await
}

/// Opens a shell in the app's terminal with the environment's variables in
/// its environment, and nowhere else: `shell` (an id from `terminal_shells`)
/// or the default one. It starts where the environment works
/// (`sshkm_core::vault::projects::places`): its part's folder, else the
/// first of the project's folders found here; one in Personal, or with none
/// here, in the home folder. Output and events arrive on `events`, as for
/// `terminal_open`. Secret values go in only once the user said yes in a
/// native dialog ([`crate::secret_gate::confirm_env_secrets`]).
#[tauri::command]
pub async fn envs_run(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
    shell: Option<String>,
    cols: u16,
    rows: u16,
    events: Channel<InvokeResponseBody>,
) -> AppResult<TerminalInfo> {
    let shared = Arc::clone(&state);
    blocking(&state, move |state| {
        crate::secret_gate::confirm_env_secrets(
            &app,
            state,
            &id,
            &crate::secret_gate::EnvUse::Shell,
        )?;
        let (label, vars, places) = state.vault.with(&app, |vault| {
            let env = vault.environment(&id)?.summary;
            let vars: Vec<(String, SecretString)> = vault
                .env_variables(&id)?
                .into_iter()
                .map(|var| (var.name, var.value))
                .collect();
            let places = match &env.project {
                Some(project) if !env.in_trash => Some((
                    vault.project(project)?,
                    places::env_folders(&vault.project_places(project)?, &id),
                )),
                _ => None,
            };
            Ok((
                envs::label(Some(&vault.env_label(&env)), &env.name),
                vars,
                places,
            ))
        })?;
        let home = home_dir();
        let folder = places
            .and_then(|(project, folders)| {
                folders
                    .iter()
                    .find_map(|folder| place_path(&project, folder, home.as_deref()).ok())
            })
            .unwrap_or_else(|| state.paths.home.clone());
        let shell = shells::find(shell.as_deref())?;
        let sink: Arc<dyn Sink> = Arc::new(events);
        shared
            .terminals
            .open_local(&label, &shell, &vars, &folder, (cols, rows), sink)
    })
    .await
}

fn picked_import() -> std::sync::MutexGuard<'static, Option<PathBuf>> {
    PICKED_IMPORT.lock().unwrap_or_else(PoisonError::into_inner)
}

fn pending_export() -> std::sync::MutexGuard<'static, Option<(String, EnvFormat, PathBuf)>> {
    PENDING_EXPORT
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// The Git working tree `path` would be in, unless `git check-ignore` says
/// the file is ignored there. Without `git`, a working tree counts as not
/// ignoring it.
pub(crate) fn unignored_in_git(path: &Path) -> Option<PathBuf> {
    let folder = path.parent()?;
    let repository = envs::git_work_tree(folder)?;
    let mut command = process::command("git");
    // A working tree's own config could name a program to run as its file
    // system monitor; asking what it ignores needs none.
    command
        .args(["-c", "core.fsmonitor=false", "-C"])
        .arg(folder)
        .args(["check-ignore", "-q", "--"])
        .arg(path.file_name()?);
    let ignored = process::run_command(&mut command, None, Duration::from_secs(5))
        .is_ok_and(|output| output.code == Some(0));
    (!ignored).then_some(repository)
}

/// The import's file dialog: one `.env` file, which may have any name.
fn pick_env_file(app: &AppHandle) -> AppResult<Option<PathBuf>> {
    let mut dialog = app.dialog().file().set_title(
        Localized::new(
            "Choose a .env file",
            "Выберите файл .env",
            ".env faylini tanlang",
        )
        .pick(),
    );
    if let Some(window) = app.get_webview_window("main") {
        dialog = dialog.set_parent(&window);
    }
    dialog.blocking_pick_file().map(into_path).transpose()
}

/// The export's save dialog, suggesting a file name for the format.
fn pick_export_target(
    app: &AppHandle,
    format: EnvFormat,
    label: &str,
    env: &EnvSummary,
) -> AppResult<Option<PathBuf>> {
    let shown = envs::label(Some(label), &env.name);
    let mut dialog = app
        .dialog()
        .file()
        .set_title(
            Localized::new(
                format!("Save {shown}"),
                format!("Сохранить {shown}"),
                format!("{shown} ni saqlash"),
            )
            .pick(),
        )
        .set_file_name(format.file_name(&env.part, &env.name))
        .add_filter(format!(".{}", format.extension()), &[format.extension()]);
    if let Some(window) = app.get_webview_window("main") {
        dialog = dialog.set_parent(&window);
    }
    dialog.blocking_save_file().map(into_path).transpose()
}

fn into_path(picked: tauri_plugin_dialog::FilePath) -> AppResult<PathBuf> {
    let path = picked
        .into_path()
        .map_err(|e| AppError::invalid(format!("not a file path: {e}")))?;
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(AppError::invalid(format!(
            "not an absolute path: {}",
            path.display()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_git_ignores_are_fine() {
        if process::run("git", &["--version"], Duration::from_secs(5)).is_err() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        assert_eq!(unignored_in_git(&repo.join(".env")), None);
        let init = process::run(
            "git",
            &["-C", &repo.to_string_lossy(), "init", "-q"],
            Duration::from_secs(10),
        )
        .unwrap();
        assert!(init.success);
        let repo = std::fs::canonicalize(&repo).unwrap();
        assert_eq!(unignored_in_git(&repo.join(".env")), Some(repo.clone()));
        std::fs::write(repo.join(".gitignore"), ".env\n").unwrap();
        assert_eq!(unignored_in_git(&repo.join(".env")), None);
        assert_eq!(unignored_in_git(&repo.join("app.json")), Some(repo.clone()));
    }
}
