//! Managed `.env` files (see `sshkm_core::vault::envs::files` and
//! [`crate::env_files`]): an environment's kind and files, where each file
//! stands, settling a conflict, undoing an edit that went to the vault, the
//! management center's view, and taking a `.env` file found in a project's
//! folder under management.
//!
//! The page names files only by a binding (a project folder and a path in
//! it), which the core checks against the projects; it never names a path
//! on disk. Values stay on this side: the page gets names, states and
//! revisions (keyed hashes) only.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sshkm_core::paths::home_dir;
use sshkm_core::vault::envs::files::{
    self as managed, CloudRoots, EnvFile, EnvFileStatus, EnvFilesOverview, EnvFilesSynced, EnvKind,
    EnvUndo, GitInfo, GitState, KeepSide, Preference,
};
use sshkm_core::vault::envs::{
    self, EnvComparison, EnvDetail, EnvImportPreview, EnvInput, ImportChoice, looks_secret,
};
use sshkm_core::vault::projects::ProjectMember;
use tauri::{AppHandle, State};

use super::envs::{EnvImported, ImportTarget, unignored_in_git};
use super::{Shared, blocking};
use crate::env_files::{EnvFiles, context};
use crate::error::{AppError, AppResult};
use crate::process;

type Files<'a> = State<'a, Arc<EnvFiles>>;

/// Makes an environment local (it can have files) or remote. A remote one
/// has none, so its files are to be removed first.
#[tauri::command]
pub async fn envs_set_kind(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
    kind: EnvKind,
) -> AppResult<EnvDetail> {
    blocking(&state, move |state| {
        state.vault.change(&app, &state.backup_dir, |vault| {
            vault.set_env_kind(&id, kind)?;
            Ok(vault.environment(&id)?)
        })
    })
    .await
}

/// Where every file of every environment stands, without changing
/// anything. Quiet: the UI refetches it by itself.
#[tauri::command]
pub async fn envs_files_status(
    app: AppHandle,
    state: State<'_, Shared>,
    files: Files<'_>,
) -> AppResult<Vec<EnvFileStatus>> {
    let files = Arc::clone(&files);
    blocking(&state, move |state| {
        let ctx = context(state);
        let kept = files.state();
        state
            .vault
            .with_quietly(&app, |vault| Ok(vault.env_files_status(&ctx, &kept)))
    })
    .await
}

/// Writes an environment to `file` from now on, and writes the file at
/// once, or reports it as a conflict when it exists with other values.
#[tauri::command]
pub async fn envs_files_bind(
    app: AppHandle,
    state: State<'_, Shared>,
    files: Files<'_>,
    id: String,
    file: EnvFile,
) -> AppResult<EnvFileStatus> {
    let files = Arc::clone(&files);
    blocking(&state, move |state| {
        let ctx = context(state);
        let file = state.vault.change(&app, &state.backup_dir, |vault| {
            Ok(vault.bind_env_file(&id, &file, &ctx)?)
        })?;
        let synced = files.sync(&app, state, None, true)?;
        status_of(synced, &id, &file)
    })
    .await
}

/// Stops writing an environment to `file`. With `delete_file`, the file
/// is deleted first, only if it holds exactly what the vault has.
#[tauri::command]
pub async fn envs_files_unbind(
    app: AppHandle,
    state: State<'_, Shared>,
    files: Files<'_>,
    id: String,
    file: EnvFile,
    delete_file: bool,
) -> AppResult<EnvDetail> {
    let files = Arc::clone(&files);
    blocking(&state, move |state| {
        let ctx = context(state);
        if delete_file {
            state
                .vault
                .with(&app, |vault| Ok(vault.delete_env_file(&id, &file, &ctx)?))?;
        }
        let detail = state.vault.change(&app, &state.backup_dir, |vault| {
            vault.unbind_env_file(&id, &file)?;
            Ok(vault.environment(&id)?)
        })?;
        files.request();
        Ok(detail)
    })
    .await
}

/// Keeps every file in step now.
#[tauri::command]
pub async fn envs_files_sync(
    app: AppHandle,
    state: State<'_, Shared>,
    files: Files<'_>,
) -> AppResult<EnvFilesSynced> {
    let files = Arc::clone(&files);
    blocking(&state, move |state| files.sync(&app, state, None, true)).await
}

/// Settles a file in conflict: `file` keeps the file's variables (they go
/// to the vault, with Undo), `vault` writes the vault's into the file,
/// which also writes a missing file again.
#[tauri::command]
pub async fn envs_files_resolve(
    app: AppHandle,
    state: State<'_, Shared>,
    files: Files<'_>,
    id: String,
    file: EnvFile,
    keep: KeepSide,
) -> AppResult<EnvFilesSynced> {
    let files = Arc::clone(&files);
    blocking(&state, move |state| {
        let prefer = Preference {
            env_id: &id,
            file: &file,
            keep,
        };
        files.sync(&app, state, Some(prefer), true)
    })
    .await
}

/// How an environment's variables (left) and its file's (right) differ,
/// by name, for the compare dialog.
#[tauri::command]
pub async fn envs_files_compare(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
    file: EnvFile,
) -> AppResult<EnvComparison> {
    blocking(&state, move |state| {
        let ctx = context(state);
        state
            .vault
            .with(&app, |vault| Ok(vault.compare_env_file(&id, &file, &ctx)?))
    })
    .await
}

/// Undoes an edit of a file that went to the vault, if nothing changed the
/// environment since; its files follow.
#[tauri::command]
pub async fn envs_files_undo(
    app: AppHandle,
    state: State<'_, Shared>,
    files: Files<'_>,
    undo: EnvUndo,
) -> AppResult<EnvDetail> {
    let files = Arc::clone(&files);
    blocking(&state, move |state| {
        state.vault.change(&app, &state.backup_dir, |vault| {
            vault.undo_env_file_change(&undo)?;
            Ok(vault.environment(&undo.env_id)?)
        })?;
        files.sync(&app, state, None, true)?;
        state
            .vault
            .with_quietly(&app, |vault| Ok(vault.environment(&undo.env_id)?))
    })
    .await
}

/// The management center: every file, or a project's, with its state, the
/// cloud service that copies it, the names its template has that the
/// environment lacks and whether Git would take it along; and the `.env`
/// files in the projects' folders that no environment is written to.
#[tauri::command]
pub async fn envs_files_overview(
    app: AppHandle,
    state: State<'_, Shared>,
    files: Files<'_>,
    project: Option<String>,
) -> AppResult<EnvFilesOverview> {
    let files = Arc::clone(&files);
    blocking(&state, move |state| {
        let ctx = context(state);
        let kept = files.state();
        let cloud = CloudRoots::detect(home_dir().as_deref());
        let mut overview = state.vault.with_quietly(&app, |vault| {
            Ok(vault.env_files_overview(&ctx, &kept, &cloud, project.as_deref()))
        })?;
        // Git runs once the vault is free again.
        for report in &mut overview.files {
            report.git = report.status.location.as_deref().map(git_state);
        }
        for file in &mut overview.unmanaged {
            file.git = Some(git_state(&file.location));
        }
        Ok(overview)
    })
    .await
}

/// Adds the line that ignores a bound file to the `.gitignore` at the top
/// of its Git working tree, after the user said to. Returns what Git says
/// of the file then.
#[tauri::command]
pub async fn envs_files_ignore(
    app: AppHandle,
    state: State<'_, Shared>,
    files: Files<'_>,
    id: String,
    file: EnvFile,
) -> AppResult<GitInfo> {
    let files = Arc::clone(&files);
    blocking(&state, move |state| {
        let ctx = context(state);
        let kept = files.state();
        let status = state.vault.with(&app, |vault| {
            let statuses = vault.env_files_status(&ctx, &kept);
            status_of(
                EnvFilesSynced {
                    files: statuses,
                    ..EnvFilesSynced::default()
                },
                &id,
                &file,
            )
        })?;
        let location = status
            .location
            .ok_or_else(|| AppError::invalid("the file's folder isn't on this computer"))?;
        let folder = location.parent().unwrap_or(&location);
        let repository = envs::git_work_tree(folder)
            .ok_or_else(|| AppError::invalid("the file isn't in a Git working tree"))?;
        managed::ignore_in_git(&repository, &location)?;
        Ok(git_state(&location))
    })
    .await
}

/// What a `.env` file found in a project's folder holds, without values,
/// before taking it under management.
#[tauri::command]
pub async fn envs_files_adopt_preview(
    app: AppHandle,
    state: State<'_, Shared>,
    project: String,
    file: EnvFile,
) -> AppResult<EnvImportPreview> {
    blocking(&state, move |state| {
        let ctx = context(state);
        let (path, parsed) = state.vault.with(&app, |vault| {
            Ok(vault.unmanaged_env_file(&project, &file, &ctx)?)
        })?;
        Ok(envs::preview_parsed(&path, parsed))
    })
    .await
}

/// Takes a `.env` file found in a project's folder under management: every
/// variable of it goes into `target` through the import (`choices` set
/// which are secret; one not named is secret if it looks so), the
/// project holds the environment's group, and the environment is written
/// to the file from then on. A new environment is local.
#[tauri::command]
pub async fn envs_files_adopt(
    app: AppHandle,
    state: State<'_, Shared>,
    files: Files<'_>,
    project: String,
    file: EnvFile,
    target: ImportTarget,
    choices: Vec<ImportChoice>,
) -> AppResult<EnvImported> {
    let files = Arc::clone(&files);
    blocking(&state, move |state| {
        let ctx = context(state);
        let (_, parsed) = state.vault.with(&app, |vault| {
            Ok(vault.unmanaged_env_file(&project, &file, &ctx)?)
        })?;
        let every: Vec<ImportChoice> = parsed
            .vars
            .iter()
            .map(|var| ImportChoice {
                name: var.name.clone(),
                secret: choices
                    .iter()
                    .find(|choice| choice.name == var.name)
                    .map_or_else(|| looks_secret(&var.name, &var.value), |c| c.secret),
            })
            .collect();
        let vars = envs::chosen_variables(parsed, &every);
        let imported = state.vault.change(&app, &state.backup_dir, |vault| {
            let id = match &target {
                ImportTarget::New {
                    project: group,
                    name,
                } => {
                    let id = vault.add_environment(&EnvInput {
                        project: group.clone(),
                        name: name.clone(),
                        notes: String::new(),
                    })?;
                    vault.set_env_kind(&id, EnvKind::Local)?;
                    id
                }
                ImportTarget::Existing { id } => id.clone(),
            };
            let group = vault.environment(&id)?.summary.project;
            if !vault.project(&project)?.environments.contains(&group) {
                vault.set_project_member(&project, &ProjectMember::Environment { group }, true)?;
            }
            let counts = vault.import_env_variables(&id, &vars)?;
            vault.bind_env_file(&id, &file, &ctx)?;
            Ok(EnvImported { id, counts })
        })?;
        // The vault holds the file's variables now, and perhaps more: the
        // file gets those too, keeping its own lines.
        let file = managed::check_env_file(&file)?;
        let prefer = Preference {
            env_id: &imported.id,
            file: &file,
            keep: KeepSide::Vault,
        };
        files.sync(&app, state, Some(prefer), true)?;
        Ok(imported)
    })
    .await
}

/// The state of the file a binding names, from a round's files.
fn status_of(synced: EnvFilesSynced, id: &str, file: &EnvFile) -> AppResult<EnvFileStatus> {
    let file = managed::check_env_file(file)?;
    synced
        .files
        .into_iter()
        .find(|status| status.env_id == id && status.file == file)
        .ok_or_else(|| AppError::not_found(file.path))
}

/// What Git makes of `path`: outside a working tree, ignored, untracked
/// (the next `git add .` takes it along) or committed already. Without
/// `git`, a working tree counts as not ignoring it.
pub(crate) fn git_state(path: &Path) -> GitInfo {
    let outside = GitInfo {
        state: GitState::Outside,
        repository: None,
    };
    let Some(folder) = path.parent() else {
        return outside;
    };
    let Some(repository) = envs::git_work_tree(folder) else {
        return outside;
    };
    let state = if tracked(path) {
        GitState::Tracked
    } else if unignored_in_git(path).is_some() {
        GitState::Untracked
    } else {
        GitState::Ignored
    };
    GitInfo {
        state,
        repository: Some(repository),
    }
}

/// Whether Git has the file committed (in its index).
fn tracked(path: &Path) -> bool {
    let (Some(folder), Some(name)) = (path.parent(), path.file_name()) else {
        return false;
    };
    let mut command = process::command("git");
    command
        .args(["-c", "core.fsmonitor=false", "-C"])
        .arg(folder)
        .args(["ls-files", "--error-unmatch", "--"])
        .arg(name);
    process::run_command(&mut command, None, Duration::from_secs(5))
        .is_ok_and(|output| output.code == Some(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_says_what_it_would_take_along() {
        if process::run("git", &["--version"], Duration::from_secs(5)).is_err() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        assert_eq!(git_state(&repo.join(".env")).state, GitState::Outside);
        let git = |args: &[&str]| {
            let mut all = vec!["-C", repo.to_str().unwrap()];
            all.extend(args);
            assert!(
                process::run("git", &all, Duration::from_secs(10))
                    .unwrap()
                    .success
            );
        };
        git(&["init", "-q"]);
        let repo = std::fs::canonicalize(&repo).unwrap();
        let env = repo.join(".env");
        std::fs::write(&env, "A=1\n").unwrap();
        assert_eq!(
            git_state(&env),
            GitInfo {
                state: GitState::Untracked,
                repository: Some(repo.clone()),
            }
        );
        managed::ignore_in_git(&repo, &env).unwrap();
        assert_eq!(git_state(&env).state, GitState::Ignored);
        // Committed before it was ignored: ignoring doesn't take it out.
        std::fs::write(repo.join(".env.local"), "A=1\n").unwrap();
        git(&["add", "-f", ".env.local"]);
        assert_eq!(git_state(&repo.join(".env.local")).state, GitState::Tracked);
    }
}
