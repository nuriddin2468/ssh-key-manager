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

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use sshkm_core::ErrorCode;
use sshkm_core::paths::home_dir;
use sshkm_core::vault::envs::files::{
    self as managed, CloudRoots, CloudService, EnvFile, EnvFileComparison, EnvFileReport,
    EnvFileStatus, EnvFilesOverview, EnvFilesSynced, EnvKind, EnvUndo, FileLevel, GitInfo,
    GitState, KeepSide, Preference,
};
use sshkm_core::vault::envs::{
    self, EnvDetail, EnvImportPreview, EnvInput, ImportChoice, PartRename, looks_secret,
};
use sshkm_core::vault::projects::{self, PartFolderChoice};
use tauri::{AppHandle, State};

use super::envs::{EnvImported, ImportTarget, unignored_in_git};
use super::{Shared, blocking};
use crate::env_files::{EnvFiles, context};
use crate::error::{AppError, AppResult};
use crate::process;

type Files<'a> = State<'a, Arc<EnvFiles>>;

/// What writing to a file would mean, before it is bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct EnvFileCheck {
    /// The binding as it would be kept.
    pub file: EnvFile,
    /// Where the file would be on this computer, when the project's folder
    /// is here.
    pub location: Option<PathBuf>,
    /// The file's own folder is here, so it is written at once; otherwise
    /// once that folder is made.
    pub folder_here: bool,
    /// What Git makes of it there, asked from the nearest folder on the way
    /// that is here; `None` when the project's folder isn't on this
    /// computer, so Git can't be asked.
    pub git: Option<GitInfo>,
    /// The cloud service that copies its folder, if one does and doesn't
    /// leave out a file at the level asked.
    pub cloud: Option<CloudService>,
}

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

/// Writes an environment to `file` from now on, at `level` (all the time,
/// or only while the vault is unlocked, the only level a remote one has),
/// and writes the file at once, or reports it as a conflict when it exists
/// with other values.
#[tauri::command]
pub async fn envs_files_bind(
    app: AppHandle,
    state: State<'_, Shared>,
    files: Files<'_>,
    id: String,
    file: EnvFile,
    level: FileLevel,
) -> AppResult<EnvFileStatus> {
    let files = Arc::clone(&files);
    blocking(&state, move |state| {
        let ctx = context(state);
        let file = state.vault.change(&app, &state.backup_dir, |vault| {
            Ok(vault.bind_env_file_at(&id, &file, level, &ctx)?)
        })?;
        // A folder whose AI tools' rules the user asked for gets its line.
        super::env_agents::follow_choice(&app, state, &file.folder);
        if level == FileLevel::Virtual {
            super::background::keep_running_for_virtual_files(&app);
        }
        let synced = files.sync(&app, state, None, true)?;
        status_of(synced, &id, &file)
    })
    .await
}

/// Writes a file of an environment at another level from now on: all the
/// time (the file is then left to backups and cloud folders again), or only
/// while the vault is unlocked (kept out of them, and removed when it
/// locks).
#[tauri::command]
pub async fn envs_files_set_level(
    app: AppHandle,
    state: State<'_, Shared>,
    files: Files<'_>,
    id: String,
    file: EnvFile,
    level: FileLevel,
) -> AppResult<EnvFileStatus> {
    let files = Arc::clone(&files);
    blocking(&state, move |state| {
        let file = managed::check_env_file(&file)?;
        state.vault.change(&app, &state.backup_dir, |vault| {
            Ok(vault.set_env_file_level(&id, &file, level)?)
        })?;
        if level == FileLevel::Virtual {
            super::background::keep_running_for_virtual_files(&app);
        }
        // The round puts the attributes on or takes them off, or makes the
        // pipe, or the file in its place.
        let synced = files.sync(&app, state, None, true)?;
        status_of(synced, &id, &file)
    })
    .await
}

/// Stops writing an environment to `file`. With `delete_file`, the file
/// is deleted first, only if it holds exactly what the vault has. Without,
/// a file kept only while the vault is unlocked stays from then on, as the
/// user's own. A virtual file's pipe goes either way: it holds nothing; a
/// regular file saved in its place is deleted only when asked, as any.
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
        let kept = files.state();
        let level = state.vault.with(&app, |vault| {
            Ok(vault
                .env_files_status(&ctx, &kept)
                .into_iter()
                .find(|status| status.env_id == id && status.file == file)
                .map(|status| (status.level, status.location)))
        })?;
        // A virtual file's place holds a regular file only when one was
        // saved over the pipe; the pipe itself goes with the binding.
        let deletable = match &level {
            Some((FileLevel::Virtual, location)) => location.as_deref().is_some_and(|path| {
                std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file())
            }),
            _ => true,
        };
        if delete_file && deletable {
            state
                .vault
                .with(&app, |vault| Ok(vault.delete_env_file(&id, &file, &ctx)?))?;
        }
        let unbind = || {
            state.vault.change(&app, &state.backup_dir, |vault| {
                vault.unbind_env_file(&id, &file)?;
                Ok(vault.environment(&id)?)
            })
        };
        let level_two = match level {
            Some((FileLevel::WhileUnlocked, location)) => location,
            _ => None,
        };
        let detail = match level_two {
            Some(location) if !delete_file => files.keep_file(&location, unbind)?,
            _ => unbind()?,
        };
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
/// which also writes a missing file again. `seen` is the revision the
/// compare dialog showed (`envs_files_compare`): a file that changed since
/// is left alone and the call fails with `conflict`, so nothing the user
/// didn't see is lost. A missing file needs none.
#[tauri::command]
pub async fn envs_files_resolve(
    app: AppHandle,
    state: State<'_, Shared>,
    files: Files<'_>,
    id: String,
    file: EnvFile,
    keep: KeepSide,
    seen: Option<String>,
) -> AppResult<EnvFilesSynced> {
    let files = Arc::clone(&files);
    blocking(&state, move |state| {
        let ctx = context(state);
        let now = state
            .vault
            .with(&app, |vault| Ok(vault.compare_env_file(&id, &file, &ctx)?))?
            .revision;
        if now.is_some() && now != seen {
            return Err(AppError::new(
                ErrorCode::Conflict,
                "the file changed since it was compared",
            ));
        }
        let prefer = Preference {
            env_id: &id,
            file: &file,
            keep,
            seen: seen.as_deref(),
        };
        files.sync(&app, state, Some(prefer), true)
    })
    .await
}

/// How an environment's variables (left) and one of its files' (right)
/// differ, by name, for the compare dialog, with the file's revision to
/// settle the conflict with.
#[tauri::command]
pub async fn envs_files_compare(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
    file: EnvFile,
) -> AppResult<EnvFileComparison> {
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
        let (mut overview, search) = state.vault.with_quietly(&app, |vault| {
            Ok((
                vault.env_files_overview(&ctx, &kept, &cloud, project.as_deref()),
                vault.unmanaged_search(&ctx, project.as_deref()),
            ))
        })?;
        // Folders are looked through and Git asked once the vault is free.
        (overview.unmanaged, overview.truncated) = search.run(&ctx, &cloud);
        for report in &mut overview.files {
            report.git = git_of(&report.status);
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

/// What writing an environment to `file` at `level` would mean, before it
/// is bound: where the file would be, whether Git would take it along and
/// whether a cloud service copies its folder. Checks the binding as binding
/// does.
#[tauri::command]
pub async fn envs_files_check(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
    file: EnvFile,
    level: FileLevel,
) -> AppResult<EnvFileCheck> {
    blocking(&state, move |state| {
        let ctx = context(state);
        let (file, located) = state.vault.with(&app, |vault| {
            Ok(vault.check_env_file_binding(&id, &file, level, &ctx)?)
        })?;
        let cloud = CloudRoots::detect(home_dir().as_deref());
        let folder_here = located.is_some();
        // A folder on the way that isn't made yet: Git is asked from the
        // nearest one that is, inside the project's folder.
        let project = projects::folder_path(&file.folder, ctx.home.as_deref())
            .filter(|folder| folder.is_dir());
        let location = located.or_else(|| {
            let mut path = project.clone()?;
            path.extend(file.path.split('/'));
            Some(path)
        });
        let git = match (&location, folder_here) {
            (Some(path), true) => Some(git_state(path)),
            (Some(path), false) => project.as_deref().map(|root| planned_git_state(root, path)),
            (None, _) => None,
        };
        Ok(EnvFileCheck {
            cloud: location
                .as_deref()
                .and_then(|path| cloud.copies(path, level)),
            git,
            folder_here,
            location,
            file,
        })
    })
    .await
}

/// The files of one environment (`id`) or of every one, with Git and cloud
/// folders looked at, without looking through the projects' folders for
/// others: for the Environments pane.
#[tauri::command]
pub async fn envs_files_risks(
    app: AppHandle,
    state: State<'_, Shared>,
    files: Files<'_>,
    id: Option<String>,
) -> AppResult<Vec<EnvFileReport>> {
    let files = Arc::clone(&files);
    blocking(&state, move |state| {
        let ctx = context(state);
        let kept = files.state();
        let cloud = CloudRoots::detect(home_dir().as_deref());
        let mut reports = state.vault.with_quietly(&app, |vault| {
            Ok(vault.env_files_overview(&ctx, &kept, &cloud, None).files)
        })?;
        reports.retain(|report| id.as_ref().is_none_or(|id| report.status.env_id == *id));
        for report in &mut reports {
            report.git = git_of(&report.status);
        }
        Ok(reports)
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
/// project has the environment, and the environment is written to the
/// file from then on. A new environment is local. `rename` names the part
/// the project had, when this gives it a second (in the same change), and
/// `folder` the folder of its part, when the dialog chose one.
#[tauri::command]
#[expect(
    clippy::too_many_arguments,
    reason = "Tauri passes command arguments one by one"
)]
pub async fn envs_files_adopt(
    app: AppHandle,
    state: State<'_, Shared>,
    files: Files<'_>,
    project: String,
    file: EnvFile,
    target: ImportTarget,
    choices: Vec<ImportChoice>,
    rename: Option<PartRename>,
    folder: Option<PartFolderChoice>,
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
            vault.name_first_part(rename.as_ref())?;
            let id = match &target {
                // In the project whose folder has the file.
                ImportTarget::New {
                    part, name, notes, ..
                } => {
                    let id = vault.add_environment(&EnvInput {
                        project: Some(project.clone()),
                        part: part.clone(),
                        name: name.clone(),
                        notes: notes.clone().unwrap_or_default(),
                    })?;
                    vault.set_env_kind(&id, EnvKind::Local)?;
                    id
                }
                ImportTarget::Existing { id } => {
                    take_into(vault, &project, id)?;
                    id.clone()
                }
            };
            let counts = vault.import_env_variables(&id, &vars)?;
            vault.bind_env_file(&id, &file, &ctx)?;
            super::projects::apply_folder_choice(vault, &id, folder.as_ref())?;
            Ok(EnvImported { id, counts })
        })?;
        // A folder whose AI tools' rules the user asked for gets its line.
        super::env_agents::follow_choice(&app, state, &file.folder);
        // The vault holds the file's variables now, and perhaps more: the
        // file gets those too, keeping its own lines, unless it changed
        // since it was read.
        let file = managed::check_env_file(&file)?;
        let seen = state
            .vault
            .with(&app, |vault| {
                Ok(vault.compare_env_file(&imported.id, &file, &ctx)?)
            })?
            .revision;
        let prefer = Preference {
            env_id: &imported.id,
            file: &file,
            keep: KeepSide::Vault,
            seen: seen.as_deref(),
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

/// What Git makes of a bound file, when its folder is here; nothing for a
/// virtual file: Git never takes a pipe along, so there is nothing to ask.
fn git_of(status: &EnvFileStatus) -> Option<GitInfo> {
    if status.level == FileLevel::Virtual {
        return None;
    }
    status.location.as_deref().map(git_state)
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
    if !folder.is_dir() {
        // A binding waiting for its folder: Git can't be asked from there.
        return planned_git_state(&repository, path);
    }
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

/// What Git would make of `path`, a file whose folder isn't made yet,
/// inside the project folder `root`: asked from the nearest folder on the
/// way that exists. A file not there yet can't be committed already.
pub(crate) fn planned_git_state(root: &Path, path: &Path) -> GitInfo {
    let outside = GitInfo {
        state: GitState::Outside,
        repository: None,
    };
    let Some(nearest) = path
        .ancestors()
        .skip(1)
        .take_while(|folder| folder.starts_with(root))
        .find(|folder| folder.is_dir())
    else {
        return outside;
    };
    let Some(repository) = envs::git_work_tree(nearest) else {
        return outside;
    };
    let Ok(rest) = path.strip_prefix(nearest) else {
        return outside;
    };
    let ignored = process::git(nearest).is_some_and(|mut command| {
        command.args(["check-ignore", "-q", "--"]).arg(rest);
        process::run_command(&mut command, None, Duration::from_secs(5))
            .is_ok_and(|output| output.code == Some(0))
    });
    GitInfo {
        state: if ignored {
            GitState::Ignored
        } else {
            GitState::Untracked
        },
        repository: Some(repository),
    }
}

/// Whether Git has the file committed (in its index).
fn tracked(path: &Path) -> bool {
    let (Some(folder), Some(name)) = (path.parent(), path.file_name()) else {
        return false;
    };
    let Some(mut command) = process::git(folder) else {
        return false;
    };
    command
        .args(["ls-files", "--error-unmatch", "--"])
        .arg(name);
    process::run_command(&mut command, None, Duration::from_secs(5))
        .is_ok_and(|output| output.code == Some(0))
}

/// Puts the existing environment a file is taken under management into in
/// `project`, whose folder has the file: its files are written while the
/// project that has it holds their folder. One of Personal's comes in; one
/// another project has is refused, since its own files there would stop
/// being written without a word (Move to project… says so first).
fn take_into(vault: &mut sshkm_core::vault::Vault, project: &str, id: &str) -> AppResult<()> {
    match vault.environment(id)?.summary.project.as_deref() {
        Some(owner) if owner == project => Ok(()),
        Some(_) => Err(AppError::invalid(
            "the environment is in another project: move it to this one first",
        )),
        None => {
            vault.move_environment(id, Some(project))?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_goes_into_this_projects_environment_or_personals_not_anothers() {
        use sshkm_core::vault::projects::{ProjectColor, ProjectInput};
        use sshkm_core::vault::{Vault, VaultPaths};
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("vault.kdbx"));
        let (mut vault, _) =
            Vault::create(&paths, &sshkm_core::SecretString::from("master")).unwrap();
        let project = |vault: &mut Vault, name: &str| {
            vault
                .add_project(&ProjectInput {
                    name: name.into(),
                    color: ProjectColor::Blue,
                })
                .unwrap()
        };
        let shop = project(&mut vault, "Shop");
        let blog = project(&mut vault, "Blog");
        let env = |vault: &mut Vault, project: Option<&str>, name: &str| {
            vault
                .add_environment(&EnvInput {
                    project: project.map(str::to_owned),
                    part: String::new(),
                    name: name.into(),
                    notes: String::new(),
                })
                .unwrap()
        };
        let mine = env(&mut vault, None, "local");
        let shops = env(&mut vault, Some(&shop), "dev");
        let blogs = env(&mut vault, Some(&blog), "dev");
        take_into(&mut vault, &shop, &shops).unwrap();
        take_into(&mut vault, &shop, &mine).unwrap();
        let owner = |vault: &Vault, id: &str| vault.environment(id).unwrap().summary.project;
        assert_eq!(owner(&vault, &mine).as_deref(), Some(shop.as_str()));
        let refused = take_into(&mut vault, &shop, &blogs).unwrap_err();
        assert!(matches!(
            refused,
            AppError::App {
                code: ErrorCode::InvalidInput,
                ..
            }
        ));
        assert_eq!(owner(&vault, &blogs).as_deref(), Some(blog.as_str()));
    }

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

        // A file whose folders aren't made yet is asked from the nearest one.
        let planned = repo.join("apps").join("web").join(".env");
        assert_eq!(
            planned_git_state(&repo, &planned),
            GitInfo {
                state: GitState::Untracked,
                repository: Some(repo.clone()),
            }
        );
        std::fs::write(repo.join(".gitignore"), "/.env\n.env\n").unwrap();
        assert_eq!(planned_git_state(&repo, &planned).state, GitState::Ignored);
        // Ignored before its folder is made, as Add file… offers.
        let waiting = repo.join("services").join("api").join(".env.local");
        assert_eq!(git_state(&waiting).state, GitState::Untracked);
        managed::ignore_in_git(&repo, &waiting).unwrap();
        assert_eq!(
            git_state(&waiting),
            GitInfo {
                state: GitState::Ignored,
                repository: Some(repo.clone()),
            }
        );
        std::fs::create_dir_all(waiting.parent().unwrap()).unwrap();
        std::fs::write(&waiting, "A=1\n").unwrap();
        assert_eq!(git_state(&waiting).state, GitState::Ignored);
        let elsewhere = dir.path().join("plain");
        std::fs::create_dir(&elsewhere).unwrap();
        assert_eq!(
            planned_git_state(&elsewhere, &elsewhere.join("a").join(".env")).state,
            GitState::Outside
        );
    }
}
