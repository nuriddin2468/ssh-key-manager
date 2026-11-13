//! Projects (see `sshkm_core::vault::projects`): labels kept in the vault
//! that tie hosts, keys, logins, environments and folders together.
//!
//! While the vault is locked, the list comes from the copy without secrets
//! the vault runtime keeps ([`crate::vault::VaultRuntime::projects_copy`]),
//! so projects still show next to the SSH sections; changing one needs the
//! vault. A folder joins a project only from the system folder dialog this
//! side opens ([`projects_add_folder`]) or from a suggestion this side made
//! ([`projects_accept_suggestion`]), never by a path the page names.
//!
//! Suggestions (`sshkm_core::vault::projects::suggest`) change nothing by
//! themselves: the user accepts or dismisses each one.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use serde::{Deserialize, Serialize};
use sshkm_core::config::{HostEntry, HostKind, SshConfig};
use sshkm_core::hosts_file::{self, HostsAddressKind, HostsFile};
use sshkm_core::paths::home_dir;
use sshkm_core::vault::envs::PartRename;
use sshkm_core::vault::projects::suggest::{self, Declined, HostFacts, ProjectSuggestion};
use sshkm_core::vault::projects::{
    self, FolderPlace, PartFolderChoice, Project, ProjectFolder, ProjectInput, ProjectMember,
    places,
};
use sshkm_core::{ErrorCode, fsutil, keys};
use tauri::ipc::{Channel, InvokeResponseBody};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::DialogExt;

use super::{Shared, blocking};
use crate::confirm::Localized;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::terminal::Sink;
use crate::terminal::shells;
use crate::terminal::types::TerminalInfo;

/// Emitted when a sync with one of the user's devices changed the projects.
pub const CHANGED_EVENT: &str = "projects-changed";

/// The projects, by name: from the vault, or while it is locked from the
/// copy kept for then, whose projects have no logins. Quiet: the UI
/// refetches the list by itself.
#[tauri::command]
pub async fn projects_list(app: AppHandle, state: State<'_, Shared>) -> AppResult<Vec<Project>> {
    blocking(&state, move |state| {
        apply_pending_renames(&app, state);
        tidy_projects(&app, state);
        let projects = if state.vault.is_unlocked() {
            match state.vault.with_quietly(&app, |vault| Ok(vault.projects())) {
                Err(error) if error.code() == ErrorCode::VaultLocked => state.vault.projects_copy(),
                other => other?,
            }
        } else {
            state.vault.projects_copy()
        };
        Ok(projects)
    })
    .await
}

/// How long [`projects_missing_folders`] waits for the file system: a
/// network mount that doesn't answer must not hold the page.
const FOLDER_CHECK: std::time::Duration = std::time::Duration::from_secs(2);

/// The project's folders not found on this computer. A folder whose check
/// doesn't finish within [`FOLDER_CHECK`] counts as there: unknown is not
/// missing.
#[tauri::command]
pub async fn projects_missing_folders(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
) -> AppResult<Vec<String>> {
    blocking(&state, move |state| {
        let folders = match state
            .vault
            .with_quietly(&app, |vault| Ok(vault.project(&id)?.folders))
        {
            Err(error) if error.code() == ErrorCode::VaultLocked => state
                .vault
                .projects_copy()
                .into_iter()
                .find(|p| p.id == id)
                .map(|p| p.folders)
                .unwrap_or_default(),
            other => other?,
        };
        let home = home_dir();
        let gone = missing_dirs(
            folders
                .iter()
                .map(|folder| projects::folder_path(folder, home.as_deref()))
                .collect(),
        );
        Ok(folders
            .into_iter()
            .enumerate()
            .filter(|(index, _)| gone.contains(index))
            .map(|(_, folder)| folder)
            .collect())
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

/// Puts an item into a project or takes it out. A folder goes in from
/// [`projects_add_folder`]; here only one the project held comes back.
#[tauri::command]
pub async fn projects_set_member(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
    member: ProjectMember,
    included: bool,
) -> AppResult<Project> {
    blocking(&state, move |state| {
        state.vault.change(&app, &state.backup_dir, |vault| {
            // A folder goes in from the folder dialog; here only one the
            // project held already comes back (an Undo).
            if included
                && matches!(member, ProjectMember::Folder { .. })
                && !vault.project_has_held(&id, &member)?
            {
                return Err(AppError::invalid("choose the folder in the folder dialog"));
            }
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
        let title = Localized::new(
            format!("Add a folder to {name}"),
            format!("Добавить папку в {name}"),
            format!("{name} loyihasiga papka qo‘shish"),
        );
        let Some(folder) = pick_folder(&app, title.pick(), None)? else {
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

/// Asks for a folder in a system dialog, opened in `start` or the home
/// folder.
fn pick_folder(app: &AppHandle, title: &str, start: Option<PathBuf>) -> AppResult<Option<PathBuf>> {
    let mut dialog = app.dialog().file().set_title(title);
    if let Some(start) = start.or_else(home_dir) {
        dialog = dialog.set_directory(start);
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

/// What the user said about suggestions on this computer: what they
/// turned down, and the folders they asked to look into for Git working
/// trees besides the usual code folders.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct SuggestionPrefs {
    declined: Declined,
    folders: Vec<PathBuf>,
}

const PREFS_FILE: &str = "project-suggestions.json";
/// Most folders kept to look into.
const MAX_FOLDERS: usize = 100;

/// The suggestions made last, and the vault they were made for: the only
/// ones [`projects_accept_suggestion`] takes, so the folders it adds are
/// ones this side found.
static OFFERED: Mutex<(String, Vec<ProjectSuggestion>)> = Mutex::new((String::new(), Vec::new()));

fn offered() -> MutexGuard<'static, (String, Vec<ProjectSuggestion>)> {
    OFFERED.lock().unwrap_or_else(PoisonError::into_inner)
}

fn prefs_path(state: &AppState) -> PathBuf {
    state.vault.data_dir().join(PREFS_FILE)
}

fn load_prefs(state: &AppState) -> SuggestionPrefs {
    std::fs::read(prefs_path(state))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn save_prefs(state: &AppState, prefs: &SuggestionPrefs) -> AppResult<()> {
    let json = serde_json::to_vec_pretty(prefs)
        .map_err(|e| AppError::invalid(format!("suggestion settings: {e}")))?;
    Ok(fsutil::atomic_write(&prefs_path(state), &json, 0o600)?)
}

/// The hosts of `~/.ssh/config` as suggestions see them: each alias of a
/// `Host` block that isn't a pattern, with the fingerprints of the keys its
/// `IdentityFile`s name.
fn host_facts(state: &AppState) -> AppResult<Vec<HostFacts>> {
    let config = SshConfig::load(&state.paths.config)?;
    let fingerprints: Vec<(String, String)> = keys::scan(&state.paths.dir)?
        .keys
        .into_iter()
        .filter_map(|key| Some((key.private_path?, key.fingerprint?)))
        .collect();
    let usage = config.identity_usage(&state.paths);
    let mut facts = Vec::new();
    for host in config.hosts() {
        if host.kind != HostKind::Host || host.is_wildcard {
            continue;
        }
        let keys: Vec<String> = usage
            .iter()
            .filter(|u| u.host_id == Some(host.id) && u.resolved)
            .filter_map(|u| {
                fingerprints
                    .iter()
                    .find(|(path, _)| *path == u.path)
                    .map(|(_, fingerprint)| fingerprint.clone())
            })
            .collect();
        // One server is one host, whatever names its block gives it: the
        // first is what people type.
        if let Some(alias) = host.patterns.iter().find(|p| !p.starts_with('!')) {
            facts.push(HostFacts {
                alias: alias.clone(),
                host_name: host.host_name.clone(),
                proxy_jump: host.proxy_jump.clone(),
                keys,
            });
        }
    }
    Ok(facts)
}

/// Where to look for Git working trees: the usual code folders in the home
/// folder that exist, and those the user added.
fn code_roots(prefs: &SuggestionPrefs) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = home_dir()
        .map(|home| {
            suggest::CODE_FOLDERS
                .iter()
                .map(|folder| home.join(folder))
                .filter(|path| path.is_dir())
                .collect()
        })
        .unwrap_or_default();
    for folder in &prefs.folders {
        if folder.is_dir() && !roots.contains(folder) {
            roots.push(folder.clone());
        }
    }
    roots
}

/// The hosts file's names suggestions look at: not the operating system's
/// own, nor blocked ones (block lists hold thousands). None when it can't
/// be read.
fn hosts_file_names(state: &AppState) -> Vec<String> {
    let Ok(file) = HostsFile::load(&state.hosts_file) else {
        return Vec::new();
    };
    member_names(&file)
}

/// The hosts file's names a project can hold: not blocked ones, and none
/// from a line that lists a system name (`127.0.0.1 localhost app.test`),
/// which the app can't turn on or off.
fn member_names(file: &HostsFile) -> Vec<String> {
    let names: BTreeSet<String> = file
        .entries()
        .into_iter()
        .filter(|entry| entry.kind != HostsAddressKind::Blocked)
        .filter(|entry| {
            !entry
                .names
                .iter()
                .any(|name| hosts_file::is_system_name(name))
        })
        .flat_map(|entry| entry.names)
        .filter_map(|name| projects::hosts_file_name(&name))
        .collect();
    names.into_iter().collect()
}

fn suggestions(app: &AppHandle, state: &AppState) -> AppResult<Vec<ProjectSuggestion>> {
    // Nothing is read on disk while the vault is locked.
    let vault_id = state
        .vault
        .with_quietly(app, |vault| Ok(vault.vault_id().to_owned()))?;
    let prefs = load_prefs(state);
    let hosts = host_facts(state)?;
    let hosts_file = hosts_file_names(state);
    let repositories = suggest::find_repositories(&code_roots(&prefs));
    // The working trees come by their real paths; so does the home folder.
    let home = home_dir().map(|home| suggest::canonical(&home).unwrap_or(home));
    let found = state.vault.with_quietly(app, |vault| {
        let projects = vault.projects();
        let environments = vault.suggestion_environments();
        let logins = vault.suggestion_logins();
        Ok(suggest::suggest(
            &suggest::Sources {
                hosts: &hosts,
                environments: &environments,
                logins: &logins,
                repositories: &repositories,
                projects: &projects,
                home: home.as_deref(),
                hosts_file: &hosts_file,
            },
            &prefs.declined,
        ))
    })?;
    *offered() = (vault_id, found.clone());
    Ok(found)
}

/// Projects the app proposes from environments, Git working trees in the
/// usual code folders (only their `.git/config` is read), `~/.ssh/config`
/// and the vault's KeePass groups and tags. Nothing changes until the user
/// accepts one. Needs the vault: projects live in it.
#[tauri::command]
pub async fn projects_suggestions(
    app: AppHandle,
    state: State<'_, Shared>,
) -> AppResult<Vec<ProjectSuggestion>> {
    blocking(&state, move |state| suggestions(&app, state)).await
}

/// Makes the suggestion `key` a project named and colored as `input`, or
/// adds to the existing project it names, with the `members` the user kept.
/// Members that weren't in the suggestion are refused; those the user left
/// out aren't suggested again. `rename` names the part the existing project
/// had, when the environments kept give it a second (in the same change).
#[tauri::command]
pub async fn projects_accept_suggestion(
    app: AppHandle,
    state: State<'_, Shared>,
    key: String,
    input: ProjectInput,
    members: Vec<ProjectMember>,
    rename: Option<PartRename>,
) -> AppResult<Project> {
    blocking(&state, move |state| {
        let (for_vault, suggestion) = {
            let offered = offered();
            let found = offered.1.iter().find(|s| s.key == key).cloned();
            (offered.0.clone(), found)
        };
        let suggestion = suggestion
            .ok_or_else(|| AppError::not_found("the suggestion; look for suggestions again"))?;
        let project = state.vault.change(&app, &state.backup_dir, |vault| {
            if vault.vault_id() != for_vault {
                return Err(AppError::not_found(
                    "the suggestion; look for suggestions again",
                ));
            }
            // Every member is checked before anything changes; a failure
            // after that is undone with the rest of the change.
            vault.name_first_part(rename.as_ref())?;
            let id = vault.accept_suggestion(&suggestion, &input, &members)?;
            Ok(vault.project(&id)?)
        })?;
        offered().1.retain(|s| s.key != key);
        let mut prefs = load_prefs(state);
        let before = prefs.declined.clone();
        prefs.declined.left_out(&suggestion, &members);
        if prefs.declined != before {
            save_prefs(state, &prefs)?;
        }
        Ok(project)
    })
    .await
}

/// Stops suggesting `key` on this computer.
#[tauri::command]
pub async fn projects_dismiss_suggestion(state: State<'_, Shared>, key: String) -> AppResult<()> {
    blocking(&state, move |state| {
        let mut prefs = load_prefs(state);
        if prefs.declined.dismiss(&key) {
            save_prefs(state, &prefs)?;
        }
        offered().1.retain(|s| s.key != key);
        Ok(())
    })
    .await
}

/// Suggests again what was turned down on this computer.
#[tauri::command]
pub async fn projects_restore_suggestions(state: State<'_, Shared>) -> AppResult<()> {
    blocking(&state, move |state| {
        let mut prefs = load_prefs(state);
        if prefs.declined != Declined::default() {
            prefs.declined = Declined::default();
            save_prefs(state, &prefs)?;
        }
        Ok(())
    })
    .await
}

/// Asks for a folder in a system dialog to look into for Git working trees
/// from now on, and returns the suggestions with it; `None` when the dialog
/// was cancelled.
#[tauri::command]
pub async fn projects_suggest_in_folder(
    app: AppHandle,
    state: State<'_, Shared>,
) -> AppResult<Option<Vec<ProjectSuggestion>>> {
    blocking(&state, move |state| {
        // No dialog while the vault is locked.
        state.vault.with(&app, |_| Ok(()))?;
        let title = Localized::new(
            "Choose a folder with your code",
            "Выберите папку с вашим кодом",
            "Kodingiz joylashgan papkani tanlang",
        );
        let Some(folder) = pick_folder(&app, title.pick(), None)? else {
            return Ok(None);
        };
        let mut prefs = load_prefs(state);
        if !prefs.folders.contains(&folder) && prefs.folders.len() < MAX_FOLDERS {
            prefs.folders.push(folder);
            save_prefs(state, &prefs)?;
        }
        suggestions(&app, state).map(Some)
    })
    .await
}

/// Where the project's parts work (`sshkm_core::vault::projects::places`):
/// each of its folders, and the folders in them where parts work, with what
/// a terminal there gets. Those this computer doesn't have are marked. While
/// the vault is locked, from the copy kept for then: the folders the user
/// set for parts, without environments. Quiet: the page asks often.
#[tauri::command]
pub async fn projects_places(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
) -> AppResult<Vec<FolderPlace>> {
    blocking(&state, move |state| {
        let opened = state
            .vault
            .with_quietly(&app, |vault| Ok(vault.project_places(&id)?));
        let mut places = match opened {
            Err(error) if error.code() == ErrorCode::VaultLocked => {
                let project = copied(state, &id)?;
                places::places(&project, None, &BTreeMap::new())
            }
            other => other?,
        };
        let home = home_dir();
        let paths = places
            .iter()
            .map(|place| place_path_text(&place.folder, &place.path, home.as_deref()))
            .collect();
        for index in missing_dirs(paths) {
            if let Some(place) = places.get_mut(index) {
                place.missing = true;
            }
        }
        Ok(places)
    })
    .await
}

/// Sets the folder a part of the project's environments works in (`part`,
/// empty for its one unnamed part): one of the project's folders, or a
/// folder in it, found on this computer and not leading out of it through a
/// symbolic link. `None` goes back to where it works by itself: where its
/// local environment's `.env` file is, else the project's first folder.
#[tauri::command]
pub async fn projects_set_part_folder(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
    part: String,
    folder: Option<ProjectFolder>,
) -> AppResult<Project> {
    blocking(&state, move |state| {
        state.vault.change(&app, &state.backup_dir, |vault| {
            if let Some(folder) = &folder {
                place_path(&vault.project(&id)?, folder, home_dir().as_deref())?;
            }
            vault.set_part_folder(&id, &part, folder.as_ref())?;
            Ok(vault.project(&id)?)
        })
    })
    .await
}

/// Asks for a folder in a system dialog, opened in the project's first
/// folder found here, and returns it as a folder of the project or a folder
/// in one: for the page to offer as a part's folder. `None` when the dialog
/// was cancelled; refused when the folder isn't in one of the project's.
#[tauri::command]
pub async fn projects_pick_part_folder(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
) -> AppResult<Option<ProjectFolder>> {
    blocking(&state, move |state| {
        // No dialog while the vault is locked, or for a project that's gone.
        let project = state.vault.with(&app, |vault| Ok(vault.project(&id)?))?;
        let home = home_dir();
        let start = project
            .folders
            .iter()
            .filter_map(|folder| projects::folder_path(folder, home.as_deref()))
            .find(|path| path.is_dir());
        let title = Localized::new(
            format!("Choose a folder in {}", project.name),
            format!("Выберите папку в проекте {}", project.name),
            format!("{} loyihasidagi papkani tanlang", project.name),
        );
        let Some(picked) = pick_folder(&app, title.pick(), start)? else {
            return Ok(None);
        };
        let folder = folder_in_project(&project, &picked, home.as_deref())?;
        place_path(&project, &folder, home.as_deref())?;
        Ok(Some(folder))
    })
    .await
}

/// Starts a shell in one of a project's folders, or a folder in one where
/// parts of its environments work, as `terminal_open_local` does: `shell`
/// or the default one, in a `cols`×`rows` terminal. `folder` is the folder
/// as the project keeps it and `path` one in it (empty for the folder
/// itself), as the project's places name them; nothing else opens. The
/// shell gets the variables of `env`, which must be one of those the place
/// offers a terminal (a local one), or none; its secret values go in only
/// once the user said yes in a native dialog
/// ([`crate::secret_gate::confirm_env_secrets`]). While the vault is locked the
/// project comes from the copy kept for then, and the shell gets none.
#[tauri::command]
#[expect(
    clippy::too_many_arguments,
    reason = "Tauri passes command arguments one by one"
)]
pub async fn projects_open_terminal(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
    folder: String,
    path: Option<String>,
    env: Option<String>,
    shell: Option<String>,
    cols: u16,
    rows: u16,
    events: Channel<InvokeResponseBody>,
) -> AppResult<TerminalInfo> {
    let shared = Arc::clone(&state);
    let place = ProjectFolder {
        folder,
        path: path.unwrap_or_default(),
    };
    blocking(&state, move |state| {
        // The shell gets the variables as the dialog showed them, not as
        // they may be after.
        let approved = match &env {
            Some(env) => crate::secret_gate::confirm_shell_env(&app, state, env)?,
            None => Vec::new(),
        };
        let opened = state.vault.with(&app, |vault| {
            let project = vault.project(&id)?;
            let places = vault.project_places(&id)?;
            if let Some(env) = &env
                && !find_place(&places, &place)?.terminal.contains(env)
            {
                return Err(AppError::invalid(
                    "not an environment for a terminal in this folder",
                ));
            }
            Ok((project, places, approved))
        });
        let (project, places, vars) = match opened {
            // Asked for variables: none while locked would be a surprise.
            Err(error) if error.code() == ErrorCode::VaultLocked && env.is_none() => {
                let project = copied(state, &id)?;
                let places = places::places(&project, None, &BTreeMap::new());
                (project, places, Vec::new())
            }
            other => other?,
        };
        find_place(&places, &place)?;
        let path = place_path(&project, &place, home_dir().as_deref())?;
        let name = path.file_name().map_or_else(
            || place.folder.clone(),
            |n| n.to_string_lossy().into_owned(),
        );
        let shell = shells::find(shell.as_deref())?;
        let sink: Arc<dyn Sink> = Arc::new(events);
        shared.terminals.open_local(
            &format!("{} · {name}", project.name),
            &shell,
            &vars,
            &path,
            (cols, rows),
            sink,
        )
    })
    .await
}

/// Shows one of the project's folders, or a folder in one where parts of
/// its environments work, in the file manager (Finder, Explorer, Files). As
/// for its terminal, the page names the project and the place as the
/// project's places name it; only one of those that this computer has is
/// shown, never a path the page made up.
#[tauri::command]
pub async fn projects_reveal_folder(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
    folder: String,
    path: Option<String>,
) -> AppResult<()> {
    let place = ProjectFolder {
        folder,
        path: path.unwrap_or_default(),
    };
    blocking(&state, move |state| {
        let opened = state.vault.with(&app, |vault| {
            Ok((vault.project(&id)?, vault.project_places(&id)?))
        });
        let (project, places) = match opened {
            Err(error) if error.code() == ErrorCode::VaultLocked => {
                let project = copied(state, &id)?;
                let places = places::places(&project, None, &BTreeMap::new());
                (project, places)
            }
            other => other?,
        };
        find_place(&places, &place)?;
        let path = place_path(&project, &place, home_dir().as_deref())?;
        tauri_plugin_opener::reveal_item_in_dir(&path)
            .map_err(|error| AppError::new(ErrorCode::Io, error.to_string()))
    })
    .await
}

/// Sets the folder of the part the environment `env` is in, as a dialog
/// that made or edited it chose (`None` leaves it): one of its project's
/// folders, or one in it found here ([`place_path`]), or back to automatic.
/// An environment in Personal has no folder.
pub(crate) fn apply_folder_choice(
    vault: &mut sshkm_core::vault::Vault,
    env: &str,
    choice: Option<&PartFolderChoice>,
) -> AppResult<()> {
    let Some(choice) = choice else {
        return Ok(());
    };
    let summary = vault.environment(env)?.summary;
    let Some(project) = summary.project else {
        return Err(AppError::invalid(
            "an environment in Personal has no folder",
        ));
    };
    let place = choice.place();
    if let Some(place) = &place {
        place_path(&vault.project(&project)?, place, home_dir().as_deref())?;
    }
    vault.set_part_folder(&project, &summary.part, place.as_ref())?;
    Ok(())
}

/// The project from the copy kept for while the vault is locked.
fn copied(state: &AppState, id: &str) -> AppResult<Project> {
    state
        .vault
        .projects_copy()
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| AppError::not_found(format!("project {id}")))
}

/// The place `wanted` names among a project's places: one of its folders,
/// or a folder in one where parts work.
fn find_place<'a>(places: &'a [FolderPlace], wanted: &ProjectFolder) -> AppResult<&'a FolderPlace> {
    places
        .iter()
        .find(|place| place.folder == wanted.folder && place.path == wanted.path)
        .ok_or_else(|| AppError::invalid("not one of the project's folders"))
}

/// The folder `place` names on this computer: one of the project's folders,
/// found here, or a folder in it that is found here and stays inside it
/// (no symbolic link leads out). A folder in it comes back as it was
/// checked, with links resolved, so one changed after the check can't
/// lead elsewhere.
pub(crate) fn place_path(
    project: &Project,
    place: &ProjectFolder,
    home: Option<&Path>,
) -> AppResult<PathBuf> {
    let root = terminal_folder(project, &place.folder, home)?;
    let path = places::check_path(&place.path)?;
    if path.is_empty() {
        return Ok(root);
    }
    let target = path
        .split('/')
        .fold(root.clone(), |dir, name| dir.join(name));
    let gone = || AppError::not_found(format!("{}/{path} on this computer", place.folder));
    let (real_root, real) = (
        root.canonicalize().map_err(|_| gone())?,
        target.canonicalize().map_err(|_| gone())?,
    );
    if !real.starts_with(&real_root) {
        return Err(AppError::invalid(
            "the folder leads out of the project's folder",
        ));
    }
    if !real.is_dir() {
        return Err(gone());
    }
    Ok(fsutil::without_verbatim_prefix(real))
}

/// Where `place` would be on this computer, without checking it: for
/// telling whether it is here.
fn place_path_text(folder: &str, path: &str, home: Option<&Path>) -> Option<PathBuf> {
    let root = projects::folder_path(folder, home)?;
    let path = places::check_path(path).ok()?;
    Some(
        path.split('/')
            .filter(|name| !name.is_empty())
            .fold(root, |dir, name| dir.join(name)),
    )
}

/// `picked` (from the folder dialog) as one of the project's folders, or a
/// folder in one: in the deepest of them that holds it, compared as they
/// are on disk.
fn folder_in_project(
    project: &Project,
    picked: &Path,
    home: Option<&Path>,
) -> AppResult<ProjectFolder> {
    let real = picked
        .canonicalize()
        .map_err(|_| AppError::not_found(format!("{}", picked.display())))?;
    project
        .folders
        .iter()
        .filter_map(|folder| {
            let root = projects::folder_path(folder, home)?.canonicalize().ok()?;
            let rest = real.strip_prefix(&root).ok()?;
            let names: Option<Vec<&str>> =
                rest.components().map(|c| c.as_os_str().to_str()).collect();
            let path = places::check_path(&names?.join("/")).ok()?;
            Some((root.components().count(), folder, path))
        })
        .max_by_key(|(depth, _, _)| *depth)
        .map(|(_, folder, path)| ProjectFolder {
            folder: folder.clone(),
            path,
        })
        .ok_or_else(|| AppError::invalid("choose a folder inside one of the project's folders"))
}

/// Which of `paths` this computer doesn't have as folders, by index; one
/// that isn't a path here counts as missing. A check that doesn't finish
/// within [`FOLDER_CHECK`] counts as there: unknown is not missing.
fn missing_dirs(paths: Vec<Option<PathBuf>>) -> BTreeSet<usize> {
    let (tx, rx) = std::sync::mpsc::channel();
    let count = paths.len();
    std::thread::spawn(move || {
        for (index, path) in paths.into_iter().enumerate() {
            let found = path.is_some_and(|path| path.is_dir());
            if tx.send((index, found)).is_err() {
                return;
            }
        }
    });
    let deadline = std::time::Instant::now() + FOLDER_CHECK;
    let mut gone = BTreeSet::new();
    let mut seen = 0;
    while seen < count
        && let Some(left) = deadline.checked_duration_since(std::time::Instant::now())
    {
        match rx.recv_timeout(left) {
            Ok((index, found)) => {
                seen += 1;
                if !found {
                    gone.insert(index);
                }
            }
            Err(_) => break,
        }
    }
    gone
}

/// The folder a terminal opens in, or the file manager shows: one of the
/// project's, found here.
fn terminal_folder(project: &Project, folder: &str, home: Option<&Path>) -> AppResult<PathBuf> {
    if !project.folders.iter().any(|f| f == folder) {
        return Err(AppError::invalid("not one of the project's folders"));
    }
    projects::folder_path(folder, home)
        .filter(|path| path.is_dir())
        .ok_or_else(|| AppError::not_found(format!("{folder} on this computer")))
}

/// Host renames made while the vault was locked, oldest first: applied the
/// next time projects are listed with the vault open.
const PENDING_RENAMES: &str = "project-host-renames.json";
/// Most renames kept waiting; past it the oldest go.
const MAX_PENDING_RENAMES: usize = 200;
/// Held while the file of waiting renames is read and written, so a rename
/// saved meanwhile is never lost.
static PENDING_LOCK: Mutex<()> = Mutex::new(());

type Rename = (String, String);

/// The renames between a block's aliases `before` and `after`, pair by
/// pair: an alias that went and the one in its place that is new.
pub fn renamed_aliases(before: &[String], after: &[String]) -> Vec<Rename> {
    before
        .iter()
        .zip(after)
        .filter(|(old, new)| old != new && !after.contains(old) && !before.contains(new))
        .map(|(old, new)| (old.clone(), new.clone()))
        .collect()
}

/// Every name the `Host` blocks of a file answer to.
fn file_aliases(hosts: &[HostEntry]) -> BTreeSet<&str> {
    hosts
        .iter()
        .filter(|host| host.kind == HostKind::Host)
        .flat_map(|host| host.patterns.iter().map(String::as_str))
        .collect()
}

/// The renames of block `old` (of the file `before`) into block `new` (of
/// the file `after`): only an alias that is in no block of the new file,
/// replaced by one that was in no block of the old file. A name that moved
/// to another block, or one that was there already, is no rename.
pub fn block_renames(
    before: &[HostEntry],
    after: &[HostEntry],
    old: &HostEntry,
    new: &HostEntry,
) -> Vec<Rename> {
    let (was, now) = (file_aliases(before), file_aliases(after));
    renamed_aliases(&old.patterns, &new.patterns)
        .into_iter()
        .filter(|(from, to)| !now.contains(from.as_str()) && !was.contains(to.as_str()))
        .collect()
}

/// The renames a whole new text of `~/.ssh/config` makes, as far as it can
/// tell: the blocks line up one for one, and a block whose options stayed
/// the same got new names ([`block_renames`]). Reordered, added or removed
/// blocks are no renames.
pub fn file_renames(before: &[HostEntry], after: &[HostEntry]) -> Vec<Rename> {
    if before.len() != after.len() {
        return Vec::new();
    }
    before
        .iter()
        .zip(after)
        .filter(|(old, new)| old.kind == new.kind && old.options == new.options)
        .flat_map(|(old, new)| block_renames(before, after, old, new))
        .collect()
}

/// Moves renamed hosts in the projects that hold them, after `~/.ssh/config`
/// was saved ([`block_renames`], [`file_renames`]). While the vault is
/// locked the renames wait beside it and are made once it is open
/// ([`apply_pending_renames`]). A failure here never undoes the host's save.
pub fn follow_host_renames(app: &AppHandle, state: &AppState, renames: Vec<Rename>) {
    if renames.is_empty() {
        return;
    }
    if let Err(error) = queue_renames(state.vault.data_dir(), renames) {
        log::warn!("projects: a renamed host was not kept for later: {error}");
        return;
    }
    if state.vault.is_unlocked() {
        apply_pending_renames(app, state);
    }
}

/// Takes the step from environment groups to projects, settles holds a sync
/// left in two projects, and writes the `project/` tags
/// ([`sshkm_core::vault::Vault::tidy_projects`]), saving the vault only when
/// there is something to do: after an unlock, or a change of the vault's
/// file from another device. The managed files' round starts with it
/// ([`crate::env_files::EnvFiles::sync`]), so their states follow at once.
pub(crate) fn tidy_projects(app: &AppHandle, state: &AppState) {
    if !state.vault.is_unlocked() {
        return;
    }
    let untidy = state
        .vault
        .with_quietly(app, |vault| Ok(vault.projects_untidy()));
    if !matches!(untidy, Ok(true)) {
        return;
    }
    if let Err(error) = state.vault.change(app, &state.backup_dir, |vault| {
        vault.tidy_projects();
        Ok(())
    }) {
        log::warn!("projects: environments were not moved to projects yet: {error}");
    }
}

/// Makes the host renames that waited for the vault, in order, then takes
/// them off the list; renames added meanwhile stay. Does nothing while the
/// vault is locked.
pub fn apply_pending_renames(app: &AppHandle, state: &AppState) {
    let dir = state.vault.data_dir();
    let pending = {
        let _guard = pending_lock();
        load_pending(dir)
    };
    if pending.is_empty() || !state.vault.is_unlocked() {
        return;
    }
    // A rename followed by another of the same host chains: `web` → `prod`
    // → `api` moves `web` to `api`.
    let holds = state.vault.with_quietly(app, |vault| {
        let held: BTreeSet<String> = vault
            .projects()
            .into_iter()
            .flat_map(|project| project.hosts)
            .collect();
        Ok(pending.iter().any(|(old, _)| held.contains(old)))
    });
    let moved = match holds {
        Ok(false) => Ok(()),
        Ok(true) => state.vault.change(app, &state.backup_dir, |vault| {
            for (old, new) in &pending {
                vault.rename_host_in_projects(old, new)?;
            }
            Ok(())
        }),
        Err(error) => Err(error),
    };
    match moved.and_then(|()| forget_renames(dir, &pending)) {
        Ok(()) => {}
        Err(error) => log::warn!("projects: renamed hosts were not moved yet: {error}"),
    }
}

fn pending_lock() -> MutexGuard<'static, ()> {
    PENDING_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Adds `renames` to the waiting ones in `dir`, keeping the latest
/// [`MAX_PENDING_RENAMES`].
fn queue_renames(dir: &Path, renames: Vec<Rename>) -> AppResult<()> {
    let _guard = pending_lock();
    let mut pending = load_pending(dir);
    pending.extend(renames);
    let excess = pending.len().saturating_sub(MAX_PENDING_RENAMES);
    pending.drain(..excess);
    save_pending(dir, &pending)
}

/// Takes `applied` off the waiting renames in `dir`, each once and in
/// order; what was added since stays.
fn forget_renames(dir: &Path, applied: &[Rename]) -> AppResult<()> {
    let _guard = pending_lock();
    let mut pending = load_pending(dir);
    for rename in applied {
        if let Some(index) = pending.iter().position(|p| p == rename) {
            pending.remove(index);
        }
    }
    save_pending(dir, &pending)
}

fn load_pending(dir: &Path) -> Vec<Rename> {
    std::fs::read(dir.join(PENDING_RENAMES))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn save_pending(dir: &Path, pending: &[Rename]) -> AppResult<()> {
    let path = dir.join(PENDING_RENAMES);
    if pending.is_empty() {
        return match std::fs::remove_file(&path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
            _ => Ok(()),
        };
    }
    let json = serde_json::to_vec(pending)
        .map_err(|e| AppError::invalid(format!("renamed hosts: {e}")))?;
    Ok(fsutil::atomic_write(&path, &json, 0o600)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(folders: &[&str], envs: &[&str]) -> Project {
        Project {
            id: "p".into(),
            name: "Shop".into(),
            color: projects::ProjectColor::Blue,
            folders: folders.iter().map(|f| (*f).to_owned()).collect(),
            hosts: Vec::new(),
            keys: Vec::new(),
            environments: envs.iter().map(|e| (*e).to_owned()).collect(),
            logins: Vec::new(),
            hosts_file: Vec::new(),
            parts: Vec::new(),
            modified: String::new(),
        }
    }

    #[test]
    fn hosts_file_names_come_from_lines_the_app_can_switch() {
        let file = HostsFile::parse(
            "127.0.0.1 localhost app.test\n\
             10.0.0.3 API.test.\n\
             # 10.0.0.4 off.test\n\
             0.0.0.0 ads.example\n",
        );
        assert_eq!(member_names(&file), ["api.test", "off.test"]);
    }

    #[test]
    fn a_terminal_opens_only_in_a_folder_of_the_project_found_here() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        std::fs::create_dir_all(home.join("code").join("shop")).unwrap();
        let shop = project(&["~/code/shop", "~/code/gone"], &[]);
        assert_eq!(
            terminal_folder(&shop, "~/code/shop", Some(home)).unwrap(),
            home.join("code").join("shop")
        );
        let refused = terminal_folder(&shop, "/etc", Some(home)).unwrap_err();
        assert_eq!(refused.code(), ErrorCode::InvalidInput);
        let gone = terminal_folder(&shop, "~/code/gone", Some(home)).unwrap_err();
        assert_eq!(gone.code(), ErrorCode::NotFound);
    }

    #[test]
    fn a_folder_in_a_project_folder_opens_only_inside_it() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let shop = home.join("code").join("shop");
        std::fs::create_dir_all(shop.join("apps").join("api")).unwrap();
        std::fs::create_dir_all(home.join("outside")).unwrap();
        let project = project(&["~/code/shop"], &[]);
        let at = |path: &str| ProjectFolder {
            folder: "~/code/shop".into(),
            path: path.into(),
        };
        assert_eq!(
            place_path(&project, &at("apps/api"), Some(home)).unwrap(),
            // As it was checked: links resolved, and on Windows `C:\…`, not `\\?\C:\…`.
            fsutil::without_verbatim_prefix(shop.join("apps").join("api").canonicalize().unwrap())
        );
        assert_eq!(place_path(&project, &at(""), Some(home)).unwrap(), shop);
        for bad in ["..", "apps/../..", "/etc"] {
            let refused = place_path(&project, &at(bad), Some(home)).unwrap_err();
            assert_eq!(refused.code(), ErrorCode::InvalidInput, "{bad}");
        }
        let gone = place_path(&project, &at("apps/web"), Some(home)).unwrap_err();
        assert_eq!(gone.code(), ErrorCode::NotFound);
        #[cfg(unix)]
        {
            // A symbolic link in the project that leads out of it.
            std::os::unix::fs::symlink(home.join("outside"), shop.join("out")).unwrap();
            let out = place_path(&project, &at("out"), Some(home)).unwrap_err();
            assert_eq!(out.code(), ErrorCode::InvalidInput);
        }
    }

    #[test]
    fn a_picked_folder_is_found_in_the_deepest_project_folder() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let api = home.join("code").join("shop").join("apps").join("api");
        std::fs::create_dir_all(&api).unwrap();
        std::fs::create_dir_all(home.join("blog")).unwrap();
        let project = project(&["~/code", "~/code/shop"], &[]);
        assert_eq!(
            folder_in_project(&project, &api, Some(home)).unwrap(),
            ProjectFolder {
                folder: "~/code/shop".into(),
                path: "apps/api".into(),
            }
        );
        assert_eq!(
            folder_in_project(&project, &home.join("code"), Some(home)).unwrap(),
            ProjectFolder {
                folder: "~/code".into(),
                path: String::new(),
            }
        );
        let outside = folder_in_project(&project, &home.join("blog"), Some(home)).unwrap_err();
        assert_eq!(outside.code(), ErrorCode::InvalidInput);
    }

    #[test]
    fn folders_not_here_are_missing() {
        let dir = tempfile::tempdir().unwrap();
        let gone = missing_dirs(vec![
            Some(dir.path().to_path_buf()),
            Some(dir.path().join("gone")),
            None,
        ]);
        assert_eq!(gone.into_iter().collect::<Vec<_>>(), [1, 2]);
    }

    fn hosts(text: &str) -> Vec<HostEntry> {
        SshConfig::parse(text).hosts()
    }

    fn rename(old: &str, new: &str) -> Rename {
        (old.to_owned(), new.to_owned())
    }

    #[test]
    fn the_raw_editor_follows_only_real_renames() {
        let before = "Host web\n    HostName 10.0.0.1\n\nHost db\n    HostName 10.0.0.2\n";
        // Reordered blocks: nothing was renamed.
        let reordered = "Host db\n    HostName 10.0.0.2\n\nHost web\n    HostName 10.0.0.1\n";
        assert_eq!(file_renames(&hosts(before), &hosts(reordered)), []);
        // One removed, one added: no rename either.
        let swapped_out = "Host db\n    HostName 10.0.0.2\n\nHost new\n    HostName 10.0.0.9\n";
        assert_eq!(file_renames(&hosts(before), &hosts(swapped_out)), []);
        // Two blocks swapping names, options staying.
        let names_swapped = "Host db\n    HostName 10.0.0.1\n\nHost web\n    HostName 10.0.0.2\n";
        assert_eq!(file_renames(&hosts(before), &hosts(names_swapped)), []);
        // A real rename among unchanged blocks.
        let renamed = "Host prod\n    HostName 10.0.0.1\n\nHost db\n    HostName 10.0.0.2\n";
        assert_eq!(
            file_renames(&hosts(before), &hosts(renamed)),
            [rename("web", "prod")]
        );
        // Renamed and changed at once: the raw editor can't tell.
        let changed = "Host prod\n    HostName 10.9.9.9\n\nHost db\n    HostName 10.0.0.2\n";
        assert_eq!(file_renames(&hosts(before), &hosts(changed)), []);
    }

    #[test]
    fn the_host_editor_follows_a_rename_to_a_name_no_other_block_has() {
        let before = hosts("Host web\n    User a\n\nHost db\n    User b\n");
        let to_new = hosts("Host prod\n    User a\n\nHost db\n    User b\n");
        assert_eq!(
            block_renames(&before, &to_new, &before[0], &to_new[0]),
            [rename("web", "prod")]
        );
        // Renamed to a name another block has: that host is still there.
        let to_db = hosts("Host db\n    User a\n\nHost db\n    User b\n");
        assert_eq!(block_renames(&before, &to_db, &before[0], &to_db[0]), []);
    }

    #[test]
    fn renames_wait_in_a_file_and_leave_it_only_once_made() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        assert_eq!(load_pending(path), Vec::<Rename>::new());
        queue_renames(path, vec![rename("web", "prod")]).unwrap();
        queue_renames(path, vec![rename("prod", "api")]).unwrap();
        let loaded = load_pending(path);
        assert_eq!(loaded, [rename("web", "prod"), rename("prod", "api")]);
        // Saved while the first two were being made: it stays.
        queue_renames(path, vec![rename("db", "pg")]).unwrap();
        forget_renames(path, &loaded).unwrap();
        assert_eq!(load_pending(path), [rename("db", "pg")]);
        forget_renames(path, &[rename("db", "pg")]).unwrap();
        assert!(!path.join(PENDING_RENAMES).exists());
        // Only the latest are kept.
        let many: Vec<Rename> = (0..MAX_PENDING_RENAMES + 5)
            .map(|n| rename(&format!("h{n}"), &format!("n{n}")))
            .collect();
        queue_renames(path, many).unwrap();
        let kept = load_pending(path);
        assert_eq!(kept.len(), MAX_PENDING_RENAMES);
        assert_eq!(kept[0], rename("h5", "n5"));
    }

    #[test]
    fn renames_pair_a_gone_alias_with_the_new_one_in_its_place() {
        let s = |names: &[&str]| names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            renamed_aliases(&s(&["web"]), &s(&["prod"])),
            [("web".to_owned(), "prod".to_owned())]
        );
        // Kept, added or swapped names aren't renames.
        assert_eq!(renamed_aliases(&s(&["web"]), &s(&["web", "www"])), []);
        assert_eq!(renamed_aliases(&s(&["a", "b"]), &s(&["b", "a"])), []);
        assert_eq!(
            renamed_aliases(&s(&["web", "www"]), &s(&["prod", "www"])),
            [("web".to_owned(), "prod".to_owned())]
        );
    }
}
