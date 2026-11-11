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

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use serde::{Deserialize, Serialize};
use sshkm_core::config::{HostKind, SshConfig};
use sshkm_core::paths::home_dir;
use sshkm_core::vault::projects::suggest::{self, Declined, HostFacts, ProjectSuggestion};
use sshkm_core::vault::projects::{self, Project, ProjectInput, ProjectMember};
use sshkm_core::{ErrorCode, SecretString, fsutil, keys};
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
/// copy kept for then, whose projects have no logins; with the folders not
/// found on this computer. Quiet: the UI refetches the list by itself.
#[tauri::command]
pub async fn projects_list(app: AppHandle, state: State<'_, Shared>) -> AppResult<Vec<Project>> {
    blocking(&state, move |state| {
        let mut projects = if state.vault.is_unlocked() {
            match state.vault.with_quietly(&app, |vault| Ok(vault.projects())) {
                Err(error) if error.code() == ErrorCode::VaultLocked => state.vault.projects_copy(),
                other => other?,
            }
        } else {
            state.vault.projects_copy()
        };
        let home = home_dir();
        for project in &mut projects {
            project.missing_folders = project
                .folders
                .iter()
                .filter(|folder| {
                    !projects::folder_path(folder, home.as_deref()).is_some_and(|p| p.is_dir())
                })
                .cloned()
                .collect();
        }
        Ok(projects)
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
        let title = Localized::new(
            format!("Add a folder to {name}"),
            format!("Добавить папку в {name}"),
            format!("{name} loyihasiga papka qo‘shish"),
        );
        let Some(folder) = pick_folder(&app, title.pick())? else {
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

fn pick_folder(app: &AppHandle, title: &str) -> AppResult<Option<PathBuf>> {
    let mut dialog = app.dialog().file().set_title(title);
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

fn suggestions(app: &AppHandle, state: &AppState) -> AppResult<Vec<ProjectSuggestion>> {
    // Nothing is read on disk while the vault is locked.
    let vault_id = state
        .vault
        .with_quietly(app, |vault| Ok(vault.vault_id().to_owned()))?;
    let prefs = load_prefs(state);
    let hosts = host_facts(state)?;
    let repositories = suggest::find_repositories(&code_roots(&prefs));
    // The working trees come by their real paths; so does the home folder.
    let home = home_dir().map(|home| suggest::canonical(&home).unwrap_or(home));
    let found = state.vault.with_quietly(app, |vault| {
        let projects = vault.projects();
        let groups = vault.environment_groups();
        let logins = vault.suggestion_logins();
        Ok(suggest::suggest(
            &suggest::Sources {
                hosts: &hosts,
                environment_groups: &groups,
                logins: &logins,
                repositories: &repositories,
                projects: &projects,
                home: home.as_deref(),
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
/// out aren't suggested again.
#[tauri::command]
pub async fn projects_accept_suggestion(
    app: AppHandle,
    state: State<'_, Shared>,
    key: String,
    input: ProjectInput,
    members: Vec<ProjectMember>,
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
        let Some(folder) = pick_folder(&app, title.pick())? else {
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

/// Starts a shell in one of a project's folders, as `terminal_open_local`
/// does: `shell` or the default one, in a `cols`×`rows` terminal. `folder`
/// is the folder as the project keeps it; nothing outside the project's
/// folders opens. While the vault is unlocked, the shell gets the variables
/// of the project's `local` environment, if it has one; while it is locked
/// the project comes from the copy kept for then, and the shell gets none.
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
    shell: Option<String>,
    cols: u16,
    rows: u16,
    events: Channel<InvokeResponseBody>,
) -> AppResult<TerminalInfo> {
    let shared = Arc::clone(&state);
    blocking(&state, move |state| {
        let opened = state.vault.with(&app, |vault| {
            let project = vault.project(&id)?;
            let vars = local_variables(vault, &project)?;
            Ok((project, vars))
        });
        let (project, vars) = match opened {
            Ok(found) => found,
            Err(error) if error.code() == ErrorCode::VaultLocked => {
                let project = state
                    .vault
                    .projects_copy()
                    .into_iter()
                    .find(|p| p.id == id)
                    .ok_or_else(|| AppError::not_found(format!("project {id}")))?;
                (project, Vec::new())
            }
            Err(error) => return Err(error),
        };
        if !project.folders.contains(&folder) {
            return Err(AppError::invalid("not one of the project's folders"));
        }
        let path = projects::folder_path(&folder, home_dir().as_deref())
            .filter(|path| path.is_dir())
            .ok_or_else(|| AppError::not_found(format!("{folder} on this computer")))?;
        let name = path
            .file_name()
            .map_or_else(|| folder.clone(), |n| n.to_string_lossy().into_owned());
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

/// The variables of the project's `local` environment: the first of its
/// environments' groups that has one outside the recycle bin.
fn local_variables(
    vault: &mut sshkm_core::vault::Vault,
    project: &Project,
) -> AppResult<Vec<(String, SecretString)>> {
    let local = vault.environments().into_iter().find(|env| {
        !env.in_trash
            && env.name.eq_ignore_ascii_case("local")
            && project.environments.contains(&env.project)
    });
    let Some(local) = local else {
        return Ok(Vec::new());
    };
    Ok(vault
        .env_variables(&local.id)?
        .into_iter()
        .map(|var| (var.name, var.value))
        .collect())
}

/// Moves renamed hosts in the projects that hold them, after `~/.ssh/config`
/// was saved: `before` and `after` are a block's aliases. Only while the
/// vault is unlocked; a failure here never undoes the host's save.
pub fn follow_host_renames(app: &AppHandle, state: &AppState, before: &[String], after: &[String]) {
    let renames: Vec<(&String, &String)> = before
        .iter()
        .zip(after)
        .filter(|(old, new)| old != new && !after.contains(old) && !before.contains(new))
        .collect();
    if renames.is_empty() || !state.vault.is_unlocked() {
        return;
    }
    let holds = state.vault.with_quietly(app, |vault| {
        Ok(vault
            .projects()
            .iter()
            .any(|project| renames.iter().any(|(old, _)| project.hosts.contains(old))))
    });
    if !holds.unwrap_or(false) {
        return;
    }
    let moved = state.vault.change(app, &state.backup_dir, |vault| {
        for (old, new) in &renames {
            vault.rename_host_in_projects(old, new)?;
        }
        Ok(())
    });
    if let Err(error) = moved {
        log::warn!("projects: a renamed host was not moved: {error}");
    }
}
