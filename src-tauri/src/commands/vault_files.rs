//! The vault's files: importing the CSV exports of other password managers,
//! exporting, and moving or switching the database, e.g. into a Dropbox or
//! iCloud Drive folder so other computers see it.
//!
//! Import previews carry no passwords: the CSV file is read again when the
//! chosen rows are imported. Paths come from the system file dialogs.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use serde::Serialize;
use sshkm_core::SecretString;
use sshkm_core::keys::move_to_trash;
use sshkm_core::vault::{self, ImportPreview, Vault, VaultPaths};
use tauri::{AppHandle, Emitter, Manager, State};

use super::{Shared, blocking};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::vault::{LOCKED_EVENT, LockReason, VaultRuntime};
use crate::vault_watcher::VaultWatcher;

/// The CSV file imported last: the only one [`vault_trash_import_file`]
/// moves to the Trash.
static LAST_IMPORT: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Where the vault is, and whether that is the default place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct VaultLocation {
    pub paths: VaultPaths,
    /// The database file exists.
    pub exists: bool,
    /// `paths` are the default place, in the app's data folder.
    pub is_default: bool,
    pub default_paths: VaultPaths,
    /// A database exists at the default place. When the vault is elsewhere,
    /// going back either switches to it (it exists) or moves the files there.
    pub default_exists: bool,
}

/// Reads a CSV export and lists its rows, without passwords, marking those
/// already in the vault.
#[tauri::command]
pub async fn vault_import_preview(
    app: AppHandle,
    state: State<'_, Shared>,
    path: String,
) -> AppResult<ImportPreview> {
    let path = absolute(&path)?;
    blocking(&state, move |state| {
        state
            .vault
            .with(&app, |vault| Ok(vault.import_preview(&path)?))
    })
    .await
}

/// Imports the rows at `indices` (from the preview) and returns how many
/// entries were added.
#[tauri::command]
pub async fn vault_import(
    app: AppHandle,
    state: State<'_, Shared>,
    path: String,
    indices: Vec<u32>,
) -> AppResult<usize> {
    let path = absolute(&path)?;
    if indices.is_empty() {
        return Err(AppError::invalid("choose at least one row to import"));
    }
    blocking(&state, move |state| {
        let count = state.vault.change(&app, &state.backup_dir, |vault| {
            Ok(vault.import_csv(&path, &indices)?)
        })?;
        *last_import() = Some(path);
        Ok(count)
    })
    .await
}

/// Moves the CSV file just imported to the system Trash, since it holds
/// every password in plain text. No other file can be moved this way.
#[tauri::command]
pub async fn vault_trash_import_file(state: State<'_, Shared>, path: String) -> AppResult<()> {
    let path = absolute(&path)?;
    blocking(&state, move |_| {
        let mut last = last_import();
        if last.as_deref() != Some(path.as_path()) {
            return Err(AppError::invalid(
                "only the CSV file just imported can be moved to the Trash",
            ));
        }
        move_to_trash(std::slice::from_ref(&path))?;
        *last = None;
        Ok(())
    })
    .await
}

/// Writes the vault as a KeePassXC-style CSV file, in plain text, after
/// checking the master password. Returns how many entries were written.
#[tauri::command]
pub async fn vault_export_csv(
    app: AppHandle,
    state: State<'_, Shared>,
    path: String,
    master: SecretString,
) -> AppResult<usize> {
    let path = absolute(&path)?;
    blocking(&state, move |state| {
        state.vault.with(&app, |vault| {
            Ok(vault.export_csv(&master, &path, &state.paths.dir)?)
        })
    })
    .await
}

/// Copies the KeePass database, which opens with the recovery key. Works
/// while the vault is locked, too. Never into `~/.ssh`.
#[tauri::command]
pub async fn vault_export_kdbx(state: State<'_, Shared>, path: String) -> AppResult<()> {
    let path = absolute(&path)?;
    blocking(&state, move |state| {
        state.vault.exclusive(|_| {
            Ok(vault::export_kdbx(
                &state.vault.paths(),
                &path,
                &state.paths.dir,
            )?)
        })
    })
    .await
}

#[tauri::command]
pub async fn vault_location(state: State<'_, Shared>) -> AppResult<VaultLocation> {
    blocking(&state, |state| Ok(location(&state.vault))).await
}

/// Moves both files into `folder`, locked or unlocked. Refuses if the
/// folder already has files of those names.
#[tauri::command]
pub async fn vault_move(
    app: AppHandle,
    state: State<'_, Shared>,
    folder: String,
) -> AppResult<VaultLocation> {
    let folder = absolute(&folder)?;
    blocking(&state, move |state| {
        move_to_folder(&state.vault, &folder)?;
        Ok(after_change(&app, state))
    })
    .await
}

/// Switches to an existing KeePass file — this vault on another computer,
/// or a KeePassXC database. The current vault locks and stays where it is;
/// the new one opens with its master password, or, without a keys file,
/// with its recovery key or KeePass password.
#[tauri::command]
pub async fn vault_use_file(
    app: AppHandle,
    state: State<'_, Shared>,
    path: String,
) -> AppResult<VaultLocation> {
    let path = absolute(&path)?;
    blocking(&state, move |state| {
        if use_file(&state.vault, &path)? {
            let _ = app.emit(LOCKED_EVENT, LockReason::Manual);
        }
        Ok(after_change(&app, state))
    })
    .await
}

/// Goes back to the default place: with `move_files`, the vault's files
/// move there (refused if a vault is there already); otherwise the vault
/// there is used and the current one locks and stays where it is.
#[tauri::command]
pub async fn vault_use_default(
    app: AppHandle,
    state: State<'_, Shared>,
    move_files: bool,
) -> AppResult<VaultLocation> {
    blocking(&state, move |state| {
        if use_default(&state.vault, move_files)? {
            let _ = app.emit(LOCKED_EVENT, LockReason::Manual);
        }
        Ok(after_change(&app, state))
    })
    .await
}

fn location(runtime: &VaultRuntime) -> VaultLocation {
    let paths = runtime.paths();
    let default_paths = runtime.default_paths();
    VaultLocation {
        exists: paths.database.is_file(),
        is_default: paths == default_paths,
        default_exists: default_paths.database.is_file(),
        paths,
        default_paths,
    }
}

fn after_change(app: &AppHandle, state: &AppState) -> VaultLocation {
    if let Some(watcher) = app.try_state::<VaultWatcher>() {
        watcher.follow(app, &state.vault.paths());
    }
    location(&state.vault)
}

fn move_to_folder(runtime: &VaultRuntime, folder: &Path) -> AppResult<()> {
    runtime.exclusive(|slot| {
        let from = runtime.paths();
        let name = from
            .database
            .file_name()
            .ok_or_else(|| AppError::invalid("the vault has no file name"))?;
        let to = VaultPaths::new(folder.join(name));
        move_files(runtime, slot, &from, &to)
    })
}

/// Returns whether an unlocked vault was locked.
fn use_file(runtime: &VaultRuntime, path: &Path) -> AppResult<bool> {
    runtime.exclusive(|slot| {
        vault::check_database(path)?;
        if same_file(&runtime.paths().database, path) {
            return Ok(false);
        }
        runtime.set_database(path)?;
        Ok(slot.take().is_some())
    })
}

/// Returns whether an unlocked vault was locked.
fn use_default(runtime: &VaultRuntime, move_files_there: bool) -> AppResult<bool> {
    runtime.exclusive(|slot| {
        let current = runtime.paths();
        let default = runtime.default_paths();
        if current == default {
            return Ok(false);
        }
        if move_files_there {
            if let Some(dir) = default.database.parent() {
                std::fs::create_dir_all(dir)?;
            }
            move_files(runtime, slot, &current, &default)?;
            return Ok(false);
        }
        runtime.set_database(&default.database)?;
        Ok(slot.take().is_some())
    })
}

/// Copies the files, records the new place, points an unlocked vault at it
/// and only then removes the originals, so a failure leaves a working vault
/// where the settings point.
fn move_files(
    runtime: &VaultRuntime,
    slot: &mut Option<Vault>,
    from: &VaultPaths,
    to: &VaultPaths,
) -> AppResult<()> {
    if let Some(vault) = slot.as_mut() {
        // Move what is on disk now, including changes from elsewhere.
        vault.refresh()?;
    }
    vault::copy_files(from, to)?;
    if let Err(error) = runtime.set_database(&to.database) {
        let _ = vault::remove_files(to);
        return Err(error);
    }
    if let Some(vault) = slot.as_mut() {
        vault.relocate(to.clone());
    }
    if let Err(error) = vault::remove_files(from) {
        log::warn!(
            "the vault moved, but its old files remain at {}: {error}",
            from.database.display()
        );
    }
    Ok(())
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

fn absolute(path: &str) -> AppResult<PathBuf> {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(AppError::invalid(format!(
            "not an absolute path: {}",
            path.display()
        )))
    }
}

fn last_import() -> std::sync::MutexGuard<'static, Option<PathBuf>> {
    LAST_IMPORT.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use sshkm_core::vault::EntryInput;

    use super::*;

    fn s(text: &str) -> SecretString {
        SecretString::from(text.to_owned())
    }

    fn code(error: &AppError) -> String {
        serde_json::to_value(error).unwrap()["code"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// A runtime with an unlocked vault holding one entry in its default place.
    fn unlocked() -> (tempfile::TempDir, VaultRuntime) {
        let dir = tempfile::tempdir().unwrap();
        let runtime = VaultRuntime::new(dir.path().join("data"));
        fs::create_dir_all(dir.path().join("data")).unwrap();
        let (mut vault, _) = Vault::create(&runtime.paths(), &s("master")).unwrap();
        vault
            .add_entry(&EntryInput {
                title: "GitHub".into(),
                ..EntryInput::default()
            })
            .unwrap();
        vault.save(&dir.path().join("backups")).unwrap();
        runtime.set_unlocked(vault);
        (dir, runtime)
    }

    fn entries(runtime: &VaultRuntime) -> usize {
        runtime
            .exclusive(|slot| Ok(slot.as_ref().map(|v| v.entries().len())))
            .unwrap()
            .unwrap()
    }

    #[test]
    fn moving_an_unlocked_vault_keeps_it_open_and_saving_at_the_new_place() {
        let (dir, runtime) = unlocked();
        let old = runtime.paths();
        let dropbox = dir.path().join("Dropbox");
        fs::create_dir(&dropbox).unwrap();

        move_to_folder(&runtime, &dropbox).unwrap();
        let moved = location(&runtime);
        assert_eq!(moved.paths.database, dropbox.join("vault.kdbx"));
        assert!(moved.exists && !moved.is_default && !moved.default_exists);
        assert!(!old.database.exists() && !old.keys.exists());
        assert!(runtime.is_unlocked());
        // The setting survives a restart.
        let again = VaultRuntime::new(dir.path().join("data"));
        assert_eq!(again.paths(), moved.paths);

        runtime
            .exclusive(|slot| {
                let vault = slot.as_mut().unwrap();
                vault.add_entry(&EntryInput {
                    title: "after".into(),
                    ..EntryInput::default()
                })?;
                vault.save(&dir.path().join("backups"))?;
                Ok(())
            })
            .unwrap();
        let reopened = Vault::unlock(&moved.paths, &s("master")).unwrap();
        assert_eq!(reopened.entries().len(), 2);

        // Moving back to the default place stores no path at all.
        use_default(&runtime, true).unwrap();
        assert!(location(&runtime).is_default);
        assert_eq!(runtime.settings().database, None);
        assert!(!dropbox.join("vault.kdbx").exists());
        assert_eq!(entries(&runtime), 2);
    }

    #[test]
    fn a_locked_vault_moves_too_and_existing_files_are_never_replaced() {
        let (dir, runtime) = unlocked();
        runtime.exclusive(|slot| Ok(slot.take())).unwrap();
        let target = dir.path().join("iCloud");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("vault.kdbx"), "another vault").unwrap();

        let error = move_to_folder(&runtime, &target).unwrap_err();
        assert_eq!(code(&error), "already_exists");
        assert!(location(&runtime).is_default);
        assert_eq!(
            fs::read_to_string(target.join("vault.kdbx")).unwrap(),
            "another vault"
        );

        fs::remove_file(target.join("vault.kdbx")).unwrap();
        move_to_folder(&runtime, &target).unwrap();
        assert!(target.join("vault.kdbx").is_file() && target.join("vault.keys").is_file());
        assert!(!runtime.is_unlocked());
        let error = move_to_folder(&runtime, &target).unwrap_err();
        assert_eq!(code(&error), "invalid_input");
    }

    #[test]
    fn using_another_file_locks_the_vault_and_going_back_switches_to_it_again() {
        let (dir, runtime) = unlocked();
        let other_dir = dir.path().join("other");
        fs::create_dir(&other_dir).unwrap();
        let other = VaultPaths::new(other_dir.join("Passwords.kdbx"));
        Vault::create(&other, &s("other")).unwrap();
        fs::remove_file(&other.keys).unwrap();

        assert!(use_file(&runtime, &other.database).unwrap());
        assert!(!runtime.is_unlocked());
        let switched = location(&runtime);
        assert_eq!(switched.paths, other);
        assert!(switched.default_exists && !switched.is_default);
        // Without a keys file, the page offers the recovery key form.
        assert!(!vault::probe(&switched.paths).unwrap().has_master_password);
        // Choosing the same file again changes nothing.
        assert!(!use_file(&runtime, &other.database).unwrap());

        let csv = dir.path().join("passwords.csv");
        fs::write(&csv, "name,url,username,password\n").unwrap();
        let error = use_file(&runtime, &csv).unwrap_err();
        assert_eq!(code(&error), "parse");
        assert_eq!(runtime.paths(), other);

        // Back to the default vault, which is still there; the other file stays.
        assert!(!use_default(&runtime, false).unwrap());
        assert!(location(&runtime).is_default);
        assert!(other.database.is_file());
        // Moving there instead would replace it, which is refused.
        use_file(&runtime, &other.database).unwrap();
        let error = use_default(&runtime, true).unwrap_err();
        assert_eq!(code(&error), "already_exists");
        assert!(other.database.is_file());
    }
}
