//! The vault's files: importing the CSV exports of other password managers,
//! exporting, and moving or switching the database, e.g. into a Dropbox or
//! iCloud Drive folder so other computers see it.
//!
//! Import previews carry no passwords: the CSV file is read again when the
//! chosen rows are imported.
//!
//! The files read and written here are chosen in system file dialogs that
//! this side opens, never named by the page: the import's CSV file, the
//! export's target, the folder the vault moves to and the file it switches
//! to. Moving or switching then needs the user's confirmation in a native
//! dialog that shows the path, its control and invisible characters made
//! visible; the file switched to isn't opened before that.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use serde::Serialize;
use sshkm_core::{ExposeSecret, SecretString};

use sshkm_core::keys::move_to_trash;
use sshkm_core::vault::{self, ImportOutcome, ImportPreview, Vault, VaultPaths};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;

use super::{Shared, blocking};
use crate::confirm::{self, Localized};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::vault::{LOCKED_EVENT, LockReason, VaultRuntime};
use crate::vault_watcher::VaultWatcher;

/// The CSV file picked in the import's file dialog: the only one
/// [`vault_import`] reads.
static PICKED_IMPORT: Mutex<Option<PathBuf>> = Mutex::new(None);
/// The CSV file imported last: the only one [`vault_trash_import_file`]
/// moves to the Trash.
static LAST_IMPORT: Mutex<Option<PathBuf>> = Mutex::new(None);
/// The folder picked in [`vault_pick_folder`]: the only one [`vault_move`]
/// moves the vault to.
static PICKED_FOLDER: Mutex<Option<PathBuf>> = Mutex::new(None);
/// The KeePass file picked in [`vault_pick_file`]: the only one
/// [`vault_use_file`] switches to.
static PICKED_DATABASE: Mutex<Option<PathBuf>> = Mutex::new(None);

/// A CSV file picked for import, and its rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct ImportPick {
    pub path: PathBuf,
    pub preview: ImportPreview,
}

/// The two passwords of an import row whose entry has another one, shown
/// side by side when the user asks, to choose which to keep.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct ImportPasswords {
    /// The password in the file.
    pub file: String,
    /// The password in the vault, which importing the row replaces.
    pub vault: String,
}

/// Where an export went, and how many entries it holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct Exported {
    pub path: PathBuf,
    pub count: usize,
}

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

/// Asks for a CSV export in a system file dialog and lists its rows, without
/// passwords, marking those already in the vault. `None` when the dialog
/// was cancelled.
#[tauri::command]
pub async fn vault_import_preview(
    app: AppHandle,
    state: State<'_, Shared>,
) -> AppResult<Option<ImportPick>> {
    blocking(&state, move |state| {
        // No dialog while the vault is locked.
        state.vault.with(&app, |_| Ok(()))?;
        let Some(path) = pick_csv(&app)? else {
            return Ok(None);
        };
        let preview = state
            .vault
            .with(&app, |vault| Ok(vault.import_preview(&path)?))?;
        *picked_import() = Some(path.clone());
        Ok(Some(ImportPick { path, preview }))
    })
    .await
}

/// Imports the rows at `indices` (from the preview) of the file picked for
/// it: adds them, or sets their new password on the entries they match.
/// Returns how many entries were added and updated.
#[tauri::command]
pub async fn vault_import(
    app: AppHandle,
    state: State<'_, Shared>,
    indices: Vec<u32>,
) -> AppResult<ImportOutcome> {
    if indices.is_empty() {
        return Err(AppError::invalid("choose at least one row to import"));
    }
    blocking(&state, move |state| {
        let path = picked_import()
            .clone()
            .ok_or_else(|| AppError::invalid("choose the file to import again"))?;
        let count = state.vault.change(&app, &state.backup_dir, |vault| {
            Ok(vault.import_csv(&path, &indices)?)
        })?;
        *picked_import() = None;
        *last_import() = Some(path);
        Ok(count)
    })
    .await
}

/// Both passwords of the row at `index` of the file picked for import, for
/// the user to compare. Only for a row whose entry has another password;
/// see [`Vault::import_compare`].
#[tauri::command]
pub async fn vault_import_compare(
    app: AppHandle,
    state: State<'_, Shared>,
    index: u32,
) -> AppResult<ImportPasswords> {
    blocking(&state, move |state| {
        // The vault's password, shown: past a few a minute, each is asked for.
        crate::secret_gate::take_secret(
            &app,
            crate::secret_gate::Taking::Show,
            &crate::secret_gate::import_password(),
        )?;
        let path = picked_import()
            .clone()
            .ok_or_else(|| AppError::invalid("choose the file to import again"))?;
        state.vault.with(&app, |vault| {
            let both = vault.import_compare(&path, index)?;
            Ok(ImportPasswords {
                file: both.file.expose_secret().to_owned(),
                vault: both.vault.expose_secret().to_owned(),
            })
        })
    })
    .await
}

/// Moves the CSV file just imported to the system Trash, since it holds
/// every password in plain text. No other file can be moved this way.
#[tauri::command]
pub async fn vault_trash_import_file(state: State<'_, Shared>) -> AppResult<()> {
    blocking(&state, move |_| {
        let mut last = last_import();
        let path = last.clone().ok_or_else(|| {
            AppError::invalid("only the CSV file just imported can be moved to the Trash")
        })?;
        move_to_trash(std::slice::from_ref(&path))?;
        *last = None;
        Ok(())
    })
    .await
}

/// Checks the master password, asks where to save in a system file dialog,
/// and writes the vault there as a KeePassXC-style CSV file, in plain text.
/// `None` when the dialog was cancelled.
#[tauri::command]
pub async fn vault_export_csv(
    app: AppHandle,
    state: State<'_, Shared>,
    master: SecretString,
) -> AppResult<Option<Exported>> {
    blocking(&state, move |state| {
        // A wrong password shows no dialog.
        state
            .vault
            .with(&app, |vault| Ok(vault.verify_master_password(&master)?))?;
        let Some(path) = pick_export_target(&app, ExportFormat::Csv)? else {
            return Ok(None);
        };
        let count = state.vault.with(&app, |vault| {
            Ok(vault.export_csv(&master, &path, &state.paths.dir)?)
        })?;
        Ok(Some(Exported { path, count }))
    })
    .await
}

/// Like [`vault_export_csv`], for a copy of the KeePass database, which
/// opens with the recovery key. Needs the vault unlocked and the master
/// password, too. Never into `~/.ssh`, never over the vault's own files.
#[tauri::command]
pub async fn vault_export_kdbx(
    app: AppHandle,
    state: State<'_, Shared>,
    master: SecretString,
) -> AppResult<Option<Exported>> {
    blocking(&state, move |state| {
        state
            .vault
            .with(&app, |vault| Ok(vault.verify_master_password(&master)?))?;
        let Some(path) = pick_export_target(&app, ExportFormat::Kdbx)? else {
            return Ok(None);
        };
        let count = state.vault.with(&app, |vault| {
            vault.export_kdbx(&master, &path, &state.paths.dir)?;
            Ok(vault.entries().iter().filter(|e| !e.in_trash).count())
        })?;
        Ok(Some(Exported { path, count }))
    })
    .await
}

#[derive(Clone, Copy)]
enum ExportFormat {
    Csv,
    Kdbx,
}

/// The import's file dialog: one CSV file.
fn pick_csv(app: &AppHandle) -> AppResult<Option<PathBuf>> {
    let mut dialog = app
        .dialog()
        .file()
        .set_title(
            Localized::new(
                "Choose a password export",
                "Выберите выгрузку паролей",
                "Parollar eksportini tanlang",
            )
            .pick(),
        )
        .add_filter(
            Localized::new("CSV files", "Файлы CSV", "CSV fayllar").pick(),
            &["csv"],
        );
    if let Some(window) = app.get_webview_window("main") {
        dialog = dialog.set_parent(&window);
    }
    dialog.blocking_pick_file().map(into_path).transpose()
}

/// The export's save dialog, suggesting a dated file name.
fn pick_export_target(app: &AppHandle, format: ExportFormat) -> AppResult<Option<PathBuf>> {
    let today = time::OffsetDateTime::now_utc().date();
    let (name, filter, extension) = match format {
        ExportFormat::Csv => (
            format!("passwords-{today}.csv"),
            Localized::new("CSV files", "Файлы CSV", "CSV fayllar"),
            "csv",
        ),
        ExportFormat::Kdbx => (
            format!("vault-{today}.kdbx"),
            Localized::new("KeePass databases", "Базы KeePass", "KeePass bazalari"),
            "kdbx",
        ),
    };
    let mut dialog = app
        .dialog()
        .file()
        .set_title(
            Localized::new(
                "Save the exported passwords",
                "Сохранить выгруженные пароли",
                "Eksport qilingan parollarni saqlash",
            )
            .pick(),
        )
        .set_file_name(name)
        .add_filter(filter.pick(), &[extension]);
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

#[tauri::command]
pub async fn vault_location(state: State<'_, Shared>) -> AppResult<VaultLocation> {
    blocking(&state, |state| Ok(location(&state.vault))).await
}

/// Asks for a folder to move the vault to in a system file dialog, and
/// returns it for the page to show; `None` when the dialog was cancelled.
#[tauri::command]
pub async fn vault_pick_folder(
    app: AppHandle,
    state: State<'_, Shared>,
) -> AppResult<Option<String>> {
    blocking(&state, move |_| {
        let mut dialog = app.dialog().file().set_title(
            Localized::new(
                "Choose a folder for the vault",
                "Выберите папку для хранилища",
                "Ombor uchun papka tanlang",
            )
            .pick(),
        );
        if let Some(window) = app.get_webview_window("main") {
            dialog = dialog.set_parent(&window);
        }
        let picked = dialog.blocking_pick_folder().map(into_path).transpose()?;
        Ok(remember(&PICKED_FOLDER, picked))
    })
    .await
}

/// Asks for a KeePass file to use in a system file dialog, and returns it
/// for the page to show; `None` when the dialog was cancelled. Nothing is
/// read from it yet.
#[tauri::command]
pub async fn vault_pick_file(
    app: AppHandle,
    state: State<'_, Shared>,
) -> AppResult<Option<String>> {
    blocking(&state, move |_| {
        let mut dialog = app
            .dialog()
            .file()
            .set_title(
                Localized::new(
                    "Choose a vault file",
                    "Выберите файл хранилища",
                    "Ombor faylini tanlang",
                )
                .pick(),
            )
            .add_filter(
                Localized::new("KeePass databases", "Базы KeePass", "KeePass bazalari").pick(),
                &["kdbx"],
            );
        if let Some(window) = app.get_webview_window("main") {
            dialog = dialog.set_parent(&window);
        }
        let picked = dialog.blocking_pick_file().map(into_path).transpose()?;
        Ok(remember(&PICKED_DATABASE, picked))
    })
    .await
}

/// Moves both files into `folder`, the one picked in [`vault_pick_folder`],
/// locked or unlocked, once the user confirms in a native dialog. Refuses
/// if the folder already has files of those names.
#[tauri::command]
pub async fn vault_move(
    app: AppHandle,
    state: State<'_, Shared>,
    folder: String,
) -> AppResult<VaultLocation> {
    let folder = picked(&PICKED_FOLDER, &folder, "choose the folder again")?;
    blocking(&state, move |state| {
        confirm_move(&app, &folder)?;
        move_to_folder(&state.vault, &folder)?;
        forget_pick(&PICKED_FOLDER);
        Ok(after_change(&app, state))
    })
    .await
}

/// Switches to an existing KeePass file — this vault on another computer,
/// or a KeePassXC database — once the user confirms in a native dialog:
/// `path`, the one picked in [`vault_pick_file`], which isn't opened before.
/// The current vault locks and stays where it is; the new one opens with
/// its master password, or, without a keys file, with its recovery key or
/// KeePass password.
#[tauri::command]
pub async fn vault_use_file(
    app: AppHandle,
    state: State<'_, Shared>,
    path: String,
) -> AppResult<VaultLocation> {
    let path = picked(&PICKED_DATABASE, &path, "choose the file again")?;
    blocking(&state, move |state| {
        // Compared as named: the file is touched only after the yes.
        if state.vault.paths().database != path {
            confirm_switch(&app, &path)?;
        }
        vault::check_database(&path)?;
        forget_pick(&PICKED_DATABASE);
        // The `.env` files written while it is unlocked go first, their
        // edits in the vault; back if it stays.
        state.vault.put_files_away();
        let locked = use_file(&state.vault, &path);
        if !matches!(locked, Ok(true)) {
            state.vault.resume_files();
        }
        if locked? {
            state.vault.lost();
            let _ = app.emit(LOCKED_EVENT, LockReason::Manual);
        }
        Ok(after_change(&app, state))
    })
    .await
}

/// Goes back to the default place, once the user confirms in a native
/// dialog: with `move_files`, the vault's files move there (refused if a
/// vault is there already); otherwise the vault there is used and the
/// current one locks and stays where it is.
#[tauri::command]
pub async fn vault_use_default(
    app: AppHandle,
    state: State<'_, Shared>,
    move_files: bool,
) -> AppResult<VaultLocation> {
    blocking(&state, move |state| {
        let default = state.vault.default_paths();
        if state.vault.paths() != default {
            match default.database.parent() {
                Some(folder) if move_files => confirm_move(&app, folder)?,
                _ => confirm_switch(&app, &default.database)?,
            }
        }
        // The `.env` files written while it is unlocked go first, their
        // edits in the vault; back if it stays.
        state.vault.put_files_away();
        let locked = use_default(&state.vault, move_files);
        if !matches!(locked, Ok(true)) {
            state.vault.resume_files();
        }
        if locked? {
            state.vault.lost();
            let _ = app.emit(LOCKED_EVENT, LockReason::Manual);
        }
        Ok(after_change(&app, state))
    })
    .await
}

fn confirm_move(app: &AppHandle, folder: &Path) -> AppResult<()> {
    confirm::require(
        app,
        &Localized::new(
            "Move the vault?",
            "Переместить хранилище?",
            "Ombor koʻchirilsinmi?",
        ),
        &move_body(folder),
        &Localized::new("Move", "Переместить", "Koʻchirish"),
    )
}

fn move_body(folder: &Path) -> Localized {
    let folder = shown_path(folder);
    Localized::new(
        format!(
            "The vault’s files will move to:\n{folder}\n\n\
                 Anyone who can read this folder gets the encrypted vault. \
                 Continue only if you chose this folder yourself."
        ),
        format!(
            "Файлы хранилища переместятся в папку:\n{folder}\n\n\
                 Любой, кто может читать эту папку, получит зашифрованное хранилище. \
                 Продолжайте, только если эту папку выбрали вы."
        ),
        format!(
            "Ombor fayllari bu papkaga koʻchadi:\n{folder}\n\n\
                 Bu papkani oʻqiy oladigan har kim shifrlangan omborni oladi. \
                 Bu papkani oʻzingiz tanlagan boʻlsangizgina davom eting."
        ),
    )
}

fn confirm_switch(app: &AppHandle, database: &Path) -> AppResult<()> {
    confirm::require(
        app,
        &Localized::new(
            "Use another vault file?",
            "Открыть другой файл хранилища?",
            "Boshqa ombor fayli ishlatilsinmi?",
        ),
        &switch_body(database),
        &Localized::new("Use this file", "Открыть файл", "Shu faylni ishlatish"),
    )
}

fn switch_body(database: &Path) -> Localized {
    let database = shown_path(database);
    Localized::new(
        format!(
            "The current vault locks, and passwords will be read from and saved to:\n\
                 {database}\n\nContinue only if you chose this file yourself."
        ),
        format!(
            "Текущее хранилище заблокируется, а пароли будут читаться из этого файла \
                 и сохраняться в него:\n{database}\n\n\
                 Продолжайте, только если этот файл выбрали вы."
        ),
        format!(
            "Joriy ombor qulflanadi, parollar esa shu fayldan oʻqiladi va unga \
                 saqlanadi:\n{database}\n\n\
                 Bu faylni oʻzingiz tanlagan boʻlsangizgina davom eting."
        ),
    )
}

/// A path as the confirmation shows it: whole, with control and invisible
/// characters made visible, so a name can't add lines to the dialog or
/// show its text reversed.
fn shown_path(path: &Path) -> String {
    confirm::shown(&path.to_string_lossy(), usize::MAX)
}

/// Keeps `picked`, the path a system dialog this side opened returned, as
/// the one `slot` lets the page use, and returns it for the page to show.
fn remember(slot: &Mutex<Option<PathBuf>>, picked: Option<PathBuf>) -> Option<String> {
    let mut slot = slot.lock().unwrap_or_else(PoisonError::into_inner);
    let picked = picked?;
    let shown = picked.to_string_lossy().into_owned();
    *slot = Some(picked);
    Some(shown)
}

/// The path picked last into `slot`, if the page names that one; any other
/// path fails with `again`.
fn picked(slot: &Mutex<Option<PathBuf>>, named: &str, again: &str) -> AppResult<PathBuf> {
    let slot = slot.lock().unwrap_or_else(PoisonError::into_inner);
    match slot.as_ref() {
        Some(path) if path.as_os_str() == named => Ok(path.clone()),
        _ => Err(AppError::invalid(again)),
    }
}

fn forget_pick(slot: &Mutex<Option<PathBuf>>) {
    slot.lock().unwrap_or_else(PoisonError::into_inner).take();
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

fn last_import() -> std::sync::MutexGuard<'static, Option<PathBuf>> {
    LAST_IMPORT.lock().unwrap_or_else(PoisonError::into_inner)
}

fn picked_import() -> std::sync::MutexGuard<'static, Option<PathBuf>> {
    PICKED_IMPORT.lock().unwrap_or_else(PoisonError::into_inner)
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
    fn only_the_path_picked_in_the_dialog_is_used() {
        let slot = Mutex::new(None);
        assert_eq!(
            code(&picked(&slot, "/elsewhere", "again").unwrap_err()),
            "invalid_input"
        );
        let shown = remember(&slot, Some(PathBuf::from("/Users/me/Dropbox"))).unwrap();
        assert_eq!(shown, "/Users/me/Dropbox");
        assert_eq!(
            picked(&slot, "/Users/me/Dropbox", "again").unwrap(),
            PathBuf::from("/Users/me/Dropbox")
        );
        // Another path, even one that leads to the same place, is refused.
        for named in ["/Users/me/Dropbox/../Public", "/Users/Shared", ""] {
            assert!(picked(&slot, named, "again").is_err(), "{named}");
        }
        forget_pick(&slot);
        assert!(picked(&slot, "/Users/me/Dropbox", "again").is_err());
    }

    #[test]
    fn the_dialogs_show_the_path_with_its_hidden_characters() {
        let folder = Path::new("/Users/me/Cloud\u{202E}stnemucod\nOK");
        let body = move_body(folder).en;
        assert!(body.contains("/Users/me/Cloud<U+202E>stnemucod<U+000A>OK\n\nAnyone"));
        assert!(!body.contains('\u{202E}'));
        let body = switch_body(Path::new("/Volumes/USB/vault\u{200F}.kdbx")).ru;
        assert!(body.contains("/Volumes/USB/vault<U+200F>.kdbx"));
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
