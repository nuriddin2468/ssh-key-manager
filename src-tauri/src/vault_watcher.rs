//! Tells the UI when the vault's files change on disk — typically a sync
//! client (Dropbox, iCloud Drive) bringing a version saved on another
//! computer — so it refetches, and the unlocked vault reloads the file.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Mutex, PoisonError};
use std::thread;

use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use sshkm_core::vault::VaultPaths;
use tauri::{AppHandle, Emitter, Manager};

use crate::watcher::{QUIET, debounce, is_change};

pub const EVENT: &str = "vault-changed";

/// Starts watching the vault's folder; [`VaultWatcher::follow`] moves the
/// watch along with the vault.
pub fn start(app: &AppHandle, paths: &VaultPaths) {
    let watcher = VaultWatcher::default();
    watcher.follow(app, paths);
    app.manage(watcher);
}

/// The watch on the vault's folder; replaced when the vault moves.
#[derive(Default)]
pub struct VaultWatcher(Mutex<Option<Watching>>);

struct Watching {
    database: PathBuf,
    /// Dropping it stops the watch and its debounce thread.
    _watcher: RecommendedWatcher,
}

impl VaultWatcher {
    /// Watches the folder of `paths` for changes to the vault's files,
    /// instead of wherever it watched before. A folder that doesn't exist
    /// (no vault yet) isn't watched.
    pub fn follow(&self, app: &AppHandle, paths: &VaultPaths) {
        let mut current = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if current
            .as_ref()
            .is_some_and(|w| w.database == paths.database)
        {
            return;
        }
        *current = None;
        let Some(folder) = paths.database.parent().filter(|dir| dir.is_dir()) else {
            return;
        };
        let names: Vec<OsString> = [&paths.database, &paths.keys]
            .iter()
            .filter_map(|p| p.file_name().map(ToOwned::to_owned))
            .collect();
        let emitter = app.clone();
        match watch(folder, names, move || {
            let _ = emitter.emit(EVENT, ());
        }) {
            Ok(watcher) => {
                *current = Some(Watching {
                    database: paths.database.clone(),
                    _watcher: watcher,
                });
            }
            Err(error) => log::warn!("not watching {}: {error}", folder.display()),
        }
    }
}

fn watch(
    folder: &Path,
    names: Vec<OsString>,
    on_change: impl Fn() + Send + 'static,
) -> notify::Result<RecommendedWatcher> {
    let (signal, signals) = mpsc::channel();
    let mut watcher = notify::recommended_watcher(move |result: notify::Result<Event>| {
        if let Ok(event) = result
            && is_change(&event)
            && concerns(&event, &names)
        {
            let _ = signal.send(());
        }
    })?;
    watcher.watch(folder, RecursiveMode::NonRecursive)?;
    thread::spawn(move || debounce(&signals, QUIET, on_change));
    Ok(watcher)
}

/// The event touches one of the vault's files. Events without paths (a
/// rescan after dropped events) might, too.
fn concerns(event: &Event, names: &[OsString]) -> bool {
    event.paths.is_empty()
        || event.paths.iter().any(|path| {
            path.file_name()
                .is_some_and(|name| names.iter().any(|n| n == name))
        })
}

#[cfg(test)]
mod tests {
    use notify::EventKind;
    use notify::event::{CreateKind, ModifyKind, RenameMode};

    use super::*;

    #[test]
    fn only_the_vault_files_count() {
        let names = vec![OsString::from("vault.kdbx"), OsString::from("vault.keys")];
        let event = |path: &str| {
            Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::To))).add_path(path.into())
        };
        assert!(concerns(&event("/sync/vault.kdbx"), &names));
        assert!(concerns(&event("/sync/vault.keys"), &names));
        assert!(!concerns(&event("/sync/notes.txt"), &names));
        assert!(!concerns(&event("/sync/.vault.kdbx.abc.sshkm-tmp"), &names));
        assert!(concerns(
            &Event::new(EventKind::Create(CreateKind::Any)),
            &names
        ));
    }
}
