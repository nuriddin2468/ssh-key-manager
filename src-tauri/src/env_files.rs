//! Keeps the managed `.env` files in step with the vault while the app runs
//! (`sshkm_core::vault::envs::files`).
//!
//! A round runs after the vault changes (a change here, an unlock, the
//! vault's file changed by another computer) and after a bound file changes
//! on disk. Each folder that holds a bound file is watched for changes to
//! those names, so an editor that saves by writing a new file and renaming
//! it over the old one is seen as well. Bursts of changes are taken once
//! they settle. A round does nothing while the vault is locked; the next
//! one after unlocking catches what changed meanwhile, by the revisions
//! kept in `env-files.json` (keyed hashes, no values).
//!
//! The UI hears of each round that changed something, or where a file's
//! state changed, through [`EVENT`], with the edits that went to the vault
//! (to offer Undo) and every file's state.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;

use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use sshkm_core::ErrorCode;
use sshkm_core::paths::home_dir;
use sshkm_core::vault::envs::files::{
    EnvFileStatus, EnvFilesSynced, FilesContext, Preference, SyncState,
};
use sshkm_core::vault::projects;
use tauri::{AppHandle, Emitter, Manager};

use crate::error::AppResult;
use crate::state::AppState;
use crate::watcher::{QUIET, debounce, is_change};

pub const EVENT: &str = "env-files-changed";
const STATE_FILE: &str = "env-files.json";

/// The managed files' state on this computer, and the watch on their
/// folders.
pub struct EnvFiles {
    state_path: PathBuf,
    state: Mutex<SyncState>,
    signal: Mutex<Option<Sender<()>>>,
    watch: Mutex<Watch>,
    /// The files as the UI last heard of them.
    last: Mutex<Vec<EnvFileStatus>>,
}

#[derive(Default)]
struct Watch {
    watcher: Option<RecommendedWatcher>,
    folders: BTreeSet<PathBuf>,
    /// What changes count.
    wanted: Arc<Mutex<Wanted>>,
}

/// What a change has to touch to count.
#[derive(Default)]
struct Wanted {
    /// The names of the bound files ([`name_key`]); a change to any other
    /// name in their folders is not one of theirs.
    names: BTreeSet<String>,
    /// Folders on the way to a bound file's folder that isn't there yet,
    /// inside its project's folder: anything made in them may be it.
    on_the_way: BTreeSet<PathBuf>,
}

impl EnvFiles {
    pub fn new(data_dir: &Path) -> Self {
        let state_path = data_dir.join(STATE_FILE);
        Self {
            state: Mutex::new(SyncState::load(&state_path)),
            state_path,
            signal: Mutex::new(None),
            watch: Mutex::new(Watch::default()),
            last: Mutex::new(Vec::new()),
        }
    }

    /// Starts the thread that runs a round once requests settle, and has
    /// every change of the vault request one.
    pub fn start(self: &Arc<Self>, app: &AppHandle, state: &AppState) {
        let (signal, signals) = mpsc::channel();
        *lock(&self.signal) = Some(signal);
        let files = Arc::clone(self);
        let handle = app.clone();
        thread::spawn(move || {
            debounce(&signals, QUIET, || {
                let Some(shared) = handle.try_state::<Arc<AppState>>() else {
                    return;
                };
                if let Err(error) = files.sync(&handle, shared.inner(), None, false)
                    && error.code() != ErrorCode::VaultLocked
                {
                    log::warn!("env files: {error}");
                }
            });
        });
        let files = Arc::clone(self);
        state.vault.on_change(move || files.request());
        self.request();
    }

    /// Asks for a round soon.
    pub fn request(&self) {
        if let Some(signal) = lock(&self.signal).as_ref() {
            let _ = signal.send(());
        }
    }

    /// The revisions kept, for a view of the files.
    pub fn state(&self) -> SyncState {
        lock(&self.state).clone()
    }

    /// One round now: edits of files go to the vault, which is saved, then
    /// files whose vault side changed are written. `prefer` settles one
    /// file a given way. Tells the UI if anything changed.
    pub fn sync(
        &self,
        app: &AppHandle,
        shared: &AppState,
        prefer: Option<Preference<'_>>,
        activity: bool,
    ) -> AppResult<EnvFilesSynced> {
        // Environments from before projects are in theirs first: a file of
        // one isn't out of its project just because the step is to come.
        crate::commands::projects::tidy_projects(app, shared);
        let ctx = context(shared);
        let mut state = lock(&self.state);
        let synced =
            shared
                .vault
                .with_files(app, &shared.backup_dir, activity, |vault, save| {
                    let before = vault.snapshot();
                    let pulled = match vault.env_files_pull(&ctx, &state, prefer) {
                        Ok(pulled) => pulled,
                        Err(error) => {
                            vault.restore(before);
                            return Err(error.into());
                        }
                    };
                    if pulled.vault_changed {
                        save(vault)?;
                    }
                    Ok(vault.env_files_push(&ctx, &mut state, pulled, prefer))
                })?;
        if let Err(error) = state.save(&self.state_path) {
            log::warn!("env files: the revisions were not kept: {error}");
        }
        drop(state);
        self.follow(app, &synced.files);
        self.tell(app, &synced);
        Ok(synced)
    }

    /// Tells the UI of a round that changed something, or after which a
    /// file stands elsewhere.
    fn tell(&self, app: &AppHandle, synced: &EnvFilesSynced) {
        let mut last = lock(&self.last);
        let moved = *last != synced.files;
        if moved || !synced.changes.is_empty() || !synced.written.is_empty() {
            last.clone_from(&synced.files);
            let _ = app.emit(EVENT, synced);
        }
    }

    /// Watches the folders of the files in `files` for changes to their
    /// names, instead of the folders watched before; for a file whose folder
    /// isn't there yet, the nearest folder on the way inside its project's
    /// folder, for anything made there.
    fn follow(&self, app: &AppHandle, files: &[EnvFileStatus]) {
        let home = home_dir();
        let mut folders: BTreeSet<PathBuf> = BTreeSet::new();
        let mut wanted = Wanted::default();
        for status in files {
            let Some(location) = status.location.as_deref() else {
                continue;
            };
            if let Some(name) = location.file_name() {
                wanted.names.insert(name_key(name));
            }
            let Some(folder) = location.parent() else {
                continue;
            };
            if folder.is_dir() {
                folders.insert(folder.to_path_buf());
            } else if let Some(project) =
                projects::folder_path(&status.file.folder, home.as_deref())
                && let Some(nearest) = folder
                    .ancestors()
                    .take_while(|ancestor| ancestor.starts_with(&project))
                    .find(|ancestor| ancestor.is_dir())
            {
                folders.insert(nearest.to_path_buf());
                wanted.on_the_way.insert(nearest.to_path_buf());
                if let Ok(real) = std::fs::canonicalize(nearest) {
                    wanted.on_the_way.insert(real);
                }
            }
        }
        let mut guard = lock(&self.watch);
        let watch: &mut Watch = &mut guard;
        *lock(&watch.wanted) = wanted;
        if watch.watcher.is_none() {
            let wanted = Arc::clone(&watch.wanted);
            let handle = app.clone();
            let made = notify::recommended_watcher(move |result: notify::Result<Event>| {
                if let Ok(event) = result
                    && is_change(&event)
                    && concerns(&event, &lock(&wanted))
                    && let Some(files) = handle.try_state::<Arc<EnvFiles>>()
                {
                    files.request();
                }
            });
            match made {
                Ok(watcher) => watch.watcher = Some(watcher),
                Err(error) => {
                    log::warn!("env files: not watching: {error}");
                    return;
                }
            }
        }
        let gone: Vec<PathBuf> = watch.folders.difference(&folders).cloned().collect();
        let new: Vec<PathBuf> = folders.difference(&watch.folders).cloned().collect();
        let Some(watcher) = watch.watcher.as_mut() else {
            return;
        };
        for folder in &gone {
            let _ = watcher.unwatch(folder);
        }
        let mut watching: BTreeSet<PathBuf> = watch
            .folders
            .iter()
            .filter(|folder| !gone.contains(folder))
            .cloned()
            .collect();
        for folder in new {
            match watcher.watch(&folder, RecursiveMode::NonRecursive) {
                Ok(()) => {
                    watching.insert(folder);
                }
                Err(error) => log::warn!("env files: not watching {}: {error}", folder.display()),
            }
        }
        watch.folders = watching;
    }
}

/// What finding files on this computer needs.
pub fn context(state: &AppState) -> FilesContext {
    FilesContext {
        home: home_dir(),
        ssh_dir: state.paths.dir.clone(),
    }
}

/// The event names a bound file, or may (a rescan names none), or makes
/// something in a folder on the way to a bound file's folder.
fn concerns(event: &Event, wanted: &Wanted) -> bool {
    event.paths.is_empty()
        || event.paths.iter().any(|path| {
            path.file_name()
                .is_some_and(|name| wanted.names.contains(&name_key(name)))
                || path
                    .parent()
                    .is_some_and(|folder| wanted.on_the_way.contains(folder))
        })
}

/// A file name as names are compared: without case where the file system
/// usually ignores it (macOS, Windows), so a binding whose case differs
/// from the file's is seen.
fn name_key(name: &OsStr) -> String {
    let name = name.to_string_lossy();
    if cfg!(any(target_os = "macos", windows)) {
        name.to_lowercase()
    } else {
        name.into_owned()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use notify::EventKind;
    use notify::event::{CreateKind, ModifyKind, RenameMode};

    use super::*;

    #[test]
    fn only_bound_names_count() {
        let wanted = Wanted {
            names: [".env", ".env.local"]
                .map(|n| name_key(OsStr::new(n)))
                .into(),
            on_the_way: [PathBuf::from("/code/shop/apps")].into(),
        };
        let event = |path: &str| {
            Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::To))).add_path(path.into())
        };
        assert!(concerns(&event("/code/shop/.env"), &wanted));
        assert!(concerns(&event("/code/shop/.env.local"), &wanted));
        assert!(!concerns(&event("/code/shop/.env.local.swp"), &wanted));
        assert!(!concerns(
            &event("/code/shop/.env.sshkm-Ab12Cd.tmp"),
            &wanted
        ));
        // A folder made on the way to a bound file's folder.
        assert!(concerns(&event("/code/shop/apps/web"), &wanted));
        assert!(!concerns(&event("/code/shop/docs/web"), &wanted));
        assert!(concerns(
            &Event::new(EventKind::Create(CreateKind::Any)),
            &wanted
        ));
        // Case counts only where the file system keeps it.
        assert_eq!(
            concerns(&event("/code/shop/.ENV"), &wanted),
            cfg!(any(target_os = "macos", windows))
        );
    }
}
