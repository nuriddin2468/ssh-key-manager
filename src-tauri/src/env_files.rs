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
//!
//! **Files written only while the vault is unlocked** (level 2). Each round
//! keeps the list of those that hold what the vault holds, as they are on
//! disk, in `env-files-unlocked.json` (no values). Before the vault locks,
//! and when the app quits, one last round takes their edits to the vault
//! and they are removed ([`EnvFiles::put_away`]); one the vault couldn't
//! take stays, and the UI hears of it through [`LEFT_EVENT`]. Until the
//! next unlock no round writes them. A crash or a forced quit is caught by
//! the guard ([`crate::env_guard`]), and failing that by the next start.
//!
//! **Virtual files** (level 3, macOS and Linux). Each round makes or keeps
//! their pipes and gives them their answers, which [`crate::env_pipes`]
//! serves; a pipe whose binding went or whose level changed is stopped, and
//! the round runs once more to write a file due in its place. Before the
//! vault locks they answer that it is locked; they go when the app quits.
//! The watcher takes no notice of the app's own pipes: answering a reader
//! touches a pipe's times, which isn't an edit.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;

use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use sshkm_core::ErrorCode;
use sshkm_core::paths::home_dir;
use sshkm_core::vault::envs::files::{
    self as managed, EnvFileStatus, EnvFilesSynced, FilesContext, Leftovers, PipeId, Preference,
    PutAway, SyncState,
};
use sshkm_core::vault::projects;
use tauri::{AppHandle, Emitter, Manager};

use crate::env_guard::Guard;
use crate::env_pipes::{KnownPipes, Pipes};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::vault::VaultHooks;
use crate::watcher::{QUIET, debounce, is_change};

pub const EVENT: &str = "env-files-changed";
/// Emitted with the level-2 files left on disk when the vault locked: the
/// vault couldn't take what they hold ([`PutAway::kept`]).
pub const LEFT_EVENT: &str = "env-files-left";
const STATE_FILE: &str = "env-files.json";
/// The level-2 files on disk ([`Leftovers`]).
const LEFTOVERS_FILE: &str = "env-files-unlocked.json";

/// The managed files' state on this computer, and the watch on their
/// folders.
pub struct EnvFiles {
    state_path: PathBuf,
    state: Mutex<SyncState>,
    signal: Mutex<Option<Sender<()>>>,
    watch: Mutex<Watch>,
    /// The files as the UI last heard of them.
    last: Mutex<Vec<EnvFileStatus>>,
    leftovers_path: PathBuf,
    /// The level-2 files are put away: no round runs until the vault is
    /// unlocked again. Changed only while `state` is held.
    away: AtomicBool,
    guard: Guard,
    /// The pipes of the virtual files.
    pipes: Pipes,
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
    /// The app's pipes: a change to one that is still the same pipe is
    /// an answer it gave.
    pipes: Vec<(PathBuf, PipeId)>,
}

impl EnvFiles {
    pub fn new(data_dir: &Path, known: KnownPipes) -> Self {
        let state_path = data_dir.join(STATE_FILE);
        let leftovers_path = data_dir.join(LEFTOVERS_FILE);
        // Level-2 files a crash or a forced quit left, still as the app
        // wrote them, go before anything else.
        let removed = Leftovers::sweep_at(&leftovers_path);
        if removed > 0 {
            log::info!("env files: removed {removed} left by the last run");
        }
        Self {
            state: Mutex::new(SyncState::load(&state_path)),
            state_path,
            signal: Mutex::new(None),
            watch: Mutex::new(Watch::default()),
            last: Mutex::new(Vec::new()),
            leftovers_path,
            away: AtomicBool::new(false),
            guard: Guard::default(),
            pipes: Pipes::new(data_dir, known),
        }
    }

    /// How many virtual files the app serves now.
    pub fn served(&self) -> usize {
        self.pipes.count()
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
        let (before, after, lost) = (Arc::clone(self), Arc::clone(self), Arc::clone(self));
        let handle = app.clone();
        state.vault.set_hooks(VaultHooks {
            before_lock: Box::new(move || {
                if let Some(shared) = handle.try_state::<Arc<AppState>>() {
                    before.put_away(&handle, shared.inner());
                }
            }),
            after_unlock: Box::new(move || after.come_back()),
            after_loss: Box::new(move || lost.forget()),
        });
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
        let mut state = lock(&self.state);
        if self.away.load(Ordering::SeqCst) {
            return Err(AppError::new(
                ErrorCode::VaultLocked,
                "the vault is locking",
            ));
        }
        let synced = self.round(&mut state, app, shared, prefer, activity)?;
        drop(state);
        self.follow(app, &synced.files);
        self.tell(app, &synced);
        Ok(synced)
    }

    /// The round of [`Self::sync`], with the revisions held: pull, save,
    /// push, then the revisions and the list of level-2 files on disk are
    /// kept, and the virtual files served. When a pipe went (its level
    /// changed), once more, to write the file due in its place.
    fn round(
        &self,
        state: &mut SyncState,
        app: &AppHandle,
        shared: &AppState,
        prefer: Option<Preference<'_>>,
        activity: bool,
    ) -> AppResult<EnvFilesSynced> {
        let mut synced = self.round_once(state, app, shared, prefer, activity)?;
        if self
            .pipes
            .follow(&synced.virtual_files, !shared.vault.is_unlocked())
        {
            let first = synced;
            synced = self.round_once(state, app, shared, prefer, activity)?;
            synced.changes.splice(0..0, first.changes);
            synced.written.splice(0..0, first.written);
            self.pipes
                .follow(&synced.virtual_files, !shared.vault.is_unlocked());
        }
        if !self.pipes.is_empty() || !synced.unlocked.is_empty() {
            self.guard
                .ensure(&self.leftovers_path, self.pipes.list_path());
        }
        Ok(synced)
    }

    /// One pass of [`Self::round`].
    fn round_once(
        &self,
        state: &mut SyncState,
        app: &AppHandle,
        shared: &AppState,
        prefer: Option<Preference<'_>>,
        activity: bool,
    ) -> AppResult<EnvFilesSynced> {
        let ctx = context(shared);
        let synced =
            shared
                .vault
                .with_files(app, &shared.backup_dir, activity, |vault, save| {
                    let before = vault.snapshot();
                    let pulled = match vault.env_files_pull(&ctx, state, prefer) {
                        Ok(pulled) => pulled,
                        Err(error) => {
                            vault.restore(before);
                            return Err(error.into());
                        }
                    };
                    if pulled.vault_changed {
                        save(vault)?;
                    }
                    Ok(vault.env_files_push(&ctx, state, pulled, prefer))
                })?;
        if let Err(error) = state.save(&self.state_path) {
            log::warn!("env files: the revisions were not kept: {error}");
        }
        let leftovers = Leftovers::new(synced.unlocked.clone());
        // Those whose binding went since the last round go now: nothing
        // else would remove them.
        Leftovers::load(&self.leftovers_path).sweep_dropped(&leftovers, &synced.always);
        if let Err(error) = leftovers.save(&self.leftovers_path) {
            log::warn!("env files: the files written while unlocked were not listed: {error}");
        }
        // The vault went while the round finished: its files go too.
        if !leftovers.is_empty() && !shared.vault.is_unlocked() {
            self.forget();
        }
        Ok(synced)
    }

    /// Puts the files written only while the vault is unlocked away, before
    /// it locks or the app quits: one last round takes their edits to the
    /// vault, then those that hold what it holds are removed. Those it
    /// couldn't take stay, and the UI hears of them ([`LEFT_EVENT`]). No
    /// round runs after, until the vault is unlocked again. Without the
    /// vault, the files still as the last round left them go.
    pub fn put_away(&self, app: &AppHandle, shared: &AppState) -> PutAway {
        let mut state = lock(&self.state);
        if self.away.swap(true, Ordering::SeqCst) {
            return PutAway::default();
        }
        // No level-2 file on disk as the app wrote it: none to take edits
        // from or to remove, and the lock doesn't wait for a round. Those
        // the vault couldn't take, by the last round, stay.
        if Leftovers::load(&self.leftovers_path).is_empty() {
            self.pipes.lock();
            let kept = managed::left_on_disk(&lock(&self.last));
            drop(state);
            if !kept.is_empty() {
                let _ = app.emit(LEFT_EVENT, &kept);
            }
            return PutAway { removed: 0, kept };
        }
        let away = match self.round(&mut state, app, shared, None, false) {
            Ok(synced) => managed::put_away(&synced),
            Err(error) => {
                if error.code() != ErrorCode::VaultLocked {
                    log::warn!("env files: the last round before locking failed: {error}");
                }
                PutAway {
                    removed: Leftovers::sweep_at(&self.leftovers_path),
                    kept: Vec::new(),
                }
            }
        };
        if let Err(error) = Leftovers::default().save(&self.leftovers_path) {
            log::warn!("env files: the list of files written while unlocked stays: {error}");
        }
        self.pipes.lock();
        drop(state);
        if !away.kept.is_empty() {
            log::warn!(
                "env files: {} written while unlocked stay on disk until the next unlock",
                away.kept.len()
            );
            let _ = app.emit(LEFT_EVENT, &away.kept);
        }
        away
    }

    /// Runs `unbind`, which stops writing a level-2 file the user keeps (at
    /// `location`), while no round runs, then takes the file off the list,
    /// so no sweep removes it.
    pub fn keep_file<T>(
        &self,
        location: &Path,
        unbind: impl FnOnce() -> AppResult<T>,
    ) -> AppResult<T> {
        let _state = lock(&self.state);
        let result = unbind()?;
        let real = std::fs::canonicalize(location).unwrap_or_else(|_| location.to_path_buf());
        let mut list = Leftovers::load(&self.leftovers_path);
        if list.forget(&real)
            && let Err(error) = list.save(&self.leftovers_path)
        {
            log::warn!("env files: the list of files written while unlocked stays: {error}");
        }
        Ok(result)
    }

    /// After an unlock: rounds run again, and write the level-2 files.
    fn come_back(&self) {
        let _state = lock(&self.state);
        self.away.store(false, Ordering::SeqCst);
    }

    /// The vault went without [`Self::put_away`]: the level-2 files still
    /// as the last round left them go, and the virtual files answer that
    /// it is locked. Runs while the vault may be held, by this thread too,
    /// so it doesn't wait for the revisions.
    fn forget(&self) {
        self.pipes.lock();
        Leftovers::sweep_at(&self.leftovers_path);
    }

    /// When the app quits: the files written only while unlocked go, the
    /// virtual files' pipes too, and the guard with them.
    pub fn quit(&self, app: &AppHandle, shared: &AppState) {
        self.put_away(app, shared);
        let _state = lock(&self.state);
        self.pipes.quit();
        self.guard.stop();
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
        wanted.pipes = self.pipes.watched();
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
        pipes: state
            .served_pipes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone(),
    }
}

/// The event names a bound file, or may (a rescan names none), or makes
/// something in a folder on the way to a bound file's folder. Not one of
/// the app's pipes that is still the same pipe: that is an answer it gave.
fn concerns(event: &Event, wanted: &Wanted) -> bool {
    event.paths.is_empty()
        || event.paths.iter().any(|path| {
            let own_pipe = wanted
                .pipes
                .iter()
                .any(|(pipe, id)| pipe == path && PipeId::of(path) == Some(*id));
            !own_pipe
                && (path
                    .file_name()
                    .is_some_and(|name| wanted.names.contains(&name_key(name)))
                    || path
                        .parent()
                        .is_some_and(|folder| wanted.on_the_way.contains(folder)))
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
            pipes: Vec::new(),
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

    #[cfg(unix)]
    #[test]
    fn the_apps_own_pipes_dont_count() {
        use notify::event::MetadataKind;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        let id = managed::pipes::make(&path).unwrap();
        let wanted = Wanted {
            names: [name_key(OsStr::new(".env"))].into(),
            on_the_way: BTreeSet::new(),
            pipes: vec![(path.clone(), id)],
        };
        let touched = Event::new(EventKind::Modify(ModifyKind::Metadata(MetadataKind::Any)))
            .add_path(path.clone());
        // Answering a reader touches its times: not an edit.
        assert!(!concerns(&touched, &wanted));
        // A file saved over it is one.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, "A=1\n").unwrap();
        assert!(concerns(&touched, &wanted));
    }
}
