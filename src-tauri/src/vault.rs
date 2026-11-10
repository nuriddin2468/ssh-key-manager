//! The password vault while the app runs: where it lives, whether it is
//! unlocked, when it locks itself, and copying its secrets to the clipboard.
//!
//! The unlocked [`Vault`] exists only in this process and is dropped (locked)
//! on request, after a period without activity, after the computer slept,
//! when the screen locks ([`crate::device_unlock`]) or when the window is
//! minimised, as the settings say. Every lock emits
//! [`LOCKED_EVENT`] so the UI can switch to its lock screen, and clears the
//! clipboard if it still holds a secret copied from the vault. Every unlock
//! emits [`UNLOCKED_EVENT`]: the vault may be opened outside the main window
//! (for the browser, while that window is hidden), and the main window, the
//! tray and the browser's unlock window follow.
//!
//! Activity is what the user does: the UI reports input ([`VaultRuntime::touch`])
//! and commands the user starts count too. Reads the UI repeats on its own —
//! the entry list, an entry, a 2FA code refreshing every 30 seconds — use
//! [`VaultRuntime::with_quietly`], so an open window never keeps the vault
//! unlocked by itself.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sshkm_core::vault::projects::{self, Project};
use sshkm_core::vault::{self as core_vault, Vault, VaultPaths};
use sshkm_core::{ErrorCode, ExposeSecret, SecretString, fsutil};
use tauri::{AppHandle, Emitter};

use crate::error::{AppError, AppResult};

/// Emitted with a [`LockReason`] whenever the vault locks.
pub const LOCKED_EVENT: &str = "vault-locked";
/// Emitted whenever the vault is unlocked, by any window or prompt.
pub const UNLOCKED_EVENT: &str = "vault-unlocked";

const SETTINGS_FILE: &str = "vault.json";
/// The projects without secrets, shown while the vault is locked.
const PROJECTS_COPY: &str = "projects.json";
const DATABASE_FILE: &str = "vault.kdbx";
const TICK: Duration = Duration::from_secs(5);
/// A tick that comes this late means the computer was asleep.
const SLEEP_GAP: Duration = Duration::from_secs(60);

/// Vault preferences, kept by the Rust side because the timers run here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent on/off preferences"
)]
pub struct VaultSettings {
    /// The database file; `None` for the default in the app's data folder.
    pub database: Option<PathBuf>,
    /// Lock after this many minutes without activity; `None` never.
    pub auto_lock_minutes: Option<u32>,
    /// Clear a copied password or code after this many seconds; 0 never.
    pub clipboard_seconds: u32,
    pub lock_on_sleep: bool,
    pub lock_on_screen_lock: bool,
    pub lock_on_minimize: bool,
    /// Unlock SSH keys whose passphrases are saved when the vault opens.
    pub unlock_keys_on_open: bool,
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            database: None,
            auto_lock_minutes: Some(5),
            clipboard_seconds: 30,
            lock_on_sleep: true,
            lock_on_screen_lock: true,
            lock_on_minimize: false,
            unlock_keys_on_open: false,
        }
    }
}

/// Why the vault locked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum LockReason {
    Manual,
    Idle,
    Sleep,
    ScreenLock,
    Minimize,
    /// The vault changed elsewhere in a way this copy can't follow, e.g. its
    /// recovery key was replaced on another computer.
    Changed,
}

impl LockReason {
    /// Whether this lock means the user left the computer, or the vault is
    /// another now, which ends their [session](VaultRuntime::session). Locks
    /// after inactivity or on minimise don't.
    fn ends_session(self) -> bool {
        !matches!(self, Self::Idle | Self::Minimize)
    }
}

/// The vault's runtime state, shared by all commands.
pub struct VaultRuntime {
    data_dir: PathBuf,
    settings: Mutex<VaultSettings>,
    unlocked: Mutex<Option<Vault>>,
    last_activity: Mutex<Instant>,
    clipboard: Mutex<ClipboardState>,
    /// Bumped whenever a session ends.
    session: AtomicU64,
    /// For [`UNLOCKED_EVENT`]; set when the timer starts.
    app: OnceLock<AppHandle>,
}

#[derive(Default)]
struct ClipboardState {
    /// Kept alive: on X11 the clipboard's owner must stay around to serve it.
    clipboard: Option<arboard::Clipboard>,
    /// Bumped on every copy, so a pending clear only clears its own copy.
    generation: u64,
    /// SHA-256 of the secret copied last, cleared when the vault locks if
    /// the clipboard still holds it.
    secret: Option<[u8; 32]>,
}

/// How long a copied recovery key stays on the clipboard when the settings
/// say never to clear it: it opens everything, so it is always cleared.
const RECOVERY_KEY_SECONDS: u32 = 30;

/// A settings change that leaves the vault less protected; it needs the
/// user's confirmation in a native dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Weakening {
    /// Auto-lock after `old` minutes becomes never (`None`) or later.
    AutoLock {
        old: u32,
        new: Option<u32>,
    },
    /// Clearing the clipboard after `old` seconds becomes never (0) or later.
    Clipboard {
        old: u32,
        new: u32,
    },
    LockOnSleep,
    LockOnScreenLock,
    LockOnMinimize,
}

impl VaultSettings {
    /// What `next` weakens compared with these settings, in the order the
    /// settings page shows them.
    pub fn weakened_by(&self, next: &Self) -> Vec<Weakening> {
        let mut weakened = Vec::new();
        if let Some(old) = self.auto_lock_minutes
            && next.auto_lock_minutes.is_none_or(|new| new > old)
        {
            weakened.push(Weakening::AutoLock {
                old,
                new: next.auto_lock_minutes,
            });
        }
        let (old, new) = (self.clipboard_seconds, next.clipboard_seconds);
        if old > 0 && (new == 0 || new > old) {
            weakened.push(Weakening::Clipboard { old, new });
        }
        for (was, is, weakening) in [
            (
                self.lock_on_sleep,
                next.lock_on_sleep,
                Weakening::LockOnSleep,
            ),
            (
                self.lock_on_screen_lock,
                next.lock_on_screen_lock,
                Weakening::LockOnScreenLock,
            ),
            (
                self.lock_on_minimize,
                next.lock_on_minimize,
                Weakening::LockOnMinimize,
            ),
        ] {
            if was && !is {
                weakened.push(weakening);
            }
        }
        weakened
    }
}

impl VaultRuntime {
    pub fn new(data_dir: PathBuf) -> Self {
        let settings = load_settings(&data_dir.join(SETTINGS_FILE));
        Self {
            data_dir,
            settings: Mutex::new(settings),
            unlocked: Mutex::new(None),
            last_activity: Mutex::new(Instant::now()),
            clipboard: Mutex::new(ClipboardState::default()),
            session: AtomicU64::new(0),
            app: OnceLock::new(),
        }
    }

    /// The user's session at the computer, as a number that changes when it
    /// ends: when the vault is locked by hand, the screen locks, the computer
    /// sleeps (whatever the lock settings say), or the vault changed
    /// elsewhere or is another file now. Locking after inactivity or on
    /// minimise keeps it. What the user allowed browsers to fill lasts as
    /// long as it does.
    pub fn session(&self) -> u64 {
        self.session.load(Ordering::SeqCst)
    }

    /// Ends the user's [session](Self::session).
    pub fn end_session(&self) {
        self.session.fetch_add(1, Ordering::SeqCst);
    }

    pub fn settings(&self) -> VaultSettings {
        lock(&self.settings).clone()
    }

    /// The app's data folder, home of the vault's settings.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn set_settings(&self, settings: VaultSettings) -> AppResult<VaultSettings> {
        if settings.auto_lock_minutes == Some(0) {
            return Err(AppError::invalid("auto-lock needs at least one minute"));
        }
        let mut json = serde_json::to_vec_pretty(&settings)
            .map_err(|e| AppError::new(ErrorCode::Io, e.to_string()))?;
        json.push(b'\n');
        fsutil::atomic_write(&self.data_dir.join(SETTINGS_FILE), &json, 0o600)?;
        *lock(&self.settings) = settings.clone();
        Ok(settings)
    }

    /// Where the vault's files are, as the settings say.
    pub fn paths(&self) -> VaultPaths {
        let database = lock(&self.settings)
            .database
            .clone()
            .unwrap_or_else(|| self.data_dir.join(DATABASE_FILE));
        VaultPaths::new(database)
    }

    /// The vault's default place, in the app's data folder.
    pub fn default_paths(&self) -> VaultPaths {
        VaultPaths::new(self.data_dir.join(DATABASE_FILE))
    }

    /// Points the settings at another database file and saves them. The
    /// default place is stored as `None`, so it follows the data folder.
    pub fn set_database(&self, database: &Path) -> AppResult<VaultSettings> {
        self.end_session();
        let mut settings = self.settings();
        settings.database =
            (database != self.default_paths().database).then(|| database.to_path_buf());
        self.set_settings(settings)
    }

    /// Runs `work` with the vault, unlocked (`Some`) or locked (`None`),
    /// while no other command can use it: for moving or switching its files.
    /// Taking the vault out of the slot locks it without telling the UI.
    pub fn exclusive<T>(
        &self,
        work: impl FnOnce(&mut Option<Vault>) -> AppResult<T>,
    ) -> AppResult<T> {
        let mut guard = lock(&self.unlocked);
        work(&mut guard)
    }

    pub fn is_unlocked(&self) -> bool {
        lock(&self.unlocked).is_some()
    }

    pub fn set_unlocked(&self, vault: Vault) {
        // Logins read from a browser for the vault open before are not for this one.
        crate::commands::browser_import::forget();
        self.remember_projects(&vault);
        *lock(&self.unlocked) = Some(vault);
        self.touch();
        if let Some(app) = self.app.get() {
            let _ = app.emit(UNLOCKED_EVENT, ());
        }
    }

    /// Locks the vault, telling the UI why. Does nothing if it is locked.
    pub fn lock(&self, app: &AppHandle, reason: LockReason) {
        if reason.ends_session() {
            self.end_session();
        }
        if self.lock_now() {
            log::info!("vault locked ({reason:?})");
            let _ = app.emit(LOCKED_EVENT, reason);
        }
    }

    /// Drops the unlocked vault and clears a secret it copied. Returns
    /// whether it was unlocked.
    fn lock_now(&self) -> bool {
        let Some(vault) = lock(&self.unlocked).take() else {
            return false;
        };
        // What another computer changed meanwhile shows while it is locked.
        self.remember_projects(&vault);
        drop(vault);
        self.clear_copied_secret();
        true
    }

    /// Keeps the copy of the vault's projects without secrets that shows
    /// while it is locked ([`projects::save_copy`]). A copy that can't be
    /// written is logged: it only makes the locked view out of date.
    pub fn remember_projects(&self, vault: &Vault) {
        let path = self.data_dir.join(PROJECTS_COPY);
        if let Err(error) = projects::save_copy(&path, vault.vault_id(), &vault.projects()) {
            log::warn!("projects: the copy for a locked vault was not saved: {error}");
        }
    }

    /// The projects kept for the vault while it is locked; none for another
    /// vault, or with no vault.
    pub fn projects_copy(&self) -> Vec<Project> {
        let Some(vault_id) = core_vault::probe(&self.paths())
            .ok()
            .and_then(|files| files.vault_id)
        else {
            return Vec::new();
        };
        projects::load_copy(&self.data_dir.join(PROJECTS_COPY), &vault_id)
    }

    /// Records activity, postponing the auto-lock.
    pub fn touch(&self) {
        *lock(&self.last_activity) = Instant::now();
    }

    /// Runs `work` on the unlocked vault after picking up changes made
    /// elsewhere, counting as activity: for what the user asked for. Fails
    /// with `vault_locked` when it is locked.
    pub fn with<T>(
        &self,
        app: &AppHandle,
        work: impl FnOnce(&mut Vault) -> AppResult<T>,
    ) -> AppResult<T> {
        self.access(app, true, work)
    }

    /// Like [`Self::with`], without counting as activity: for reads that
    /// happen without the user doing anything — the browser extension's
    /// lookups whenever a login field gets focus, the UI's refetches, a 2FA
    /// code refreshing — which must not keep the vault open.
    pub fn with_quietly<T>(
        &self,
        app: &AppHandle,
        work: impl FnOnce(&mut Vault) -> AppResult<T>,
    ) -> AppResult<T> {
        self.access(app, false, work)
    }

    fn access<T>(
        &self,
        app: &AppHandle,
        activity: bool,
        work: impl FnOnce(&mut Vault) -> AppResult<T>,
    ) -> AppResult<T> {
        self.access_then(activity, work, || {
            let _ = app.emit(LOCKED_EVENT, LockReason::Changed);
        })
    }

    /// [`Self::access`], calling `on_changed` instead of telling the UI when
    /// the vault locks because it changed in a way this copy can't follow.
    fn access_then<T>(
        &self,
        activity: bool,
        work: impl FnOnce(&mut Vault) -> AppResult<T>,
        on_changed: impl FnOnce(),
    ) -> AppResult<T> {
        let mut guard = lock(&self.unlocked);
        let vault = guard.as_mut().ok_or_else(locked)?;
        if let Err(error) = vault.refresh() {
            if error.code() == ErrorCode::WrongPassphrase {
                guard.take();
                drop(guard);
                self.end_session();
                self.clear_copied_secret();
                on_changed();
                return Err(locked());
            }
            return Err(error.into());
        }
        if activity {
            self.touch();
        }
        work(vault)
    }

    /// Like [`Self::with`], then writes the vault. On a conflict the change
    /// is dropped in favour of the version on disk (a copy of it is kept next
    /// to the backups, named in the error).
    pub fn change<T>(
        &self,
        app: &AppHandle,
        backup_dir: &Path,
        work: impl FnOnce(&mut Vault) -> AppResult<T>,
    ) -> AppResult<T> {
        self.change_then_save(app, work, |vault| vault.save(backup_dir))
    }

    /// Like [`Self::change`], without a backup of the previous file
    /// ([`Vault::save_without_backup`]): for a browser's new keys.
    pub fn change_without_backup<T>(
        &self,
        app: &AppHandle,
        backup_dir: &Path,
        work: impl FnOnce(&mut Vault) -> AppResult<T>,
    ) -> AppResult<T> {
        self.change_then_save(app, work, |vault| vault.save_without_backup(backup_dir))
    }

    fn change_then_save<T>(
        &self,
        app: &AppHandle,
        work: impl FnOnce(&mut Vault) -> AppResult<T>,
        save: impl FnOnce(&mut Vault) -> sshkm_core::Result<()>,
    ) -> AppResult<T> {
        self.change_then_save_or(work, save, || {
            let _ = app.emit(LOCKED_EVENT, LockReason::Changed);
        })
    }

    /// [`Self::change_then_save`], calling `on_changed` as
    /// [`Self::access_then`] does.
    fn change_then_save_or<T>(
        &self,
        work: impl FnOnce(&mut Vault) -> AppResult<T>,
        save: impl FnOnce(&mut Vault) -> sshkm_core::Result<()>,
        on_changed: impl FnOnce(),
    ) -> AppResult<T> {
        self.access_then(
            true,
            |vault| {
                let result = match work(vault) {
                    Ok(result) => result,
                    Err(error) => {
                        // What a change that failed halfway made in memory
                        // must not go out with the next save.
                        if let Err(reload) = vault.discard_changes() {
                            log::warn!("vault: a failed change was not undone: {reload}");
                        }
                        return Err(error);
                    }
                };
                if let Err(error) = save(vault) {
                    // Reload what is on disk, whatever happened to the write.
                    let _ = vault.refresh();
                    return Err(error.into());
                }
                self.remember_projects(vault);
                Ok(result)
            },
            on_changed,
        )
    }

    /// Copies `text` so that clipboard history and cloud clipboards skip it,
    /// and, if `clear` is set, clears it after the configured time unless
    /// something else was copied meanwhile. Returns the seconds until then.
    pub fn copy(self: &Arc<Self>, text: &SecretString, clear: bool) -> AppResult<Option<u32>> {
        let seconds = if clear {
            lock(&self.settings).clipboard_seconds
        } else {
            0
        };
        self.copy_for(text, clear, seconds)
    }

    /// Copies a recovery key like a password, and clears it after the
    /// configured time — or [`RECOVERY_KEY_SECONDS`] if the settings say
    /// never: it opens the vault and every copy of it.
    pub fn copy_recovery_key(self: &Arc<Self>, key: &SecretString) -> AppResult<Option<u32>> {
        let seconds = match lock(&self.settings).clipboard_seconds {
            0 => RECOVERY_KEY_SECONDS,
            seconds => seconds,
        };
        self.copy_for(key, true, seconds)
    }

    fn copy_for(
        self: &Arc<Self>,
        text: &SecretString,
        secret: bool,
        seconds: u32,
    ) -> AppResult<Option<u32>> {
        let digest: [u8; 32] = Sha256::digest(text.expose_secret().as_bytes()).into();
        let generation = {
            let mut state = lock(&self.clipboard);
            let clipboard = match &mut state.clipboard {
                Some(clipboard) => clipboard,
                slot @ None => {
                    slot.insert(arboard::Clipboard::new().map_err(|e| clipboard_error(&e))?)
                }
            };
            set_excluded(clipboard, text.expose_secret())?;
            state.generation += 1;
            state.secret = secret.then_some(digest);
            state.generation
        };
        if seconds == 0 {
            return Ok(None);
        }
        let runtime = Arc::clone(self);
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(seconds.into()));
            let mut state = lock(&runtime.clipboard);
            if state.generation == generation {
                clear_if_holding(&mut state, &digest);
            }
        });
        Ok(Some(seconds))
    }

    /// Clears the clipboard if it still holds the secret copied last.
    /// Also drops the logins read from a browser for an import: whenever the
    /// open vault goes, they go with it.
    fn clear_copied_secret(&self) {
        crate::commands::browser_import::forget();
        let mut state = lock(&self.clipboard);
        if let Some(digest) = state.secret {
            clear_if_holding(&mut state, &digest);
        }
    }

    /// Starts the thread that locks the vault after inactivity or sleep, and
    /// keeps `app` to tell of unlocks.
    pub fn start_timer(self: &Arc<Self>, app: AppHandle) {
        let _ = self.app.set(app.clone());
        let runtime = Arc::clone(self);
        thread::spawn(move || {
            let mut last_tick = SystemTime::now();
            loop {
                thread::sleep(TICK);
                let now = SystemTime::now();
                let slept = now
                    .duration_since(last_tick)
                    .is_ok_and(|gap| gap > SLEEP_GAP);
                last_tick = now;
                if slept {
                    runtime.end_session();
                }
                if let Some(reason) = runtime.lock_due(slept) {
                    runtime.lock(&app, reason);
                }
            }
        });
    }

    /// Why the unlocked vault should lock now, if it should: after the
    /// computer `slept`, or after the configured time without activity.
    fn lock_due(&self, slept: bool) -> Option<LockReason> {
        if !self.is_unlocked() {
            return None;
        }
        let settings = self.settings();
        if slept && settings.lock_on_sleep {
            return Some(LockReason::Sleep);
        }
        let minutes = settings.auto_lock_minutes?;
        let idle = lock(&self.last_activity).elapsed();
        (idle >= Duration::from_secs(u64::from(minutes) * 60)).then_some(LockReason::Idle)
    }
}

/// Clears the clipboard if it holds the text with SHA-256 `digest`, and
/// forgets the secret either way.
fn clear_if_holding(state: &mut ClipboardState, digest: &[u8; 32]) {
    if state.secret.as_ref() == Some(digest) {
        state.secret = None;
    }
    if let Some(clipboard) = state.clipboard.as_mut() {
        let still_ours = clipboard
            .get_text()
            .is_ok_and(|current| Sha256::digest(current.as_bytes()).as_slice() == digest);
        if still_ours {
            let _ = clipboard.clear();
        }
    }
}

fn set_excluded(clipboard: &mut arboard::Clipboard, text: &str) -> AppResult<()> {
    let set = clipboard.set();
    #[cfg(target_os = "macos")]
    let set = {
        use arboard::SetExtApple;
        set.exclude_from_history()
    };
    #[cfg(windows)]
    let set = {
        use arboard::SetExtWindows;
        set.exclude_from_history()
            .exclude_from_cloud()
            .exclude_from_monitoring()
    };
    #[cfg(target_os = "linux")]
    let set = {
        use arboard::SetExtLinux;
        set.exclude_from_history()
    };
    set.text(text).map_err(|e| clipboard_error(&e))
}

fn clipboard_error(error: &arboard::Error) -> AppError {
    AppError::new(ErrorCode::Io, format!("clipboard: {error}"))
}

fn load_settings(path: &Path) -> VaultSettings {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn locked() -> AppError {
    AppError::new(ErrorCode::VaultLocked, "the vault is locked")
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use sshkm_core::vault;

    use super::*;

    fn s(text: &str) -> SecretString {
        SecretString::from(text.to_owned())
    }

    /// A runtime whose data folder is `data` and whose vault is `database`.
    fn runtime(data: &Path, database: &Path) -> VaultRuntime {
        std::fs::create_dir_all(data).unwrap();
        let runtime = VaultRuntime::new(data.to_path_buf());
        runtime.set_database(database).unwrap();
        runtime
    }

    /// Runs `work` the way a command does, as user activity or quietly.
    fn run<T>(
        runtime: &VaultRuntime,
        activity: bool,
        work: impl FnOnce(&mut Vault) -> AppResult<T>,
    ) -> T {
        runtime.access_then(activity, work, || {}).unwrap()
    }

    #[test]
    fn stepping_away_ends_the_session_and_idling_does_not() {
        for reason in [LockReason::Idle, LockReason::Minimize] {
            assert!(!reason.ends_session(), "{reason:?}");
        }
        for reason in [
            LockReason::Manual,
            LockReason::Sleep,
            LockReason::ScreenLock,
            LockReason::Changed,
        ] {
            assert!(reason.ends_session(), "{reason:?}");
        }
        let dir = tempfile::tempdir().unwrap();
        let runtime = runtime(&dir.path().join("data"), &dir.path().join("vault.kdbx"));
        let before = runtime.session();
        runtime
            .set_database(&dir.path().join("other.kdbx"))
            .unwrap();
        assert_ne!(runtime.session(), before, "another vault, another session");
    }

    #[test]
    fn quiet_reads_never_postpone_the_idle_lock() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = runtime(&dir.path().join("data"), &dir.path().join("vault.kdbx"));
        let (vault, _) = Vault::create(&runtime.paths(), &s("master")).unwrap();
        runtime.set_unlocked(vault);
        assert_eq!(runtime.lock_due(false), None);
        let Some(long_ago) = Instant::now().checked_sub(Duration::from_secs(6 * 60)) else {
            return;
        };
        *lock(&runtime.last_activity) = long_ago;

        // An entry with a 2FA code stays open: the list, the entry and the
        // code are fetched again and again without the user doing anything.
        for _ in 0..20 {
            run(&runtime, false, |vault| Ok(vault.entries().len()));
        }
        assert_eq!(runtime.lock_due(false), Some(LockReason::Idle));

        // Something the user did counts.
        run(&runtime, true, |_| Ok(()));
        assert_eq!(runtime.lock_due(false), None);
        assert_eq!(runtime.lock_due(true), Some(LockReason::Sleep));
        assert!(runtime.lock_now());
        assert_eq!(runtime.lock_due(true), None);
    }

    #[test]
    fn a_change_that_fails_halfway_leaves_nothing_behind() {
        use sshkm_core::vault::projects::{ProjectColor, ProjectInput, ProjectMember};
        let dir = tempfile::tempdir().unwrap();
        let rt = runtime(&dir.path().join("data"), &dir.path().join("vault.kdbx"));
        let (vault, _) = Vault::create(&rt.paths(), &s("master")).unwrap();
        rt.set_unlocked(vault);
        let backups = dir.path().join("backups");
        let input = ProjectInput {
            name: "Shop".into(),
            color: ProjectColor::Blue,
        };
        // The project is made, then a member it can't take fails the change.
        let failed = rt.change_then_save_or(
            |vault| {
                let id = vault.add_project(&input)?;
                let gone = ProjectMember::Login {
                    id: "6f1c2d3e-0000-4000-8000-0000000000aa".into(),
                };
                vault.set_project_member(&id, &gone, true)?;
                Ok(())
            },
            |vault| vault.save(&backups),
            || {},
        );
        assert!(failed.is_err());
        assert_eq!(run(&rt, false, |vault| Ok(vault.projects().len())), 0);
        // The next change doesn't save it either, and trying again works.
        rt.change_then_save_or(
            |vault| Ok(vault.add_project(&input)?),
            |vault| vault.save(&backups),
            || {},
        )
        .unwrap();
        let reopened = Vault::unlock(&rt.paths(), &s("master")).unwrap();
        assert_eq!(reopened.projects().len(), 1);
    }

    #[test]
    fn two_computers_on_one_synced_vault_keep_each_others_key_slots() {
        let dir = tempfile::tempdir().unwrap();
        let shared = dir.path().join("Dropbox/vault.kdbx");
        std::fs::create_dir_all(shared.parent().unwrap()).unwrap();
        let laptop = runtime(&dir.path().join("laptop"), &shared);
        let desktop = runtime(&dir.path().join("desktop"), &shared);
        let (vault, _) = Vault::create(&laptop.paths(), &s("old")).unwrap();
        laptop.set_unlocked(vault);
        desktop.set_unlocked(Vault::unlock(&desktop.paths(), &s("old")).unwrap());

        // The laptop turns on device unlock and changes the master password.
        let laptop_slot = run(&laptop, true, |vault| {
            let key = vault.enable_device_unlock()?;
            vault.change_master_password(&s("old"), &s("new"))?;
            Ok(key.slot_id)
        });
        // The desktop, opened before that, turns device unlock on as well:
        // the old password must not come back, nor the laptop's slot go.
        let desktop_slot = run(&desktop, true, |vault| {
            Ok(vault.enable_device_unlock()?.slot_id)
        });
        let files = vault::probe(&laptop.paths()).unwrap();
        assert_eq!(files.device_slots, [laptop_slot, desktop_slot.clone()]);
        assert!(Vault::unlock(&laptop.paths(), &s("old")).is_err());
        assert!(Vault::unlock(&laptop.paths(), &s("new")).is_ok());

        // And the laptop sees the desktop's slot without reopening.
        let slots = run(&laptop, false, |vault| Ok(vault.device_slots()));
        assert!(slots.contains(&desktop_slot));
    }

    #[test]
    fn weakening_changes_are_recognised() {
        let current = VaultSettings::default();
        assert_eq!(current.weakened_by(&current), []);
        let stronger = VaultSettings {
            auto_lock_minutes: Some(1),
            clipboard_seconds: 10,
            lock_on_minimize: true,
            ..VaultSettings::default()
        };
        assert_eq!(current.weakened_by(&stronger), []);
        assert_eq!(
            stronger.weakened_by(&current),
            [
                Weakening::AutoLock {
                    old: 1,
                    new: Some(5)
                },
                Weakening::Clipboard { old: 10, new: 30 },
                Weakening::LockOnMinimize,
            ]
        );
        let off = VaultSettings {
            auto_lock_minutes: None,
            clipboard_seconds: 0,
            lock_on_sleep: false,
            lock_on_screen_lock: false,
            unlock_keys_on_open: true,
            ..VaultSettings::default()
        };
        assert_eq!(
            current.weakened_by(&off),
            [
                Weakening::AutoLock { old: 5, new: None },
                Weakening::Clipboard { old: 30, new: 0 },
                Weakening::LockOnSleep,
                Weakening::LockOnScreenLock,
            ]
        );
        // Turning protection back on needs no confirmation.
        assert_eq!(off.weakened_by(&current), []);
    }

    #[test]
    fn settings_default_and_survive_a_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = VaultRuntime::new(dir.path().to_path_buf());
        assert_eq!(runtime.settings(), VaultSettings::default());
        assert_eq!(runtime.paths().database, dir.path().join("vault.kdbx"));

        let changed = VaultSettings {
            database: Some(dir.path().join("sync/passwords.kdbx")),
            auto_lock_minutes: None,
            ..VaultSettings::default()
        };
        runtime.set_settings(changed.clone()).unwrap();
        let again = VaultRuntime::new(dir.path().to_path_buf());
        assert_eq!(again.settings(), changed);
        assert_eq!(again.paths().keys, dir.path().join("sync/passwords.keys"));
    }

    #[test]
    fn zero_minute_auto_lock_is_refused_and_missing_fields_default() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = VaultRuntime::new(dir.path().to_path_buf());
        let bad = VaultSettings {
            auto_lock_minutes: Some(0),
            ..VaultSettings::default()
        };
        assert!(runtime.set_settings(bad).is_err());
        std::fs::write(dir.path().join(SETTINGS_FILE), r#"{"clipboardSeconds":90}"#).unwrap();
        let loaded = VaultRuntime::new(dir.path().to_path_buf()).settings();
        assert_eq!(loaded.clipboard_seconds, 90);
        assert!(loaded.lock_on_sleep);
    }
}
