//! The password vault while the app runs: where it lives, whether it is
//! unlocked, when it locks itself, and copying its secrets to the clipboard.
//!
//! The unlocked [`Vault`] exists only in this process and is dropped (locked)
//! on request, after a period without activity, after the computer slept, or
//! when the window is minimised, as the settings say. Every lock emits
//! [`LOCKED_EVENT`] so the UI can switch to its lock screen.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sshkm_core::vault::{Vault, VaultPaths};
use sshkm_core::{ErrorCode, ExposeSecret, SecretString, fsutil};
use tauri::{AppHandle, Emitter};

use crate::error::{AppError, AppResult};

/// Emitted with a [`LockReason`] whenever the vault locks.
pub const LOCKED_EVENT: &str = "vault-locked";

const SETTINGS_FILE: &str = "vault.json";
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
    #[expect(dead_code, reason = "sent once the screen-lock watcher is wired in")]
    ScreenLock,
    Minimize,
    /// The vault changed elsewhere in a way this copy can't follow, e.g. its
    /// recovery key was replaced on another computer.
    Changed,
}

/// The vault's runtime state, shared by all commands.
pub struct VaultRuntime {
    data_dir: PathBuf,
    settings: Mutex<VaultSettings>,
    unlocked: Mutex<Option<Vault>>,
    last_activity: Mutex<Instant>,
    clipboard: Mutex<ClipboardState>,
}

#[derive(Default)]
struct ClipboardState {
    /// Kept alive: on X11 the clipboard's owner must stay around to serve it.
    clipboard: Option<arboard::Clipboard>,
    /// Bumped on every copy, so a pending clear only clears its own copy.
    generation: u64,
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
        }
    }

    pub fn settings(&self) -> VaultSettings {
        lock(&self.settings).clone()
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
        *lock(&self.unlocked) = Some(vault);
        self.touch();
    }

    /// Locks the vault, telling the UI why. Does nothing if it is locked.
    pub fn lock(&self, app: &AppHandle, reason: LockReason) {
        if lock(&self.unlocked).take().is_some() {
            log::info!("vault locked ({reason:?})");
            let _ = app.emit(LOCKED_EVENT, reason);
        }
    }

    /// Records activity, postponing the auto-lock.
    pub fn touch(&self) {
        *lock(&self.last_activity) = Instant::now();
    }

    /// Runs `work` on the unlocked vault after picking up changes made
    /// elsewhere. Fails with `vault_locked` when it is locked.
    pub fn with<T>(
        &self,
        app: &AppHandle,
        work: impl FnOnce(&mut Vault) -> AppResult<T>,
    ) -> AppResult<T> {
        let mut guard = lock(&self.unlocked);
        let vault = guard.as_mut().ok_or_else(locked)?;
        if let Err(error) = vault.refresh() {
            if error.code() == ErrorCode::WrongPassphrase {
                guard.take();
                drop(guard);
                let _ = app.emit(LOCKED_EVENT, LockReason::Changed);
                return Err(locked());
            }
            return Err(error.into());
        }
        self.touch();
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
        self.with(app, |vault| {
            let result = work(vault)?;
            if let Err(error) = vault.save(backup_dir) {
                // Reload what is on disk, whatever happened to the write.
                let _ = vault.refresh();
                return Err(error.into());
            }
            Ok(result)
        })
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
            state.generation
        };
        if seconds == 0 {
            return Ok(None);
        }
        let digest = Sha256::digest(text.expose_secret().as_bytes());
        let runtime = Arc::clone(self);
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(seconds.into()));
            let mut state = lock(&runtime.clipboard);
            if state.generation != generation {
                return;
            }
            if let Some(clipboard) = state.clipboard.as_mut() {
                let still_ours = clipboard
                    .get_text()
                    .is_ok_and(|current| Sha256::digest(current.as_bytes()) == digest);
                if still_ours {
                    let _ = clipboard.clear();
                }
            }
        });
        Ok(Some(seconds))
    }

    /// Starts the thread that locks the vault after inactivity or sleep.
    pub fn start_timer(self: &Arc<Self>, app: AppHandle) {
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
                if !runtime.is_unlocked() {
                    continue;
                }
                let settings = runtime.settings();
                if slept && settings.lock_on_sleep {
                    runtime.lock(&app, LockReason::Sleep);
                    continue;
                }
                if let Some(minutes) = settings.auto_lock_minutes {
                    let idle = lock(&runtime.last_activity).elapsed();
                    if idle >= Duration::from_secs(u64::from(minutes) * 60) {
                        runtime.lock(&app, LockReason::Idle);
                    }
                }
            }
        });
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
    use super::*;

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
