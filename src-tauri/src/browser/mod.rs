//! Browser autofill: the bridge between the browser extension and the vault.
//!
//! ```text
//! extension ──native messaging──▶ host (this executable) ──socket/pipe──▶ app
//! ```
//!
//! - The **host** ([`run_host_from_args`]) is this executable, started by the
//!   browser with the extension's origin as its argument. `main` runs it
//!   before Tauri starts. It relays JSON, nothing else.
//! - The **bridge** ([`Bridge`]) runs in the app while browser autofill is on.
//!   It listens on a Unix socket in a fresh private directory, or on Windows
//!   on a named pipe with a random name that rejects remote clients, and
//!   writes where to [`endpoint_file`], in the app's local data folder, which
//!   only this user can write. The host reads it there.
//! - Turning autofill on registers the host with each installed browser
//!   ([`manifests`]); turning it off removes the registrations and stops the
//!   listener. A copy of the app in a temporary folder, or on macOS on a
//!   mounted volume, is never registered ([`host_program`]).
//!
//! What the extension may ask, and the pairing that guards it, is the
//! [`broker`]'s business; the cryptography and the page matching are in
//! [`sshkm_core::browser`]. Unlocking the vault when the extension asks,
//! without the main window, is [`unlock`]'s.

pub mod broker;
mod host;
pub mod manifests;
mod prompt;
#[cfg(unix)]
mod unix;
pub mod unlock;
#[cfg(windows)]
mod windows;

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sshkm_core::browser::protocol::{MAX_MESSAGE, VaultLock};
use sshkm_core::vault::{PairedBrowser, Vault};
use sshkm_core::{ErrorCode, fsutil};
use tauri::{AppHandle, Emitter, Manager};

pub use host::run_host_from_args;

#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
use windows as platform;

use self::broker::{Broker, Changed, Env, FillAnswer, FillPrompt, PairingRequest};
use crate::commands::Shared;
use crate::error::{AppError, AppResult};

/// The native messaging host's name, as the browsers know it.
pub const HOST_NAME: &str = "dev.sshkeymanager.autofill";
pub const MANIFEST_FILE: &str = "dev.sshkeymanager.autofill.json";
/// The extension in Chrome, Edge and other Chromium browsers: its Chrome Web
/// Store item. The `key` in `extension/manifest.json` is that item's public
/// key, so unpacked builds get the same id.
pub const CHROMIUM_EXTENSION_IDS: &[&str] = &["lkmgdcanagjeajepncgokapkbihahddb"];
/// The extension in Firefox.
pub const FIREFOX_EXTENSION_ID: &str = "autofill@sshkeymanager.dev";
/// The app's identifier (`tauri.conf.json`), naming its data folder.
const APP_ID: &str = "dev.sshkeymanager.desktop";

/// Emitted with a [`PairingRequest`] when a browser asks to pair, and with
/// `null` when that is over.
pub const PAIRING_EVENT: &str = "browser-pairing";
/// Emitted when a browser was paired or revoked.
pub const CHANGED_EVENT: &str = "browser-changed";
/// Emitted when the extension asks to unlock the vault.
pub const UNLOCK_EVENT: &str = "browser-unlock";

const SETTINGS_FILE: &str = "browser.json";
const ENDPOINT_FILE: &str = "browser-endpoint";
/// How long the bridge waits for the host to send or read a message.
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the host waits for the app's reply: a pairing waits for the user.
#[cfg(unix)]
const HOST_WAIT: Duration = Duration::from_secs(150);

/// Answers one request frame with a reply frame.
type Handler = Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>;

/// The app's local data folder; the host finds the bridge through it.
fn data_dir() -> io::Result<PathBuf> {
    dirs::data_local_dir()
        .map(|dir| dir.join(APP_ID))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no local data folder"))
}

/// The file that names the running app's socket or pipe.
pub fn endpoint_file() -> io::Result<PathBuf> {
    Ok(data_dir()?.join(ENDPOINT_FILE))
}

/// Where the browsers are to start the host from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostProgram {
    /// This program, at a path that lasts.
    At(PathBuf),
    /// This program, in a temporary folder: an `AppImage`'s mount, or a copy
    /// unpacked there. The path goes away when the app quits, and in a shared
    /// folder such as `/tmp` another user could then put a program of theirs
    /// at it, which the browser would start as this user. Browsers are not
    /// pointed at it.
    Temporary(PathBuf),
    /// This program, on macOS, on a volume under `/Volumes` (a disk image, a
    /// USB drive, a network share), or in the read-only mount macOS runs a
    /// downloaded app from until it is moved (App Translocation). The path
    /// goes away when the volume is ejected or the app quits, and any user can
    /// then mount a volume of their own under the same name, with a program
    /// of theirs at the same path. Browsers are not pointed at it.
    Mounted(PathBuf),
}

/// The program to register with the browsers: this executable, or for an
/// `AppImage` the `.AppImage` file itself, since the executable inside runs
/// from a mount under `/tmp` that lasts only while the app runs.
pub fn host_program() -> io::Result<HostProgram> {
    let exe = std::env::current_exe()?;
    let appimage = if cfg!(target_os = "linux") {
        appimage_of(
            &exe,
            std::env::var_os("APPDIR"),
            std::env::var_os("APPIMAGE"),
        )
    } else {
        None
    };
    Ok(classify(appimage.unwrap_or(exe), &temporary_dirs()))
}

/// Whether `program` is somewhere that doesn't last: in a temporary folder or
/// on a mounted volume (see [`HostProgram`]).
pub fn is_temporary(program: &Path) -> bool {
    !matches!(
        classify(program.to_path_buf(), &temporary_dirs()),
        HostProgram::At(_)
    )
}

/// The `AppImage` that `exe` runs from: `$APPIMAGE`, when `exe` is inside that
/// image's mount, `$APPDIR`. An `AppImage` that started this app (a terminal,
/// say) passes its own variables on, so they count only then.
fn appimage_of(
    exe: &Path,
    appdir: Option<OsString>,
    appimage: Option<OsString>,
) -> Option<PathBuf> {
    let appdir = PathBuf::from(appdir.filter(|dir| !dir.is_empty())?);
    let appimage = PathBuf::from(appimage.filter(|file| !file.is_empty())?);
    (appdir.is_absolute() && appimage.is_absolute() && exe.starts_with(&appdir)).then_some(appimage)
}

fn classify(program: PathBuf, temporary: &[PathBuf]) -> HostProgram {
    let real = std::fs::canonicalize(&program).unwrap_or_else(|_| program.clone());
    if cfg!(target_os = "macos") && on_mounted_volume(&program, &real) {
        return HostProgram::Mounted(program);
    }
    let in_mount = [&program, &real].into_iter().any(|path| {
        path.components()
            .any(|part| part.as_os_str().to_string_lossy().starts_with(".mount_"))
    });
    let in_temporary = temporary
        .iter()
        .any(|dir| program.starts_with(dir) || real.starts_with(dir));
    if in_mount || in_temporary {
        HostProgram::Temporary(program)
    } else {
        HostProgram::At(program)
    }
}

/// Whether a program at `program` (`real` once links are resolved) runs, on
/// macOS, from a mounted volume (see [`HostProgram::Mounted`]): anything
/// under `/Volumes`, or an app App Translocation runs from under
/// `/private/var/folders/…/AppTranslocation/`. The startup disk shows in
/// `/Volumes` too, as a link to `/`: a path through it counts by where it
/// leads.
fn on_mounted_volume(program: &Path, real: &Path) -> bool {
    let translocated = |path: &Path| {
        (path.starts_with("/private/var/folders") || path.starts_with("/var/folders"))
            && path
                .components()
                .any(|part| part.as_os_str() == "AppTranslocation")
    };
    real.starts_with("/Volumes") || translocated(program) || translocated(real)
}

/// Folders whose contents don't last: the system's temporary folder and, on
/// Unix, the usual shared ones. A temporary folder that holds the home folder
/// (a `TMPDIR` of `/`, say) is left out, or every path would be temporary.
fn temporary_dirs() -> Vec<PathBuf> {
    let mut candidates = vec![std::env::temp_dir()];
    if cfg!(unix) {
        candidates.extend(["/tmp", "/var/tmp", "/dev/shm"].map(PathBuf::from));
    }
    let home = dirs::home_dir();
    let mut dirs = Vec::new();
    for dir in candidates {
        let real = std::fs::canonicalize(&dir).ok();
        for dir in [Some(dir), real].into_iter().flatten() {
            let holds_home = home.as_ref().is_some_and(|home| home.starts_with(&dir));
            if dir.parent().is_some() && !holds_home && !dirs.contains(&dir) {
                dirs.push(dir);
            }
        }
    }
    dirs
}

/// Frames between the host and the app: a big-endian `u32` length, then the
/// bytes.
mod frame {
    use super::{MAX_MESSAGE, Read, Write, io};

    /// The extension's message plus the host's envelope around it.
    const MAX_FRAME: usize = MAX_MESSAGE + 4096;

    pub fn header(len: usize) -> [u8; 4] {
        u32::try_from(len).unwrap_or(u32::MAX).to_be_bytes()
    }

    pub fn length(header: [u8; 4]) -> io::Result<usize> {
        usize::try_from(u32::from_be_bytes(header))
            .ok()
            .filter(|&len| len <= MAX_FRAME)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "frame too long"))
    }

    pub fn read(reader: &mut impl Read) -> io::Result<Vec<u8>> {
        let mut header = [0; 4];
        reader.read_exact(&mut header)?;
        let mut payload = vec![0; length(header)?];
        reader.read_exact(&mut payload)?;
        Ok(payload)
    }

    pub fn write(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() > MAX_FRAME {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too long"));
        }
        writer.write_all(&header(bytes.len()))?;
        writer.write_all(bytes)?;
        writer.flush()
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Settings {
    enabled: bool,
}

/// Browser autofill while the app runs.
pub struct Bridge {
    settings_file: PathBuf,
    broker: Arc<Broker>,
    running: Mutex<Option<Serving>>,
    /// Why the listener could not start, for the settings page.
    problem: Mutex<Option<String>>,
}

/// The bridge while it listens. Dropping it stops listening and removes the
/// endpoint file, if that still names this bridge.
pub struct Serving {
    endpoint: String,
    // Dropped first: stops listening and removes the socket.
    _listener: platform::Listener,
}

/// Serves `broker` to the native host, answering with `env`, and writes the
/// endpoint file so the host finds it. The app does this while autofill is
/// on; `examples/autofill_bridge.rs` does it over a test vault.
pub fn serve<E: Env + Send + Sync + 'static>(broker: Arc<Broker>, env: E) -> io::Result<Serving> {
    let handler: Handler = Arc::new(move |request| broker.handle(&env, request));
    let listener = platform::Listener::start(handler)?;
    let endpoint = listener.endpoint().to_string_lossy().into_owned();
    write_endpoint(&endpoint)?;
    Ok(Serving {
        endpoint,
        _listener: listener,
    })
}

impl Drop for Serving {
    fn drop(&mut self) {
        if let Ok(file) = endpoint_file()
            && std::fs::read_to_string(&file).is_ok_and(|text| text.trim() == self.endpoint)
        {
            let _ = std::fs::remove_file(file);
        }
    }
}

impl Bridge {
    /// `data_dir` is the app's data folder, home of the setting.
    pub fn new(data_dir: &Path) -> Self {
        Self {
            settings_file: data_dir.join(SETTINGS_FILE),
            broker: Arc::new(Broker::default()),
            running: Mutex::new(None),
            problem: Mutex::new(None),
        }
    }

    pub fn enabled(&self) -> bool {
        std::fs::read(&self.settings_file)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Settings>(&bytes).ok())
            .is_some_and(|s| s.enabled)
    }

    pub fn broker(&self) -> &Broker {
        &self.broker
    }

    pub fn problem(&self) -> Option<String> {
        lock(&self.problem).clone()
    }

    /// At startup: listens and refreshes the browser registrations, so they
    /// follow the app when it moves, if autofill is on. If it is off, removes
    /// an endpoint file left behind by a crash: on Windows another user could
    /// otherwise wait for the host under the pipe name it gives.
    pub fn start_if_enabled(&self, app: &AppHandle) {
        if self.enabled() {
            self.start(app);
        } else {
            forget_endpoint();
        }
    }

    /// Turns browser autofill on or off and saves the choice.
    pub fn set_enabled(&self, app: &AppHandle, enabled: bool) -> AppResult<()> {
        let mut json = serde_json::to_vec_pretty(&Settings { enabled })
            .map_err(|e| AppError::new(ErrorCode::Io, e.to_string()))?;
        json.push(b'\n');
        fsutil::atomic_write(&self.settings_file, &json, 0o600)?;
        if enabled {
            self.start(app);
        } else {
            self.stop();
            manifests::remove();
        }
        Ok(())
    }

    fn start(&self, app: &AppHandle) {
        match host_program() {
            Ok(HostProgram::At(program)) => {
                manifests::install(&program);
            }
            Ok(HostProgram::Temporary(program)) => {
                log::warn!(
                    "browser: not registering {}: it is in a temporary folder",
                    program.display()
                );
                manifests::remove_temporary();
            }
            Ok(HostProgram::Mounted(program)) => {
                log::warn!(
                    "browser: not registering {}: it is on a mounted volume",
                    program.display()
                );
                manifests::remove_temporary();
            }
            Err(error) => log::warn!("browser: cannot tell where this program is: {error}"),
        }
        let mut running = lock(&self.running);
        if running.is_some() {
            return;
        }
        let env = TauriEnv { app: app.clone() };
        match serve(Arc::clone(&self.broker), env) {
            Ok(started) => {
                *running = Some(started);
                *lock(&self.problem) = None;
            }
            Err(error) => {
                log::warn!("browser: cannot listen: {error}");
                *lock(&self.problem) = Some(error.to_string());
                forget_endpoint();
            }
        }
    }

    /// Stops listening and removes the endpoint file, if it is still ours.
    pub fn stop(&self) {
        lock(&self.running).take();
    }

    /// Whether the listener runs.
    pub fn listening(&self) -> bool {
        lock(&self.running).is_some()
    }
}

fn write_endpoint(endpoint: &str) -> io::Result<()> {
    let file = endpoint_file()?;
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir)?;
    }
    fsutil::atomic_write(&file, endpoint.as_bytes(), 0o600)
        .map_err(|e| io::Error::other(e.to_string()))
}

/// Removes the endpoint file while nothing of this app listens.
fn forget_endpoint() {
    if let Ok(file) = endpoint_file() {
        match std::fs::remove_file(&file) {
            Ok(()) => log::info!("browser: removed a stale endpoint file"),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => log::warn!("browser: cannot remove the endpoint file: {e}"),
        }
    }
}

/// The broker's view of the running app.
struct TauriEnv {
    app: AppHandle,
}

impl TauriEnv {
    fn state(&self) -> AppResult<Shared> {
        self.app
            .try_state::<Shared>()
            .map(|state| Arc::clone(&state))
            .ok_or_else(|| AppError::new(ErrorCode::Io, "the app is starting"))
    }
}

impl Env for TauriEnv {
    fn vault_lock(&self) -> VaultLock {
        let Ok(state) = self.state() else {
            return VaultLock::Locked;
        };
        if state.vault.is_unlocked() {
            VaultLock::Unlocked
        } else if state.vault.paths().database.is_file() {
            VaultLock::Locked
        } else {
            VaultLock::Missing
        }
    }

    fn read<T>(&self, active: bool, work: impl FnOnce(&Vault) -> AppResult<T>) -> AppResult<T> {
        let state = self.state()?;
        if active {
            state.vault.with(&self.app, |vault| work(vault))
        } else {
            state.vault.with_quietly(&self.app, |vault| work(vault))
        }
    }

    fn write<T>(&self, work: impl FnOnce(&mut Vault) -> AppResult<T>) -> AppResult<T> {
        let state = self.state()?;
        state.vault.change(&self.app, &state.backup_dir, work)
    }

    fn write_keys<T>(&self, work: impl FnOnce(&mut Vault) -> AppResult<T>) -> AppResult<T> {
        let state = self.state()?;
        state
            .vault
            .change_without_backup(&self.app, &state.backup_dir, work)
    }

    fn ask(&self, request: Option<&PairingRequest>) {
        if request.is_some() {
            crate::tray::show_window(&self.app);
        }
        let _ = self.app.emit(PAIRING_EVENT, request);
    }

    fn show(&self) {
        show_app(&self.app);
    }

    fn unlock(&self) {
        unlock::ask(&self.app, unlock::Asker::Browser);
    }

    fn changed(&self, what: Changed) {
        let event = match what {
            Changed::Entries => crate::vault_watcher::EVENT,
            Changed::Browsers => CHANGED_EVENT,
        };
        let _ = self.app.emit(event, ());
    }

    fn computer(&self) -> String {
        gethostname::gethostname().to_string_lossy().into_owned()
    }

    fn version(&self) -> String {
        self.app.package_info().version.to_string()
    }

    fn session(&self) -> u64 {
        self.state().map_or(0, |state| state.vault.session())
    }

    fn confirm_fill(&self, prompt: FillPrompt, answer: FillAnswer) {
        let app = self.app.clone();
        std::thread::spawn(move || answer(prompt::confirm_fill(&app, &prompt)));
    }

    fn copied(&self, browser: &PairedBrowser) {
        prompt::copied(&self.app, browser);
    }
}

/// Brings the main window forward on the vault, to unlock it there.
fn show_app(app: &AppHandle) {
    crate::tray::show_window(app);
    let _ = app.emit(UNLOCK_EVENT, ());
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_id_matches_the_tauri_config() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../../tauri.conf.json")).unwrap();
        assert_eq!(config["identifier"], APP_ID);
    }

    #[test]
    fn extension_ids_match_the_extension() {
        let manifest: serde_json::Value =
            serde_json::from_str(include_str!("../../../extension/manifest.json")).unwrap();
        assert_eq!(
            manifest["browser_specific_settings"]["gecko"]["id"],
            FIREFOX_EXTENSION_ID
        );
        assert_eq!(
            manifest["version"],
            env!("CARGO_PKG_VERSION"),
            "extension/manifest.json follows the app's version"
        );
        // Chrome derives the id from the public key: SHA-256, first 16
        // bytes, each nibble as a letter from `a` to `p`.
        let key =
            sshkm_core::browser::channel::decode(manifest["key"].as_str().unwrap(), 4096).unwrap();
        let digest = <sha2::Sha256 as sha2::Digest>::digest(&key);
        let id: String = digest[..16]
            .iter()
            .flat_map(|b| [b >> 4, b & 0xf])
            .map(|nibble| char::from(b'a' + nibble))
            .collect();
        assert_eq!(id, CHROMIUM_EXTENSION_IDS[0]);
    }

    #[test]
    fn frames_round_trip_and_refuse_oversized_ones() {
        let mut buffer = Vec::new();
        frame::write(&mut buffer, b"{\"a\":1}").unwrap();
        assert_eq!(frame::read(&mut buffer.as_slice()).unwrap(), b"{\"a\":1}");
        assert!(frame::read(&mut u32::MAX.to_be_bytes().as_slice()).is_err());
        assert!(frame::write(&mut Vec::new(), &vec![0; MAX_MESSAGE + 5000]).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn an_appimage_is_registered_as_its_file() {
        let mount = "/tmp/.mount_SSH KeAbC123";
        let exe = Path::new(mount).join("usr/bin/sshkm-app");
        let image = "/home/me/Apps/SSH Key Manager.AppImage";
        assert_eq!(
            appimage_of(&exe, Some(mount.into()), Some(image.into())),
            Some(PathBuf::from(image))
        );
        // Variables passed on by another AppImage that started this app.
        let installed = Path::new("/usr/bin/sshkm-app");
        assert_eq!(
            appimage_of(installed, Some(mount.into()), Some(image.into())),
            None
        );
        assert_eq!(appimage_of(&exe, None, Some(image.into())), None);
        assert_eq!(appimage_of(&exe, Some(mount.into()), Some("".into())), None);
        assert_eq!(
            appimage_of(&exe, Some(mount.into()), Some("relative.AppImage".into())),
            None
        );
    }

    #[test]
    fn programs_in_temporary_folders_are_not_registered() {
        let temp = tempfile::tempdir().unwrap();
        let temporary = [temp.path().to_path_buf()];
        let inside = temp.path().join("Temp1_app.zip").join("sshkm-app");
        assert_eq!(
            classify(inside.clone(), &temporary),
            HostProgram::Temporary(inside)
        );
        let mount = PathBuf::from("/run/user/1000/.mount_SSH KeAbC123/usr/bin/sshkm-app");
        assert_eq!(
            classify(mount.clone(), &temporary),
            HostProgram::Temporary(mount)
        );
        let installed = PathBuf::from("/opt/SSH Key Manager/sshkm-app");
        assert_eq!(
            classify(installed.clone(), &temporary),
            HostProgram::At(installed)
        );
        assert!(is_temporary(&std::env::temp_dir().join("x/sshkm-app")));
        assert!(is_temporary(Path::new("/tmp/.mount_abc/usr/bin/sshkm-app")));
    }

    #[test]
    fn programs_on_mounted_volumes_are_spotted() {
        let on_image =
            Path::new("/Volumes/SSH Key Manager/SSH Key Manager.app/Contents/MacOS/sshkm-app");
        assert!(on_mounted_volume(on_image, on_image));
        let translocated = Path::new(
            "/private/var/folders/x1/abc123/T/AppTranslocation/0F1E2D3C/d/SSH Key Manager.app/Contents/MacOS/sshkm-app",
        );
        assert!(on_mounted_volume(translocated, translocated));
        let unresolved = Path::new(
            "/var/folders/x1/abc123/T/AppTranslocation/0F1E2D3C/d/SSH Key Manager.app/Contents/MacOS/sshkm-app",
        );
        assert!(on_mounted_volume(unresolved, unresolved));

        let installed = Path::new("/Applications/SSH Key Manager.app/Contents/MacOS/sshkm-app");
        assert!(!on_mounted_volume(installed, installed));
        // The startup disk, through its link in /Volumes.
        let startup = Path::new(
            "/Volumes/Macintosh HD/Applications/SSH Key Manager.app/Contents/MacOS/sshkm-app",
        );
        assert!(!on_mounted_volume(startup, installed));
        // Only App Translocation's folder, not any under /var/folders.
        let cached = Path::new("/private/var/folders/x1/abc123/C/sshkm-app");
        assert!(!on_mounted_volume(cached, cached));
        assert!(!on_mounted_volume(
            Path::new("/Users/me/Volumes/sshkm-app"),
            Path::new("/Users/me/Volumes/sshkm-app")
        ));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn programs_on_mounted_volumes_are_not_registered() {
        let on_image =
            PathBuf::from("/Volumes/SSH Key Manager/SSH Key Manager.app/Contents/MacOS/sshkm-app");
        assert_eq!(
            classify(on_image.clone(), &[]),
            HostProgram::Mounted(on_image.clone())
        );
        assert!(is_temporary(&on_image));
        let installed = PathBuf::from("/Applications/SSH Key Manager.app/Contents/MacOS/sshkm-app");
        assert_eq!(classify(installed.clone(), &[]), HostProgram::At(installed));
    }

    #[test]
    fn the_setting_defaults_to_off_and_is_saved() {
        let dir = tempfile::tempdir().unwrap();
        let bridge = Bridge::new(dir.path());
        assert!(!bridge.enabled());
        std::fs::write(dir.path().join(SETTINGS_FILE), r#"{"enabled":true}"#).unwrap();
        assert!(bridge.enabled());
        std::fs::write(dir.path().join(SETTINGS_FILE), "garbage").unwrap();
        assert!(!bridge.enabled());
    }
}
