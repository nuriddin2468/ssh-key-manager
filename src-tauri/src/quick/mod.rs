//! Quick search: a small window the user calls up from anywhere, with a
//! system-wide shortcut or from the tray menu, to connect to a host, copy a
//! password, user name or 2FA code, or unlock the vault.
//!
//! - The shortcut is the user's (Settings → Quick search), saved in
//!   `quick.json` in the app's data folder; ⇧⌘Space on macOS and
//!   Ctrl+Shift+Space elsewhere until changed ([`shortcut::DEFAULT`]). The
//!   system may refuse it, when another app has it: the Settings page then
//!   says so ([`QuickStatus::registered`]). On Linux it is an X11 key grab,
//!   which a Wayland desktop gives only while an X11 window has the focus;
//!   there a shortcut of the desktop's own can run the app with [`ARG`],
//!   which opens the window in the running app.
//! - The window ([`LABEL`], `quick.html`) may call only what it does
//!   (`capabilities/quick.json`): list the hosts and the vault's entries
//!   without their secrets ([`items`]), copy through the vault's own copy
//!   (out of clipboard history, cleared after a while), unlock the vault the
//!   way the unlock window does, connect and close.
//! - Like the unlock window it stays above other windows, has no taskbar
//!   button and opens near the top of the screen with the mouse pointer.
//!   Pressing the shortcut again closes it; so do Escape, a copy and losing
//!   the focus. After Escape or a copy, the app the user was in gets the
//!   focus back ([`sshkm_os::focus`]), so a copied password can be pasted
//!   right away. Connecting brings the main window forward on the session.

pub mod items;
pub mod shortcut;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;

use serde::{Deserialize, Serialize};
use sshkm_core::{ErrorCode, fsutil};
use sshkm_os::focus::Previous;
use tauri::plugin::TauriPlugin;
use tauri::window::Color;
use tauri::{
    AppHandle, Emitter, LogicalPosition, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder,
    Wry,
};
use tauri_plugin_global_shortcut::{GlobalShortcutExt, Shortcut, ShortcutState};

use crate::confirm::Localized;
use crate::error::{AppError, AppResult};

/// The quick search window's label; its capability names it.
pub const LABEL: &str = "quick";
/// Starting the app with this opens the window, in the running app if there
/// is one.
pub const ARG: &str = "--quick-search";
/// Its page, next to the main window's `index.html`.
const PAGE: &str = "quick.html";
const WIDTH: f64 = 620.0;
const HEIGHT: f64 = 420.0;
/// The main window's background, so the window doesn't flash white.
const BACKGROUND: Color = Color(0x0A, 0x0D, 0x14, 0xFF);
const SETTINGS_FILE: &str = "quick.json";

/// The app the user was in when the window opened.
static PREVIOUS: Mutex<Option<Previous>> = Mutex::new(None);

/// What `quick.json` holds.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Settings {
    enabled: bool,
    /// `None`: [`shortcut::DEFAULT`].
    shortcut: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            shortcut: None,
        }
    }
}

/// The shortcut as the Settings page shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct QuickStatus {
    pub enabled: bool,
    /// In the order and spelling of [`shortcut`], e.g. `Shift+Super+Space`.
    pub shortcut: String,
    pub default_shortcut: String,
    /// The system took the shortcut, so it works now. `false` while
    /// `enabled` means another app has it (or the system refused it).
    pub registered: bool,
}

pub type SharedQuick = Arc<Quick>;

pub struct Quick {
    settings_file: PathBuf,
    state: Mutex<State>,
}

struct State {
    settings: Settings,
    /// The shortcut the system has for the app now.
    registered: Option<Shortcut>,
}

/// The global shortcut plugin, calling [`toggle`] on the shortcut.
pub fn plugin() -> TauriPlugin<Wry> {
    tauri_plugin_global_shortcut::Builder::new()
        .with_handler(|app, _shortcut, event| {
            if event.state == ShortcutState::Pressed {
                toggle(app);
            }
        })
        .build()
}

impl Quick {
    /// Reads the setting and registers the shortcut. Called once at start,
    /// after the plugin is set up.
    pub fn install(app: &AppHandle, data_dir: &Path) -> SharedQuick {
        let settings_file = data_dir.join(SETTINGS_FILE);
        let settings: Settings = std::fs::read(&settings_file)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        let quick = Arc::new(Self {
            settings_file,
            state: Mutex::new(State {
                settings,
                registered: None,
            }),
        });
        let mut state = lock(&quick.state);
        state.registered = register(app, &state.settings);
        drop(state);
        quick
    }

    pub fn status(&self) -> QuickStatus {
        let state = lock(&self.state);
        QuickStatus {
            enabled: state.settings.enabled,
            shortcut: wanted(&state.settings)
                .map_or_else(|| shortcut::DEFAULT.to_owned(), |(_, text)| text),
            default_shortcut: shortcut::DEFAULT.to_owned(),
            registered: state.registered.is_some(),
        }
    }

    /// Turns the shortcut on or off, or changes it (`None`: the default),
    /// and saves that. A shortcut the system refuses is saved too: the
    /// status then says it isn't registered.
    pub fn set(
        &self,
        app: &AppHandle,
        enabled: bool,
        text: Option<&str>,
    ) -> AppResult<QuickStatus> {
        let shortcut = match text {
            Some(text) => Some(shortcut::parse(text)?.1),
            None => None,
        }
        .filter(|text| text != shortcut::DEFAULT);
        let settings = Settings { enabled, shortcut };
        let mut json = serde_json::to_vec_pretty(&settings)
            .map_err(|e| AppError::new(ErrorCode::Io, e.to_string()))?;
        json.push(b'\n');
        fsutil::atomic_write(&self.settings_file, &json, 0o600)?;

        let mut state = lock(&self.state);
        if let Some(old) = state.registered.take()
            && let Err(e) = app.global_shortcut().unregister(old)
        {
            log::warn!("quick search: the old shortcut stays registered: {e}");
        }
        state.registered = register(app, &settings);
        state.settings = settings;
        drop(state);
        Ok(self.status())
    }
}

/// The shortcut the settings ask for, if they ask for one.
fn wanted(settings: &Settings) -> Option<(Shortcut, String)> {
    let text = settings.shortcut.as_deref().unwrap_or(shortcut::DEFAULT);
    shortcut::parse(text)
        .or_else(|_| shortcut::parse(shortcut::DEFAULT))
        .ok()
}

/// Registers the shortcut the settings ask for; `None` if they ask for none
/// or the system refused it.
fn register(app: &AppHandle, settings: &Settings) -> Option<Shortcut> {
    if !settings.enabled {
        return None;
    }
    let (shortcut, text) = wanted(settings)?;
    match app.global_shortcut().register(shortcut) {
        Ok(()) => Some(shortcut),
        Err(e) => {
            log::warn!("quick search: {text} can't be registered: {e}");
            None
        }
    }
}

/// Opens the window, or closes it if it is open: what the shortcut does.
pub fn toggle(app: &AppHandle) {
    match app.get_webview_window(LABEL) {
        Some(window) => {
            let _ = window.close();
        }
        None => open(app),
    }
}

/// Opens the window, or brings it forward. Returns at once.
pub fn open(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(LABEL) {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
        return;
    }
    // Before the window takes the focus.
    *lock(&PREVIOUS) = Previous::frontmost();
    let app = app.clone();
    // Not on the thread of the shortcut's or the menu's event: building a
    // window there can deadlock on Windows.
    thread::spawn(move || build(&app));
}

fn build(app: &AppHandle) {
    let title = Localized::new("Quick Search", "Быстрый поиск", "Tezkor qidiruv");
    let built = WebviewWindowBuilder::new(app, LABEL, WebviewUrl::App(PAGE.into()))
        .title(title.pick())
        .inner_size(WIDTH, HEIGHT)
        .resizable(false)
        .maximizable(false)
        .minimizable(false)
        .decorations(false)
        .shadow(true)
        .always_on_top(true)
        .skip_taskbar(true)
        .center()
        .focused(true)
        .theme(Some(tauri::Theme::Dark))
        .background_color(BACKGROUND)
        .build();
    match built {
        Ok(window) => {
            place(app, &window);
            let _ = window.set_focus();
            log::info!("quick search: window opened");
        }
        Err(error) => log::warn!("quick search: no window ({error})"),
    }
}

/// A fifth of the way down the screen with the mouse pointer, where the
/// eyes are, rather than in the middle.
fn place(app: &AppHandle, window: &WebviewWindow) {
    let monitor = app
        .cursor_position()
        .ok()
        .and_then(|at| app.monitor_from_point(at.x, at.y).ok().flatten())
        .or_else(|| app.primary_monitor().ok().flatten());
    let Some(monitor) = monitor else {
        return;
    };
    let scale = monitor.scale_factor();
    let origin = monitor.position().to_logical::<f64>(scale);
    let size = monitor.size().to_logical::<f64>(scale);
    let x = origin.x + (size.width - WIDTH) / 2.0;
    let y = origin.y + (size.height / 5.0).max(40.0);
    let _ = window.set_position(LogicalPosition::new(x, y));
}

/// Closes the window. With `back`, the app the user was in gets the focus
/// again (Escape, a copy); without, the focus stays where it went (the user
/// clicked elsewhere).
pub fn close(app: &AppHandle, back: bool) {
    let previous = lock(&PREVIOUS).take();
    if let Some(window) = app.get_webview_window(LABEL) {
        let _ = window.close();
    }
    if back && let Some(previous) = previous {
        previous.restore();
    }
}

/// Closes the window and opens a terminal session to `alias` in the main
/// window, which comes forward.
pub fn connect(app: &AppHandle, alias: &str) -> AppResult<()> {
    crate::commands::remote::check_alias(alias)?;
    close(app, false);
    crate::tray::show_window(app);
    app.emit(crate::tray::PAGE_EVENT, format!("connect:{alias}"))
        .map_err(|e| AppError::new(ErrorCode::Io, e.to_string()))
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_default_to_the_default_shortcut_on() {
        let settings: Settings = serde_json::from_str("{}").unwrap();
        assert!(settings.enabled);
        assert_eq!(wanted(&settings).unwrap().1, shortcut::DEFAULT);
    }

    #[test]
    fn a_broken_saved_shortcut_falls_back_to_the_default() {
        let settings = Settings {
            enabled: true,
            shortcut: Some("Shift+KeyA".into()),
        };
        assert_eq!(wanted(&settings).unwrap().1, shortcut::DEFAULT);
        let settings = Settings {
            enabled: true,
            shortcut: Some("Alt+Ctrl+KeyK".into()),
        };
        assert_eq!(wanted(&settings).unwrap().1, "Ctrl+Alt+KeyK");
    }
}
