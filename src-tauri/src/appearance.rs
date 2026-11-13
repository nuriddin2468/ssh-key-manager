//! Light or dark: the windows' own look (the title bar, the colour a window
//! shows before its page paints, native dialogs) follows the Appearance
//! setting. The page keeps that setting (`src/lib/settings.ts`) and passes it
//! here through [`set_appearance`]; a copy in the app's data folder lets the
//! next start open its window in the right colour before any page loads.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use serde::{Deserialize, Serialize};
use sshkm_core::fsutil;
use tauri::window::Color;
use tauri::{AppHandle, Manager, Runtime, State, Theme, Window, WindowEvent};

const FILE: &str = "appearance.json";

/// `--color-canvas` in `src/styles/app.css`, dark and light.
const DARK: Color = Color(0x0A, 0x0D, 0x14, 0xFF);
const LIGHT: Color = Color(0xEC, 0xEE, 0xF2, 0xFF);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Appearance {
    /// The system's appearance.
    #[default]
    System,
    Light,
    Dark,
}

impl Appearance {
    /// The theme to force on the windows; `None` follows the system.
    fn theme(self) -> Option<Theme> {
        match self {
            Self::System => None,
            Self::Light => Some(Theme::Light),
            Self::Dark => Some(Theme::Dark),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Saved {
    appearance: Appearance,
    /// What the page last showed, for when the system's own theme can't be
    /// read before a window exists.
    #[serde(default = "dark_by_default")]
    dark: bool,
}

fn dark_by_default() -> bool {
    true
}

/// Before anything is saved: the system's appearance, dark until known.
impl Default for Saved {
    fn default() -> Self {
        Self {
            appearance: Appearance::System,
            dark: true,
        }
    }
}

pub struct Appearances {
    file: PathBuf,
    saved: Mutex<Saved>,
}

impl Appearances {
    fn lock(&self) -> MutexGuard<'_, Saved> {
        self.saved.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn read(file: &Path) -> Saved {
    std::fs::read(file)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn color(dark: bool) -> Color {
    if dark { DARK } else { LIGHT }
}

/// Whether a window of the app shows dark now: the forced theme, or the
/// system's as the main window reports it, or what the page last showed.
fn is_dark<R: Runtime>(app: &AppHandle<R>, saved: Saved) -> bool {
    match saved.appearance {
        Appearance::Light => false,
        Appearance::Dark => true,
        Appearance::System => app
            .get_webview_window("main")
            .and_then(|window| window.theme().ok())
            .map_or(saved.dark, |theme| theme == Theme::Dark),
    }
}

/// Reads the saved appearance and gives it to the app and the main window,
/// which is still hidden. Call it before the window is shown.
pub fn install<R: Runtime>(app: &AppHandle<R>, data_dir: &Path) {
    let file = data_dir.join(FILE);
    let saved = read(&file);
    app.set_theme(saved.appearance.theme());
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.set_background_color(Some(color(is_dark(app, saved))));
    }
    app.manage(Appearances {
        file,
        saved: Mutex::new(saved),
    });
}

/// The theme a new window should force (`None`: the system's).
pub fn theme<R: Runtime>(app: &AppHandle<R>) -> Option<Theme> {
    app.try_state::<Appearances>()
        .and_then(|state| state.lock().appearance.theme())
}

/// The colour a new window shows before its page paints.
pub fn background<R: Runtime>(app: &AppHandle<R>) -> Color {
    let saved = app
        .try_state::<Appearances>()
        .map(|state| *state.lock())
        .unwrap_or_default();
    color(is_dark(app, saved))
}

/// The page's Appearance setting, and whether it shows dark (`dark`). Sets
/// the windows' theme and background, and saves both for the next start.
#[tauri::command]
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri passes command arguments by value"
)]
pub fn set_appearance(
    app: AppHandle,
    state: State<'_, Appearances>,
    appearance: Appearance,
    dark: bool,
) {
    let next = Saved { appearance, dark };
    let changed = {
        let mut saved = state.lock();
        let changed = *saved != next;
        *saved = next;
        changed
    };
    if changed {
        save(&state.file, next);
        app.set_theme(appearance.theme());
    }
    for window in app.webview_windows().values() {
        let _ = window.set_background_color(Some(color(dark)));
    }
}

fn save(file: &Path, saved: Saved) {
    let Ok(mut json) = serde_json::to_vec_pretty(&saved) else {
        return;
    };
    json.push(b'\n');
    if let Some(dir) = file.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Err(error) = fsutil::atomic_write(file, &json, 0o600) {
        log::warn!("appearance: not saved ({error})");
    }
}

/// While the setting is System, a window that the system turns light or dark
/// takes the matching background at once, before its page catches up.
pub fn on_window_event<R: Runtime>(window: &Window<R>, event: &WindowEvent) {
    let WindowEvent::ThemeChanged(theme) = event else {
        return;
    };
    let app = window.app_handle();
    let Some(state) = app.try_state::<Appearances>() else {
        return;
    };
    if state.lock().appearance == Appearance::System {
        let _ = window.set_background_color(Some(color(*theme == Theme::Dark)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_what_it_saves() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("nested").join(FILE);
        assert_eq!(read(&file), Saved::default());
        let light = Saved {
            appearance: Appearance::Light,
            dark: false,
        };
        save(&file, light);
        assert_eq!(read(&file), light);
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(text.contains("\"light\""), "{text}");
    }

    #[test]
    fn a_broken_file_means_the_system() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(FILE);
        std::fs::write(&file, "not json").unwrap();
        assert_eq!(read(&file), Saved::default());
        std::fs::write(&file, r#"{"appearance":"dark"}"#).unwrap();
        assert_eq!(
            read(&file),
            Saved {
                appearance: Appearance::Dark,
                dark: true
            }
        );
    }

    #[test]
    fn system_forces_no_theme() {
        assert_eq!(Appearance::System.theme(), None);
        assert_eq!(Appearance::Light.theme(), Some(Theme::Light));
        assert_eq!(Appearance::Dark.theme(), Some(Theme::Dark));
        assert_eq!(color(true), DARK);
        assert_eq!(color(false), LIGHT);
    }
}
