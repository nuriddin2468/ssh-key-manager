//! Running on with the window closed, and the tray icon (on macOS, in the
//! menu bar) that stays meanwhile.
//!
//! With the setting on, closing the window hides it: browser autofill, the
//! user's own devices on Nearby, terminal sessions, tunnels and the vault's
//! timers carry on. The icon's menu brings the window back and offers what
//! needs no window: the vault's state, locking it and unlocking it (in the
//! small unlock window, [`crate::browser::unlock`]), the tunnels that are on
//! and stopping them, quick search ([`crate::quick`]), connecting to a host,
//! a Nearby conversation waiting for the user, and quitting. A conversation
//! that starts waiting while the window is hidden brings the window back by
//! itself, as a browser's pairing request already does: both come only from
//! something the user started or allowed, and time out.
//!
//! One worker thread rebuilds the menu whenever what it shows may have
//! changed ([`refresh`]): the vault locked or unlocked, `~/.ssh` changed, a
//! tunnel changed, a Nearby conversation started or stopped waiting, the
//! window lost focus (the user may head for the icon next, after unlocking or
//! connecting in the window), or the language changed. It sets the menu only if it came out different.
//!
//! The setting is on by default on macOS and Windows, which always have a
//! place for the icon. On Linux it is off by default, and can't be turned on
//! without the `AppIndicator` library ([`sshkm_os::tray`]); on a desktop that
//! has the library but shows no tray (plain GNOME), opening the app again
//! brings the window back.

pub mod menu;

use std::mem::Discriminant;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sshkm_core::config::{HostKind, SshConfig};
use sshkm_core::{ErrorCode, fsutil};
use tauri::menu::{IsMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{TrayIcon, TrayIconBuilder};
use tauri::{AppHandle, Emitter, Listener, Manager, Window, WindowEvent, Wry};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

use self::menu::{Input, Item, Vault, Waiting};
use crate::commands::Shared;
use crate::confirm::Localized;
use crate::error::{AppError, AppResult};
use crate::nearby::SharedNearby;
use crate::nearby::pairing::PairingPhase;
use crate::tunnels::SharedTunnels;
use crate::vault::LockReason;

const SETTINGS_FILE: &str = "background.json";
const TRAY_ID: &str = "main";
/// How the page is told what to show: the event the macOS menu bar sends
/// its commands with (`useAppEvents`).
pub(crate) const PAGE_EVENT: &str = "menu";
/// Changes coming close together make one rebuild.
const SETTLE: Duration = Duration::from_millis(150);

/// What `background.json` holds.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Settings {
    /// `None`: the platform's default.
    enabled: Option<bool>,
}

/// The setting as the Settings page shows it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct BackgroundStatus {
    pub enabled: bool,
    /// The system can show the tray icon; without it, the setting stays off.
    pub available: bool,
}

pub type SharedBackground = Arc<Background>;

pub struct Background {
    settings_file: PathBuf,
    available: bool,
    enabled: AtomicBool,
    /// Wakes the worker that rebuilds the menu.
    worker: Sender<()>,
    /// The menu shown, so an unchanged one isn't rebuilt.
    shown: Mutex<Option<Vec<Item>>>,
    /// The Nearby conversation and step waiting for the user, if one is.
    asking: Mutex<Option<(u32, Discriminant<PairingPhase>)>>,
}

impl Background {
    /// Reads the setting, starts the worker and, with the setting on, makes
    /// the icon. Called once at start, after the app's state is managed.
    pub fn install(app: &AppHandle, data_dir: &std::path::Path) -> SharedBackground {
        let settings_file = data_dir.join(SETTINGS_FILE);
        let settings: Settings = std::fs::read(&settings_file)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        let available = sshkm_os::tray::available();
        let enabled = available && settings.enabled.unwrap_or(cfg!(not(target_os = "linux")));
        let (worker, wake) = mpsc::channel::<()>();
        let background = Arc::new(Self {
            settings_file,
            available,
            enabled: AtomicBool::new(enabled),
            worker,
            shown: Mutex::new(None),
            asking: Mutex::new(None),
        });

        let handle = app.clone();
        thread::spawn(move || {
            while wake.recv().is_ok() {
                thread::sleep(SETTLE);
                while wake.try_recv().is_ok() {}
                rebuild(&handle);
            }
        });
        for event in [
            crate::vault::LOCKED_EVENT,
            crate::vault::UNLOCKED_EVENT,
            crate::watcher::EVENT,
            crate::vault_watcher::EVENT,
            crate::tunnels::CHANGED_EVENT,
        ] {
            let handle = app.clone();
            app.listen_any(event, move |_| refresh(&handle));
        }
        let handle = app.clone();
        app.listen_any(crate::nearby::CHANGED_EVENT, move |_| {
            nearby_changed(&handle);
        });

        if enabled {
            match create_icon(app) {
                Ok(items) => *lock(&background.shown) = Some(items),
                Err(e) => {
                    log::warn!("tray: no icon: {e}");
                    background.enabled.store(false, Ordering::Relaxed);
                }
            }
        }
        background
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn status(&self) -> BackgroundStatus {
        BackgroundStatus {
            enabled: self.enabled(),
            available: self.available,
        }
    }

    /// Turns running on with the window closed on or off, and saves it.
    pub fn set_enabled(&self, app: &AppHandle, on: bool) -> AppResult<BackgroundStatus> {
        if on && !self.available {
            return Err(AppError::new(
                ErrorCode::Unsupported,
                "this desktop has no tray for the icon",
            ));
        }
        let mut json = serde_json::to_vec_pretty(&Settings { enabled: Some(on) })
            .map_err(|e| AppError::new(ErrorCode::Io, e.to_string()))?;
        json.push(b'\n');
        fsutil::atomic_write(&self.settings_file, &json, 0o600)?;
        if on {
            let items =
                create_icon(app).map_err(|e| AppError::new(ErrorCode::Io, e.to_string()))?;
            *lock(&self.shown) = Some(items);
        } else {
            app.remove_tray_by_id(TRAY_ID);
            *lock(&self.shown) = None;
        }
        self.enabled.store(on, Ordering::Relaxed);
        Ok(self.status())
    }

    fn poke(&self) {
        let _ = self.worker.send(());
    }
}

/// Rebuilds the menu soon, if it changed. Cheap: call it whenever what the
/// menu shows may have changed.
pub fn refresh(app: &AppHandle) {
    if let Some(background) = app.try_state::<SharedBackground>()
        && background.enabled()
    {
        background.poke();
    }
}

/// Closing the window hides it while the setting is on, and the window
/// losing focus refreshes the menu.
pub fn on_window_event(window: &Window, event: &WindowEvent) {
    let app = window.app_handle();
    match event {
        WindowEvent::CloseRequested { api, .. }
            if window.label() == "main"
                && app
                    .try_state::<SharedBackground>()
                    .is_some_and(|background| background.enabled()) =>
        {
            api.prevent_close();
            hide(window);
        }
        WindowEvent::Focused(false) => refresh(app),
        _ => {}
    }
}

/// Shows the main window and brings it to the front.
pub fn show_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Hides the window, locking the vault first if the settings say to lock it
/// when the window is minimised.
fn hide(window: &Window) {
    let app = window.app_handle();
    if let Some(state) = app.try_state::<Shared>()
        && state.vault.settings().lock_on_minimize
    {
        state.vault.lock(app, LockReason::Minimize);
    }
    let _ = window.hide();
    refresh(app);
}

/// Makes the icon with its menu, and returns the menu's items.
fn create_icon(app: &AppHandle) -> tauri::Result<Vec<Item>> {
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let items = items(app);
        set_menu(app, &tray, &items)?;
        return Ok(items);
    }
    let builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("SSH Key Manager")
        // Windows: a click opens the window and the menu is on the right
        // button, as there. Linux: the indicator shows the menu on any click
        // and reports no clicks.
        .show_menu_on_left_click(!cfg!(windows))
        .on_menu_event(|app, event| act(app, event.id().as_ref()))
        .on_tray_icon_event(|tray, event| {
            use tauri::tray::{MouseButton, MouseButtonState, TrayIconEvent};
            if cfg!(windows)
                && let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = event
            {
                show_window(tray.app_handle());
            }
        });
    // macOS: a template image, which the menu bar tints for light and dark.
    #[cfg(target_os = "macos")]
    let builder = builder
        .icon(tauri::image::Image::from_bytes(include_bytes!(
            "../../icons/tray-template.png"
        ))?)
        .icon_as_template(true);
    #[cfg(not(target_os = "macos"))]
    let builder = match app.default_window_icon() {
        Some(icon) => builder.icon(icon.clone()),
        None => builder,
    };
    let tray = builder.build(app)?;
    // An indicator without a menu isn't shown at all on Linux, so the first
    // one is set right away.
    let items = items(app);
    set_menu(app, &tray, &items)?;
    Ok(items)
}

/// Works out the menu and sets it if it changed.
fn rebuild(app: &AppHandle) {
    let Some(background) = app.try_state::<SharedBackground>() else {
        return;
    };
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return;
    };
    let items = items(app);
    let mut shown = lock(&background.shown);
    if shown.as_ref() == Some(&items) {
        return;
    }
    match set_menu(app, &tray, &items) {
        Ok(()) => *shown = Some(items),
        Err(e) => log::warn!("tray: menu not updated: {e}"),
    }
}

fn set_menu(app: &AppHandle, tray: &TrayIcon, items: &[Item]) -> tauri::Result<()> {
    let menu = Menu::new(app)?;
    for item in items {
        menu.append(&*native(app, item)?)?;
    }
    tray.set_menu(Some(menu))
}

fn native(app: &AppHandle, item: &Item) -> tauri::Result<Box<dyn IsMenuItem<Wry>>> {
    // `&` marks a mnemonic in menu texts; a device's name may hold one.
    let escape = |text: &str| text.replace('&', "&&");
    Ok(match item {
        Item::Label(text) => Box::new(MenuItem::new(app, escape(text), false, None::<&str>)?),
        Item::Action { id, text } => Box::new(MenuItem::with_id(
            app,
            id.as_str(),
            escape(text),
            true,
            None::<&str>,
        )?),
        Item::Submenu { text, items } => {
            let submenu = Submenu::new(app, escape(text), true)?;
            for item in items {
                submenu.append(&*native(app, item)?)?;
            }
            Box::new(submenu)
        }
        Item::Separator => Box::new(PredefinedMenuItem::separator(app)?),
    })
}

/// The menu for the app's state now.
fn items(app: &AppHandle) -> Vec<Item> {
    let Some(state) = app.try_state::<Shared>() else {
        return Vec::new();
    };
    let vault = if state.vault.is_unlocked() {
        Vault::Unlocked
    } else if state.vault.paths().database.is_file() {
        Vault::Locked
    } else {
        Vault::Missing
    };
    // A config that can't be read lists no hosts; the window says why.
    let aliases: Vec<String> = SshConfig::load(&state.paths.config)
        .map(|config| {
            config
                .view()
                .hosts
                .into_iter()
                .filter(|host| host.kind == HostKind::Host && !host.is_wildcard)
                .flat_map(|host| host.patterns)
                .collect()
        })
        .unwrap_or_default();
    let history = state.history.all();
    let waiting = app.try_state::<SharedNearby>().and_then(|nearby| {
        let pairing = nearby.status().pairing?;
        pairing
            .phase
            .asks_user()
            .then_some(Waiting { peer: pairing.peer })
    });
    let tunnels = app
        .try_state::<SharedTunnels>()
        .map(|tunnels| tunnels.active())
        .unwrap_or_default();
    menu::items(&Input {
        vault,
        aliases: &aliases,
        history: &history,
        waiting,
        tunnels: &tunnels,
    })
}

/// Follows Nearby: when a conversation starts waiting for the user, or
/// stops, the menu changes, and a hidden window comes back to ask.
fn nearby_changed(app: &AppHandle) {
    let (Some(background), Some(nearby)) = (
        app.try_state::<SharedBackground>(),
        app.try_state::<SharedNearby>(),
    ) else {
        return;
    };
    let asking = nearby
        .status()
        .pairing
        .filter(|pairing| pairing.phase.asks_user())
        .map(|pairing| (pairing.id, std::mem::discriminant(&pairing.phase)));
    let before = std::mem::replace(&mut *lock(&background.asking), asking);
    if asking == before {
        return;
    }
    if asking.is_some()
        && let Some(window) = app.get_webview_window("main")
        && !window.is_visible().unwrap_or(true)
    {
        show_window(app);
    }
    refresh(app);
}

/// Does what the menu item `id` is for.
fn act(app: &AppHandle, id: &str) {
    let page = |command: &str| {
        show_window(app);
        let _ = app.emit(PAGE_EVENT, command);
    };
    match id {
        menu::OPEN | menu::NEARBY => show_window(app),
        menu::QUICK => crate::quick::open(app),
        menu::ALL_HOSTS => page("new-session"),
        // Touch ID or Windows Hello, else the small unlock window: the main
        // window stays as it is.
        menu::UNLOCK => crate::browser::unlock::ask(app, crate::browser::unlock::Asker::Tray),
        menu::LOCK => {
            if let Some(state) = app.try_state::<Shared>() {
                state.vault.lock(app, LockReason::Manual);
            }
        }
        menu::QUIT => quit(app),
        menu::TUNNELS => page("tool:tunnels"),
        menu::STOP_TUNNELS => {
            if let Some(tunnels) = app.try_state::<SharedTunnels>() {
                tunnels.stop_all();
            }
        }
        _ => {
            if let Some(alias) = id.strip_prefix(menu::HOST)
                && crate::commands::remote::check_alias(alias).is_ok()
            {
                page(&format!("connect:{alias}"));
            }
        }
    }
}

/// Quits, after asking if terminal sessions would end.
fn quit(app: &AppHandle) {
    let sessions = app
        .try_state::<Shared>()
        .map_or(0, |state| state.terminals.list().len());
    if sessions == 0 {
        app.exit(0);
        return;
    }
    let title = Localized::new(
        if sessions == 1 {
            "Quit and close the terminal session?".to_owned()
        } else {
            format!("Quit and close {sessions} terminal sessions?")
        },
        format!("Выйти и закрыть сессии терминала ({sessions})?"),
        format!("Chiqib, terminal seanslarini ({sessions}) yopasizmi?"),
    );
    let body = Localized::new(
        "Their connections to the servers end.",
        "Подключения к серверам будут разорваны.",
        "Serverlarga ulanishlar uziladi.",
    );
    let quit = Localized::new("Quit", "Выйти", "Chiqish");
    let cancel = Localized::new("Cancel", "Отмена", "Bekor qilish");
    let handle = app.clone();
    app.dialog()
        .message(body.pick())
        .title(title.pick())
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(
            quit.pick().to_owned(),
            cancel.pick().to_owned(),
        ))
        .show(move |approved| {
            if approved {
                handle.exit(0);
            }
        });
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
