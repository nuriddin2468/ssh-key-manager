//! Unlocking the vault without the app's main window: when the browser asks,
//! and from the tray menu.
//!
//! The extension's "Unlock" on a login field sends [`Message::Unlock`]; the
//! broker limits how often ([`super::broker::MAX_UNLOCKS`]) and asks here.
//! The tray's "Unlock Vault…" asks here too ([`Asker::Tray`]). The app then
//! asks the user itself, outside the browser:
//!
//! 1. With Touch ID or Windows Hello set up for the vault, the system prompt
//!    and nothing else: an app in the tray stays there. The prompt's text is
//!    the app's own ([`crate::device_unlock`]).
//! 2. Without it, or if the user dismisses the prompt or it fails, a small
//!    window of the app's own ([`LABEL`], `unlock.html`) asks for the master
//!    password, offering Touch ID again where it is set up. The main window
//!    stays as it is. The unlock window may call only the unlock commands
//!    (`capabilities/unlock.json`), and closes once the vault is unlocked,
//!    whichever way that happened.
//!
//! Neither is drawn by the browser: a page could draw a look-alike of
//! anything shown there, and the master password never passes through the
//! extension. While the prompt is up, asking again does nothing; while the
//! window is open, asking again brings it forward instead of opening another.
//!
//! The window stays above other windows, has no taskbar button and opens in
//! the middle of the screen. Where the system decides otherwise, it still
//! opens: on Windows a program in the background may be refused the focus
//! (`tao` works around that with a synthetic Alt key press, as the system
//! allows the program that last received input to take it), and on Wayland
//! the compositor places windows and may keep the focus or the top for the
//! browser.
//!
//! [`Message::Unlock`]: sshkm_core::browser::protocol::Message::Unlock

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use sshkm_core::ErrorCode;
use sshkm_core::vault;
use tauri::window::Color;
use tauri::{AppHandle, Listener, Manager, WebviewUrl, WebviewWindowBuilder};

use crate::commands::Shared;
use crate::confirm::Localized;
use crate::device_unlock;
use crate::state::AppState;
use crate::vault::UNLOCKED_EVENT;

/// The unlock window's label; its capability names it.
pub const LABEL: &str = "unlock";
/// Its page, next to the main window's `index.html`.
const PAGE: &str = "unlock.html";
const WIDTH: f64 = 380.0;
const HEIGHT: f64 = 240.0;
/// The main window's background, so the window doesn't flash white.
const BACKGROUND: Color = Color(0x0A, 0x0D, 0x14, 0xFF);

/// A Touch ID or Windows Hello prompt is up.
static PROMPTING: AtomicBool = AtomicBool::new(false);

/// Who asked to unlock, which the window says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asker {
    /// The browser extension, to fill a login.
    Browser,
    /// The user, from the tray menu.
    Tray,
}

impl Asker {
    /// The page with what it says: `unlock.html?for=…`.
    fn page(self) -> String {
        let asker = match self {
            Self::Browser => "browser",
            Self::Tray => "tray",
        };
        format!("{PAGE}?for={asker}")
    }
}

/// Closes the unlock window whenever the vault is unlocked. Called once at
/// start.
pub fn watch(app: &AppHandle) {
    let handle = app.clone();
    app.listen_any(UNLOCKED_EVENT, move |_| {
        if let Some(window) = handle.get_webview_window(LABEL) {
            let _ = window.close();
        }
    });
}

/// Asks the user to unlock the vault: the system prompt where it is set up,
/// else (or if it is dismissed) the unlock window. A vault this computer
/// opens only with its recovery key is unlocked in the main window, which
/// comes forward instead. Returns at once.
pub fn ask(app: &AppHandle, asker: Asker) {
    if focus(app) || PROMPTING.swap(true, Ordering::SeqCst) {
        return;
    }
    let app = app.clone();
    thread::spawn(move || {
        let ways = app.try_state::<Shared>().and_then(|state| ways_in(&state));
        let unlocked = ways.as_ref().is_some_and(|ways| ways.device) && with_device(&app);
        PROMPTING.store(false, Ordering::SeqCst);
        match ways {
            _ if unlocked => {}
            Some(ways) if ways.master || ways.device => open(&app, asker),
            _ => super::show_app(&app),
        }
    });
}

/// How this computer can unlock the vault without the recovery key.
struct WaysIn {
    master: bool,
    /// Touch ID or Windows Hello, set up for this vault and available now.
    device: bool,
}

fn ways_in(state: &AppState) -> Option<WaysIn> {
    let files = vault::probe(&state.vault.paths()).ok()?;
    let link = device_unlock::load_link(state.vault.data_dir());
    let device = device_unlock::status(
        link.as_ref(),
        files.vault_id.as_deref(),
        &files.device_slots,
    );
    Some(WaysIn {
        master: files.has_master_password,
        device: device.enabled && device.kind.is_some(),
    })
}

/// Unlocks with Touch ID or Windows Hello. Blocks until the user answers.
fn with_device(app: &AppHandle) -> bool {
    let Some(state) = app.try_state::<Shared>() else {
        return false;
    };
    if state.vault.is_unlocked() {
        return true;
    }
    match device_unlock::unlock(state.vault.data_dir(), &state.vault.paths()) {
        Ok(vault) => {
            state.vault.set_unlocked(vault);
            true
        }
        Err(error) if error.code() == ErrorCode::Cancelled => {
            log::info!("unlock: device unlock dismissed; asking in the unlock window");
            false
        }
        Err(error) => {
            log::warn!("unlock: device unlock failed ({error}); asking in the unlock window");
            false
        }
    }
}

/// Brings the unlock window forward if it is open.
fn focus(app: &AppHandle) -> bool {
    let Some(window) = app.get_webview_window(LABEL) else {
        return false;
    };
    let _ = window.unminimize();
    let _ = window.show();
    let _ = window.set_focus();
    true
}

/// Opens the unlock window, or brings it forward. If it can't be made, the
/// main window comes forward on the vault instead, as before.
fn open(app: &AppHandle, asker: Asker) {
    if focus(app) {
        return;
    }
    let title = Localized::new(
        "Unlock the Vault",
        "Разблокировка хранилища",
        "Omborni ochish",
    );
    let built = WebviewWindowBuilder::new(app, LABEL, WebviewUrl::App(asker.page().into()))
        .title(title.pick())
        .inner_size(WIDTH, HEIGHT)
        .resizable(false)
        .maximizable(false)
        .minimizable(false)
        .always_on_top(true)
        .skip_taskbar(true)
        .center()
        .focused(true)
        .theme(Some(tauri::Theme::Dark))
        .background_color(BACKGROUND)
        .build();
    match built {
        Ok(window) => {
            let _ = window.set_focus();
        }
        Err(error) => {
            log::warn!("unlock: no unlock window ({error}); showing the app");
            super::show_app(app);
        }
    }
}
