//! Native confirmation dialogs for changes that page script must not be able
//! to approve by itself: running commands from the SSH config, weakening the
//! vault's protection, writing files where the user didn't pick them. The
//! operating system draws the dialog outside the webview, so a script in the
//! page can neither click it nor change its text. Every text shown here is
//! built in Rust; the page only chooses the language.

use std::sync::atomic::{AtomicU8, Ordering};

use sshkm_core::ErrorCode;
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

use crate::error::{AppError, AppResult};

/// The interface language: 0 English, 1 Russian, 2 Uzbek.
static LANGUAGE: AtomicU8 = AtomicU8::new(0);

/// A text in each language of the interface.
pub struct Localized {
    pub en: String,
    pub ru: String,
    pub uz: String,
}

impl Localized {
    pub fn new(en: impl Into<String>, ru: impl Into<String>, uz: impl Into<String>) -> Self {
        Self {
            en: en.into(),
            ru: ru.into(),
            uz: uz.into(),
        }
    }

    /// The text in the interface's language.
    pub fn pick(&self) -> &str {
        match LANGUAGE.load(Ordering::Relaxed) {
            1 => &self.ru,
            2 => &self.uz,
            _ => &self.en,
        }
    }
}

/// Follows the interface's language (`en`, `ru` or `uz`; anything else is
/// English).
#[tauri::command]
pub fn set_ui_language(language: &str) {
    let code = match language {
        "ru" => 1,
        "uz" => 2,
        _ => 0,
    };
    LANGUAGE.store(code, Ordering::Relaxed);
}

/// Shows `body` in a native dialog and returns `Ok` only if the user chose
/// `approve`; otherwise fails with `cancelled`. Blocks until the dialog
/// closes, so call it from a blocking task, never on the main thread.
pub fn require(
    app: &AppHandle,
    title: &Localized,
    body: &Localized,
    approve: &Localized,
) -> AppResult<()> {
    let cancel = Localized::new("Cancel", "Отмена", "Bekor qilish");
    let mut dialog = app
        .dialog()
        .message(body.pick())
        .title(title.pick())
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(
            approve.pick().to_owned(),
            cancel.pick().to_owned(),
        ));
    if let Some(window) = app.get_webview_window("main") {
        dialog = dialog.parent(&window);
    }
    if dialog.blocking_show() {
        Ok(())
    } else {
        Err(AppError::new(ErrorCode::Cancelled, "not approved"))
    }
}
