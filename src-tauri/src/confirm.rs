//! Native confirmation dialogs for changes that page script must not be able
//! to approve by itself: running commands from the SSH config, weakening the
//! vault's protection, writing files where the user didn't pick them. The
//! operating system draws the dialog outside the webview, so a script in the
//! page can neither click it nor change its text. Every text shown here is
//! built in Rust; the page only chooses the language.
//!
//! The page can choose when a dialog opens, though, and the approving button
//! is the default one (Return): rfd adds it first, and neither rfd nor the
//! dialog plugin can pick another default. Putting Cancel first instead would
//! turn Escape and closing the dialog into a yes on Windows and Linux, where
//! the plugin reports those as the second button. So a yes that comes within
//! a second of the dialog appearing doesn't count, and the dialog is shown
//! again: it may have been a key press or click meant for the page.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use sshkm_core::ErrorCode;
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

use crate::error::{AppError, AppResult};

/// The interface language: 0 English, 1 Russian, 2 Uzbek.
static LANGUAGE: AtomicU8 = AtomicU8::new(0);

/// A yes given sooner than this after the dialog appeared is not taken.
const MIN_ANSWER_TIME: Duration = Duration::from_secs(1);

/// How many times a dialog is shown before quick yeses count as a no, so a
/// held Return key doesn't keep reopening it.
const MAX_ASKS: u32 = 3;

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
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri passes command arguments by value"
)]
pub fn set_ui_language(app: AppHandle, language: &str) {
    let code = match language {
        "ru" => 1,
        "uz" => 2,
        _ => 0,
    };
    LANGUAGE.store(code, Ordering::Relaxed);
    crate::tray::refresh(&app);
}

/// Shows `body` in a native dialog and returns `Ok` only if the user chose
/// `approve` at least [`MIN_ANSWER_TIME`] after the dialog appeared; a
/// quicker choice shows the dialog again. Otherwise fails with `cancelled`.
/// Blocks until the dialog closes, so call it from a blocking task, never on
/// the main thread.
pub fn require(
    app: &AppHandle,
    title: &Localized,
    body: &Localized,
    approve: &Localized,
) -> AppResult<()> {
    let cancel = Localized::new("Cancel", "Отмена", "Bekor qilish");
    let again = Localized::new(
        "Asked again: the answer came less than a second after this question appeared, so \
         it may have been a key press meant for something else.",
        "Вопрос задан ещё раз: ответ пришёл меньше чем через секунду после его появления, \
         поэтому это могло быть нажатие, предназначенное для чего-то другого.",
        "Savol qayta berildi: javob u paydo boʻlganidan keyin bir soniyaga yetmay keldi, \
         shuning uchun bu boshqa narsa uchun bosilgan tugma boʻlishi mumkin.",
    );
    let approved = ask(|asked_before| {
        let body = if asked_before {
            format!("{}\n\n{}", again.pick(), body.pick())
        } else {
            body.pick().to_owned()
        };
        show(app, title.pick(), &body, approve.pick(), cancel.pick())
    });
    if approved {
        Ok(())
    } else {
        Err(AppError::new(ErrorCode::Cancelled, "not approved"))
    }
}

/// Asks with `show` until the answer is no, or a yes that came at least
/// [`MIN_ANSWER_TIME`] after the question appeared; after [`MAX_ASKS`] quick
/// yeses, the answer is no. `show` is told whether the question was asked
/// before, and returns the answer and how long the question was open.
fn ask(mut show: impl FnMut(bool) -> (bool, Duration)) -> bool {
    for asked in 0..MAX_ASKS {
        match show(asked > 0) {
            (false, _) => return false,
            (true, open) if open >= MIN_ANSWER_TIME => return true,
            (true, open) => {
                log::info!("confirm: a yes {open:?} after the dialog opened doesn't count");
            }
        }
    }
    false
}

/// Shows one dialog and waits for it to close: whether the user chose
/// `approve`, and how long the dialog had been open by then.
fn show(app: &AppHandle, title: &str, body: &str, approve: &str, cancel: &str) -> (bool, Duration) {
    let mut dialog = app
        .dialog()
        .message(body)
        .title(title)
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(
            approve.to_owned(),
            cancel.to_owned(),
        ));
    if let Some(window) = app.get_webview_window("main") {
        dialog = dialog.parent(&window);
    }
    let (send_answer, answer) = mpsc::channel();
    let asked = Instant::now();
    dialog.show(move |approved| {
        let _ = send_answer.send((approved, Instant::now()));
    });
    // The dialog opens in a task on the main thread, and this task runs right
    // after it, so a main thread kept busy can't make the dialog seem older
    // than it is. (On Windows and Linux the dialog's own thread may take a
    // few milliseconds more to draw it.)
    let (send_opened, opened) = mpsc::channel();
    let _ = app.run_on_main_thread(move || {
        let _ = send_opened.send(Instant::now());
    });
    let Ok((approved, answered)) = answer.recv() else {
        return (false, Duration::ZERO);
    };
    let opened = opened.recv().unwrap_or(asked);
    (approved, answered.saturating_duration_since(opened))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The answers `ask` got, and whether each question was asked before.
    fn asked(answers: &[(bool, u64)]) -> (bool, Vec<bool>) {
        let mut answers = answers.iter();
        let mut again = Vec::new();
        let approved = ask(|asked_before| {
            again.push(asked_before);
            let (yes, millis) = answers.next().expect("asked too often");
            (*yes, Duration::from_millis(*millis))
        });
        (approved, again)
    }

    #[test]
    fn a_quick_yes_asks_again() {
        assert_eq!(asked(&[(true, 1500)]), (true, vec![false]));
        assert_eq!(asked(&[(true, 1000)]), (true, vec![false]));
        assert_eq!(asked(&[(false, 50)]), (false, vec![false]));
        assert_eq!(asked(&[(false, 5000)]), (false, vec![false]));
        assert_eq!(
            asked(&[(true, 80), (true, 2000)]),
            (true, vec![false, true])
        );
        assert_eq!(
            asked(&[(true, 80), (false, 2000)]),
            (false, vec![false, true])
        );
        // A held Return key answers every time at once.
        assert_eq!(
            asked(&[(true, 30), (true, 30), (true, 999)]),
            (false, vec![false, true, true])
        );
    }
}
