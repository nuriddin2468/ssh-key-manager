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

use std::fmt::Write as _;
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

/// Shows `body` in a native dialog whose default button is `keep` (Return)
/// and `act` the other one; `true` only if the user chose `act` at least
/// [`MIN_ANSWER_TIME`] after the dialog appeared (a quicker choice shows it
/// again). Escape and closing the dialog are `keep`. For a question whose
/// safe answer is no. Blocks like [`require`].
///
/// The dialog plugin reports Escape as the second button, so this one is
/// drawn with `rfd` itself, which tells Escape apart: `keep` first, so it is
/// the default, and anything but a click on `act` is no.
pub fn ask_default_no(
    app: &AppHandle,
    title: &Localized,
    body: &Localized,
    act: &Localized,
    keep: &Localized,
) -> bool {
    let again = Localized::new(
        "Asked again: the answer came less than a second after this question appeared, so \
         it may have been a key press meant for something else.",
        "Вопрос задан ещё раз: ответ пришёл меньше чем через секунду после его появления, \
         поэтому это могло быть нажатие, предназначенное для чего-то другого.",
        "Savol qayta berildi: javob u paydo boʻlganidan keyin bir soniyaga yetmay keldi, \
         shuning uchun bu boshqa narsa uchun bosilgan tugma boʻlishi mumkin.",
    );
    ask(|asked_before| {
        let body = if asked_before {
            format!("{}\n\n{}", again.pick(), body.pick())
        } else {
            body.pick().to_owned()
        };
        show_default_no(app, title.pick(), &body, act.pick(), keep.pick())
    })
}

/// The buttons of [`ask_default_no`]'s dialog: `keep` first, the default.
fn default_no_buttons(act: &str, keep: &str) -> rfd::MessageButtons {
    rfd::MessageButtons::OkCancelCustom(keep.to_owned(), act.to_owned())
}

/// Whether `result` is a click on `act`: Escape, closing the dialog and
/// the other button are not.
fn chose(result: &rfd::MessageDialogResult, act: &str) -> bool {
    matches!(result, rfd::MessageDialogResult::Custom(label) if label == act)
}

/// Shows one [`ask_default_no`] dialog and waits for it to close: whether
/// the user chose `act`, and how long the dialog had been open by then.
fn show_default_no(
    app: &AppHandle,
    title: &str,
    body: &str,
    act: &str,
    keep: &str,
) -> (bool, Duration) {
    let dialog = rfd::AsyncMessageDialog::new()
        .set_level(rfd::MessageLevel::Warning)
        .set_title(title)
        .set_description(body)
        .set_buttons(default_no_buttons(act, keep));
    let window = app.get_webview_window("main");
    let (send_answer, answer) = mpsc::channel();
    // As the dialog plugin does: made on the main thread, awaited elsewhere.
    let shown = app.run_on_main_thread(move || {
        let dialog = match &window {
            Some(window) => dialog.set_parent(window),
            None => dialog,
        };
        let opened = Instant::now();
        let result = dialog.show();
        std::thread::spawn(move || {
            let result = tauri::async_runtime::block_on(result);
            let _ = send_answer.send((result, opened, Instant::now()));
        });
    });
    if shown.is_err() {
        return (false, Duration::ZERO);
    }
    let Ok((result, opened, answered)) = answer.recv() else {
        return (false, Duration::ZERO);
    };
    (
        chose(&result, act),
        answered.saturating_duration_since(opened),
    )
}

/// `text` as a dialog shows it: control characters and invisible or
/// direction-changing ones as `<U+…>`, so what is shown is what is there,
/// and at most `max` characters, with how many more there are.
pub fn shown(text: &str, max: usize) -> String {
    let mut out = String::with_capacity(text.len().min(max * 4));
    for (i, c) in text.chars().enumerate() {
        if i == max {
            let rest = text.chars().count() - max;
            let _ = write!(out, "… (+{rest})");
            break;
        }
        let invisible = matches!(
            c,
            '\u{00AD}'
                | '\u{061C}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2069}'
                | '\u{FEFF}'
        );
        if c.is_control() || invisible {
            let _ = write!(out, "<U+{:04X}>", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_click_on_the_action_is_a_yes() {
        // The safe answer comes first, so it is the default (Return).
        assert!(matches!(
            default_no_buttons("Fill in", "Don't fill in"),
            rfd::MessageButtons::OkCancelCustom(first, second)
                if first == "Don't fill in" && second == "Fill in"
        ));
        assert!(chose(
            &rfd::MessageDialogResult::Custom("Fill in".into()),
            "Fill in"
        ));
        for other in [
            rfd::MessageDialogResult::Custom("Don't fill in".into()),
            // Escape, or the dialog closed.
            rfd::MessageDialogResult::Cancel,
            rfd::MessageDialogResult::Ok,
            rfd::MessageDialogResult::Yes,
            rfd::MessageDialogResult::No,
        ] {
            assert!(!chose(&other, "Fill in"), "{other:?}");
        }
    }

    #[test]
    fn shows_text_as_it_is() {
        assert_eq!(shown("nc %h %p", 300), "nc %h %p");
        // A right-to-left override would show `curl x | sh` reversed.
        assert_eq!(
            shown("echo \u{202E}hs | x lruc", 300),
            "echo <U+202E>hs | x lruc"
        );
        assert_eq!(shown("a\nb\x1b[2J", 300), "a<U+000A>b<U+001B>[2J");
        assert_eq!(shown("abcdef", 3), "abc… (+3)");
    }

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
