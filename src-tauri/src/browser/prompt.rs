//! What the user sees about browsers outside the page: the question before a
//! login is filled, and the warning when a copy of a browser's keys turns up.
//!
//! The question is Touch ID or Windows Hello where the computer has it, and
//! a native dialog otherwise. The system draws both, outside the browser and
//! the app's page, so neither a web page nor a program that copied the
//! browser's keys can answer them. (A program running as the user can click
//! a plain dialog on Windows and under X11; macOS asks the user before it
//! lets one, and Wayland doesn't let one.) Every text is built here, from
//! the vault and the pairing; the page only picked the login.

use sshkm_core::vault::PairedBrowser;
use sshkm_os::biometrics;
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

use super::broker::FillPrompt;
use crate::confirm::{self, Localized};

/// Asks whether to fill the login in `prompt`; blocks until the user
/// answers, so call it off the main thread.
pub fn confirm_fill(app: &AppHandle, prompt: &FillPrompt) -> bool {
    if biometrics::availability().is_available() {
        match biometrics::authenticate(fill_reason(prompt).pick()) {
            Ok(()) => return true,
            // Gone since the check (a lid closed, a keyboard unplugged): ask
            // in a dialog instead.
            Err(sshkm_os::Error::Unavailable(why)) => {
                log::info!(
                    "browser: Touch ID or Windows Hello unavailable ({why}); asking in a dialog"
                );
            }
            Err(_) => return false,
        }
    }
    super::show_window(app);
    let browser = &prompt.browser;
    let login = login(prompt);
    let site = &prompt.site;
    confirm::require(
        app,
        &Localized::new(
            format!("Fill a login in {browser}?"),
            format!("Заполнить логин в {browser}?"),
            format!("{browser} brauzerida login toʻldirilsinmi?"),
        ),
        &Localized::new(
            format!(
                "{browser} wants to fill {} on {site}.\n\nAllow it only if you just chose this login there. Until you lock the vault or the screen, it then fills there without asking.",
                login.en
            ),
            format!(
                "{browser} хочет заполнить {} на {site}.\n\nРазрешайте, только если вы только что выбрали этот логин там. Пока вы не заблокируете хранилище или экран, он будет заполняться там без вопроса.",
                login.ru
            ),
            format!(
                "{browser} {site} saytida {} loginini toʻldirmoqchi.\n\nFaqat shu loginni hozirgina oʻsha yerda tanlagan boʻlsangiz, ruxsat bering. Ombor yoki ekranni qulflamaguningizcha, u yerda soʻramasdan toʻldiriladi.",
                login.uz
            ),
        ),
        &Localized::new("Fill", "Заполнить", "Toʻldirish"),
    )
    .is_ok()
}

/// The Touch ID or Windows Hello reason. macOS shows it after "*App* is
/// trying to".
fn fill_reason(prompt: &FillPrompt) -> Localized {
    let browser = &prompt.browser;
    let login = login(prompt);
    let site = &prompt.site;
    Localized::new(
        format!("fill {} on {site} in {browser}", login.en),
        format!("заполнить {} на {site} в {browser}", login.ru),
        format!(
            "{browser} brauzerida {site} saytiga {} loginini toʻldirish",
            login.uz
        ),
    )
}

/// “Title” (username), quoted as each language quotes.
fn login(prompt: &FillPrompt) -> Localized {
    let title = &prompt.title;
    let user = if prompt.username.is_empty() {
        String::new()
    } else {
        format!(" ({})", prompt.username)
    };
    Localized::new(
        format!("“{title}”{user}"),
        format!("«{title}»{user}"),
        format!("«{title}»{user}"),
    )
}

/// Tells the user that a copy of `browser`'s keys was used and the browser
/// is disconnected. Doesn't wait for them to close the message.
pub fn copied(app: &AppHandle, browser: &PairedBrowser) {
    super::show_window(app);
    let name = &browser.browser;
    let computer = &browser.computer;
    let title = Localized::new("Browser disconnected", "Браузер отключён", "Brauzer uzildi");
    let body = Localized::new(
        format!(
            "Someone used a copy of the keys of {name} on {computer}, so the app disconnected it.\n\nIf you restored or copied that browser's profile, just connect it again. Otherwise another program may have read the browser's data: check this computer for malware before you connect it again."
        ),
        format!(
            "Кто-то воспользовался копией ключей {name} на {computer}, поэтому приложение отключило этот браузер.\n\nЕсли вы восстанавливали или копировали профиль браузера, просто подключите его снова. Если нет, другая программа могла прочитать данные браузера: проверьте компьютер на вредоносные программы, прежде чем подключать браузер снова."
        ),
        format!(
            "Kimdir {computer} kompyuteridagi {name} kalitlari nusxasidan foydalandi, shuning uchun ilova uni uzdi.\n\nAgar brauzer profilini tiklagan yoki nusxalagan boʻlsangiz, uni qayta ulang. Aks holda boshqa dastur brauzer ma’lumotlarini oʻqigan boʻlishi mumkin: qayta ulashdan oldin kompyuterni zararli dasturlarga tekshiring."
        ),
    );
    let mut dialog = app
        .dialog()
        .message(body.pick())
        .title(title.pick())
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::Ok);
    if let Some(window) = app.get_webview_window("main") {
        dialog = dialog.parent(&window);
    }
    dialog.show(|_| {});
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prompt(username: &str) -> FillPrompt {
        FillPrompt {
            browser: "Chrome".into(),
            title: "GitHub".into(),
            username: username.into(),
            site: "github.com".into(),
        }
    }

    #[test]
    fn reasons_name_the_login_the_site_and_the_browser() {
        let reason = fill_reason(&prompt("octo"));
        assert_eq!(reason.en, "fill “GitHub” (octo) on github.com in Chrome");
        assert_eq!(
            reason.ru,
            "заполнить «GitHub» (octo) на github.com в Chrome"
        );
        assert_eq!(
            fill_reason(&prompt("")).en,
            "fill “GitHub” on github.com in Chrome"
        );
    }
}
