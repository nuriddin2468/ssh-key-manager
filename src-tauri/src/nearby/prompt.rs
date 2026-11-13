//! The texts of the system dialogs Nearby asks in besides those of chats
//! ([`super::chat::prompt`], whose dialog for sending a secret a pairing's
//! send asks too, naming the variables that run code): adding a device (on
//! either computer), and saving a host that settings here would give access
//! to this computer. They are built here, never by the page, and every name
//! in them that came from somewhere else (a device name, an alias, an
//! address) is passed through [`shown`].

use std::fmt::Write as _;

use sshkm_core::p2p::protocol::Item;

use super::chat::prompt::{Prompt, shown};
use crate::confirm::Localized;

/// Most settings a dialog lists.
const SHOWN_LINES: usize = 8;
/// Most variable names a dialog lists.
const SHOWN_NAMES: usize = 12;

/// The dialog before `item` leaves for `peer` (the one chats ask in), if it
/// holds a secret, naming the variables among it that make programs run
/// code.
pub fn send_item(peer: &str, item: &Item) -> Option<Prompt> {
    super::chat::prompt::send_item(peer, &item.summary())
        .map(|prompt| naming_code_running(prompt, &item.code_running()))
}

/// `prompt`, which sends variables, saying which of them (`names`) make
/// programs run code wherever they are set.
pub fn naming_code_running(mut prompt: Prompt, names: &[String]) -> Prompt {
    if names.is_empty() {
        return prompt;
    }
    let first: Vec<String> = names.iter().take(SHOWN_NAMES).map(|n| shown(n)).collect();
    let more = names.len().saturating_sub(SHOWN_NAMES);
    let joined = |more_text: String| {
        let mut list = first.clone();
        if more > 0 {
            list.push(more_text);
        }
        list.join(", ")
    };
    let en = joined(format!("and {more} more"));
    let ru = joined(format!("и ещё {more}"));
    let uz = joined(format!("va yana {more} ta"));
    let _ = write!(
        prompt.body.en,
        "\n\nThese make programs run code wherever they are set: {en}. The other computer \
         leaves them out unless its user picks them."
    );
    let _ = write!(
        prompt.body.ru,
        "\n\nЭти переменные заставляют программы выполнять код везде, где они заданы: {ru}. \
         Другой компьютер не добавит их, если там их не выберут."
    );
    let _ = write!(
        prompt.body.uz,
        "\n\nBu oʻzgaruvchilar qayerda berilsa, dasturlarni kod bajarishga majbur qiladi: \
         {uz}. Boshqa kompyuter ularni u yerda tanlanmasa qoʻshmaydi."
    );
    prompt
}

/// A pairing code as both screens show it: `123 456`.
pub fn code(code: &str) -> String {
    match (code.get(..3), code.get(3..)) {
        (Some(head), Some(tail)) if !tail.is_empty() => format!("{head} {tail}"),
        _ => code.to_owned(),
    }
}

/// The other computer, for a dialog about adding a device: by the name
/// this vault keeps for it, if it knows it, and always by the code both
/// screens show. A name a computer gives itself is never shown, since any
/// computer may give any name.
fn computer(known: Option<&str>, code: &str) -> (String, String, String) {
    let code = self::code(code);
    match known {
        Some(name) => {
            let name = shown(name);
            (
                format!("“{name}”, showing the code {code}"),
                format!("«{name}» с кодом {code} на экране"),
                format!("{code} kodini koʻrsatayotgan “{name}”"),
            )
        }
        None => (
            format!("the computer showing the code {code}"),
            format!("компьютер с кодом {code} на экране"),
            format!("{code} kodini koʻrsatayotgan kompyuter"),
        ),
    }
}

/// What Touch ID / Windows Hello names when the user confirms adding a
/// device: the code, and with `vault`, that the vault goes to it.
pub fn add_reason(known: Option<&str>, code: &str, vault: bool) -> Localized {
    let (en, ru, uz) = computer(known, code);
    if vault {
        Localized::new(
            format!("give your vault to {en}"),
            format!("передать ваше хранилище на {ru}"),
            format!("omboringizni {uz} ga berish"),
        )
    } else {
        Localized::new(
            format!("add {en} to your devices"),
            format!("добавить {ru} в ваши устройства"),
            format!("{uz} ni qurilmalaringizga qoʻshish"),
        )
    }
}

/// Adding a device, after the master password was checked: the dialog the
/// page can't answer.
pub fn add(known: Option<&str>, code: &str, vault: bool) -> Prompt {
    let (en, ru, uz) = computer(known, code);
    let check = Localized::new(
        "Check that your other computer shows the same code.",
        "Проверьте, что ваш другой компьютер показывает тот же код.",
        "Boshqa kompyuteringiz xuddi shu kodni koʻrsatayotganini tekshiring.",
    );
    if vault {
        Prompt {
            title: Localized::new(
                "Give your vault to this computer?",
                "Передать хранилище на этот компьютер?",
                "Ombor bu kompyuterga berilsinmi?",
            ),
            body: Localized::new(
                format!(
                    "Give your vault to {en}? It gets every password, key and environment, and \
                     becomes one of your devices.\n\n{}",
                    check.en
                ),
                format!(
                    "Передать ваше хранилище на {ru}? Он получит все пароли, ключи и окружения \
                     и станет одним из ваших устройств.\n\n{}",
                    check.ru
                ),
                format!(
                    "Omboringiz {uz} ga berilsinmi? U barcha parollar, kalitlar va muhitlarni \
                     oladi hamda qurilmalaringizdan biriga aylanadi.\n\n{}",
                    check.uz
                ),
            ),
            approve: Localized::new("Give vault", "Передать хранилище", "Omborni berish"),
        }
    } else {
        Prompt {
            title: Localized::new(
                "Add this device?",
                "Добавить это устройство?",
                "Bu qurilma qoʻshilsinmi?",
            ),
            body: Localized::new(
                format!(
                    "Add {en} to your devices? It will then sync hosts, server keys and devices \
                     with this computer.\n\n{}",
                    check.en
                ),
                format!(
                    "Добавить {ru} в ваши устройства? После этого он будет синхронизировать с \
                     этим компьютером хосты, ключи серверов и устройства.\n\n{}",
                    check.ru
                ),
                format!(
                    "{uz} qurilmalaringizga qoʻshilsinmi? Shundan keyin u bu kompyuter bilan \
                     xostlar, server kalitlari va qurilmalarni sinxronlaydi.\n\n{}",
                    check.uz
                ),
            ),
            approve: Localized::new("Add device", "Добавить устройство", "Qurilmani qoʻshish"),
        }
    }
}

/// On the computer being added, which has the vault already: becoming one
/// of the user's devices together with the computer that adds it.
pub fn added(known: Option<&str>, code: &str) -> Prompt {
    let (en, ru, uz) = computer(known, code);
    Prompt {
        title: Localized::new(
            "Add this computer to your devices?",
            "Добавить этот компьютер в ваши устройства?",
            "Bu kompyuter qurilmalaringizga qoʻshilsinmi?",
        ),
        body: Localized::new(
            format!(
                "{en} is adding this computer to your devices. The two will then sync hosts, \
                 server keys and devices.\n\nAllow this only if you started it on your other \
                 computer."
            ),
            format!(
                "{ru} добавляет этот компьютер в ваши устройства. После этого они будут \
                 синхронизировать хосты, ключи серверов и устройства.\n\nРазрешайте, только \
                 если вы сами начали это на другом компьютере."
            ),
            format!(
                "{uz} bu kompyuterni qurilmalaringizga qoʻshmoqda. Shundan keyin ikkalasi \
                 xostlar, server kalitlari va qurilmalarni sinxronlaydi.\n\nFaqat buni \
                 boshqa kompyuteringizda oʻzingiz boshlagan boʻlsangiz, ruxsat bering."
            ),
        ),
        approve: Localized::new(
            "Add this computer",
            "Добавить этот компьютер",
            "Bu kompyuterni qoʻshish",
        ),
    }
}

/// A host `peer` sent, `alias` leading to `address`, which settings in
/// `file` (`lines`, as `Host …: Keyword value`) would give access to this
/// computer.
pub fn host_access(peer: &str, alias: &str, address: &str, file: &str, lines: &[String]) -> Prompt {
    let (peer, alias, address) = (shown(peer), shown(alias), shown(address));
    let shown_lines: Vec<String> = lines
        .iter()
        .take(SHOWN_LINES)
        .map(|line| format!("• {}", shown(line)))
        .collect();
    let more = lines.len().saturating_sub(SHOWN_LINES);
    let list = |more_text: String| {
        let mut list = shown_lines.clone();
        if more > 0 {
            list.push(more_text);
        }
        list.join("\n")
    };
    let en = list(format!("…and {more} more"));
    let ru = list(format!("…и ещё {more}"));
    let uz = list(format!("…va yana {more} ta"));
    Prompt {
        title: Localized::new(
            "Give a server access to this computer?",
            "Дать серверу доступ к этому компьютеру?",
            "Serverga bu kompyuterdan foydalanishga ruxsat berilsinmi?",
        ),
        body: Localized::new(
            format!(
                "“{peer}” sent the host {alias}, which leads to {address}. These settings in \
                 {file} would let that server use this computer whenever you connect to \
                 it:\n\n{en}\n\nAllow this only if you trust {address}. If you don’t, the host \
                 isn’t saved."
            ),
            format!(
                "«{peer}» прислал хост {alias}, который ведёт на {address}. Из-за этих настроек \
                 в {file} этот сервер сможет пользоваться этим компьютером при каждом \
                 подключении к нему:\n\n{ru}\n\nРазрешайте, только если доверяете {address}. \
                 Иначе хост не сохранится."
            ),
            format!(
                "“{peer}” {address} ga olib boradigan {alias} xostini yubordi. {file} dagi bu \
                 sozlamalar tufayli u server har safar ulanganingizda bu kompyuterdan \
                 foydalana oladi:\n\n{uz}\n\nFaqat {address} ga ishonsangiz, ruxsat bering. \
                 Aks holda xost saqlanmaydi."
            ),
        ),
        approve: Localized::new(
            "Allow and save",
            "Разрешить и сохранить",
            "Ruxsat berish va saqlash",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_read_as_both_screens_show_them() {
        assert_eq!(code("123456"), "123 456");
        assert_eq!(code("12"), "12");
    }

    #[test]
    fn adding_a_device_names_the_code_and_never_a_name_it_gave_itself() {
        let reason = add_reason(None, "123456", true);
        assert_eq!(
            reason.en,
            "give your vault to the computer showing the code 123 456"
        );
        let prompt = add(Some("Work\u{202E}PC"), "123456", false);
        assert!(
            prompt
                .body
                .en
                .contains("“Work<U+202E>PC”, showing the code 123 456")
        );
        assert!(prompt.body.ru.contains("123 456"));
        assert!(prompt.body.uz.contains("123 456"));
        let prompt = added(Some("Mac\u{2028}Book"), "654321");
        assert!(
            prompt
                .body
                .en
                .contains("“Mac<U+2028>Book”, showing the code 654 321")
        );
    }

    #[test]
    fn sending_names_the_variables_that_run_code() {
        let var = |name: &str| sshkm_core::p2p::protocol::EnvVariable {
            name: name.into(),
            value: "x".into(),
            secret: false,
            note: String::new(),
        };
        let item = Item::Environment {
            project: "Shop".into(),
            name: "dev".into(),
            notes: String::new(),
            variables: vec![var("PORT"), var("NODE_OPTIONS"), var("path")],
        };
        let prompt = send_item("Carol", &item).unwrap();
        assert!(
            prompt.body.en.contains(
                "These make programs run code wherever they are set: NODE_OPTIONS, path."
            )
        );
        assert!(prompt.body.ru.contains("NODE_OPTIONS, path"));
        assert!(prompt.body.uz.contains("NODE_OPTIONS, path"));
        // None among them: the dialog as chats have it.
        let plain = Item::Environment {
            project: "Shop".into(),
            name: "dev".into(),
            notes: String::new(),
            variables: vec![var("PORT")],
        };
        assert!(
            !send_item("Carol", &plain)
                .unwrap()
                .body
                .en
                .contains("run code")
        );
        let many: Vec<String> = (0..14).map(|n| format!("GIT_CONFIG_KEY_{n}")).collect();
        let empty = super::super::chat::prompt::send_variables("Carol", "dev", &many);
        let prompt = naming_code_running(empty, &many);
        assert!(prompt.body.en.contains("GIT_CONFIG_KEY_11, and 2 more."));
    }

    #[test]
    fn a_long_list_of_settings_is_cut() {
        let lines: Vec<String> = (0..10)
            .map(|n| format!("Host *.lab{n}: ForwardAgent yes"))
            .collect();
        let prompt = host_access("Carol", "db.lab1", "10.0.0.1", "~/.ssh/config", &lines);
        assert!(prompt.body.en.contains("…and 2 more"));
        assert!(prompt.body.ru.contains("…и ещё 2"));
        assert!(!prompt.body.en.contains("lab9"));
    }
}
