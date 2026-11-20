//! The texts of the system dialogs a sync with one of the user's devices
//! asks in before it makes a risky change ([`User::allow_risky`],
//! [`User::allow_risky_variables`]): built here, never by the page, with
//! every name and value that came from the other device passed through
//! [`shown`].
//!
//! [`User::allow_risky`]: sshkm_core::p2p::conversation::User::allow_risky
//! [`User::allow_risky_variables`]: sshkm_core::p2p::conversation::User::allow_risky_variables

use sshkm_core::p2p::conversation::{RiskyChange, RiskyVariables};

use crate::confirm::{Localized, invisible, shown};

/// Most directives the system dialog lists.
const SHOWN_LINES: usize = 8;
/// Longest name the system dialog shows in full.
const SHOWN_CHARS: usize = 120;
/// Longest value of a directive or variable the system dialog shows in
/// full: past it, its start and its end.
const SHOWN_VALUE: usize = 1000;

/// The system dialog that asks to allow `changes` from a sync with `peer`
/// in the config file `file`: its title, text and button.
pub fn risky_prompt(
    peer: &str,
    file: &str,
    changes: &[RiskyChange],
) -> (Localized, Localized, Localized) {
    let en = risky_list(changes, |n| format!("…and {n} more"));
    let ru = risky_list(changes, |n| format!("…и ещё {n}"));
    let uz = risky_list(changes, |n| format!("…va yana {n} ta"));
    let peer = shown(peer, SHOWN_CHARS);
    (
        Localized::new(
            "Allow ssh to run this?",
            "Разрешить ssh запускать это?",
            "ssh buni ishga tushirsinmi?",
        ),
        Localized::new(
            format!(
                "The sync with {peer} adds to {file} what makes ssh run programs, load code \
                 or let the server use this computer each time you connect:\n\n{en}\n\n\
                 Allow it only if you made these changes on {peer} yourself. Otherwise \
                 they wait for the next sync."
            ),
            format!(
                "Синхронизация с {peer} добавляет в {file} то, из-за чего ssh при каждом \
                 подключении запускает программы, загружает код или даёт серверу доступ к \
                 этому компьютеру:\n\n{ru}\n\n\
                 Разрешайте, только если эти изменения на {peer} сделали вы сами. Иначе \
                 они подождут следующей синхронизации."
            ),
            format!(
                "{peer} bilan sinxronlash {file} ga ssh har safar ulanganda dasturlarni \
                 ishga tushiradigan, kod yuklaydigan yoki serverga bu kompyuterdan \
                 foydalanishga ruxsat beradigan narsalarni qoʻshadi:\n\n{uz}\n\n\
                 Faqat bu oʻzgarishlarni {peer} da oʻzingiz qilgan boʻlsangiz, ruxsat \
                 bering. Aks holda ular keyingi sinxronlashni kutadi."
            ),
        ),
        Localized::new(
            "Allow and sync",
            "Разрешить и синхронизировать",
            "Ruxsat berish va sinxronlash",
        ),
    )
}

/// One line per directive (`• Host prod: ProxyCommand …`), at most
/// [`SHOWN_LINES`] of them; `more` says how many were left out.
fn risky_list(changes: &[RiskyChange], more: impl Fn(usize) -> String) -> String {
    let all: Vec<String> = changes
        .iter()
        .flat_map(|change| {
            change.lines.iter().map(move |line| {
                format!(
                    "• Host {}: {} {}",
                    shown(&change.id, SHOWN_CHARS),
                    shown(&line.key, SHOWN_CHARS),
                    shown_value(&line.value)
                )
            })
        })
        .collect();
    let mut lines: Vec<String> = all.iter().take(SHOWN_LINES).cloned().collect();
    if all.len() > SHOWN_LINES {
        lines.push(more(all.len() - SHOWN_LINES));
    }
    lines.join("\n")
}

/// The system dialog that asks to allow `changes` to environments from a
/// sync with `peer`: its title, text and button. One line per variable,
/// with the value `value` gives for it (`NODE_OPTIONS=--require …`), so
/// what is allowed is what programs will load.
pub fn variables_prompt(
    peer: &str,
    changes: &[RiskyVariables],
    value: &dyn Fn(&RiskyVariables, &str) -> Option<String>,
) -> (Localized, Localized, Localized) {
    let list = |more: &dyn Fn(usize) -> String| {
        let all: Vec<String> = changes
            .iter()
            .flat_map(|change| {
                change.names.iter().map(move |name| {
                    let shown_value = value(change, name)
                        .map(|value| format!("={}", shown_value(&value)))
                        .unwrap_or_default();
                    format!(
                        "• {}: {}{shown_value}",
                        shown(&change.environment, SHOWN_CHARS),
                        shown(name, SHOWN_CHARS)
                    )
                })
            })
            .collect();
        let mut lines: Vec<String> = all.iter().take(SHOWN_LINES).cloned().collect();
        if all.len() > SHOWN_LINES {
            lines.push(more(all.len() - SHOWN_LINES));
        }
        lines.join("\n")
    };
    let en = list(&|n| format!("…and {n} more"));
    let ru = list(&|n| format!("…и ещё {n}"));
    let uz = list(&|n| format!("…va yana {n} ta"));
    let peer = shown(peer, SHOWN_CHARS);
    (
        Localized::new(
            "Allow variables that run code?",
            "Разрешить переменные, которые запускают код?",
            "Kod ishga tushiradigan oʻzgaruvchilarga ruxsat berilsinmi?",
        ),
        Localized::new(
            format!(
                "The sync with {peer} adds or changes variables that make programs load \
                 code or run commands when you use the environment in a terminal or a \
                 .env file:\n\n{en}\n\nAllow it only if you made these changes on {peer} \
                 yourself. Otherwise they wait for the next sync."
            ),
            format!(
                "Синхронизация с {peer} добавляет или меняет переменные, из-за которых \
                 программы загружают код или запускают команды, когда вы используете \
                 окружение в терминале или в файле .env:\n\n{ru}\n\nРазрешайте, только \
                 если эти изменения на {peer} сделали вы сами. Иначе они подождут следующей \
                 синхронизации."
            ),
            format!(
                "{peer} bilan sinxronlash muhitni terminalda yoki .env faylida \
                 ishlatganingizda dasturlarga kod yuklatadigan yoki buyruq ishga \
                 tushiradigan oʻzgaruvchilarni qoʻshadi yoki oʻzgartiradi:\n\n{uz}\n\n\
                 Faqat bu oʻzgarishlarni {peer} da oʻzingiz qilgan boʻlsangiz, ruxsat \
                 bering. Aks holda ular keyingi sinxronlashni kutadi."
            ),
        ),
        Localized::new(
            "Allow and sync",
            "Разрешить и синхронизировать",
            "Ruxsat berish va sinxronlash",
        ),
    )
}

/// A value as the dialog shows it ([`shown`]): a run of spaces as one, so
/// padding can't push what follows out of sight, and in full up to
/// [`SHOWN_VALUE`] characters; past that, its start and its end.
fn shown_value(text: &str) -> String {
    let mut collapsed = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_whitespace() && !c.is_control() && !invisible(c) {
            if !collapsed.ends_with(' ') {
                collapsed.push(' ');
            }
        } else {
            collapsed.push(c);
        }
    }
    let chars: Vec<char> = collapsed.chars().collect();
    if chars.len() <= SHOWN_VALUE {
        return shown(&collapsed, SHOWN_VALUE);
    }
    let half = SHOWN_VALUE / 2;
    let head: String = chars[..half].iter().collect();
    let tail: String = chars[chars.len() - half..].iter().collect();
    format!(
        "{} … (+{}) … {}",
        shown(&head, half),
        chars.len() - SHOWN_VALUE,
        shown(&tail, half)
    )
}

#[cfg(test)]
mod tests {
    use sshkm_core::sync::hosts::RiskyLine;

    use super::*;

    #[test]
    fn the_system_dialog_lists_hosts_and_directives_as_ssh_reads_them() {
        let change = |id: &str, n: usize| RiskyChange {
            id: id.into(),
            lines: (0..n)
                .map(|i| RiskyLine {
                    key: "LocalCommand".into(),
                    value: format!("echo {i}\u{202E}"),
                })
                .collect(),
        };
        let (title, body, approve) =
            risky_prompt("Bob\u{200B}", "~/.ssh/config", &[change("prod", 2)]);
        assert_eq!(title.en, "Allow ssh to run this?");
        assert_eq!(approve.ru, "Разрешить и синхронизировать");
        assert!(
            body.en
                .contains("The sync with Bob<U+200B> adds to ~/.ssh/config")
        );
        assert!(
            body.en
                .contains("• Host prod: LocalCommand echo 0<U+202E>\n")
        );
        assert!(body.uz.contains("• Host prod: LocalCommand echo 1<U+202E>"));

        let (_, body, _) = risky_prompt("Bob", "config", &[change("a", 5), change("b", 6)]);
        assert_eq!(body.en.matches("• Host").count(), SHOWN_LINES);
        assert!(body.en.contains("…and 3 more"));
        assert!(body.ru.contains("…и ещё 3"));
        // Padding can't hide what follows, nor a line break of its own.
        let padded = format!(
            "--max-old-space-size=4096{}--require /tmp/x.js",
            " ".repeat(100)
        );
        assert_eq!(
            shown_value(&padded),
            "--max-old-space-size=4096 --require /tmp/x.js"
        );
        assert_eq!(shown_value("a\u{2028}b\u{2029}c"), "a<U+2028>b<U+2029>c");
        let long = format!("{}{}", "x".repeat(SHOWN_VALUE), "--require /tmp/x.js");
        let value = shown_value(&long);
        assert!(value.ends_with("--require /tmp/x.js"), "{value}");
        assert!(value.contains(" … (+19) … "));
    }

    #[test]
    fn the_variables_dialog_names_the_environment_and_shows_the_values() {
        let value = |_: &RiskyVariables, name: &str| {
            (name == "NODE_OPTIONS").then(|| "--require /tmp/x.js\u{202E}".to_owned())
        };
        let (_, body, _) = variables_prompt(
            "MacBook",
            &[RiskyVariables {
                id: "x".into(),
                environment: "Shop · dev".into(),
                names: vec!["NODE_OPTIONS".into(), "PATH".into()],
            }],
            &value,
        );
        assert!(
            body.en.contains(
                "• Shop · dev: NODE_OPTIONS=--require /tmp/x.js<U+202E>\n• Shop · dev: PATH\n"
            ),
            "{}",
            body.en
        );
        assert!(body.ru.contains("MacBook"));
    }
}
