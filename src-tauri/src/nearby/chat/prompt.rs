//! The system dialogs chats ask in before a secret leaves the vault for
//! another computer, or before something received goes into the vault. They
//! are built here, never by the page: a script in the page can't answer
//! them ([`crate::confirm::require`]). Every name in them that came from
//! elsewhere (a computer's name, a label, an entry's title, a variable's
//! name) goes through [`shown`].

use std::fmt::Write as _;

use sshkm_core::p2p::protocol::ItemSummary;

use crate::confirm::Localized;

/// Longest name a dialog shows whole.
const SHOWN_CHARS: usize = 80;
/// Most variable names a dialog lists.
const SHOWN_NAMES: usize = 12;

/// A dialog's title, text and approving button.
pub struct Prompt {
    pub title: Localized,
    pub body: Localized,
    pub approve: Localized,
}

/// `text` from elsewhere as a dialog shows it: control characters and
/// invisible or direction-changing ones as `<U+…>`, so it can neither add
/// lines of its own nor read differently from what it is, and at most
/// [`SHOWN_CHARS`] characters. (`confirm::shown` once #65 is in.)
pub fn shown(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (i, c) in text.chars().enumerate() {
        if i == SHOWN_CHARS {
            let rest = text.chars().count() - SHOWN_CHARS;
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

/// Variable names as a dialog lists them: the first few, and how many more.
fn names(list: &[String]) -> String {
    let mut out = list
        .iter()
        .take(SHOWN_NAMES)
        .map(|name| shown(name))
        .collect::<Vec<_>>()
        .join(", ");
    if list.len() > SHOWN_NAMES {
        let _ = write!(out, " … (+{})", list.len() - SHOWN_NAMES);
    }
    out
}

/// Sending the values of variables `vars` of environment `label` to `peer`
/// (the name this vault keeps for it).
pub fn send_variables(peer: &str, label: &str, vars: &[String]) -> Prompt {
    let (peer, label, list, count) = (shown(peer), shown(label), names(vars), vars.len());
    Prompt {
        title: Localized::new(
            "Send these values?",
            "Отправить эти значения?",
            "Bu qiymatlar yuborilsinmi?",
        ),
        body: Localized::new(
            format!(
                "Send the values of {count} variables of “{label}” to “{peer}”: {list}. They \
                 are hidden there and wiped when their term ends, but whoever uses “{peer}” can \
                 copy them before then."
            ),
            format!(
                "Отправить на «{peer}» значения переменных «{label}» ({count}): {list}? Там они \
                 скрыты и стираются, когда истечёт срок, но на «{peer}» их могут скопировать \
                 раньше."
            ),
            format!(
                "«{label}»dagi {count} ta oʻzgaruvchi qiymatlari «{peer}» ga yuborilsinmi: \
                 {list}? U yerda ular yashirin turadi va muddati tugagach oʻchiriladi, lekin \
                 «{peer}» da ulardan oldinroq nusxa olish mumkin."
            ),
        ),
        approve: Localized::new("Send values", "Отправить значения", "Qiymatlarni yuborish"),
    }
}

/// Offering `item` to `peer`, if it holds a secret from the vault (a
/// login's password, an environment's values); `None` for what holds none.
pub fn send_item(peer: &str, item: &ItemSummary) -> Option<Prompt> {
    let peer = shown(peer);
    match item {
        ItemSummary::Password {
            title,
            username,
            otp,
            ..
        } => {
            let (title, user) = (shown(title), shown(username));
            let (otp_en, otp_ru, otp_uz) = if *otp {
                (
                    " and its 2FA secret",
                    " и его секрет 2FA",
                    " va uning 2FA siri",
                )
            } else {
                ("", "", "")
            };
            Some(Prompt {
                title: Localized::new(
                    "Send this password?",
                    "Отправить этот пароль?",
                    "Bu parol yuborilsinmi?",
                ),
                body: Localized::new(
                    format!(
                        "Offer “{peer}” the login “{title}” ({user}). If they accept, its \
                         password{otp_en} goes to “{peer}” and stays there."
                    ),
                    format!(
                        "Предложить «{peer}» логин «{title}» ({user})? Если там примут, \
                         пароль{otp_ru} уйдёт на «{peer}» и останется там."
                    ),
                    format!(
                        "«{peer}» ga «{title}» ({user}) login taklif qilinsinmi? Qabul qilinsa, \
                         parol{otp_uz} «{peer}» ga boradi va oʻsha yerda qoladi."
                    ),
                ),
                approve: Localized::new("Offer", "Предложить", "Taklif qilish"),
            })
        }
        ItemSummary::Environment {
            project,
            name,
            variables,
            ..
        } => {
            let label = shown(&[project.as_str(), name.as_str()].join(" / "));
            let label = label.trim_start_matches(" / ").to_owned();
            Some(Prompt {
                title: Localized::new(
                    "Send this environment?",
                    "Отправить это окружение?",
                    "Bu muhit yuborilsinmi?",
                ),
                body: Localized::new(
                    format!(
                        "Offer “{peer}” the environment “{label}”. If they accept, the values \
                         of its {variables} variables go to “{peer}” and stay there."
                    ),
                    format!(
                        "Предложить «{peer}» окружение «{label}»? Если там примут, значения его \
                         переменных ({variables}) уйдут на «{peer}» и останутся там."
                    ),
                    format!(
                        "«{peer}» ga «{label}» muhiti taklif qilinsinmi? Qabul qilinsa, uning \
                         {variables} ta oʻzgaruvchisi qiymatlari «{peer}» ga boradi va oʻsha \
                         yerda qoladi."
                    ),
                ),
                approve: Localized::new("Offer", "Предложить", "Taklif qilish"),
            })
        }
        _ => None,
    }
}

/// Accepting `item` from `peer` when it goes into the vault (a login, an
/// environment); `None` for what goes elsewhere.
pub fn accept_item(peer: &str, item: &ItemSummary) -> Option<Prompt> {
    let peer = shown(peer);
    let approve = Localized::new("Save", "Сохранить", "Saqlash");
    match item {
        ItemSummary::Password {
            title, username, ..
        } => {
            let (title, user) = (shown(title), shown(username));
            Some(Prompt {
                title: Localized::new(
                    "Save this login?",
                    "Сохранить этот логин?",
                    "Bu login saqlansinmi?",
                ),
                body: Localized::new(
                    format!("Save the login “{title}” ({user}) from “{peer}” in Passwords?"),
                    format!("Сохранить логин «{title}» ({user}) от «{peer}» в «Паролях»?"),
                    format!(
                        "«{peer}» dan «{title}» ({user}) loginini «Parollar»da saqlash kerakmi?"
                    ),
                ),
                approve,
            })
        }
        ItemSummary::Environment {
            project,
            name,
            variables,
            ..
        } => {
            let label = shown(&[project.as_str(), name.as_str()].join(" / "));
            let label = label.trim_start_matches(" / ").to_owned();
            Some(Prompt {
                title: Localized::new(
                    "Save this environment?",
                    "Сохранить это окружение?",
                    "Bu muhit saqlansinmi?",
                ),
                body: Localized::new(
                    format!(
                        "Save the environment “{label}” with {variables} variables from \
                         “{peer}”, as a new environment?"
                    ),
                    format!(
                        "Сохранить окружение «{label}» с переменными ({variables}) от «{peer}» \
                         как новое окружение?"
                    ),
                    format!(
                        "«{peer}» dan {variables} ta oʻzgaruvchili «{label}» muhiti yangi muhit \
                         sifatida saqlansinmi?"
                    ),
                ),
                approve,
            })
        }
        _ => None,
    }
}

/// Adding variables `vars` from `peer` to environment `env`: `replaced` of
/// them change a value there, `risky` change how programs start.
pub fn add_variables(
    peer: &str,
    env: &str,
    vars: &[String],
    replaced: &[String],
    risky: &[String],
) -> Prompt {
    let (peer, env, list, count) = (shown(peer), shown(env), names(vars), vars.len());
    let replace = |en: &str, ru: &str, uz: &str| {
        if replaced.is_empty() {
            (String::new(), String::new(), String::new())
        } else {
            let list = names(replaced);
            (
                format!(" {en}: {list}."),
                format!(" {ru}: {list}."),
                format!(" {uz}: {list}."),
            )
        }
    };
    let (replace_en, replace_ru, replace_uz) = replace(
        "These replace your values",
        "Эти заменят ваши значения",
        "Bular qiymatlaringizni almashtiradi",
    );
    let (risky_en, risky_ru, risky_uz) = if risky.is_empty() {
        (String::new(), String::new(), String::new())
    } else {
        let list = names(risky);
        (
            format!(" These change how programs start: {list}."),
            format!(" Эти меняют запуск программ: {list}."),
            format!(" Bular dasturlar ishga tushishini oʻzgartiradi: {list}."),
        )
    };
    Prompt {
        title: Localized::new(
            "Add these variables?",
            "Добавить эти переменные?",
            "Bu oʻzgaruvchilar qoʻshilsinmi?",
        ),
        body: Localized::new(
            format!(
                "Add {count} variables from “{peer}” to “{env}”: {list}.{replace_en}{risky_en}"
            ),
            format!(
                "Добавить в «{env}» переменные от «{peer}» ({count}): {list}.{replace_ru}{risky_ru}"
            ),
            format!(
                "«{peer}» dan {count} ta oʻzgaruvchi «{env}» ga qoʻshilsinmi: \
                 {list}.{replace_uz}{risky_uz}"
            ),
        ),
        approve: Localized::new(
            "Add variables",
            "Добавить переменные",
            "Oʻzgaruvchilarni qoʻshish",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(prompt: &Prompt) -> String {
        [&prompt.title, &prompt.body, &prompt.approve]
            .iter()
            .map(|text| text.pick().to_owned())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn names_from_elsewhere_show_their_hidden_characters() {
        assert_eq!(shown("ThinkPad\u{202E}dab"), "ThinkPad<U+202E>dab");
        assert_eq!(shown("a\nCancel"), "a<U+000A>Cancel");
        assert_eq!(
            shown(&"x".repeat(90)).chars().count(),
            80 + "… (+10)".chars().count()
        );
        let prompt = send_variables("Bob\u{200B}", "shop · prod", &["API_KEY".into()]);
        assert!(all(&prompt).contains("Bob<U+200B>"));
    }

    #[test]
    fn secrets_leaving_are_named_with_where_they_go() {
        let prompt = send_variables(
            "ThinkPad Bob",
            "shop · prod",
            &["API_KEY".into(), "DATABASE_URL".into()],
        );
        let text = all(&prompt);
        assert!(text.contains("ThinkPad Bob") && text.contains("API_KEY, DATABASE_URL"));
        let login = ItemSummary::Password {
            title: "prod DB".into(),
            username: "deploy".into(),
            url: String::new(),
            otp: true,
        };
        let text = all(&send_item("Bob", &login).unwrap());
        assert!(text.contains("prod DB") && text.contains("2FA"));
        let personal = ItemSummary::Environment {
            project: String::new(),
            name: "dev".into(),
            variables: 3,
            secrets: 1,
            names: vec![],
        };
        assert!(all(&send_item("Bob", &personal).unwrap()).contains("“dev”"));
        let host = ItemSummary::Host {
            alias: "prod".into(),
            address: "10.0.0.1".into(),
            proxy_jump: None,
            host_keys: 1,
        };
        assert!(send_item("Bob", &host).is_none(), "a host holds no secret");
        assert!(accept_item("Bob", &host).is_none(), "a host goes to ~/.ssh");
        assert!(all(&accept_item("Bob", &login).unwrap()).contains("Passwords"));
    }

    #[test]
    fn adding_lists_replaced_and_risky_names() {
        let many: Vec<String> = (0..15).map(|i| format!("V{i}")).collect();
        let text = all(&add_variables(
            "Bob",
            "shop · prod",
            &many,
            &["V1".into()],
            &["PATH".into()],
        ));
        assert!(text.contains("V0, V1") && text.contains("(+3)"));
        assert!(text.contains("replace your values: V1"));
        assert!(text.contains("change how programs start: PATH"));
        let plain = all(&add_variables("Bob", "dev", &["A".into()], &[], &[]));
        assert!(!plain.contains("replace") && !plain.contains("programs start"));
    }
}
