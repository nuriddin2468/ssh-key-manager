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
/// invisible or direction-changing ones as `<U+…>`, at most [`SHOWN_CHARS`]
/// characters ([`crate::confirm::shown`]).
pub fn shown(text: &str) -> String {
    crate::confirm::shown(text, SHOWN_CHARS)
}

/// A received secret or variable, as the reveal and copy budget names it
/// ([`crate::secret_gate::take_secret`]): `name` is the variable's, else
/// `label` the secret's (empty for one without); `peer` the computer it came
/// from.
pub fn chat_value(peer: &str, label: &str, name: Option<&str>) -> Localized {
    let peer = shown(peer);
    if let Some(name) = name {
        let name = shown(name);
        return Localized::new(
            format!("{name} from “{peer}”"),
            format!("{name} от «{peer}»"),
            format!("«{peer}» kompyuteridan {name}"),
        );
    }
    if label.is_empty() {
        return Localized::new(
            format!("a secret from “{peer}”"),
            format!("секрет от «{peer}»"),
            format!("«{peer}» kompyuteridan maxfiy qiymat"),
        );
    }
    let label = shown(label);
    Localized::new(
        format!("the secret “{label}” from “{peer}”"),
        format!("секрет «{label}» от «{peer}»"),
        format!("«{peer}» kompyuteridan «{label}» maxfiy qiymati"),
    )
}

/// `n` and the English word for one or more: "1 variable", "3 variables".
fn en(n: usize, one: &str, other: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { other })
}

/// `n` and the Russian word that agrees with it: `one` for 1, 21…, `few`
/// for 2–4, 22…, `many` for the rest (5–20, 25…).
fn ru(n: usize, one: &str, few: &str, many: &str) -> String {
    let (last, two) = (n % 10, n % 100);
    let word = if last == 1 && two != 11 {
        one
    } else if (2..=4).contains(&last) && !(12..=14).contains(&two) {
        few
    } else {
        many
    };
    format!("{n} {word}")
}

/// An environment as the page names it: its project or part, and its name.
fn env_label(project: &str, name: &str) -> String {
    let label = [project, name]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" · ");
    shown(&label)
}

/// A login's name and, if it has one, its user: `“prod DB” (deploy)`.
fn login(title: &str, user: &str, open: char, close: char) -> String {
    let title = shown(title);
    if user.is_empty() {
        format!("{open}{title}{close}")
    } else {
        format!("{open}{title}{close} ({})", shown(user))
    }
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
    let one = count == 1;
    Prompt {
        title: Localized::new(
            if one {
                "Send this value?"
            } else {
                "Send these values?"
            },
            if one {
                "Отправить это значение?"
            } else {
                "Отправить эти значения?"
            },
            if one {
                "Bu qiymat yuborilsinmi?"
            } else {
                "Bu qiymatlar yuborilsinmi?"
            },
        ),
        body: Localized::new(
            format!(
                "Send the values of {} of “{label}” to “{peer}”: {list}. They are hidden there \
                 and wiped when their term ends, but whoever uses “{peer}” can copy them before \
                 then.",
                en(count, "variable", "variables")
            ),
            format!(
                "Отправить на «{peer}» значения {} из «{label}»: {list}? Там они скрыты и \
                 стираются, когда истечёт срок, но на «{peer}» их могут скопировать раньше.",
                ru(count, "переменной", "переменных", "переменных")
            ),
            format!(
                "«{label}» muhitidagi {count} ta oʻzgaruvchi qiymati «{peer}» kompyuteriga \
                 yuborilsinmi: {list}? U yerda ular yashirin turadi va muddati tugagach \
                 oʻchiriladi, lekin «{peer}» kompyuterida ulardan oldinroq nusxa olish mumkin."
            ),
        ),
        approve: Localized::new(
            if one { "Send value" } else { "Send values" },
            if one {
                "Отправить значение"
            } else {
                "Отправить значения"
            },
            if one {
                "Qiymatni yuborish"
            } else {
                "Qiymatlarni yuborish"
            },
        ),
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
            let (en_login, ru_login) = (
                login(title, username, '“', '”'),
                login(title, username, '«', '»'),
            );
            let (en_goes, ru_goes, uz_goes) = if *otp {
                (
                    format!("its password and 2FA secret go to “{peer}” and stay there"),
                    format!("пароль и секрет 2FA уйдут на «{peer}» и останутся там"),
                    "paroli va 2FA siri",
                )
            } else {
                (
                    format!("its password goes to “{peer}” and stays there"),
                    format!("пароль уйдёт на «{peer}» и останется там"),
                    "paroli",
                )
            };
            Some(Prompt {
                title: Localized::new(
                    "Offer this login?",
                    "Предложить этот логин?",
                    "Bu login taklif qilinsinmi?",
                ),
                body: Localized::new(
                    format!("Offer “{peer}” the login {en_login}. If they accept, {en_goes}."),
                    format!("Предложить «{peer}» логин {ru_login}? Если там примут, {ru_goes}."),
                    format!(
                        "«{peer}» kompyuteriga {ru_login} logini taklif qilinsinmi? Qabul \
                         qilinsa, {uz_goes} «{peer}» kompyuteriga boradi va oʻsha yerda qoladi."
                    ),
                ),
                approve: Localized::new("Offer login", "Предложить логин", "Loginni taklif qilish"),
            })
        }
        ItemSummary::Environment {
            project,
            name,
            variables,
            ..
        } => {
            let label = env_label(project, name);
            let n = usize::try_from(*variables).unwrap_or(usize::MAX);
            Some(Prompt {
                title: Localized::new(
                    "Offer this environment?",
                    "Предложить это окружение?",
                    "Bu muhit taklif qilinsinmi?",
                ),
                body: Localized::new(
                    format!(
                        "Offer “{peer}” the environment “{label}”. If they accept, the values of \
                         its {} go to “{peer}” and stay there.",
                        en(n, "variable", "variables")
                    ),
                    format!(
                        "Предложить «{peer}» окружение «{label}»? Если там примут, значения его \
                         {} уйдут на «{peer}» и останутся там.",
                        ru(n, "переменной", "переменных", "переменных")
                    ),
                    format!(
                        "«{peer}» kompyuteriga «{label}» muhiti taklif qilinsinmi? Qabul \
                         qilinsa, uning {n} ta oʻzgaruvchisi qiymatlari «{peer}» kompyuteriga \
                         boradi va oʻsha yerda qoladi."
                    ),
                ),
                approve: Localized::new(
                    "Offer environment",
                    "Предложить окружение",
                    "Muhitni taklif qilish",
                ),
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
            let (en_login, ru_login) = (
                login(title, username, '“', '”'),
                login(title, username, '«', '»'),
            );
            Some(Prompt {
                title: Localized::new(
                    "Save this login?",
                    "Сохранить этот логин?",
                    "Bu login saqlansinmi?",
                ),
                body: Localized::new(
                    format!("Save the login {en_login} from “{peer}” in Passwords?"),
                    format!("Сохранить логин {ru_login} от «{peer}» в «Паролях»?"),
                    format!(
                        "«{peer}» kompyuteridan kelgan {ru_login} logini «Parollar»da \
                         saqlansinmi?"
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
            let label = env_label(project, name);
            let n = usize::try_from(*variables).unwrap_or(usize::MAX);
            Some(Prompt {
                title: Localized::new(
                    "Save this environment?",
                    "Сохранить это окружение?",
                    "Bu muhit saqlansinmi?",
                ),
                body: Localized::new(
                    format!(
                        "Save the environment “{label}” from “{peer}”, with {}, as a new \
                         environment?",
                        en(n, "variable", "variables")
                    ),
                    format!(
                        "Сохранить окружение «{label}» от «{peer}» ({}) как новое окружение?",
                        ru(n, "переменная", "переменные", "переменных")
                    ),
                    format!(
                        "«{peer}» kompyuteridan kelgan, {n} ta oʻzgaruvchili «{label}» muhiti \
                         yangi muhit sifatida saqlansinmi?"
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
    let one = count == 1;
    let (replace_en, replace_ru, replace_uz) = if replaced.is_empty() {
        (String::new(), String::new(), String::new())
    } else {
        let list = names(replaced);
        (
            format!(" These replace your values: {list}."),
            format!(" Эти заменят ваши значения: {list}."),
            format!(" Bular qiymatlaringizni almashtiradi: {list}."),
        )
    };
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
            if one {
                "Add this variable?"
            } else {
                "Add these variables?"
            },
            if one {
                "Добавить эту переменную?"
            } else {
                "Добавить эти переменные?"
            },
            if one {
                "Bu oʻzgaruvchi qoʻshilsinmi?"
            } else {
                "Bu oʻzgaruvchilar qoʻshilsinmi?"
            },
        ),
        body: Localized::new(
            format!(
                "Add {} from “{peer}” to “{env}”: {list}.{replace_en}{risky_en}",
                en(count, "variable", "variables")
            ),
            format!(
                "Добавить в «{env}» {} от «{peer}»: {list}?{replace_ru}{risky_ru}",
                ru(count, "переменную", "переменные", "переменных")
            ),
            format!(
                "«{peer}» kompyuteridan {count} ta oʻzgaruvchi «{env}» muhitiga qoʻshilsinmi: \
                 {list}?{replace_uz}{risky_uz}"
            ),
        ),
        approve: Localized::new(
            if one { "Add variable" } else { "Add variables" },
            if one {
                "Добавить переменную"
            } else {
                "Добавить переменные"
            },
            if one {
                "Oʻzgaruvchini qoʻshish"
            } else {
                "Oʻzgaruvchilarni qoʻshish"
            },
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
            host: None,
            server: None,
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

    #[test]
    fn counts_agree_with_their_words() {
        assert_eq!(en(1, "variable", "variables"), "1 variable");
        assert_eq!(en(3, "variable", "variables"), "3 variables");
        let forms = |n| ru(n, "переменная", "переменные", "переменных");
        assert_eq!(forms(1), "1 переменная");
        assert_eq!(forms(2), "2 переменные");
        assert_eq!(forms(5), "5 переменных");
        assert_eq!(forms(11), "11 переменных");
        assert_eq!(forms(12), "12 переменных");
        assert_eq!(forms(21), "21 переменная");
        assert_eq!(forms(24), "24 переменные");
        let one = all(&send_variables("Bob", "shop · prod", &["API_KEY".into()]));
        assert!(
            one.contains("1 variable of") && one.contains("Send this value?"),
            "{one}"
        );
        assert!(!one.contains("1 variables"));
        let added = all(&add_variables("Bob", "dev", &["A".into()], &[], &[]));
        assert!(
            added.contains("Add 1 variable from") && added.contains("Add variable"),
            "{added}"
        );
    }

    #[test]
    fn environments_are_named_as_the_page_names_them() {
        let env = ItemSummary::Environment {
            project: "shop".into(),
            name: "prod".into(),
            variables: 1,
            secrets: 1,
            names: vec![],
        };
        let offer = all(&send_item("Bob", &env).unwrap());
        assert!(
            offer.contains("“shop · prod”") && offer.contains("its 1 variable go"),
            "{offer}"
        );
        assert!(!offer.contains(" / "));
        let saved = all(&accept_item("Bob", &env).unwrap());
        assert!(
            saved.contains("“shop · prod”") && saved.contains("with 1 variable,"),
            "{saved}"
        );
    }

    #[test]
    fn a_secret_without_a_label_is_named_by_what_it_is() {
        let named = chat_value("Bob", "", None);
        assert_eq!(named.en, "a secret from “Bob”");
        assert!(!named.en.contains("“”") && !named.ru.contains("«»") && !named.uz.contains("«»"));
        assert_eq!(
            chat_value("Bob", "db", None).en,
            "the secret “db” from “Bob”"
        );
        // As the page says it in Uzbek: a secret value, never "sir".
        assert!(chat_value("Bob", "db", None).uz.contains("maxfiy qiymat"));
        assert!(!chat_value("Bob", "", None).uz.contains(" sir"));
    }

    #[test]
    fn uzbek_suffixes_go_on_a_word_not_on_a_quoted_name() {
        let texts = [
            send_variables("Bob", "shop · prod", &["A".into()]).body.uz,
            add_variables("Bob", "dev", &["A".into()], &[], &[]).body.uz,
            chat_value("Bob", "db", Some("A")).uz,
        ];
        for text in texts {
            // A suffix right after a closing quote, or after a space, is never there.
            assert!(
                !text.contains("»dagi") && !text.contains("» ga ") && !text.contains("» dan "),
                "{text}"
            );
        }
    }

    #[test]
    fn a_login_without_a_user_has_no_empty_brackets() {
        let login = ItemSummary::Password {
            title: "router".into(),
            username: String::new(),
            url: String::new(),
            otp: false,
            host: None,
            server: None,
        };
        let text = all(&send_item("Bob", &login).unwrap());
        assert!(text.contains("“router”.") && !text.contains("()"), "{text}");
        assert!(
            text.contains("its password goes to “Bob” and stays there"),
            "{text}"
        );
    }
}
