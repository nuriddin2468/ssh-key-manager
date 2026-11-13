//! What the tray menu shows, worked out from the app's state without Tauri.
//! The texts are in the interface's language, so comparing two menus also
//! tells when the language changed; the tray rebuilds its menu only then.

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::commands::remote::check_alias;
use crate::confirm::Localized;
use crate::history::{HostHistory, Via};
use crate::tunnels::Active;

/// Hosts the Connect submenu lists before "All hosts…".
pub const HOSTS_SHOWN: usize = 8;

// The macOS menu bar's handler sees these ids too and passes them to the
// page, which knows none of them.
pub const OPEN: &str = "tray:open";
pub const QUICK: &str = "tray:quick";
pub const NEARBY: &str = "tray:nearby";
/// Nearby's chats, when messages wait there unread.
pub const CHATS: &str = "tray:chats";
/// Followed by the alias.
pub const HOST: &str = "tray:host:";
pub const ALL_HOSTS: &str = "tray:hosts";
pub const LOCK: &str = "tray:lock";
pub const UNLOCK: &str = "tray:unlock";
pub const QUIT: &str = "tray:quit";
/// The Tunnels tool, and stopping every tunnel.
pub const TUNNELS: &str = "tray:tunnels";
pub const STOP_TUNNELS: &str = "tray:tunnels:stop";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vault {
    Missing,
    Locked,
    Unlocked,
}

/// A Nearby conversation that waits for the user's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Waiting {
    /// The other computer's name, once it said who it is.
    pub peer: Option<String>,
}

/// What the menu is made of.
pub struct Input<'a> {
    pub vault: Vault,
    /// The config's host aliases, in file order.
    pub aliases: &'a [String],
    pub history: &'a HostHistory,
    pub waiting: Option<Waiting>,
    /// Chat messages the user hasn't read.
    pub unread: u32,
    /// The tunnels that are on, in the Tunnels tool's order.
    pub tunnels: &'a [Active],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// Greyed-out text.
    Label(String),
    Action {
        id: String,
        text: String,
    },
    Submenu {
        text: String,
        items: Vec<Item>,
    },
    Separator,
}

/// What waits on Nearby: a conversation that asks the user, chat messages
/// they haven't read.
fn nearby(input: &Input, items: &mut Vec<Item>) {
    if let Some(waiting) = &input.waiting {
        items.push(Item::Separator);
        let waiting = match &waiting.peer {
            Some(peer) => Localized::new(
                format!("{peer} is waiting for your answer"),
                format!("{peer} ждёт вашего ответа"),
                format!("{peer} javobingizni kutmoqda"),
            )
            .pick()
            .to_owned(),
            None => text(
                "A computer nearby is waiting for your answer",
                "Компьютер рядом ждёт вашего ответа",
                "Yaqindagi kompyuter javobingizni kutmoqda",
            ),
        };
        items.push(action(NEARBY, waiting));
    }

    if input.unread > 0 && input.vault == Vault::Unlocked {
        let unread = input.unread;
        items.push(Item::Separator);
        items.push(action(
            CHATS,
            Localized::new(
                format!("Unread messages: {unread}"),
                format!("Непрочитанные сообщения: {unread}"),
                format!("Oʻqilmagan xabarlar: {unread}"),
            )
            .pick()
            .to_owned(),
        ));
    }
}

pub fn items(input: &Input) -> Vec<Item> {
    let mut items = Vec::new();
    match input.vault {
        Vault::Missing => {}
        Vault::Locked => items.push(Item::Label(text(
            "Vault locked",
            "Хранилище заблокировано",
            "Ombor qulflangan",
        ))),
        Vault::Unlocked => items.push(Item::Label(text(
            "Vault unlocked",
            "Хранилище разблокировано",
            "Ombor ochiq",
        ))),
    }
    items.push(action(
        OPEN,
        text(
            "Open SSH Key Manager",
            "Открыть SSH Key Manager",
            "SSH Key Manager’ni ochish",
        ),
    ));
    items.push(action(
        QUICK,
        text("Quick Search…", "Быстрый поиск…", "Tezkor qidiruv…"),
    ));

    nearby(input, &mut items);

    if !input.tunnels.is_empty() {
        items.push(Item::Separator);
        items.push(tunnels(input.tunnels));
    }

    let hosts = hosts(input.aliases, input.history);
    if !hosts.is_empty() {
        items.push(Item::Separator);
        let mut connect: Vec<Item> = hosts
            .into_iter()
            .map(|alias| action(&format!("{HOST}{alias}"), alias))
            .collect();
        connect.push(Item::Separator);
        connect.push(action(
            ALL_HOSTS,
            text("All Hosts…", "Все хосты…", "Barcha xostlar…"),
        ));
        items.push(Item::Submenu {
            text: text("Connect", "Подключиться", "Ulanish"),
            items: connect,
        });
    }

    items.push(Item::Separator);
    match input.vault {
        Vault::Missing => {}
        Vault::Locked => items.push(action(
            UNLOCK,
            text(
                "Unlock Vault…",
                "Разблокировать хранилище…",
                "Omborni ochish…",
            ),
        )),
        Vault::Unlocked => items.push(action(
            LOCK,
            text("Lock Vault", "Заблокировать хранилище", "Omborni qulflash"),
        )),
    }
    items.push(action(
        QUIT,
        text(
            "Quit SSH Key Manager",
            "Выйти из SSH Key Manager",
            "SSH Key Manager’dan chiqish",
        ),
    ));
    items
}

/// "Tunnels: 2 on", with each tunnel, stopping them all and the tool.
fn tunnels(tunnels: &[Active]) -> Item {
    let mut items: Vec<Item> = tunnels
        .iter()
        .map(|tunnel| {
            let label = &tunnel.label;
            Item::Label(if tunnel.waiting {
                Localized::new(
                    format!("{label} — waiting for your answer"),
                    format!("{label} — ждёт вашего ответа"),
                    format!("{label} — javobingizni kutmoqda"),
                )
                .pick()
                .to_owned()
            } else {
                label.clone()
            })
        })
        .collect();
    items.push(Item::Separator);
    items.push(action(
        STOP_TUNNELS,
        text(
            "Stop All Tunnels",
            "Остановить все туннели",
            "Barcha tunnellarni toʻxtatish",
        ),
    ));
    items.push(action(
        TUNNELS,
        text(
            "Show Tunnels…",
            "Показать туннели…",
            "Tunnellarni koʻrsatish…",
        ),
    ));
    let count = tunnels.len();
    Item::Submenu {
        text: Localized::new(
            format!("Tunnels: {count} on"),
            format!("Туннели: включено {count}"),
            format!("Tunnellar: {count} ta yoqilgan"),
        )
        .pick()
        .to_owned(),
        items,
    }
}

/// The aliases the Connect submenu lists: those with a terminal session,
/// latest first, then the others in the config's order; at most
/// [`HOSTS_SHOWN`]. Only plain names `ssh` can be started with, each once.
pub fn hosts(aliases: &[String], history: &HostHistory) -> Vec<String> {
    let mut plain: Vec<&String> = Vec::new();
    for alias in aliases {
        if check_alias(alias).is_ok() && !plain.contains(&alias) {
            plain.push(alias);
        }
    }
    let last_session = |alias: &str| {
        history
            .get(alias)?
            .iter()
            .filter(|event| event.via == Via::Terminal)
            .filter_map(|event| OffsetDateTime::parse(&event.at, &Rfc3339).ok())
            .max()
    };
    let mut recent: Vec<(OffsetDateTime, &String)> = plain
        .iter()
        .filter_map(|alias| Some((last_session(alias)?, *alias)))
        .collect();
    recent.sort_by_key(|(at, _)| std::cmp::Reverse(*at));
    let mut shown: Vec<String> = recent.into_iter().map(|(_, a)| a.clone()).collect();
    for alias in plain {
        if shown.len() >= HOSTS_SHOWN {
            break;
        }
        if !shown.contains(alias) {
            shown.push(alias.clone());
        }
    }
    shown.truncate(HOSTS_SHOWN);
    shown
}

fn action(id: &str, text: String) -> Item {
    Item::Action {
        id: id.to_owned(),
        text,
    }
}

fn text(en: &str, ru: &str, uz: &str) -> String {
    Localized::new(en, ru, uz).pick().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::{ConnectionEvent, Outcome};

    fn event(at: &str, via: Via) -> ConnectionEvent {
        ConnectionEvent {
            at: at.to_owned(),
            via,
            outcome: Outcome::SignedIn,
            duration_secs: None,
        }
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    fn ids(items: &[Item]) -> Vec<String> {
        items
            .iter()
            .map(|item| match item {
                Item::Label(_) => "label".to_owned(),
                Item::Action { id, .. } => id.clone(),
                Item::Submenu { items, .. } => format!("[{}]", ids(items).join(" ")),
                Item::Separator => "-".to_owned(),
            })
            .collect()
    }

    #[test]
    fn hosts_put_the_latest_sessions_first_then_the_config_order() {
        let aliases = names(&["alpha", "beta", "gamma", "delta"]);
        let mut history = HostHistory::new();
        history.insert(
            "gamma".into(),
            vec![event("2026-11-01T10:00:00Z", Via::Terminal)],
        );
        // A later check doesn't count: only sessions do.
        history.insert(
            "delta".into(),
            vec![
                event("2026-11-03T10:00:00Z", Via::Check),
                event("2026-11-02T10:00:00.5Z", Via::Terminal),
            ],
        );
        history.insert(
            "beta".into(),
            vec![event("2026-11-02T10:00:00Z", Via::Terminal)],
        );
        assert_eq!(
            hosts(&aliases, &history),
            names(&["delta", "beta", "gamma", "alpha"])
        );
    }

    #[test]
    fn hosts_skip_names_ssh_cant_start_and_stop_at_the_limit() {
        let mut aliases = names(&["-oProxyCommand=x", "a b", "web", "web", "db$(id)"]);
        aliases.extend((0..20).map(|n| format!("host{n}")));
        let shown = hosts(&aliases, &HostHistory::new());
        assert_eq!(shown.len(), HOSTS_SHOWN);
        assert_eq!(shown[0], "web");
        assert_eq!(shown[1], "host0");
    }

    #[test]
    fn hosts_forget_sessions_of_hosts_gone_from_the_config() {
        let mut history = HostHistory::new();
        history.insert(
            "old".into(),
            vec![event("2026-11-01T10:00:00Z", Via::Terminal)],
        );
        assert_eq!(hosts(&names(&["new"]), &history), names(&["new"]));
    }

    #[test]
    fn an_unlocked_vault_offers_locking_and_hosts_a_submenu() {
        let aliases = names(&["web"]);
        let history = HostHistory::new();
        let items = items(&Input {
            vault: Vault::Unlocked,
            aliases: &aliases,
            history: &history,
            waiting: None,
            unread: 0,
            tunnels: &[],
        });
        assert_eq!(
            ids(&items),
            [
                "label",
                OPEN,
                QUICK,
                "-",
                &format!("[{HOST}web - {ALL_HOSTS}]"),
                "-",
                LOCK,
                QUIT
            ]
        );
    }

    #[test]
    fn a_locked_vault_offers_unlocking_and_a_waiting_peer_comes_first() {
        let history = HostHistory::new();
        let items = items(&Input {
            vault: Vault::Locked,
            aliases: &[],
            history: &history,
            waiting: Some(Waiting {
                peer: Some("Laptop".into()),
            }),
            // Locked: unread chats aren't counted aloud.
            unread: 3,
            tunnels: &[],
        });
        assert_eq!(
            ids(&items),
            ["label", OPEN, QUICK, "-", NEARBY, "-", UNLOCK, QUIT]
        );
        assert!(matches!(&items[4], Item::Action { text, .. } if text.starts_with("Laptop")));
    }

    #[test]
    fn unread_chats_lead_to_them_while_the_vault_is_unlocked() {
        let history = HostHistory::new();
        let items = items(&Input {
            vault: Vault::Unlocked,
            aliases: &[],
            history: &history,
            waiting: None,
            unread: 2,
            tunnels: &[],
        });
        let chats = items
            .iter()
            .find(|item| matches!(item, Item::Action { id, .. } if id == CHATS));
        assert!(
            matches!(chats, Some(Item::Action { text, .. }) if text == "Unread messages: 2"),
            "{items:?}"
        );
    }

    #[test]
    fn without_a_vault_there_is_nothing_to_lock() {
        let history = HostHistory::new();
        let items = items(&Input {
            vault: Vault::Missing,
            aliases: &[],
            history: &history,
            waiting: None,
            unread: 0,
            tunnels: &[],
        });
        assert_eq!(ids(&items), [OPEN, QUICK, "-", QUIT]);
    }

    #[test]
    fn tunnels_that_are_on_get_a_submenu_to_stop_them() {
        let history = HostHistory::new();
        let tunnels = [
            Active {
                label: "8080 → localhost:80 (web)".into(),
                waiting: false,
            },
            Active {
                label: "SOCKS 1080 (db)".into(),
                waiting: true,
            },
        ];
        let items = items(&Input {
            vault: Vault::Missing,
            aliases: &[],
            history: &history,
            waiting: None,
            unread: 0,
            tunnels: &tunnels,
        });
        assert_eq!(
            ids(&items),
            [
                OPEN,
                QUICK,
                "-",
                &format!("[label label - {STOP_TUNNELS} {TUNNELS}]"),
                "-",
                QUIT
            ]
        );
        let Item::Submenu { text, items } = &items[3] else {
            panic!("no submenu");
        };
        assert!(text.contains('2'));
        assert!(matches!(&items[1], Item::Label(label) if label.starts_with("SOCKS 1080 (db) — ")));
    }
}
