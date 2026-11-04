//! Hosts as they go to the user's other computers.
//!
//! Only `Host` blocks for single names travel (`Host prod`, `Host db1 db2`):
//! not `Match`, not `Host *` or other patterns, and never the options before
//! the first block or an `Include`. A block goes without what belongs to
//! this computer: its keys (`IdentityFile`, `CertificateFile`, …), agent,
//! sockets and files, and any value with an absolute or home path. When a
//! block changes, this computer's own options stay as they are.

use serde::Serialize;

use super::{Change, Field, Item};
use crate::Result;
use crate::config::{HostEdit, HostEntry, HostKind, HostOption, SshConfig};

/// Options that name something on this computer.
const LOCAL: &[&str] = &[
    "certificatefile",
    "controlpath",
    "globalknownhostsfile",
    "identitiesonly",
    "identityagent",
    "identityfile",
    "pkcs11provider",
    "revokedhostkeys",
    "securitykeyprovider",
    "smartcarddevice",
    "userknownhostsfile",
    "usekeychain",
    "xauthlocation",
];

/// A directive a change would add that runs a program or reaches beyond
/// the host (see [`crate::config`]'s `risky`): never applied unasked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct RiskyLine {
    pub key: String,
    pub value: String,
}

/// Whether an option belongs to this computer and stays out of a sync.
pub fn is_local(option: &HostOption) -> bool {
    let key = option.key.to_ascii_lowercase();
    LOCAL.contains(&key.as_str()) || has_path(&option.value)
}

/// Whether a value names a file by an absolute or home path.
fn has_path(value: &str) -> bool {
    value.split_whitespace().any(|word| {
        let word = word.trim_matches(|c| c == '"' || c == '\'');
        let bytes = word.as_bytes();
        word.starts_with(['/', '~'])
            || word.starts_with("\\\\")
            || word.starts_with("%d")
            || word.starts_with("$HOME")
            || word.starts_with("${HOME}")
            || (bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && matches!(bytes[2], b'\\' | b'/'))
    })
}

/// The hosts of `config` that go to the user's other computers, in file
/// order; a second block with the same patterns is left out.
pub fn portable(config: &SshConfig) -> Vec<Item> {
    let mut items: Vec<Item> = Vec::new();
    for entry in config.hosts() {
        let Some(id) = id_of(&entry) else {
            continue;
        };
        if items.iter().any(|item| item.id == id) {
            continue;
        }
        let mut item = Item {
            id,
            fields: Vec::new(),
        };
        for option in entry.options.iter().filter(|o| !is_local(o)) {
            match item
                .fields
                .iter_mut()
                .find(|f| f.key.eq_ignore_ascii_case(&option.key))
            {
                Some(field) => field.values.push(option.value.clone()),
                None => item.fields.push(Field {
                    key: option.key.clone(),
                    values: vec![option.value.clone()],
                }),
            }
        }
        items.push(item);
    }
    items
}

/// The id a block syncs under, if it syncs: its patterns, for a `Host`
/// block of names only.
fn id_of(entry: &HostEntry) -> Option<String> {
    (entry.kind == HostKind::Host
        && !entry.is_wildcard
        && !entry.patterns.is_empty()
        && entry.patterns.iter().all(|p| !p.starts_with('!')))
    .then(|| entry.patterns.join(" "))
}

fn find(config: &SshConfig, id: &str) -> Option<HostEntry> {
    config
        .hosts()
        .into_iter()
        .find(|entry| id_of(entry).as_deref() == Some(id))
}

/// Makes `change` in `config`. A new host goes before a trailing `Host *`;
/// a changed one keeps this computer's own options where they are.
pub fn apply(config: &mut SshConfig, change: &Change) -> Result<()> {
    match change {
        Change::Add(item) | Change::Update(item) => {
            let existing = find(config, &item.id);
            let options = match &existing {
                Some(entry) => merge_options(&entry.options, item),
                None => item
                    .fields
                    .iter()
                    .flat_map(|f| f.values.iter().map(|v| HostOption::new(&f.key, v)))
                    .collect(),
            };
            if existing.as_ref().is_some_and(|e| e.options == options) {
                return Ok(());
            }
            config.upsert_host(&HostEdit {
                id: existing.map(|e| e.id),
                patterns: item.id.split(' ').map(str::to_owned).collect(),
                options,
            })?;
            Ok(())
        }
        Change::Delete(id) => match find(config, id) {
            Some(entry) => config.delete_host(entry.id),
            None => Ok(()),
        },
    }
}

/// This computer's options with the portable ones replaced by `item`'s:
/// its own ones stay in place, each portable keyword takes the place of
/// its first line, and new keywords go last.
fn merge_options(options: &[HostOption], item: &Item) -> Vec<HostOption> {
    let mut out = Vec::new();
    let mut done: Vec<String> = Vec::new();
    for option in options {
        if is_local(option) {
            out.push(option.clone());
            continue;
        }
        let key = option.key.to_ascii_lowercase();
        if done.contains(&key) {
            continue;
        }
        if let Some(field) = item.field(&key) {
            out.extend(
                field
                    .values
                    .iter()
                    .map(|value| HostOption::new(&option.key, value)),
            );
        }
        done.push(key);
    }
    for field in &item.fields {
        if !done.contains(&field.key.to_ascii_lowercase()) {
            out.extend(
                field
                    .values
                    .iter()
                    .map(|value| HostOption::new(&field.key, value)),
            );
        }
    }
    out
}

/// What `change` would add to `config` that runs a program or reaches
/// beyond the host; empty when it is safe to make unasked.
pub fn risky(config: &SshConfig, change: &Change) -> Result<Vec<RiskyLine>> {
    let mut after = config.clone();
    apply(&mut after, change)?;
    Ok(after
        .added_risky_directives(config)
        .into_iter()
        .map(|d| RiskyLine {
            key: d.key,
            value: d.value,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = "\
Host *.corp
    User me

Host prod
    HostName 10.0.0.1
    User deploy
    IdentityFile ~/.ssh/id_prod
    UseKeychain yes
    LocalForward 8080 localhost:80
    LocalForward 9090 /tmp/local.sock

Match host db exec \"true\"
    User x

Host db1 db2
    HostName db.example.com
    ProxyCommand /usr/local/bin/cloudflared access ssh --hostname %h

Host *
    ServerAliveInterval 30
";

    fn field(key: &str, values: &[&str]) -> Field {
        Field {
            key: key.into(),
            values: values.iter().map(|v| (*v).to_owned()).collect(),
        }
    }

    #[test]
    fn only_name_blocks_go_and_without_what_is_this_computers() {
        let config = SshConfig::parse(CONFIG);
        let items = portable(&config);
        assert_eq!(
            items,
            [
                Item {
                    id: "prod".into(),
                    fields: vec![
                        field("HostName", &["10.0.0.1"]),
                        field("User", &["deploy"]),
                        field("LocalForward", &["8080 localhost:80"]),
                    ],
                },
                Item {
                    id: "db1 db2".into(),
                    fields: vec![field("HostName", &["db.example.com"])],
                },
            ]
        );
    }

    #[test]
    fn paths_mark_a_value_as_this_computers() {
        for value in [
            "/usr/bin/nc %h %p",
            "ssh -i ~/.ssh/x -W %h:%p jump",
            "%d/.ssh/sock",
            "$HOME/x",
            "${HOME}/x",
            "C:\\Users\\me\\key",
            "\\\\server\\share",
            "\"/quoted path\"",
        ] {
            assert!(has_path(value), "{value}");
        }
        for value in [
            "ssh -W %h:%p bastion",
            "8080 localhost:80",
            "yes",
            "10.0.0.1",
        ] {
            assert!(!has_path(value), "{value}");
        }
    }

    #[test]
    fn a_new_host_goes_before_host_star() {
        let mut config = SshConfig::parse(CONFIG);
        let staging = Item {
            id: "staging".into(),
            fields: vec![field("HostName", &["10.0.0.7"]), field("Port", &["2222"])],
        };
        apply(&mut config, &Change::Add(staging.clone())).unwrap();
        let text = config.to_string();
        let at = text.find("Host staging").unwrap();
        assert!(at < text.find("Host *\n").unwrap());
        assert!(text.contains("Host staging\n    HostName 10.0.0.7\n    Port 2222\n"));
        assert_eq!(portable(&config).last(), Some(&staging));
    }

    #[test]
    fn a_changed_host_keeps_this_computers_options() {
        let mut config = SshConfig::parse(CONFIG);
        let prod = Item {
            id: "prod".into(),
            fields: vec![
                field("HostName", &["10.0.0.2"]),
                field("LocalForward", &["8081 localhost:81", "8082 localhost:82"]),
                field("Port", &["2200"]),
            ],
        };
        apply(&mut config, &Change::Update(prod.clone())).unwrap();
        let entry = find(&config, "prod").unwrap();
        let options: Vec<(&str, &str)> = entry
            .options
            .iter()
            .map(|o| (o.key.as_str(), o.value.as_str()))
            .collect();
        assert_eq!(
            options,
            [
                ("HostName", "10.0.0.2"),
                ("IdentityFile", "~/.ssh/id_prod"),
                ("UseKeychain", "yes"),
                ("LocalForward", "8081 localhost:81"),
                ("LocalForward", "8082 localhost:82"),
                ("LocalForward", "9090 /tmp/local.sock"),
                ("Port", "2200"),
            ]
        );
        assert_eq!(portable(&config)[0], prod);
    }

    #[test]
    fn a_deleted_host_goes_and_the_rest_stays() {
        let mut config = SshConfig::parse(CONFIG);
        apply(&mut config, &Change::Delete("db1 db2".into())).unwrap();
        let text = config.to_string();
        assert!(!text.contains("db.example.com"));
        assert!(text.contains("Host prod") && text.contains("Match host db"));
        // Deleting what isn't there is nothing.
        apply(&mut config, &Change::Delete("db1 db2".into())).unwrap();
        assert_eq!(config.to_string(), text);
    }

    #[test]
    fn a_change_that_adds_a_command_is_risky() {
        let config = SshConfig::parse(CONFIG);
        let safe = Change::Add(Item {
            id: "web".into(),
            fields: vec![field("HostName", &["web.example.com"])],
        });
        assert_eq!(risky(&config, &safe).unwrap().len(), 0);
        let command = Change::Add(Item {
            id: "web".into(),
            fields: vec![
                field("HostName", &["web.example.com"]),
                field("ProxyCommand", &["ssh -W %h:%p bastion"]),
                field("ForwardAgent", &["yes"]),
            ],
        });
        let lines = risky(&config, &command).unwrap();
        let keys: Vec<&str> = lines.iter().map(|l| l.key.as_str()).collect();
        assert_eq!(keys, ["ProxyCommand", "ForwardAgent"]);
        // Nothing happened to the config itself.
        assert_eq!(config.to_string(), CONFIG);
    }
}
