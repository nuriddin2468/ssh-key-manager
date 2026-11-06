//! What the quick search window lists: the hosts `ssh` can be started with
//! and, while the vault is unlocked, its entries without their secrets.

use serde::Serialize;
use sshkm_core::config::{ConfigView, HostKind};
use sshkm_core::vault::{EntryKind, EntrySummary};

use crate::commands::remote::check_alias;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct QuickItems {
    pub hosts: Vec<QuickHost>,
    /// `None` while the vault is locked, or there is none.
    pub entries: Option<Vec<QuickEntry>>,
}

/// A host alias, in the config's order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct QuickHost {
    pub alias: String,
    pub user: Option<String>,
    pub host_name: Option<String>,
}

/// An entry as the window shows it: what it is and which secrets it has,
/// never the secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct QuickEntry {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub kind: EntryKind,
    pub has_password: bool,
    pub has_otp: bool,
}

/// The aliases of `Host` blocks for single names, each once, that `ssh` can
/// be started with ([`check_alias`]).
pub fn hosts(view: &ConfigView) -> Vec<QuickHost> {
    let mut hosts: Vec<QuickHost> = Vec::new();
    for block in &view.hosts {
        if block.kind != HostKind::Host || block.is_wildcard {
            continue;
        }
        for alias in &block.patterns {
            if check_alias(alias).is_err() || hosts.iter().any(|host| &host.alias == alias) {
                continue;
            }
            hosts.push(QuickHost {
                alias: alias.clone(),
                user: block.user.clone(),
                host_name: block.host_name.clone(),
            });
        }
    }
    hosts
}

/// The entries outside the recycle bin.
pub fn entries(all: Vec<EntrySummary>) -> Vec<QuickEntry> {
    all.into_iter()
        .filter(|entry| !entry.in_trash)
        .map(|entry| QuickEntry {
            id: entry.id,
            title: entry.title,
            username: entry.username,
            url: entry.url,
            kind: entry.kind,
            has_password: entry.has_password,
            has_otp: entry.has_otp,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use sshkm_core::config::SshConfig;

    use super::*;

    #[test]
    fn hosts_are_single_names_ssh_can_start_each_once() {
        let config = SshConfig::parse(
            "Host web db\n  HostName 10.0.0.5\n  User deploy\n\
             Host *.internal\n  User me\n\
             Host -oProxyCommand=x web\n\
             Match host other\n  User x\n\
             Host bastion\n",
        );
        let hosts = hosts(&config.view());
        let aliases: Vec<&str> = hosts.iter().map(|host| host.alias.as_str()).collect();
        assert_eq!(aliases, ["web", "db", "bastion"]);
        assert_eq!(hosts[1].user.as_deref(), Some("deploy"));
        assert_eq!(hosts[1].host_name.as_deref(), Some("10.0.0.5"));
        assert_eq!(hosts[2].user, None);
    }

    fn summary(id: &str, in_trash: bool) -> EntrySummary {
        EntrySummary {
            id: id.into(),
            title: format!("Title {id}"),
            username: "me".into(),
            url: "https://example.com".into(),
            kind: EntryKind::Login,
            host: None,
            key_fingerprint: None,
            has_password: true,
            has_otp: false,
            group: Some("Work".into()),
            in_trash,
            created: None,
            modified: None,
        }
    }

    #[test]
    fn entries_leave_out_the_recycle_bin() {
        let entries = entries(vec![summary("a", false), summary("b", true)]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "a");
        assert!(entries[0].has_password);
    }
}
