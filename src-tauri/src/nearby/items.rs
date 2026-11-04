//! The items Nearby sends: read here from the vault, `~/.ssh` and the hosts
//! file when the user sends one, and saved there when the user accepts one.
//! The UI only names what to send; secrets never pass through it.
//!
//! A hosts file group is not written when it comes: it waits here
//! ([`ReceivedGroup`]) until the Hosts file page shows the change, which the
//! user saves with the administrator password.

use std::path::Path;

use serde::{Deserialize, Serialize};
use ssh_key::{HashAlg, PublicKey};
use sshkm_core::ErrorCode;
use sshkm_core::config::{HostEdit, HostKind, HostOption, SshConfig};
use sshkm_core::hosts_file::{HostsChange, HostsEntryEdit, HostsFile, is_system_name};
use sshkm_core::keys;
use sshkm_core::known_hosts::KnownHosts;
use sshkm_core::p2p::protocol::{HostKey, HostsEntry, Item};
use sshkm_core::vault::{EntryInput, EntryKind, SecretField};
use sshkm_core::{ExposeSecret, SecretString};
use tauri::AppHandle;

use super::Nearby;
use super::pairing::PairingFailure;
use crate::commands::keys::find_key;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// What the user sends: the UI names it, the backend reads it.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum SendRequest {
    /// A login or a server's password from the vault.
    Password {
        #[serde(rename = "entryId")]
        entry_id: String,
        /// Send its 2FA secret too.
        otp: bool,
    },
    /// A host from `~/.ssh/config`, by its alias, with the server's keys.
    Host { alias: String },
    /// A group of the hosts file, by its name, with its entries.
    HostsGroup { name: String },
    /// A key's public half, by the key's id.
    PublicKey {
        #[serde(rename = "keyId")]
        key_id: String,
    },
}

/// A hosts file group another computer sent, waiting for the user to look
/// at the change and save it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct ReceivedGroup {
    /// The pairing it came with.
    pub id: u32,
    /// The group's name on the other computer.
    pub name: String,
    /// The other computer's name.
    pub from: Option<String>,
    /// Its entries, each in the group `name`.
    pub entries: Vec<HostsEntryEdit>,
}

/// The item `request` names.
pub fn build(state: &AppState, app: &AppHandle, request: &SendRequest) -> AppResult<Item> {
    let item = match request {
        SendRequest::Password { entry_id, otp } => state.vault.with(app, |vault| {
            let entry = vault.entry(entry_id)?;
            if entry.summary.kind == EntryKind::Key {
                return Err(AppError::invalid(
                    "a key's passphrase stays with the key: send the key's host instead",
                ));
            }
            let password = vault.secret(entry_id, SecretField::Password)?;
            let otp = if *otp && entry.summary.has_otp {
                Some(vault.secret(entry_id, SecretField::Otp)?)
            } else {
                None
            };
            Ok(Item::Password {
                title: entry.summary.title,
                username: entry.summary.username,
                password: password.expose_secret().to_owned(),
                url: entry.summary.url,
                notes: entry.notes,
                otp: otp.map(|otp| otp.expose_secret().to_owned()),
                host: entry.summary.host,
            })
        })?,
        SendRequest::Host { alias } => {
            let config = SshConfig::load(&state.paths.config)?;
            let host = config
                .hosts()
                .into_iter()
                .find(|host| {
                    host.kind == HostKind::Host
                        && !host.is_wildcard
                        && host.patterns == [alias.clone()]
                })
                .ok_or_else(|| AppError::not_found(format!("no host {alias} of its own")))?;
            let known = KnownHosts::load(&state.paths.known_hosts)?;
            let address = host.host_name.as_deref().unwrap_or(alias);
            let host_keys = known
                .keys_for(address, host.port.unwrap_or(22))
                .into_iter()
                .map(|(key_type, key)| HostKey { key_type, key })
                .collect();
            Item::Host {
                alias: alias.clone(),
                host_name: host.host_name,
                user: host.user,
                port: host.port,
                proxy_jump: host
                    .proxy_jump
                    .filter(|jump| !jump.eq_ignore_ascii_case("none")),
                host_keys,
            }
        }
        SendRequest::HostsGroup { name } => hosts_group(&state.hosts_file, name)?,
        SendRequest::PublicKey { key_id } => {
            let key = find_key(state, key_id)?;
            let line = key
                .public_key
                .ok_or_else(|| AppError::invalid("the key's public half can't be read"))?;
            Item::PublicKey {
                name: key.name,
                key: line.trim().to_owned(),
            }
        }
    };
    item.check()
        .map_err(|error| AppError::invalid(format!("it can't be sent as it is: {error}")))?;
    Ok(item)
}

/// The group `name` of the hosts file at `path`, without the system's own
/// names and without addresses with a scope (`%en0`), which name one of this
/// computer's network interfaces.
fn hosts_group(path: &Path, name: &str) -> AppResult<Item> {
    let file = HostsFile::load(path)?;
    if !file.groups().iter().any(|group| group.name == name) {
        return Err(AppError::not_found(format!("no group {name:?}")));
    }
    let entries: Vec<HostsEntry> = file
        .entries()
        .into_iter()
        .filter(|entry| entry.group.as_deref() == Some(name) && !entry.address.contains('%'))
        .filter_map(|entry| {
            let names: Vec<String> = entry
                .names
                .into_iter()
                .filter(|name| !is_system_name(name))
                .collect();
            (!names.is_empty()).then_some(HostsEntry {
                address: entry.address,
                names,
                enabled: entry.enabled,
                expires: entry.expires,
            })
        })
        .collect();
    if entries.is_empty() {
        return Err(AppError::invalid("the group has no entries to send"));
    }
    Ok(Item::HostsGroup {
        name: name.to_owned(),
        entries,
    })
}

/// Saves an item the user accepted, which came with pairing `id` from
/// `peer`. Returns the name it got and whether a host's keys differ from the
/// ones this computer has for it. A hosts file group waits in `nearby` for
/// the user to save it.
pub fn store(
    nearby: &Nearby,
    id: u32,
    peer: Option<&str>,
    item: &Item,
) -> Result<(String, bool), PairingFailure> {
    let state = nearby.state().map_err(|_| PairingFailure::Broken)?;
    let app = nearby.app().map_err(|_| PairingFailure::Broken)?;
    let not_saved = |error: AppError| {
        log::warn!("nearby: a received item was not saved: {error}");
        PairingFailure::NotSaved
    };
    match item {
        Item::Password {
            title,
            username,
            password,
            url,
            notes,
            otp,
            host,
        } => {
            let input = EntryInput {
                title: title.clone(),
                username: username.clone(),
                password: Some(SecretString::from(password.clone())),
                url: url.clone(),
                notes: notes.clone(),
                otp: otp.clone().map(SecretString::from),
                kind: if host.is_some() {
                    EntryKind::Host
                } else {
                    EntryKind::Login
                },
                host: host.clone(),
                key_fingerprint: None,
            };
            state
                .vault
                .change(app, &state.backup_dir, |vault| Ok(vault.add_entry(&input)?))
                .map_err(|error| match error.code() {
                    ErrorCode::VaultLocked => PairingFailure::VaultLocked,
                    _ => PairingFailure::NotSaved,
                })?;
            Ok((title.clone(), false))
        }
        Item::Host { .. } => store_host(&state, item).map_err(not_saved),
        Item::HostsGroup { name, entries } => {
            let group =
                group_draft(&state.hosts_file, id, peer, name, entries).map_err(not_saved)?;
            nearby.keep_group(group);
            Ok((name.clone(), false))
        }
        Item::PublicKey { name, key } => {
            let name = save_key(
                &state.paths.dir,
                peer.unwrap_or_default(),
                name,
                key,
                |fp| nearby.remember_key(fp),
            )
            .map_err(not_saved)?;
            Ok((name, false))
        }
    }
}

/// A received group as the change the Hosts file page shows, checked the
/// way saving will check it. Fails when this app can't write the file.
fn group_draft(
    path: &Path,
    id: u32,
    peer: Option<&str>,
    name: &str,
    entries: &[HostsEntry],
) -> AppResult<ReceivedGroup> {
    let file = HostsFile::load(path)?;
    if let Some(reason) = file.read_only_reason(path) {
        return Err(AppError::invalid(format!(
            "the hosts file can't be changed here: {reason:?}"
        )));
    }
    let entries: Vec<HostsEntryEdit> = entries
        .iter()
        .map(|entry| HostsEntryEdit {
            address: entry.address.clone(),
            names: entry.names.clone(),
            comment: None,
            enabled: entry.enabled,
            expires: entry.expires.clone(),
            group: Some(name.to_owned()),
        })
        .collect();
    let changes: Vec<HostsChange> = entries
        .iter()
        .map(|entry| HostsChange::Add {
            entry: entry.clone(),
        })
        .collect();
    file.edited(&changes)?;
    Ok(ReceivedGroup {
        id,
        name: name.to_owned(),
        from: peer.map(str::to_owned),
        entries,
    })
}

/// Saves someone's public key in `dir` (see [`keys::add_public`]), unless a
/// key there has its fingerprint already; returns its name here. `remember`
/// gets the fingerprint of a key saved anew, before it is written, so the
/// audit never takes it for a key whose private half is missing.
fn save_key(
    dir: &Path,
    from: &str,
    name: &str,
    key: &str,
    remember: impl FnOnce(&str) -> AppResult<()>,
) -> AppResult<String> {
    let key =
        PublicKey::from_openssh(key).map_err(|_| AppError::invalid("not an OpenSSH public key"))?;
    let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
    if let Some(known) = keys::scan(dir)?
        .keys
        .into_iter()
        .find(|known| known.fingerprint.as_deref() == Some(fingerprint.as_str()))
    {
        return Ok(known.name);
    }
    remember(&fingerprint)?;
    Ok(keys::add_public(dir, name, from, &key)?.name)
}

fn store_host(state: &AppState, item: &Item) -> AppResult<(String, bool)> {
    let Item::Host {
        alias,
        host_name,
        user,
        port,
        proxy_jump,
        host_keys,
    } = item
    else {
        return Err(AppError::invalid("not a host"));
    };
    let before = SshConfig::load(&state.paths.config)?;
    let alias = free_alias(&before, alias);
    let mut options = Vec::new();
    if let Some(host_name) = host_name {
        options.push(HostOption::new("HostName", host_name));
    }
    if let Some(user) = user {
        options.push(HostOption::new("User", user));
    }
    if let Some(port) = port {
        options.push(HostOption::new("Port", port.to_string()));
    }
    if let Some(proxy_jump) = proxy_jump {
        options.push(HostOption::new("ProxyJump", proxy_jump));
    }
    let mut config = before.clone();
    config.upsert_host(&HostEdit {
        id: None,
        patterns: vec![alias.clone()],
        options,
    })?;
    // Nothing that runs a program comes from another computer.
    if !config.added_risky_directives(&before).is_empty() {
        return Err(AppError::invalid("the host would run a program"));
    }
    config.save(&state.paths.config, &state.backup_dir)?;

    // The server's keys are trusted only for a host this computer has none
    // for: keys of its own are never joined by another computer's.
    let address = host_name.as_deref().unwrap_or(&alias);
    let port = port.unwrap_or(22);
    let mut known = KnownHosts::load(&state.paths.known_hosts)?;
    let mine = known.keys_for(address, port);
    let theirs: Vec<(String, String)> = host_keys
        .iter()
        .map(|key| (key.key_type.clone(), key.key.clone()))
        .collect();
    let differ = !mine.is_empty() && theirs.iter().any(|key| !mine.contains(key));
    if mine.is_empty() && !theirs.is_empty() {
        let mut added = false;
        for (key_type, key) in &theirs {
            added |= known.add_key(address, port, key_type, key)?;
        }
        if added {
            known.save(&state.paths.known_hosts, &state.backup_dir)?;
        }
    }
    Ok((alias, differ))
}

/// `alias`, or `alias-2`, `alias-3`… if a host of the file has it already.
fn free_alias(config: &SshConfig, alias: &str) -> String {
    let taken = |name: &str| {
        config
            .hosts()
            .iter()
            .any(|host| host.patterns.iter().any(|p| p.eq_ignore_ascii_case(name)))
    };
    if !taken(alias) {
        return alias.to_owned();
    }
    (2..1000)
        .map(|n| format!("{alias}-{n}"))
        .find(|name| !taken(name))
        .unwrap_or_else(|| format!("{alias}-new"))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::fs;

    use sshkm_core::p2p::protocol::ItemSummary;

    use super::*;

    #[test]
    fn taken_aliases_get_a_number() {
        let config = SshConfig::parse("Host prod\n  HostName a\nHost prod-2 staging\n  User b\n");
        assert_eq!(free_alias(&config, "new"), "new");
        assert_eq!(free_alias(&config, "prod"), "prod-3");
        assert_eq!(free_alias(&config, "STAGING"), "STAGING-2");
    }

    const HOSTS: &str = "\
127.0.0.1 localhost
# >>> sshkm: dev
10.0.4.12 api.dev.local api # the API
# 10.0.4.13 db.dev.local
127.0.0.1 localhost web.dev.local
fe80::1%lo0 router.dev.local
10.0.4.20 tmp.dev.local # sshkm-until=2026-11-05T09:00:00Z
# <<< sshkm: dev
# >>> sshkm: system
::1 localhost
# <<< sshkm: system
";

    #[test]
    fn sends_a_group_without_the_systems_names() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        fs::write(&path, HOSTS).unwrap();
        let item = hosts_group(&path, "dev").unwrap();
        let entry = |address: &str, names: &[&str], enabled, expires: Option<&str>| HostsEntry {
            address: address.into(),
            names: names.iter().map(|&n| n.to_owned()).collect(),
            enabled,
            expires: expires.map(str::to_owned),
        };
        assert_eq!(
            item,
            Item::HostsGroup {
                name: "dev".into(),
                entries: vec![
                    entry("10.0.4.12", &["api.dev.local", "api"], true, None),
                    entry("10.0.4.13", &["db.dev.local"], false, None),
                    entry("127.0.0.1", &["web.dev.local"], true, None),
                    entry(
                        "10.0.4.20",
                        &["tmp.dev.local"],
                        true,
                        Some("2026-11-05T09:00:00Z")
                    ),
                ],
            }
        );
        assert!(item.check().is_ok());
        assert!(matches!(
            item.summary(),
            ItemSummary::HostsGroup { entries: 4, .. }
        ));
        assert!(hosts_group(&path, "system").is_err());
        assert!(hosts_group(&path, "nope").is_err());
    }

    #[test]
    fn a_received_group_waits_as_a_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        fs::write(&path, HOSTS).unwrap();
        let Item::HostsGroup { entries, .. } = hosts_group(&path, "dev").unwrap() else {
            unreachable!()
        };
        let group = group_draft(&path, 7, Some("MacBook"), "dev", &entries).unwrap();
        assert_eq!(group.id, 7);
        assert_eq!(group.from.as_deref(), Some("MacBook"));
        assert_eq!(group.entries.len(), 4);
        assert!(
            group
                .entries
                .iter()
                .all(|e| e.group.as_deref() == Some("dev"))
        );
        // Nothing is written until the user saves it.
        assert_eq!(fs::read_to_string(&path).unwrap(), HOSTS);

        // What saving would refuse is refused now.
        let mut bad = entries;
        bad[0].names = vec!["localhost".into()];
        assert!(group_draft(&path, 7, None, "dev", &bad).is_err());
    }

    #[test]
    fn a_received_key_is_saved_once() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(".ssh");
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBIZFNq0hlvHGZ/oas65Ba4jkcFEy3dX/aRZy70M73oL aziz@mac";
        let remembered = RefCell::new(Vec::new());
        let remember = |fp: &str| {
            remembered.borrow_mut().push(fp.to_owned());
            Ok(())
        };
        assert_eq!(
            save_key(&dir, "MacBook", "id_ed25519", line, remember).unwrap(),
            "id_ed25519-MacBook"
        );
        assert_eq!(
            *remembered.borrow(),
            ["SHA256:76vvbGumhP/HpDH4tlyySHWs5hgRZJHr2wQ7hSDwRK8"]
        );
        // The same key again: it is there already.
        assert_eq!(
            save_key(&dir, "MacBook", "work", line, |_| unreachable!()).unwrap(),
            "id_ed25519-MacBook"
        );
        assert_eq!(keys::scan(&dir).unwrap().keys.len(), 1);
        assert!(save_key(&dir, "x", "id", "ssh-ed25519 AAAA", |_| Ok(())).is_err());
    }
}
