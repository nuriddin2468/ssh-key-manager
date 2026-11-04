//! The items Nearby sends: read here from the vault, `~/.ssh` and the hosts
//! file when the user sends one, and saved there when the user accepts one.
//! The UI only names what to send; secrets never pass through it.
//!
//! A hosts file group is not written when it comes: it waits here
//! ([`ReceivedGroup`]) until the Hosts file page shows the change, which the
//! user saves with the administrator password.
//!
//! A host never takes over a name `ssh` reaches on this computer already: an
//! alias that the config (or a file it includes) has, that a block leading
//! names elsewhere may cover, or that `known_hosts` trusts a key for gets a
//! number; and the server's keys go in only for a host `known_hosts` trusts
//! nothing for.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use ssh_key::{HashAlg, PublicKey};
use sshkm_core::ErrorCode;
use sshkm_core::config::{HostEdit, HostEntry, HostKind, HostOption, Risk, SshConfig};
use sshkm_core::hosts_file::{HostsChange, HostsEntryEdit, HostsFile, is_system_name};
use sshkm_core::keys;
use sshkm_core::known_hosts::{HostMarker, KnownHosts};
use sshkm_core::p2p::protocol::{HostKey, HostsEntry, Item};
use sshkm_core::paths::{SshPaths, expand_tilde_in};
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
        Item::Host { .. } => store_host(&state.paths, &state.backup_dir, item).map_err(not_saved),
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

/// Saves a received host in the config at `paths`, and its server's keys
/// in `known_hosts`. Returns the alias it got and whether the keys differ
/// from the ones trusted here.
fn store_host(paths: &SshPaths, backup_dir: &Path, item: &Item) -> AppResult<(String, bool)> {
    let Item::Host {
        alias: sent,
        host_name,
        user,
        port,
        proxy_jump,
        host_keys,
    } = item
    else {
        return Err(AppError::invalid("not a host"));
    };
    let before = SshConfig::load(&paths.config)?;
    let mut known = KnownHosts::load(&paths.known_hosts)?;
    let mut configs = included(&before, paths);
    configs.push(before.clone());
    let alias = free_alias(&configs, &known, sent, port.unwrap_or(22));
    // A host that got a number still leads where the sender's alias did.
    let host_name = host_name
        .as_deref()
        .or_else(|| (alias != *sent).then_some(sent.as_str()));
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
    // Nothing that runs a program, opens this computer to a server or checks
    // servers less strictly comes from another computer. Where the host
    // leads is what the user saw and accepted, so a `ForwardAgent` of a
    // `Host *` block reaching it is no reason to refuse it.
    if config
        .added_risky_directives(&before)
        .iter()
        .any(|directive| directive.risk != Risk::Destination)
    {
        return Err(AppError::invalid("the host would run a program"));
    }
    config.save(&paths.config, backup_dir)?;

    // The server's keys are trusted only for a host this computer trusts
    // nothing for: keys of its own, or a certificate authority's, are never
    // joined by another computer's.
    let address = host_name.unwrap_or(&alias);
    let port = port.unwrap_or(22);
    let mine = known.keys_for(address, port);
    let theirs: Vec<(String, String)> = host_keys
        .iter()
        .map(|key| (key.key_type.clone(), key.key.clone()))
        .collect();
    let trusted = trusts(&known, address, port);
    let differ = trusted && theirs.iter().any(|key| !mine.contains(key));
    if !trusted && !theirs.is_empty() {
        let mut added = false;
        for (key_type, key) in &theirs {
            added |= known.add_key(address, port, key_type, key)?;
        }
        if added {
            known.save(&paths.known_hosts, backup_dir)?;
        }
    }
    Ok((alias, differ))
}

/// `alias`, or `alias-2`, `alias-3`… if `ssh` takes it already on this
/// computer: a `Host` line of `configs` (the config and the files it
/// includes) names it, `known_hosts` trusts a key for it on `port` or 22,
/// or a block that sets where names lead may lead it somewhere. A number
/// makes a name this computer never used, so only the first two count for
/// it.
fn free_alias(configs: &[SshConfig], known: &KnownHosts, alias: &str, port: u16) -> String {
    let hosts: Vec<HostEntry> = configs.iter().flat_map(SshConfig::hosts).collect();
    let used = |name: &str| {
        hosts.iter().any(|host| {
            host.kind == HostKind::Host
                && host.patterns.iter().any(|p| p.eq_ignore_ascii_case(name))
        }) || trusts(known, name, port)
            || trusts(known, name, 22)
    };
    let led = hosts.iter().any(|host| leads(host, alias));
    if !used(alias) && !led {
        return alias.to_owned();
    }
    (2..1000)
        .map(|n| format!("{alias}-{n}"))
        .find(|name| !used(name))
        .unwrap_or_else(|| format!("{alias}-new"))
}

/// Whether `host` sets where `name` leads (`HostName` or `HostKeyAlias`).
/// What a `Match` block applies to is not worked out here: one that sets
/// either may apply to any name.
fn leads(host: &HostEntry, name: &str) -> bool {
    let sets = host.options.iter().any(|option| {
        option.key.eq_ignore_ascii_case("hostname")
            || option.key.eq_ignore_ascii_case("hostkeyalias")
    });
    sets && match host.kind {
        HostKind::Host => covers(&host.patterns, name),
        HostKind::Match => true,
    }
}

/// Whether a `Host` line's patterns apply to `name`, as `ssh` reads them:
/// one of them fits it and none that starts with `!` does.
fn covers(patterns: &[String], name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let mut fit = false;
    for pattern in patterns {
        let pattern = pattern.to_ascii_lowercase();
        match pattern.strip_prefix('!') {
            Some(negated) if fits(negated, &name) => return false,
            Some(_) => {}
            None => fit |= fits(&pattern, &name),
        }
    }
    fit
}

/// Whether `name` fits `pattern`, in which `*` stands for any run of
/// characters and `?` for one.
fn fits(pattern: &str, name: &str) -> bool {
    let (pattern, name) = (pattern.as_bytes(), name.as_bytes());
    let (mut p, mut n) = (0, 0);
    // Where the last `*` was, and how much of the name it took so far.
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some((p, n));
            p += 1;
        } else if let Some((at, took)) = star {
            p = at + 1;
            n = took + 1;
            star = Some((at, took + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&c| c == b'*')
}

/// Whether `known_hosts` trusts a key for `host` on `port`: a key of its
/// own, or a certificate authority's. A revoked key trusts nothing.
fn trusts(known: &KnownHosts, host: &str, port: u16) -> bool {
    known
        .matches(host, port)
        .iter()
        .any(|entry| entry.marker != HostMarker::Revoked)
}

/// Most files [`included`] reads, and how deep it follows `Include`s.
const MAX_INCLUDED: usize = 64;
const INCLUDE_DEPTH: usize = 4;

/// The files `config` includes, and those they include, as `ssh` finds
/// them: a relative path in the `.ssh` folder, `*` and `?` in a file's
/// name. A file that can't be read is left out.
fn included(config: &SshConfig, paths: &SshPaths) -> Vec<SshConfig> {
    let mut found = Vec::new();
    let mut pending: Vec<(String, usize)> = config
        .includes()
        .into_iter()
        .map(|path| (path, 1))
        .collect();
    while let Some((include, depth)) = pending.pop() {
        for path in include_paths(&include, paths) {
            if found.len() == MAX_INCLUDED {
                return found;
            }
            let Ok(file) = SshConfig::load(&path) else {
                continue;
            };
            if depth < INCLUDE_DEPTH {
                pending.extend(file.includes().into_iter().map(|path| (path, depth + 1)));
            }
            found.push(file);
        }
    }
    found
}

/// The files one `Include` argument names.
fn include_paths(include: &str, paths: &SshPaths) -> Vec<PathBuf> {
    let path = expand_tilde_in(include, &paths.home);
    let path = if path.is_absolute() {
        path
    } else {
        paths.dir.join(path)
    };
    let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(OsStr::to_str)) else {
        return Vec::new();
    };
    if !name.contains(['*', '?']) {
        return vec![path];
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_name().to_str().is_some_and(|file| {
                (!file.starts_with('.') || name.starts_with('.')) && fits(name, file)
            })
        })
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect();
    files.sort();
    files
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::fs;

    use sshkm_core::p2p::protocol::ItemSummary;

    use super::*;

    const KEY_HERE: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIBIZFNq0hlvHGZ/oas65Ba4jkcFEy3dX/aRZy70M73oL";
    const KEY_THEIRS: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIFR8U3VxsN3V7MFbnGqYVNCEWbAVE2k5oNMYoprkbtE8";

    fn ed25519(key: &str) -> Vec<(String, String)> {
        vec![("ssh-ed25519".to_owned(), key.to_owned())]
    }

    #[test]
    fn taken_aliases_get_a_number() {
        let config = SshConfig::parse("Host prod\n  HostName a\nHost prod-2 staging\n  User b\n");
        let none = KnownHosts::parse("");
        let free = |alias| free_alias(std::slice::from_ref(&config), &none, alias, 22);
        assert_eq!(free("new"), "new");
        assert_eq!(free("prod"), "prod-3");
        assert_eq!(free("STAGING"), "STAGING-2");

        // A name known_hosts trusts a key for, on port 22 or the host's.
        let known = KnownHosts::parse(&format!(
            "github.com ssh-ed25519 {KEY_HERE}\n\
             [git.example.com]:2222 ssh-ed25519 {KEY_HERE}\n\
             @cert-authority *.corp.example.com ssh-ed25519 {KEY_HERE}\n\
             @revoked * ssh-ed25519 {KEY_THEIRS}\n"
        ));
        let empty = [SshConfig::default()];
        let free = |alias, port| free_alias(&empty, &known, alias, port);
        assert_eq!(free("GitHub.com", 2222), "GitHub.com-2");
        assert_eq!(free("git.example.com", 2222), "git.example.com-2");
        assert_eq!(free("git.example.com", 22), "git.example.com");
        assert_eq!(free("db.corp.example.com", 22), "db.corp.example.com-2");
        // A revoked key trusts nothing.
        assert_eq!(free("other", 22), "other");

        // A block that leads names elsewhere may lead this one there.
        let config =
            SshConfig::parse("Host *.lab !gw.lab\n  HostName %h.example.com\nHost *\n  User me\n");
        let free = |alias| free_alias(std::slice::from_ref(&config), &none, alias, 22);
        assert_eq!(free("db.lab"), "db.lab-2");
        assert_eq!(free("gw.lab"), "gw.lab");
        assert_eq!(free("prod"), "prod");
        let config = SshConfig::parse("Match host x exec \"true\"\n  HostKeyAlias y\n");
        assert_eq!(free_alias(&[config], &none, "prod", 22), "prod-2");
    }

    #[test]
    fn patterns_fit_as_ssh_reads_them() {
        assert!(fits("*", ""));
        assert!(fits("*.lab", "db.lab"));
        assert!(!fits("*.lab", "db.lab2"));
        assert!(fits("db?", "db1"));
        assert!(fits("a*b*c", "aXXbYc"));
        assert!(!fits("a*b*c", "aXXbY"));
        let patterns = ["*.lab".to_owned(), "!gw.lab".to_owned()];
        assert!(covers(&patterns, "db.LAB"));
        assert!(!covers(&patterns, "gw.lab"));
        assert!(!covers(&patterns[1..], "db.lab"));
    }

    /// A home folder with this `~/.ssh/config` and `known_hosts`.
    fn ssh_dir(config: &str, known: &str) -> (tempfile::TempDir, SshPaths) {
        let home = tempfile::tempdir().unwrap();
        let paths = SshPaths::from_dir(home.path().join(".ssh"));
        fs::create_dir_all(&paths.dir).unwrap();
        fs::write(&paths.config, config).unwrap();
        fs::write(&paths.known_hosts, known).unwrap();
        (home, paths)
    }

    fn received(alias: &str, host_name: Option<&str>) -> Item {
        Item::Host {
            alias: alias.into(),
            host_name: host_name.map(str::to_owned),
            user: Some("git".into()),
            port: None,
            proxy_jump: None,
            host_keys: vec![HostKey {
                key_type: "ssh-ed25519".into(),
                key: KEY_THEIRS.into(),
            }],
        }
    }

    #[test]
    fn a_received_host_never_takes_over_a_name_trusted_here() {
        let (home, paths) = ssh_dir(
            "Host *\n  ServerAliveInterval 60\n",
            &format!("github.com ssh-ed25519 {KEY_HERE}\n"),
        );
        let backups = home.path().join("backups");
        let item = received("github.com", Some("192.168.1.66"));
        let (alias, differ) = store_host(&paths, &backups, &item).unwrap();
        assert_eq!((alias.as_str(), differ), ("github.com-2", false));
        let hosts = SshConfig::load(&paths.config).unwrap().hosts();
        assert!(hosts.iter().all(|host| host.patterns != ["github.com"]));
        let added = hosts.iter().find(|host| host.patterns == ["github.com-2"]);
        assert_eq!(
            added.and_then(|host| host.host_name.as_deref()),
            Some("192.168.1.66")
        );
        // github.com keeps its key alone; the new name's server has the
        // sender's.
        let known = KnownHosts::load(&paths.known_hosts).unwrap();
        assert_eq!(known.keys_for("github.com", 22), ed25519(KEY_HERE));
        assert_eq!(known.keys_for("192.168.1.66", 22), ed25519(KEY_THEIRS));

        // Without a HostName, the host with a number leads where the
        // sender's alias did, and the key trusted for that here stays the
        // only one.
        let item = received("github.com", None);
        let (alias, differ) = store_host(&paths, &backups, &item).unwrap();
        assert_eq!((alias.as_str(), differ), ("github.com-3", true));
        let hosts = SshConfig::load(&paths.config).unwrap().hosts();
        let added = hosts.iter().find(|host| host.patterns == ["github.com-3"]);
        assert_eq!(
            added.and_then(|host| host.host_name.as_deref()),
            Some("github.com")
        );
        let known = KnownHosts::load(&paths.known_hosts).unwrap();
        assert_eq!(known.keys_for("github.com", 22), ed25519(KEY_HERE));
    }

    /// Agent forwarding for every host doesn't keep a host from coming in:
    /// where it leads is what the user saw and accepted.
    #[test]
    fn a_host_is_taken_under_agent_forwarding_for_every_host() {
        let (home, paths) = ssh_dir("Host *\n  ForwardAgent yes\n", "");
        let backups = home.path().join("backups");
        let item = received("build", Some("192.168.1.66"));
        let (alias, _) = store_host(&paths, &backups, &item).unwrap();
        assert_eq!(alias, "build");
        let hosts = SshConfig::load(&paths.config).unwrap().hosts();
        assert!(hosts.iter().any(|host| host.patterns == ["build"]));
    }

    #[test]
    fn a_host_a_certificate_authority_vouches_for_gets_no_key() {
        let known = format!("@cert-authority *.corp.example.com ssh-ed25519 {KEY_HERE}\n");
        let (home, paths) = ssh_dir("", &known);
        let item = received("db", Some("db.corp.example.com"));
        let (alias, differ) = store_host(&paths, &home.path().join("backups"), &item).unwrap();
        assert_eq!((alias.as_str(), differ), ("db", true));
        assert_eq!(fs::read_to_string(&paths.known_hosts).unwrap(), known);
    }

    #[test]
    fn names_in_included_files_are_taken_too() {
        let (_home, paths) = ssh_dir(
            "Include config.d/*\n\nHost *\n  HostName %h.corp.example.com\n",
            "",
        );
        fs::create_dir_all(paths.dir.join("config.d")).unwrap();
        fs::write(
            paths.dir.join("config.d/work"),
            "Host jump\n  HostName 10.0.0.1\nInclude ~/.ssh/more\n",
        )
        .unwrap();
        fs::write(paths.dir.join("config.d/.hidden"), "Host hidden\n").unwrap();
        fs::write(paths.dir.join("more"), "Host deep\n  User me\n").unwrap();
        let config = SshConfig::load(&paths.config).unwrap();
        let mut configs = included(&config, &paths);
        let names: Vec<String> = configs
            .iter()
            .flat_map(SshConfig::hosts)
            .flat_map(|host| host.patterns)
            .collect();
        assert_eq!(names, ["jump", "deep"]);
        configs.push(config);
        let none = KnownHosts::parse("");
        assert_eq!(free_alias(&configs, &none, "jump", 22), "jump-2");
        assert_eq!(free_alias(&configs, &none, "deep", 22), "deep-2");
        // `Host *` leads every name elsewhere: a received one gets a number.
        assert_eq!(free_alias(&configs, &none, "build", 22), "build-2");
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
