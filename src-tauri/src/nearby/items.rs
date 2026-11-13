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
//! names elsewhere may cover, or that a `known_hosts` file `ssh` reads
//! trusts a key for gets a number; and the server's keys go in only for a
//! host those files trust nothing for. When settings here would give its
//! server access to this computer, the user allows it in a system dialog.
//!
//! A server's password goes with where its alias leads on the sender's
//! computer, and is saved for an alias here only if that one leads to the
//! same server; otherwise for no host.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use ssh_key::{HashAlg, PublicKey};
use sshkm_core::config::{HostEdit, HostEntry, HostKind, HostOption, Risk, SshConfig};
use sshkm_core::hosts_file::{HostsChange, HostsEntryEdit, HostsFile, is_system_name};
use sshkm_core::keys;
use sshkm_core::known_hosts::KnownHosts;
use sshkm_core::p2p::protocol::{EnvVariable, HostKey, HostsEntry, Item, ItemSummary, Server};
use sshkm_core::paths::{SshPaths, expand_tilde_in};
use sshkm_core::sync::host_keys::trusted_in;
use sshkm_core::vault::{EntryInput, EntryKind, SecretField, envs};
use sshkm_core::{ErrorCode, ExposeSecret, SecretString, fsutil};
use tauri::AppHandle;

use super::pairing::PairingFailure;
use super::{Nearby, prompt};
use crate::commands::keys::find_key;
use crate::confirm;
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
    /// A secret environment from the vault, with its values.
    Environment {
        #[serde(rename = "envId")]
        env_id: String,
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
                server: None,
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
        SendRequest::Environment { env_id } => state.vault.with(app, |vault| {
            let env = vault.environment(env_id)?;
            // Where it is, for the other device: its project and part there.
            let label = vault.env_label(&env.summary);
            let variables = vault
                .env_variables(env_id)?
                .into_iter()
                .map(|var| EnvVariable {
                    value: var.value.expose_secret().to_owned(),
                    name: var.name,
                    secret: var.secret,
                    note: var.note,
                })
                .collect();
            Ok(Item::Environment {
                project: label,
                name: env.summary.name,
                notes: env.notes,
                variables,
            })
        })?,
    };
    let item = with_server(item);
    item.check()
        .map_err(|error| AppError::invalid(format!("it can't be sent as it is: {error}")))?;
    Ok(item)
}

/// `item`, and if it is a server's password, where its alias leads here,
/// which the receiver holds against its own hosts. Without that, it goes
/// for no host, so no version binds it to a name that leads elsewhere there.
fn with_server(item: Item) -> Item {
    match item {
        Item::Password {
            host: Some(alias),
            title,
            username,
            password,
            url,
            notes,
            otp,
            ..
        } => {
            let server = resolve_server(&alias);
            Item::Password {
                host: server.is_some().then_some(alias),
                server,
                title,
                username,
                password,
                url,
                notes,
                otp,
            }
        }
        item => item,
    }
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
        Item::Password { .. } => store_password(&state, app, item),
        Item::Host { .. } => {
            let ItemSummary::Host { address, .. } = item.summary() else {
                unreachable!("a host's summary is a host's")
            };
            let file = state.paths.config.display().to_string();
            let allow = |alias: &str, lines: &[String]| {
                let prompt =
                    prompt::host_access(peer.unwrap_or_default(), alias, &address, &file, lines);
                confirm::require(app, &prompt.title, &prompt.body, &prompt.approve).is_ok()
            };
            store_host(
                &state.paths,
                &state.backup_dir,
                item,
                &global_known_hosts(),
                allow,
            )
            .map_err(|error| match error.code() {
                ErrorCode::Cancelled => PairingFailure::Turned,
                _ => not_saved(error),
            })
        }
        Item::HostsGroup { name, entries } => {
            let group =
                group_draft(&state.hosts_file, id, peer, name, entries).map_err(not_saved)?;
            nearby.keep_group(group);
            Ok((name.clone(), false))
        }
        Item::Environment {
            project,
            name,
            notes,
            variables,
        } => {
            let variables: Vec<envs::EnvVariable> = variables
                .iter()
                .map(|var| envs::EnvVariable {
                    name: var.name.clone(),
                    value: SecretString::from(var.value.as_str()),
                    secret: var.secret,
                    note: var.note.clone(),
                })
                .collect();
            let (_, name) = state
                .vault
                .change(app, &state.backup_dir, |vault| {
                    Ok(vault.add_received_environment(project, name, notes, &variables)?)
                })
                .map_err(|error| match error.code() {
                    ErrorCode::VaultLocked => PairingFailure::VaultLocked,
                    _ => PairingFailure::NotSaved,
                })?;
            Ok((envs::label(Some(project), &name), false))
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
        Item::Unknown => Err(PairingFailure::Unsupported),
    }
}

/// Saves a password from another computer as a new entry: for a host here
/// only if it leads where the sender's did, since the terminal gives the
/// password, and the 2FA code, to the server the alias leads to here.
fn store_password(
    state: &AppState,
    app: &AppHandle,
    item: &Item,
) -> Result<(String, bool), PairingFailure> {
    let Item::Password {
        title,
        username,
        password,
        url,
        notes,
        otp,
        host,
        server,
    } = item
    else {
        return Err(PairingFailure::Broken);
    };
    let host = match (host, server) {
        (Some(alias), Some(server)) => SshConfig::load(&state.paths.config)
            .ok()
            .and_then(|config| bind(&config, alias, server, resolve_server)),
        _ => None,
    };
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
        host,
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
/// from the ones trusted here. `global` are the system's `known_hosts`
/// files. When settings here would give the host's server access to this
/// computer (`ForwardAgent` of a `Host *.corp` block, say), `allow` is
/// asked with the alias and those settings; on a no nothing is saved and
/// it fails with `cancelled`.
fn store_host(
    paths: &SshPaths,
    backup_dir: &Path,
    item: &Item,
    global: &[PathBuf],
    allow: impl FnOnce(&str, &[String]) -> bool,
) -> AppResult<(String, bool)> {
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
    // `ssh` trusts keys from more files than this one: a key or a
    // certificate authority trusted there counts too.
    let mut trusted = known_hosts_elsewhere(paths, &configs, global);
    trusted.push(known.clone());
    let alias = free_alias(&configs, &trusted, sent, port.unwrap_or(22));
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
    // servers less strictly comes from another computer.
    let added = config.added_risky_directives(&before);
    if added
        .iter()
        .any(|directive| directive.risk != Risk::Destination)
    {
        return Err(AppError::invalid("the host would run a program"));
    }
    // Where the host leads is what the user saw and accepted; but settings
    // here that give a server access to this computer (a `ForwardAgent` of
    // a block that covers the alias) would give it to that server too. The
    // user allows that in a system dialog, as for any change of which
    // server gets such access.
    let mut access = access_lines(&configs, &alias);
    if access.is_empty() {
        access = added
            .iter()
            .map(|d| {
                format!(
                    "{}: {} {}",
                    d.block.as_deref().unwrap_or("*"),
                    d.key,
                    d.value
                )
            })
            .collect();
    }
    if !access.is_empty() {
        if !allow(&alias, &access) {
            return Err(AppError::new(ErrorCode::Cancelled, "not allowed"));
        }
        // The dialog may have been open a while: an edit made meanwhile is
        // never overwritten.
        fsutil::ensure_revision(
            &paths.config,
            &SshConfig::load(&paths.config)?.revision(),
            &before.revision(),
        )?;
        fsutil::ensure_revision(
            &paths.known_hosts,
            &KnownHosts::load(&paths.known_hosts)?.revision(),
            &known.revision(),
        )?;
    }
    config.save(&paths.config, backup_dir)?;

    // The server's keys are trusted only for a host this computer trusts
    // nothing for: keys of its own, or a certificate authority's, are never
    // joined by another computer's.
    let address = host_name.unwrap_or(&alias);
    let port = port.unwrap_or(22);
    let mine: Vec<(String, String)> = trusted
        .iter()
        .flat_map(|file| file.keys_for(address, port))
        .collect();
    let theirs: Vec<(String, String)> = host_keys
        .iter()
        .map(|key| (key.key_type.clone(), key.key.clone()))
        .collect();
    let trusted = trusted_in(&trusted, address, port);
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
/// includes) names it, one of the `known_hosts` files (`trusted`) trusts a
/// key for it on `port` or 22, or a block that sets where names lead may
/// lead it somewhere. A number makes a name this computer never used, so
/// only the first two count for it.
fn free_alias(configs: &[SshConfig], trusted: &[KnownHosts], alias: &str, port: u16) -> String {
    let hosts: Vec<HostEntry> = configs.iter().flat_map(SshConfig::hosts).collect();
    let used = |name: &str| {
        hosts.iter().any(|host| {
            host.kind == HostKind::Host
                && host.patterns.iter().any(|p| p.eq_ignore_ascii_case(name))
        }) || trusted_in(trusted, name, port)
            || trusted_in(trusted, name, 22)
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

/// The settings of `configs` that give a server access to this computer
/// (see [`Risk::ServerAccess`]) and may apply to `alias`, each as
/// `Host …: Keyword value` (or without the block, for one before the
/// first block).
fn access_lines(configs: &[SshConfig], alias: &str) -> Vec<String> {
    configs
        .iter()
        .flat_map(SshConfig::risky_directives)
        .filter(|d| d.risk == Risk::ServerAccess)
        .filter(|d| match &d.block {
            None => true,
            Some(block) => {
                let mut words = block.split_whitespace();
                let keyword = words.next().unwrap_or_default();
                if keyword.eq_ignore_ascii_case("host") {
                    let patterns: Vec<String> = words.map(|word| word.replace('"', "")).collect();
                    covers(&patterns, alias)
                } else {
                    // A `Match` block may apply to any host.
                    true
                }
            }
        })
        .map(|d| match &d.block {
            Some(block) => format!("{block}: {} {}", d.key, d.value),
            None => format!("{} {}", d.key, d.value),
        })
        .collect()
}

/// The system's `known_hosts` files, which `ssh` reads after the user's.
fn global_known_hosts() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("ProgramData")
            .map(|data| {
                let dir = PathBuf::from(data).join("ssh");
                vec![dir.join("ssh_known_hosts"), dir.join("ssh_known_hosts2")]
            })
            .unwrap_or_default()
    }
    #[cfg(not(windows))]
    {
        vec![
            PathBuf::from("/etc/ssh/ssh_known_hosts"),
            PathBuf::from("/etc/ssh/ssh_known_hosts2"),
        ]
    }
}

/// The `known_hosts` files `ssh` reads besides the user's own: its
/// `known_hosts2`, the system's (`global`), and those `UserKnownHostsFile`
/// and `GlobalKnownHostsFile` name in `configs`, as far as their paths say
/// where they are (`~` and `%d` stand for the home folder; one with
/// another `%` token is left out). A file that is missing is empty, one
/// that can't be read is left out.
pub(super) fn known_hosts_elsewhere(
    paths: &SshPaths,
    configs: &[SshConfig],
    global: &[PathBuf],
) -> Vec<KnownHosts> {
    let mut files: Vec<PathBuf> = vec![paths.dir.join("known_hosts2")];
    files.extend_from_slice(global);
    let home = paths.home.to_string_lossy();
    for directive in configs.iter().flat_map(SshConfig::risky_directives) {
        let key = directive.key.to_ascii_lowercase();
        if key != "userknownhostsfile" && key != "globalknownhostsfile" {
            continue;
        }
        for value in directive.value.split_whitespace() {
            let value = value.replace('"', "").replace("%d", &home);
            if value.eq_ignore_ascii_case("none") || value.contains('%') {
                continue;
            }
            let path = expand_tilde_in(&value, &paths.home);
            if path.is_absolute() {
                files.push(path);
            }
        }
    }
    files.sort();
    files.dedup();
    files
        .iter()
        .filter(|path| **path != paths.known_hosts)
        .filter_map(|path| KnownHosts::load(path).ok())
        .collect()
}

/// [`known_hosts_elsewhere`] for the config at `paths` and the files it
/// includes, and the system's files.
pub(super) fn trusted_elsewhere(paths: &SshPaths) -> Vec<KnownHosts> {
    let configs = SshConfig::load(&paths.config)
        .map(|config| {
            let mut configs = included(&config, paths);
            configs.push(config);
            configs
        })
        .unwrap_or_default();
    known_hosts_elsewhere(paths, &configs, &global_known_hosts())
}

/// Where `alias` leads, as `ssh -G` works it out with this computer's
/// configuration; `None` if it can't, or if a name in it is not one a
/// [`Server`] may have.
fn resolve_server(alias: &str) -> Option<Server> {
    let output = crate::process::run("ssh", &["-G", "--", alias], Duration::from_secs(10)).ok()?;
    if !output.success {
        return None;
    }
    parse_server(&output.stdout)
}

/// A [`Server`] from `ssh -G` output: one `keyword value` per line.
fn parse_server(text: &str) -> Option<Server> {
    let value = |key: &str| {
        text.lines().find_map(|line| {
            let (k, v) = line.split_once(' ')?;
            (k == key).then(|| v.trim().to_owned())
        })
    };
    let server = Server {
        user: value("user")?,
        host_name: value("hostname")?,
        port: value("port")?.parse().ok()?,
        proxy_jump: value("proxyjump").filter(|jump| jump != "none"),
    };
    server.check().is_ok().then_some(server)
}

/// The alias a server's password from another computer is saved for:
/// the one it was sent for, or another `Host` alias of `config`, that
/// leads to the same `server` here, as `resolve` (`ssh -G`) works it out.
/// `None` when none does: then it is saved for no host, since the terminal
/// would give it to whatever server the alias leads to here.
fn bind(
    config: &SshConfig,
    sent: &str,
    server: &Server,
    resolve: impl Fn(&str) -> Option<Server>,
) -> Option<String> {
    let (mut named, mut leading): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    // The alias it was sent for first, then those whose block names the
    // server: `ssh -G` has the last word on each.
    for host in config
        .hosts()
        .into_iter()
        .filter(|host| host.kind == HostKind::Host && !host.is_wildcard)
    {
        for pattern in host.patterns.iter().filter(|p| !p.starts_with('!')) {
            let list = if pattern.eq_ignore_ascii_case(sent) {
                &mut named
            } else if host
                .host_name
                .as_deref()
                .unwrap_or(pattern)
                .eq_ignore_ascii_case(&server.host_name)
            {
                &mut leading
            } else {
                continue;
            };
            if !list.contains(pattern) {
                list.push(pattern.clone());
            }
        }
    }
    named
        .into_iter()
        .chain(leading)
        .find(|alias| resolve(alias).is_some_and(|here| here.same(server)))
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
        let none = [KnownHosts::parse("")];
        let free = |alias| free_alias(std::slice::from_ref(&config), &none, alias, 22);
        assert_eq!(free("new"), "new");
        assert_eq!(free("prod"), "prod-3");
        assert_eq!(free("STAGING"), "STAGING-2");

        // A name known_hosts trusts a key for, on port 22 or the host's.
        // Or one of the other files `ssh` reads.
        let known = [
            KnownHosts::parse(&format!(
                "github.com ssh-ed25519 {KEY_HERE}\n\
                 [git.example.com]:2222 ssh-ed25519 {KEY_HERE}\n\
                 @revoked * ssh-ed25519 {KEY_THEIRS}\n"
            )),
            KnownHosts::parse(&format!(
                "@cert-authority *.corp.example.com ssh-ed25519 {KEY_HERE}\n"
            )),
        ];
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
        let (alias, differ) = store_host(&paths, &backups, &item, &[], unasked).unwrap();
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
        let (alias, differ) = store_host(&paths, &backups, &item, &[], unasked).unwrap();
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

    /// What `store_host` is given when nothing should ask the user.
    fn unasked(alias: &str, lines: &[String]) -> bool {
        panic!("asked about {alias}: {lines:?}")
    }

    /// Settings here that give a server access to this computer apply to a
    /// received host too: it comes in only after the user's yes in the
    /// system dialog, which lists them.
    #[test]
    fn a_host_that_settings_here_give_access_comes_in_only_when_allowed() {
        let config = "Host *.corp\n  ForwardAgent yes\n  IdentityFile ~/.ssh/corp\n\n\
                      Host *\n  ServerAliveInterval 30\n";
        let (home, paths) = ssh_dir(config, "");
        let backups = home.path().join("backups");
        let item = received("build.corp", Some("192.168.1.66"));
        let mut asked = Vec::new();
        let refused = store_host(&paths, &backups, &item, &[], |alias, lines| {
            asked.push((alias.to_owned(), lines.to_vec()));
            false
        });
        assert_eq!(refused.unwrap_err().code(), ErrorCode::Cancelled);
        assert_eq!(
            asked,
            [(
                "build.corp".to_owned(),
                vec!["Host *.corp: ForwardAgent yes".to_owned()]
            )]
        );
        assert_eq!(fs::read_to_string(&paths.config).unwrap(), config);
        assert_eq!(fs::read_to_string(&paths.known_hosts).unwrap(), "");

        let (alias, _) = store_host(&paths, &backups, &item, &[], |_, _| true).unwrap();
        assert_eq!(alias, "build.corp");
        let hosts = SshConfig::load(&paths.config).unwrap().hosts();
        assert!(hosts.iter().any(|host| host.patterns == ["build.corp"]));

        // The same for every host, and for a `Match` block.
        for config in [
            "Host *\n  ForwardAgent yes\n",
            "Match user git\n  ForwardX11 yes\n",
        ] {
            let (home, paths) = ssh_dir(config, "");
            let mut asked = 0;
            let item = received("build", Some("192.168.1.66"));
            let stored = store_host(&paths, &home.path().join("b"), &item, &[], |_, _| {
                asked += 1;
                true
            });
            assert_eq!(stored.unwrap().0, "build");
            assert_eq!(asked, 1, "{config}");
        }

        // A block that doesn't cover it asks nothing.
        let (home, paths) = ssh_dir("Host *.corp\n  ForwardAgent yes\n", "");
        let item = received("build.lab", Some("192.168.1.66"));
        let stored = store_host(&paths, &home.path().join("b"), &item, &[], unasked);
        assert_eq!(stored.unwrap().0, "build.lab");
    }

    #[test]
    fn a_host_a_certificate_authority_vouches_for_gets_no_key() {
        let known = format!("@cert-authority *.corp.example.com ssh-ed25519 {KEY_HERE}\n");
        let (home, paths) = ssh_dir("", &known);
        let item = received("db", Some("db.corp.example.com"));
        let (alias, differ) =
            store_host(&paths, &home.path().join("backups"), &item, &[], unasked).unwrap();
        assert_eq!((alias.as_str(), differ), ("db", true));
        assert_eq!(fs::read_to_string(&paths.known_hosts).unwrap(), known);
    }

    /// `ssh` reads the system's `known_hosts` and `known_hosts2` too: a key
    /// or a certificate authority trusted there counts as trusted here.
    #[test]
    fn keys_trusted_in_the_other_known_hosts_files_count() {
        let (home, paths) = ssh_dir("", "");
        let system = home.path().join("ssh_known_hosts");
        fs::write(
            &system,
            format!("@cert-authority *.corp.example.com ssh-ed25519 {KEY_HERE}\n"),
        )
        .unwrap();
        let item = received("db", Some("db.corp.example.com"));
        let global = [system.clone()];
        let (alias, differ) =
            store_host(&paths, &home.path().join("b"), &item, &global, unasked).unwrap();
        assert_eq!((alias.as_str(), differ), ("db", true));
        assert_eq!(fs::read_to_string(&paths.known_hosts).unwrap(), "");

        // known_hosts2, and a file the config names.
        fs::write(
            paths.dir.join("known_hosts2"),
            format!("git.example.com ssh-ed25519 {KEY_HERE}\n"),
        )
        .unwrap();
        fs::write(
            home.path().join("team_hosts"),
            format!("10.0.4.12 ssh-ed25519 {KEY_HERE}\n"),
        )
        .unwrap();
        fs::write(
            &paths.config,
            "Host *\n  UserKnownHostsFile ~/.ssh/known_hosts %d/team_hosts\n",
        )
        .unwrap();
        for host_name in ["git.example.com", "10.0.4.12"] {
            let item = received("other", Some(host_name));
            store_host(&paths, &home.path().join("b"), &item, &[], unasked).unwrap();
        }
        assert_eq!(fs::read_to_string(&paths.known_hosts).unwrap(), "");
        // What nothing trusts gets the sender's key.
        let item = received("new", Some("192.168.1.66"));
        store_host(&paths, &home.path().join("b"), &item, &[], unasked).unwrap();
        let known = KnownHosts::load(&paths.known_hosts).unwrap();
        assert_eq!(known.keys_for("192.168.1.66", 22), ed25519(KEY_THEIRS));
    }

    fn server(user: &str, host_name: &str, port: u16) -> Server {
        Server {
            user: user.into(),
            host_name: host_name.into(),
            port,
            proxy_jump: None,
        }
    }

    #[test]
    fn a_servers_password_is_saved_only_for_an_alias_that_leads_there() {
        // Here `prod` is another server; `prod-2`, the host received with
        // it, is the sender's.
        let config = SshConfig::parse(
            "Host prod\n  HostName 203.0.113.9\n\nHost prod-2\n  HostName 10.0.4.12\n  \
             User deploy\n\nHost db\n  HostName db.example.com\n",
        );
        let resolve = |alias: &str| match alias {
            "prod" => Some(server("deploy", "203.0.113.9", 22)),
            "prod-2" => Some(server("deploy", "10.0.4.12", 22)),
            "db" => Some(server("deploy", "db.example.com", 22)),
            _ => None,
        };
        let theirs = server("deploy", "10.0.4.12", 22);
        assert_eq!(
            bind(&config, "prod", &theirs, resolve).as_deref(),
            Some("prod-2")
        );
        // The alias it was sent for, when it leads there.
        let db = server("deploy", "DB.example.com", 22);
        assert_eq!(bind(&config, "db", &db, resolve).as_deref(), Some("db"));
        // Another port, account or way there is another server.
        for other in [
            server("deploy", "10.0.4.12", 2222),
            server("root", "10.0.4.12", 22),
            Server {
                proxy_jump: Some("bastion".into()),
                ..server("deploy", "10.0.4.12", 22)
            },
        ] {
            assert_eq!(bind(&config, "prod", &other, resolve), None);
        }
        // Where the config seems to lead is not enough: `ssh -G` decides.
        assert_eq!(bind(&config, "prod", &theirs, |_| None), None);
    }

    #[test]
    fn reads_where_an_alias_leads_from_ssh() {
        let output = "user deploy\nhostname 10.0.4.12\nport 2222\nproxyjump bastion\n\
                      identityfile ~/.ssh/id_ed25519\n";
        assert_eq!(
            parse_server(output),
            Some(Server {
                proxy_jump: Some("bastion".into()),
                ..server("deploy", "10.0.4.12", 2222)
            })
        );
        let plain = "user deploy\nhostname 10.0.4.12\nport 22\nproxyjump none\n";
        assert_eq!(parse_server(plain), Some(server("deploy", "10.0.4.12", 22)));
        assert_eq!(parse_server("user deploy\nport 22\n"), None);
        assert_eq!(
            parse_server("user a b\nhostname h\nport 22\n"),
            None,
            "not a name"
        );
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
        let none = [KnownHosts::parse("")];
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
