//! The items Nearby sends: read here from the vault and `~/.ssh` when the
//! user sends one, and saved there when the user accepts one. The UI only
//! names what to send; secrets never pass through it.

use serde::Deserialize;
use sshkm_core::ErrorCode;
use sshkm_core::config::{HostEdit, HostKind, HostOption, SshConfig};
use sshkm_core::known_hosts::KnownHosts;
use sshkm_core::p2p::protocol::{HostKey, Item};
use sshkm_core::vault::{EntryInput, EntryKind, SecretField};
use sshkm_core::{ExposeSecret, SecretString};
use tauri::AppHandle;

use super::pairing::PairingFailure;
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
    };
    item.check()
        .map_err(|error| AppError::invalid(format!("it can't be sent as it is: {error}")))?;
    Ok(item)
}

/// Saves an item the user accepted. Returns the name it got and whether a
/// host's keys differ from the ones this computer has for it.
pub fn store(
    state: &AppState,
    app: &AppHandle,
    item: &Item,
) -> Result<(String, bool), PairingFailure> {
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
        Item::Host { .. } => store_host(state, item).map_err(|error| {
            log::warn!("nearby: a received host was not saved: {error}");
            PairingFailure::NotSaved
        }),
    }
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
    use super::*;

    #[test]
    fn taken_aliases_get_a_number() {
        let config = SshConfig::parse("Host prod\n  HostName a\nHost prod-2 staging\n  User b\n");
        assert_eq!(free_alias(&config, "new"), "new");
        assert_eq!(free_alias(&config, "prod"), "prod-3");
        assert_eq!(free_alias(&config, "STAGING"), "STAGING-2");
    }
}
