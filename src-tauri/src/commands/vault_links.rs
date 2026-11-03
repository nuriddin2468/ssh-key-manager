//! Where the password vault meets the SSH features: unlocking keys with the
//! passphrases saved in the vault, and checking the vault's entries.
//!
//! A saved passphrase is read and used here, in Rust, and goes no further than
//! the key it decrypts: it never reaches the UI.

use std::collections::{HashMap, HashSet};

use serde::Serialize;
use sshkm_core::agent::AgentClient;
use sshkm_core::config::SshConfig;
use sshkm_core::keys::{self, KeyInfo, UnlockedKey};
use sshkm_core::vault::{
    self, EntryKind, EntrySummary, SecretField, Vault, VaultAuditInput, VaultFinding,
};
use sshkm_core::{ErrorCode, SecretString};
use tauri::{AppHandle, State};

use super::keys::{agent_comment, find_key, private_path};
use super::{Shared, blocking};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::types::VaultState;

/// What [`agent_add_all_from_vault`] did.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct AddFromVaultReport {
    /// Names of the keys added to ssh-agent.
    pub added: Vec<String>,
    /// Keys with a saved passphrase that could not be added.
    pub failed: Vec<AddFromVaultFailure>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct AddFromVaultFailure {
    pub key_id: String,
    pub name: String,
    /// `wrong_passphrase` when the saved passphrase no longer opens the key.
    pub code: ErrorCode,
}

/// The vault's findings, or why there are none.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct VaultAudit {
    pub state: VaultState,
    /// Empty unless the vault is unlocked. Most severe first.
    pub findings: Vec<VaultFinding>,
}

/// Adds a key to ssh-agent with the passphrase saved in the vault. Fails with
/// `vault_locked` while the vault is locked and `not_found` when it has no
/// passphrase for the key.
#[tauri::command]
pub async fn agent_add_from_vault(
    app: AppHandle,
    state: State<'_, Shared>,
    key_id: String,
    lifetime_secs: Option<u32>,
) -> AppResult<()> {
    blocking(&state, move |state| {
        let info = find_key(state, &key_id)?;
        let fingerprint = info
            .fingerprint
            .clone()
            .ok_or_else(|| AppError::not_found(format!("fingerprint of {}", info.name)))?;
        let mut saved = state.vault.with(&app, |vault| {
            saved_passphrases(vault, [fingerprint.as_str()])
        })?;
        let passphrase = saved
            .remove(&fingerprint)
            .ok_or_else(|| AppError::not_found(format!("saved passphrase of {}", info.name)))?;
        let unlocked = decrypt(&info, &passphrase)?;
        add_to_agent(
            state,
            &AgentClient::from_env()?,
            &info,
            &unlocked,
            lifetime_secs,
        )
    })
    .await
}

/// Adds every key in `~/.ssh` that has a saved passphrase and is not in
/// ssh-agent yet. Fails with `vault_locked` while the vault is locked.
#[tauri::command]
pub async fn agent_add_all_from_vault(
    app: AppHandle,
    state: State<'_, Shared>,
    lifetime_secs: Option<u32>,
) -> AppResult<AddFromVaultReport> {
    blocking(&state, move |state| {
        let agent = AgentClient::from_env()?;
        let loaded: HashSet<String> = agent.list()?.into_iter().map(|i| i.fingerprint).collect();
        let candidates = keys_to_add(keys::scan(&state.paths.dir)?.keys, &loaded);
        let fingerprints: Vec<&str> = candidates
            .iter()
            .filter_map(|k| k.fingerprint.as_deref())
            .collect();
        let mut saved = state
            .vault
            .with(&app, |vault| saved_passphrases(vault, fingerprints))?;

        let mut report = AddFromVaultReport::default();
        for info in &candidates {
            let Some(passphrase) = info.fingerprint.as_ref().and_then(|fp| saved.remove(fp)) else {
                continue;
            };
            let result = decrypt(info, &passphrase)
                .and_then(|unlocked| add_to_agent(state, &agent, info, &unlocked, lifetime_secs));
            match result {
                Ok(()) => report.added.push(info.name.clone()),
                Err(error) => {
                    log::warn!("adding {} from the vault: {error}", info.name);
                    report.failed.push(AddFromVaultFailure {
                        key_id: info.id.clone(),
                        name: info.name.clone(),
                        code: error.code(),
                    });
                }
            }
        }
        Ok(report)
    })
    .await
}

/// Checks the vault's entries against `~/.ssh`. Never fails because the
/// vault is locked or missing: the state says so instead.
#[tauri::command]
pub async fn run_vault_audit(app: AppHandle, state: State<'_, Shared>) -> AppResult<VaultAudit> {
    blocking(&state, move |state| {
        let idle = |state| VaultAudit {
            state,
            findings: Vec::new(),
        };
        if !state.vault.is_unlocked() {
            let exists = vault::probe(&state.vault.paths())?.exists;
            return Ok(idle(if exists {
                VaultState::Locked
            } else {
                VaultState::Missing
            }));
        }
        let keys = keys::scan(&state.paths.dir)
            .map(|scan| scan.keys)
            .unwrap_or_default();
        let hosts = SshConfig::load(&state.paths.config)
            .map(|config| config.hosts())
            .unwrap_or_default();
        let input = VaultAuditInput::new(&keys, &hosts);
        // Quiet: the audit page refetches by itself.
        match state
            .vault
            .with_quietly(&app, |vault| Ok(vault.audit(&input)))
        {
            Ok(findings) => Ok(VaultAudit {
                state: VaultState::Unlocked,
                findings,
            }),
            // It locked in the meantime.
            Err(error) if error.code() == ErrorCode::VaultLocked => Ok(idle(VaultState::Locked)),
            Err(error) => Err(error),
        }
    })
    .await
}

/// Private keys that are not loaded yet, one per fingerprint. Hardware keys
/// have no passphrase to fill in.
fn keys_to_add(scanned: Vec<KeyInfo>, loaded: &HashSet<String>) -> Vec<KeyInfo> {
    let mut seen = HashSet::new();
    scanned
        .into_iter()
        .filter(|key| key.private_path.is_some() && !key.hardware)
        .filter(|key| {
            key.fingerprint
                .as_ref()
                .is_some_and(|fp| !loaded.contains(fp) && seen.insert(fp.clone()))
        })
        .collect()
}

/// The saved passphrases of the keys with these fingerprints, by fingerprint.
/// A key's passphrase is the password of a key entry outside the recycle bin;
/// with several such entries, the most recently changed one wins.
fn saved_passphrases<'a>(
    vault: &Vault,
    fingerprints: impl IntoIterator<Item = &'a str>,
) -> AppResult<HashMap<String, SecretString>> {
    let entries = vault.entries();
    let mut saved = HashMap::new();
    for fingerprint in fingerprints {
        if let Some(entry) = key_entry(&entries, fingerprint) {
            saved.insert(
                fingerprint.to_owned(),
                vault.secret(&entry.id, SecretField::Password)?,
            );
        }
    }
    Ok(saved)
}

/// The key entry holding the passphrase of the key with this fingerprint.
pub(crate) fn key_entry<'a>(
    entries: &'a [EntrySummary],
    fingerprint: &str,
) -> Option<&'a EntrySummary> {
    entries
        .iter()
        .filter(|e| {
            e.kind == EntryKind::Key
                && !e.in_trash
                && e.has_password
                && e.key_fingerprint.as_deref() == Some(fingerprint)
        })
        .max_by(|a, b| a.modified.cmp(&b.modified))
}

/// Decrypts a key; fails with `wrong_passphrase` if the saved passphrase is
/// out of date.
fn decrypt(info: &KeyInfo, passphrase: &SecretString) -> AppResult<UnlockedKey> {
    Ok(keys::load_private(&private_path(info)?, Some(passphrase))?)
}

fn add_to_agent(
    state: &AppState,
    agent: &AgentClient,
    info: &KeyInfo,
    unlocked: &UnlockedKey,
    lifetime_secs: Option<u32>,
) -> AppResult<()> {
    agent.add(unlocked, &agent_comment(info), lifetime_secs, false)?;
    state.record_lifetime(&unlocked.fingerprint(), lifetime_secs);
    Ok(())
}

#[cfg(test)]
mod tests {
    use sshkm_core::ExposeSecret;
    use sshkm_core::keys::{GenerateAlgorithm, GenerateRequest};
    use sshkm_core::vault::{EntryInput, VaultPaths};

    use super::*;

    fn s(text: &str) -> SecretString {
        SecretString::from(text.to_owned())
    }

    fn key_entry_input(title: &str, fingerprint: &str, passphrase: &str) -> EntryInput {
        EntryInput {
            title: title.into(),
            password: Some(s(passphrase)),
            kind: EntryKind::Key,
            key_fingerprint: Some(fingerprint.into()),
            ..EntryInput::default()
        }
    }

    fn vault(dir: &std::path::Path) -> Vault {
        let paths = VaultPaths::new(dir.join("vault.kdbx"));
        Vault::create(&paths, &s("master")).unwrap().0
    }

    fn generate(dir: &std::path::Path, name: &str, passphrase: &str) -> KeyInfo {
        keys::generate(
            dir,
            &GenerateRequest {
                algorithm: GenerateAlgorithm::Ed25519,
                file_name: name.into(),
                comment: "test".into(),
                passphrase: Some(s(passphrase)),
            },
        )
        .unwrap()
    }

    #[test]
    fn the_saved_passphrase_decrypts_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path().join("ssh");
        std::fs::create_dir(&ssh).unwrap();
        let info = generate(&ssh, "id_ed25519", "Tundra-Velvet-Rocket-Mango7");
        let fingerprint = info.fingerprint.clone().unwrap();

        let mut vault = vault(dir.path());
        vault
            .add_entry(&key_entry_input(
                "id_ed25519",
                &fingerprint,
                "Tundra-Velvet-Rocket-Mango7",
            ))
            .unwrap();
        let mut saved = saved_passphrases(&vault, [fingerprint.as_str()]).unwrap();
        let passphrase = saved.remove(&fingerprint).unwrap();
        assert_eq!(
            decrypt(&info, &passphrase).unwrap().fingerprint(),
            fingerprint
        );
    }

    #[test]
    fn an_outdated_passphrase_is_a_wrong_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let info = generate(dir.path(), "id_ed25519", "the new one");
        let error = decrypt(&info, &s("the old one")).err().unwrap();
        assert_eq!(error.code(), ErrorCode::WrongPassphrase);
    }

    #[test]
    fn the_lookup_skips_other_keys_the_trash_and_empty_passwords() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = vault(dir.path());
        let trashed = vault
            .add_entry(&key_entry_input("old copy", "SHA256:a", "trashed"))
            .unwrap();
        vault.trash_entry(&trashed).unwrap();
        vault
            .add_entry(&key_entry_input("blank", "SHA256:a", ""))
            .unwrap();
        vault
            .add_entry(&key_entry_input("other", "SHA256:b", "other"))
            .unwrap();
        vault
            .add_entry(&EntryInput {
                title: "a login named like the key".into(),
                password: Some(s("login")),
                ..EntryInput::default()
            })
            .unwrap();
        assert!(saved_passphrases(&vault, ["SHA256:a"]).unwrap().is_empty());

        vault
            .add_entry(&key_entry_input("id_ed25519", "SHA256:a", "right"))
            .unwrap();
        let saved = saved_passphrases(&vault, ["SHA256:a", "SHA256:c"]).unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved["SHA256:a"].expose_secret(), "right");
    }

    #[test]
    fn only_unloaded_private_keys_are_tried_once_each() {
        let dir = tempfile::tempdir().unwrap();
        let first = generate(dir.path(), "a", "pass");
        let copy = dir.path().join("b");
        std::fs::copy(first.private_path.as_ref().unwrap(), &copy).unwrap();
        let loaded_key = generate(dir.path(), "c", "pass");
        let scanned = keys::scan(dir.path()).unwrap().keys;
        assert_eq!(scanned.len(), 3);
        let loaded = HashSet::from([loaded_key.fingerprint.unwrap()]);
        let names: Vec<String> = keys_to_add(scanned, &loaded)
            .into_iter()
            .map(|k| k.name)
            .collect();
        assert_eq!(names, ["a"]);
    }
}
