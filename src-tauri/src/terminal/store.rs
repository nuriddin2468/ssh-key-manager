//! The vault behind a terminal's prompt bridge: the host's entry (password,
//! 2FA) and the entries of keys in `~/.ssh` (passphrases).

use std::path::Path;
use std::sync::Arc;

use sshkm_core::keys::{self, KeyInfo};
use sshkm_core::vault::{self, EntryInput, EntryKind, SecretField, Vault};
use sshkm_core::{ExposeSecret, SecretString};
use tauri::AppHandle;

use super::bridge::{SaveTarget, Store};
use super::types::SaveOffer;
use crate::askpass::names_key;
use crate::commands::vault_hosts::{fresh_code, host_entry};
use crate::commands::vault_links::key_entry;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

pub struct VaultStore {
    pub app: AppHandle,
    pub state: Arc<AppState>,
    pub alias: String,
    /// The host's `User`, for a new entry.
    pub user: Option<String>,
}

impl VaultStore {
    /// `work` on the unlocked vault; `None` when it is locked or fails.
    fn read<T>(&self, work: impl FnOnce(&mut Vault) -> AppResult<Option<T>>) -> Option<T> {
        self.state.vault.with(&self.app, work).ok().flatten()
    }

    /// The key in `~/.ssh` whose private file `ssh` names.
    fn key(&self, shown: &str) -> Option<KeyInfo> {
        keys::scan(&self.state.paths.dir)
            .ok()?
            .keys
            .into_iter()
            .find(|key| {
                key.fingerprint.is_some()
                    && key
                        .private_path
                        .as_deref()
                        .is_some_and(|path| names_key(shown, Path::new(path)))
            })
    }
}

fn non_empty(secret: SecretString) -> Option<SecretString> {
    (!secret.expose_secret().is_empty()).then_some(secret)
}

impl Store for VaultStore {
    fn password(&self) -> Option<SecretString> {
        self.read(|vault| {
            let entries = vault.entries();
            Ok(host_entry(&entries, &self.alias)
                .map(|entry| vault.secret(&entry.id, SecretField::Password))
                .transpose()?)
        })
        .and_then(non_empty)
    }

    fn one_time_code(&self) -> Option<SecretString> {
        self.read(|vault| {
            let entries = vault.entries();
            host_entry(&entries, &self.alias)
                .filter(|entry| entry.has_otp)
                .map(|entry| fresh_code(vault, &entry.id))
                .transpose()
        })
    }

    fn passphrase(&self, key: &str) -> Option<SecretString> {
        let fingerprint = self.key(key)?.fingerprint?;
        self.read(|vault| {
            let entries = vault.entries();
            Ok(key_entry(&entries, &fingerprint)
                .map(|entry| vault.secret(&entry.id, SecretField::Password))
                .transpose()?)
        })
        .and_then(non_empty)
    }

    fn offer(&self, target: &SaveTarget) -> SaveOffer {
        let fingerprint = match target {
            SaveTarget::Password => None,
            SaveTarget::Passphrase { key } => match self.key(key).and_then(|k| k.fingerprint) {
                Some(fingerprint) => Some(fingerprint),
                None => return SaveOffer::None,
            },
        };
        if !self.state.vault.is_unlocked() {
            let exists = vault::probe(&self.state.vault.paths()).is_ok_and(|files| files.exists);
            return if exists {
                SaveOffer::Locked
            } else {
                SaveOffer::NoVault
            };
        }
        let saved = self.state.vault.with(&self.app, |vault| {
            let entries = vault.entries();
            Ok(match &fingerprint {
                None => host_entry(&entries, &self.alias).is_some(),
                Some(fingerprint) => key_entry(&entries, fingerprint).is_some(),
            })
        });
        match saved {
            Ok(true) => SaveOffer::Update,
            Ok(false) => SaveOffer::New,
            Err(_) => SaveOffer::Locked,
        }
    }

    fn save(&self, target: &SaveTarget, secret: &SecretString) -> AppResult<()> {
        let key = match target {
            SaveTarget::Password => None,
            SaveTarget::Passphrase { key } => Some(
                self.key(key)
                    .ok_or_else(|| AppError::not_found("the key is not in ~/.ssh"))?,
            ),
        };
        let state = &self.state;
        state.vault.change(&self.app, &state.backup_dir, |vault| {
            let entries = vault.entries();
            match &key {
                None => {
                    let current = host_entry(&entries, &self.alias).map(|e| e.id.clone());
                    save_entry(vault, current, |current| EntryInput {
                        title: current.map_or_else(|| self.alias.clone(), |c| c.title.clone()),
                        username: current.map_or_else(
                            || self.user.clone().unwrap_or_default(),
                            |c| c.username.clone(),
                        ),
                        password: Some(secret.clone()),
                        url: current.map(|c| c.url.clone()).unwrap_or_default(),
                        notes: current.map(|c| c.notes.clone()).unwrap_or_default(),
                        otp: None,
                        kind: EntryKind::Host,
                        host: Some(self.alias.clone()),
                        key_fingerprint: None,
                    })
                }
                Some(key) => {
                    let fingerprint = key.fingerprint.clone().unwrap_or_default();
                    let current = key_entry(&entries, &fingerprint).map(|e| e.id.clone());
                    save_entry(vault, current, |current| EntryInput {
                        title: current.map_or_else(|| key.name.clone(), |c| c.title.clone()),
                        username: current.map(|c| c.username.clone()).unwrap_or_default(),
                        password: Some(secret.clone()),
                        url: current.map(|c| c.url.clone()).unwrap_or_default(),
                        notes: current.map(|c| c.notes.clone()).unwrap_or_default(),
                        otp: None,
                        kind: EntryKind::Key,
                        host: None,
                        key_fingerprint: Some(fingerprint.clone()),
                    })
                }
            }
        })
    }
}

/// The fields of an existing entry that a save keeps.
struct Current {
    title: String,
    username: String,
    url: String,
    notes: String,
}

/// Updates entry `id` (keeping its other fields) or adds a new one.
fn save_entry(
    vault: &mut Vault,
    id: Option<String>,
    input: impl Fn(Option<&Current>) -> EntryInput,
) -> AppResult<()> {
    match id {
        Some(id) => {
            let detail = vault.entry(&id)?;
            let current = Current {
                title: detail.summary.title,
                username: detail.summary.username,
                url: detail.summary.url,
                notes: detail.notes,
            };
            vault.update_entry(&id, &input(Some(&current)))?;
        }
        None => {
            vault.add_entry(&input(None))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use sshkm_core::vault::VaultPaths;

    use super::*;

    fn s(text: &str) -> SecretString {
        SecretString::from(text.to_owned())
    }

    #[test]
    fn saving_updates_the_entry_and_keeps_its_other_fields() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("vault.kdbx"));
        let mut vault = Vault::create(&paths, &s("master")).unwrap().0;
        let host = |current: Option<&Current>, password: &str| EntryInput {
            title: current.map_or_else(|| "prod".into(), |c| c.title.clone()),
            username: current.map_or_else(|| "ubuntu".into(), |c| c.username.clone()),
            password: Some(s(password)),
            notes: current.map(|c| c.notes.clone()).unwrap_or_default(),
            kind: EntryKind::Host,
            host: Some("prod".into()),
            ..EntryInput::default()
        };

        save_entry(&mut vault, None, |c| host(c, "first")).unwrap();
        let id = host_entry(&vault.entries(), "prod").unwrap().id.clone();
        vault
            .update_entry(
                &id,
                &EntryInput {
                    title: "Production".into(),
                    username: "ubuntu".into(),
                    notes: "keep me".into(),
                    kind: EntryKind::Host,
                    host: Some("prod".into()),
                    ..EntryInput::default()
                },
            )
            .unwrap();

        save_entry(&mut vault, Some(id.clone()), |c| host(c, "second")).unwrap();
        assert_eq!(vault.entries().len(), 1, "updated, not added");
        let detail = vault.entry(&id).unwrap();
        assert_eq!(detail.summary.title, "Production");
        assert_eq!(detail.notes, "keep me");
        assert_eq!(
            vault
                .secret(&id, SecretField::Password)
                .unwrap()
                .expose_secret(),
            "second"
        );
    }
}
