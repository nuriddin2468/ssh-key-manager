//! The secrets the leak scanner looks for ([`crate::leaks`]).

use keepass::db::fields;
use secrecy::{ExposeSecret, SecretString};

use super::Vault;
use super::envs::{is_environment, is_shared};
use crate::leaks::{KnownSecret, LeakSecret};

impl Vault {
    /// The values the leak scanner looks for: the variables marked secret
    /// of every environment, and the password of every entry (a login's, a
    /// host's, a key's passphrase), outside the recycle bin. Empty values
    /// are left out; the scanner leaves out those too plain to find.
    pub fn known_secrets(&self) -> Vec<KnownSecret> {
        let mut out = Vec::new();
        let owners = self.environment_owners();
        for entry in self.db.iter_all_entries() {
            if is_environment(&entry) {
                let env = self.env_summary(&entry, &owners);
                if env.in_trash {
                    continue;
                }
                // Shared values resolved: found as the variables that use
                // them, not as entries of their own.
                let Ok(vars) = self.env_variables(&env.id) else {
                    continue;
                };
                for var in vars {
                    if !var.secret || var.value.expose_secret().is_empty() {
                        continue;
                    }
                    out.push(KnownSecret {
                        secret: LeakSecret::Variable {
                            env_id: env.id.clone(),
                            project: self.env_label(&env),
                            environment: env.name.clone(),
                            name: var.name,
                        },
                        value: var.value,
                    });
                }
                continue;
            }
            if is_shared(&entry) {
                continue;
            }
            let summary = self.summary(&entry);
            let password = entry.get(fields::PASSWORD).unwrap_or_default();
            if summary.in_trash || password.is_empty() {
                continue;
            }
            out.push(KnownSecret {
                secret: LeakSecret::Password {
                    entry_id: summary.id,
                    title: summary.title,
                    entry_kind: summary.kind,
                },
                value: SecretString::from(password),
            });
        }
        out
    }
}

impl Vault {
    /// The one secret `key` names ([`LeakSecret::key`]), if the vault still
    /// has it as a secret: for redacting it, without reading the others.
    pub fn known_secret(&self, key: &str) -> Option<KnownSecret> {
        if let Some(id) = key.strip_prefix("entry:") {
            let entry = self.find(id).ok()?;
            if is_environment(&entry) || is_shared(&entry) {
                return None;
            }
            let summary = self.summary(&entry);
            let password = entry.get(fields::PASSWORD).unwrap_or_default();
            if summary.in_trash || password.is_empty() {
                return None;
            }
            return Some(KnownSecret {
                secret: LeakSecret::Password {
                    entry_id: summary.id,
                    title: summary.title,
                    entry_kind: summary.kind,
                },
                value: SecretString::from(password),
            });
        }
        let (env_id, name) = key.strip_prefix("var:")?.split_once(':')?;
        let detail = self.environment(env_id).ok()?;
        let secret = detail
            .variables
            .iter()
            .any(|var| var.name == name && var.secret && !var.empty);
        if detail.summary.in_trash || !secret {
            return None;
        }
        Some(KnownSecret {
            secret: LeakSecret::Variable {
                project: self.env_label(&detail.summary),
                env_id: detail.summary.id,
                environment: detail.summary.name,
                name: name.to_owned(),
            },
            value: self.env_value(env_id, name).ok()?,
        })
    }
}
