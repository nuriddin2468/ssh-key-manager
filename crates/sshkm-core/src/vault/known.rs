//! The secrets the leak scanner looks for ([`crate::leaks`]).

use keepass::db::fields;
use secrecy::{ExposeSecret, SecretString};

use super::Vault;
use super::envs::{is_environment, variables_of};
use crate::leaks::{KnownSecret, LeakSecret};

impl Vault {
    /// The values the leak scanner looks for: the variables marked secret
    /// of every environment, and the password of every entry (a login's, a
    /// host's, a key's passphrase), outside the recycle bin. Empty values
    /// are left out; the scanner leaves out those too plain to find.
    pub fn known_secrets(&self) -> Vec<KnownSecret> {
        let mut out = Vec::new();
        for entry in self.db.iter_all_entries() {
            if is_environment(&entry) {
                let env = self.env_summary(&entry);
                if env.in_trash {
                    continue;
                }
                for var in variables_of(&entry) {
                    if !var.secret || var.value.expose_secret().is_empty() {
                        continue;
                    }
                    out.push(KnownSecret {
                        secret: LeakSecret::Variable {
                            env_id: env.id.clone(),
                            project: env.project.clone(),
                            environment: env.name.clone(),
                            name: var.name,
                        },
                        value: var.value,
                    });
                }
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
