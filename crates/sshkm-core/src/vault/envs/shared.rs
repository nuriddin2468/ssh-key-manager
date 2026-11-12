//! Shared values: one value that several environments use, so changing it
//! once changes it in every environment and every file that uses it.
//!
//! A shared value is a KeePass entry of its own, marked with the custom data
//! [`SHARED`] and filed under `Environments/Shared`: its title is the name it
//! was shared under, its password the value, with the entry's history. A
//! variable uses it through a KeePass field reference in its own field,
//! `{REF:P@I:<entry uuid>}`, which KeePassXC resolves too. The value lives in
//! that one entry only: there are no copies to keep in step, so whatever
//! brings the vault's entries together (the vault file shared between
//! computers, a sync of entries) ends with every environment using the same
//! value, whichever computer changed it last.
//!
//! The vault resolves references wherever values leave it — files, the
//! terminal, exports, comparisons, the leak scanner, another computer (which
//! gets plain values) — and never writes a reference into a file. A
//! reference to an entry that isn't there (deleted elsewhere) can't be
//! resolved: the environment's files wait until it is, or the variable gets
//! a value of its own. One to another entry's password (made in KeePassXC)
//! resolves as KeePass resolves it.
//!
//! Changing a shared variable — in the app, by an import, or in a file —
//! changes the shared value; "Use its own value here" gives one environment
//! its own copy. Deleting a shared value gives each environment that uses it
//! a copy first, in the same change.

use keepass::db::{CustomDataItem, CustomDataValue, EntryId, EntryRef, Times, Value, fields};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use uuid::Uuid;

use super::{EnvVariable, GROUP, check_field, child_group, is_environment, variables_of};
use crate::vault::{Vault, in_group};
use crate::{Error, Result};

/// Custom data that marks an entry as a shared value.
pub const SHARED: &str = "sshkm.shared";
/// The group under `Environments` that holds the shared values.
const SHARED_GROUP: &str = "Shared";

/// A shared value, without the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct SharedValue {
    /// The entry UUID.
    pub id: String,
    /// The name it was shared under.
    pub name: String,
    pub empty: bool,
    /// The variables that use it, of environments outside the recycle bin
    /// first.
    pub users: Vec<SharedUse>,
    /// It is in the vault's recycle bin; it still resolves.
    pub in_trash: bool,
}

/// A variable that uses a shared value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct SharedUse {
    pub env_id: String,
    pub variable: String,
}

/// Whether a KeePass entry is a shared value.
pub(crate) fn is_shared(entry: &EntryRef<'_>) -> bool {
    entry.custom_data.contains_key(SHARED)
}

/// The field reference to the password of the entry `id`, as KeePass writes
/// it.
pub(super) fn reference(id: Uuid) -> String {
    format!(
        "{{REF:P@I:{}}}",
        id.simple().to_string().to_ascii_uppercase()
    )
}

/// The entry whose password `value` refers to, if it is a reference and
/// nothing else (KeePass reads placeholders without case).
pub(super) fn referenced(value: &str) -> Option<Uuid> {
    const PREFIX: &str = "{REF:P@I:";
    if value.len() != PREFIX.len() + 33 || !value.is_char_boundary(PREFIX.len()) {
        return None;
    }
    let (prefix, rest) = value.split_at(PREFIX.len());
    let hex = rest.strip_suffix('}')?;
    (prefix.eq_ignore_ascii_case(PREFIX) && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| Uuid::parse_str(hex).ok())
        .flatten()
}

impl Vault {
    /// The value `value` stands for: `None` if it isn't a reference, else
    /// the password of the entry it refers to, or `Err` if there is none.
    pub(super) fn dereference(&self, value: &str) -> Option<std::result::Result<String, ()>> {
        let id = referenced(value)?;
        Some(match self.db.entry(EntryId::from(id)) {
            // One level, as references in references aren't followed.
            Some(entry) if !is_environment(&entry) => {
                let password = entry.get(fields::PASSWORD).unwrap_or_default();
                if referenced(password).is_some() {
                    Err(())
                } else {
                    Ok(password.to_owned())
                }
            }
            _ => Err(()),
        })
    }

    /// `vars` with every reference replaced by what it refers to. Fails, by
    /// the variable's name, for one that can't be resolved.
    pub(super) fn resolve(&self, vars: Vec<EnvVariable>) -> Result<Vec<EnvVariable>> {
        vars.into_iter()
            .map(|var| match self.dereference(var.value.expose_secret()) {
                None => Ok(var),
                Some(Ok(value)) => Ok(EnvVariable {
                    value: SecretString::from(value),
                    ..var
                }),
                Some(Err(())) => Err(Error::NotFound(format!("the shared value of {}", var.name))),
            })
            .collect()
    }

    /// The shared value a variable's own field refers to, if it is one.
    pub(super) fn shared_of(&self, raw_value: &str) -> Option<Uuid> {
        let id = referenced(raw_value)?;
        self.db
            .entry(EntryId::from(id))
            .filter(is_shared)
            .map(|_| id)
    }

    /// Every shared value, with the variables that use it.
    pub fn shared_values(&self) -> Vec<SharedValue> {
        let bin = self.db.meta.recyclebin_uuid;
        let mut values: Vec<SharedValue> = self
            .db
            .iter_all_entries()
            .filter(is_shared)
            .map(|entry| SharedValue {
                id: entry.id().uuid().to_string(),
                name: entry.get(fields::TITLE).unwrap_or_default().to_owned(),
                empty: entry.get(fields::PASSWORD).unwrap_or_default().is_empty(),
                users: Vec::new(),
                in_trash: in_group(entry.parent().id(), bin, &self.db),
            })
            .collect();
        let mut users: Vec<(bool, SharedUse, Uuid)> = Vec::new();
        for entry in self.db.iter_all_entries().filter(is_environment) {
            let in_trash = in_group(entry.parent().id(), bin, &self.db);
            for var in variables_of(&entry) {
                if let Some(id) = referenced(var.value.expose_secret()) {
                    users.push((
                        in_trash,
                        SharedUse {
                            env_id: entry.id().uuid().to_string(),
                            variable: var.name,
                        },
                        id,
                    ));
                }
            }
        }
        users.sort_by(|a, b| {
            (a.0, &a.1.env_id, &a.1.variable).cmp(&(b.0, &b.1.env_id, &b.1.variable))
        });
        for value in &mut values {
            value.users = users
                .iter()
                .filter(|(_, _, id)| id.to_string() == value.id)
                .map(|(_, used, _)| used.clone())
                .collect();
        }
        values.sort_by_cached_key(|value| (value.in_trash, value.name.to_lowercase()));
        values
    }

    /// Shares the variable `name` of the environment `id` with the
    /// environments `others`: its value becomes a shared value (unless it
    /// uses one already), and each of them uses it under the same name,
    /// added where they lack the variable, its value replaced where they
    /// have it (the entry's history keeps the old one). Returns the shared
    /// value's id.
    pub fn share_env_variable(
        &mut self,
        id: &str,
        name: &str,
        others: &[String],
    ) -> Result<String> {
        let raw = self.raw_env_variable(id, name)?;
        let shared = if let Some(shared) = self.shared_of(raw.value.expose_secret()) {
            shared
        } else {
            let value = self
                .env_variables(id)?
                .into_iter()
                .find(|var| var.name == name)
                .map(|var| var.value)
                .ok_or_else(|| Error::NotFound(format!("variable {name}")))?;
            let shared = self.add_shared_value(name, &value)?;
            self.link_variable(id, name, shared, raw.secret)?;
            shared
        };
        for other in others.iter().filter(|other| *other != id) {
            self.link_variable(other, name, shared, raw.secret)?;
        }
        Ok(shared.to_string())
    }

    /// Gives the variable `name` of the environment `id` a value of its own:
    /// the shared value's, as it is now.
    pub fn unshare_env_variable(&mut self, id: &str, name: &str) -> Result<()> {
        let raw = self.raw_env_variable(id, name)?;
        if referenced(raw.value.expose_secret()).is_none() {
            return Ok(());
        }
        let value = match self.dereference(raw.value.expose_secret()) {
            Some(Ok(value)) => SecretString::from(value),
            _ => return Err(Error::NotFound(format!("the shared value of {name}"))),
        };
        self.edit_variables(id, |vars| {
            if let Some(var) = vars.iter_mut().find(|var| var.name == name) {
                var.value = value;
            }
            Ok(())
        })
    }

    /// Moves a shared value to the recycle bin, each variable that uses it
    /// given a value of its own first, in the same change.
    pub fn delete_shared_value(&mut self, shared: &str) -> Result<()> {
        let entry = self.find(shared)?;
        if !is_shared(&entry) {
            return Err(Error::NotFound(format!("shared value {shared}")));
        }
        let users = self
            .shared_values()
            .into_iter()
            .find(|value| value.id == shared)
            .map(|value| value.users)
            .unwrap_or_default();
        for user in users {
            self.unshare_env_variable(&user.env_id, &user.variable)?;
        }
        self.trash_entry(shared)
    }

    /// Changes a shared value, keeping the previous one in its history.
    /// Returns whether it changed.
    pub(super) fn set_shared_value(&mut self, shared: Uuid, value: &str) -> Result<bool> {
        check_field(value)?;
        let entry_id = EntryId::from(shared);
        {
            let mut entry = self
                .db
                .entry_mut(entry_id)
                .ok_or_else(|| Error::NotFound(format!("shared value {shared}")))?;
            if entry.get(fields::PASSWORD) == Some(value) {
                return Ok(false);
            }
            let mut tracked = entry.track_changes();
            tracked.set(fields::PASSWORD, Value::protected(value));
            tracked.times.last_modification = Some(Times::now());
        }
        self.settle_history(entry_id, true);
        Ok(true)
    }

    /// The values a shared value had, newest first.
    pub(super) fn shared_history(&self, shared: Uuid) -> Vec<String> {
        self.db
            .entry(EntryId::from(shared))
            .map(|entry| {
                super::history_newest_first(&entry)
                    .into_iter()
                    .map(|version| version.get(fields::PASSWORD).unwrap_or_default().to_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The current value of a shared value.
    pub(super) fn shared_value(&self, shared: Uuid) -> Option<String> {
        self.db
            .entry(EntryId::from(shared))
            .map(|entry| entry.get(fields::PASSWORD).unwrap_or_default().to_owned())
    }

    /// A variable as its environment keeps it, its reference unresolved.
    fn raw_env_variable(&self, id: &str, name: &str) -> Result<EnvVariable> {
        self.raw_env_variables(id)?
            .into_iter()
            .find(|var| var.name == name)
            .ok_or_else(|| Error::NotFound(format!("variable {name}")))
    }

    /// Makes the variable `name` of the environment `id` use the shared
    /// value `shared`: added if it lacks one, its value replaced if not.
    fn link_variable(&mut self, id: &str, name: &str, shared: Uuid, secret: bool) -> Result<()> {
        let reference = SecretString::from(reference(shared));
        self.edit_variables(id, |vars| {
            match vars.iter_mut().find(|var| var.name == name) {
                Some(var) => {
                    var.value = SecretString::from(reference.expose_secret());
                    var.secret = secret;
                }
                None => vars.push(EnvVariable {
                    name: name.to_owned(),
                    value: SecretString::from(reference.expose_secret()),
                    secret,
                    note: String::new(),
                }),
            }
            Ok(())
        })
    }

    /// Adds a shared value named `name` holding `value`, under
    /// `Environments/Shared`.
    fn add_shared_value(&mut self, name: &str, value: &SecretString) -> Result<Uuid> {
        check_field(value.expose_secret())?;
        let root = self.db.root().id();
        let environments = child_group(&mut self.db, root, GROUP)?;
        let group = child_group(&mut self.db, environments, SHARED_GROUP)?;
        let mut group = self
            .db
            .group_mut(group)
            .ok_or_else(|| Error::NotFound(GROUP.into()))?;
        let mut entry = group.add_entry();
        entry.set_unprotected(fields::TITLE, name);
        entry.set_protected(fields::PASSWORD, value.expose_secret());
        entry.custom_data.insert(
            SHARED.to_owned(),
            CustomDataItem {
                value: Some(CustomDataValue::String("{}".to_owned())),
                last_modification_time: Some(Times::now()),
            },
        );
        Ok(entry.id().uuid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_are_read_as_keepass_writes_them() {
        let id = Uuid::parse_str("46c9b1ff-bd4a-bc4b-bb26-0c6190bad20c").unwrap();
        let text = reference(id);
        assert_eq!(text, "{REF:P@I:46C9B1FFBD4ABC4BBB260C6190BAD20C}");
        assert_eq!(referenced(&text), Some(id));
        assert_eq!(
            referenced("{ref:p@i:46c9b1ffbd4abc4bbb260c6190bad20c}"),
            Some(id)
        );
        for not in [
            "",
            "{REF:P@I:46C9B1FFBD4ABC4BBB260C6190BAD20}",
            "{REF:U@I:46C9B1FFBD4ABC4BBB260C6190BAD20C}",
            "x{REF:P@I:46C9B1FFBD4ABC4BBB260C6190BAD20C}",
            "{REF:P@I:46C9B1FFBD4ABC4BBB260C6190BAD20Z}",
            "{REF:P@I:46C9B1FF-BD4A-BC4B-BB26-0C6190BAD20C}",
            "{REF:P@I:46C9B1FFBD4ABC4BBB260C6190BAD2é}",
        ] {
            assert_eq!(referenced(not), None, "{not}");
        }
    }
}
