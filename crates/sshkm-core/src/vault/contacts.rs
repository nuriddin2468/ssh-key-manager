//! Devices paired over the local network (see [`crate::p2p`]).
//!
//! A contact is kept in the database's custom data as
//! `sshkm.contact.<device key>`, like a paired browser: encrypted with
//! everything else, gone with the vault, and shared with the user's other
//! computers when the vault is in a synced folder.

use keepass::db::{CustomDataItem, CustomDataValue, Times};
use serde::{Deserialize, Serialize};

use super::{Vault, check_field, rfc3339};
use crate::p2p::PeerKey;
use crate::p2p::protocol::clean_name;
use crate::{Error, Result};

const CONTACT_PREFIX: &str = "sshkm.contact.";

/// A paired device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct Contact {
    /// The device's public key, standard base64: how it is recognised.
    pub key: String,
    /// The name the device gave when it was paired.
    pub name: String,
    /// RFC 3339, UTC.
    pub paired: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Stored {
    name: String,
    paired: String,
}

impl Vault {
    /// The paired devices, by name.
    pub fn contacts(&self) -> Vec<Contact> {
        let mut contacts: Vec<Contact> = self
            .db
            .meta
            .custom_data
            .iter()
            .filter_map(|(key, item)| contact(key.strip_prefix(CONTACT_PREFIX)?, item))
            .collect();
        contacts.sort_by(|a, b| {
            a.name
                .to_lowercase()
                .cmp(&b.name.to_lowercase())
                .then_with(|| a.key.cmp(&b.key))
        });
        contacts
    }

    /// The contact with this device key, if it is one.
    pub fn contact(&self, key: &PeerKey) -> Option<Contact> {
        let item = self
            .db
            .meta
            .custom_data
            .get(&format!("{CONTACT_PREFIX}{key}"))?;
        contact(&key.to_string(), item)
    }

    /// Records a pairing both users confirmed, replacing an earlier one with
    /// the same key. `paired` is now.
    pub fn add_contact(&mut self, key: &PeerKey, name: &str) -> Result<Contact> {
        let name = clean_name(name);
        if name.is_empty() {
            return Err(Error::invalid("a device needs a name"));
        }
        check_field(&name)?;
        let now = Times::now();
        let stored = Stored {
            name: name.clone(),
            paired: rfc3339(now),
        };
        let json =
            serde_json::to_string(&stored).map_err(|e| Error::Parse(format!("contact: {e}")))?;
        self.db.meta.custom_data.insert(
            format!("{CONTACT_PREFIX}{key}"),
            CustomDataItem {
                value: Some(CustomDataValue::String(json)),
                last_modification_time: Some(now),
            },
        );
        Ok(Contact {
            key: key.to_string(),
            name,
            paired: stored.paired,
        })
    }

    /// Forgets a contact. Returns whether it was there.
    pub fn remove_contact(&mut self, key: &str) -> bool {
        self.db
            .meta
            .custom_data
            .remove(&format!("{CONTACT_PREFIX}{key}"))
            .is_some()
    }

    /// The name Nearby shows for the device with this key, if it is one of
    /// the user's devices or a contact: the name kept here, never the one
    /// the device gives itself now. A name that another device or contact
    /// here has too comes with the day it was added or paired, as
    /// `ubuntu (2026-03-04)`, so that the user can tell the two apart.
    pub fn known_name(&self, key: &PeerKey) -> Option<String> {
        let key = key.to_string();
        let known: Vec<(String, String, String)> = self
            .own_devices()
            .into_iter()
            .map(|device| (device.key, device.name, device.added))
            .chain(
                self.contacts()
                    .into_iter()
                    .map(|contact| (contact.key, contact.name, contact.paired)),
            )
            .collect();
        let (_, name, since) = known.iter().find(|(other, ..)| *other == key)?;
        let shared = known.iter().any(|(other, other_name, _)| {
            *other != key && other_name.to_lowercase() == name.to_lowercase()
        });
        if !shared {
            return Some(name.clone());
        }
        let day = since.get(..10).unwrap_or(&key[..8]);
        Some(format!("{name} ({day})"))
    }
}

fn contact(key: &str, item: &CustomDataItem) -> Option<Contact> {
    PeerKey::from_base64(key).ok()?;
    let Some(CustomDataValue::String(json)) = &item.value else {
        return None;
    };
    let stored: Stored = serde_json::from_str(json).ok()?;
    Some(Contact {
        key: key.to_owned(),
        name: stored.name,
        paired: stored.paired,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::Identity;
    use crate::vault::VaultPaths;

    fn s(text: &str) -> secrecy::SecretString {
        secrecy::SecretString::from(text)
    }

    #[test]
    fn contacts_are_kept_with_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("vault.kdbx"));
        let (mut vault, _) = Vault::create(&paths, &s("master")).unwrap();
        let aziz = Identity::generate().unwrap().public();
        let bobur = Identity::generate().unwrap().public();
        assert_eq!(vault.contact(&aziz), None);

        let added = vault.add_contact(&aziz, "  MacBook\nof Aziz ").unwrap();
        assert_eq!(added.name, "MacBook of Aziz");
        assert_eq!(added.key, aziz.to_string());
        vault.add_contact(&bobur, "bobur-pc").unwrap();
        vault.save(&dir.path().join("backups")).unwrap();

        let reopened = Vault::unlock(&paths, &s("master")).unwrap();
        let names: Vec<_> = reopened.contacts().into_iter().map(|c| c.name).collect();
        assert_eq!(names, ["bobur-pc", "MacBook of Aziz"]);
        assert_eq!(reopened.contact(&aziz), Some(added));

        let mut vault = reopened;
        assert!(vault.remove_contact(&aziz.to_string()));
        assert!(!vault.remove_contact(&aziz.to_string()));
        assert_eq!(vault.contact(&aziz), None);
        assert!(vault.add_contact(&aziz, " \u{7} ").is_err());
    }

    #[test]
    fn devices_go_by_the_name_kept_here() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("vault.kdbx"));
        let (mut vault, _) = Vault::create(&paths, &s("master")).unwrap();
        let [laptop, bobur, carol, stranger] =
            [(); 4].map(|()| Identity::generate().unwrap().public());
        vault.add_own_device(&laptop, "MacBook").unwrap();
        vault.add_contact(&laptop, "Old name").unwrap();
        vault.add_contact(&bobur, "ubuntu").unwrap();
        // One of the user's devices goes by its name there.
        assert_eq!(vault.known_name(&laptop).as_deref(), Some("MacBook"));
        assert_eq!(vault.known_name(&bobur).as_deref(), Some("ubuntu"));
        assert_eq!(vault.known_name(&stranger), None);

        // Two of one name come with the day each was paired.
        let added = vault.add_contact(&carol, "Ubuntu").unwrap();
        let paired = vault.contact(&bobur).unwrap().paired;
        assert_eq!(
            vault.known_name(&bobur),
            Some(format!("ubuntu ({})", &paired[..10]))
        );
        assert_eq!(
            vault.known_name(&carol),
            Some(format!("Ubuntu ({})", &added.paired[..10]))
        );
    }
}
