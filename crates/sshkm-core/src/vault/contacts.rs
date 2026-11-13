//! Devices paired over the local network (see [`crate::p2p`]).
//!
//! A contact is kept in the database's custom data as
//! `sshkm.contact.<device key>`, like a paired browser: encrypted with
//! everything else, gone with the vault, and shared with the user's other
//! computers when the vault is in a synced folder or when they sync.
//!
//! A contact is a device, known by its key, not a person: the same device
//! paired on two of the user's computers is one record. Records go to the
//! user's other devices as they are stored ([`ContactRecord`]) and the one
//! changed last wins, never asking: pairing it again on either computer
//! renames it. A removed contact stays as a tombstone for
//! [`KEEP_REMOVED_MS`] so that a sync doesn't bring it back; older versions
//! skip a tombstone, which has no name.

use keepass::db::{CustomDataItem, CustomDataValue, Times};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::{Duration, OffsetDateTime};

use super::own_devices::time;
use super::projects::KEEP_REMOVED_MS;
use super::{Vault, check_field, rfc3339};
use crate::p2p::PeerKey;
use crate::p2p::protocol::clean_name;
use crate::{Error, Result};

const CONTACT_PREFIX: &str = "sshkm.contact.";
/// Most records a sync takes, and the longest one.
pub const MAX_CONTACTS: usize = 1024;
const MAX_RECORD: usize = 16 * 1024;
/// How far ahead of this computer's clock a record from another device may
/// be dated.
const MAX_AHEAD: Duration = Duration::minutes(5);

/// A contact's record as it goes to the user's other devices: the stored
/// JSON as it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactRecord {
    pub key: String,
    pub record: String,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Stored {
    /// Empty in a tombstone, which older versions then skip.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    paired: String,
    /// When it last changed: RFC 3339, UTC. Missing from records made
    /// before contacts synced, which go by `paired`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    modified: String,
    /// When it was removed, for a tombstone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    removed: Option<String>,
    /// Whatever a later version keeps here.
    #[serde(flatten)]
    rest: Map<String, Value>,
}

impl Stored {
    /// When it last changed.
    fn changed(&self) -> Option<OffsetDateTime> {
        time(if self.modified.is_empty() {
            &self.paired
        } else {
            &self.modified
        })
    }
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
        let now = rfc3339(Times::now());
        let stored = Stored {
            name: name.clone(),
            paired: now.clone(),
            modified: now,
            removed: None,
            rest: Map::new(),
        };
        self.put_contact(&key.to_string(), &stored)?;
        Ok(Contact {
            key: key.to_string(),
            name,
            paired: stored.paired,
        })
    }

    /// Forgets a contact, leaving a tombstone so that a sync doesn't bring
    /// it back. Returns whether it was there.
    pub fn remove_contact(&mut self, key: &str) -> bool {
        let name = format!("{CONTACT_PREFIX}{key}");
        let Some(item) = self.db.meta.custom_data.get(&name) else {
            return false;
        };
        match stored(key, item) {
            // Unreadable: nothing a sync could bring back.
            None => self.db.meta.custom_data.remove(&name).is_some(),
            Some(stored) if stored.removed.is_some() => false,
            Some(_) => {
                let now = rfc3339(Times::now());
                let tombstone = Stored {
                    name: String::new(),
                    paired: String::new(),
                    modified: now.clone(),
                    removed: Some(now),
                    rest: Map::new(),
                };
                self.put_contact(key, &tombstone).is_ok()
            }
        }
    }

    /// The contacts' records, tombstones included, to send to another of
    /// the user's devices.
    pub fn contact_records(&self) -> Vec<ContactRecord> {
        self.db
            .meta
            .custom_data
            .iter()
            .filter_map(|(key, item)| {
                let key = key.strip_prefix(CONTACT_PREFIX)?;
                stored(key, item)?;
                let Some(CustomDataValue::String(json)) = &item.value else {
                    return None;
                };
                Some(ContactRecord {
                    key: key.to_owned(),
                    record: json.clone(),
                })
            })
            .collect()
    }

    /// Takes the records another own device sent that changed after this
    /// vault's, but none dated more than [`MAX_AHEAD`] from now and no
    /// tombstone older than [`KEEP_REMOVED_MS`]; drops this vault's own
    /// tombstones that old. Returns whether anything changed.
    pub fn merge_contacts(&mut self, theirs: &[ContactRecord]) -> Result<bool> {
        let now = OffsetDateTime::now_utc();
        let latest = now + MAX_AHEAD;
        let oldest = now - Duration::milliseconds(KEEP_REMOVED_MS);
        let mut changed = false;
        for record in theirs.iter().take(MAX_CONTACTS) {
            let Some(incoming) = parse(&record.key, &record.record) else {
                continue;
            };
            let Some(when) = incoming.changed() else {
                continue;
            };
            if when > latest || (incoming.removed.is_some() && when < oldest) {
                continue;
            }
            let item = self
                .db
                .meta
                .custom_data
                .get(&format!("{CONTACT_PREFIX}{}", record.key));
            let mine = item.and_then(|item| stored(&record.key, item));
            let newer = match mine.as_ref().and_then(Stored::changed) {
                None => true,
                Some(here) if when != here => when > here,
                // The same second: the larger record, so both sides pick
                // the same one.
                Some(_) => item
                    .and_then(|item| match &item.value {
                        Some(CustomDataValue::String(json)) => Some(json.as_str()),
                        _ => None,
                    })
                    .is_some_and(|json| record.record.as_str() > json),
            };
            if newer {
                self.put_contact(&record.key, &incoming)?;
                changed = true;
            }
        }
        let stale: Vec<String> = self
            .db
            .meta
            .custom_data
            .iter()
            .filter_map(|(key, item)| {
                let short = key.strip_prefix(CONTACT_PREFIX)?;
                let stored = stored(short, item)?;
                (stored.removed.is_some() && stored.changed().is_some_and(|t| t < oldest))
                    .then(|| key.clone())
            })
            .collect();
        for key in stale {
            self.db.meta.custom_data.remove(&key);
            changed = true;
        }
        Ok(changed)
    }

    fn put_contact(&mut self, key: &str, stored: &Stored) -> Result<()> {
        let json =
            serde_json::to_string(stored).map_err(|e| Error::Parse(format!("contact: {e}")))?;
        self.db.meta.custom_data.insert(
            format!("{CONTACT_PREFIX}{key}"),
            CustomDataItem {
                value: Some(CustomDataValue::String(json)),
                last_modification_time: Some(Times::now()),
            },
        );
        Ok(())
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
    let stored = stored(key, item)?;
    if stored.removed.is_some() {
        return None;
    }
    Some(Contact {
        key: key.to_owned(),
        name: stored.name,
        paired: stored.paired,
    })
}

fn stored(key: &str, item: &CustomDataItem) -> Option<Stored> {
    let Some(CustomDataValue::String(json)) = &item.value else {
        return None;
    };
    parse(key, json)
}

/// A record, if it is one: a device key and either a name and when it was
/// paired or, for a tombstone, when it was removed.
fn parse(key: &str, json: &str) -> Option<Stored> {
    if json.len() > MAX_RECORD {
        return None;
    }
    PeerKey::from_base64(key).ok()?;
    let stored: Stored = serde_json::from_str(json).ok()?;
    if !stored.modified.is_empty() {
        time(&stored.modified)?;
    }
    let fine = match &stored.removed {
        Some(removed) => time(removed).is_some() && time(&stored.modified).is_some(),
        None => {
            time(&stored.paired).is_some()
                && !stored.name.is_empty()
                && clean_name(&stored.name) == stored.name
        }
    };
    fine.then_some(stored)
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

    #[test]
    fn contacts_sync_as_records_the_latest_winning() {
        let dir = tempfile::tempdir().unwrap();
        let (mut left, _) =
            Vault::create(&VaultPaths::new(dir.path().join("a.kdbx")), &s("master")).unwrap();
        let (mut right, _) =
            Vault::create(&VaultPaths::new(dir.path().join("b.kdbx")), &s("master")).unwrap();
        let phone = Identity::generate().unwrap().public();
        let other = Identity::generate().unwrap().public();

        // One device paired on both computers separately, under two names:
        // one record, the later pairing's name, never a question.
        left.add_contact(&phone, "Aziz's phone").unwrap();
        let mut later = left.contact_records();
        later[0].record = later[0].record.replace(
            &left.contact(&phone).unwrap().paired,
            "2099-01-01T00:00:00Z",
        );
        std::thread::sleep(std::time::Duration::from_millis(1100));
        right.add_contact(&phone, "Pixel").unwrap();
        right.add_contact(&other, "bobur-pc").unwrap();
        assert!(left.merge_contacts(&right.contact_records()).unwrap());
        assert!(!right.merge_contacts(&left.contact_records()).unwrap());
        assert_eq!(left.contact(&phone).unwrap().name, "Pixel");
        assert_eq!(left.contact(&phone), right.contact(&phone));
        assert_eq!(left.contacts().len(), 2);
        // Nothing left to take.
        assert!(!left.merge_contacts(&right.contact_records()).unwrap());
        // A record dated far ahead of this clock isn't taken.
        assert!(!right.merge_contacts(&later).unwrap());

        // A removal goes across and isn't undone by the other's old record.
        let before = right.contact_records();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(left.remove_contact(&other.to_string()));
        assert!(!left.remove_contact(&other.to_string()));
        assert_eq!(left.contact(&other), None);
        assert!(right.merge_contacts(&left.contact_records()).unwrap());
        assert_eq!(right.contact(&other), None);
        assert!(!left.merge_contacts(&before).unwrap());
        assert_eq!(left.contact(&other), None);
        // Pairing it again later wins over the tombstone.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        right.add_contact(&other, "bobur-pc").unwrap();
        assert!(left.merge_contacts(&right.contact_records()).unwrap());
        assert!(left.contact(&other).is_some());
    }

    #[test]
    fn older_versions_skip_tombstones_and_read_new_records() {
        #[derive(Deserialize)]
        struct Old {
            name: String,
            paired: String,
        }
        let live =
            r#"{"name":"Pixel","paired":"2026-11-04T10:00:00Z","modified":"2026-11-05T10:00:00Z"}"#;
        let old: Old = serde_json::from_str(live).unwrap();
        assert_eq!((old.name.as_str(), old.paired.len()), ("Pixel", 20));
        let tombstone = r#"{"modified":"2026-11-05T10:00:00Z","removed":"2026-11-05T10:00:00Z"}"#;
        assert!(serde_json::from_str::<Old>(tombstone).is_err());
        // Records of older versions, without `modified`, are read here.
        let key = Identity::generate().unwrap().public().to_string();
        assert!(parse(&key, r#"{"name":"Pixel","paired":"2026-11-04T10:00:00Z"}"#).is_some());
        assert!(parse(&key, r#"{"name":"","paired":"2026-11-04T10:00:00Z"}"#).is_none());
        assert!(parse("not a key", live).is_none());
    }
}
