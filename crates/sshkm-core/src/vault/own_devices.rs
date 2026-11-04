//! The user's own computers: a separate, higher level of trust than a
//! contact. An own device has the vault, gets synced with, and a later
//! version lets it install this computer's key on servers.
//!
//! Each is kept in the database's custom data as `sshkm.device.<device
//! key>`, this computer included, so every copy of the vault knows all of
//! them. A removed device stays as a tombstone, so a sync with a computer
//! that hasn't heard yet doesn't bring it back. Records go to the other
//! devices as they are stored, fields of later versions included, and the
//! one changed last wins.

use keepass::db::{CustomDataItem, CustomDataValue, Times};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{Vault, check_field, rfc3339};
use crate::p2p::PeerKey;
use crate::p2p::protocol::clean_name;
use crate::{Error, Result};

const DEVICE_PREFIX: &str = "sshkm.device.";
/// Most records a sync takes, and the longest one.
pub const MAX_RECORDS: usize = 256;
const MAX_RECORD: usize = 16 * 1024;

/// One of the user's own computers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnDevice {
    /// Its device key, standard base64.
    pub key: String,
    pub name: String,
    /// When it became one of the user's devices: RFC 3339, UTC.
    pub added: String,
}

/// A device's record as it goes to the user's other devices: the stored
/// JSON as it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRecord {
    pub key: String,
    pub record: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Stored {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    added: String,
    /// RFC 3339, UTC, to the second: the newer record wins.
    modified: String,
    /// When it was removed, for a tombstone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    removed: Option<String>,
    /// Whatever a later version keeps here.
    #[serde(flatten)]
    rest: Map<String, Value>,
}

impl Vault {
    /// The user's own devices, by name.
    pub fn own_devices(&self) -> Vec<OwnDevice> {
        let mut devices: Vec<OwnDevice> = self
            .db
            .meta
            .custom_data
            .iter()
            .filter_map(|(key, item)| {
                let key = key.strip_prefix(DEVICE_PREFIX)?;
                let stored = stored(key, item)?;
                stored.removed.is_none().then(|| OwnDevice {
                    key: key.to_owned(),
                    name: stored.name,
                    added: stored.added,
                })
            })
            .collect();
        devices.sort_by(|a, b| {
            a.name
                .to_lowercase()
                .cmp(&b.name.to_lowercase())
                .then_with(|| a.key.cmp(&b.key))
        });
        devices
    }

    /// Whether `key` is one of the user's own devices.
    pub fn is_own_device(&self, key: &PeerKey) -> bool {
        self.record(&key.to_string())
            .is_some_and(|stored| stored.removed.is_none())
    }

    /// Records `key` as one of the user's devices named `name`; returns
    /// whether anything changed (then the vault needs saving).
    pub fn add_own_device(&mut self, key: &PeerKey, name: &str) -> Result<bool> {
        let name = clean_name(name);
        if name.is_empty() {
            return Err(Error::invalid("a device needs a name"));
        }
        check_field(&name)?;
        let key = key.to_string();
        let now = rfc3339(Times::now());
        let mut stored = match self.record(&key) {
            Some(stored) if stored.removed.is_none() && stored.name == name => return Ok(false),
            Some(stored) if stored.removed.is_none() => stored,
            _ => Stored {
                name: String::new(),
                added: now.clone(),
                modified: String::new(),
                removed: None,
                rest: Map::new(),
            },
        };
        stored.name = name;
        stored.modified = now;
        self.put(&key, &stored)?;
        Ok(true)
    }

    /// Removes one of the user's devices, leaving a tombstone. Returns
    /// whether it was one.
    pub fn remove_own_device(&mut self, key: &str) -> Result<bool> {
        if PeerKey::from_base64(key).is_err()
            || self.record(key).is_none_or(|s| s.removed.is_some())
        {
            return Ok(false);
        }
        let now = rfc3339(Times::now());
        self.put(
            key,
            &Stored {
                name: String::new(),
                added: String::new(),
                modified: now.clone(),
                removed: Some(now),
                rest: Map::new(),
            },
        )?;
        Ok(true)
    }

    /// Every record, tombstones too, to send to another own device.
    pub fn device_records(&self) -> Vec<DeviceRecord> {
        self.db
            .meta
            .custom_data
            .iter()
            .filter_map(|(key, item)| {
                let key = key.strip_prefix(DEVICE_PREFIX)?;
                stored(key, item)?;
                let Some(CustomDataValue::String(json)) = &item.value else {
                    return None;
                };
                Some(DeviceRecord {
                    key: key.to_owned(),
                    record: json.clone(),
                })
            })
            .collect()
    }

    /// Takes the records another own device sent that are newer than this
    /// vault's; returns whether anything changed.
    pub fn merge_own_devices(&mut self, theirs: &[DeviceRecord]) -> Result<bool> {
        let mut changed = false;
        for record in theirs.iter().take(MAX_RECORDS) {
            let Some(incoming) = parse(&record.key, &record.record) else {
                continue;
            };
            if self
                .record(&record.key)
                .is_some_and(|mine| !newer(&incoming, &record.record, &mine))
            {
                continue;
            }
            self.put(&record.key, &incoming)?;
            changed = true;
        }
        Ok(changed)
    }

    fn record(&self, key: &str) -> Option<Stored> {
        let item = self
            .db
            .meta
            .custom_data
            .get(&format!("{DEVICE_PREFIX}{key}"))?;
        stored(key, item)
    }

    fn put(&mut self, key: &str, stored: &Stored) -> Result<()> {
        let json =
            serde_json::to_string(stored).map_err(|e| Error::Parse(format!("device: {e}")))?;
        self.db.meta.custom_data.insert(
            format!("{DEVICE_PREFIX}{key}"),
            CustomDataItem {
                value: Some(CustomDataValue::String(json)),
                last_modification_time: Some(Times::now()),
            },
        );
        Ok(())
    }
}

/// Fails unless the records are ones a sync may take.
pub fn check_records(records: &[DeviceRecord]) -> Result<()> {
    if records.len() > MAX_RECORDS {
        return Err(Error::invalid("too many devices"));
    }
    for record in records {
        if parse(&record.key, &record.record).is_none() {
            return Err(Error::invalid("not a device record"));
        }
    }
    Ok(())
}

fn stored(key: &str, item: &CustomDataItem) -> Option<Stored> {
    let Some(CustomDataValue::String(json)) = &item.value else {
        return None;
    };
    parse(key, json)
}

/// A record, if it is one: a device key, a time, and a name unless removed.
fn parse(key: &str, json: &str) -> Option<Stored> {
    if json.len() > MAX_RECORD {
        return None;
    }
    PeerKey::from_base64(key).ok()?;
    let stored: Stored = serde_json::from_str(json).ok()?;
    let time = |t: &str| t.len() == 20 && t.ends_with('Z');
    let named = stored.removed.is_some()
        || (!stored.name.is_empty() && clean_name(&stored.name) == stored.name);
    (time(&stored.modified) && named && stored.removed.as_deref().is_none_or(time))
        .then_some(stored)
}

/// Whether `incoming` (stored as `json`) wins over `mine`: changed later,
/// or at the same second a tombstone, or else the greater JSON, so both
/// computers pick the same.
fn newer(incoming: &Stored, json: &str, mine: &Stored) -> bool {
    match incoming.modified.cmp(&mine.modified) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => match (incoming.removed.is_some(), mine.removed.is_some()) {
            (true, false) => true,
            (false, true) => false,
            _ => serde_json::to_string(mine).is_ok_and(|mine| json > mine.as_str()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::Identity;
    use crate::vault::VaultPaths;

    fn s(text: &str) -> secrecy::SecretString {
        secrecy::SecretString::from(text)
    }

    fn vault(dir: &tempfile::TempDir, name: &str) -> Vault {
        let paths = VaultPaths::new(dir.path().join(format!("{name}.kdbx")));
        Vault::create(&paths, &s("master")).unwrap().0
    }

    fn record(key: &PeerKey, json: &str) -> DeviceRecord {
        DeviceRecord {
            key: key.to_string(),
            record: json.into(),
        }
    }

    #[test]
    fn own_devices_are_kept_with_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = vault(&dir, "vault");
        let (laptop, desktop) = (
            Identity::generate().unwrap().public(),
            Identity::generate().unwrap().public(),
        );
        assert!(!vault.is_own_device(&laptop));
        assert!(vault.add_own_device(&laptop, " MacBook\n Air ").unwrap());
        assert!(!vault.add_own_device(&laptop, "MacBook Air").unwrap());
        assert!(vault.add_own_device(&desktop, "Desktop").unwrap());
        assert!(vault.is_own_device(&laptop));
        let names: Vec<_> = vault.own_devices().into_iter().map(|d| d.name).collect();
        assert_eq!(names, ["Desktop", "MacBook Air"]);
        assert!(vault.add_own_device(&laptop, " ").is_err());

        vault.save(&dir.path().join("backups")).unwrap();
        let mut vault = Vault::unlock(vault.paths(), &s("master")).unwrap();
        assert_eq!(vault.own_devices().len(), 2);

        assert!(vault.remove_own_device(&laptop.to_string()).unwrap());
        assert!(!vault.remove_own_device(&laptop.to_string()).unwrap());
        assert!(!vault.is_own_device(&laptop));
        assert_eq!(vault.own_devices().len(), 1);
        // The tombstone goes along to the other devices.
        assert_eq!(vault.device_records().len(), 2);
    }

    #[test]
    fn the_record_changed_last_wins_and_tombstones_stay() {
        let dir = tempfile::tempdir().unwrap();
        let mut here = vault(&dir, "here");
        let laptop = Identity::generate().unwrap().public();
        let newer = r#"{"name":"New name","added":"2026-01-01T00:00:00Z","modified":"2030-01-01T00:00:00Z","keys":["ssh-ed25519 AAAA"]}"#;
        let older = r#"{"name":"Old name","added":"2026-01-01T00:00:00Z","modified":"2026-01-01T00:00:00Z"}"#;
        assert!(here.merge_own_devices(&[record(&laptop, older)]).unwrap());
        assert!(here.merge_own_devices(&[record(&laptop, newer)]).unwrap());
        assert!(!here.merge_own_devices(&[record(&laptop, older)]).unwrap());
        assert_eq!(here.own_devices()[0].name, "New name");
        // A field this version doesn't know travels on as it is.
        assert!(here.device_records()[0].record.contains("ssh-ed25519 AAAA"));

        // A tombstone of the same second wins over the record.
        let removed = r#"{"modified":"2030-01-01T00:00:00Z","removed":"2030-01-01T00:00:00Z"}"#;
        assert!(here.merge_own_devices(&[record(&laptop, removed)]).unwrap());
        assert!(!here.is_own_device(&laptop));
        assert!(!here.merge_own_devices(&[record(&laptop, newer)]).unwrap());
    }

    #[test]
    fn a_new_device_takes_the_file_and_secret_and_sets_its_own_master_password() {
        let dir = tempfile::tempdir().unwrap();
        let mut here = vault(&dir, "here");
        let laptop = Identity::generate().unwrap().public();
        here.add_own_device(&laptop, "Laptop").unwrap();
        here.save(&dir.path().join("backups")).unwrap();
        let (bytes, secret) = (here.saved_bytes().unwrap(), here.share_secret());
        assert!(crate::vault::check_shared(&bytes, &secret).is_ok());
        assert!(crate::vault::check_shared(&bytes, &s("not the secret")).is_err());

        let there = VaultPaths::new(dir.path().join("there").join("vault.kdbx"));
        std::fs::create_dir_all(there.database.parent().unwrap()).unwrap();
        let joined = Vault::join(&there, &bytes, &secret, &s("another master")).unwrap();
        assert!(joined.is_own_device(&laptop));
        assert_ne!(joined.vault_id(), here.vault_id());
        assert!(Vault::unlock(&there, &s("another master")).is_ok());
        assert!(Vault::unlock(&there, &s("master")).is_err());
        // Both hold the same vault, so both prove it alike.
        let hash = [5; 32];
        assert!(
            joined
                .own_key()
                .verify(&hash, true, &here.own_key().proof(&hash, true))
        );
        // Never over a vault that is there.
        assert!(Vault::join(&there, &bytes, &secret, &s("x")).is_err());

        // A change on disk since it was read: not sent.
        std::fs::write(&here.paths().database, b"changed").unwrap();
        assert!(here.saved_bytes().is_err());
    }

    #[test]
    fn records_that_are_not_ones_are_refused() {
        let laptop = Identity::generate().unwrap().public();
        let fine =
            r#"{"name":"Laptop","added":"2026-01-01T00:00:00Z","modified":"2026-01-01T00:00:00Z"}"#;
        assert!(check_records(&[record(&laptop, fine)]).is_ok());
        for bad in [
            r#"{"name":"Laptop"}"#,
            r#"{"name":"","modified":"2026-01-01T00:00:00Z"}"#,
            r#"{"name":"two\nlines","modified":"2026-01-01T00:00:00Z"}"#,
            r#"{"name":"Laptop","modified":"yesterday"}"#,
            "not json",
        ] {
            assert!(check_records(&[record(&laptop, bad)]).is_err(), "{bad}");
        }
        let bad_key = DeviceRecord {
            key: "not a key".into(),
            record: fine.into(),
        };
        assert!(check_records(&[bad_key]).is_err());
    }
}
