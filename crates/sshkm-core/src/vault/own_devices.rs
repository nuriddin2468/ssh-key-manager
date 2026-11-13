//! The user's own computers: a separate, higher level of trust than a
//! contact. An own device has the vault, gets synced with, and a later
//! version lets it install this computer's key on servers.
//!
//! Each is kept in the database's custom data as `sshkm.device.<device
//! key>`, this computer included, so every copy of the vault knows all of
//! them. Records go to the other devices as they are stored, fields of
//! later versions included, and the one changed last wins. Their times are
//! RFC 3339 in UTC, to the second; a record from another device dated more
//! than [`MAX_AHEAD`] ahead of this computer's clock is not taken.
//!
//! A removed device stays as a tombstone, and a tombstone is final here: a
//! sync never brings the device back, whatever the other computer's record
//! says. Only adding it again on this computer does
//! ([`Vault::add_own_device`], which the app calls only after "Add device":
//! the code compared, and the adding user's Touch ID or master password).
//! A tombstone from another device removes one here unless it was added
//! here again after that removal.
//!
//! The key own devices share ([`OwnKey`]) comes from 32 random bytes kept
//! next to the records, as `sshkm.own.key`.

use std::path::Path;

use keepass::Database;
use keepass::db::{CustomDataItem, CustomDataValue, Times};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

use super::{Vault, check_field, rfc3339};
use crate::p2p::PeerKey;
use crate::p2p::own::{OwnKey, SEED_LEN, Seed, new_seed};
use crate::p2p::protocol::clean_name;
use crate::{Error, Result};

const DEVICE_PREFIX: &str = "sshkm.device.";
/// Where the random value of the key own devices share is kept.
const OWN_KEY: &str = "sshkm.own.key";
/// Most records a sync takes, and the longest one.
pub const MAX_RECORDS: usize = 256;
const MAX_RECORD: usize = 16 * 1024;
/// How far ahead of this computer's clock a record from another device may
/// be dated, for clocks a little apart.
const MAX_AHEAD: Duration = Duration::minutes(5);

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
    /// The key the user's own devices share (see [`crate::p2p::own`]), once
    /// this vault has one ([`Self::make_own_key`]).
    pub fn own_key(&self) -> Option<OwnKey> {
        own_seed(&self.db).map(|seed| OwnKey::from_seed(&seed))
    }

    /// Makes the key the user's own devices share and saves the vault,
    /// unless it has one already; returns whether it made one. A key that
    /// isn't saved is not kept: what goes to a new device is the file. Of
    /// two computers that share the vault file and make one each, the first
    /// to save wins; the other's write fails with [`Error::Conflict`], and
    /// it reads the key from the file once it re-reads it.
    pub fn make_own_key(&mut self, backup_dir: &Path) -> Result<bool> {
        if own_seed(&self.db).is_some() {
            return Ok(false);
        }
        put_own_seed(&mut self.db);
        if let Err(error) = self.save(backup_dir) {
            self.db.meta.custom_data.remove(OWN_KEY);
            return Err(error);
        }
        Ok(true)
    }

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

    /// Whether `key` was one of the user's devices and was removed: its
    /// tombstone is final, so it never adds this computer as a device of
    /// the user's (only "Add device" on a computer that still is one adds
    /// it again).
    pub fn is_removed_device(&self, key: &PeerKey) -> bool {
        self.record(&key.to_string())
            .is_some_and(|stored| stored.removed.is_some())
    }

    /// Records `key` as one of the user's devices named `name`; returns
    /// whether anything changed (then the vault needs saving). A device that
    /// was removed comes back: the app calls this for the computer the user
    /// adds after "Add device" and the user's own confirmation, and on the
    /// computer being added, only for one that is not
    /// [removed](Self::is_removed_device).
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

    /// Takes the records another own device sent that win over this
    /// vault's ([`wins`]), but none dated more than [`MAX_AHEAD`] from now;
    /// returns whether anything changed.
    pub fn merge_own_devices(&mut self, theirs: &[DeviceRecord]) -> Result<bool> {
        let latest = OffsetDateTime::now_utc() + MAX_AHEAD;
        let mut changed = false;
        for record in theirs.iter().take(MAX_RECORDS) {
            let Some(incoming) = parse(&record.key, &record.record) else {
                continue;
            };
            if incoming.times().any(|time| time > latest)
                || self
                    .record(&record.key)
                    .is_some_and(|mine| !wins(&incoming, &record.record, &mine))
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

/// Replaces the key the user's own devices share, if `db` has one: for a
/// new recovery key, so a computer that is gone fails their check too. So
/// does every other device with a copy of its own, as it does with the old
/// secret, until it gets the vault again; one that shares the file through
/// a synced folder reads the new key from it.
pub(super) fn renew_own_key(db: &mut Database) {
    if own_seed(db).is_some() {
        put_own_seed(db);
    }
}

fn own_seed(db: &Database) -> Option<Seed> {
    // Kept as binary, which KeePass writes in base64; the reader takes any
    // value that reads as base64 for binary.
    let Some(CustomDataValue::Binary(bytes)) = &db.meta.custom_data.get(OWN_KEY)?.value else {
        return None;
    };
    if bytes.len() != SEED_LEN {
        return None;
    }
    let mut seed = Zeroizing::new([0; SEED_LEN]);
    seed.copy_from_slice(bytes);
    Some(seed)
}

fn put_own_seed(db: &mut Database) {
    db.meta.custom_data.insert(
        OWN_KEY.to_owned(),
        CustomDataItem {
            value: Some(CustomDataValue::Binary(new_seed().to_vec())),
            last_modification_time: Some(Times::now()),
        },
    );
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

/// A record, if it is one: a device key, the time it changed, and either a
/// name and when it was added or, for a tombstone, when it was removed.
fn parse(key: &str, json: &str) -> Option<Stored> {
    if json.len() > MAX_RECORD {
        return None;
    }
    PeerKey::from_base64(key).ok()?;
    let stored: Stored = serde_json::from_str(json).ok()?;
    time(&stored.modified)?;
    let fine = match &stored.removed {
        Some(removed) => time(removed).is_some(),
        None => {
            time(&stored.added).is_some()
                && !stored.name.is_empty()
                && clean_name(&stored.name) == stored.name
        }
    };
    fine.then_some(stored)
}

/// A time as the records keep it: RFC 3339 in UTC, to the second, as
/// `2026-11-04T10:30:00Z`.
pub(super) fn time(text: &str) -> Option<OffsetDateTime> {
    if text.len() != 20 || !text.ends_with('Z') {
        return None;
    }
    OffsetDateTime::parse(text, &Rfc3339).ok()
}

impl Stored {
    /// Every time the record has; each was checked by [`parse`].
    fn times(&self) -> impl Iterator<Item = OffsetDateTime> + '_ {
        [
            Some(&self.modified),
            Some(&self.added),
            self.removed.as_ref(),
        ]
        .into_iter()
        .flatten()
        .filter_map(|text| time(text))
    }
}

/// The devices that records from another own device (`theirs`) would make
/// the user's here, as [`Vault::merge_own_devices`] takes them: live ones
/// this computer has no record of. A sync tells the user of each.
pub fn learned_devices(mine: &[DeviceRecord], theirs: &[DeviceRecord]) -> Vec<OwnDevice> {
    let latest = OffsetDateTime::now_utc() + MAX_AHEAD;
    let here: std::collections::BTreeSet<&str> = mine
        .iter()
        .filter(|record| parse(&record.key, &record.record).is_some())
        .map(|record| record.key.as_str())
        .collect();
    let mut learned: std::collections::BTreeMap<&str, OwnDevice> =
        std::collections::BTreeMap::new();
    for record in theirs.iter().take(MAX_RECORDS) {
        let Some(incoming) = parse(&record.key, &record.record) else {
            continue;
        };
        if incoming.removed.is_some()
            || incoming.times().any(|time| time > latest)
            || here.contains(record.key.as_str())
        {
            continue;
        }
        learned.insert(
            &record.key,
            OwnDevice {
                key: record.key.clone(),
                name: incoming.name,
                added: incoming.added,
            },
        );
    }
    learned.into_values().collect()
}

/// Whether `incoming` (stored as `json`) takes the place of `mine`.
///
/// - A tombstone here is final: nothing from a sync replaces it.
/// - A tombstone from the other device removes a device here unless it was
///   added here after that removal (it was added again).
/// - Between two devices, the record changed later wins, at the same second
///   the greater JSON, so both computers pick the same.
fn wins(incoming: &Stored, json: &str, mine: &Stored) -> bool {
    if mine.removed.is_some() {
        return false;
    }
    if let Some(removed) = &incoming.removed {
        return time(removed) >= time(&mine.added);
    }
    match time(&incoming.modified).cmp(&time(&mine.modified)) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => {
            serde_json::to_string(mine).is_ok_and(|mine| json > mine.as_str())
        }
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

        assert!(!vault.is_removed_device(&laptop));
        assert!(vault.remove_own_device(&laptop.to_string()).unwrap());
        assert!(!vault.remove_own_device(&laptop.to_string()).unwrap());
        assert!(!vault.is_own_device(&laptop));
        assert!(vault.is_removed_device(&laptop));
        assert!(!vault.is_removed_device(&desktop));
        assert_eq!(vault.own_devices().len(), 1);
        // The tombstone goes along to the other devices.
        assert_eq!(vault.device_records().len(), 2);
    }

    #[test]
    fn the_record_changed_last_wins_and_tombstones_stay() {
        let dir = tempfile::tempdir().unwrap();
        let mut here = vault(&dir, "here");
        let laptop = Identity::generate().unwrap().public();
        let newer = r#"{"name":"New name","added":"2026-01-01T00:00:00Z","modified":"2026-06-01T00:00:00Z","keys":["ssh-ed25519 AAAA"]}"#;
        let older = r#"{"name":"Old name","added":"2026-01-01T00:00:00Z","modified":"2026-01-01T00:00:00Z"}"#;
        assert!(here.merge_own_devices(&[record(&laptop, older)]).unwrap());
        assert!(here.merge_own_devices(&[record(&laptop, newer)]).unwrap());
        assert!(!here.merge_own_devices(&[record(&laptop, older)]).unwrap());
        assert_eq!(here.own_devices()[0].name, "New name");
        // A field this version doesn't know travels on as it is.
        assert!(here.device_records()[0].record.contains("ssh-ed25519 AAAA"));

        // A tombstone wins over the record, even of an earlier change; and
        // nothing from a sync brings the device back.
        let removed = r#"{"modified":"2026-03-01T00:00:00Z","removed":"2026-03-01T00:00:00Z"}"#;
        assert!(here.merge_own_devices(&[record(&laptop, removed)]).unwrap());
        assert!(!here.is_own_device(&laptop));
        assert!(!here.merge_own_devices(&[record(&laptop, newer)]).unwrap());
        let now = from_now(0);
        let fresh = dated("Back", &now, &now);
        assert!(!here.merge_own_devices(&[record(&laptop, &fresh)]).unwrap());
        assert!(!here.is_own_device(&laptop));
    }

    #[test]
    fn a_device_only_the_other_side_knows_is_learned() {
        let dir = tempfile::tempdir().unwrap();
        let mut here = vault(&dir, "here");
        let (known, new, gone) = (
            Identity::generate().unwrap().public(),
            Identity::generate().unwrap().public(),
            Identity::generate().unwrap().public(),
        );
        let now = from_now(0);
        let live = |name: &str| dated(name, &now, &now);
        let removed = format!(r#"{{"modified":"{now}","removed":"{now}"}}"#);
        assert!(
            here.merge_own_devices(&[record(&known, &live("Known"))])
                .unwrap()
        );
        assert!(here.merge_own_devices(&[record(&gone, &removed)]).unwrap());
        let theirs = [
            record(&known, &live("Known, renamed")),
            record(&new, &live("New")),
            record(&gone, &live("Back")),
            record(&Identity::generate().unwrap().public(), &removed),
        ];
        let learned = learned_devices(&here.device_records(), &theirs);
        assert_eq!(
            learned.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
            ["New"]
        );
        assert_eq!(learned[0].key, new.to_string());
    }

    /// A record of a device added at `added` and changed at `modified`.
    fn dated(name: &str, added: &str, modified: &str) -> String {
        format!(r#"{{"name":"{name}","added":"{added}","modified":"{modified}"}}"#)
    }

    fn tombstone(removed: &str) -> String {
        format!(r#"{{"modified":"{removed}","removed":"{removed}"}}"#)
    }

    /// `seconds` from now, as records keep times.
    fn from_now(seconds: i64) -> String {
        let time = (OffsetDateTime::now_utc() + Duration::seconds(seconds))
            .replace_nanosecond(0)
            .unwrap();
        time.format(&Rfc3339).unwrap()
    }

    #[test]
    fn a_record_dated_ahead_is_not_taken() {
        let dir = tempfile::tempdir().unwrap();
        let mut here = vault(&dir, "here");
        let (laptop, phone) = (
            Identity::generate().unwrap().public(),
            Identity::generate().unwrap().public(),
        );
        assert_eq!(from_now(0).len(), 20);
        let past = "2026-01-01T00:00:00Z";
        let first = dated("Laptop", past, past);
        assert!(here.merge_own_devices(&[record(&laptop, &first)]).unwrap());
        // Far ahead, it wins nothing: neither a change nor a removal.
        let far = "9999-12-31T23:59:59Z";
        for ahead in [
            dated("Renamed", past, far),
            dated("Renamed", far, far),
            tombstone(far),
            dated("Renamed", past, &from_now(MAX_AHEAD.whole_seconds() + 60)),
        ] {
            assert!(check_records(&[record(&laptop, &ahead)]).is_ok());
            let taken = here.merge_own_devices(&[record(&laptop, &ahead)]).unwrap();
            assert!(!taken, "{ahead}");
            assert!(!here.merge_own_devices(&[record(&phone, &ahead)]).unwrap());
        }
        assert_eq!(here.own_devices()[0].name, "Laptop");
        // A clock a little ahead is fine.
        let soon = dated("Renamed", past, &from_now(60));
        assert!(here.merge_own_devices(&[record(&laptop, &soon)]).unwrap());
        assert_eq!(here.own_devices()[0].name, "Renamed");
    }

    #[test]
    fn a_removed_device_comes_back_only_by_being_added_here() {
        let dir = tempfile::tempdir().unwrap();
        let mut here = vault(&dir, "here");
        let laptop = Identity::generate().unwrap().public();
        here.add_own_device(&laptop, "Laptop").unwrap();
        let removed_before = tombstone(&from_now(-60));
        assert!(here.remove_own_device(&laptop.to_string()).unwrap());
        let mine = here.device_records();

        // A later record from a sync, of the same device, changes nothing.
        let later = dated("Laptop", &from_now(-30), &from_now(0));
        assert!(!here.merge_own_devices(&[record(&laptop, &later)]).unwrap());
        assert!(!here.is_own_device(&laptop));
        assert_eq!(here.device_records(), mine);

        // Added again here: a tombstone from before doesn't remove it, one
        // from after does.
        assert!(here.add_own_device(&laptop, "Laptop").unwrap());
        assert!(here.is_own_device(&laptop));
        let taken = here.merge_own_devices(&[record(&laptop, &removed_before)]);
        assert!(!taken.unwrap());
        assert!(here.is_own_device(&laptop));
        let removed_after = tombstone(&from_now(1));
        assert!(
            here.merge_own_devices(&[record(&laptop, &removed_after)])
                .unwrap()
        );
        assert!(!here.is_own_device(&laptop));
    }

    #[test]
    fn a_new_device_takes_the_file_and_secret_and_sets_its_own_master_password() {
        let dir = tempfile::tempdir().unwrap();
        let mut here = vault(&dir, "here");
        let laptop = Identity::generate().unwrap().public();
        here.add_own_device(&laptop, "Laptop").unwrap();
        assert!(here.make_own_key(&dir.path().join("backups")).unwrap());
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
        let proof = here.own_key().unwrap().proof(&hash, true);
        assert!(joined.own_key().unwrap().verify(&hash, true, &proof));
        // Never over a vault that is there.
        assert!(Vault::join(&there, &bytes, &secret, &s("x")).is_err());

        // A change on disk since it was read: not sent.
        std::fs::write(&here.paths().database, b"changed").unwrap();
        assert!(here.saved_bytes().is_err());
    }

    #[test]
    fn the_key_own_devices_share_is_random_and_kept_in_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let backups = dir.path().join("backups");
        let mut here = vault(&dir, "here");
        assert!(here.own_key().is_none());
        assert!(here.make_own_key(&backups).unwrap());
        assert!(!here.make_own_key(&backups).unwrap());
        let hash = [3; 32];
        let proof = here.own_key().unwrap().proof(&hash, false);

        // Another computer that opens the same file has it too.
        let mut there = Vault::unlock(here.paths(), &s("master")).unwrap();
        assert!(there.own_key().unwrap().verify(&hash, false, &proof));
        assert!(!there.make_own_key(&backups).unwrap());

        // It isn't made from the secret or the password: another vault of
        // the same password has another one.
        let mut other = vault(&dir, "other");
        other.make_own_key(&backups).unwrap();
        assert!(!other.own_key().unwrap().verify(&hash, false, &proof));

        // Two that share the file and both make one: the second to save
        // keeps none of its own, and finds the first one's in the file.
        let mut first = vault(&dir, "shared");
        let mut second = Vault::unlock(first.paths(), &s("master")).unwrap();
        assert!(first.make_own_key(&backups).unwrap());
        let error = second.make_own_key(&backups).unwrap_err();
        assert!(matches!(error, Error::Conflict(_)), "{error:?}");
        assert!(second.own_key().is_none());
        second.refresh().unwrap();
        let proof_of_first = first.own_key().unwrap().proof(&hash, true);
        assert!(
            second
                .own_key()
                .unwrap()
                .verify(&hash, true, &proof_of_first)
        );

        // A new recovery key makes a new one.
        here.new_recovery_key(&s("master"), &backups).unwrap();
        let renewed = here.own_key().unwrap();
        assert!(!renewed.verify(&hash, false, &proof));
        let reopened = Vault::unlock(here.paths(), &s("master")).unwrap();
        assert!(
            reopened
                .own_key()
                .unwrap()
                .verify(&hash, false, &renewed.proof(&hash, false))
        );
        // A vault without one gets none from it.
        let mut plain = vault(&dir, "plain");
        plain.new_recovery_key(&s("master"), &backups).unwrap();
        assert!(plain.own_key().is_none());
    }

    #[test]
    fn records_that_are_not_ones_are_refused() {
        let laptop = Identity::generate().unwrap().public();
        let fine =
            r#"{"name":"Laptop","added":"2026-01-01T00:00:00Z","modified":"2026-01-01T00:00:00Z"}"#;
        assert!(check_records(&[record(&laptop, fine)]).is_ok());
        let tombstone = r#"{"modified":"2026-01-01T00:00:00Z","removed":"2026-01-01T00:00:00Z"}"#;
        assert!(check_records(&[record(&laptop, tombstone)]).is_ok());
        let day = r#""added":"2026-01-01T00:00:00Z""#;
        for bad in [
            r#"{"name":"Laptop"}"#.to_owned(),
            format!(r#"{{"name":"",{day},"modified":"2026-01-01T00:00:00Z"}}"#),
            format!(r#"{{"name":"two\nlines",{day},"modified":"2026-01-01T00:00:00Z"}}"#),
            format!(r#"{{"name":"Laptop",{day},"modified":"yesterday"}}"#),
            r#"{"name":"Laptop","modified":"2026-01-01T00:00:00Z"}"#.to_owned(),
            format!(r#"{{"name":"Laptop",{day},"modified":"~~~~~~~~~~~~~~~~~~~Z"}}"#),
            format!(r#"{{"name":"Laptop",{day},"modified":"2026-13-01T00:00:00Z"}}"#),
            format!(r#"{{"name":"Laptop",{day},"modified":"2026-01-01T00:00:00+05:00"}}"#),
            format!(r#"{{"name":"Laptop",{day},"modified":"2026-01-01T00:00:00.5Z"}}"#),
            r#"{"modified":"2026-01-01T00:00:00Z","removed":"soon"}"#.to_owned(),
            "not json".to_owned(),
        ] {
            assert!(check_records(&[record(&laptop, &bad)]).is_err(), "{bad}");
        }
        let bad_key = DeviceRecord {
            key: "not a key".into(),
            record: fine.into(),
        };
        assert!(check_records(&[bad_key]).is_err());
    }
}
