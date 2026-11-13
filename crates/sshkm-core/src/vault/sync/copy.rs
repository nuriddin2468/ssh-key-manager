//! The copy of the vault one device sends another, and the checks on one
//! that comes.

use std::collections::{HashMap, HashSet};

use chrono::{Duration, NaiveDateTime};
use keepass::Database;
use keepass::config::CompressionConfig;
use keepass::db::{CustomDataItem, CustomDataValue, EntryId, GroupId, History, Icon, Times};
use secrecy::SecretString;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::model::local_set;
use super::payload;
use super::{MAX_ATTACHMENTS, MAX_DELETED, MAX_DEPTH, MAX_ENTRIES, MAX_GROUPS, MAX_VERSIONS};
use crate::vault::projects::KEEP_REMOVED_MS;
use crate::vault::{
    MAX_DATABASE_SIZE, Vault, kdf, parse_database, read_database, serialize, sha256,
};
use crate::{Error, Result};

/// How far ahead of this computer's clock a time from another device is
/// believed; a later one counts as now.
const MAX_AHEAD: Duration = Duration::minutes(5);
/// The custom data of a copy that names, by UUID only, what the sender
/// keeps on its computer ([`super::LOCAL`]): the receiver doesn't take it
/// for deleted.
const LOCAL_IDS: &str = "sshkm.sync.local";
/// Deepest the elements of a copy's XML go: groups [`MAX_DEPTH`] deep, and
/// the levels around and inside them.
const MAX_XML_DEPTH: usize = MAX_DEPTH + 32;
/// Most elements a copy's XML holds.
const MAX_XML_ELEMENTS: usize = 1 << 23;

/// Another device's copy of the vault, checked and opened.
pub struct PeerVault {
    pub(super) db: Database,
    /// What the other device keeps on its computer, by UUID.
    pub(super) local: HashSet<Uuid>,
}

impl std::fmt::Debug for PeerVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PeerVault")
    }
}

impl Vault {
    /// This vault as it goes to another of the user's devices: a KDBX file
    /// encrypted with the vault's secret, without database custom data
    /// (paired browsers, the own-device key, `.env` revisions, the chat's
    /// key, other programs' settings), without anything marked
    /// [`super::LOCAL`], and without removal records older than
    /// [`KEEP_REMOVED_MS`].
    pub fn sync_copy(&self) -> Result<Zeroizing<Vec<u8>>> {
        let local = local_set(&self.db);
        let mut db = self.db.clone();
        strip(&mut db);
        newest_removals(&mut db.deleted_objects, true);
        // Not compressed: the receiver reads it without inflating anything.
        db.config.compression_config = CompressionConfig::None;
        if !local.is_empty() {
            let mut ids: Vec<String> = local.iter().map(Uuid::to_string).collect();
            ids.sort();
            let json = serde_json::to_string(&ids).map_err(|e| Error::Parse(e.to_string()))?;
            db.meta.custom_data.insert(
                LOCAL_IDS.to_owned(),
                CustomDataItem {
                    value: Some(CustomDataValue::String(json)),
                    last_modification_time: None,
                },
            );
        }
        Ok(Zeroizing::new(serialize(&db, &self.secret)?))
    }

    /// Opens a copy another of the user's devices sent: it must be this
    /// vault (it opens with this secret and has this root), within bounds,
    /// and it is read without what never syncs. It must be KDBX 4 without
    /// compression, and its XML is checked before it is parsed
    /// ([`read_bounded`]). Times ahead of this clock count as now, and each
    /// entry keeps only its newest [`MAX_VERSIONS`] earlier versions.
    pub fn open_sync_copy(&self, bytes: &[u8]) -> Result<PeerVault> {
        let mut db = read_bounded(bytes, &self.secret).map_err(|error| match error {
            Error::WrongPassphrase => Error::invalid("another vault"),
            other => other,
        })?;
        if db.root().id().uuid() != self.db.root().id().uuid() {
            return Err(Error::invalid("another vault"));
        }
        check(&db)?;
        let local = local_ids(&db)?;
        strip(&mut db);
        settle_times(&mut db);
        Ok(PeerVault { db, local })
    }

    /// The database as it goes to a new device of the user's, which makes
    /// it its vault: whole, but not compressed, so that the receiver reads
    /// it within bounds ([`check_moved`]). Fails with [`Error::Conflict`]
    /// if the file changed on disk since it was read here.
    pub fn moved_copy(&self) -> Result<Zeroizing<Vec<u8>>> {
        let on_disk = read_database(&self.paths.database)?;
        if sha256(&on_disk) != self.disk_hash {
            return Err(Error::Conflict(self.paths.database.display().to_string()));
        }
        let mut db = self.db.clone();
        db.config.compression_config = CompressionConfig::None;
        Ok(Zeroizing::new(serialize(&db, &self.secret)?))
    }
}

/// Checks a vault another of the user's devices sent to become this one's
/// ([`Vault::moved_copy`]): KDBX 4 without compression, its XML within
/// bounds, sane key derivation, and `secret` opens it. A compressed file,
/// as older versions send, is [`Error::Unsupported`]: the sender needs the
/// new version.
pub fn check_moved(database: &[u8], secret: &SecretString) -> Result<()> {
    if kdf::compressed_kdbx(database) {
        return Err(Error::Unsupported(
            "a vault sent compressed, by an older version".into(),
        ));
    }
    read_bounded(database, secret).map(drop)
}

/// Reads a database another device sent, within bounds: at most
/// [`MAX_DATABASE_SIZE`], sane key derivation, KDBX 4 without compression,
/// and its payload, decrypted here first ([`payload`]): at most
/// [`MAX_ATTACHMENTS`] attachments in its inner header, and its XML
/// neither deeper than [`MAX_XML_DEPTH`] nor more than [`MAX_XML_ELEMENTS`]
/// elements, without a DTD and without attachments stored compressed in it.
/// The `keepass` crate allocates, inflates and recurses without limits;
/// this is the guard in front of it.
fn read_bounded(bytes: &[u8], secret: &SecretString) -> Result<Database> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_DATABASE_SIZE {
        return Err(Error::invalid("the copy is too large"));
    }
    kdf::check_kdbx(bytes)?;
    kdf::check_uncompressed_kdbx4(bytes)?;
    let decrypted = payload::decrypt(bytes, secret)?;
    let xml = payload::xml_start(&decrypted, MAX_ATTACHMENTS)?;
    check_xml(&decrypted[xml..])?;
    drop(decrypted);
    parse_database(bytes, secret)
}

/// Fails unless a database's XML is within the bounds of [`read_bounded`].
fn check_xml(xml: &[u8]) -> Result<()> {
    let bad = |what: &str| Error::invalid(format!("the copy's XML: {what}"));
    let find = |from: usize, needle: &[u8]| -> Result<usize> {
        xml.get(from..)
            .and_then(|rest| rest.windows(needle.len()).position(|w| w == needle))
            .map(|at| from + at + needle.len())
            .ok_or_else(|| bad("cut off"))
    };
    let (mut depth, mut elements, mut at) = (0usize, 0usize, 0usize);
    while let Some(start) = xml
        .get(at..)
        .and_then(|rest| rest.iter().position(|b| *b == b'<'))
        .map(|offset| at + offset)
    {
        let rest = &xml[start..];
        if rest.starts_with(b"<!--") {
            // Not the `-->` of `<!-->`: a comment ends after it starts.
            at = find(start + 4, b"-->")?;
            continue;
        }
        if rest.starts_with(b"<![CDATA[") {
            at = find(start, b"]]>")?;
            continue;
        }
        if rest.starts_with(b"<!") {
            return Err(bad("a document type"));
        }
        if rest.starts_with(b"<?") {
            at = find(start, b"?>")?;
            continue;
        }
        // The tag's end, minding quoted attribute values.
        let mut end = 1;
        let mut quote = None;
        loop {
            let c = *rest.get(end).ok_or_else(|| bad("cut off"))?;
            match quote {
                Some(q) if c == q => quote = None,
                None if c == b'"' || c == b'\'' => quote = Some(c),
                None if c == b'>' => break,
                _ => {}
            }
            end += 1;
        }
        let tag = &rest[..=end];
        at = start + end + 1;
        if tag.starts_with(b"</") {
            depth = depth.saturating_sub(1);
            continue;
        }
        elements += 1;
        if elements > MAX_XML_ELEMENTS {
            return Err(bad("too many elements"));
        }
        if compressed_binary(tag) {
            return Err(bad("a compressed attachment"));
        }
        if !tag.ends_with(b"/>") {
            depth += 1;
            if depth > MAX_XML_DEPTH {
                return Err(bad("too deep"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn check_xml_for_tests(xml: &[u8]) -> Result<()> {
    check_xml(xml)
}

/// Whether a start tag is a `Binary` whose `Compressed` attribute is
/// anything but false: the parser inflates such a value without a limit.
fn compressed_binary(tag: &[u8]) -> bool {
    let name_end = tag
        .iter()
        .position(|b| b.is_ascii_whitespace() || *b == b'/' || *b == b'>')
        .unwrap_or(tag.len());
    if tag.get(1..name_end) != Some(&b"Binary"[..]) {
        return false;
    }
    let Some(at) = tag.windows(11).position(|w| w == b"Compressed=") else {
        return false;
    };
    let value = &tag[at + 11..];
    let Some(quote) = value.first().copied() else {
        return true;
    };
    let inner = value.get(1..).unwrap_or_default();
    let end = inner
        .iter()
        .position(|b| *b == quote)
        .unwrap_or(inner.len());
    !inner[..end].eq_ignore_ascii_case(b"false")
}

/// Longest list of what the sender keeps on its computer that is read: a
/// UUID in quotes and a comma for each entry and group a copy may hold.
const MAX_LOCAL_IDS_LEN: usize = (MAX_ENTRIES + MAX_GROUPS) * 40;

/// What the sender keeps on its computer, from a copy's custom data; a list
/// longer than any copy needs is refused before it is parsed.
fn local_ids(db: &Database) -> Result<HashSet<Uuid>> {
    let Some(CustomDataValue::String(json)) = db
        .meta
        .custom_data
        .get(LOCAL_IDS)
        .and_then(|item| item.value.as_ref())
    else {
        return Ok(HashSet::new());
    };
    if json.len() > MAX_LOCAL_IDS_LEN {
        return Err(Error::invalid("the copy's list of local items is too long"));
    }
    Ok(serde_json::from_str::<Vec<String>>(json)
        .unwrap_or_default()
        .iter()
        .take(MAX_ENTRIES + MAX_GROUPS)
        .filter_map(|id| Uuid::parse_str(id).ok())
        .collect())
}

/// Keeps removal records within what a copy may carry: at most the newest
/// [`MAX_DELETED`], and, for a copy (`for_copy`), none older than
/// [`KEEP_REMOVED_MS`] (a vault's own stay in its file, as KeePass keeps
/// them).
pub(super) fn newest_removals(records: &mut HashMap<Uuid, Option<NaiveDateTime>>, for_copy: bool) {
    if for_copy {
        let oldest = Times::now() - Duration::milliseconds(KEEP_REMOVED_MS);
        records.retain(|_, when| when.is_none_or(|when| when >= oldest));
    }
    if records.len() > MAX_DELETED {
        let mut all: Vec<(Option<NaiveDateTime>, Uuid)> =
            records.iter().map(|(uuid, when)| (*when, *uuid)).collect();
        all.sort_unstable_by(|a, b| b.cmp(a));
        let keep: HashSet<Uuid> = all
            .iter()
            .take(MAX_DELETED)
            .map(|(_, uuid)| *uuid)
            .collect();
        records.retain(|uuid, _| keep.contains(uuid));
    }
}

/// Fails unless `db` is within bounds and no entry has a group's UUID.
fn check(db: &Database) -> Result<()> {
    if db.num_entries() > MAX_ENTRIES
        || db.num_groups() > MAX_GROUPS
        || db.deleted_objects.len() > MAX_DELETED
    {
        return Err(Error::invalid("the copy is too large"));
    }
    if db
        .iter_all_entries()
        .any(|entry| db.group(GroupId::from_uuid(entry.id().uuid())).is_some())
    {
        return Err(Error::invalid("an entry with a group's id"));
    }
    let mut stack = vec![(db.root().id(), 0usize)];
    while let Some((id, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            return Err(Error::invalid("groups too deep"));
        }
        if let Some(group) = db.group(id) {
            stack.extend(group.group_ids().map(|child| (child, depth + 1)));
        }
    }
    Ok(())
}

/// Takes out what never syncs: database custom data and anything local.
fn strip(db: &mut Database) {
    db.meta.custom_data.clear();
    let local = local_set(db);
    let groups: Vec<GroupId> = db
        .iter_all_groups()
        .map(|group| group.id())
        .filter(|id| local.contains(&id.uuid()) && *id != db.root().id())
        .collect();
    let entries: Vec<EntryId> = db
        .iter_all_entries()
        .map(|entry| entry.id())
        .filter(|id| local.contains(&id.uuid()))
        .collect();
    for id in entries {
        if let Some(entry) = db.entry_mut(id) {
            entry.remove();
        }
    }
    for id in groups {
        // A local group inside another went with it.
        if let Some(group) = db.group_mut(id) {
            group.remove();
        }
    }
    drop_unused_icons(db);
}

/// Removes the custom icons nothing left uses (an entry, an earlier
/// version of one, a group): the `keepass` crate writes them all, and one
/// a local item used would otherwise go in the copy.
fn drop_unused_icons(db: &mut Database) {
    let mut used = HashSet::new();
    let mut note = |icon: Option<&Icon>| {
        if let Some(Icon::Custom(id)) = icon {
            used.insert(*id);
        }
    };
    for entry in db.iter_all_entries() {
        note(entry.icon());
        let versions = entry.history.as_ref().map_or(0, |h| h.get_entries().len());
        for version in (0..versions).filter_map(|i| entry.historical(i)) {
            note(version.icon());
        }
    }
    for group in db.iter_all_groups() {
        note(group.icon());
    }
    let unused: Vec<_> = db
        .iter_all_custom_icons()
        .map(|icon| icon.id())
        .filter(|id| !used.contains(id))
        .collect();
    for id in unused {
        if let Some(icon) = db.custom_icon_mut(id) {
            icon.remove();
        }
    }
}

/// Times from another device's clock no later than this one's (plus a
/// little), and at most [`MAX_VERSIONS`] earlier versions per entry.
fn settle_times(db: &mut Database) {
    let now = Times::now();
    let latest = now + MAX_AHEAD;
    let clamp = |time: &mut Option<NaiveDateTime>| {
        if time.is_some_and(|time| time > latest) {
            *time = Some(now);
        }
    };
    let ids: Vec<EntryId> = db.iter_all_entries().map(|entry| entry.id()).collect();
    for id in ids {
        let Some(mut entry) = db.entry_mut(id) else {
            continue;
        };
        clamp(&mut entry.times.last_modification);
        clamp(&mut entry.times.creation);
        clamp(&mut entry.times.location_changed);
        let Some(history) = entry.history.as_ref() else {
            continue;
        };
        let mut versions = history.get_entries().clone();
        for version in &mut versions {
            clamp(&mut version.times.last_modification);
            clamp(&mut version.times.creation);
        }
        versions.sort_by_key(|version| version.times.last_modification);
        if versions.len() > MAX_VERSIONS {
            versions.drain(..versions.len() - MAX_VERSIONS);
        }
        let mut settled = History::default();
        for version in versions.into_iter().rev() {
            settled.add_entry(version);
        }
        entry.history = Some(settled);
    }
    let groups: Vec<GroupId> = db.iter_all_groups().map(|group| group.id()).collect();
    for id in groups {
        if let Some(mut group) = db.group_mut(id) {
            clamp(&mut group.times.last_modification);
            clamp(&mut group.times.creation);
        }
    }
    for when in db.deleted_objects.values_mut() {
        clamp(when);
    }
    db.remove_unused_attachments();
}
