//! The copy of the vault one device sends another, and the checks on one
//! that comes.

use chrono::{Duration, NaiveDateTime};
use keepass::Database;
use keepass::db::{EntryId, GroupId, History, Times};
use zeroize::Zeroizing;

use super::model::local_set;
use super::{MAX_DELETED, MAX_DEPTH, MAX_ENTRIES, MAX_GROUPS, MAX_VERSIONS};
use crate::vault::projects::KEEP_REMOVED_MS;
use crate::vault::{MAX_DATABASE_SIZE, Vault, parse_database, serialize};
use crate::{Error, Result};

/// How far ahead of this computer's clock a time from another device is
/// believed; a later one counts as now.
const MAX_AHEAD: Duration = Duration::minutes(5);

/// Another device's copy of the vault, checked and opened.
pub struct PeerVault {
    pub(super) db: Database,
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
        let mut db = self.db.clone();
        strip(&mut db);
        let oldest = Times::now() - Duration::milliseconds(KEEP_REMOVED_MS);
        db.deleted_objects
            .retain(|_, when| when.is_none_or(|when| when >= oldest));
        Ok(Zeroizing::new(serialize(&db, &self.secret)?))
    }

    /// Opens a copy another of the user's devices sent: it must be this
    /// vault (it opens with this secret and has this root), within bounds,
    /// and it is read without what never syncs. Times ahead of this clock
    /// count as now, and each entry keeps only its newest
    /// [`MAX_VERSIONS`] earlier versions.
    pub fn open_sync_copy(&self, bytes: &[u8]) -> Result<PeerVault> {
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_DATABASE_SIZE {
            return Err(Error::invalid("the copy is too large"));
        }
        let mut db = parse_database(bytes, &self.secret).map_err(|error| match error {
            Error::WrongPassphrase => Error::invalid("another vault"),
            other => other,
        })?;
        if db.root().id().uuid() != self.db.root().id().uuid() {
            return Err(Error::invalid("another vault"));
        }
        check(&db)?;
        strip(&mut db);
        settle_times(&mut db);
        Ok(PeerVault { db })
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
