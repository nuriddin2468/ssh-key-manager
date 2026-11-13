//! Making a plan's changes in the vault, in memory, as one change.
//!
//! The `keepass` crate keeps attachments in a pool that entries refer to,
//! and an earlier version's references can't be set from outside the
//! crate. So each version that comes from the other side is built on the
//! entry itself (whose attachments then are in this pool, under its UUID),
//! copied into its history, and the entry then set to what it ends as.
//!
//! Taking an attachment off an entry drops it from the pool unless another
//! entry refers to it, and the crate counts the entry's own earlier
//! versions as the entry. So before one leaves, a copy of the entry as it
//! is goes into the history of a temporary entry ([`Keeper`]), which holds
//! the files until the end, when the references are put right
//! ([`Database::remove_unused_attachments`]) and the keeper removed.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use keepass::Database;
use keepass::db::{
    CustomDataItem, Entry, EntryId, EntryMut, EntryRef, GroupId, GroupRef, Icon, Times, Value,
};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use uuid::Uuid;

use super::copy::newest_removals;
use super::model::{BIN, GROUP, Item, ROOT, Side, fingerprint, is_project_tag};
use super::plan::skips;
use super::plan::{ChangeOp, ItemKind};
use super::{LOCAL, MAX_ENTRIES, MAX_GROUPS, Pairs, PeerVault, VaultPlan};
use crate::sync::Hasher;
use crate::vault::Vault;
use crate::vault::envs::{is_environment, is_shared, referenced, settle_versions, variables_of};
use crate::vault::fields;
use crate::{Error, Result};

/// How many items of one kind a sync added, changed and removed here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    feature = "ts",
    derive(ts_rs::TS),
    ts(export, export_to = crate::TS_DIR, rename = "SyncCounts")
)]
pub struct Counts {
    pub added: u32,
    pub changed: u32,
    /// Deleted, or moved to the recycle bin.
    pub removed: u32,
}

/// What a sync did to the vault here, by kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct VaultCounts {
    pub logins: Counts,
    pub environments: Counts,
    pub shared: Counts,
    pub folders: Counts,
}

impl VaultCounts {
    fn of(&mut self, kind: ItemKind) -> &mut Counts {
        match kind {
            ItemKind::Login => &mut self.logins,
            ItemKind::Environment => &mut self.environments,
            ItemKind::Shared => &mut self.shared,
            ItemKind::Folder => &mut self.folders,
        }
    }

    /// Nothing changed.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// What the user, or the rules, chose to do with a plan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VaultChoices {
    /// The changes to make, by id.
    pub make: BTreeSet<String>,
    /// Conflicts settled for the other side's version.
    pub theirs: BTreeSet<String>,
    /// Conflicts settled for this side's version: the other's goes among
    /// the entry's earlier versions here too.
    pub kept: BTreeSet<String>,
}

/// What [`Vault::apply_sync`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VaultApplied {
    pub counts: VaultCounts,
    /// Changes left for the next sync: the item changed here meanwhile, or
    /// couldn't be put where it goes.
    pub skipped: BTreeSet<String>,
    /// Groups kept because something is still in them.
    pub kept: u32,
}

impl Vault {
    /// Makes the changes of `plan` the `choices` name, and settles its
    /// conflicts: for the other side's version (`theirs`), or for this
    /// side's (`kept`), whose entry then keeps the other's among its earlier
    /// versions, as the other side keeps this one's. An item that changed
    /// here since the plan is left alone. All in memory: on an error
    /// nothing is changed, and the caller saves.
    pub fn apply_sync(
        &mut self,
        peer: &PeerVault,
        plan: &VaultPlan,
        hasher: &Hasher,
        choices: &VaultChoices,
    ) -> Result<VaultApplied> {
        let snapshot = self.snapshot();
        match self.apply_inner(peer, plan, hasher, choices) {
            Ok(applied) => Ok(applied),
            Err(error) => {
                self.restore(snapshot);
                Err(error)
            }
        }
    }

    fn apply_inner(
        &mut self,
        peer: &PeerVault,
        plan: &VaultPlan,
        hasher: &Hasher,
        choices: &VaultChoices,
    ) -> Result<VaultApplied> {
        let mut applied = VaultApplied::default();
        let my_local = super::model::local_set(&self.db);
        let (mine_skip, their_skip) = skips(&self.db, peer);
        let their_side = Side::new(&peer.db, &plan.pairs, false, &their_skip);
        let t_items = their_side.items(hasher);
        let work = self.work(plan, hasher, &mine_skip, &t_items, choices, &mut applied);
        let mut groups = GroupMap::new(self, &peer.db, &plan.pairs, &mine_skip, &their_skip);
        let (deletions, rest): (Vec<Work>, Vec<Work>) =
            work.into_iter().partition(|w| w.op == ChangeOp::Delete);
        // Groups first, then entries, then what goes.
        let (folders, entries): (Vec<Work>, Vec<Work>) =
            rest.into_iter().partition(|w| w.kind == ItemKind::Folder);
        for item in &folders {
            let done = t_items
                .get(&item.id)
                .ok_or_else(|| Error::invalid("no such group"))
                .and_then(|t| match item.op {
                    ChangeOp::Add => groups.ensure(&mut self.db, &item.id).map(drop),
                    _ => groups.update(
                        &mut self.db,
                        &item.id,
                        &peer.db,
                        t.uuid,
                        item.fields.as_deref(),
                    ),
                });
            applied.note(item, done.is_ok());
        }
        let mut keeper = Keeper::default();
        for item in &entries {
            let their_entry = t_items
                .get(&item.id)
                .and_then(|t| peer.db.entry(EntryId::from_uuid(t.uuid)));
            let full = self.db.num_entries() >= MAX_ENTRIES;
            let done = their_entry.map_or_else(
                || Err(Error::invalid("no such entry")),
                |their| match item.op {
                    // A vault this full takes no more from a sync.
                    ChangeOp::Add if full => Err(Error::invalid("too many entries")),
                    ChangeOp::Add => {
                        add_entry(&mut self.db, &mut keeper, &mut groups, &their, &their_side)
                    }
                    _ => update_entry(
                        &mut self.db,
                        &mut keeper,
                        &mut groups,
                        &their,
                        &their_side,
                        item.fields.as_deref(),
                    ),
                },
            );
            applied.note(item, done.is_ok());
        }
        for id in &choices.kept {
            let their_entry = t_items
                .get(id)
                .filter(|t| t.kind != ItemKind::Folder)
                .and_then(|t| peer.db.entry(EntryId::from_uuid(t.uuid)));
            if let Some(their) = their_entry
                && self.db.entry(their.id()).is_some()
            {
                keep_theirs(&mut self.db, &mut keeper, &their);
            }
        }
        keeper.finish(&mut self.db);
        self.delete(peer, &groups, deletions, &mut applied)?;
        self.join_removal_records(peer, &my_local);
        self.db.remove_unused_attachments();
        self.sync_tags();
        Ok(applied)
    }

    /// What to do: the changes in `make` and the conflicts in `theirs`, but
    /// none for an item that changed here since the plan (left in
    /// `applied.skipped`).
    fn work(
        &self,
        plan: &VaultPlan,
        hasher: &Hasher,
        mine_skip: &HashSet<Uuid>,
        t_items: &BTreeMap<String, Item>,
        choices: &VaultChoices,
        applied: &mut VaultApplied,
    ) -> Vec<Work> {
        let (make, theirs) = (&choices.make, &choices.theirs);
        let now_items = Side::new(&self.db, &plan.pairs, true, mine_skip).items(hasher);
        let mut work: Vec<Work> = plan
            .changes
            .iter()
            .filter(|change| make.contains(&change.id))
            .map(|change| Work {
                id: change.id.clone(),
                kind: change.kind,
                op: change.op,
                fields: (!change.whole).then(|| change.fields.clone()),
                removal: change.removal,
            })
            .collect();
        for conflict in plan.conflicts.iter().filter(|c| theirs.contains(&c.id)) {
            let (here, there) = (now_items.get(&conflict.id), t_items.get(&conflict.id));
            let op = match (here, there) {
                (_, None) => ChangeOp::Delete,
                (None, Some(_)) => ChangeOp::Add,
                (Some(_), Some(_)) => ChangeOp::Update,
            };
            let binned = there.is_some_and(|t| t.in_bin) && here.is_some_and(|m| !m.in_bin);
            work.push(Work {
                id: conflict.id.clone(),
                kind: conflict.kind,
                op,
                fields: None,
                removal: op == ChangeOp::Delete || binned,
            });
        }
        work.retain(|item| {
            let now = now_items.get(&item.id).map(|i| &i.hashes);
            let same = plan
                .found
                .get(&item.id)
                .is_some_and(|found| found.as_ref() == now);
            if !same {
                applied.skipped.insert(item.id.clone());
            }
            same
        });
        work
    }

    /// Deletes what goes: shared values after the environments here that
    /// still use them got copies, groups last and only empty ones.
    fn delete(
        &mut self,
        peer: &PeerVault,
        groups: &GroupMap,
        deletions: Vec<Work>,
        applied: &mut VaultApplied,
    ) -> Result<()> {
        let (folders, entries): (Vec<Work>, Vec<Work>) = deletions
            .into_iter()
            .partition(|w| w.kind == ItemKind::Folder);
        let (shared, others): (Vec<Work>, Vec<Work>) = entries
            .into_iter()
            .partition(|w| w.kind == ItemKind::Shared);
        for item in others.iter().chain(&shared) {
            let Ok(uuid) = Uuid::parse_str(&item.id) else {
                continue;
            };
            if item.kind == ItemKind::Shared {
                self.release_shared(&item.id)?;
            }
            let when = peer
                .db
                .deleted_objects
                .get(&uuid)
                .copied()
                .flatten()
                .unwrap_or_else(Times::now);
            if let Some(entry) = self.db.entry_mut(EntryId::from_uuid(uuid)) {
                entry.remove();
                self.db.deleted_objects.insert(uuid, Some(when));
                applied.note(item, true);
            }
        }
        let mut folders: Vec<(usize, Work)> = folders
            .into_iter()
            .filter_map(|w| Some((depth(&self.db, groups.mine(&w.id)?), w)))
            .collect();
        folders.sort_by_key(|(depth, _)| std::cmp::Reverse(*depth));
        for (_, item) in folders {
            let Some(gid) = groups.mine(&item.id) else {
                continue;
            };
            let empty = self
                .db
                .group(gid)
                .is_some_and(|g| g.entry_ids().next().is_none() && g.group_ids().next().is_none());
            if !empty {
                applied.kept += 1;
                continue;
            }
            if let Some(group) = self.db.group_mut(gid) {
                group.remove();
                self.db
                    .deleted_objects
                    .insert(gid.uuid(), Some(Times::now()));
                applied.note(&item, true);
            }
        }
        Ok(())
    }

    /// Takes the other side's removal records, the old ones left out, but
    /// none for what is here after all.
    fn join_removal_records(&mut self, peer: &PeerVault, my_local: &HashSet<Uuid>) {
        let oldest =
            Times::now() - chrono::Duration::milliseconds(crate::vault::projects::KEEP_REMOVED_MS);
        for (uuid, when) in &peer.db.deleted_objects {
            let live = self.db.entry(EntryId::from_uuid(*uuid)).is_some()
                || self.db.group(GroupId::from_uuid(*uuid)).is_some();
            if live || my_local.contains(uuid) || when.is_some_and(|when| when < oldest) {
                continue;
            }
            let mine = self.db.deleted_objects.entry(*uuid).or_insert(*when);
            if when.is_some_and(|when| mine.is_none_or(|here| when > here)) {
                *mine = *when;
            }
        }
        // Within what another device takes in a copy.
        newest_removals(&mut self.db.deleted_objects, false);
    }

    /// The hashes of each item here, by common id, after a sync with the
    /// groups paired as `pairs`: the next snapshot, or (with a key both
    /// sides share) what [`super::digests`] compares.
    pub fn sync_items(
        &self,
        pairs: &Pairs,
        hasher: &Hasher,
    ) -> BTreeMap<String, crate::sync::Hashes> {
        Side::new(&self.db, pairs, true, &HashSet::new())
            .items(hasher)
            .into_iter()
            .map(|(id, item)| (id, item.hashes))
            .collect()
    }

    /// A string field of an item in a conflict, as this side (`theirs`
    /// false) or the other has it: for the user who asked to see it. Never
    /// a 2FA secret ([`crate::vault::is_otp_field`]).
    pub fn sync_value(
        &self,
        peer: &PeerVault,
        id: &str,
        field: &str,
        theirs: bool,
    ) -> Result<SecretString> {
        let name = field
            .strip_prefix("s:")
            .ok_or_else(|| Error::invalid("not a text field"))?;
        // A 2FA secret is never shown, in any of the forms it is kept in.
        if crate::vault::is_otp_field(name) {
            return Err(Error::invalid("a 2FA secret is never shown"));
        }
        let uuid = Uuid::parse_str(id).map_err(|_| Error::invalid("not an entry"))?;
        let db = if theirs { &peer.db } else { &self.db };
        if !theirs && super::model::local_set(db).contains(&uuid) {
            return Err(Error::NotFound("entry".into()));
        }
        let entry = db
            .entry(EntryId::from_uuid(uuid))
            .ok_or_else(|| Error::NotFound("entry".into()))?;
        let value = entry
            .fields
            .get(name)
            .ok_or_else(|| Error::NotFound("field".into()))?;
        Ok(SecretString::from(value.get().clone()))
    }

    /// Whether `field` of the item `id` is a secret on either side: an
    /// entry's password, or a field kept protected (a secret variable or
    /// custom field). Reads no value: the app asks before showing one.
    pub fn sync_value_secret(&self, peer: &PeerVault, id: &str, field: &str) -> bool {
        let Some(name) = field.strip_prefix("s:") else {
            return false;
        };
        if name == fields::PASSWORD {
            return true;
        }
        let Ok(uuid) = Uuid::parse_str(id) else {
            return false;
        };
        [&self.db, &peer.db].into_iter().any(|db| {
            db.entry(EntryId::from_uuid(uuid))
                .and_then(|entry| entry.fields.get(name).map(Value::is_protected))
                .unwrap_or(false)
        })
    }
}

impl PeerVault {
    /// The value the variable `name` takes from the copy's item `id`, for
    /// the system dialog that asks to allow it: the environment's variable,
    /// or the shared value's password; a reference to a shared value is
    /// read from the copy. `None` when the copy has none.
    pub fn variable(&self, id: &str, name: &str) -> Option<SecretString> {
        let uuid = Uuid::parse_str(id).ok()?;
        let entry = self.db.entry(EntryId::from_uuid(uuid))?;
        let value = if is_environment(&entry) {
            variables_of(&entry)
                .into_iter()
                .find(|var| var.name == name)?
                .value
        } else if is_shared(&entry) {
            SecretString::from(entry.get(fields::PASSWORD).unwrap_or_default())
        } else {
            return None;
        };
        let Some(shared) = referenced(value.expose_secret()) else {
            return Some(value);
        };
        let entry = self.db.entry(EntryId::from_uuid(shared))?;
        (is_shared(&entry) && !is_environment(&entry))
            .then(|| SecretString::from(entry.get(fields::PASSWORD).unwrap_or_default()))
    }
}

struct Work {
    id: String,
    kind: ItemKind,
    op: ChangeOp,
    /// The fields to take; `None` for the other side's whole version.
    fields: Option<Vec<String>>,
    /// It leaves the vault or goes to the recycle bin.
    removal: bool,
}

impl VaultApplied {
    /// Counts what was done, or leaves it for the next sync.
    fn note(&mut self, item: &Work, done: bool) {
        if !done {
            self.skipped.insert(item.id.clone());
            return;
        }
        let counts = self.counts.of(item.kind);
        match item.op {
            ChangeOp::Add => counts.added += 1,
            _ if item.removal => counts.removed += 1,
            ChangeOp::Update => counts.changed += 1,
            ChangeOp::Delete => counts.removed += 1,
        }
    }
}

fn depth(db: &Database, group: GroupId) -> usize {
    let mut depth = 0;
    let mut current = db.group(group).and_then(|g| g.parent().map(|p| p.id()));
    while let Some(id) = current {
        depth += 1;
        current = db.group(id).and_then(|g| g.parent().map(|p| p.id()));
        if depth > super::MAX_DEPTH * 2 {
            break;
        }
    }
    depth
}

/// The groups of both sides by common id.
struct GroupMap {
    /// Here: common id → group.
    mine: HashMap<String, GroupId>,
    /// There: common id → UUID, and each group's parent's common id.
    theirs: HashMap<String, Uuid>,
    parents: HashMap<Uuid, String>,
    /// There: each group as it is, to make one here.
    states: HashMap<Uuid, GroupState>,
}

impl GroupMap {
    fn new(
        vault: &Vault,
        theirs: &Database,
        pairs: &Pairs,
        mine_skip: &HashSet<Uuid>,
        their_skip: &HashSet<Uuid>,
    ) -> Self {
        let my_side = Side::new(&vault.db, pairs, true, mine_skip);
        let their_side = Side::new(theirs, pairs, false, their_skip);
        let mine = vault
            .db
            .iter_all_groups()
            .filter(|g| !my_side.is_local(g.id().uuid()))
            .map(|g| (my_side.canon(g.id().uuid()), g.id()))
            .collect();
        let mut map = HashMap::new();
        let mut parents = HashMap::new();
        let mut states = HashMap::new();
        for group in theirs.iter_all_groups() {
            let uuid = group.id().uuid();
            if their_side.is_local(uuid) {
                continue;
            }
            map.insert(their_side.canon(uuid), uuid);
            states.insert(uuid, GroupState::of(&group));
            if let Some(parent) = group.parent() {
                parents.insert(uuid, their_side.canon(parent.id().uuid()));
            }
        }
        Self {
            mine,
            theirs: map,
            parents,
            states,
        }
    }

    fn mine(&self, id: &str) -> Option<GroupId> {
        self.mine.get(id).copied()
    }

    /// The group here for the common id `id`, made (with its parents) as
    /// the other side has it if there is none.
    fn ensure(&mut self, db: &mut Database, id: &str) -> Result<GroupId> {
        let mut chain = Vec::new();
        let mut current = id.to_owned();
        while !self.mine.contains_key(&current) {
            if current == BIN {
                let bin = recycle_bin(db);
                self.mine.insert(BIN.into(), bin);
                break;
            }
            if current == ROOT || chain.len() > super::MAX_DEPTH {
                return Err(Error::invalid("no such group"));
            }
            let uuid = *self
                .theirs
                .get(&current)
                .ok_or_else(|| Error::invalid("no such group"))?;
            chain.push((current.clone(), uuid));
            current = self
                .parents
                .get(&uuid)
                .cloned()
                .ok_or_else(|| Error::invalid("no such group"))?;
        }
        while let Some((common, uuid)) = chain.pop() {
            if db.num_groups() >= MAX_GROUPS {
                return Err(Error::invalid("too many groups"));
            }
            let parent = self.parent_here(uuid)?;
            let mut parent = db
                .group_mut(parent)
                .ok_or_else(|| Error::invalid("no such group"))?;
            let mut made = parent
                .add_group_with_id(GroupId::from_uuid(uuid))
                .map_err(|_| Error::invalid("a group's id is taken"))?;
            if let Some(state) = self.states.get(&uuid) {
                state.put(&mut made, &|_| true);
                made.times = state.times.clone();
            }
            let made = made.id();
            self.mine.insert(common, made);
        }
        self.mine
            .get(id)
            .copied()
            .ok_or_else(|| Error::invalid("no such group"))
    }

    fn parent_here(&self, uuid: Uuid) -> Result<GroupId> {
        self.parents
            .get(&uuid)
            .and_then(|parent| self.mine.get(parent))
            .copied()
            .ok_or_else(|| Error::invalid("no such group"))
    }

    /// Takes `fields` (all when `None`) of the other side's group `uuid`
    /// into the group here with the common id `id`.
    fn update(
        &mut self,
        db: &mut Database,
        id: &str,
        theirs: &Database,
        uuid: Uuid,
        fields: Option<&[String]>,
    ) -> Result<()> {
        let here = self
            .mine(id)
            .ok_or_else(|| Error::invalid("no such group"))?;
        let their = theirs
            .group(GroupId::from_uuid(uuid))
            .ok_or_else(|| Error::invalid("no such group"))?;
        let all = fields.is_none();
        let wants = |key: &str| all || fields.is_some_and(|f| f.iter().any(|k| k == key));
        let state = GroupState::of(&their);
        if wants(GROUP) {
            let common = self
                .parents
                .get(&uuid)
                .cloned()
                .ok_or_else(|| Error::invalid("the root moves nowhere"))?;
            let target = self.ensure(db, &common)?;
            let mut group = db
                .group_mut(here)
                .ok_or_else(|| Error::invalid("no such group"))?;
            if group.as_ref().parent().map(|p| p.id()) != Some(target) {
                group
                    .move_to(target)
                    .map_err(|_| Error::invalid("a group can't go there"))?;
            }
        }
        let mut group = db
            .group_mut(here)
            .ok_or_else(|| Error::invalid("no such group"))?;
        state.put(&mut group, &wants);
        if all {
            group.times = state.times.clone();
        } else {
            group.times.last_modification = Some(Times::now());
        }
        Ok(())
    }
}

/// The recycle bin group, made the way KeePass does if there is none.
fn recycle_bin(db: &mut Database) -> GroupId {
    if let Some(bin) = db.recycle_bin() {
        return bin.id();
    }
    let mut root = db.root_mut();
    let mut bin = root.add_group();
    bin.name = "Recycle Bin".into();
    bin.set_icon_builtin(43);
    bin.enable_autotype = Some(false);
    bin.enable_searching = Some(false);
    let id = bin.id();
    db.meta.recyclebin_enabled = Some(true);
    db.meta.recyclebin_uuid = Some(id.uuid());
    db.meta.recyclebin_changed = Some(Times::now());
    id
}

/// A temporary entry whose earlier versions hold files an entry's own
/// versions still use while the entry changes.
#[derive(Default)]
struct Keeper {
    temp: Option<EntryId>,
}

impl Keeper {
    /// Keeps what the entry `id` refers to now.
    fn hold(&mut self, db: &mut Database, id: EntryId) {
        let Some(version) = db.entry(id).map(|entry| {
            let mut version: Entry = Entry::clone(&entry);
            version.history = None;
            version
        }) else {
            return;
        };
        let temp = if let Some(temp) = self.temp {
            temp
        } else {
            let temp = db.root_mut().add_entry().id();
            self.temp = Some(temp);
            temp
        };
        if let Some(mut keeper) = db.entry_mut(temp) {
            keeper
                .history
                .get_or_insert_with(keepass::db::History::default)
                .add_entry(version);
        }
        db.remove_unused_attachments();
    }

    /// Puts every reference right and removes the keeper.
    fn finish(&mut self, db: &mut Database) {
        db.remove_unused_attachments();
        if let Some(keeper) = self.temp.take().and_then(|id| db.entry_mut(id)) {
            keeper.remove();
        }
        db.remove_unused_attachments();
    }
}

/// A group's fields, taken out of a database.
#[derive(Clone)]
struct GroupState {
    name: String,
    notes: Option<String>,
    tags: Vec<String>,
    custom_data: HashMap<String, CustomDataItem>,
    enable_autotype: Option<bool>,
    default_autotype_sequence: Option<String>,
    enable_searching: Option<bool>,
    times: Times,
    icon: Option<IconState>,
}

impl GroupState {
    fn of(group: &GroupRef<'_>) -> Self {
        Self {
            name: group.name.clone(),
            notes: group.notes.clone(),
            tags: group.tags.clone(),
            custom_data: without_local(&group.custom_data),
            enable_autotype: group.enable_autotype,
            default_autotype_sequence: group.default_autotype_sequence.clone(),
            enable_searching: group.enable_searching,
            times: group.times.clone(),
            icon: IconState::of(group.icon(), group.custom_icon().map(|i| i.data.clone())),
        }
    }

    /// Puts the fields `wants` names on `group`.
    fn put(&self, group: &mut keepass::db::GroupMut<'_>, wants: &dyn Fn(&str) -> bool) {
        if wants("name") {
            group.name.clone_from(&self.name);
        }
        if wants("notes") {
            group.notes.clone_from(&self.notes);
        }
        if wants("tags") {
            group.tags.clone_from(&self.tags);
        }
        if wants("autotype") {
            group.enable_autotype = self.enable_autotype;
        }
        if wants("sequence") {
            group
                .default_autotype_sequence
                .clone_from(&self.default_autotype_sequence);
        }
        if wants("search") {
            group.enable_searching = self.enable_searching;
        }
        if wants("expiry") {
            group.times.expires = self.times.expires;
            group.times.expiry = self.times.expiry;
        }
        let keys: BTreeSet<String> = group
            .custom_data
            .keys()
            .chain(self.custom_data.keys())
            .filter(|key| *key != LOCAL)
            .cloned()
            .collect();
        for key in keys {
            if !wants(&format!("cd:{key}")) {
                continue;
            }
            match self.custom_data.get(&key) {
                Some(item) => {
                    group.custom_data.insert(key, item.clone());
                }
                None => {
                    group.custom_data.remove(&key);
                }
            }
        }
        if wants("icon") {
            match &self.icon {
                Some(IconState::BuiltIn(id)) => group.set_icon_builtin(*id),
                Some(IconState::Custom(data)) => {
                    let found = group
                        .as_ref()
                        .database()
                        .iter_all_custom_icons()
                        .find(|icon| icon.data == *data)
                        .map(|icon| icon.id());
                    match found {
                        Some(id) => {
                            let _ = group.set_icon_custom(id);
                        }
                        None => {
                            group.set_icon_custom_new(data.clone());
                        }
                    }
                }
                None => group.set_icon_none(),
            }
        }
    }
}

#[derive(Clone, PartialEq)]
enum IconState {
    BuiltIn(usize),
    Custom(Vec<u8>),
}

impl IconState {
    fn of(icon: Option<&Icon>, custom: Option<Vec<u8>>) -> Option<Self> {
        match (icon, custom) {
            (Some(Icon::BuiltIn(id)), _) => Some(Self::BuiltIn(*id)),
            (Some(Icon::Custom(_)), Some(data)) => Some(Self::Custom(data)),
            _ => None,
        }
    }
}

fn without_local(data: &HashMap<String, CustomDataItem>) -> HashMap<String, CustomDataItem> {
    data.iter()
        .filter(|(key, _)| *key != LOCAL)
        .map(|(key, item)| (key.clone(), item.clone()))
        .collect()
}

/// A version of an entry, taken out of a database: everything but its
/// place and history.
struct EntryState {
    fields: HashMap<String, Value<String>>,
    tags: Vec<String>,
    times: Times,
    custom_data: HashMap<String, CustomDataItem>,
    autotype: Option<keepass::db::AutoType>,
    foreground_color: Option<keepass::db::Color>,
    background_color: Option<keepass::db::Color>,
    override_url: Option<String>,
    quality_check: bool,
    icon: Option<IconState>,
    attachments: Vec<(String, Value<Vec<u8>>)>,
}

impl EntryState {
    fn of(entry: &EntryRef<'_>) -> Self {
        Self {
            fields: entry.fields.clone(),
            tags: entry.tags.clone(),
            times: entry.times.clone(),
            custom_data: without_local(&entry.custom_data),
            autotype: entry.autotype.clone(),
            foreground_color: entry.foreground_color.clone(),
            background_color: entry.background_color.clone(),
            override_url: entry.override_url.clone(),
            quality_check: entry.quality_check,
            icon: IconState::of(entry.icon(), entry.custom_icon().map(|i| i.data.clone())),
            attachments: entry
                .attachments_named()
                .map(|(name, attachment)| (name.to_owned(), attachment.data.clone()))
                .collect(),
        }
    }
}

/// Puts the fields `wants` names (by [`super::model`]'s names) of `state`
/// on the entry `id`: its attachments by name, keeping one whose content
/// is the same, and, before one leaves, putting right the references of
/// the versions in its history.
fn put_state(
    db: &mut Database,
    keeper: &mut Keeper,
    id: EntryId,
    state: &EntryState,
    wants: &dyn Fn(&str) -> bool,
) {
    put_attachments(db, keeper, id, state, wants);
    let Some(mut entry) = db.entry_mut(id) else {
        return;
    };
    put_fields(&mut entry, state, wants);
}

/// The attachments part of [`put_state`].
fn put_attachments(
    db: &mut Database,
    keeper: &mut Keeper,
    id: EntryId,
    state: &EntryState,
    wants: &dyn Fn(&str) -> bool,
) {
    let have: Vec<(String, Vec<u8>)> = db
        .entry(id)
        .map(|entry| {
            entry
                .attachments_named()
                .map(|(name, attachment)| (name.to_owned(), attachment.data.get().clone()))
                .collect()
        })
        .unwrap_or_default();
    let same = |name: &str, data: &[u8]| {
        state
            .attachments
            .iter()
            .any(|(n, d)| n == name && d.get().as_slice() == data)
    };
    let leaving: Vec<&String> = have
        .iter()
        .filter(|(name, data)| wants(&format!("a:{name}")) && !same(name, data))
        .map(|(name, _)| name)
        .collect();
    if !leaving.is_empty() {
        keeper.hold(db, id);
    }
    let Some(mut entry) = db.entry_mut(id) else {
        return;
    };
    for name in leaving {
        entry.remove_attachment_by_name(name);
    }
    for (name, data) in &state.attachments {
        let kept = have.iter().any(|(n, d)| n == name && d == data.get());
        if wants(&format!("a:{name}")) && !kept {
            entry.add_attachment(name.clone(), data.clone());
        }
    }
}

/// The rest of [`put_state`]: strings, custom data, tags and the look.
fn put_fields(entry: &mut EntryMut<'_>, state: &EntryState, wants: &dyn Fn(&str) -> bool) {
    let names: BTreeSet<String> = entry
        .fields
        .keys()
        .chain(state.fields.keys())
        .cloned()
        .collect();
    for name in names {
        if !wants(&format!("s:{name}")) {
            continue;
        }
        match state.fields.get(&name) {
            Some(value) => {
                entry.fields.insert(name, value.clone());
            }
            None => {
                entry.fields.remove(&name);
            }
        }
    }
    let keys: BTreeSet<String> = entry
        .custom_data
        .keys()
        .chain(state.custom_data.keys())
        .filter(|key| *key != LOCAL)
        .cloned()
        .collect();
    for key in keys {
        if !wants(&format!("cd:{key}")) {
            continue;
        }
        match state.custom_data.get(&key) {
            Some(item) => {
                entry.custom_data.insert(key, item.clone());
            }
            None => {
                entry.custom_data.remove(&key);
            }
        }
    }
    if wants("tags") {
        let mut tags: Vec<String> = state
            .tags
            .iter()
            .filter(|tag| !is_project_tag(tag))
            .cloned()
            .collect();
        tags.extend(entry.tags.iter().filter(|tag| is_project_tag(tag)).cloned());
        entry.tags = tags;
    }
    if wants("fg") {
        entry.foreground_color.clone_from(&state.foreground_color);
    }
    if wants("bg") {
        entry.background_color.clone_from(&state.background_color);
    }
    if wants("overrideUrl") {
        entry.override_url.clone_from(&state.override_url);
    }
    if wants("autotype") {
        entry.autotype.clone_from(&state.autotype);
    }
    if wants("qualityCheck") {
        entry.quality_check = state.quality_check;
    }
    if wants("expiry") {
        entry.times.expires = state.times.expires;
        entry.times.expiry = state.times.expiry;
    }
    if wants("icon") {
        set_icon(entry, state.icon.as_ref());
    }
}

fn set_icon(entry: &mut EntryMut<'_>, icon: Option<&IconState>) {
    match icon {
        Some(IconState::BuiltIn(id)) => entry.set_icon_builtin(*id),
        Some(IconState::Custom(data)) => {
            let found = entry
                .as_ref()
                .database()
                .iter_all_custom_icons()
                .find(|icon| icon.data == *data)
                .map(|icon| icon.id());
            match found {
                Some(id) => {
                    let _ = entry.set_icon_custom(id);
                }
                None => {
                    entry.set_icon_custom_new(data.clone());
                }
            }
        }
        None => entry.set_icon_none(),
    }
}

/// Every field, for a version taken whole.
fn all(_: &str) -> bool {
    true
}

/// Puts a copy of the entry as it is now into its own history.
fn keep_version(db: &mut Database, id: EntryId) {
    let Some(mut entry) = db.entry_mut(id) else {
        return;
    };
    let mut version: Entry = Entry::clone(&entry);
    version.history = None;
    entry
        .history
        .get_or_insert_with(keepass::db::History::default)
        .add_entry(version);
}

/// The earlier versions of the other side's entry this one hasn't got,
/// oldest first.
fn missing_versions(db: &Database, id: EntryId, their: &EntryRef<'_>) -> Vec<EntryState> {
    let have: HashSet<[u8; 32]> = db
        .entry(id)
        .map(|entry| {
            let count = entry.history.as_ref().map_or(0, |h| h.get_entries().len());
            (0..count)
                .filter_map(|i| entry.historical(i).map(|v| fingerprint(&v)))
                .collect()
        })
        .unwrap_or_default();
    let count = their.history.as_ref().map_or(0, |h| h.get_entries().len());
    let mut versions: Vec<(Option<chrono::NaiveDateTime>, EntryState)> = (0..count)
        .filter_map(|i| their.historical(i))
        .filter(|version| !have.contains(&fingerprint(version)))
        .map(|version| (version.times.last_modification, EntryState::of(&version)))
        .collect();
    versions.sort_by_key(|(time, _)| *time);
    versions.into_iter().map(|(_, state)| state).collect()
}

/// Builds each of `versions` on the entry and keeps it in its history.
fn add_versions(db: &mut Database, keeper: &mut Keeper, id: EntryId, versions: &[EntryState]) {
    for version in versions {
        put_state(db, keeper, id, version, &all);
        if let Some(mut entry) = db.entry_mut(id) {
            entry.times = version.times.clone();
        }
        keep_version(db, id);
    }
}

/// Adds the other side's entry here, with its history, where it is there.
fn add_entry(
    db: &mut Database,
    keeper: &mut Keeper,
    groups: &mut GroupMap,
    their: &EntryRef<'_>,
    their_side: &Side<'_>,
) -> Result<()> {
    let target = groups.ensure(db, &their_side.canon(their.parent().id().uuid()))?;
    // In the recycle bin there: made where it was before, so that restoring
    // it puts it back there here too.
    let before = (Some(target) == groups.mine(BIN))
        .then(|| their.previous_parent())
        .flatten()
        .and_then(|group| groups.mine(&their_side.canon(group.id().uuid())));
    let id = their.id();
    db.group_mut(before.unwrap_or(target))
        .ok_or_else(|| Error::invalid("no such group"))?
        .add_entry_with_id(id)
        .map_err(|_| Error::invalid("an entry's id is taken"))?;
    if let Some(mut entry) = db.entry_mut(id) {
        entry.history = Some(keepass::db::History::default());
        if before.is_some() {
            let _ = entry.move_to(target);
        }
    }
    let state = EntryState::of(their);
    let versions = missing_versions(db, id, their);
    add_versions(db, keeper, id, &versions);
    put_state(db, keeper, id, &state, &all);
    if let Some(mut entry) = db.entry_mut(id) {
        entry.times = state.times.clone();
    }
    settle_versions(db, id, false);
    Ok(())
}

/// Takes `fields` of the other side's entry (all when `None`) into this
/// one, keeping this one's version and the other's earlier ones in its
/// history.
fn update_entry(
    db: &mut Database,
    keeper: &mut Keeper,
    groups: &mut GroupMap,
    their: &EntryRef<'_>,
    their_side: &Side<'_>,
    fields: Option<&[String]>,
) -> Result<()> {
    let id = their.id();
    let mine = EntryState::of(
        &db.entry(id)
            .ok_or_else(|| Error::NotFound("entry".into()))?,
    );
    let wants = |key: &str| fields.is_none_or(|fields| fields.iter().any(|k| k == key));
    let target = if wants(GROUP) {
        Some(groups.ensure(db, &their_side.canon(their.parent().id().uuid()))?)
    } else {
        None
    };
    let state = EntryState::of(their);
    let displaced = db
        .entry(id)
        .map(|entry| fingerprint(&entry))
        .ok_or_else(|| Error::NotFound("entry".into()))?;
    keep_version(db, id);
    let versions = missing_versions(db, id, their);
    add_versions(db, keeper, id, &versions);
    // Back to this side's version, then the fields taken.
    put_state(db, keeper, id, &mine, &all);
    put_state(db, keeper, id, &state, &wants);
    if let Some(mut entry) = db.entry_mut(id) {
        if fields.is_none() {
            entry.times = state.times.clone();
        } else {
            entry.times = mine.times.clone();
            entry.times.last_modification = Some(Times::now());
        }
        if let Some(target) = target
            && entry.as_ref().parent().id() != target
        {
            let _ = entry.move_to(target);
            entry.times.location_changed = Some(Times::now());
        }
    }
    settle_keeping(db, id, &[displaced]);
    Ok(())
}

/// Keeps the other side's version of an entry this side kept in a
/// conflict among its earlier versions, the entry itself as it is.
fn keep_theirs(db: &mut Database, keeper: &mut Keeper, their: &EntryRef<'_>) {
    let id = their.id();
    let Some(mine) = db.entry(id).map(|entry| EntryState::of(&entry)) else {
        return;
    };
    add_versions(db, keeper, id, &[EntryState::of(their)]);
    put_state(db, keeper, id, &mine, &all);
    if let Some(mut entry) = db.entry_mut(id) {
        entry.times = mine.times.clone();
    }
    settle_keeping(db, id, &[fingerprint(their)]);
}

/// Puts an entry's earlier versions in order and keeps the newest the
/// vault's limit allows ([`settle_versions`]), but never one of `keep`:
/// the version a sync just displaced stays, whatever the limit.
fn settle_keeping(db: &mut Database, id: EntryId, keep: &[[u8; 32]]) {
    let max = match db.meta.history_max_items {
        None => Some(10),
        Some(max) if max < 0 => None,
        Some(max) => Some(usize::try_from(max).unwrap_or(usize::MAX)),
    };
    let Some(entry) = db.entry(id) else {
        return;
    };
    let count = entry.history.as_ref().map_or(0, |h| h.get_entries().len());
    let mut versions: Vec<(Option<chrono::NaiveDateTime>, bool, Entry)> = (0..count)
        .filter_map(|i| entry.historical(i))
        .map(|version| {
            let kept = keep.contains(&fingerprint(&version));
            (
                version.times.last_modification,
                kept,
                Entry::clone(&version),
            )
        })
        .collect();
    versions.sort_by_key(|(time, _, _)| *time);
    if let Some(max) = max {
        while versions.len() > max {
            let Some(oldest) = versions.iter().position(|(_, kept, _)| !kept) else {
                break;
            };
            versions.remove(oldest);
        }
    }
    let mut settled = keepass::db::History::default();
    for (_, _, version) in versions.into_iter().rev() {
        settled.add_entry(version);
    }
    if let Some(mut entry) = db.entry_mut(id) {
        entry.history = Some(settled);
    }
}
