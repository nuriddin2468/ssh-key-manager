//! What to take from another device's copy of the vault.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use chrono::NaiveDateTime;
use keepass::Database;
use keepass::db::{EntryId, GroupId, Times, fields};
use serde::Serialize;
use uuid::Uuid;

use super::model::{GROUP, Item, KIND, Side, local_set};
use super::{MAX_DEPTH, Pair, Pairs, PeerVault, VaultBase};
use crate::sync::{Hasher, Hashes, Outcome, plan_hashed};
use crate::vault::Vault;
use crate::vault::envs::{PART, risky_variable, shared_references};
use crate::vault::projects::KEEP_REMOVED_MS;

/// What a synced item is, for people.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    feature = "ts",
    derive(ts_rs::TS),
    ts(export, export_to = crate::TS_DIR, rename = "SyncItemKind")
)]
pub enum ItemKind {
    /// A password, a host's or a key's included.
    Login,
    Environment,
    /// A value environments share.
    Shared,
    /// A group.
    Folder,
}

impl ItemKind {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Environment => "environment",
            Self::Shared => "shared",
            Self::Folder => "folder",
        }
    }
}

/// What a change does here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    feature = "ts",
    derive(ts_rs::TS),
    ts(export, export_to = crate::TS_DIR, rename = "SyncChangeOp")
)]
pub enum ChangeOp {
    Add,
    Update,
    Delete,
}

/// A change the sync would make here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct VaultChange {
    /// The entry's UUID, or the group's common id.
    pub id: String,
    pub kind: ItemKind,
    /// Its title, an environment as `Shop · backend · prod`, a group's
    /// path.
    pub label: String,
    pub op: ChangeOp,
    /// For an update, the fields taken: `s:<name>` a string field (an
    /// environment's variable), `a:<name>` an attachment, `cd:<key>`
    /// custom data, `group` the place, `tags`, and the look.
    pub fields: Vec<String>,
    /// It leaves the vault, or goes to the recycle bin, here.
    pub removal: bool,
    /// It was in the recycle bin here.
    pub from_bin: bool,
    /// Variables it adds or changes that make programs load code.
    pub risky: Vec<String>,
    /// The other side's version is taken whole.
    #[serde(skip)]
    pub(super) whole: bool,
}

/// What one side did to an item both changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    feature = "ts",
    derive(ts_rs::TS),
    ts(export, export_to = crate::TS_DIR, rename = "SyncParty")
)]
pub enum Party {
    Changed,
    Deleted,
}

/// An item both sides changed, differently, or one deleted and the other
/// changed: the user keeps one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct VaultConflict {
    pub id: String,
    pub kind: ItemKind,
    pub label: String,
    /// What this side did.
    pub here: Party,
    /// What the other side did.
    pub there: Party,
    /// The fields that differ, named as [`VaultChange::fields`]; values
    /// only on request ([`Vault::sync_value`]).
    pub fields: Vec<String>,
    /// Variables taking the other side's version would add or change that
    /// make programs load code.
    pub risky: Vec<String>,
    /// The other side's version is in the recycle bin and this side's
    /// isn't: taking it moves the item there, as a deletion does.
    pub to_bin: bool,
}

/// What to take from the other device's copy, and what the user decides.
#[derive(Debug, Clone, Default)]
pub struct VaultPlan {
    pub changes: Vec<VaultChange>,
    pub conflicts: Vec<VaultConflict>,
    /// Groups paired, old and new: this side's UUID → the other's.
    pub pairs: Pairs,
    /// Each item a change or conflict touches here, as the plan found it,
    /// so that one changed meanwhile is left alone.
    pub(super) found: BTreeMap<String, Option<Hashes>>,
}

impl Vault {
    /// Works out what to take from another device's copy against `base`,
    /// this computer's snapshot of the last sync with it.
    pub fn plan_sync(&self, peer: &PeerVault, base: &VaultBase, hasher: &Hasher) -> VaultPlan {
        let (mine_skip, their_skip) = skips(&self.db, peer);
        let pairs = pair_groups(&self.db, &peer.db, base, &mine_skip, &their_skip);
        let mine = Side::new(&self.db, &pairs, true, &mine_skip);
        let theirs = Side::new(&peer.db, &pairs, false, &their_skip);
        let m_items = mine.items(hasher);
        let t_items = theirs.items(hasher);
        let labels = Labels::new(self);
        let blocked = blocked(&self.db, &mine);
        let refs = references(&self.db, &peer.db);
        let mut plan = VaultPlan {
            pairs,
            ..VaultPlan::default()
        };
        for (id, outcome) in outcomes(&base.base, &peer.db, &m_items, &t_items) {
            let (m, t) = (m_items.get(&id), t_items.get(&id));
            let outcome = match (&outcome, t) {
                // Only there, with no snapshot: unless this side deleted it.
                (Outcome::Add, Some(t)) => match removed(&self.db, t.uuid) {
                    None => outcome,
                    Some(when) if t.modified.is_none_or(|changed| when >= changed) => {
                        continue;
                    }
                    Some(_) => Outcome::Conflict,
                },
                _ => outcome,
            };
            // Something kept on this computer holds the item here: it
            // stays, and isn't asked about again.
            let deletes = matches!(outcome, Outcome::Delete)
                || (matches!(outcome, Outcome::Conflict) && t.is_none());
            if deletes && blocked.contains(&id) {
                continue;
            }
            let label = match (m, t) {
                (Some(m), _) => labels.of(&self.db, &mine, m),
                (None, Some(t)) => labels.of(&peer.db, &theirs, t),
                (None, None) => continue,
            };
            plan.found.insert(id.clone(), m.map(|m| m.hashes.clone()));
            plan.record(id, label, outcome, (m, t), &refs);
        }
        plan
    }
}

/// The UUIDs each side leaves out of a sync, besides what it keeps local
/// itself: this side, what the other keeps on its computer (sent as ids
/// only, so it isn't taken for deleted); both, an id that is an entry on
/// one side and a group on the other, which is never merged.
pub(super) fn skips(mine: &Database, peer: &PeerVault) -> (HashSet<Uuid>, HashSet<Uuid>) {
    let ids = |db: &Database| -> (HashSet<Uuid>, HashSet<Uuid>) {
        (
            db.iter_all_entries().map(|e| e.id().uuid()).collect(),
            db.iter_all_groups().map(|g| g.id().uuid()).collect(),
        )
    };
    let ((my_entries, my_groups), (their_entries, their_groups)) = (ids(mine), ids(&peer.db));
    let crossed: HashSet<Uuid> = my_entries
        .intersection(&their_groups)
        .chain(my_groups.intersection(&their_entries))
        .copied()
        .collect();
    let mine_skip = peer
        .local
        .iter()
        .copied()
        .chain(crossed.iter().copied())
        .collect();
    let their_skip = local_set(mine).into_iter().chain(crossed).collect();
    (mine_skip, their_skip)
}

/// The items here whose deletion something kept on this computer blocks:
/// the groups a local entry or group is in, and the shared values a local
/// environment uses.
fn blocked(db: &Database, mine: &Side<'_>) -> HashSet<String> {
    let mut blocked = HashSet::new();
    for uuid in local_set(db) {
        let parent = db
            .entry(EntryId::from_uuid(uuid))
            .map(|entry| entry.parent().id())
            .or_else(|| {
                db.group(GroupId::from_uuid(uuid))
                    .and_then(|group| group.parent().map(|p| p.id()))
            });
        let mut current = parent;
        let mut steps = 0;
        while let Some(id) = current {
            blocked.insert(mine.canon(id.uuid()));
            current = db.group(id).and_then(|g| g.parent().map(|p| p.id()));
            steps += 1;
            if steps > MAX_DEPTH * 2 {
                break;
            }
        }
        if let Some(entry) = db.entry(EntryId::from_uuid(uuid)) {
            for (_, shared) in shared_references(&entry) {
                blocked.insert(shared.to_string());
            }
        }
    }
    blocked
}

/// For each shared value, by id, the names of the variables that use it,
/// here and in the other side's copy.
type References = HashMap<String, BTreeSet<String>>;

fn references(mine: &Database, theirs: &Database) -> References {
    let mut refs = References::new();
    for db in [mine, theirs] {
        for entry in db.iter_all_entries() {
            for (name, shared) in shared_references(&entry) {
                refs.entry(shared.to_string()).or_default().insert(name);
            }
        }
    }
    refs
}

impl VaultPlan {
    /// Adds what the plan says about one item.
    fn record(
        &mut self,
        id: String,
        label: String,
        outcome: Outcome,
        (m, t): (Option<&Item>, Option<&Item>),
        refs: &References,
    ) {
        let kind = m.or(t).map_or(ItemKind::Login, |item| item.kind);
        let change = |op, fields: Vec<String>| VaultChange {
            id: id.clone(),
            kind,
            label: label.clone(),
            op,
            fields,
            removal: false,
            from_bin: false,
            risky: Vec::new(),
            whole: true,
        };
        match (outcome, m, t) {
            (Outcome::Add, None, Some(t)) => self.changes.push(VaultChange {
                risky: risky(t, &id, t.hashes.keys(), refs),
                ..change(ChangeOp::Add, Vec::new())
            }),
            (Outcome::Delete, Some(m), _) => self.changes.push(VaultChange {
                removal: true,
                from_bin: m.in_bin,
                ..change(ChangeOp::Delete, Vec::new())
            }),
            (Outcome::Take(fields), Some(m), Some(t)) => {
                let differ: BTreeSet<String> = differing(m, t).into_iter().collect();
                self.changes.push(VaultChange {
                    risky: risky(t, &id, fields.iter(), refs),
                    whole: fields.iter().cloned().collect::<BTreeSet<_>>() == differ,
                    removal: fields.iter().any(|f| f == GROUP) && t.in_bin && !m.in_bin,
                    ..change(ChangeOp::Update, fields.clone())
                });
            }
            (_, m, t) => {
                let party = |item: Option<&Item>| {
                    if item.is_some() {
                        Party::Changed
                    } else {
                        Party::Deleted
                    }
                };
                let (fields, risky) = match (m, t) {
                    (Some(m), Some(t)) => {
                        let differ = differing(m, t);
                        let risky = risky(t, &id, differ.iter(), refs);
                        (differ, risky)
                    }
                    (None, Some(t)) => (Vec::new(), risky(t, &id, t.hashes.keys(), refs)),
                    _ => (Vec::new(), Vec::new()),
                };
                let to_bin = matches!((m, t), (Some(m), Some(t)) if t.in_bin && !m.in_bin);
                self.conflicts.push(VaultConflict {
                    id,
                    kind,
                    label,
                    here: party(m),
                    there: party(t),
                    fields,
                    risky,
                    to_bin,
                });
            }
        }
    }
}

/// What the three-way merge says about each item, by id: items that are
/// something else on the other side are conflicts, never merged field by
/// field, and one only here with no snapshot goes if the other side's
/// removal record is newer than its last change (a conflict if older).
fn outcomes(
    base: &crate::sync::Base,
    theirs: &Database,
    m_items: &BTreeMap<String, Item>,
    t_items: &BTreeMap<String, Item>,
) -> Vec<(String, Outcome)> {
    let odd: BTreeSet<&String> = m_items
        .iter()
        .filter(|(id, m)| t_items.get(*id).is_some_and(|t| t.kind != m.kind))
        .map(|(id, _)| id)
        .collect();
    let by_hash = |items: &BTreeMap<String, Item>| -> BTreeMap<String, Hashes> {
        items
            .iter()
            .filter(|(id, _)| !odd.contains(id))
            .map(|(id, item)| (id.clone(), item.hashes.clone()))
            .collect()
    };
    let mut outcomes = plan_hashed(base, &by_hash(m_items), &by_hash(t_items));
    outcomes.extend(odd.iter().map(|id| ((*id).clone(), Outcome::Conflict)));
    for (id, m) in m_items {
        if t_items.contains_key(id) || base.items.contains_key(id) {
            continue;
        }
        match removed(theirs, m.uuid) {
            None => {}
            Some(when) if m.modified.is_none_or(|changed| when >= changed) => {
                outcomes.push((id.clone(), Outcome::Delete));
            }
            Some(_) => outcomes.push((id.clone(), Outcome::Conflict)),
        }
    }
    outcomes.sort_by(|a, b| a.0.cmp(&b.0));
    outcomes
}

/// When `db` deleted the item `uuid` for good: `None` if it has no record
/// of it, or one older than [`KEEP_REMOVED_MS`]; a record without a time
/// counts as made at the start of 1970, so it deletes nothing changed.
fn removed(db: &Database, uuid: Uuid) -> Option<NaiveDateTime> {
    let oldest = Times::now() - chrono::Duration::milliseconds(KEEP_REMOVED_MS);
    match db.deleted_objects.get(&uuid).copied()? {
        Some(when) => (when >= oldest).then_some(when),
        None => Some(Times::epoch()),
    }
}

/// The fields two versions of an item don't have alike, but the kind.
fn differing(m: &Item, t: &Item) -> Vec<String> {
    let keys: BTreeSet<&String> = m.hashes.keys().chain(t.hashes.keys()).collect();
    keys.into_iter()
        .filter(|key| *key != KIND && m.hashes.get(*key) != t.hashes.get(*key))
        .cloned()
        .collect()
}

/// The variables that `fields` of the other side's version add or change
/// and that make programs load code: an environment's own, or, for a shared
/// value whose value changes, the names of the variables here or there that
/// use it. A field only removed isn't counted.
fn risky<'a>(
    theirs: &Item,
    id: &str,
    fields: impl Iterator<Item = &'a String>,
    refs: &References,
) -> Vec<String> {
    let fields: Vec<&String> = fields
        .filter(|field| theirs.hashes.contains_key(*field))
        .collect();
    let mut names: Vec<String> = match theirs.kind {
        ItemKind::Environment => fields
            .iter()
            .filter_map(|field| field.strip_prefix("s:"))
            .map(|name| name.strip_prefix("env.").unwrap_or(name))
            .filter(|name| risky_variable(name))
            .map(str::to_owned)
            .collect(),
        ItemKind::Shared if fields.iter().any(|field| *field == "s:Password") => refs
            .get(id)
            .into_iter()
            .flatten()
            .filter(|name| risky_variable(name))
            .cloned()
            .collect(),
        _ => Vec::new(),
    };
    names.sort();
    names.dedup();
    names
}

/// Pairs the groups each side made separately for the same thing: a group
/// only one side has, by UUID, with the same name and the same parent (in
/// common terms) as a group only the other side has. Of several such, the
/// first by UUID on each side pair, and so on, so both sides pair alike. A
/// new pair goes by the id the snapshot holds, if it holds one of the two,
/// else by the smaller; a pair stays, with its id, while either group is
/// there, so deleting one doesn't change what the other is called.
fn pair_groups(
    mine: &Database,
    theirs: &Database,
    base: &VaultBase,
    mine_skip: &HashSet<Uuid>,
    their_skip: &HashSet<Uuid>,
) -> Pairs {
    let has = |db: &Database, uuid: &str| {
        Uuid::parse_str(uuid).is_ok_and(|uuid| db.group(GroupId::from_uuid(uuid)).is_some())
    };
    let mut pairs: Pairs = base
        .pairs
        .iter()
        .filter(|(m, pair)| {
            let t = &pair.there;
            *m != t && (has(mine, m) || has(theirs, t)) && !has(mine, t) && !has(theirs, m)
        })
        .map(|(m, pair)| (m.clone(), pair.clone()))
        .collect();
    let held = |id: &String| base.base.items.contains_key(id);
    for _ in 0..=MAX_DEPTH {
        let my_side = Side::new(mine, &pairs, true, mine_skip);
        let their_side = Side::new(theirs, &pairs, false, their_skip);
        let paired_mine: HashSet<&String> = pairs.keys().collect();
        let paired_theirs: HashSet<&String> = pairs.values().map(|pair| &pair.there).collect();
        let unmatched =
            |side: &Side<'_>, db: &Database, other: &Database, paired: &HashSet<&String>| {
                let mut buckets: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
                let root = db.root().id();
                for group in db.iter_all_groups() {
                    let uuid = group.id().uuid();
                    let text = uuid.to_string();
                    if group.id() == root
                        || Some(uuid) == db.meta.recyclebin_uuid
                        || side.is_local(uuid)
                        || other.group(GroupId::from_uuid(uuid)).is_some()
                        || paired.contains(&text)
                    {
                        continue;
                    }
                    let parent = group.parent().map_or(root.uuid(), |p| p.id().uuid());
                    buckets
                        .entry((side.canon(parent), group.name.clone()))
                        .or_default()
                        .push(text);
                }
                for uuids in buckets.values_mut() {
                    uuids.sort();
                }
                buckets
            };
        let m_buckets = unmatched(&my_side, mine, theirs, &paired_mine);
        let t_buckets = unmatched(&their_side, theirs, mine, &paired_theirs);
        let mut found = Vec::new();
        for (key, m_uuids) in &m_buckets {
            if let Some(t_uuids) = t_buckets.get(key) {
                found.extend(m_uuids.iter().cloned().zip(t_uuids.iter().cloned()));
            }
        }
        if found.is_empty() {
            break;
        }
        for (m, t) in found {
            let common = match (held(&m), held(&t)) {
                (true, false) => m.clone(),
                (false, true) => t.clone(),
                _ => m.clone().min(t.clone()),
            };
            pairs.insert(m, Pair { there: t, common });
        }
    }
    pairs
}

/// How items are named for people.
struct Labels {
    /// Environments' projects' names, by entry id.
    projects: BTreeMap<String, String>,
}

impl Labels {
    fn new(vault: &Vault) -> Self {
        let mut projects = BTreeMap::new();
        for project in vault.projects() {
            for env in project.environments {
                projects.insert(env, project.name.clone());
            }
        }
        Self { projects }
    }

    fn of(&self, db: &Database, side: &Side<'_>, item: &Item) -> String {
        if item.kind == ItemKind::Folder {
            let mut path = Vec::new();
            let mut current = Some(GroupId::from_uuid(item.uuid));
            while let Some(group) = current.and_then(|id| db.group(id)) {
                let Some(parent) = group.parent().map(|p| p.id()) else {
                    break;
                };
                path.push(group.name.clone());
                current = Some(parent);
                if path.len() > MAX_DEPTH {
                    break;
                }
            }
            path.reverse();
            return path.join("/");
        }
        let Some(entry) = db.entry(EntryId::from_uuid(item.uuid)) else {
            return String::new();
        };
        let title = entry.get(fields::TITLE).unwrap_or_default().to_owned();
        if item.kind != ItemKind::Environment {
            return title;
        }
        // Kept on the entry (an empty one reads back as empty binary); from
        // before parts, its group's name.
        let part = match entry.custom_data.get(PART).and_then(|d| d.value.as_ref()) {
            Some(keepass::db::CustomDataValue::String(part)) => part.clone(),
            Some(keepass::db::CustomDataValue::Binary(_)) => String::new(),
            None => {
                let parent = entry.parent();
                let common = side.canon(parent.id().uuid());
                let generic =
                    [crate::vault::envs::GROUP, "Personal"].contains(&parent.name.as_str());
                if common == "root" || common == "bin" || generic {
                    String::new()
                } else {
                    parent.name.clone()
                }
            }
        };
        let project = self
            .projects
            .get(&item.uuid.to_string())
            .cloned()
            .unwrap_or_default();
        [project, part, title]
            .into_iter()
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join(" · ")
    }
}
