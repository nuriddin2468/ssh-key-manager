//! What to take from another device's copy of the vault.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use chrono::NaiveDateTime;
use keepass::Database;
use keepass::db::{EntryId, GroupId, Times, fields};
use serde::Serialize;
use uuid::Uuid;

use super::model::{GROUP, Item, KIND, Side, local_set};
use super::{MAX_DEPTH, PeerVault, VaultBase};
use crate::sync::{Hasher, Hashes, Outcome, plan_hashed};
use crate::vault::Vault;
use crate::vault::envs::{PART, risky_variable};
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
}

/// What to take from the other device's copy, and what the user decides.
#[derive(Debug, Clone, Default)]
pub struct VaultPlan {
    pub changes: Vec<VaultChange>,
    pub conflicts: Vec<VaultConflict>,
    /// Groups paired, old and new: this side's UUID → the other's.
    pub pairs: BTreeMap<String, String>,
    /// Each item a change or conflict touches here, as the plan found it,
    /// so that one changed meanwhile is left alone.
    pub(super) found: BTreeMap<String, Option<Hashes>>,
}

impl Vault {
    /// Works out what to take from another device's copy against `base`,
    /// this computer's snapshot of the last sync with it.
    pub fn plan_sync(&self, peer: &PeerVault, base: &VaultBase, hasher: &Hasher) -> VaultPlan {
        let my_local = local_set(&self.db);
        let pairs = pair_groups(&self.db, &peer.db, &base.pairs, &my_local);
        let mine = Side::new(&self.db, &pairs, true, &HashSet::new());
        let theirs = Side::new(&peer.db, &pairs, false, &my_local);
        let m_items = mine.items(hasher);
        let t_items = theirs.items(hasher);
        let labels = Labels::new(self);
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
            let label = match (m, t) {
                (Some(m), _) => labels.of(&self.db, &mine, m),
                (None, Some(t)) => labels.of(&peer.db, &theirs, t),
                (None, None) => continue,
            };
            plan.found.insert(id.clone(), m.map(|m| m.hashes.clone()));
            plan.record(id, label, outcome, m, t);
        }
        plan
    }
}

impl VaultPlan {
    /// Adds what the plan says about one item.
    fn record(
        &mut self,
        id: String,
        label: String,
        outcome: Outcome,
        m: Option<&Item>,
        t: Option<&Item>,
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
                risky: risky(t, t.hashes.keys()),
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
                    risky: risky(t, fields.iter()),
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
                        let risky = risky(t, differ.iter());
                        (differ, risky)
                    }
                    (None, Some(t)) => (Vec::new(), risky(t, t.hashes.keys())),
                    _ => (Vec::new(), Vec::new()),
                };
                self.conflicts.push(VaultConflict {
                    id,
                    kind,
                    label,
                    here: party(m),
                    there: party(t),
                    fields,
                    risky,
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

/// The variables of an environment that `fields` of the other side's
/// version add or change and that make programs load code; `mine` is what
/// this side has, so a field only removed isn't counted.
fn risky<'a>(theirs: &Item, fields: impl Iterator<Item = &'a String>) -> Vec<String> {
    if theirs.kind != ItemKind::Environment {
        return Vec::new();
    }
    let mut names: Vec<String> = fields
        .filter(|field| theirs.hashes.contains_key(*field))
        .filter_map(|field| field.strip_prefix("s:"))
        .filter(|name| risky_variable(name))
        .map(|name| name.strip_prefix("env.").unwrap_or(name).to_owned())
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Pairs the groups each side made separately for the same thing: a group
/// only one side has, by UUID, with the same name and the same parent (in
/// common terms) as a group only the other side has. Of several such, the
/// first by UUID on each side pair, and so on, so both sides pair alike.
/// Pairs already made stay while both groups are there.
fn pair_groups(
    mine: &Database,
    theirs: &Database,
    old: &BTreeMap<String, String>,
    my_local: &HashSet<Uuid>,
) -> BTreeMap<String, String> {
    let has = |db: &Database, uuid: &str| {
        Uuid::parse_str(uuid).is_ok_and(|uuid| db.group(GroupId::from_uuid(uuid)).is_some())
    };
    let mut pairs: BTreeMap<String, String> = old
        .iter()
        .filter(|(m, t)| {
            m != t && has(mine, m) && has(theirs, t) && !has(mine, t) && !has(theirs, m)
        })
        .map(|(m, t)| (m.clone(), t.clone()))
        .collect();
    for _ in 0..=MAX_DEPTH {
        let my_side = Side::new(mine, &pairs, true, &HashSet::new());
        let their_side = Side::new(theirs, &pairs, false, my_local);
        let paired_mine: HashSet<&String> = pairs.keys().collect();
        let paired_theirs: HashSet<&String> = pairs.values().collect();
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
        pairs.extend(found);
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
