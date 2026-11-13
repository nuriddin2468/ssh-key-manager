//! What the plan compares: a database's entries and groups as items, each
//! a set of field hashes keyed with a key of this computer's.
//!
//! An entry's fields are its strings (KeePass's own, custom ones, an
//! environment's variables) with their protection, its custom data, its
//! attachments, its tags without the app's `project/` ones (records decide
//! those), its look (icon, colours, auto-type, URL override, quality
//! check), its expiry and its group. Times and earlier versions aren't
//! compared. A group's fields are its name, notes, look, tags, custom data,
//! expiry and parent.
//!
//! Groups are named in common ([`Side::canon`]): the root and the recycle
//! bin by role, whatever their UUIDs, and two groups made separately on
//! each computer for the same thing by the smaller of their two UUIDs.

use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::NaiveDateTime;
use keepass::Database;
use keepass::db::{CustomDataItem, CustomDataValue, EntryRef, GroupId, GroupRef, Icon};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::plan::ItemKind;
use super::{LOCAL, Pairs};
use crate::sync::{Hasher, Hashes};
use crate::vault::envs::{MARKER, is_shared};
use crate::vault::projects::TAG_PREFIX;

/// The root group's common id.
pub(super) const ROOT: &str = "root";
/// The recycle bin's common id.
pub(super) const BIN: &str = "bin";
/// The field naming an item's kind.
pub(super) const KIND: &str = "kind";
/// The field naming an item's group.
pub(super) const GROUP: &str = "group";

/// One side of a sync: a database and how its groups are named in common.
pub(super) struct Side<'a> {
    pub db: &'a Database,
    root: Uuid,
    bin: Option<Uuid>,
    /// Entries and groups kept on this computer, and those the other side
    /// keeps on its own (by UUID).
    local: HashSet<Uuid>,
    /// Groups in the recycle bin, the bin included.
    binned: HashSet<Uuid>,
    /// Paired groups' common ids.
    paired: HashMap<Uuid, String>,
}

/// An entry or a group as the plan sees it.
#[derive(Debug, Clone)]
pub(super) struct Item {
    pub kind: ItemKind,
    /// Its UUID on this side.
    pub uuid: Uuid,
    pub hashes: Hashes,
    pub modified: Option<NaiveDateTime>,
    /// It is in the recycle bin.
    pub in_bin: bool,
}

impl<'a> Side<'a> {
    /// `pairs` are by this computer's UUIDs: `mine` says whether `db` is
    /// this computer's; items with a UUID in `also_local` are left out.
    pub fn new(db: &'a Database, pairs: &Pairs, mine: bool, also_local: &HashSet<Uuid>) -> Self {
        let paired = pairs
            .iter()
            .filter_map(|(here, pair)| {
                let here = if mine { here } else { &pair.there };
                Some((Uuid::parse_str(here).ok()?, pair.common.clone()))
            })
            .collect();
        let bin = db.meta.recyclebin_uuid;
        let mut local = local_set(db);
        local.extend(also_local.iter().copied());
        let mut binned = HashSet::new();
        let mut stack: Vec<GroupId> = bin.map(GroupId::from_uuid).into_iter().collect();
        while let Some(id) = stack.pop() {
            let Some(group) = db.group(id) else {
                continue;
            };
            binned.insert(id.uuid());
            stack.extend(group.group_ids());
        }
        Self {
            db,
            root: db.root().id().uuid(),
            bin,
            local,
            binned,
            paired,
        }
    }

    /// The common id of a group.
    pub fn canon(&self, group: Uuid) -> String {
        if group == self.root {
            ROOT.into()
        } else if Some(group) == self.bin {
            BIN.into()
        } else if let Some(common) = self.paired.get(&group) {
            common.clone()
        } else {
            group.to_string()
        }
    }

    pub fn is_local(&self, uuid: Uuid) -> bool {
        self.local.contains(&uuid)
    }

    /// Every entry and group but the root, the bin and what is local, by
    /// common id.
    pub fn items(&self, hasher: &Hasher) -> BTreeMap<String, Item> {
        let mut items = BTreeMap::new();
        for group in self.db.iter_all_groups() {
            let uuid = group.id().uuid();
            if uuid == self.root || Some(uuid) == self.bin || self.is_local(uuid) {
                continue;
            }
            let id = self.canon(uuid);
            let parent = group
                .parent()
                .map_or(self.root, |parent| parent.id().uuid());
            items.insert(
                id.clone(),
                Item {
                    kind: ItemKind::Folder,
                    uuid,
                    hashes: self.group_hashes(&group, &id, hasher),
                    modified: group.times.last_modification,
                    in_bin: self.binned.contains(&parent),
                },
            );
        }
        for entry in self.db.iter_all_entries() {
            let uuid = entry.id().uuid();
            if self.is_local(uuid) {
                continue;
            }
            let id = uuid.to_string();
            let parent = entry.parent().id().uuid();
            let group = self.canon(parent);
            items.insert(
                id.clone(),
                Item {
                    kind: kind_of(&entry),
                    uuid,
                    hashes: entry_hashes(&entry, &id, Some(&group), hasher),
                    modified: entry.times.last_modification,
                    in_bin: self.binned.contains(&parent),
                },
            );
        }
        items
    }

    fn group_hashes(&self, group: &GroupRef<'_>, id: &str, hasher: &Hasher) -> Hashes {
        let mut out = Fields::new(id, hasher);
        out.put(KIND, &[ItemKind::Folder.as_str().as_bytes()]);
        out.put("name", &[group.name.as_bytes()]);
        if let Some(notes) = group.notes.as_deref().filter(|n| !n.is_empty()) {
            out.put("notes", &[notes.as_bytes()]);
        }
        icon(
            &mut out,
            group.icon(),
            group.custom_icon().map(|i| i.data.clone()),
        );
        tags(&mut out, &group.tags);
        custom_data(&mut out, &group.custom_data);
        if let Some(enabled) = group.enable_autotype {
            out.put("autotype", &[if enabled { b"1" } else { b"0" }]);
        }
        if let Some(sequence) = &group.default_autotype_sequence {
            out.put("sequence", &[sequence.as_bytes()]);
        }
        if let Some(enabled) = group.enable_searching {
            out.put("search", &[if enabled { b"1" } else { b"0" }]);
        }
        if group.times.expires == Some(true) {
            out.put("expiry", &[group.times.expiry.to_string().as_bytes()]);
        }
        let parent = group
            .parent()
            .map_or(self.root, |parent| parent.id().uuid());
        out.put(GROUP, &[self.canon(parent).as_bytes()]);
        out.hashes
    }
}

/// What an entry is.
pub(super) fn kind_of(entry: &EntryRef<'_>) -> ItemKind {
    if entry.custom_data.contains_key(MARKER) {
        ItemKind::Environment
    } else if is_shared(entry) {
        ItemKind::Shared
    } else {
        ItemKind::Login
    }
}

/// The hashes of an entry's fields; `group` is its group's common id, or
/// `None` for an earlier version, which has no place of its own.
pub(super) fn entry_hashes(
    entry: &EntryRef<'_>,
    id: &str,
    group: Option<&str>,
    hasher: &Hasher,
) -> Hashes {
    let mut out = Fields::new(id, hasher);
    out.put(KIND, &[kind_of(entry).as_str().as_bytes()]);
    for (name, value) in &entry.fields {
        let protection: &[u8] = if value.is_protected() { b"p" } else { b"u" };
        out.put(&format!("s:{name}"), &[protection, value.get().as_bytes()]);
    }
    custom_data(&mut out, &entry.custom_data);
    for (name, attachment) in entry.attachments_named() {
        let protection: &[u8] = if attachment.data.is_protected() {
            b"p"
        } else {
            b"u"
        };
        out.put(&format!("a:{name}"), &[protection, attachment.data.get()]);
    }
    tags(&mut out, &entry.tags);
    icon(
        &mut out,
        entry.icon(),
        entry.custom_icon().map(|i| i.data.clone()),
    );
    if let Some(color) = &entry.foreground_color {
        out.put("fg", &[color.to_string().as_bytes()]);
    }
    if let Some(color) = &entry.background_color {
        out.put("bg", &[color.to_string().as_bytes()]);
    }
    if let Some(url) = entry.override_url.as_deref().filter(|u| !u.is_empty()) {
        out.put("overrideUrl", &[url.as_bytes()]);
    }
    if let Some(autotype) = &entry.autotype {
        let mut parts: Vec<Vec<u8>> = vec![
            vec![u8::from(autotype.enabled)],
            autotype
                .default_sequence
                .clone()
                .unwrap_or_default()
                .into_bytes(),
            format!("{:?}", autotype.data_transfer_obfuscation).into_bytes(),
        ];
        for association in &autotype.associations {
            parts.push(association.window.clone().into_bytes());
            parts.push(association.sequence.clone().into_bytes());
        }
        let parts: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        out.put("autotype", &parts);
    }
    if entry.times.expires == Some(true) {
        out.put("expiry", &[entry.times.expiry.to_string().as_bytes()]);
    }
    if !entry.quality_check {
        out.put("qualityCheck", &[b"0"]);
    }
    if let Some(group) = group {
        out.put(GROUP, &[group.as_bytes()]);
    }
    out.hashes
}

/// What an earlier version holds, without its place, to tell two copies
/// of one version apart from two versions: in memory only.
pub(super) fn fingerprint(entry: &EntryRef<'_>) -> [u8; 32] {
    let hasher = Hasher::new(Zeroizing::new([0; 32]));
    let mut hash = Sha256::new();
    for (key, value) in entry_hashes(entry, "", None, &hasher) {
        hash.update(key.as_bytes());
        hash.update([0]);
        hash.update(value.as_bytes());
        hash.update([0]);
    }
    if let Some(time) = entry.times.last_modification {
        hash.update(time.to_string().as_bytes());
    }
    hash.finalize().into()
}

/// The entries and groups of `db` marked [`LOCAL`], and everything in such
/// a group.
pub(super) fn local_set(db: &Database) -> HashSet<Uuid> {
    let mut local = HashSet::new();
    let mut stack = vec![(db.root().id(), false)];
    while let Some((id, inherited)) = stack.pop() {
        let Some(group) = db.group(id) else {
            continue;
        };
        let here = inherited || group.custom_data.contains_key(LOCAL);
        if here {
            local.insert(id.uuid());
        }
        for entry in group.entries() {
            if here || entry.custom_data.contains_key(LOCAL) {
                local.insert(entry.id().uuid());
            }
        }
        stack.extend(group.group_ids().map(|child| (child, here)));
    }
    local
}

/// Whether a tag is one the app writes from project records.
pub(super) fn is_project_tag(tag: &str) -> bool {
    tag.starts_with(TAG_PREFIX)
}

struct Fields<'a> {
    hashes: Hashes,
    id: &'a str,
    hasher: &'a Hasher,
}

impl<'a> Fields<'a> {
    fn new(id: &'a str, hasher: &'a Hasher) -> Self {
        Self {
            hashes: Hashes::new(),
            id,
            hasher,
        }
    }

    fn put(&mut self, key: &str, parts: &[&[u8]]) {
        self.hashes
            .insert(key.to_owned(), self.hasher.parts(self.id, key, parts));
    }
}

fn custom_data(out: &mut Fields<'_>, data: &HashMap<String, CustomDataItem>) {
    for (key, item) in data {
        if key == LOCAL {
            continue;
        }
        // An item with an empty value doesn't come back from the file: as
        // good as none.
        match &item.value {
            Some(CustomDataValue::String(text)) if !text.is_empty() => {
                out.put(&format!("cd:{key}"), &[b"s", text.as_bytes()]);
            }
            Some(CustomDataValue::Binary(bytes)) if !bytes.is_empty() => {
                out.put(&format!("cd:{key}"), &[b"b", bytes]);
            }
            _ => {}
        }
    }
}

fn tags(out: &mut Fields<'_>, tags: &[String]) {
    let mut kept: Vec<&str> = tags
        .iter()
        .map(String::as_str)
        .filter(|tag| !is_project_tag(tag))
        .collect();
    kept.sort_unstable();
    kept.dedup();
    if !kept.is_empty() {
        let parts: Vec<&[u8]> = kept.iter().map(|tag| tag.as_bytes()).collect();
        out.put("tags", &parts);
    }
}

fn icon(out: &mut Fields<'_>, icon: Option<&Icon>, custom: Option<Vec<u8>>) {
    match (icon, custom) {
        (Some(Icon::BuiltIn(id)), _) => out.put("icon", &[b"b", id.to_string().as_bytes()]),
        (Some(Icon::Custom(_)), Some(data)) => out.put("icon", &[b"c", &data]),
        _ => {}
    }
}
