//! The three-way merge: what each side has against what both had.

use std::collections::{BTreeMap, BTreeSet};

use base64ct::{Base64, Encoding};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Something kept in step: a host, for one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    feature = "ts",
    derive(ts_rs::TS),
    ts(export, export_to = crate::TS_DIR, rename = "SyncItem")
)]
pub struct Item {
    /// What names it on both computers: a host's patterns.
    pub id: String,
    /// Its fields in order, each key once (compared without case).
    pub fields: Vec<Field>,
}

/// A field of an [`Item`]: a keyword and its values in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    feature = "ts",
    derive(ts_rs::TS),
    ts(export, export_to = crate::TS_DIR, rename = "SyncField")
)]
pub struct Field {
    /// As written; compared without case.
    pub key: String,
    pub values: Vec<String>,
}

impl Item {
    pub fn field(&self, key: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.key.eq_ignore_ascii_case(key))
    }

    /// The first value of a field.
    pub fn value(&self, key: &str) -> Option<&str> {
        self.field(key)?.values.first().map(String::as_str)
    }

    fn set(&mut self, field: Option<&Field>, key: &str) {
        let at = self
            .fields
            .iter()
            .position(|f| f.key.eq_ignore_ascii_case(key));
        match (at, field) {
            (Some(at), Some(field)) => self.fields[at].values.clone_from(&field.values),
            (None, Some(field)) => self.fields.push(field.clone()),
            (Some(at), None) => {
                self.fields.remove(at);
            }
            (None, None) => {}
        }
    }
}

/// What both computers had after they last synced: for each item, a hash
/// of each field, by lowercase key. It holds no values.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Base {
    pub items: BTreeMap<String, BTreeMap<String, String>>,
}

/// Hashes fields for a [`Base`] with a key of this computer's, so a base on
/// disk can't be checked against guessed values.
pub struct Hasher(Zeroizing<[u8; 32]>);

impl Hasher {
    pub fn new(key: Zeroizing<[u8; 32]>) -> Self {
        Self(key)
    }

    /// The hashes of an item's fields, by lowercase key.
    pub fn snapshot(&self, item: &Item) -> BTreeMap<String, String> {
        item.fields
            .iter()
            .map(|field| (field.key.to_ascii_lowercase(), self.field(&item.id, field)))
            .collect()
    }

    fn field(&self, id: &str, field: &Field) -> String {
        let mut mac = self.mac();
        absorb(&mut mac, id, field);
        let digest = mac.finalize().into_bytes();
        Base64::encode_string(&digest[..16])
    }

    /// The hash of a field made of any parts, for things that aren't hosts
    /// (a vault entry's fields): the item's id, the field's name and each
    /// part, each with its length.
    pub fn parts(&self, id: &str, key: &str, parts: &[&[u8]]) -> String {
        let mut mac = self.mac();
        for part in [id.as_bytes(), key.as_bytes()]
            .into_iter()
            .chain(parts.iter().copied())
        {
            mac.update(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
            mac.update(part);
        }
        let digest = mac.finalize().into_bytes();
        Base64::encode_string(&digest[..16])
    }

    fn mac(&self) -> Hmac<Sha256> {
        <Hmac<Sha256> as Mac>::new_from_slice(self.0.as_ref())
            .unwrap_or_else(|_| unreachable!("HMAC takes any key length"))
    }
}

/// An item's fields as hashes, by field name: what the plan compares.
pub type Hashes = BTreeMap<String, String>;

/// What the plan says about one item, compared by hashes alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Only the other side has it and it's new: add it here.
    Add,
    /// Take these fields from the other side; the rest stays.
    Take(Vec<String>),
    /// The other side deleted it, and it's as it was here.
    Delete,
    /// Both changed it differently, or one deleted what the other changed.
    Conflict,
}

/// [`plan`] on hashes: for each item that needs something here, by id,
/// what. Items alike on both sides, or changed only here, are left out.
pub fn plan_hashed(
    base: &Base,
    mine: &BTreeMap<String, Hashes>,
    theirs: &BTreeMap<String, Hashes>,
) -> Vec<(String, Outcome)> {
    let ids: BTreeSet<&String> = mine.keys().chain(theirs.keys()).collect();
    let mut out = Vec::new();
    for id in ids {
        let (m, t, b) = (mine.get(id), theirs.get(id), base.items.get(id));
        let outcome = match (m, t) {
            (None, None) => None,
            (Some(m), None) => match b {
                None => None,
                Some(b) if m == b => Some(Outcome::Delete),
                Some(_) => Some(Outcome::Conflict),
            },
            (None, Some(t)) => match b {
                None => Some(Outcome::Add),
                Some(b) if t == b => None,
                Some(_) => Some(Outcome::Conflict),
            },
            (Some(m), Some(t)) if m == t => None,
            (Some(m), Some(t)) => match b.map(|b| take_fields(b, m, t)) {
                Some(Some(fields)) if fields.is_empty() => None,
                Some(Some(fields)) => Some(Outcome::Take(fields)),
                Some(None) | None => Some(Outcome::Conflict),
            },
        };
        if let Some(outcome) = outcome {
            out.push((id.clone(), outcome));
        }
    }
    out
}

/// The fields only the other side changed since `base`; `None` if a field
/// changed on both sides, differently.
fn take_fields(base: &Hashes, mine: &Hashes, theirs: &Hashes) -> Option<Vec<String>> {
    let keys: BTreeSet<&String> = mine
        .keys()
        .chain(theirs.keys())
        .chain(base.keys())
        .collect();
    let mut take = Vec::new();
    for key in keys {
        let (mv, tv, bv) = (mine.get(key), theirs.get(key), base.get(key));
        if mv == tv || tv == bv {
            continue;
        }
        if mv != bv {
            return None;
        }
        take.push(key.clone());
    }
    Some(take)
}

/// Feeds an item's id and a field to a hash, each part with its length so
/// no two different fields hash alike.
fn absorb(hash: &mut impl Mac, id: &str, field: &Field) {
    let mut part = |bytes: &[u8]| {
        hash.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
        hash.update(bytes);
    };
    part(id.as_bytes());
    part(field.key.to_ascii_lowercase().as_bytes());
    for value in &field.values {
        part(value.as_bytes());
    }
}

/// The SHA-256 of an item as both computers compare it: its id and fields,
/// with keys in lowercase and in order of key.
pub fn digest(item: &Item) -> String {
    let mut hash = Sha256::new();
    let mut part = |bytes: &[u8]| {
        hash.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
        hash.update(bytes);
    };
    part(item.id.as_bytes());
    let mut fields: Vec<&Field> = item.fields.iter().collect();
    fields.sort_by_key(|f| f.key.to_ascii_lowercase());
    for field in fields {
        part(field.key.to_ascii_lowercase().as_bytes());
        part(
            &u64::try_from(field.values.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        for value in &field.values {
            part(value.as_bytes());
        }
    }
    Base64::encode_string(&hash.finalize())
}

/// [`digest`] of each item, by id.
pub fn digests(items: &[Item]) -> BTreeMap<String, String> {
    items
        .iter()
        .map(|item| (item.id.clone(), digest(item)))
        .collect()
}

/// A change to make on this computer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "item", rename_all = "camelCase")]
pub enum Change {
    /// The other computer has an item this one doesn't.
    Add(Item),
    /// This computer's item becomes this.
    Update(Item),
    /// The other computer deleted the item, by id.
    Delete(String),
}

impl Change {
    pub fn id(&self) -> &str {
        match self {
            Self::Add(item) | Self::Update(item) => &item.id,
            Self::Delete(id) => id,
        }
    }
}

/// An item both computers changed, differently, since they last synced;
/// `None` on the side that deleted it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct Conflict {
    pub id: String,
    pub mine: Option<Item>,
    pub theirs: Option<Item>,
}

impl Conflict {
    /// The change that makes this computer's item the other's.
    pub fn take_theirs(&self) -> Change {
        match (&self.mine, &self.theirs) {
            (_, None) => Change::Delete(self.id.clone()),
            (None, Some(theirs)) => Change::Add(theirs.clone()),
            (Some(_), Some(theirs)) => Change::Update(theirs.clone()),
        }
    }
}

/// What to take from the other computer, and what the user decides.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub changes: Vec<Change>,
    pub conflicts: Vec<Conflict>,
}

/// Works out what this computer takes from the other one.
///
/// Against `base`, an item (or a field of one) that only the other changed
/// is taken, one that only this computer changed stays (the other takes
/// it), and one both changed differently is a [`Conflict`]. An item one
/// side deleted is deleted on the other, unless that one changed it. With
/// no base for an item, both versions are new: one that only one side has
/// is added to the other, and two that differ are a conflict.
pub fn plan(base: &Base, hasher: &Hasher, mine: &[Item], theirs: &[Item]) -> Plan {
    let by_id = |items: &[Item]| -> BTreeMap<String, Item> {
        items.iter().map(|i| (i.id.clone(), i.clone())).collect()
    };
    let (mine, theirs) = (by_id(mine), by_id(theirs));
    let snapshots = |items: &BTreeMap<String, Item>| -> BTreeMap<String, Hashes> {
        items
            .iter()
            .map(|(id, item)| (id.clone(), hasher.snapshot(item)))
            .collect()
    };
    let mut plan = Plan::default();
    for (id, outcome) in plan_hashed(base, &snapshots(&mine), &snapshots(&theirs)) {
        let (m, t) = (mine.get(&id), theirs.get(&id));
        match (outcome, m, t) {
            (Outcome::Add, _, Some(t)) => plan.changes.push(Change::Add(t.clone())),
            (Outcome::Delete, ..) => plan.changes.push(Change::Delete(id)),
            (Outcome::Take(fields), Some(m), Some(t)) => {
                let mut merged = m.clone();
                for key in &fields {
                    merged.set(t.field(key), key);
                }
                plan.changes.push(Change::Update(merged));
            }
            _ => plan.conflicts.push(Conflict {
                id,
                mine: m.cloned(),
                theirs: t.cloned(),
            }),
        }
    }
    plan
}

/// The base after a sync: for each item both computers now have alike (by
/// `theirs`, the other's [`digests`]), its snapshot; for one they still
/// disagree on, the old base, so it comes up again next time.
pub fn agree(
    old: &Base,
    hasher: &Hasher,
    mine: &[Item],
    theirs: &BTreeMap<String, String>,
) -> Base {
    let snapshots = mine
        .iter()
        .map(|item| (item.id.clone(), hasher.snapshot(item)))
        .collect();
    agree_hashed(old, &snapshots, &digests(mine), theirs)
}

/// [`agree`] on hashes: `mine` are this side's snapshots by id, `ours` and
/// `theirs` the digests each side has now.
pub fn agree_hashed(
    old: &Base,
    mine: &BTreeMap<String, Hashes>,
    ours: &BTreeMap<String, String>,
    theirs: &BTreeMap<String, String>,
) -> Base {
    let mut items = BTreeMap::new();
    for (id, snapshot) in mine {
        if theirs
            .get(id)
            .is_some_and(|digest| ours.get(id) == Some(digest))
        {
            items.insert(id.clone(), snapshot.clone());
        } else if let Some(base) = old.items.get(id) {
            items.insert(id.clone(), base.clone());
        }
    }
    for (id, base) in &old.items {
        if !mine.contains_key(id) && theirs.contains_key(id) {
            items.insert(id.clone(), base.clone());
        }
    }
    Base { items }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hasher() -> Hasher {
        Hasher::new(Zeroizing::new([3; 32]))
    }

    fn item(id: &str, fields: &[(&str, &str)]) -> Item {
        let mut item = Item {
            id: id.into(),
            fields: Vec::new(),
        };
        for (key, value) in fields {
            match item
                .fields
                .iter_mut()
                .find(|f| f.key.eq_ignore_ascii_case(key))
            {
                Some(field) => field.values.push((*value).into()),
                None => item.fields.push(Field {
                    key: (*key).into(),
                    values: vec![(*value).into()],
                }),
            }
        }
        item
    }

    fn base_of(items: &[Item]) -> Base {
        let hasher = hasher();
        Base {
            items: items
                .iter()
                .map(|i| (i.id.clone(), hasher.snapshot(i)))
                .collect(),
        }
    }

    #[test]
    fn what_only_the_other_changed_is_taken() {
        let prod = item("prod", &[("HostName", "10.0.0.1"), ("User", "deploy")]);
        let base = base_of(std::slice::from_ref(&prod));
        let theirs = item("prod", &[("HostName", "10.0.0.2"), ("User", "deploy")]);
        let got = plan(
            &base,
            &hasher(),
            std::slice::from_ref(&prod),
            std::slice::from_ref(&theirs),
        );
        assert_eq!(got.changes, [Change::Update(theirs.clone())]);
        assert_eq!(got.conflicts.len(), 0);

        // The other way round, nothing comes in: the other takes it.
        let got = plan(&base, &hasher(), &[theirs], &[prod]);
        assert_eq!(got, Plan::default());
    }

    #[test]
    fn fields_changed_on_different_sides_merge() {
        let prod = item("prod", &[("HostName", "10.0.0.1"), ("User", "deploy")]);
        let base = base_of(std::slice::from_ref(&prod));
        let mine = item(
            "prod",
            &[("HostName", "10.0.0.1"), ("User", "root"), ("Port", "2222")],
        );
        let theirs = item(
            "prod",
            &[
                ("hostname", "10.0.0.9"),
                ("User", "deploy"),
                ("LocalForward", "8080 db:5432"),
            ],
        );
        let got = plan(&base, &hasher(), &[mine], &[theirs]);
        assert_eq!(
            got.changes,
            [Change::Update(item(
                "prod",
                &[
                    ("HostName", "10.0.0.9"),
                    ("User", "root"),
                    ("Port", "2222"),
                    ("LocalForward", "8080 db:5432"),
                ],
            ))]
        );
    }

    #[test]
    fn a_field_changed_on_both_sides_is_a_conflict() {
        let prod = item("prod", &[("HostName", "10.0.0.1")]);
        let base = base_of(std::slice::from_ref(&prod));
        let mine = item("prod", &[("HostName", "10.0.0.2")]);
        let theirs = item("prod", &[("HostName", "10.0.0.3")]);
        let got = plan(
            &base,
            &hasher(),
            std::slice::from_ref(&mine),
            std::slice::from_ref(&theirs),
        );
        assert_eq!(got.changes.len(), 0);
        assert_eq!(
            got.conflicts,
            [Conflict {
                id: "prod".into(),
                mine: Some(mine),
                theirs: Some(theirs.clone()),
            }]
        );
        assert_eq!(got.conflicts[0].take_theirs(), Change::Update(theirs));
    }

    #[test]
    fn the_same_change_on_both_sides_is_no_change() {
        let base = base_of(&[item("prod", &[("HostName", "10.0.0.1")])]);
        let both = item("prod", &[("HostName", "10.0.0.2")]);
        let got = plan(
            &base,
            &hasher(),
            std::slice::from_ref(&both),
            std::slice::from_ref(&both),
        );
        assert_eq!(got, Plan::default());
    }

    #[test]
    fn deletions_go_across_unless_the_other_side_changed_the_item() {
        let prod = item("prod", &[("HostName", "10.0.0.1")]);
        let base = base_of(std::slice::from_ref(&prod));
        // They deleted it; it is as it was here.
        let got = plan(&base, &hasher(), std::slice::from_ref(&prod), &[]);
        assert_eq!(got.changes, [Change::Delete("prod".into())]);
        // This side deleted it: nothing comes in.
        assert_eq!(
            plan(&base, &hasher(), &[], std::slice::from_ref(&prod)),
            Plan::default()
        );

        // Deleted there, changed here (or the other way round): ask.
        let changed = item("prod", &[("HostName", "10.0.0.5")]);
        let got = plan(&base, &hasher(), std::slice::from_ref(&changed), &[]);
        assert_eq!(got.conflicts.len(), 1);
        assert_eq!(
            got.conflicts[0].take_theirs(),
            Change::Delete("prod".into())
        );
        let got = plan(&base, &hasher(), &[], std::slice::from_ref(&changed));
        assert_eq!(got.conflicts[0].take_theirs(), Change::Add(changed));
    }

    #[test]
    fn without_a_base_new_items_are_added_and_differences_asked() {
        let empty = Base::default();
        let theirs = item("prod", &[("HostName", "10.0.0.1")]);
        let got = plan(&empty, &hasher(), &[], std::slice::from_ref(&theirs));
        assert_eq!(got.changes, [Change::Add(theirs.clone())]);

        let mine = item("prod", &[("HostName", "10.0.0.1"), ("User", "me")]);
        let got = plan(&empty, &hasher(), &[mine], &[theirs]);
        assert_eq!(got.conflicts.len(), 1);
    }

    #[test]
    fn keys_compare_without_case() {
        let base = base_of(&[item("prod", &[("HostName", "10.0.0.1")])]);
        let mine = item("prod", &[("HostName", "10.0.0.1")]);
        let theirs = item("prod", &[("hostname", "10.0.0.1")]);
        assert_eq!(digest(&mine), digest(&theirs));
        assert_eq!(plan(&base, &hasher(), &[mine], &[theirs]), Plan::default());
    }

    #[test]
    fn a_removed_field_is_removed() {
        let prod = item("prod", &[("HostName", "10.0.0.1"), ("User", "deploy")]);
        let base = base_of(std::slice::from_ref(&prod));
        let theirs = item("prod", &[("HostName", "10.0.0.1")]);
        let got = plan(&base, &hasher(), &[prod], std::slice::from_ref(&theirs));
        assert_eq!(got.changes, [Change::Update(theirs)]);
    }

    #[test]
    fn the_new_base_keeps_only_what_both_have_alike() {
        let hasher = hasher();
        let (a, b, c) = (
            item("a", &[("HostName", "1")]),
            item("b", &[("HostName", "2")]),
            item("c", &[("HostName", "3")]),
        );
        let old = base_of(&[a.clone(), b.clone(), item("gone", &[])]);
        let b_there = item("b", &[("HostName", "other")]);
        let theirs = digests(&[a.clone(), b_there, c.clone(), item("gone", &[])]);
        let new = agree(&old, &hasher, &[a.clone(), b.clone(), c.clone()], &theirs);
        assert_eq!(new.items.get("a"), Some(&hasher.snapshot(&a)));
        // They differ on b: its old base stays, so it comes up again.
        assert_eq!(new.items.get("b"), old.items.get("b"));
        assert_eq!(new.items.get("c"), Some(&hasher.snapshot(&c)));
        // Gone here but still there (a deletion put off): kept.
        assert!(new.items.contains_key("gone"));
        let new = agree(&old, &hasher, &[a], &digests(&[]));
        assert!(!new.items.contains_key("gone"));
        assert!(!new.items.contains_key("b"));
    }

    #[test]
    fn hashes_depend_on_the_key_and_on_every_part() {
        let prod = item("prod", &[("LocalForward", "1"), ("LocalForward", "2")]);
        let other_key = Hasher::new(Zeroizing::new([4; 32]));
        assert_ne!(hasher().snapshot(&prod), other_key.snapshot(&prod));
        let joined = item("prod", &[("LocalForward", "12")]);
        assert_ne!(hasher().snapshot(&prod), hasher().snapshot(&joined));
        assert_ne!(digest(&prod), digest(&joined));
    }
}
