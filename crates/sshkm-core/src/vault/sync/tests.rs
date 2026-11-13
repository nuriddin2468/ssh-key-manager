use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use keepass::db::{CustomDataItem, CustomDataValue, EntryId, Times, Value, fields};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use super::*;
use crate::sync::{Hasher, agree_hashed};
use crate::vault::envs::files::{EnvFile, FileLevel, FileState, FilesContext, InactiveReason};
use crate::vault::envs::{EnvInput, EnvVarInput};
use crate::vault::projects::{ProjectColor, ProjectInput, ProjectMember};
use crate::vault::{EntryInput, SecretField, Vault, VaultPaths};
use crate::{Error, Result};

fn s(text: &str) -> SecretString {
    SecretString::from(text)
}

/// Both sides' key for the digests they compare.
fn shared() -> Hasher {
    Hasher::new(Zeroizing::new([9; 32]))
}

/// One of the user's computers with the vault.
struct Device {
    paths: VaultPaths,
    backups: PathBuf,
    vault: Vault,
    base: VaultBase,
    hasher: Hasher,
}

impl Device {
    fn save(&mut self) {
        self.vault.save(&self.backups).unwrap();
    }

    fn reopen(&mut self) {
        self.vault = Vault::unlock(&self.paths, &s("master")).unwrap();
    }

    fn login(&mut self, title: &str, password: &str) -> String {
        let id = self
            .vault
            .add_entry(&EntryInput {
                title: title.into(),
                password: Some(s(password)),
                ..EntryInput::default()
            })
            .unwrap();
        self.save();
        id
    }

    fn edit(&mut self, id: &str, edit: impl FnOnce(&mut EntryInput)) {
        let detail = self.vault.entry(id).unwrap();
        let mut input = EntryInput {
            title: detail.summary.title,
            username: detail.summary.username,
            url: detail.summary.url,
            notes: detail.notes,
            ..EntryInput::default()
        };
        edit(&mut input);
        self.vault.update_entry(id, &input).unwrap();
        self.save();
    }

    fn password(&self, id: &str) -> String {
        self.vault
            .secret(id, SecretField::Password)
            .unwrap()
            .expose_secret()
            .to_owned()
    }

    fn env(&mut self, name: &str, vars: &[(&str, &str)]) -> String {
        let id = self
            .vault
            .add_environment(&EnvInput {
                project: None,
                part: String::new(),
                name: name.into(),
                notes: String::new(),
            })
            .unwrap();
        for (name, value) in vars {
            self.set_var(&id, name, value);
        }
        id
    }

    fn set_var(&mut self, env: &str, name: &str, value: &str) {
        let previous = self
            .vault
            .environment(env)
            .unwrap()
            .variables
            .iter()
            .any(|var| var.name == name)
            .then_some(name);
        self.vault
            .set_env_variable(
                env,
                previous,
                &EnvVarInput {
                    name: name.into(),
                    value: Some(s(value)),
                    secret: true,
                    note: String::new(),
                },
            )
            .unwrap();
        self.save();
    }

    fn value(&self, env: &str, name: &str) -> String {
        self.vault
            .env_value(env, name)
            .unwrap()
            .expose_secret()
            .to_owned()
    }

    fn digests(&self, pairs: &BTreeMap<String, String>) -> Vec<(String, String)> {
        digests(&self.vault.sync_items(pairs, &shared()))
            .into_iter()
            .collect()
    }
}

/// One vault, made on the first computer and copied to the second.
fn two() -> (tempfile::TempDir, Device, Device) {
    let dir = tempfile::tempdir().unwrap();
    let make = |name: &str| VaultPaths::new(dir.path().join(name).join("vault.kdbx"));
    let (a_paths, b_paths) = (make("a"), make("b"));
    fs::create_dir_all(a_paths.database.parent().unwrap()).unwrap();
    fs::create_dir_all(b_paths.database.parent().unwrap()).unwrap();
    let (vault, _) = Vault::create(&a_paths, &s("master")).unwrap();
    drop(vault);
    fs::copy(&a_paths.database, &b_paths.database).unwrap();
    fs::copy(&a_paths.keys, &b_paths.keys).unwrap();
    let device = |paths: VaultPaths, n: u8| Device {
        vault: Vault::unlock(&paths, &s("master")).unwrap(),
        backups: paths.database.parent().unwrap().join("backups"),
        paths,
        base: VaultBase::default(),
        hasher: Hasher::new(Zeroizing::new([n; 32])),
    };
    (dir, device(a_paths, 1), device(b_paths, 2))
}

/// What a sync did on each side.
struct Synced {
    a: VaultApplied,
    b: VaultApplied,
    a_plan: VaultPlan,
    b_plan: VaultPlan,
}

/// A sync as the app does it: `a` connected, and its user takes `b`'s
/// version of the conflicts `take` says yes to and keeps its own of the
/// rest; every other change is made on both sides.
fn sync_taking(a: &mut Device, b: &mut Device, take: impl Fn(&VaultConflict) -> bool) -> Synced {
    let peer_b = a
        .vault
        .open_sync_copy(&b.vault.sync_copy().unwrap())
        .unwrap();
    let peer_a = b
        .vault
        .open_sync_copy(&a.vault.sync_copy().unwrap())
        .unwrap();
    let a_plan = a.vault.plan_sync(&peer_b, &a.base, &a.hasher);
    let b_plan = b.vault.plan_sync(&peer_a, &b.base, &b.hasher);
    let a_theirs: BTreeSet<String> = a_plan
        .conflicts
        .iter()
        .filter(|c| take(c))
        .map(|c| c.id.clone())
        .collect();
    let b_theirs: BTreeSet<String> = b_plan
        .conflicts
        .iter()
        .filter(|c| !a_theirs.contains(&c.id))
        .map(|c| c.id.clone())
        .collect();
    let all = |plan: &VaultPlan| -> BTreeSet<String> {
        plan.changes.iter().map(|c| c.id.clone()).collect()
    };
    let applied_a = a
        .vault
        .apply_sync(&peer_b, &a_plan, &a.hasher, &all(&a_plan), &a_theirs)
        .unwrap();
    let applied_b = b
        .vault
        .apply_sync(&peer_a, &b_plan, &b.hasher, &all(&b_plan), &b_theirs)
        .unwrap();
    a.save();
    b.save();
    agree(a, b, &a_plan, &b_plan);
    Synced {
        a: applied_a,
        b: applied_b,
        a_plan,
        b_plan,
    }
}

fn sync(a: &mut Device, b: &mut Device) -> Synced {
    sync_taking(a, b, |_| false)
}

/// The snapshots after a sync, from what both have alike.
fn agree(a: &mut Device, b: &mut Device, a_plan: &VaultPlan, b_plan: &VaultPlan) {
    let a_digests = digests(&a.vault.sync_items(&a_plan.pairs, &shared()));
    let b_digests = digests(&b.vault.sync_items(&b_plan.pairs, &shared()));
    a.base = VaultBase {
        base: agree_hashed(
            &a.base.base,
            &a.vault.sync_items(&a_plan.pairs, &a.hasher),
            &a_digests,
            &b_digests,
        ),
        pairs: a_plan.pairs.clone(),
    };
    b.base = VaultBase {
        base: agree_hashed(
            &b.base.base,
            &b.vault.sync_items(&b_plan.pairs, &b.hasher),
            &b_digests,
            &a_digests,
        ),
        pairs: b_plan.pairs.clone(),
    };
}

/// The fields two sides have differently, by item, for a failing test.
fn differences(a: &Device, b: &Device) -> Vec<(String, Vec<String>)> {
    let (left, right) = (
        a.vault.sync_items(&a.base.pairs, &shared()),
        b.vault.sync_items(&b.base.pairs, &shared()),
    );
    let ids: BTreeSet<&String> = left.keys().chain(right.keys()).collect();
    ids.into_iter()
        .filter_map(|id| {
            let (l, r) = (left.get(id), right.get(id));
            if l == r {
                return None;
            }
            let keys: BTreeSet<&String> = l.into_iter().chain(r).flat_map(|h| h.keys()).collect();
            let differ = keys
                .into_iter()
                .filter(|k| l.and_then(|h| h.get(*k)) != r.and_then(|h| h.get(*k)))
                .cloned()
                .collect();
            Some((id.clone(), differ))
        })
        .collect()
}

fn nothing_left(a: &mut Device, b: &mut Device) {
    let before = differences(a, b);
    let synced = sync(a, b);
    assert!(
        synced.a_plan.conflicts.is_empty() && synced.b_plan.conflicts.is_empty(),
        "{before:?}"
    );
    assert!(
        synced.a_plan.changes.is_empty(),
        "{:?}",
        synced.a_plan.changes
    );
    assert!(
        synced.b_plan.changes.is_empty(),
        "{:?}",
        synced.b_plan.changes
    );
    assert_eq!(
        synced.a_plan.conflicts.len(),
        0,
        "{:?}",
        synced.a_plan.conflicts
    );
    assert_eq!(
        synced.b_plan.conflicts.len(),
        0,
        "{:?}",
        synced.b_plan.conflicts
    );
    assert_eq!(a.digests(&a.base.pairs), b.digests(&b.base.pairs));
}

fn titles_in_root_named(vault: &Vault, name: &str) -> usize {
    vault
        .db
        .root()
        .groups()
        .filter(|group| group.name == name)
        .count()
}

#[test]
fn two_vaults_edited_apart_sync_and_converge() {
    let (_dir, mut a, mut b) = two();
    let mail = a.login("Mail", "x1");
    let bank = a.login("Bank", "b1");
    let old = a.login("Old", "o1");
    a.save();
    // The first sync: one side has what the other hasn't.
    let first = sync(&mut a, &mut b);
    assert_eq!(first.b.counts.logins.added, 3);
    nothing_left(&mut a, &mut b);

    // Apart: a password here, its address there; a title on both; a new
    // login with a file here, environments with a shared value there, and
    // a login put in the recycle bin here.
    a.edit(&mail, |e| e.password = Some(s("x2")));
    b.edit(&mail, |e| e.url = "https://mail.example".into());
    a.edit(&bank, |e| e.title = "Bank (A)".into());
    b.edit(&bank, |e| e.title = "Bank (B)".into());
    let new = a.login("New", "n1");
    {
        let mut entry = a
            .vault
            .db
            .entry_mut(EntryId::from_uuid(new.parse().unwrap()))
            .unwrap();
        entry.add_attachment(
            "key.pem",
            Value::unprotected(b"-----BEGIN KEY-----".to_vec()),
        );
    }
    a.vault.trash_entry(&old).unwrap();
    a.save();
    let api = b.env("api", &[("TOKEN", "t1"), ("PORT", "80")]);
    let web = b.env("web", &[("TOKEN", "t1")]);
    b.vault
        .share_env_variable(&api, "TOKEN", std::slice::from_ref(&web))
        .unwrap();
    b.save();

    let synced = sync_taking(&mut a, &mut b, |conflict| conflict.id == bank);
    assert_eq!(synced.a_plan.conflicts.len(), 1);
    let conflict = &synced.a_plan.conflicts[0];
    assert_eq!(conflict.fields, ["s:Title"]);
    assert_eq!(
        (conflict.here, conflict.there),
        (Party::Changed, Party::Changed)
    );
    assert_eq!(
        synced.a.counts.environments.added, 2,
        "{:?} {:?}",
        synced.a, synced.a_plan.changes
    );
    assert_eq!(
        synced.a.counts.shared.added, 1,
        "{:?} {:?}",
        synced.a, synced.a_plan.changes
    );
    assert_eq!(synced.b.counts.logins.added, 1);
    assert_eq!(synced.b.counts.logins.removed, 1);

    // Both files, read again from disk, hold the same.
    a.reopen();
    b.reopen();
    assert_eq!(a.digests(&a.base.pairs), b.digests(&b.base.pairs));
    for device in [&a, &b] {
        assert_eq!(device.password(&mail), "x2");
        assert_eq!(
            device.vault.entry(&mail).unwrap().summary.url,
            "https://mail.example"
        );
        assert_eq!(device.vault.entry(&bank).unwrap().summary.title, "Bank (B)");
        assert!(device.vault.entry(&old).unwrap().summary.in_trash);
        assert_eq!(device.value(&web, "TOKEN"), "t1");
        assert_eq!(device.value(&api, "PORT"), "80");
        let entry = device
            .vault
            .db
            .entry(EntryId::from_uuid(new.parse().unwrap()))
            .unwrap();
        let (name, file) = entry.attachments_named().next().unwrap();
        assert_eq!(
            (name, file.data.get().as_slice()),
            ("key.pem", &b"-----BEGIN KEY-----"[..])
        );
        assert_eq!(device.vault.shared_values().len(), 1);
        assert_eq!(titles_in_root_named(&device.vault, "Environments"), 1);
    }
    // The version not kept stays among the entry's earlier versions.
    let entry = a
        .vault
        .db
        .entry(EntryId::from_uuid(bank.parse().unwrap()))
        .unwrap();
    let titles: Vec<String> = (0..entry.history.as_ref().unwrap().get_entries().len())
        .filter_map(|i| entry.historical(i))
        .map(|v| v.get(fields::TITLE).unwrap_or_default().to_owned())
        .collect();
    assert!(titles.contains(&"Bank (A)".to_owned()), "{titles:?}");
    nothing_left(&mut a, &mut b);
}

#[test]
fn the_merge_rules_hold_for_each_case() {
    let (_dir, mut a, mut b) = two();
    let [same, gone, kept, both] = ["Same", "Gone", "Kept", "Both"].map(|t| a.login(t, "p"));
    sync(&mut a, &mut b);

    // The same change on both sides is no change.
    a.edit(&same, |e| e.notes = "alike".into());
    b.edit(&same, |e| e.notes = "alike".into());
    // Deleted there, as it was here: deleted.
    a.vault.trash_entry(&gone).unwrap();
    a.vault.delete_entry(&gone).unwrap();
    a.save();
    // Deleted there, changed here: asked.
    a.vault.trash_entry(&kept).unwrap();
    a.vault.delete_entry(&kept).unwrap();
    a.save();
    b.edit(&kept, |e| e.notes = "still needed".into());
    // Changed on both, differently: asked; kept here.
    a.edit(&both, |e| e.username = "a".into());
    b.edit(&both, |e| e.username = "b".into());

    let synced = sync(&mut a, &mut b);
    let ids = |plan: &VaultPlan| -> Vec<(String, ChangeOp)> {
        plan.changes.iter().map(|c| (c.id.clone(), c.op)).collect()
    };
    assert_eq!(ids(&synced.b_plan), [(gone.clone(), ChangeOp::Delete)]);
    assert_eq!(ids(&synced.a_plan).len(), 0, "{:?}", ids(&synced.a_plan));
    let mut asked: Vec<(String, Party, Party)> = synced
        .b_plan
        .conflicts
        .iter()
        .map(|c| (c.id.clone(), c.here, c.there))
        .collect();
    asked.sort();
    let mut want = vec![
        (kept.clone(), Party::Changed, Party::Deleted),
        (both.clone(), Party::Changed, Party::Changed),
    ];
    want.sort();
    assert_eq!(asked, want);
    // `a` kept its own: `b` deleted `kept` and took `a`'s `both`.
    assert!(b.vault.entry(&gone).is_err());
    assert!(
        b.vault
            .db
            .deleted_objects
            .contains_key(&gone.parse().unwrap())
    );
    assert!(b.vault.entry(&kept).is_err());
    assert_eq!(b.vault.entry(&both).unwrap().summary.username, "a");
    nothing_left(&mut a, &mut b);
}

#[test]
fn a_deleted_entry_comes_back_when_the_other_version_is_chosen() {
    let (_dir, mut a, mut b) = two();
    let kept = a.login("Kept", "p");
    sync(&mut a, &mut b);
    a.vault.trash_entry(&kept).unwrap();
    a.vault.delete_entry(&kept).unwrap();
    a.save();
    b.edit(&kept, |e| e.notes = "needed".into());
    let synced = sync_taking(&mut a, &mut b, |_| true);
    assert_eq!(synced.a_plan.conflicts[0].here, Party::Deleted);
    assert_eq!(a.vault.entry(&kept).unwrap().notes, "needed");
    nothing_left(&mut a, &mut b);
}

#[test]
fn without_a_snapshot_removal_records_decide() {
    let (_dir, mut a, mut b) = two();
    let old = a.login("Old", "p");
    let later = a.login("Changed later", "p");
    a.save();
    // `b` has both from a copy of the file, deleted both, then `a` changed
    // one after.
    drop(std::mem::replace(
        &mut b.vault,
        Vault::unlock(&a.paths, &s("master")).unwrap(),
    ));
    fs::copy(&a.paths.database, &b.paths.database).unwrap();
    b.reopen();
    let set_time = |vault: &mut Vault, id: &str, when: chrono::NaiveDateTime| {
        let mut entry = vault
            .db
            .entry_mut(EntryId::from_uuid(id.parse().unwrap()))
            .unwrap();
        entry.times.last_modification = Some(when);
    };
    let past = Times::now() - chrono::Duration::days(3);
    let removed = Times::now() - chrono::Duration::days(2);
    set_time(&mut a.vault, &old, past);
    set_time(
        &mut a.vault,
        &later,
        Times::now() - chrono::Duration::hours(1),
    );
    a.save();
    for id in [&old, &later] {
        let uuid = id.parse().unwrap();
        b.vault
            .db
            .entry_mut(EntryId::from_uuid(uuid))
            .unwrap()
            .remove();
        b.vault.db.deleted_objects.insert(uuid, Some(removed));
    }
    b.save();
    let synced = sync(&mut a, &mut b);
    assert_eq!(
        synced
            .a_plan
            .changes
            .iter()
            .map(|c| (&c.id, c.op))
            .collect::<Vec<_>>(),
        [(&old, ChangeOp::Delete)]
    );
    assert_eq!(synced.a_plan.conflicts.len(), 1);
    assert_eq!(synced.a_plan.conflicts[0].id, later);
    assert_eq!(synced.a_plan.conflicts[0].there, Party::Deleted);
    // From the other side: its removal is older than the change.
    assert_eq!(synced.b_plan.conflicts[0].here, Party::Deleted);
    assert_eq!(
        synced.b_plan.changes.len(),
        0,
        "{:?}",
        synced.b_plan.changes
    );
}

#[test]
fn an_item_of_another_kind_is_never_merged() {
    let (_dir, mut a, mut b) = two();
    let id = a.login("Login", "p");
    sync(&mut a, &mut b);
    {
        let mut entry = b
            .vault
            .db
            .entry_mut(EntryId::from_uuid(id.parse().unwrap()))
            .unwrap();
        entry.custom_data.insert(
            crate::vault::envs::MARKER.into(),
            CustomDataItem {
                value: Some(CustomDataValue::String(r#"{"vars":[]}"#.into())),
                last_modification_time: None,
            },
        );
    }
    b.save();
    let synced = sync(&mut a, &mut b);
    assert_eq!(
        synced.a_plan.changes.len(),
        0,
        "{:?}",
        synced.a_plan.changes
    );
    assert_eq!(synced.a_plan.conflicts.len(), 1);
    assert_eq!(synced.a_plan.conflicts[0].kind, ItemKind::Login);
}

#[test]
fn moves_merge_with_edits_and_bins_and_groups_pair() {
    let (_dir, mut a, mut b) = two();
    let moved = a.login("Moved", "p");
    let trashed = a.login("Trashed", "p");
    sync(&mut a, &mut b);
    // Each side makes its own recycle bin and its own `Environments`.
    a.vault.trash_entry(&trashed).unwrap();
    a.save();
    b.vault.trash_entry(&moved).unwrap();
    b.save();
    b.edit(&trashed, |e| e.notes = "edited".into());
    a.edit(&moved, |e| e.username = "me".into());
    let a_env = a.env("dev", &[("A", "1")]);
    let b_env = b.env("prod", &[("B", "2")]);
    assert_ne!(
        a.vault.db.meta.recyclebin_uuid,
        b.vault.db.meta.recyclebin_uuid
    );

    let synced = sync(&mut a, &mut b);
    assert!(
        synced.a_plan.conflicts.is_empty() && synced.b_plan.conflicts.is_empty(),
        "{:?} {:?}",
        synced.a_plan.conflicts,
        synced.b_plan.conflicts
    );
    let moving = synced
        .a_plan
        .changes
        .iter()
        .find(|c| c.id == moved)
        .unwrap();
    assert!(moving.removal);
    for device in [&a, &b] {
        // Moved to the bin with the edit made elsewhere: nothing lost.
        let entry = device.vault.entry(&trashed).unwrap();
        assert!(entry.summary.in_trash);
        assert_eq!(entry.notes, "edited");
        let entry = device.vault.entry(&moved).unwrap();
        assert!(entry.summary.in_trash);
        assert_eq!(entry.summary.username, "me");
        assert_eq!(titles_in_root_named(&device.vault, "Environments"), 1);
        assert_eq!(titles_in_root_named(&device.vault, "Recycle Bin"), 1);
        assert_eq!(device.vault.environments().len(), 2);
    }
    assert_eq!(a.vault.environment(&b_env).unwrap().summary.name, "prod");
    assert_eq!(b.vault.environment(&a_env).unwrap().summary.name, "dev");
    nothing_left(&mut a, &mut b);

    // A paired group renamed on one side is renamed on the other.
    let group = a
        .vault
        .db
        .root()
        .groups()
        .find(|g| g.name == "Environments")
        .unwrap()
        .id();
    a.vault.db.group_mut(group).unwrap().name = "Envs".into();
    a.save();
    let synced = sync(&mut a, &mut b);
    assert_eq!(synced.b.counts.folders.changed, 1);
    assert_eq!(titles_in_root_named(&b.vault, "Envs"), 1);
    assert_eq!(titles_in_root_named(&b.vault, "Environments"), 0);
    nothing_left(&mut a, &mut b);
}

#[test]
fn a_group_deleted_there_stays_while_something_new_is_in_it() {
    let (_dir, mut a, mut b) = two();
    let group = {
        let mut root = a.vault.db.root_mut();
        let mut group = root.add_group();
        group.name = "Work".into();
        group.id()
    };
    a.save();
    sync(&mut a, &mut b);
    // Deleted here, a login added to it there.
    a.vault.db.group_mut(group).unwrap().remove();
    a.vault
        .db
        .deleted_objects
        .insert(group.uuid(), Some(Times::now()));
    a.save();
    let id = {
        let mut group = b.vault.db.group_mut(group).unwrap();
        let mut entry = group.add_entry();
        entry.set_unprotected(fields::TITLE, "In Work");
        entry.id()
    };
    b.save();
    let synced = sync(&mut a, &mut b);
    assert_eq!(synced.b.kept, 1);
    assert!(a.vault.db.entry(id).is_some());
    assert_eq!(a.vault.db.entry(id).unwrap().parent().name, "Work");
    nothing_left(&mut a, &mut b);
}

#[test]
fn histories_join_without_doubles_and_keep_their_limit() {
    let (_dir, mut a, mut b) = two();
    a.vault.db.meta.history_max_items = Some(4);
    b.vault.db.meta.history_max_items = Some(4);
    b.save();
    let id = a.login("Mail", "p0");
    sync(&mut a, &mut b);
    for n in 1..=6 {
        a.edit(&id, |e| e.password = Some(s(&format!("p{n}"))));
        std::thread::sleep(std::time::Duration::from_millis(1050));
    }
    sync(&mut a, &mut b);
    let versions = |device: &Device| -> Vec<String> {
        let entry = device
            .vault
            .db
            .entry(EntryId::from_uuid(id.parse().unwrap()))
            .unwrap();
        (0..entry.history.as_ref().map_or(0, |h| h.get_entries().len()))
            .filter_map(|i| entry.historical(i))
            .map(|v| v.get(fields::PASSWORD).unwrap_or_default().to_owned())
            .collect()
    };
    assert_eq!(b.password(&id), "p6");
    assert!(versions(&b).len() <= 4, "{:?}", versions(&b));
    let mut unique = versions(&b);
    unique.dedup();
    assert_eq!(unique.len(), versions(&b).len());
    assert_eq!(versions(&b).last().map(String::as_str), Some("p5"));
    nothing_left(&mut a, &mut b);
}

#[test]
fn attachments_come_go_and_stay_in_history() {
    let (_dir, mut a, mut b) = two();
    let id = a.login("Server", "p");
    let uuid = EntryId::from_uuid(id.parse().unwrap());
    let large: Vec<u8> = (0..6 * 1024 * 1024).map(|i: u32| (i % 251) as u8).collect();
    {
        let mut entry = a.vault.db.entry_mut(uuid).unwrap();
        entry.add_attachment("big.bin", Value::protected(large.clone()));
        entry.add_attachment("note.txt", Value::unprotected(b"one".to_vec()));
    }
    a.save();
    sync(&mut a, &mut b);
    let file = |device: &Device, name: &str| -> Option<Vec<u8>> {
        let entry = device.vault.db.entry(uuid)?;
        entry
            .attachments_named()
            .find(|(n, _)| *n == name)
            .map(|(_, file)| file.data.get().clone())
    };
    assert_eq!(file(&b, "big.bin").as_deref(), Some(large.as_slice()));

    // Changed there: the old one stays in the history here.
    {
        let mut entry = a.vault.db.entry_mut(uuid).unwrap();
        let mut tracked = entry.track_changes();
        tracked
            .as_mut()
            .add_attachment("note.txt", Value::unprotected(b"two".to_vec()));
    }
    a.save();
    sync(&mut a, &mut b);
    assert_eq!(file(&b, "note.txt").as_deref(), Some(&b"two"[..]));
    let entry = b.vault.db.entry(uuid).unwrap();
    let old: Vec<Vec<u8>> = (0..entry.history.as_ref().unwrap().get_entries().len())
        .filter_map(|i| entry.historical(i))
        .flat_map(|v| {
            v.attachments_named()
                .filter(|(n, _)| *n == "note.txt")
                .map(|(_, f)| f.data.get().clone())
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(old.contains(&b"one".to_vec()), "{old:?}");
    b.reopen();
    assert_eq!(file(&b, "big.bin").as_deref(), Some(large.as_slice()));

    // Removed there: removed here.
    a.vault
        .db
        .entry_mut(uuid)
        .unwrap()
        .remove_attachment_by_name("big.bin");
    a.save();
    sync(&mut a, &mut b);
    assert!(file(&b, "big.bin").is_none());
    b.reopen();
    assert_eq!(file(&b, "note.txt").as_deref(), Some(&b"two"[..]));
    nothing_left(&mut a, &mut b);
}

#[test]
fn a_shared_value_deleted_there_leaves_copies_here() {
    let (_dir, mut a, mut b) = two();
    let api = a.env("api", &[("TOKEN", "t1")]);
    let web = a.env("web", &[("TOKEN", "t1")]);
    let shared_id = a
        .vault
        .share_env_variable(&api, "TOKEN", std::slice::from_ref(&web))
        .unwrap();
    a.save();
    sync(&mut a, &mut b);
    // There: the shared value deleted for good. Here: a new environment
    // uses it.
    a.vault.delete_shared_value(&shared_id).unwrap();
    a.vault.empty_trash().unwrap();
    a.save();
    let jobs = b.env("jobs", &[("TOKEN", "x")]);
    b.vault
        .share_env_variable(&api, "TOKEN", std::slice::from_ref(&jobs))
        .unwrap();
    b.save();
    assert_eq!(b.value(&jobs, "TOKEN"), "t1");
    let synced = sync(&mut a, &mut b);
    assert!(
        synced
            .b_plan
            .changes
            .iter()
            .any(|c| c.id == shared_id && c.op == ChangeOp::Delete)
    );
    assert_eq!(
        b.vault.shared_values().len(),
        0,
        "{:?}",
        b.vault.shared_values()
    );
    for env in [&api, &web, &jobs] {
        assert_eq!(b.value(env, "TOKEN"), "t1");
    }
}

#[test]
fn removal_records_older_than_their_lifetime_do_nothing() {
    let (_dir, mut a, mut b) = two();
    let id = b.login("Back", "p");
    let ancient = Times::now() - chrono::Duration::days(500);
    a.vault
        .db
        .deleted_objects
        .insert(id.parse().unwrap(), Some(ancient));
    a.save();
    let copy = a.vault.sync_copy().unwrap();
    let peer = b.vault.open_sync_copy(&copy).unwrap();
    assert!(!peer.db.deleted_objects.contains_key(&id.parse().unwrap()));
    let synced = sync(&mut a, &mut b);
    assert_eq!(
        synced.b_plan.changes.len(),
        0,
        "{:?}",
        synced.b_plan.changes
    );
    assert!(a.vault.entry(&id).is_ok());
}

#[test]
fn what_never_syncs_is_not_in_the_copy_and_not_taken() {
    let (_dir, mut a, mut b) = two();
    for key in [
        "sshkm.browser.client",
        "sshkm.own.key",
        "sshkm.env.key",
        "sshkm.chat.AAAA",
        "KPXC_BROWSER_x",
    ] {
        a.vault.db.meta.custom_data.insert(
            key.into(),
            CustomDataItem {
                value: Some(CustomDataValue::String("secret".into())),
                last_modification_time: None,
            },
        );
    }
    a.save();
    let copy = a.vault.sync_copy().unwrap();
    let parsed = crate::vault::parse_database(&copy, &a.vault.secret).unwrap();
    assert_eq!(
        parsed.meta.custom_data.len(),
        0,
        "{:?}",
        parsed.meta.custom_data
    );
    let before = b.vault.db.meta.custom_data.clone();
    sync(&mut a, &mut b);
    assert_eq!(b.vault.db.meta.custom_data, before);
}

#[test]
fn local_items_stay_on_their_computer() {
    let (_dir, mut a, mut b) = two();
    let (chat, message) = {
        let mut root = a.vault.db.root_mut();
        let mut group = root.add_group();
        group.name = "Chat".into();
        group.custom_data.insert(
            LOCAL.into(),
            CustomDataItem {
                value: Some(CustomDataValue::String("chat".into())),
                last_modification_time: None,
            },
        );
        let gid = group.id();
        let mut inner = group.add_group();
        inner.name = "With Bobur".into();
        let mut entry = inner.add_entry();
        entry.set_protected(fields::NOTES, "hello");
        (gid, entry.id())
    };
    a.save();
    let shape = |vault: &Vault| {
        let entry = vault.db.entry(message).unwrap();
        (
            entry.get(fields::NOTES).unwrap().to_owned(),
            entry.parent().id(),
        )
    };
    let before = shape(&a.vault);
    let copy = a.vault.sync_copy().unwrap();
    let parsed = crate::vault::parse_database(&copy, &a.vault.secret).unwrap();
    assert!(parsed.group(chat).is_none() && parsed.entry(message).is_none());

    // The other side sends an entry with the local one's id, and a group
    // marked local of its own: neither is taken, nothing local changes.
    {
        let mut root = b.vault.db.root_mut();
        let mut entry = root.add_entry_with_id(message).unwrap();
        entry.set_protected(fields::NOTES, "overwritten");
    }
    b.save();
    let synced = sync(&mut a, &mut b);
    assert!(
        synced
            .a_plan
            .changes
            .iter()
            .all(|c| c.id != message.uuid().to_string())
    );
    assert_eq!(
        synced.a_plan.conflicts.len(),
        0,
        "{:?}",
        synced.a_plan.conflicts
    );
    assert_eq!(shape(&a.vault), before);
    assert!(b.vault.db.group(chat).is_none());
    assert_eq!(
        b.vault.db.entry(message).unwrap().get(fields::NOTES),
        Some("overwritten")
    );
    // Nothing is asked or changed next time either.
    let synced = sync(&mut a, &mut b);
    let left = |plan: &VaultPlan| plan.changes.len() + plan.conflicts.len();
    assert_eq!((left(&synced.a_plan), left(&synced.b_plan)), (0, 0));
    assert_eq!(shape(&a.vault), before);
}

#[test]
fn a_copy_must_be_this_vault_and_within_bounds() {
    let (dir, mut a, b) = two();
    // Another vault: its secret doesn't open it.
    let other = VaultPaths::new(dir.path().join("other.kdbx"));
    let (other, _) = Vault::create(&other, &s("master")).unwrap();
    let refused = |result: Result<PeerVault>| matches!(result, Err(Error::InvalidInput(_)));
    assert!(refused(a.vault.open_sync_copy(&other.sync_copy().unwrap())));
    // This secret, another root.
    let stranger = keepass::Database::with_config(a.vault.db.config.clone());
    let bytes = crate::vault::serialize(&stranger, &a.vault.secret).unwrap();
    assert!(refused(a.vault.open_sync_copy(&bytes)));
    // An entry with a group's id.
    let mut odd = b.vault.db.clone();
    let root = odd.root().id();
    odd.root_mut()
        .add_entry_with_id(EntryId::from_uuid(root.uuid()))
        .unwrap();
    let bytes = crate::vault::serialize(&odd, &a.vault.secret).unwrap();
    assert!(refused(a.vault.open_sync_copy(&bytes)));
    // Groups too deep.
    let mut deep = b.vault.db.clone();
    let mut parent = deep.root().id();
    for _ in 0..=MAX_DEPTH + 1 {
        parent = deep.group_mut(parent).unwrap().add_group().id();
    }
    let bytes = crate::vault::serialize(&deep, &a.vault.secret).unwrap();
    assert!(refused(a.vault.open_sync_copy(&bytes)));
    // A time far ahead counts as now.
    let mut ahead = b.vault.db.clone();
    let id = ahead.root_mut().add_entry().id();
    let year_2099 = chrono::NaiveDate::from_ymd_opt(2099, 1, 1)
        .unwrap()
        .and_hms_opt(0, 0, 0)
        .unwrap();
    ahead.entry_mut(id).unwrap().times.last_modification = Some(year_2099);
    let bytes = crate::vault::serialize(&ahead, &a.vault.secret).unwrap();
    let peer = a.vault.open_sync_copy(&bytes).unwrap();
    let when = peer.db.entry(id).unwrap().times.last_modification.unwrap();
    assert!(when < Times::now() + chrono::Duration::minutes(6));
    a.save();
}

#[test]
fn variables_that_load_code_are_flagged() {
    let (_dir, mut a, mut b) = two();
    let env = a.env("dev", &[("PORT", "80")]);
    sync(&mut a, &mut b);
    a.set_var(&env, "NODE_OPTIONS", "--require /tmp/x.js");
    a.set_var(&env, "PORT", "81");
    let other = a.env("ops", &[("LD_PRELOAD", "/tmp/x.so"), ("HOST", "h")]);
    let peer = b
        .vault
        .open_sync_copy(&a.vault.sync_copy().unwrap())
        .unwrap();
    let plan = b.vault.plan_sync(&peer, &b.base, &b.hasher);
    let risky = |id: &str| {
        plan.changes
            .iter()
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("{id}: {:?} {:?}", plan.changes, plan.conflicts))
            .risky
            .clone()
    };
    assert_eq!(risky(&env), ["NODE_OPTIONS"]);
    assert_eq!(risky(&other), ["LD_PRELOAD"]);
    let label = |id: &str| {
        plan.changes
            .iter()
            .find(|c| c.id == id)
            .unwrap()
            .label
            .clone()
    };
    assert_eq!(label(&other), "ops");
}

#[test]
fn an_item_changed_during_the_review_is_left_for_next_time() {
    let (_dir, mut a, mut b) = two();
    let id = a.login("Mail", "p1");
    sync(&mut a, &mut b);
    a.edit(&id, |e| e.password = Some(s("p2")));
    let peer = b
        .vault
        .open_sync_copy(&a.vault.sync_copy().unwrap())
        .unwrap();
    let plan = b.vault.plan_sync(&peer, &b.base, &b.hasher);
    // Meanwhile, here.
    b.edit(&id, |e| e.notes = "typed while the dialog was open".into());
    let make = plan.changes.iter().map(|c| c.id.clone()).collect();
    let applied = b
        .vault
        .apply_sync(&peer, &plan, &b.hasher, &make, &BTreeSet::new())
        .unwrap();
    assert!(applied.skipped.contains(&id));
    assert_eq!(b.password(&id), "p1");
    // The next sync merges both.
    b.save();
    sync(&mut a, &mut b);
    assert_eq!(b.password(&id), "p2");
    assert_eq!(
        a.vault.entry(&id).unwrap().notes,
        "typed while the dialog was open"
    );
}

#[test]
fn a_conflict_value_is_shown_only_when_asked_for_one_field() {
    let (_dir, mut a, mut b) = two();
    let id = a.login("Mail", "p1");
    sync(&mut a, &mut b);
    a.edit(&id, |e| e.password = Some(s("mine")));
    b.edit(&id, |e| e.password = Some(s("theirs")));
    let peer = a
        .vault
        .open_sync_copy(&b.vault.sync_copy().unwrap())
        .unwrap();
    let plan = a.vault.plan_sync(&peer, &a.base, &a.hasher);
    let conflict = &plan.conflicts[0];
    assert_eq!(conflict.fields, ["s:Password"]);
    let shown = |theirs| {
        a.vault
            .sync_value(&peer, &id, "s:Password", theirs)
            .unwrap()
            .expose_secret()
            .to_owned()
    };
    assert_eq!(
        (shown(false), shown(true)),
        ("mine".into(), "theirs".into())
    );
    assert!(a.vault.sync_value(&peer, &id, "a:file", true).is_err());
    assert!(a.vault.sync_value(&peer, &id, "s:otp", true).is_err());
}

/// A project `Shop` with the folder `shop` on both sides, and an
/// environment in it on `a`.
fn project_with_env(dir: &std::path::Path, a: &mut Device, b: &mut Device) -> (String, EnvFile) {
    let folder = dir.join("shop");
    fs::create_dir_all(&folder).unwrap();
    let folder_text = crate::vault::projects::folder_text(&folder, None).unwrap();
    let project = a
        .vault
        .add_project(&ProjectInput {
            name: "Shop".into(),
            color: ProjectColor::Blue,
        })
        .unwrap();
    a.vault
        .set_project_member(
            &project,
            &ProjectMember::Folder {
                path: folder_text.clone(),
            },
            true,
        )
        .unwrap();
    let env = a
        .vault
        .add_environment(&EnvInput {
            project: Some(project),
            part: String::new(),
            name: "dev".into(),
            notes: String::new(),
        })
        .unwrap();
    a.set_var(&env, "PORT", "3000");
    a.save();
    b.vault.merge_projects(&a.vault.project_records()).unwrap();
    b.save();
    (
        env,
        EnvFile {
            folder: folder_text,
            path: ".env".into(),
        },
    )
}

fn ctx(dir: &std::path::Path) -> FilesContext {
    FilesContext {
        home: None,
        ssh_dir: dir.join(".ssh"),
        pipes: Vec::new(),
        pipe_list: None,
    }
}

/// What a round of `.env` files does on `device`: the files' states.
fn round(device: &mut Device, dir: &std::path::Path) -> Vec<FileState> {
    let ctx = ctx(dir);
    let mut state = crate::vault::envs::files::SyncState::default();
    let pulled = device.vault.env_files_pull(&ctx, &state, None).unwrap();
    if pulled.vault_changed {
        device.save();
    }
    device.vault.env_files_push(&ctx, &mut state, pulled, None);
    device
        .vault
        .env_files_status(&ctx, &state)
        .into_iter()
        .map(|status| status.state)
        .collect()
}

#[cfg(unix)]
#[test]
fn a_virtual_file_never_becomes_a_file_where_pipes_are_missing() {
    let (dir, mut a, mut b) = two();
    let (env, file) = project_with_env(dir.path(), &mut a, &mut b);
    a.vault
        .bind_env_file_at(&env, &file, FileLevel::Virtual, &ctx(dir.path()))
        .unwrap();
    a.save();
    sync(&mut a, &mut b);
    // `b` is a system without pipes in folders, as Windows is.
    crate::vault::envs::files::NO_PIPES.with(|no| no.set(true));
    let states = round(&mut b, dir.path());
    crate::vault::envs::files::NO_PIPES.with(|no| no.set(false));
    assert_eq!(
        states,
        [FileState::Inactive {
            reason: InactiveReason::Unsupported
        }]
    );
    assert!(fs::symlink_metadata(dir.path().join("shop").join(".env")).is_err());
}

#[test]
fn a_remote_environment_gets_no_file_from_a_sync() {
    let (dir, mut a, mut b) = two();
    let (env, file) = project_with_env(dir.path(), &mut a, &mut b);
    sync(&mut a, &mut b);
    // A device (buggy, or not the user's) says the remote environment
    // has a file at level 1.
    {
        let mut entry = a
            .vault
            .db
            .entry_mut(EntryId::from_uuid(env.parse().unwrap()))
            .unwrap();
        let data = serde_json::json!({
            "kind": "remote",
            "files": [{ "folder": file.folder, "path": file.path }],
        });
        entry.custom_data.insert(
            "sshkm.env.files".into(),
            CustomDataItem {
                value: Some(CustomDataValue::String(data.to_string())),
                last_modification_time: None,
            },
        );
    }
    a.save();
    sync(&mut a, &mut b);
    let states = round(&mut b, dir.path());
    assert_eq!(
        states,
        [FileState::Inactive {
            reason: InactiveReason::Remote
        }]
    );
    assert!(!dir.path().join("shop").join(".env").exists());
}
