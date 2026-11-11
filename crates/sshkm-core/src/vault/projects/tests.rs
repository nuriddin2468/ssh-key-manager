use std::path::Path;

use keepass::{Database, DatabaseKey};
use secrecy::{ExposeSecret, SecretString};
use tempfile::TempDir;

use super::*;
use crate::vault::envs::EnvInput;
use crate::vault::{EntryInput, VaultPaths};

fn s(text: &str) -> SecretString {
    SecretString::from(text.to_owned())
}

fn vault(dir: &TempDir, name: &str) -> Vault {
    let paths = VaultPaths::new(dir.path().join(format!("{name}.kdbx")));
    Vault::create(&paths, &s("master")).unwrap().0
}

fn input(name: &str) -> ProjectInput {
    ProjectInput {
        name: name.into(),
        color: ProjectColor::Blue,
    }
}

fn login(vault: &mut Vault, title: &str) -> String {
    vault
        .add_entry(&EntryInput {
            title: title.into(),
            ..EntryInput::default()
        })
        .unwrap()
}

fn host(alias: &str) -> ProjectMember {
    ProjectMember::Host {
        alias: alias.into(),
    }
}

fn names(vault: &Vault) -> Vec<String> {
    vault.projects().into_iter().map(|p| p.name).collect()
}

/// The tags of an entry as KeePass reads them from the saved file.
fn tags_on_disk(vault: &Vault, secret: &SecretString, title: &str) -> Vec<String> {
    let bytes = std::fs::read(&vault.paths().database).unwrap();
    let db = Database::parse(
        &bytes,
        DatabaseKey::new().with_password(secret.expose_secret()),
    )
    .unwrap();
    let entry = db
        .iter_all_entries()
        .find(|entry| entry.get(keepass::db::fields::TITLE) == Some(title))
        .unwrap();
    entry.tags.clone()
}

fn tags(vault: &Vault, entry: &str) -> Vec<String> {
    vault.find(entry).unwrap().tags.clone()
}

fn set_tags(vault: &mut Vault, entry: &str, tags: &[&str]) {
    let id = super::super::parse_id(entry).unwrap();
    vault.db.entry_mut(id).unwrap().tags = tags.iter().map(|t| (*t).to_owned()).collect();
}

fn add(vault: &mut Vault, id: &str, member: &ProjectMember) {
    assert!(vault.set_project_member(id, member, true).unwrap());
}

fn login_member(id: &str) -> ProjectMember {
    ProjectMember::Login { id: id.into() }
}

#[test]
fn projects_are_kept_in_the_vault_with_their_members() {
    let dir = tempfile::tempdir().unwrap();
    let paths = VaultPaths::new(dir.path().join("vault.kdbx"));
    let (mut vault, secret) = Vault::create(&paths, &s("master")).unwrap();
    let id = vault.add_project(&input(" Shop ")).unwrap();
    let env = vault
        .add_environment(&EnvInput {
            project: None,
            part: "shop-api".into(),
            name: "dev".into(),
            notes: String::new(),
        })
        .unwrap();
    for member in [
        host("shop-prod"),
        host("shop-bastion"),
        ProjectMember::Key {
            fingerprint: "SHA256:k3XbV9qL2mT8sRw4YzN1cJ6hD0fGpA5uE7oIiKjBnHw".into(),
        },
        ProjectMember::Environment { id: env.clone() },
        ProjectMember::Folder {
            path: "~/code/shop".into(),
        },
    ] {
        assert!(vault.set_project_member(&id, &member, true).unwrap());
        assert!(!vault.set_project_member(&id, &member, true).unwrap());
    }
    let github = login(&mut vault, "GitHub");
    set_tags(&mut vault, &github, &["work"]);
    add(&mut vault, &id, &login_member(&github));
    assert!(
        vault
            .set_project_member(&id, &host("shop-bastion"), false)
            .unwrap()
    );
    vault.save(&dir.path().join("backups")).unwrap();

    let vault = Vault::unlock(&paths, &s("master")).unwrap();
    let project = vault.project(&id).unwrap();
    assert_eq!(project.name, "Shop");
    assert_eq!(project.color, ProjectColor::Blue);
    assert_eq!(project.hosts, ["shop-prod"]);
    assert_eq!(
        project.keys,
        ["SHA256:k3XbV9qL2mT8sRw4YzN1cJ6hD0fGpA5uE7oIiKjBnHw"]
    );
    assert_eq!(project.environments, std::slice::from_ref(&env));
    assert_eq!(project.folders, ["~/code/shop"]);
    assert_eq!(project.logins, std::slice::from_ref(&github));
    // A KeePass tag, as KeePassXC reads and shows it, next to the user's own.
    assert_eq!(
        tags_on_disk(&vault, &secret, "GitHub"),
        ["work", "project/Shop"]
    );
}

#[test]
fn names_are_labels_unique_in_any_case() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "vault");
    let shop = vault.add_project(&input("Shop")).unwrap();
    assert!(matches!(
        vault.add_project(&input("shop")),
        Err(Error::AlreadyExists(_))
    ));
    for bad in [
        "",
        "  ",
        "a;b",
        "a,b",
        "a:b",
        "a\tb",
        "line\nbreak",
        &"x".repeat(65),
    ] {
        assert!(vault.add_project(&input(bad)).is_err(), "{bad:?}");
    }
    let blog = vault.add_project(&input("Blog")).unwrap();
    assert!(vault.update_project(&blog, &input("SHOP")).is_err());
    // Changing only the case of its own name is fine.
    vault.update_project(&shop, &input("SHOP")).unwrap();
    assert_eq!(names(&vault), ["Blog", "SHOP"]);
    assert!(vault.project("not-an-id").is_err());
}

#[test]
fn logins_are_members_by_id_whatever_their_own_tags_say() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "vault");
    // The user's own tag named like a project makes nothing a member; a
    // `project/` tag for a name no project has is theirs and stays.
    let tagged = login(&mut vault, "Tagged in KeePassXC");
    set_tags(&mut vault, &tagged, &["work", " shop ", ""]);
    let thesis = login(&mut vault, "Thesis");
    set_tags(&mut vault, &thesis, &["project/thesis", "work"]);
    let chosen = login(&mut vault, "Chosen");
    let trashed = login(&mut vault, "Old");
    let id = vault.add_project(&input("Shop")).unwrap();
    assert_eq!(vault.project(&id).unwrap().logins, Vec::<String>::new());
    add(&mut vault, &id, &login_member(&chosen));
    add(&mut vault, &id, &login_member(&trashed));
    assert_eq!(tags(&vault, &tagged), ["work", " shop ", ""]);
    assert_eq!(tags(&vault, &chosen), ["project/Shop"]);
    assert_eq!(tags(&vault, &thesis), ["project/thesis", "work"]);
    vault.trash_entry(&trashed).unwrap();
    assert_eq!(
        vault.project(&id).unwrap().logins,
        std::slice::from_ref(&chosen)
    );

    vault.update_project(&id, &input("Shop Co")).unwrap();
    assert_eq!(tags(&vault, &chosen), ["project/Shop Co"]);
    assert_eq!(tags(&vault, &trashed), ["project/Shop Co"]);
    let work = vault.add_project(&input("work")).unwrap();
    add(&mut vault, &work, &login_member(&chosen));
    assert_eq!(tags(&vault, &chosen), ["project/Shop Co", "project/work"]);

    vault
        .set_project_member(&id, &login_member(&chosen), false)
        .unwrap();
    assert_eq!(tags(&vault, &chosen), ["project/work"]);
    // Removing project "work" leaves the user's own `work` tag alone.
    vault.remove_project(&work).unwrap();
    vault.remove_project(&id).unwrap();
    assert_eq!(tags(&vault, &chosen), Vec::<String>::new());
    assert_eq!(tags(&vault, &trashed), Vec::<String>::new());
    assert_eq!(tags(&vault, &tagged), ["work", " shop ", ""]);
    assert_eq!(tags(&vault, &thesis), ["project/thesis", "work"]);
    assert_eq!(vault.projects(), Vec::<Project>::new());
    assert!(vault.project(&id).is_err());
    assert!(vault.update_project(&id, &input("Again")).is_err());

    let env = vault
        .add_environment(&EnvInput {
            project: None,
            part: "shop".into(),
            name: "dev".into(),
            notes: String::new(),
        })
        .unwrap();
    let again = vault.add_project(&input("Shop")).unwrap();
    assert!(
        vault
            .set_project_member(&again, &login_member(&env), true)
            .is_err()
    );
    // A login that is gone can't go in, and can still come out.
    let gone = "6f1c2d3e-0000-4000-8000-0000000000aa";
    assert!(
        vault
            .set_project_member(&again, &login_member(gone), true)
            .is_err()
    );
    assert!(
        vault
            .check_project_member(&login_member(gone), false)
            .is_ok()
    );
}

#[test]
fn a_login_tagged_with_a_project_in_keepassxc_joins_it_unless_taken_out() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "vault");
    let early = login(&mut vault, "Tagged before");
    set_tags(&mut vault, &early, &["project/thesis"]);
    // Made with the name of a tag: the tagged login is in it at once.
    let id = vault.add_project(&input("Thesis")).unwrap();
    assert_eq!(
        vault.project(&id).unwrap().logins,
        std::slice::from_ref(&early)
    );
    assert_eq!(tags(&vault, &early), ["project/Thesis"]);

    // Tagged later in KeePassXC: it joins at the next change.
    let later = login(&mut vault, "Tagged later");
    set_tags(&mut vault, &later, &["project/Thesis"]);
    add(&mut vault, &id, &host("lab"));
    vault.update_project(&id, &input("Thesis")).unwrap();
    let renamed = ProjectInput {
        name: "Thesis".into(),
        color: ProjectColor::Green,
    };
    vault.update_project(&id, &renamed).unwrap();
    let mut logins = vault.project(&id).unwrap().logins;
    logins.sort();
    let mut expected = vec![early.clone(), later.clone()];
    expected.sort();
    assert_eq!(logins, expected);

    // Taken out in the app, it stays out though KeePassXC still tags it.
    vault
        .set_project_member(&id, &login_member(&later), false)
        .unwrap();
    set_tags(&mut vault, &later, &["project/Thesis"]);
    vault.update_project(&id, &input("Thesis")).unwrap();
    assert_eq!(
        vault.project(&id).unwrap().logins,
        std::slice::from_ref(&early)
    );
    assert_eq!(tags(&vault, &later), Vec::<String>::new());
}

#[test]
fn a_renamed_host_moves_in_every_project_that_holds_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "vault");
    let shop = vault.add_project(&input("Shop")).unwrap();
    let blog = vault.add_project(&input("Blog")).unwrap();
    let other = vault.add_project(&input("Other")).unwrap();
    add(&mut vault, &shop, &host("bastion"));
    add(&mut vault, &blog, &host("bastion"));
    add(&mut vault, &blog, &host("jump"));
    add(&mut vault, &other, &host("db"));
    assert!(vault.rename_host_in_projects("bastion", "jump").unwrap());
    assert_eq!(vault.project(&shop).unwrap().hosts, ["jump"]);
    assert_eq!(vault.project(&blog).unwrap().hosts, ["jump"]);
    assert_eq!(vault.project(&other).unwrap().hosts, ["db"]);
    assert!(!vault.rename_host_in_projects("bastion", "x").unwrap());
    assert!(!vault.rename_host_in_projects("db", "two words").unwrap());
}

#[test]
fn a_folder_taken_out_is_one_the_project_held() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "vault");
    let id = vault.add_project(&input("Shop")).unwrap();
    let shop = ProjectMember::Folder {
        path: "~/code/shop".into(),
    };
    let other = ProjectMember::Folder {
        path: "/etc".into(),
    };
    assert!(!vault.project_has_held(&id, &shop).unwrap());
    add(&mut vault, &id, &shop);
    vault.set_project_member(&id, &shop, false).unwrap();
    assert!(vault.project_has_held(&id, &shop).unwrap());
    assert!(!vault.project_has_held(&id, &other).unwrap());
}

#[test]
fn members_are_checked() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "vault");
    let id = vault.add_project(&input("Shop")).unwrap();
    for bad in [
        host(""),
        host("two words"),
        host("prod*"),
        host("!prod"),
        host("a\nb"),
        host("say\"hi"),
        ProjectMember::Key {
            fingerprint: "MD5:aa:bb".into(),
        },
        ProjectMember::Key {
            fingerprint: "SHA256:".into(),
        },
        ProjectMember::Key {
            fingerprint: "SHA256:abc def".into(),
        },
        ProjectMember::Environment {
            id: "not-an-id".into(),
        },
        ProjectMember::Folder {
            path: String::new(),
        },
        ProjectMember::Folder {
            path: "~/a\nb".into(),
        },
        login_member("not-an-id"),
        ProjectMember::HostsFile {
            name: "API.local".into(),
        },
        ProjectMember::HostsFile {
            name: "api.local.".into(),
        },
        ProjectMember::HostsFile {
            name: "two words".into(),
        },
        ProjectMember::HostsFile {
            name: String::new(),
        },
    ] {
        assert!(!is_valid_member(&bad), "{bad:?}");
        assert!(
            vault.set_project_member(&id, &bad, true).is_err(),
            "{bad:?}"
        );
    }
    assert_eq!(vault.project(&id).unwrap().hosts, Vec::<String>::new());
}

#[test]
fn folders_are_kept_relative_to_home() {
    let root = Path::new(if cfg!(windows) { "C:\\" } else { "/" });
    let home = root.join("home").join("me");
    let srv = root.join("srv").join("shop");
    let text = |path: &Path| folder_text(path, Some(&home)).ok();
    assert_eq!(
        text(&home.join("code").join("shop")).as_deref(),
        Some("~/code/shop")
    );
    assert_eq!(text(&home).as_deref(), Some("~"));
    assert_eq!(text(&srv).as_deref(), srv.to_str());
    assert_eq!(text(Path::new("relative/path")), None);
    assert_eq!(text(&home.join("..").join("other")), None);
    assert_eq!(
        folder_text(&home.join("code"), None).ok().as_deref(),
        home.join("code").to_str()
    );

    let path = |text: &str| folder_path(text, Some(&home));
    assert_eq!(path("~/code/shop"), Some(home.join("code").join("shop")));
    assert_eq!(path("~"), Some(home.clone()));
    assert_eq!(path("~\\code"), Some(home.join("code")));
    assert_eq!(path(srv.to_str().unwrap()), Some(srv.clone()));
    assert_eq!(path("~/../etc"), None);
    assert_eq!(
        path(root.join("srv").join("..").join("etc").to_str().unwrap()),
        None
    );
    assert_eq!(path("relative"), None);
    assert_eq!(folder_path("~/code", None), None);
}

/// Sends each vault's records to the other, as a sync does both ways.
fn sync(a: &mut Vault, b: &mut Vault) {
    let (from_a, from_b) = (a.project_records(), b.project_records());
    a.merge_projects(&from_b).unwrap();
    b.merge_projects(&from_a).unwrap();
}

/// A record as another device would send it.
fn record(id: &str, json: &Value) -> ProjectRecord {
    ProjectRecord {
        id: id.into(),
        record: json.to_string(),
    }
}

/// Milliseconds from now, for records dated around it.
fn at(minutes: i64) -> i64 {
    now_ms() + minutes * 60_000
}

#[test]
fn members_come_back_in_the_order_they_were_added() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "laptop");
    let id = vault.add_project(&input("Shop")).unwrap();
    let folder = |path: &str| ProjectMember::Folder { path: path.into() };
    add(&mut vault, &id, &folder("~/code/shop-web"));
    add(&mut vault, &id, &host("prod-api"));
    add(&mut vault, &id, &folder("~/code/api"));
    add(&mut vault, &id, &host("bastion"));
    let project = vault.project(&id).unwrap();
    // The card's "main" folder and host: the first added, not the first by name.
    assert_eq!(project.folders, ["~/code/shop-web", "~/code/api"]);
    assert_eq!(project.hosts, ["prod-api", "bastion"]);

    // One taken out and added again goes last.
    vault
        .set_project_member(&id, &host("prod-api"), false)
        .unwrap();
    add(&mut vault, &id, &host("prod-api"));
    assert_eq!(vault.project(&id).unwrap().hosts, ["bastion", "prod-api"]);
}

#[test]
fn changes_made_on_two_devices_before_they_sync_all_survive() {
    let dir = tempfile::tempdir().unwrap();
    let (mut laptop, mut desktop) = (vault(&dir, "laptop"), vault(&dir, "desktop"));
    let id = laptop.add_project(&input("Shop")).unwrap();
    add(&mut laptop, &id, &host("shop-prod"));
    add(&mut laptop, &id, &host("shop-old"));
    sync(&mut laptop, &mut desktop);
    // In the order they were added.
    assert_eq!(
        desktop.project(&id).unwrap().hosts,
        ["shop-prod", "shop-old"]
    );

    // Each adds, removes and renames something before they sync again.
    add(
        &mut laptop,
        &id,
        &ProjectMember::Folder {
            path: "~/code/shop".into(),
        },
    );
    laptop
        .update_project(
            &id,
            &ProjectInput {
                name: "Shop".into(),
                color: ProjectColor::Green,
            },
        )
        .unwrap();
    add(&mut desktop, &id, &host("shop-db"));
    desktop
        .set_project_member(&id, &host("shop-old"), false)
        .unwrap();
    desktop.update_project(&id, &input("Shop Co")).unwrap();
    sync(&mut laptop, &mut desktop);

    for vault in [&laptop, &desktop] {
        let project = vault.project(&id).unwrap();
        assert_eq!(project.name, "Shop Co");
        assert_eq!(project.color, ProjectColor::Green);
        assert_eq!(project.hosts, ["shop-prod", "shop-db"]);
        assert_eq!(project.folders, ["~/code/shop"]);
    }
    assert_eq!(laptop.project_records(), desktop.project_records());
}

#[test]
fn a_rename_that_lost_leaves_no_tag_behind() {
    let dir = tempfile::tempdir().unwrap();
    let (mut laptop, mut desktop) = (vault(&dir, "laptop"), vault(&dir, "desktop"));
    let id = laptop.add_project(&input("Shop")).unwrap();
    let github = login(&mut laptop, "GitHub");
    add(&mut laptop, &id, &login_member(&github));
    sync(&mut laptop, &mut desktop);
    laptop.update_project(&id, &input("Shop A")).unwrap();
    desktop.update_project(&id, &input("Shop B")).unwrap();
    sync(&mut laptop, &mut desktop);
    let name = laptop.project(&id).unwrap().name;
    assert_eq!(desktop.project(&id).unwrap().name, name);
    assert_eq!(tags(&laptop, &github), [format!("project/{name}")]);
}

#[test]
fn the_order_records_come_in_doesnt_matter() {
    let dir = tempfile::tempdir().unwrap();
    for reverse in [false, true] {
        // A phone got "Acme" (b1) and put a login in it; meanwhile the desktop
        // and the laptop joined their two "Acme"s into a1, the smaller id.
        let mut phone = vault(&dir, &format!("phone-{reverse}"));
        let (a1, b1) = (
            "00000000-0000-4000-8000-000000000001",
            "ffffffff-0000-4000-8000-000000000001",
        );
        let early = at(-60);
        phone
            .merge_projects(&[record(
                b1,
                &serde_json::json!({"name": {"v": "Acme", "t": early}, "color": {"v": "blue", "t": early}}),
            )])
            .unwrap();
        let github = login(&mut phone, "GitHub");
        add(&mut phone, b1, &login_member(&github));
        let join = at(1);
        let mut records = vec![
            record(
                b1,
                &serde_json::json!({"name": {"v": "Acme", "t": early}, "color": {"v": "blue", "t": early}, "removed": join, "joined": a1}),
            ),
            record(
                a1,
                &serde_json::json!({"name": {"v": "Acme", "t": early}, "color": {"v": "teal", "t": early}}),
            ),
        ];
        if reverse {
            records.reverse();
        }
        assert!(phone.merge_projects(&records).unwrap());
        let projects = phone.projects();
        assert_eq!(projects.len(), 1, "{reverse}");
        assert_eq!(projects[0].id, a1);
        assert_eq!(
            projects[0].logins,
            std::slice::from_ref(&github),
            "{reverse}"
        );
        assert_eq!(tags(&phone, &github), ["project/Acme"], "{reverse}");

        // Two projects swap names: A becomes C, B becomes A.
        let (pa, pb) = (
            "10000000-0000-4000-8000-000000000001",
            "20000000-0000-4000-8000-000000000002",
        );
        let named = |name: &str, t: i64, login: &str| {
            serde_json::json!({
                "name": {"v": name, "t": t},
                "color": {"v": "blue", "t": early},
                "members": {format!("login:{login}"): {"a": early}},
            })
        };
        let (la, lb) = (login(&mut phone, "A login"), login(&mut phone, "B login"));
        phone
            .merge_projects(&[
                record(pa, &named("A", early, &la)),
                record(pb, &named("B", early, &lb)),
            ])
            .unwrap();
        assert_eq!(tags(&phone, &la), ["project/A"]);
        let mut swap = vec![
            record(pa, &named("C", join, &la)),
            record(pb, &named("A", join, &lb)),
        ];
        if reverse {
            swap.reverse();
        }
        phone.merge_projects(&swap).unwrap();
        assert_eq!(tags(&phone, &la), ["project/C"], "{reverse}");
        assert_eq!(tags(&phone, &lb), ["project/A"], "{reverse}");
    }
}

#[test]
fn projects_made_on_two_computers_with_one_name_become_one() {
    let dir = tempfile::tempdir().unwrap();
    let mut laptop = vault(&dir, "laptop");
    let mut desktop = vault(&dir, "desktop");
    let on_laptop = laptop.add_project(&input("Shop")).unwrap();
    add(&mut laptop, &on_laptop, &host("shop-prod"));
    let on_desktop = desktop.add_project(&input("shop")).unwrap();
    add(&mut desktop, &on_desktop, &host("shop-db"));
    laptop.add_project(&input("Blog")).unwrap();

    sync(&mut laptop, &mut desktop);
    // Once more, as the next sync would.
    sync(&mut laptop, &mut desktop);

    let kept = on_laptop.clone().min(on_desktop.clone());
    for vault in [&laptop, &desktop] {
        let projects = vault.projects();
        assert_eq!(projects.len(), 2, "{projects:?}");
        let shop = projects.iter().find(|p| p.id == kept).unwrap();
        // Added on two devices at about the same time: which came first is
        // the clocks' call, so only what it holds is checked here (the
        // order is in `members_come_back_in_the_order_they_were_added`).
        let mut hosts = shop.hosts.clone();
        hosts.sort();
        assert_eq!(hosts, ["shop-db", "shop-prod"]);
    }
    assert_eq!(laptop.projects(), desktop.projects());
    assert_eq!(laptop.project_records(), desktop.project_records());
}

#[test]
fn a_removal_wins_over_older_changes_and_a_later_change_wins_over_it() {
    let dir = tempfile::tempdir().unwrap();
    let (mut laptop, mut desktop) = (vault(&dir, "laptop"), vault(&dir, "desktop"));
    let id = laptop.add_project(&input("Shop")).unwrap();
    sync(&mut laptop, &mut desktop);
    laptop.remove_project(&id).unwrap();
    sync(&mut laptop, &mut desktop);
    assert_eq!(desktop.projects(), Vec::<Project>::new());

    // A change made after the removal brings it back, on both.
    let later = at(1);
    let back = record(
        &id,
        &serde_json::json!({"name": {"v": "Shop", "t": 0}, "color": {"v": "blue", "t": 0}, "members": {"host:shop-prod": {"a": later}}}),
    );
    assert!(desktop.merge_projects(&[back]).unwrap());
    sync(&mut laptop, &mut desktop);
    assert_eq!(laptop.project(&id).unwrap().hosts, ["shop-prod"]);
}

#[test]
fn a_sync_skips_what_it_cant_take_one_record_at_a_time() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "vault");
    let fine = new_id();
    let t = at(0);
    let records = [
        record(
            &new_id(),
            &serde_json::json!({"name": {"v": "a;b", "t": t}, "color": {"v": "blue", "t": t}}),
        ),
        record(
            "not-an-id",
            &serde_json::json!({"name": {"v": "X", "t": t}, "color": {"v": "blue", "t": t}}),
        ),
        record(&new_id(), &serde_json::json!({"name": "old format"})),
        // Fine, with a color and a kind of member of a later version.
        record(
            &fine,
            &serde_json::json!({
                "name": {"v": "Fine", "t": t},
                "color": {"v": "a-color-of-the-future", "t": t},
                "members": {"host:fine-prod": {"a": t}, "gadget:x": {"a": t}, "host:bad alias": {"a": t}},
                "future": {"x": 1},
            }),
        ),
    ];
    assert!(vault.merge_projects(&records).unwrap());
    let projects = vault.projects();
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0].name, "Fine");
    assert_eq!(projects[0].color, ProjectColor::Teal);
    assert_eq!(projects[0].hosts, ["fine-prod"]);
    // What a later version keeps goes on to the next device.
    let sent = vault.project_records();
    assert!(sent[0].record.contains("gadget:x") && sent[0].record.contains("future"));
    assert!(!sent[0].record.contains("bad alias"));
}

#[test]
fn times_ahead_of_this_clock_are_taken_as_a_few_minutes_ahead() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "vault");
    let id = new_id();
    vault
        .merge_projects(&[record(
            &id,
            &serde_json::json!({"name": {"v": "Ahead", "t": at(600)}, "color": {"v": "blue", "t": i64::MAX}}),
        )])
        .unwrap();
    assert_eq!(names(&vault), ["Ahead"]);
    let stored = vault.stored_project(&id).unwrap();
    assert!(stored.times().all(|t| t <= at(6)), "{stored:?}");
    // A change here still wins, without overflowing.
    vault.update_project(&id, &input("Here")).unwrap();
    assert_eq!(names(&vault), ["Here"]);
}

#[test]
fn a_keepassxc_tag_joins_a_project_made_by_a_join_or_made_again() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b) = (vault(&dir, "a"), vault(&dir, "b"));
    let on_a = a.add_project(&input("Shop")).unwrap();
    let on_b = b.add_project(&input("Shop")).unwrap();
    sync(&mut a, &mut b);
    let kept = on_a.min(on_b);
    // Tagged in KeePassXC after the join: it joins the project.
    let tagged = login(&mut a, "Tagged after the join");
    set_tags(&mut a, &tagged, &["project/Shop"]);
    // It joins at the next change of a project's name, color or logins.
    let green = ProjectInput {
        name: "Shop".into(),
        color: ProjectColor::Green,
    };
    a.update_project(&kept, &green).unwrap();
    assert_eq!(
        a.project(&kept).unwrap().logins,
        std::slice::from_ref(&tagged)
    );
    assert_eq!(tags(&a, &tagged), ["project/Shop"]);

    // Deleted and made again: its old logins stay out, a login tagged
    // afterwards joins the new one.
    a.remove_project(&kept).unwrap();
    assert_eq!(tags(&a, &tagged), Vec::<String>::new());
    set_tags(&mut a, &tagged, &["project/Shop"]);
    let fresh = login(&mut a, "Tagged for the new one");
    set_tags(&mut a, &fresh, &["project/Shop"]);
    let again = a.add_project(&input("Shop")).unwrap();
    assert_eq!(
        a.project(&again).unwrap().logins,
        std::slice::from_ref(&fresh)
    );
    assert_eq!(tags(&a, &tagged), Vec::<String>::new());
}

#[test]
fn a_time_from_a_clock_ahead_doesnt_undo_a_later_change() {
    let dir = tempfile::tempdir().unwrap();
    let mut peer = vault(&dir, "peer");
    let id = new_id();
    let from_fast = serde_json::json!({
        "name": {"v": "Shop", "t": at(-10)},
        "color": {"v": "blue", "t": at(-10)},
        "members": {"host:x": {"a": at(600)}},
    });
    peer.merge_projects(&[record(&id, &from_fast)]).unwrap();
    assert_eq!(peer.project(&id).unwrap().hosts, ["x"]);
    peer.set_project_member(&id, &host("x"), false).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    // The same record again: its time doesn't climb with this clock.
    peer.merge_projects(&[record(&id, &from_fast)]).unwrap();
    assert_eq!(peer.project(&id).unwrap().hosts, Vec::<String>::new());

    // A device whose own record is dated ahead (its clock was) heals: the
    // next merge brings its times back.
    let mut fast = vault(&dir, "fast");
    let own = new_id();
    fast.put_project(&own, &parse(&own, &from_fast.to_string()).unwrap())
        .unwrap();
    fast.merge_projects(&[]).unwrap();
    let healed = fast.stored_project(&own).unwrap();
    assert!(healed.times().all(|t| t <= at(6)), "{healed:?}");
}

#[test]
fn a_project_brought_back_by_a_removed_member_isnt_pruned() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "vault");
    let day = 24 * 60 * 60 * 1000;
    let id = new_id();
    let json = serde_json::json!({
        "name": {"v": "Back", "t": now_ms() - 600 * day},
        "color": {"v": "blue", "t": now_ms() - 600 * day},
        "removed": now_ms() - 500 * day,
        "members": {
            "host:kept": {"a": now_ms() - 600 * day},
            "host:dropped": {"a": now_ms() - 600 * day, "r": now_ms() - 450 * day},
        },
    });
    vault.merge_projects(&[record(&id, &json)]).unwrap();
    assert_eq!(names(&vault), ["Back"]);
    assert_eq!(vault.project_records().len(), 1);
    assert_eq!(names(&vault), ["Back"]);
}

#[test]
fn past_the_limit_live_projects_are_sent_before_removed_ones() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "vault");
    let t = at(0);
    let live = "ffffffff-ffff-4fff-8fff-ffffffffffff";
    let removed: Vec<ProjectRecord> = (0..MAX_RECORDS)
        .map(|n| {
            record(
                &new_id(),
                &serde_json::json!({"name": {"v": format!("gone{n}"), "t": t}, "color": {"v": "blue", "t": t}, "removed": t + 1}),
            )
        })
        .collect();
    vault.merge_projects(&removed).unwrap();
    vault
        .merge_projects(&[record(
            live,
            &serde_json::json!({"name": {"v": "Live", "t": t}, "color": {"v": "blue", "t": t}}),
        )])
        .unwrap();
    let sent = vault.project_records();
    assert_eq!(sent.len(), MAX_RECORDS);
    assert_eq!(sent[0].id, live);
}

#[test]
fn a_snapshot_puts_back_what_a_failed_change_did() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "vault");
    let before = vault.snapshot();
    let id = vault.add_project(&input("Shop")).unwrap();
    assert!(
        vault
            .set_project_member(
                &id,
                &login_member("6f1c2d3e-0000-4000-8000-0000000000aa"),
                true
            )
            .is_err()
    );
    vault.restore(before);
    assert_eq!(vault.projects(), Vec::<Project>::new());
}

#[test]
fn removals_are_forgotten_after_a_while() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "vault");
    let long_ago = now_ms() - KEEP_REMOVED_MS - 1;
    let (old, recent) = (new_id(), new_id());
    vault
        .merge_projects(&[
            record(
                &old,
                &serde_json::json!({"name": {"v": "Old", "t": 0}, "color": {"v": "blue", "t": 0}, "removed": long_ago}),
            ),
            record(
                &recent,
                &serde_json::json!({"name": {"v": "Kept", "t": 0}, "color": {"v": "blue", "t": 0},
                    "members": {"host:gone": {"a": 0, "r": long_ago}, "host:here": {"a": 1}}}),
            ),
        ])
        .unwrap();
    let sent = vault.project_records();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].id, recent);
    assert!(!sent[0].record.contains("host:gone"));
}

#[test]
fn a_sync_brings_no_more_projects_than_a_vault_holds() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "vault");
    let t = at(0);
    let records: Vec<ProjectRecord> = (0..=MAX_PROJECTS)
        .map(|n| {
            record(
                &new_id(),
                &serde_json::json!({"name": {"v": format!("p{n}"), "t": t}, "color": {"v": "blue", "t": t}}),
            )
        })
        .collect();
    vault.merge_projects(&records).unwrap();
    assert_eq!(vault.projects().len(), MAX_PROJECTS);
    assert!(vault.add_project(&input("one more")).is_err());
}

#[test]
fn a_new_project_gets_a_color_few_have() {
    assert_eq!(ProjectColor::next([]), ProjectColor::Teal);
    assert_eq!(
        ProjectColor::next([ProjectColor::Teal, ProjectColor::Indigo]),
        ProjectColor::Blue
    );
    assert_eq!(ProjectColor::next(ProjectColor::ALL), ProjectColor::Teal);
}

#[test]
fn the_copy_for_a_locked_vault_has_no_logins_and_belongs_to_one_vault() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "vault");
    let id = vault.add_project(&input("Shop")).unwrap();
    vault
        .set_project_member(&id, &host("shop-prod"), true)
        .unwrap();
    let github = login(&mut vault, "GitHub");
    vault
        .set_project_member(&id, &ProjectMember::Login { id: github }, true)
        .unwrap();
    let path = dir.path().join("projects.json");
    save_copy(&path, vault.vault_id(), &vault.projects()).unwrap();
    let copy = load_copy(&path, vault.vault_id());
    assert_eq!(copy.len(), 1);
    assert_eq!(copy[0].hosts, ["shop-prod"]);
    assert_eq!(copy[0].logins, Vec::<String>::new());
    assert_eq!(load_copy(&path, "another vault"), Vec::<Project>::new());
    assert_eq!(
        load_copy(&dir.path().join("missing.json"), vault.vault_id()),
        Vec::<Project>::new()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn hosts_file_names_are_members_in_lower_case() {
    assert_eq!(
        hosts_file_name(" API.Shop.local. ").as_deref(),
        Some("api.shop.local")
    );
    assert_eq!(hosts_file_name("a b"), None);
    assert_eq!(hosts_file_name(""), None);

    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "vault");
    let id = vault.add_project(&input("Shop")).unwrap();
    let member = ProjectMember::HostsFile {
        name: "api.shop.local".into(),
    };
    add(&mut vault, &id, &member);
    assert_eq!(vault.project(&id).unwrap().hosts_file, ["api.shop.local"]);
    assert!(
        vault.project_records()[0]
            .record
            .contains("hostsfile:api.shop.local")
    );
    assert!(vault.set_project_member(&id, &member, false).unwrap());
    assert_eq!(vault.project(&id).unwrap().hosts_file, Vec::<String>::new());

    // A copy kept by a version without hosts file names still reads.
    let path = dir.path().join("projects.json");
    let json = serde_json::json!({
        "vaultId": "v",
        "projects": [{
            "id": id, "name": "Shop", "color": "blue", "folders": [], "hosts": [],
            "keys": [], "environments": [], "logins": [], "modified": "2026-11-10T10:00:00Z",
        }],
    });
    std::fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
    assert_eq!(load_copy(&path, "v")[0].hosts_file, Vec::<String>::new());
}

/// An environment as versions before projects made it: in the group
/// `Environments/<group>`, with no part kept on it.
fn legacy_env(vault: &mut Vault, group: &str, stage: &str) -> String {
    let id = vault
        .add_environment(&EnvInput {
            project: None,
            part: group.into(),
            name: stage.into(),
            notes: String::new(),
        })
        .unwrap();
    let mut entry = vault
        .db
        .entry_mut(crate::vault::parse_id(&id).unwrap())
        .unwrap();
    entry.custom_data.remove(envs::PART);
    id
}

/// A project naming an environments' group, as projects held them before.
fn name_group(vault: &mut Vault, project: &str, group: &str) {
    let t = vault.stored_project(project).unwrap().tick();
    name_group_at(vault, project, group, t);
}

/// [`name_group`] at a set time, for an order that doesn't depend on the clock.
fn name_group_at(vault: &mut Vault, project: &str, group: &str, a: i64) {
    let mut stored = vault.stored_project(project).unwrap();
    stored
        .members
        .insert(format!("env:{group}"), Presence { a, r: None });
    vault.put_project(project, &stored).unwrap();
}

fn env_in<'a>(envs: &'a [envs::EnvSummary], id: &str) -> &'a envs::EnvSummary {
    envs.iter().find(|env| env.id == id).unwrap()
}

fn sorted(mut ids: Vec<String>) -> Vec<String> {
    ids.sort();
    ids
}

fn new_env(vault: &mut Vault, project: Option<&str>, part: &str, stage: &str) -> Result<String> {
    vault.add_environment(&EnvInput {
        project: project.map(str::to_owned),
        part: part.into(),
        name: stage.into(),
        notes: String::new(),
    })
}

#[test]
fn environments_join_the_project_that_named_their_group() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "laptop");
    let shop = vault.add_project(&input("Shop")).unwrap();
    let api_local = legacy_env(&mut vault, "shop-api", "local");
    let api_prod = legacy_env(&mut vault, "shop-api", "prod");
    let web = legacy_env(&mut vault, "shop-web", "local");
    let scripts = legacy_env(&mut vault, "scripts", "dev");
    name_group(&mut vault, &shop, "shop-api");
    name_group(&mut vault, &shop, "shop-web");

    assert!(vault.tidy_projects());
    let project = vault.project(&shop).unwrap();
    assert_eq!(
        sorted(project.environments),
        sorted(vec![api_local.clone(), api_prod.clone(), web.clone()])
    );
    // Their groups are their parts; nothing moved in KeePass.
    let envs = vault.environments();
    assert_eq!(
        env_in(&envs, &api_prod).project.as_deref(),
        Some(shop.as_str())
    );
    assert_eq!(env_in(&envs, &api_prod).part, "shop-api");
    assert_eq!(env_in(&envs, &web).part, "shop-web");
    assert_eq!(env_in(&envs, &web).group, "shop-web");
    // KeePassXC shows the project as a tag, as for logins.
    assert_eq!(tags(&vault, &web), ["project/Shop"]);
    // A group no project named stays in Personal, its name the part.
    assert_eq!(env_in(&envs, &scripts).project, None);
    assert_eq!(env_in(&envs, &scripts).part, "scripts");
    assert_eq!(tags(&vault, &scripts), Vec::<String>::new());
    // Older versions still find the group in the record.
    let stored = vault.stored_project(&shop).unwrap();
    assert!(stored.members.contains_key("env:shop-api"));

    // Again: nothing to do.
    assert!(!vault.tidy_projects());
    // One taken out stays out; one an older device makes in the group joins.
    assert!(vault.move_environment(&api_prod, None).unwrap());
    let newer = legacy_env(&mut vault, "shop-api", "staging");
    assert!(vault.tidy_projects());
    let project = vault.project(&shop).unwrap();
    assert!(!project.environments.contains(&api_prod));
    assert!(project.environments.contains(&newer));
    assert_eq!(tags(&vault, &api_prod), Vec::<String>::new());
}

#[test]
fn a_group_two_projects_named_goes_to_the_first() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "laptop");
    let shop = vault.add_project(&input("Shop")).unwrap();
    let blog = vault.add_project(&input("Blog")).unwrap();
    let shared = legacy_env(&mut vault, "shared", "dev");
    name_group_at(&mut vault, &blog, "shared", at(-2));
    name_group_at(&mut vault, &shop, "shared", at(-1));
    vault.tidy_projects();
    assert_eq!(vault.project(&blog).unwrap().environments, [shared]);
    assert_eq!(
        vault.project(&shop).unwrap().environments,
        Vec::<String>::new()
    );
}

#[test]
fn two_devices_migrating_at_once_end_up_with_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let paths = VaultPaths::new(dir.path().join("vault.kdbx"));
    let (mut vault, _) = Vault::create(&paths, &s("master")).unwrap();
    let shop = vault.add_project(&input("Shop")).unwrap();
    let blog = vault.add_project(&input("Blog")).unwrap();
    let api = legacy_env(&mut vault, "shop-api", "local");
    let web = legacy_env(&mut vault, "shop-web", "local");
    let shared = legacy_env(&mut vault, "shared", "dev");
    name_group(&mut vault, &shop, "shop-api");
    name_group(&mut vault, &shop, "shop-web");
    name_group_at(&mut vault, &blog, "shared", at(-2));
    name_group_at(&mut vault, &shop, "shared", at(-1));
    vault.save(&dir.path().join("backups")).unwrap();

    // The same file, opened on two devices before either took the step.
    let mut laptop = Vault::unlock(&paths, &s("master")).unwrap();
    let mut desktop = Vault::unlock(&paths, &s("master")).unwrap();
    assert!(laptop.tidy_projects());
    assert!(desktop.tidy_projects());
    sync(&mut laptop, &mut desktop);
    sync(&mut laptop, &mut desktop);

    assert_eq!(laptop.project_records(), desktop.project_records());
    assert_eq!(laptop.projects(), desktop.projects());
    for vault in [&laptop, &desktop] {
        let project = vault.project(&shop).unwrap();
        assert_eq!(
            sorted(project.environments),
            sorted(vec![api.clone(), web.clone()])
        );
        assert_eq!(
            vault.project(&blog).unwrap().environments,
            std::slice::from_ref(&shared)
        );
    }
    assert!(!laptop.tidy_projects());
    assert!(!desktop.tidy_projects());
}

#[test]
fn an_environment_is_in_one_project_and_the_latest_move_wins() {
    let dir = tempfile::tempdir().unwrap();
    let paths = VaultPaths::new(dir.path().join("vault.kdbx"));
    let (mut vault, _) = Vault::create(&paths, &s("master")).unwrap();
    let shop = vault.add_project(&input("Shop")).unwrap();
    let blog = vault.add_project(&input("Blog")).unwrap();
    let env = new_env(&mut vault, Some(&shop), "", "dev").unwrap();
    assert_eq!(
        vault.project(&shop).unwrap().environments,
        std::slice::from_ref(&env)
    );
    // Into another project: out of the first.
    let member = ProjectMember::Environment { id: env.clone() };
    add(&mut vault, &blog, &member);
    assert_eq!(
        vault.project(&shop).unwrap().environments,
        Vec::<String>::new()
    );
    assert_eq!(
        vault.project(&blog).unwrap().environments,
        std::slice::from_ref(&env)
    );
    assert_eq!(tags(&vault, &env), ["project/Blog"]);
    // Taken back.
    assert!(vault.set_project_member(&shop, &member, true).unwrap());
    assert_eq!(
        vault.project(&shop).unwrap().environments,
        std::slice::from_ref(&env)
    );
    vault.save(&dir.path().join("backups")).unwrap();

    // Two devices move it at once: both end up with the one moved last.
    let mut laptop = Vault::unlock(&paths, &s("master")).unwrap();
    let mut desktop = Vault::unlock(&paths, &s("master")).unwrap();
    laptop.move_environment(&env, Some(&blog)).unwrap();
    desktop.move_environment(&env, None).unwrap();
    desktop.move_environment(&env, Some(&shop)).unwrap();
    sync(&mut laptop, &mut desktop);
    // Of the records that hold it after the merge, the one that took it last.
    let rank = |project: &str| {
        let presence = laptop.stored_project(project).unwrap().members[&format!("envid:{env}")];
        presence
            .present()
            .then_some((presence.a, std::cmp::Reverse(project.to_owned())))
    };
    let last = if rank(&blog) > rank(&shop) {
        &blog
    } else {
        &shop
    };
    assert!(rank(last).is_some());
    for vault in [&laptop, &desktop] {
        let holders: Vec<String> = vault
            .projects()
            .into_iter()
            .filter(|p| p.environments.contains(&env))
            .map(|p| p.id)
            .collect();
        assert_eq!(holders, std::slice::from_ref(last));
    }
}

#[test]
fn a_stage_is_unique_within_a_project_and_its_part() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "laptop");
    let shop = vault.add_project(&input("Shop")).unwrap();
    let blog = vault.add_project(&input("Blog")).unwrap();
    let backend = new_env(&mut vault, Some(&shop), "backend", "local").unwrap();
    assert!(matches!(
        new_env(&mut vault, Some(&shop), "Backend", "LOCAL"),
        Err(Error::AlreadyExists(_))
    ));
    let frontend = new_env(&mut vault, Some(&shop), "frontend", "local").unwrap();
    new_env(&mut vault, Some(&blog), "backend", "local").unwrap();
    new_env(&mut vault, None, "backend", "local").unwrap();
    assert!(new_env(&mut vault, Some(&shop), "a/b", "local").is_err());
    // Filed for KeePassXC under the project and the part.
    let root = vault.db.root();
    let group = root
        .group_by_path(&[envs::GROUP, "Shop", "backend"])
        .expect("Environments/Shop/backend");
    assert!(group.entry_by_name("local").is_some());

    // Naming a part: not onto a stage it has.
    assert!(matches!(
        vault.set_environment_part(std::slice::from_ref(&frontend), "backend"),
        Err(Error::AlreadyExists(_))
    ));
    let envs = vault.environments();
    assert_eq!(env_in(&envs, &backend).part, "backend");
    assert_eq!(env_in(&envs, &frontend).part, "frontend");
}

#[test]
fn the_parts_a_project_had_as_groups_can_be_named() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "laptop");
    let shop = vault.add_project(&input("Shop")).unwrap();
    let local = legacy_env(&mut vault, "shop-api", "local");
    let prod = legacy_env(&mut vault, "shop-api", "prod");
    name_group(&mut vault, &shop, "shop-api");
    vault.tidy_projects();
    // A second part comes: the first is named, then kept on the entries.
    vault
        .set_environment_part(&[local.clone(), prod.clone()], "backend")
        .unwrap();
    new_env(&mut vault, Some(&shop), "frontend", "local").unwrap();
    let envs = vault.environments();
    assert_eq!(env_in(&envs, &local).part, "backend");
    assert_eq!(env_in(&envs, &prod).part, "backend");
    assert_eq!(env_in(&envs, &prod).group, "shop-api");
    // Personal's environments with a part may make a project.
    let scripts = legacy_env(&mut vault, "scripts", "dev");
    let facts = vault.suggestion_environments();
    assert_eq!(
        facts,
        [suggest::EnvFacts {
            id: scripts,
            part: "scripts".into(),
        }]
    );
}
