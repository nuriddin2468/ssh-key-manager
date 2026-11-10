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

#[test]
fn projects_are_kept_in_the_vault_with_their_members() {
    let dir = tempfile::tempdir().unwrap();
    let paths = VaultPaths::new(dir.path().join("vault.kdbx"));
    let (mut vault, secret) = Vault::create(&paths, &s("master")).unwrap();
    let id = vault.add_project(&input(" Shop ")).unwrap();
    for member in [
        host("shop-prod"),
        host("shop-bastion"),
        ProjectMember::Key {
            fingerprint: "SHA256:k3XbV9qL2mT8sRw4YzN1cJ6hD0fGpA5uE7oIiKjBnHw".into(),
        },
        ProjectMember::Environment {
            group: "shop-api".into(),
        },
        ProjectMember::Folder {
            path: "~/code/shop".into(),
        },
    ] {
        assert!(vault.set_project_member(&id, &member, true).unwrap());
        assert!(!vault.set_project_member(&id, &member, true).unwrap());
    }
    let github = login(&mut vault, "GitHub");
    assert!(
        vault
            .set_project_member(&id, &ProjectMember::Login { id: github.clone() }, true)
            .unwrap()
    );
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
    assert_eq!(project.environments, ["shop-api"]);
    assert_eq!(project.folders, ["~/code/shop"]);
    assert_eq!(project.logins, [github]);
    // The tag is a KeePass tag, as KeePassXC reads and shows it.
    assert_eq!(tags_on_disk(&vault, &secret, "GitHub"), ["Shop"]);
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
fn logins_belong_by_tag_and_follow_renames_and_removals() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "vault");
    let tagged = login(&mut vault, "Tagged in KeePassXC");
    {
        let id = parse_id_for_test(&tagged);
        let mut entry = vault.db.entry_mut(id).unwrap();
        entry.tags = vec!["work".into(), " shop ".into(), String::new()];
    }
    let trashed = login(&mut vault, "Old");
    let id = vault.add_project(&input("Shop")).unwrap();
    // A login already tagged with the name is a member at once.
    assert_eq!(
        vault.project(&id).unwrap().logins,
        std::slice::from_ref(&tagged)
    );
    vault
        .set_project_member(
            &id,
            &ProjectMember::Login {
                id: trashed.clone(),
            },
            true,
        )
        .unwrap();
    vault.trash_entry(&trashed).unwrap();
    assert_eq!(
        vault.project(&id).unwrap().logins,
        std::slice::from_ref(&tagged)
    );

    vault.update_project(&id, &input("Shop Co")).unwrap();
    let tags = |vault: &Vault, entry: &str| vault.find(entry).unwrap().tags.clone();
    assert_eq!(tags(&vault, &tagged), ["work", "Shop Co"]);
    assert_eq!(tags(&vault, &trashed), ["Shop Co"]);
    assert_eq!(
        vault.project(&id).unwrap().logins,
        std::slice::from_ref(&tagged)
    );

    vault
        .set_project_member(&id, &ProjectMember::Login { id: tagged.clone() }, false)
        .unwrap();
    assert_eq!(tags(&vault, &tagged), ["work"]);
    vault.remove_project(&id).unwrap();
    assert_eq!(tags(&vault, &trashed), Vec::<String>::new());
    assert_eq!(vault.projects(), Vec::<Project>::new());
    assert!(vault.project(&id).is_err());
    assert!(vault.update_project(&id, &input("Again")).is_err());

    let env = vault
        .add_environment(&EnvInput {
            project: "shop".into(),
            name: "dev".into(),
            notes: String::new(),
        })
        .unwrap();
    let again = vault.add_project(&input("Shop")).unwrap();
    assert!(
        vault
            .set_project_member(&again, &ProjectMember::Login { id: env }, true)
            .is_err()
    );
}

fn parse_id_for_test(id: &str) -> EntryId {
    super::super::parse_id(id).unwrap()
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
            group: "a/b".into(),
        },
        ProjectMember::Folder {
            path: String::new(),
        },
        ProjectMember::Folder {
            path: "~/a\nb".into(),
        },
        ProjectMember::Login {
            id: "not-an-id".into(),
        },
    ] {
        assert!(
            vault.set_project_member(&id, &bad, true).is_err(),
            "{bad:?}"
        );
    }
    assert_eq!(vault.project(&id).unwrap().hosts, Vec::<String>::new());
}

#[test]
fn folders_are_kept_relative_to_home() {
    let home = Path::new("/home/me");
    let text = |path: &str| folder_text(Path::new(path), Some(home)).ok();
    assert_eq!(text("/home/me/code/shop").as_deref(), Some("~/code/shop"));
    assert_eq!(text("/home/me").as_deref(), Some("~"));
    assert_eq!(text("/srv/shop").as_deref(), Some("/srv/shop"));
    assert_eq!(text("relative/path"), None);
    assert_eq!(text("/home/me/../other"), None);
    assert_eq!(
        folder_text(Path::new("/home/me/code"), None)
            .as_deref()
            .ok(),
        Some("/home/me/code")
    );

    let path = |text: &str| folder_path(text, Some(home));
    assert_eq!(path("~/code/shop"), Some(home.join("code").join("shop")));
    assert_eq!(path("~"), Some(home.to_path_buf()));
    assert_eq!(path("~\\code"), Some(home.join("code")));
    assert_eq!(path("/srv/shop"), Some("/srv/shop".into()));
    assert_eq!(path("~/../etc"), None);
    assert_eq!(path("/srv/../etc"), None);
    assert_eq!(path("relative"), None);
    assert_eq!(folder_path("~/code", None), None);
}

/// A record as another device would send it, changed at `modified`.
fn record(id: &str, json: &Value) -> ProjectRecord {
    ProjectRecord {
        id: id.into(),
        record: json.to_string(),
    }
}

#[test]
fn a_sync_takes_what_changed_last() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "vault");
    let id = vault.add_project(&input("Shop")).unwrap();
    let github = login(&mut vault, "GitHub");
    vault
        .set_project_member(&id, &ProjectMember::Login { id: github.clone() }, true)
        .unwrap();

    // Older than the one here: not taken.
    let old = record(
        &id,
        &serde_json::json!({"name": "Old", "modified": "2020-01-01T00:00:00Z"}),
    );
    assert!(!vault.merge_projects(&[old]).unwrap());
    assert_eq!(names(&vault), ["Shop"]);

    // Renamed there later: taken, and the tag here moves along. Fields of a
    // later version are kept.
    let in_minutes = |minutes: i64| {
        let text = (OffsetDateTime::now_utc() + Duration::minutes(minutes))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        format!("{}Z", &text[..19])
    };
    let later = in_minutes(1);
    let renamed = record(
        &id,
        &serde_json::json!({
            "name": "Shop Co",
            "color": "a-color-of-the-future",
            "hosts": ["shop-prod"],
            "modified": later,
            "future": {"x": 1},
        }),
    );
    assert!(
        vault
            .merge_projects(std::slice::from_ref(&renamed))
            .unwrap()
    );
    let project = vault.project(&id).unwrap();
    assert_eq!(project.name, "Shop Co");
    assert_eq!(project.color, ProjectColor::Teal);
    assert_eq!(project.logins, std::slice::from_ref(&github));
    assert_eq!(vault.find(&github).unwrap().tags, ["Shop Co"]);
    assert_eq!(vault.project_records(), [renamed]);

    // From too far in the future: not taken.
    let ahead = record(
        &id,
        &serde_json::json!({"name": "Ahead", "modified": "2999-01-01T00:00:00Z"}),
    );
    assert!(!vault.merge_projects(&[ahead]).unwrap());

    // Removed there, later still: removed here, with its tag.
    let latest = in_minutes(2);
    let removed = record(
        &id,
        &serde_json::json!({"modified": latest, "removed": latest}),
    );
    assert!(vault.merge_projects(&[removed]).unwrap());
    assert_eq!(vault.projects(), Vec::<Project>::new());
    assert_eq!(vault.find(&github).unwrap().tags, Vec::<String>::new());

    // A record that isn't one is skipped, and refused by the check.
    let bad = record(
        &uuid::Uuid::nil().to_string(),
        &serde_json::json!({"name": "a;b", "modified": "2026-01-01T00:00:00Z"}),
    );
    assert!(check_records(std::slice::from_ref(&bad)).is_err());
    assert!(!vault.merge_projects(&[bad]).unwrap());
    let not_an_id = record(
        "x",
        &serde_json::json!({"name": "Fine", "modified": "2026-01-01T00:00:00Z"}),
    );
    assert!(check_records(&[not_an_id]).is_err());
}

#[test]
fn projects_made_on_two_computers_with_one_name_become_one() {
    let dir = tempfile::tempdir().unwrap();
    let mut laptop = vault(&dir, "laptop");
    let mut desktop = vault(&dir, "desktop");
    let on_laptop = laptop.add_project(&input("Shop")).unwrap();
    laptop
        .set_project_member(&on_laptop, &host("shop-prod"), true)
        .unwrap();
    let on_desktop = desktop.add_project(&input("shop")).unwrap();
    desktop
        .set_project_member(&on_desktop, &host("shop-db"), true)
        .unwrap();
    laptop.add_project(&input("Blog")).unwrap();

    let from_laptop = laptop.project_records();
    let from_desktop = desktop.project_records();
    assert!(check_records(&from_laptop).is_ok());
    assert!(laptop.merge_projects(&from_desktop).unwrap());
    assert!(desktop.merge_projects(&from_laptop).unwrap());
    // Once more, as the next sync would.
    let (from_laptop, from_desktop) = (laptop.project_records(), desktop.project_records());
    laptop.merge_projects(&from_desktop).unwrap();
    desktop.merge_projects(&from_laptop).unwrap();

    let kept = on_laptop.clone().min(on_desktop.clone());
    for vault in [&laptop, &desktop] {
        let projects = vault.projects();
        assert_eq!(projects.len(), 2, "{projects:?}");
        let shop = projects.iter().find(|p| p.id == kept).unwrap();
        let mut hosts = shop.hosts.clone();
        hosts.sort();
        assert_eq!(hosts, ["shop-db", "shop-prod"]);
    }
    assert_eq!(laptop.projects(), desktop.projects());
}

#[test]
fn a_sync_brings_no_more_projects_than_a_vault_holds() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "vault");
    let records: Vec<ProjectRecord> = (0..=MAX_PROJECTS)
        .map(|n| {
            record(
                &new_id(),
                &serde_json::json!({"name": format!("p{n}"), "modified": "2026-01-01T00:00:00Z"}),
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
