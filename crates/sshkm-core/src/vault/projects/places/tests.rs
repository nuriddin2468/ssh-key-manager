use secrecy::SecretString;
use tempfile::TempDir;

use super::*;
use crate::vault::VaultPaths;
use crate::vault::envs::{EnvInput, PartRename};
use crate::vault::projects::{ProjectColor, ProjectInput, ProjectMember, ProjectRecord};

fn vault(dir: &TempDir, name: &str) -> Vault {
    let paths = VaultPaths::new(dir.path().join(format!("{name}.kdbx")));
    Vault::create(&paths, &SecretString::from("master".to_owned()))
        .unwrap()
        .0
}

fn at(folder: &str, path: &str) -> ProjectFolder {
    ProjectFolder {
        folder: folder.into(),
        path: path.into(),
    }
}

fn folder(path: &str) -> ProjectMember {
    ProjectMember::Folder { path: path.into() }
}

/// A project `Shop` holding `~/code/shop`.
fn shop(vault: &mut Vault) -> String {
    let id = vault
        .add_project(&ProjectInput {
            name: "Shop".into(),
            color: ProjectColor::Blue,
        })
        .unwrap();
    vault
        .set_project_member(&id, &folder("~/code/shop"), true)
        .unwrap();
    id
}

fn env(vault: &mut Vault, project: &str, part: &str, name: &str) -> String {
    vault
        .add_environment(&EnvInput {
            project: Some(project.into()),
            part: part.into(),
            name: name.into(),
            notes: String::new(),
        })
        .unwrap()
}

/// No part folders.
const NONE: Vec<(String, String)> = Vec::new();

fn set(vault: &Vault, id: &str) -> Vec<(String, String)> {
    vault
        .project(id)
        .unwrap()
        .parts
        .into_iter()
        .map(|p| (p.part, format!("{}/{}", p.folder, p.path)))
        .collect()
}

/// Syncs both ways until nothing changes, and checks both ended up with one
/// set of records.
fn settle(a: &mut Vault, b: &mut Vault) {
    for _ in 0..3 {
        let (from_a, from_b) = (a.project_records(), b.project_records());
        a.merge_projects(&from_b).unwrap();
        b.merge_projects(&from_a).unwrap();
    }
    assert!(!a.merge_projects(&b.project_records()).unwrap());
    assert_eq!(a.project_records(), b.project_records());
}

#[test]
fn a_part_folder_goes_to_other_devices_and_the_one_set_last_wins() {
    let dir = tempfile::tempdir().unwrap();
    let (mut laptop, mut desktop) = (vault(&dir, "laptop"), vault(&dir, "desktop"));
    let id = shop(&mut laptop);
    assert!(
        laptop
            .set_part_folder(&id, "api", Some(&at("~/code/shop", "apps/api")))
            .unwrap()
    );
    // The same again changes nothing.
    assert!(
        !laptop
            .set_part_folder(&id, "API", Some(&at("~/code/shop", "apps\\api")))
            .unwrap()
    );
    settle(&mut laptop, &mut desktop);
    assert_eq!(
        set(&desktop, &id),
        [("api".to_owned(), "~/code/shop/apps/api".to_owned())]
    );

    // Each sets another before they sync: the later one, on both.
    desktop
        .set_part_folder(&id, "api", Some(&at("~/code/shop", "services/api")))
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    laptop
        .set_part_folder(&id, "api", Some(&at("~/code/shop", "api")))
        .unwrap();
    settle(&mut laptop, &mut desktop);
    for device in [&laptop, &desktop] {
        assert_eq!(
            set(device, &id),
            [("api".to_owned(), "~/code/shop/api".to_owned())]
        );
    }

    // A third device that gets the two records in either order agrees.
    let records = [desktop.project_records(), laptop.project_records()];
    for reverse in [false, true] {
        let mut phone = vault(&dir, &format!("phone-{reverse}"));
        let mut order = records.clone();
        if reverse {
            order.reverse();
        }
        for records in order {
            phone.merge_projects(&records).unwrap();
        }
        assert_eq!(set(&phone, &id), set(&laptop, &id), "{reverse}");
        assert_eq!(phone.project_records(), laptop.project_records());
    }
}

#[test]
fn automatic_takes_the_folder_out_and_a_set_made_meanwhile_stays() {
    let dir = tempfile::tempdir().unwrap();
    let (mut laptop, mut desktop) = (vault(&dir, "laptop"), vault(&dir, "desktop"));
    let id = shop(&mut laptop);
    laptop
        .set_part_folder(&id, "", Some(&at("~/code/shop", "app")))
        .unwrap();
    assert!(laptop.set_part_folder(&id, "", None).unwrap());
    assert!(!laptop.set_part_folder(&id, "", None).unwrap());
    assert_eq!(set(&laptop, &id), NONE);

    laptop
        .set_part_folder(&id, "", Some(&at("~/code/shop", "app")))
        .unwrap();
    settle(&mut laptop, &mut desktop);
    // One goes back to automatic while the other sets a folder, earlier.
    desktop
        .set_part_folder(&id, "", Some(&at("~/code/shop", "web")))
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    laptop.set_part_folder(&id, "", None).unwrap();
    settle(&mut laptop, &mut desktop);
    for device in [&laptop, &desktop] {
        assert_eq!(
            set(device, &id),
            [(String::new(), "~/code/shop/web".to_owned())]
        );
    }
}

#[test]
fn a_part_folder_counts_while_the_project_holds_its_folder() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "laptop");
    let id = shop(&mut vault);
    // Only in one of the project's folders.
    assert!(
        vault
            .set_part_folder(&id, "api", Some(&at("~/code/blog", "api")))
            .is_err()
    );
    vault
        .set_part_folder(&id, "api", Some(&at("~/code/shop", "api")))
        .unwrap();
    vault
        .set_project_member(&id, &folder("~/code/shop"), false)
        .unwrap();
    assert_eq!(set(&vault, &id), NONE);
    // Put back (an Undo): it counts again.
    vault
        .set_project_member(&id, &folder("~/code/shop"), true)
        .unwrap();
    assert_eq!(set(&vault, &id).len(), 1);
}

#[test]
fn paths_and_keys_are_checked() {
    assert_eq!(check_path("").unwrap(), "");
    assert_eq!(check_path("apps\\web").unwrap(), "apps/web");
    for bad in [
        "..",
        "apps/../..",
        "/apps",
        "apps/",
        "./apps",
        "apps/.git",
        " apps",
        "C:/x",
        "a\nb",
    ] {
        assert!(check_path(bad).is_err(), "{bad:?}");
    }
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "laptop");
    let id = shop(&mut vault);
    for bad in ["..", "a/../b"] {
        assert!(
            vault
                .set_part_folder(&id, "api", Some(&at("~/code/shop", bad)))
                .is_err()
        );
    }
    assert!(
        vault
            .set_part_folder(&id, "a/b", Some(&at("~/code/shop", "")))
            .is_err()
    );

    // A record's keys: the form `key` writes, or dropped.
    assert!(parse_key(r#"partdir:["api","~/code/shop","apps/api"]"#).is_some());
    for bad in [
        r#"partdir:["api","~/code/shop","../x"]"#,
        r#"partdir:[ "api","~/code/shop","x"]"#,
        r#"partdir:["api","~/code/shop","apps\\api"]"#,
        r#"partdir:["a/b","~/code/shop","x"]"#,
        r#"partdir:["api","~/code/shop"]"#,
        r#"partdir:{"part":"api"}"#,
    ] {
        assert!(parse_key(bad).is_none(), "{bad}");
    }
    let record = serde_json::json!({
        "name": {"v": "Blog", "t": 1},
        "color": {"v": "blue", "t": 1},
        "members": {
            "folder:~/code/blog": {"a": 1},
            r#"partdir:["api","~/code/blog","api"]"#: {"a": 2},
            r#"partdir:["web","~/code/blog","../web"]"#: {"a": 2},
        },
    });
    let blog = "00000000-0000-4000-8000-0000000000b1";
    vault
        .merge_projects(&[ProjectRecord {
            id: blog.into(),
            record: record.to_string(),
        }])
        .unwrap();
    assert_eq!(
        set(&vault, blog),
        [("api".to_owned(), "~/code/blog/api".to_owned())]
    );
    assert!(!vault.project_records()[0].record.contains("../web"));
}

#[test]
fn a_renamed_part_takes_its_folder_along() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "laptop");
    let id = shop(&mut vault);
    let local = env(&mut vault, &id, "", "local");
    vault
        .set_part_folder(&id, "", Some(&at("~/code/shop", "web")))
        .unwrap();
    // The project gets a second part: the first one is named in the same change.
    vault
        .name_first_part(Some(&PartRename {
            ids: vec![local.clone()],
            part: "web".into(),
        }))
        .unwrap();
    env(&mut vault, &id, "api", "local");
    assert_eq!(
        set(&vault, &id),
        [("web".to_owned(), "~/code/shop/web".to_owned())]
    );
}

#[test]
fn a_part_renamed_into_another_keeps_that_ones_folder() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "laptop");
    let id = shop(&mut vault);
    env(&mut vault, &id, "api", "local");
    let docs = env(&mut vault, &id, "docs", "preview");
    vault
        .set_part_folder(&id, "api", Some(&at("~/code/shop", "api")))
        .unwrap();
    vault
        .set_part_folder(&id, "docs", Some(&at("~/code/shop", "docs")))
        .unwrap();
    vault
        .set_environment_part(std::slice::from_ref(&docs), "API")
        .unwrap();
    assert_eq!(
        set(&vault, &id),
        [("api".to_owned(), "~/code/shop/api".to_owned())]
    );

    // Renamed but some of its stages stay: the folder stays with them.
    let web = env(&mut vault, &id, "web", "local");
    env(&mut vault, &id, "web", "prod");
    vault
        .set_part_folder(&id, "web", Some(&at("~/code/shop", "web")))
        .unwrap();
    vault.set_environment_part(&[web], "site").unwrap();
    assert!(
        set(&vault, &id)
            .iter()
            .any(|(part, path)| part == "web" && path == "~/code/shop/web")
    );
}

fn summary(id: &str, part: &str, name: &str, kind: EnvKind) -> EnvSummary {
    EnvSummary {
        id: id.into(),
        project: Some("p".into()),
        part: part.into(),
        group: part.into(),
        name: name.into(),
        kind,
        variable_count: 0,
        secret_count: 0,
        in_trash: false,
        modified: None,
    }
}

fn project(folders: &[&str], parts: &[(&str, &str, &str)]) -> Project {
    Project {
        id: "p".into(),
        name: "Shop".into(),
        color: ProjectColor::Blue,
        folders: folders.iter().map(|f| (*f).to_owned()).collect(),
        hosts: Vec::new(),
        keys: Vec::new(),
        environments: Vec::new(),
        logins: Vec::new(),
        hosts_file: Vec::new(),
        parts: parts
            .iter()
            .map(|(part, folder, path)| PartFolder {
                part: (*part).into(),
                folder: (*folder).into(),
                path: (*path).into(),
            })
            .collect(),
        modified: String::new(),
    }
}

fn file(folder: &str, path: &str) -> EnvFile {
    EnvFile {
        folder: folder.into(),
        path: path.into(),
    }
}

fn spots(places: &[FolderPlace]) -> Vec<(String, Vec<String>, Vec<String>)> {
    places
        .iter()
        .map(|place| {
            (
                format!("{}/{}", place.folder, place.path),
                place.parts.iter().map(|p| p.part.clone()).collect(),
                place.terminal.clone(),
            )
        })
        .collect()
}

#[test]
fn a_part_works_where_it_was_set_else_by_its_local_file_else_in_the_first_folder() {
    use EnvKind::{Local, Remote};
    let envs = [
        summary("api-local", "api", "local", Local),
        summary("api-prod", "api", "prod", Remote),
        summary("web-test", "web", "test", Local),
        summary("web-local", "web", "local", Local),
        summary("web-prod", "web", "prod", Remote),
        summary("docs-prod", "docs", "prod", Remote),
        summary("ops-local", "ops", "local", Local),
    ];
    let files = BTreeMap::from([
        // The stage named `local` comes first, whatever the order.
        (
            "web-test".to_owned(),
            vec![file("~/shop", "apps/web/test/.env.test")],
        ),
        (
            "web-local".to_owned(),
            vec![file("~/shop", "apps/web/.env.local")],
        ),
        // A remote one's file is suggested, not used.
        ("docs-prod".to_owned(), vec![file("~/shop", "docs/.env")]),
        // Not in a folder the project holds.
        ("ops-local".to_owned(), vec![file("~/elsewhere", ".env")]),
    ]);
    let project = project(
        &["~/shop", "~/shop-infra"],
        &[("API", "~/shop", "services/api"), ("gone", "~/old", "x")],
    );
    let places = places(&project, Some(&envs), &files);
    assert_eq!(
        spots(&places),
        [
            (
                "~/shop/".to_owned(),
                vec!["docs".to_owned(), "ops".to_owned()],
                vec!["ops-local".to_owned()],
            ),
            (
                "~/shop/apps/web".to_owned(),
                vec!["web".to_owned()],
                vec!["web-local".to_owned()],
            ),
            (
                "~/shop/services/api".to_owned(),
                vec!["api".to_owned()],
                vec!["api-local".to_owned()],
            ),
            ("~/shop-infra/".to_owned(), vec![], vec![]),
        ]
    );
    let api = &places[2].parts[0];
    assert_eq!(api.source, PlaceSource::Set);
    assert_eq!(api.environments, ["api-local", "api-prod"]);
    assert_eq!(api.automatic, Some(at("~/shop", "")));
    let web = &places[1].parts[0];
    assert_eq!(web.source, PlaceSource::File);
    assert_eq!(
        web.suggested,
        [at("~/shop", "apps/web"), at("~/shop", "apps/web/test")]
    );
    let docs = &places[0].parts[0];
    assert_eq!(docs.source, PlaceSource::Project);
    assert_eq!(docs.local, None);
    assert_eq!(docs.suggested, [at("~/shop", "docs")]);

    // Run in terminal: its part's folder, what it would be without, then
    // the project's folders.
    assert_eq!(
        env_folders(&places, "api-prod"),
        [
            at("~/shop", "services/api"),
            at("~/shop", ""),
            at("~/shop-infra", "")
        ]
    );
    assert_eq!(
        env_folders(&places, "docs-prod"),
        [at("~/shop", ""), at("~/shop-infra", "")]
    );
    assert_eq!(
        env_folders(&places, "elsewhere"),
        Vec::<ProjectFolder>::new()
    );
}

#[test]
fn a_terminal_in_a_folder_with_several_parts_asks() {
    use EnvKind::{Local, Remote};
    let envs = [
        summary("api-local", "api", "local", Local),
        summary("web-local", "web", "local", Local),
        summary("web-prod", "web", "prod", Remote),
        summary("ops-prod", "ops", "prod", Remote),
    ];
    let files = BTreeMap::new();
    // Both below the root: the root asks.
    let below = project(
        &["~/shop"],
        &[("api", "~/shop", "api"), ("web", "~/shop", "web/app")],
    );
    let places_below = places(&below, Some(&envs), &files);
    assert_eq!(places_below[0].terminal, ["api-local", "web-local"]);
    assert_eq!(places_below[1].terminal, ["api-local"]);
    // One at the root, with a local stage: that one.
    let root = project(&["~/shop"], &[("api", "~/shop", "api")]);
    let places_root = places(&root, Some(&envs), &files);
    assert_eq!(places_root[0].terminal, ["web-local"]);
    // Only remote ones at the root: those below.
    let remote = project(
        &["~/shop"],
        &[("api", "~/shop", "api"), ("web", "~/shop", "web")],
    );
    assert_eq!(
        places(&remote, Some(&envs), &files)[0].terminal,
        ["api-local", "web-local"]
    );
    // Without folders, nowhere.
    assert_eq!(
        places(&project(&[], &[]), Some(&envs), &files),
        Vec::<FolderPlace>::new()
    );
}

#[test]
fn while_locked_the_folders_set_are_known() {
    let project = project(&["~/shop"], &[("api", "~/shop", "api")]);
    let places = places(&project, None, &BTreeMap::new());
    assert_eq!(
        spots(&places),
        [
            ("~/shop/".to_owned(), vec![], vec![]),
            ("~/shop/api".to_owned(), vec!["api".to_owned()], vec![]),
        ]
    );
}

#[test]
fn the_vault_finds_where_its_parts_work() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "laptop");
    let id = shop(&mut vault);
    let api = env(&mut vault, &id, "api", "local");
    let web = env(&mut vault, &id, "web", "local");
    vault
        .set_part_folder(&id, "api", Some(&at("~/code/shop", "api")))
        .unwrap();
    let places = vault.project_places(&id).unwrap();
    assert_eq!(places[0].parts[0].environments, std::slice::from_ref(&web));
    assert_eq!(places[0].terminal, [web]);
    assert_eq!(places[1].path, "api");
    assert_eq!(places[1].terminal, [api]);
}

#[test]
fn a_folder_picked_again_is_the_one_set_last() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b) = (vault(&dir, "a"), vault(&dir, "b"));
    let id = shop(&mut a);
    settle(&mut a, &mut b);
    let pause = || std::thread::sleep(std::time::Duration::from_millis(5));
    let pick = |device: &mut Vault, path: &str| {
        device
            .set_part_folder(&id, "api", Some(&at("~/code/shop", path)))
            .unwrap()
    };
    // Each sets one before they sync: both are in the records, `b` wins.
    pick(&mut a, "a");
    pause();
    pick(&mut b, "b");
    settle(&mut a, &mut b);
    pause();
    // B sets `c`; A, not having heard of it, picks `a` again, later.
    pick(&mut b, "c");
    pause();
    assert!(pick(&mut a, "a"));
    settle(&mut a, &mut b);
    for device in [&a, &b] {
        assert_eq!(
            set(device, &id),
            [("api".to_owned(), "~/code/shop/a".to_owned())]
        );
    }
}

#[test]
fn an_edited_stage_takes_its_parts_folder_to_its_new_part() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "laptop");
    let id = shop(&mut vault);
    let local = env(&mut vault, &id, "api", "local");
    vault
        .set_part_folder(&id, "api", Some(&at("~/code/shop", "apps/api")))
        .unwrap();
    vault
        .update_environment(
            &local,
            &EnvInput {
                project: Some(id.clone()),
                part: "backend".into(),
                name: "local".into(),
                notes: String::new(),
            },
        )
        .unwrap();
    assert_eq!(
        set(&vault, &id),
        [("backend".to_owned(), "~/code/shop/apps/api".to_owned())]
    );
}

#[test]
fn a_stage_moved_to_another_project_leaves_its_parts_folder_behind() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = vault(&dir, "laptop");
    let shop = shop(&mut vault);
    let blog = vault
        .add_project(&ProjectInput {
            name: "Blog".into(),
            color: ProjectColor::Green,
        })
        .unwrap();
    let api = env(&mut vault, &shop, "api", "local");
    env(&mut vault, &shop, "web", "local");
    vault
        .set_part_folder(&shop, "api", Some(&at("~/code/shop", "apps/api")))
        .unwrap();
    // To Blog's `web`: Shop's own `web` keeps working where it did.
    vault
        .update_environment(
            &api,
            &EnvInput {
                project: Some(blog),
                part: "web".into(),
                name: "local".into(),
                notes: String::new(),
            },
        )
        .unwrap();
    assert!(set(&vault, &shop).iter().all(|(part, _)| part != "web"));
}
