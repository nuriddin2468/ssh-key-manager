use std::path::{Path, PathBuf};

use super::*;

/// The root of absolute paths on this system.
fn root() -> PathBuf {
    PathBuf::from(if cfg!(windows) { "C:\\" } else { "/" })
}

/// Entry ids, as the vault's logins have.
const L1: &str = "6f1c2d3e-0000-4000-8000-0000000000a1";
const L2: &str = "6f1c2d3e-0000-4000-8000-0000000000a2";
/// Environments' entry ids.
const E1: &str = "6f1c2d3e-0000-4000-8000-0000000000e1";
const E2: &str = "6f1c2d3e-0000-4000-8000-0000000000e2";

fn host(alias: &str, host_name: Option<&str>, jump: Option<&str>) -> HostFacts {
    HostFacts {
        alias: alias.into(),
        host_name: host_name.map(Into::into),
        proxy_jump: jump.map(Into::into),
        keys: Vec::new(),
    }
}

fn names(suggestions: &[ProjectSuggestion]) -> Vec<&str> {
    suggestions.iter().map(|s| s.name.as_str()).collect()
}

fn find<'a>(suggestions: &'a [ProjectSuggestion], name: &str) -> &'a ProjectSuggestion {
    suggestions
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("no suggestion {name}: {suggestions:?}"))
}

fn project(name: &str, hosts: &[&str]) -> Project {
    Project {
        id: format!("id-{name}"),
        name: name.into(),
        color: ProjectColor::Violet,
        folders: Vec::new(),
        hosts: hosts.iter().map(|h| (*h).to_owned()).collect(),
        keys: Vec::new(),
        environments: Vec::new(),
        logins: Vec::new(),
        hosts_file: Vec::new(),
        modified: "2026-11-10T10:00:00Z".into(),
    }
}

#[test]
fn names_read_alike_without_case_and_punctuation() {
    assert_eq!(key("Shop API"), "shop-api");
    assert_eq!(key(" shop_api "), "shop-api");
    assert_eq!(key("shop--api."), "shop-api");
    assert_eq!(key("Магазин"), "магазин");
    assert_eq!(key("--"), "");
}

#[test]
fn remotes_name_the_host_they_reach() {
    assert_eq!(
        remote_host("git@github.com:acme/shop.git"),
        Some("github.com")
    );
    assert_eq!(
        remote_host("github-work:acme/shop.git"),
        Some("github-work")
    );
    assert_eq!(
        remote_host("ssh://git@git.acme.com:2222/shop.git"),
        Some("git.acme.com")
    );
    assert_eq!(remote_host("ssh://[::1]:22/x"), Some("::1"));
    assert_eq!(remote_host("https://github.com/acme/shop.git"), None);
    assert_eq!(remote_host("/srv/git/shop.git"), None);
    assert_eq!(remote_host("../shop"), None);
    assert_eq!(remote_host("C:\\repos\\shop"), None);
}

#[test]
fn hosts_alike_by_name_place_or_bastion_are_suggested_together() {
    let hosts = [
        host("bastion", Some("bastion.acme.com"), None),
        host("shop-prod", Some("10.0.0.1"), Some("bastion")),
        host("shop-db", Some("10.0.0.2"), Some("me@bastion:2222")),
        host("prod-web", Some("web.blog.io"), None),
        host("prod-cache", Some("cache.blog.io"), None),
        host("lonely", Some("example.org"), None),
        host("gh1", Some("github.com"), None),
        host("gh2", Some("github.com"), None),
    ];
    let suggestions = suggest(
        &Sources {
            hosts: &hosts,
            ..Sources::default()
        },
        &Declined::default(),
    );
    // Behind the bastion and named alike: one project.
    let shop = find(&suggestions, "shop");
    assert_eq!(shop.hosts, ["bastion", "shop-prod", "shop-db"]);
    assert_eq!(shop.reasons.len(), 2);
    // `prod-…` is a stage, not a project; their domain is.
    let blog = find(&suggestions, "blog");
    assert_eq!(blog.hosts, ["prod-web", "prod-cache"]);
    // One host alone, and code hosting everyone uses, aren't projects.
    assert!(!names(&suggestions).contains(&"prod"));
    assert!(!names(&suggestions).contains(&"example"));
    assert!(!names(&suggestions).contains(&"github"));
}

#[test]
fn environments_folders_and_keepass_join_by_name() {
    let mut keyed = host("github-shop", Some("github.com"), None);
    keyed.keys = vec!["SHA256:shopkey".into()];
    let hosts = [keyed, host("github.com", None, None)];
    let home = root().join("home").join("me");
    let blog_folder = root().join("srv").join("blog");
    let repositories = [
        Repository {
            folder: home.join("code").join("shop_api"),
            remotes: vec![
                "github-shop:acme/shop-api.git".into(),
                "git@github.com:me/fork.git".into(),
            ],
        },
        Repository {
            folder: blog_folder.clone(),
            remotes: Vec::new(),
        },
    ];
    let logins = [
        LoginFacts {
            id: L1.into(),
            group: Some("Shop API/Admin".into()),
            tags: Vec::new(),
        },
        LoginFacts {
            id: L2.into(),
            group: Some("General".into()),
            tags: vec!["Blog".into(), " ".into()],
        },
    ];
    // Personal's environments with a part: from before projects, their group.
    let envs = [EnvFacts {
        id: E1.into(),
        part: "shop-api".into(),
    }];
    let suggestions = suggest(
        &Sources {
            hosts: &hosts,
            environments: &envs,
            logins: &logins,
            repositories: &repositories,
            projects: &[],
            home: Some(&home),
            hosts_file: &[],
        },
        &Declined::default(),
    );
    assert_eq!(names(&suggestions), ["shop-api", "blog"]);
    let shop = &suggestions[0];
    assert_eq!(shop.environments, [E1]);
    assert_eq!(shop.folders, ["~/code/shop_api"]);
    // The remote's own alias and its key; github.com is everyone's.
    assert_eq!(shop.hosts, ["github-shop"]);
    assert_eq!(shop.keys, ["SHA256:shopkey"]);
    assert_eq!(shop.logins, [L1]);
    assert_eq!(shop.reasons.len(), 3);
    let blog = &suggestions[1];
    assert_eq!(blog.folders, [blog_folder.to_str().unwrap()]);
    assert_eq!(blog.logins, [L2]);
    // KeePass's starter groups say nothing.
    assert!(!names(&suggestions).contains(&"General"));
    assert_ne!(shop.color, blog.color);
}

#[test]
fn what_projects_hold_and_what_was_dismissed_isnt_suggested_again() {
    let hosts = [
        host("shop-prod", None, None),
        host("shop-db", None, None),
        host("shop-web", None, None),
        host("blog-a", None, None),
        host("blog-b", None, None),
    ];
    let projects = [project("Shop", &["shop-prod"])];
    let dismissed = Declined {
        keys: ["blog".to_owned()].into(),
        ..Declined::default()
    };
    let suggestions = suggest(
        &Sources {
            hosts: &hosts,
            projects: &projects,
            ..Sources::default()
        },
        &dismissed,
    );
    assert_eq!(names(&suggestions), ["Shop"]);
    let shop = &suggestions[0];
    assert_eq!(shop.existing.as_deref(), Some("id-Shop"));
    assert_eq!(shop.color, ProjectColor::Violet);
    assert_eq!(shop.hosts, ["shop-db", "shop-web"]);

    // Once everything is in the project, there's nothing to suggest.
    let projects = [project("Shop", &["shop-prod", "shop-db", "shop-web"])];
    let suggestions = suggest(
        &Sources {
            hosts: &hosts,
            projects: &projects,
            ..Sources::default()
        },
        &dismissed,
    );
    assert_eq!(suggestions, []);
}

#[test]
fn members_left_out_of_an_accepted_suggestion_arent_offered_again() {
    let hosts = [
        host("shop-prod", None, None),
        host("shop-db", None, None),
        host("shop-web", None, None),
    ];
    let sources = Sources {
        hosts: &hosts,
        ..Sources::default()
    };
    let offered = suggest(&sources, &Declined::default());
    let shop = &offered[0];
    assert!(shop.offers(&ProjectMember::Host {
        alias: "shop-db".into()
    }));
    let kept = [ProjectMember::Host {
        alias: "shop-prod".into(),
    }];
    let mut declined = Declined::default();
    declined.left_out(shop, &kept);
    // The project now holds what was kept; the rest was turned down.
    let projects = [project("shop", &["shop-prod"])];
    let again = suggest(
        &Sources {
            projects: &projects,
            ..sources
        },
        &declined,
    );
    assert_eq!(again, []);
}

#[test]
fn working_trees_are_found_in_code_folders() {
    let (_dir, root) = real_tempdir();
    let code = root.join("code");
    let make = |path: &Path, config: Option<&str>| {
        std::fs::create_dir_all(path.join(".git")).unwrap();
        if let Some(config) = config {
            std::fs::write(path.join(".git").join("config"), config).unwrap();
        }
    };
    make(
        &code.join("shop"),
        Some(
            "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = git@github-shop:acme/shop.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[remote \"up\"]\n\turl = \"https://github.com/acme/shop.git\"\n[branch \"main\"]\n\turl = not-a-remote\n",
        ),
    );
    // A working tree inside one isn't searched for.
    make(&code.join("shop").join("vendor-lib"), None);
    make(&code.join("clients").join("acme").join("site"), None);
    make(&code.join("node_modules").join("pkg"), None);
    make(&code.join(".hidden").join("repo"), None);
    make(&code.join("a").join("b").join("c").join("too-deep"), None);
    // A worktree's `.git` is a file.
    std::fs::create_dir_all(code.join("wt")).unwrap();
    std::fs::write(code.join("wt").join(".git"), "gitdir: /elsewhere").unwrap();

    let found = find_repositories(&[code.clone(), root.join("missing")]);
    let folders: Vec<&Path> = found.iter().map(|r| r.folder.as_path()).collect();
    assert_eq!(
        folders,
        [
            code.join("shop").as_path(),
            code.join("wt").as_path(),
            code.join("clients").join("acme").join("site").as_path(),
        ]
    );
    assert_eq!(
        found[0].remotes,
        [
            "git@github-shop:acme/shop.git",
            "https://github.com/acme/shop.git"
        ]
    );
    assert_eq!(found[1].remotes, Vec::<String>::new());
}

/// A temporary folder by its real path (`/var` is a link on macOS).
fn real_tempdir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let real = canonical(dir.path()).unwrap();
    (dir, real)
}

#[test]
fn a_code_folder_is_searched_once_whatever_its_case_or_links() {
    let (_dir, root) = real_tempdir();
    std::fs::create_dir_all(root.join("Code").join("shop").join(".git")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(root.join("Code"), root.join("work")).unwrap();
    // `code` and `Code` are one folder where the disk ignores case; `work`
    // is a link to it where links can be made.
    let roots: Vec<PathBuf> = ["code", "Code", "work"]
        .iter()
        .map(|folder| root.join(folder))
        .filter(|path| path.is_dir())
        .collect();
    let found = find_repositories(&roots);
    let texts: Vec<String> = found
        .iter()
        .map(|r| folder_text(&r.folder, Some(&root)).unwrap())
        .collect();
    assert_eq!(texts, ["~/Code/shop"]);
}

#[cfg(unix)]
#[test]
fn a_git_config_that_isnt_a_regular_file_is_not_read() {
    let (_dir, root) = real_tempdir();
    let fifo = root.join("code").join("trap").join(".git");
    std::fs::create_dir_all(&fifo).unwrap();
    let made = std::process::Command::new("mkfifo")
        .arg(fifo.join("config"))
        .status()
        .unwrap();
    assert!(made.success());
    let linked = root.join("code").join("zero").join(".git");
    std::fs::create_dir_all(&linked).unwrap();
    std::os::unix::fs::symlink("/dev/zero", linked.join("config")).unwrap();
    let roots = vec![root.join("code")];
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(find_repositories(&roots));
    });
    let found = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("the search still runs after 5 s");
    assert_eq!(found.len(), 2);
    assert!(found.iter().all(|r| r.remotes.is_empty()));
}

#[test]
fn members_a_project_cant_take_arent_suggested() {
    let hosts = [
        host("shop-prod", None, None),
        host("shop-\"db\"", None, None),
        host("shop-web", None, None),
    ];
    let envs = [
        EnvFacts {
            id: "not-an-id".into(),
            part: "broken".into(),
        },
        EnvFacts {
            id: E2.into(),
            part: "fine".into(),
        },
    ];
    let suggestions = suggest(
        &Sources {
            hosts: &hosts,
            environments: &envs,
            ..Sources::default()
        },
        &Declined::default(),
    );
    assert_eq!(names(&suggestions), ["shop", "fine"]);
    assert_eq!(suggestions[0].hosts, ["shop-prod", "shop-web"]);
}

#[test]
fn logins_left_out_of_a_tag_suggestion_stay_out() {
    let logins = [
        LoginFacts {
            id: "l1".into(),
            group: None,
            tags: vec!["work".into()],
        },
        LoginFacts {
            id: "l2".into(),
            group: None,
            tags: vec!["work".into()],
        },
    ];
    let sources = Sources {
        logins: &logins,
        ..Sources::default()
    };
    // The ids here aren't entry ids, which a project would refuse: this
    // checks what is offered, before any project.
    let offered = suggest(&sources, &Declined::default());
    assert_eq!(offered, []);

    let logins = [
        LoginFacts {
            id: "6f1c2d3e-0000-4000-8000-000000000001".into(),
            group: None,
            tags: vec!["work".into()],
        },
        LoginFacts {
            id: "6f1c2d3e-0000-4000-8000-000000000002".into(),
            group: None,
            tags: vec!["work".into()],
        },
    ];
    let sources = Sources {
        logins: &logins,
        ..Sources::default()
    };
    let offered = suggest(&sources, &Declined::default());
    let work = &offered[0];
    assert_eq!(work.logins.len(), 2);
    let kept = [ProjectMember::Login {
        id: logins[0].id.clone(),
    }];
    let mut declined = Declined::default();
    declined.left_out(work, &kept);
    let mut project = project("work", &[]);
    project.logins = vec![logins[0].id.clone()];
    let projects = [project];
    let again = suggest(
        &Sources {
            projects: &projects,
            ..sources
        },
        &declined,
    );
    assert_eq!(again, []);
}

#[test]
fn dismissals_are_kept_up_to_a_limit_oldest_out_first() {
    let mut declined = Declined::default();
    assert!(declined.dismiss("a"));
    assert!(!declined.dismiss("a"));
    for n in 0..Declined::MAX_KEYS {
        declined.dismiss(&format!("k{n}"));
    }
    assert_eq!(declined.keys.len(), Declined::MAX_KEYS);
    assert!(!declined.keys.contains(&"a".to_owned()));
    assert!(
        declined
            .keys
            .contains(&format!("k{}", Declined::MAX_KEYS - 1))
    );
}

#[test]
fn a_project_tag_no_project_has_is_suggested_by_its_name() {
    let dir = tempfile::tempdir().unwrap();
    let paths = crate::vault::VaultPaths::new(dir.path().join("vault.kdbx"));
    let (mut vault, _) =
        crate::vault::Vault::create(&paths, &secrecy::SecretString::from("master")).unwrap();
    let mut entry = |title: &str, tags: &[&str]| {
        let id = vault
            .add_entry(&crate::vault::EntryInput {
                title: title.into(),
                ..crate::vault::EntryInput::default()
            })
            .unwrap();
        let uuid = uuid::Uuid::parse_str(&id).unwrap();
        vault.db.entry_mut(uuid.into()).unwrap().tags =
            tags.iter().map(|t| (*t).to_owned()).collect();
        id
    };
    let thesis = entry("Thesis", &["project/thesis"]);
    let shop = entry("Shop", &["project/Shop"]);
    drop(entry);
    let id = vault
        .add_project(&crate::vault::projects::ProjectInput {
            name: "Shop".into(),
            color: ProjectColor::Blue,
        })
        .unwrap();
    assert_eq!(
        vault.project(&id).unwrap().logins,
        std::slice::from_ref(&shop)
    );
    let logins = vault.suggestion_logins();
    let tags_of = |id: &str| logins.iter().find(|l| l.id == id).unwrap().tags.clone();
    assert_eq!(tags_of(&thesis), ["thesis"]);
    assert_eq!(tags_of(&shop), Vec::<String>::new());
}

#[test]
fn logins_left_out_when_accepting_stay_out_though_tagged() {
    let dir = tempfile::tempdir().unwrap();
    let paths = crate::vault::VaultPaths::new(dir.path().join("vault.kdbx"));
    let (mut vault, _) =
        crate::vault::Vault::create(&paths, &secrecy::SecretString::from("master")).unwrap();
    let mut tagged = |title: &str| {
        let id = vault
            .add_entry(&crate::vault::EntryInput {
                title: title.into(),
                ..crate::vault::EntryInput::default()
            })
            .unwrap();
        let uuid = uuid::Uuid::parse_str(&id).unwrap();
        vault.db.entry_mut(uuid.into()).unwrap().tags = vec!["project/thesis".into()];
        id
    };
    let (kept, unchecked) = (tagged("Kept"), tagged("Unchecked"));
    drop(tagged);
    let logins = vault.suggestion_logins();
    let offered = suggest(
        &Sources {
            logins: &logins,
            ..Sources::default()
        },
        &Declined::default(),
    );
    let thesis = offered.iter().find(|s| s.name == "thesis").unwrap();
    assert_eq!(thesis.logins.len(), 2);
    let keep = [ProjectMember::Login { id: kept.clone() }];
    let input = crate::vault::projects::ProjectInput {
        name: thesis.name.clone(),
        color: thesis.color,
    };
    let id = vault.accept_suggestion(thesis, &input, &keep).unwrap();
    assert_eq!(
        vault.project(&id).unwrap().logins,
        std::slice::from_ref(&kept)
    );
    let tags = |vault: &crate::vault::Vault, id: &str| {
        let uuid = uuid::Uuid::parse_str(id).unwrap();
        vault.db.entry(uuid.into()).unwrap().tags.clone()
    };
    assert_eq!(tags(&vault, &unchecked), Vec::<String>::new());
    // Tagged again in KeePassXC, it still stays out.
    let uuid = uuid::Uuid::parse_str(&unchecked).unwrap();
    vault.db.entry_mut(uuid.into()).unwrap().tags = vec!["project/thesis".into()];
    vault
        .update_project(
            &id,
            &crate::vault::projects::ProjectInput {
                name: "thesis".into(),
                color: ProjectColor::Slate,
            },
        )
        .unwrap();
    assert_eq!(
        vault.project(&id).unwrap().logins,
        std::slice::from_ref(&kept)
    );
    // Members it didn't offer are refused before anything changes.
    let other = [ProjectMember::Host {
        alias: "elsewhere".into(),
    }];
    assert!(vault.accept_suggestion(thesis, &input, &other).is_err());
}

#[test]
fn a_login_that_joined_since_the_suggestion_stays_when_left_unticked() {
    let dir = tempfile::tempdir().unwrap();
    let paths = crate::vault::VaultPaths::new(dir.path().join("vault.kdbx"));
    let (mut vault, _) =
        crate::vault::Vault::create(&paths, &secrecy::SecretString::from("master")).unwrap();
    let mut grouped = |title: &str| {
        let id = vault
            .add_entry(&crate::vault::EntryInput {
                title: title.into(),
                ..crate::vault::EntryInput::default()
            })
            .unwrap();
        let uuid = uuid::Uuid::parse_str(&id).unwrap();
        vault.db.entry_mut(uuid.into()).unwrap().tags = vec!["thesis".into()];
        id
    };
    let (first, second) = (grouped("First"), grouped("Second"));
    drop(grouped);
    let input = crate::vault::projects::ProjectInput {
        name: "Thesis".into(),
        color: ProjectColor::Blue,
    };
    let id = vault.add_project(&input).unwrap();
    // The list the user looks at: both logins, to add to "Thesis".
    let logins = vault.suggestion_logins();
    let projects = vault.projects();
    let offered = suggest(
        &Sources {
            logins: &logins,
            projects: &projects,
            ..Sources::default()
        },
        &Declined::default(),
    );
    let stale = offered
        .iter()
        .find(|s| s.existing.as_deref() == Some(&id))
        .unwrap();
    assert_eq!(stale.logins.len(), 2);
    // Meanwhile the second joins (in the app, or by a sync).
    vault
        .set_project_member(&id, &ProjectMember::Login { id: second.clone() }, true)
        .unwrap();
    let keep = [ProjectMember::Login { id: first.clone() }];
    vault.accept_suggestion(stale, &input, &keep).unwrap();
    let mut members = vault.project(&id).unwrap().logins;
    members.sort();
    let mut expected = vec![first, second];
    expected.sort();
    assert_eq!(members, expected);
}

#[test]
fn hosts_file_names_join_the_project_their_hosts_are_in() {
    let hosts = [
        host("shop-prod", Some("api.shop.example.com"), None),
        host("blog", Some("blog.example.org"), None),
        host("gh", Some("github.com"), None),
    ];
    let in_file: Vec<String> = [
        "api.shop.example.com",
        "staging.shop.example.com",
        "shop-prod",
        "blog.example.org",
        "github.com",
        "unrelated.test",
    ]
    .map(String::from)
    .into();
    let projects = [project("Shop", &["shop-prod", "gh"])];
    let suggestions = suggest(
        &Sources {
            hosts: &hosts,
            projects: &projects,
            hosts_file: &in_file,
            ..Sources::default()
        },
        &Declined::default(),
    );
    // The project's hosts by name and by domain; code hosting says nothing.
    let shop = find(&suggestions, "Shop");
    assert_eq!(shop.existing.as_deref(), Some("id-Shop"));
    assert_eq!(
        shop.hosts_file,
        [
            "api.shop.example.com",
            "staging.shop.example.com",
            "shop-prod"
        ]
    );
    assert_eq!(
        shop.reasons,
        [
            SuggestionReason::HostsFile {
                host: "shop-prod".into()
            },
            SuggestionReason::Domain {
                domain: "example.com".into()
            },
        ]
    );
    // One host in a domain doesn't make a new project, with hosts file names or not.
    assert_eq!(names(&suggestions), ["Shop"]);

    // Names a project has already aren't suggested again.
    let mut held = project("Shop", &["shop-prod"]);
    held.hosts_file = in_file[..3].to_vec();
    let suggestions = suggest(
        &Sources {
            hosts: &hosts,
            projects: &[held],
            hosts_file: &in_file,
            ..Sources::default()
        },
        &Declined::default(),
    );
    assert_eq!(suggestions, []);
}

#[test]
fn left_out_members_are_kept_as_record_keys_and_read_from_any_build() {
    let mut declined = Declined::default();
    declined.dismiss("shop");
    declined.members.insert(
        "shop".into(),
        vec!["host:shop-db".into(), "hostsfile:app.test".into()],
    );
    let json = serde_json::to_value(&declined).unwrap();
    assert_eq!(
        json["members"]["shop"],
        serde_json::json!(["host:shop-db", "hostsfile:app.test"])
    );
    // An earlier build wrote members; a later one may add kinds this one
    // doesn't know: they are dropped, never the whole settings.
    let read: Declined = serde_json::from_value(serde_json::json!({
        "keys": ["shop"],
        "members": {
            "shop": [
                { "type": "host", "alias": "shop-db" },
                "hostsfile:app.test",
                { "type": "bucket", "name": "s3://shop" },
                "bucket:s3://shop"
            ]
        }
    }))
    .unwrap();
    assert_eq!(read.keys, ["shop"]);
    assert_eq!(
        read.members["shop"],
        ["host:shop-db", "hostsfile:app.test", "bucket:s3://shop"]
    );
}
