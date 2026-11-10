use std::path::{Path, PathBuf};

use super::*;

/// The root of absolute paths on this system.
fn root() -> PathBuf {
    PathBuf::from(if cfg!(windows) { "C:\\" } else { "/" })
}

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
            id: "l1".into(),
            group: Some("Shop API/Admin".into()),
            tags: Vec::new(),
        },
        LoginFacts {
            id: "l2".into(),
            group: Some("General".into()),
            tags: vec!["Blog".into(), " ".into()],
        },
    ];
    let groups = ["shop-api".to_owned()];
    let suggestions = suggest(
        &Sources {
            hosts: &hosts,
            environment_groups: &groups,
            logins: &logins,
            repositories: &repositories,
            projects: &[],
            home: Some(&home),
        },
        &Declined::default(),
    );
    assert_eq!(names(&suggestions), ["shop-api", "blog"]);
    let shop = &suggestions[0];
    assert_eq!(shop.environments, ["shop-api"]);
    assert_eq!(shop.folders, ["~/code/shop_api"]);
    // The remote's own alias and its key; github.com is everyone's.
    assert_eq!(shop.hosts, ["github-shop"]);
    assert_eq!(shop.keys, ["SHA256:shopkey"]);
    assert_eq!(shop.logins, ["l1"]);
    assert_eq!(shop.reasons.len(), 3);
    let blog = &suggestions[1];
    assert_eq!(blog.folders, [blog_folder.to_str().unwrap()]);
    assert_eq!(blog.logins, ["l2"]);
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
    let dir = tempfile::tempdir().unwrap();
    let code = dir.path().join("code");
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

    let found = find_repositories(&[code.clone(), dir.path().join("missing")]);
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
