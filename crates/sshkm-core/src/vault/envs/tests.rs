use std::path::Path;

use keepass::db::fields;
use keepass::{Database, DatabaseKey};
use secrecy::{ExposeSecret, SecretString};

use super::*;
use crate::vault::{EntryInput, EntrySummary, Vault, VaultPaths};

fn s(text: &str) -> SecretString {
    SecretString::from(text)
}

struct Fixture {
    dir: tempfile::TempDir,
    paths: VaultPaths,
    vault: Vault,
    recovery: SecretString,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("vault.kdbx"));
        let (vault, recovery) = Vault::create(&paths, &s("master")).unwrap();
        Self {
            dir,
            paths,
            vault,
            recovery,
        }
    }

    fn save(&mut self) {
        self.vault.save(&self.dir.path().join("backups")).unwrap();
    }

    fn reopen(&mut self) {
        self.save();
        self.vault = Vault::unlock(&self.paths, &s("master")).unwrap();
    }

    /// The database as KeePassXC would read it.
    fn keepass(&self) -> Database {
        let bytes = std::fs::read(&self.paths.database).unwrap();
        Database::parse(
            &bytes,
            DatabaseKey::new().with_password(self.recovery.expose_secret()),
        )
        .unwrap()
    }
}

fn env(project: &str, name: &str) -> EnvInput {
    EnvInput {
        project: None,
        part: project.into(),
        name: name.into(),
        notes: String::new(),
    }
}

fn input(name: &str, value: Option<&str>, secret: bool, note: &str) -> EnvVarInput {
    EnvVarInput {
        name: name.into(),
        value: value.map(s),
        secret,
        note: note.into(),
    }
}

fn var(name: &str, value: &str, secret: bool) -> EnvVariable {
    EnvVariable {
        name: name.into(),
        value: s(value),
        secret,
        note: String::new(),
    }
}

fn names(detail: &EnvDetail) -> Vec<&str> {
    detail.variables.iter().map(|v| v.name.as_str()).collect()
}

fn value(vault: &Vault, id: &str, name: &str) -> String {
    vault
        .env_value(id, name)
        .unwrap()
        .expose_secret()
        .to_owned()
}

#[test]
fn environments_round_trip_through_the_kdbx_file() {
    let mut fx = Fixture::new();
    let id = fx
        .vault
        .add_environment(&EnvInput {
            project: None,
            part: " shop-api ".into(),
            name: "prod".into(),
            notes: "Hetzner, eu-central".into(),
        })
        .unwrap();
    let vault = &mut fx.vault;
    vault
        .set_env_variable(&id, None, &input("PORT", Some("8080"), false, "HTTP"))
        .unwrap();
    vault
        .set_env_variable(
            &id,
            None,
            &input("DATABASE_URL", Some("postgres://app:pw@db/app"), true, ""),
        )
        .unwrap();
    vault
        .set_env_variable(
            &id,
            None,
            &input("URL", Some("https://shop.example"), false, ""),
        )
        .unwrap();
    vault
        .set_env_variable(&id, None, &input("CERT", Some("line 1\nline 2"), true, ""))
        .unwrap();
    fx.reopen();

    let detail = fx.vault.environment(&id).unwrap();
    assert_eq!(detail.summary.part, "shop-api");
    assert_eq!(detail.summary.project, None);
    assert_eq!(detail.summary.name, "prod");
    assert_eq!(detail.notes, "Hetzner, eu-central");
    assert_eq!(
        (detail.summary.variable_count, detail.summary.secret_count),
        (4, 2)
    );
    assert_eq!(names(&detail), ["PORT", "DATABASE_URL", "URL", "CERT"]);
    assert_eq!(detail.variables[0].note, "HTTP");
    assert!(detail.variables[1].secret && !detail.variables[0].secret);
    assert_eq!(value(&fx.vault, &id, "URL"), "https://shop.example");
    assert_eq!(value(&fx.vault, &id, "CERT"), "line 1\nline 2");
    // The details carry no values.
    let json = serde_json::to_string(&detail).unwrap();
    assert!(!json.contains("postgres://") && !json.contains("8080"));

    // KeePassXC sees an entry in Environments/shop-api with the variables
    // as attributes, the secret ones protected.
    let db = fx.keepass();
    let root = db.root();
    let group = root
        .group_by_path(&[GROUP, "shop-api"])
        .expect("the project's group");
    let entry = group
        .entry_by_name("prod")
        .expect("the environment's entry");
    assert_eq!(entry.get("PORT"), Some("8080"));
    assert!(entry.fields["DATABASE_URL"].is_protected());
    assert!(!entry.fields["PORT"].is_protected());
    // `URL` is KeePass's own field: the variable goes as `env.URL`.
    assert_eq!(entry.get("env.URL"), Some("https://shop.example"));
    assert_eq!(entry.get(fields::URL), None);
    assert_eq!(entry.get(fields::NOTES), Some("Hetzner, eu-central"));

    // It is not a password.
    assert_eq!(fx.vault.entries(), Vec::<EntrySummary>::new());
}

#[test]
fn attributes_added_in_keepassxc_show_as_variables() {
    let mut fx = Fixture::new();
    let id = fx.vault.add_environment(&env("app", "dev")).unwrap();
    fx.vault
        .set_env_variable(&id, None, &input("B", Some("2"), false, ""))
        .unwrap();
    fx.save();
    // Another app adds attributes: one a variable, one not.
    let mut db = fx.keepass();
    let entry_id = keepass::db::EntryId::from(uuid::Uuid::parse_str(&id).unwrap());
    let mut entry = db.entry_mut(entry_id).unwrap();
    entry.set_protected("A_TOKEN", "t0k");
    entry.set_unprotected("not a variable", "x");
    let mut bytes = Vec::new();
    db.save(
        &mut bytes,
        DatabaseKey::new().with_password(fx.recovery.expose_secret()),
    )
    .unwrap();
    std::fs::write(&fx.paths.database, bytes).unwrap();
    fx.vault = Vault::unlock(&fx.paths, &s("master")).unwrap();

    let detail = fx.vault.environment(&id).unwrap();
    assert_eq!(names(&detail), ["B", "A_TOKEN"]);
    assert!(detail.variables[1].secret);
    assert_eq!(value(&fx.vault, &id, "A_TOKEN"), "t0k");
}

#[test]
fn variables_are_added_changed_renamed_and_removed() {
    let mut fx = Fixture::new();
    let vault = &mut fx.vault;
    let id = vault.add_environment(&env("app", "dev")).unwrap();
    vault
        .set_env_variable(&id, None, &input("API_KEY", Some("k1"), true, "old"))
        .unwrap();
    vault
        .set_env_variable(&id, None, &input("EMPTY", None, false, ""))
        .unwrap();
    // Renaming keeps the value when none is given, and the position.
    vault
        .set_env_variable(
            &id,
            Some("API_KEY"),
            &input("STRIPE_KEY", None, true, "live"),
        )
        .unwrap();
    let detail = vault.environment(&id).unwrap();
    assert_eq!(names(&detail), ["STRIPE_KEY", "EMPTY"]);
    assert_eq!(detail.variables[0].note, "live");
    assert!(detail.variables[1].empty);
    assert_eq!(value(vault, &id, "STRIPE_KEY"), "k1");
    // A secret made plain stays as it was otherwise.
    vault
        .set_env_variable(
            &id,
            Some("STRIPE_KEY"),
            &input("STRIPE_KEY", None, false, "live"),
        )
        .unwrap();
    assert!(!vault.environment(&id).unwrap().variables[0].secret);

    // Names must be variable names, once each.
    for bad in ["1X", "A-B", "", "A B", "π"] {
        assert!(
            vault
                .set_env_variable(&id, None, &input(bad, Some("x"), false, ""))
                .is_err(),
            "{bad:?}"
        );
    }
    assert!(matches!(
        vault.set_env_variable(&id, None, &input("EMPTY", Some("x"), false, "")),
        Err(Error::AlreadyExists(_))
    ));
    assert!(matches!(
        vault.set_env_variable(&id, Some("STRIPE_KEY"), &input("EMPTY", None, false, "")),
        Err(Error::AlreadyExists(_))
    ));
    assert!(
        vault
            .set_env_variable(&id, None, &input("NOTE", Some("x"), false, "two\nlines"))
            .is_err()
    );

    vault.remove_env_variable(&id, "EMPTY").unwrap();
    assert!(matches!(
        vault.remove_env_variable(&id, "EMPTY"),
        Err(Error::NotFound(_))
    ));
    assert_eq!(names(&vault.environment(&id).unwrap()), ["STRIPE_KEY"]);
}

#[test]
fn names_are_checked_and_free() {
    let mut fx = Fixture::new();
    let vault = &mut fx.vault;
    let dev = vault.add_environment(&env("app", "dev")).unwrap();
    assert!(matches!(
        vault.add_environment(&env("app", "DEV")),
        Err(Error::AlreadyExists(_))
    ));
    // Another project may have one of that name.
    let other = vault.add_environment(&env("site", "dev")).unwrap();
    for (project, name) in [("a/b", "x"), ("app", " "), ("app", "a\tb")] {
        assert!(vault.add_environment(&env(project, name)).is_err());
    }
    assert!(vault.add_environment(&env("app", &"x".repeat(65))).is_err());

    // Renaming and moving.
    assert!(matches!(
        vault.update_environment(&other, &env("app", "dev")),
        Err(Error::AlreadyExists(_))
    ));
    vault
        .update_environment(
            &other,
            &EnvInput {
                project: None,
                part: "app".into(),
                name: "staging".into(),
                notes: "moved".into(),
            },
        )
        .unwrap();
    let list = vault.environments();
    let shown: Vec<(&str, &str)> = list
        .iter()
        .map(|e| (e.part.as_str(), e.name.as_str()))
        .collect();
    assert_eq!(shown, [("app", "dev"), ("app", "staging")]);
    assert_eq!(vault.environment(&other).unwrap().notes, "moved");
    // Not an environment.
    let login = vault
        .add_entry(&EntryInput {
            title: "GitHub".into(),
            ..EntryInput::default()
        })
        .unwrap();
    assert!(matches!(vault.environment(&login), Err(Error::NotFound(_))));
    assert!(vault.trash_environment(&login).is_err());
    assert_eq!(vault.environment(&dev).unwrap().summary.name, "dev");
}

#[test]
fn environments_sort_from_development_to_production() {
    let mut fx = Fixture::new();
    for (project, name) in [
        ("web", "prod"),
        ("api", "zeta"),
        ("api", "production"),
        ("api", "staging"),
        ("api", "dev"),
        ("api", "local"),
    ] {
        fx.vault.add_environment(&env(project, name)).unwrap();
    }
    let shown: Vec<String> = fx
        .vault
        .environments()
        .into_iter()
        .map(|e| format!("{}/{}", e.part, e.name))
        .collect();
    assert_eq!(
        shown,
        [
            "api/local",
            "api/dev",
            "api/staging",
            "api/production",
            "api/zeta",
            "web/prod"
        ]
    );
}

#[test]
fn trash_restore_and_delete() {
    let mut fx = Fixture::new();
    let vault = &mut fx.vault;
    let id = vault.add_environment(&env("app", "dev")).unwrap();
    vault
        .set_env_variable(&id, None, &input("A", Some("1"), false, ""))
        .unwrap();
    assert!(vault.delete_environment(&id).is_err());
    vault.trash_environment(&id).unwrap();
    let trashed = vault.environment(&id).unwrap().summary;
    assert!(trashed.in_trash);
    assert_eq!(trashed.part, "app");
    assert!(
        vault
            .set_env_variable(&id, None, &input("B", Some("2"), false, ""))
            .is_err()
    );
    // Trashed environments are not passwords either, and the password
    // list's "Empty trash" leaves them.
    assert_eq!(vault.entries(), Vec::<EntrySummary>::new());
    assert_eq!(vault.empty_trash().unwrap(), 0);

    // A new one took the name meanwhile: restoring waits.
    let newer = vault.add_environment(&env("app", "dev")).unwrap();
    assert!(matches!(
        vault.restore_environment(&id),
        Err(Error::AlreadyExists(_))
    ));
    vault.trash_environment(&newer).unwrap();
    vault.restore_environment(&id).unwrap();
    let restored = vault.environment(&id).unwrap().summary;
    assert!(!restored.in_trash);
    assert_eq!(restored.part, "app");

    vault.delete_environment(&newer).unwrap();
    assert_eq!(vault.environments().len(), 1);
    fx.reopen();
    assert_eq!(fx.vault.environments().len(), 1);
}

#[test]
fn imports_merge_into_an_environment() {
    let mut fx = Fixture::new();
    let dir = fx.dir.path().join("shop api");
    std::fs::create_dir(&dir).unwrap();
    let file = dir.join(".env.production");
    std::fs::write(
        &file,
        "# shop\nPORT=8080\nexport STRIPE_SECRET_KEY=sk_live_abc\nBROKEN\nNOTE=\"a\nb\"\nEMPTY=\n",
    )
    .unwrap();
    let preview = preview_file(&file).unwrap();
    assert_eq!(
        (
            preview.suggested_project.as_str(),
            preview.suggested_name.as_str()
        ),
        ("shop api", "production")
    );
    let shown: Vec<(&str, bool, bool, bool)> = preview
        .variables
        .iter()
        .map(|v| (v.name.as_str(), v.secret, v.empty, v.multiline))
        .collect();
    assert_eq!(
        shown,
        [
            ("PORT", false, false, false),
            ("STRIPE_SECRET_KEY", true, false, false),
            ("NOTE", false, false, true),
            ("EMPTY", false, true, false),
        ]
    );
    assert_eq!(preview.problems.len(), 1);
    assert_eq!(preview.problems[0].line, 4);
    let json = serde_json::to_string(&preview).unwrap();
    assert!(!json.contains("sk_live_abc"));

    let vault = &mut fx.vault;
    let id = vault
        .add_environment(&env("shop api", "production"))
        .unwrap();
    vault
        .set_env_variable(&id, None, &input("PORT", Some("80"), false, "kept note"))
        .unwrap();
    vault
        .set_env_variable(&id, None, &input("OTHER", Some("x"), false, ""))
        .unwrap();
    // The user left NOTE out and made PORT secret.
    let chosen = chosen_variables(
        read_file(&file).unwrap(),
        &[
            ImportChoice {
                name: "PORT".into(),
                secret: true,
            },
            ImportChoice {
                name: "STRIPE_SECRET_KEY".into(),
                secret: true,
            },
            ImportChoice {
                name: "EMPTY".into(),
                secret: false,
            },
        ],
    );
    let counts = vault.import_env_variables(&id, &chosen).unwrap();
    assert_eq!(
        counts,
        ImportCounts {
            added: 2,
            replaced: 1
        }
    );
    let detail = vault.environment(&id).unwrap();
    assert_eq!(
        names(&detail),
        ["PORT", "OTHER", "STRIPE_SECRET_KEY", "EMPTY"]
    );
    assert!(detail.variables[0].secret);
    assert_eq!(detail.variables[0].note, "kept note");
    assert_eq!(value(vault, &id, "PORT"), "8080");
    assert_eq!(value(vault, &id, "STRIPE_SECRET_KEY"), "sk_live_abc");

    // A plain `.env` suggests no environment name.
    assert_eq!(
        suggested_names(Path::new("/w/api/.env")),
        ("api".into(), String::new())
    );
    assert_eq!(
        suggested_names(Path::new("/w/api/staging.env")),
        ("api".into(), "staging".into())
    );
    // Too large, or not text.
    let big = dir.join("big.env");
    std::fs::write(&big, vec![b'#'; 1024 * 1024 + 1]).unwrap();
    assert!(read_file(&big).is_err());
    std::fs::write(&big, [0xff, 0xfe, 0x00]).unwrap();
    assert!(matches!(read_file(&big), Err(Error::Parse(_))));
}

#[test]
fn compares_without_showing_values() {
    let mut fx = Fixture::new();
    let vault = &mut fx.vault;
    let dev = vault.add_environment(&env("app", "dev")).unwrap();
    let prod = vault.add_environment(&env("app", "prod")).unwrap();
    vault
        .import_env_variables(
            &dev,
            &[
                var("PORT", "3000", false),
                var("DEBUG", "1", false),
                var("API_KEY", "dev-key", true),
                var("REGION", "eu", false),
            ],
        )
        .unwrap();
    vault
        .import_env_variables(
            &prod,
            &[
                var("PORT", "80", false),
                var("API_KEY", "dev-key", true),
                var("REGION", "eu", false),
                var("SENTRY_DSN", "https://x", true),
            ],
        )
        .unwrap();
    let comparison = vault.compare_environments(&dev, &prod).unwrap();
    assert_eq!(
        comparison,
        EnvComparison {
            only_left: vec!["DEBUG".into()],
            only_right: vec!["SENTRY_DSN".into()],
            changed: vec!["PORT".into()],
            same: vec!["API_KEY".into(), "REGION".into()],
        }
    );
    let json = serde_json::to_string(&comparison).unwrap();
    assert!(!json.contains("3000") && !json.contains("dev-key"));
}

#[test]
fn received_environments_never_replace_one() {
    let mut fx = Fixture::new();
    let vault = &mut fx.vault;
    vault.add_environment(&env("app", "dev")).unwrap();
    let vars = [var("A", "1", false), var("B", "2", true)];
    let (id, name) = vault
        .add_received_environment("app", "dev", "from Aziz", &vars)
        .unwrap();
    assert_eq!(name, "dev 2");
    let detail = vault.environment(&id).unwrap();
    assert_eq!(detail.notes, "from Aziz");
    assert_eq!(names(&detail), ["A", "B"]);
    assert!(detail.variables[1].secret);
    let (_, name) = vault
        .add_received_environment("app", "dev", "", &vars)
        .unwrap();
    assert_eq!(name, "dev 3");
    let long = "x".repeat(64);
    vault.add_environment(&env("app", &long)).unwrap();
    let (_, name) = vault
        .add_received_environment("app", &long, "", &[])
        .unwrap();
    assert_eq!(name, format!("{} 2", "x".repeat(62)));
    assert!(
        vault
            .add_received_environment("app", "x", "", &[var("bad name", "1", false)])
            .is_err()
    );
}

#[test]
fn exports_go_to_private_files_outside_the_ssh_folder() {
    let mut fx = Fixture::new();
    let id = fx.vault.add_environment(&env("app", "dev")).unwrap();
    fx.vault
        .import_env_variables(&id, &[var("PORT", "3000", false), var("TOKEN", "t", true)])
        .unwrap();
    let ssh = fx.dir.path().join(".ssh");
    std::fs::create_dir(&ssh).unwrap();
    let target = fx.dir.path().join("app.env");
    let count = fx
        .vault
        .export_environment(&id, EnvFormat::Dotenv, &target, &ssh)
        .unwrap();
    assert_eq!(count, 2);
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "PORT=3000\nTOKEN=t\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&target).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert!(
        fx.vault
            .export_environment(&id, EnvFormat::Json, &ssh.join("x.json"), &ssh)
            .is_err()
    );
    let own = fx.paths.database.clone();
    assert!(
        fx.vault
            .export_environment(&id, EnvFormat::Dotenv, &own, &ssh)
            .is_err()
    );
}

#[test]
fn finds_the_git_work_tree() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let nested = repo.join("a").join("b");
    std::fs::create_dir_all(&nested).unwrap();
    assert_eq!(git_work_tree(&nested), None);
    std::fs::create_dir(repo.join(".git")).unwrap();
    assert_eq!(git_work_tree(&nested), Some(repo.clone()));
    assert_eq!(git_work_tree(&repo), Some(repo));
}

#[test]
fn the_leak_scanner_gets_secret_variables_and_passwords() {
    use crate::leaks::LeakSecret;
    let mut fx = Fixture::new();
    let id = fx.vault.add_environment(&env("shop", "prod")).unwrap();
    for (name, value, secret) in [
        ("STRIPE_KEY", "tok-9fQ2xLm7Rt4Wb8Kp", true),
        ("PORT", "8080", false),
        ("EMPTY_SECRET", "", true),
    ] {
        fx.vault
            .set_env_variable(&id, None, &input(name, Some(value), secret, ""))
            .unwrap();
    }
    let gone = fx.vault.add_environment(&env("shop", "old")).unwrap();
    fx.vault
        .set_env_variable(
            &gone,
            None,
            &input("OLD_KEY", Some("Zt7#qL0p!vX2"), true, ""),
        )
        .unwrap();
    fx.vault.trash_environment(&gone).unwrap();
    let login = fx
        .vault
        .add_entry(&EntryInput {
            title: "GitLab".into(),
            password: Some(s("Hn4$wQ8!zR2#pL6")),
            ..EntryInput::default()
        })
        .unwrap();
    fx.vault
        .add_entry(&EntryInput {
            title: "No password".into(),
            ..EntryInput::default()
        })
        .unwrap();

    let known = fx.vault.known_secrets();
    let secrets: Vec<&LeakSecret> = known.iter().map(|k| &k.secret).collect();
    assert_eq!(known.len(), 2, "{secrets:?}");
    assert!(secrets.contains(&&LeakSecret::Variable {
        env_id: id.clone(),
        project: "shop".into(),
        environment: "prod".into(),
        name: "STRIPE_KEY".into(),
    }));
    assert!(secrets.contains(&&LeakSecret::Password {
        entry_id: login,
        title: "GitLab".into(),
        entry_kind: crate::vault::EntryKind::Login,
    }));
    // Their Debug output names them only.
    let debug = format!("{known:?}");
    assert!(!debug.contains("9fQ2xLm7") && !debug.contains("Hn4$"));

    // One of them alone, by its key; none for a plain, trashed or unknown one.
    for known in &known {
        let one = fx.vault.known_secret(&known.secret.key()).unwrap();
        assert_eq!(one.secret, known.secret);
        assert_eq!(one.value.expose_secret(), known.value.expose_secret());
    }
    for key in [
        format!("var:{id}:PORT"),
        format!("var:{id}:EMPTY_SECRET"),
        format!("var:{gone}:OLD_KEY"),
        "entry:00000000-0000-0000-0000-000000000000".to_owned(),
        "nonsense".to_owned(),
    ] {
        assert!(fx.vault.known_secret(&key).is_none(), "{key}");
    }
}
