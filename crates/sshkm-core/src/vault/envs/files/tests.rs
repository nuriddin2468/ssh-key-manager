use std::fs;
use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret, SecretString};

use super::*;
use crate::vault::envs::{EnvInput, EnvVarInput};
use crate::vault::projects::{ProjectColor, ProjectInput, ProjectMember};
use crate::vault::{Vault, VaultPaths};

fn s(text: &str) -> SecretString {
    SecretString::from(text)
}

struct Fixture {
    dir: tempfile::TempDir,
    vault: Vault,
    ctx: FilesContext,
    state: SyncState,
    project: String,
    /// The project's folder, `shop`.
    folder: PathBuf,
    /// How the project keeps it.
    folder_text: String,
    env: String,
}

impl Fixture {
    /// A vault with a project `Shop` holding the folder `shop` and the
    /// environments of the group `shop-api`, which has a local `dev`
    /// environment with two variables.
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("vault.kdbx"));
        let (mut vault, _) = Vault::create(&paths, &s("master")).unwrap();
        let folder = dir.path().join("shop");
        fs::create_dir_all(&folder).unwrap();
        let folder_text = projects::folder_text(&folder, None).unwrap();
        let project = vault
            .add_project(&ProjectInput {
                name: "Shop".into(),
                color: ProjectColor::Blue,
            })
            .unwrap();
        vault
            .set_project_member(
                &project,
                &ProjectMember::Folder {
                    path: folder_text.clone(),
                },
                true,
            )
            .unwrap();
        vault
            .set_project_member(
                &project,
                &ProjectMember::Environment {
                    group: "shop-api".into(),
                },
                true,
            )
            .unwrap();
        let env = vault
            .add_environment(&EnvInput {
                project: "shop-api".into(),
                name: "dev".into(),
                notes: String::new(),
            })
            .unwrap();
        let mut fixture = Self {
            ctx: FilesContext {
                home: None,
                ssh_dir: dir.path().join(".ssh"),
            },
            dir,
            vault,
            state: SyncState::default(),
            project,
            folder,
            folder_text,
            env,
        };
        fixture.set("PORT", "3000", false);
        fixture.set("API_TOKEN", "tok-1", true);
        fixture
    }

    fn set(&mut self, name: &str, value: &str, secret: bool) {
        let previous = self
            .vault
            .environment(&self.env)
            .unwrap()
            .variables
            .iter()
            .any(|var| var.name == name)
            .then_some(name);
        self.vault
            .set_env_variable(
                &self.env,
                previous,
                &EnvVarInput {
                    name: name.into(),
                    value: Some(s(value)),
                    secret,
                    note: String::new(),
                },
            )
            .unwrap();
    }

    fn file(&self, path: &str) -> EnvFile {
        EnvFile {
            folder: self.folder_text.clone(),
            path: path.into(),
        }
    }

    fn path(&self, path: &str) -> PathBuf {
        let mut full = self.folder.clone();
        full.extend(path.split('/'));
        full
    }

    fn bind(&mut self, path: &str) -> EnvFile {
        let env = self.env.clone();
        self.vault.bind_env_file(&env, &self.file(path), &self.ctx).unwrap()
    }

    /// One round, as the app does it: pull, save, push.
    fn sync(&mut self) -> EnvFilesSynced {
        self.sync_preferring(None)
    }

    fn sync_preferring(&mut self, prefer: Option<Preference<'_>>) -> EnvFilesSynced {
        let pulled = self
            .vault
            .env_files_pull(&self.ctx, &self.state, prefer)
            .unwrap();
        if pulled.vault_changed {
            self.vault.save(&self.dir.path().join("backups")).unwrap();
        }
        self.vault
            .env_files_push(&self.ctx, &mut self.state, pulled, prefer)
    }

    fn values(&self) -> Vec<(String, String, bool)> {
        self.vault
            .env_variables(&self.env)
            .unwrap()
            .into_iter()
            .map(|var| (var.name, var.value.expose_secret().to_owned(), var.secret))
            .collect()
    }

    fn states(&self) -> Vec<FileState> {
        self.vault
            .env_files_status(&self.ctx, &self.state)
            .into_iter()
            .map(|status| status.state)
            .collect()
    }
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap()
}

fn owned(list: &[(&str, &str, bool)]) -> Vec<(String, String, bool)> {
    list.iter()
        .map(|(n, v, s)| ((*n).to_owned(), (*v).to_owned(), *s))
        .collect()
}

#[test]
fn kinds_come_from_names_until_set() {
    for (name, kind) in [
        ("local", EnvKind::Local),
        ("Dev", EnvKind::Local),
        ("development", EnvKind::Local),
        ("staging", EnvKind::Remote),
        ("prod", EnvKind::Remote),
        ("dev-server", EnvKind::Remote),
    ] {
        assert_eq!(EnvKind::from_name(name), kind, "{name}");
    }
    let mut f = Fixture::new();
    assert_eq!(f.vault.environment(&f.env).unwrap().summary.kind, EnvKind::Local);
    f.vault.set_env_kind(&f.env, EnvKind::Remote).unwrap();
    assert_eq!(f.vault.env_files(&f.env).unwrap().0, EnvKind::Remote);
    // A remote one gets no file.
    let env = f.env.clone();
    let refused = f.vault.bind_env_file(&env, &f.file(".env"), &f.ctx);
    assert_eq!(refused.unwrap_err().code(), crate::ErrorCode::InvalidInput);
    f.vault.set_env_kind(&f.env, EnvKind::Local).unwrap();
    f.bind(".env");
    // And one with files can't become remote.
    assert!(f.vault.set_env_kind(&f.env, EnvKind::Remote).is_err());
    // A new name doesn't take its files away: binding made it local.
    let mut input = EnvInput {
        project: "shop-api".into(),
        name: "staging".into(),
        notes: String::new(),
    };
    f.vault.update_environment(&f.env, &input).unwrap();
    assert_eq!(f.vault.environment(&f.env).unwrap().summary.kind, EnvKind::Local);
    input.name = "dev".into();
    f.vault.update_environment(&f.env, &input).unwrap();
}

#[test]
fn file_names_and_paths_are_checked() {
    let f = Fixture::new();
    for path in [
        ".env",
        ".env.local",
        ".env.development.local",
        "apps/web/.env",
        "docker/app.env",
        ".dev.vars",
    ] {
        assert_eq!(check_env_file(&f.file(path)).unwrap().path, path);
    }
    assert_eq!(
        check_env_file(&f.file(r"apps\web\.env.local")).unwrap().path,
        "apps/web/.env.local"
    );
    for path in [
        "",
        "/.env",
        "../.env",
        "apps/../.env",
        "./.env",
        "apps//.env",
        ".git/.env",
        "C:/.env",
        "package.json",
        ".envrc",
        ".env.example",
        ".env.local.sample",
        ".env.template",
        "example.env",
        "app/.env.defaults",
        " .env",
        "a\n/.env",
    ] {
        assert!(check_env_file(&f.file(path)).is_err(), "{path:?}");
    }
    assert!(
        check_env_file(&EnvFile {
            folder: "relative\nfolder".into(),
            path: ".env".into(),
        })
        .is_err()
    );
}

#[test]
fn only_folders_of_a_project_that_holds_the_environment() {
    let mut f = Fixture::new();
    let other = f.dir.path().join("other");
    fs::create_dir_all(&other).unwrap();
    let file = EnvFile {
        folder: projects::folder_text(&other, None).unwrap(),
        path: ".env".into(),
    };
    let env = f.env.clone();
    assert!(f.vault.bind_env_file(&env, &file, &f.ctx).is_err());
    // The same file twice is refused too.
    f.bind(".env");
    let again = f.vault.bind_env_file(&env, &f.file(".env"), &f.ctx);
    assert_eq!(again.unwrap_err().code(), crate::ErrorCode::AlreadyExists);
}

#[test]
fn a_new_binding_writes_the_file_owner_only() {
    let mut f = Fixture::new();
    f.bind(".env.local");
    let synced = f.sync();
    assert_eq!(synced.written.len(), 1);
    assert_eq!(synced.files[0].state, FileState::InSync);
    let path = f.path(".env.local");
    assert_eq!(read(&path), "PORT=3000\nAPI_TOKEN=tok-1\n");
    assert_eq!(synced.files[0].location.as_deref(), Some(path.as_path()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    // Nothing more to do.
    let again = f.sync();
    assert!(again.written.is_empty() && again.changes.is_empty());
    assert_eq!(f.states(), [FileState::InSync]);
}

#[test]
fn edits_of_the_file_go_to_the_vault_and_can_be_undone() {
    let mut f = Fixture::new();
    f.bind(".env");
    f.sync();
    let path = f.path(".env");
    fs::write(
        &path,
        "# mine\nPORT=4000\nNEW_SECRET_KEY=sk-123456789\nDEBUG=true\n",
    )
    .unwrap();
    let synced = f.sync();
    assert_eq!(synced.changes.len(), 1);
    let change = &synced.changes[0];
    assert_eq!(change.changed, ["PORT"]);
    assert_eq!(change.added, ["NEW_SECRET_KEY", "DEBUG"]);
    assert_eq!(change.removed, ["API_TOKEN"]);
    assert_eq!(
        f.values(),
        owned(&[
            ("PORT", "4000", false),
            ("NEW_SECRET_KEY", "sk-123456789", true),
            ("DEBUG", "true", false),
        ])
    );
    // The file is left as the user wrote it.
    assert_eq!(
        read(&path),
        "# mine\nPORT=4000\nNEW_SECRET_KEY=sk-123456789\nDEBUG=true\n"
    );
    assert!(synced.written.is_empty());
    let undo = change.undo.clone();

    f.vault.undo_env_file_change(&undo).unwrap();
    f.sync();
    assert_eq!(
        f.values(),
        owned(&[("PORT", "3000", false), ("API_TOKEN", "tok-1", true)])
    );
    // The file follows; its comment stays.
    assert_eq!(read(&path), "# mine\nPORT=3000\nAPI_TOKEN=tok-1\n");
    // Undoing twice is refused: the variables changed since.
    assert_eq!(
        f.vault.undo_env_file_change(&undo).unwrap_err().code(),
        crate::ErrorCode::Conflict
    );
}

#[test]
fn a_secret_stays_secret_when_its_value_changes_in_the_file() {
    let mut f = Fixture::new();
    f.bind(".env");
    f.sync();
    fs::write(f.path(".env"), "PORT=3000\nAPI_TOKEN=tok-2\n").unwrap();
    f.sync();
    assert_eq!(
        f.values(),
        owned(&[("PORT", "3000", false), ("API_TOKEN", "tok-2", true)])
    );
}

#[test]
fn a_change_in_the_vault_rewrites_only_its_lines_in_every_file() {
    let mut f = Fixture::new();
    fs::create_dir_all(f.path("apps/web")).unwrap();
    f.bind(".env");
    f.bind("apps/web/.env.local");
    f.sync();
    let root = f.path(".env");
    let text = "\u{feff}# The API\r\n\r\nexport PORT = 3000 # dev port\r\nAPI_TOKEN=\"tok-1\"\r\nnot a variable\r\n";
    fs::write(&root, text).unwrap();
    assert!(f.sync().changes.is_empty(), "same variables, nothing to take");

    f.set("API_TOKEN", "tok 2", true);
    let synced = f.sync();
    assert_eq!(synced.written.len(), 2);
    assert_eq!(
        read(&root),
        "\u{feff}# The API\r\n\r\nexport PORT = 3000 # dev port\r\nAPI_TOKEN=\"tok 2\"\r\nnot a variable\r\n"
    );
    assert_eq!(
        read(&f.path("apps/web/.env.local")),
        "PORT=3000\nAPI_TOKEN=\"tok 2\"\n"
    );
}

#[test]
fn an_edit_in_one_file_reaches_the_others() {
    let mut f = Fixture::new();
    fs::create_dir_all(f.path("apps/web")).unwrap();
    f.bind(".env");
    f.bind("apps/web/.env");
    f.sync();
    fs::write(f.path("apps/web/.env"), "PORT=3000\nAPI_TOKEN=tok-9\n").unwrap();
    let synced = f.sync();
    assert_eq!(synced.changes.len(), 1);
    assert_eq!(synced.written.len(), 1);
    assert_eq!(read(&f.path(".env")), "PORT=3000\nAPI_TOKEN=tok-9\n");
}

#[test]
fn editors_that_save_by_renaming_are_followed() {
    let mut f = Fixture::new();
    f.bind(".env");
    f.sync();
    let path = f.path(".env");
    let temp = f.path(".env.swp-save");
    fs::write(&temp, "PORT=5000\nAPI_TOKEN=tok-1\n").unwrap();
    fs::rename(&temp, &path).unwrap();
    let synced = f.sync();
    assert_eq!(synced.changes[0].changed, ["PORT"]);
    assert_eq!(f.values()[0].1, "5000");
}

#[test]
fn both_sides_changed_is_a_conflict_until_one_is_kept() {
    let mut f = Fixture::new();
    f.bind(".env");
    f.sync();
    let path = f.path(".env");
    fs::write(&path, "PORT=4000\nAPI_TOKEN=tok-1\n").unwrap();
    f.set("PORT", "5000", false);
    let synced = f.sync();
    assert!(synced.changes.is_empty() && synced.written.is_empty());
    assert_eq!(synced.files[0].state, FileState::Conflict);
    assert_eq!(read(&path), "PORT=4000\nAPI_TOKEN=tok-1\n");
    assert_eq!(f.values()[0].1, "5000");
    let comparison = f
        .vault
        .compare_env_file(&f.env, &f.file(".env"), &f.ctx)
        .unwrap();
    assert_eq!(comparison.changed, ["PORT"]);
    assert_eq!(comparison.same, ["API_TOKEN"]);
    // Still a conflict on the next round.
    assert_eq!(f.sync().files[0].state, FileState::Conflict);

    // Keeping the file.
    let env = f.env.clone();
    let file = f.file(".env");
    let synced = f.sync_preferring(Some(Preference {
        env_id: &env,
        file: &file,
        keep: KeepSide::File,
    }));
    assert_eq!(synced.changes.len(), 1);
    assert_eq!(f.values()[0].1, "4000");
    assert_eq!(f.states(), [FileState::InSync]);

    // Keeping the vault.
    fs::write(&path, "PORT=1\nAPI_TOKEN=tok-1\n").unwrap();
    f.set("PORT", "2", false);
    assert_eq!(f.states(), [FileState::Conflict]);
    f.sync_preferring(Some(Preference {
        env_id: &env,
        file: &file,
        keep: KeepSide::Vault,
    }));
    assert_eq!(read(&path), "PORT=2\nAPI_TOKEN=tok-1\n");
    assert_eq!(f.states(), [FileState::InSync]);
}

#[test]
fn a_file_that_differs_with_nothing_to_go_by_is_a_conflict() {
    let mut f = Fixture::new();
    let path = f.path(".env");
    fs::write(&path, "PORT=1\n").unwrap();
    f.bind(".env");
    assert_eq!(f.sync().files[0].state, FileState::Conflict);
    assert_eq!(read(&path), "PORT=1\n");
    // The same variables are in step at once.
    fs::write(&path, "API_TOKEN=tok-1\nPORT=3000\n").unwrap();
    assert_eq!(f.sync().files[0].state, FileState::InSync);
}

#[test]
fn files_changed_while_the_app_was_closed_are_caught_by_the_stored_revision() {
    let mut f = Fixture::new();
    f.bind(".env");
    f.sync();
    let kept = f.dir.path().join("env-files.json");
    f.state.save(&kept).unwrap();
    // Revisions are keyed hashes: no value is in the file.
    let saved = read(&kept);
    assert!(!saved.contains("tok-1") && !saved.contains("3000"));

    fs::write(f.path(".env"), "PORT=3000\nAPI_TOKEN=tok-closed\n").unwrap();
    f.state = SyncState::load(&kept);
    assert_eq!(f.states(), [FileState::FileChanged]);
    f.sync();
    assert_eq!(f.values()[1].1, "tok-closed");
}

#[test]
fn a_deleted_file_is_reported_and_written_again_only_when_asked() {
    let mut f = Fixture::new();
    f.bind(".env");
    f.sync();
    let path = f.path(".env");
    fs::remove_file(&path).unwrap();
    f.set("PORT", "4000", false);
    assert_eq!(f.sync().files[0].state, FileState::Missing);
    assert!(!path.exists());
    let env = f.env.clone();
    let file = f.file(".env");
    f.sync_preferring(Some(Preference {
        env_id: &env,
        file: &file,
        keep: KeepSide::Vault,
    }));
    assert_eq!(read(&path), "PORT=4000\nAPI_TOKEN=tok-1\n");
}

#[test]
fn a_missing_folder_is_never_made() {
    let mut f = Fixture::new();
    f.bind("apps/api/.env");
    let synced = f.sync();
    assert_eq!(synced.files[0].state, FileState::FolderMissing);
    assert!(!f.path("apps").exists());
    fs::remove_dir_all(&f.folder).unwrap();
    f.bind(".env");
    assert!(
        f.sync()
            .files
            .iter()
            .all(|status| status.state == FileState::FolderMissing)
    );
    assert!(!f.folder.exists());
}

#[test]
fn unreadable_lines_change_nothing_either_way() {
    let mut f = Fixture::new();
    f.bind(".env");
    f.sync();
    let path = f.path(".env");
    let broken = "PORT=3000\nAPI_TOKEN=\"tok-1\nOTHER=1\n";
    fs::write(&path, broken).unwrap();
    let synced = f.sync();
    assert!(matches!(synced.files[0].state, FileState::Invalid { .. }));
    assert!(synced.changes.is_empty());
    assert_eq!(f.values().len(), 2);
    f.set("PORT", "1", false);
    f.sync();
    assert_eq!(read(&path), broken);
    // A word without `=` is not a problem.
    fs::write(&path, "PORT=1\nAPI_TOKEN=tok-1\njust a note\n").unwrap();
    assert_eq!(f.sync().files[0].state, FileState::InSync);
}

#[test]
fn files_of_environments_out_of_use_are_left_alone() {
    let mut f = Fixture::new();
    f.bind(".env");
    f.sync();
    let path = f.path(".env");
    let env = f.env.clone();
    f.vault.trash_environment(&env).unwrap();
    assert_eq!(
        f.states(),
        [FileState::Inactive {
            reason: InactiveReason::InTrash
        }]
    );
    f.vault.restore_environment(&env).unwrap();
    let project = f.project.clone();
    f.vault
        .set_project_member(
            &project,
            &ProjectMember::Folder {
                path: f.folder_text.clone(),
            },
            false,
        )
        .unwrap();
    assert_eq!(
        f.states(),
        [FileState::Inactive {
            reason: InactiveReason::NotInProject
        }]
    );
    f.set("PORT", "9", false);
    f.sync();
    assert_eq!(read(&path), "PORT=3000\nAPI_TOKEN=tok-1\n");
}

#[test]
fn a_file_can_be_deleted_only_when_the_vault_has_all_of_it() {
    let mut f = Fixture::new();
    f.bind(".env");
    f.sync();
    let path = f.path(".env");
    let env = f.env.clone();
    let file = f.file(".env");
    fs::write(&path, "PORT=3000\nAPI_TOKEN=tok-1\nEXTRA=1\n").unwrap();
    assert_eq!(
        f.vault
            .delete_env_file(&env, &file, &f.ctx)
            .unwrap_err()
            .code(),
        crate::ErrorCode::Conflict
    );
    assert!(path.exists());
    fs::write(&path, "# same\nAPI_TOKEN=tok-1\nPORT=3000\n").unwrap();
    assert!(f.vault.delete_env_file(&env, &file, &f.ctx).unwrap());
    assert!(!path.exists());
    assert!(f.vault.unbind_env_file(&env, &file).unwrap());
    assert!(f.vault.env_files(&env).unwrap().1.is_empty());
}

#[test]
fn a_new_key_starts_over_without_losing_anything() {
    let mut f = Fixture::new();
    f.bind(".env");
    f.sync();
    // Another vault's state, or one made with a key the vault no longer has.
    f.state.key = "0000".into();
    fs::write(f.path(".env"), "PORT=1\nAPI_TOKEN=tok-1\n").unwrap();
    assert_eq!(f.sync().files[0].state, FileState::Conflict);
    assert_eq!(f.values()[0].1, "3000");
}

#[cfg(unix)]
#[test]
fn links_are_never_followed() {
    let mut f = Fixture::new();
    let outside = f.dir.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    let target = outside.join("secret.env");
    fs::write(&target, "KEEP=1\n").unwrap();
    // The file is a link.
    std::os::unix::fs::symlink(&target, f.path(".env")).unwrap();
    let env = f.env.clone();
    let refused = f.vault.bind_env_file(&env, &f.file(".env"), &f.ctx);
    assert!(refused.is_err());
    // A link made after binding is refused, never written through.
    fs::remove_file(f.path(".env")).unwrap();
    f.bind(".env");
    f.sync();
    fs::remove_file(f.path(".env")).unwrap();
    std::os::unix::fs::symlink(&target, f.path(".env")).unwrap();
    f.set("PORT", "1", false);
    let synced = f.sync();
    assert_eq!(
        synced.files[0].state,
        FileState::Refused {
            reason: RefusedReason::Link
        }
    );
    assert_eq!(read(&target), "KEEP=1\n");
    // A folder on the way that leads out of the project's folder.
    std::os::unix::fs::symlink(&outside, f.path("linked")).unwrap();
    let out = f.vault.bind_env_file(&env, &f.file("linked/.env"), &f.ctx);
    assert!(out.unwrap_err().to_string().contains("out of the project"));
    assert!(!outside.join(".env").exists());
}

#[cfg(unix)]
#[test]
fn a_pipe_is_refused_at_once() {
    let mut f = Fixture::new();
    f.bind(".env");
    let pipe = f.path(".env");
    let made = std::process::Command::new("mkfifo")
        .arg(&pipe)
        .status()
        .is_ok_and(|status| status.success());
    if !made {
        return;
    }
    let synced = f.sync();
    assert_eq!(
        synced.files[0].state,
        FileState::Refused {
            reason: RefusedReason::NotAFile
        }
    );
}

#[test]
fn one_file_through_two_folders_is_written_by_one_environment() {
    let mut f = Fixture::new();
    // `Shop` on a file system that ignores case, or a link on others.
    let twin = f.dir.path().join("SHOP");
    let same_on_disk = twin.exists();
    #[cfg(unix)]
    let same_on_disk = same_on_disk || {
        std::os::unix::fs::symlink(&f.folder, &twin).unwrap();
        true
    };
    if !same_on_disk {
        return;
    }
    let twin_text = projects::folder_text(&twin, None).unwrap();
    let project = f.project.clone();
    f.vault
        .set_project_member(
            &project,
            &ProjectMember::Folder {
                path: twin_text.clone(),
            },
            true,
        )
        .unwrap();
    f.bind(".env");
    let env = f.env.clone();
    let twin_file = EnvFile {
        folder: twin_text,
        path: ".ENV".into(),
    };
    let refused = f.vault.bind_env_file(&env, &twin_file, &f.ctx);
    assert_eq!(refused.unwrap_err().code(), crate::ErrorCode::AlreadyExists);
}

#[test]
fn nothing_is_written_into_the_ssh_folder_or_over_the_vault() {
    let mut f = Fixture::new();
    // The project's folder is the one the vault and `.ssh` are in.
    let parent = f.dir.path().to_path_buf();
    fs::create_dir_all(parent.join(".ssh")).unwrap();
    let text = projects::folder_text(&parent, None).unwrap();
    let project = f.project.clone();
    f.vault
        .set_project_member(&project, &ProjectMember::Folder { path: text.clone() }, true)
        .unwrap();
    let env = f.env.clone();
    let file = EnvFile {
        folder: text,
        path: ".ssh/app.env".into(),
    };
    assert!(f.vault.bind_env_file(&env, &file, &f.ctx).is_err());
}

#[test]
fn the_overview_finds_unmanaged_files_templates_and_cloud_folders() {
    let mut f = Fixture::new();
    fs::create_dir_all(f.path("apps/web")).unwrap();
    fs::create_dir_all(f.path("node_modules/pkg")).unwrap();
    fs::write(f.path("apps/web/.env.local"), "X=1\n").unwrap();
    fs::write(f.path("node_modules/pkg/.env"), "X=1\n").unwrap();
    fs::write(f.path(".env.example"), "PORT=\nAPI_TOKEN=\nSENTRY_DSN=\n").unwrap();
    fs::write(f.path(".envrc"), "export X=1\n").unwrap();
    f.bind(".env");
    f.sync();
    let cloud = CloudRoots::new(vec![(f.folder.clone(), CloudService::Dropbox)]);
    let overview = f
        .vault
        .env_files_overview(&f.ctx, &f.state, &cloud, Some(&f.project));
    assert_eq!(overview.files.len(), 1);
    let report = &overview.files[0];
    assert_eq!(report.projects, [f.project.clone()]);
    assert_eq!(report.cloud, Some(CloudService::Dropbox));
    assert_eq!(
        report.example,
        Some(ExampleCheck {
            file: ".env.example".into(),
            missing: vec!["SENTRY_DSN".into()],
        })
    );
    let unmanaged: Vec<&str> = overview
        .unmanaged
        .iter()
        .map(|file| file.file.path.as_str())
        .collect();
    assert_eq!(unmanaged, ["apps/web/.env.local"]);
    assert_eq!(overview.unmanaged[0].location, f.path("apps/web/.env.local"));
    assert!(!overview.truncated);
    let path = f
        .vault
        .unmanaged_env_file(&f.project, &f.file("apps/web/.env.local"), &f.ctx)
        .unwrap();
    assert_eq!(read(&path), "X=1\n");
    assert!(
        f.vault
            .unmanaged_env_file(&f.project, &f.file(".env.example"), &f.ctx)
            .is_err()
    );
    // Another project's view leaves this one out.
    let none = f
        .vault
        .env_files_overview(&f.ctx, &f.state, &cloud, Some("nope"));
    assert!(none.files.is_empty() && none.unmanaged.is_empty());
}

#[test]
fn files_go_to_other_computers_with_the_vault() {
    let mut f = Fixture::new();
    f.bind("apps/api/.env");
    f.vault.save(&f.dir.path().join("backups")).unwrap();
    let reopened = Vault::unlock(f.vault.paths(), &s("master")).unwrap();
    let (kind, files) = reopened.env_files(&f.env).unwrap();
    assert_eq!(kind, EnvKind::Local);
    assert_eq!(files, [f.file("apps/api/.env")]);
    assert_eq!(reopened.environment(&f.env).unwrap().files, files);
}

#[test]
fn fields_of_later_versions_are_kept() {
    let mut f = Fixture::new();
    f.bind(".env");
    let id = parse_id(&f.env).unwrap();
    {
        let mut entry = f.vault.db.entry_mut(id).unwrap();
        let json = r#"{"kind":"local","files":[{"folder":"F","path":".env","level":2}],"future":true}"#
            .replace('F', &f.folder_text.replace('\\', "\\\\"));
        entry.custom_data.insert(
            FILES_DATA.to_owned(),
            CustomDataItem {
                value: Some(CustomDataValue::String(json)),
                last_modification_time: None,
            },
        );
    }
    f.bind(".env.local");
    let entry = f.vault.db.entry(id).unwrap();
    let Some(CustomDataValue::String(json)) = &entry.custom_data[FILES_DATA].value else {
        panic!("no data");
    };
    assert!(json.contains("\"level\":2") && json.contains("\"future\":true"));
}

#[test]
fn ignore_lines_are_added_once_and_keep_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    fs::create_dir_all(repo.join("apps").join("web")).unwrap();
    let file = repo.join("apps").join("web").join(".env.local");
    ignore_in_git(&repo, &file).unwrap();
    assert_eq!(read(&repo.join(".gitignore")), "/apps/web/.env.local\n");
    fs::write(repo.join(".gitignore"), "node_modules\r\ndist").unwrap();
    ignore_in_git(&repo, &file).unwrap();
    ignore_in_git(&repo, &file).unwrap();
    assert_eq!(
        read(&repo.join(".gitignore")),
        "node_modules\r\ndist\r\n/apps/web/.env.local\r\n"
    );
    assert!(ignore_in_git(&repo, &dir.path().join(".env")).is_err());
}

#[test]
fn nothing_shows_a_value() {
    let mut f = Fixture::new();
    f.bind(".env");
    f.sync();
    fs::write(f.path(".env"), "PORT=3000\nAPI_TOKEN=tok-secret-77\n").unwrap();
    let synced = f.sync();
    let shown = format!("{synced:?}{:?}", serde_json::to_string(&synced).unwrap());
    assert!(!shown.contains("tok-secret-77") && !shown.contains("tok-1"));
}
