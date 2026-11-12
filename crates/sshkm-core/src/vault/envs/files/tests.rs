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
        // In the project, as `Environments/Shop/dev` in KeePass.
        let env = vault
            .add_environment(&EnvInput {
                project: Some(project.clone()),
                part: String::new(),
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
        self.vault
            .bind_env_file(&env, &self.file(path), &self.ctx)
            .unwrap()
    }

    fn bind_at(&mut self, path: &str, level: FileLevel) -> EnvFile {
        let env = self.env.clone();
        self.vault
            .bind_env_file_at(&env, &self.file(path), level, &self.ctx)
            .unwrap()
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

    /// Settles `path` keeping `side`, as the compare dialog does: with the
    /// revision of the file it showed.
    fn keep(&mut self, path: &str, side: KeepSide) -> EnvFilesSynced {
        let env = self.env.clone();
        let file = self.file(path);
        let seen = self
            .vault
            .compare_env_file(&env, &file, &self.ctx)
            .unwrap()
            .revision;
        self.sync_preferring(Some(Preference {
            env_id: &env,
            file: &file,
            keep: side,
            seen: seen.as_deref(),
        }))
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
    assert_eq!(
        f.vault.environment(&f.env).unwrap().summary.kind,
        EnvKind::Local
    );
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
        project: Some(f.project.clone()),
        part: String::new(),
        name: "staging".into(),
        notes: String::new(),
    };
    f.vault.update_environment(&f.env, &input).unwrap();
    assert_eq!(
        f.vault.environment(&f.env).unwrap().summary.kind,
        EnvKind::Local
    );
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
        check_env_file(&f.file(r"apps\web\.env.local"))
            .unwrap()
            .path,
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
fn a_binding_is_checked_before_it_is_made() {
    let mut f = Fixture::new();
    let env = f.env.clone();
    let (file, location) = f
        .vault
        .check_env_file_binding(
            &env,
            &f.file(r"apps\web\.env.local"),
            FileLevel::Always,
            &f.ctx,
        )
        .unwrap();
    assert_eq!(file.path, "apps/web/.env.local");
    // The folder isn't there yet: nothing to show, nothing made.
    assert_eq!(location, None);
    let (_, location) = f
        .vault
        .check_env_file_binding(&env, &f.file(".env"), FileLevel::Always, &f.ctx)
        .unwrap();
    assert_eq!(location, Some(f.path(".env")));
    assert!(!f.path(".env").exists());
    assert_eq!(f.vault.env_files(&env).unwrap().1, []);
    f.bind(".env");
    let again = f
        .vault
        .check_env_file_binding(&env, &f.file(".env"), FileLevel::Always, &f.ctx);
    assert_eq!(again.unwrap_err().code(), crate::ErrorCode::AlreadyExists);
    assert!(
        f.vault
            .check_env_file_binding(&env, &f.file(".env.example"), FileLevel::Always, &f.ctx)
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
    assert_eq!(synced.written, []);
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
    assert!(
        f.sync().changes.is_empty(),
        "same variables, nothing to take"
    );

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
    assert_eq!(comparison.comparison.changed, ["PORT"]);
    assert_eq!(comparison.comparison.same, ["API_TOKEN"]);
    // Still a conflict on the next round.
    assert_eq!(f.sync().files[0].state, FileState::Conflict);

    // Keeping the file.
    let synced = f.keep(".env", KeepSide::File);
    assert_eq!(synced.changes.len(), 1);
    assert_eq!(f.values()[0].1, "4000");
    assert_eq!(f.states(), [FileState::InSync]);

    // Keeping the vault.
    fs::write(&path, "PORT=1\nAPI_TOKEN=tok-1\n").unwrap();
    f.set("PORT", "2", false);
    assert_eq!(f.states(), [FileState::Conflict]);
    f.keep(".env", KeepSide::Vault);
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
    f.keep(".env", KeepSide::Vault);
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
    assert_eq!(synced.changes, []);
    assert_eq!(f.values().len(), 2);
    f.set("PORT", "1", false);
    f.sync();
    assert_eq!(read(&path), broken);
    // A word without `=` is not a problem.
    fs::write(&path, "PORT=1\nAPI_TOKEN=tok-1\njust a note\n").unwrap();
    assert_eq!(f.sync().files[0].state, FileState::InSync);
}

#[test]
fn a_file_left_without_variables_asks_first() {
    let mut f = Fixture::new();
    f.bind(".env");
    f.sync();
    let path = f.path(".env");
    // An editor that writes in place, caught halfway, or everything deleted.
    fs::write(&path, "").unwrap();
    let synced = f.sync();
    assert_eq!(synced.files[0].state, FileState::Conflict);
    assert_eq!(f.values().len(), 2);
    assert_eq!(read(&path), "");
    // The editor finishes: nothing was lost.
    fs::write(&path, "PORT=3000\nAPI_TOKEN=tok-1\n").unwrap();
    assert_eq!(f.sync().files[0].state, FileState::InSync);
    // Emptied on purpose, and kept.
    fs::write(&path, "# nothing here\n").unwrap();
    f.keep(".env", KeepSide::File);
    assert_eq!(f.values(), []);
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
    assert_eq!(f.vault.env_files(&env).unwrap().1, []);
}

#[test]
fn a_new_key_starts_over_without_losing_anything() {
    let mut f = Fixture::new();
    f.bind(".env");
    f.sync();
    // The revisions are lost, or were made with a key the vault no longer has.
    f.state = SyncState::default();
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
        .set_project_member(
            &project,
            &ProjectMember::Folder { path: text.clone() },
            true,
        )
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
    let mut overview = f
        .vault
        .env_files_overview(&f.ctx, &f.state, &cloud, Some(&f.project));
    (overview.unmanaged, overview.truncated) = f
        .vault
        .unmanaged_search(&f.ctx, Some(&f.project))
        .run(&f.ctx, &cloud);
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
    assert_eq!(
        overview.unmanaged[0].location,
        f.path("apps/web/.env.local")
    );
    assert!(!overview.truncated);
    let (path, parsed) = f
        .vault
        .unmanaged_env_file(&f.project, &f.file("apps/web/.env.local"), &f.ctx)
        .unwrap();
    assert_eq!(path, f.path("apps/web/.env.local"));
    assert_eq!(parsed.vars[0].name, "X");
    assert!(
        f.vault
            .unmanaged_env_file(&f.project, &f.file(".env.example"), &f.ctx)
            .is_err()
    );
    // Another project's view leaves this one out.
    let none = f
        .vault
        .env_files_overview(&f.ctx, &f.state, &cloud, Some("nope"));
    assert_eq!(none.files, []);
    let (found, _) = f
        .vault
        .unmanaged_search(&f.ctx, Some("nope"))
        .run(&f.ctx, &cloud);
    assert_eq!(found, []);
}

#[test]
fn files_go_to_other_computers_with_the_vault() {
    let mut f = Fixture::new();
    f.bind("apps/api/.env");
    f.vault.save(&f.dir.path().join("backups")).unwrap();
    let reopened = Vault::unlock(f.vault.paths(), &s("master")).unwrap();
    let (kind, files) = reopened.env_files(&f.env).unwrap();
    assert_eq!(kind, EnvKind::Local);
    assert_eq!(files, [(f.file("apps/api/.env"), FileLevel::Always)]);
    assert_eq!(
        reopened.environment(&f.env).unwrap().files,
        [f.file("apps/api/.env")]
    );
}

#[test]
fn fields_of_later_versions_are_kept() {
    let mut f = Fixture::new();
    f.bind(".env");
    let id = parse_id(&f.env).unwrap();
    {
        let mut entry = f.vault.db.entry_mut(id).unwrap();
        let json =
            r#"{"kind":"local","files":[{"folder":"F","path":".env","level":2}],"future":true}"#
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
fn ignore_lines_are_added_for_a_folder_not_made_yet() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    fs::create_dir_all(repo.join("apps")).unwrap();
    // `apps/web` comes later: the binding waits for it, Git ignores it first.
    let file = repo.join("apps").join("web").join(".env.local");
    ignore_in_git(&repo, &file).unwrap();
    assert_eq!(read(&repo.join(".gitignore")), "/apps/web/.env.local\n");
    let deeper = repo.join("services").join("api").join(".env");
    ignore_in_git(&repo, &deeper).unwrap();
    assert_eq!(
        read(&repo.join(".gitignore")),
        "/apps/web/.env.local\n/services/api/.env\n"
    );
    // Not past the working tree, and only plain names on the way.
    let outside = dir.path().join("elsewhere").join(".env");
    assert!(ignore_in_git(&repo, &outside).is_err());
    let back = repo.join("gone").join("..").join("..").join(".env");
    assert!(ignore_in_git(&repo, &back).is_err());
    // A file where a folder should be.
    fs::write(repo.join("notes"), "").unwrap();
    assert!(ignore_in_git(&repo, &repo.join("notes").join("x").join(".env")).is_err());
    assert_eq!(
        read(&repo.join(".gitignore")),
        "/apps/web/.env.local\n/services/api/.env\n"
    );
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

/// Adds `DB_HOST`, secret, with a note, and binds `.env`, in step.
fn with_db_host() -> Fixture {
    let mut f = Fixture::new();
    let env = f.env.clone();
    f.vault
        .set_env_variable(
            &env,
            None,
            &EnvVarInput {
                name: "DB_HOST".into(),
                value: Some(s("db.internal")),
                secret: true,
                note: "read replica".into(),
            },
        )
        .unwrap();
    f.bind(".env");
    f.sync();
    f
}

fn db_host(f: &Fixture) -> Option<(bool, String)> {
    f.vault
        .environment(&f.env)
        .unwrap()
        .variables
        .into_iter()
        .find(|var| var.name == "DB_HOST")
        .map(|var| (var.secret, var.note))
}

#[test]
fn a_line_being_typed_keeps_its_variable() {
    let mut f = with_db_host();
    let path = f.path(".env");
    let text = read(&path);
    // Saved while `DB_HOST=` is retyped, or with a name Node's dotenv takes
    // and a shell doesn't, or halfway through the name.
    for broken in [
        text.replace("DB_HOST=", "DB_HOST "),
        text.replace("DB_HOST=", "export db-host="),
        text.replace("DB_HOST=db.internal", "DB_HO"),
    ] {
        fs::write(&path, &broken).unwrap();
        let synced = f.sync();
        assert!(
            matches!(synced.files[0].state, FileState::Invalid { .. }),
            "{:?}",
            synced.files[0].state
        );
        assert_eq!(synced.changes, []);
        assert_eq!(db_host(&f), Some((true, "read replica".into())));
        assert_eq!(read(&path), broken);
    }
    fs::write(&path, &text).unwrap();
    assert_eq!(f.sync().files[0].state, FileState::InSync);
}

#[test]
fn a_variable_deleted_and_written_again_keeps_its_flag_and_note() {
    let mut f = with_db_host();
    let path = f.path(".env");
    let text = read(&path);
    fs::write(&path, text.replace("DB_HOST=db.internal\n", "")).unwrap();
    assert_eq!(f.sync().changes[0].removed, ["DB_HOST"]);
    assert_eq!(db_host(&f), None);
    fs::write(&path, &text).unwrap();
    assert_eq!(f.sync().changes[0].added, ["DB_HOST"]);
    assert_eq!(db_host(&f), Some((true, "read replica".into())));
}

#[test]
fn removing_half_the_variables_at_once_asks_first() {
    let mut f = Fixture::new();
    f.set("C", "3", false);
    f.set("D", "4", false);
    f.bind(".env");
    f.sync();
    let path = f.path(".env");
    // A script that writes the file a line at a time, caught halfway.
    fs::write(&path, "PORT=3000\nAPI_TOKEN=tok-1\n").unwrap();
    let synced = f.sync();
    assert_eq!(synced.files[0].state, FileState::Conflict);
    assert_eq!(f.values().len(), 4);
    fs::write(&path, "PORT=3000\nAPI_TOKEN=tok-1\nC=3\nD=4\n").unwrap();
    assert_eq!(f.sync().files[0].state, FileState::InSync);
    // One at a time is an ordinary edit.
    fs::write(&path, "PORT=3000\nAPI_TOKEN=tok-1\nC=3\n").unwrap();
    assert_eq!(f.sync().changes[0].removed, ["D"]);
}

#[test]
fn stored_bindings_are_checked_whenever_they_are_used() {
    let mut f = Fixture::new();
    f.bind(".env");
    fs::create_dir_all(f.path(".git/hooks")).unwrap();
    let id = parse_id(&f.env).unwrap();
    let folder = f.folder_text.replace('\\', "\\\\");
    let foreign = [
        ".git/hooks/notes.txt",
        ".zshenv",
        "..\\\\..\\\\x.env",
        "apps\\\\.env",
        "C:\\\\x.env",
        "/etc/x.env",
        "./.env",
    ];
    {
        let files: Vec<String> = foreign
            .iter()
            .map(|path| format!(r#"{{"folder":"{folder}","path":"{path}"}}"#))
            .collect();
        let json = format!(r#"{{"kind":"local","files":[{}]}}"#, files.join(","));
        let mut entry = f.vault.db.entry_mut(id).unwrap();
        entry.custom_data.insert(
            FILES_DATA.to_owned(),
            CustomDataItem {
                value: Some(CustomDataValue::String(json)),
                last_modification_time: None,
            },
        );
    }
    let synced = f.sync();
    assert_eq!(synced.files.len(), foreign.len());
    for status in &synced.files {
        assert_eq!(
            status.state,
            FileState::Refused {
                reason: RefusedReason::Name
            },
            "{}",
            status.file.path
        );
    }
    assert!(!f.path(".git/hooks/notes.txt").exists());
    assert!(!f.path(".zshenv").exists());
    assert!(!f.dir.path().join("x.env").exists());
    let env = f.env.clone();
    for status in &synced.files {
        assert!(
            f.vault
                .compare_env_file(&env, &status.file, &f.ctx)
                .is_err()
        );
        assert!(f.vault.delete_env_file(&env, &status.file, &f.ctx).is_err());
    }
}

#[test]
fn only_the_environments_own_files_are_compared() {
    let f = Fixture::new();
    let elsewhere = f.dir.path().join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    fs::write(
        elsewhere.join("credentials"),
        "aws_secret_access_key=tok-1\n",
    )
    .unwrap();
    for file in [
        EnvFile {
            folder: projects::folder_text(&elsewhere, None).unwrap(),
            path: "credentials".into(),
        },
        // In the project's folder, but not bound.
        f.file(".env.local"),
    ] {
        let compared = f.vault.compare_env_file(&f.env, &file, &f.ctx);
        assert_eq!(compared.unwrap_err().code(), crate::ErrorCode::NotFound);
    }
}

#[cfg(unix)]
#[test]
fn a_folder_swapped_for_a_link_is_no_edit() {
    let mut f = Fixture::new();
    fs::create_dir_all(f.path("apps/web")).unwrap();
    fs::create_dir_all(f.path("apps/other")).unwrap();
    fs::write(f.path("apps/other/.env"), "SOMETHING_ELSE=1\n").unwrap();
    f.bind(".env");
    f.bind("apps/web/.env");
    f.sync();
    fs::remove_dir_all(f.path("apps/web")).unwrap();
    std::os::unix::fs::symlink(f.path("apps/other"), f.path("apps/web")).unwrap();
    let synced = f.sync();
    assert_eq!(synced.changes, []);
    let web = synced
        .files
        .iter()
        .find(|status| status.file.path == "apps/web/.env")
        .unwrap();
    assert_eq!(web.state, FileState::Conflict);
    assert_eq!(
        f.values(),
        owned(&[("PORT", "3000", false), ("API_TOKEN", "tok-1", true)])
    );
    assert_eq!(read(&f.path(".env")), "PORT=3000\nAPI_TOKEN=tok-1\n");
    assert_eq!(read(&f.path("apps/other/.env")), "SOMETHING_ELSE=1\n");
}

#[test]
fn a_conflict_is_settled_only_as_it_was_compared() {
    let mut f = Fixture::new();
    f.bind(".env");
    f.sync();
    let path = f.path(".env");
    fs::write(&path, "PORT=1\nAPI_TOKEN=tok-1\n").unwrap();
    f.set("PORT", "2", false);
    let env = f.env.clone();
    let file = f.file(".env");
    let seen = f
        .vault
        .compare_env_file(&env, &file, &f.ctx)
        .unwrap()
        .revision;
    // Edited again while the dialog was open.
    fs::write(&path, "PORT=1\nAPI_TOKEN=tok-1\nNEW=typed later\n").unwrap();
    for keep in [KeepSide::Vault, KeepSide::File] {
        let synced = f.sync_preferring(Some(Preference {
            env_id: &env,
            file: &file,
            keep,
            seen: seen.as_deref(),
        }));
        assert_eq!(synced.files[0].state, FileState::Conflict);
        assert_eq!(synced.changes, []);
    }
    assert_eq!(read(&path), "PORT=1\nAPI_TOKEN=tok-1\nNEW=typed later\n");
    assert_eq!(f.values()[0].1, "2");
    // Nor without a revision, while the file is there.
    let synced = f.sync_preferring(Some(Preference {
        env_id: &env,
        file: &file,
        keep: KeepSide::Vault,
        seen: None,
    }));
    assert_eq!(synced.files[0].state, FileState::Conflict);
}

#[test]
fn history_keeps_only_the_latest_versions() {
    let mut f = Fixture::new();
    f.bind(".env");
    f.sync();
    for n in 0..15 {
        fs::write(f.path(".env"), format!("PORT={n}\nAPI_TOKEN=tok-1\n")).unwrap();
        f.sync();
    }
    let id = parse_id(&f.env).unwrap();
    let kept = f
        .vault
        .db
        .entry(id)
        .unwrap()
        .history
        .as_ref()
        .map_or(0, |history| history.get_entries().len());
    assert_eq!(kept, 10);
    // The newest are the ones kept, oldest first as KeePass keeps them.
    assert_eq!(
        history_ports(&f),
        ["4", "5", "6", "7", "8", "9", "10", "11", "12", "13"]
    );
}

fn port_of(version: &Entry) -> String {
    variables_of(version)
        .into_iter()
        .find(|var| var.name == "PORT")
        .map(|var| var.value.expose_secret().to_owned())
        .unwrap_or_default()
}

/// `PORT` of each earlier version of the fixture's environment, in the
/// order the entry keeps them.
fn history_ports(f: &Fixture) -> Vec<String> {
    let id = parse_id(&f.env).unwrap();
    let entry = f.vault.db.entry(id).unwrap();
    entry
        .history
        .as_ref()
        .map(|history| history.get_entries().iter().map(port_of).collect())
        .unwrap_or_default()
}

/// A day in 2020, as a version's time.
fn day(n: u32) -> chrono::NaiveDateTime {
    chrono::NaiveDate::from_ymd_opt(2020, 1, n)
        .unwrap()
        .and_hms_opt(0, 0, 0)
        .unwrap()
}

/// Gives the fixture's environment `versions` as its history, in that
/// order, as a file another app wrote would have them.
fn set_history(f: &mut Fixture, versions: Vec<Entry>) {
    let id = parse_id(&f.env).unwrap();
    let mut history = keepass::db::History::default();
    // Each one added goes in front.
    for version in versions.into_iter().rev() {
        history.add_entry(version);
    }
    f.vault.db.entry_mut(id).unwrap().history = Some(history);
}

/// The fixture's environment as it is now, as an earlier version made on
/// day `n`.
fn version_now(f: &Fixture, n: u32) -> Entry {
    let id = parse_id(&f.env).unwrap();
    let mut version: Entry = f.vault.db.entry(id).unwrap().clone();
    version.history = None;
    version.times.last_modification = Some(day(n));
    version
}

#[test]
fn history_is_kept_oldest_first_whatever_order_it_came_in() {
    for newest_first in [false, true] {
        let mut f = Fixture::new();
        f.vault.db.meta.history_max_items = Some(3);
        let mut versions: Vec<Entry> = (1..=3)
            .map(|n| {
                let mut version = version_now(&f, n);
                version.set("PORT", keepass::db::Value::unprotected(n.to_string()));
                version
            })
            .collect();
        // As KeePass and KeePassXC keep them, or as earlier versions of this
        // app did.
        if newest_first {
            versions.reverse();
        }
        set_history(&mut f, versions);
        f.set("PORT", "5", false);
        // The oldest went, the newest stayed, the one this change kept is
        // last.
        assert_eq!(history_ports(&f), ["2", "3", "3000"], "{newest_first}");
        f.set("PORT", "6", false);
        assert_eq!(history_ports(&f), ["3", "3000", "5"], "{newest_first}");
    }
}

#[test]
fn a_variable_written_again_gets_the_newest_flag_and_note() {
    for newest_first in [false, true] {
        let mut f = Fixture::new();
        let env = f.env.clone();
        let mut versions = Vec::new();
        for (n, secret, note) in [(1, false, "old"), (2, true, "new")] {
            f.vault
                .set_env_variable(
                    &env,
                    f.vault
                        .env_variables(&env)
                        .unwrap()
                        .iter()
                        .any(|var| var.name == "DB_HOST")
                        .then_some("DB_HOST"),
                    &EnvVarInput {
                        name: "DB_HOST".into(),
                        value: Some(s("db.internal")),
                        secret,
                        note: note.into(),
                    },
                )
                .unwrap();
            versions.push(version_now(&f, n));
        }
        f.vault.remove_env_variable(&env, "DB_HOST").unwrap();
        if newest_first {
            versions.reverse();
        }
        set_history(&mut f, versions);
        f.bind(".env");
        f.sync();
        fs::write(
            f.path(".env"),
            "PORT=3000\nAPI_TOKEN=tok-1\nDB_HOST=db.internal\n",
        )
        .unwrap();
        assert_eq!(f.sync().changes[0].added, ["DB_HOST"]);
        assert_eq!(db_host(&f), Some((true, "new".into())), "{newest_first}");
    }
}

#[test]
fn values_are_written_so_every_loader_reads_them_as_they_are() {
    let mut f = Fixture::new();
    fs::write(f.path(".env"), "PORT=3000\nAPI_TOKEN=\"tok-1\"\n").unwrap();
    f.bind(".env");
    f.sync();
    f.set("PASSWORD", "pa$word", true);
    f.set("API_TOKEN", "C:\\new", true);
    f.sync();
    assert_eq!(
        read(&f.path(".env")),
        "PORT=3000\nAPI_TOKEN='C:\\new'\nPASSWORD='pa$word'\n"
    );
}

#[test]
fn temporary_files_a_crash_left_are_swept() {
    let mut f = Fixture::new();
    f.bind(".env");
    let leftover = f.path(".env.sshkm-Ab12Cd.tmp");
    fs::write(&leftover, "API_TOKEN=tok-1\n").unwrap();
    fs::write(f.path(".env.local"), "X=1\n").unwrap();
    f.sync();
    assert!(!leftover.exists());
    assert!(f.path(".env.local").exists());
    assert!(!is_env_file_name(".env.sshkm-Ab12Cd.tmp"));
}

#[test]
fn revisions_made_with_another_vaults_key_are_kept() {
    let mut f = Fixture::new();
    f.bind(".env");
    f.sync();
    fs::remove_file(f.path(".env")).unwrap();
    // Another vault on this computer, used in between.
    let mut other = Fixture::new();
    other.state = f.state.clone();
    other.bind(".env");
    other.sync();
    // Back to the first: the file it wrote and someone deleted stays gone.
    f.state = other.state.clone();
    assert_eq!(f.sync().files[0].state, FileState::Missing);
    assert!(!f.path(".env").exists());
}

#[cfg(windows)]
#[test]
fn reparse_points_are_never_read() {
    let mut f = Fixture::new();
    let outside = f.dir.path().join("secret.env");
    fs::write(&outside, "KEEP=1\n").unwrap();
    // Making a link needs a right not every account has.
    if std::os::windows::fs::symlink_file(&outside, f.path(".env")).is_err() {
        return;
    }
    assert!(matches!(
        disk::read(&f.path(".env")),
        Disk::Refused(RefusedReason::Link)
    ));
    let env = f.env.clone();
    assert!(
        f.vault
            .bind_env_file(&env, &f.file(".env"), &f.ctx)
            .is_err()
    );
    fs::remove_file(f.path(".env")).unwrap();
    f.bind(".env");
    f.sync();
    fs::remove_file(f.path(".env")).unwrap();
    std::os::windows::fs::symlink_file(&outside, f.path(".env")).unwrap();
    f.set("PORT", "1", false);
    let synced = f.sync();
    assert_eq!(
        synced.files[0].state,
        FileState::Refused {
            reason: RefusedReason::Link
        }
    );
    assert_eq!(read(&outside), "KEEP=1\n");
}

#[test]
fn level_two_files_come_and_go_with_the_vault() {
    let mut f = Fixture::new();
    f.bind_at(".env", FileLevel::WhileUnlocked);
    let synced = f.sync();
    let path = f.path(".env");
    assert_eq!(read(&path), "PORT=3000\nAPI_TOKEN=tok-1\n");
    assert_eq!(synced.files[0].level, FileLevel::WhileUnlocked);
    assert_eq!(synced.files[0].state, FileState::InSync);
    assert_eq!(synced.unlocked.len(), 1);
    if cfg!(any(target_os = "macos", target_os = "linux", windows)) {
        // Where the file system keeps attributes: the temporary folder may
        // be one that doesn't (tmpfs on an older Linux).
        let kept_out = fsutil::is_kept_out_of_copies(&path);
        let supported = cfg!(target_os = "macos") || kept_out;
        assert!(!supported || kept_out);
    }

    // The vault locks: the file goes.
    let away = put_away(&synced);
    assert_eq!(away.removed, 1);
    assert_eq!(away.kept, []);
    assert!(!path.exists());
    // Unlocked again, it is to be written, not deleted.
    assert_eq!(f.states(), [FileState::VaultChanged]);

    // Unlocked again: written again, though the app wrote it before.
    let synced = f.sync();
    assert_eq!(synced.written.len(), 1);
    assert_eq!(read(&path), "PORT=3000\nAPI_TOKEN=tok-1\n");

    // A level-1 file next to it stays when the vault locks.
    f.bind(".env.local");
    let synced = f.sync();
    assert_eq!(synced.unlocked.len(), 1);
    assert_eq!(put_away(&synced).removed, 1);
    assert!(!path.exists());
    assert!(f.path(".env.local").exists());
}

#[test]
fn an_edit_reaches_the_vault_before_its_file_goes() {
    let mut f = Fixture::new();
    f.bind_at(".env", FileLevel::WhileUnlocked);
    f.sync();
    let path = f.path(".env");
    fs::write(&path, "PORT=3000\nAPI_TOKEN=tok-2\n").unwrap();
    // The last round before the lock takes the edit.
    let synced = f.sync();
    assert_eq!(synced.changes.len(), 1);
    assert_eq!(
        f.values(),
        owned(&[("PORT", "3000", false), ("API_TOKEN", "tok-2", true)])
    );
    assert_eq!(put_away(&synced).removed, 1);
    assert!(!path.exists());
}

#[test]
fn a_level_two_file_the_vault_cant_take_stays() {
    let mut f = Fixture::new();
    f.bind_at(".env", FileLevel::WhileUnlocked);
    f.sync();
    let path = f.path(".env");
    // A quote being typed: the vault can't take it.
    fs::write(&path, "PORT=3000\nAPI_TOKEN=\"tok-2\n").unwrap();
    let synced = f.sync();
    let away = put_away(&synced);
    assert_eq!(away.removed, 0);
    assert_eq!(away.kept.len(), 1);
    assert!(matches!(away.kept[0].state, FileState::Invalid { .. }));
    assert!(path.exists());

    // Both sides changed: it stays too.
    fs::write(&path, "PORT=3000\nAPI_TOKEN=tok-3\n").unwrap();
    f.set("PORT", "4000", false);
    let synced = f.sync();
    let away = put_away(&synced);
    assert_eq!(away.kept.len(), 1);
    assert_eq!(away.kept[0].state, FileState::Conflict);
    assert!(path.exists());

    // Changed after the round: as the user left it.
    f.keep(".env", KeepSide::Vault);
    let synced = f.sync();
    assert_eq!(synced.unlocked.len(), 1);
    std::thread::sleep(std::time::Duration::from_millis(20));
    fs::write(&path, "PORT=4000\nAPI_TOKEN=tok-4\n").unwrap();
    assert_eq!(put_away(&synced).removed, 0);
    assert!(path.exists());
}

#[test]
fn remote_environments_have_files_only_while_unlocked() {
    let mut f = Fixture::new();
    let env = f.env.clone();
    f.vault.set_env_kind(&env, EnvKind::Remote).unwrap();
    assert!(
        f.vault
            .bind_env_file(&env, &f.file(".env"), &f.ctx)
            .is_err()
    );
    let file = f.bind_at(".env", FileLevel::WhileUnlocked);
    // Binding keeps it remote.
    assert_eq!(f.vault.env_files(&env).unwrap().0, EnvKind::Remote);
    let synced = f.sync();
    assert_eq!(synced.files[0].state, FileState::InSync);
    assert!(f.path(".env").exists());
    assert!(
        f.vault
            .set_env_file_level(&env, &file, FileLevel::Always)
            .is_err()
    );

    // Made local, its file can be there all the time.
    f.vault.set_env_kind(&env, EnvKind::Local).unwrap();
    assert!(
        f.vault
            .set_env_file_level(&env, &file, FileLevel::Always)
            .unwrap()
    );
    assert!(
        !f.vault
            .set_env_file_level(&env, &file, FileLevel::Always)
            .unwrap()
    );
    let synced = f.sync();
    assert_eq!(synced.unlocked, []);
    assert_eq!(put_away(&synced).removed, 0);
    assert!(f.path(".env").exists());
    // With a level-1 file, it can't be remote.
    assert!(f.vault.set_env_kind(&env, EnvKind::Remote).is_err());
    let detail = f.vault.environment(&env).unwrap();
    assert_eq!(detail.files, std::slice::from_ref(&file));
    assert_eq!(detail.while_unlocked, []);
    f.vault
        .set_env_file_level(&env, &file, FileLevel::WhileUnlocked)
        .unwrap();
    assert_eq!(f.vault.environment(&env).unwrap().while_unlocked, [file]);
    f.vault.set_env_kind(&env, EnvKind::Remote).unwrap();
}

#[test]
fn older_versions_never_see_level_two_files() {
    let mut f = Fixture::new();
    f.bind(".env");
    f.bind_at(".env.local", FileLevel::WhileUnlocked);
    let entry = f.vault.env_entry(&f.env).unwrap();
    let Some(CustomDataValue::String(json)) = entry
        .custom_data
        .get(FILES_DATA)
        .and_then(|item| item.value.as_ref())
    else {
        panic!("no file list");
    };
    let data: Value = serde_json::from_str(json).unwrap();
    // `files` is the list older versions write; the other they keep as it is.
    assert_eq!(data["files"].as_array().unwrap().len(), 1);
    assert_eq!(data["files"][0]["path"], ".env");
    assert_eq!(data["unlocked"][0]["path"], ".env.local");
    // Unbinding finds it in either list.
    let env = f.env.clone();
    assert!(
        f.vault
            .unbind_env_file(&env, &f.file(".env.local"))
            .unwrap()
    );
    assert_eq!(f.vault.environment(&env).unwrap().files, [f.file(".env")]);
}

#[test]
fn a_level_two_file_no_longer_kept_in_step_goes() {
    let mut f = Fixture::new();
    f.bind_at(".env", FileLevel::WhileUnlocked);
    f.sync();
    let path = f.path(".env");
    assert!(path.exists());
    // Its environment goes to the recycle bin: the file goes too.
    let env = f.env.clone();
    f.vault.trash_environment(&env).unwrap();
    let synced = f.sync();
    assert!(matches!(
        synced.files[0].state,
        FileState::Inactive {
            reason: InactiveReason::InTrash
        }
    ));
    assert!(!path.exists());

    // One changed by hand stays.
    f.vault.restore_environment(&env).unwrap();
    f.sync();
    assert!(path.exists());
    fs::write(&path, "PORT=1\n").unwrap();
    f.vault.trash_environment(&env).unwrap();
    f.sync();
    assert!(path.exists());
}

#[test]
fn cloud_folders_that_leave_out_level_two_files_are_no_risk_for_them() {
    let mut f = Fixture::new();
    f.bind(".env");
    f.bind_at(".env.local", FileLevel::WhileUnlocked);
    f.sync();
    let services = |cloud: &CloudRoots| -> Vec<(String, Option<CloudService>)> {
        f.vault
            .env_files_overview(&f.ctx, &f.state, cloud, None)
            .files
            .into_iter()
            .map(|report| (report.status.file.path, report.cloud))
            .collect()
    };
    // Dropbox skips a file kept out of copies; OneDrive doesn't everywhere.
    let dropbox = CloudRoots::new(vec![(f.folder.clone(), CloudService::Dropbox)]);
    assert_eq!(
        services(&dropbox),
        [
            (".env".to_owned(), Some(CloudService::Dropbox)),
            (".env.local".to_owned(), None),
        ]
    );
    let onedrive = CloudRoots::new(vec![(f.folder.clone(), CloudService::OneDrive)]);
    assert_eq!(
        services(&onedrive),
        [
            (".env".to_owned(), Some(CloudService::OneDrive)),
            (".env.local".to_owned(), Some(CloudService::OneDrive)),
        ]
    );
}

#[test]
fn a_file_back_at_level_one_goes_back_to_backups() {
    let mut f = Fixture::new();
    let file = f.bind_at(".env", FileLevel::WhileUnlocked);
    f.sync();
    let path = f.path(".env");
    if !fsutil::is_kept_out_of_copies(&path) {
        // A file system that keeps no attributes: nothing to take off.
        let kept_by_system: bool = cfg!(target_os = "macos");
        assert!(!kept_by_system);
        return;
    }
    // As another computer would: only the binding changes.
    let env = f.env.clone();
    f.vault
        .set_env_file_level(&env, &file, FileLevel::Always)
        .unwrap();
    let synced = f.sync();
    assert_eq!(synced.unlocked, []);
    assert_eq!(synced.always.len(), 1);
    assert!(!fsutil::is_kept_out_of_copies(&path));
    // A level-1 file the app never kept out is left as it is.
    fsutil::keep_out_of_copies_at(&path);
    f.sync();
    assert!(fsutil::is_kept_out_of_copies(&path));
}

#[test]
fn a_folders_files_are_listed_for_ai_tools_rules() {
    let mut f = Fixture::new();
    f.bind("apps/web/.env.local");
    f.bind_at(".env", FileLevel::WhileUnlocked);
    let folder = f.folder_text.clone();
    assert_eq!(
        f.vault.env_files_in_folder(&folder),
        [".env", "apps/web/.env.local"]
    );
    assert_eq!(
        f.vault.env_files_in_folder("~/elsewhere"),
        Vec::<String>::new()
    );
    // Not those of an environment in the recycle bin.
    let env = f.env.clone();
    f.vault.trash_environment(&env).unwrap();
    assert_eq!(f.vault.env_files_in_folder(&folder), Vec::<String>::new());
}

impl Fixture {
    /// Another environment in the project, `name`, with the variables
    /// `vars`.
    fn other_env(&mut self, name: &str, vars: &[(&str, &str, bool)]) -> String {
        let id = self
            .vault
            .add_environment(&EnvInput {
                project: Some(self.project.clone()),
                part: String::new(),
                name: name.into(),
                notes: String::new(),
            })
            .unwrap();
        for (var, value, secret) in vars {
            self.vault
                .set_env_variable(
                    &id,
                    None,
                    &EnvVarInput {
                        name: (*var).into(),
                        value: Some(s(value)),
                        secret: *secret,
                        note: String::new(),
                    },
                )
                .unwrap();
        }
        id
    }

    fn values_of(&self, id: &str) -> Vec<(String, String, bool)> {
        self.vault
            .env_variables(id)
            .unwrap()
            .into_iter()
            .map(|var| (var.name, var.value.expose_secret().to_owned(), var.secret))
            .collect()
    }
}

#[test]
fn a_shared_value_changes_once_for_every_environment() {
    let mut f = Fixture::new();
    let env = f.env.clone();
    let other = f.other_env("test", &[("PORT", "4000", false)]);
    let shared = f
        .vault
        .share_env_variable(&env, "API_TOKEN", std::slice::from_ref(&other))
        .unwrap();
    assert_eq!(
        f.values_of(&other),
        owned(&[("PORT", "4000", false), ("API_TOKEN", "tok-1", true)])
    );
    let info = f.vault.environment(&other).unwrap();
    let token = info
        .variables
        .iter()
        .find(|var| var.name == "API_TOKEN")
        .unwrap();
    assert_eq!(token.shared.as_deref(), Some(shared.as_str()));
    assert!(!token.unresolved && !token.empty);

    // Changed in one environment: changed in both, once.
    f.set("API_TOKEN", "tok-2", true);
    assert_eq!(
        f.vault
            .env_value(&other, "API_TOKEN")
            .unwrap()
            .expose_secret(),
        "tok-2"
    );
    let listed = f.vault.shared_values();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "API_TOKEN");
    assert_eq!(listed[0].users.len(), 2);
    // The shared value isn't a login, nor a password the scanner names.
    assert!(f.vault.entries().iter().all(|entry| entry.id != shared));
    let secrets = f.vault.known_secrets();
    assert!(secrets.iter().all(|known| !matches!(&known.secret,
        crate::leaks::LeakSecret::Password { entry_id, .. } if *entry_id == shared)));
    let found: Vec<&str> = secrets
        .iter()
        .filter(|known| known.value.expose_secret() == "tok-2")
        .map(|known| match &known.secret {
            crate::leaks::LeakSecret::Variable { env_id, .. } => env_id.as_str(),
            crate::leaks::LeakSecret::Password { .. } => "",
        })
        .collect();
    assert_eq!(found.len(), 2);
    assert!(found.contains(&env.as_str()) && found.contains(&other.as_str()));

    // An import over it changes it too.
    f.vault
        .import_env_variables(
            &other,
            &[EnvVariable {
                name: "API_TOKEN".into(),
                value: s("tok-3"),
                secret: true,
                note: String::new(),
            }],
        )
        .unwrap();
    assert_eq!(
        f.vault
            .env_value(&env, "API_TOKEN")
            .unwrap()
            .expose_secret(),
        "tok-3"
    );

    // One environment gets its own value: the other keeps the shared one.
    f.vault.unshare_env_variable(&other, "API_TOKEN").unwrap();
    f.set("API_TOKEN", "tok-4", true);
    assert_eq!(
        f.vault
            .env_value(&other, "API_TOKEN")
            .unwrap()
            .expose_secret(),
        "tok-3"
    );
    assert_eq!(f.vault.shared_values()[0].users.len(), 1);

    // Deleted: each that used it keeps a copy.
    f.vault.delete_shared_value(&shared).unwrap();
    assert_eq!(
        f.vault
            .env_value(&env, "API_TOKEN")
            .unwrap()
            .expose_secret(),
        "tok-4"
    );
    let info = f.vault.environment(&env).unwrap();
    assert!(info.variables.iter().all(|var| var.shared.is_none()));
    assert!(f.vault.shared_values()[0].in_trash);
}

#[test]
fn a_file_edit_of_a_shared_value_reaches_every_file_and_undoes() {
    let mut f = Fixture::new();
    let env = f.env.clone();
    let other = f.other_env("local", &[("PORT", "4000", false)]);
    f.vault
        .share_env_variable(&env, "API_TOKEN", std::slice::from_ref(&other))
        .unwrap();
    f.bind(".env");
    f.vault
        .bind_env_file(&other, &f.file(".env.test"), &f.ctx)
        .unwrap();
    f.sync();
    // The files hold values, never references.
    assert_eq!(read(&f.path(".env")), "PORT=3000\nAPI_TOKEN=tok-1\n");
    assert_eq!(read(&f.path(".env.test")), "PORT=4000\nAPI_TOKEN=tok-1\n");

    fs::write(f.path(".env"), "PORT=3000\nAPI_TOKEN=tok-9\n").unwrap();
    let synced = f.sync();
    assert_eq!(synced.changes.len(), 1);
    let change = &synced.changes[0];
    assert_eq!(change.changed, ["API_TOKEN"]);
    assert_eq!(change.undo.shared.len(), 1);
    // The other environment's file follows in the same round.
    assert_eq!(read(&f.path(".env.test")), "PORT=4000\nAPI_TOKEN=tok-9\n");
    // The variable still uses the shared value.
    let raw = f.vault.raw_env_variables(&env).unwrap();
    let token = raw.iter().find(|var| var.name == "API_TOKEN").unwrap();
    assert!(super::super::shared::referenced(token.value.expose_secret()).is_some());

    let undo = change.undo.clone();
    f.vault.undo_env_file_change(&undo).unwrap();
    f.sync();
    assert_eq!(read(&f.path(".env")), "PORT=3000\nAPI_TOKEN=tok-1\n");
    assert_eq!(read(&f.path(".env.test")), "PORT=4000\nAPI_TOKEN=tok-1\n");
    // Twice is once too many.
    assert!(f.vault.undo_env_file_change(&undo).is_err());
}

#[test]
fn a_shared_value_that_is_gone_holds_its_files() {
    let mut f = Fixture::new();
    let env = f.env.clone();
    let other = f.other_env("test", &[]);
    let shared = f
        .vault
        .share_env_variable(&env, "API_TOKEN", std::slice::from_ref(&other))
        .unwrap();
    f.bind(".env");
    f.sync();
    // Deleted for good elsewhere, without giving the environments copies.
    f.vault.trash_entry(&shared).unwrap();
    assert_eq!(
        f.vault
            .env_value(&env, "API_TOKEN")
            .unwrap()
            .expose_secret(),
        "tok-1"
    );
    f.vault.delete_entry(&shared).unwrap();
    let info = f.vault.environment(&env).unwrap();
    let token = info
        .variables
        .iter()
        .find(|var| var.name == "API_TOKEN")
        .unwrap();
    assert!(token.unresolved);
    assert!(f.vault.env_value(&env, "API_TOKEN").is_err());
    fs::write(f.path(".env"), "PORT=3001\nAPI_TOKEN=tok-1\n").unwrap();
    let synced = f.sync();
    assert_eq!(synced.changes, []);
    assert!(matches!(synced.files[0].state, FileState::Failed { .. }));
    // The file is as the user left it.
    assert_eq!(read(&f.path(".env")), "PORT=3001\nAPI_TOKEN=tok-1\n");
    // A value of its own sets it free.
    f.set("API_TOKEN", "tok-5", true);
    let synced = f.sync();
    assert_ne!(synced.files[0].state, FileState::InSync);
    let _ = other;
}
