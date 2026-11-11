//! Managed `.env` files: an environment written to files in the folders of
//! the projects that hold it, and kept in step with them both ways.
//!
//! An environment is `local` (the developer's own machine) or `remote`
//! (everything else); only a local one gets files. Its files are kept on its
//! entry, as custom data `sshkm.env.files`, by a project folder as the
//! project keeps it (`~/code/shop`) and a path in it (`apps/web/.env.local`),
//! so they go to the user's other computers with the vault. A file is only
//! ever written inside a folder of a project that holds the environment, as
//! the binding the user made names it, never through a symbolic link, and
//! with permissions for its owner only ([`disk`]). A folder that isn't on
//! this computer is reported, never made.
//!
//! **In step.** Each computer remembers, per file, a revision of the
//! variables the file and the vault last agreed on ([`SyncState`]): a keyed
//! hash, never a value, made with a key kept in the vault. Comparing the
//! file's variables and the vault's with it says which side changed:
//!
//! - only the file → its variables go to the vault ([`Vault::env_files_pull`]):
//!   changed values, new names, and removed lines remove variables. The
//!   entry's history keeps the previous version, and the change comes back
//!   with what it takes to undo it ([`Vault::undo_env_file_change`]);
//! - only the vault → the file is rewritten in place ([`super::document`]),
//!   touching only the lines of variables that changed
//!   ([`Vault::env_files_push`]);
//! - both, differently, or the two differ with no revision to go by → a
//!   conflict: nothing changes until the user keeps one side.
//!
//! A file the app wrote and someone deleted is reported, not written again;
//! one never written on this computer is written. A file whose lines can't
//! all be read (a quote that never closes, a value too long) changes
//! nothing either way until it is fixed, so a typo can't empty the vault;
//! nor does a file left without a variable, which is a conflict.
//! Values never reach errors or logs.

mod cloud;
mod disk;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use base64ct::{Base64, Encoding};
use hmac::{Hmac, Mac};
use keepass::db::{CustomDataItem, CustomDataValue, Entry, Times};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub use self::cloud::{CloudRoots, CloudService};
use self::disk::{Disk, Target};
pub use self::disk::{find_env_files, ignore_in_git};
use super::document::EnvDocument;
use super::dotenv::{self, ParseProblem, ParsedEnv, ProblemKind};
use super::{EnvComparison, EnvVariable, is_environment, looks_secret, variables_of};
pub use crate::leaks::GitState;
use crate::vault::projects::{self, Project};
use crate::vault::{Vault, in_group, parse_id};
use crate::{Error, Result, fsutil};

/// Custom data of an environment's entry: its kind and files.
const FILES_DATA: &str = "sshkm.env.files";
/// Custom data of the database: the key revisions are made with.
const REVISION_KEY: &str = "sshkm.env.key";
/// Most files one environment is written to.
pub const MAX_FILES: usize = 32;
/// Longest path of a file in its folder, in bytes.
const MAX_PATH: usize = 1024;
/// Words that make a file a template to commit (`.env.example`), which
/// never gets values.
const TEMPLATE_WORDS: [&str; 6] = ["example", "sample", "template", "dist", "defaults", "tmpl"];

/// Where an environment is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum EnvKind {
    /// On the developer's own computer: it can have files.
    Local,
    /// A shared server, staging, production: used through the app's
    /// terminal, without files.
    Remote,
}

impl EnvKind {
    /// The kind an environment has until the user sets one: `local`, `dev`
    /// and `development` are local, anything else remote.
    pub fn from_name(name: &str) -> Self {
        match name.trim().to_lowercase().as_str() {
            "local" | "dev" | "development" => Self::Local,
            _ => Self::Remote,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Remote => "remote",
        }
    }

    /// A stored kind; one this version doesn't know is taken as remote,
    /// which writes nothing.
    fn parse(text: &str) -> Self {
        if text == "local" {
            Self::Local
        } else {
            Self::Remote
        }
    }
}

/// A file an environment is written to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct EnvFile {
    /// A folder of a project that holds the environment, as the project
    /// keeps it: `~/code/shop`.
    pub folder: String,
    /// The file in it, with `/` between folders: `.env`,
    /// `apps/web/.env.local`.
    pub path: String,
}

/// What an environment's entry keeps about its files. Fields of later
/// versions are kept as they are.
#[derive(Debug, Default, Serialize, Deserialize)]
struct FilesData {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    files: Vec<StoredFile>,
    #[serde(flatten)]
    rest: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredFile {
    folder: String,
    path: String,
    #[serde(flatten)]
    rest: Map<String, Value>,
}

impl StoredFile {
    fn file(&self) -> EnvFile {
        EnvFile {
            folder: self.folder.clone(),
            path: self.path.clone(),
        }
    }
}

/// Why a file isn't kept in step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum InactiveReason {
    /// The environment is remote now.
    Remote,
    /// The environment is in the recycle bin.
    InTrash,
    /// No project holds both the environment and the folder.
    NotInProject,
}

/// Why a file is never written or read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum RefusedReason {
    /// It is a symbolic link.
    Link,
    /// It is a folder, a pipe or a device.
    NotAFile,
    /// A link on the way leads out of the project's folder.
    Outside,
    /// It is one of the vault's files or in the SSH folder.
    Protected,
}

/// Where a file stands against the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum FileState {
    /// It holds what the vault holds.
    InSync,
    /// It changed since it was last in step; its changes go to the vault.
    FileChanged,
    /// The vault changed since; the file is to be rewritten.
    VaultChanged,
    /// Both changed, or they differ with nothing to go by: the user keeps
    /// one side.
    Conflict,
    /// It isn't there: deleted after the app wrote it.
    Missing,
    /// Its folder isn't on this computer.
    FolderMissing,
    Inactive {
        reason: InactiveReason,
    },
    Refused {
        reason: RefusedReason,
    },
    /// Lines that can't be read, by number: nothing changes either way
    /// until they are fixed.
    Invalid {
        problems: Vec<ParseProblem>,
    },
    /// Another file binding names the same file; that one is kept in step.
    Duplicate,
    /// Reading or writing it failed.
    Failed {
        message: String,
    },
}

/// A file of an environment and where it stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct EnvFileStatus {
    pub env_id: String,
    /// The environment's group under `Environments`.
    pub group: String,
    pub env_name: String,
    pub file: EnvFile,
    /// The file on this computer, when its folder is a full path here.
    pub location: Option<PathBuf>,
    pub state: FileState,
}

/// What an edit of a file changed in the vault, by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct EnvFileChange {
    pub env_id: String,
    pub group: String,
    pub env_name: String,
    pub file: EnvFile,
    pub added: Vec<String>,
    pub changed: Vec<String>,
    pub removed: Vec<String>,
    /// What [`Vault::undo_env_file_change`] takes to undo it.
    pub undo: EnvUndo,
}

/// An edit to undo: the environment's variables before and after it, as
/// keyed hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct EnvUndo {
    pub env_id: String,
    pub before: String,
    pub after: String,
}

/// Which side a conflict keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum KeepSide {
    /// The file's variables go to the vault.
    File,
    /// The vault's variables are written to the file, which is written
    /// again if it is missing.
    Vault,
}

/// One file to settle a certain way.
#[derive(Debug, Clone, Copy)]
pub struct Preference<'a> {
    pub env_id: &'a str,
    pub file: &'a EnvFile,
    pub keep: KeepSide,
}

impl Preference<'_> {
    fn keeps(&self, bound: &Bound, side: KeepSide) -> bool {
        self.keep == side && self.env_id == bound.env_id && *self.file == bound.file
    }
}

/// What one round of keeping files in step did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct EnvFilesSynced {
    /// Edits of files saved to the vault.
    pub changes: Vec<EnvFileChange>,
    /// Files written from the vault.
    pub written: Vec<EnvFileStatus>,
    /// Every file and where it stands now.
    pub files: Vec<EnvFileStatus>,
}

/// A template next to a file (`.env.example`) and the names it sets that
/// the environment lacks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct ExampleCheck {
    /// The template's name: `.env.example`.
    pub file: String,
    pub missing: Vec<String>,
}

/// What Git makes of a file, and the top folder of its working tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct GitInfo {
    /// Untracked means the next `git add .` takes it along; tracked means
    /// ignoring it doesn't take it out.
    pub state: GitState,
    pub repository: Option<PathBuf>,
}

/// A file of an environment for the management center.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct EnvFileReport {
    #[serde(flatten)]
    #[cfg_attr(feature = "ts", ts(flatten))]
    pub status: EnvFileStatus,
    /// The projects (by id) that hold the environment and the folder.
    pub projects: Vec<String>,
    /// The cloud service that copies the file's folder, if one does.
    pub cloud: Option<CloudService>,
    /// What a template next to it sets that the environment lacks.
    pub example: Option<ExampleCheck>,
    /// What Git makes of it; `None` when not looked at.
    pub git: Option<GitInfo>,
}

/// A `.env` file in a project's folder that no environment is written to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct UnmanagedEnvFile {
    /// The project (by id) whose folder holds it.
    pub project: String,
    pub file: EnvFile,
    pub location: PathBuf,
    pub cloud: Option<CloudService>,
    pub git: Option<GitInfo>,
}

/// The management center: every file of every environment, or of one
/// project, and the `.env` files found in the projects' folders that no
/// environment is written to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct EnvFilesOverview {
    pub files: Vec<EnvFileReport>,
    pub unmanaged: Vec<UnmanagedEnvFile>,
    /// A folder was too large to look through to the end.
    pub truncated: bool,
}

/// What the first half of a round did in the vault ([`Vault::env_files_pull`]):
/// to save before the second half writes any file.
#[derive(Debug, Default)]
pub struct Pulled {
    /// The vault changed and must be saved.
    pub vault_changed: bool,
    pub changes: Vec<EnvFileChange>,
    /// New revisions for [`SyncState`], by file, once the vault is saved.
    updates: Vec<(String, String)>,
}

/// Where this computer's files and the vault last agreed: a revision per
/// file. Kept by the app, one per computer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncState {
    /// Which key the revisions were made with.
    #[serde(default)]
    key: String,
    #[serde(default)]
    files: BTreeMap<String, String>,
}

impl SyncState {
    /// The state kept at `path`; empty if there is none or it can't be read.
    pub fn load(path: &Path) -> Self {
        fsutil::read_limited(path, 16 * 1024 * 1024)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    /// Keeps the state at `path`, readable by this user only.
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_vec(self).map_err(|e| Error::Parse(format!("{e}")))?;
        if std::fs::read(path).is_ok_and(|current| current == json) {
            return Ok(());
        }
        fsutil::atomic_write(path, &json, 0o600)
    }

    fn base(&self, key_id: &str, file: &str) -> Option<&str> {
        (self.key == key_id)
            .then(|| self.files.get(file).map(String::as_str))
            .flatten()
    }
}

/// What finding files on this computer needs.
#[derive(Debug, Clone)]
pub struct FilesContext {
    /// The home folder, for folders kept as `~/…`.
    pub home: Option<PathBuf>,
    /// `~/.ssh`, where no file is ever written.
    pub ssh_dir: PathBuf,
}

/// A file binding with its environment.
#[derive(Debug, Clone)]
struct Bound {
    env_id: String,
    group: String,
    env_name: String,
    kind: EnvKind,
    in_trash: bool,
    file: EnvFile,
}

impl Bound {
    /// How [`SyncState`] knows the file: no part has a line break.
    fn state_key(&self) -> String {
        format!("{}\n{}\n{}", self.env_id, self.file.folder, self.file.path)
    }

    fn status(&self, location: Option<PathBuf>, state: FileState) -> EnvFileStatus {
        EnvFileStatus {
            env_id: self.env_id.clone(),
            group: self.group.clone(),
            env_name: self.env_name.clone(),
            file: self.file.clone(),
            location,
            state,
        }
    }
}

/// A file found where a binding points, or why it can't be used.
type Located = std::result::Result<Target, FileState>;

/// Checks a file binding and puts its path in one form: parts between
/// `/`, each a plain name, the last a `.env` file's name that isn't a
/// template ([`is_env_file_name`]).
pub fn check_env_file(file: &EnvFile) -> Result<EnvFile> {
    if !projects::is_valid_member(&projects::ProjectMember::Folder {
        path: file.folder.clone(),
    }) {
        return Err(Error::invalid("not a project folder"));
    }
    let parts: Vec<&str> = file.path.split(['/', '\\']).collect();
    let bad_part = |part: &&str| {
        part.is_empty()
            || *part == "."
            || *part == ".."
            || part.len() > 255
            || part.trim() != *part
            || part.eq_ignore_ascii_case(".git")
            || part.chars().any(|c| c.is_control() || c == ':')
    };
    if file.path.len() > MAX_PATH || parts.iter().any(bad_part) {
        return Err(Error::invalid(format!(
            "not a file in a folder: {:?}",
            file.path.chars().take(64).collect::<String>()
        )));
    }
    let name = parts.last().copied().unwrap_or_default();
    if !is_env_file_name(name) {
        return Err(Error::invalid(format!(
            "{name:?} isn't a .env file's name, or it is a template to commit"
        )));
    }
    Ok(EnvFile {
        folder: file.folder.clone(),
        path: parts.join("/"),
    })
}

/// A name an environment's file can have: `.env`, `.env.local`,
/// `.env.development.local`, `app.env`, `.dev.vars`; not a template to
/// commit (`.env.example`, `.env.sample`, `example.env`…) nor `.envrc`,
/// which is a shell script.
pub fn is_env_file_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    let env_like = lower == ".env"
        || lower.starts_with(".env.")
        || Path::new(&lower)
            .extension()
            .is_some_and(|extension| extension == "env")
        || lower == ".dev.vars";
    env_like && !is_template_name(&lower)
}

/// `.env.example`, `.env.local.sample`, `example.env`, `.env.defaults`…
pub fn is_template_name(name: &str) -> bool {
    name.to_lowercase()
        .split('.')
        .any(|part| TEMPLATE_WORDS.contains(&part))
}

fn files_data(entry: &Entry) -> Result<FilesData> {
    match entry
        .custom_data
        .get(FILES_DATA)
        .and_then(|item| item.value.as_ref())
    {
        Some(CustomDataValue::String(json)) => serde_json::from_str(json)
            .map_err(|_| Error::invalid("the environment's file list can't be read")),
        _ => Ok(FilesData::default()),
    }
}

/// An environment's kind: as set, else from its name.
pub(super) fn kind_of(entry: &Entry) -> EnvKind {
    files_data(entry)
        .ok()
        .and_then(|data| data.kind)
        .map_or_else(
            || EnvKind::from_name(entry.get(keepass::db::fields::TITLE).unwrap_or_default()),
            |kind| EnvKind::parse(&kind),
        )
}

/// An environment's files, in the order they were added.
pub(super) fn files_of(entry: &Entry) -> Vec<EnvFile> {
    files_data(entry)
        .map(|data| data.files.iter().map(StoredFile::file).collect())
        .unwrap_or_default()
}

/// The variables as names and values.
fn pairs(vars: &[EnvVariable]) -> Vec<(&str, &str)> {
    vars.iter()
        .map(|var| (var.name.as_str(), var.value.expose_secret()))
        .collect()
}

fn parsed_pairs(parsed: &ParsedEnv) -> Vec<(&str, &str)> {
    parsed
        .vars
        .iter()
        .map(|var| (var.name.as_str(), var.value.as_str()))
        .collect()
}

/// A keyed hash of a set of variables, whatever their order: the same
/// names and values give the same revision.
fn revision(key: &[u8; 32], vars: &[(&str, &str)]) -> String {
    let mut sorted = vars.to_vec();
    sorted.sort_unstable();
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC takes any key length"));
    for (name, value) in sorted {
        for part in [name, value] {
            mac.update(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
            mac.update(part.as_bytes());
        }
    }
    Base64::encode_string(&mac.finalize().into_bytes())
}

/// Which key a [`SyncState`] was made with: the start of its hash.
fn key_id(key: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    Sha256::digest(key)[..8]
        .iter()
        .fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// Lines whose loss would remove variables from the vault: a quote that
/// never closes takes every line after it, and a value too long or after
/// too many is left out. A word without `=` or a name a shell can't take
/// sets nothing the vault has, so it doesn't count.
fn blocking(parsed: &ParsedEnv) -> Option<Vec<ParseProblem>> {
    let problems: Vec<ParseProblem> = parsed
        .problems
        .iter()
        .filter(|problem| {
            matches!(
                problem.kind,
                ProblemKind::Unterminated
                    | ProblemKind::TrailingText
                    | ProblemKind::TooLong
                    | ProblemKind::TooMany
            )
        })
        .cloned()
        .collect();
    (!problems.is_empty()).then_some(problems)
}

/// A file without a variable left, of an environment that has some: what
/// an editor that writes in place leaves for a moment, or a mistake. It
/// would remove every variable, so the user says so first, as for a
/// conflict.
fn emptied(file: &ParsedEnv, vault: &[EnvVariable]) -> bool {
    file.vars.is_empty() && !vault.is_empty()
}

/// The variables an environment has after taking a file's: the file's
/// values and names, in the vault's order with new ones last; a variable
/// keeps its secret flag and note, a new one is secret if it looks so.
fn take_file(vault: &[EnvVariable], file: &ParsedEnv) -> (Vec<EnvVariable>, FileEdit) {
    let mut edit = FileEdit::default();
    let mut out = Vec::with_capacity(file.vars.len());
    for var in vault {
        match file.vars.iter().find(|other| other.name == var.name) {
            Some(other) => {
                if other.value.as_str() != var.value.expose_secret() {
                    edit.changed.push(var.name.clone());
                }
                out.push(EnvVariable {
                    name: var.name.clone(),
                    value: SecretString::from(other.value.as_str()),
                    secret: var.secret,
                    note: var.note.clone(),
                });
            }
            None => edit.removed.push(var.name.clone()),
        }
    }
    for other in &file.vars {
        if !vault.iter().any(|var| var.name == other.name) {
            edit.added.push(other.name.clone());
            out.push(EnvVariable {
                name: other.name.clone(),
                value: SecretString::from(other.value.as_str()),
                secret: looks_secret(&other.name, &other.value),
                note: String::new(),
            });
        }
    }
    (out, edit)
}

#[derive(Default)]
struct FileEdit {
    added: Vec<String>,
    changed: Vec<String>,
    removed: Vec<String>,
}

/// Compares two sets of variables by name and value.
fn compare(left: &[(&str, &str)], right: &[(&str, &str)]) -> EnvComparison {
    let mut comparison = EnvComparison::default();
    for (name, value) in left {
        match right.iter().find(|(other, _)| other == name) {
            None => comparison.only_left.push((*name).to_owned()),
            Some((_, other)) if other == value => comparison.same.push((*name).to_owned()),
            Some(_) => comparison.changed.push((*name).to_owned()),
        }
    }
    comparison.only_right = right
        .iter()
        .filter(|(name, _)| !left.iter().any(|(other, _)| other == name))
        .map(|(name, _)| (*name).to_owned())
        .collect();
    comparison
}

impl Vault {
    /// An environment's kind and files.
    pub fn env_files(&self, id: &str) -> Result<(EnvKind, Vec<EnvFile>)> {
        let entry = self.env_entry(id)?;
        Ok((kind_of(&entry), files_of(&entry)))
    }

    /// Makes an environment local or remote. A remote one has no files, so
    /// its files are to be removed first.
    pub fn set_env_kind(&mut self, id: &str, kind: EnvKind) -> Result<()> {
        let entry = self.env_entry(id)?;
        let mut data = files_data(&entry)?;
        if kind == EnvKind::Remote && !data.files.is_empty() {
            return Err(Error::invalid(
                "a remote environment has no files: remove its files first",
            ));
        }
        data.kind = Some(kind.as_str().to_owned());
        self.put_files_data(id, &data)
    }

    /// Writes `file` from now on with the environment `id`: a local one,
    /// outside the recycle bin, in a folder of a project that holds it.
    /// Makes the environment local for good, so a new name doesn't take
    /// its files away. Fails for a file another binding names already,
    /// here or through another folder that is the same on disk, and for one
    /// that can never be written ([`RefusedReason`]). Returns the binding as
    /// kept.
    pub fn bind_env_file(
        &mut self,
        id: &str,
        file: &EnvFile,
        ctx: &FilesContext,
    ) -> Result<EnvFile> {
        let file = check_env_file(file)?;
        let entry = self.env_entry(id)?;
        let mut data = files_data(&entry)?;
        if in_group(entry.parent().id(), self.db.meta.recyclebin_uuid, &self.db) {
            return Err(Error::invalid("restore the environment first"));
        }
        if kind_of(&entry) == EnvKind::Remote {
            return Err(Error::invalid(
                "a remote environment has no files: make it local first",
            ));
        }
        let group = self.env_summary(&entry).project;
        let projects = self.projects();
        if !holds(&projects, &group, &file.folder) {
            return Err(Error::invalid(
                "the folder isn't in a project that holds the environment",
            ));
        }
        if data.files.iter().any(|stored| stored.file() == file) {
            return Err(Error::AlreadyExists(file.path));
        }
        if data.files.len() >= MAX_FILES {
            return Err(Error::invalid(format!(
                "an environment is written to at most {MAX_FILES} files"
            )));
        }
        match disk::locate(&file, ctx, &self.paths) {
            Ok(target) => {
                let others = self.bound();
                let taken = others.iter().any(|other| {
                    disk::locate(&other.file, ctx, &self.paths)
                        .is_ok_and(|theirs| theirs.identity == target.identity)
                });
                if taken {
                    return Err(Error::AlreadyExists(format!(
                        "{} is written by another environment's file",
                        target.display.display()
                    )));
                }
            }
            Err(FileState::Refused { reason }) => {
                return Err(Error::invalid(match reason {
                    RefusedReason::Link => "the file is a symbolic link",
                    RefusedReason::NotAFile => "that is a folder, a pipe or a device, not a file",
                    RefusedReason::Outside => "a link leads out of the project's folder",
                    RefusedReason::Protected => "the app never writes there",
                }));
            }
            // A folder that isn't on this computer is fine: the binding is
            // for every computer of the user's.
            Err(_) => {}
        }
        data.kind = Some(EnvKind::Local.as_str().to_owned());
        data.files.push(StoredFile {
            folder: file.folder.clone(),
            path: file.path.clone(),
            rest: Map::new(),
        });
        self.ensure_revision_key();
        self.put_files_data(id, &data)?;
        Ok(file)
    }

    /// Stops writing `file` with the environment. The file stays as it is.
    /// Returns whether it was bound.
    pub fn unbind_env_file(&mut self, id: &str, file: &EnvFile) -> Result<bool> {
        let entry = self.env_entry(id)?;
        let mut data = files_data(&entry)?;
        let before = data.files.len();
        data.files.retain(|stored| stored.file() != *file);
        if data.files.len() == before {
            return Ok(false);
        }
        self.put_files_data(id, &data)?;
        Ok(true)
    }

    /// Deletes the file of a binding, only if it holds exactly what the
    /// vault has, so nothing is lost. Returns whether there was one.
    pub fn delete_env_file(&self, id: &str, file: &EnvFile, ctx: &FilesContext) -> Result<bool> {
        let bound = self
            .bound()
            .into_iter()
            .find(|bound| bound.env_id == id && bound.file == *file)
            .ok_or_else(|| Error::NotFound(file.path.clone()))?;
        let target = disk::locate(&bound.file, ctx, &self.paths)
            .map_err(|_| Error::invalid("the file can't be reached"))?;
        let text = match disk::read(&target.real) {
            Disk::Missing => return Ok(false),
            Disk::Text(text) => text,
            Disk::Refused(_) | Disk::Failed(_) => {
                return Err(Error::invalid("the file can't be read"));
            }
        };
        let vars = self.env_variables(id)?;
        let parsed = dotenv::parse(&text);
        let same = {
            let mut file_vars = parsed_pairs(&parsed);
            let mut vault_vars = pairs(&vars);
            file_vars.sort_unstable();
            vault_vars.sort_unstable();
            file_vars == vault_vars
        };
        if !same {
            return Err(Error::Conflict(target.display.display().to_string()));
        }
        disk::remove(&target)?;
        Ok(true)
    }

    /// Every file and where it stands, without changing anything.
    pub fn env_files_status(&self, ctx: &FilesContext, state: &SyncState) -> Vec<EnvFileStatus> {
        // Without a key yet, nothing was ever in step here: a key made up
        // for the comparison matches no revision kept.
        let key = self.revision_key().unwrap_or_else(|| {
            let mut key = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(key.as_mut());
            key
        });
        let id = key_id(&key);
        self.plan(ctx)
            .into_iter()
            .map(|(bound, located)| match located {
                Err(state) => bound.status(None, state),
                Ok(target) => {
                    let base = state.base(&id, &bound.state_key()).map(str::to_owned);
                    let (file_state, _) =
                        self.settle(&key, &bound, &target, base.as_deref(), None, false);
                    bound.status(Some(target.display.clone()), file_state)
                }
            })
            .collect()
    }

    /// The first half of keeping files in step: the edits of files whose
    /// vault side didn't change since go to the vault, in memory. The vault
    /// is to be saved before [`Self::env_files_push`] writes any file, so
    /// a save that fails can't leave files with values the vault lost.
    /// `prefer` takes one file's variables whatever changed.
    pub fn env_files_pull(
        &mut self,
        ctx: &FilesContext,
        state: &SyncState,
        prefer: Option<Preference<'_>>,
    ) -> Result<Pulled> {
        let mut pulled = Pulled::default();
        let plan = self.plan(ctx);
        if plan.is_empty() {
            return Ok(pulled);
        }
        pulled.vault_changed = self.ensure_revision_key();
        let key = self
            .revision_key()
            .ok_or_else(|| Error::NotFound("the files' key".into()))?;
        let id = key_id(&key);
        for (bound, located) in plan {
            let Ok(target) = located else { continue };
            let Disk::Text(text) = disk::read(&target.real) else {
                continue;
            };
            let parsed = dotenv::parse(&text);
            if blocking(&parsed).is_some() {
                continue;
            }
            let vault = self.env_variables(&bound.env_id)?;
            let file_rev = revision(&key, &parsed_pairs(&parsed));
            let vault_rev = revision(&key, &pairs(&vault));
            if file_rev == vault_rev {
                pulled.updates.push((bound.state_key(), vault_rev));
                continue;
            }
            let base = state.base(&id, &bound.state_key());
            let wanted = prefer.is_some_and(|p| p.keeps(&bound, KeepSide::File));
            if !wanted && (base != Some(vault_rev.as_str()) || emptied(&parsed, &vault)) {
                continue;
            }
            let (after, edit) = take_file(&vault, &parsed);
            self.edit_variables(&bound.env_id, |vars| {
                *vars = after;
                Ok(())
            })?;
            let after_rev = revision(&key, &pairs(&self.env_variables(&bound.env_id)?));
            pulled.updates.push((bound.state_key(), after_rev.clone()));
            pulled.changes.push(EnvFileChange {
                env_id: bound.env_id.clone(),
                group: bound.group.clone(),
                env_name: bound.env_name.clone(),
                file: bound.file.clone(),
                added: edit.added,
                changed: edit.changed,
                removed: edit.removed,
                undo: EnvUndo {
                    env_id: bound.env_id.clone(),
                    before: vault_rev,
                    after: after_rev,
                },
            });
            pulled.vault_changed = true;
        }
        Ok(pulled)
    }

    /// The second half, once the vault is saved: files whose vault side
    /// changed are rewritten in place, files never written on this computer
    /// are written, and `state` learns where each file and the vault agree
    /// now. `prefer` writes one file from the vault whatever changed, and
    /// writes it again if it is missing.
    pub fn env_files_push(
        &self,
        ctx: &FilesContext,
        state: &mut SyncState,
        pulled: Pulled,
        prefer: Option<Preference<'_>>,
    ) -> EnvFilesSynced {
        let mut synced = EnvFilesSynced {
            changes: pulled.changes,
            ..EnvFilesSynced::default()
        };
        let plan = self.plan(ctx);
        let Some(key) = self.revision_key() else {
            synced.files = self.env_files_status(ctx, state);
            return synced;
        };
        let id = key_id(&key);
        if state.key != id {
            state.key = id;
            state.files.clear();
        }
        let known: BTreeSet<String> = plan.iter().map(|(bound, _)| bound.state_key()).collect();
        state.files.retain(|file, _| known.contains(file));
        for (file, revision) in pulled.updates {
            state.files.insert(file, revision);
        }
        for (bound, located) in plan {
            let status = match located {
                Err(file_state) => bound.status(None, file_state),
                Ok(target) => {
                    let key_of = bound.state_key();
                    let base = state.files.get(&key_of).cloned();
                    let (file_state, agreed) =
                        self.settle(&key, &bound, &target, base.as_deref(), prefer, true);
                    if let Some(agreed) = agreed {
                        state.files.insert(key_of, agreed.revision);
                        let status = bound.status(Some(target.display.clone()), file_state);
                        if agreed.written {
                            synced.written.push(status.clone());
                        }
                        status
                    } else {
                        bound.status(Some(target.display.clone()), file_state)
                    }
                }
            };
            synced.files.push(status);
        }
        synced
    }

    /// Puts back an environment's variables as they were before an edit
    /// of a file was saved, if nothing changed them since: from the entry's
    /// history, with their secret flags and notes. The files are rewritten
    /// by the next [`Self::env_files_push`].
    pub fn undo_env_file_change(&mut self, undo: &EnvUndo) -> Result<()> {
        let key = self
            .revision_key()
            .ok_or_else(|| Error::NotFound("nothing to undo".into()))?;
        let previous = {
            let entry = self.env_entry(&undo.env_id)?;
            let now = revision(&key, &pairs(&variables_of(&entry)));
            if now != undo.after {
                return Err(Error::Conflict(
                    "the environment changed again since".into(),
                ));
            }
            entry
                .history
                .as_ref()
                .and_then(|history| {
                    history
                        .get_entries()
                        .iter()
                        .map(variables_of)
                        .find(|vars| revision(&key, &pairs(vars)) == undo.before)
                })
                .ok_or_else(|| {
                    Error::NotFound("the earlier version isn't in the entry's history".into())
                })?
        };
        self.edit_variables(&undo.env_id, |vars| {
            *vars = previous;
            Ok(())
        })
    }

    /// Compares the vault's variables of an environment (left) with those
    /// of its file (right), for the compare dialog; values are compared
    /// here.
    pub fn compare_env_file(
        &self,
        id: &str,
        file: &EnvFile,
        ctx: &FilesContext,
    ) -> Result<EnvComparison> {
        let target = disk::locate(file, ctx, &self.paths)
            .map_err(|_| Error::invalid("the file can't be reached"))?;
        let text = match disk::read(&target.real) {
            Disk::Text(text) => text,
            Disk::Missing => Zeroizing::new(String::new()),
            Disk::Refused(_) | Disk::Failed(_) => {
                return Err(Error::invalid("the file can't be read"));
            }
        };
        let parsed = dotenv::parse(&text);
        let vars = self.env_variables(id)?;
        Ok(compare(&pairs(&vars), &parsed_pairs(&parsed)))
    }

    /// Where `bound`'s file and the vault stand, and, when `act`, what is
    /// done about it: the file rewritten from the vault when only the vault
    /// changed or `prefer` says so, and written when it was never written
    /// here. Returns the state and, when the two agree now, their revision.
    fn settle(
        &self,
        key: &[u8; 32],
        bound: &Bound,
        target: &Target,
        base: Option<&str>,
        prefer: Option<Preference<'_>>,
        act: bool,
    ) -> (FileState, Option<Agreed>) {
        let failed = |error: &Error| FileState::Failed {
            message: error.to_string(),
        };
        let vault = match self.env_variables(&bound.env_id) {
            Ok(vars) => vars,
            Err(error) => return (failed(&error), None),
        };
        let wanted = pairs(&vault);
        let vault_rev = revision(key, &wanted);
        let keep_vault = prefer.is_some_and(|p| p.keeps(bound, KeepSide::Vault));
        let text = match disk::read(&target.real) {
            Disk::Text(text) => Some(text),
            Disk::Missing => None,
            Disk::Refused(reason) => return (FileState::Refused { reason }, None),
            Disk::Failed(message) => return (FileState::Failed { message }, None),
        };
        let write = |current: Option<&str>| -> (FileState, Option<Agreed>) {
            if !act {
                return (
                    if current.is_some() {
                        FileState::VaultChanged
                    } else {
                        FileState::Missing
                    },
                    None,
                );
            }
            let mut doc = EnvDocument::new(current.unwrap_or_default());
            if let Err(error) = doc.set_variables(&wanted) {
                return (failed(&error), None);
            }
            match disk::write(target, current.map(str::as_bytes), doc.text().as_bytes()) {
                Ok(true) => (
                    FileState::InSync,
                    Some(Agreed {
                        revision: vault_rev.clone(),
                        written: true,
                    }),
                ),
                // It changed while this was being worked out: the next
                // round sees it.
                Ok(false) => (FileState::FileChanged, None),
                Err(error) => (failed(&error), None),
            }
        };
        let Some(text) = text else {
            return if base.is_none() || keep_vault {
                write(None)
            } else {
                (FileState::Missing, None)
            };
        };
        let parsed = dotenv::parse(&text);
        if let Some(problems) = blocking(&parsed) {
            return (FileState::Invalid { problems }, None);
        }
        let file_rev = revision(key, &parsed_pairs(&parsed));
        if file_rev == vault_rev {
            let agreed = Agreed {
                revision: vault_rev,
                written: false,
            };
            return (FileState::InSync, Some(agreed));
        }
        if keep_vault || base == Some(file_rev.as_str()) {
            write(Some(text.as_str()))
        } else if base == Some(vault_rev.as_str()) && !emptied(&parsed, &vault) {
            (FileState::FileChanged, None)
        } else {
            (FileState::Conflict, None)
        }
    }

    /// Every file binding with what it can be: its file on this computer,
    /// or why it isn't kept in step. Of two bindings that name one file on
    /// disk, the first in order is.
    fn plan(&self, ctx: &FilesContext) -> Vec<(Bound, Located)> {
        let projects = self.projects();
        let mut seen: Vec<disk::Identity> = Vec::new();
        self.bound()
            .into_iter()
            .map(|bound| {
                let reason = if bound.in_trash {
                    Some(InactiveReason::InTrash)
                } else if bound.kind == EnvKind::Remote {
                    Some(InactiveReason::Remote)
                } else if !holds(&projects, &bound.group, &bound.file.folder) {
                    Some(InactiveReason::NotInProject)
                } else {
                    None
                };
                if let Some(reason) = reason {
                    return (bound, Err(FileState::Inactive { reason }));
                }
                let located = disk::locate(&bound.file, ctx, &self.paths).and_then(|target| {
                    if seen.contains(&target.identity) {
                        Err(FileState::Duplicate)
                    } else {
                        seen.push(target.identity.clone());
                        Ok(target)
                    }
                });
                (bound, located)
            })
            .collect()
    }

    /// Every file binding of every environment, in a fixed order.
    fn bound(&self) -> Vec<Bound> {
        let mut all: Vec<Bound> = self
            .db
            .iter_all_entries()
            .filter(is_environment)
            .flat_map(|entry| {
                let summary = self.env_summary(&entry);
                files_of(&entry)
                    .into_iter()
                    .map(move |file| Bound {
                        env_id: summary.id.clone(),
                        group: summary.project.clone(),
                        env_name: summary.name.clone(),
                        kind: summary.kind,
                        in_trash: summary.in_trash,
                        file,
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        all.sort_by(|a, b| {
            (a.in_trash, &a.group, &a.env_name, &a.env_id, &a.file).cmp(&(
                b.in_trash,
                &b.group,
                &b.env_name,
                &b.env_id,
                &b.file,
            ))
        });
        all
    }

    /// The management center's view, of every project or of the one with
    /// the id `project`: each file with its state, the cloud service that
    /// copies it and the names its template sets that the environment
    /// lacks; and the `.env` files in the projects' folders that no
    /// environment is written to. Git is the caller's to look at.
    pub fn env_files_overview(
        &self,
        ctx: &FilesContext,
        state: &SyncState,
        cloud: &CloudRoots,
        project: Option<&str>,
    ) -> EnvFilesOverview {
        let mut overview = EnvFilesOverview::default();
        let wanted = |ids: &[String]| project.is_none_or(|id| ids.iter().any(|p| p == id));
        for status in self.env_files_status(ctx, state) {
            let projects = self.env_file_projects(&status.group, &status.file);
            if !wanted(&projects) {
                continue;
            }
            let example = status.location.as_ref().and_then(|location| {
                let (file, names) = disk::example_names(location.parent()?)?;
                let have: BTreeSet<String> = self
                    .environment(&status.env_id)
                    .map(|env| env.variables.into_iter().map(|var| var.name).collect())
                    .unwrap_or_default();
                let missing = names
                    .into_iter()
                    .filter(|name| !have.contains(name))
                    .collect();
                Some(ExampleCheck { file, missing })
            });
            overview.files.push(EnvFileReport {
                cloud: status
                    .location
                    .as_deref()
                    .and_then(|path| cloud.service(path)),
                status,
                projects,
                example,
                git: None,
            });
        }
        let bound: Vec<disk::Identity> = self
            .bound()
            .iter()
            .filter_map(|bound| disk::locate(&bound.file, ctx, &self.paths).ok())
            .map(|target| target.identity)
            .collect();
        let mut seen: BTreeSet<(String, PathBuf)> = BTreeSet::new();
        for project in self
            .projects()
            .into_iter()
            .filter(|p| project.is_none_or(|id| p.id == id))
        {
            for folder in &project.folders {
                let Some(path) = projects::folder_path(folder, ctx.home.as_deref()) else {
                    continue;
                };
                if !path.is_dir() {
                    continue;
                }
                let (found, truncated) = find_env_files(&path);
                overview.truncated |= truncated;
                for found in found {
                    let file = EnvFile {
                        folder: folder.clone(),
                        path: found,
                    };
                    let Ok(target) = disk::locate(&file, ctx, &self.paths) else {
                        continue;
                    };
                    if bound.contains(&target.identity)
                        || !seen.insert((project.id.clone(), target.real.clone()))
                    {
                        continue;
                    }
                    overview.unmanaged.push(UnmanagedEnvFile {
                        project: project.id.clone(),
                        cloud: cloud.service(&target.display),
                        location: target.display,
                        file,
                        git: None,
                    });
                }
            }
        }
        overview
    }

    /// Reads the `.env` file `file` in a folder of the project `project`,
    /// to take it under management, as a binding's file is read: without
    /// following a link, a regular file only. Returns where it is and what
    /// it holds.
    pub fn unmanaged_env_file(
        &self,
        project: &str,
        file: &EnvFile,
        ctx: &FilesContext,
    ) -> Result<(PathBuf, ParsedEnv)> {
        let file = check_env_file(file)?;
        let project = self.project(project)?;
        if !project.folders.contains(&file.folder) {
            return Err(Error::invalid("the folder isn't in the project"));
        }
        let target = disk::locate(&file, ctx, &self.paths)
            .map_err(|_| Error::invalid("the file can't be reached"))?;
        match disk::read(&target.real) {
            Disk::Text(text) => Ok((target.display, dotenv::parse(&text))),
            Disk::Missing => Err(Error::NotFound(target.display.display().to_string())),
            Disk::Refused(_) | Disk::Failed(_) => Err(Error::invalid("the file can't be read")),
        }
    }

    /// The projects (by id) that hold `file` of an environment in `group`.
    pub fn env_file_projects(&self, group: &str, file: &EnvFile) -> Vec<String> {
        self.projects()
            .into_iter()
            .filter(|project| {
                project.environments.iter().any(|g| g == group)
                    && project.folders.contains(&file.folder)
            })
            .map(|project| project.id)
            .collect()
    }

    fn put_files_data(&mut self, id: &str, data: &FilesData) -> Result<()> {
        let json = serde_json::to_string(data).map_err(|e| Error::Parse(format!("{e}")))?;
        let mut entry = self
            .db
            .entry_mut(parse_id(id)?)
            .ok_or_else(|| Error::NotFound(format!("environment {id}")))?;
        entry.custom_data.insert(
            FILES_DATA.to_owned(),
            CustomDataItem {
                value: Some(CustomDataValue::String(json)),
                last_modification_time: Some(Times::now()),
            },
        );
        entry.times.last_modification = Some(Times::now());
        Ok(())
    }

    /// The key revisions are made with, if the vault has one.
    fn revision_key(&self) -> Option<Zeroizing<[u8; 32]>> {
        let Some(CustomDataValue::String(text)) = self
            .db
            .meta
            .custom_data
            .get(REVISION_KEY)
            .and_then(|item| item.value.as_ref())
        else {
            return None;
        };
        let mut key = Zeroizing::new([0u8; 32]);
        let decoded = Base64::decode(text.as_bytes(), key.as_mut()).ok()?;
        (decoded.len() == 32).then_some(key)
    }

    /// Makes the key if the vault has none. Returns whether it did.
    fn ensure_revision_key(&mut self) -> bool {
        if self.revision_key().is_some() {
            return false;
        }
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(key.as_mut());
        self.db.meta.custom_data.insert(
            REVISION_KEY.to_owned(),
            CustomDataItem {
                value: Some(CustomDataValue::String(Base64::encode_string(key.as_ref()))),
                last_modification_time: Some(Times::now()),
            },
        );
        true
    }
}

/// The two sides agree on `revision`; `written` when the file was written
/// to get there.
struct Agreed {
    revision: String,
    written: bool,
}

/// Whether a live project holds both the environments of `group` and
/// `folder`.
fn holds(projects: &[Project], group: &str, folder: &str) -> bool {
    projects.iter().any(|project| {
        project.environments.iter().any(|g| g == group)
            && project.folders.iter().any(|f| f == folder)
    })
}
