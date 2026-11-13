//! Secret environments: the variables of a project's `.env` files (dev,
//! staging, prod…), kept in the vault.
//!
//! Each environment is one KeePass entry under the group `Environments`,
//! titled with its stage (`local`, `staging`, `prod`…), with one custom
//! string field per variable, so KeePassXC shows them as additional
//! attributes. It belongs to one project, or to none (Personal): the
//! project's record holds it by entry id ([`super::projects`]). Within a
//! project it may have a part (`backend`, `frontend`), kept on the entry as
//! [`PART`]; an environment from before parts has its KeePass group's name
//! as its part, so nothing had to move when groups gave way to projects. New
//! ones are filed under `Environments/<project>/<part>` for KeePassXC. A secret variable's field is protected, as a password is. The
//! entry's custom data `sshkm.env` marks it as an environment and keeps the
//! variables' order and notes. A variable named like one of KeePass's own
//! fields (`URL`, `Password`, …) is kept as `env.URL`.
//!
//! Environments stay off the password list ([`super::Vault::entries`]).
//! Like passwords, values reach the UI one at a time, when the user shows or
//! copies one: [`EnvDetail`] holds names, flags and notes only.

mod detect;
mod document;
pub mod dotenv;
pub mod files;
mod format;
mod shared;
#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};

use keepass::Database;
use keepass::db::{
    CustomDataItem, CustomDataValue, Entry, EntryRef, GroupId, Times, Value, fields,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub use self::detect::looks_secret;
pub use self::document::EnvDocument;
pub use self::dotenv::{ParseProblem, ParsedEnv, ProblemKind};
pub use self::files::{EnvFile, EnvKind, FileLevel};
pub use self::format::{EnvFormat, render};
pub(crate) use self::shared::is_shared;
pub use self::shared::{SharedUse, SharedValue};
use super::export::{checked_target, write_private};
use super::{Vault, check_field, duplicate, in_group, parse_id, rfc3339};
use crate::{Error, Result};

/// Most variables one environment holds.
pub const MAX_VARIABLES: usize = 1000;
/// Largest `.env` file that is read.
pub const MAX_FILE_SIZE: u64 = 1024 * 1024;
/// Longest name of a project or an environment, in characters.
const MAX_LABEL: usize = 64;
/// Longest variable name, in bytes.
const MAX_NAME: usize = 255;
/// The group under the root that holds the environments.
pub const GROUP: &str = "Environments";
/// Custom data that marks an entry as an environment.
pub(super) const MARKER: &str = "sshkm.env";
/// Custom data with an environment's part of its project; without it, the
/// part is its KeePass group's name.
pub const PART: &str = "sshkm.env.part";
/// The group under `Environments` for Personal environments without a part.
const PERSONAL: &str = "Personal";
/// KeePass's own fields, which a variable can't be: such a variable is
/// kept under [`ESCAPE`] and its name.
const RESERVED: [&str; 6] = [
    fields::TITLE,
    fields::USERNAME,
    fields::PASSWORD,
    fields::URL,
    fields::NOTES,
    fields::OTP,
];
const ESCAPE: &str = "env.";

/// An environment as the list shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct EnvSummary {
    /// The KeePass entry UUID.
    pub id: String,
    /// The project it belongs to, by id; `None` for Personal.
    pub project: Option<String>,
    /// Its part of the project (`backend`, `frontend`), or empty. A project
    /// with one part shows none.
    pub part: String,
    /// The KeePass group it is in, which older versions take as its
    /// project.
    pub group: String,
    /// Its stage, `local`, `dev`, `staging`, `prod`…: the entry's title.
    pub name: String,
    /// Local (it can have files) or remote.
    pub kind: EnvKind,
    /// How many variables it has.
    pub variable_count: u32,
    /// How many of them are secret.
    pub secret_count: u32,
    /// It is in the vault's recycle bin.
    pub in_trash: bool,
    /// RFC 3339, UTC.
    pub modified: Option<String>,
}

/// A variable without its value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct EnvVarInfo {
    pub name: String,
    pub secret: bool,
    pub note: String,
    /// The value is empty.
    pub empty: bool,
    /// The shared value it uses, by id.
    pub shared: Option<String>,
    /// It refers to a value the vault doesn't have (deleted elsewhere):
    /// its environment's files wait until it gets one.
    pub unresolved: bool,
}

/// An environment and its variables, without values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct EnvDetail {
    #[serde(flatten)]
    #[cfg_attr(feature = "ts", ts(flatten))]
    pub summary: EnvSummary,
    pub notes: String,
    pub variables: Vec<EnvVarInfo>,
    /// The files it is written to: level 1 first.
    pub files: Vec<EnvFile>,
    /// Those of `files` written only while the vault is unlocked (level 2).
    pub while_unlocked: Vec<EnvFile>,
    /// Those of `files` that are pipes the app answers (level 3).
    pub virtual_files: Vec<EnvFile>,
}

/// A new environment, or where an environment is, its stage and notes.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct EnvInput {
    /// The project, by id; `None` for Personal.
    #[serde(default)]
    pub project: Option<String>,
    /// Its part of the project, or empty.
    #[serde(default)]
    pub part: String,
    /// Its stage.
    pub name: String,
    #[serde(default)]
    pub notes: String,
}

/// A part to name with a change that gives a project its second part: the
/// environments that share it (those in the recycle bin too) and its name
/// ([`Vault::set_environment_part`]). Named in the same change, so neither
/// happens without the other.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct PartRename {
    pub ids: Vec<String>,
    pub part: String,
}

/// A new variable, or the new state of one.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct EnvVarInput {
    pub name: String,
    /// `None` keeps the current value (an empty one for a new variable).
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(type = "string | null"))]
    pub value: Option<SecretString>,
    pub secret: bool,
    #[serde(default)]
    pub note: String,
}

/// A variable with its value: for a file, a shell or another computer, never
/// for the UI.
pub struct EnvVariable {
    pub name: String,
    pub value: SecretString,
    pub secret: bool,
    pub note: String,
}

impl std::fmt::Debug for EnvVariable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvVariable")
            .field("name", &self.name)
            .field("secret", &self.secret)
            .finish_non_exhaustive()
    }
}

impl EnvVariable {
    fn duplicate(&self) -> Self {
        Self {
            name: self.name.clone(),
            value: duplicate(&self.value),
            secret: self.secret,
            note: self.note.clone(),
        }
    }
}

/// How two environments differ, by name only: values are compared here and
/// never shown.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct EnvComparison {
    /// Names only the first one has: missing from the second.
    pub only_left: Vec<String>,
    /// Names only the second one has: extra there.
    pub only_right: Vec<String>,
    /// Names both have, with different values.
    pub changed: Vec<String>,
    /// Names both have, with the same value.
    pub same: Vec<String>,
}

/// A `.env` file's variables as an import shows them, without values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct EnvImportPreview {
    /// The folder's name, as the project.
    pub suggested_project: String,
    /// From the file's name: `production` for `.env.production`; empty for
    /// a plain `.env`.
    pub suggested_name: String,
    pub variables: Vec<ImportVariable>,
    pub problems: Vec<ParseProblem>,
}

/// A variable found in a `.env` file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct ImportVariable {
    pub name: String,
    /// Where it starts in the file, from 1.
    pub line: u32,
    /// It looks like a secret ([`looks_secret`]).
    pub secret: bool,
    pub empty: bool,
    /// The value spans several lines.
    pub multiline: bool,
}

/// One variable to take from the file, and whether it is secret.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct ImportChoice {
    pub name: String,
    pub secret: bool,
}

/// What an import changed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct ImportCounts {
    pub added: u32,
    /// Variables the environment had already, whose values were replaced.
    pub replaced: u32,
}

/// The order and notes of the variables, in the marker.
#[derive(Default, Serialize, Deserialize)]
struct Stored {
    #[serde(default)]
    vars: Vec<StoredVar>,
}

#[derive(Serialize, Deserialize)]
struct StoredVar {
    name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    note: String,
}

/// Whether a variable of this name makes programs load code or run a
/// command they otherwise wouldn't, once it is in a shell's environment or
/// a `.env` file: the dynamic loader's (`LD_*`, `DYLD_*`), interpreters'
/// startup and module paths, shells' startup files, Git's and ssh's
/// commands, and `PATH`. Such a variable that comes from another device is
/// a risky change, which the user allows in a system dialog.
pub fn risky_variable(name: &str) -> bool {
    const EXACT: [&str; 22] = [
        "PATH",
        "NODE_OPTIONS",
        "NODE_PATH",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONHOME",
        "PERL5OPT",
        "PERL5LIB",
        "PERLLIB",
        "RUBYOPT",
        "RUBYLIB",
        "BASH_ENV",
        "ENV",
        "ZDOTDIR",
        "PROMPT_COMMAND",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_EXEC_PATH",
        "SSH_ASKPASS",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "JDK_JAVA_OPTIONS",
    ];
    const PREFIXES: [&str; 4] = ["LD_", "DYLD_", "GIT_CONFIG_", "DOTNET_STARTUP_HOOKS"];
    let name = name.strip_prefix(ESCAPE).unwrap_or(name);
    EXACT.contains(&name) || PREFIXES.iter().any(|prefix| name.starts_with(prefix))
}

/// A variable name: ASCII letters, digits and `_`, not starting with a
/// digit, as a shell takes it.
pub fn is_valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && name.len() <= MAX_NAME
}

/// Whether a KeePass entry is an environment.
pub(super) fn is_environment(entry: &EntryRef<'_>) -> bool {
    entry.custom_data.contains_key(MARKER)
}

/// Whether a KeePass entry is a login, the password list's: neither an
/// environment nor a shared value.
pub(super) fn is_login(entry: &EntryRef<'_>) -> bool {
    !is_environment(entry) && !is_shared(entry)
}

/// The field a variable is kept in.
fn field_name(var: &str) -> String {
    if RESERVED.contains(&var) {
        format!("{ESCAPE}{var}")
    } else {
        var.to_owned()
    }
}

/// The variable a field holds, if it is one.
fn var_name(field: &str) -> Option<&str> {
    if RESERVED.contains(&field) {
        return None;
    }
    match field.strip_prefix(ESCAPE) {
        Some(var) => RESERVED.contains(&var).then_some(var),
        None => is_valid_name(field).then_some(field),
    }
}

fn stored(entry: &Entry) -> Stored {
    match entry
        .custom_data
        .get(MARKER)
        .and_then(|item| item.value.as_ref())
    {
        Some(CustomDataValue::String(json)) => serde_json::from_str(json).unwrap_or_default(),
        _ => Stored::default(),
    }
}

/// The variables of an environment entry with their values: in the order
/// kept in its marker, then those added elsewhere (KeePassXC) by name.
pub(super) fn variables_of(entry: &Entry) -> Vec<EnvVariable> {
    let stored = stored(entry);
    let mut found: Vec<(&str, &Value<String>)> = entry
        .fields
        .iter()
        .filter_map(|(field, value)| Some((var_name(field)?, value)))
        .collect();
    found.sort_by_key(|(name, _)| {
        let position = stored.vars.iter().position(|var| var.name == *name);
        (position.unwrap_or(usize::MAX), *name)
    });
    found
        .into_iter()
        .map(|(name, value)| EnvVariable {
            name: name.to_owned(),
            value: SecretString::from(value.get().as_str()),
            secret: value.is_protected(),
            note: stored
                .vars
                .iter()
                .find(|var| var.name == name)
                .map(|var| var.note.clone())
                .unwrap_or_default(),
        })
        .collect()
}

/// A project's or an environment's name, trimmed: no control characters,
/// no `/` (it names a group), at most [`MAX_LABEL`] characters.
pub(super) fn check_label(text: &str, what: &str) -> Result<String> {
    let text = text.trim();
    if text.is_empty() {
        return Err(Error::invalid(format!("{what} needs a name")));
    }
    if text.chars().count() > MAX_LABEL {
        return Err(Error::invalid(format!(
            "{what} names are at most {MAX_LABEL} characters"
        )));
    }
    if text.chars().any(|c| c.is_control() || c == '/') {
        return Err(Error::invalid(format!(
            "{what} names can't have `/` or control characters"
        )));
    }
    Ok(text.to_owned())
}

/// `text` made into a name [`check_label`] takes, or empty.
fn clean_label(text: &str) -> String {
    let words: Vec<&str> = text.split_whitespace().collect();
    words
        .join(" ")
        .chars()
        .filter(|c| !c.is_control() && *c != '/')
        .take(MAX_LABEL)
        .collect::<String>()
        .trim()
        .to_owned()
}

/// Where an environment comes in the list: local and development ones
/// first, production last.
fn stage(name: &str) -> u8 {
    match name.to_lowercase().as_str() {
        "local" => 0,
        "dev" | "development" => 1,
        "test" | "testing" | "qa" => 2,
        "stage" | "staging" | "preprod" | "pre-prod" | "uat" => 3,
        "prod" | "production" | "live" => 4,
        _ => 5,
    }
}

/// Checks the variables an environment is to have.
fn check_variables(vars: &[EnvVariable]) -> Result<()> {
    if vars.len() > MAX_VARIABLES {
        return Err(Error::invalid(format!(
            "an environment holds at most {MAX_VARIABLES} variables"
        )));
    }
    for (index, var) in vars.iter().enumerate() {
        if !is_valid_name(&var.name) {
            return Err(Error::invalid(format!(
                "not a variable name: {:?}",
                var.name.chars().take(MAX_LABEL).collect::<String>()
            )));
        }
        if vars[..index].iter().any(|other| other.name == var.name) {
            return Err(Error::AlreadyExists(var.name.clone()));
        }
        check_field(var.value.expose_secret())?;
        check_field(&var.note)?;
        if var.note.chars().any(char::is_control) {
            return Err(Error::invalid("a note is one line of text"));
        }
    }
    Ok(())
}

/// Values from outside the vault (a file, another computer) never refer to
/// a vault entry: only the vault makes a variable use a shared value.
fn check_no_references(vars: &[EnvVariable]) -> Result<()> {
    match vars
        .iter()
        .find(|var| shared::referenced(var.value.expose_secret()).is_some())
    {
        Some(var) => Err(Error::invalid(format!(
            "{} refers to a vault entry, which only the vault sets",
            var.name
        ))),
        None => Ok(()),
    }
}

fn same_variables(a: &[EnvVariable], b: &[EnvVariable]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(a, b)| {
            a.name == b.name
                && a.secret == b.secret
                && a.note == b.note
                && a.value.expose_secret() == b.value.expose_secret()
        })
}

/// The project and environment names an import suggests for `path`.
fn suggested_names(path: &Path) -> (String, String) {
    let file = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name = file
        .strip_prefix(".env.")
        .or_else(|| file.strip_suffix(".env"))
        .unwrap_or_default();
    let project = path
        .parent()
        .and_then(Path::file_name)
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    (clean_label(&project), clean_label(name))
}

/// Reads a `.env` file of at most [`MAX_FILE_SIZE`] bytes.
pub fn read_file(path: &Path) -> Result<ParsedEnv> {
    let meta = std::fs::metadata(path).map_err(|e| Error::io(e, path))?;
    if !meta.is_file() {
        return Err(Error::invalid(format!("{} is not a file", path.display())));
    }
    if meta.len() > MAX_FILE_SIZE {
        return Err(Error::invalid(format!("{} is too large", path.display())));
    }
    let bytes = Zeroizing::new(std::fs::read(path).map_err(|e| Error::io(e, path))?);
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Error::Parse(format!("{} is not UTF-8 text", path.display())))?;
    Ok(dotenv::parse(text))
}

/// What an import of the file shows: names, suggested secrets and the lines
/// that can't be read, without values.
pub fn preview_file(path: &Path) -> Result<EnvImportPreview> {
    Ok(preview_parsed(path, read_file(path)?))
}

/// What an import of `parsed`, read from the file at `path`, shows.
pub fn preview_parsed(path: &Path, parsed: ParsedEnv) -> EnvImportPreview {
    let (suggested_project, suggested_name) = suggested_names(path);
    EnvImportPreview {
        suggested_project,
        suggested_name,
        variables: parsed
            .vars
            .iter()
            .map(|var| ImportVariable {
                name: var.name.clone(),
                line: var.line,
                secret: looks_secret(&var.name, &var.value),
                empty: var.value.is_empty(),
                multiline: var.value.contains('\n'),
            })
            .collect(),
        problems: parsed.problems,
    }
}

/// The variables of `parsed` that `choices` name, with the secret flags
/// chosen there, in the file's order.
pub fn chosen_variables(parsed: ParsedEnv, choices: &[ImportChoice]) -> Vec<EnvVariable> {
    parsed
        .vars
        .into_iter()
        .filter_map(|var| {
            let choice = choices.iter().find(|choice| choice.name == var.name)?;
            Some(EnvVariable {
                name: var.name,
                value: SecretString::from(var.value.as_str()),
                secret: choice.secret,
                note: String::new(),
            })
        })
        .collect()
}

/// The top folder of the Git working tree `folder` is in, if any: where a
/// `.git` folder (or, for a worktree, file) is.
pub fn git_work_tree(folder: &Path) -> Option<PathBuf> {
    folder
        .ancestors()
        .find(|ancestor| ancestor.join(".git").exists())
        .map(Path::to_path_buf)
}

impl Vault {
    /// Every environment, including those in the recycle bin, by project
    /// and part, then from development to production.
    pub fn environments(&self) -> Vec<EnvSummary> {
        let owners = self.environment_owners();
        let mut list: Vec<EnvSummary> = self
            .db
            .iter_all_entries()
            .filter(is_environment)
            .map(|entry| self.env_summary(&entry, &owners))
            .collect();
        list.sort_by_cached_key(|env| {
            (
                env.in_trash,
                env.project.clone(),
                env.part.to_lowercase(),
                stage(&env.name),
                env.name.to_lowercase(),
            )
        });
        list
    }

    pub fn environment(&self, id: &str) -> Result<EnvDetail> {
        let entry = self.env_entry(id)?;
        let bindings = files::bindings_of(&entry);
        Ok(EnvDetail {
            summary: self.env_summary(&entry, &self.environment_owners()),
            notes: entry.get(fields::NOTES).unwrap_or_default().to_owned(),
            variables: variables_of(&entry)
                .into_iter()
                .map(|var| {
                    let raw = var.value.expose_secret();
                    let (empty, unresolved) = match self.dereference(raw) {
                        None => (raw.is_empty(), false),
                        Some(Ok(value)) => (value.is_empty(), false),
                        Some(Err(())) => (false, true),
                    };
                    EnvVarInfo {
                        shared: self.shared_of(raw).map(|id| id.to_string()),
                        empty,
                        unresolved,
                        name: var.name,
                        secret: var.secret,
                        note: var.note,
                    }
                })
                .collect(),
            while_unlocked: bindings
                .iter()
                .filter(|(_, level)| *level == FileLevel::WhileUnlocked)
                .map(|(file, _)| file.clone())
                .collect(),
            virtual_files: bindings
                .iter()
                .filter(|(_, level)| *level == FileLevel::Virtual)
                .map(|(file, _)| file.clone())
                .collect(),
            files: bindings.into_iter().map(|(file, _)| file).collect(),
        })
    }

    /// The variables of an environment with their values, a shared one's
    /// resolved ([`shared`]). Fails if one can't be resolved.
    pub fn env_variables(&self, id: &str) -> Result<Vec<EnvVariable>> {
        let entry = self.env_entry(id)?;
        self.resolve(variables_of(&entry))
    }

    /// The variables as the environment keeps them: a shared one's value is
    /// its reference.
    pub(super) fn raw_env_variables(&self, id: &str) -> Result<Vec<EnvVariable>> {
        let entry = self.env_entry(id)?;
        Ok(variables_of(&entry))
    }

    /// One variable's value, a shared one's resolved.
    pub fn env_value(&self, id: &str, name: &str) -> Result<SecretString> {
        let entry = self.env_entry(id)?;
        let var = variables_of(&entry)
            .into_iter()
            .find(|var| var.name == name)
            .ok_or_else(|| Error::NotFound(format!("variable {name}")))?;
        Ok(self.resolve(vec![var])?.remove(0).value)
    }

    /// Adds an empty environment to a project (or Personal) and returns its
    /// id. It is filed in KeePass under `Environments/<project>/<part>`.
    pub fn add_environment(&mut self, input: &EnvInput) -> Result<String> {
        let project = match &input.project {
            Some(id) => Some(self.project(id)?),
            None => None,
        };
        let part = check_part(&input.part)?;
        let name = check_label(&input.name, "an environment")?;
        check_field(&input.notes)?;
        let owner = project.as_ref().map(|p| p.id.as_str());
        self.check_free(owner, &part, &name, None)?;
        let folder = match &project {
            Some(project) => vec![project.name.clone()],
            None => Vec::new(),
        };
        let group = self.env_group(&folder, &part)?;
        let id = {
            let mut group = self
                .db
                .group_mut(group)
                .ok_or_else(|| Error::NotFound(GROUP.into()))?;
            let mut entry = group.add_entry();
            entry.set_unprotected(fields::TITLE, name);
            entry.set_protected(fields::PASSWORD, "");
            if !input.notes.trim().is_empty() {
                entry.set_unprotected(fields::NOTES, input.notes.trim_end());
            }
            entry
                .custom_data
                .insert(MARKER.to_owned(), marker(&Stored::default()));
            entry.custom_data.insert(PART.to_owned(), text_item(&part));
            entry.id().uuid().to_string()
        };
        if let Some(project) = owner {
            self.set_project_member(
                project,
                &super::projects::ProjectMember::Environment { id: id.clone() },
                true,
            )?;
        }
        Ok(id)
    }

    /// Changes an environment's stage or notes (keeping the previous version
    /// in its history), its part, or the project it is in (or Personal).
    /// Nothing moves in KeePass: its files stay bound, and are written only
    /// while the project holding it has their folder.
    pub fn update_environment(&mut self, id: &str, input: &EnvInput) -> Result<()> {
        let part = check_part(&input.part)?;
        let name = check_label(&input.name, "an environment")?;
        check_field(&input.notes)?;
        if let Some(project) = &input.project {
            self.project(project)?;
        }
        let current = self.environment(id)?;
        if current.summary.in_trash {
            return Err(Error::invalid("restore the environment first"));
        }
        self.check_free(input.project.as_deref(), &part, &name, Some(id))?;
        let notes = input.notes.trim_end();
        let entry_id = parse_id(id)?;
        if name != current.summary.name || notes != current.notes {
            {
                let mut entry = self
                    .db
                    .entry_mut(entry_id)
                    .ok_or_else(|| Error::NotFound(format!("environment {id}")))?;
                let mut tracked = entry.track_changes();
                if name != current.summary.name {
                    tracked.set(fields::TITLE, Value::unprotected(name));
                }
                if notes != current.notes {
                    if notes.is_empty() {
                        tracked.fields.remove(fields::NOTES);
                    } else {
                        tracked.set(fields::NOTES, Value::unprotected(notes));
                    }
                }
                tracked.times.last_modification = Some(Times::now());
            }
            self.settle_history(entry_id, true);
        }
        if part != current.summary.part {
            self.put_part(entry_id, &part)?;
            // Its part's folder goes with it, when it was the last there
            // and stays in its project (a folder is the project's).
            if let Some(project) = &current.summary.project
                && input.project.as_ref() == Some(project)
            {
                self.follow_part_folders(
                    &[(project.clone(), current.summary.part.clone())],
                    &part,
                )?;
            }
        }
        if input.project != current.summary.project {
            self.move_environment(id, input.project.as_deref())?;
        }
        Ok(())
    }

    /// Gives environments the part `part` (or none): a part renamed, or
    /// the one a project had before it got a second, named then. Those in
    /// the recycle bin take it too, so a restore doesn't bring the old name
    /// back; their stages are checked when they are restored. All are
    /// checked before any changes. A part left without environments gives
    /// its folder to the new one, unless that one has its own.
    pub fn set_environment_part(&mut self, ids: &[String], part: &str) -> Result<()> {
        let part = check_part(part)?;
        let envs = self.environments();
        let mut changes = Vec::new();
        // The parts the environments leave, by project.
        let mut left: Vec<(String, String)> = Vec::new();
        for id in ids {
            let env = envs
                .iter()
                .find(|env| env.id == *id)
                .ok_or_else(|| Error::NotFound(format!("environment {id}")))?;
            if env.part == part {
                continue;
            }
            if !env.in_trash {
                let taken = envs.iter().any(|other| {
                    !other.in_trash
                        && other.id != env.id
                        && other.project == env.project
                        && same(&other.name, &env.name)
                        && (same(&other.part, &part) || ids.contains(&other.id))
                });
                if taken {
                    return Err(Error::AlreadyExists(format!("{part} / {}", env.name)));
                }
            }
            changes.push(parse_id(id)?);
            if let Some(project) = &env.project
                && !left.contains(&(project.clone(), env.part.clone()))
            {
                left.push((project.clone(), env.part.clone()));
            }
        }
        for entry in changes {
            self.put_part(entry, &part)?;
        }
        self.follow_part_folders(&left, &part)
    }

    /// Gives the folder of each part `left` (by project) to `part`, which
    /// its environments went to, once no environment is left in it
    /// ([`super::projects::places`]).
    fn follow_part_folders(&mut self, left: &[(String, String)], part: &str) -> Result<()> {
        let now = self.environments();
        for (project, before) in left {
            let emptied = !now
                .iter()
                .any(|env| env.project.as_ref() == Some(project) && same(&env.part, before));
            if emptied {
                self.move_part_folder(project, before, part)?;
            }
        }
        Ok(())
    }

    /// Names the part a project had, when what comes next gives it a
    /// second one ([`PartRename`]); called in the same change.
    pub fn name_first_part(&mut self, rename: Option<&PartRename>) -> Result<()> {
        match rename {
            Some(rename) => self.set_environment_part(&rename.ids, &rename.part),
            None => Ok(()),
        }
    }

    /// Keeps an environment's part on its entry, when it has none there yet
    /// (one an older version made, whose part is its group's name): it is
    /// placed by the user from then on, and the step from groups leaves it
    /// alone ([`Vault::tidy_projects`]).
    pub(super) fn keep_part(&mut self, id: &str) -> Result<()> {
        let part = {
            let entry = self.env_entry(id)?;
            if entry.custom_data.contains_key(PART) {
                return Ok(());
            }
            self.env_summary(&entry, &std::collections::BTreeMap::new())
                .part
        };
        self.put_part(parse_id(id)?, &part)
    }

    /// The environments that keep their part on the entry: every one this
    /// version made or placed. The others, an older version made.
    pub(super) fn envs_with_part(&self) -> std::collections::BTreeSet<String> {
        self.db
            .iter_all_entries()
            .filter(|entry| is_environment(entry) && entry.custom_data.contains_key(PART))
            .map(|entry| entry.id().uuid().to_string())
            .collect()
    }

    /// Keeps `part` on the entry.
    fn put_part(&mut self, entry_id: keepass::db::EntryId, part: &str) -> Result<()> {
        let mut entry = self
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| Error::NotFound("environment".into()))?;
        entry.custom_data.insert(PART.to_owned(), text_item(part));
        entry.times.last_modification = Some(Times::now());
        Ok(())
    }

    /// Adds a variable (`previous` is `None`) or changes the one named
    /// `previous`, perhaps renaming it. A new value of a shared variable
    /// changes the shared value, for every environment that uses it.
    pub fn set_env_variable(
        &mut self,
        id: &str,
        previous: Option<&str>,
        input: &EnvVarInput,
    ) -> Result<()> {
        let name = input.name.trim().to_owned();
        let note = input.note.trim().to_owned();
        if let Some(value) = &input.value {
            check_no_references(&[EnvVariable {
                name: name.clone(),
                value: duplicate(value),
                secret: input.secret,
                note: String::new(),
            }])?;
        }
        let shared = previous
            .and_then(|previous| {
                self.raw_env_variables(id)
                    .ok()?
                    .into_iter()
                    .find(|var| var.name == previous)
            })
            .and_then(|var| self.shared_of(var.value.expose_secret()));
        let mut value_in = input.value.as_ref().map(duplicate);
        if let (Some(shared), Some(value)) = (shared, &value_in) {
            self.set_shared_value(shared, value.expose_secret())?;
            // The variable keeps its reference.
            value_in = None;
        }
        self.edit_variables(id, |vars| {
            let value = match &value_in {
                Some(value) => duplicate(value),
                None => previous
                    .and_then(|previous| vars.iter().find(|var| var.name == previous))
                    .map_or_else(|| SecretString::from(""), |var| duplicate(&var.value)),
            };
            let var = EnvVariable {
                name: name.clone(),
                value,
                secret: input.secret,
                note,
            };
            if vars
                .iter()
                .any(|other| other.name == name && Some(name.as_str()) != previous)
            {
                return Err(Error::AlreadyExists(name.clone()));
            }
            match previous {
                Some(previous) => {
                    let index = vars
                        .iter()
                        .position(|var| var.name == previous)
                        .ok_or_else(|| Error::NotFound(format!("variable {previous}")))?;
                    vars[index] = var;
                }
                None => vars.push(var),
            }
            Ok(())
        })
    }

    /// Removes a variable. A shared value no variable uses any more goes to
    /// the recycle bin.
    pub fn remove_env_variable(&mut self, id: &str, name: &str) -> Result<()> {
        self.edit_variables(id, |vars| {
            let index = vars
                .iter()
                .position(|var| var.name == name)
                .ok_or_else(|| Error::NotFound(format!("variable {name}")))?;
            vars.remove(index);
            Ok(())
        })
    }

    /// Takes `imported` into an environment: a variable it has already gets
    /// the new value and secret flag (and keeps its note); the others are
    /// added at the end. A shared variable's new value changes the shared
    /// value.
    pub fn import_env_variables(
        &mut self,
        id: &str,
        imported: &[EnvVariable],
    ) -> Result<ImportCounts> {
        let mut counts = ImportCounts::default();
        check_no_references(imported)?;
        let raw = self.raw_env_variables(id)?;
        let mut linked = Vec::new();
        for new in imported {
            if let Some(shared) = raw
                .iter()
                .find(|var| var.name == new.name)
                .and_then(|var| self.shared_of(var.value.expose_secret()))
            {
                self.set_shared_value(shared, new.value.expose_secret())?;
                linked.push(new.name.clone());
            }
        }
        self.edit_variables(id, |vars| {
            for new in imported {
                if let Some(var) = vars.iter_mut().find(|var| var.name == new.name) {
                    if !linked.contains(&new.name) {
                        var.value = duplicate(&new.value);
                    }
                    var.secret = new.secret;
                    counts.replaced += 1;
                } else {
                    vars.push(new.duplicate());
                    counts.added += 1;
                }
            }
            Ok(())
        })?;
        Ok(counts)
    }

    /// Adds an environment another computer sent, as a new one in Personal,
    /// its label (the project or part it had there) as its part: if that
    /// part has one of that name, it gets a number (`dev 2`). Returns its id
    /// and name.
    pub fn add_received_environment(
        &mut self,
        label: &str,
        name: &str,
        notes: &str,
        vars: &[EnvVariable],
    ) -> Result<(String, String)> {
        check_variables(vars)?;
        check_no_references(vars)?;
        let part = check_part(label)?;
        let base = check_label(name, "an environment")?;
        let mut name = base.clone();
        let mut n = 2;
        while self.check_free(None, &part, &name, None).is_err() {
            let suffix = format!(" {n}");
            let room = MAX_LABEL - suffix.chars().count();
            name = format!("{}{suffix}", base.chars().take(room).collect::<String>());
            n += 1;
        }
        let id = self.add_environment(&EnvInput {
            project: None,
            part,
            name: name.clone(),
            notes: notes.to_owned(),
        })?;
        self.import_env_variables(&id, vars)?;
        Ok((id, name))
    }

    /// Compares two environments' variables by name and value.
    pub fn compare_environments(&self, left: &str, right: &str) -> Result<EnvComparison> {
        let left = self.env_variables(left)?;
        let right = self.env_variables(right)?;
        let mut comparison = EnvComparison::default();
        for var in &left {
            match right.iter().find(|other| other.name == var.name) {
                None => comparison.only_left.push(var.name.clone()),
                Some(other) if other.value.expose_secret() == var.value.expose_secret() => {
                    comparison.same.push(var.name.clone());
                }
                Some(_) => comparison.changed.push(var.name.clone()),
            }
        }
        comparison.only_right = right
            .iter()
            .filter(|var| !left.iter().any(|other| other.name == var.name))
            .map(|var| var.name.clone())
            .collect();
        Ok(comparison)
    }

    /// Writes an environment to `target` in `format` (mode 0600; on
    /// Windows only the user, SYSTEM and Administrators can read it), in
    /// plain text. Like the vault's exports, never over the vault's own
    /// files and never into `ssh_dir`. Returns how many variables it holds.
    pub fn export_environment(
        &self,
        id: &str,
        format: EnvFormat,
        target: &Path,
        ssh_dir: &Path,
    ) -> Result<usize> {
        let target = checked_target(target, &self.paths, ssh_dir)?;
        let env = self.environment(id)?;
        let vars = self.env_variables(id)?;
        let text = render(
            format,
            &self.env_label(&env.summary),
            &env.summary.name,
            &vars,
        )?;
        write_private(&target, text.as_bytes())?;
        Ok(vars.len())
    }

    /// Moves an environment to the recycle bin.
    pub fn trash_environment(&mut self, id: &str) -> Result<()> {
        self.env_entry(id)?;
        self.trash_entry(id)
    }

    /// Takes an environment out of the recycle bin, back into its project
    /// and part, unless that part has one of its stage now; the shared
    /// values it uses come back too.
    pub fn restore_environment(&mut self, id: &str) -> Result<()> {
        let env = self.environment(id)?.summary;
        if !env.in_trash {
            return Ok(());
        }
        self.check_free(env.project.as_deref(), &env.part, &env.name, Some(id))?;
        self.restore_entry(id)?;
        // The shared values it uses come back with it.
        let shared: Vec<uuid::Uuid> = self
            .raw_env_variables(id)?
            .iter()
            .filter_map(|var| self.shared_of(var.value.expose_secret()))
            .collect();
        for shared in shared {
            self.restore_shared(shared)?;
        }
        Ok(())
    }

    /// Where an environment is, for people: `Shop · backend`, `Shop`, a
    /// Personal one's part, or nothing.
    pub fn env_label(&self, env: &EnvSummary) -> String {
        let project = env
            .project
            .as_deref()
            .and_then(|id| self.project(id).ok())
            .map(|project| project.name);
        label(project.as_deref(), &env.part)
    }

    /// Deletes an environment in the recycle bin for good. A shared value
    /// it was the last to use goes to the recycle bin.
    pub fn delete_environment(&mut self, id: &str) -> Result<()> {
        self.env_entry(id)?;
        self.delete_entry(id)?;
        self.trash_unused_shared()
    }

    fn env_entry(&self, id: &str) -> Result<EntryRef<'_>> {
        let entry = self.find(id)?;
        if !is_environment(&entry) {
            return Err(Error::NotFound(format!("environment {id}")));
        }
        Ok(entry)
    }

    pub(super) fn env_summary(
        &self,
        entry: &EntryRef<'_>,
        owners: &std::collections::BTreeMap<String, String>,
    ) -> EnvSummary {
        let bin = self.db.meta.recyclebin_uuid;
        let in_trash = in_group(entry.parent().id(), bin, &self.db);
        let group = if in_trash {
            entry.previous_parent()
        } else {
            Some(entry.parent())
        };
        // The group holding it, unless that is the root or `Environments`.
        let group = group
            .filter(|group| {
                group
                    .parent()
                    .is_some_and(|parent| parent.parent().is_some() || group.name != GROUP)
            })
            .map(|group| group.name.clone())
            .unwrap_or_default();
        // Kept on the entry; from before parts, its group's name.
        let part = match entry
            .custom_data
            .get(PART)
            .and_then(|item| item.value.as_ref())
        {
            Some(CustomDataValue::String(part)) => part.clone(),
            _ => group.clone(),
        };
        let vars = variables_of(entry);
        let id = entry.id().uuid().to_string();
        EnvSummary {
            project: owners.get(&id).cloned(),
            id,
            part,
            group,
            name: entry.get(fields::TITLE).unwrap_or_default().to_owned(),
            kind: files::kind_of(entry),
            variable_count: count(vars.len()),
            secret_count: count(vars.iter().filter(|var| var.secret).count()),
            in_trash,
            modified: entry.times.last_modification.map(rfc3339),
        }
    }

    /// Fails if `project` (or Personal) has an environment with the stage
    /// `name` in `part` (ignoring case) outside the recycle bin, other than
    /// `except`.
    pub(super) fn check_free(
        &self,
        project: Option<&str>,
        part: &str,
        name: &str,
        except: Option<&str>,
    ) -> Result<()> {
        let taken = self.environments().into_iter().any(|env| {
            !env.in_trash
                && Some(env.id.as_str()) != except
                && env.project.as_deref() == project
                && same(&env.part, part)
                && same(&env.name, name)
        });
        if taken {
            return Err(Error::AlreadyExists(format!("{part} / {name}")));
        }
        Ok(())
    }

    /// The group a new environment is filed in, made if needed:
    /// `Environments/<project>/<part>`; a Personal one without a part goes
    /// into `Environments/Personal`.
    fn env_group(&mut self, project: &[String], part: &str) -> Result<GroupId> {
        let root = self.db.root().id();
        let mut group = child_group(&mut self.db, root, GROUP)?;
        let mut path: Vec<&str> = project.iter().map(String::as_str).collect();
        if !part.is_empty() {
            path.push(part);
        }
        if path.is_empty() {
            path.push(PERSONAL);
        }
        for name in path {
            group = child_group(&mut self.db, group, name)?;
        }
        Ok(group)
    }

    /// Changes an environment's variables: `change` gets them in order with
    /// their values. What it leaves is checked and written back as one new
    /// version, keeping the previous one in the entry's history.
    pub(super) fn edit_variables(
        &mut self,
        id: &str,
        change: impl FnOnce(&mut Vec<EnvVariable>) -> Result<()>,
    ) -> Result<()> {
        self.edit_variables_in(id, false, change)
    }

    /// [`Self::edit_variables`], also of an environment in the recycle bin
    /// with `in_trash`: for giving it a copy of a shared value that goes.
    pub(super) fn edit_variables_in(
        &mut self,
        id: &str,
        in_trash: bool,
        change: impl FnOnce(&mut Vec<EnvVariable>) -> Result<()>,
    ) -> Result<()> {
        let entry_id = parse_id(id)?;
        let before = {
            let entry = self.env_entry(id)?;
            if !in_trash && in_group(entry.parent().id(), self.db.meta.recyclebin_uuid, &self.db) {
                return Err(Error::invalid("restore the environment first"));
            }
            variables_of(&entry)
        };
        let mut after: Vec<EnvVariable> = before.iter().map(EnvVariable::duplicate).collect();
        change(&mut after)?;
        check_variables(&after)?;
        if same_variables(&before, &after) {
            return Ok(());
        }
        let shared_before = before
            .iter()
            .any(|var| self.shared_of(var.value.expose_secret()).is_some());
        let shared_after: Vec<uuid::Uuid> = after
            .iter()
            .filter_map(|var| self.shared_of(var.value.expose_secret()))
            .collect();
        {
            let mut entry = self
                .db
                .entry_mut(entry_id)
                .ok_or_else(|| Error::NotFound(format!("environment {id}")))?;
            let mut tracked = entry.track_changes();
            write_variables(&mut tracked, &before, &after);
        }
        self.settle_history(entry_id, true);
        // A shared value it uses again (an Undo) comes out of the recycle
        // bin; one it no longer uses may be used by none.
        for shared in shared_after {
            self.restore_shared(shared)?;
        }
        if shared_before {
            self.trash_unused_shared()?;
        }
        Ok(())
    }

    /// Puts an entry's earlier versions in the order KeePass keeps them,
    /// oldest first by when each was made, after a change here: the
    /// `keepass` crate puts the version a change keeps in front, so it is
    /// moved to the end first (`added`), where KeePass and KeePassXC add
    /// theirs. Then keeps no more than the database's `HistoryMaxItems` says
    /// (10 when it says nothing, none at 0, all at -1), the newest, as
    /// KeePass does on saving: an editor saving a managed file often would
    /// otherwise add a full copy each time.
    pub(super) fn settle_history(&mut self, entry_id: keepass::db::EntryId, added: bool) {
        settle_versions(&mut self.db, entry_id, added);
    }
}

/// [`Vault::settle_history`] on a database.
pub(super) fn settle_versions(db: &mut Database, entry_id: keepass::db::EntryId, added: bool) {
    let max = match db.meta.history_max_items {
        None => Some(10),
        Some(max) if max < 0 => None,
        Some(max) => Some(usize::try_from(max).unwrap_or(usize::MAX)),
    };
    let Some(mut entry) = db.entry_mut(entry_id) else {
        return;
    };
    let Some(before) = entry.history.as_ref().map(|h| h.get_entries().clone()) else {
        return;
    };
    let mut versions = before.clone();
    if added && !versions.is_empty() {
        let kept = versions.remove(0);
        versions.push(kept);
    }
    // Stable: of two made the same second, the later in place stays
    // later.
    versions.sort_by_key(|version| version.times.last_modification);
    if let Some(max) = max
        && versions.len() > max
    {
        versions.drain(..versions.len() - max);
    }
    if versions == before {
        return;
    }
    let mut settled = keepass::db::History::default();
    // Each one added goes in front.
    for version in versions.into_iter().rev() {
        settled.add_entry(version);
    }
    entry.history = Some(settled);
}

/// An entry's earlier versions, newest first by when each was made; of two
/// made the same second, the later in place (KeePass keeps them oldest
/// first).
pub(super) fn history_newest_first(entry: &Entry) -> Vec<&Entry> {
    let mut versions: Vec<&Entry> = entry
        .history
        .as_ref()
        .map(|history| history.get_entries().iter().rev().collect())
        .unwrap_or_default();
    versions.sort_by_key(|version| std::cmp::Reverse(version.times.last_modification));
    versions
}

/// Writes `after` over the variables `before` of an entry, with the marker
/// keeping their order and notes.
fn write_variables(entry: &mut Entry, before: &[EnvVariable], after: &[EnvVariable]) {
    for var in before {
        if !after.iter().any(|kept| kept.name == var.name) {
            entry.fields.remove(&field_name(&var.name));
        }
    }
    for var in after {
        let value = var.value.expose_secret();
        entry.set(
            field_name(&var.name),
            if var.secret {
                Value::protected(value)
            } else {
                Value::unprotected(value)
            },
        );
    }
    let stored = Stored {
        vars: after
            .iter()
            .map(|var| StoredVar {
                name: var.name.clone(),
                note: var.note.clone(),
            })
            .collect(),
    };
    entry.custom_data.insert(MARKER.to_owned(), marker(&stored));
    entry.times.last_modification = Some(Times::now());
}

/// The child group of `parent` named exactly `name`, made if needed.
pub(super) fn child_group(db: &mut Database, parent: GroupId, name: &str) -> Result<GroupId> {
    let found = db.group(parent).and_then(|group| {
        group
            .groups()
            .find(|child| child.name == name)
            .map(|child| child.id())
    });
    if let Some(found) = found {
        return Ok(found);
    }
    let mut parent = db
        .group_mut(parent)
        .ok_or_else(|| Error::NotFound(GROUP.into()))?;
    let mut group = parent.add_group();
    name.clone_into(&mut group.name);
    Ok(group.id())
}

/// `Shop · backend`, `Shop`, `backend`, or nothing.
pub fn label(project: Option<&str>, part: &str) -> String {
    [project.unwrap_or_default(), part]
        .into_iter()
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join(" · ")
}

/// A part as an environment keeps it: none, or a label like a project's.
pub fn check_part(part: &str) -> Result<String> {
    if part.trim().is_empty() {
        return Ok(String::new());
    }
    check_label(part, "a part")
}

fn same(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

fn text_item(text: &str) -> CustomDataItem {
    CustomDataItem {
        value: Some(CustomDataValue::String(text.to_owned())),
        last_modification_time: Some(Times::now()),
    }
}

fn marker(stored: &Stored) -> CustomDataItem {
    CustomDataItem {
        value: Some(CustomDataValue::String(
            serde_json::to_string(stored).unwrap_or_else(|_| "{}".to_owned()),
        )),
        last_modification_time: Some(Times::now()),
    }
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}
