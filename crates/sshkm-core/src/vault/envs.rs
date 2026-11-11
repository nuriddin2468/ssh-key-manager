//! Secret environments: the variables of a project's `.env` files (dev,
//! staging, prod…), kept in the vault.
//!
//! Each environment is one KeePass entry in the group
//! `Environments/<project>`, titled with the environment's name, with one
//! custom string field per variable, so KeePassXC shows them as additional
//! attributes. A secret variable's field is protected, as a password is. The
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
pub use self::files::{EnvFile, EnvKind};
pub use self::format::{EnvFormat, render};
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
/// The group under the root that holds one group per project.
pub const GROUP: &str = "Environments";
/// Custom data that marks an entry as an environment.
const MARKER: &str = "sshkm.env";
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
    /// The project it belongs to: its group under `Environments`.
    pub project: String,
    /// `dev`, `staging`, `prod`…: the entry's title.
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
    /// The files it is written to.
    pub files: Vec<EnvFile>,
}

/// A new environment, or the new names of one.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct EnvInput {
    pub project: String,
    pub name: String,
    #[serde(default)]
    pub notes: String,
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
    /// and then from development to production.
    pub fn environments(&self) -> Vec<EnvSummary> {
        let mut list: Vec<EnvSummary> = self
            .db
            .iter_all_entries()
            .filter(is_environment)
            .map(|entry| self.env_summary(&entry))
            .collect();
        list.sort_by_cached_key(|env| {
            (
                env.in_trash,
                env.project.to_lowercase(),
                stage(&env.name),
                env.name.to_lowercase(),
            )
        });
        list
    }

    pub fn environment(&self, id: &str) -> Result<EnvDetail> {
        let entry = self.env_entry(id)?;
        Ok(EnvDetail {
            summary: self.env_summary(&entry),
            notes: entry.get(fields::NOTES).unwrap_or_default().to_owned(),
            variables: variables_of(&entry)
                .into_iter()
                .map(|var| EnvVarInfo {
                    empty: var.value.expose_secret().is_empty(),
                    name: var.name,
                    secret: var.secret,
                    note: var.note,
                })
                .collect(),
            files: files::files_of(&entry),
        })
    }

    /// The variables of an environment with their values.
    pub fn env_variables(&self, id: &str) -> Result<Vec<EnvVariable>> {
        let entry = self.env_entry(id)?;
        Ok(variables_of(&entry))
    }

    /// One variable's value.
    pub fn env_value(&self, id: &str, name: &str) -> Result<SecretString> {
        let entry = self.env_entry(id)?;
        variables_of(&entry)
            .into_iter()
            .find(|var| var.name == name)
            .map(|var| var.value)
            .ok_or_else(|| Error::NotFound(format!("variable {name}")))
    }

    /// Adds an empty environment and returns its id.
    pub fn add_environment(&mut self, input: &EnvInput) -> Result<String> {
        let project = check_label(&input.project, "a project")?;
        let name = check_label(&input.name, "an environment")?;
        check_field(&input.notes)?;
        self.check_free(&project, &name, None)?;
        let group = self.project_group(&project)?;
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
        Ok(entry.id().uuid().to_string())
    }

    /// Renames an environment, moves it to another project, or changes its
    /// notes, keeping the previous version in its history.
    pub fn update_environment(&mut self, id: &str, input: &EnvInput) -> Result<()> {
        let project = check_label(&input.project, "a project")?;
        let name = check_label(&input.name, "an environment")?;
        check_field(&input.notes)?;
        let current = self.environment(id)?;
        if current.summary.in_trash {
            return Err(Error::invalid("restore the environment first"));
        }
        self.check_free(&project, &name, Some(id))?;
        let notes = input.notes.trim_end();
        let target = if project == current.summary.project {
            None
        } else {
            Some(self.project_group(&project)?)
        };
        if target.is_none() && name == current.summary.name && notes == current.notes {
            return Ok(());
        }
        let mut entry = self
            .db
            .entry_mut(parse_id(id)?)
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
        if let Some(group) = target {
            tracked
                .move_to(group)
                .map_err(|_| Error::NotFound(GROUP.into()))?;
        }
        tracked.times.last_modification = Some(Times::now());
        Ok(())
    }

    /// Adds a variable (`previous` is `None`) or changes the one named
    /// `previous`, perhaps renaming it.
    pub fn set_env_variable(
        &mut self,
        id: &str,
        previous: Option<&str>,
        input: &EnvVarInput,
    ) -> Result<()> {
        let name = input.name.trim().to_owned();
        let note = input.note.trim().to_owned();
        self.edit_variables(id, |vars| {
            let value = match &input.value {
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

    /// Removes a variable.
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
    /// added at the end.
    pub fn import_env_variables(
        &mut self,
        id: &str,
        imported: &[EnvVariable],
    ) -> Result<ImportCounts> {
        let mut counts = ImportCounts::default();
        self.edit_variables(id, |vars| {
            for new in imported {
                if let Some(var) = vars.iter_mut().find(|var| var.name == new.name) {
                    var.value = duplicate(&new.value);
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

    /// Adds an environment another computer sent, as a new one: if the
    /// project has one of that name, it gets a number (`dev 2`). Returns its
    /// id and name.
    pub fn add_received_environment(
        &mut self,
        project: &str,
        name: &str,
        notes: &str,
        vars: &[EnvVariable],
    ) -> Result<(String, String)> {
        check_variables(vars)?;
        let project = check_label(project, "a project")?;
        let base = check_label(name, "an environment")?;
        let mut name = base.clone();
        let mut n = 2;
        while self.check_free(&project, &name, None).is_err() {
            let suffix = format!(" {n}");
            let room = MAX_LABEL - suffix.chars().count();
            name = format!("{}{suffix}", base.chars().take(room).collect::<String>());
            n += 1;
        }
        let id = self.add_environment(&EnvInput {
            project,
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
        let text = render(format, &env.summary.project, &env.summary.name, &vars)?;
        write_private(&target, text.as_bytes())?;
        Ok(vars.len())
    }

    /// Moves an environment to the recycle bin.
    pub fn trash_environment(&mut self, id: &str) -> Result<()> {
        self.env_entry(id)?;
        self.trash_entry(id)
    }

    /// Takes an environment out of the recycle bin, back into its project,
    /// unless that project has one of its name now.
    pub fn restore_environment(&mut self, id: &str) -> Result<()> {
        let env = self.environment(id)?.summary;
        if !env.in_trash {
            return Ok(());
        }
        self.check_free(&env.project, &env.name, Some(id))?;
        self.restore_entry(id)
    }

    /// Deletes an environment in the recycle bin for good.
    pub fn delete_environment(&mut self, id: &str) -> Result<()> {
        self.env_entry(id)?;
        self.delete_entry(id)
    }

    fn env_entry(&self, id: &str) -> Result<EntryRef<'_>> {
        let entry = self.find(id)?;
        if !is_environment(&entry) {
            return Err(Error::NotFound(format!("environment {id}")));
        }
        Ok(entry)
    }

    pub(super) fn env_summary(&self, entry: &EntryRef<'_>) -> EnvSummary {
        let bin = self.db.meta.recyclebin_uuid;
        let in_trash = in_group(entry.parent().id(), bin, &self.db);
        let group = if in_trash {
            entry.previous_parent()
        } else {
            Some(entry.parent())
        };
        // The group holding it, unless that is the root or `Environments`.
        let project = group
            .filter(|group| {
                group
                    .parent()
                    .is_some_and(|parent| parent.parent().is_some() || group.name != GROUP)
            })
            .map(|group| group.name.clone())
            .unwrap_or_default();
        let vars = variables_of(entry);
        EnvSummary {
            id: entry.id().uuid().to_string(),
            project,
            name: entry.get(fields::TITLE).unwrap_or_default().to_owned(),
            kind: files::kind_of(entry),
            variable_count: count(vars.len()),
            secret_count: count(vars.iter().filter(|var| var.secret).count()),
            in_trash,
            modified: entry.times.last_modification.map(rfc3339),
        }
    }

    /// Fails if `project` has an environment named `name` (ignoring case)
    /// outside the recycle bin, other than `except`.
    fn check_free(&self, project: &str, name: &str, except: Option<&str>) -> Result<()> {
        let taken = self.environments().into_iter().any(|env| {
            !env.in_trash
                && Some(env.id.as_str()) != except
                && env.project == project
                && env.name.to_lowercase() == name.to_lowercase()
        });
        if taken {
            return Err(Error::AlreadyExists(format!("{project} / {name}")));
        }
        Ok(())
    }

    /// The group of `project` under `Environments`, made if needed.
    fn project_group(&mut self, project: &str) -> Result<GroupId> {
        let root = self.db.root().id();
        let envs = child_group(&mut self.db, root, GROUP)?;
        child_group(&mut self.db, envs, project)
    }

    /// Changes an environment's variables: `change` gets them in order with
    /// their values. What it leaves is checked and written back as one new
    /// version, keeping the previous one in the entry's history.
    fn edit_variables(
        &mut self,
        id: &str,
        change: impl FnOnce(&mut Vec<EnvVariable>) -> Result<()>,
    ) -> Result<()> {
        let entry_id = parse_id(id)?;
        let before = {
            let entry = self.env_entry(id)?;
            if in_group(entry.parent().id(), self.db.meta.recyclebin_uuid, &self.db) {
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
        {
            let mut entry = self
                .db
                .entry_mut(entry_id)
                .ok_or_else(|| Error::NotFound(format!("environment {id}")))?;
            let mut tracked = entry.track_changes();
            write_variables(&mut tracked, &before, &after);
        }
        self.trim_history(entry_id);
        Ok(())
    }

    /// Keeps no more earlier versions of an entry than the database's
    /// `HistoryMaxItems` says (10 when it says nothing; none is kept at 0;
    /// all at -1), the newest ones, as KeePass does on saving: an editor
    /// saving a managed file often would otherwise add a full copy each
    /// time.
    fn trim_history(&mut self, entry_id: keepass::db::EntryId) {
        let max = match self.db.meta.history_max_items {
            None => 10,
            Some(max) if max < 0 => return,
            Some(max) => usize::try_from(max).unwrap_or(usize::MAX),
        };
        let Some(mut entry) = self.db.entry_mut(entry_id) else {
            return;
        };
        let kept: Vec<Entry> = match entry.history.as_ref() {
            Some(history) if history.get_entries().len() > max => {
                history.get_entries()[..max].to_vec()
            }
            _ => return,
        };
        let mut trimmed = keepass::db::History::default();
        // Newest first: each one added goes in front.
        for version in kept.into_iter().rev() {
            trimmed.add_entry(version);
        }
        entry.history = Some(trimmed);
    }
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
fn child_group(db: &mut Database, parent: GroupId, name: &str) -> Result<GroupId> {
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
