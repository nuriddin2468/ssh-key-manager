//! Projects: labels that tie together what one piece of work needs — its
//! SSH hosts and keys, vault logins, environments and local folders.
//!
//! A project is a record in the database's custom data, as
//! `sshkm.project.<id>`: its name, color and folders, and its members by
//! reference — hosts by their `Host` alias in `~/.ssh/config`, keys by their
//! `SHA256:` fingerprint, environments by their group under `Environments`
//! ([`super::envs`]). Nothing is written into `~/.ssh/config`. Logins are
//! members by KeePass tag: an entry tagged with the project's name (in any
//! case), which KeePassXC shows and filters by. Membership is a label, so
//! an item can be in several projects; one in none is *Personal*, which is
//! nothing stored.
//!
//! Records go to the user's other devices as they are stored, as the device
//! records do ([`super::own_devices`]): the one changed last wins, fields of
//! later versions included, and a removed project stays as a tombstone so
//! that a sync doesn't bring it back. Two live projects with one name are
//! one label: whichever computer finds them joins them into the one with
//! the smaller id, so every computer ends up with the same.
//!
//! What the app shows while the vault is locked is a copy without secrets
//! ([`save_copy`]): names, colors and references.

use std::collections::{BTreeSet, HashMap};
use std::path::{Component, Path, PathBuf};

use keepass::db::{CustomDataItem, CustomDataValue, EntryId, Times};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::{Duration, OffsetDateTime};

use super::envs::{self, check_label};
use super::own_devices::time as record_time;
use super::{Vault, in_group, rfc3339};
use crate::{Error, Result, fsutil};

const PREFIX: &str = "sshkm.project.";
/// Most projects a vault has, not counting removed ones.
pub const MAX_PROJECTS: usize = 256;
/// Most records a sync takes, removed projects included.
pub const MAX_RECORDS: usize = 1024;
/// Most members of one kind a project has, and folders.
pub const MAX_MEMBERS: usize = 1000;
/// Longest record, in bytes of JSON.
const MAX_RECORD: usize = 256 * 1024;
/// Longest project name, in characters.
const MAX_NAME: usize = 64;
/// Longest folder, host alias or fingerprint, in bytes.
const MAX_REFERENCE: usize = 4096;
/// How far ahead of this computer's clock a record from another device may
/// be dated, for clocks a little apart.
const MAX_AHEAD: Duration = Duration::minutes(5);

/// A project's color, a name the UI maps to its palette.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum ProjectColor {
    #[default]
    Teal,
    Blue,
    Indigo,
    Violet,
    Pink,
    Red,
    Orange,
    Amber,
    Green,
    Slate,
}

impl ProjectColor {
    pub const ALL: [Self; 10] = [
        Self::Teal,
        Self::Blue,
        Self::Indigo,
        Self::Violet,
        Self::Pink,
        Self::Red,
        Self::Orange,
        Self::Amber,
        Self::Green,
        Self::Slate,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Self::Teal => "teal",
            Self::Blue => "blue",
            Self::Indigo => "indigo",
            Self::Violet => "violet",
            Self::Pink => "pink",
            Self::Red => "red",
            Self::Orange => "orange",
            Self::Amber => "amber",
            Self::Green => "green",
            Self::Slate => "slate",
        }
    }

    /// The color a record names; one this version doesn't know (from a
    /// later one) shows as the default.
    fn parse(text: &str) -> Self {
        Self::ALL
            .into_iter()
            .find(|color| color.as_str() == text)
            .unwrap_or_default()
    }

    /// A color for the next new project: the first that no project has, or
    /// the one fewest have.
    pub fn next(taken: impl IntoIterator<Item = Self>) -> Self {
        let mut counts = [0usize; Self::ALL.len()];
        for color in taken {
            if let Some(index) = Self::ALL.iter().position(|c| *c == color) {
                counts[index] += 1;
            }
        }
        let fewest = counts.iter().copied().min().unwrap_or_default();
        Self::ALL[counts.iter().position(|n| *n == fewest).unwrap_or_default()]
    }
}

/// A project as the app shows it. Holds no secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct Project {
    pub id: String,
    pub name: String,
    pub color: ProjectColor,
    /// Folders on the user's computers: `~/…` under the home folder, else
    /// the full path ([`folder_text`]).
    pub folders: Vec<String>,
    /// Hosts by their `Host` alias in `~/.ssh/config`.
    pub hosts: Vec<String>,
    /// Keys by their `SHA256:…` fingerprint.
    pub keys: Vec<String>,
    /// Environments by their project's group under `Environments`: the
    /// `project` of an [`envs::EnvSummary`].
    pub environments: Vec<String>,
    /// The vault's logins tagged with the project's name, by entry id, not
    /// counting those in the recycle bin. Empty in the copy kept for while
    /// the vault is locked.
    pub logins: Vec<String>,
    /// RFC 3339, UTC.
    pub modified: String,
}

/// A new project, or the new name and color of one.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct ProjectInput {
    pub name: String,
    pub color: ProjectColor,
}

/// Something a project can hold, by reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum ProjectMember {
    /// A host by its `Host` alias in `~/.ssh/config`.
    Host { alias: String },
    /// A key by its `SHA256:…` fingerprint.
    Key { fingerprint: String },
    /// A login of the vault by its entry id: the entry gets the project's
    /// name as a KeePass tag.
    Login { id: String },
    /// The environments of one project group under `Environments`.
    Environment { group: String },
    /// A folder as [`folder_text`] keeps it.
    Folder { path: String },
}

/// A project's record as it goes to the user's other devices: the stored
/// JSON as it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectRecord {
    pub id: String,
    pub record: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Stored {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    color: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    folders: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    environments: Vec<String>,
    /// RFC 3339, UTC, to the second: the newer record wins.
    modified: String,
    /// When it was removed, for a tombstone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    removed: Option<String>,
    /// Whatever a later version keeps here.
    #[serde(flatten)]
    rest: Map<String, Value>,
}

impl Stored {
    fn is_live(&self) -> bool {
        self.removed.is_none()
    }

    /// Adds the members of `other` this one lacks.
    fn take_members(&mut self, other: &Self) {
        for (mine, theirs) in [
            (&mut self.folders, &other.folders),
            (&mut self.hosts, &other.hosts),
            (&mut self.keys, &other.keys),
            (&mut self.environments, &other.environments),
        ] {
            for value in theirs {
                if !mine.contains(value) && mine.len() < MAX_MEMBERS {
                    mine.push(value.clone());
                }
            }
        }
    }
}

/// The name a project's logins are tagged with, checked: trimmed, at most
/// [`MAX_NAME`] characters, without control characters or the `;` and `,`
/// that separate KeePass tags.
fn check_name(text: &str) -> Result<String> {
    let text = text.trim();
    if text.is_empty() {
        return Err(Error::invalid("a project needs a name"));
    }
    if text.chars().count() > MAX_NAME {
        return Err(Error::invalid(format!(
            "project names are at most {MAX_NAME} characters"
        )));
    }
    if text.chars().any(|c| c.is_control() || c == ';' || c == ',') {
        return Err(Error::invalid(
            "project names can't have `;`, `,` or control characters",
        ));
    }
    Ok(text.to_owned())
}

/// A `Host` alias a project can hold: one word, not a pattern.
fn check_alias(alias: &str) -> Result<String> {
    let alias = alias.trim();
    let fine = !alias.is_empty()
        && alias.len() <= 255
        && !alias.starts_with(['#', '!'])
        && !alias.contains(['*', '?'])
        && !alias
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '\'' | '\\'));
    if !fine {
        return Err(Error::invalid(format!(
            "not a host alias: {:?}",
            alias.chars().take(MAX_NAME).collect::<String>()
        )));
    }
    Ok(alias.to_owned())
}

/// A key's `SHA256:` fingerprint.
fn check_fingerprint(fingerprint: &str) -> Result<String> {
    let fingerprint = fingerprint.trim();
    let fine = fingerprint.strip_prefix("SHA256:").is_some_and(|hash| {
        !hash.is_empty()
            && hash.len() <= 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
    });
    if !fine {
        return Err(Error::invalid("not a SHA256 key fingerprint"));
    }
    Ok(fingerprint.to_owned())
}

/// A folder as a record keeps it: one line, not too long. Whether it names
/// a folder on this computer is [`folder_path`]'s question.
fn check_folder_text(text: &str) -> Result<String> {
    if text.is_empty()
        || text.len() > MAX_REFERENCE
        || text.chars().any(char::is_control)
        || text.trim() != text
    {
        return Err(Error::invalid("not a folder"));
    }
    Ok(text.to_owned())
}

/// How a project keeps the folder `path`: `~/…` when it is in `home`, so
/// the same folder on another of the user's computers is the same text;
/// else the full path. The path must be absolute, without `..`, and in
/// Unicode.
pub fn folder_text(path: &Path, home: Option<&Path>) -> Result<String> {
    if !path.is_absolute() || path.components().any(|c| c == Component::ParentDir) {
        return Err(Error::invalid(format!(
            "{} is not a full path",
            path.display()
        )));
    }
    let unicode = || Error::invalid(format!("{} is not in Unicode", path.display()));
    if let Some(rest) = home.and_then(|home| path.strip_prefix(home).ok()) {
        let parts: Vec<&str> = rest
            .components()
            .map(|c| c.as_os_str().to_str().ok_or_else(unicode))
            .collect::<Result<_>>()?;
        let text = if parts.is_empty() {
            "~".to_owned()
        } else {
            format!("~/{}", parts.join("/"))
        };
        return check_folder_text(&text);
    }
    check_folder_text(path.to_str().ok_or_else(unicode)?)
}

/// The folder a project's `text` names on this computer, if it is a full
/// path here (`~/…` against `home`) without `..`. Whether it exists is not
/// checked.
pub fn folder_path(text: &str, home: Option<&Path>) -> Option<PathBuf> {
    check_folder_text(text).ok()?;
    let path = if text == "~" {
        home?.to_path_buf()
    } else if let Some(rest) = text.strip_prefix("~/").or_else(|| text.strip_prefix("~\\")) {
        let mut path = home?.to_path_buf();
        for part in rest.split(['/', '\\']).filter(|part| !part.is_empty()) {
            path.push(part);
        }
        path
    } else {
        PathBuf::from(text)
    };
    let fine = path.is_absolute()
        && path
            .components()
            .all(|c| !matches!(c, Component::ParentDir | Component::CurDir));
    fine.then_some(path)
}

/// A record, if it is one: a time it changed and, unless it is a
/// tombstone, a name; every reference checked.
fn parse(id: &str, json: &str) -> Option<Stored> {
    if json.len() > MAX_RECORD || uuid::Uuid::parse_str(id).is_err() {
        return None;
    }
    let stored: Stored = serde_json::from_str(json).ok()?;
    record_time(&stored.modified)?;
    if let Some(removed) = &stored.removed {
        return record_time(removed).map(|_| stored);
    }
    let fine = check_name(&stored.name).is_ok_and(|name| name == stored.name)
        && [
            &stored.folders,
            &stored.hosts,
            &stored.keys,
            &stored.environments,
        ]
        .iter()
        .all(|list| list.len() <= MAX_MEMBERS)
        && stored.folders.iter().all(|f| check_folder_text(f).is_ok())
        && stored.hosts.iter().all(|h| check_alias(h).is_ok())
        && stored.keys.iter().all(|k| check_fingerprint(k).is_ok())
        && stored
            .environments
            .iter()
            .all(|e| check_label(e, "a project").is_ok_and(|label| label == *e));
    fine.then_some(stored)
}

/// Fails unless the records are ones a sync may take.
pub fn check_records(records: &[ProjectRecord]) -> Result<()> {
    if records.len() > MAX_RECORDS {
        return Err(Error::invalid("too many projects"));
    }
    for (index, record) in records.iter().enumerate() {
        if parse(&record.id, &record.record).is_none()
            || records[..index].iter().any(|other| other.id == record.id)
        {
            return Err(Error::invalid("not a project record"));
        }
    }
    Ok(())
}

/// Whether `incoming` (stored as `json`) takes the place of `mine`: the
/// record changed later wins, a tombstone like any other; at the same
/// second the greater JSON, so both computers pick the same.
fn wins(incoming: &Stored, json: &str, mine: &Stored) -> bool {
    let changed = |stored: &Stored| {
        [Some(&stored.modified), stored.removed.as_ref()]
            .into_iter()
            .flatten()
            .filter_map(|text| record_time(text))
            .max()
    };
    match changed(incoming).cmp(&changed(mine)) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => {
            serde_json::to_string(mine).is_ok_and(|mine| json > mine.as_str())
        }
    }
}

fn new_id() -> String {
    let mut bytes = [0; 16];
    OsRng.fill_bytes(&mut bytes);
    uuid::Builder::from_random_bytes(bytes)
        .into_uuid()
        .to_string()
}

fn now() -> String {
    rfc3339(Times::now())
}

fn project_view(id: String, stored: Stored, tagged: &HashMap<String, Vec<String>>) -> Project {
    Project {
        id,
        color: ProjectColor::parse(&stored.color),
        logins: tagged
            .get(&stored.name.to_lowercase())
            .cloned()
            .unwrap_or_default(),
        name: stored.name,
        folders: stored.folders,
        hosts: stored.hosts,
        keys: stored.keys,
        environments: stored.environments,
        modified: stored.modified,
    }
}

fn same_name(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

impl Vault {
    /// The projects, by name.
    pub fn projects(&self) -> Vec<Project> {
        let tagged = self.tagged_logins();
        let mut projects: Vec<Project> = self
            .project_records_stored()
            .into_iter()
            .filter(|(_, stored)| stored.is_live())
            .map(|(id, stored)| project_view(id, stored, &tagged))
            .collect();
        projects.sort_by_cached_key(|p| (p.name.to_lowercase(), p.id.clone()));
        projects
    }

    pub fn project(&self, id: &str) -> Result<Project> {
        let stored = self.live_project(id)?;
        Ok(project_view(id.to_owned(), stored, &self.tagged_logins()))
    }

    /// Adds a project and returns its id. The logins already tagged with
    /// its name are its members at once.
    pub fn add_project(&mut self, input: &ProjectInput) -> Result<String> {
        let name = check_name(&input.name)?;
        let live: Vec<(String, Stored)> = self
            .project_records_stored()
            .into_iter()
            .filter(|(_, stored)| stored.is_live())
            .collect();
        if live.len() >= MAX_PROJECTS {
            return Err(Error::invalid(format!(
                "a vault holds at most {MAX_PROJECTS} projects"
            )));
        }
        if live
            .iter()
            .any(|(_, stored)| same_name(&stored.name, &name))
        {
            return Err(Error::AlreadyExists(name));
        }
        let id = new_id();
        self.put_project(
            &id,
            &Stored {
                name,
                color: input.color.as_str().to_owned(),
                folders: Vec::new(),
                hosts: Vec::new(),
                keys: Vec::new(),
                environments: Vec::new(),
                modified: now(),
                removed: None,
                rest: Map::new(),
            },
        )?;
        Ok(id)
    }

    /// Renames a project or changes its color. A new name moves the tag on
    /// its logins along.
    pub fn update_project(&mut self, id: &str, input: &ProjectInput) -> Result<()> {
        let name = check_name(&input.name)?;
        let mut stored = self.live_project(id)?;
        let color = input.color.as_str();
        if stored.name == name && stored.color == color {
            return Ok(());
        }
        let renamed = stored.name != name;
        if renamed
            && self
                .project_records_stored()
                .iter()
                .any(|(other, s)| other != id && s.is_live() && same_name(&s.name, &name))
        {
            return Err(Error::AlreadyExists(name));
        }
        let old = std::mem::replace(&mut stored.name, name.clone());
        color.clone_into(&mut stored.color);
        stored.modified = now();
        self.put_project(id, &stored)?;
        if renamed {
            self.retag(&old, Some(&name));
        }
        Ok(())
    }

    /// Removes a project, leaving a tombstone. Its logins lose its tag;
    /// nothing else changes: hosts, keys, environments and folders are only
    /// referenced.
    pub fn remove_project(&mut self, id: &str) -> Result<()> {
        let stored = self.live_project(id)?;
        let time = now();
        self.put_project(
            id,
            &Stored {
                name: String::new(),
                color: String::new(),
                folders: Vec::new(),
                hosts: Vec::new(),
                keys: Vec::new(),
                environments: Vec::new(),
                modified: time.clone(),
                removed: Some(time),
                rest: Map::new(),
            },
        )?;
        self.retag(&stored.name, None);
        Ok(())
    }

    /// Puts `member` into the project (`included`) or takes it out.
    /// Returns whether anything changed.
    pub fn set_project_member(
        &mut self,
        id: &str,
        member: &ProjectMember,
        included: bool,
    ) -> Result<bool> {
        let mut stored = self.live_project(id)?;
        let (list, value) = match member {
            ProjectMember::Login { id: entry } => {
                return self.tag_login(entry, &stored.name, included);
            }
            ProjectMember::Host { alias } => (&mut stored.hosts, check_alias(alias)?),
            ProjectMember::Key { fingerprint } => {
                (&mut stored.keys, check_fingerprint(fingerprint)?)
            }
            ProjectMember::Environment { group } => {
                (&mut stored.environments, check_label(group, "a project")?)
            }
            ProjectMember::Folder { path } => (&mut stored.folders, check_folder_text(path)?),
        };
        let position = list.iter().position(|v| *v == value);
        match (included, position) {
            (true, Some(_)) | (false, None) => return Ok(false),
            (true, None) => {
                if list.len() >= MAX_MEMBERS {
                    return Err(Error::invalid(format!(
                        "a project holds at most {MAX_MEMBERS} of a kind"
                    )));
                }
                list.push(value);
            }
            (false, Some(index)) => {
                list.remove(index);
            }
        }
        stored.modified = now();
        self.put_project(id, &stored)?;
        Ok(true)
    }

    /// Every record, tombstones too, to send to another own device.
    pub fn project_records(&self) -> Vec<ProjectRecord> {
        self.db
            .meta
            .custom_data
            .iter()
            .filter_map(|(key, item)| {
                let id = key.strip_prefix(PREFIX)?;
                let Some(CustomDataValue::String(json)) = &item.value else {
                    return None;
                };
                parse(id, json)?;
                Some(ProjectRecord {
                    id: id.to_owned(),
                    record: json.clone(),
                })
            })
            .collect()
    }

    /// Takes the records another own device sent that win over this
    /// vault's ([`wins`]), but none dated more than [`MAX_AHEAD`] from now.
    /// A project renamed or removed there moves or drops the tag on this
    /// vault's logins too, and projects that end up with one name are
    /// joined. Returns whether anything changed.
    pub fn merge_projects(&mut self, theirs: &[ProjectRecord]) -> Result<bool> {
        let latest = OffsetDateTime::now_utc() + MAX_AHEAD;
        let mut changed = false;
        let mut live = self
            .project_records_stored()
            .iter()
            .filter(|(_, stored)| stored.is_live())
            .count();
        for record in theirs.iter().take(MAX_RECORDS) {
            let Some(incoming) = parse(&record.id, &record.record) else {
                continue;
            };
            let ahead = [Some(&incoming.modified), incoming.removed.as_ref()]
                .into_iter()
                .flatten()
                .any(|text| record_time(text).is_none_or(|t| t > latest));
            let mine = self.stored_project(&record.id);
            if ahead
                || mine
                    .as_ref()
                    .is_some_and(|mine| !wins(&incoming, &record.record, mine))
            {
                continue;
            }
            let was_live = mine.as_ref().is_some_and(Stored::is_live);
            match (was_live, incoming.is_live()) {
                (false, true) if live >= MAX_PROJECTS => continue,
                (false, true) => live += 1,
                (true, false) => live -= 1,
                _ => {}
            }
            self.put_raw(&record.id, &record.record);
            if let Some(mine) = mine.filter(Stored::is_live)
                && !(incoming.is_live() && incoming.name == mine.name)
            {
                let still_named = self
                    .project_records_stored()
                    .iter()
                    .any(|(_, s)| s.is_live() && same_name(&s.name, &mine.name));
                if !still_named {
                    self.retag(&mine.name, incoming.is_live().then_some(&*incoming.name));
                }
            }
            changed = true;
        }
        if self.join_same_names()? {
            changed = true;
        }
        Ok(changed)
    }

    /// Joins live projects that have one name into the one with the
    /// smallest id, which gets the others' members; the others become
    /// tombstones. Returns whether any were joined.
    fn join_same_names(&mut self) -> Result<bool> {
        let live: Vec<(String, Stored)> = self
            .project_records_stored()
            .into_iter()
            .filter(|(_, stored)| stored.is_live())
            .collect();
        let mut joined = false;
        let mut done = BTreeSet::new();
        for (_, stored) in &live {
            let key = stored.name.to_lowercase();
            if done.contains(&key) {
                continue;
            }
            let mut same: Vec<&(String, Stored)> = live
                .iter()
                .filter(|(_, other)| other.name.to_lowercase() == key)
                .collect();
            done.insert(key);
            if same.len() < 2 {
                continue;
            }
            same.sort_by(|a, b| a.0.cmp(&b.0));
            let (keep_id, keep) = same[0];
            let mut keep = keep.clone();
            let time = now();
            for (other_id, other) in &same[1..] {
                keep.take_members(other);
                let mut tombstone = (*other).clone();
                tombstone.removed = Some(time.clone());
                tombstone.modified.clone_from(&time);
                self.put_project(other_id, &tombstone)?;
            }
            keep.modified = time;
            self.put_project(keep_id, &keep)?;
            joined = true;
        }
        Ok(joined)
    }

    /// Adds the project's tag to a login or removes it. Returns whether
    /// anything changed.
    fn tag_login(&mut self, entry: &str, name: &str, included: bool) -> Result<bool> {
        let entry_id = super::parse_id(entry)?;
        {
            let found = self.find(entry)?;
            if envs::is_environment(&found) {
                return Err(Error::invalid(
                    "an environment joins a project by its group",
                ));
            }
            let has = found.tags.iter().any(|tag| same_name(tag.trim(), name));
            if has == included {
                return Ok(false);
            }
        }
        let mut entry = self
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| Error::NotFound(format!("entry {entry}")))?;
        if included {
            entry.tags.retain(|tag| !tag.trim().is_empty());
            entry.tags.push(name.to_owned());
        } else {
            entry
                .tags
                .retain(|tag| !tag.trim().is_empty() && !same_name(tag.trim(), name));
        }
        entry.times.last_modification = Some(Times::now());
        Ok(true)
    }

    /// Moves the tag `old` to `new` on every entry that has it, or removes
    /// it (`new` is `None`). Environments are left alone.
    fn retag(&mut self, old: &str, new: Option<&str>) {
        let ids: Vec<EntryId> = self
            .db
            .iter_all_entries()
            .filter(|entry| {
                !envs::is_environment(entry)
                    && entry.tags.iter().any(|tag| same_name(tag.trim(), old))
            })
            .map(|entry| entry.id())
            .collect();
        for id in ids {
            let Some(mut entry) = self.db.entry_mut(id) else {
                continue;
            };
            let mut tags: Vec<String> = Vec::new();
            for tag in &entry.tags {
                let tag = tag.trim();
                let tag = if same_name(tag, old) {
                    match new {
                        Some(new) => new,
                        None => continue,
                    }
                } else {
                    tag
                };
                if !tag.is_empty() && !tags.iter().any(|t| t == tag) {
                    tags.push(tag.to_owned());
                }
            }
            entry.tags = tags;
            entry.times.last_modification = Some(Times::now());
        }
    }

    /// The ids of the logins outside the recycle bin, by each of their
    /// tags in lower case.
    fn tagged_logins(&self) -> HashMap<String, Vec<String>> {
        let bin = self.db.meta.recyclebin_uuid;
        let mut tagged: HashMap<String, Vec<String>> = HashMap::new();
        for entry in self.db.iter_all_entries() {
            if envs::is_environment(&entry) || in_group(entry.parent().id(), bin, &self.db) {
                continue;
            }
            let tags: BTreeSet<String> = entry
                .tags
                .iter()
                .map(|tag| tag.trim().to_lowercase())
                .filter(|tag| !tag.is_empty())
                .collect();
            for tag in tags {
                tagged
                    .entry(tag)
                    .or_default()
                    .push(entry.id().uuid().to_string());
            }
        }
        tagged
    }

    fn project_records_stored(&self) -> Vec<(String, Stored)> {
        self.db
            .meta
            .custom_data
            .iter()
            .filter_map(|(key, item)| {
                let id = key.strip_prefix(PREFIX)?;
                let Some(CustomDataValue::String(json)) = &item.value else {
                    return None;
                };
                Some((id.to_owned(), parse(id, json)?))
            })
            .collect()
    }

    fn stored_project(&self, id: &str) -> Option<Stored> {
        let item = self.db.meta.custom_data.get(&format!("{PREFIX}{id}"))?;
        let Some(CustomDataValue::String(json)) = &item.value else {
            return None;
        };
        parse(id, json)
    }

    fn live_project(&self, id: &str) -> Result<Stored> {
        self.stored_project(id)
            .filter(Stored::is_live)
            .ok_or_else(|| Error::NotFound(format!("project {id}")))
    }

    fn put_project(&mut self, id: &str, stored: &Stored) -> Result<()> {
        let json =
            serde_json::to_string(stored).map_err(|e| Error::Parse(format!("project: {e}")))?;
        if json.len() > MAX_RECORD {
            return Err(Error::invalid("the project is too large"));
        }
        self.put_raw(id, &json);
        Ok(())
    }

    fn put_raw(&mut self, id: &str, json: &str) {
        self.db.meta.custom_data.insert(
            format!("{PREFIX}{id}"),
            CustomDataItem {
                value: Some(CustomDataValue::String(json.to_owned())),
                last_modification_time: Some(Times::now()),
            },
        );
    }
}

/// The copy of the projects kept for while the vault is locked.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LockedCopy {
    vault_id: String,
    projects: Vec<Project>,
}

/// Keeps a copy of `projects` without secrets — names, colors and
/// references; no logins — for the vault `vault_id`, readable by this user
/// only. Writes nothing when the file holds the same already.
pub fn save_copy(path: &Path, vault_id: &str, projects: &[Project]) -> Result<()> {
    let copy = LockedCopy {
        vault_id: vault_id.to_owned(),
        projects: projects
            .iter()
            .map(|project| Project {
                logins: Vec::new(),
                ..project.clone()
            })
            .collect(),
    };
    let json = serde_json::to_vec(&copy).map_err(|e| Error::Parse(format!("projects: {e}")))?;
    if std::fs::read(path).is_ok_and(|current| current == json) {
        return Ok(());
    }
    fsutil::atomic_write(path, &json, 0o600)
}

/// The projects [`save_copy`] kept for the vault `vault_id`; none if the
/// copy is of another vault, missing or unreadable.
pub fn load_copy(path: &Path, vault_id: &str) -> Vec<Project> {
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    match serde_json::from_slice::<LockedCopy>(&bytes) {
        Ok(copy) if copy.vault_id == vault_id => copy.projects,
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests;
