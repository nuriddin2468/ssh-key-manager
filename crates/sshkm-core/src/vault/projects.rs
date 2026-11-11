//! Projects: labels that tie together what one piece of work needs — its
//! SSH hosts and keys, vault logins, environments and local folders.
//!
//! A project is a record in the database's custom data, as
//! `sshkm.project.<id>`: its name, color and members by reference — hosts by
//! their `Host` alias in `~/.ssh/config`, keys by their `SHA256:`
//! fingerprint, logins by their entry id, environments by their group under
//! `Environments` ([`super::envs`]), and folders. Nothing is written into
//! `~/.ssh/config`. Membership is a label, so an item can be in several
//! projects; one in none is *Personal*, which is nothing stored.
//!
//! A project's logins also carry the KeePass tag `project/<name>`
//! ([`TAG_PREFIX`]), so KeePassXC shows and filters by them. The record is
//! what counts: the tags are written from the records after every change
//! and sync ([`Vault::sync_tags`]), so the user's own tags never make or
//! break a membership. Only `project/` tags with a name some record has or
//! had are the app's; a login tagged in KeePassXC with a live project's
//! name joins it, unless it was taken out of it before.
//!
//! Records go to the user's other devices as they are stored, and two
//! copies of a record merge field by field and member by member: the name
//! and the color as the one changed last, and each member with the times it
//! was added and removed, so additions and removals made on two computers
//! before they synced all survive. A removed project stays as a tombstone
//! for a while ([`KEEP_REMOVED_MS`]) so that a sync doesn't bring it back;
//! a change made after the removal does. Two live projects with one name
//! are one label: whichever computer finds them joins them into the one
//! with the smaller id, and a project joined into another keeps passing on
//! what it is given, so every computer ends up with the same.
//!
//! What the app shows while the vault is locked is a copy without secrets
//! ([`save_copy`]): names, colors and references.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use keepass::db::{CustomDataItem, CustomDataValue, EntryId, Times};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use super::envs::{self, check_label};
use super::{Vault, in_group};
use crate::{Error, Result, fsutil};

pub mod suggest;

const PREFIX: &str = "sshkm.project.";
/// What a project's logins are tagged with in KeePass, before its name.
pub const TAG_PREFIX: &str = "project/";
/// Most projects a vault has, not counting removed ones.
pub const MAX_PROJECTS: usize = 256;
/// Most records a sync takes, removed projects included.
pub const MAX_RECORDS: usize = 1024;
/// Most members of one kind a project has, and folders.
pub const MAX_MEMBERS: usize = 1000;
/// Most members a record keeps, removed ones and later kinds included.
const MAX_STORED_MEMBERS: usize = 8 * MAX_MEMBERS;
/// Longest record, in bytes of JSON.
const MAX_RECORD: usize = 2 * 1024 * 1024;
/// Longest project name, in characters.
const MAX_NAME: usize = 64;
/// Most former names a record keeps.
const MAX_AKA: usize = 16;
/// Longest folder, host alias or fingerprint, in bytes.
const MAX_REFERENCE: usize = 4096;
/// How far ahead of this computer's clock a time from another device is
/// taken as it is, in milliseconds, for clocks a little apart; a later one
/// is taken as this much ahead.
const MAX_AHEAD_MS: i64 = 5 * 60 * 1000;
/// How long a removed project or member is remembered, in milliseconds: a
/// device that syncs after longer than that may bring it back.
pub const KEEP_REMOVED_MS: i64 = 400 * 24 * 60 * 60 * 1000;

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
    /// The vault's logins by entry id, not counting those in the recycle
    /// bin or gone. Empty in the copy kept for while the vault is locked.
    pub logins: Vec<String>,
    /// Of `folders`, those not found on this computer: filled in by the app
    /// as it lists projects, empty here.
    #[serde(default)]
    pub missing_folders: Vec<String>,
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
    /// A login of the vault by its entry id; the entry gets the tag
    /// [`TAG_PREFIX`] and the project's name.
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

/// A value and when it was set, in milliseconds since 1970: of two, the one
/// set later wins, at the same time the greater value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Lww {
    v: String,
    t: i64,
}

impl Lww {
    fn merge(&mut self, other: &Self) {
        if (other.t, &other.v) > (self.t, &self.v) {
            self.clone_from(other);
        }
    }
}

/// When a member was last added and removed, in milliseconds: it is in the
/// project when it was added after it was last removed. Two copies keep the
/// later of each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct Presence {
    a: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    r: Option<i64>,
}

impl Presence {
    fn present(self) -> bool {
        self.r.is_none_or(|r| self.a > r)
    }

    fn latest(self) -> i64 {
        self.r.map_or(self.a, |r| r.max(self.a))
    }

    fn merge(&mut self, other: Self) {
        self.a = self.a.max(other.a);
        self.r = self.r.max(other.r);
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Stored {
    name: Lww,
    color: Lww,
    /// By [`member_key`]; kinds of later versions are kept as they are.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    members: BTreeMap<String, Presence>,
    /// When it was removed: it stays removed unless something in it changed
    /// later.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    removed: Option<i64>,
    /// The project it was joined into, for one removed because another had
    /// its name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    joined: Option<String>,
    /// Names it had before, newest last: tags with them are its own.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    aka: Vec<String>,
    /// Whatever a later version keeps here.
    #[serde(flatten)]
    rest: Map<String, Value>,
}

impl Stored {
    fn new(name: String, color: ProjectColor, t: i64) -> Self {
        Self {
            name: Lww { v: name, t },
            color: Lww {
                v: color.as_str().to_owned(),
                t,
            },
            members: BTreeMap::new(),
            removed: None,
            joined: None,
            aka: Vec::new(),
            rest: Map::new(),
        }
    }

    /// When anything in it but its removal last changed.
    fn latest(&self) -> i64 {
        self.members
            .values()
            .map(|p| p.latest())
            .fold(self.name.t.max(self.color.t), i64::max)
    }

    /// Every time it holds.
    fn times(&self) -> impl Iterator<Item = i64> + '_ {
        [self.name.t, self.color.t]
            .into_iter()
            .chain(self.removed)
            .chain(
                self.members
                    .values()
                    .flat_map(|p| [Some(p.a), p.r])
                    .flatten(),
            )
    }

    fn is_live(&self) -> bool {
        self.removed.is_none_or(|removed| self.latest() > removed)
    }

    /// A time for a change now, later than every time it holds, so that a
    /// change here always wins over what it changes.
    fn tick(&self) -> i64 {
        self.times()
            .fold(now_ms(), |now, t| now.max(t.saturating_add(1)))
    }

    /// Brings every time later than `latest` back: to the time `mine` (this
    /// device's copy) has for it, if any, else to `latest`. A device whose
    /// clock ran ahead can't make its changes win for good, its records are
    /// still taken, and a time taken once doesn't climb again with this
    /// clock when the same record comes back.
    fn clamp(&mut self, latest: i64, mine: Option<&Self>) {
        let cap = |t: i64, known: Option<i64>| {
            if t > latest {
                known.map_or(latest, |k| k.min(latest))
            } else {
                t
            }
        };
        self.name.t = cap(self.name.t, mine.map(|m| m.name.t));
        self.color.t = cap(self.color.t, mine.map(|m| m.color.t));
        self.removed = self.removed.map(|t| cap(t, mine.and_then(|m| m.removed)));
        for (key, presence) in &mut self.members {
            let known = mine.and_then(|m| m.members.get(key));
            presence.a = cap(presence.a, known.map(|k| k.a));
            presence.r = presence.r.map(|t| cap(t, known.and_then(|k| k.r)));
        }
    }

    /// Remembers `name` as one it had, unless it is its name now.
    fn remember_name(&mut self, name: &str) {
        if same_name(name, &self.name.v) || self.aka.iter().any(|n| same_name(n, name)) {
            return;
        }
        if self.aka.len() >= MAX_AKA {
            self.aka.remove(0);
        }
        self.aka.push(name.to_owned());
    }

    /// The members in the project, of every kind this version knows.
    fn present(&self) -> impl Iterator<Item = ProjectMember> + '_ {
        self.members
            .iter()
            .filter(|(_, p)| p.present())
            .filter_map(|(key, _)| parse_member(key))
    }

    fn count(&self, kind: &str) -> usize {
        self.members
            .iter()
            .filter(|(key, p)| p.present() && key.split(':').next() == Some(kind))
            .count()
    }

    /// Takes in another copy of the same record.
    fn merge(&mut self, other: &Self) {
        if other.latest() > self.latest() {
            for (key, value) in &other.rest {
                self.rest.insert(key.clone(), value.clone());
            }
        } else {
            for (key, value) in &other.rest {
                self.rest
                    .entry(key.clone())
                    .or_insert_with(|| value.clone());
            }
        }
        let before = self.name.v.clone();
        self.name.merge(&other.name);
        // The name that lost is one it had: its tags go.
        for name in std::iter::once(&before)
            .chain([&other.name.v])
            .chain(&other.aka)
        {
            self.remember_name(name);
        }
        self.color.merge(&other.color);
        self.take_members(other);
        if other.removed > self.removed {
            self.removed = other.removed;
            self.joined.clone_from(&other.joined);
        } else if other.removed == self.removed && other.joined > self.joined {
            self.joined.clone_from(&other.joined);
        }
    }

    /// Takes in another record's members, added and removed.
    fn take_members(&mut self, other: &Self) {
        for (key, presence) in &other.members {
            let room = self.members.len() < MAX_STORED_MEMBERS;
            match self.members.get_mut(key) {
                Some(mine) => mine.merge(*presence),
                None if room => {
                    self.members.insert(key.clone(), *presence);
                }
                None => {}
            }
        }
    }

    /// Forgets removals older than `before`: the members, and the whole
    /// record once it is removed. A member's removal later than the
    /// project's is kept, since it may be what keeps the project. Returns
    /// `false` for a record to drop.
    fn prune(&mut self, before: i64) -> bool {
        if !self.is_live() {
            return self.removed.is_none_or(|r| r >= before);
        }
        let removed = self.removed;
        self.members.retain(|_, p| {
            p.present()
                || p.r
                    .is_none_or(|r| r >= before || removed.is_some_and(|gone| r > gone))
        });
        true
    }
}

/// How a record keeps a member: its kind, `:`, and the reference.
fn member_key(member: &ProjectMember) -> String {
    match member {
        ProjectMember::Host { alias } => format!("host:{alias}"),
        ProjectMember::Key { fingerprint } => format!("key:{fingerprint}"),
        ProjectMember::Login { id } => format!("login:{id}"),
        ProjectMember::Environment { group } => format!("env:{group}"),
        ProjectMember::Folder { path } => format!("folder:{path}"),
    }
}

/// The member a record's key names, if this version knows its kind and the
/// reference is one it takes.
fn parse_member(key: &str) -> Option<ProjectMember> {
    let (kind, value) = key.split_once(':')?;
    let value = value.to_owned();
    let member = match kind {
        "host" => ProjectMember::Host { alias: value },
        "key" => ProjectMember::Key { fingerprint: value },
        "login" => ProjectMember::Login { id: value },
        "env" => ProjectMember::Environment { group: value },
        "folder" => ProjectMember::Folder { path: value },
        _ => return None,
    };
    is_valid_member(&member).then_some(member)
}

/// Whether `member` is a reference a project takes, by its form alone: a
/// host alias that isn't a pattern, a `SHA256:` fingerprint, an entry id,
/// an environments' group name, a folder on one line. Whether it exists is
/// another question.
pub fn is_valid_member(member: &ProjectMember) -> bool {
    match member {
        ProjectMember::Host { alias } => check_alias(alias).is_ok_and(|a| a == *alias),
        ProjectMember::Key { fingerprint } => {
            check_fingerprint(fingerprint).is_ok_and(|f| f == *fingerprint)
        }
        ProjectMember::Login { id } => {
            uuid::Uuid::parse_str(id).is_ok_and(|u| u.to_string() == *id)
        }
        ProjectMember::Environment { group } => {
            check_label(group, "a project").is_ok_and(|g| g == *group)
        }
        ProjectMember::Folder { path } => check_folder_text(path).is_ok(),
    }
}

/// A record, if it is one: an id, a name unless it is removed, times this
/// side can compare, and not too much of anything. Members of kinds this
/// version doesn't know are kept; members it can't read are dropped.
fn parse(id: &str, json: &str) -> Option<Stored> {
    if json.len() > MAX_RECORD || !is_id(id) {
        return None;
    }
    let mut stored: Stored = serde_json::from_str(json).ok()?;
    if stored.members.len() > MAX_STORED_MEMBERS || stored.times().any(|t| t < 0) {
        return None;
    }
    stored.members.retain(|key, _| {
        key.len() <= MAX_REFERENCE + 16
            && match key.split_once(':') {
                Some((kind, _)) if ["host", "key", "login", "env", "folder"].contains(&kind) => {
                    parse_member(key).is_some()
                }
                Some((kind, _)) => !kind.is_empty(),
                None => false,
            }
    });
    let named = check_name(&stored.name.v).is_ok_and(|name| name == stored.name.v);
    (named || stored.removed.is_some()).then_some(stored)
}

fn is_id(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok_and(|u| u.to_string() == id)
}

fn new_id() -> String {
    let mut bytes = [0; 16];
    OsRng.fill_bytes(&mut bytes);
    uuid::Builder::from_random_bytes(bytes)
        .into_uuid()
        .to_string()
}

fn now_ms() -> i64 {
    i64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000).unwrap_or(0)
}

/// RFC 3339 in UTC, to the second.
fn rfc3339_ms(ms: i64) -> String {
    OffsetDateTime::from_unix_timestamp(ms.div_euclid(1000))
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

fn same_name(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

/// The tag a project's logins carry.
fn tag(name: &str) -> String {
    format!("{TAG_PREFIX}{name}")
}

fn project_view(id: String, stored: &Stored, logins: &BTreeSet<String>) -> Project {
    let modified = rfc3339_ms(stored.latest());
    let mut project = Project {
        id,
        name: stored.name.v.clone(),
        color: ProjectColor::parse(&stored.color.v),
        folders: Vec::new(),
        hosts: Vec::new(),
        keys: Vec::new(),
        environments: Vec::new(),
        logins: Vec::new(),
        missing_folders: Vec::new(),
        modified,
    };
    for member in stored.present() {
        match member {
            ProjectMember::Host { alias } => project.hosts.push(alias),
            ProjectMember::Key { fingerprint } => project.keys.push(fingerprint),
            ProjectMember::Environment { group } => project.environments.push(group),
            ProjectMember::Folder { path } => project.folders.push(path),
            ProjectMember::Login { id } if logins.contains(&id) => project.logins.push(id),
            ProjectMember::Login { .. } => {}
        }
    }
    project
}

impl Vault {
    /// The projects, by name.
    pub fn projects(&self) -> Vec<Project> {
        let logins = self.login_ids();
        let mut projects: Vec<Project> = self
            .stored_projects()
            .into_iter()
            .filter(|(_, stored)| stored.is_live())
            .map(|(id, stored)| project_view(id, &stored, &logins))
            .collect();
        projects.sort_by_cached_key(|p| (p.name.to_lowercase(), p.id.clone()));
        projects
    }

    pub fn project(&self, id: &str) -> Result<Project> {
        let stored = self.live_project(id)?;
        Ok(project_view(id.to_owned(), &stored, &self.login_ids()))
    }

    /// Adds a project and returns its id. Logins already tagged
    /// `project/<name>` are its members.
    pub fn add_project(&mut self, input: &ProjectInput) -> Result<String> {
        let name = check_name(&input.name)?;
        let live: Vec<(String, Stored)> = self
            .stored_projects()
            .into_iter()
            .filter(|(_, stored)| stored.is_live())
            .collect();
        if live.len() >= MAX_PROJECTS {
            return Err(Error::invalid(format!(
                "a vault holds at most {MAX_PROJECTS} projects"
            )));
        }
        if live.iter().any(|(_, s)| same_name(&s.name.v, &name)) {
            return Err(Error::AlreadyExists(name));
        }
        let id = new_id();
        self.put_project(&id, &Stored::new(name, input.color, now_ms()))?;
        // Logins tagged `project/<name>` in KeePassXC are in it at once.
        self.sync_tags();
        Ok(id)
    }

    /// Renames a project or changes its color. Its logins' tags follow.
    pub fn update_project(&mut self, id: &str, input: &ProjectInput) -> Result<()> {
        let name = check_name(&input.name)?;
        let mut stored = self.live_project(id)?;
        let color = input.color.as_str();
        if stored.name.v == name && stored.color.v == color {
            return Ok(());
        }
        if !same_name(&stored.name.v, &name)
            && self
                .stored_projects()
                .iter()
                .any(|(other, s)| other != id && s.is_live() && same_name(&s.name.v, &name))
        {
            return Err(Error::AlreadyExists(name));
        }
        let t = stored.tick();
        if stored.name.v != name {
            let old = std::mem::replace(&mut stored.name, Lww { v: name, t });
            stored.remember_name(&old.v);
        }
        if stored.color.v != color {
            stored.color = Lww {
                v: color.to_owned(),
                t,
            };
        }
        self.put_project(id, &stored)?;
        self.sync_tags();
        Ok(())
    }

    /// Removes a project, leaving a tombstone. Its logins lose its tag;
    /// nothing else changes: hosts, keys, environments and folders are only
    /// referenced.
    pub fn remove_project(&mut self, id: &str) -> Result<()> {
        let mut stored = self.live_project(id)?;
        stored.removed = Some(stored.tick());
        stored.joined = None;
        self.put_project(id, &stored)?;
        self.prune_projects();
        self.sync_tags();
        Ok(())
    }

    /// Checks that `member` can go into a project (`included`) or come out:
    /// by its form, and for a login going in, that it is one of the vault's
    /// logins.
    pub fn check_project_member(&self, member: &ProjectMember, included: bool) -> Result<()> {
        if !is_valid_member(member) {
            return Err(match member {
                ProjectMember::Host { alias } => check_alias(alias).err(),
                ProjectMember::Key { fingerprint } => check_fingerprint(fingerprint).err(),
                ProjectMember::Environment { group } => check_label(group, "a project").err(),
                ProjectMember::Folder { path } => check_folder_text(path).err(),
                ProjectMember::Login { id } => {
                    Some(Error::invalid(format!("not an entry id: {id}")))
                }
            }
            .unwrap_or_else(|| Error::invalid("not something a project holds")));
        }
        if let (true, ProjectMember::Login { id }) = (included, member)
            && envs::is_environment(&self.find(id)?)
        {
            return Err(Error::invalid(
                "an environment joins a project by its group",
            ));
        }
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
        self.check_project_member(member, included)?;
        let mut stored = self.live_project(id)?;
        let key = member_key(member);
        let presence = stored.members.get(&key).copied();
        if presence.is_some_and(Presence::present) == included {
            return Ok(false);
        }
        let kind = key.split(':').next().unwrap_or_default();
        if included && stored.count(kind) >= MAX_MEMBERS {
            return Err(Error::invalid(format!(
                "a project holds at most {MAX_MEMBERS} of a kind"
            )));
        }
        let t = stored.tick();
        let next = match (presence, included) {
            (Some(p), true) => Presence { a: t, r: p.r },
            (Some(p), false) => Presence { a: p.a, r: Some(t) },
            (None, _) => Presence { a: t, r: None },
        };
        if presence.is_none() && stored.members.len() >= MAX_STORED_MEMBERS {
            return Err(Error::invalid("the project is too large"));
        }
        stored.members.insert(key, next);
        self.put_project(id, &stored)?;
        if matches!(member, ProjectMember::Login { .. }) {
            self.sync_tags();
        }
        Ok(true)
    }

    /// Moves the host `old` to `new` in every live project that holds it:
    /// for a host renamed in `~/.ssh/config`. Returns whether any changed.
    pub fn rename_host_in_projects(&mut self, old: &str, new: &str) -> Result<bool> {
        let old = ProjectMember::Host {
            alias: old.to_owned(),
        };
        let new = ProjectMember::Host {
            alias: new.to_owned(),
        };
        if !is_valid_member(&old) || !is_valid_member(&new) || old == new {
            return Ok(false);
        }
        let (old_key, new_key) = (member_key(&old), member_key(&new));
        let mut changed = false;
        for (id, stored) in self.stored_projects() {
            if !stored.is_live() || !stored.members.get(&old_key).is_some_and(|p| p.present()) {
                continue;
            }
            let mut stored = self.live_project(&id)?;
            let t = stored.tick();
            if let Some(presence) = stored.members.get_mut(&old_key) {
                presence.r = Some(t);
            }
            let room = stored.members.len() < MAX_STORED_MEMBERS;
            match stored.members.get_mut(&new_key) {
                Some(presence) if !presence.present() => presence.a = t,
                None if room => {
                    stored
                        .members
                        .insert(new_key.clone(), Presence { a: t, r: None });
                }
                Some(_) | None => {}
            }
            self.put_project(&id, &stored)?;
            changed = true;
        }
        Ok(changed)
    }

    /// Makes `suggestion` a project named and colored as `input`, or adds
    /// to the existing project it names, with the members the user `kept`.
    /// Each must be one the suggestion offers and one a project takes; all
    /// are checked before anything changes. Logins it offered that weren't
    /// kept, and that the project didn't hold already, are recorded as taken
    /// out, so a `project/` tag on them doesn't bring them in. Returns the
    /// project's id.
    pub fn accept_suggestion(
        &mut self,
        suggestion: &suggest::ProjectSuggestion,
        input: &ProjectInput,
        kept: &[ProjectMember],
    ) -> Result<String> {
        for member in kept {
            if !suggestion.offers(member) {
                return Err(Error::invalid(format!(
                    "not part of the suggestion: {member:?}"
                )));
            }
            self.check_project_member(member, true)?;
        }
        // Logins the project holds already (added since the suggestion was
        // made, or by a sync) stay, whatever the suggestion's list says.
        let held: BTreeSet<String> = match &suggestion.existing {
            Some(id) => self.project(id)?.logins.into_iter().collect(),
            None => BTreeSet::new(),
        };
        let id = match &suggestion.existing {
            Some(id) => id.clone(),
            None => self.add_project(input)?,
        };
        for member in kept {
            self.set_project_member(&id, member, true)?;
        }
        let left_out: Vec<&String> = suggestion
            .logins
            .iter()
            .filter(|login| {
                !held.contains(*login)
                    && !kept
                        .iter()
                        .any(|m| matches!(m, ProjectMember::Login { id } if id == *login))
            })
            .collect();
        if !left_out.is_empty() {
            let mut stored = self.live_project(&id)?;
            let t = stored.tick();
            for login in left_out {
                let key = format!("login:{login}");
                let next = match stored.members.get(&key) {
                    Some(p) if !p.present() => continue,
                    Some(p) => Presence { a: p.a, r: Some(t) },
                    None if stored.members.len() >= MAX_STORED_MEMBERS => continue,
                    None => Presence { a: 0, r: Some(t) },
                };
                stored.members.insert(key, next);
            }
            self.put_project(&id, &stored)?;
            self.sync_tags();
        }
        Ok(id)
    }

    /// Every record, tombstones too, to send to another own device; those
    /// removed longer ago than [`KEEP_REMOVED_MS`] are left out.
    pub fn project_records(&self) -> Vec<ProjectRecord> {
        let before = now_ms() - KEEP_REMOVED_MS;
        let mut kept: Vec<(String, Stored)> = self
            .stored_projects()
            .into_iter()
            .filter_map(|(id, mut stored)| stored.prune(before).then_some((id, stored)))
            .collect();
        // Past [`MAX_RECORDS`], live projects go first, then the latest
        // removals.
        kept.sort_by_key(|(id, stored)| {
            (
                !stored.is_live(),
                std::cmp::Reverse(stored.removed),
                id.clone(),
            )
        });
        kept.into_iter()
            .take(MAX_RECORDS)
            .filter_map(|(id, stored)| {
                let record = serde_json::to_string(&stored).ok()?;
                Some(ProjectRecord { id, record })
            })
            .collect()
    }

    /// Takes in the records another own device sent, member by member
    /// ([`Stored::merge`]). A record this version can't read, and those
    /// past [`MAX_RECORDS`], are skipped; times more than [`MAX_AHEAD_MS`]
    /// from now are taken as that. Then projects that end up with one name are joined, and
    /// the logins' tags are written from the result, so the order records
    /// come in doesn't matter. Returns whether anything changed.
    pub fn merge_projects(&mut self, theirs: &[ProjectRecord]) -> Result<bool> {
        let latest = now_ms() + MAX_AHEAD_MS;
        let mut changed = self.heal_clock();
        let mut live = self
            .stored_projects()
            .iter()
            .filter(|(_, stored)| stored.is_live())
            .count();
        for record in theirs.iter().take(MAX_RECORDS) {
            let Some(mut incoming) = parse(&record.id, &record.record) else {
                continue;
            };
            let mine = self.stored_project(&record.id);
            incoming.clamp(latest, mine.as_ref());
            let was_live = mine.as_ref().is_some_and(Stored::is_live);
            let merged = match mine.clone() {
                Some(mut mine) => {
                    mine.merge(&incoming);
                    mine
                }
                None => incoming,
            };
            if Some(&merged) == mine.as_ref() {
                continue;
            }
            match (was_live, merged.is_live()) {
                (false, true) if live >= MAX_PROJECTS => continue,
                (false, true) => live += 1,
                (true, false) => live -= 1,
                _ => {}
            }
            self.put_project(&record.id, &merged)?;
            changed = true;
        }
        if self.settle_projects()? {
            changed = true;
        }
        if changed {
            self.prune_projects();
            self.sync_tags();
        }
        Ok(changed)
    }

    /// Joins live projects that have one name into the one with the
    /// smallest id, and passes on to that one what a project joined into it
    /// holds. Returns whether anything changed.
    fn settle_projects(&mut self) -> Result<bool> {
        let mut changed = false;
        let mut all: BTreeMap<String, Stored> = self.stored_projects().into_iter().collect();
        let mut names: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (id, stored) in &all {
            if stored.is_live() {
                names
                    .entry(stored.name.v.to_lowercase())
                    .or_default()
                    .push(id.clone());
            }
        }
        for ids in names.values().filter(|ids| ids.len() > 1) {
            // `all` is sorted by id: the first is the smallest.
            let (keep, others) = ids.split_first().expect("two or more");
            for other in others {
                let mut gone = all[other].clone();
                gone.removed = Some(gone.tick());
                gone.joined = Some(keep.clone());
                all.insert(other.clone(), gone);
            }
        }
        let joined: Vec<(String, String)> = all
            .iter()
            .filter(|(_, stored)| !stored.is_live())
            .filter_map(|(id, stored)| Some((id.clone(), stored.joined.clone()?)))
            .collect();
        for (from, into) in joined {
            let Some(source) = all.get(&from).cloned() else {
                continue;
            };
            if let Some(target) = all.get_mut(&into).filter(|t| t.is_live()) {
                target.take_members(&source);
            }
        }
        for (id, stored) in all {
            if self.stored_project(&id).as_ref() != Some(&stored) {
                self.put_project(&id, &stored)?;
                changed = true;
            }
        }
        Ok(changed)
    }

    /// Brings this vault's own times later than [`MAX_AHEAD_MS`] from now
    /// back to that, so that a device whose clock was once ahead heals once
    /// it is right. Returns whether any changed.
    fn heal_clock(&mut self) -> bool {
        let latest = now_ms() + MAX_AHEAD_MS;
        let mut changed = false;
        for (id, mut stored) in self.stored_projects() {
            if stored.times().any(|t| t > latest) {
                stored.clamp(latest, None);
                changed |= self.put_project(&id, &stored).is_ok();
            }
        }
        changed
    }

    /// Forgets what was removed longer ago than [`KEEP_REMOVED_MS`].
    fn prune_projects(&mut self) {
        let before = now_ms() - KEEP_REMOVED_MS;
        for (id, mut stored) in self.stored_projects() {
            let before_prune = stored.clone();
            if !stored.prune(before) {
                self.db.meta.custom_data.remove(&format!("{PREFIX}{id}"));
            } else if stored != before_prune {
                let _ = self.put_project(&id, &stored);
            }
        }
    }

    /// Writes each login's `project/…` tags from the records: one for each
    /// live project it is in. A `project/<name>` tag for a name a record
    /// knows, now or before, and the login isn't in, goes; one for a name no
    /// record knows is the user's and stays. Other tags stay as they are.
    /// First, logins tagged with a project in KeePassXC join it
    /// ([`Self::adopt_tagged_logins`]).
    fn sync_tags(&mut self) {
        self.adopt_tagged_logins();
        self.write_tags();
    }

    /// A login tagged (in KeePassXC) with a live project's name joins it:
    /// the `project/` tag says so explicitly, unlike the user's own tags.
    /// Not when a project that has or had that name — this one, one removed
    /// or joined into it, one renamed — holds the login or took it out: the
    /// tag is then that project's doing, and the record says what holds.
    fn adopt_tagged_logins(&mut self) {
        let all = self.stored_projects();
        let mut live: BTreeMap<String, &str> = BTreeMap::new();
        for (id, stored) in all.iter().filter(|(_, stored)| stored.is_live()) {
            // Of two live projects with one name, the one they join into.
            live.entry(stored.name.v.to_lowercase())
                .or_insert(id.as_str());
        }
        let decided = |name: &str, login: &str| {
            let key = format!("login:{login}");
            all.iter().any(|(_, stored)| {
                (same_name(&stored.name.v, name)
                    || stored.aka.iter().any(|old| same_name(old, name)))
                    && stored.members.contains_key(&key)
            })
        };
        let mut adopted: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for entry in self.db.iter_all_entries() {
            if envs::is_environment(&entry) {
                continue;
            }
            let login = entry.id().uuid().to_string();
            for name in entry
                .tags
                .iter()
                .filter_map(|t| t.trim().strip_prefix(TAG_PREFIX))
            {
                if let Some(id) = live.get(&name.to_lowercase())
                    && !decided(name, &login)
                {
                    adopted
                        .entry((*id).to_owned())
                        .or_default()
                        .push(login.clone());
                }
            }
        }
        for (id, logins) in adopted {
            let Some(mut stored) = self.stored_project(&id) else {
                continue;
            };
            let t = stored.tick();
            for login in logins {
                if stored.count("login") < MAX_MEMBERS {
                    stored
                        .members
                        .entry(format!("login:{login}"))
                        .or_insert(Presence { a: t, r: None });
                }
            }
            let _ = self.put_project(&id, &stored);
        }
    }

    /// The tag writing half of [`Self::sync_tags`].
    fn write_tags(&mut self) {
        let mut known: BTreeSet<String> = BTreeSet::new();
        let mut wanted: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (_, stored) in self.stored_projects() {
            known.insert(stored.name.v.to_lowercase());
            known.extend(stored.aka.iter().map(|name| name.to_lowercase()));
            if !stored.is_live() {
                continue;
            }
            for member in stored.present() {
                if let ProjectMember::Login { id } = member {
                    wanted.entry(id).or_default().insert(tag(&stored.name.v));
                }
            }
        }
        let ours = |t: &str| {
            t.strip_prefix(TAG_PREFIX)
                .is_some_and(|name| known.contains(&name.to_lowercase()))
        };
        let none = BTreeSet::new();
        let changes: Vec<(EntryId, Vec<String>)> = self
            .db
            .iter_all_entries()
            .filter(|entry| !envs::is_environment(entry))
            .filter_map(|entry| {
                let want = wanted.get(&entry.id().uuid().to_string()).unwrap_or(&none);
                let has: BTreeSet<String> = entry
                    .tags
                    .iter()
                    .map(|t| t.trim())
                    .filter(|t| ours(t))
                    .map(str::to_owned)
                    .collect();
                if has == *want {
                    return None;
                }
                let mut tags: Vec<String> = Vec::new();
                for t in entry.tags.iter().map(|t| t.trim()) {
                    if !t.is_empty() && !ours(t) && !tags.iter().any(|x| x == t) {
                        tags.push(t.to_owned());
                    }
                }
                tags.extend(want.iter().cloned());
                Some((entry.id(), tags))
            })
            .collect();
        for (id, tags) in changes {
            if let Some(mut entry) = self.db.entry_mut(id) {
                entry.tags = tags;
                entry.times.last_modification = Some(Times::now());
            }
        }
    }

    /// The vault's logins outside the recycle bin as suggestions see them:
    /// their KeePass group and the user's own tags. A `project/<name>` tag
    /// for a name no record knows counts as the tag `<name>`; the app's own
    /// `project/` tags don't count.
    pub fn suggestion_logins(&self) -> Vec<suggest::LoginFacts> {
        let known: BTreeSet<String> = self
            .stored_projects()
            .iter()
            .flat_map(|(_, stored)| std::iter::once(&stored.name.v).chain(&stored.aka))
            .map(|name| name.to_lowercase())
            .collect();
        self.db
            .iter_all_entries()
            .filter(|entry| !envs::is_environment(entry))
            .filter_map(|entry| {
                let summary = self.summary(&entry);
                (!summary.in_trash).then(|| suggest::LoginFacts {
                    id: summary.id,
                    group: summary.group,
                    tags: entry
                        .tags
                        .iter()
                        .map(|t| t.trim())
                        .filter_map(|t| match t.strip_prefix(TAG_PREFIX) {
                            Some(name) if known.contains(&name.to_lowercase()) => None,
                            Some(name) => Some(name.to_owned()),
                            None => Some(t.to_owned()),
                        })
                        .collect(),
                })
            })
            .collect()
    }

    /// The project groups of the environments outside the recycle bin.
    pub fn environment_groups(&self) -> Vec<String> {
        let groups: BTreeSet<String> = self
            .environments()
            .into_iter()
            .filter(|env| !env.in_trash && !env.project.is_empty())
            .map(|env| env.project)
            .collect();
        groups.into_iter().collect()
    }

    /// The vault's logins outside the recycle bin, by id.
    fn login_ids(&self) -> BTreeSet<String> {
        let bin = self.db.meta.recyclebin_uuid;
        self.db
            .iter_all_entries()
            .filter(|entry| {
                !envs::is_environment(entry) && !in_group(entry.parent().id(), bin, &self.db)
            })
            .map(|entry| entry.id().uuid().to_string())
            .collect()
    }

    fn stored_projects(&self) -> Vec<(String, Stored)> {
        let mut all: Vec<(String, Stored)> = self
            .db
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
            .collect();
        all.sort_by(|a, b| a.0.cmp(&b.0));
        all
    }

    fn stored_project(&self, id: &str) -> Option<Stored> {
        let item = self.db.meta.custom_data.get(&format!("{PREFIX}{id}"))?;
        let Some(CustomDataValue::String(json)) = &item.value else {
            return None;
        };
        parse(id, json)
    }

    /// A live project, to change: with times ahead of this clock brought
    /// back ([`Self::heal_clock`]), so a change's time stays near now.
    fn live_project(&self, id: &str) -> Result<Stored> {
        let mut stored = self
            .stored_project(id)
            .filter(Stored::is_live)
            .ok_or_else(|| Error::NotFound(format!("project {id}")))?;
        stored.clamp(now_ms() + MAX_AHEAD_MS, None);
        Ok(stored)
    }

    fn put_project(&mut self, id: &str, stored: &Stored) -> Result<()> {
        let json =
            serde_json::to_string(stored).map_err(|e| Error::Parse(format!("project: {e}")))?;
        if json.len() > MAX_RECORD {
            return Err(Error::invalid("the project is too large"));
        }
        self.db.meta.custom_data.insert(
            format!("{PREFIX}{id}"),
            CustomDataItem {
                value: Some(CustomDataValue::String(json)),
                last_modification_time: Some(Times::now()),
            },
        );
        Ok(())
    }
}

/// A project's name, checked: trimmed, at most [`MAX_NAME`] characters,
/// without control characters or the `;`, `,` and `:` that KeePass apps
/// split tags at (the name is part of its logins' tag).
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
    if text
        .chars()
        .any(|c| c.is_control() || matches!(c, ';' | ',' | ':'))
    {
        return Err(Error::invalid(
            "project names can't have `;`, `,`, `:` or control characters",
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
