//! Where a project's parts work: the folder a part's environments are used
//! in, by their terminals and on the project's folder tree.
//!
//! A part's folder is one of the project's folders and a path in it
//! (`~/code/shop` and `apps/api`). The user may set it. The project's record
//! keeps it as a member of its own kind ([`KIND`]), so it goes to the user's
//! other devices with the project and merges as members do, and older
//! versions pass it on without reading it. A part has one: of its members
//! present, the one put in last ([`super::Stored::part_folders`]); setting
//! one takes the part's others out at the same time, so whatever order
//! records come in, every device ends up with the same. One counts only
//! while the project holds its folder.
//!
//! Without one set, a part works where its local environment's first `.env`
//! file is, else in the project's first folder ([`places`]). Every stage of a
//! part works there, remote ones included.

use std::collections::BTreeMap;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

use super::{MAX_MEMBERS, MAX_REFERENCE, MAX_STORED_MEMBERS, Presence, Project, Stored};
use crate::vault::Vault;
use crate::vault::envs::{self, EnvFile, EnvKind, EnvSummary};
use crate::{Error, Result};

/// How a record names a part's folder: the kind, then the part, the folder
/// and the path as a JSON array, `partdir:["api","~/code/shop","apps/api"]`.
pub(super) const KIND: &str = "partdir:";
/// The kind's name, as [`Stored::count`] takes it.
pub(super) const KIND_NAME: &str = "partdir";
/// Longest path in a folder, in bytes.
const MAX_PATH: usize = 1024;

/// A folder of a project, or a folder in it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct ProjectFolder {
    /// One of the project's folders, as the project keeps it: `~/code/shop`.
    pub folder: String,
    /// A folder in it, with `/` between names: `apps/api`; empty for the
    /// folder itself.
    pub path: String,
}

/// The folder the user set for a part of a project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct PartFolder {
    /// The part, as its environments name it; empty for a project's one
    /// unnamed part.
    pub part: String,
    /// One of the project's folders, as the project keeps it.
    pub folder: String,
    /// A folder in it, with `/` between names; empty for the folder itself.
    pub path: String,
}

impl PartFolder {
    fn place(&self) -> ProjectFolder {
        ProjectFolder {
            folder: self.folder.clone(),
            path: self.path.clone(),
        }
    }
}

/// A change of a part's folder made with an environment of it: back to
/// automatic, or a folder of the project or in one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum PartFolderChoice {
    /// Where it works by itself ([`places`]).
    Automatic,
    /// One of the project's folders, and a folder in it (empty for the
    /// folder itself).
    Folder { folder: String, path: String },
}

impl PartFolderChoice {
    /// The folder it names; `None` for automatic.
    pub fn place(&self) -> Option<ProjectFolder> {
        match self {
            Self::Automatic => None,
            Self::Folder { folder, path } => Some(ProjectFolder {
                folder: folder.clone(),
                path: path.clone(),
            }),
        }
    }
}

/// How a part's folder was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum PlaceSource {
    /// The user set it.
    Set,
    /// Where its local environment's first `.env` file is.
    File,
    /// The project's first folder.
    Project,
}

/// A part of a project where it works.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct PartPlace {
    /// The part, as its environments name it; empty for a project's one
    /// unnamed part.
    pub part: String,
    /// How its folder was found.
    pub source: PlaceSource,
    /// Its environments outside the recycle bin, from development to
    /// production. Empty while the vault is locked.
    pub environments: Vec<String>,
    /// The environment a terminal in its folder gets: its local one, the
    /// one named `local` first. A remote one never goes into a shell but by
    /// its own Run in terminal.
    pub local: Option<String>,
    /// Where it would work without the folder the user set: where its local
    /// environment's first file is, else the project's first folder.
    pub automatic: Option<ProjectFolder>,
    /// `automatic` is where its local environment's first file is (not the
    /// project's first folder).
    pub automatic_from_file: bool,
    /// The folders its environments' files are in, local ones' first: what
    /// the user is offered to set.
    pub suggested: Vec<ProjectFolder>,
}

/// A project's folder, or a folder in it where parts work, with what a
/// terminal there gets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct FolderPlace {
    /// One of the project's folders, as the project keeps it.
    pub folder: String,
    /// A folder in it where parts work, with `/` between names; empty for
    /// the folder itself.
    pub path: String,
    /// The parts that work here.
    pub parts: Vec<PartPlace>,
    /// The environments a terminal here may get, by id: the local ones of
    /// the parts that work here, else of those that work in folders below.
    /// With several, the user picks one, or none.
    pub terminal: Vec<String>,
    /// Not found on this computer (checked by the app; `false` if unknown).
    pub missing: bool,
}

/// The key a record keeps `part`'s folder under.
fn key(part: &str, folder: &str, path: &str) -> String {
    let value = serde_json::to_string(&(part, folder, path)).unwrap_or_default();
    format!("{KIND}{value}")
}

/// The part folder a record's key names, if it is one in the form
/// [`key`] writes: a part as environments keep it, a folder as a project
/// keeps it, and a path in it as [`check_path`] keeps it.
pub(super) fn parse_key(text: &str) -> Option<PartFolder> {
    let value = text.strip_prefix(KIND)?;
    let (part, folder, path): (String, String, String) = serde_json::from_str(value).ok()?;
    let fine = envs::check_part(&part).is_ok_and(|p| p == part)
        && super::check_folder_text(&folder).is_ok()
        && check_path(&path).is_ok_and(|p| p == path)
        && key(&part, &folder, &path) == text;
    fine.then_some(PartFolder { part, folder, path })
}

/// A path in a project's folder, put in one form: plain names between `/`,
/// none of them `.`, `..` or `.git`; empty for the folder itself.
pub fn check_path(path: &str) -> Result<String> {
    if path.is_empty() {
        return Ok(String::new());
    }
    let parts: Vec<&str> = path.split(['/', '\\']).collect();
    let bad = |part: &&str| {
        let mut components = Path::new(part).components();
        let plain =
            matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();
        !plain
            || part.is_empty()
            || *part == "."
            || *part == ".."
            || part.len() > 255
            || part.trim() != *part
            || part.eq_ignore_ascii_case(".git")
            || part.chars().any(|c| c.is_control() || c == ':')
    };
    if path.len() > MAX_PATH || parts.iter().any(bad) {
        return Err(Error::invalid(format!(
            "not a folder in a project's folder: {:?}",
            path.chars().take(64).collect::<String>()
        )));
    }
    Ok(parts.join("/"))
}

/// The folder `path` (a file in a project's folder) is in.
fn parent(path: &str) -> String {
    path.rsplit_once('/')
        .map(|(folder, _)| folder.to_owned())
        .unwrap_or_default()
}

/// Parts compare as environments keep them: trimmed, without case.
fn same(a: &str, b: &str) -> bool {
    a.trim().to_lowercase() == b.trim().to_lowercase()
}

/// Whether `path` is below `under` in one folder (and not `under` itself).
fn below(path: &str, under: &str) -> bool {
    !path.is_empty()
        && (under.is_empty()
            || path
                .strip_prefix(under)
                .is_some_and(|rest| rest.starts_with('/')))
}

impl Stored {
    /// The folder of each part the user set, while the project holds the
    /// folder it is in: of a part's members present, the one put in last
    /// (at the same time, the greater key). By part.
    pub(super) fn part_folders(&self) -> Vec<PartFolder> {
        let held = |folder: &str| {
            self.members
                .get(&format!("folder:{folder}"))
                .is_some_and(|p| p.present())
        };
        let mut best: BTreeMap<String, (i64, &String, PartFolder)> = BTreeMap::new();
        for (key, presence) in &self.members {
            if !key.starts_with(KIND) || !presence.present() {
                continue;
            }
            let Some(folder) = parse_key(key) else {
                continue;
            };
            let part = folder.part.to_lowercase();
            if best
                .get(&part)
                .is_none_or(|(a, k, _)| (presence.a, key) > (*a, *k))
            {
                best.insert(part, (presence.a, key, folder));
            }
        }
        best.into_values()
            .map(|(_, _, folder)| folder)
            .filter(|folder| held(&folder.folder))
            .collect()
    }
}

/// Where the part `part` of `project` works, with its environments `list`
/// ([`places`]); `None` for a project without folders.
fn place_part(
    project: &Project,
    part: String,
    list: &[&EnvSummary],
    files: &BTreeMap<String, Vec<EnvFile>>,
) -> Option<(ProjectFolder, PartPlace)> {
    let held = |folder: &str| project.folders.iter().any(|f| f == folder);
    let first = project.folders.first().map(|folder| ProjectFolder {
        folder: folder.clone(),
        path: String::new(),
    });
    let set = project
        .parts
        .iter()
        .find(|p| same(&p.part, &part) && held(&p.folder))
        .map(PartFolder::place);
    let mut locals: Vec<&EnvSummary> = list
        .iter()
        .copied()
        .filter(|env| env.kind == EnvKind::Local)
        .collect();
    locals.sort_by_key(|env| !env.name.eq_ignore_ascii_case("local"));
    // The folders the environments' files are in, once each, in order.
    let spots = |envs: &mut dyn Iterator<Item = &&EnvSummary>| -> Vec<ProjectFolder> {
        let mut spots: Vec<ProjectFolder> = Vec::new();
        for file in envs
            .flat_map(|env| files.get(&env.id).into_iter().flatten())
            .filter(|file| held(&file.folder))
        {
            let spot = ProjectFolder {
                folder: file.folder.clone(),
                path: parent(&file.path),
            };
            if !spots.contains(&spot) {
                spots.push(spot);
            }
        }
        spots
    };
    let from_file = spots(&mut locals.iter()).into_iter().next();
    let suggested = spots(
        &mut locals
            .iter()
            .chain(list.iter().filter(|env| env.kind != EnvKind::Local)),
    );
    let automatic = from_file.clone().or_else(|| first.clone());
    let (at, source) = match (set, &from_file) {
        (Some(set), _) => (set, PlaceSource::Set),
        (None, Some(file)) => (file.clone(), PlaceSource::File),
        (None, None) => (first?, PlaceSource::Project),
    };
    Some((
        at,
        PartPlace {
            part,
            source,
            environments: list.iter().map(|env| env.id.clone()).collect(),
            local: locals.first().map(|env| env.id.clone()),
            automatic,
            automatic_from_file: from_file.is_some(),
            suggested,
        },
    ))
}

/// Where the parts of `project` work: one place for each of its folders, in
/// order, then after each the folders in it where parts work, by path.
/// `envs` are the vault's environments ([`Vault::environments`]) and
/// `files` their files by id, level 1 first; `None` while the vault is
/// locked, when only the folders the user set are known.
pub fn places(
    project: &Project,
    envs: Option<&[EnvSummary]>,
    files: &BTreeMap<String, Vec<EnvFile>>,
) -> Vec<FolderPlace> {
    // The project's environments outside the recycle bin, by part, in the
    // order they are listed; while locked, the parts with a folder set.
    let mut parts: Vec<(String, Vec<&EnvSummary>)> = Vec::new();
    match envs {
        Some(envs) => {
            for env in envs
                .iter()
                .filter(|env| !env.in_trash && env.project.as_deref() == Some(&project.id))
            {
                match parts.iter_mut().find(|(part, _)| same(part, &env.part)) {
                    Some((_, list)) => list.push(env),
                    None => parts.push((env.part.clone(), vec![env])),
                }
            }
        }
        None => parts.extend(project.parts.iter().map(|p| (p.part.clone(), Vec::new()))),
    }
    let placed: Vec<(ProjectFolder, PartPlace)> = parts
        .into_iter()
        .filter_map(|(part, list)| place_part(project, part, &list, files))
        .collect();
    let mut out = Vec::new();
    for folder in &project.folders {
        let mut paths: Vec<&str> = placed
            .iter()
            .filter(|(at, _)| at.folder == *folder && !at.path.is_empty())
            .map(|(at, _)| at.path.as_str())
            .collect();
        paths.sort_unstable();
        paths.dedup();
        for path in std::iter::once("").chain(paths) {
            let here: Vec<PartPlace> = placed
                .iter()
                .filter(|(at, _)| at.folder == *folder && at.path == path)
                .map(|(_, part)| part.clone())
                .collect();
            let locals = |parts: &mut dyn Iterator<Item = &PartPlace>| -> Vec<String> {
                parts.filter_map(|part| part.local.clone()).collect()
            };
            let mut terminal = locals(&mut here.iter());
            if terminal.is_empty() {
                terminal = locals(
                    &mut placed
                        .iter()
                        .filter(|(at, _)| at.folder == *folder && below(&at.path, path))
                        .map(|(_, part)| part),
                );
            }
            out.push(FolderPlace {
                folder: folder.clone(),
                path: path.to_owned(),
                parts: here,
                terminal,
                missing: false,
            });
        }
    }
    out
}

/// Where the environment `env` works, best first, for its Run in terminal:
/// its part's folder, then where it would work without the folder the user
/// set, then each of the project's folders. Empty for one in no project
/// (or in the recycle bin).
pub fn env_folders(places: &[FolderPlace], env: &str) -> Vec<ProjectFolder> {
    let Some((place, part)) = places.iter().find_map(|place| {
        place
            .parts
            .iter()
            .find(|part| part.environments.iter().any(|id| id == env))
            .map(|part| (place, part))
    }) else {
        return Vec::new();
    };
    let mut out = vec![ProjectFolder {
        folder: place.folder.clone(),
        path: place.path.clone(),
    }];
    out.extend(part.automatic.clone());
    out.extend(
        places
            .iter()
            .filter(|place| place.path.is_empty())
            .map(|place| ProjectFolder {
                folder: place.folder.clone(),
                path: String::new(),
            }),
    );
    let mut seen = Vec::new();
    out.retain(|spot| {
        let new = !seen.contains(spot);
        seen.push(spot.clone());
        new
    });
    out
}

impl Vault {
    /// Where the parts of the project `id` work ([`places`]).
    pub fn project_places(&self, id: &str) -> Result<Vec<FolderPlace>> {
        let project = self.project(id)?;
        let envs = self.environments();
        let mut files = BTreeMap::new();
        for env in envs
            .iter()
            .filter(|env| project.environments.contains(&env.id))
        {
            let (_, bound) = self.env_files(&env.id)?;
            files.insert(
                env.id.clone(),
                bound.into_iter().map(|(file, _)| file).collect::<Vec<_>>(),
            );
        }
        Ok(places(&project, Some(&envs), &files))
    }

    /// Sets the folder of a project's part (`part`, empty for its one
    /// unnamed part): one of the project's folders and a path in it; `None`
    /// goes back to where it works without one. Whether the folder is on
    /// this computer is the app's to check. Returns whether anything
    /// changed.
    pub fn set_part_folder(
        &mut self,
        id: &str,
        part: &str,
        to: Option<&ProjectFolder>,
    ) -> Result<bool> {
        let part = envs::check_part(part)?;
        let mut stored = self.live_project(id)?;
        let wanted_path = to
            .map(|to| check_path(&to.path))
            .transpose()?
            .unwrap_or_default();
        let wanted = match to {
            Some(to) => {
                let path = wanted_path.clone();
                if !stored
                    .members
                    .get(&format!("folder:{}", to.folder))
                    .is_some_and(|p| p.present())
                {
                    return Err(Error::invalid("not one of the project's folders"));
                }
                let key = key(&part, &to.folder, &path);
                if key.len() > MAX_REFERENCE + 16 {
                    return Err(Error::invalid("the folder's path is too long"));
                }
                Some(key)
            }
            None => None,
        };
        // The part's folders present (in any case of the part's name).
        let present: Vec<(String, PartFolder)> = stored
            .members
            .iter()
            .filter(|(_, presence)| presence.present())
            .filter_map(|(key, _)| {
                parse_key(key)
                    .filter(|f| same(&f.part, &part))
                    .map(|f| (key.clone(), f))
            })
            .collect();
        // Already so: nothing changes, not even a time.
        let unchanged = match (&to, present.as_slice()) {
            (None, []) => true,
            (Some(to), [(_, only)]) => only.folder == to.folder && only.path == wanted_path,
            _ => false,
        };
        if unchanged {
            return Ok(false);
        }
        // Set now: the one wanted is put in last, whether or not it was
        // there already, and the part's others are taken out.
        let t = stored.tick();
        for (key, _) in &present {
            if Some(key) != wanted.as_ref()
                && let Some(presence) = stored.members.get_mut(key)
            {
                presence.r = Some(t);
            }
        }
        if let Some(key) = wanted {
            let room = stored.members.len() < MAX_STORED_MEMBERS;
            let full = stored.count(KIND_NAME) >= MAX_MEMBERS;
            match stored.members.get_mut(&key) {
                Some(presence) => presence.a = t,
                None if full => {
                    return Err(Error::invalid(format!(
                        "a project holds at most {MAX_MEMBERS} folders of parts"
                    )));
                }
                None if room => {
                    stored.members.insert(key, Presence { a: t, r: None });
                }
                None => return Err(Error::invalid("the project is too large")),
            }
        }
        self.put_project(id, &stored)?;
        Ok(true)
    }

    /// Gives a part's folder to the part `to` it was renamed to, unless
    /// that one has its own (two parts made one), and takes it from `from`.
    pub(in crate::vault) fn move_part_folder(
        &mut self,
        id: &str,
        from: &str,
        to: &str,
    ) -> Result<()> {
        if same(from, to) {
            return Ok(());
        }
        let Ok(stored) = self.live_project(id) else {
            return Ok(());
        };
        let folders = stored.part_folders();
        let Some(current) = folders.iter().find(|p| same(&p.part, from)) else {
            return Ok(());
        };
        if !folders.iter().any(|p| same(&p.part, to)) {
            self.set_part_folder(id, to, Some(&current.place()))?;
        }
        self.set_part_folder(id, from, None)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
