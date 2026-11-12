//! AI tools' own ignore rules for a folder's managed `.env` files, added
//! only when the user says so for that folder.
//!
//! Each tool reads its rules where it looks for them:
//!
//! - `.gitignore` patterns at the top of the project folder: Cursor
//!   `.cursorignore`, Windsurf `.codeiumignore`, Gemini CLI `.geminiignore`,
//!   Cline `.clineignore`, Roo Code `.rooignore`, Continue `.continueignore`,
//!   `JetBrains` AI Assistant and Gemini Code Assist `.aiexclude`;
//! - Aider: `.aiderignore` at the top of the Git working tree;
//! - Claude Code: deny rules in the user's own settings,
//!   `~/.claude/settings.json` (`$CLAUDE_CONFIG_DIR` if set), naming each
//!   file by its full path (`Read(//Users/me/code/shop/.env)`), so they hold
//!   wherever Claude Code is started and whichever settings the project has.
//!
//! Each file gets one line (or rule) per managed file, naming that file
//! alone, as the line the app adds to `.gitignore` does
//! ([`super::ignore_in_git`]); lines it has already are left alone, and
//! nothing else in the file changes (a settings file keeps its keys in their
//! order and its line ends). A file in a project folder is never written
//! through a link; the user's own settings may be one (a dotfiles folder).
//! A file that can't be changed is passed over, and the others still get
//! their lines. Codex and GitHub Copilot have no such file.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::disk::ignore_pattern;
use crate::vault::projects;
use crate::{Error, Result, fsutil};

/// Largest rules file that is read.
const MAX_RULES_FILE: u64 = 1024 * 1024;

/// An AI tool that reads ignore rules of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum AgentTool {
    ClaudeCode,
    Cursor,
    Windsurf,
    Aider,
    GeminiCli,
    Cline,
    RooCode,
    Continue,
    /// `JetBrains` AI Assistant, and Gemini Code Assist, which reads the same
    /// file.
    JetBrains,
}

impl AgentTool {
    pub const ALL: [Self; 9] = [
        Self::ClaudeCode,
        Self::Cursor,
        Self::Windsurf,
        Self::Aider,
        Self::GeminiCli,
        Self::Cline,
        Self::RooCode,
        Self::Continue,
        Self::JetBrains,
    ];

    /// The name of the tool's rules file.
    fn file_name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "settings.json",
            Self::Cursor => ".cursorignore",
            Self::Windsurf => ".codeiumignore",
            Self::Aider => ".aiderignore",
            Self::GeminiCli => ".geminiignore",
            Self::Cline => ".clineignore",
            Self::RooCode => ".rooignore",
            Self::Continue => ".continueignore",
            Self::JetBrains => ".aiexclude",
        }
    }

    /// What in a folder says the tool is used there.
    fn folder_signs(self) -> &'static [&'static str] {
        match self {
            Self::ClaudeCode => &[".claude", "CLAUDE.md"],
            Self::Cursor => &[".cursor", ".cursorrules", ".cursorignore"],
            Self::Windsurf => &[".windsurf", ".windsurfrules", ".codeiumignore"],
            Self::Aider => &[".aider.conf.yml", ".aiderignore", ".aider.chat.history.md"],
            Self::GeminiCli => &[".gemini", "GEMINI.md", ".geminiignore"],
            Self::Cline => &[".clinerules", ".clineignore"],
            Self::RooCode => &[".roo", ".roomodes", ".rooignore"],
            Self::Continue => &[".continue", ".continueignore"],
            Self::JetBrains => &[".idea", ".aiexclude"],
        }
    }
}

/// Where a folder's AI tools read their rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesPlaces {
    /// The project folder, on this computer.
    pub folder: PathBuf,
    /// The top of the Git working tree the folder is in, if any.
    pub repository: Option<PathBuf>,
    /// Claude Code's user settings, if there is a home folder.
    pub claude_settings: Option<PathBuf>,
    /// The home folder, to show files as `~/…`.
    pub home: Option<PathBuf>,
}

impl RulesPlaces {
    /// The places for the project folder `folder` on this computer.
    pub fn of(folder: &Path, home: Option<&Path>) -> Self {
        let claude = std::env::var_os("CLAUDE_CONFIG_DIR")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .or_else(|| home.map(|home| home.join(".claude")));
        Self {
            folder: folder.to_path_buf(),
            repository: super::super::git_work_tree(folder),
            claude_settings: claude.map(|dir| dir.join("settings.json")),
            home: home.map(Path::to_path_buf),
        }
    }

    /// The tool's rules file, and the folder its lines' paths start from
    /// (`None`: they are full paths).
    fn place(&self, tool: AgentTool) -> Option<(PathBuf, Option<PathBuf>)> {
        match tool {
            AgentTool::ClaudeCode => Some((self.claude_settings.clone()?, None)),
            AgentTool::Aider => {
                let base = self
                    .repository
                    .clone()
                    .unwrap_or_else(|| self.folder.clone());
                Some((base.join(tool.file_name()), Some(base)))
            }
            _ => Some((
                self.folder.join(tool.file_name()),
                Some(self.folder.clone()),
            )),
        }
    }

    /// The file as the dialog names it: by its name in the project folder,
    /// else `~/…` or in full.
    fn shown(&self, path: &Path) -> String {
        if path.parent() == Some(self.folder.as_path()) {
            return path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
        }
        projects::folder_text(path, self.home.as_deref())
            .unwrap_or_else(|_| path.display().to_string())
    }
}

/// Why a tool's rules file can't be changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum RulesProblem {
    /// It, or the folder it is in, is a symbolic link.
    Link,
    /// It is a folder or something else that isn't a regular file.
    NotAFile,
    /// It can't be read as text, or as settings for Claude Code.
    Unreadable,
    /// There is no place for it on this computer (no home folder).
    NoPlace,
}

/// A tool's rules file, and what it lacks for the folder's managed files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct AgentRules {
    pub tool: AgentTool,
    /// The file: `.cursorignore` in the folder, `~/.claude/settings.json`.
    pub file: String,
    /// The file is there already.
    pub exists: bool,
    /// The lines (for Claude Code, the rules) it lacks, as they would be
    /// added.
    pub missing: Vec<String>,
    /// The tool is used in the folder or on this computer.
    pub found: bool,
    pub problem: Option<RulesProblem>,
}

/// What the user said about a folder's AI tools' rules: which tools get
/// lines (also for files bound there later), or not for this folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum FolderChoice {
    Added { tools: Vec<AgentTool> },
    Declined,
}

/// The user's choices by project folder, as projects keep folders
/// (`~/code/shop`): kept by the app, one per computer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentChoices {
    #[serde(default)]
    folders: BTreeMap<String, FolderChoice>,
}

impl AgentChoices {
    /// The choices kept at `path`; none if there is no file. Fails if one
    /// is there that can't be read, so it isn't written over.
    pub fn load(path: &Path) -> Result<Self> {
        match fs::symlink_metadata(path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            _ => {}
        }
        let bytes = fsutil::read_limited(path, 4 * 1024 * 1024)?;
        serde_json::from_slice(&bytes)
            .map_err(|_| Error::Parse(format!("{} can't be read", path.display())))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_vec_pretty(self).map_err(|e| Error::Parse(format!("{e}")))?;
        fsutil::atomic_write(path, &json, 0o600)
    }

    pub fn get(&self, folder: &str) -> Option<&FolderChoice> {
        self.folders.get(folder)
    }

    pub fn set(&mut self, folder: &str, choice: FolderChoice) {
        self.folders.insert(folder.to_owned(), choice);
    }
}

/// What adding rules did, by tool.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RulesAdded {
    /// The tools whose file changed.
    pub changed: Vec<AgentTool>,
    /// The tools whose file couldn't be changed, passed over.
    pub failed: Vec<AgentTool>,
}

/// A path's parts, in Unicode, or `None`.
fn parts(path: &Path) -> Option<Vec<String>> {
    path.components()
        .filter_map(|part| match part {
            Component::Normal(name) => Some(name.to_str().map(str::to_owned)),
            _ => None,
        })
        .collect()
}

/// The line `.gitignore`-like files in `base` get for the managed file
/// `path` of `folder`.
fn ignore_line(base: &Path, folder: &Path, path: &str) -> Option<String> {
    let mut all = parts(folder.strip_prefix(base).ok()?)?;
    all.extend(path.split('/').map(str::to_owned));
    Some(format!("/{}", ignore_pattern(&all.join("/"))))
}

/// Claude Code's deny rules for the managed file `path` of `folder`, by its
/// full path as Claude Code writes paths (`C:\x` is `/c/x`): the folder as
/// given and, if links lead elsewhere, as it is on disk.
fn claude_rules(folder: &Path, path: &str) -> Vec<String> {
    let mut folders = vec![folder.to_path_buf()];
    if let Ok(real) = fs::canonicalize(folder)
        && real != folder
    {
        folders.push(real);
    }
    folders
        .iter()
        .filter_map(|folder| {
            let mut all = Vec::new();
            for part in folder.components() {
                match part {
                    Component::Prefix(prefix) => {
                        let drive = prefix.as_os_str().to_str()?.trim_start_matches(r"\\?\");
                        all.push(drive.trim_end_matches(':').to_lowercase());
                    }
                    Component::Normal(name) => all.push(name.to_str()?.to_owned()),
                    _ => {}
                }
            }
            all.extend(path.split('/').map(str::to_owned));
            Some(format!("Read(//{})", ignore_pattern(&all.join("/"))))
        })
        .collect()
}

/// The lines a tool's file should have for `files`: from `base`, or full
/// paths for Claude Code (`base` is `None`).
fn wanted(places: &RulesPlaces, base: Option<&Path>, files: &[String]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    files
        .iter()
        .flat_map(|path| match base {
            None => claude_rules(&places.folder, path),
            Some(base) => ignore_line(base, &places.folder, path)
                .into_iter()
                .collect(),
        })
        .filter(|line| seen.insert(line.clone()))
        .collect()
}

/// What each tool's rules file lacks for the managed files `files` (paths
/// in the folder, with `/` between parts). `found` names the tools used on
/// this computer; a sign of a tool in the folder counts too.
pub fn agent_rules(
    places: &RulesPlaces,
    files: &[String],
    found: &BTreeSet<AgentTool>,
) -> Vec<AgentRules> {
    AgentTool::ALL
        .into_iter()
        .map(|tool| {
            let used_here = tool
                .folder_signs()
                .iter()
                .any(|sign| fs::symlink_metadata(places.folder.join(sign)).is_ok());
            let found = used_here || found.contains(&tool);
            let Some((path, base)) = places.place(tool) else {
                return AgentRules {
                    tool,
                    file: tool.file_name().to_owned(),
                    exists: false,
                    missing: Vec::new(),
                    found,
                    problem: Some(RulesProblem::NoPlace),
                };
            };
            let (exists, missing, problem) = match read_rules(&path, tool) {
                Ok(current) => (
                    current.is_some(),
                    lacking(current.as_ref(), wanted(places, base.as_deref(), files)),
                    None,
                ),
                Err(problem) => (true, Vec::new(), Some(problem)),
            };
            AgentRules {
                tool,
                file: places.shown(&path),
                exists,
                missing,
                found,
                problem,
            }
        })
        .collect()
}

/// Adds to the rules files of `tools` what they lack for the managed files
/// `files`, making a file that isn't there. One that can't be changed is
/// passed over, and named.
pub fn add_agent_rules(places: &RulesPlaces, files: &[String], tools: &[AgentTool]) -> RulesAdded {
    let mut added = RulesAdded::default();
    for &tool in tools {
        match add_one(places, files, tool) {
            Ok(true) => added.changed.push(tool),
            Ok(false) => {}
            Err(_) => added.failed.push(tool),
        }
    }
    added
}

/// Adds to one tool's file what it lacks. Returns whether it changed.
fn add_one(places: &RulesPlaces, files: &[String], tool: AgentTool) -> Result<bool> {
    let (path, base) = places
        .place(tool)
        .ok_or_else(|| Error::invalid("no place for the file"))?;
    let current =
        read_rules(&path, tool).map_err(|problem| Error::invalid(format!("{problem:?}")))?;
    let missing = lacking(current.as_ref(), wanted(places, base.as_deref(), files));
    if missing.is_empty() {
        return Ok(false);
    }
    let text = match current {
        Some(Rules::Settings(mut settings, crlf)) => settings_text(&mut settings, &missing, crlf)?,
        None if tool == AgentTool::ClaudeCode => {
            settings_text(&mut Json::Object(Vec::new()), &missing, false)?
        }
        Some(Rules::Lines(mut text)) => {
            let eol = if text.contains("\r\n") { "\r\n" } else { "\n" };
            if !text.is_empty() && !text.ends_with('\n') {
                text.push_str(eol);
            }
            for line in &missing {
                text.push_str(line);
                text.push_str(eol);
            }
            text
        }
        None => {
            let mut text = missing.join("\n");
            text.push('\n');
            text
        }
    };
    if tool == AgentTool::ClaudeCode
        && let Some(dir) = path.parent()
    {
        fs::create_dir_all(dir).map_err(|e| Error::io(e, dir))?;
    }
    fsutil::atomic_write(&path, text.as_bytes(), 0o644)?;
    Ok(true)
}

/// Claude Code's settings with `missing` added to `permissions.deny`, as
/// text with the line ends the file had.
fn settings_text(settings: &mut Json, missing: &[String], crlf: bool) -> Result<String> {
    add_deny_rules(settings, missing)?;
    let mut text =
        serde_json::to_string_pretty(settings).map_err(|e| Error::Parse(format!("{e}")))?;
    text.push('\n');
    Ok(if crlf {
        text.replace('\n', "\r\n")
    } else {
        text
    })
}

/// A rules file as read.
enum Rules {
    Lines(String),
    /// Claude Code's settings, and whether its lines end with CRLF.
    Settings(Json, bool),
}

/// The tool's rules file at `path`; `None` if there is none yet. A file in
/// a project folder is never one through a link; Claude Code's user
/// settings may be.
fn read_rules(path: &Path, tool: AgentTool) -> std::result::Result<Option<Rules>, RulesProblem> {
    let own = tool == AgentTool::ClaudeCode;
    let meta = if own {
        fs::metadata(path)
    } else {
        fs::symlink_metadata(path)
    };
    match meta {
        Ok(meta) if meta.file_type().is_symlink() => return Err(RulesProblem::Link),
        Ok(meta) if !meta.is_file() => return Err(RulesProblem::NotAFile),
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(RulesProblem::Unreadable),
    }
    let bytes = fsutil::read_limited(path, MAX_RULES_FILE).map_err(|_| RulesProblem::Unreadable)?;
    let text = String::from_utf8(bytes).map_err(|_| RulesProblem::Unreadable)?;
    if !own {
        return Ok(Some(Rules::Lines(text)));
    }
    let crlf = text.contains("\r\n");
    if text.trim().is_empty() {
        return Ok(Some(Rules::Settings(Json::Object(Vec::new()), crlf)));
    }
    let settings: Json = serde_json::from_str(&text).map_err(|_| RulesProblem::Unreadable)?;
    if !matches!(settings, Json::Object(_)) || deny_list(&settings).is_err() {
        return Err(RulesProblem::Unreadable);
    }
    Ok(Some(Rules::Settings(settings, crlf)))
}

/// The lines of `wanted` the rules file `current` lacks.
fn lacking(current: Option<&Rules>, wanted: Vec<String>) -> Vec<String> {
    wanted
        .into_iter()
        .filter(|wanted| match current {
            None => true,
            Some(Rules::Lines(text)) => !text.lines().any(|line| line.trim_end() == wanted),
            Some(Rules::Settings(settings, _)) => {
                !deny_list(settings).ok().flatten().is_some_and(|rules| {
                    rules
                        .iter()
                        .any(|rule| matches!(rule, Json::String(s) if s == wanted))
                })
            }
        })
        .collect()
}

/// The `permissions.deny` list of Claude Code's settings, if there is one;
/// an error if one of them isn't what Claude Code reads.
fn deny_list(settings: &Json) -> std::result::Result<Option<&Vec<Json>>, ()> {
    let Some(permissions) = settings.get("permissions") else {
        return Ok(None);
    };
    let Json::Object(_) = permissions else {
        return Err(());
    };
    match permissions.get("deny") {
        None => Ok(None),
        Some(Json::Array(rules)) => Ok(Some(rules)),
        Some(_) => Err(()),
    }
}

/// Adds `rules` to the end of `permissions.deny`, making either if needed.
fn add_deny_rules(settings: &mut Json, rules: &[String]) -> Result<()> {
    let unreadable = || Error::invalid("Claude Code's settings can't be read");
    let Json::Object(fields) = settings else {
        return Err(unreadable());
    };
    let Json::Object(fields) = entry(fields, "permissions", || Json::Object(Vec::new())) else {
        return Err(unreadable());
    };
    let Json::Array(list) = entry(fields, "deny", || Json::Array(Vec::new())) else {
        return Err(unreadable());
    };
    list.extend(rules.iter().cloned().map(Json::String));
    Ok(())
}

/// The value of `key` in an object's fields (the last one, as JSON readers
/// take it), added at the end if missing.
fn entry<'a>(
    fields: &'a mut Vec<(String, Json)>,
    key: &str,
    new: impl FnOnce() -> Json,
) -> &'a mut Json {
    let index = if let Some(index) = fields.iter().rposition(|(name, _)| name == key) {
        index
    } else {
        fields.push((key.to_owned(), new()));
        fields.len() - 1
    };
    &mut fields[index].1
}

/// The AI tools used on this computer, by their own folders: `home` is the
/// user's home folder and `config` the system's configuration folder
/// (`~/Library/Application Support`, `%APPDATA%`, `$XDG_CONFIG_HOME`).
pub fn agent_tools_found(home: &Path, config: Option<&Path>) -> BTreeSet<AgentTool> {
    let mut found = BTreeSet::new();
    let there = |path: PathBuf| fs::symlink_metadata(path).is_ok();
    let claude = std::env::var_os("CLAUDE_CONFIG_DIR")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| home.join(".claude"));
    for (tool, path) in [
        (AgentTool::ClaudeCode, claude),
        (AgentTool::Cursor, home.join(".cursor")),
        (AgentTool::Windsurf, home.join(".codeium").join("windsurf")),
        (AgentTool::Aider, home.join(".aider.conf.yml")),
        (AgentTool::GeminiCli, home.join(".gemini")),
        (AgentTool::Continue, home.join(".continue")),
    ] {
        if there(path) {
            found.insert(tool);
        }
    }
    if let Some(config) = config {
        for editor in ["Code", "Code - Insiders", "VSCodium", "Cursor", "Windsurf"] {
            let storage = config.join(editor).join("User").join("globalStorage");
            for (tool, extension) in [
                (AgentTool::Cline, "saoudrizwan.claude-dev"),
                (AgentTool::RooCode, "rooveterinaryinc.roo-cline"),
            ] {
                if there(storage.join(extension)) {
                    found.insert(tool);
                }
            }
        }
        if there(config.join("JetBrains")) {
            found.insert(AgentTool::JetBrains);
        }
    }
    found
}

/// JSON that keeps its objects' keys in their order, so a settings file
/// changes only where something is added.
#[derive(Debug, Clone, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(fields) => fields
                .iter()
                .rev()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }
}

impl<'de> Deserialize<'de> for Json {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Json;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON")
            }
            fn visit_unit<E>(self) -> std::result::Result<Json, E> {
                Ok(Json::Null)
            }
            fn visit_bool<E>(self, v: bool) -> std::result::Result<Json, E> {
                Ok(Json::Bool(v))
            }
            fn visit_i64<E>(self, v: i64) -> std::result::Result<Json, E> {
                Ok(Json::Number(v.into()))
            }
            fn visit_u64<E>(self, v: u64) -> std::result::Result<Json, E> {
                Ok(Json::Number(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Json, E> {
                serde_json::Number::from_f64(v)
                    .map(Json::Number)
                    .ok_or_else(|| E::custom("not a JSON number"))
            }
            fn visit_str<E>(self, v: &str) -> std::result::Result<Json, E> {
                Ok(Json::String(v.to_owned()))
            }
            fn visit_string<E>(self, v: String) -> std::result::Result<Json, E> {
                Ok(Json::String(v))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Json, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Json::Array(items))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Json, A::Error> {
                let mut fields = Vec::new();
                while let Some(field) = map.next_entry()? {
                    fields.push(field);
                }
                Ok(Json::Object(fields))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

impl Serialize for Json {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::{SerializeMap, SerializeSeq};
        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(v) => serializer.serialize_bool(*v),
            Self::Number(v) => v.serialize(serializer),
            Self::String(v) => serializer.serialize_str(v),
            Self::Array(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Self::Object(fields) => {
                let mut map = serializer.serialize_map(Some(fields.len()))?;
                for (key, value) in fields {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files() -> Vec<String> {
        vec![".env".into(), "apps/web/.env.local".into()]
    }

    /// A folder `shop` in a working tree `repo`, and Claude Code's settings
    /// in a home folder of its own.
    fn places(dir: &Path) -> RulesPlaces {
        let folder = dir.join("repo").join("shop");
        fs::create_dir_all(&folder).unwrap();
        RulesPlaces {
            folder,
            repository: Some(dir.join("repo")),
            claude_settings: Some(dir.join("home").join(".claude").join("settings.json")),
            home: Some(dir.join("home")),
        }
    }

    fn rules_of(places: &RulesPlaces, tool: AgentTool) -> AgentRules {
        agent_rules(places, &files(), &BTreeSet::new())
            .into_iter()
            .find(|rules| rules.tool == tool)
            .unwrap()
    }

    /// Claude Code's rule for `file` in `folder`, as the app writes it.
    #[cfg(unix)]
    fn full(folder: &Path, file: &str) -> String {
        let text = folder.to_str().unwrap().trim_start_matches('/');
        format!("Read(//{})", ignore_pattern(&format!("{text}/{file}")))
    }

    #[test]
    fn ignore_files_get_one_line_per_file_once_where_each_tool_reads_them() {
        let dir = tempfile::tempdir().unwrap();
        let places = places(dir.path());
        fs::write(places.folder.join(".cursorignore"), "node_modules\r\n/.env").unwrap();
        let cursor = rules_of(&places, AgentTool::Cursor);
        assert_eq!(cursor.file, ".cursorignore");
        assert!(cursor.exists);
        assert_eq!(cursor.missing, ["/apps/web/.env.local"]);
        assert!(cursor.found, "its own file is a sign");
        // Aider reads its file at the top of the working tree.
        let aider = rules_of(&places, AgentTool::Aider);
        assert!(!aider.exists && !aider.found);
        assert_eq!(aider.missing, ["/shop/.env", "/shop/apps/web/.env.local"]);

        let added = add_agent_rules(&places, &files(), &[AgentTool::Cursor, AgentTool::Aider]);
        assert_eq!(added.changed, [AgentTool::Cursor, AgentTool::Aider]);
        assert_eq!(added.failed, []);
        // Its line ends kept, its lines as they were.
        assert_eq!(
            fs::read_to_string(places.folder.join(".cursorignore")).unwrap(),
            "node_modules\r\n/.env\r\n/apps/web/.env.local\r\n"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("repo").join(".aiderignore")).unwrap(),
            "/shop/.env\n/shop/apps/web/.env.local\n"
        );
        // Nothing to add a second time.
        let again = add_agent_rules(&places, &files(), &[AgentTool::Cursor]);
        assert_eq!(again, RulesAdded::default());
        assert_eq!(
            rules_of(&places, AgentTool::Cursor).missing,
            Vec::<String>::new()
        );
    }

    #[cfg(unix)]
    #[test]
    fn claude_code_gets_full_paths_in_the_users_settings_keys_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let places = places(dir.path());
        let real = fs::canonicalize(&places.folder).unwrap();
        let rules_for = |file: &str| {
            let mut rules = vec![full(&places.folder, file)];
            if real != places.folder {
                rules.push(full(&real, file));
            }
            rules
        };
        let claude = rules_of(&places, AgentTool::ClaudeCode);
        assert_eq!(claude.file, "~/.claude/settings.json");
        // None yet: made, with its folder.
        let added = add_agent_rules(&places, &[".env".into()], &[AgentTool::ClaudeCode]);
        assert_eq!(added.changed, [AgentTool::ClaudeCode]);
        let path = places.claude_settings.clone().unwrap();
        let settings_now = || -> serde_json::Value {
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap()
        };
        assert_eq!(
            settings_now(),
            serde_json::json!({ "permissions": { "deny": rules_for(".env") } })
        );

        // The user's own settings: keys in their order, line ends kept.
        let first = rules_for(".env")[0].clone();
        fs::write(
            &path,
            format!(
                "{{\r\n\"z\": 1, \"permissions\": {{\"allow\": [\"Bash(ls)\"], \"deny\": [\"{first}\"]}}, \"a\": [true, null, 1.5]}}\r\n"
            ),
        )
        .unwrap();
        add_agent_rules(&places, &files(), &[AgentTool::ClaudeCode]);
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("\r\n") && !text.replace("\r\n", "").contains('\n'));
        let mut deny = rules_for(".env");
        deny.extend(rules_for("apps/web/.env.local"));
        assert_eq!(
            settings_now(),
            serde_json::json!({
                "z": 1,
                "permissions": { "allow": ["Bash(ls)"], "deny": deny },
                "a": [true, null, 1.5]
            })
        );
        let at = |key: &str| text.find(key).unwrap();
        assert!(at("\"z\"") < at("\"permissions\"") && at("\"permissions\"") < at("\"a\""));

        // Settings it can't read are left alone, and the others go on.
        fs::write(&path, r#"{"permissions": {"deny": "Read(/.env)"}}"#).unwrap();
        assert_eq!(
            rules_of(&places, AgentTool::ClaudeCode).problem,
            Some(RulesProblem::Unreadable)
        );
        let added = add_agent_rules(
            &places,
            &files(),
            &[AgentTool::ClaudeCode, AgentTool::Cline],
        );
        assert_eq!(added.failed, [AgentTool::ClaudeCode]);
        assert_eq!(added.changed, [AgentTool::Cline]);
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            r#"{"permissions": {"deny": "Read(/.env)"}}"#
        );
    }

    #[cfg(unix)]
    #[test]
    fn project_files_are_never_written_through_a_link() {
        let dir = tempfile::tempdir().unwrap();
        let places = places(dir.path());
        let elsewhere = dir.path().join("elsewhere");
        fs::write(&elsewhere, "x\n").unwrap();
        std::os::unix::fs::symlink(&elsewhere, places.folder.join(".geminiignore")).unwrap();
        assert_eq!(
            rules_of(&places, AgentTool::GeminiCli).problem,
            Some(RulesProblem::Link)
        );
        let added = add_agent_rules(&places, &files(), &[AgentTool::GeminiCli]);
        assert_eq!(added.failed, [AgentTool::GeminiCli]);
        assert_eq!(fs::read_to_string(&elsewhere).unwrap(), "x\n");
        // The user's own settings may be a link, to a dotfiles folder.
        let dotfiles = dir.path().join("dotfiles.json");
        fs::write(&dotfiles, "{}").unwrap();
        let settings = places.claude_settings.clone().unwrap();
        fs::create_dir_all(settings.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&dotfiles, &settings).unwrap();
        let added = add_agent_rules(&places, &files(), &[AgentTool::ClaudeCode]);
        assert_eq!(added.changed, [AgentTool::ClaudeCode]);
        assert!(fs::read_to_string(&dotfiles).unwrap().contains("Read(//"));
    }

    #[test]
    fn choices_are_kept_by_folder_and_never_written_over_unread() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent-rules.json");
        assert_eq!(AgentChoices::load(&path).unwrap(), AgentChoices::default());
        let mut choices = AgentChoices::default();
        let added = FolderChoice::Added {
            tools: vec![AgentTool::Cursor, AgentTool::ClaudeCode],
        };
        choices.set("~/code/shop", added.clone());
        choices.set("~/code/blog", FolderChoice::Declined);
        choices.save(&path).unwrap();
        let loaded = AgentChoices::load(&path).unwrap();
        assert_eq!(loaded.get("~/code/shop"), Some(&added));
        assert_eq!(loaded.get("~/code/blog"), Some(&FolderChoice::Declined));
        assert_eq!(loaded.get("~/code/other"), None);
        // One a later version wrote, with a tool this one doesn't know.
        fs::write(
            &path,
            r#"{"folders": {"~/x": {"type": "added", "tools": ["zed"]}}}"#,
        )
        .unwrap();
        assert!(AgentChoices::load(&path).is_err());
    }

    #[test]
    fn tools_are_found_by_their_folders() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        fs::create_dir(home.join(".cursor")).unwrap();
        let config = home.join("config");
        fs::create_dir_all(
            config
                .join("Code")
                .join("User")
                .join("globalStorage")
                .join("saoudrizwan.claude-dev"),
        )
        .unwrap();
        let found = agent_tools_found(home, Some(&config));
        assert!(found.contains(&AgentTool::Cursor));
        assert!(found.contains(&AgentTool::Cline));
        assert!(!found.contains(&AgentTool::Aider));
    }

    #[test]
    fn windows_paths_are_written_as_claude_code_reads_them() {
        if cfg!(windows) {
            let rules = claude_rules(Path::new(r"C:\Users\me\code\shop"), "apps/.env");
            assert_eq!(rules[0], "Read(//c/Users/me/code/shop/apps/.env)");
        }
    }
}
