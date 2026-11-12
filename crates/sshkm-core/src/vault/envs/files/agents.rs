//! AI tools' own ignore rules for a folder's managed `.env` files, added
//! only when the user says so for that folder.
//!
//! Most tools read a file of `.gitignore` patterns at the top of the
//! project: Cursor `.cursorignore`, Windsurf `.codeiumignore`, Aider
//! `.aiderignore`, Gemini CLI `.geminiignore`, Cline `.clineignore`, Roo
//! Code `.rooignore`, Continue `.continueignore`, `JetBrains` AI Assistant and
//! Gemini Code Assist `.aiexclude`. Claude Code reads deny rules from its
//! settings: `Read(/apps/web/.env.local)` in `.claude/settings.local.json`,
//! the user's own settings for the project (a path starting with `/` is from
//! the folder the settings are for). Each file gets one line (or rule) per
//! managed file, naming that file alone, as the line the app adds to
//! `.gitignore` does ([`super::ignore_in_git`]); lines it has already are
//! left alone, and nothing else in the file changes (a settings file keeps
//! its keys in their order). A file is never written through a link.
//! Codex and GitHub Copilot have no such file.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::disk::ignore_pattern;
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

    /// The tool's rules file in a folder, with `/` between parts.
    pub fn rules_file(self) -> &'static str {
        match self {
            Self::ClaudeCode => ".claude/settings.local.json",
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
}

/// A tool's rules file in a folder, and what it lacks for the folder's
/// managed files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct AgentRules {
    pub tool: AgentTool,
    /// The file in the folder: `.cursorignore`.
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

/// The users' choices by project folder, as projects keep folders
/// (`~/code/shop`): kept by the app, one per computer, since the rules
/// files are this computer's (or come with the repository).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentChoices {
    #[serde(default)]
    folders: BTreeMap<String, FolderChoice>,
}

impl AgentChoices {
    /// The choices kept at `path`; none if there are none or they can't be
    /// read.
    pub fn load(path: &Path) -> Self {
        fsutil::read_limited(path, 4 * 1024 * 1024)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
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

/// The line `.gitignore`-like files get for the managed file `path`, a
/// path in the folder with `/` between parts.
fn ignore_line(path: &str) -> String {
    format!("/{}", ignore_pattern(path))
}

/// Claude Code's deny rule for the managed file `path`.
fn claude_rule(path: &str) -> String {
    format!("Read(/{})", ignore_pattern(path))
}

/// What each tool's rules file in `folder` lacks for the managed files
/// `files` (paths in it, with `/` between parts). `found` names the tools
/// used on this computer; a sign of a tool in the folder counts too.
pub fn agent_rules(
    folder: &Path,
    files: &[String],
    found: &BTreeSet<AgentTool>,
) -> Vec<AgentRules> {
    AgentTool::ALL
        .into_iter()
        .map(|tool| {
            let used_here = tool
                .folder_signs()
                .iter()
                .any(|sign| fs::symlink_metadata(folder.join(sign)).is_ok());
            let (exists, missing, problem) = match read_rules(folder, tool) {
                Ok(current) => (
                    current.is_some(),
                    lacking(tool, current.as_ref(), files),
                    None,
                ),
                Err(problem) => (true, Vec::new(), Some(problem)),
            };
            AgentRules {
                tool,
                file: tool.rules_file().to_owned(),
                exists,
                missing,
                found: used_here || found.contains(&tool),
                problem,
            }
        })
        .collect()
}

/// Adds to the rules files of `tools` in `folder` what they lack for the
/// managed files `files`, making a file that isn't there. Returns the tools
/// whose file changed. One whose file can't be changed fails the call, after
/// those before it are written.
pub fn add_agent_rules(
    folder: &Path,
    files: &[String],
    tools: &[AgentTool],
) -> Result<Vec<AgentTool>> {
    let mut changed = Vec::new();
    for &tool in tools {
        let current = read_rules(folder, tool).map_err(|problem| {
            Error::invalid(format!(
                "{} can't be changed: {}",
                tool.rules_file(),
                match problem {
                    RulesProblem::Link => "it is a symbolic link",
                    RulesProblem::NotAFile => "it isn't a regular file",
                    RulesProblem::Unreadable => "it can't be read",
                }
            ))
        })?;
        let missing = lacking(tool, current.as_ref(), files);
        if missing.is_empty() {
            continue;
        }
        let text = if tool == AgentTool::ClaudeCode {
            let mut settings = match current {
                Some(Rules::Settings(settings)) => settings,
                _ => Json::Object(Vec::new()),
            };
            add_deny_rules(&mut settings, &missing)?;
            let mut text = serde_json::to_string_pretty(&settings)
                .map_err(|e| Error::Parse(format!("{e}")))?;
            text.push('\n');
            text
        } else {
            let mut text = match current {
                Some(Rules::Lines(text)) => text,
                _ => String::new(),
            };
            let eol = if text.contains("\r\n") { "\r\n" } else { "\n" };
            if !text.is_empty() && !text.ends_with('\n') {
                text.push_str(eol);
            }
            for line in &missing {
                text.push_str(line);
                text.push_str(eol);
            }
            text
        };
        let path = rules_path(folder, tool);
        ensure_folder(folder, &path)?;
        fsutil::atomic_write(&path, text.as_bytes(), 0o644)?;
        changed.push(tool);
    }
    Ok(changed)
}

/// A rules file as read.
enum Rules {
    Lines(String),
    Settings(Json),
}

fn rules_path(folder: &Path, tool: AgentTool) -> PathBuf {
    let mut path = folder.to_path_buf();
    path.extend(tool.rules_file().split('/'));
    path
}

/// The tool's rules file in `folder`; `None` if there is none yet.
fn read_rules(folder: &Path, tool: AgentTool) -> std::result::Result<Option<Rules>, RulesProblem> {
    let path = rules_path(folder, tool);
    // The folder on the way (`.claude`), if any, is a real folder.
    if let Some(parent) = path.parent().filter(|parent| *parent != folder) {
        match fs::symlink_metadata(parent) {
            Ok(meta) if meta.file_type().is_symlink() => return Err(RulesProblem::Link),
            Ok(meta) if !meta.is_dir() => return Err(RulesProblem::NotAFile),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(RulesProblem::Unreadable),
        }
    }
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_symlink() => return Err(RulesProblem::Link),
        Ok(meta) if !meta.is_file() => return Err(RulesProblem::NotAFile),
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(RulesProblem::Unreadable),
    }
    let bytes =
        fsutil::read_limited(&path, MAX_RULES_FILE).map_err(|_| RulesProblem::Unreadable)?;
    let text = String::from_utf8(bytes).map_err(|_| RulesProblem::Unreadable)?;
    if tool != AgentTool::ClaudeCode {
        return Ok(Some(Rules::Lines(text)));
    }
    if text.trim().is_empty() {
        return Ok(Some(Rules::Settings(Json::Object(Vec::new()))));
    }
    let settings: Json = serde_json::from_str(&text).map_err(|_| RulesProblem::Unreadable)?;
    if !matches!(settings, Json::Object(_)) || deny_list(&settings).is_err() {
        return Err(RulesProblem::Unreadable);
    }
    Ok(Some(Rules::Settings(settings)))
}

/// What the rules file `current` lacks for `files`.
fn lacking(tool: AgentTool, current: Option<&Rules>, files: &[String]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    files
        .iter()
        .map(|path| {
            if tool == AgentTool::ClaudeCode {
                claude_rule(path)
            } else {
                ignore_line(path)
            }
        })
        .filter(|wanted| seen.insert(wanted.clone()))
        .filter(|wanted| match current {
            None => true,
            Some(Rules::Lines(text)) => !text.lines().any(|line| line.trim_end() == wanted),
            Some(Rules::Settings(settings)) => {
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
    let unreadable = || Error::invalid(".claude/settings.local.json can't be read");
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

/// Makes the folder on the way to `path` (`.claude`), inside `folder`, if
/// it isn't there; never through a link.
fn ensure_folder(folder: &Path, path: &Path) -> Result<()> {
    let Some(parent) = path.parent().filter(|parent| *parent != folder) else {
        return Ok(());
    };
    match fs::symlink_metadata(parent) {
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => Err(Error::invalid(format!(
            "{} isn't a folder",
            parent.display()
        ))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(parent).map_err(|e| Error::io(e, parent))
        }
        Err(e) => Err(Error::io(e, parent)),
    }
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

    fn rules_of(folder: &Path, tool: AgentTool) -> AgentRules {
        agent_rules(folder, &files(), &BTreeSet::new())
            .into_iter()
            .find(|rules| rules.tool == tool)
            .unwrap()
    }

    #[test]
    fn ignore_files_get_one_line_per_file_once() {
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path();
        fs::write(folder.join(".cursorignore"), "node_modules\r\n/.env").unwrap();
        let cursor = rules_of(folder, AgentTool::Cursor);
        assert!(cursor.exists);
        assert_eq!(cursor.missing, ["/apps/web/.env.local"]);
        assert!(cursor.found, "its own file is a sign");
        let aider = rules_of(folder, AgentTool::Aider);
        assert!(!aider.exists && !aider.found);
        assert_eq!(aider.missing, ["/.env", "/apps/web/.env.local"]);

        let changed =
            add_agent_rules(folder, &files(), &[AgentTool::Cursor, AgentTool::Aider]).unwrap();
        assert_eq!(changed, [AgentTool::Cursor, AgentTool::Aider]);
        // Its line ends kept, its lines as they were.
        assert_eq!(
            fs::read_to_string(folder.join(".cursorignore")).unwrap(),
            "node_modules\r\n/.env\r\n/apps/web/.env.local\r\n"
        );
        assert_eq!(
            fs::read_to_string(folder.join(".aiderignore")).unwrap(),
            "/.env\n/apps/web/.env.local\n"
        );
        // Nothing to add a second time.
        assert_eq!(
            add_agent_rules(folder, &files(), &[AgentTool::Cursor]).unwrap(),
            []
        );
        assert_eq!(
            rules_of(folder, AgentTool::Cursor).missing,
            Vec::<String>::new()
        );
    }

    #[test]
    fn claude_code_settings_keep_their_keys_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path();
        // None yet: made, with its folder.
        add_agent_rules(folder, &[".env".into()], &[AgentTool::ClaudeCode]).unwrap();
        let path = folder.join(".claude").join("settings.local.json");
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "{\n  \"permissions\": {\n    \"deny\": [\n      \"Read(/.env)\"\n    ]\n  }\n}\n"
        );
        fs::write(
            &path,
            r#"{"z": 1, "permissions": {"allow": ["Bash(ls)"], "deny": ["Read(/.env)"]}, "a": [true, null, 1.5]}"#,
        )
        .unwrap();
        let claude = rules_of(folder, AgentTool::ClaudeCode);
        assert_eq!(claude.missing, ["Read(/apps/web/.env.local)"]);
        add_agent_rules(folder, &files(), &[AgentTool::ClaudeCode]).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        let settings: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            settings,
            serde_json::json!({
                "z": 1,
                "permissions": {
                    "allow": ["Bash(ls)"],
                    "deny": ["Read(/.env)", "Read(/apps/web/.env.local)"]
                },
                "a": [true, null, 1.5]
            })
        );
        let at = |key: &str| text.find(key).unwrap();
        assert!(at("\"z\"") < at("\"permissions\"") && at("\"permissions\"") < at("\"a\""));

        // Settings it can't read are left alone.
        fs::write(&path, r#"{"permissions": {"deny": "Read(/.env)"}}"#).unwrap();
        assert_eq!(
            rules_of(folder, AgentTool::ClaudeCode).problem,
            Some(RulesProblem::Unreadable)
        );
        assert!(add_agent_rules(folder, &files(), &[AgentTool::ClaudeCode]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rules_files_are_never_written_through_a_link() {
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join("shop");
        fs::create_dir(&folder).unwrap();
        let elsewhere = dir.path().join("elsewhere");
        fs::write(&elsewhere, "x\n").unwrap();
        std::os::unix::fs::symlink(&elsewhere, folder.join(".geminiignore")).unwrap();
        std::os::unix::fs::symlink(dir.path(), folder.join(".claude")).unwrap();
        assert_eq!(
            rules_of(&folder, AgentTool::GeminiCli).problem,
            Some(RulesProblem::Link)
        );
        assert_eq!(
            rules_of(&folder, AgentTool::ClaudeCode).problem,
            Some(RulesProblem::Link)
        );
        assert!(add_agent_rules(&folder, &files(), &[AgentTool::GeminiCli]).is_err());
        assert!(add_agent_rules(&folder, &files(), &[AgentTool::ClaudeCode]).is_err());
        assert_eq!(fs::read_to_string(&elsewhere).unwrap(), "x\n");
        assert!(!dir.path().join("settings.local.json").exists());
    }

    #[test]
    fn choices_are_kept_by_folder() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent-rules.json");
        assert_eq!(AgentChoices::load(&path), AgentChoices::default());
        let mut choices = AgentChoices::default();
        let added = FolderChoice::Added {
            tools: vec![AgentTool::Cursor, AgentTool::ClaudeCode],
        };
        choices.set("~/code/shop", added.clone());
        choices.set("~/code/blog", FolderChoice::Declined);
        choices.save(&path).unwrap();
        let loaded = AgentChoices::load(&path);
        assert_eq!(loaded.get("~/code/shop"), Some(&added));
        assert_eq!(loaded.get("~/code/blog"), Some(&FolderChoice::Declined));
        assert_eq!(loaded.get("~/code/other"), None);
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
}
