//! A lossless, editable model of `~/.ssh/config`.
//!
//! [`SshConfig::parse`] never fails and `to_string()` reproduces the input
//! byte for byte (comments, blank lines, tabs, `Key=Value`, quotes, CRLF, a
//! missing final newline, a UTF-8 BOM, …). Edits touch only the lines they
//! change: indentation, separator style, keyword spelling and inline comments
//! of edited lines are kept, everything else stays exactly as it was.
//!
//! Lexing follows OpenSSH (`readconf.c`, `argv_split()`): keywords are
//! case-insensitive, values may be quoted with `"` or `'`, `\` escapes quotes,
//! backslashes and spaces, and an unquoted `#` at the start of an argument
//! begins a comment — except for `ProxyCommand`, `LocalCommand`,
//! `RemoteCommand` and `KnownHostsCommand`, which take the rest of the line
//! literally.

mod lexer;

use std::{
    collections::HashSet,
    fmt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use self::lexer::{Directive, LineKind, lex, render_value, split_args};
use crate::{
    Error, Result, fsutil,
    paths::{SshPaths, native_separators, path_string},
    text::{self, Eol, Line},
};

/// Largest config file that is loaded.
const MAX_CONFIG_SIZE: u64 = 4 * 1024 * 1024;
/// Indentation of options in new blocks when the file has no example.
const DEFAULT_INDENT: &str = "    ";

/// Kind of a configuration block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum HostKind {
    /// `Host pattern…`
    Host,
    /// `Match criteria…`
    Match,
}

/// One `Keyword value` option.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct HostOption {
    /// Keyword as written (case-insensitive when matching).
    pub key: String,
    /// Value. Single-argument keywords (`HostName`, `User`, `Port`,
    /// `IdentityFile`, `ProxyJump`, `CertificateFile`, `IdentityAgent`,
    /// `ControlPath`, …) are unquoted here and quoted on write when they contain
    /// spaces; other values are the text as written.
    pub value: String,
}

impl HostOption {
    /// Convenience constructor.
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

/// Read view of one `Host` or `Match` block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct HostEntry {
    /// Index of the block in the file; valid for the current file contents.
    pub id: u32,
    /// `host` or `match`.
    pub kind: HostKind,
    /// Patterns of a `Host` line (empty for `Match`).
    pub patterns: Vec<String>,
    /// The criteria of a `Match` line as written.
    pub criteria: Option<String>,
    /// Options of the block in file order (without the header line).
    pub options: Vec<HostOption>,
    /// First `HostName`.
    pub host_name: Option<String>,
    /// First `User`.
    pub user: Option<String>,
    /// First `Port`, if it is a valid port number.
    pub port: Option<u16>,
    /// All `IdentityFile` values as written (unexpanded).
    pub identity_files: Vec<String>,
    /// First `ProxyJump`.
    pub proxy_jump: Option<String>,
    /// The block matches many hosts: a pattern contains `*` or `?`, or it is
    /// `Match all`.
    pub is_wildcard: bool,
    /// 1-based line number of the header.
    pub line_start: u32,
    /// 1-based line number of the last option (the header if there is none).
    pub line_end: u32,
}

/// Request to create or update a `Host` block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct HostEdit {
    /// Block to update; `None` creates a new block.
    pub id: Option<u32>,
    /// Host patterns (non-empty, without whitespace or quotes).
    pub patterns: Vec<String>,
    /// The complete desired option list of the block, in order. Repeated
    /// keywords (`IdentityFile`, `LocalForward`, …) are allowed.
    pub options: Vec<HostOption>,
}

/// An `IdentityFile` reference, for showing which hosts use a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct IdentityUsage {
    /// The block, or `None` for an `IdentityFile` before the first block
    /// (applies to every host).
    pub host_id: Option<u32>,
    /// The block's host patterns.
    pub patterns: Vec<String>,
    /// The path with `~`, `%d`, `%%`, `%u`, `%h`, `%n`, `%r`, `%p` and `${VAR}`
    /// expanded as far as possible, using platform separators.
    pub path: String,
    /// The value as written in the file.
    pub raw: String,
    /// True if `path` is absolute and fully expanded (no unknown tokens).
    pub resolved: bool,
    /// True if `path` or `path.pub` exists (`ssh` uses the `.pub` to pick the
    /// key from the agent). Always false when not `resolved`.
    pub exists: bool,
}

/// Kind of a syntax problem in the file. The line is kept unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum ConfigIssueKind {
    /// A keyword without a value.
    MissingValue,
    /// A line starting with `=`.
    MissingKeyword,
    /// A quote is not closed.
    UnterminatedQuote,
}

/// A syntax problem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct ConfigIssue {
    /// 1-based line number.
    pub line: u32,
    /// What is wrong.
    pub kind: ConfigIssueKind,
}

/// Everything the UI shows about a config file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct ConfigView {
    /// Options before the first `Host`/`Match` (apply to every host).
    pub global_options: Vec<HostOption>,
    /// All blocks in file order.
    pub hosts: Vec<HostEntry>,
    /// Arguments of all `Include` lines.
    pub includes: Vec<String>,
    /// Syntax problems.
    pub issues: Vec<ConfigIssue>,
}

/// The parsed file. Cheap to clone; edits are applied in memory and written
/// with [`SshConfig::save`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshConfig {
    lines: Vec<Line>,
}

/// Line range of a block: `header..end` (end exclusive, up to the next header).
#[derive(Debug, Clone, Copy)]
struct Block {
    kind: HostKind,
    header: usize,
    end: usize,
}

impl SshConfig {
    /// Parses config text. Never fails.
    pub fn parse(input: &str) -> Self {
        Self {
            lines: text::split_lines(input),
        }
    }

    /// Loads a config file; a missing file is an empty config. Non-UTF-8 files
    /// are rejected ([`Error::Parse`]) so they are never rewritten lossily.
    pub fn load(path: &Path) -> Result<Self> {
        match fsutil::read_limited(path, MAX_CONFIG_SIZE) {
            Ok(bytes) => String::from_utf8(bytes)
                .map(|s| Self::parse(&s))
                .map_err(|_| Error::Parse(format!("{} is not valid UTF-8", path.display()))),
            Err(Error::NotFound(_)) => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    /// Writes the config atomically after backing up the current file into
    /// `backup_dir`. A new file gets mode 0600; an existing one keeps its
    /// permissions (and stays a symlink if it is one). Returns the backup path.
    pub fn save(&self, path: &Path, backup_dir: &Path) -> Result<Option<PathBuf>> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fsutil::ensure_private_dir(parent)?;
        }
        let backup = fsutil::backup(path, backup_dir)?;
        fsutil::atomic_write(path, self.to_string().as_bytes(), 0o600)?;
        Ok(backup)
    }

    /// True if the file has no lines.
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// All blocks.
    pub fn hosts(&self) -> Vec<HostEntry> {
        self.blocks()
            .iter()
            .enumerate()
            .map(|(i, b)| self.entry(i, *b))
            .collect()
    }

    /// One block by id.
    pub fn host(&self, id: u32) -> Option<HostEntry> {
        let index = usize::try_from(id).ok()?;
        self.blocks().get(index).map(|b| self.entry(index, *b))
    }

    /// Options before the first block.
    pub fn global_options(&self) -> Vec<HostOption> {
        let end = self.blocks().first().map_or(self.lines.len(), |b| b.header);
        self.options_in(0, end)
    }

    /// Arguments of all `Include` lines (global and inside blocks), unexpanded.
    pub fn includes(&self) -> Vec<String> {
        self.directives(0, self.lines.len())
            .filter(|(_, d)| d.key.eq_ignore_ascii_case("include"))
            .flat_map(|(_, d)| split_args(d.value).0)
            .collect()
    }

    /// Syntax problems (the file is still kept and written unchanged).
    pub fn issues(&self) -> Vec<ConfigIssue> {
        let mut issues = Vec::new();
        for (i, d) in self.directives(0, self.lines.len()) {
            let line = line_number(i);
            let kind = if d.key.is_empty() {
                Some(ConfigIssueKind::MissingKeyword)
            } else if d.value.is_empty() {
                Some(ConfigIssueKind::MissingValue)
            } else if lexer::value_style(&d.key_lower()) != lexer::ValueStyle::RestOfLine
                && split_args(d.value).1
            {
                Some(ConfigIssueKind::UnterminatedQuote)
            } else {
                None
            };
            if let Some(kind) = kind {
                issues.push(ConfigIssue { line, kind });
            }
        }
        issues
    }

    /// Hosts, global options, includes and issues in one value.
    pub fn view(&self) -> ConfigView {
        ConfigView {
            global_options: self.global_options(),
            hosts: self.hosts(),
            includes: self.includes(),
            issues: self.issues(),
        }
    }

    /// Creates (`edit.id == None`) or updates a `Host` block; returns its id.
    ///
    /// Updating keeps every untouched line as is, rewrites changed values in
    /// place, removes options missing from `edit.options` and appends new ones
    /// after the block's last option with the block's indentation. A new block
    /// is inserted before a trailing `Host *` block (the first obtained value
    /// wins in `ssh_config`, so catch-all defaults must stay last), otherwise
    /// appended, separated by one blank line.
    pub fn upsert_host(&mut self, edit: &HostEdit) -> Result<u32> {
        // Surrounding whitespace is insignificant to OpenSSH; drop it so it is
        // neither quoted into values nor rejected in patterns.
        let edit = HostEdit {
            id: edit.id,
            patterns: edit.patterns.iter().map(|p| p.trim().to_owned()).collect(),
            options: edit
                .options
                .iter()
                .map(|o| HostOption::new(o.key.trim(), o.value.trim()))
                .collect(),
        };
        validate_patterns(&edit.patterns)?;
        for option in &edit.options {
            validate_option(option)?;
        }
        match edit.id {
            Some(id) => {
                self.update_block(id, &edit)?;
                Ok(id)
            }
            None => Ok(self.insert_block(&edit)),
        }
    }

    /// Removes a block together with the comment lines directly above it.
    pub fn delete_host(&mut self, id: u32) -> Result<()> {
        let blocks = self.blocks();
        let index = block_index(id, &blocks)?;
        let block = blocks[index];
        let mut start = self.attached_comment_start(block.header);
        let end = blocks.get(index + 1).map_or(self.lines.len(), |next| {
            self.attached_comment_start(next.header)
        });
        if end == self.lines.len() {
            while start > 0 && self.lines[start - 1].is_blank() {
                start -= 1;
            }
        }
        text::remove_range(&mut self.lines, start, end);
        Ok(())
    }

    /// Removes the `IdentityFile` lines whose value equals `value` from a
    /// block (`host_id`) or from the global section (`None`). Returns whether
    /// anything was removed.
    pub fn remove_identity_file(&mut self, host_id: Option<u32>, value: &str) -> Result<bool> {
        let blocks = self.blocks();
        let (start, end) = match host_id {
            Some(id) => {
                let b = blocks[block_index(id, &blocks)?];
                (b.header + 1, b.end)
            }
            None => (0, blocks.first().map_or(self.lines.len(), |b| b.header)),
        };
        let doomed: HashSet<usize> = self
            .directives(start, end)
            .filter(|(_, d)| {
                d.key.eq_ignore_ascii_case("identityfile") && d.logical_value() == value
            })
            .map(|(i, _)| i)
            .collect();
        if doomed.is_empty() {
            return Ok(false);
        }
        self.rebuild(&doomed, &[], None, &[]);
        Ok(true)
    }

    /// Where each `IdentityFile` points, with `~` and tokens expanded relative
    /// to `paths.home`.
    pub fn identity_usage(&self, paths: &SshPaths) -> Vec<IdentityUsage> {
        let local_user = std::env::var(if cfg!(windows) { "USERNAME" } else { "USER" }).ok();
        let mut out = Vec::new();
        let blocks = self.blocks();
        let global_end = blocks.first().map_or(self.lines.len(), |b| b.header);
        let global_ctx = TokenContext {
            home: &paths.home,
            local_user: local_user.as_deref(),
            alias: None,
            host_name: None,
            user: None,
            port: None,
        };
        for value in self.identity_values(0, global_end) {
            out.push(resolve_identity(None, Vec::new(), &value, &global_ctx));
        }
        for (i, b) in blocks.iter().enumerate() {
            let entry = self.entry(i, *b);
            let alias = match entry.patterns.as_slice() {
                [one] if !one.contains(['*', '?', '!']) => Some(one.as_str()),
                _ => None,
            };
            let ctx = TokenContext {
                home: &paths.home,
                local_user: local_user.as_deref(),
                alias,
                host_name: entry.host_name.as_deref().or(alias),
                user: entry.user.as_deref(),
                port: entry.port,
            };
            for value in entry
                .identity_files
                .iter()
                .filter(|v| !v.eq_ignore_ascii_case("none"))
            {
                out.push(resolve_identity(
                    Some(entry.id),
                    entry.patterns.clone(),
                    value,
                    &ctx,
                ));
            }
        }
        out
    }

    // -- internals ----------------------------------------------------------

    fn blocks(&self) -> Vec<Block> {
        let mut blocks: Vec<Block> = Vec::new();
        for (i, line) in self.lines.iter().enumerate() {
            if let LineKind::Directive(d) = lex(&line.text) {
                let kind = if d.key.eq_ignore_ascii_case("host") {
                    HostKind::Host
                } else if d.key.eq_ignore_ascii_case("match") {
                    HostKind::Match
                } else {
                    continue;
                };
                if let Some(last) = blocks.last_mut() {
                    last.end = i;
                }
                blocks.push(Block {
                    kind,
                    header: i,
                    end: self.lines.len(),
                });
            }
        }
        blocks
    }

    fn directives(&self, start: usize, end: usize) -> impl Iterator<Item = (usize, Directive<'_>)> {
        self.lines[start..end.min(self.lines.len())]
            .iter()
            .enumerate()
            .filter_map(move |(off, line)| match lex(&line.text) {
                LineKind::Directive(d) => Some((start + off, d)),
                _ => None,
            })
    }

    fn options_in(&self, start: usize, end: usize) -> Vec<HostOption> {
        self.directives(start, end)
            .map(|(_, d)| HostOption::new(d.key, d.logical_value()))
            .collect()
    }

    fn identity_values(&self, start: usize, end: usize) -> Vec<String> {
        self.directives(start, end)
            .filter(|(_, d)| d.key.eq_ignore_ascii_case("identityfile"))
            .map(|(_, d)| d.logical_value())
            .filter(|v| !v.eq_ignore_ascii_case("none"))
            .collect()
    }

    fn header(&self, b: Block) -> Option<Directive<'_>> {
        match lex(&self.lines[b.header].text) {
            LineKind::Directive(d) => Some(d),
            _ => None,
        }
    }

    fn entry(&self, index: usize, b: Block) -> HostEntry {
        let header_value = self.header(b).map(|d| d.value).unwrap_or_default();
        let (patterns, criteria) = match b.kind {
            HostKind::Host => (split_args(header_value).0, None),
            HostKind::Match => (Vec::new(), Some(header_value.to_owned())),
        };
        let options = self.options_in(b.header + 1, b.end);
        let first = |key: &str| {
            options
                .iter()
                .find(|o| o.key.eq_ignore_ascii_case(key))
                .map(|o| o.value.clone())
        };
        let last_option = self
            .directives(b.header + 1, b.end)
            .last()
            .map_or(b.header, |(i, _)| i);
        let is_wildcard = match b.kind {
            HostKind::Host => patterns.iter().any(|p| p.contains(['*', '?'])),
            HostKind::Match => header_value.trim().eq_ignore_ascii_case("all"),
        };
        HostEntry {
            id: u32::try_from(index).unwrap_or(u32::MAX),
            kind: b.kind,
            host_name: first("hostname"),
            user: first("user"),
            port: first("port").and_then(|p| p.parse().ok()),
            proxy_jump: first("proxyjump"),
            identity_files: options
                .iter()
                .filter(|o| o.key.eq_ignore_ascii_case("identityfile"))
                .map(|o| o.value.clone())
                .collect(),
            patterns,
            criteria,
            options,
            is_wildcard,
            line_start: line_number(b.header),
            line_end: line_number(last_option),
        }
    }

    /// First line of the run of comment lines directly above `header`.
    fn attached_comment_start(&self, header: usize) -> usize {
        let mut start = header;
        while start > 0 && lex(&self.lines[start - 1].text) == LineKind::Comment {
            start -= 1;
        }
        start
    }

    /// Indentation used by option lines in this file (first indented option
    /// inside any block), else four spaces.
    fn default_indent(&self) -> String {
        for b in self.blocks() {
            for (_, d) in self.directives(b.header + 1, b.end) {
                if !d.indent.is_empty() {
                    return d.indent.trim_start_matches('\u{feff}').to_owned();
                }
            }
        }
        DEFAULT_INDENT.to_owned()
    }

    fn update_block(&mut self, id: u32, edit: &HostEdit) -> Result<()> {
        let blocks = self.blocks();
        let block = blocks[block_index(id, &blocks)?];
        if block.kind == HostKind::Match {
            return Err(Error::Unsupported("editing Match blocks".into()));
        }
        let header = self
            .header(block)
            .ok_or_else(|| Error::Parse("block header is not a directive".into()))?;
        let mut rewrites: Vec<(usize, String)> = Vec::new();
        if split_args(header.value).0 != edit.patterns {
            rewrites.push((block.header, header.with_value(&edit.patterns.join(" "))));
        }

        let existing: Vec<(usize, String, String, Directive<'_>)> = self
            .directives(block.header + 1, block.end)
            .map(|(i, d)| (i, d.key_lower(), d.logical_value(), d))
            .collect();
        let mut used = vec![false; existing.len()];
        let mut appends = Vec::new();
        for option in &edit.options {
            let key = option.key.to_ascii_lowercase();
            match (0..existing.len()).find(|&j| !used[j] && existing[j].1 == key) {
                Some(j) => {
                    used[j] = true;
                    if existing[j].2 != option.value {
                        let value = render_value(&key, &option.value);
                        rewrites.push((existing[j].0, existing[j].3.with_value(&value)));
                    }
                }
                None => appends.push(option),
            }
        }
        let doomed: HashSet<usize> = existing
            .iter()
            .zip(&used)
            .filter(|(_, used)| !**used)
            .map(|(e, _)| e.0)
            .collect();
        let indent = existing
            .first()
            .map(|e| e.3.indent.trim_start_matches('\u{feff}').to_owned())
            .filter(|i| !i.is_empty())
            .unwrap_or_else(|| self.default_indent());
        let anchor = existing
            .iter()
            .rev()
            .map(|e| e.0)
            .find(|i| !doomed.contains(i))
            .unwrap_or(block.header);
        let new_lines: Vec<String> = appends.iter().map(|o| option_line(&indent, o)).collect();
        self.rebuild(&doomed, &rewrites, Some(anchor), &new_lines);
        Ok(())
    }

    fn insert_block(&mut self, edit: &HostEdit) -> u32 {
        let blocks = self.blocks();
        let eol = text::dominant_eol(&self.lines);
        let had_final_eol = self.lines.last().is_none_or(|l| l.eol != Eol::None);
        let trailing_star = blocks.last().filter(|b| {
            b.kind == HostKind::Host
                && self
                    .header(**b)
                    .is_some_and(|d| split_args(d.value).0 == ["*"])
        });
        let (pos, index) = match trailing_star {
            Some(b) => (self.attached_comment_start(b.header), blocks.len() - 1),
            None => (self.lines.len(), blocks.len()),
        };
        let indent = self.default_indent();
        let mut new = Vec::new();
        if pos > 0 && !self.lines[pos - 1].is_blank() {
            new.push(Line::new("", eol));
        }
        new.push(Line::new(format!("Host {}", edit.patterns.join(" ")), eol));
        for option in &edit.options {
            new.push(Line::new(option_line(&indent, option), eol));
        }
        if trailing_star.is_some() {
            new.push(Line::new("", eol));
        }
        if pos > 0 && self.lines[pos - 1].eol == Eol::None {
            self.lines[pos - 1].eol = eol;
        }
        self.lines.splice(pos..pos, new);
        text::fix_final_eol(&mut self.lines, had_final_eol);
        u32::try_from(index).unwrap_or(u32::MAX)
    }

    /// Rebuilds the line list: drops `doomed`, applies `rewrites`, inserts
    /// `inserts` after line `anchor`, and keeps the final-newline property.
    fn rebuild(
        &mut self,
        doomed: &HashSet<usize>,
        rewrites: &[(usize, String)],
        anchor: Option<usize>,
        inserts: &[String],
    ) {
        let eol = text::dominant_eol(&self.lines);
        let had_final_eol = self.lines.last().is_none_or(|l| l.eol != Eol::None);
        let old = std::mem::take(&mut self.lines);
        let mut lines = Vec::with_capacity(old.len() + inserts.len());
        for (i, mut line) in old.into_iter().enumerate() {
            if doomed.contains(&i) {
                continue;
            }
            if let Some((_, text)) = rewrites.iter().find(|(j, _)| *j == i) {
                line.text.clone_from(text);
            }
            let is_anchor = anchor == Some(i);
            if is_anchor && !inserts.is_empty() && line.eol == Eol::None {
                line.eol = eol;
            }
            lines.push(line);
            if is_anchor {
                lines.extend(inserts.iter().map(|t| Line::new(t.clone(), eol)));
            }
        }
        text::fix_final_eol(&mut lines, had_final_eol);
        self.lines = lines;
    }
}

impl fmt::Display for SshConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        text::write_lines(&self.lines, f)
    }
}

fn line_number(index: usize) -> u32 {
    u32::try_from(index + 1).unwrap_or(u32::MAX)
}

fn block_index(id: u32, blocks: &[Block]) -> Result<usize> {
    usize::try_from(id)
        .ok()
        .filter(|i| *i < blocks.len())
        .ok_or_else(|| Error::NotFound(format!("host block {id}")))
}

fn option_line(indent: &str, option: &HostOption) -> String {
    let value = render_value(&option.key.to_ascii_lowercase(), &option.value);
    format!("{indent}{} {value}", option.key)
}

fn validate_patterns(patterns: &[String]) -> Result<()> {
    if patterns.is_empty() {
        return Err(Error::invalid("a host needs at least one pattern"));
    }
    for p in patterns {
        if p.is_empty()
            || p.starts_with('#')
            || p.chars()
                .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '\'' | '\\'))
        {
            return Err(Error::invalid(format!("invalid host pattern: {p:?}")));
        }
    }
    Ok(())
}

fn validate_option(option: &HostOption) -> Result<()> {
    let key_ok = option
        .key
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic())
        && option.key.chars().all(|c| c.is_ascii_alphanumeric());
    if !key_ok {
        return Err(Error::invalid(format!("invalid keyword: {:?}", option.key)));
    }
    if option.key.eq_ignore_ascii_case("host") || option.key.eq_ignore_ascii_case("match") {
        return Err(Error::invalid("Host and Match cannot be used as options"));
    }
    if option.value.trim().is_empty()
        || option
            .value
            .chars()
            .any(|c| matches!(c, '\n' | '\r' | '\0'))
    {
        return Err(Error::invalid(format!(
            "invalid value for {}: must be one non-empty line",
            option.key
        )));
    }
    Ok(())
}

struct TokenContext<'a> {
    home: &'a Path,
    local_user: Option<&'a str>,
    alias: Option<&'a str>,
    host_name: Option<&'a str>,
    user: Option<&'a str>,
    port: Option<u16>,
}

fn resolve_identity(
    host_id: Option<u32>,
    patterns: Vec<String>,
    raw: &str,
    ctx: &TokenContext<'_>,
) -> IdentityUsage {
    let (path, resolved) = expand_identity(raw, ctx);
    let exists = resolved && (path.exists() || crate::keys::sibling_pub(&path).exists());
    IdentityUsage {
        host_id,
        patterns,
        path: path_string(&path),
        raw: raw.to_owned(),
        resolved,
        exists,
    }
}

/// Expands `~` and the `ssh_config` tokens that are known without connecting.
fn expand_identity(raw: &str, ctx: &TokenContext<'_>) -> (PathBuf, bool) {
    let mut resolved = true;
    let home = ctx.home.to_string_lossy();
    let tilde_rest = if raw == "~" {
        Some("")
    } else {
        raw.strip_prefix("~/")
            .or_else(|| cfg!(windows).then(|| raw.strip_prefix("~\\")).flatten())
    };
    let input = if let Some(rest) = tilde_rest {
        format!("%d/{rest}")
    } else {
        // `~user/…` cannot be resolved without the user database.
        resolved &= !raw.starts_with('~');
        raw.to_owned()
    };
    let mut out = String::with_capacity(input.len() + home.len());
    let mut chars = input.chars().peekable();
    let mut push_or_unresolved = |out: &mut String, value: Option<&str>, token: &str| {
        if let Some(v) = value {
            out.push_str(v);
        } else {
            resolved = false;
            out.push_str(token);
        }
    };
    while let Some(c) = chars.next() {
        match c {
            '%' => match chars.next() {
                Some('%') => out.push('%'),
                Some('d') => out.push_str(&home),
                Some('u') => push_or_unresolved(&mut out, ctx.local_user, "%u"),
                Some('h') => push_or_unresolved(&mut out, ctx.host_name, "%h"),
                Some('n') => push_or_unresolved(&mut out, ctx.alias, "%n"),
                Some('r') => push_or_unresolved(&mut out, ctx.user.or(ctx.local_user), "%r"),
                Some('p') => out.push_str(&ctx.port.unwrap_or(22).to_string()),
                Some(other) => push_or_unresolved(&mut out, None, &format!("%{other}")),
                None => push_or_unresolved(&mut out, None, "%"),
            },
            '$' if chars.peek() == Some(&'{') => {
                chars.next();
                let name: String = chars.by_ref().take_while(|c| *c != '}').collect();
                let value = std::env::var(&name).ok();
                push_or_unresolved(&mut out, value.as_deref(), &format!("${{{name}}}"));
            }
            _ => out.push(c),
        }
    }
    let path = PathBuf::from(native_separators(&out));
    if !path.is_absolute() {
        resolved = false;
    }
    (path, resolved)
}

#[cfg(test)]
mod tests;
