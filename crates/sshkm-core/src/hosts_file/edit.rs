//! Changes to the hosts file. A change names an entry by its line in the
//! revision it was made against; every line no change touches is written back
//! byte for byte.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

use super::{
    GROUP_END, GROUP_START, HostsFile, HostsFileEntry, HostsGroup, LineKind, Scanned, UNTIL,
    is_system_name, is_valid_name, line_number, parse_address, revision_of,
};
use crate::{
    Error, Result,
    text::{self, Eol, Line},
};

/// Longest group name.
const MAX_GROUP_NAME: usize = 64;
/// Unchanged lines a diff shows around each change.
const CONTEXT: usize = 2;

/// An entry as the user wants it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct HostsEntryEdit {
    /// IPv4 or IPv6 address.
    pub address: String,
    /// One or more names.
    pub names: Vec<String>,
    /// Comment without the `#`.
    pub comment: Option<String>,
    /// False writes the entry commented out.
    pub enabled: bool,
    /// When a temporary entry expires (RFC 3339).
    pub expires: Option<String>,
    /// The group the entry belongs in; a name no group has yet creates one at
    /// the end of the file.
    pub group: Option<String>,
}

/// One change. Lines are those of the revision the changes were made against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum HostsChange {
    /// Rewrites the entry on `line`. Turning it on or off alone keeps the
    /// line's text and only adds or removes the `#`; a different group moves
    /// the entry to the end of that group.
    Set {
        /// 1-based line of the entry.
        line: u32,
        /// What it should be.
        entry: HostsEntryEdit,
    },
    /// Removes the entry on `line`.
    Remove {
        /// 1-based line of the entry.
        line: u32,
    },
    /// Adds an entry at the end of its group, or of the file.
    Add {
        /// The new entry.
        entry: HostsEntryEdit,
    },
    /// Renames a group.
    RenameGroup {
        /// Current name.
        name: String,
        /// New name.
        to: String,
    },
    /// Removes a group's markers; its entries stay where they are.
    Ungroup {
        /// The group.
        name: String,
    },
}

/// What a diff line is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum HostsDiffKind {
    /// Unchanged, shown for context.
    Same,
    /// Only in the new file.
    Added,
    /// Only in the old file.
    Removed,
    /// A run of unchanged lines that are not shown.
    Skipped,
}

/// One line of a diff between the file and its edited version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct HostsDiffLine {
    /// What the line is.
    pub kind: HostsDiffKind,
    /// The line's text; empty when skipped.
    pub text: String,
    /// 1-based line in the old file.
    pub old_line: Option<u32>,
    /// 1-based line in the new file.
    pub new_line: Option<u32>,
    /// How many unchanged lines a skipped row stands for.
    pub count: u32,
}

/// The file after a set of changes, with the diff to show before writing it.
#[derive(Debug, Clone)]
pub struct HostsEdited {
    /// The new file.
    pub file: HostsFile,
    /// Changed lines with a little context.
    pub diff: Vec<HostsDiffLine>,
}

enum Op {
    Keep,
    Replace(String),
    Delete,
}

impl HostsEntryEdit {
    /// Checks the entry and returns it trimmed, with the expiry time in UTC.
    fn normalized(&self) -> Result<Self> {
        let address = self.address.trim().to_owned();
        if parse_address(&address).is_none() {
            return Err(Error::invalid(format!("{address:?} is not an IP address")));
        }
        let names: Vec<String> = self
            .names
            .iter()
            .map(|name| name.trim().to_owned())
            .filter(|name| !name.is_empty())
            .collect();
        if names.is_empty() {
            return Err(Error::invalid("an entry needs at least one name"));
        }
        if let Some(bad) = names.iter().find(|name| !is_valid_name(name)) {
            return Err(Error::invalid(format!("{bad:?} is not a host name")));
        }
        if let Some(system) = names.iter().find(|name| is_system_name(name)) {
            return Err(Error::invalid(format!(
                "{system} is reserved for the system"
            )));
        }
        let comment = self
            .comment
            .as_deref()
            .map(str::trim)
            .filter(|comment| !comment.is_empty());
        if comment.is_some_and(|c| c.contains(['\n', '\r']) || c.contains(UNTIL)) {
            return Err(Error::invalid(
                "the comment has a line break or a reserved word",
            ));
        }
        let expires = self.expires.as_deref().map(canonical_time).transpose()?;
        let group = self.group.as_deref().map(group_name).transpose()?;
        Ok(Self {
            address,
            names,
            comment: comment.map(str::to_owned),
            enabled: self.enabled,
            expires,
            group,
        })
    }
}

impl HostsFile {
    /// The file with `changes` applied. Fails without changing anything when
    /// a change names a line that is not an editable entry, a group that does
    /// not exist, or invalid values.
    pub fn edited(&self, changes: &[HostsChange]) -> Result<HostsEdited> {
        let groups = self.groups();
        let mut plan = Plan {
            ops: self.lines.iter().map(|_| Op::Keep).collect(),
            touched: HashSet::new(),
            final_names: HashMap::new(),
            additions: Vec::new(),
        };
        // Groups first, so entries can be compared with their group's new name.
        for change in changes {
            plan.group_change(change, &groups)?;
        }
        let entries: HashMap<u32, HostsFileEntry> =
            self.entries().into_iter().map(|e| (e.line, e)).collect();
        let sep = separator(&self.scan(), &self.lines);
        for change in changes {
            plan.entry_change(change, &entries, &groups, &self.lines, sep)?;
        }
        Ok(self.assemble(plan, &groups))
    }

    fn assemble(&self, plan: Plan, groups: &[HostsGroup]) -> HostsEdited {
        let mut insert_before: HashMap<usize, Vec<String>> = HashMap::new();
        let mut ungrouped: Vec<String> = Vec::new();
        let mut new_groups: Vec<(String, Vec<String>)> = Vec::new();
        let ends = plan.group_ends(groups, self.lines.len());
        for (group, text) in plan.additions {
            match group {
                None => ungrouped.push(text),
                Some(name) => {
                    if let Some((_, end)) = ends.iter().find(|(g, _)| *g == name) {
                        insert_before.entry(*end).or_default().push(text);
                    } else if let Some((_, texts)) = new_groups.iter_mut().find(|(g, _)| *g == name)
                    {
                        texts.push(text);
                    } else {
                        new_groups.push((name, vec![text]));
                    }
                }
            }
        }

        let mut out = Builder::new(text::dominant_eol(&self.lines));
        for (i, line) in self.lines.iter().enumerate() {
            for text in insert_before.remove(&i).unwrap_or_default() {
                out.add(text);
            }
            match &plan.ops[i] {
                Op::Keep => out.keep(i, line),
                Op::Replace(text) => out.replace(i, line, text.clone()),
                Op::Delete => out.delete(i, line),
            }
        }
        for text in insert_before.remove(&self.lines.len()).unwrap_or_default() {
            out.add(text);
        }
        // A last group without a closing marker would swallow what follows.
        let trailing_open = groups
            .last()
            .filter(|g| g.end_line.is_none())
            .and_then(|g| final_name(groups, &plan.final_names, Some(&g.name)));
        if let Some(name) = trailing_open
            && (!ungrouped.is_empty() || !new_groups.is_empty())
        {
            out.add(end_marker(&name));
        }
        for text in ungrouped {
            out.add(text);
        }
        for (name, texts) in new_groups {
            if out.lines.last().is_some_and(|l| !l.is_blank()) {
                out.add(String::new());
            }
            out.add(start_marker(&name));
            for text in texts {
                out.add(text);
            }
            out.add(end_marker(&name));
        }

        let had_final_eol = self.lines.last().is_none_or(|l| l.eol != Eol::None);
        text::fix_final_eol(&mut out.lines, had_final_eol || out.added_any);
        let mut file = Self {
            lines: out.lines,
            revision: String::new(),
            utf8: true,
        };
        file.revision = revision_of(file.to_string().as_bytes());
        HostsEdited {
            file,
            diff: compress(out.diff),
        }
    }
}

/// What happens to each existing line, and the lines to add.
struct Plan {
    ops: Vec<Op>,
    touched: HashSet<u32>,
    /// Groups that are renamed (`Some`) or dissolved (`None`), by the line of
    /// their opening marker.
    final_names: HashMap<u32, Option<String>>,
    /// New lines with the group they go in.
    additions: Vec<(Option<String>, String)>,
}

impl Plan {
    /// Marks a line as changed; a line can change only once.
    fn touch(&mut self, line: u32) -> Result<usize> {
        if !self.touched.insert(line) {
            return Err(Error::invalid(format!("line {line} is changed twice")));
        }
        Ok(index(line))
    }

    fn group_change(&mut self, change: &HostsChange, groups: &[HostsGroup]) -> Result<()> {
        match change {
            HostsChange::RenameGroup { name, to } => {
                let to = group_name(to)?;
                let group = find_group(groups, name)?;
                if groups.iter().any(|g| g.name == to && g.line != group.line) {
                    return Err(Error::AlreadyExists(format!("group {to}")));
                }
                let i = self.touch(group.line)?;
                self.ops[i] = Op::Replace(start_marker(&to));
                if let Some(end) = group.end_line {
                    let i = self.touch(end)?;
                    self.ops[i] = Op::Replace(end_marker(&to));
                }
                self.final_names.insert(group.line, Some(to));
            }
            HostsChange::Ungroup { name } => {
                let group = find_group(groups, name)?;
                let i = self.touch(group.line)?;
                self.ops[i] = Op::Delete;
                if let Some(end) = group.end_line {
                    let i = self.touch(end)?;
                    self.ops[i] = Op::Delete;
                }
                self.final_names.insert(group.line, None);
            }
            HostsChange::Set { .. } | HostsChange::Remove { .. } | HostsChange::Add { .. } => {}
        }
        Ok(())
    }

    fn entry_change(
        &mut self,
        change: &HostsChange,
        entries: &HashMap<u32, HostsFileEntry>,
        groups: &[HostsGroup],
        lines: &[Line],
        sep: &str,
    ) -> Result<()> {
        match change {
            HostsChange::Set { line, entry: edit } => {
                let current = editable_entry(entries, *line)?;
                let i = self.touch(*line)?;
                let edit = edit.normalized()?;
                if edit.group == final_name(groups, &self.final_names, current.group.as_deref()) {
                    let mut text = replacement(&lines[i].text, current, &edit, sep)?;
                    if i == 0 && lines[i].text.starts_with('\u{feff}') {
                        text.insert(0, '\u{feff}');
                    }
                    self.ops[i] = Op::Replace(text);
                } else {
                    self.ops[i] = Op::Delete;
                    self.additions
                        .push((edit.group.clone(), render(&edit, sep)));
                }
            }
            HostsChange::Remove { line } => {
                editable_entry(entries, *line)?;
                let i = self.touch(*line)?;
                self.ops[i] = Op::Delete;
            }
            HostsChange::Add { entry } => {
                let edit = entry.normalized()?;
                self.additions
                    .push((edit.group.clone(), render(&edit, sep)));
            }
            HostsChange::RenameGroup { .. } | HostsChange::Ungroup { .. } => {}
        }
        Ok(())
    }

    /// Where each kept group ends, by its final name: before its closing
    /// marker, or before the next group (the end of the file for the last).
    fn group_ends(&self, groups: &[HostsGroup], len: usize) -> Vec<(String, usize)> {
        let mut ends = Vec::new();
        for (position, group) in groups.iter().enumerate() {
            let name = match self.final_names.get(&group.line) {
                Some(Some(name)) => name.clone(),
                Some(None) => continue,
                None => group.name.clone(),
            };
            let end = group.end_line.map_or_else(
                || {
                    groups
                        .get(position + 1)
                        .map_or(len, |next| index(next.line))
                },
                index,
            );
            ends.push((name, end));
        }
        ends
    }
}

/// The name a group has after the changes (`None`: no group, or dissolved).
fn final_name(
    groups: &[HostsGroup],
    final_names: &HashMap<u32, Option<String>>,
    name: Option<&str>,
) -> Option<String> {
    let group = groups.iter().find(|g| Some(g.name.as_str()) == name)?;
    final_names
        .get(&group.line)
        .cloned()
        .unwrap_or_else(|| Some(group.name.clone()))
}

/// Collects the new lines and the full diff.
struct Builder {
    lines: Vec<Line>,
    diff: Vec<HostsDiffLine>,
    eol: Eol,
    added_any: bool,
}

impl Builder {
    fn new(eol: Eol) -> Self {
        Self {
            lines: Vec::new(),
            diff: Vec::new(),
            eol,
            added_any: false,
        }
    }

    fn new_line(&self) -> u32 {
        line_number(self.lines.len() - 1)
    }

    fn keep(&mut self, index: usize, line: &Line) {
        self.lines.push(line.clone());
        let new_line = self.new_line();
        self.diff.push(row(
            HostsDiffKind::Same,
            &line.text,
            Some(index),
            Some(new_line),
        ));
    }

    fn replace(&mut self, index: usize, line: &Line, text: String) {
        self.diff
            .push(row(HostsDiffKind::Removed, &line.text, Some(index), None));
        self.lines.push(Line::new(text, line.eol));
        let added = row(
            HostsDiffKind::Added,
            &self.lines[self.lines.len() - 1].text,
            None,
            Some(self.new_line()),
        );
        self.diff.push(added);
    }

    fn delete(&mut self, index: usize, line: &Line) {
        self.diff
            .push(row(HostsDiffKind::Removed, &line.text, Some(index), None));
    }

    fn add(&mut self, text: String) {
        if let Some(last) = self.lines.last_mut()
            && last.eol == Eol::None
        {
            last.eol = self.eol;
        }
        self.lines.push(Line::new(text, self.eol));
        self.added_any = true;
        let added = row(
            HostsDiffKind::Added,
            &self.lines[self.lines.len() - 1].text,
            None,
            Some(self.new_line()),
        );
        self.diff.push(added);
    }
}

fn row(
    kind: HostsDiffKind,
    text: &str,
    old: Option<usize>,
    new_line: Option<u32>,
) -> HostsDiffLine {
    HostsDiffLine {
        kind,
        text: text.trim_start_matches('\u{feff}').to_owned(),
        old_line: old.map(line_number),
        new_line,
        count: 0,
    }
}

/// Keeps changed lines and [`CONTEXT`] lines around them; each other run of
/// unchanged lines becomes one skipped row.
fn compress(rows: Vec<HostsDiffLine>) -> Vec<HostsDiffLine> {
    let changed: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, r)| r.kind != HostsDiffKind::Same)
        .map(|(i, _)| i)
        .collect();
    let near = |i: usize| changed.iter().any(|&c| c.abs_diff(i) <= CONTEXT);
    let mut out: Vec<HostsDiffLine> = Vec::new();
    for (i, r) in rows.into_iter().enumerate() {
        if r.kind != HostsDiffKind::Same || near(i) {
            out.push(r);
        } else if let Some(skipped) = out.last_mut().filter(|l| l.kind == HostsDiffKind::Skipped) {
            skipped.count += 1;
        } else {
            out.push(HostsDiffLine {
                kind: HostsDiffKind::Skipped,
                text: String::new(),
                old_line: None,
                new_line: None,
                count: 1,
            });
        }
    }
    out
}

/// The 0-based index of a 1-based line.
fn index(line: u32) -> usize {
    usize::try_from(line).map_or(usize::MAX, |line| line.saturating_sub(1))
}

fn editable_entry(entries: &HashMap<u32, HostsFileEntry>, line: u32) -> Result<&HostsFileEntry> {
    let entry = entries
        .get(&line)
        .ok_or_else(|| Error::NotFound(format!("an entry on line {line}")))?;
    if entry.system {
        return Err(Error::invalid(format!("line {line} is a system entry")));
    }
    Ok(entry)
}

fn find_group<'a>(groups: &'a [HostsGroup], name: &str) -> Result<&'a HostsGroup> {
    groups
        .iter()
        .find(|g| g.name == name)
        .ok_or_else(|| Error::NotFound(format!("group {name}")))
}

/// A trimmed group name of 1–64 characters without control characters.
fn group_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty()
        || name.chars().count() > MAX_GROUP_NAME
        || name.chars().any(char::is_control)
    {
        return Err(Error::invalid(format!("{name:?} is not a group name")));
    }
    Ok(name.to_owned())
}

/// An RFC 3339 time in UTC, to the second.
fn canonical_time(time: &str) -> Result<String> {
    OffsetDateTime::parse(time.trim(), &Rfc3339)
        .ok()
        .and_then(|t| t.to_offset(UtcOffset::UTC).replace_nanosecond(0).ok())
        .and_then(|t| t.format(&Rfc3339).ok())
        .ok_or_else(|| Error::invalid(format!("{time:?} is not an RFC 3339 time")))
}

fn start_marker(name: &str) -> String {
    format!("# {GROUP_START} {name}")
}

fn end_marker(name: &str) -> String {
    format!("# {GROUP_END}: {name}")
}

/// The field separator the file already uses: a tab when its first turned-on
/// entry has one after the address, otherwise a space.
fn separator(scan: &[Scanned<'_>], lines: &[Line]) -> &'static str {
    let first = scan.iter().zip(lines).find_map(|(s, line)| match &s.kind {
        LineKind::Entry {
            fields,
            enabled: true,
        } => line
            .text
            .trim_start_matches('\u{feff}')
            .trim_start()
            .strip_prefix(fields.address),
        _ => None,
    });
    match first {
        Some(rest) if !rest.starts_with('\t') => " ",
        _ => "\t",
    }
}

/// A fresh line for an entry.
fn render(edit: &HostsEntryEdit, sep: &str) -> String {
    let mut line = String::new();
    if !edit.enabled {
        line.push_str("# ");
    }
    line.push_str(&edit.address);
    line.push_str(sep);
    line.push_str(&edit.names.join(" "));
    let mut note: Vec<String> = edit.comment.iter().cloned().collect();
    if let Some(expires) = &edit.expires {
        note.push(format!("{UNTIL}{expires}"));
    }
    if !note.is_empty() {
        line.push_str(sep);
        line.push_str("# ");
        line.push_str(&note.join(" "));
    }
    line
}

/// The new text of an edited line. Turning an entry on or off keeps its text
/// and only adds or removes the leading `#`.
fn replacement(
    original: &str,
    current: &HostsFileEntry,
    edit: &HostsEntryEdit,
    sep: &str,
) -> Result<String> {
    let current_expires = current.expires.as_deref().map(canonical_time).transpose()?;
    let same = current.address == edit.address
        && current.names == edit.names
        && current.comment == edit.comment
        && current_expires == edit.expires;
    let body = original.trim_start_matches('\u{feff}');
    Ok(match (same, current.enabled, edit.enabled) {
        (false, ..) => render(edit, sep),
        (true, true, false) => format!("# {body}"),
        (true, false, true) => {
            let rest = body.trim_start().trim_start_matches('#');
            rest.strip_prefix(' ').unwrap_or(rest).to_owned()
        }
        (true, ..) => body.to_owned(),
    })
}
