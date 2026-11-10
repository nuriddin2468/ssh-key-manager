//! The leak scanner: where the vault's secrets turned up outside it.
//!
//! The vault knows the exact values of its secrets — environments'
//! variables marked secret and entries' passwords — so it looks for those
//! values themselves, not for things that look like secrets, and a match
//! means a leak. Values too short or too plain to mean anything when found
//! ([`needles::searchable`]: `true`, `3000`, `localhost`, a bare URL) are
//! not looked for. Each value is also looked for as it appears once
//! escaped in JSON, percent-encoded or in base64, and a multi-line value
//! (a private key) by its lines too.
//!
//! Where ([`sources`]):
//!
//! - AI coding tools' session history, in the places those tools document:
//!   Claude Code, Codex, Gemini CLI, Continue, Cline and Roo Code, and
//!   Aider's history files in the folders the user picked. What a session
//!   read, ran or was told went to the tool's provider.
//! - The shell history ([`crate::shell_history::default_history_files`]).
//! - Folders the user picked: in Git working trees, the files Git would
//!   commit (tracked or untracked and not ignored), plus `.env` files and
//!   the like that Git ignores; outside them, `.env` files only.
//!
//! Values stay in this crate. A finding names the secret ([`LeakSecret`]),
//! the file and the line, never the value or any of its forms; the types
//! that hold values ([`KnownSecret`], [`Matcher`]) are neither serialisable
//! nor shown by `Debug`. All values are searched at once with
//! Aho-Corasick, a file at a time in chunks, so a large file is never read
//! whole. Files are only read, except that [`redact`] replaces a secret in
//! an AI session file, in place, when the user asks.

pub mod needles;
mod search;
pub mod sources;

#[cfg(test)]
mod tests;

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use secrecy::SecretString;
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

pub use self::needles::Matcher;
pub use self::sources::{
    AiLocation, AiTool, AiToolInfo, GitFiles, GitLister, Listing, Plan, ai_locations,
    default_ai_locations, detect_ai_tools, list_files,
};
use crate::audit::Severity;
use crate::shell_history::Shell;
use crate::vault::EntryKind;

/// A secret of the vault, to look for. Holds the value, so it is neither
/// serialisable nor shown by `Debug`.
pub struct KnownSecret {
    pub secret: LeakSecret,
    pub value: SecretString,
}

impl std::fmt::Debug for KnownSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KnownSecret")
            .field("secret", &self.secret)
            .finish_non_exhaustive()
    }
}

/// Which secret leaked: its name, never its value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum LeakSecret {
    /// A variable marked secret, in an environment of a project.
    Variable {
        env_id: String,
        project: String,
        environment: String,
        name: String,
    },
    /// An entry's password: a login's, a host's, or a key's passphrase.
    Password {
        entry_id: String,
        title: String,
        entry_kind: EntryKind,
    },
}

impl LeakSecret {
    /// Names the secret in finding ids: `var:<environment id>:<name>` or
    /// `entry:<entry id>`.
    pub fn key(&self) -> String {
        match self {
            Self::Variable { env_id, name, .. } => format!("var:{env_id}:{name}"),
            Self::Password { entry_id, .. } => format!("entry:{entry_id}"),
        }
    }
}

/// An AI tool's session history, a shell's history, or a file in a folder
/// the user picked.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum LeakPlace {
    /// What an AI coding tool read, ran and was told, which went to its
    /// provider.
    AiSession {
        tool: AiTool,
    },
    ShellHistory {
        shell: Shell,
    },
    /// A file in a folder the user picked.
    File {
        git: GitState,
        /// The top folder of its Git working tree.
        repository: Option<String>,
    },
}

/// What Git makes of a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum GitState {
    /// Committed, or added to be.
    Tracked,
    /// Not committed yet, and not ignored: the next `git add .` takes it.
    Untracked,
    /// Ignored: stays on this computer.
    Ignored,
    /// In no Git working tree, or Git couldn't say.
    Outside,
}

/// How a value appeared, when it wasn't as it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum Encoding {
    Base64,
    /// Percent-encoded, as in a URL.
    Url,
}

/// A secret found in a file. Never its value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct LeakFinding {
    /// Stable while the secret is in that file: a hash of the secret's
    /// [`LeakSecret::key`] and the path.
    pub id: String,
    pub severity: Severity,
    pub secret: LeakSecret,
    pub place: LeakPlace,
    pub path: String,
    /// The first line it is on, from 1.
    pub line: u32,
    /// How many times it is in the file.
    pub occurrences: u32,
    /// Encoded forms it was found in, besides as it is.
    pub encodings: Vec<Encoding>,
    /// [`redact`] may replace it in the file: an AI session's.
    pub redactable: bool,
    /// When the file last changed, RFC 3339 in UTC.
    pub modified: Option<String>,
    /// The file the scan read, for [`redact`]; not for the page.
    #[serde(skip)]
    #[cfg_attr(feature = "ts", ts(skip))]
    pub file: Option<FileId>,
}

/// Which file a path named when it was read: its device and inode (Unix;
/// `None` elsewhere).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId {
    dev: u64,
    ino: u64,
}

impl FileId {
    pub fn of(meta: &fs::Metadata) -> Option<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Some(Self {
                dev: meta.dev(),
                ino: meta.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = meta;
            None
        }
    }
}

/// A file to search, and what it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanFile {
    pub path: PathBuf,
    pub place: LeakPlace,
    pub size: u64,
}

/// Shared with the scan while it runs: how far it got, and a way to stop
/// it.
#[derive(Debug, Default)]
pub struct ScanControl {
    pub cancel: AtomicBool,
    pub files_done: AtomicU32,
    pub bytes_done: AtomicU64,
}

impl ScanControl {
    pub fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
}

/// The user stopped the scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cancelled;

/// What [`scan_files`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanOutcome {
    /// Most severe first, then by secret and path.
    pub findings: Vec<LeakFinding>,
    /// Files that couldn't be read.
    pub unreadable: u32,
}

/// Searches `files` for every secret of `matcher`, one file at a time,
/// counting progress in `control` and stopping when it is cancelled.
pub fn scan_files(
    files: &[ScanFile],
    matcher: &Matcher,
    control: &ScanControl,
) -> Result<ScanOutcome, Cancelled> {
    let mut outcome = ScanOutcome::default();
    for file in files {
        if control.cancelled() {
            return Err(Cancelled);
        }
        match scan_file(file, matcher, control) {
            Ok(Some(found)) => outcome.findings.extend(found),
            Ok(None) => {}
            Err(search::Stop::Cancelled) => return Err(Cancelled),
            Err(search::Stop::Io(_)) => outcome.unreadable += 1,
        }
        control.files_done.fetch_add(1, Ordering::Relaxed);
    }
    sort(&mut outcome.findings);
    Ok(outcome)
}

/// Most severe first, then by secret, path.
pub fn sort(findings: &mut [LeakFinding]) {
    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.secret.cmp(&b.secret))
            .then_with(|| a.path.cmp(&b.path))
    });
}

/// The findings in one file; `None` for a binary file, which is skipped.
fn scan_file(
    file: &ScanFile,
    matcher: &Matcher,
    control: &ScanControl,
) -> Result<Option<Vec<LeakFinding>>, search::Stop> {
    let handle = fs::File::open(&file.path)?;
    let meta = handle.metadata()?;
    if !meta.is_file() {
        return Ok(Some(Vec::new()));
    }
    // Text only: a NUL in the first chunk of a picked file means binary.
    // Session histories are text, however large.
    let text_only = matches!(file.place, LeakPlace::File { .. });
    let mut found: HashMap<usize, Occurrences> = HashMap::new();
    let complete = search::search(
        handle,
        matcher,
        search::Options {
            text_only,
            control: Some(control),
            ..search::Options::default()
        },
        |hit| {
            for owner in matcher.owners(hit.pattern) {
                found.entry(owner.secret).or_default().add(&hit, owner);
            }
        },
    )?;
    if !complete {
        return Ok(None);
    }
    let path = file.path.display().to_string();
    let modified = meta
        .modified()
        .ok()
        .map(OffsetDateTime::from)
        .and_then(|t| t.format(&Rfc3339).ok());
    Ok(Some(
        found
            .into_iter()
            .filter_map(|(secret, occurrences)| {
                let occurrences = occurrences.finish();
                let line = occurrences.first_line?;
                let secret = matcher.secret(secret).clone();
                Some(LeakFinding {
                    id: finding_id(&secret, &path),
                    severity: severity(&file.place),
                    redactable: matches!(file.place, LeakPlace::AiSession { .. }),
                    place: file.place.clone(),
                    path: path.clone(),
                    line,
                    occurrences: occurrences.counted,
                    encodings: occurrences.encodings.into_iter().collect(),
                    modified: modified.clone(),
                    file: FileId::of(&meta),
                    secret,
                })
            })
            .collect(),
    ))
}

/// Bytes between two matches of a secret that still make them one
/// occurrence: a line break as it is or escaped (`\n`, `\r\n`, `\\n`).
const JOIN_GAP: u64 = 4;

/// Matches of one secret in one file, grouped: matches that overlap or
/// nearly touch (a key's lines, or the whole key and one of its lines) are
/// one occurrence. An occurrence counts when it holds a whole form of the
/// value, or two of its lines ([`needles::Form::line`]): a line alone may
/// be one that every key of its kind has.
#[derive(Default)]
struct Occurrences {
    current: Option<Occurrence>,
    counted: u32,
    first_line: Option<u32>,
    encodings: BTreeSet<Encoding>,
    /// The byte ranges of the counted occurrences' matches, when kept.
    ranges: Option<Vec<(u64, u64)>>,
}

struct Occurrence {
    line: u32,
    end: u64,
    whole: bool,
    lines: Vec<u32>,
    encodings: BTreeSet<Encoding>,
    ranges: Vec<(u64, u64)>,
}

impl Occurrences {
    fn keeping_ranges() -> Self {
        Self {
            ranges: Some(Vec::new()),
            ..Self::default()
        }
    }

    fn add(&mut self, hit: &search::Hit, owner: &needles::Owner) {
        let joins = self
            .current
            .as_ref()
            .is_some_and(|current| hit.start <= current.end + JOIN_GAP);
        if !joins {
            self.close();
        }
        let current = self.current.get_or_insert_with(|| Occurrence {
            line: hit.line,
            end: hit.end,
            whole: false,
            lines: Vec::new(),
            encodings: BTreeSet::new(),
            ranges: Vec::new(),
        });
        current.end = current.end.max(hit.end);
        current.line = current.line.min(hit.line);
        match owner.line {
            None => current.whole = true,
            Some(line) if !current.lines.contains(&line) => current.lines.push(line),
            Some(_) => {}
        }
        current.encodings.extend(owner.encoding);
        if self.ranges.is_some() {
            current.ranges.push((hit.start, hit.end));
        }
    }

    fn close(&mut self) {
        let Some(occurrence) = self.current.take() else {
            return;
        };
        if !occurrence.whole && occurrence.lines.len() < 2 {
            return;
        }
        self.counted = self.counted.saturating_add(1);
        self.first_line = Some(
            self.first_line
                .map_or(occurrence.line, |line| line.min(occurrence.line)),
        );
        self.encodings.extend(occurrence.encodings);
        if let Some(ranges) = &mut self.ranges {
            ranges.extend(occurrence.ranges);
        }
    }

    fn finish(mut self) -> Self {
        self.close();
        self
    }
}

/// How bad a leak is, by where it is: what went to an AI provider or into
/// a repository is out of the user's hands; the shell history and a stray
/// `.env` are copies on this computer; a `.env` Git ignores is a local
/// copy, as a project's own may be.
pub fn severity(place: &LeakPlace) -> Severity {
    match place {
        LeakPlace::AiSession { .. }
        | LeakPlace::File {
            git: GitState::Tracked | GitState::Untracked,
            ..
        } => Severity::Critical,
        LeakPlace::ShellHistory { .. }
        | LeakPlace::File {
            git: GitState::Outside,
            ..
        } => Severity::Warning,
        LeakPlace::File {
            git: GitState::Ignored,
            ..
        } => Severity::Info,
    }
}

/// A finding's id: `leak:` and 32 hex digits of SHA-256 of the secret's
/// key and the path.
pub fn finding_id(secret: &LeakSecret, path: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(secret.key().as_bytes());
    hash.update([0]);
    hash.update(path.as_bytes());
    let digest = hash.finalize();
    let mut id = String::with_capacity(37);
    id.push_str("leak:");
    for byte in &digest[..16] {
        let _ = write!(id, "{byte:02x}");
    }
    id
}

/// What [`redact`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Redacted {
    /// Places in the file the value was replaced at.
    pub replaced: u32,
    /// Places it was at that held something else by the time they were
    /// written: the file changed meanwhile. Left as they are.
    pub skipped: u32,
    /// Occurrences found after: in a form the replacement doesn't cover, or
    /// written meanwhile.
    pub left: u32,
}

/// Replaces every occurrence of `matcher`'s secrets in the file at `path`
/// with a marker of the same length (`[REDACTED___]`), in place: the file
/// keeps its size and lines, JSON stays valid, and what a running tool
/// appends meanwhile is kept. Then searches what the path holds again.
///
/// The file is the one the scan read: a symbolic link, or another file than
/// `scanned`, is refused with [`io::ErrorKind::InvalidData`]. Each place is
/// read back right before it is written and written only if it still holds
/// the value, so a tool that rewrote the file meanwhile, moving everything,
/// loses nothing.
pub fn redact(path: &Path, scanned: Option<FileId>, matcher: &Matcher) -> io::Result<Redacted> {
    let mut file = open_checked(path, scanned, true)?;
    let ranges = occurrence_ranges(&mut file, matcher)?;
    let (replaced, skipped) = write_markers(&mut file, &ranges, matcher)?;
    drop(file);
    let mut now = open_checked(path, None, false)?;
    let left = count_occurrences(&mut now, matcher)?;
    Ok(Redacted {
        replaced,
        skipped,
        left,
    })
}

/// Opens `path` (for writing too, with `write`), refusing a symbolic link,
/// anything but a regular file, and another file than `scanned`.
fn open_checked(path: &Path, scanned: Option<FileId>, write: bool) -> io::Result<fs::File> {
    let refused = |why: &str| io::Error::new(io::ErrorKind::InvalidData, why.to_owned());
    let file = fs::OpenOptions::new().read(true).write(write).open(path)?;
    let opened = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if named.file_type().is_symlink() || !opened.is_file() {
        return Err(refused("not a regular file"));
    }
    // The path still names the file opened, which is the one scanned.
    let id = FileId::of(&opened);
    if id != FileId::of(&named) || scanned.is_some_and(|scanned| Some(scanned) != id) {
        return Err(refused("the file was replaced since the scan"));
    }
    Ok(file)
}

/// The byte ranges of the occurrences of `matcher`'s secrets in `file`,
/// sorted, overlapping ones merged.
fn occurrence_ranges(file: &mut fs::File, matcher: &Matcher) -> io::Result<Vec<(u64, u64)>> {
    file.seek(SeekFrom::Start(0))?;
    let mut found: HashMap<usize, Occurrences> = HashMap::new();
    search::search(&mut *file, matcher, search::Options::default(), |hit| {
        for owner in matcher.owners(hit.pattern) {
            found
                .entry(owner.secret)
                .or_insert_with(Occurrences::keeping_ranges)
                .add(&hit, owner);
        }
    })
    .map_err(search::Stop::into_io)?;
    let mut ranges: Vec<(u64, u64)> = found
        .into_values()
        .flat_map(|occurrences| occurrences.finish().ranges.unwrap_or_default())
        .collect();
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    Ok(merged)
}

/// Writes a marker over each range that still holds forms of `matcher`'s
/// secrets from end to end; returns how many were written and how many
/// skipped.
fn write_markers(
    file: &mut fs::File,
    ranges: &[(u64, u64)],
    matcher: &Matcher,
) -> io::Result<(u32, u32)> {
    let (mut replaced, mut skipped) = (0_u32, 0_u32);
    for &(start, end) in ranges {
        let len = usize::try_from(end - start)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "match too long"))?;
        file.seek(SeekFrom::Start(start))?;
        let mut now = Zeroizing::new(vec![0_u8; len]);
        if file.read_exact(&mut now).is_err() || !covered(&now, matcher) {
            skipped = skipped.saturating_add(1);
            continue;
        }
        file.seek(SeekFrom::Start(start))?;
        file.write_all(&marker(len))?;
        replaced = replaced.saturating_add(1);
    }
    file.sync_all()?;
    Ok((replaced, skipped))
}

/// Whether `bytes` are made of `matcher`'s patterns from end to end.
fn covered(bytes: &[u8], matcher: &Matcher) -> bool {
    let Some(automaton) = matcher.automaton() else {
        return false;
    };
    let mut spans: Vec<(usize, usize)> = automaton
        .find_overlapping_iter(bytes)
        .map(|found| (found.start(), found.end()))
        .collect();
    spans.sort_unstable();
    let mut reach = 0;
    for (start, end) in spans {
        if start > reach {
            return false;
        }
        reach = reach.max(end);
    }
    !bytes.is_empty() && reach == bytes.len()
}

/// How many occurrences of `matcher`'s secrets `file` holds.
fn count_occurrences(file: &mut fs::File, matcher: &Matcher) -> io::Result<u32> {
    file.seek(SeekFrom::Start(0))?;
    let mut found: HashMap<usize, Occurrences> = HashMap::new();
    search::search(&mut *file, matcher, search::Options::default(), |hit| {
        for owner in matcher.owners(hit.pattern) {
            found.entry(owner.secret).or_default().add(&hit, owner);
        }
    })
    .map_err(search::Stop::into_io)?;
    Ok(found
        .into_values()
        .map(|occurrences| occurrences.finish().counted)
        .sum())
}

/// A marker `len` bytes long: `[REDACTED]`, padded with `_` inside the
/// brackets, or cut to `REDACTED` and less for short values.
pub fn marker(len: usize) -> Vec<u8> {
    const WORD: &[u8] = b"REDACTED";
    if len < WORD.len() + 2 {
        return WORD
            .iter()
            .copied()
            .chain(std::iter::repeat(b'_'))
            .take(len)
            .collect();
    }
    let mut out = Vec::with_capacity(len);
    out.push(b'[');
    out.extend_from_slice(WORD);
    out.resize(len - 1, b'_');
    out.push(b']');
    out
}
