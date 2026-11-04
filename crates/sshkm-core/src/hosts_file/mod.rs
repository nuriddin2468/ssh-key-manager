//! A lossless, editable model of the system hosts file.
//!
//! The hosts file (`/etc/hosts`, `%SystemRoot%\System32\drivers\etc\hosts` on
//! Windows) maps names to addresses before DNS is asked, so it decides where
//! `ssh`, `git` and everything else connect. Every line is kept and the model
//! round-trips byte for byte; edits ([`HostsFile::edited`]) change only the
//! lines they touch.
//!
//! A line is `address name… # comment`, and `#` starts a comment anywhere. A
//! comment that holds a complete entry (`# 10.0.0.5 api.local`) is reported
//! as a turned-off entry, the usual way to switch one off by hand. Names are
//! case-insensitive, and when several lines list a name for the same address
//! family, resolvers use the first one.
//!
//! Two conventions of this app live in comments, so the file stays plain:
//!
//! - Groups are blocks between `# >>> sshkm: <name>` and `# <<< sshkm: <name>`.
//! - `sshkm-until=<RFC 3339 time>` in an entry's comment marks it temporary.
//!
//! Writing the file needs administrator rights; see [`install`].

mod edit;
mod install;
#[cfg(test)]
mod tests;

use std::{
    collections::HashSet,
    fmt::{self, Write as _},
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub use self::edit::{HostsChange, HostsDiffKind, HostsDiffLine, HostsEdited, HostsEntryEdit};
pub use self::install::{InstallOutcome, can_install, install};
use crate::{
    Error, Result, fsutil,
    text::{self, Line},
};

/// Largest hosts file that is loaded. Block lists reach a few megabytes.
const MAX_HOSTS_FILE_SIZE: u64 = 64 * 1024 * 1024;
/// Longest scope on an IPv6 address: an interface name or index.
const MAX_SCOPE: usize = 64;

/// Names the operating system itself relies on.
const SYSTEM_NAMES: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "localhost4",
    "localhost4.localdomain4",
    "localhost6",
    "localhost6.localdomain6",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
];

/// Comment text that opens a group, before its name.
const GROUP_START: &str = ">>> sshkm:";
/// Comment text that closes a group (followed by the name, for people).
const GROUP_END: &str = "<<< sshkm";
/// Comment token that holds a temporary entry's expiry time.
const UNTIL: &str = "sshkm-until=";

/// Where the operating system reads the hosts file from.
pub fn system_path() -> PathBuf {
    if cfg!(windows) {
        crate::paths::system32("drivers").join("etc").join("hosts")
    } else {
        PathBuf::from("/etc/hosts")
    }
}

/// What an address points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum HostsAddressKind {
    /// `127.0.0.0/8` or `::1`: this computer.
    Loopback,
    /// `0.0.0.0` or `::`: nowhere, which blocks the name.
    Blocked,
    /// Private, shared (`100.64.0.0/10`), link-local, broadcast and multicast
    /// ranges: the local network or a VPN.
    Private,
    /// Anything else.
    Public,
}

/// One entry, turned on or off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct HostsFileEntry {
    /// 1-based line number.
    pub line: u32,
    /// The address as written (`fe80::1%lo0` keeps its scope).
    pub address: String,
    /// What the address points at.
    pub kind: HostsAddressKind,
    /// Names in file order.
    pub names: Vec<String>,
    /// Trailing comment without the `#` and the expiry token.
    pub comment: Option<String>,
    /// False when the entry is commented out.
    pub enabled: bool,
    /// Every name is one the operating system relies on (`localhost`, …).
    pub system: bool,
    /// Names an earlier turned-on line already lists for the same address
    /// family, so resolvers use that line for them. Empty when turned off.
    pub shadowed: Vec<String>,
    /// The group the entry is in.
    pub group: Option<String>,
    /// When a temporary entry expires (RFC 3339).
    pub expires: Option<String>,
}

impl HostsFileEntry {
    /// The address is IPv6.
    pub fn is_ipv6(&self) -> bool {
        self.address.contains(':')
    }

    /// The entry is temporary and its time has passed.
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        self.expires
            .as_deref()
            .and_then(|expires| OffsetDateTime::parse(expires, &Rfc3339).ok())
            .is_some_and(|expires| expires <= now)
    }
}

/// Why a line is not an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum HostsLineProblem {
    /// The first field is not an IP address.
    BadAddress,
    /// An address without names.
    NoNames,
    /// A name with characters host names cannot have.
    BadName,
}

/// A line that could not be parsed (kept unchanged).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct HostsFileIssue {
    /// 1-based line number.
    pub line: u32,
    /// What is wrong.
    pub problem: HostsLineProblem,
}

/// A block of entries between this app's group markers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct HostsGroup {
    /// The name in the opening marker.
    pub name: String,
    /// 1-based line of the opening marker.
    pub line: u32,
    /// 1-based line of the closing marker, if there is one.
    pub end_line: Option<u32>,
}

/// Everything the UI shows about a hosts file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct HostsFileView {
    /// Entries in file order, turned off ones included.
    pub entries: Vec<HostsFileEntry>,
    /// Lines that could not be parsed.
    pub invalid: Vec<HostsFileIssue>,
    /// Groups in file order.
    pub groups: Vec<HostsGroup>,
}

/// Why the app cannot change a hosts file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum HostsReadOnly {
    /// The file is not UTF-8; writing it back would mangle text in a legacy
    /// code page.
    NotUtf8,
    /// The file is a symbolic link, so another tool (`NixOS`, a container
    /// runtime) manages it.
    Link,
    /// There is no way to ask for administrator rights (`pkexec` is missing).
    NoElevation,
}

/// The parsed file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostsFile {
    lines: Vec<Line>,
    revision: String,
    utf8: bool,
}

enum LineKind<'a> {
    Blank,
    Entry {
        fields: Fields<'a>,
        enabled: bool,
    },
    /// Not an entry; `resolved` is what resolvers still read from it.
    Invalid {
        problem: HostsLineProblem,
        resolved: Option<Fields<'a>>,
    },
    GroupStart(&'a str),
    GroupEnd,
}

struct Fields<'a> {
    address: &'a str,
    ip: IpAddr,
    names: Vec<&'a str>,
    comment: Option<&'a str>,
}

/// A line with the group it is in (`None` for the markers themselves).
struct Scanned<'a> {
    kind: LineKind<'a>,
    group: Option<&'a str>,
}

impl HostsFile {
    /// Parses hosts file text. Never fails.
    pub fn parse(input: &str) -> Self {
        Self {
            lines: text::split_lines(input),
            revision: revision_of(input.as_bytes()),
            utf8: true,
        }
    }

    /// Loads a file; a missing file is empty. Text that is not UTF-8 (a legacy
    /// code page on Windows) is decoded lossily for display, and such a file
    /// is never written back (see [`Self::read_only_reason`]).
    pub fn load(path: &Path) -> Result<Self> {
        match fsutil::read_limited(path, MAX_HOSTS_FILE_SIZE) {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                Ok(Self {
                    lines: text::split_lines(&text),
                    revision: revision_of(&bytes),
                    utf8: matches!(text, std::borrow::Cow::Borrowed(_)),
                })
            }
            Err(Error::NotFound(_)) => Ok(Self::parse("")),
            Err(e) => Err(e),
        }
    }

    /// SHA-256 of the file's bytes, in hex. Edits name the revision they were
    /// made against, so changes made elsewhere in the meantime are not lost.
    pub fn revision(&self) -> &str {
        &self.revision
    }

    /// Why this app cannot write the file at `path`, if it cannot.
    pub fn read_only_reason(&self, path: &Path) -> Option<HostsReadOnly> {
        if !self.utf8 {
            Some(HostsReadOnly::NotUtf8)
        } else if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
            Some(HostsReadOnly::Link)
        } else if !can_install() {
            Some(HostsReadOnly::NoElevation)
        } else {
            None
        }
    }

    /// All entries, turned off ones included.
    pub fn entries(&self) -> Vec<HostsFileEntry> {
        self.collect_entries(false)
    }

    /// Turned-on lines as resolvers read them, in file order: the turned-on
    /// entries, plus lines [`Self::invalid_lines`] reports that still give
    /// names an address (a name with characters host names cannot have, an
    /// unusual scope). The audit and lookups use these, since resolvers do.
    pub fn resolver_entries(&self) -> Vec<HostsFileEntry> {
        self.collect_entries(true)
    }

    fn collect_entries(&self, resolver: bool) -> Vec<HostsFileEntry> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for (i, line) in self.scan().into_iter().enumerate() {
            let (fields, enabled, listed) = match line.kind {
                LineKind::Entry { fields, enabled } => (fields, enabled, enabled || !resolver),
                // Resolvers use the line, so it shadows later ones either way.
                LineKind::Invalid {
                    resolved: Some(fields),
                    ..
                } => (fields, true, resolver),
                _ => continue,
            };
            let ipv6 = fields.ip.is_ipv6();
            let shadowed = if enabled {
                fields
                    .names
                    .iter()
                    .filter(|name| !seen.insert((ipv6, normalize_name(name))))
                    .map(|name| (*name).to_owned())
                    .collect()
            } else {
                Vec::new()
            };
            if listed {
                out.push(entry(i, &fields, enabled, shadowed, line.group));
            }
        }
        out
    }

    /// Lines that could not be parsed.
    pub fn invalid_lines(&self) -> Vec<HostsFileIssue> {
        self.scan()
            .into_iter()
            .enumerate()
            .filter_map(|(i, line)| match line.kind {
                LineKind::Invalid { problem, .. } => Some(HostsFileIssue {
                    line: line_number(i),
                    problem,
                }),
                _ => None,
            })
            .collect()
    }

    /// Groups in file order. A group without a closing marker runs to the
    /// next group or the end of the file.
    pub fn groups(&self) -> Vec<HostsGroup> {
        let mut groups: Vec<HostsGroup> = Vec::new();
        let mut open = false;
        for (i, line) in self.scan().into_iter().enumerate() {
            match line.kind {
                LineKind::GroupStart(name) => {
                    groups.push(HostsGroup {
                        name: name.to_owned(),
                        line: line_number(i),
                        end_line: None,
                    });
                    open = true;
                }
                LineKind::GroupEnd if open => {
                    if let Some(group) = groups.last_mut() {
                        group.end_line = Some(line_number(i));
                    }
                    open = false;
                }
                _ => {}
            }
        }
        groups
    }

    /// Entries, invalid lines and groups together.
    pub fn view(&self) -> HostsFileView {
        HostsFileView {
            entries: self.entries(),
            invalid: self.invalid_lines(),
            groups: self.groups(),
        }
    }

    /// Turned-on lines that list `name`, in file order, as resolvers read
    /// them ([`Self::resolver_entries`]). For each address family the first
    /// one is what resolvers use.
    pub fn lookup(&self, name: &str) -> Vec<HostsFileEntry> {
        let name = normalize_name(name);
        self.resolver_entries()
            .into_iter()
            .filter(|e| e.names.iter().any(|n| normalize_name(n) == name))
            .collect()
    }

    fn scan(&self) -> Vec<Scanned<'_>> {
        let mut group = None;
        self.lines
            .iter()
            .map(|line| {
                let kind = parse_line(&line.text);
                let in_group = match kind {
                    LineKind::GroupStart(name) => {
                        group = Some(name);
                        None
                    }
                    LineKind::GroupEnd => {
                        group = None;
                        None
                    }
                    _ => group,
                };
                Scanned {
                    kind,
                    group: in_group,
                }
            })
            .collect()
    }
}

impl fmt::Display for HostsFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        text::write_lines(&self.lines, f)
    }
}

/// Whether `name` can be a host name: ASCII letters, digits, `-` and `_` in
/// dot-separated labels of up to 63 characters, 253 in total, with an
/// optional final dot.
pub fn is_valid_name(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// The form resolvers compare names in: lower case, without a final dot.
pub fn normalize_name(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

fn revision_of(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

fn line_number(index: usize) -> u32 {
    u32::try_from(index + 1).unwrap_or(u32::MAX)
}

/// Whether the operating system relies on `name` (`localhost`, …), so the
/// app never sets it.
pub fn is_system_name(name: &str) -> bool {
    SYSTEM_NAMES.contains(&normalize_name(name).as_str())
}

fn entry(
    index: usize,
    fields: &Fields<'_>,
    enabled: bool,
    shadowed: Vec<String>,
    group: Option<&str>,
) -> HostsFileEntry {
    let (comment, expires) = split_expiry(fields.comment);
    HostsFileEntry {
        line: line_number(index),
        address: fields.address.to_owned(),
        kind: address_kind(fields.ip),
        names: fields.names.iter().map(|n| (*n).to_owned()).collect(),
        comment,
        enabled,
        system: fields.names.iter().all(|n| is_system_name(n)),
        shadowed,
        group: group.map(str::to_owned),
        expires,
    }
}

/// Separates the expiry token from the rest of a comment.
fn split_expiry(comment: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(comment) = comment else {
        return (None, None);
    };
    let token = comment.split_whitespace().find(|word| {
        word.strip_prefix(UNTIL)
            .is_some_and(|time| OffsetDateTime::parse(time, &Rfc3339).is_ok())
    });
    match token {
        Some(token) => {
            let rest: Vec<&str> = comment
                .split_whitespace()
                .filter(|word| *word != token)
                .collect();
            let rest = rest.join(" ");
            (
                (!rest.is_empty()).then_some(rest),
                token.strip_prefix(UNTIL).map(str::to_owned),
            )
        }
        None => (Some(comment.to_owned()), None),
    }
}

fn parse_line(raw: &str) -> LineKind<'_> {
    let (data, comment) = split_comment(raw.trim_start_matches('\u{feff}'));
    if !data.trim().is_empty() {
        return match parse_fields(data, comment) {
            Ok(fields) => LineKind::Entry {
                fields,
                enabled: true,
            },
            Err(problem) => LineKind::Invalid {
                problem,
                resolved: resolver_fields(data),
            },
        };
    }
    let Some(comment) = comment else {
        return LineKind::Blank;
    };
    let body = comment.trim_start_matches('#').trim();
    if let Some(name) = body.strip_prefix(GROUP_START).map(str::trim)
        && !name.is_empty()
    {
        return LineKind::GroupStart(name);
    }
    if body.starts_with(GROUP_END) {
        return LineKind::GroupEnd;
    }
    // A comment that is a complete entry is a turned-off entry.
    let (data, comment) = split_comment(comment.trim_start_matches('#'));
    match parse_fields(data, comment) {
        Ok(fields) => LineKind::Entry {
            fields,
            enabled: false,
        },
        Err(_) => LineKind::Blank,
    }
}

fn split_comment(s: &str) -> (&str, Option<&str>) {
    match s.split_once('#') {
        Some((data, comment)) => (data, Some(comment)),
        None => (s, None),
    }
}

fn parse_fields<'a>(
    data: &'a str,
    comment: Option<&'a str>,
) -> std::result::Result<Fields<'a>, HostsLineProblem> {
    let mut words = data.split_whitespace();
    let address = words.next().ok_or(HostsLineProblem::NoNames)?;
    let ip = parse_address(address).ok_or(HostsLineProblem::BadAddress)?;
    let names: Vec<&str> = words.collect();
    if names.is_empty() {
        return Err(HostsLineProblem::NoNames);
    }
    if !names.iter().all(|name| is_valid_name(name)) {
        return Err(HostsLineProblem::BadName);
    }
    Ok(Fields {
        address,
        ip,
        names,
        comment: comment.map(str::trim).filter(|c| !c.is_empty()),
    })
}

/// What resolvers read from a line [`parse_fields`] rejects: an address with
/// any scope but an empty one, and every word after it as a name. The comment
/// is left out, as this app does not edit such a line.
fn resolver_fields(data: &str) -> Option<Fields<'_>> {
    let mut words = data.split_whitespace();
    let address = words.next()?;
    let ip = match address.split_once('%') {
        Some((_, "")) => return None,
        Some((ip, _)) => ip,
        None => address,
    }
    .parse()
    .ok()?;
    let names: Vec<&str> = words.collect();
    (!names.is_empty()).then_some(Fields {
        address,
        ip,
        names,
        comment: None,
    })
}

/// An IP address, allowing a scope on IPv6 ones (`fe80::1%lo0`) of up to
/// [`MAX_SCOPE`] letters, digits, `_`, `.` and `-`. Whitespace and control
/// characters are never part of an address, so one cannot add a line.
fn parse_address(field: &str) -> Option<IpAddr> {
    match field.split_once('%') {
        Some((address, scope)) => address
            .parse()
            .ok()
            .filter(|ip: &IpAddr| ip.is_ipv6() && is_scope(scope)),
        None => field.parse().ok(),
    }
}

fn is_scope(scope: &str) -> bool {
    (1..=MAX_SCOPE).contains(&scope.len())
        && scope
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

fn address_kind(ip: IpAddr) -> HostsAddressKind {
    if ip.is_unspecified() {
        return HostsAddressKind::Blocked;
    }
    if ip.is_loopback() {
        return HostsAddressKind::Loopback;
    }
    let local = match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || (a == 100 && (64..128).contains(&b))
        }
        // fc00::/7 unique local, fe00::/8 link- and site-local, multicast.
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            first & 0xfe00 == 0xfc00 || first & 0xff00 == 0xfe00 || v6.is_multicast()
        }
    };
    if local {
        HostsAddressKind::Private
    } else {
        HostsAddressKind::Public
    }
}
