//! A lossless model of the system hosts file.
//!
//! The hosts file (`/etc/hosts`, `%SystemRoot%\System32\drivers\etc\hosts` on
//! Windows) maps names to addresses before DNS is asked, so it decides where
//! `ssh`, `git` and everything else connect. Every line is kept and the model
//! round-trips byte for byte.
//!
//! A line is `address name… # comment`, and `#` starts a comment anywhere. A
//! comment that holds a complete entry (`# 10.0.0.5 api.local`) is reported
//! as a turned-off entry, the usual way to switch one off by hand. Names are
//! case-insensitive, and when several lines list a name for the same address
//! family, resolvers use the first one.

use std::{
    collections::HashSet,
    fmt,
    net::IpAddr,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    Error, Result, fsutil,
    text::{self, Line},
};

/// Largest hosts file that is loaded. Block lists reach a few megabytes.
const MAX_HOSTS_FILE_SIZE: u64 = 64 * 1024 * 1024;

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

/// Where the operating system reads the hosts file from.
pub fn system_path() -> PathBuf {
    if cfg!(windows) {
        let root = std::env::var_os("SystemRoot")
            .filter(|root| !root.is_empty())
            .map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
        root.join("System32")
            .join("drivers")
            .join("etc")
            .join("hosts")
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
    /// Trailing comment without the `#`.
    pub comment: Option<String>,
    /// False when the entry is commented out.
    pub enabled: bool,
    /// Every name is one the operating system relies on (`localhost`, …).
    pub system: bool,
    /// Names an earlier turned-on line already lists for the same address
    /// family, so resolvers use that line for them. Empty when turned off.
    pub shadowed: Vec<String>,
}

impl HostsFileEntry {
    /// The address is IPv6.
    pub fn is_ipv6(&self) -> bool {
        self.address.contains(':')
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

/// Everything the UI shows about a hosts file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct HostsFileView {
    /// Entries in file order, turned off ones included.
    pub entries: Vec<HostsFileEntry>,
    /// Lines that could not be parsed.
    pub invalid: Vec<HostsFileIssue>,
}

/// The parsed file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostsFile {
    lines: Vec<Line>,
}

enum Parsed<'a> {
    Blank,
    Entry { fields: Fields<'a>, enabled: bool },
    Invalid(HostsLineProblem),
}

struct Fields<'a> {
    address: &'a str,
    ip: IpAddr,
    names: Vec<&'a str>,
    comment: Option<&'a str>,
}

impl HostsFile {
    /// Parses hosts file text. Never fails.
    pub fn parse(input: &str) -> Self {
        Self {
            lines: text::split_lines(input),
        }
    }

    /// Loads a file; a missing file is empty. The app never writes this file,
    /// so text that is not UTF-8 (a legacy code page on Windows) is decoded
    /// lossily for display.
    pub fn load(path: &Path) -> Result<Self> {
        match fsutil::read_limited(path, MAX_HOSTS_FILE_SIZE) {
            Ok(bytes) => Ok(Self::parse(&String::from_utf8_lossy(&bytes))),
            Err(Error::NotFound(_)) => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    /// All entries, turned off ones included.
    pub fn entries(&self) -> Vec<HostsFileEntry> {
        let mut seen = HashSet::new();
        self.parsed()
            .filter_map(|(i, parsed)| match parsed {
                Parsed::Entry { fields, enabled } => {
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
                    Some(entry(i, &fields, enabled, shadowed))
                }
                _ => None,
            })
            .collect()
    }

    /// Lines that could not be parsed.
    pub fn invalid_lines(&self) -> Vec<HostsFileIssue> {
        self.parsed()
            .filter_map(|(i, parsed)| match parsed {
                Parsed::Invalid(problem) => Some(HostsFileIssue {
                    line: line_number(i),
                    problem,
                }),
                _ => None,
            })
            .collect()
    }

    /// Entries and invalid lines together.
    pub fn view(&self) -> HostsFileView {
        HostsFileView {
            entries: self.entries(),
            invalid: self.invalid_lines(),
        }
    }

    /// Turned-on entries that list `name`, in file order. For each address
    /// family the first one is what resolvers use.
    pub fn lookup(&self, name: &str) -> Vec<HostsFileEntry> {
        let name = normalize_name(name);
        self.entries()
            .into_iter()
            .filter(|e| e.enabled && e.names.iter().any(|n| normalize_name(n) == name))
            .collect()
    }

    fn parsed(&self) -> impl Iterator<Item = (usize, Parsed<'_>)> + '_ {
        self.lines
            .iter()
            .enumerate()
            .map(|(i, line)| (i, parse_line(&line.text)))
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

fn line_number(index: usize) -> u32 {
    u32::try_from(index + 1).unwrap_or(u32::MAX)
}

fn entry(
    index: usize,
    fields: &Fields<'_>,
    enabled: bool,
    shadowed: Vec<String>,
) -> HostsFileEntry {
    HostsFileEntry {
        line: line_number(index),
        address: fields.address.to_owned(),
        kind: address_kind(fields.ip),
        names: fields.names.iter().map(|n| (*n).to_owned()).collect(),
        comment: fields.comment.map(str::to_owned),
        enabled,
        system: fields
            .names
            .iter()
            .all(|n| SYSTEM_NAMES.contains(&normalize_name(n).as_str())),
        shadowed,
    }
}

fn parse_line(raw: &str) -> Parsed<'_> {
    let (data, comment) = split_comment(raw.trim_start_matches('\u{feff}'));
    if !data.trim().is_empty() {
        return match parse_fields(data, comment) {
            Ok(fields) => Parsed::Entry {
                fields,
                enabled: true,
            },
            Err(problem) => Parsed::Invalid(problem),
        };
    }
    // A comment that is a complete entry is a turned-off entry.
    let disabled = comment.and_then(|body| {
        let (data, comment) = split_comment(body.trim_start_matches('#'));
        parse_fields(data, comment).ok()
    });
    match disabled {
        Some(fields) => Parsed::Entry {
            fields,
            enabled: false,
        },
        None => Parsed::Blank,
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

/// An IP address, allowing a scope on IPv6 ones (`fe80::1%lo0`).
fn parse_address(field: &str) -> Option<IpAddr> {
    match field.split_once('%') {
        Some((address, scope)) if !scope.is_empty() => address.parse().ok().filter(IpAddr::is_ipv6),
        Some(_) => None,
        None => field.parse().ok(),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\u{feff}##\n\
         # Host Database\n\
         #\n\
         127.0.0.1\tlocalhost\n\
         255.255.255.255\tbroadcasthost\n\
         ::1             localhost\n\
         fe80::1%lo0\tlocalhost\n\
         \n\
         10.0.4.12   api.internal  API.internal.  # staging API\n\
         # 10.0.4.13 old-api.internal\n\
         ## 192.168.1.5 nas.local nas # the NAS\n\
         # localhost is used to configure the loopback interface\n\
         10.0.9.9 api.internal\n\
         0.0.0.0 ads.example.com\n\
         100.101.102.103 tailnet-box\n\
         140.82.112.3 github.com\n\
         300.1.1.1 broken.example\n\
         10.0.0.1\n\
         10.0.0.2 bad/name\n\
         fe80::1% nowhere\n\
         \t  # indented comment\n\
         ::ffff:10.0.0.1 mapped";

    fn sample() -> HostsFile {
        HostsFile::parse(SAMPLE)
    }

    fn lines(entries: &[HostsFileEntry]) -> Vec<u32> {
        entries.iter().map(|e| e.line).collect()
    }

    #[test]
    fn round_trips() {
        for input in [
            SAMPLE.to_owned(),
            SAMPLE.replace('\n', "\r\n"),
            format!("{SAMPLE}\n"),
            String::new(),
        ] {
            assert_eq!(HostsFile::parse(&input).to_string(), input);
        }
    }

    #[test]
    fn parses_entries() {
        let entries = sample().entries();
        assert_eq!(lines(&entries), [4, 5, 6, 7, 9, 10, 11, 13, 14, 15, 16, 22]);
        let by_line = |line| entries.iter().find(|e| e.line == line).unwrap();

        let localhost = by_line(4);
        assert_eq!(localhost.names, ["localhost"]);
        assert!(localhost.enabled && localhost.system);
        assert_eq!(localhost.kind, HostsAddressKind::Loopback);
        assert_eq!(by_line(5).kind, HostsAddressKind::Private);
        assert!(by_line(5).system);
        assert_eq!(by_line(7).address, "fe80::1%lo0");
        assert!(by_line(7).is_ipv6() && !by_line(4).is_ipv6());

        let api = by_line(9);
        assert_eq!(api.names, ["api.internal", "API.internal."]);
        assert_eq!(api.comment.as_deref(), Some("staging API"));
        assert_eq!(api.kind, HostsAddressKind::Private);
        assert!(!api.system);

        let off = by_line(10);
        assert!(!off.enabled);
        assert_eq!(off.names, ["old-api.internal"]);
        let nas = by_line(11);
        assert!(!nas.enabled);
        assert_eq!(nas.names, ["nas.local", "nas"]);
        assert_eq!(nas.comment.as_deref(), Some("the NAS"));

        assert_eq!(by_line(14).kind, HostsAddressKind::Blocked);
        assert_eq!(by_line(15).kind, HostsAddressKind::Private, "CGNAT range");
        assert_eq!(by_line(16).kind, HostsAddressKind::Public);
        assert_eq!(by_line(22).kind, HostsAddressKind::Public);
    }

    #[test]
    fn reports_invalid_lines() {
        let invalid: Vec<_> = sample()
            .invalid_lines()
            .into_iter()
            .map(|i| (i.line, i.problem))
            .collect();
        assert_eq!(
            invalid,
            [
                (17, HostsLineProblem::BadAddress),
                (18, HostsLineProblem::NoNames),
                (19, HostsLineProblem::BadName),
                (20, HostsLineProblem::BadAddress),
            ]
        );
    }

    #[test]
    fn earlier_lines_shadow_later_ones_per_family() {
        let entries = sample().entries();
        let shadowed = |line| {
            entries
                .iter()
                .find(|e| e.line == line)
                .unwrap()
                .shadowed
                .clone()
        };
        // Line 9 lists the name twice (case and final dot differ).
        assert_eq!(shadowed(9), ["API.internal."]);
        assert_eq!(shadowed(13), ["api.internal"]);
        // IPv6 localhost lines: the first one counts, the scoped one does not.
        assert_eq!(shadowed(6), Vec::<String>::new());
        assert_eq!(shadowed(7), ["localhost"]);
        // Turned-off entries never shadow or get shadowed.
        assert_eq!(shadowed(10), Vec::<String>::new());
    }

    #[test]
    fn lookup() {
        let hosts = sample();
        assert_eq!(lines(&hosts.lookup("API.Internal")), [9, 13]);
        assert_eq!(lines(&hosts.lookup("api.internal.")), [9, 13]);
        assert_eq!(lines(&hosts.lookup("localhost")), [4, 6, 7]);
        assert_eq!(lines(&hosts.lookup("old-api.internal")), Vec::<u32>::new());
        assert_eq!(lines(&hosts.lookup("nowhere")), Vec::<u32>::new());
    }

    #[test]
    fn names() {
        let longest_label = "a".repeat(63);
        let long_label = "a".repeat(64);
        let long_name = ["a"; 128].join(".");
        for good in ["a", "a.b", "a-b_c.example.", "x1", longest_label.as_str()] {
            assert!(is_valid_name(good), "{good}");
        }
        for bad in [
            "",
            ".",
            "a..b",
            ".a",
            "a b",
            "a/b",
            "ünï.example",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            assert!(!is_valid_name(bad), "{bad}");
        }
        assert_eq!(normalize_name("Git.Example.COM."), "git.example.com");
    }

    #[test]
    fn parsing_is_total() {
        for line in [
            "#",
            "# #",
            "%",
            "::",
            ":: #",
            "1.2.3.4 #x",
            "# 1.2.3.4",
            "\u{feff}",
        ] {
            let _ = parse_line(line);
        }
        assert!(matches!(parse_line(":: x"), Parsed::Entry { .. }));
    }

    #[test]
    fn load_missing_and_lossy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        assert_eq!(HostsFile::load(&path).unwrap().entries(), []);
        // "10.0.0.1 box # сервер" in Windows-1251.
        let mut bytes = b"10.0.0.1 box # ".to_vec();
        bytes.extend_from_slice(&[0xf1, 0xe5, 0xf0, 0xe2, 0xe5, 0xf0]);
        std::fs::write(&path, bytes).unwrap();
        let entries = HostsFile::load(&path).unwrap().entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].names, ["box"]);
    }

    #[test]
    fn system_path_is_absolute() {
        assert!(system_path().is_absolute());
        assert!(system_path().ends_with("hosts"));
    }

    #[test]
    fn view_serializes() {
        let v = serde_json::to_value(sample().view()).unwrap();
        assert_eq!(v["entries"][0]["kind"], "loopback");
        assert_eq!(v["entries"][0]["enabled"], true);
        assert_eq!(v["entries"][8]["kind"], "blocked");
        assert_eq!(v["invalid"][0]["problem"], "badAddress");
    }
}
