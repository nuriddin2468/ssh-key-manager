//! A lossless model of `known_hosts`.
//!
//! Every line is kept; unparsable lines are reported and written back
//! unchanged. Host matching follows OpenSSH (`hostfile.c`, `match.c`): the
//! lookup name is `host`, or `[host]:port` when the port is not 22; plain
//! entries are comma-separated patterns with `*`, `?` and `!` negation; hashed
//! entries (`|1|salt|hash`, `HashKnownHosts yes`) are HMAC-SHA1 of the lookup
//! name keyed with the salt.

use std::{
    collections::HashSet,
    fmt,
    path::{Path, PathBuf},
};

use base64ct::{Base64, Base64Unpadded, Encoding};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::{
    Error, Result, fsutil,
    text::{self, Eol, Line},
};

/// Largest `known_hosts` file that is loaded.
const MAX_KNOWN_HOSTS_SIZE: u64 = 32 * 1024 * 1024;

/// Line marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum HostMarker {
    /// A plain host key.
    None,
    /// `@cert-authority`: a CA key trusted for host certificates.
    CertAuthority,
    /// `@revoked`: the key must never be accepted.
    Revoked,
}

/// One parsed host key line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct KnownHostEntry {
    /// 1-based line number (the handle for [`KnownHosts::remove_lines`]).
    pub line: u32,
    /// Marker.
    pub marker: HostMarker,
    /// Host patterns; empty when the entry is hashed.
    pub hosts: Vec<String>,
    /// The host name is hashed.
    pub hashed: bool,
    /// Key type, e.g. `ssh-ed25519`.
    pub key_type: String,
    /// `SHA256:…` fingerprint of the key.
    pub fingerprint: String,
    /// Trailing comment.
    pub comment: Option<String>,
}

/// Why a line could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum InvalidReason {
    /// Fewer than three fields.
    MissingFields,
    /// A marker other than `@cert-authority` / `@revoked`.
    UnknownMarker,
    /// The key is not valid Base64 or does not match its type.
    BadKey,
    /// A `|…` host field that is not a valid `|1|salt|hash`.
    BadHashedHost,
}

/// A line that could not be parsed (kept unchanged).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct InvalidLine {
    /// 1-based line number.
    pub line: u32,
    /// What is wrong.
    pub reason: InvalidReason,
}

/// Everything the UI shows about a `known_hosts` file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct KnownHostsView {
    /// Parsed entries in file order.
    pub entries: Vec<KnownHostEntry>,
    /// Lines that could not be parsed.
    pub invalid: Vec<InvalidLine>,
    /// SHA-256 of the file's bytes, in hex. Removals name the revision their
    /// line numbers belong to, so a line that moved in the meantime (an
    /// `@revoked` one, say) is never removed instead.
    pub revision: String,
}

/// The parsed file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KnownHosts {
    lines: Vec<Line>,
}

enum Parsed {
    Blank,
    Entry(Parts),
    Invalid(InvalidReason),
}

struct Parts {
    marker: HostMarker,
    hosts: HostField,
    key_type: String,
    blob: Vec<u8>,
    comment: Option<String>,
}

enum HostField {
    Plain(String),
    Hashed { salt: Vec<u8>, hash: Vec<u8> },
}

impl KnownHosts {
    /// Parses `known_hosts` text. Never fails.
    pub fn parse(input: &str) -> Self {
        Self {
            lines: text::split_lines(input),
        }
    }

    /// Loads a file; a missing file is empty. Non-UTF-8 files are rejected
    /// ([`Error::Parse`]) so they are never rewritten lossily.
    pub fn load(path: &Path) -> Result<Self> {
        match fsutil::read_limited(path, MAX_KNOWN_HOSTS_SIZE) {
            Ok(bytes) => String::from_utf8(bytes)
                .map(|s| Self::parse(&s))
                .map_err(|_| Error::Parse(format!("{} is not valid UTF-8", path.display()))),
            Err(Error::NotFound(_)) => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    /// Writes the file atomically after backing up the current one into
    /// `backup_dir` (mode 0644 for a new file). Returns the backup path.
    pub fn save(&self, path: &Path, backup_dir: &Path) -> Result<Option<PathBuf>> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fsutil::ensure_private_dir(parent)?;
        }
        let backup = fsutil::backup(path, backup_dir)?;
        fsutil::atomic_write(path, self.to_string().as_bytes(), 0o644)?;
        Ok(backup)
    }

    /// All parsed entries.
    pub fn entries(&self) -> Vec<KnownHostEntry> {
        self.parsed()
            .filter_map(|(i, p)| match p {
                Parsed::Entry(parts) => Some(entry(i, &parts)),
                _ => None,
            })
            .collect()
    }

    /// Lines that could not be parsed.
    pub fn invalid_lines(&self) -> Vec<InvalidLine> {
        self.parsed()
            .filter_map(|(i, p)| match p {
                Parsed::Invalid(reason) => Some(InvalidLine {
                    line: line_number(i),
                    reason,
                }),
                _ => None,
            })
            .collect()
    }

    /// Entries and invalid lines together.
    pub fn view(&self) -> KnownHostsView {
        KnownHostsView {
            entries: self.entries(),
            invalid: self.invalid_lines(),
            revision: self.revision(),
        }
    }

    /// SHA-256 of the file's bytes (see [`KnownHostsView::revision`]).
    pub fn revision(&self) -> String {
        fsutil::revision(self.to_string().as_bytes())
    }

    /// Entries (of any marker) that apply to `host` on `port`.
    pub fn matches(&self, host: &str, port: u16) -> Vec<KnownHostEntry> {
        let name = lookup_name(host, port);
        self.parsed()
            .filter_map(|(i, p)| match p {
                Parsed::Entry(parts) if parts.hosts.matches(&name) => Some(entry(i, &parts)),
                _ => None,
            })
            .collect()
    }

    /// Removes the given 1-based lines (entries, invalid lines or comments).
    /// Returns how many lines were removed.
    pub fn remove_lines(&mut self, lines: &[u32]) -> usize {
        let doomed: HashSet<usize> = lines
            .iter()
            .filter_map(|n| usize::try_from(*n).ok()?.checked_sub(1))
            .collect();
        text::remove_indices(&mut self.lines, &doomed)
    }

    /// The keys plain (unmarked) entries give `host`/`port`, hashed or not,
    /// as `(key type, standard base64)`, each once, in file order.
    pub fn keys_for(&self, host: &str, port: u16) -> Vec<(String, String)> {
        let name = lookup_name(host, port);
        let mut keys = Vec::new();
        for (_, parsed) in self.parsed() {
            if let Parsed::Entry(parts) = parsed
                && parts.marker == HostMarker::None
                && parts.hosts.matches(&name)
            {
                let key = (parts.key_type.clone(), Base64::encode_string(&parts.blob));
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }
        }
        keys
    }

    /// Trusts `key` (standard base64 of a `key_type` key) for `host`/`port`
    /// with a plain entry at the end, unless the host has that key already.
    /// Returns whether a line was added.
    pub fn add_key(&mut self, host: &str, port: u16, key_type: &str, key: &str) -> Result<bool> {
        if host.is_empty()
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
        {
            return Err(Error::invalid("not a host name"));
        }
        let blob = decode_b64(key)
            .filter(|blob| blob_type(blob) == Some(key_type))
            .ok_or_else(|| Error::invalid("not a host key of that type"))?;
        let encoded = Base64::encode_string(&blob);
        if self
            .keys_for(host, port)
            .iter()
            .any(|(kind, known)| kind == key_type && *known == encoded)
        {
            return Ok(false);
        }
        if let Some(last) = self.lines.last_mut()
            && last.eol == Eol::None
        {
            last.eol = Eol::Lf;
        }
        self.lines.push(Line::new(
            format!("{} {key_type} {encoded}", lookup_name(host, port)),
            Eol::Lf,
        ));
        Ok(true)
    }

    /// Removes every plain (unmarked) entry for `host`/`port`, hashed or not,
    /// like `ssh-keygen -R`. `@cert-authority` and `@revoked` lines are kept.
    /// Returns the number of removed lines.
    pub fn remove_host(&mut self, host: &str, port: u16) -> usize {
        let name = lookup_name(host, port);
        let doomed: HashSet<usize> = self
            .parsed()
            .filter_map(|(i, p)| match p {
                Parsed::Entry(parts)
                    if parts.marker == HostMarker::None && parts.hosts.matches(&name) =>
                {
                    Some(i)
                }
                _ => None,
            })
            .collect();
        text::remove_indices(&mut self.lines, &doomed)
    }

    fn parsed(&self) -> impl Iterator<Item = (usize, Parsed)> + '_ {
        self.lines
            .iter()
            .enumerate()
            .map(|(i, line)| (i, parse_line(&line.text)))
    }
}

impl fmt::Display for KnownHosts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        text::write_lines(&self.lines, f)
    }
}

impl HostField {
    fn matches(&self, name: &str) -> bool {
        match self {
            Self::Plain(list) => match_host_list(list, name),
            Self::Hashed { salt, hash } => {
                let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(salt) else {
                    return false;
                };
                mac.update(name.as_bytes());
                mac.verify_slice(hash).is_ok()
            }
        }
    }
}

fn line_number(index: usize) -> u32 {
    u32::try_from(index + 1).unwrap_or(u32::MAX)
}

fn entry(index: usize, parts: &Parts) -> KnownHostEntry {
    let (hosts, hashed) = match &parts.hosts {
        HostField::Plain(list) => (
            list.split(',')
                .filter(|h| !h.is_empty())
                .map(str::to_owned)
                .collect(),
            false,
        ),
        HostField::Hashed { .. } => (Vec::new(), true),
    };
    KnownHostEntry {
        line: line_number(index),
        marker: parts.marker,
        hosts,
        hashed,
        key_type: parts.key_type.clone(),
        fingerprint: format!(
            "SHA256:{}",
            Base64Unpadded::encode_string(&Sha256::digest(&parts.blob))
        ),
        comment: parts.comment.clone(),
    }
}

/// The `SHA256:…` fingerprint of a key in standard base64, as
/// `ssh-keygen -l` prints it; `None` if it is not base64.
pub fn fingerprint(key: &str) -> Option<String> {
    let blob = decode_b64(key)?;
    Some(format!(
        "SHA256:{}",
        Base64Unpadded::encode_string(&Sha256::digest(&blob))
    ))
}

/// The name OpenSSH looks up: `host`, or `[host]:port` for non-default ports.
fn lookup_name(host: &str, port: u16) -> String {
    let host = host.to_ascii_lowercase();
    if port == 22 {
        host
    } else {
        format!("[{host}]:{port}")
    }
}

fn is_field_sep(c: char) -> bool {
    matches!(c, ' ' | '\t')
}

/// Splits off the next whitespace-separated field.
fn next_field(s: &str) -> (&str, &str) {
    let s = s.trim_start_matches(is_field_sep);
    match s.find(is_field_sep) {
        Some(end) => (&s[..end], &s[end..]),
        None => (s, ""),
    }
}

fn decode_b64(s: &str) -> Option<Vec<u8>> {
    Base64::decode_vec(s)
        .or_else(|_| Base64Unpadded::decode_vec(s))
        .ok()
}

fn parse_line(raw: &str) -> Parsed {
    let line = raw
        .trim_start_matches('\u{feff}')
        .trim_matches(|c: char| is_field_sep(c) || c == '\r');
    if line.is_empty() || line.starts_with('#') {
        return Parsed::Blank;
    }
    let (first, rest) = next_field(line);
    let (marker, hosts, rest) = match first.strip_prefix('@') {
        Some("cert-authority") => (
            HostMarker::CertAuthority,
            next_field(rest).0,
            next_field(rest).1,
        ),
        Some("revoked") => (HostMarker::Revoked, next_field(rest).0, next_field(rest).1),
        Some(_) => return Parsed::Invalid(InvalidReason::UnknownMarker),
        None => (HostMarker::None, first, rest),
    };
    let (key_type, rest) = next_field(rest);
    let (key_b64, rest) = next_field(rest);
    if hosts.is_empty() || key_type.is_empty() || key_b64.is_empty() {
        return Parsed::Invalid(InvalidReason::MissingFields);
    }
    let Some(blob) = decode_b64(key_b64).filter(|b| blob_type(b) == Some(key_type)) else {
        return Parsed::Invalid(InvalidReason::BadKey);
    };
    let hosts = if hosts.starts_with('|') {
        match parse_hashed(hosts) {
            Some(field) => field,
            None => return Parsed::Invalid(InvalidReason::BadHashedHost),
        }
    } else {
        HostField::Plain(hosts.to_owned())
    };
    let comment = rest.trim_matches(is_field_sep);
    Parsed::Entry(Parts {
        marker,
        hosts,
        key_type: key_type.to_owned(),
        blob,
        comment: (!comment.is_empty()).then(|| comment.to_owned()),
    })
}

/// The key type string at the start of an SSH public key blob.
fn blob_type(blob: &[u8]) -> Option<&str> {
    let len = usize::try_from(u32::from_be_bytes(blob.get(..4)?.try_into().ok()?)).ok()?;
    std::str::from_utf8(blob.get(4..4usize.checked_add(len)?)?).ok()
}

fn parse_hashed(field: &str) -> Option<HostField> {
    let rest = field.strip_prefix("|1|")?;
    let (salt, hash) = rest.split_once('|')?;
    let salt = decode_b64(salt)?;
    let hash = decode_b64(hash)?;
    (!salt.is_empty() && hash.len() == 20).then_some(HostField::Hashed { salt, hash })
}

/// OpenSSH `match_host_and_ip`-style list matching: any negated match wins,
/// otherwise any positive match.
fn match_host_list(list: &str, name: &str) -> bool {
    let mut matched = false;
    for pattern in list.split(',').filter(|p| !p.is_empty()) {
        let (negated, pattern) = match pattern.strip_prefix('!') {
            Some(p) => (true, p),
            None => (false, pattern),
        };
        if wildcard_match(&pattern.to_ascii_lowercase(), name) {
            if negated {
                return false;
            }
            matched = true;
        }
    }
    matched
}

/// `*` matches any sequence, `?` any single character.
fn wildcard_match(pattern: &str, s: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let s: Vec<char> = s.chars().collect();
    let (mut pi, mut si) = (0, 0);
    let mut backtrack: Option<(usize, usize)> = None;
    while si < s.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            backtrack = Some((pi, si));
            pi += 1;
        } else if let Some((bp, bs)) = backtrack {
            pi = bp + 1;
            si = bs + 1;
            backtrack = Some((bp, bs + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorCode;

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBIZFNq0hlvHGZ/oas65Ba4jkcFEy3dX/aRZy70M73oL";
    const FP: &str = "SHA256:76vvbGumhP/HpDH4tlyySHWs5hgRZJHr2wQ7hSDwRK8";
    /// `github.com`, hashed by `ssh-keygen -H`.
    const HASHED_GITHUB: &str = "|1|7OnEpkCfd62ApXJ9JCLHvQM0qE8=|WdcFteNcQm/sb3U5RHrKRL7XG9k=";
    /// `[git.example.com]:2222`, hashed by `ssh-keygen -H`.
    const HASHED_PORT: &str = "|1|xa2oqDsMeHpnThNMXpu8gE/dOoI=|4WKgcm39ho5uYGibUAqaPxjYNAk=";

    fn sample() -> String {
        format!(
            "# comment\n\
             example.com,192.0.2.1 {KEY} laptop key\n\
             {HASHED_GITHUB} {KEY}\n\
             {HASHED_PORT} {KEY}\n\
             *.corp.example.com,!secret.corp.example.com {KEY}\n\
             [bastion.example.com]:2200 {KEY}\n\
             @cert-authority *.example.com {KEY}\n\
             @revoked example.com {KEY}\n\
             @bogus example.com {KEY}\n\
             onlyhost\n\
             host ssh-ed25519 !!!notbase64\n\
             host ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIBIZFNq0hlvHGZ/oas65Ba4jkcFEy3dX/aRZy70M73oL\n\
             |1|bad|bad {KEY}\n\
             \n\
             \ttabbed.example.com\t{KEY}   "
        )
    }

    #[test]
    fn keys_for_a_host_and_adding_one() {
        let mut file = KnownHosts::parse(&sample());
        let (key_type, base64) = KEY.split_once(' ').unwrap();
        let want = vec![(key_type.to_owned(), base64.to_owned())];
        // Plain and hashed, the same key once; never @revoked or @cert-authority.
        assert_eq!(file.keys_for("example.com", 22), want);
        assert_eq!(file.keys_for("github.com", 22), want);
        assert_eq!(file.keys_for("git.example.com", 2222), want);
        assert_eq!(file.keys_for("other.org", 22), Vec::new());

        // A known key is not added twice; a new host gets a plain line.
        assert!(!file.add_key("example.com", 22, key_type, base64).unwrap());
        assert!(
            file.add_key("New.Example.org", 2200, key_type, base64)
                .unwrap()
        );
        assert_eq!(file.keys_for("new.example.org", 2200), want);
        assert!(
            file.to_string()
                .ends_with(&format!("{KEY}   \n[new.example.org]:2200 {KEY}\n"))
        );
        for (host, kind, key) in [
            ("a b", key_type, base64),
            ("a,b", key_type, base64),
            ("", key_type, base64),
            ("host", "ssh-rsa", base64),
            ("host", key_type, "!!!"),
        ] {
            assert!(file.add_key(host, 22, kind, key).is_err(), "{host} {kind}");
        }
    }

    #[test]
    fn round_trips_and_parses() {
        for input in [
            sample(),
            sample().replace('\n', "\r\n"),
            format!("{}\n", sample()),
            String::new(),
        ] {
            assert_eq!(KnownHosts::parse(&input).to_string(), input);
        }
        let kh = KnownHosts::parse(&sample());
        let entries = kh.entries();
        assert_eq!(entries.len(), 8);
        assert_eq!(entries[0].line, 2);
        assert_eq!(entries[0].hosts, ["example.com", "192.0.2.1"]);
        assert_eq!(entries[0].comment.as_deref(), Some("laptop key"));
        assert_eq!(entries[0].fingerprint, FP);
        assert_eq!(entries[0].key_type, "ssh-ed25519");
        assert!(entries[1].hashed && entries[1].hosts.is_empty());
        assert_eq!(entries[5].marker, HostMarker::CertAuthority);
        assert_eq!(entries[6].marker, HostMarker::Revoked);
        assert_eq!(entries[7].hosts, ["tabbed.example.com"]);
        assert_eq!(entries[7].comment, None);
        let invalid: Vec<_> = kh
            .invalid_lines()
            .into_iter()
            .map(|l| (l.line, l.reason))
            .collect();
        assert_eq!(
            invalid,
            [
                (9, InvalidReason::UnknownMarker),
                (10, InvalidReason::MissingFields),
                (11, InvalidReason::BadKey),
                (12, InvalidReason::BadKey),
                (13, InvalidReason::BadHashedHost),
            ]
        );
    }

    #[test]
    fn matching() {
        let kh = KnownHosts::parse(&sample());
        let lines = |host: &str, port: u16| -> Vec<u32> {
            kh.matches(host, port).into_iter().map(|e| e.line).collect()
        };
        assert_eq!(lines("example.com", 22), [2, 8]);
        assert_eq!(lines("EXAMPLE.com", 22), [2, 8]);
        assert_eq!(lines("192.0.2.1", 22), [2]);
        assert_eq!(lines("example.com", 2222), Vec::<u32>::new());
        assert_eq!(lines("github.com", 22), [3]);
        assert_eq!(lines("github.com", 2222), Vec::<u32>::new());
        assert_eq!(lines("git.example.com", 2222), [4]);
        assert_eq!(lines("web.corp.example.com", 22), [5, 7]);
        assert_eq!(lines("secret.corp.example.com", 22), [7]);
        assert_eq!(lines("bastion.example.com", 2200), [6]);
        assert_eq!(lines("bastion.example.com", 22), [7]);
    }

    #[test]
    fn wildcards() {
        assert!(wildcard_match("*", ""));
        assert!(wildcard_match("a*b*c", "aXXbYc"));
        assert!(!wildcard_match("a*b*c", "aXXbY"));
        assert!(wildcard_match("h?st", "host"));
        assert!(!wildcard_match("h?st", "hst"));
        assert!(wildcard_match("[h]:*", "[h]:2222"));
        assert!(wildcard_match("**", "x"));
    }

    #[test]
    fn removal() {
        let mut kh = KnownHosts::parse(&sample());
        assert_eq!(
            kh.remove_host("example.com", 22),
            1,
            "CA and revoked lines stay"
        );
        assert!(
            kh.matches("example.com", 22)
                .iter()
                .all(|e| e.marker != HostMarker::None)
        );
        assert_eq!(kh.remove_host("git.example.com", 2222), 1);
        assert_eq!(kh.remove_host("nobody.example", 22), 0);
        let before = kh.to_string();
        assert_eq!(kh.remove_lines(&[1, 999, 0]), 1);
        assert!(!kh.to_string().contains("# comment"));
        assert_eq!(before.lines().count() - 1, kh.to_string().lines().count());
        // The file still ends without a newline, as before.
        assert!(!kh.to_string().ends_with('\n'));
    }

    #[test]
    fn load_and_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let backups = dir.path().join("backups");
        assert_eq!(KnownHosts::load(&path).unwrap().entries(), []);
        std::fs::write(&path, format!("example.com {KEY}\nother.example {KEY}\n")).unwrap();
        let mut kh = KnownHosts::load(&path).unwrap();
        assert_eq!(kh.remove_host("example.com", 22), 1);
        let backup = kh.save(&path, &backups).unwrap().unwrap();
        assert!(
            std::fs::read_to_string(backup)
                .unwrap()
                .contains("example.com")
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("other.example {KEY}\n")
        );
        std::fs::write(&path, b"\xff\xfe").unwrap();
        assert_eq!(
            KnownHosts::load(&path).unwrap_err().code(),
            ErrorCode::Parse
        );
    }

    #[test]
    fn revision_is_the_hash_of_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let missing = KnownHosts::load(&path).unwrap();
        assert_eq!(missing.revision(), fsutil::revision(b""));
        let text = format!("example.com {KEY}\r\n@revoked bad.example {KEY}");
        std::fs::write(&path, &text).unwrap();
        let kh = KnownHosts::load(&path).unwrap();
        assert_eq!(kh.revision(), fsutil::revision(text.as_bytes()));
        assert_eq!(kh.view().revision, kh.revision());
        let mut edited = kh.clone();
        edited.remove_lines(&[1]);
        assert_ne!(edited.revision(), kh.revision());
    }

    #[test]
    fn parsing_is_total() {
        for line in [
            "@",
            "@cert-authority",
            "@revoked x",
            "|",
            "|1|",
            "|1||",
            "x y",
            "x y z",
            "\u{feff}",
            "x ssh-ed25519 AAAA",
            "x ssh-ed25519 AAAAAAAA",
            "x ssh-ed25519 /////w==",
        ] {
            let _ = parse_line(line);
        }
        assert_eq!(blob_type(&[0, 0, 0, 9, b'a']), None);
        assert_eq!(blob_type(&[0xff, 0xff, 0xff, 0xff]), None);
    }

    #[test]
    fn view_serializes() {
        let v = serde_json::to_value(KnownHosts::parse(&sample()).view()).unwrap();
        assert_eq!(v["entries"][5]["marker"], "certAuthority");
        assert_eq!(v["entries"][0]["keyType"], "ssh-ed25519");
        assert_eq!(v["invalid"][0]["reason"], "unknownMarker");
        assert_eq!(v["revision"].as_str().map(str::len), Some(64));
    }
}
