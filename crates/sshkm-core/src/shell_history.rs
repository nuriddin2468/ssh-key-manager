//! Hosts worth adding to `~/.ssh/config`, found in the user's shell history.
//!
//! The history of zsh, bash, fish and PowerShell is read on this computer
//! only, and only after the user said yes ([`HistoryPrefs`]). Of each
//! command, only `ssh`, `autossh`, `mosh`, `scp` and `sftp` invocations are
//! looked at, and of those only the target (user, host, port) and the
//! options a `Host` block can hold (`-i`, `-J`, `-A`, some `-o`). Nothing
//! else of a command leaves this module: no remote command, file name or
//! other argument, and never a password. Passwords typed into such commands
//! (`sshpass -p`, `ssh://user:password@`, a `-o` option named like one) are
//! counted per file, so the user can be told to clean their history,
//! without seeing them.
//!
//! Targets that a `Host` block already covers are left out: by its name, or
//! by `HostName`, `User` and `Port`. Dismissed suggestions are remembered as
//! a keyed hash of the target, not as the command or the host.

mod formats;
mod invocation;
mod words;

#[cfg(test)]
mod tests;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use self::invocation::Target;
use self::words::Dialect;
use crate::config::{HostEntry, HostKind, HostOption};
use crate::{Error, Result, fsutil};

/// Most of a history file that is read: its end, the newest commands.
const MAX_READ: u64 = 16 * 1024 * 1024;
/// Suggestions returned, most used first.
const MAX_SUGGESTIONS: usize = 50;
/// Dismissed targets remembered; the oldest go first.
const MAX_DISMISSED: usize = 2000;
/// First labels of a host name that say little about it (`ssh.example.com`).
const GENERIC_LABELS: &[&str] = &["www", "ssh", "sftp", "shell"];

/// A shell whose history is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum Shell {
    Zsh,
    Bash,
    Fish,
    PowerShell,
}

impl Shell {
    fn entries(self, bytes: &[u8]) -> Vec<formats::Entry> {
        match self {
            Self::Zsh => formats::zsh(bytes),
            Self::Bash => formats::bash(bytes),
            Self::Fish => formats::fish(bytes),
            Self::PowerShell => formats::powershell(bytes),
        }
    }

    fn dialect(self) -> Dialect {
        match self {
            Self::Zsh | Self::Bash => Dialect::Posix,
            Self::Fish => Dialect::Fish,
            Self::PowerShell => Dialect::PowerShell,
        }
    }
}

/// A history file to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryFile {
    pub shell: Shell,
    pub path: PathBuf,
}

/// The usual history files of the user whose home is `home`:
///
/// - zsh: `~/.zsh_history`;
/// - bash: `~/.bash_history`;
/// - fish: `<data>/fish/fish_history`;
/// - PowerShell: `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
///   on Windows, `<data>/powershell/PSReadLine/ConsoleHost_history.txt` elsewhere.
///
/// `data` is `$XDG_DATA_HOME`, else `~/.local/share`; `app_data` is
/// `%APPDATA%` (Windows only).
pub fn history_files(
    home: &Path,
    data: Option<&Path>,
    app_data: Option<&Path>,
) -> Vec<HistoryFile> {
    let data = data.map_or_else(|| home.join(".local").join("share"), Path::to_path_buf);
    let powershell = match app_data {
        Some(app_data) => app_data
            .join("Microsoft")
            .join("Windows")
            .join("PowerShell"),
        None => data.join("powershell"),
    };
    vec![
        HistoryFile {
            shell: Shell::Zsh,
            path: home.join(".zsh_history"),
        },
        HistoryFile {
            shell: Shell::Bash,
            path: home.join(".bash_history"),
        },
        HistoryFile {
            shell: Shell::Fish,
            path: data.join("fish").join("fish_history"),
        },
        HistoryFile {
            shell: Shell::PowerShell,
            path: powershell
                .join("PSReadLine")
                .join("ConsoleHost_history.txt"),
        },
    ]
}

/// [`history_files`] for this computer: `$XDG_DATA_HOME` if it is set, and
/// the roaming application data folder on Windows.
pub fn default_history_files(home: &Path) -> Vec<HistoryFile> {
    let data = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute());
    let app_data = if cfg!(windows) {
        dirs::config_dir()
    } else {
        None
    };
    history_files(home, data.as_deref(), app_data.as_deref())
}

/// A host the history connects to that no `Host` block covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct HostSuggestion {
    /// Names the target to [`HistoryPrefs::dismiss`]: a keyed hash of its
    /// user, host and port.
    pub id: String,
    /// A name for the `Host` line that no block uses yet.
    pub alias: String,
    /// A host name or address; an IPv6 address without brackets.
    pub host: String,
    pub user: Option<String>,
    /// `None` for 22.
    pub port: Option<u16>,
    /// The first key the commands named with `-i`.
    pub identity_file: Option<String>,
    pub proxy_jump: Option<String>,
    /// `-A` or `-o ForwardAgent=yes`.
    pub forward_agent: bool,
    /// More options for the block: further `IdentityFile`s and the `-o`
    /// options worth keeping.
    pub options: Vec<HostOption>,
    /// Commands that connected to it.
    pub uses: u32,
    /// When it was last connected to, RFC 3339 in UTC; `None` when no
    /// history says.
    pub last_used: Option<String>,
    /// The shells whose history has it.
    pub shells: Vec<Shell>,
}

/// One history file that was read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct HistoryFileSummary {
    pub shell: Shell,
    pub path: String,
    /// Commands in it that hold a password typed for `ssh` and the like;
    /// the commands themselves are never passed on.
    pub secrets: u32,
}

/// What [`scan`] found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct HistoryScan {
    /// Most used first.
    pub suggestions: Vec<HostSuggestion>,
    /// The history files found and read.
    pub files: Vec<HistoryFileSummary>,
    /// Suggestions left out because the user dismissed them.
    pub dismissed: u32,
}

/// Reads `files` (those that exist) and suggests the hosts their commands
/// connect to that none of `hosts` covers, leaving out those `prefs` says
/// were dismissed.
pub fn scan(files: &[HistoryFile], hosts: &[HostEntry], prefs: &HistoryPrefs) -> HistoryScan {
    let read: Vec<(Shell, String, Vec<u8>)> = files
        .iter()
        .filter_map(|file| {
            let bytes = read_tail(&file.path).ok()??;
            Some((file.shell, file.path.display().to_string(), bytes))
        })
        .collect();
    scan_contents(&read, hosts, prefs)
}

/// [`scan`] over the contents of history files: their shell, path and
/// bytes.
pub fn scan_contents(
    files: &[(Shell, String, Vec<u8>)],
    hosts: &[HostEntry],
    prefs: &HistoryPrefs,
) -> HistoryScan {
    let mut groups: HashMap<TargetKey, Group> = HashMap::new();
    let mut summaries = Vec::new();
    let mut seq = 0_u64;
    for (shell, path, bytes) in files {
        let mut secrets = 0;
        for entry in shell.entries(bytes) {
            seq += 1;
            let found = invocation::find(&entry.text, shell.dialect());
            if found.secrets > 0 {
                secrets += 1;
            }
            // A command that names a host twice (`scp a:x a:y`) used it once.
            let mut seen = HashSet::new();
            for target in found.targets {
                let key = TargetKey::of(&target);
                if !seen.insert(key.clone()) {
                    continue;
                }
                let recency = (entry.when.unwrap_or(i64::MIN), seq);
                groups
                    .entry(key)
                    .or_insert_with(|| Group::new(&target))
                    .add(target, *shell, entry.when, recency);
            }
        }
        summaries.push(HistoryFileSummary {
            shell: *shell,
            path: path.clone(),
            secrets,
        });
    }

    let mut dismissed = 0;
    let mut kept: Vec<(TargetKey, Group)> = groups
        .into_iter()
        .filter(|(_, group)| !configured(&group.target, hosts))
        .filter(|(key, _)| {
            let hidden = prefs.is_dismissed(&prefs.target_id(key));
            dismissed += u32::from(hidden);
            !hidden
        })
        .collect();
    kept.sort_by(|(a_key, a), (b_key, b)| {
        b.uses
            .cmp(&a.uses)
            .then(b.last.cmp(&a.last))
            .then_with(|| a_key.cmp(b_key))
    });
    kept.truncate(MAX_SUGGESTIONS);

    let mut taken: HashSet<String> = hosts
        .iter()
        .filter(|h| h.kind == HostKind::Host)
        .flat_map(|h| h.patterns.iter().map(|p| p.to_ascii_lowercase()))
        .collect();
    let suggestions = kept
        .into_iter()
        .map(|(key, group)| {
            let alias = unique_alias(&group.target, &mut taken);
            group.into_suggestion(prefs.target_id(&key), alias)
        })
        .collect();
    HistoryScan {
        suggestions,
        files: summaries,
        dismissed,
    }
}

/// The end of the file at `path`, at most [`MAX_READ`] bytes from the
/// start of a line; `None` if there is no such file.
fn read_tail(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Ok(None);
    }
    let start = meta.len().saturating_sub(MAX_READ);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.take(MAX_READ).read_to_end(&mut bytes)?;
    if start > 0 {
        let line = bytes
            .iter()
            .position(|b| *b == b'\n')
            .map_or(0, |at| at + 1);
        bytes.drain(..line);
    }
    Ok(Some(bytes))
}

/// What makes two commands connect to the same place: user, host (in any
/// case) and port, 22 when none is given.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct TargetKey {
    host: String,
    user: Option<String>,
    port: u16,
}

impl TargetKey {
    fn of(target: &Target) -> Self {
        Self {
            host: target.host.to_ascii_lowercase(),
            user: target.user.clone(),
            port: target.port.unwrap_or(22),
        }
    }

    /// The text that is hashed into a suggestion's id.
    fn text(&self) -> String {
        format!(
            "{}\0{}\0{}",
            self.user.as_deref().unwrap_or_default(),
            self.host,
            self.port
        )
    }
}

/// The commands that connect to one target.
struct Group {
    /// The newest options seen, each field from the newest command that
    /// set it.
    target: Target,
    recency: (i64, u64),
    uses: u32,
    last: Option<i64>,
    shells: BTreeSet<Shell>,
}

impl Group {
    fn new(target: &Target) -> Self {
        Self {
            target: Target {
                host: target.host.clone(),
                user: target.user.clone(),
                port: target.port.filter(|p| *p != 22),
                ..Target::default()
            },
            recency: (i64::MIN, 0),
            uses: 0,
            last: None,
            shells: BTreeSet::new(),
        }
    }

    fn add(&mut self, target: Target, shell: Shell, when: Option<i64>, recency: (i64, u64)) {
        self.uses = self.uses.saturating_add(1);
        self.last = self.last.max(when);
        self.shells.insert(shell);
        let newer = recency >= self.recency;
        if newer {
            self.recency = recency;
        }
        let ours = &mut self.target;
        if !target.identity_files.is_empty() && (newer || ours.identity_files.is_empty()) {
            ours.identity_files = target.identity_files;
        }
        if target.proxy_jump.is_some() && (newer || ours.proxy_jump.is_none()) {
            ours.proxy_jump = target.proxy_jump;
        }
        ours.forward_agent |= target.forward_agent;
        for option in target.options {
            match ours.options.iter_mut().find(|o| o.key == option.key) {
                Some(existing) if newer => *existing = option,
                Some(_) => {}
                None => ours.options.push(option),
            }
        }
    }

    fn into_suggestion(self, id: String, alias: String) -> HostSuggestion {
        let mut identities = self.target.identity_files.into_iter();
        let identity_file = identities.next();
        let mut options: Vec<HostOption> = identities
            .map(|path| HostOption::new("IdentityFile", path))
            .collect();
        options.extend(self.target.options);
        HostSuggestion {
            id,
            alias,
            host: self.target.host,
            user: self.target.user,
            port: self.target.port,
            identity_file,
            proxy_jump: self.target.proxy_jump,
            forward_agent: self.target.forward_agent,
            options,
            uses: self.uses,
            last_used: self.last.and_then(rfc3339),
            shells: self.shells.into_iter().collect(),
        }
    }
}

fn rfc3339(seconds: i64) -> Option<String> {
    OffsetDateTime::from_unix_timestamp(seconds)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

/// A `Host` block covers `target`: one of its names (not a pattern) is the
/// host, or its `HostName` is, with the same port and, if the command named
/// one, the same user.
fn configured(target: &Target, hosts: &[HostEntry]) -> bool {
    let port = target.port.unwrap_or(22);
    hosts.iter().filter(|h| h.kind == HostKind::Host).any(|h| {
        let named = h.patterns.iter().any(|p| {
            !p.starts_with('!') && !p.contains(['*', '?']) && p.eq_ignore_ascii_case(&target.host)
        });
        let same_server = h
            .host_name
            .as_deref()
            .is_some_and(|name| name.eq_ignore_ascii_case(&target.host))
            && h.port.unwrap_or(22) == port
            && target
                .user
                .as_deref()
                .is_none_or(|user| h.user.as_deref() == Some(user));
        named || same_server
    })
}

/// A short name for `target` that isn't in `taken`, which it is added to:
/// the host's first telling label (`web1` for `web1.prod.example.com`,
/// `github` for `ssh.github.com`), or user and address for an address
/// (`root-10-0-0-5`). On a clash the user or the port is added, then a
/// number.
fn unique_alias(target: &Target, taken: &mut HashSet<String>) -> String {
    let base = alias_base(target);
    let user = target.user.as_deref().map(alias_text).unwrap_or_default();
    let mut candidates = vec![base.clone()];
    if !user.is_empty() && !base.starts_with(&format!("{user}-")) {
        candidates.push(format!("{base}-{user}"));
    }
    if let Some(port) = target.port {
        candidates.push(format!("{base}-{port}"));
    }
    let alias = candidates
        .into_iter()
        .find(|candidate| !taken.contains(candidate))
        .unwrap_or_else(|| {
            let mut n = 2_u32;
            loop {
                let candidate = format!("{base}-{n}");
                if !taken.contains(&candidate) {
                    break candidate;
                }
                n += 1;
            }
        });
    taken.insert(alias.clone());
    alias
}

fn alias_base(target: &Target) -> String {
    let host = target.host.to_ascii_lowercase();
    let address = host.parse::<IpAddr>().is_ok() || host.contains(':');
    let base = if address {
        let user = target.user.as_deref().map_or("host".to_owned(), alias_text);
        format!("{user}-{}", alias_text(&host))
    } else {
        let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
        let named = labels
            .iter()
            .take(labels.len().saturating_sub(1).max(1))
            .find(|label| !GENERIC_LABELS.contains(label));
        alias_text(named.or(labels.first()).copied().unwrap_or("host"))
    };
    if base.is_empty() || base == "-" {
        "host".to_owned()
    } else {
        base
    }
}

/// `text` as letters, digits, `-` and `_`, lower case, other characters as
/// single dashes.
fn alias_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            out.push(c.to_ascii_lowercase());
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_end_matches('-').to_owned()
}

/// Whether the user allowed reading their history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum HistoryConsent {
    /// Not asked yet: the Hosts page asks.
    Unasked,
    On,
    Off,
}

/// The state of the feature, for the Hosts and Settings pages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct HistoryStatus {
    pub consent: HistoryConsent,
    /// Suggestions the user dismissed.
    pub dismissed: u32,
}

/// The user's answer and the suggestions they dismissed, kept in a file of
/// the app's own (`shell-history.json` in its data folder). Dismissed
/// targets are kept as HMAC-SHA-256 of user, host and port, under a random
/// key of this file, so it doesn't list servers in plain text.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryPrefs {
    /// `None` until the user answers.
    #[serde(default)]
    enabled: Option<bool>,
    /// The hashes' key, hex; made when the feature is turned on.
    #[serde(default)]
    key: String,
    /// Dismissed targets by [`HostSuggestion::id`], oldest first.
    #[serde(default)]
    dismissed: Vec<String>,
}

impl HistoryPrefs {
    /// The preferences in `path`; defaults if there is no such file or it
    /// can't be read.
    pub fn load(path: &Path) -> Self {
        fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    /// Writes the preferences to `path`, readable by this user only.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            fsutil::ensure_private_dir(dir)?;
        }
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| Error::invalid(format!("shell history settings: {e}")))?;
        fsutil::atomic_write(path, &json, 0o600)
    }

    pub fn status(&self) -> HistoryStatus {
        HistoryStatus {
            consent: match self.enabled {
                None => HistoryConsent::Unasked,
                Some(true) => HistoryConsent::On,
                Some(false) => HistoryConsent::Off,
            },
            dismissed: u32::try_from(self.dismissed.len()).unwrap_or(u32::MAX),
        }
    }

    /// The user allowed reading their history.
    pub fn enabled(&self) -> bool {
        self.enabled == Some(true)
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = Some(enabled);
        if enabled {
            self.ensure_key();
        }
    }

    /// Makes the hashes' key if there is none; true if it did.
    pub fn ensure_key(&mut self) -> bool {
        if self.key.len() == 64 {
            return false;
        }
        let mut key = [0_u8; 32];
        OsRng.fill_bytes(&mut key);
        self.key = hex(&key);
        // Hashes under another key mean nothing now.
        self.dismissed.clear();
        true
    }

    /// Stops suggesting the target `id` names ([`HostSuggestion::id`]).
    pub fn dismiss(&mut self, id: &str) -> Result<()> {
        let valid = id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !valid {
            return Err(Error::invalid("not a suggestion id"));
        }
        if !self.is_dismissed(id) {
            self.dismissed.push(id.to_owned());
            let over = self.dismissed.len().saturating_sub(MAX_DISMISSED);
            self.dismissed.drain(..over);
        }
        Ok(())
    }

    /// Suggests the dismissed targets again.
    pub fn forget_dismissed(&mut self) {
        self.dismissed.clear();
    }

    fn is_dismissed(&self, id: &str) -> bool {
        self.dismissed.iter().any(|d| d == id)
    }

    fn target_id(&self, key: &TargetKey) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.key.as_bytes())
            .expect("HMAC takes a key of any length");
        mac.update(key.text().as_bytes());
        hex(&mac.finalize().into_bytes()[..16])
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}
