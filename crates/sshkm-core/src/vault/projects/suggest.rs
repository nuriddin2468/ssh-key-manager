//! Projects the app proposes from what it finds, for the user to confirm
//! one by one: nothing here changes anything.
//!
//! Each source gives candidates, and candidates whose names read the same
//! ([`key`]: case, spaces and punctuation aside) are one suggestion:
//!
//! - an environments' project group (`Environments/<group>`);
//! - a Git working tree in a code folder, with the host and keys its
//!   remotes reach through `~/.ssh/config`;
//! - hosts behind one `ProxyJump` host;
//! - hosts whose aliases start alike (`shop-prod`, `shop-db`) or whose
//!   `HostName`s share a domain (`api.acme.com`, `db.acme.com`);
//! - a top-level group of a KeePass file, and a KeePass tag no project has.
//!
//! Members already in a project aren't suggested again; a suggestion named
//! like an existing project offers to add to that one.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{
    MAX_MEMBERS, MAX_NAME, Project, ProjectColor, ProjectMember, check_name, folder_text,
    is_valid_member,
};

/// Most suggestions offered at once.
pub const MAX_SUGGESTIONS: usize = 50;
/// Most folders a search for Git working trees looks into.
const MAX_FOLDERS_SEEN: usize = 4000;
/// Most working trees it takes.
const MAX_REPOSITORIES: usize = 300;
/// How deep below a code folder it looks.
const MAX_DEPTH: usize = 3;
/// Largest `.git/config` read.
const MAX_GIT_CONFIG: u64 = 256 * 1024;

/// Folders under the home folder where people keep code, looked into for
/// Git working trees.
pub const CODE_FOLDERS: &[&str] = &[
    "code",
    "Code",
    "dev",
    "Dev",
    "Developer",
    "src",
    "projects",
    "Projects",
    "repos",
    "git",
    "work",
    "Work",
    "workspace",
    "Workspace",
    "Sites",
    "go/src",
    "source/repos",
    "Documents/GitHub",
    "Documents/Code",
    "Documents/Projects",
];

/// Folders a search never goes into.
const SKIPPED: &[&str] = &[
    "node_modules",
    "target",
    "vendor",
    "dist",
    "build",
    "Library",
    "Applications",
    "venv",
];

/// Words that name a stage or a role, not a project: `prod-db` and
/// `prod-web` are not the project "prod".
const NOT_PROJECTS: &[&str] = &[
    "prod",
    "production",
    "staging",
    "stage",
    "stg",
    "dev",
    "development",
    "test",
    "testing",
    "qa",
    "uat",
    "preprod",
    "demo",
    "local",
    "sandbox",
    "live",
    "db",
    "web",
    "app",
    "api",
    "srv",
    "server",
    "host",
    "node",
    "vm",
    "worker",
    "bastion",
    "jump",
    "gw",
    "gateway",
    "proxy",
    "vpn",
    "git",
    "ci",
    "build",
    "backup",
    "my",
    "old",
    "new",
];

/// Where code lives for everyone: a host there isn't one project's.
const CODE_HOSTS: &[&str] = &[
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "codeberg.org",
    "ssh.dev.azure.com",
    "vs-ssh.visualstudio.com",
    "git.sr.ht",
];

/// KeePass's own starter groups, which say nothing of a project.
const KEEPASS_STARTER_GROUPS: &[&str] = &[
    "general",
    "windows",
    "network",
    "internet",
    "email",
    "e-mail",
    "homebanking",
];

/// A host of `~/.ssh/config` as suggestions see it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostFacts {
    pub alias: String,
    pub host_name: Option<String>,
    pub proxy_jump: Option<String>,
    /// Fingerprints of the keys its `IdentityFile`s name.
    pub keys: Vec<String>,
}

/// A login of the vault as suggestions see it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoginFacts {
    pub id: String,
    /// Its folder path in the KeePass file, as `Work/Servers`.
    pub group: Option<String>,
    pub tags: Vec<String>,
}

/// What the user turned down: suggestions dismissed, and members left out
/// when they accepted one. Neither is suggested again.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Declined {
    /// Suggestions dismissed, by key, oldest first.
    pub keys: Vec<String>,
    /// Members left out of an accepted suggestion, by its key.
    pub members: BTreeMap<String, Vec<ProjectMember>>,
}

impl Declined {
    /// Most dismissals kept: past it, the oldest is forgotten.
    pub const MAX_KEYS: usize = 1000;

    /// Stops suggesting `key`. Returns whether that is news.
    pub fn dismiss(&mut self, key: &str) -> bool {
        if self.keys.iter().any(|k| k == key) {
            return false;
        }
        if self.keys.len() >= Self::MAX_KEYS {
            self.keys.remove(0);
        }
        self.keys.push(key.to_owned());
        true
    }

    /// Remembers what `suggestion` offered that the user didn't keep.
    pub fn left_out(&mut self, suggestion: &ProjectSuggestion, kept: &[ProjectMember]) {
        let left: Vec<ProjectMember> = suggestion
            .member_list()
            .into_iter()
            .filter(|member| !kept.contains(member))
            .collect();
        if left.is_empty() {
            return;
        }
        let list = self.members.entry(suggestion.key.clone()).or_default();
        for member in left {
            if !list.contains(&member) && list.len() < MAX_MEMBERS {
                list.push(member);
            }
        }
    }
}

/// A Git working tree found on this computer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repository {
    pub folder: PathBuf,
    /// Its remotes' URLs.
    pub remotes: Vec<String>,
}

/// What suggestions are made from.
#[derive(Debug, Default)]
pub struct Sources<'a> {
    pub hosts: &'a [HostFacts],
    pub environment_groups: &'a [String],
    pub logins: &'a [LoginFacts],
    pub repositories: &'a [Repository],
    pub projects: &'a [Project],
    pub home: Option<&'a Path>,
}

/// Why a project is suggested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum SuggestionReason {
    /// Environments of this project group.
    Environments { group: String },
    /// A Git working tree.
    GitFolder { folder: String },
    /// Hosts reached through this `ProxyJump` host.
    ProxyJump { bastion: String },
    /// Host aliases that start with this.
    NamePrefix { prefix: String },
    /// Hosts in this domain.
    Domain { domain: String },
    /// Logins in this group of a KeePass file.
    KeepassGroup { group: String },
    /// Logins with this KeePass tag.
    KeepassTag { tag: String },
}

/// A project the app proposes, for the user to confirm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct ProjectSuggestion {
    /// Its name read without case and punctuation: what a dismissal keeps.
    pub key: String,
    pub name: String,
    /// A color few projects have.
    pub color: ProjectColor,
    /// The project of that name, when there is one: the suggestion adds to it.
    pub existing: Option<String>,
    pub reasons: Vec<SuggestionReason>,
    pub folders: Vec<String>,
    pub hosts: Vec<String>,
    pub keys: Vec<String>,
    pub environments: Vec<String>,
    pub logins: Vec<String>,
}

impl ProjectSuggestion {
    /// Everything it offers, as members.
    pub fn member_list(&self) -> Vec<ProjectMember> {
        let mut list = Vec::new();
        list.extend(self.hosts.iter().map(|alias| ProjectMember::Host {
            alias: alias.clone(),
        }));
        list.extend(self.keys.iter().map(|fingerprint| ProjectMember::Key {
            fingerprint: fingerprint.clone(),
        }));
        list.extend(
            self.environments
                .iter()
                .map(|group| ProjectMember::Environment {
                    group: group.clone(),
                }),
        );
        list.extend(
            self.folders
                .iter()
                .map(|path| ProjectMember::Folder { path: path.clone() }),
        );
        list.extend(
            self.logins
                .iter()
                .map(|id| ProjectMember::Login { id: id.clone() }),
        );
        list
    }

    /// Whether it offers `member`.
    pub fn offers(&self, member: &ProjectMember) -> bool {
        match member {
            ProjectMember::Host { alias } => self.hosts.contains(alias),
            ProjectMember::Key { fingerprint } => self.keys.contains(fingerprint),
            ProjectMember::Login { id } => self.logins.contains(id),
            ProjectMember::Environment { group } => self.environments.contains(group),
            ProjectMember::Folder { path } => self.folders.contains(path),
        }
    }

    /// Drops members a project can't take ([`is_valid_member`]): a group
    /// named with `/` in KeePassXC, an alias with quotes.
    fn retain_valid(&mut self) {
        let valid: Vec<ProjectMember> = self
            .member_list()
            .into_iter()
            .filter(is_valid_member)
            .collect();
        self.hosts.clear();
        self.keys.clear();
        self.environments.clear();
        self.folders.clear();
        self.logins.clear();
        for member in valid {
            match member {
                ProjectMember::Host { alias } => self.hosts.push(alias),
                ProjectMember::Key { fingerprint } => self.keys.push(fingerprint),
                ProjectMember::Environment { group } => self.environments.push(group),
                ProjectMember::Folder { path } => self.folders.push(path),
                ProjectMember::Login { id } => self.logins.push(id),
            }
        }
    }

    /// Drops what `declined` says the user left out.
    fn drop_declined(&mut self, declined: &[ProjectMember]) {
        for member in declined {
            match member {
                ProjectMember::Host { alias } => self.hosts.retain(|v| v != alias),
                ProjectMember::Key { fingerprint } => self.keys.retain(|v| v != fingerprint),
                ProjectMember::Login { id } => self.logins.retain(|v| v != id),
                ProjectMember::Environment { group } => self.environments.retain(|v| v != group),
                ProjectMember::Folder { path } => self.folders.retain(|v| v != path),
            }
        }
    }

    fn members(&self) -> usize {
        self.folders.len()
            + self.hosts.len()
            + self.keys.len()
            + self.environments.len()
            + self.logins.len()
    }

    fn take(&mut self, other: Self) {
        for reason in other.reasons {
            if !self.reasons.contains(&reason) {
                self.reasons.push(reason);
            }
        }
        for (mine, theirs) in [
            (&mut self.folders, other.folders),
            (&mut self.hosts, other.hosts),
            (&mut self.keys, other.keys),
            (&mut self.environments, other.environments),
            (&mut self.logins, other.logins),
        ] {
            for value in theirs {
                if !mine.contains(&value) && mine.len() < MAX_MEMBERS {
                    mine.push(value);
                }
            }
        }
    }
}

/// A name read without case, spaces and punctuation: `Shop API`,
/// `shop_api` and `shop-api` are one.
pub fn key(name: &str) -> String {
    let mut key = String::new();
    for c in name.trim().chars().flat_map(char::to_lowercase) {
        if c.is_alphanumeric() {
            key.push(c);
        } else if !key.is_empty() && !key.ends_with('-') {
            key.push('-');
        }
    }
    key.trim_end_matches('-').to_owned()
}

/// `text` made into a project name [`check_name`] takes, or `None`.
fn clean_name(text: &str) -> Option<String> {
    let words: Vec<&str> = text.split_whitespace().collect();
    let name: String = words
        .join(" ")
        .chars()
        .filter(|c| !c.is_control() && *c != ';' && *c != ',')
        .take(MAX_NAME)
        .collect();
    check_name(&name).ok()
}

fn candidate(name: &str, reason: SuggestionReason) -> Option<ProjectSuggestion> {
    let name = clean_name(name)?;
    let key = key(&name);
    (!key.is_empty()).then(|| ProjectSuggestion {
        key,
        name,
        color: ProjectColor::default(),
        existing: None,
        reasons: vec![reason],
        folders: Vec::new(),
        hosts: Vec::new(),
        keys: Vec::new(),
        environments: Vec::new(),
        logins: Vec::new(),
    })
}

/// Whether a host is code hosting everyone uses, by alias or `HostName`:
/// it says nothing of a project.
fn is_code_host(host: &HostFacts) -> bool {
    let everyones = |name: &str| {
        CODE_HOSTS
            .iter()
            .any(|code| code.eq_ignore_ascii_case(name))
    };
    everyones(&host.alias) || host.host_name.as_deref().is_some_and(everyones)
}

/// The first word of an alias, before `-`, `_` or `.`, if it can name a
/// project.
fn prefix(alias: &str) -> Option<&str> {
    let first = alias.split(['-', '_', '.']).next()?;
    let fine = first.len() >= 2
        && first.len() < alias.len()
        && first.chars().any(char::is_alphabetic)
        && !NOT_PROJECTS.contains(&first.to_lowercase().as_str());
    fine.then_some(first)
}

/// The registrable domain of a host name (`acme.com` for `db.acme.com`),
/// not for addresses or for code hosting everyone uses.
fn domain(host_name: &str) -> Option<String> {
    let host = host_name.trim().trim_end_matches('.').to_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok() || !host.contains('.') {
        return None;
    }
    let domain = psl::domain_str(&host)?.to_owned();
    let everyones = CODE_HOSTS
        .iter()
        .any(|code| *code == domain || code.ends_with(&format!(".{domain}")));
    (!everyones).then_some(domain)
}

/// The host a `ProxyJump` value goes through first: `bastion` for
/// `me@bastion:2222,inner`.
fn first_jump(value: &str) -> Option<&str> {
    let first = value.split(',').next()?.trim();
    let first = first.strip_prefix("ssh://").unwrap_or(first);
    let host = first.rsplit('@').next()?;
    let host = host.split(':').next()?;
    (!host.is_empty() && !host.eq_ignore_ascii_case("none")).then_some(host)
}

/// The host a Git remote URL reaches over SSH: `github-work` for
/// `github-work:acme/shop.git` and `git@github-work:…`, the host of
/// `ssh://…`; `None` for HTTPS and local paths.
pub fn remote_host(url: &str) -> Option<&str> {
    let url = url.trim();
    if let Some(rest) = url
        .strip_prefix("ssh://")
        .or_else(|| url.strip_prefix("git+ssh://"))
        .or_else(|| url.strip_prefix("ssh+git://"))
    {
        let authority = rest.split('/').next()?;
        let host = authority.rsplit('@').next()?;
        let host = if let Some(inner) = host.strip_prefix('[') {
            inner.split(']').next()?
        } else {
            host.split(':').next()?
        };
        return (!host.is_empty()).then_some(host);
    }
    if url.contains("://") || url.starts_with('/') || url.starts_with('.') {
        return None;
    }
    // scp-like: `[user@]host:path`, where the host has no `/`.
    let (before, _) = url.split_once(':')?;
    let host = before.rsplit('@').next()?;
    let fine = !host.is_empty()
        && !host.contains(['/', '\\'])
        // `C:\…` on Windows is a path.
        && host.len() > 1;
    fine.then_some(host)
}

/// The suggestions for `sources`, without what the user `declined`: most
/// members first.
pub fn suggest(sources: &Sources<'_>, declined: &Declined) -> Vec<ProjectSuggestion> {
    let mut candidates: Vec<ProjectSuggestion> = Vec::new();
    environments(sources, &mut candidates);
    repositories(sources, &mut candidates);
    keepass(sources, &mut candidates);
    jumps(sources, &mut candidates);
    prefixes(sources, &mut candidates);
    domains(sources, &mut candidates);

    let mut by_key: BTreeMap<String, ProjectSuggestion> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();
    for candidate in candidates {
        if let Some(found) = by_key.get_mut(&candidate.key) {
            found.take(candidate);
        } else {
            order.push(candidate.key.clone());
            by_key.insert(candidate.key.clone(), candidate);
        }
    }

    let taken = Taken::of(sources.projects);
    let mut colors: Vec<ProjectColor> = sources.projects.iter().map(|p| p.color).collect();
    let mut suggestions: Vec<ProjectSuggestion> = order
        .into_iter()
        .filter(|key| !declined.keys.contains(key))
        .filter_map(|key| by_key.remove(&key))
        .filter_map(|mut suggestion| {
            let existing = sources
                .projects
                .iter()
                .find(|p| key(&p.name) == suggestion.key);
            if let Some(project) = existing {
                suggestion.existing = Some(project.id.clone());
                suggestion.name.clone_from(&project.name);
                suggestion.color = project.color;
            }
            suggestion.retain_valid();
            taken.drop_from(&mut suggestion);
            if let Some(left_out) = declined.members.get(&suggestion.key) {
                suggestion.drop_declined(left_out);
            }
            // Hosts alike only by name or place: two at least.
            let worth = if suggestion.reasons.iter().all(only_hosts) {
                suggestion.hosts.len() >= 2
            } else {
                suggestion.members() > 0
            };
            worth.then_some(suggestion)
        })
        .collect();
    suggestions.sort_by_cached_key(|s| (std::cmp::Reverse(s.members()), s.name.to_lowercase()));
    suggestions.truncate(MAX_SUGGESTIONS);
    for suggestion in &mut suggestions {
        if suggestion.existing.is_none() {
            suggestion.color = ProjectColor::next(colors.iter().copied());
            colors.push(suggestion.color);
        }
    }
    suggestions
}

fn only_hosts(reason: &SuggestionReason) -> bool {
    matches!(
        reason,
        SuggestionReason::ProxyJump { .. }
            | SuggestionReason::NamePrefix { .. }
            | SuggestionReason::Domain { .. }
    )
}

/// What projects hold already.
struct Taken {
    folders: BTreeSet<String>,
    hosts: BTreeSet<String>,
    keys: BTreeSet<String>,
    environments: BTreeSet<String>,
    logins: BTreeSet<String>,
}

impl Taken {
    fn of(projects: &[Project]) -> Self {
        let all = |pick: fn(&Project) -> &Vec<String>| {
            projects
                .iter()
                .flat_map(|p| pick(p).iter().cloned())
                .collect::<BTreeSet<String>>()
        };
        Self {
            folders: all(|p| &p.folders),
            hosts: all(|p| &p.hosts),
            keys: all(|p| &p.keys),
            environments: all(|p| &p.environments),
            logins: all(|p| &p.logins),
        }
    }

    fn drop_from(&self, suggestion: &mut ProjectSuggestion) {
        suggestion.folders.retain(|v| !self.folders.contains(v));
        suggestion.hosts.retain(|v| !self.hosts.contains(v));
        suggestion.keys.retain(|v| !self.keys.contains(v));
        suggestion
            .environments
            .retain(|v| !self.environments.contains(v));
        suggestion.logins.retain(|v| !self.logins.contains(v));
    }
}

fn environments(sources: &Sources<'_>, out: &mut Vec<ProjectSuggestion>) {
    for group in sources.environment_groups {
        if let Some(mut c) = candidate(
            group,
            SuggestionReason::Environments {
                group: group.clone(),
            },
        ) {
            c.environments.push(group.clone());
            out.push(c);
        }
    }
}

fn repositories(sources: &Sources<'_>, out: &mut Vec<ProjectSuggestion>) {
    for repository in sources.repositories {
        let Some(name) = repository.folder.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Ok(folder) = folder_text(&repository.folder, sources.home) else {
            continue;
        };
        let Some(mut c) = candidate(
            name,
            SuggestionReason::GitFolder {
                folder: folder.clone(),
            },
        ) else {
            continue;
        };
        c.folders.push(folder);
        for url in &repository.remotes {
            let Some(host) = remote_host(url) else {
                continue;
            };
            if CODE_HOSTS
                .iter()
                .any(|code| code.eq_ignore_ascii_case(host))
            {
                continue;
            }
            if let Some(facts) = sources.hosts.iter().find(|h| h.alias == host) {
                if !c.hosts.contains(&facts.alias) {
                    c.hosts.push(facts.alias.clone());
                }
                for key in &facts.keys {
                    if !c.keys.contains(key) {
                        c.keys.push(key.clone());
                    }
                }
            }
        }
        out.push(c);
    }
}

fn keepass(sources: &Sources<'_>, out: &mut Vec<ProjectSuggestion>) {
    let mut groups: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
    let mut tags: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
    for login in sources.logins {
        if let Some(top) = login
            .group
            .as_deref()
            .and_then(|g| g.split('/').next())
            .map(str::trim)
            .filter(|top| {
                !top.is_empty() && !KEEPASS_STARTER_GROUPS.contains(&top.to_lowercase().as_str())
            })
        {
            groups
                .entry(top.to_lowercase())
                .or_insert_with(|| (top.to_owned(), Vec::new()))
                .1
                .push(login.id.clone());
        }
        for tag in login
            .tags
            .iter()
            .map(|t| t.trim())
            .filter(|t| !t.is_empty())
        {
            let ids = &mut tags
                .entry(tag.to_lowercase())
                .or_insert_with(|| (tag.to_owned(), Vec::new()))
                .1;
            if !ids.contains(&login.id) {
                ids.push(login.id.clone());
            }
        }
    }
    for (name, ids) in groups.into_values() {
        if let Some(mut c) = candidate(
            &name,
            SuggestionReason::KeepassGroup {
                group: name.clone(),
            },
        ) {
            c.logins = ids;
            out.push(c);
        }
    }
    for (name, ids) in tags.into_values() {
        if let Some(mut c) = candidate(&name, SuggestionReason::KeepassTag { tag: name.clone() }) {
            c.logins = ids;
            out.push(c);
        }
    }
}

/// The name hosts share: a common first word of their aliases, else a
/// common domain.
fn shared_name(hosts: &[&HostFacts]) -> Option<String> {
    let first = hosts.first()?;
    if let Some(word) = prefix(&first.alias) {
        let word_key = word.to_lowercase();
        if hosts
            .iter()
            .all(|h| prefix(&h.alias).is_some_and(|p| p.to_lowercase() == word_key))
        {
            return Some(word.to_owned());
        }
    }
    let shared = domain(first.host_name.as_deref()?)?;
    hosts
        .iter()
        .all(|h| h.host_name.as_deref().and_then(domain).as_ref() == Some(&shared))
        .then(|| domain_label(&shared))
}

/// `acme` for `acme.com`.
fn domain_label(domain: &str) -> String {
    domain.split('.').next().unwrap_or(domain).to_owned()
}

fn jumps(sources: &Sources<'_>, out: &mut Vec<ProjectSuggestion>) {
    let mut behind: BTreeMap<&str, Vec<&HostFacts>> = BTreeMap::new();
    for host in sources.hosts.iter().filter(|h| !is_code_host(h)) {
        if let Some(jump) = host.proxy_jump.as_deref().and_then(first_jump)
            && jump != host.alias
        {
            behind.entry(jump).or_default().push(host);
        }
    }
    for (jump, hosts) in behind {
        let bastion = sources.hosts.iter().find(|h| h.alias == jump);
        let mut all: Vec<&HostFacts> = bastion.into_iter().collect();
        all.extend(hosts.iter().copied());
        let name = shared_name(&hosts)
            .or_else(|| shared_name(&all))
            .unwrap_or_else(|| jump.to_owned());
        let Some(mut c) = candidate(
            &name,
            SuggestionReason::ProxyJump {
                bastion: jump.to_owned(),
            },
        ) else {
            continue;
        };
        c.hosts = all.iter().map(|h| h.alias.clone()).collect();
        out.push(c);
    }
}

fn prefixes(sources: &Sources<'_>, out: &mut Vec<ProjectSuggestion>) {
    let mut groups: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
    for host in sources.hosts.iter().filter(|h| !is_code_host(h)) {
        if let Some(prefix) = prefix(&host.alias) {
            groups
                .entry(prefix.to_lowercase())
                .or_insert_with(|| (prefix.to_owned(), Vec::new()))
                .1
                .push(host.alias.clone());
        }
    }
    for (prefix, aliases) in groups.into_values() {
        if aliases.len() < 2 {
            continue;
        }
        if let Some(mut c) = candidate(
            &prefix,
            SuggestionReason::NamePrefix {
                prefix: prefix.clone(),
            },
        ) {
            c.hosts = aliases;
            out.push(c);
        }
    }
}

fn domains(sources: &Sources<'_>, out: &mut Vec<ProjectSuggestion>) {
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for host in sources.hosts {
        if let Some(domain) = host.host_name.as_deref().and_then(domain) {
            groups.entry(domain).or_default().push(host.alias.clone());
        }
    }
    for (domain, aliases) in groups {
        if aliases.len() < 2 {
            continue;
        }
        if let Some(mut c) = candidate(
            &domain_label(&domain),
            SuggestionReason::Domain {
                domain: domain.clone(),
            },
        ) {
            c.hosts = aliases;
            out.push(c);
        }
    }
}

/// Finds Git working trees in `roots` and the folders below them, up to
/// [`MAX_DEPTH`] deep, without going into hidden folders, symbolic links
/// or build output; a working tree's own subfolders aren't searched.
/// Reads only each one's `.git/config`, for its remotes.
pub fn find_repositories(roots: &[PathBuf]) -> Vec<Repository> {
    let mut found = Vec::new();
    let mut seen = 0usize;
    // `code` and `Code` are one folder on a disk that ignores case, and a
    // root may be a link: each is searched once, by its real path, so the
    // working trees come with the names they have on disk.
    let mut canonical_roots: Vec<PathBuf> = Vec::new();
    for root in roots.iter().filter_map(|root| canonical(root)) {
        if !canonical_roots.contains(&root) {
            canonical_roots.push(root);
        }
    }
    let mut queue: std::collections::VecDeque<(PathBuf, usize)> =
        canonical_roots.into_iter().map(|root| (root, 0)).collect();
    let mut visited: BTreeSet<PathBuf> = BTreeSet::new();
    while let Some((folder, depth)) = queue.pop_front() {
        if seen >= MAX_FOLDERS_SEEN || found.len() >= MAX_REPOSITORIES {
            break;
        }
        if !visited.insert(folder.clone()) {
            continue;
        }
        seen += 1;
        let git = folder.join(".git");
        if let Ok(meta) = std::fs::symlink_metadata(&git) {
            let remotes = if meta.is_dir() {
                read_remotes(&git.join("config"))
            } else {
                Vec::new()
            };
            found.push(Repository { folder, remotes });
            continue;
        }
        if depth >= MAX_DEPTH {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&folder) else {
            continue;
        };
        let mut children: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_ok_and(|t| t.is_dir()))
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|name| !name.starts_with('.') && !SKIPPED.contains(&name))
            })
            .collect();
        children.sort();
        queue.extend(children.into_iter().map(|child| (child, depth + 1)));
    }
    found
}

/// A folder's real path: links followed, names as the disk has them, and
/// on Windows without the `\\?\` prefix where a drive letter does.
pub fn canonical(path: &Path) -> Option<PathBuf> {
    let real = std::fs::canonicalize(path).ok()?;
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        let mut components = real.components();
        if let Some(Component::Prefix(prefix)) = components.next()
            && let Prefix::VerbatimDisk(letter) = prefix.kind()
        {
            let mut plain = PathBuf::from(format!("{}:\\", char::from(letter)));
            plain.extend(components.filter(|c| !matches!(c, Component::RootDir)));
            return Some(plain);
        }
    }
    Some(real)
}

/// The `url`s of the `[remote "…"]` sections of a Git config file. Only a
/// regular file is read, and no more than [`MAX_GIT_CONFIG`] bytes of it:
/// a pipe or a device there would never end.
fn read_remotes(config: &Path) -> Vec<String> {
    use std::io::Read as _;
    let Ok(meta) = std::fs::symlink_metadata(config) else {
        return Vec::new();
    };
    if !meta.is_file() || meta.len() > MAX_GIT_CONFIG {
        return Vec::new();
    }
    let Ok(file) = std::fs::File::open(config) else {
        return Vec::new();
    };
    let mut bytes = Vec::new();
    if file
        .take(MAX_GIT_CONFIG + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > MAX_GIT_CONFIG
    {
        return Vec::new();
    }
    let Ok(text) = String::from_utf8(bytes) else {
        return Vec::new();
    };
    let mut in_remote = false;
    let mut urls = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_remote = line.to_lowercase().starts_with("[remote ");
            continue;
        }
        if !in_remote {
            continue;
        }
        if let Some((name, value)) = line.split_once('=')
            && name.trim().eq_ignore_ascii_case("url")
        {
            let value = value.trim().trim_matches('"').to_owned();
            if !value.is_empty() && !urls.contains(&value) {
                urls.push(value);
            }
        }
    }
    urls
}

#[cfg(test)]
mod tests;
