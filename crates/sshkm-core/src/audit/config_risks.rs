//! Settings of `ssh_config` that make `ssh` check less whether a server is
//! the real one, hand servers the user's keys, or offer more keys than
//! servers accept.
//!
//! Within a section (the options before the first block, or one block) only
//! the first value of a keyword counts, as `ssh` reads it. Each finding is
//! about the section that sets the value; its fix removes that setting, or
//! adds `IdentitiesOnly yes`, and is applied only while the rules still
//! offer it ([`apply_config_fix`]).

use super::{Finding, FindingKind, FindingSubject, FixAction, Severity};
use crate::{
    Error, Result,
    config::{HostEntry, HostKind, HostOption, SshConfig, matches_pattern, split_args},
};

/// Most keys ssh-agent can hold before `ssh` may run out of attempts: servers
/// allow 6 by default (`MaxAuthTries`), and each key offered takes one.
pub const AGENT_KEYS_LIMIT: usize = 5;

/// The options before the first block, or one block.
struct Section {
    /// `None` before the first block.
    host_id: Option<u32>,
    kind: Option<HostKind>,
    /// Host patterns as written (empty for `Match` and the global section).
    patterns: Vec<String>,
    criteria: Option<String>,
    options: Vec<HostOption>,
}

impl Section {
    fn sections(config: &SshConfig) -> Vec<Self> {
        let global = Self {
            host_id: None,
            kind: None,
            patterns: Vec::new(),
            criteria: None,
            options: config.global_options(),
        };
        std::iter::once(global)
            .chain(config.hosts().into_iter().map(Self::block))
            .collect()
    }

    fn block(entry: HostEntry) -> Self {
        Self {
            host_id: Some(entry.id),
            kind: Some(entry.kind),
            patterns: entry.patterns,
            criteria: entry.criteria,
            options: entry.options,
        }
    }

    /// The first `key` (lower case) of the section, which is the one `ssh`
    /// uses, with its arguments.
    fn first(&self, key: &str) -> Option<(&HostOption, Vec<String>)> {
        self.options
            .iter()
            .find(|o| o.key.eq_ignore_ascii_case(key))
            .map(|o| (o, split_args(&o.value).0))
    }

    /// Part of finding ids: the same while the block's header is.
    fn id(&self) -> String {
        match (self.kind, &self.criteria) {
            (None, _) => "global".to_owned(),
            (Some(HostKind::Match), Some(criteria)) => format!("match:{}", criteria.trim()),
            _ => format!("host:{}", self.patterns.join(" ")),
        }
    }

    /// The section may apply to more than a few named hosts: the global
    /// section, a `Host` block with a wildcard pattern, or a `Match` block
    /// that doesn't name its hosts.
    fn is_wildcard(&self) -> bool {
        match self.kind {
            None => true,
            Some(HostKind::Host) => positive(&self.patterns).any(is_wild),
            Some(HostKind::Match) => !match_names_hosts(self.criteria.as_deref().unwrap_or("")),
        }
    }

    /// The section applies to every host `other` applies to.
    fn covers(&self, other: &Self) -> bool {
        match self.kind {
            None => true,
            Some(_) if self.host_id == other.host_id => true,
            Some(HostKind::Match) => self
                .criteria
                .as_deref()
                .is_some_and(|c| c.trim().eq_ignore_ascii_case("all")),
            Some(HostKind::Host) => {
                let ours: Vec<String> = positive(&self.patterns).map(str::to_lowercase).collect();
                let not: Vec<String> = self
                    .patterns
                    .iter()
                    .filter_map(|p| p.strip_prefix('!'))
                    .map(str::to_lowercase)
                    .collect();
                let mut theirs = positive(&other.patterns).map(str::to_lowercase).peekable();
                theirs.peek().is_some()
                    && theirs.all(|name| {
                        if is_wild(&name) {
                            // Only `*` is sure to take in every name a pattern may match.
                            not.is_empty() && ours.iter().any(|p| p == "*")
                        } else {
                            let hit = |p: &String| matches_pattern(p.as_bytes(), name.as_bytes());
                            ours.iter().any(hit) && !not.iter().any(hit)
                        }
                    })
            }
        }
    }

    fn subject(&self, path: Option<&str>) -> FindingSubject {
        FindingSubject {
            host_id: self.host_id,
            path: path.map(str::to_owned),
            ..FindingSubject::default()
        }
    }

    fn removal(&self, option: &HostOption) -> FixAction {
        FixAction::RemoveConfigOption {
            host_id: self.host_id,
            key: option.key.clone(),
            value: option.value.clone(),
        }
    }
}

/// Patterns that are not negated.
fn positive(patterns: &[String]) -> impl Iterator<Item = &str> {
    patterns
        .iter()
        .map(String::as_str)
        .filter(|p| !p.starts_with('!'))
}

fn is_wild(pattern: &str) -> bool {
    pattern.contains(['*', '?'])
}

/// A `Match` line that names its hosts: a `host` or `originalhost`
/// criterion with at least one name and no wildcard, and no `all`. Other
/// criteria only narrow it down.
fn match_names_hosts(criteria: &str) -> bool {
    let args: Vec<String> = split_args(criteria)
        .0
        .iter()
        .map(|a| a.to_ascii_lowercase())
        .collect();
    if args.iter().any(|a| a == "all") {
        return false;
    }
    args.windows(2).any(|pair| {
        (pair[0] == "host" || pair[0] == "originalhost") && {
            let names: Vec<&str> = pair[1].split(',').filter(|n| !n.starts_with('!')).collect();
            !names.is_empty() && !names.iter().any(|n| n.is_empty() || is_wild(n))
        }
    })
}

/// `yes`/`no` as `ssh` reads them: `true` and `false` too, in any case.
fn flag(args: &[String], values: &[&str]) -> bool {
    matches!(args, [one, ..] if values.iter().any(|v| one.eq_ignore_ascii_case(v)))
}

/// `/dev/null`, and on Windows `NUL`: where `ssh` writes nothing and reads
/// no keys.
fn is_null_device(path: &str, windows: bool) -> bool {
    path == "/dev/null" || (windows && path.eq_ignore_ascii_case("nul"))
}

/// A `UserKnownHostsFile` that only names the null device.
fn discards_known_hosts(args: &[String], windows: bool) -> bool {
    !args.is_empty() && args.iter().all(|a| is_null_device(a, windows))
}

/// The findings about the config's settings. `path` is the config file, for
/// the subject; `agent_keys` the number of keys in ssh-agent (`None`:
/// unknown, which skips the `IdentitiesOnly` rule).
pub(super) fn findings(
    config: &SshConfig,
    path: Option<&str>,
    agent_keys: Option<usize>,
) -> Vec<Finding> {
    let sections = Section::sections(config);
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut push = |finding: Finding| {
        if seen.insert(finding.id.clone()) {
            out.push(finding);
        }
    };
    for section in &sections {
        let discarded = section
            .first("userknownhostsfile")
            .filter(|(_, args)| discards_known_hosts(args, cfg!(windows)));
        if let Some((option, args)) = section.first("stricthostkeychecking")
            && flag(&args, &["no", "off", "false"])
        {
            push(Finding {
                id: format!("strictHostKeyCheckingOff:{}", section.id()),
                severity: if discarded.is_some() {
                    Severity::Critical
                } else {
                    Severity::Warning
                },
                kind: FindingKind::StrictHostKeyCheckingOff {
                    value: option.value.clone(),
                    patterns: section.patterns.clone(),
                    known_hosts_discarded: discarded.is_some(),
                },
                subject: section.subject(path),
                fix: Some(section.removal(option)),
            });
        }
        if let Some((option, _)) = discarded {
            push(Finding {
                id: format!("knownHostsDiscarded:{}", section.id()),
                severity: Severity::Warning,
                kind: FindingKind::KnownHostsDiscarded {
                    value: option.value.clone(),
                    patterns: section.patterns.clone(),
                },
                subject: section.subject(path),
                fix: Some(section.removal(option)),
            });
        }
        if let Some((option, args)) = section.first("forwardagent")
            && !args.is_empty()
            && !flag(&args, &["no", "false"])
        {
            let wildcard = section.is_wildcard();
            push(Finding {
                id: format!("agentForwarding:{}", section.id()),
                severity: if wildcard {
                    Severity::Critical
                } else {
                    Severity::Info
                },
                kind: FindingKind::AgentForwarding {
                    value: option.value.clone(),
                    patterns: section.patterns.clone(),
                    wildcard,
                },
                subject: section.subject(path),
                fix: Some(section.removal(option)),
            });
        }
    }
    if let Some(count) = agent_keys.filter(|&n| n > AGENT_KEYS_LIMIT) {
        let lacking = lacking_identities_only(&sections);
        if !lacking.is_empty() {
            push(Finding {
                id: "tooManyAgentKeys".to_owned(),
                severity: Severity::Warning,
                kind: FindingKind::TooManyAgentKeys {
                    agent_keys: u32::try_from(count).unwrap_or(u32::MAX),
                    hosts: lacking.iter().map(|s| s.patterns.join(" ")).collect(),
                },
                subject: FindingSubject {
                    path: path.map(str::to_owned),
                    ..FindingSubject::default()
                },
                fix: Some(FixAction::AddIdentitiesOnly {
                    host_ids: lacking.iter().filter_map(|s| s.host_id).collect(),
                }),
            });
        }
    }
    out
}

/// `Host` blocks with an `IdentityFile` for which `ssh` also offers every
/// key in the agent, and where `IdentitiesOnly yes` added to the block
/// would count: no section that applies to all of the block's hosts sets
/// `IdentitiesOnly` before it or in it (one that turns it off there was
/// turned off on purpose), and none after it turns it on.
///
/// `Host *` is left out (`IdentitiesOnly` there would apply to every host,
/// also those that sign in with a key only the agent has), and so are
/// `Match` blocks and the global section.
fn lacking_identities_only(sections: &[Section]) -> Vec<&Section> {
    sections
        .iter()
        .enumerate()
        .filter(|(_, s)| s.kind == Some(HostKind::Host))
        .filter(|(_, s)| !s.patterns.iter().any(|p| p == "*"))
        .filter(|(_, s)| {
            s.options.iter().any(|o| {
                o.key.eq_ignore_ascii_case("identityfile") && !o.value.eq_ignore_ascii_case("none")
            })
        })
        .filter(|&(index, target)| {
            // The first value in file order of a section that applies to all
            // of the block's hosts, which is the one `ssh` uses.
            let decided = sections.iter().enumerate().find_map(|(at, s)| {
                s.first("identitiesonly")
                    .filter(|_| s.covers(target))
                    .map(|(_, args)| (at, args))
            });
            match decided {
                Some((_, args)) if flag(&args, &["yes", "true"]) => false,
                Some((at, _)) => at > index,
                None => true,
            }
        })
        .map(|(_, s)| s)
        .collect()
}

/// Applies a fix of [`FixAction::RemoveConfigOption`] or
/// [`FixAction::AddIdentitiesOnly`] to `config`, if the rules offer it for
/// `config` now (whatever the number of keys in the agent): so a page can't
/// remove other settings or add `IdentitiesOnly` elsewhere. Returns whether
/// the config changed. Other fixes fail with `unsupported`; one the rules
/// don't offer fails with `invalid_input`.
pub fn apply_config_fix(config: &mut SshConfig, fix: &FixAction) -> Result<bool> {
    match fix {
        FixAction::RemoveConfigOption {
            host_id,
            key,
            value,
        } => {
            let offered = findings(config, None, None)
                .into_iter()
                .any(|f| f.fix.as_ref() == Some(fix));
            if !offered {
                return Err(Error::invalid(format!("no finding offers removing {key}")));
            }
            config.remove_option(*host_id, key, value)
        }
        FixAction::AddIdentitiesOnly { host_ids } => {
            let sections = Section::sections(config);
            let lacking: Vec<u32> = lacking_identities_only(&sections)
                .iter()
                .filter_map(|s| s.host_id)
                .collect();
            let mut ids = host_ids.clone();
            ids.sort_unstable();
            ids.dedup();
            if ids.is_empty() || ids.iter().any(|id| !lacking.contains(id)) {
                return Err(Error::invalid(
                    "IdentitiesOnly is only added to blocks the audit names",
                ));
            }
            for id in ids {
                config.append_option(id, &HostOption::new("IdentitiesOnly", "yes"))?;
            }
            Ok(true)
        }
        _ => Err(Error::Unsupported("this fix is not a config edit".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorCode;

    fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.id.as_str()).collect()
    }

    fn by_id<'a>(findings: &'a [Finding], id: &str) -> &'a Finding {
        findings.iter().find(|f| f.id == id).unwrap()
    }

    #[test]
    fn host_key_checking_and_known_hosts() {
        let config = SshConfig::parse(
            "StrictHostKeyChecking accept-new\n\
             \n\
             Host lab-*\n\
             \tStrictHostKeyChecking no\n\
             \tUserKnownHostsFile /dev/null\n\
             \n\
             Host build\n\
             \tStrictHostKeyChecking=OFF\n\
             \tStrictHostKeyChecking no\n\
             \n\
             Host scratch\n\
             \tUserKnownHostsFile \"/dev/null\"\n\
             \n\
             Host mixed\n\
             \tUserKnownHostsFile /dev/null ~/.ssh/known_hosts\n\
             \tStrictHostKeyChecking yes\n\
             \n\
             Host win\n\
             \tUserKnownHostsFile NUL\n",
        );
        let found = findings(&config, Some("/h/.ssh/config"), None);
        assert_eq!(
            ids(&found),
            [
                "strictHostKeyCheckingOff:host:lab-*",
                "knownHostsDiscarded:host:lab-*",
                "strictHostKeyCheckingOff:host:build",
                "knownHostsDiscarded:host:scratch",
            ]
        );
        let lab = by_id(&found, "strictHostKeyCheckingOff:host:lab-*");
        assert_eq!(lab.severity, Severity::Critical);
        assert_eq!(
            lab.kind,
            FindingKind::StrictHostKeyCheckingOff {
                value: "no".into(),
                patterns: vec!["lab-*".into()],
                known_hosts_discarded: true,
            }
        );
        assert_eq!(
            lab.subject,
            FindingSubject {
                host_id: Some(0),
                path: Some("/h/.ssh/config".into()),
                key_id: None,
            }
        );
        let build = by_id(&found, "strictHostKeyCheckingOff:host:build");
        assert_eq!(build.severity, Severity::Warning);
        // The first value is the one that counts, and the one removed.
        assert_eq!(
            build.fix,
            Some(FixAction::RemoveConfigOption {
                host_id: Some(1),
                key: "StrictHostKeyChecking".into(),
                value: "OFF".into(),
            })
        );
        assert_eq!(
            by_id(&found, "knownHostsDiscarded:host:scratch").severity,
            Severity::Warning
        );

        assert!(is_null_device("NUL", true));
        assert!(is_null_device("nul", true));
        assert!(!is_null_device("NUL", false));
        assert!(discards_known_hosts(
            &["/dev/null".into(), "NUL".into()],
            true
        ));
        assert!(!discards_known_hosts(&[], true));
    }

    #[test]
    fn agent_forwarding_by_reach() {
        let config = SshConfig::parse(
            "Host bastion\n\
             \tForwardAgent yes\n\
             Host web db\n\
             \tForwardAgent ~/.ssh/agent.sock\n\
             Host off\n\
             \tForwardAgent False\n\
             Host *.corp !build.corp\n\
             \tForwardAgent yes\n\
             Match host jump user admin\n\
             \tForwardAgent yes\n\
             Match host *.lab\n\
             \tForwardAgent yes\n\
             Host *\n\
             \tForwardAgent yes\n",
        );
        let found = findings(&config, None, None);
        let severities: Vec<(&str, Severity)> =
            found.iter().map(|f| (f.id.as_str(), f.severity)).collect();
        assert_eq!(
            severities,
            [
                ("agentForwarding:host:bastion", Severity::Info),
                ("agentForwarding:host:web db", Severity::Info),
                (
                    "agentForwarding:host:*.corp !build.corp",
                    Severity::Critical
                ),
                ("agentForwarding:match:host jump user admin", Severity::Info),
                ("agentForwarding:match:host *.lab", Severity::Critical),
                ("agentForwarding:host:*", Severity::Critical),
            ]
        );
        assert_eq!(
            found[1].kind,
            FindingKind::AgentForwarding {
                value: "~/.ssh/agent.sock".into(),
                patterns: vec!["web".into(), "db".into()],
                wildcard: false,
            }
        );

        let global = SshConfig::parse("ForwardAgent yes\nHost a\n\tUser me\n");
        let found = findings(&global, Some("/h/.ssh/config"), None);
        assert_eq!(ids(&found), ["agentForwarding:global"]);
        assert_eq!(found[0].severity, Severity::Critical);
        assert_eq!(found[0].subject.host_id, None);
        assert_eq!(
            found[0].fix,
            Some(FixAction::RemoveConfigOption {
                host_id: None,
                key: "ForwardAgent".into(),
                value: "yes".into(),
            })
        );
        assert!(match_names_hosts("Host a,b"));
        assert!(!match_names_hosts("host !a"));
        assert!(!match_names_hosts("all"));
        assert!(!match_names_hosts("exec true"));
    }

    const IDENTITIES: &str = "\
Host gh github.com
    IdentityFile ~/.ssh/github
Host prod
    IdentityFile ~/.ssh/prod
    IdentitiesOnly yes
Host db.corp
    IdentityFile ~/.ssh/corp
Host web.corp
    IdentitiesOnly no
    IdentityFile ~/.ssh/corp
Host plain
    User me
Host none
    IdentityFile none
Match host x
    IdentityFile ~/.ssh/x
Host build
    IdentityFile ~/.ssh/build
Host *.corp
    IdentitiesOnly yes
Host *
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly no
";

    #[test]
    fn too_many_agent_keys() {
        let config = SshConfig::parse(IDENTITIES);
        assert_eq!(findings(&config, None, None), []);
        assert_eq!(findings(&config, None, Some(AGENT_KEYS_LIMIT)), []);
        let found = findings(&config, Some("/h/.ssh/config"), Some(8));
        assert_eq!(ids(&found), ["tooManyAgentKeys"]);
        // `db.corp` is covered by `*.corp`, and `web.corp` turns it off
        // itself. `Host *` turns it off only after `gh` and `build`, so
        // adding it to them counts.
        assert_eq!(
            found[0].kind,
            FindingKind::TooManyAgentKeys {
                agent_keys: 8,
                hosts: vec!["gh github.com".into(), "build".into()],
            }
        );
        assert_eq!(
            found[0].fix,
            Some(FixAction::AddIdentitiesOnly {
                host_ids: vec![0, 7]
            })
        );

        let covered = SshConfig::parse(&format!("IdentitiesOnly yes\n{IDENTITIES}"));
        assert_eq!(findings(&covered, None, Some(8)), []);
        let star_first = SshConfig::parse(&format!("Host *\n  IdentitiesOnly yes\n{IDENTITIES}"));
        assert_eq!(findings(&star_first, None, Some(8)), []);
    }

    #[test]
    fn fixes_apply_only_when_offered() {
        let mut config = SshConfig::parse(IDENTITIES);
        let made_up = [
            FixAction::AddIdentitiesOnly { host_ids: vec![1] },
            FixAction::AddIdentitiesOnly {
                host_ids: vec![0, 3],
            },
            FixAction::AddIdentitiesOnly { host_ids: vec![] },
            FixAction::AddIdentitiesOnly { host_ids: vec![9] },
            FixAction::RemoveConfigOption {
                host_id: Some(3),
                key: "IdentitiesOnly".into(),
                value: "no".into(),
            },
        ];
        for fix in &made_up {
            let error = apply_config_fix(&mut config, fix).unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidInput, "{fix:?}");
        }
        assert_eq!(
            apply_config_fix(&mut config, &FixAction::TurnOffHostsEntry { line: 1 })
                .unwrap_err()
                .code(),
            ErrorCode::Unsupported
        );
        assert_eq!(config.to_string(), IDENTITIES);

        let fix = findings(&config, None, Some(8))[0].fix.clone().unwrap();
        assert!(apply_config_fix(&mut config, &fix).unwrap());
        assert_eq!(findings(&config, None, Some(8)), []);
        assert!(config.to_string().starts_with(
            "Host gh github.com\n    IdentityFile ~/.ssh/github\n    IdentitiesOnly yes\n"
        ));

        let mut config = SshConfig::parse(
            "Host lab\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n  User me\n",
        );
        for finding in findings(&config.clone(), None, None) {
            assert!(apply_config_fix(&mut config, &finding.fix.unwrap()).unwrap());
        }
        assert_eq!(config.to_string(), "Host lab\n  User me\n");
    }
}
