//! Health checks of the vault's entries.
//!
//! Like [`crate::audit`], findings carry a machine-readable kind with
//! parameters, so the UI renders and localises them, and a stable `id`, so a
//! dismissal is remembered. They never contain a password: reused passwords
//! are found by comparing them in memory and reported as entry ids.
//!
//! | Rule | Severity |
//! |---|---|
//! | password guessed almost at once (zxcvbn score 0) | critical |
//! | password seen in known data breaches (when checked, see [`BreachCache`]) | critical |
//! | weak password (zxcvbn score 1) | warning |
//! | the same password in several entries | warning |
//! | password unchanged for more than a year | info |
//! | key entry whose key is not in `~/.ssh` | info |
//! | host entry whose alias is not in `~/.ssh/config` | info |
//! | host entry, i.e. a password login (a key is safer) | info |
//!
//! Entries in the recycle bin are skipped. The password rules also skip
//! entries without a password and entries KeePass excludes from its quality
//! check.

use std::collections::HashMap;

use chrono::NaiveDateTime;
use keepass::db::{EntryRef, Times, fields};
use secrecy::SecretString;
use serde::Serialize;

use super::{BreachCache, EntryKind, Vault, password_changed, rfc3339, strength};
use crate::audit::Severity;
use crate::config::{HostEntry, HostKind};
use crate::keys::KeyInfo;

/// A password is old after this many days.
const OLD_AFTER_DAYS: i64 = 365;
/// zxcvbn scores up to this one count as weak.
const WEAK_SCORE: u8 = 1;

/// What the vault is checked against.
#[derive(Debug, Clone, Copy)]
pub struct VaultAuditInput<'a> {
    /// Keys in `~/.ssh` ([`crate::keys::scan`]).
    pub keys: &'a [KeyInfo],
    /// Blocks of `~/.ssh/config` ([`crate::config::SshConfig::hosts`]).
    pub hosts: &'a [HostEntry],
    /// The current time, UTC.
    pub now: NaiveDateTime,
    /// Results of the breach check, if it is on.
    pub breaches: Option<&'a BreachCache>,
}

impl<'a> VaultAuditInput<'a> {
    /// An input for checking now.
    pub fn new(keys: &'a [KeyInfo], hosts: &'a [HostEntry]) -> Self {
        Self {
            keys,
            hosts,
            now: Times::now(),
            breaches: None,
        }
    }
}

/// What was found, with its parameters. Never a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum VaultFindingKind {
    /// zxcvbn rates the password [`WEAK_SCORE`] or lower.
    WeakPassword {
        /// 0 (guessed almost at once) or 1.
        score: u8,
    },
    /// Several entries share one password.
    ReusedPassword {
        /// All entries with it, sorted by title.
        entry_ids: Vec<String>,
    },
    /// The password has not changed for more than a year.
    OldPassword {
        /// When it was set, RFC 3339 UTC.
        changed: String,
        /// Whole years since then, at least 1.
        years: u32,
    },
    /// A key entry whose fingerprint matches no key in `~/.ssh`.
    KeyNotFound {
        /// The entry's `SHA256:…` fingerprint.
        fingerprint: String,
    },
    /// A host entry whose alias is not a `Host` in `~/.ssh/config`.
    HostNotFound {
        /// The entry's alias.
        host: String,
    },
    /// A host entry: the host is logged in to with a password, where a key
    /// would be safer.
    PasswordLogin {
        /// The entry's alias.
        host: String,
    },
    /// The password appears in known data breaches (Have I Been Pwned).
    BreachedPassword {
        /// How many times it was seen there.
        count: u32,
    },
}

/// One finding about the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct VaultFinding {
    /// Stable id, e.g. `weakPassword:<entry id>`.
    pub id: String,
    pub severity: Severity,
    pub kind: VaultFindingKind,
    /// The entry it is about; for a reused password the first of the group.
    pub entry_id: String,
    /// The key in `~/.ssh` the entry holds the passphrase of ([`KeyInfo::id`]).
    pub key_id: Option<String>,
    /// The `Host` block the entry holds the password of ([`HostEntry::id`]).
    pub host_id: Option<u32>,
}

/// An entry as the rules see it.
struct Checked<'a> {
    id: String,
    title: String,
    username: String,
    kind: EntryKind,
    host: Option<String>,
    fingerprint: Option<String>,
    /// The password is read from here, so it is never copied around.
    entry: EntryRef<'a>,
    changed: Option<NaiveDateTime>,
    key_id: Option<String>,
    host_id: Option<u32>,
}

impl Checked<'_> {
    fn password(&self) -> &str {
        self.entry.get(fields::PASSWORD).unwrap_or_default()
    }

    fn checks_password(&self) -> bool {
        !self.password().is_empty() && self.entry.quality_check
    }

    fn finding(&self, rule: &str, severity: Severity, kind: VaultFindingKind) -> VaultFinding {
        VaultFinding {
            id: format!("{rule}:{}", self.id),
            severity,
            kind,
            entry_id: self.id.clone(),
            key_id: self.key_id.clone(),
            host_id: self.host_id,
        }
    }
}

impl Vault {
    /// Checks every entry outside the recycle bin. Findings come most severe
    /// first, then by id.
    pub fn audit(&self, input: &VaultAuditInput<'_>) -> Vec<VaultFinding> {
        let entries: Vec<Checked<'_>> = self
            .db
            .iter_all_entries()
            .filter_map(|entry| {
                let summary = self.summary(&entry);
                if summary.in_trash {
                    return None;
                }
                let history = entry.history.as_ref().map(|h| h.get_entries().as_slice());
                let changed = password_changed(&entry, history.unwrap_or_default());
                Some(Checked {
                    key_id: summary
                        .key_fingerprint
                        .as_deref()
                        .filter(|_| summary.kind == EntryKind::Key)
                        .and_then(|fp| key_for(input.keys, fp)),
                    host_id: summary
                        .host
                        .as_deref()
                        .filter(|_| summary.kind == EntryKind::Host)
                        .and_then(|alias| host_for(input.hosts, alias)),
                    id: summary.id,
                    title: summary.title,
                    username: summary.username,
                    kind: summary.kind,
                    host: summary.host,
                    fingerprint: summary.key_fingerprint,
                    entry,
                    changed,
                })
            })
            .collect();

        let mut findings = Vec::new();
        for entry in &entries {
            link_findings(entry, &mut findings);
            if entry.checks_password() {
                password_findings(entry, input.now, &mut findings);
                if let Some(count) = input
                    .breaches
                    .and_then(|cache| cache.count(entry.password()))
                    .filter(|&count| count > 0)
                {
                    findings.push(entry.finding(
                        "breachedPassword",
                        Severity::Critical,
                        VaultFindingKind::BreachedPassword { count },
                    ));
                }
            }
        }
        reuse_findings(&entries, &mut findings);
        findings.sort_by(|a, b| a.severity.cmp(&b.severity).then_with(|| a.id.cmp(&b.id)));
        findings
    }
}

fn link_findings(entry: &Checked<'_>, out: &mut Vec<VaultFinding>) {
    let (rule, kind) = match (entry.kind, &entry.fingerprint, &entry.host) {
        (EntryKind::Key, Some(fingerprint), _) if entry.key_id.is_none() => (
            "keyNotFound",
            VaultFindingKind::KeyNotFound {
                fingerprint: fingerprint.clone(),
            },
        ),
        (EntryKind::Host, _, Some(host)) if entry.host_id.is_none() => (
            "hostNotFound",
            VaultFindingKind::HostNotFound { host: host.clone() },
        ),
        // Suggesting a key only makes sense for a host that exists.
        (EntryKind::Host, _, Some(host)) if !entry.password().is_empty() => (
            "passwordLogin",
            VaultFindingKind::PasswordLogin { host: host.clone() },
        ),
        _ => return,
    };
    out.push(entry.finding(rule, Severity::Info, kind));
}

fn password_findings(entry: &Checked<'_>, now: NaiveDateTime, out: &mut Vec<VaultFinding>) {
    let context: Vec<&str> = [entry.title.as_str(), entry.username.as_str()]
        .into_iter()
        .filter(|word| !word.is_empty())
        .collect();
    let score = strength(&SecretString::from(entry.password()), &context).score;
    if score <= WEAK_SCORE {
        let severity = if score == 0 {
            Severity::Critical
        } else {
            Severity::Warning
        };
        out.push(entry.finding(
            "weakPassword",
            severity,
            VaultFindingKind::WeakPassword { score },
        ));
    }
    if let Some(changed) = entry.changed {
        let days = now.signed_duration_since(changed).num_days();
        if days > OLD_AFTER_DAYS {
            out.push(entry.finding(
                "oldPassword",
                Severity::Info,
                VaultFindingKind::OldPassword {
                    changed: rfc3339(changed),
                    years: u32::try_from(days / OLD_AFTER_DAYS).unwrap_or(u32::MAX),
                },
            ));
        }
    }
}

/// One finding per group of entries that share a password.
fn reuse_findings(entries: &[Checked<'_>], out: &mut Vec<VaultFinding>) {
    let mut groups: HashMap<&str, Vec<&Checked<'_>>> = HashMap::new();
    for entry in entries.iter().filter(|e| e.checks_password()) {
        groups.entry(entry.password()).or_default().push(entry);
    }
    let mut groups: Vec<Vec<&Checked<'_>>> = groups.into_values().filter(|g| g.len() > 1).collect();
    for group in &mut groups {
        group.sort_by_cached_key(|e| (e.title.to_lowercase(), e.id.clone()));
    }
    for group in groups {
        // The id stays the same while the group's oldest member is in it,
        // whatever titles are changed or added.
        let anchor = group
            .iter()
            .map(|e| e.id.as_str())
            .min()
            .unwrap_or_default();
        let first = group[0];
        out.push(VaultFinding {
            id: format!("reusedPassword:{anchor}"),
            severity: Severity::Warning,
            kind: VaultFindingKind::ReusedPassword {
                entry_ids: group.iter().map(|e| e.id.clone()).collect(),
            },
            entry_id: first.id.clone(),
            key_id: first.key_id.clone(),
            host_id: first.host_id,
        });
    }
}

/// The key in `~/.ssh` with this fingerprint, preferring one with a private
/// key (the passphrase is useless without it).
fn key_for(keys: &[KeyInfo], fingerprint: &str) -> Option<String> {
    let mut matching = keys
        .iter()
        .filter(|k| k.fingerprint.as_deref() == Some(fingerprint));
    let first = matching.clone().next()?;
    Some(
        matching
            .find(|k| k.private_path.is_some())
            .unwrap_or(first)
            .id
            .clone(),
    )
}

/// The `Host` block that names this alias (not as a negated or wildcard
/// pattern). ssh compares host names without regard to case.
fn host_for(hosts: &[HostEntry], alias: &str) -> Option<u32> {
    hosts
        .iter()
        .filter(|h| h.kind == HostKind::Host)
        .find(|h| h.patterns.iter().any(|p| p.eq_ignore_ascii_case(alias)))
        .map(|h| h.id)
}

#[cfg(test)]
mod tests {
    use chrono::TimeDelta;
    use tempfile::TempDir;

    use super::*;
    use crate::config::SshConfig;
    use crate::keys::{KeyAlgorithm, KeyFormat};
    use crate::perms::{PermKind, evaluate_mode};
    use crate::vault::{EntryInput, VaultPaths, parse_id};

    struct Fixture {
        _dir: TempDir,
        vault: Vault,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("vault.kdbx"));
        let (vault, _) = Vault::create(&paths, &SecretString::from("master")).unwrap();
        Fixture { _dir: dir, vault }
    }

    fn add(vault: &mut Vault, input: &EntryInput) -> String {
        vault.add_entry(input).unwrap()
    }

    fn login(title: &str, password: &str) -> EntryInput {
        EntryInput {
            title: title.into(),
            username: "me@example.com".into(),
            password: Some(SecretString::from(password)),
            ..EntryInput::default()
        }
    }

    fn key_entry(title: &str, fingerprint: &str, password: &str) -> EntryInput {
        EntryInput {
            kind: EntryKind::Key,
            key_fingerprint: Some(fingerprint.into()),
            ..login(title, password)
        }
    }

    fn host_entry(alias: &str, password: &str) -> EntryInput {
        EntryInput {
            kind: EntryKind::Host,
            host: Some(alias.into()),
            ..login(alias, password)
        }
    }

    fn key(name: &str, fingerprint: &str, private: bool) -> KeyInfo {
        KeyInfo {
            id: format!("{fingerprint}#{name}"),
            name: name.into(),
            private_path: private.then(|| format!("/h/.ssh/{name}")),
            public_path: Some(format!("/h/.ssh/{name}.pub")),
            algorithm: KeyAlgorithm::Ed25519,
            key_type: "ssh-ed25519".into(),
            bits: Some(256),
            fingerprint: Some(fingerprint.into()),
            comment: String::new(),
            encrypted: Some(true),
            hardware: false,
            format: KeyFormat::Openssh,
            public_key: None,
            modified: None,
            pair_mismatch: false,
            permissions: evaluate_mode(0o600, PermKind::PrivateKey),
        }
    }

    fn run(vault: &Vault, keys: &[KeyInfo], hosts: &[HostEntry]) -> Vec<VaultFinding> {
        vault.audit(&VaultAuditInput::new(keys, hosts))
    }

    fn ids(findings: &[VaultFinding]) -> Vec<String> {
        let mut ids: Vec<String> = findings.iter().map(|f| f.id.clone()).collect();
        ids.sort();
        ids
    }

    const STRONG: &str = "Vq7#mZ2!pL9@xR4$";

    #[test]
    fn a_healthy_vault_has_no_findings() {
        let mut fx = fixture();
        add(&mut fx.vault, &login("GitHub", STRONG));
        add(&mut fx.vault, &login("Mail", "kV9#pL2!mZ7qR4xT"));
        assert_eq!(run(&fx.vault, &[], &[]), []);
    }

    #[test]
    fn breached_passwords_are_found_once_checked() {
        use sha1::{Digest, Sha1};
        fn input(cache: &BreachCache) -> VaultAuditInput<'_> {
            VaultAuditInput {
                breaches: Some(cache),
                ..VaultAuditInput::new(&[], &[])
            }
        }
        let mut fx = fixture();
        let github = add(&mut fx.vault, &login("GitHub", STRONG));
        add(&mut fx.vault, &login("Mail", "kV9#pL2!mZ7qR4xT"));
        let mut cache = BreachCache::new();
        assert_eq!(fx.vault.audit(&input(&cache)), []);

        let hash = format!("{:X}", Sha1::digest(STRONG.as_bytes()));
        let mut query = fx.vault.breach_query(&cache, None);
        for prefix in query.prefixes() {
            let body = if hash.starts_with(prefix.as_str()) {
                format!("{}:42\r\n", &hash[5..])
            } else {
                String::new()
            };
            query
                .answer(&prefix, &body, &mut cache, std::time::Instant::now())
                .unwrap();
        }
        let findings = fx.vault.audit(&input(&cache));
        assert_eq!(ids(&findings), [format!("breachedPassword:{github}")]);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(
            findings[0].kind,
            VaultFindingKind::BreachedPassword { count: 42 }
        );
        // Not without the check's results.
        assert_eq!(run(&fx.vault, &[], &[]), []);
    }

    #[test]
    fn weak_passwords_are_rated_with_the_title_and_user_name() {
        let mut fx = fixture();
        let guessable = add(&mut fx.vault, &login("AWS console", "password"));
        // Strong on its own, but it is the user name.
        let name = "nuriddinyuldashev";
        assert!(strength(&SecretString::from(name), &[]).score > WEAK_SCORE);
        let named = add(
            &mut fx.vault,
            &EntryInput {
                username: name.into(),
                ..login("Forum", name)
            },
        );
        add(&mut fx.vault, &login("Strong", STRONG));
        let findings = run(&fx.vault, &[], &[]);
        let mut expected = vec![
            format!("weakPassword:{guessable}"),
            format!("weakPassword:{named}"),
        ];
        expected.sort();
        assert_eq!(ids(&findings), expected);
        let first = findings.iter().find(|f| f.entry_id == guessable).unwrap();
        assert_eq!(first.severity, Severity::Critical);
        assert_eq!(first.kind, VaultFindingKind::WeakPassword { score: 0 });
    }

    #[test]
    fn reused_passwords_form_one_group_without_trash_or_empty_ones() {
        let mut fx = fixture();
        let router = add(&mut fx.vault, &login("Router admin", STRONG));
        let aws = add(&mut fx.vault, &login("AWS console", STRONG));
        let trashed = add(&mut fx.vault, &login("Old forum", STRONG));
        fx.vault.trash_entry(&trashed).unwrap();
        add(&mut fx.vault, &login("Blank one", ""));
        add(&mut fx.vault, &login("Blank two", ""));
        add(&mut fx.vault, &login("Unique", "kV9#pL2!mZ7qR4xT"));

        let findings = run(&fx.vault, &[], &[]);
        assert_eq!(findings.len(), 1, "{findings:?}");
        let reused = &findings[0];
        assert_eq!(reused.severity, Severity::Warning);
        assert_eq!(
            reused.id,
            format!("reusedPassword:{}", router.clone().min(aws.clone()))
        );
        assert_eq!(reused.entry_id, aws);
        assert_eq!(
            reused.kind,
            VaultFindingKind::ReusedPassword {
                entry_ids: vec![aws, router]
            }
        );
    }

    #[test]
    fn passwords_older_than_a_year_are_reported_once_changed_is_known() {
        let mut fx = fixture();
        let old = add(&mut fx.vault, &login("Old", STRONG));
        let fresh = add(&mut fx.vault, &login("Fresh", "kV9#pL2!mZ7qR4xT"));
        let two_years_ago = Times::now() - TimeDelta::days(2 * 365 + 10);
        fx.vault
            .db
            .entry_mut(parse_id(&old).unwrap())
            .unwrap()
            .times
            .last_modification = Some(two_years_ago);

        let findings = run(&fx.vault, &[], &[]);
        assert_eq!(ids(&findings), [format!("oldPassword:{old}")]);
        assert_eq!(
            findings[0].kind,
            VaultFindingKind::OldPassword {
                changed: rfc3339(two_years_ago),
                years: 2
            }
        );
        assert!(findings.iter().all(|f| f.entry_id != fresh));
    }

    #[test]
    fn entries_excluded_from_quality_checks_are_skipped() {
        let mut fx = fixture();
        let id = add(&mut fx.vault, &login("Printer", "1234"));
        fx.vault
            .db
            .entry_mut(parse_id(&id).unwrap())
            .unwrap()
            .quality_check = false;
        assert_eq!(run(&fx.vault, &[], &[]), []);
    }

    #[test]
    fn key_entries_are_matched_to_keys_in_the_ssh_folder() {
        let mut fx = fixture();
        let present = add(
            &mut fx.vault,
            &key_entry(
                "id_ed25519",
                "SHA256:present",
                "Tundra-Velvet-Rocket-Mango7",
            ),
        );
        let gone = add(
            &mut fx.vault,
            &key_entry("old_key", "SHA256:gone", "Harbor-Pixel-Quartz-Lantern4"),
        );
        let keys = [
            key("id_ed25519.pub-only", "SHA256:present", false),
            key("id_ed25519", "SHA256:present", true),
        ];
        let findings = run(&fx.vault, &keys, &[]);
        assert_eq!(ids(&findings), [format!("keyNotFound:{gone}")]);
        assert_eq!(
            findings[0].kind,
            VaultFindingKind::KeyNotFound {
                fingerprint: "SHA256:gone".into()
            }
        );

        // A weak passphrase points at the key it protects.
        fx.vault
            .update_entry(
                &present,
                &key_entry("id_ed25519", "SHA256:present", "123456"),
            )
            .unwrap();
        let weak = run(&fx.vault, &keys, &[])
            .into_iter()
            .find(|f| f.entry_id == present)
            .unwrap();
        assert_eq!(weak.key_id.as_deref(), Some("SHA256:present#id_ed25519"));
    }

    #[test]
    fn host_entries_suggest_keys_or_report_a_missing_alias() {
        let mut fx = fixture();
        let known = add(&mut fx.vault, &host_entry("prod-api", STRONG));
        let missing = add(&mut fx.vault, &host_entry("old-vpn", "kV9#pL2!mZ7qR4xT"));
        // Only a `Match` block names it, which is not a `Host` alias.
        let matched = add(&mut fx.vault, &host_entry("no-password", ""));
        let hosts = SshConfig::parse(
            "Host *.corp\n  User me\n\nHost bastion PROD-API\n  HostName 10.0.4.12\n\nMatch host no-password\n  User x\n",
        )
        .hosts();

        let findings = run(&fx.vault, &[], &hosts);
        let mut expected = vec![
            format!("hostNotFound:{missing}"),
            format!("hostNotFound:{matched}"),
            format!("passwordLogin:{known}"),
        ];
        expected.sort();
        assert_eq!(ids(&findings), expected);
        let login = findings.iter().find(|f| f.entry_id == known).unwrap();
        assert_eq!(login.host_id, Some(1));
        assert_eq!(
            login.kind,
            VaultFindingKind::PasswordLogin {
                host: "prod-api".into()
            }
        );
    }

    #[test]
    fn findings_never_contain_a_password() {
        let mut fx = fixture();
        let secrets = ["password123", "Tundra-Velvet-Rocket-Mango7", "hunter2"];
        add(&mut fx.vault, &login("A", secrets[0]));
        add(&mut fx.vault, &login("B", secrets[0]));
        add(&mut fx.vault, &key_entry("k", "SHA256:x", secrets[1]));
        add(&mut fx.vault, &host_entry("h", secrets[2]));
        let findings = run(&fx.vault, &[], &[]);
        // Weak A, B and h, A and B reused, k's key and h's host missing.
        assert_eq!(findings.len(), 6, "{findings:?}");
        let json = serde_json::to_string(&findings).unwrap();
        for secret in secrets {
            assert!(!json.contains(secret), "{secret} leaked");
        }
    }
}
