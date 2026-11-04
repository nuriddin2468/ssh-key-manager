//! Security audit of keys, permissions and `IdentityFile` references.
//!
//! Findings are machine-readable (a kind with parameters plus a subject), so
//! the UI renders and localises them. Each finding has a stable `id` that is
//! the same across runs while the underlying issue persists, so the UI can
//! remember dismissals.
//!
//! | Rule | Severity |
//! |---|---|
//! | DSA key | critical |
//! | RSA < 2048 bits | critical |
//! | RSA < 3072 bits | warning |
//! | private key without passphrase (not for hardware keys) | warning |
//! | private key accessible by others | critical |
//! | `~/.ssh` accessible by others | warning |
//! | config writable by others | critical |
//! | private key without `.pub` | info |
//! | `.pub` without private key | info |
//! | `.pub` does not match its private key | critical |
//! | same key in several files | info |
//! | `IdentityFile` pointing to a missing file | warning |
//! | legacy PEM / PKCS#8 format | info |
//! | hosts file sends a code host elsewhere, or `localhost` off this computer | critical |
//! | hosts file gives a name several addresses | warning |
//! | temporary hosts file entry past its time | warning |

use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{
    Result,
    config::{IdentityUsage, SshConfig},
    hosts_file::{self, HostsAddressKind, HostsFile, HostsFileEntry},
    keys::{self, KeyAlgorithm, KeyFormat, KeyInfo},
    paths::{SshPaths, path_string},
    perms::{self, PermKind, PermissionProblem, PermissionReport},
};

/// RSA keys below this size are broken.
pub const RSA_MIN_BITS: u32 = 2048;
/// RSA keys below this size are discouraged (NIST: 3072 bits for use beyond 2030).
pub const RSA_RECOMMENDED_BITS: u32 = 3072;

/// Names `ssh` and `git` reach on well-known code hosts. The hosts file has no
/// reason to send them anywhere, and malware does exactly that.
const CODE_HOSTS: &[&str] = &[
    "github.com",
    "ssh.github.com",
    "gitlab.com",
    "altssh.gitlab.com",
    "bitbucket.org",
    "altssh.bitbucket.org",
    "codeberg.org",
    "ssh.dev.azure.com",
    "vs-ssh.visualstudio.com",
    "git.sr.ht",
    "gitea.com",
];

/// How serious a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum Severity {
    /// Insecure or broken; fix now.
    Critical,
    /// Should be fixed.
    Warning,
    /// Worth knowing.
    Info,
}

/// What was found, with its parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum FindingKind {
    /// A DSA key (insecure, disabled in OpenSSH).
    DsaKey,
    /// RSA key shorter than [`RSA_MIN_BITS`].
    RsaTooShort {
        /// Key size.
        bits: u32,
    },
    /// RSA key shorter than [`RSA_RECOMMENDED_BITS`].
    RsaBelowRecommended {
        /// Key size.
        bits: u32,
    },
    /// Private key without a passphrase.
    UnencryptedKey,
    /// Private key file accessible by other users.
    PrivateKeyPermissions {
        /// Octal mode (Unix).
        mode: Option<String>,
        /// The problem.
        problem: PermissionProblem,
    },
    /// The `.ssh` directory is accessible by other users.
    SshDirPermissions {
        /// Octal mode (Unix).
        mode: Option<String>,
        /// The problem.
        problem: PermissionProblem,
    },
    /// `ssh_config` is writable by other users (ssh refuses to use it).
    ConfigPermissions {
        /// Octal mode (Unix).
        mode: Option<String>,
        /// The problem.
        problem: PermissionProblem,
    },
    /// Private key without its `.pub` file.
    MissingPublicKey,
    /// `.pub` file without a private key (fine for keys on hardware tokens or
    /// in another agent).
    OrphanPublicKey,
    /// The `.pub` file contains a different key than the private key.
    PairMismatch,
    /// The same key is stored in several files.
    DuplicateKey {
        /// The shared fingerprint.
        fingerprint: String,
        /// All keys with it.
        key_ids: Vec<String>,
    },
    /// An `IdentityFile` points to a file that does not exist.
    IdentityFileMissing {
        /// The expanded path.
        path: String,
        /// Patterns of the host block.
        patterns: Vec<String>,
    },
    /// The private key uses a legacy format (convert with `ssh-keygen -p`).
    LegacyFormat {
        /// `pem` or `pkcs8`.
        format: KeyFormat,
    },
    /// The hosts file sends a well-known code host to an address of its
    /// choosing, or `localhost` off this computer.
    HostsFileRedirect {
        /// The name as written.
        name: String,
        /// Where it is sent.
        address: String,
        /// 1-based line in the hosts file.
        line: u32,
    },
    /// The hosts file lists a name with different addresses of one family;
    /// resolvers use the first line.
    HostsFileConflict {
        /// The name, normalised.
        name: String,
        /// The distinct addresses in file order.
        addresses: Vec<String>,
        /// 1-based lines that list the name.
        lines: Vec<u32>,
    },
    /// A temporary hosts file entry is still turned on after its time.
    HostsFileExpired {
        /// The entry's names.
        names: Vec<String>,
        /// Its address.
        address: String,
        /// 1-based line in the hosts file.
        line: u32,
        /// When it expired (RFC 3339).
        expires: String,
    },
}

/// What a finding is about.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct FindingSubject {
    /// [`KeyInfo::id`].
    pub key_id: Option<String>,
    /// [`crate::config::HostEntry::id`].
    pub host_id: Option<u32>,
    /// A file or directory.
    pub path: Option<String>,
}

/// A one-click fix the app can offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum FixAction {
    /// [`perms::fix`]`(path, target)`.
    FixPermissions {
        /// Path to fix.
        path: String,
        /// Which rule to apply.
        target: PermKind,
    },
    /// Ask for a passphrase and call [`keys::change_passphrase`].
    AddPassphrase {
        /// The key.
        key_id: String,
    },
    /// [`keys::regenerate_public`].
    RegeneratePublic {
        /// The key.
        key_id: String,
    },
    /// [`SshConfig::remove_identity_file`]`(host_id, path)` then save.
    RemoveIdentityFile {
        /// The block (`None`: global section).
        host_id: Option<u32>,
        /// The `IdentityFile` value as written.
        path: String,
    },
    /// Turn the hosts file entry on `line` off (needs administrator rights).
    TurnOffHostsEntry {
        /// 1-based line in the hosts file.
        line: u32,
    },
}

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct Finding {
    /// Stable id, e.g. `rsaTooShort:<keyId>`.
    pub id: String,
    /// Severity.
    pub severity: Severity,
    /// What was found.
    pub kind: FindingKind,
    /// What it is about.
    pub subject: FindingSubject,
    /// Suggested fix.
    pub fix: Option<FixAction>,
}

/// Number of findings per severity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct AuditCounts {
    /// Critical findings.
    pub critical: u32,
    /// Warnings.
    pub warning: u32,
    /// Informational findings.
    pub info: u32,
}

/// Result of an audit.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct AuditReport {
    /// Findings, most severe first, then by id.
    pub findings: Vec<Finding>,
    /// Totals.
    pub counts: AuditCounts,
}

/// A path with its permission report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct PathPermissions {
    /// The path.
    pub path: String,
    /// Its permissions.
    pub permissions: PermissionReport,
}

/// Everything the audit looks at. Build it from [`keys::scan`],
/// [`SshConfig::identity_usage`] and [`perms::check_many`], or use
/// [`run_for_paths`].
#[derive(Debug, Clone, Copy, Default)]
pub struct AuditInput<'a> {
    /// Scanned keys (plus any inspected ones).
    pub keys: &'a [KeyInfo],
    /// Permissions of the `.ssh` directory.
    pub ssh_dir: Option<&'a PathPermissions>,
    /// Permissions of the config file (when it exists).
    pub config_file: Option<&'a PathPermissions>,
    /// `IdentityFile` references.
    pub identity_usage: &'a [IdentityUsage],
    /// Lines of the system hosts file as resolvers read them
    /// ([`HostsFile::resolver_entries`]); turned-off entries are skipped.
    pub hosts_file: &'a [HostsFileEntry],
    /// The time temporary entries are compared with (none: never expired).
    pub now: Option<OffsetDateTime>,
    /// Fingerprints of other people's public keys, received from them: a
    /// `.pub` of one is no orphan, as its private key is theirs.
    pub others: &'a [String],
}

/// Runs all rules. Pure: no file system access.
pub fn run(input: &AuditInput<'_>) -> AuditReport {
    let mut findings = Vec::new();
    for key in input.keys {
        let theirs = key
            .fingerprint
            .as_ref()
            .is_some_and(|fingerprint| input.others.contains(fingerprint));
        key_findings(key, theirs, &mut findings);
    }
    duplicate_findings(input.keys, &mut findings);
    if let Some(dir) = input.ssh_dir.filter(|d| d.permissions.is_problem()) {
        findings.push(path_finding(
            "sshDirPermissions",
            Severity::Warning,
            dir,
            PermKind::SshDir,
            |mode, problem| FindingKind::SshDirPermissions { mode, problem },
        ));
    }
    if let Some(cfg) = input.config_file.filter(|c| c.permissions.is_problem()) {
        findings.push(path_finding(
            "configPermissions",
            Severity::Critical,
            cfg,
            PermKind::Config,
            |mode, problem| FindingKind::ConfigPermissions { mode, problem },
        ));
    }
    let mut seen = HashSet::new();
    for usage in input
        .identity_usage
        .iter()
        .filter(|u| u.resolved && !u.exists)
    {
        let host = usage
            .host_id
            .map_or_else(|| "global".to_owned(), |id| id.to_string());
        let id = format!("identityFileMissing:{host}:{}", usage.raw);
        if !seen.insert(id.clone()) {
            continue;
        }
        findings.push(Finding {
            id,
            severity: Severity::Warning,
            kind: FindingKind::IdentityFileMissing {
                path: usage.path.clone(),
                patterns: usage.patterns.clone(),
            },
            subject: FindingSubject {
                host_id: usage.host_id,
                path: Some(usage.path.clone()),
                ..FindingSubject::default()
            },
            fix: Some(FixAction::RemoveIdentityFile {
                host_id: usage.host_id,
                path: usage.raw.clone(),
            }),
        });
    }
    hosts_file_findings(input.hosts_file, input.now, &mut findings);

    findings.sort_by(|a, b| a.severity.cmp(&b.severity).then_with(|| a.id.cmp(&b.id)));
    let mut counts = AuditCounts::default();
    for f in &findings {
        match f.severity {
            Severity::Critical => counts.critical += 1,
            Severity::Warning => counts.warning += 1,
            Severity::Info => counts.info += 1,
        }
    }
    AuditReport { findings, counts }
}

/// Scans `paths.dir`, loads `paths.config` and the hosts file, checks the
/// directory and config permissions and runs the audit. A config or hosts
/// file that cannot be read is skipped (the pages that show them report why).
/// `others` are the fingerprints of other people's keys ([`AuditInput::others`]).
pub fn run_for_paths(
    paths: &SshPaths,
    hosts_file: &Path,
    others: &[String],
) -> Result<AuditReport> {
    let scan = keys::scan(&paths.dir)?;
    let config = SshConfig::load(&paths.config).ok();
    let usage = config
        .as_ref()
        .map(|c| c.identity_usage(paths))
        .unwrap_or_default();
    let hosts = HostsFile::load(hosts_file)
        .map(|file| file.resolver_entries())
        .unwrap_or_default();
    let mut items: Vec<(PathBuf, PermKind)> = Vec::new();
    if paths.dir.exists() {
        items.push((paths.dir.clone(), PermKind::SshDir));
    }
    if paths.config.exists() {
        items.push((paths.config.clone(), PermKind::Config));
    }
    let mut reports = perms::check_many(&items).into_iter();
    let mut take = |present: bool, path: &Path| {
        present.then(|| PathPermissions {
            path: path_string(path),
            permissions: reports.next().unwrap_or(PermissionReport {
                ok: false,
                mode: None,
                problem: Some(PermissionProblem::CheckFailed),
            }),
        })
    };
    let ssh_dir = take(paths.dir.exists(), &paths.dir);
    let config_file = take(paths.config.exists(), &paths.config);
    Ok(run(&AuditInput {
        keys: &scan.keys,
        ssh_dir: ssh_dir.as_ref(),
        config_file: config_file.as_ref(),
        identity_usage: &usage,
        hosts_file: &hosts,
        now: Some(OffsetDateTime::now_utc()),
        others,
    }))
}

/// `theirs`: the key is someone else's, so it has no private key here.
fn key_findings(key: &KeyInfo, theirs: bool, out: &mut Vec<Finding>) {
    let subject = || FindingSubject {
        key_id: Some(key.id.clone()),
        path: key.private_path.clone().or_else(|| key.public_path.clone()),
        host_id: None,
    };
    let mut push = |rule: &str, severity, kind, fix| {
        out.push(Finding {
            id: format!("{rule}:{}", key.id),
            severity,
            kind,
            subject: subject(),
            fix,
        });
    };

    match (key.algorithm, key.bits) {
        (KeyAlgorithm::Dsa, _) => push("dsaKey", Severity::Critical, FindingKind::DsaKey, None),
        (KeyAlgorithm::Rsa, Some(bits)) if bits < RSA_MIN_BITS => push(
            "rsaTooShort",
            Severity::Critical,
            FindingKind::RsaTooShort { bits },
            None,
        ),
        (KeyAlgorithm::Rsa, Some(bits)) if bits < RSA_RECOMMENDED_BITS => push(
            "rsaBelowRecommended",
            Severity::Warning,
            FindingKind::RsaBelowRecommended { bits },
            None,
        ),
        _ => {}
    }

    let Some(private_path) = &key.private_path else {
        if !theirs {
            push(
                "orphanPublicKey",
                Severity::Info,
                FindingKind::OrphanPublicKey,
                None,
            );
        }
        return;
    };

    if key.encrypted == Some(false) && !key.hardware {
        let fix = (key.format == KeyFormat::Openssh).then(|| FixAction::AddPassphrase {
            key_id: key.id.clone(),
        });
        push(
            "unencryptedKey",
            Severity::Warning,
            FindingKind::UnencryptedKey,
            fix,
        );
    }
    if key.permissions.is_problem()
        && let Some(problem) = key.permissions.problem
    {
        push(
            "privateKeyPermissions",
            Severity::Critical,
            FindingKind::PrivateKeyPermissions {
                mode: key.permissions.mode.clone(),
                problem,
            },
            Some(FixAction::FixPermissions {
                path: private_path.clone(),
                target: PermKind::PrivateKey,
            }),
        );
    }
    if key.public_path.is_none() {
        // The public half can be derived from OpenSSH keys and unencrypted
        // legacy keys (those have a fingerprint).
        let derivable = key.format == KeyFormat::Openssh || key.fingerprint.is_some();
        let fix = derivable.then(|| FixAction::RegeneratePublic {
            key_id: key.id.clone(),
        });
        push(
            "missingPublicKey",
            Severity::Info,
            FindingKind::MissingPublicKey,
            fix,
        );
    }
    if key.pair_mismatch {
        push(
            "pairMismatch",
            Severity::Critical,
            FindingKind::PairMismatch,
            None,
        );
    }
    if matches!(key.format, KeyFormat::Pem | KeyFormat::Pkcs8) {
        push(
            "legacyFormat",
            Severity::Info,
            FindingKind::LegacyFormat { format: key.format },
            None,
        );
    }
}

fn duplicate_findings(keys: &[KeyInfo], out: &mut Vec<Finding>) {
    let mut groups: BTreeMap<&str, Vec<&KeyInfo>> = BTreeMap::new();
    for key in keys {
        if let Some(fp) = key.fingerprint.as_deref() {
            groups.entry(fp).or_default().push(key);
        }
    }
    for (fingerprint, group) in groups.into_iter().filter(|(_, g)| g.len() > 1) {
        out.push(Finding {
            id: format!("duplicateKey:{fingerprint}"),
            severity: Severity::Info,
            kind: FindingKind::DuplicateKey {
                fingerprint: fingerprint.to_owned(),
                key_ids: group.iter().map(|k| k.id.clone()).collect(),
            },
            subject: FindingSubject {
                key_id: Some(group[0].id.clone()),
                ..FindingSubject::default()
            },
            fix: None,
        });
    }
}

/// The distinct addresses the hosts file gives a name, and the lines that do.
#[derive(Default)]
struct NameUse<'a> {
    addresses: Vec<&'a str>,
    lines: Vec<u32>,
}

fn hosts_file_findings(
    entries: &[HostsFileEntry],
    now: Option<OffsetDateTime>,
    out: &mut Vec<Finding>,
) {
    if let Some(now) = now {
        for entry in entries.iter().filter(|e| e.enabled && e.is_expired(now)) {
            out.push(Finding {
                id: format!(
                    "hostsFileExpired:{}:{}",
                    entry.address,
                    entry.names.join(",")
                ),
                severity: Severity::Warning,
                kind: FindingKind::HostsFileExpired {
                    names: entry.names.clone(),
                    address: entry.address.clone(),
                    line: entry.line,
                    expires: entry.expires.clone().unwrap_or_default(),
                },
                subject: FindingSubject::default(),
                fix: Some(FixAction::TurnOffHostsEntry { line: entry.line }),
            });
        }
    }
    // Keyed by name and IPv6-ness: each address family resolves on its own.
    let mut by_name: BTreeMap<(String, bool), NameUse<'_>> = BTreeMap::new();
    for entry in entries.iter().filter(|e| e.enabled) {
        // Scoped addresses (`fe80::1%lo0 localhost`) apply to one interface:
        // fine for localhost and not a conflict, but no place for a code host.
        let scoped = entry.address.contains('%');
        for name in &entry.names {
            let key = hosts_file::normalize_name(name);
            let redirected = if key == "localhost" {
                !scoped
                    && matches!(
                        entry.kind,
                        HostsAddressKind::Private | HostsAddressKind::Public
                    )
            } else {
                CODE_HOSTS.contains(&key.as_str())
            };
            if redirected && !entry.shadowed.contains(name) {
                out.push(Finding {
                    id: format!("hostsFileRedirect:{key}:{}", entry.address),
                    severity: Severity::Critical,
                    kind: FindingKind::HostsFileRedirect {
                        name: name.clone(),
                        address: entry.address.clone(),
                        line: entry.line,
                    },
                    subject: FindingSubject::default(),
                    fix: None,
                });
            }
            if scoped {
                continue;
            }
            let uses = by_name.entry((key, entry.is_ipv6())).or_default();
            if !uses.addresses.contains(&entry.address.as_str()) {
                uses.addresses.push(&entry.address);
            }
            if !uses.lines.contains(&entry.line) {
                uses.lines.push(entry.line);
            }
        }
    }
    for ((name, ipv6), NameUse { addresses, lines }) in by_name {
        if addresses.len() < 2 {
            continue;
        }
        let family = if ipv6 { "ipv6" } else { "ipv4" };
        out.push(Finding {
            id: format!("hostsFileConflict:{name}:{family}"),
            severity: Severity::Warning,
            kind: FindingKind::HostsFileConflict {
                name,
                addresses: addresses.into_iter().map(str::to_owned).collect(),
                lines,
            },
            subject: FindingSubject::default(),
            fix: None,
        });
    }
}

fn path_finding(
    rule: &str,
    severity: Severity,
    item: &PathPermissions,
    target: PermKind,
    kind: impl FnOnce(Option<String>, PermissionProblem) -> FindingKind,
) -> Finding {
    Finding {
        id: rule.to_owned(),
        severity,
        kind: kind(
            item.permissions.mode.clone(),
            item.permissions
                .problem
                .unwrap_or(PermissionProblem::CheckFailed),
        ),
        subject: FindingSubject {
            path: Some(item.path.clone()),
            ..FindingSubject::default()
        },
        fix: Some(FixAction::FixPermissions {
            path: item.path.clone(),
            target,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::perms::evaluate_mode;

    fn key(id: &str) -> KeyInfo {
        KeyInfo {
            id: id.into(),
            name: id.into(),
            private_path: Some(format!("/h/.ssh/{id}")),
            public_path: Some(format!("/h/.ssh/{id}.pub")),
            algorithm: KeyAlgorithm::Ed25519,
            key_type: "ssh-ed25519".into(),
            bits: Some(256),
            fingerprint: Some(format!("SHA256:{id}")),
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

    fn ids(report: &AuditReport) -> Vec<&str> {
        report.findings.iter().map(|f| f.id.as_str()).collect()
    }

    #[test]
    fn someone_elses_key_is_no_orphan() {
        let orphan = |id: &str, algorithm| KeyInfo {
            private_path: None,
            encrypted: None,
            format: KeyFormat::PublicOnly,
            algorithm,
            ..key(id)
        };
        let keys = [
            orphan("mine", KeyAlgorithm::Ed25519),
            orphan("theirs", KeyAlgorithm::Ed25519),
            orphan("old", KeyAlgorithm::Dsa),
        ];
        let others = ["SHA256:theirs".to_owned(), "SHA256:old".to_owned()];
        let report = run(&AuditInput {
            keys: &keys,
            others: &others,
            ..AuditInput::default()
        });
        // Its strength still counts.
        assert_eq!(ids(&report), ["dsaKey:old", "orphanPublicKey:mine"]);
    }

    #[test]
    fn clean_input_has_no_findings() {
        let keys = [key("a")];
        let report = run(&AuditInput {
            keys: &keys,
            ..AuditInput::default()
        });
        assert_eq!(report.findings, []);
        assert_eq!(report.counts, AuditCounts::default());
    }

    #[test]
    fn key_rules() {
        let dsa = KeyInfo {
            algorithm: KeyAlgorithm::Dsa,
            bits: Some(1024),
            ..key("dsa")
        };
        let rsa1024 = KeyInfo {
            algorithm: KeyAlgorithm::Rsa,
            bits: Some(1024),
            ..key("rsa1024")
        };
        let rsa2048 = KeyInfo {
            algorithm: KeyAlgorithm::Rsa,
            bits: Some(2048),
            format: KeyFormat::Pem,
            encrypted: Some(false),
            ..key("rsa2048")
        };
        let rsa4096 = KeyInfo {
            algorithm: KeyAlgorithm::Rsa,
            bits: Some(4096),
            ..key("rsa4096")
        };
        let plain = KeyInfo {
            encrypted: Some(false),
            permissions: evaluate_mode(0o644, PermKind::PrivateKey),
            public_path: None,
            ..key("plain")
        };
        let hw = KeyInfo {
            algorithm: KeyAlgorithm::SkEd25519,
            hardware: true,
            encrypted: Some(false),
            ..key("hw")
        };
        let orphan = KeyInfo {
            private_path: None,
            encrypted: None,
            format: KeyFormat::PublicOnly,
            ..key("orphan")
        };
        let mismatch = KeyInfo {
            pair_mismatch: true,
            ..key("mismatch")
        };
        let keys = [dsa, rsa1024, rsa2048, rsa4096, plain, hw, orphan, mismatch];
        let report = run(&AuditInput {
            keys: &keys,
            ..AuditInput::default()
        });
        assert_eq!(
            ids(&report),
            [
                "dsaKey:dsa",
                "pairMismatch:mismatch",
                "privateKeyPermissions:plain",
                "rsaTooShort:rsa1024",
                "rsaBelowRecommended:rsa2048",
                "unencryptedKey:plain",
                "unencryptedKey:rsa2048",
                "legacyFormat:rsa2048",
                "missingPublicKey:plain",
                "orphanPublicKey:orphan",
            ]
        );
        assert_eq!(
            report.counts,
            AuditCounts {
                critical: 4,
                warning: 3,
                info: 3
            }
        );
        let by_id = |id: &str| report.findings.iter().find(|f| f.id == id).unwrap();
        assert_eq!(
            by_id("unencryptedKey:plain").fix,
            Some(FixAction::AddPassphrase {
                key_id: "plain".into()
            })
        );
        // No passphrase fix for legacy keys (change_passphrase does not support them).
        assert_eq!(by_id("unencryptedKey:rsa2048").fix, None);
        assert_eq!(
            by_id("privateKeyPermissions:plain").fix,
            Some(FixAction::FixPermissions {
                path: "/h/.ssh/plain".into(),
                target: PermKind::PrivateKey
            })
        );
        assert_eq!(
            by_id("missingPublicKey:plain").fix,
            Some(FixAction::RegeneratePublic {
                key_id: "plain".into()
            })
        );
        assert_eq!(
            by_id("rsaTooShort:rsa1024").kind,
            FindingKind::RsaTooShort { bits: 1024 }
        );
    }

    #[test]
    fn duplicates_paths_and_identity_files() {
        let a = key("a");
        let copy = KeyInfo {
            id: "SHA256:a#copy".into(),
            ..key("a")
        };
        let keys = [a, copy];
        let dir = PathPermissions {
            path: "/h/.ssh".into(),
            permissions: evaluate_mode(0o755, PermKind::SshDir),
        };
        let cfg = PathPermissions {
            path: "/h/.ssh/config".into(),
            permissions: evaluate_mode(0o666, PermKind::Config),
        };
        let missing = IdentityUsage {
            host_id: Some(3),
            patterns: vec!["gh".into()],
            path: "/h/.ssh/gone".into(),
            raw: "~/.ssh/gone".into(),
            resolved: true,
            exists: false,
            remote: false,
        };
        let unresolved = IdentityUsage {
            resolved: false,
            raw: "~/.ssh/%C".into(),
            ..missing.clone()
        };
        let usage = [missing.clone(), missing, unresolved];
        let report = run(&AuditInput {
            keys: &keys,
            ssh_dir: Some(&dir),
            config_file: Some(&cfg),
            identity_usage: &usage,
            hosts_file: &[],
            now: None,
            others: &[],
        });
        assert_eq!(
            ids(&report),
            [
                "configPermissions",
                "identityFileMissing:3:~/.ssh/gone",
                "sshDirPermissions",
                "duplicateKey:SHA256:a",
            ]
        );
        let f = &report.findings[1];
        assert_eq!(
            f.fix,
            Some(FixAction::RemoveIdentityFile {
                host_id: Some(3),
                path: "~/.ssh/gone".into()
            })
        );
        let dup = &report.findings[3];
        assert_eq!(
            dup.kind,
            FindingKind::DuplicateKey {
                fingerprint: "SHA256:a".into(),
                key_ids: vec!["a".into(), "SHA256:a#copy".into()],
            }
        );
    }

    #[test]
    fn hosts_file_rules() {
        let entries = HostsFile::parse(
            "127.0.0.1 localhost\n\
             ::1 localhost\n\
             fe80::1%lo0 localhost\n\
             10.0.4.12 api.internal\n\
             10.0.9.9 API.internal\n\
             10.0.4.12 api.internal\n\
             ::1 api.internal\n\
             # 6.6.6.6 github.com\n\
             6.6.6.6 GitHub.com # mirror\n\
             0.0.0.0 gitlab.com\n\
             203.0.113.5 example.com\n",
        )
        .entries();
        let report = run(&AuditInput {
            hosts_file: &entries,
            ..AuditInput::default()
        });
        assert_eq!(
            ids(&report),
            [
                "hostsFileRedirect:github.com:6.6.6.6",
                "hostsFileRedirect:gitlab.com:0.0.0.0",
                "hostsFileConflict:api.internal:ipv4",
            ]
        );
        assert_eq!(
            report.findings[0].kind,
            FindingKind::HostsFileRedirect {
                name: "GitHub.com".into(),
                address: "6.6.6.6".into(),
                line: 9,
            }
        );
        assert_eq!(
            report.findings[2].kind,
            FindingKind::HostsFileConflict {
                name: "api.internal".into(),
                addresses: vec!["10.0.4.12".into(), "10.0.9.9".into()],
                lines: vec![4, 5, 6],
            }
        );

        let entries = HostsFile::parse(
            "10.0.9.1 demo.local # sshkm-until=2026-11-02T19:00:00Z\n\
             # 10.0.9.2 old.local # sshkm-until=2026-11-02T19:00:00Z\n",
        )
        .entries();
        let at = |now| {
            run(&AuditInput {
                hosts_file: &entries,
                now: Some(now),
                ..AuditInput::default()
            })
        };
        assert_eq!(
            ids(&at(time::macros::datetime!(2026-11-02 18:00 UTC))),
            Vec::<&str>::new()
        );
        let report = at(time::macros::datetime!(2026-11-02 19:30 UTC));
        assert_eq!(ids(&report), ["hostsFileExpired:10.0.9.1:demo.local"]);
        assert_eq!(
            report.findings[0].fix,
            Some(FixAction::TurnOffHostsEntry { line: 1 })
        );

        let entries = HostsFile::parse("10.1.1.1 localhost\n").entries();
        let report = run(&AuditInput {
            hosts_file: &entries,
            ..AuditInput::default()
        });
        assert_eq!(ids(&report), ["hostsFileRedirect:localhost:10.1.1.1"]);
        assert_eq!(report.counts.critical, 1);
    }

    #[test]
    fn hosts_file_redirects_are_found_where_resolvers_find_them() {
        // Line 1 has a name the app rejects, line 3 a scope it rejects, but
        // resolvers read both.
        let entries = HostsFile::parse(
            "203.0.113.66 github.com x/1\n\
             140.82.112.3 github.com\n\
             fe80::1%en0/1 bitbucket.org\n\
             fe80::1%en0 gitlab.com\n\
             fe80::1%lo0 localhost\n\
             fe80::2%lo0 localhost\n\
             ::1 localhost\n",
        )
        .resolver_entries();
        let report = run(&AuditInput {
            hosts_file: &entries,
            ..AuditInput::default()
        });
        assert_eq!(
            ids(&report),
            [
                "hostsFileRedirect:bitbucket.org:fe80::1%en0/1",
                "hostsFileRedirect:github.com:203.0.113.66",
                "hostsFileRedirect:gitlab.com:fe80::1%en0",
                "hostsFileConflict:github.com:ipv4",
            ]
        );
        assert_eq!(
            report.findings[1].kind,
            FindingKind::HostsFileRedirect {
                name: "github.com".into(),
                address: "203.0.113.66".into(),
                line: 1,
            }
        );

        let dir = tempfile::tempdir().unwrap();
        let hosts = dir.path().join("hosts");
        std::fs::write(&hosts, "203.0.113.66 github.com x/1\n").unwrap();
        let paths = SshPaths::with_home(dir.path(), dir.path().join(".ssh"));
        let report = run_for_paths(&paths, &hosts, &[]).unwrap();
        assert_eq!(ids(&report), ["hostsFileRedirect:github.com:203.0.113.66"]);
    }

    #[test]
    fn serializes_tagged() {
        let keys = [KeyInfo {
            algorithm: KeyAlgorithm::Rsa,
            bits: Some(1024),
            ..key("r")
        }];
        let report = run(&AuditInput {
            keys: &keys,
            ..AuditInput::default()
        });
        let v = serde_json::to_value(&report).unwrap();
        let f = &v["findings"][0];
        assert_eq!(f["severity"], "critical");
        assert_eq!(f["kind"]["kind"], "rsaTooShort");
        assert_eq!(f["kind"]["bits"], 1024);
        assert_eq!(f["subject"]["keyId"], "r");
        assert_eq!(v["counts"]["critical"], 1);
        let fix = serde_json::to_value(FixAction::RemoveIdentityFile {
            host_id: Some(1),
            path: "p".into(),
        })
        .unwrap();
        assert_eq!(fix["kind"], "removeIdentityFile");
        assert_eq!(fix["hostId"], 1);
        let fix = serde_json::to_value(FixAction::FixPermissions {
            path: "p".into(),
            target: PermKind::SshDir,
        })
        .unwrap();
        assert_eq!(fix["target"], "sshDir");
        let dup = serde_json::to_value(FindingKind::DuplicateKey {
            fingerprint: "f".into(),
            key_ids: vec![],
        })
        .unwrap();
        assert!(dup.get("keyIds").is_some());
    }

    #[cfg(unix)]
    #[test]
    fn run_for_paths_end_to_end() {
        use crate::keys::testdata as td;
        use std::{fs, os::unix::fs::PermissionsExt};
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(".ssh");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let key = dir.join("id_ed25519");
        fs::write(&key, td::OPENSSH_ED25519).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(
            dir.join("config"),
            "Host gh\n  IdentityFile ~/.ssh/id_ed25519\n  IdentityFile ~/.ssh/missing\n",
        )
        .unwrap();
        fs::set_permissions(dir.join("config"), fs::Permissions::from_mode(0o600)).unwrap();
        let paths = SshPaths::with_home(home.path(), &dir);
        let report = run_for_paths(&paths, &home.path().join("hosts"), &[]).unwrap();
        let kinds: Vec<_> = report
            .findings
            .iter()
            .map(|f| f.id.split(':').next().unwrap())
            .collect();
        assert_eq!(
            kinds,
            [
                "privateKeyPermissions",
                "identityFileMissing",
                "sshDirPermissions",
                "unencryptedKey",
                "missingPublicKey",
            ]
        );
        // Apply the offered fixes and re-run.
        for f in &report.findings {
            if let Some(FixAction::FixPermissions { path, target }) = &f.fix {
                perms::fix(Path::new(path), *target).unwrap();
            }
            if let Some(FixAction::RegeneratePublic { .. }) = &f.fix {
                keys::regenerate_public(&key).unwrap();
            }
            if let Some(FixAction::RemoveIdentityFile { host_id, path }) = &f.fix {
                let mut config = SshConfig::load(&paths.config).unwrap();
                assert!(config.remove_identity_file(*host_id, path).unwrap());
                config
                    .save(&paths.config, &home.path().join("backups"))
                    .unwrap();
            }
        }
        let report = run_for_paths(&paths, &home.path().join("hosts"), &[]).unwrap();
        assert_eq!(
            ids(&report),
            [format!(
                "unencryptedKey:{}",
                report.findings[0].subject.key_id.clone().unwrap()
            )]
        );
    }
}
