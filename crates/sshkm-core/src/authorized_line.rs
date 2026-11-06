//! One `authorized_keys` line for a public key, with the options `sshd`
//! reads (`man sshd`, "`AUTHORIZED_KEYS` FILE FORMAT"): `restrict`, `from=`,
//! `command=`, `expiry-time=` and the `no-…` flags.
//!
//! Each value is checked so the line says no more than the form shows: host
//! patterns without quotes, commas or spaces, a command on one line (its
//! quotes escaped the way `sshd` unescapes them), a real date. The line is
//! then read back with [`crate::authorized_keys::parse`], which reads it as
//! `sshd` does, and must come out as the same key with the same options.

use serde::{Deserialize, Serialize};
use ssh_key::PublicKey;
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime};

use crate::authorized_keys;
use crate::keys::fingerprint;

/// The longest command accepted.
const MAX_COMMAND: usize = 4096;
const MAX_PATTERNS: usize = 64;

/// The options of a line, as the form sets them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
#[allow(clippy::struct_excessive_bools, reason = "the form's switches")]
pub struct LineOptions {
    /// Everything off (forwarding, a terminal, `~/.ssh/rc`) unless allowed
    /// again; includes the `no-…` flags below.
    pub restrict: bool,
    /// `from=`: the hosts the key may sign in from; `!` before a pattern
    /// excludes it. Empty: any host.
    pub from: Vec<String>,
    /// `command=`: the only command the key may run.
    pub command: Option<String>,
    /// `expiry-time=`: `YYYYMMDD`, `YYYYMMDDHHMM` or `YYYYMMDDHHMMSS`, with
    /// `Z` for UTC; the server's local time otherwise.
    pub expiry_time: Option<String>,
    pub no_port_forwarding: bool,
    pub no_agent_forwarding: bool,
    pub no_pty: bool,
    pub no_x11_forwarding: bool,
}

/// What is wrong with the input, for the form to say next to the field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum LineProblem {
    /// No public key yet.
    KeyMissing,
    /// A private key was pasted.
    KeyPrivate,
    /// Not one `<type> <base64> [comment]` line.
    KeyInvalid,
    /// A `from=` pattern with a character `sshd` would read otherwise.
    FromInvalid { pattern: String },
    /// Only exclusions: no host could sign in.
    FromOnlyExcludes,
    /// More than one line, or a control character.
    CommandInvalid,
    /// Not one of the three forms, or no such date.
    ExpiryInvalid,
    /// The time has passed: the key would never work.
    ExpiryPast,
}

/// The line, or what keeps it from being made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct AuthorizedLine {
    /// `None` while there are problems.
    pub line: Option<String>,
    /// `SHA256:…` of the key, once it reads.
    pub fingerprint: Option<String>,
    pub problems: Vec<LineProblem>,
}

/// Builds the line for `public_key` (one OpenSSH public key line) with
/// `options`. Never fails: problems are returned for the form to show.
pub fn build(public_key: &str, options: &LineOptions) -> AuthorizedLine {
    build_at(public_key, options, OffsetDateTime::now_utc())
}

fn build_at(public_key: &str, options: &LineOptions, now: OffsetDateTime) -> AuthorizedLine {
    let mut problems = Vec::new();
    let key = read_key(public_key, &mut problems);
    let mut parts: Vec<String> = Vec::new();
    if options.restrict {
        parts.push("restrict".into());
    }

    let patterns: Vec<&str> = options
        .from
        .iter()
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .take(MAX_PATTERNS)
        .collect();
    for pattern in &patterns {
        if !is_pattern(pattern) {
            problems.push(LineProblem::FromInvalid {
                pattern: (*pattern).to_owned(),
            });
        }
    }
    if !patterns.is_empty() && patterns.iter().all(|p| p.starts_with('!')) {
        problems.push(LineProblem::FromOnlyExcludes);
    }
    if !patterns.is_empty() {
        parts.push(format!("from=\"{}\"", patterns.join(",")));
    }

    if let Some(command) = options
        .command
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
    {
        if command.len() > MAX_COMMAND || command.chars().any(char::is_control) {
            problems.push(LineProblem::CommandInvalid);
        } else {
            parts.push(format!("command=\"{}\"", command.replace('"', "\\\"")));
        }
    }

    if let Some(expiry) = options
        .expiry_time
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        match expiry_time(expiry) {
            None => problems.push(LineProblem::ExpiryInvalid),
            // Local time is the server's: a day's slack either way.
            Some((at, utc)) if at.assume_utc() < now - time::Duration::days(i64::from(!utc)) => {
                problems.push(LineProblem::ExpiryPast);
            }
            Some(_) => parts.push(format!("expiry-time=\"{expiry}\"")),
        }
    }

    if !options.restrict {
        for (on, flag) in [
            (options.no_agent_forwarding, "no-agent-forwarding"),
            (options.no_port_forwarding, "no-port-forwarding"),
            (options.no_pty, "no-pty"),
            (options.no_x11_forwarding, "no-X11-forwarding"),
        ] {
            if on {
                parts.push(flag.into());
            }
        }
    }

    let fingerprint = key.as_ref().map(|k| fingerprint(k.key_data()));
    let line = key.filter(|_| problems.is_empty()).and_then(|key| {
        let encoded = key.to_openssh().ok()?;
        let line = if parts.is_empty() {
            encoded
        } else {
            format!("{} {encoded}", parts.join(","))
        };
        reads_back(&line, &key, parts.len()).then_some(line)
    });
    if line.is_none() && problems.is_empty() {
        problems.push(LineProblem::KeyInvalid);
    }
    AuthorizedLine {
        line,
        fingerprint,
        problems,
    }
}

fn read_key(text: &str, problems: &mut Vec<LineProblem>) -> Option<PublicKey> {
    let text = text.trim();
    if text.is_empty() {
        problems.push(LineProblem::KeyMissing);
        return None;
    }
    if text.contains("PRIVATE KEY") || text.starts_with("PuTTY-User-Key-File-") {
        problems.push(LineProblem::KeyPrivate);
        return None;
    }
    let key = (!text.contains(['\n', '\r']))
        .then(|| PublicKey::from_openssh(text).ok())
        .flatten();
    if key.is_none() {
        problems.push(LineProblem::KeyInvalid);
    }
    key
}

/// A host pattern `sshd` matches as written: a name or address with `*`
/// and `?`, or an address with a `/bits` mask, `!` before it to exclude.
fn is_pattern(pattern: &str) -> bool {
    let pattern = pattern.strip_prefix('!').unwrap_or(pattern);
    if let Some((address, bits)) = pattern.split_once('/') {
        let Ok(address) = address.parse::<std::net::IpAddr>() else {
            return false;
        };
        let max = if address.is_ipv4() { 32 } else { 128 };
        return bits.parse::<u8>().is_ok_and(|bits| bits <= max);
    }
    !pattern.is_empty()
        && pattern.len() <= 253
        && pattern
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '*' | '?'))
}

/// The time `expiry-time` names, and whether it is UTC.
fn expiry_time(value: &str) -> Option<(PrimitiveDateTime, bool)> {
    let (digits, utc) = match value.strip_suffix(['Z', 'z']) {
        Some(digits) => (digits, true),
        None => (value, false),
    };
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let full = match digits.len() {
        8 => format!("{digits}000000"),
        12 => format!("{digits}00"),
        14 => digits.to_owned(),
        _ => return None,
    };
    let format = format_description!("[year][month][day][hour][minute][second]");
    PrimitiveDateTime::parse(&full, format)
        .ok()
        .map(|at| (at, utc))
}

/// The line reads back, as `sshd` reads it, as `key` with `options` options.
fn reads_back(line: &str, key: &PublicKey, options: usize) -> bool {
    let file = authorized_keys::parse(line);
    let [read] = file.keys.as_slice() else {
        return false;
    };
    let counted = read.options.len() + usize::from(read.expires.is_some());
    read.fingerprint == fingerprint(key.key_data()) && file.invalid.is_empty() && counted == options
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHJCszOHaI9X/yGLtjn22f0hO6VPMQDVtctkym6FJH1W alice@laptop";

    fn now() -> OffsetDateTime {
        time::macros::datetime!(2026-11-06 12:00 UTC)
    }

    fn line(options: &LineOptions) -> AuthorizedLine {
        build_at(KEY, options, now())
    }

    #[test]
    fn a_key_alone_is_the_key() {
        let built = line(&LineOptions::default());
        assert_eq!(built.line.as_deref(), Some(KEY));
        assert_eq!(built.problems, []);
        assert!(built.fingerprint.unwrap().starts_with("SHA256:"));
    }

    #[test]
    fn options_come_in_one_order_and_read_back() {
        let built = line(&LineOptions {
            from: vec![
                "10.0.0.0/8".into(),
                " !10.0.0.5 ".into(),
                "*.example.com".into(),
            ],
            command: Some(r#"/usr/bin/backup --tag "nightly""#.into()),
            expiry_time: Some("20271231Z".into()),
            no_port_forwarding: true,
            no_pty: true,
            ..LineOptions::default()
        });
        assert_eq!(
            built.line.as_deref(),
            Some(
                r#"from="10.0.0.0/8,!10.0.0.5,*.example.com",command="/usr/bin/backup --tag \"nightly\"",expiry-time="20271231Z",no-port-forwarding,no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHJCszOHaI9X/yGLtjn22f0hO6VPMQDVtctkym6FJH1W alice@laptop"#
            )
        );
        let read = authorized_keys::parse(built.line.as_deref().unwrap());
        assert_eq!(
            read.keys[0].expires.as_deref(),
            Some("2027-12-31T00:00:00Z")
        );
    }

    #[test]
    fn restrict_covers_the_flags() {
        let built = line(&LineOptions {
            restrict: true,
            no_agent_forwarding: true,
            no_x11_forwarding: true,
            ..LineOptions::default()
        });
        assert_eq!(built.line.unwrap(), format!("restrict {KEY}"));
    }

    #[test]
    fn problems_name_the_field() {
        let cases: [(&str, LineOptions, LineProblem); 8] = [
            ("", LineOptions::default(), LineProblem::KeyMissing),
            (
                "-----BEGIN OPENSSH PRIVATE KEY-----",
                LineOptions::default(),
                LineProblem::KeyPrivate,
            ),
            (
                "ssh-ed25519 nope",
                LineOptions::default(),
                LineProblem::KeyInvalid,
            ),
            (
                KEY,
                LineOptions {
                    from: vec![r#"a",command="sh"#.into()],
                    ..LineOptions::default()
                },
                LineProblem::FromInvalid {
                    pattern: r#"a",command="sh"#.into(),
                },
            ),
            (
                KEY,
                LineOptions {
                    from: vec!["!bad.example".into()],
                    ..LineOptions::default()
                },
                LineProblem::FromOnlyExcludes,
            ),
            (
                KEY,
                LineOptions {
                    command: Some("ls\nrm -rf ~".into()),
                    ..LineOptions::default()
                },
                LineProblem::CommandInvalid,
            ),
            (
                KEY,
                LineOptions {
                    expiry_time: Some("20261340".into()),
                    ..LineOptions::default()
                },
                LineProblem::ExpiryInvalid,
            ),
            (
                KEY,
                LineOptions {
                    expiry_time: Some("202601011200Z".into()),
                    ..LineOptions::default()
                },
                LineProblem::ExpiryPast,
            ),
        ];
        for (key, options, problem) in cases {
            let built = build_at(key, &options, now());
            assert_eq!(built.line, None, "{problem:?}");
            assert_eq!(built.problems, [problem]);
        }
        // Two keys, or one with options already, are not one key.
        let two = format!("{KEY}\n{KEY}");
        assert_eq!(
            build_at(&two, &LineOptions::default(), now()).problems,
            [LineProblem::KeyInvalid]
        );
        let masks = ["10.0.0.0/33", "::/129", "host/8", "a b", "", "a,b"];
        for mask in masks {
            assert!(!is_pattern(mask), "{mask}");
        }
        for ok in [
            "10.0.0.0/8",
            "fe80::/10",
            "*.corp",
            "db?",
            "!10.1.1.1",
            "::1",
        ] {
            assert!(is_pattern(ok), "{ok}");
        }
    }
}
