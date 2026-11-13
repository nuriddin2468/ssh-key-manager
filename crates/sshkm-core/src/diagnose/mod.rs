//! Why an `ssh` run failed, read from what it printed, as a cause the UI can
//! explain in plain words and offer a fix for.
//!
//! `ssh` writes its messages in English on every system, in wordings that
//! have held from OpenSSH 8 to 9; only the system's error strings differ
//! (`Operation timed out` on macOS, `Connection timed out` on Linux and
//! Windows). With `-v` it also says which keys it offered, which this reads
//! too.
//!
//! Debug lines are kept only when they say something about the cause: other
//! ones can hold the values of environment variables `ssh` sends (`SendEnv`).
//! [`readable`] drops them all from what the user reads.

mod probe;
#[cfg(test)]
mod tests;

use serde::Serialize;

pub use self::probe::{PortProbe, ProbeOutcome, probe};
use crate::perms::PermKind;

/// What the caller knows about the run besides its output, from `ssh -G`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Context {
    /// `HostName`, to tell the host's messages from a jump host's.
    pub host_name: Option<String>,
    /// `ProxyJump` as `ssh -G` gives it (`bastion`, `alice@a:2222,b`).
    pub proxy_jump: Option<String>,
    /// The app's own timeout stopped `ssh`.
    pub timed_out: bool,
}

/// Why a run failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct Diagnosis {
    pub cause: Cause,
    /// The jump host the failure happened at, by its `ProxyJump` name when
    /// there is one jump, else as `ssh` named it; `None` for the host itself.
    pub hop: Option<String>,
    /// The lines of `ssh`'s output that show the cause, in order.
    pub lines: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum Cause {
    /// `Permission denied (publickey)`: the server turned down every key.
    KeysRejected {
        /// The keys `ssh` offered, in order (only with `-v`).
        offered: Vec<TriedKey>,
        /// The server also takes a password, which was not tried.
        #[serde(rename = "passwordAllowed")]
        password_allowed: bool,
    },
    /// The server would take a key, but `ssh` could not open it: its
    /// passphrase was not given (and it is not in the agent).
    KeyLocked { key: String },
    /// An `IdentityFile` names a file that is not there.
    IdentityFileMissing { path: String },
    /// The server turned down the password (or the answers to its
    /// keyboard-interactive questions).
    PasswordRejected,
    /// The server signs in with a password or its own questions only, and
    /// none was given.
    PasswordRequired,
    /// The server disconnected after too many failed sign-ins: `ssh` offered
    /// more keys than its `MaxAuthTries`.
    TooManyAuthFailures { offered: Vec<TriedKey> },
    /// `ssh` does not know the server's key and was not to ask.
    HostKeyUnknown { host: Option<String> },
    /// The server's key is not the one `known_hosts` has for it.
    HostKeyChanged {
        host: Option<String>,
        /// `ED25519`, `ECDSA`, `RSA`, …
        #[serde(rename = "keyType")]
        key_type: Option<String>,
        /// The key the server sent: `SHA256:…`.
        fingerprint: Option<String>,
        /// The saved key, as `<file>:<line>`.
        #[serde(rename = "knownHosts")]
        known_hosts: Option<String>,
    },
    /// No working connection to the server.
    Network {
        problem: NetworkProblem,
        host: Option<String>,
        port: Option<u16>,
    },
    /// The host name does not resolve to an address.
    NameNotResolved { host: String },
    /// `ssh` refuses a file other users can read or change.
    BadPermissions { path: String, file: PermKind },
    /// The server offers only algorithms this `ssh` has turned off as weak.
    Legacy {
        what: Negotiation,
        /// What the server offered.
        offer: Vec<String>,
        /// The option that turns one of them back on for this host:
        /// `HostKeyAlgorithms`, `KexAlgorithms`, …
        option: String,
        /// Its value: `+<algorithm>`.
        value: String,
    },
    /// The jump host or proxy command could not carry the connection.
    Proxy {
        problem: ProxyProblem,
        /// The jump host's reason (`Connection refused`), if it gave one.
        detail: Option<String>,
    },
    /// None of the above.
    Unknown,
}

/// A key `ssh` offered or tried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct TriedKey {
    /// The key file, or for an agent's key its comment.
    pub name: String,
    pub key_type: Option<String>,
    pub fingerprint: Option<String>,
    /// It came from ssh-agent.
    pub agent: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum NetworkProblem {
    /// No answer in time: a wrong address, a firewall that drops, a VPN
    /// that is off.
    TimedOut,
    /// The computer answered, but nothing listens on the port.
    Refused,
    /// No way to the address (`No route to host`, `Host is down`).
    NoRoute,
    /// This computer has no network that leads there.
    NetworkUnreachable,
    /// The connection was cut (`Connection reset`).
    Reset,
    /// The server closed the connection before signing in.
    Closed,
    /// Something answered on the port, but not an SSH server.
    NotSsh,
    /// Another error the system reported.
    Other,
}

/// What `ssh` and the server could not agree on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum Negotiation {
    HostKey,
    KeyExchange,
    Cipher,
    Mac,
    /// A signature algorithm for the user's key (old servers sign RSA keys
    /// with SHA-1 only).
    Signature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum ProxyProblem {
    /// The jump host could not connect to the next host.
    NextHopUnreachable,
    /// The jump host does not allow forwarding (`AllowTcpForwarding no`).
    ForwardingProhibited,
    /// The `ProxyCommand` failed, such as a command that is not installed.
    CommandFailed,
    /// The connection through the proxy closed before the server answered.
    Closed,
}

/// Why `ssh` failed, from its output (with or without `-v`). Call it for a
/// run that failed: it does not tell a good run from a bad one.
pub fn diagnose(output: &str, context: &Context) -> Diagnosis {
    let run = Run::new(output);
    let (cause, lines, named) = run.cause(context);
    let hop = hop(&run, context, &cause, named.as_deref(), &lines);
    let lines = lines.into_iter().map(|i| run.lines[i].to_owned()).collect();
    Diagnosis { cause, hop, lines }
}

/// What `ssh -v` printed, for a person to read: without its debug lines, its
/// version, the server's banner and its closing statistics, which a run
/// without `-v` would not have shown either.
pub fn readable(output: &str) -> String {
    let mut banner = false;
    let mut kept = Vec::new();
    for line in output.lines().map(|line| line.trim_end_matches('\r')) {
        if let Some(debug) = debug_text(line) {
            // The server's banner comes between the service's acceptance and
            // the first list of methods.
            if debug.starts_with("SSH2_MSG_SERVICE_ACCEPT received") {
                banner = true;
            } else if debug.starts_with("Authentications that can continue") {
                banner = false;
            }
            continue;
        }
        let noise = is_version(line)
            || line.starts_with("Transferred: sent ")
            || line.starts_with("Bytes per second: ")
            || line.starts_with("Authenticated to ");
        // `ssh`'s own messages still show if the server closes meanwhile.
        let own = BANNER_BREAKERS.iter().any(|start| line.starts_with(start));
        if !noise && (!banner || own) {
            kept.push(line);
        }
    }
    kept.join("\n").trim().to_owned()
}

/// The beginnings of `ssh`'s messages that may come before the server's
/// banner has ended, which [`readable`] keeps.
const BANNER_BREAKERS: [&str; 7] = [
    "Connection ",
    "Received disconnect",
    "Disconnected from",
    "Permission denied",
    "ssh: ",
    "Load key",
    "Too many authentication failures",
];

/// The text of a `debug1:`, `debug2:` or `debug3:` line.
fn debug_text(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("debug")?;
    let (level, text) = rest.split_once(": ")?;
    (level.len() == 1 && level.as_bytes()[0].is_ascii_digit()).then_some(text)
}

/// `OpenSSH_9.9p2, LibreSSL 3.3.6`, `OpenSSH_for_Windows_9.5p1, LibreSSL 3.8.2`;
/// OpenSSH 10 logs it as a debug line (`debug1: OpenSSH_10.5p1, …`).
fn is_version(line: &str) -> bool {
    let line = debug_text(line).unwrap_or(line);
    line.starts_with("OpenSSH_") && line.contains(", ")
}

/// The output as lines, and what is found where.
struct Run<'a> {
    lines: Vec<&'a str>,
}

/// A cause, the lines that show it, and the host its deciding line names.
type Found = (Cause, Vec<usize>, Option<String>);

impl<'a> Run<'a> {
    fn new(output: &'a str) -> Self {
        Self {
            lines: output
                .lines()
                .map(|line| line.trim_end_matches('\r').trim_end())
                .collect(),
        }
    }

    /// The index of the first line containing `needle`.
    fn find(&self, needle: &str) -> Option<usize> {
        self.lines.iter().position(|line| line.contains(needle))
    }

    /// The indices of every line containing one of `needles`.
    fn all(&self, needles: &[&str]) -> Vec<usize> {
        (0..self.lines.len())
            .filter(|&i| needles.iter().any(|needle| self.lines[i].contains(needle)))
            .collect()
    }

    /// Where the sign-in that ends at line `end` starts: after the last one
    /// that succeeded before it (a jump host's), else at the start.
    fn sign_in_start(&self, end: usize) -> usize {
        self.lines[..end]
            .iter()
            .rposition(|line| {
                line.starts_with("Authenticated to ")
                    || debug_text(line)
                        .is_some_and(|text| text.starts_with("Authentication succeeded"))
            })
            .map_or(0, |i| i + 1)
    }

    /// The debug lines in `range` whose text starts with `start`.
    fn debug_in(&self, range: std::ops::Range<usize>, start: &str) -> Vec<usize> {
        range
            .filter(|&i| debug_text(self.lines[i]).is_some_and(|text| text.starts_with(start)))
            .collect()
    }

    /// The proxy closed under `ssh` after line `after`: a jump host's or the
    /// proxy command's failure, not the host's.
    fn proxy_closed_after(&self, after: usize) -> bool {
        self.lines[after + 1..]
            .iter()
            .any(|line| line.starts_with("Connection closed by UNKNOWN"))
    }

    fn cause(&self, context: &Context) -> Found {
        self.config_permissions()
            .or_else(|| self.unresolved())
            .or_else(|| self.unreachable())
            .or_else(|| self.legacy())
            .or_else(|| self.host_key())
            .or_else(|| self.forwarding())
            .or_else(|| self.too_many())
            .or_else(|| self.key_permissions())
            .or_else(|| self.denied())
            .or_else(|| self.proxy(context))
            .or_else(|| self.closed())
            .unwrap_or_else(|| self.unknown(context))
    }

    /// `Bad owner or permissions on /home/alice/.ssh/config`; on Windows
    /// after `Bad permissions. Try removing permissions for user: …`.
    fn config_permissions(&self) -> Option<Found> {
        let i = self.find("Bad owner or permissions on ")?;
        let (_, path) = self.lines[i].split_once("Bad owner or permissions on ")?;
        let mut lines = self.all(&["Bad permissions. Try removing permissions"]);
        lines.push(i);
        lines.sort_unstable();
        lines.dedup();
        Some((
            Cause::BadPermissions {
                path: path.trim().to_owned(),
                file: PermKind::Config,
            },
            lines,
            None,
        ))
    }

    /// `ssh: Could not resolve hostname nope: Name or service not known`.
    fn unresolved(&self) -> Option<Found> {
        let i = self.find("Could not resolve hostname ")?;
        let (_, rest) = self.lines[i].split_once("Could not resolve hostname ")?;
        let host = rest.split_once(": ").map_or(rest, |(host, _)| host).trim();
        Some((
            Cause::NameNotResolved {
                host: host.to_owned(),
            },
            vec![i],
            Some(host.to_owned()),
        ))
    }

    /// A connection that failed or was cut before `ssh` and the server
    /// talked: `ssh: connect to host h port 22: Connection refused`, a reset,
    /// a timeout in the banner exchange, a banner that is not SSH.
    fn unreachable(&self) -> Option<Found> {
        if let Some(i) = self.find("ssh: connect to host ") {
            let (_, rest) = self.lines[i].split_once("ssh: connect to host ")?;
            let (host, rest) = rest.split_once(" port ")?;
            let (port, reason) = rest.split_once(": ")?;
            return Some((
                Cause::Network {
                    problem: network_problem(reason).unwrap_or(NetworkProblem::Other),
                    host: Some(host.to_owned()),
                    port: port.parse().ok(),
                },
                vec![i],
                Some(host.to_owned()),
            ));
        }
        let not_ssh = self
            .lines
            .iter()
            .position(|line| {
                (line.starts_with("banner exchange: ") && line.contains("invalid format"))
                    || line.contains("banner line contains invalid characters")
                    || line.contains("Bad protocol version identification")
            })
            .map(|i| (i, NetworkProblem::NotSsh));
        let timed_out = self
            .find("timed out during banner exchange")
            .map(|i| (i, NetworkProblem::TimedOut));
        let reset = self
            .lines
            .iter()
            .position(|line| {
                line.contains("exchange_identification: read: Connection reset")
                    || (line.starts_with("Connection reset by ")
                        && !line.starts_with("Connection reset by UNKNOWN"))
            })
            .map(|i| (i, NetworkProblem::Reset));
        let (i, problem) = not_ssh.or(timed_out).or(reset)?;
        // `Connection to h port 22 timed out`, `Connection reset by h port 22`.
        let mut lines = vec![i];
        let mut address = address_in(self.lines[i]);
        if let Some(next) = self.lines.get(i + 1).filter(|line| {
            line.starts_with("Connection to ") || line.starts_with("Connection reset by ")
        }) {
            lines.push(i + 1);
            address = address.or_else(|| address_in(next));
        }
        let (host, port) = address.unzip();
        Some((
            Cause::Network {
                problem,
                host: host.clone(),
                port,
            },
            lines,
            host,
        ))
    }

    /// `Unable to negotiate with h port 22: no matching host key type found.
    /// Their offer: ssh-rsa`, or with `-v` a key the server can only check
    /// with SHA-1 signatures.
    fn legacy(&self) -> Option<Found> {
        if let Some(i) = self.find("Unable to negotiate with ") {
            let line = self.lines[i];
            let what = [
                ("no matching host key type", Negotiation::HostKey),
                ("no matching key exchange method", Negotiation::KeyExchange),
                ("no matching cipher", Negotiation::Cipher),
                ("no matching MAC", Negotiation::Mac),
            ]
            .into_iter()
            .find(|(text, _)| line.contains(text))?
            .1;
            let offer: Vec<String> = line
                .split_once("Their offer: ")
                .map(|(_, offer)| offer)
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                // Markers, not algorithms.
                .filter(|a| {
                    !a.is_empty() && !a.starts_with("ext-info-") && !a.starts_with("kex-strict-")
                })
                .map(str::to_owned)
                .collect();
            let (option, value) = legacy_option(what, &offer)?;
            let host = line
                .split_once("Unable to negotiate with ")
                .and_then(|(_, rest)| rest.split_once(" port "))
                .map(|(host, _)| host.to_owned());
            return Some((
                Cause::Legacy {
                    what,
                    offer,
                    option,
                    value,
                },
                vec![i],
                host,
            ));
        }
        let i = self.find("no mutual signature")?;
        let denied = self.find("Permission denied")?;
        Some((
            Cause::Legacy {
                what: Negotiation::Signature,
                offer: vec!["ssh-rsa".to_owned()],
                option: "PubkeyAcceptedAlgorithms".to_owned(),
                value: "+ssh-rsa".to_owned(),
            },
            vec![i, denied],
            denied_host(self.lines[denied]),
        ))
    }

    /// `REMOTE HOST IDENTIFICATION HAS CHANGED`, or a key `ssh` does not know
    /// with strict checking on (`Host key verification failed.`).
    fn host_key(&self) -> Option<Found> {
        let failed = self.find("Host key verification failed");
        let changed = self
            .find("REMOTE HOST IDENTIFICATION HAS CHANGED")
            .or_else(|| self.find("HOST KEY HAS CHANGED"));
        if let Some(start) = changed {
            // The warning's frame starts a line before its title.
            let start = start.saturating_sub(1);
            let end = failed.unwrap_or(self.lines.len() - 1).max(start);
            let block = &self.lines[start..=end];
            let key_type = block.iter().find_map(|line| {
                line.split_once("The fingerprint for the ")
                    .and_then(|(_, rest)| rest.split_once(" key sent by the remote host"))
                    .map(|(kind, _)| kind.to_owned())
            });
            let fingerprint = block
                .iter()
                .find(|line| line.starts_with("SHA256:") || line.starts_with("MD5:"))
                .map(|line| line.trim_end_matches('.').to_owned());
            let known_hosts = block.iter().find_map(|line| {
                let (_, rest) = line.split_once("Offending ")?;
                rest.split_once(" in ").map(|(_, at)| at.trim().to_owned())
            });
            // `Host key for h has changed …`; before OpenSSH 8.5
            // `ECDSA host key for h has changed …`.
            let host = block.iter().find_map(|line| {
                line.split_once("ost key for ")
                    .and_then(|(_, rest)| rest.split_once(" has changed"))
                    .map(|(host, _)| host.to_owned())
            });
            return Some((
                Cause::HostKeyChanged {
                    host: host.clone(),
                    key_type,
                    fingerprint,
                    known_hosts,
                },
                (start..=end).collect(),
                host,
            ));
        }
        let failed = failed?;
        // `No ED25519 host key is known for h and you have requested strict checking.`
        let known = self.lines[..failed]
            .iter()
            .rposition(|line| line.contains(" host key is known for "));
        let host = known.and_then(|i| {
            self.lines[i]
                .split_once(" host key is known for ")
                .and_then(|(_, rest)| rest.split_once(" and you have requested"))
                .map(|(host, _)| host.to_owned())
        });
        Some((
            Cause::HostKeyUnknown { host: host.clone() },
            known.into_iter().chain([failed]).collect(),
            host,
        ))
    }

    /// A jump host that signed in but could not open the way on:
    /// `channel 0: open failed: connect failed: Connection refused`.
    fn forwarding(&self) -> Option<Found> {
        let i = self
            .lines
            .iter()
            .position(|line| line.starts_with("channel ") && line.contains(": open failed: "))?;
        let (_, reason) = self.lines[i].split_once(": open failed: ")?;
        let mut lines = vec![i];
        lines.extend(self.find("stdio forwarding failed"));
        let found = if reason.starts_with("administratively prohibited") {
            (ProxyProblem::ForwardingProhibited, None)
        } else {
            let detail = reason.strip_prefix("connect failed: ").unwrap_or(reason);
            (
                ProxyProblem::NextHopUnreachable,
                Some(detail.trim().to_owned()),
            )
        };
        Some((
            Cause::Proxy {
                problem: found.0,
                detail: found.1,
            },
            lines,
            None,
        ))
    }

    /// `Received disconnect from h port 22:2: Too many authentication failures`.
    fn too_many(&self) -> Option<Found> {
        let i = self.find("Too many authentication failures")?;
        let from = self.sign_in_start(i);
        let mut lines = self.debug_in(from..i, "Offering public key");
        lines.push(i);
        lines.extend(
            self.lines
                .get(i + 1)
                .filter(|line| line.starts_with("Disconnected from "))
                .map(|_| i + 1),
        );
        Some((
            Cause::TooManyAuthFailures {
                offered: self.offered(from..i),
            },
            lines,
            address_in(self.lines[i]).map(|(host, _)| host),
        ))
    }

    /// `WARNING: UNPROTECTED PRIVATE KEY FILE!`: `ssh` ignored a key.
    fn key_permissions(&self) -> Option<Found> {
        let start = self.find("UNPROTECTED PRIVATE KEY FILE")?;
        let start = start.saturating_sub(1);
        // Windows names the account to take off first.
        let start = match start.checked_sub(1) {
            Some(before) if self.lines[before].starts_with("Bad permissions. Try removing") => {
                before
            }
            _ => start,
        };
        let end = self.lines[start..]
            .iter()
            .position(|line| line.contains("bad permissions") || line.contains("will be ignored"))
            .map_or(start, |offset| start + offset);
        // `Load key "…": bad permissions` follows `This private key will be ignored.`
        let end = match self.lines.get(end + 1) {
            Some(line) if line.contains("bad permissions") => end + 1,
            _ => end,
        };
        let block = &self.lines[start..=end];
        let path = block.iter().find_map(|line| {
            // `Permissions 0644 for '/k' are too open.`, `Permissions for 'C:\k' are too open.`
            let (_, rest) = line.split_once(" for '")?;
            rest.split_once("' are too open")
                .map(|(path, _)| path.to_owned())
        });
        let path = path.or_else(|| {
            block.iter().find_map(|line| {
                let (_, rest) = line.split_once("Load key \"")?;
                rest.split_once("\": bad permissions")
                    .map(|(path, _)| path.to_owned())
            })
        })?;
        Some((
            Cause::BadPermissions {
                path,
                file: PermKind::PrivateKey,
            },
            (start..=end).collect(),
            None,
        ))
    }

    /// `alice@h: Permission denied (publickey,password).`, and why.
    fn denied(&self) -> Option<Found> {
        let denied = self
            .lines
            .iter()
            .rposition(|line| line.contains("Permission denied ("));
        let retry = self.find("Permission denied, please try again");
        let i = denied.or(retry)?;
        let host = denied_host(self.lines[i]);
        let methods = methods(self.lines[i]);
        // Only this sign-in's lines, not a jump host's that succeeded.
        let from = self.sign_in_start(i);
        let offered = self.offered(from..i);

        let missing = self.lines.iter().position(|line| {
            line.starts_with("no such identity: ")
                || (line.contains("Identity file ") && line.contains(" not accessible"))
        });
        if let Some(m) = missing {
            let line = self.lines[m];
            let path = line
                .strip_prefix("no such identity: ")
                .and_then(|rest| rest.rsplit_once(": "))
                .map(|(path, _)| path)
                .or_else(|| {
                    line.split_once("Identity file ")
                        .and_then(|(_, rest)| rest.split_once(" not accessible"))
                        .map(|(path, _)| path)
                });
            if let Some(path) = path {
                return Some((
                    Cause::IdentityFileMissing {
                        path: path.trim().to_owned(),
                    },
                    vec![m, i],
                    host,
                ));
            }
        }

        let password_tried = retry.is_some()
            || self.lines[from..i]
                .iter()
                .filter_map(|line| debug_text(line))
                .any(|text| {
                    text == "Next authentication method: password"
                        || text == "Next authentication method: keyboard-interactive"
                });
        if password_tried {
            let mut lines = self.debug_in(from..i, "Next authentication method: password");
            lines
                .extend(self.debug_in(from..i, "Next authentication method: keyboard-interactive"));
            lines.extend(retry);
            lines.push(i);
            lines.sort_unstable();
            lines.dedup();
            return Some((Cause::PasswordRejected, lines, host));
        }

        // A key the server took, which `ssh` then could not open.
        let accepted = self.debug_in(from..i, "Server accepts key: ");
        if let Some(&a) = accepted.last() {
            let key = debug_text(self.lines[a])
                .and_then(|text| text.strip_prefix("Server accepts key: "))
                .map(tried_key)
                .map(|key| key.name)
                .unwrap_or_default();
            return Some((Cause::KeyLocked { key }, vec![a, i], host));
        }
        if let Some(wrong) = self.find("incorrect passphrase supplied") {
            let key = self.lines[wrong]
                .split_once("Load key \"")
                .and_then(|(_, rest)| rest.split_once('"'))
                .map(|(key, _)| key.to_owned())
                .unwrap_or_default();
            return Some((Cause::KeyLocked { key }, vec![wrong, i], host));
        }

        let takes = |method: &str| methods.iter().any(|m| m == method);
        let password_allowed = takes("password") || takes("keyboard-interactive");
        if !methods.is_empty() && !takes("publickey") && password_allowed {
            return Some((Cause::PasswordRequired, vec![i], host));
        }
        let mut lines = self.debug_in(from..i, "Offering public key");
        lines.extend(self.debug_in(from..i, "Trying private key"));
        lines.push(i);
        lines.sort_unstable();
        Some((
            Cause::KeysRejected {
                offered,
                password_allowed,
            },
            lines,
            host,
        ))
    }

    /// The keys `ssh -v` offered in `range`, in order, each once.
    fn offered(&self, range: std::ops::Range<usize>) -> Vec<TriedKey> {
        let mut keys: Vec<TriedKey> = Vec::new();
        for text in self.lines[range].iter().filter_map(|line| debug_text(line)) {
            let key = if let Some(rest) = text.strip_prefix("Offering public key: ") {
                tried_key(rest)
            } else if let Some(path) = text.strip_prefix("Trying private key: ") {
                TriedKey {
                    name: path.trim().to_owned(),
                    key_type: None,
                    fingerprint: None,
                    agent: false,
                }
            } else {
                continue;
            };
            let seen = keys.iter().any(|k| {
                k.name == key.name || (k.fingerprint.is_some() && k.fingerprint == key.fingerprint)
            });
            if !seen {
                keys.push(key);
            }
        }
        keys
    }

    /// The proxy closed under `ssh` with nothing more specific said: a
    /// `ProxyCommand` that failed (`zsh:1: command not found: …`), or a jump
    /// host that went away.
    fn proxy(&self, context: &Context) -> Option<Found> {
        let closed = self.find("Connection closed by UNKNOWN")?;
        // What the proxy printed: lines before `ssh`'s own about the closed
        // connection that are not `ssh`'s debug lines.
        let mut lines: Vec<usize> = (0..closed)
            .filter(|&i| {
                let line = self.lines[i];
                debug_text(line).is_none_or(|text| text.starts_with("Executing proxy command"))
                    && !is_version(line)
                    && !line.is_empty()
            })
            .collect();
        lines.push(closed);
        let problem = if context.proxy_jump.is_some() {
            ProxyProblem::Closed
        } else {
            ProxyProblem::CommandFailed
        };
        Some((
            Cause::Proxy {
                problem,
                detail: None,
            },
            lines,
            None,
        ))
    }

    /// `Connection closed by h port 22` before signing in.
    fn closed(&self) -> Option<Found> {
        let i = self.lines.iter().position(|line| {
            line.starts_with("Connection closed by ") && !line.contains("UNKNOWN")
        })?;
        let mut lines: Vec<usize> = self.all(&["exchange_identification: Connection closed"]);
        lines.push(i);
        lines.sort_unstable();
        lines.dedup();
        let (host, port) = address_in(self.lines[i]).unzip();
        Some((
            Cause::Network {
                problem: NetworkProblem::Closed,
                host: host.clone(),
                port,
            },
            lines,
            host,
        ))
    }

    /// Nothing recognised: what `ssh` printed besides debug lines, at most
    /// its last dozen lines.
    fn unknown(&self, context: &Context) -> Found {
        let lines: Vec<usize> = (0..self.lines.len())
            .filter(|&i| {
                let line = self.lines[i];
                debug_text(line).is_none() && !is_version(line) && !line.is_empty()
            })
            .collect();
        let lines = lines[lines.len().saturating_sub(12)..].to_vec();
        if context.timed_out {
            let cause = Cause::Network {
                problem: NetworkProblem::TimedOut,
                host: None,
                port: None,
            };
            return (cause, lines, None);
        }
        (Cause::Unknown, lines, None)
    }
}

/// Where a failure happened: the jump host whose messages decided it, or
/// `None` for the host itself.
fn hop(
    run: &Run<'_>,
    context: &Context,
    cause: &Cause,
    named: Option<&str>,
    lines: &[usize],
) -> Option<String> {
    let jumps = jumps(context.proxy_jump.as_deref()?);
    let only = (jumps.len() == 1).then(|| jumps[0].clone());
    match cause {
        // The last jump host forwards to the host itself.
        Cause::Proxy {
            problem: ProxyProblem::NextHopUnreachable | ProxyProblem::ForwardingProhibited,
            ..
        } => jumps.last().cloned(),
        Cause::Proxy { .. } => jumps.first().cloned(),
        _ => {
            let last = *lines.last()?;
            let other_host = named.is_some_and(|named| {
                context
                    .host_name
                    .as_deref()
                    .is_some_and(|host| host != named)
            });
            if run.proxy_closed_after(last) || other_host {
                only.or_else(|| named.map(str::to_owned))
                    .or_else(|| jumps.first().cloned())
            } else {
                None
            }
        }
    }
}

/// The hosts of a `ProxyJump` (`alice@a:2222,ssh://b`), without users and
/// ports.
fn jumps(proxy_jump: &str) -> Vec<String> {
    proxy_jump
        .split(',')
        .map(|spec| jump(spec).0)
        .filter(|host| !host.is_empty() && host != "none")
        .collect()
}

/// The first host of a `ProxyJump`, the one this computer connects to, and
/// its port if the `ProxyJump` names one.
pub fn first_jump(proxy_jump: &str) -> Option<(String, Option<u16>)> {
    let (host, port) = jump(proxy_jump.split(',').next()?);
    (!host.is_empty() && host != "none").then_some((host, port))
}

/// `[user@]host[:port]`, `ssh://[user@]host[:port]`, `[v6]:port`.
fn jump(spec: &str) -> (String, Option<u16>) {
    let spec = spec.trim();
    let spec = spec.strip_prefix("ssh://").unwrap_or(spec);
    let spec = spec.rsplit_once('@').map_or(spec, |(_, host)| host);
    let (host, port) = if let Some(rest) = spec.strip_prefix('[') {
        match rest.split_once(']') {
            Some((host, after)) => (host, after.strip_prefix(':')),
            None => (rest, None),
        }
    } else {
        match spec.rsplit_once(':') {
            // A bare IPv6 address has no port.
            Some((host, port))
                if !host.contains(':')
                    && !port.is_empty()
                    && port.bytes().all(|b| b.is_ascii_digit()) =>
            {
                (host, Some(port))
            }
            _ => (spec, None),
        }
    };
    (host.to_owned(), port.and_then(|port| port.parse().ok()))
}

/// `host` and `port` from `… from h port 22…`, `… by h port 22`,
/// `Connection to h port 22 timed out`.
fn address_in(line: &str) -> Option<(String, u16)> {
    let (before, after) = line.split_once(" port ")?;
    let host = before.rsplit(' ').next()?;
    let port: String = after.chars().take_while(char::is_ascii_digit).collect();
    let port = port.parse().ok()?;
    (!host.is_empty() && host != "UNKNOWN").then(|| (host.to_owned(), port))
}

/// The host in `alice@h: Permission denied (…)`.
fn denied_host(line: &str) -> Option<String> {
    let (account, _) = line.split_once(": Permission denied")?;
    let (_, host) = account.rsplit_once('@')?;
    Some(host.to_owned())
}

/// The methods in `Permission denied (publickey,password).`
fn methods(line: &str) -> Vec<String> {
    line.split_once("Permission denied (")
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(methods, _)| {
            methods
                .split(',')
                .map(str::trim)
                .filter(|m| !m.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn network_problem(reason: &str) -> Option<NetworkProblem> {
    let reason = reason.to_ascii_lowercase();
    let has = |text: &str| reason.contains(text);
    Some(if has("timed out") {
        NetworkProblem::TimedOut
    } else if has("refused") {
        NetworkProblem::Refused
    } else if has("no route to host") || has("host is down") || has("host is unreachable") {
        NetworkProblem::NoRoute
    } else if has("network is unreachable") || has("network is down") {
        NetworkProblem::NetworkUnreachable
    } else if has("reset") {
        NetworkProblem::Reset
    } else {
        return None;
    })
}

/// A key as `ssh -v` names it: `<file or comment> <TYPE> <SHA256:…>
/// [explicit] [agent]` (OpenSSH 8.1 and later), or `<TYPE> <SHA256:…>
/// <file>` before.
fn tried_key(text: &str) -> TriedKey {
    const FLAGS: [&str; 4] = ["explicit", "agent", "token", "authenticator"];
    let tokens: Vec<&str> = text.split_whitespace().collect();
    let Some(at) = tokens
        .iter()
        .position(|t| t.starts_with("SHA256:") || t.starts_with("MD5:"))
        .filter(|&at| at > 0)
    else {
        return TriedKey {
            name: text.trim().to_owned(),
            key_type: None,
            fingerprint: None,
            agent: false,
        };
    };
    let after = &tokens[at + 1..];
    let rest: Vec<&str> = after
        .iter()
        .copied()
        .filter(|t| !FLAGS.contains(t))
        .collect();
    let before = tokens[..at - 1].join(" ");
    TriedKey {
        name: if before.is_empty() {
            rest.join(" ")
        } else {
            before
        },
        key_type: Some(tokens[at - 1].to_owned()),
        fingerprint: Some(tokens[at].to_owned()),
        agent: after.contains(&"agent"),
    }
}

/// The option and value that turn one of `offer` back on, preferring the
/// strongest of the old algorithms this `ssh` still has. `None` if the
/// server offered none of them, or a name that cannot go into a config line.
fn legacy_option(what: Negotiation, offer: &[String]) -> Option<(String, String)> {
    let (option, preferred): (&str, &[&str]) = match what {
        Negotiation::HostKey => ("HostKeyAlgorithms", &["ssh-rsa", "ssh-dss"]),
        Negotiation::KeyExchange => (
            "KexAlgorithms",
            &[
                "diffie-hellman-group14-sha1",
                "diffie-hellman-group-exchange-sha1",
                "diffie-hellman-group1-sha1",
            ],
        ),
        Negotiation::Cipher => (
            "Ciphers",
            &["aes256-cbc", "aes192-cbc", "aes128-cbc", "3des-cbc"],
        ),
        Negotiation::Mac => (
            "MACs",
            &["hmac-sha1", "hmac-sha1-96", "hmac-md5", "hmac-md5-96"],
        ),
        Negotiation::Signature => ("PubkeyAcceptedAlgorithms", &["ssh-rsa"]),
    };
    let chosen = preferred
        .iter()
        .find(|p| offer.iter().any(|o| o == *p))
        .map(|p| (*p).to_owned())
        .or_else(|| offer.first().cloned())?;
    let plain = chosen
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-@._".contains(&b));
    plain.then(|| (option.to_owned(), format!("+{chosen}")))
}
