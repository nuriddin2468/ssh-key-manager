//! Directives that make `ssh` run a program or load code on this computer,
//! hand the server access to it, send that access to another server, or
//! check less whether a server is the real one, whenever the user connects.
//! A change that adds one must be approved by the user outside the webview,
//! so the app finds the ones an edit adds.
//!
//! The list follows `ssh_config(5)`. Run code ([`Risk::RunsCode`]):
//!
//! - run a program: `ProxyCommand`, `LocalCommand` (and `PermitLocalCommand`,
//!   which turns it on), `KnownHostsCommand`, `Match … exec`, `XAuthLocation`;
//! - load a library: `PKCS11Provider` (also spelled `SmartcardDevice`),
//!   `SecurityKeyProvider`;
//! - read more configuration from elsewhere, which may do any of the above:
//!   `Include`;
//! - choose who signs with the user's keys: `IdentityAgent`;
//! - names that `%h`, `%n`, `%r`, `%k` and `%j` put into the commands above,
//!   when they hold anything but name characters: `Host` patterns,
//!   `HostName`, `User`, `HostKeyAlias`, `ProxyJump` (which `ssh` itself also
//!   runs through the shell). OpenSSH checks such names only on its command
//!   line, so `HostName $(…)` would run through a `ProxyCommand` that is
//!   already there;
//! - any line with a control character other than a tab, and any keyword
//!   written other than as letters and digits (once its quotes are taken
//!   out, see [`keyword`]): `ssh` may read such a line differently from this
//!   parser, so no spelling it accepts slips by. The whole line is shown.
//!
//! Let the server use this computer ([`Risk::ServerAccess`]): `ForwardAgent`
//! (it can sign in elsewhere with every key in the agent while the session
//! lasts), `ForwardX11` and `ForwardX11Trusted` (it can read and type into
//! the display), and a `RemoteForward` that is dynamic (the server reaches
//! anything this computer can) or leads to a local socket or a path built
//! from variables (`${SSH_AUTH_SOCK}` hands over the agent, the Docker
//! socket the computer).
//!
//! Say which server gets that access ([`Risk::Destination`]): `HostName`,
//! `Port`, `User`, `ProxyJump`, `HostKeyAlias`, `CanonicalDomains` and
//! `CanonicalizeHostname`, in a block such access may apply to: a block with
//! such a directive (or an odd line), or one that may match the same host.
//! The options before the first block and a `Match` block may match any
//! host; a `Host` block the names its patterns match, and two patterns with
//! `*` or `?` are taken to meet. Like every directive here, they count as
//! new under a changed `Host` or `Match` line too. So pointing a block that
//! forwards the agent at another server asks, and editing a block that no
//! such access applies to does not. Files read through `Include` are not
//! looked at (adding an `Include` asks anyway).
//!
//! Check less whether the server is the real one ([`Risk::HostKeys`]):
//! `StrictHostKeyChecking` other than `yes` or `ask` (new keys accepted
//! unasked), `UserKnownHostsFile` and `GlobalKnownHostsFile` (which keys
//! are trusted), `VerifyHostKeyDNS` other than `no` or `ask` (keys trusted
//! from DNS), `NoHostAuthenticationForLocalhost` other than `no`.
//!
//! `RemoteCommand` is not on the list: it runs on the server, which can run
//! anything there anyway.
//!
//! The keyword is read as OpenSSH reads it: in any case and without its
//! quotes, and the value as [`lex`] reads it for that keyword.
//!
//! [`keyword`]: super::lexer::keyword

use std::collections::HashMap;

use super::SshConfig;
use super::lexer::{Directive, LineKind, is_trailing_ws, lex, split_args};

/// What a directive that needs approval lets happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Risk {
    /// `ssh` runs a program or loads code on this computer.
    RunsCode,
    /// The server can use this computer.
    ServerAccess,
    /// It says which server gets such access.
    Destination,
    /// `ssh` checks less whether the server is the real one.
    HostKeys,
}

impl Risk {
    /// Every kind, in the order the confirmation lists them.
    pub const ALL: [Self; 4] = [
        Self::RunsCode,
        Self::ServerAccess,
        Self::Destination,
        Self::HostKeys,
    ];
}

/// One directive that needs approval, as written in the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskyDirective {
    /// The `Host …` or `Match …` line of the block it is in (or that it is,
    /// for `Match … exec` and odd `Host` patterns); `None` before the first
    /// block, where it applies to every host.
    pub block: Option<String>,
    /// The keyword as written (`Match` or `Host` for a block line).
    pub key: String,
    /// The value as written; for an odd line (see the module documentation)
    /// everything after the keyword, comment included.
    pub value: String,
    /// What it lets happen.
    pub risk: Risk,
}

/// What two directives must share to be the same one: the block, the keyword
/// in lower case and the value.
type Identity = (Option<String>, String, String);

/// Keywords that say where a connection goes (see [`Risk::Destination`]).
const DESTINATION: &[&str] = &[
    "hostname",
    "port",
    "user",
    "proxyjump",
    "hostkeyalias",
    "canonicaldomains",
    "canonicalizehostname",
];

impl SshConfig {
    /// Every directive of the file that needs approval (see the module
    /// documentation), in file order.
    pub fn risky_directives(&self) -> Vec<RiskyDirective> {
        self.risky_with_identity()
            .into_iter()
            .map(|(directive, _)| directive)
            .collect()
    }

    /// The directives that need approval in `self` that `before` does not
    /// have in the same block with the same value: what saving `self` over
    /// `before` adds. Directives that are only removed, moved within their
    /// block or left alone are not reported, so an edit elsewhere in the file
    /// asks nothing.
    pub fn added_risky_directives(&self, before: &SshConfig) -> Vec<RiskyDirective> {
        let mut known: HashMap<Identity, usize> = HashMap::new();
        for (_, identity) in before.risky_with_identity() {
            *known.entry(identity).or_default() += 1;
        }
        self.risky_with_identity()
            .into_iter()
            .filter_map(|(directive, identity)| match known.get_mut(&identity) {
                Some(count) if *count > 0 => {
                    *count -= 1;
                    None
                }
                _ => Some(directive),
            })
            .collect()
    }

    fn risky_with_identity(&self) -> Vec<(RiskyDirective, Identity)> {
        // The options before the first block, then one scope per block.
        let mut scopes = vec![Scope {
            header: None,
            patterns: None,
            access: false,
        }];
        // Directives that need approval, and those that do if access
        // applies to their block (`None`), with the index of the block.
        let mut found: Vec<(usize, Option<Risk>, RiskyDirective, Identity)> = Vec::new();
        for line in &self.lines {
            let LineKind::Directive(d) = lex(&line.text) else {
                continue;
            };
            let keyword = d.keyword();
            let key = keyword.clone().unwrap_or_else(|| d.key_lower());
            if key == "host" || key == "match" {
                scopes.push(Scope::new(&key, &d));
            }
            let scope = scopes.len() - 1;
            let rest = &line.text[d.indent.len() + d.key.len() + d.sep.len()..];
            let rest = rest.trim_end_matches(is_trailing_ws);
            let odd = keyword.is_none() || rest.chars().any(is_odd_control);
            let (risk, value) = if odd {
                (Some(Risk::RunsCode), rest)
            } else {
                (risk(&key, &d, rest), d.value)
            };
            // An odd line may be anything to `ssh`, a `ForwardAgent` too.
            if odd || risk == Some(Risk::ServerAccess) {
                scopes[scope].access = true;
            }
            if risk.is_none() && !DESTINATION.contains(&key.as_str()) {
                continue;
            }
            let header = scopes[scope].header.as_ref();
            let identity = (
                header.map(|(_, compared)| compared.clone()),
                key,
                value.to_owned(),
            );
            let directive = RiskyDirective {
                block: header.map(|(written, _)| written.clone()),
                key: d.key.to_owned(),
                value: value.to_owned(),
                risk: Risk::RunsCode,
            };
            found.push((scope, risk, directive, identity));
        }
        // Worked out once per block that needs it.
        let mut reached: Vec<Option<bool>> = vec![None; scopes.len()];
        found
            .into_iter()
            .filter_map(|(scope, risk, mut directive, identity)| {
                directive.risk = match risk {
                    Some(risk) => risk,
                    None if *reached[scope]
                        .get_or_insert_with(|| access_applies(&scopes, scope)) =>
                    {
                        Risk::Destination
                    }
                    None => return None,
                };
                Some((directive, identity))
            })
            .collect()
    }
}

/// The options before the first block, or one block.
struct Scope {
    /// The `Host …` or `Match …` line as written and in the form compared:
    /// keyword in lower case, arguments unquoted, so re-quoting a header
    /// changes nothing. `None` before the first block.
    header: Option<(String, String)>,
    /// The patterns of a `Host` block that may match a host, in lower case;
    /// `None` if it may apply to any host (the options before the first
    /// block, `Match`).
    patterns: Option<Vec<String>>,
    /// A directive in it lets the server use this computer.
    access: bool,
}

impl Scope {
    /// The block that the `Host` or `Match` line `d` (keyword `key`) starts.
    fn new(key: &str, d: &Directive<'_>) -> Self {
        let args = split_args(d.value).0;
        // A negated pattern only keeps the block from hosts, so the others
        // are all it may match.
        let patterns = (key == "host").then(|| {
            args.iter()
                .filter(|p| !p.starts_with('!'))
                .map(|p| p.to_lowercase())
                .collect()
        });
        Self {
            header: Some((
                format!("{} {}", d.key, d.value),
                format!("{key} {}", args.join(" ")),
            )),
            patterns,
            access: false,
        }
    }
}

/// Whether a directive that lets the server use this computer may apply to
/// the hosts of `scopes[index]`: one in a block that may match one of them.
fn access_applies(scopes: &[Scope], index: usize) -> bool {
    let here = &scopes[index].patterns;
    scopes
        .iter()
        .filter(|scope| scope.access)
        .any(|there| match (here, &there.patterns) {
            (Some(here), Some(there)) => here
                .iter()
                .any(|a| there.iter().any(|b| may_match_one_host(a, b))),
            _ => true,
        })
}

/// Whether some host matches both `Host` patterns (in lower case): a name
/// that the other one matches, or two patterns with `*` or `?`, which may
/// always meet.
fn may_match_one_host(a: &str, b: &str) -> bool {
    let wild = |p: &str| p.contains(['*', '?']);
    match (wild(a), wild(b)) {
        (true, true) => true,
        (true, false) => matches_pattern(a.as_bytes(), b.as_bytes()),
        (false, _) => matches_pattern(b.as_bytes(), a.as_bytes()),
    }
}

/// `name` against a pattern of `*` (any run) and `?` (any one byte), byte by
/// byte as OpenSSH's `match_pattern()`. Goes back only to the last `*`, so a
/// pattern of many stars takes no more than length times length steps.
pub(crate) fn matches_pattern(pattern: &[u8], name: &[u8]) -> bool {
    let (mut p, mut n) = (0, 0);
    // Where the last `*` was, and how much of `name` it takes so far.
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        if pattern.get(p).is_some_and(|&c| c == b'?' || c == name[n]) {
            p += 1;
            n += 1;
        } else if pattern.get(p) == Some(&b'*') {
            star = Some((p, n));
            p += 1;
        } else if let Some((at, taken)) = star {
            star = Some((at, taken + 1));
            p = at + 1;
            n = taken + 1;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&c| c == b'*')
}

/// What `d` (keyword `key`, in lower case; `rest` everything after it)
/// lets happen, if it needs approval whatever block it is in. Values that
/// turn a feature off or keep the safe default (`none`, `no`, …) are
/// harmless; they are compared case-sensitively, as exactly as OpenSSH does
/// or more so, and anything else counts.
fn risk(key: &str, d: &Directive<'_>, rest: &str) -> Option<Risk> {
    use Risk::{HostKeys, RunsCode, ServerAccess};
    // Commands are taken literally: `"none"` is a program called `none`.
    let literal = d.value;
    let args = split_args(d.value).0;
    let is = |words: &[&str]| matches!(args.as_slice(), [only] if words.contains(&only.as_str()));
    let (risk, risky) = match key {
        "proxycommand" | "localcommand" | "knownhostscommand" => (RunsCode, literal != "none"),
        "pkcs11provider" | "smartcarddevice" => (RunsCode, !is(&["none"])),
        "securitykeyprovider" => (RunsCode, !is(&["internal"])),
        "identityagent" => (RunsCode, !is(&["none", "SSH_AUTH_SOCK"])),
        "permitlocalcommand" => (RunsCode, !is(&["no"])),
        "include" | "xauthlocation" => (RunsCode, true),
        // Any mention of `exec` on the line, comment included, as written
        // or unquoted (`!exec`, `"exec"`, `ex"ec"`, `exec=`), so no form
        // OpenSSH accepts slips by.
        "match" => (
            RunsCode,
            std::iter::once(rest)
                .chain(args.iter().map(String::as_str))
                .any(|text| text.to_ascii_lowercase().contains("exec")),
        ),
        "host" | "hostname" | "user" | "hostkeyalias" | "proxyjump" => (
            RunsCode,
            !args.iter().all(|arg| arg.chars().all(is_name_char)),
        ),
        "forwardagent" | "forwardx11" | "forwardx11trusted" => (ServerAccess, !is(&["no"])),
        // Dynamic (no second argument, or an empty one, as `readconf.c`
        // reads it), or to a local socket or a variable.
        "remoteforward" => (
            ServerAccess,
            match args.as_slice() {
                [_, target, ..] if !target.is_empty() => args[1..]
                    .iter()
                    .any(|arg| arg.contains(['/', '\\', '$', '%'])),
                _ => true,
            },
        ),
        "stricthostkeychecking" => (HostKeys, !is(&["yes", "ask"])),
        "userknownhostsfile" | "globalknownhostsfile" => (HostKeys, true),
        "verifyhostkeydns" => (HostKeys, !is(&["no", "ask"])),
        "nohostauthenticationforlocalhost" => (HostKeys, !is(&["no"])),
        _ => return None,
    };
    risky.then_some(risk)
}

/// A control character other than a tab.
fn is_odd_control(c: char) -> bool {
    c.is_control() && c != '\t'
}

/// Characters of host names, user names (`DOMAIN\user`), patterns (`*`, `?`,
/// `!`), jump host lists (`user@host:port,ssh://…`) and `%` tokens: nothing
/// a shell treats specially.
fn is_name_char(c: char) -> bool {
    c.is_alphanumeric()
        || matches!(
            c,
            '.' | '-' | '_' | ':' | '@' | '%' | '[' | ']' | '*' | '?' | '!' | ',' | '/' | '\\'
        )
}
