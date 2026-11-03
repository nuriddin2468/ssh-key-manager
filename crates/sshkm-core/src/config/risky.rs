//! Directives that make `ssh` run a program or load code on this computer, or
//! hand the server access to it, whenever the user connects. A change that
//! adds one must be approved by the user outside the webview, so the app
//! finds the ones an edit adds.
//!
//! The list follows `ssh_config(5)`:
//!
//! - run a program: `ProxyCommand`, `LocalCommand` (and `PermitLocalCommand`,
//!   which turns it on), `KnownHostsCommand`, `Match … exec`, `XAuthLocation`;
//! - load a library: `PKCS11Provider` (also spelled `SmartcardDevice`),
//!   `SecurityKeyProvider`;
//! - read more configuration from elsewhere, which may do any of the above:
//!   `Include`;
//! - choose who signs with the user's keys: `IdentityAgent`;
//! - let the server use this computer: `ForwardAgent` (it can sign in
//!   elsewhere with every key in the agent while the session lasts),
//!   `ForwardX11` and `ForwardX11Trusted` (it can read and type into the
//!   display), and a `RemoteForward` that is dynamic (the server reaches
//!   anything this computer can) or leads to a local socket or a path built
//!   from variables (`${SSH_AUTH_SOCK}` hands over the agent, the Docker
//!   socket the computer);
//! - names that `%h`, `%n`, `%r`, `%k` and `%j` put into the commands above,
//!   when they hold anything but name characters: `Host` patterns,
//!   `HostName`, `User`, `HostKeyAlias`, `ProxyJump` (which `ssh` itself also
//!   runs through the shell). OpenSSH checks such names only on its command
//!   line, so `HostName $(…)` would run through a `ProxyCommand` that is
//!   already there.
//!
//! `RemoteCommand` is not on the list: it runs on the server, which can run
//! anything there anyway.
//!
//! The keyword is read as OpenSSH reads it: in any case, without the quotes
//! around it and after one leading `=`. A keyword written any other way than
//! as letters and digits counts too, so no spelling `ssh` accepts slips by.

use std::collections::HashMap;

use super::SshConfig;
use super::lexer::{Directive, LineKind, lex, split_args};

/// One directive that runs or loads code, as written in the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskyDirective {
    /// The `Host …` or `Match …` line of the block it is in (or that it is,
    /// for `Match … exec` and odd `Host` patterns); `None` before the first
    /// block, where it applies to every host.
    pub block: Option<String>,
    /// The keyword as written (`Match` or `Host` for a block line).
    pub key: String,
    /// The value as written.
    pub value: String,
}

/// What two directives must share to be the same one: the block, the keyword
/// in lower case and the value.
type Identity = (Option<String>, String, String);

impl SshConfig {
    /// Every directive of the file that runs or loads code (see the module
    /// documentation), in file order.
    pub fn risky_directives(&self) -> Vec<RiskyDirective> {
        self.risky_with_identity()
            .into_iter()
            .map(|(directive, _)| directive)
            .collect()
    }

    /// The directives that run or load code in `self` that `before` does not
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
        let mut out = Vec::new();
        // The block as written and in the form compared: keyword in lower
        // case, arguments unquoted, so re-quoting a header changes nothing.
        let mut block: Option<(String, String)> = None;
        for line in &self.lines {
            let LineKind::Directive(d) = lex(&line.text) else {
                continue;
            };
            let key = keyword(d.key).unwrap_or_else(|| d.key_lower());
            if key == "host" || key == "match" {
                let written = format!("{} {}", d.key, d.value);
                let compared = format!("{key} {}", split_args(d.value).0.join(" "));
                block = Some((written, compared));
            }
            if keyword(d.key).is_none() || is_risky(&key, &d) {
                let identity = (
                    block.as_ref().map(|(_, compared)| compared.clone()),
                    key,
                    d.value.to_owned(),
                );
                let directive = RiskyDirective {
                    block: block.as_ref().map(|(written, _)| written.clone()),
                    key: d.key.to_owned(),
                    value: d.value.to_owned(),
                };
                out.push((directive, identity));
            }
        }
        out
    }
}

/// The keyword as OpenSSH reads it, in lower case: after one leading `=`
/// and without the quotes around it. `None` for anything that is not then
/// letters and digits.
fn keyword(written: &str) -> Option<String> {
    let key = written.strip_prefix('=').unwrap_or(written);
    let key = key
        .strip_prefix('"')
        .and_then(|k| k.strip_suffix('"'))
        .unwrap_or(key);
    (!key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric()))
        .then(|| key.to_ascii_lowercase())
}

/// Whether `d` (keyword `key`, in lower case) runs or loads code. Values
/// that turn a feature off (`none`, `no`, …) are harmless; they are compared
/// exactly as OpenSSH does (case-sensitively), so anything else counts.
fn is_risky(key: &str, d: &Directive<'_>) -> bool {
    // Commands are taken literally: `"none"` is a program called `none`.
    let literal = d.value;
    let args = split_args(d.value).0;
    let is = |word: &str| matches!(args.as_slice(), [only] if only == word);
    match key {
        "proxycommand" | "localcommand" | "knownhostscommand" => literal != "none",
        "pkcs11provider" | "smartcarddevice" => !is("none"),
        "securitykeyprovider" => !is("internal"),
        "identityagent" => !is("none") && !is("SSH_AUTH_SOCK"),
        "permitlocalcommand" | "forwardagent" | "forwardx11" | "forwardx11trusted" => !is("no"),
        "include" | "xauthlocation" => true,
        // Dynamic (one argument), or to a local socket or a variable.
        "remoteforward" => {
            args.len() < 2
                || args[1..]
                    .iter()
                    .any(|arg| arg.contains(['/', '\\', '$', '%']))
        }
        // Any mention of `exec` in the criteria, as written or unquoted
        // (`!exec`, `"exec"`, `ex"ec"`, `exec=`), so no form OpenSSH accepts
        // slips by.
        "match" => std::iter::once(d.value)
            .chain(args.iter().map(String::as_str))
            .any(|text| text.to_ascii_lowercase().contains("exec")),
        "host" | "hostname" | "user" | "hostkeyalias" | "proxyjump" => {
            !args.iter().all(|arg| arg.chars().all(is_name_char))
        }
        _ => false,
    }
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
