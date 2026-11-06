//! The servers that `ssh`, `autossh`, `mosh`, `scp` and `sftp` commands
//! connect to, read the way those programs read their arguments (OpenSSH's
//! `ssh.c`, `scp.c`, `sftp.c`, `misc.c`), and the passwords typed with them.
//!
//! Nothing but the target and a few options leaves this module: a remote
//! command, file names and every other argument are dropped. A password
//! (`sshpass -p`, `ssh://user:password@`, a `-o` option named like one, an
//! `SSHPASS=` assignment) is only counted.

use std::net::Ipv6Addr;

use super::words::{self, Dialect, Word};
use crate::config::HostOption;

/// A server a command connects to, and how.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Target {
    pub user: Option<String>,
    /// A host name or address; an IPv6 address without brackets.
    pub host: String,
    pub port: Option<u16>,
    /// `-i`, in order.
    pub identity_files: Vec<String>,
    /// `-J`.
    pub proxy_jump: Option<String>,
    /// `-A`.
    pub forward_agent: bool,
    /// `-o` options from [`CARRIED`].
    pub options: Vec<HostOption>,
}

/// What one history entry holds.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Found {
    pub targets: Vec<Target>,
    /// Passwords typed into the command.
    pub secrets: u32,
}

/// `-o` options a suggestion keeps. Others are left out: they change which
/// server or config is used (`HostName`, `Include`), run commands
/// (`ProxyCommand`, `LocalCommand`), weaken host key checks
/// (`StrictHostKeyChecking`, `UserKnownHostsFile`), send the environment, or
/// are one-off (forwardings).
const CARRIED: &[&str] = &[
    "AddKeysToAgent",
    "AddressFamily",
    "CertificateFile",
    "Ciphers",
    "Compression",
    "ConnectTimeout",
    "ConnectionAttempts",
    "ControlMaster",
    "ControlPath",
    "ControlPersist",
    "ForwardX11",
    "ForwardX11Trusted",
    "HostKeyAlgorithms",
    "HostKeyAlias",
    "IdentitiesOnly",
    "IdentityAgent",
    "KexAlgorithms",
    "MACs",
    "PasswordAuthentication",
    "PreferredAuthentications",
    "PubkeyAcceptedAlgorithms",
    "PubkeyAcceptedKeyTypes",
    "PubkeyAuthentication",
    "RequestTTY",
    "ServerAliveCountMax",
    "ServerAliveInterval",
    "TCPKeepAlive",
];

/// Options whose value is a shell command, searched for passwords.
const COMMANDS: &[&str] = &[
    "proxycommand",
    "localcommand",
    "remotecommand",
    "knownhostscommand",
];

/// Commands inside commands (`--ssh=`, `ProxyCommand`) are read this deep.
const MAX_DEPTH: u8 = 3;

/// The targets and passwords in one history entry.
pub(super) fn find(line: &str, dialect: Dialect) -> Found {
    let mut found = Found::default();
    scan(line, dialect, 0, &mut found);
    found
}

fn scan(line: &str, dialect: Dialect, depth: u8, found: &mut Found) {
    if depth > MAX_DEPTH {
        return;
    }
    for words in words::commands(line, dialect) {
        command(&words, depth, found);
    }
}

/// One simple command: past assignments and wrappers (`sudo`, `env`,
/// `sshpass`, …) to the program. A password in an assignment
/// (`SSHPASS=…`) counts only before a program of the `ssh` family.
fn command(words: &[Word], depth: u8, found: &mut Found) {
    let mut rest = words;
    let mut assigned = 0;
    let mut cx = Context { depth, found };
    while let Some((first, tail)) = rest.split_first() {
        if let Some((name, value)) = assignment(&first.text) {
            if secret_name(name) && !value.is_empty() {
                assigned += 1;
            }
            rest = tail;
            continue;
        }
        let program = program_name(&first.text);
        rest = match program.as_str() {
            "sudo" | "doas" => skip_options(tail, "CDghprtTUu"),
            "env" => skip_options(tail, "CSu"),
            "nice" => skip_options(tail, "n"),
            "caffeinate" => skip_options(tail, "tw"),
            "proxychains" | "proxychains4" => skip_options(tail, "f"),
            // Its options, then the duration.
            "timeout" => skip_options(tail, "ks").get(1..).unwrap_or_default(),
            "nohup" | "time" | "command" | "builtin" | "exec" | "noglob" | "nocorrect" | "-"
            | "torsocks" | "tsocks" | "and" | "or" | "not" | "!" | "if" | "then" | "else"
            | "elif" | "do" | "while" | "until" | "begin" => skip_options(tail, ""),
            "sshpass" => {
                cx.found.secrets += std::mem::take(&mut assigned);
                sshpass(tail, cx.found)
            }
            "ssh" | "autossh" | "mosh" | "scp" | "sftp" => {
                cx.found.secrets += assigned;
                match program.as_str() {
                    "ssh" => cx.ssh(tail, false),
                    "autossh" => cx.ssh(tail, true),
                    "mosh" => cx.mosh(tail),
                    "scp" => cx.scp(tail),
                    _ => cx.sftp(tail),
                }
                return;
            }
            _ => return,
        };
    }
}

/// `NAME=value` before a command.
fn assignment(word: &str) -> Option<(&str, &str)> {
    let (name, value) = word.split_once('=')?;
    let mut chars = name.chars();
    let first = chars.next()?;
    let valid = (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    valid.then_some((name, value))
}

/// A variable or option named like a password: `SSHPASS`, `DB_PASSWORD`, …
fn secret_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    ["pass", "secret", "token"].iter().any(|w| name.contains(w))
}

/// `/usr/bin/ssh`, `C:\Windows\System32\OpenSSH\ssh.exe`, `SSH` → `ssh`.
fn program_name(word: &str) -> String {
    let name = word.rsplit(['/', '\\']).next().unwrap_or(word);
    let lower = name.to_ascii_lowercase();
    match lower.strip_suffix(".exe") {
        Some(stem) => stem.to_owned(),
        None => lower,
    }
}

/// The words after a wrapper's options. `with_value` lists its single-letter
/// options that take a value.
fn skip_options<'w>(words: &'w [Word], with_value: &str) -> &'w [Word] {
    let mut i = 0;
    while let Some(word) = words.get(i) {
        let text = word.text.as_str();
        if text == "--" {
            return &words[i + 1..];
        }
        if text.len() < 2 || !text.starts_with('-') {
            break;
        }
        i += 1;
        if text.starts_with("--") {
            continue;
        }
        let letters = &text[1..];
        if let Some((at, letter)) = letters
            .char_indices()
            .find(|(_, c)| with_value.contains(*c))
            && at + letter.len_utf8() == letters.len()
        {
            i += 1;
        }
    }
    words.get(i..).unwrap_or_default()
}

/// `sshpass [-p password | -f file | -d fd | -e] [-P prompt] command…`.
fn sshpass<'w>(words: &'w [Word], found: &mut Found) -> &'w [Word] {
    let mut i = 0;
    while let Some(word) = words.get(i) {
        let text = word.text.as_str();
        i += 1;
        if text == "--" {
            break;
        }
        let Some(letter) = text.strip_prefix('-').and_then(|t| t.chars().next()) else {
            i -= 1;
            break;
        };
        if letter == 'p' {
            found.secrets += 1;
        }
        if matches!(letter, 'p' | 'f' | 'd' | 'P') && text.len() == 2 {
            i += 1;
        }
    }
    words.get(i..).unwrap_or_default()
}

/// The options of one invocation, each set by its first occurrence, as
/// OpenSSH does.
#[derive(Debug, Default)]
struct Settings {
    user: Option<String>,
    port: Option<u16>,
    identity_files: Vec<String>,
    proxy_jump: Option<String>,
    forward_agent: bool,
    options: Vec<HostOption>,
    /// The command can't be read for sure (another config file, an unknown
    /// flag, a bad port, a user from a variable): it gives no target.
    invalid: bool,
}

impl Settings {
    fn set_user(&mut self, user: &str, literal: bool) {
        if self.user.is_some() {
            return;
        }
        if literal && valid_user(user) {
            self.user = Some(user.to_owned());
        } else {
            self.invalid = true;
        }
    }

    fn set_port(&mut self, port: &str, literal: bool) {
        if self.port.is_some() {
            return;
        }
        match port.parse::<u16>() {
            Ok(port) if literal && port != 0 => self.port = Some(port),
            _ => self.invalid = true,
        }
    }

    fn add_identity(&mut self, path: &str, literal: bool) {
        if literal && valid_value(path, true) && !self.identity_files.iter().any(|p| p == path) {
            self.identity_files.push(path.to_owned());
        }
    }

    fn set_jump(&mut self, value: &str, literal: bool, found: &mut Found) {
        let hops: Vec<String> = value
            .split(',')
            .map(|hop| strip_uri_password(hop, found))
            .collect();
        if self.proxy_jump.is_none() && literal {
            let jump = hops.join(",");
            if valid_value(&jump, false) {
                self.proxy_jump = Some(jump);
            }
        }
    }

    fn target(&self, user: Option<String>, host: String) -> Target {
        Target {
            user: user.or_else(|| self.user.clone()),
            host,
            port: self.port,
            identity_files: self.identity_files.clone(),
            proxy_jump: self.proxy_jump.clone(),
            forward_agent: self.forward_agent,
            options: self.options.clone(),
        }
    }
}

/// A `-J` hop without the password of an `ssh://user:password@` form.
fn strip_uri_password(hop: &str, found: &mut Found) -> String {
    let Some(rest) = hop.strip_prefix("ssh://") else {
        return hop.to_owned();
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    match authority.rsplit_once('@') {
        Some((info, host)) if info.contains(':') => {
            found.secrets += 1;
            let user = info.split(':').next().unwrap_or_default();
            format!("ssh://{user}@{host}")
        }
        _ => hop.to_owned(),
    }
}

/// One option, attached (`-p2222`) or the next word.
struct Value {
    text: String,
    literal: bool,
}

struct Context<'f> {
    depth: u8,
    found: &'f mut Found,
}

impl Context<'_> {
    /// Single-letter options, OpenSSH style: clustered (`-vA`), with the
    /// value attached or as the next word. Returns how many words they took,
    /// or `None` at a word that isn't an option. `apply` gets each option
    /// and its value (`None` for a flag); it returns false for one the
    /// program doesn't know.
    fn options(
        words: &[Word],
        with_value: &str,
        mut apply: impl FnMut(char, Option<Value>) -> bool,
    ) -> Option<usize> {
        let first = words.first()?;
        let text = first.text.as_str();
        if text.len() < 2 || !text.starts_with('-') || text == "--" {
            return None;
        }
        for (at, letter) in text[1..].char_indices() {
            if !with_value.contains(letter) {
                if !apply(letter, None) {
                    return Some(1);
                }
                continue;
            }
            let attached = &text[1 + at + letter.len_utf8()..];
            let (value, used) = if attached.is_empty() {
                // A missing value counts as an option the program doesn't know.
                let Some(next) = words.get(1) else {
                    apply('\0', None);
                    return Some(1);
                };
                (
                    Value {
                        text: next.text.clone(),
                        literal: next.literal,
                    },
                    2,
                )
            } else {
                (
                    Value {
                        text: attached.to_owned(),
                        literal: first.literal,
                    },
                    1,
                )
            };
            apply(letter, Some(value));
            return Some(used);
        }
        Some(1)
    }

    /// What `ssh` and `scp`/`sftp` share: `-l`/`-p`/`-P`, `-i`, `-J`, `-o`
    /// and `-F`. False for an option this doesn't handle.
    fn common(&mut self, s: &mut Settings, letter: char, value: &Value, port: char) -> bool {
        match letter {
            'i' => s.add_identity(&value.text, value.literal),
            'J' => s.set_jump(&value.text, value.literal, self.found),
            'o' => self.option(s, value),
            'F' => s.invalid = true,
            _ if letter == port => s.set_port(&value.text, value.literal),
            _ => return false,
        }
        true
    }

    /// `-o Keyword=value` (or `Keyword value`).
    fn option(&mut self, s: &mut Settings, value: &Value) {
        let text = value.text.trim();
        let split = text.find(['=', ' ', '\t']).unwrap_or(text.len());
        let key = &text[..split];
        let val = text[split..].trim_start_matches([' ', '\t']);
        let val = val.strip_prefix('=').unwrap_or(val).trim();
        let lower = key.to_ascii_lowercase();
        match lower.as_str() {
            "user" => s.set_user(val, value.literal),
            "port" => s.set_port(val, value.literal),
            "identityfile" => s.add_identity(val, value.literal),
            "proxyjump" => s.set_jump(val, value.literal, self.found),
            "forwardagent" => s.forward_agent |= val.eq_ignore_ascii_case("yes"),
            "hostname" | "include" | "match" | "host" | "canonicalizehostname" => {
                s.invalid = true;
            }
            "passwordauthentication"
            | "numberofpasswordprompts"
            | "kbdinteractiveauthentication" => {
                carry(s, key, val, value.literal);
            }
            "setenv" | "sendenv" => {
                let named = val.split_whitespace().filter_map(|v| v.split_once('='));
                if named
                    .into_iter()
                    .any(|(n, v)| secret_name(n) && !v.is_empty())
                {
                    self.found.secrets += 1;
                }
            }
            // Only its passwords: the servers it reaches aren't this one.
            _ if COMMANDS.contains(&lower.as_str()) => {
                let mut inner = Found::default();
                scan(val, Dialect::Posix, self.depth + 1, &mut inner);
                self.found.secrets += inner.secrets;
            }
            _ if secret_name(&lower) => self.found.secrets += 1,
            _ => carry(s, key, val, value.literal),
        }
    }

    /// `ssh [options] destination [command]`; `autossh` adds `-M port`.
    /// Like `ssh`, options are read before and after the destination, up to
    /// the remote command.
    fn ssh(&mut self, words: &[Word], autossh: bool) {
        let mut s = Settings::default();
        let destination = self.ssh_arguments(words, autossh, &mut s);
        if let Some(target) = destination.and_then(|d| self.destination(&d, &mut s))
            && !s.invalid
        {
            self.found.targets.push(target);
        }
    }

    /// Reads `ssh`'s options into `s`; returns the destination word.
    fn ssh_arguments(&mut self, words: &[Word], autossh: bool, s: &mut Settings) -> Option<Word> {
        const FLAGS: &str = "1246AaCfGgKkMNnqsTtVvXxYy";
        let with_value = if autossh {
            "BbcDEeFIiJLlMmOoPpQRSWw"
        } else {
            "BbcDEeFIiJLlmOoPpQRSWw"
        };
        let mut destination: Option<Word> = None;
        let mut i = 0;
        while let Some(word) = words.get(i) {
            if word.text == "--" {
                if destination.is_none() {
                    destination = words.get(i + 1).cloned();
                }
                break;
            }
            let used = Self::options(&words[i..], with_value, |letter, value| {
                let known = match (letter, value) {
                    ('l', Some(v)) => {
                        s.set_user(&v.text, v.literal);
                        true
                    }
                    // A query, a control command, the config printed, the
                    // version: no connection.
                    ('Q' | 'O', Some(_)) | ('G' | 'V', None) => {
                        s.invalid = true;
                        true
                    }
                    ('A', None) => {
                        s.forward_agent = true;
                        true
                    }
                    (letter, Some(v)) => {
                        self.common(s, letter, &v, 'p');
                        true
                    }
                    (letter, None) => FLAGS.contains(letter),
                };
                if !known {
                    s.invalid = true;
                }
                known
            });
            match used {
                Some(used) => i += used,
                None if destination.is_none() => {
                    destination = Some(word.clone());
                    i += 1;
                }
                // The remote command.
                None => break,
            }
            if destination.is_some() && s.user.is_none() {
                // The destination's user counts from where it stands: a
                // `-l` after it doesn't replace it.
                if let Some(user) = destination.as_ref().and_then(|d| destination_user(&d.text)) {
                    s.set_user(&user, destination.as_ref().is_some_and(|d| d.literal));
                }
            }
        }
        destination
    }

    /// `[user@]host` or `ssh://[user@]host[:port]`.
    fn destination(&mut self, word: &Word, s: &mut Settings) -> Option<Target> {
        if !word.literal {
            return None;
        }
        if let Some(rest) = strip_scheme(&word.text, "ssh") {
            let uri = uri(rest, self.found)?;
            if !uri.path.is_empty() && uri.path != "/" {
                return None;
            }
            if let Some(user) = &uri.user {
                s.set_user(user, true);
            }
            if let Some(port) = uri.port {
                s.set_port(&port.to_string(), true);
            }
            return Some(s.target(None, uri.host));
        }
        let host = match word.text.rsplit_once('@') {
            Some((_, host)) => host,
            None => &word.text,
        };
        Some(s.target(None, plain_host(host)?))
    }

    /// `mosh [options] [--] [user@]host [command]`. Its `-p` is the UDP
    /// port; `--ssh="ssh -p 2222"` says how `ssh` is run.
    fn mosh(&mut self, words: &[Word]) {
        let mut s = Settings::default();
        let mut destination = None;
        let mut i = 0;
        while let Some(word) = words.get(i) {
            i += 1;
            let text = word.text.as_str();
            if text == "--" {
                destination = words.get(i);
                break;
            }
            if let Some(long) = text.strip_prefix("--") {
                let (name, inline) = match long.split_once('=') {
                    Some((name, value)) => (name, Some(value.to_owned())),
                    None => (long, None),
                };
                let takes = matches!(
                    name,
                    "ssh"
                        | "port"
                        | "predict"
                        | "family"
                        | "client"
                        | "server"
                        | "bind-server"
                        | "experimental-remote-ip"
                );
                if !takes {
                    continue;
                }
                let value = inline.or_else(|| {
                    i += 1;
                    words.get(i - 1).map(|w| w.text.clone())
                });
                if name == "ssh"
                    && let Some(command) = value
                {
                    self.mosh_ssh(&command, word.literal, &mut s);
                }
                continue;
            }
            if text.len() > 1 && text.starts_with('-') {
                if text == "-p" {
                    i += 1;
                }
                continue;
            }
            destination = Some(word);
            break;
        }
        let Some(word) = destination.filter(|w| w.literal) else {
            return;
        };
        let (user, host) = split_user(&word.text);
        if let Some(user) = user {
            s.set_user(user, true);
        }
        if let Some(host) = plain_host(host)
            && !s.invalid
        {
            self.found.targets.push(s.target(None, host));
        }
    }

    /// `mosh --ssh=…`: passwords anywhere in it, and the options of its
    /// `ssh`.
    fn mosh_ssh(&mut self, command: &str, literal: bool, s: &mut Settings) {
        let mut inner = Found::default();
        scan(command, Dialect::Posix, self.depth + 1, &mut inner);
        self.found.secrets += inner.secrets;
        let words = words::commands(command, Dialect::Posix);
        let Some(words) = words.first() else { return };
        let Some(at) = words.iter().position(|w| program_name(&w.text) == "ssh") else {
            return;
        };
        let mut quiet = Found::default();
        let mut nested = Context {
            depth: self.depth + 1,
            found: &mut quiet,
        };
        let mut args = words[at + 1..].to_vec();
        if !literal {
            for arg in &mut args {
                arg.literal = false;
            }
        }
        nested.ssh_arguments(&args, false, s);
    }

    /// `scp [options] source… target`: each remote operand is a target,
    /// `[user@]host:[path]` or `scp://[user@]host[:port][/path]`.
    fn scp(&mut self, words: &[Word]) {
        const FLAGS: &str = "12346ABCdfOpqRrsTtv";
        self.copy(words, "cDFiJloPSX", FLAGS, "scp", true);
    }

    /// `sftp [options] destination`: `[user@]host[:path]` or
    /// `sftp://[user@]host[:port][/path]`.
    fn sftp(&mut self, words: &[Word]) {
        const FLAGS: &str = "1246AaCfhNpqrv";
        self.copy(words, "BbcDFiJloPRSsX", FLAGS, "sftp", false);
    }

    /// `scp` and `sftp`: options first, then operands. `-P` is the port,
    /// `-l` a bandwidth limit.
    fn copy(&mut self, words: &[Word], with_value: &str, flags: &str, scheme: &str, many: bool) {
        let mut s = Settings::default();
        let mut i = 0;
        while let Some(word) = words.get(i) {
            if word.text == "--" {
                i += 1;
                break;
            }
            let used = Self::options(&words[i..], with_value, |letter, value| {
                let known = match value {
                    Some(v) => {
                        self.common(&mut s, letter, &v, 'P');
                        true
                    }
                    None => flags.contains(letter),
                };
                if !known {
                    s.invalid = true;
                }
                known
            });
            match used {
                Some(used) => i += used,
                None => break,
            }
        }
        let operands = words.get(i..).unwrap_or_default();
        let operands = if many {
            operands
        } else {
            operands.get(..1).unwrap_or_default()
        };
        let mut targets = Vec::new();
        for word in operands {
            if !word.literal {
                continue;
            }
            if let Some(rest) = strip_scheme(&word.text, scheme) {
                let Some(uri) = uri(rest, self.found) else {
                    continue;
                };
                let mut target = s.target(uri.user, uri.host);
                target.port = target.port.or(uri.port);
                targets.push(target);
                continue;
            }
            let remote = match remote_colon(&word.text) {
                Some(colon) => &word.text[..colon],
                // sftp takes a plain host too.
                None if !many => word.text.as_str(),
                None => continue,
            };
            let (user, host) = split_user(remote);
            if user.is_some_and(|u| !valid_user(u)) {
                continue;
            }
            if let Some(host) = bracketed_host(host) {
                targets.push(s.target(user.map(str::to_owned), host));
            }
        }
        if !s.invalid {
            self.found.targets.extend(targets);
        }
    }
}

/// Keeps a `-o` option from [`CARRIED`], spelt as OpenSSH documents it,
/// once.
fn carry(s: &mut Settings, key: &str, value: &str, literal: bool) {
    let Some(name) = CARRIED.iter().find(|name| name.eq_ignore_ascii_case(key)) else {
        return;
    };
    if !literal || !valid_value(value, false) {
        return;
    }
    if s.options.iter().any(|o| o.key == *name) {
        return;
    }
    s.options.push(HostOption::new(*name, value));
}

fn strip_scheme<'t>(text: &'t str, scheme: &str) -> Option<&'t str> {
    let (head, rest) = text.split_once("://")?;
    head.eq_ignore_ascii_case(scheme).then_some(rest)
}

/// The user of a destination word, as `ssh` reads it.
fn destination_user(text: &str) -> Option<String> {
    if let Some(rest) = strip_scheme(text, "ssh") {
        let authority = rest.split('/').next().unwrap_or(rest);
        let (info, _) = authority.rsplit_once('@')?;
        let user = info.split([';', ':']).next().unwrap_or_default();
        return Some(percent_decode(user));
    }
    let (user, _) = split_user(text);
    user.map(str::to_owned)
}

/// `user@host` → the user (up to the last `@`) and the host.
fn split_user(text: &str) -> (Option<&str>, &str) {
    match text.rsplit_once('@') {
        Some((user, host)) => (Some(user), host),
        None => (None, text),
    }
}

/// A host as `ssh` takes it: a name, an IPv6 address, or one in brackets.
/// `host:port` isn't one: `ssh` would look up that whole name.
fn plain_host(text: &str) -> Option<String> {
    if let Some(inner) = text.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
        return valid_ipv6(inner).then(|| inner.to_owned());
    }
    if text.contains(':') {
        return valid_ipv6(text).then(|| text.to_owned());
    }
    valid_host_name(text).then(|| text.to_owned())
}

/// The host of an `scp`/`sftp` operand, whose IPv6 addresses are in
/// brackets.
fn bracketed_host(text: &str) -> Option<String> {
    if let Some(inner) = text.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
        return valid_ipv6(inner).then(|| inner.to_owned());
    }
    valid_host_name(text).then(|| text.to_owned())
}

/// Where the host ends in an `scp` operand (`scp.c`'s `colon()`): the first
/// `:` outside brackets, before any `/`. None for a local path, a Windows
/// one (`C:\…`, `C:/…`) too.
fn remote_colon(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.first() == Some(&b':') {
        return None;
    }
    let mut bracket = bytes.first() == Some(&b'[');
    for (i, &byte) in bytes.iter().enumerate() {
        let next = bytes.get(i + 1).copied();
        if byte == b'@' && next == Some(b'[') {
            bracket = true;
        }
        if byte == b']' && next == Some(b':') && bracket {
            return Some(i + 1);
        }
        if byte == b':' && !bracket {
            let drive =
                i == 1 && bytes[0].is_ascii_alphabetic() && matches!(next, Some(b'/' | b'\\'));
            return (!drive).then_some(i);
        }
        if byte == b'/' {
            return None;
        }
    }
    None
}

/// The parts of a URI after `scheme://`.
struct Uri {
    user: Option<String>,
    host: String,
    port: Option<u16>,
    path: String,
}

/// `[user[;params][:password]@]host[:port][/path]`; a password is counted
/// and dropped.
fn uri(rest: &str, found: &mut Found) -> Option<Uri> {
    let (authority, path) = match rest.find('/') {
        Some(at) => rest.split_at(at),
        None => (rest, ""),
    };
    let (info, host_port) = match authority.rsplit_once('@') {
        Some((info, host)) => (Some(info), host),
        None => (None, authority),
    };
    let user = match info {
        Some(info) => {
            let info = info.split(';').next().unwrap_or_default();
            let name = match info.split_once(':') {
                Some((name, _)) => {
                    found.secrets += 1;
                    name
                }
                None => info,
            };
            let name = percent_decode(name);
            if !valid_user(&name) {
                return None;
            }
            Some(name)
        }
        None => None,
    };
    let (host, port) = if let Some(inner) = host_port.strip_prefix('[') {
        let (address, after) = inner.split_once(']')?;
        if !valid_ipv6(address) {
            return None;
        }
        (address.to_owned(), after.strip_prefix(':'))
    } else {
        let (host, port) = match host_port.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (host_port, None),
        };
        if !valid_host_name(host) {
            return None;
        }
        (host.to_owned(), port)
    };
    let port = match port.filter(|p| !p.is_empty()) {
        Some(port) => Some(port.parse::<u16>().ok().filter(|p| *p != 0)?),
        None => None,
    };
    Some(Uri {
        user,
        host,
        port,
        path: path.to_owned(),
    })
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(hex) = text.get(i + 1..i + 3)
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(byte);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| text.to_owned())
}

fn valid_ipv6(text: &str) -> bool {
    let (address, zone) = match text.split_once('%') {
        Some((address, zone)) => (address, Some(zone)),
        None => (text, None),
    };
    address.parse::<Ipv6Addr>().is_ok()
        && zone.is_none_or(|z| !z.is_empty() && z.chars().all(|c| c.is_ascii_alphanumeric()))
}

/// A host name or IPv4 address: letters, digits, `.`, `-` and `_`.
fn valid_host_name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 253
        && !text.starts_with(['-', '.'])
        && text.chars().any(|c| c.is_ascii_alphanumeric())
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// A user name: no spaces, quotes or shell characters, and not an option.
fn valid_user(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && !text.starts_with('-')
        && text
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | '@' | '\\' | '+' | '$'))
}

/// A value for the config: one line, and with `spaces` (a path) no quotes
/// either; without, a single word.
fn valid_value(text: &str, spaces: bool) -> bool {
    !text.is_empty()
        && text.len() <= 1024
        && !text.starts_with('-')
        && !text
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | '\'' | '#') || (!spaces && c == ' '))
}
