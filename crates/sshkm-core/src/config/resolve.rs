//! The settings `ssh` would use for one host, worked out without `ssh`: for
//! the phone, which has no `ssh` to ask (`ssh -G`).
//!
//! The rules are OpenSSH's (`readconf.c`, checked against OpenSSH 9.9 with
//! `ssh -G`): lines are read top to bottom, the options before the first
//! block apply to every host, a `Host` block applies when one of its
//! patterns matches the name as typed (case counts) and none of its negated
//! (`!`) ones does, and for each keyword the first value obtained is the one
//! used. A user given besides the files (`ssh -l`, the user of a jump spec)
//! comes first, as the command line does. `ProxyCommand` and `ProxyJump`
//! share one slot: whichever comes first wins, `none` included.
//!
//! `Match` blocks are evaluated for `all`, `host` (the `HostName` obtained so
//! far, `%h` expanded, without case), `originalhost` (the name as typed,
//! without case) and `user` (the user obtained so far, case counts), each
//! negatable with `!`. A block one of those rules out doesn't apply. `exec`
//! would run a program, so a block that needs it to decide is reported in
//! [`EffectiveSettings::runs_code`]; one that needs any other criterion
//! (`localuser`, `canonical`, `final`, `localnetwork`, `tagged`, …, or `user`
//! before any user is known) is reported in
//! [`EffectiveSettings::undecided`]. Either way its options are taken as if
//! it applied, so what it would do is reported too.
//!
//! What makes `ssh` run a program is reported as [`RiskyDirective`]s with
//! [`Risk::RunsCode`], by the rules of the [`risky`](super::risky) module, for
//! the value in effect: a later `ProxyCommand` after `ProxyCommand none`
//! changes nothing, and neither does a block that doesn't apply. `Include` is
//! reported too: the file it names may say anything. A line `ssh` may read
//! differently from this parser (an odd keyword, a control character) is
//! reported wherever it is, in [`EffectiveSettings::odd_lines`]: `ssh` may
//! read it as a new `Host` or `Match` line, so no block after it can be
//! trusted to be what it seems.

use super::SshConfig;
use super::lexer::{Directive, LineKind, is_trailing_ws, lex, split_args};
use super::risky::{Risk, RiskyDirective, matches_pattern, risk};

/// One option in effect for a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveOption {
    /// The keyword in lower case, as `ssh` reads it.
    pub key: String,
    /// The value as [`HostOption::value`](super::HostOption::value) gives it.
    pub value: String,
    /// The `Host …` or `Match …` line of the block it is in, as written;
    /// `None` before the first block.
    pub block: Option<String>,
}

/// The settings in effect for one host (see the module documentation).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectiveSettings {
    /// Every option line that applies, in the order `ssh` reads them,
    /// without the `ProxyCommand` or `ProxyJump` that the other one's
    /// earlier line set aside.
    options: Vec<EffectiveOption>,
    /// Lines in effect that make `ssh` run a program or load code on this
    /// computer: the value in effect of `ProxyCommand`, `LocalCommand`,
    /// `PermitLocalCommand`, `KnownHostsCommand`, …, a `Match … exec` that
    /// isn't ruled out otherwise, an `Include`.
    pub runs_code: Vec<RiskyDirective>,
    /// Every line of the file `ssh` may read differently from this parser,
    /// wherever it is, as written.
    pub odd_lines: Vec<String>,
    /// `Match …` lines that may apply but need a criterion only `ssh` can
    /// evaluate, as written.
    pub undecided: Vec<String>,
}

impl EffectiveSettings {
    /// The value in effect for `key` (in any case): the first one obtained.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.options
            .iter()
            .find(|o| o.key.eq_ignore_ascii_case(key))
            .map(|o| o.value.as_str())
    }

    /// Every value obtained for `key`, for keywords that add up
    /// (`IdentityFile`, `LocalForward`, …).
    pub fn all(&self, key: &str) -> Vec<&str> {
        self.options
            .iter()
            .filter(|o| o.key.eq_ignore_ascii_case(key))
            .map(|o| o.value.as_str())
            .collect()
    }

    /// Every option line that applies, in order.
    pub fn options(&self) -> &[EffectiveOption] {
        &self.options
    }
}

impl SshConfig {
    /// The settings in effect when connecting to `host`, the name as typed
    /// (see the module documentation).
    pub fn effective(&self, host: &str) -> EffectiveSettings {
        self.effective_as(host, None)
    }

    /// The same, with `user` given besides the files (`ssh -l`, or the user
    /// of a jump spec): it comes before any `User` line, and `Match user`
    /// sees it.
    pub fn effective_as(&self, host: &str, user: Option<&str>) -> EffectiveSettings {
        let original = host.to_lowercase();
        let mut out = EffectiveSettings::default();
        if let Some(user) = user {
            out.options.push(EffectiveOption {
                key: "user".to_owned(),
                value: user.to_owned(),
                block: None,
            });
        }
        // The options before the first block apply to every host.
        let mut applies = true;
        let mut header: Option<String> = None;
        for line in &self.lines {
            let LineKind::Directive(d) = lex(&line.text) else {
                continue;
            };
            let rest = &line.text[d.indent.len() + d.key.len() + d.sep.len()..];
            let rest = rest.trim_end_matches(is_trailing_ws);
            let keyword = d
                .keyword()
                .filter(|_| !rest.chars().any(|c| c.is_control() && c != '\t'));
            let Some(key) = keyword else {
                // `ssh` may read the line as anything, a new block too:
                // wherever it is, what follows may not be what it seems.
                out.odd_lines.push(line.text.clone());
                continue;
            };
            match key.as_str() {
                "host" => {
                    header = Some(format!("{} {}", d.key, d.value));
                    applies = host_line_matches(d.value, host);
                }
                "match" => {
                    header = Some(format!("{} {}", d.key, d.value));
                    applies = match match_line(d.value, &original, &out) {
                        MatchResult::No => false,
                        MatchResult::Yes => true,
                        MatchResult::NeedsExec => {
                            out.runs_code.push(RiskyDirective {
                                block: header.clone(),
                                key: d.key.to_owned(),
                                value: d.value.to_owned(),
                                risk: Risk::RunsCode,
                            });
                            true
                        }
                        MatchResult::Undecided => {
                            out.undecided.extend(header.clone());
                            true
                        }
                    };
                }
                _ if !applies => {}
                "include" => out.runs_code.push(directive(header.as_ref(), &d, d.value)),
                _ => {
                    let first = !out.options.iter().any(|o| slot(&o.key) == slot(&key));
                    // The other half of the proxy slot is set: `ssh` ignores
                    // this line.
                    if !first && slot(&key) == "proxy" && out.get(&key).is_none() {
                        continue;
                    }
                    if first && risk(&key, &d, rest) == Some(Risk::RunsCode) {
                        out.runs_code.push(directive(header.as_ref(), &d, d.value));
                    }
                    out.options.push(EffectiveOption {
                        key,
                        value: d.logical_value(),
                        block: header.clone(),
                    });
                }
            }
        }
        out
    }
}

/// The option a keyword sets: `ProxyJump` and `ProxyCommand` set the same.
fn slot(key: &str) -> &str {
    match key {
        "proxyjump" | "proxycommand" => "proxy",
        other => other,
    }
}

/// A [`RiskyDirective`] of `d` with `value`.
fn directive(header: Option<&String>, d: &Directive<'_>, value: &str) -> RiskyDirective {
    RiskyDirective {
        block: header.cloned(),
        key: d.key.to_owned(),
        value: value.to_owned(),
        risk: Risk::RunsCode,
    }
}

/// Whether a `Host` line (its value) applies to `host`, the name as typed:
/// one of its patterns matches and none of its negated ones does. Case
/// counts, as in `ssh`.
fn host_line_matches(value: &str, host: &str) -> bool {
    let mut matched = false;
    for pattern in split_args(value).0 {
        let (negated, pattern) = match pattern.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, pattern.as_str()),
        };
        if matches_pattern(pattern.as_bytes(), host.as_bytes()) {
            if negated {
                return false;
            }
            matched = true;
        }
    }
    matched
}

/// Whether a comma-separated pattern list (`a,b*,!c`) matches `name`, as
/// OpenSSH's `match_pattern_list()`: a negated match rules it out, else any
/// match counts. Without case for host names (`fold_case`), with it for
/// users.
fn pattern_list_matches(list: &str, name: &str, fold_case: bool) -> bool {
    let fold = |text: &str| {
        if fold_case {
            text.to_lowercase()
        } else {
            text.to_owned()
        }
    };
    let name = fold(name);
    let mut matched = false;
    for pattern in list.split(',').filter(|p| !p.is_empty()) {
        let pattern = fold(pattern);
        let (negated, pattern) = match pattern.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, pattern.as_str()),
        };
        if matches_pattern(pattern.as_bytes(), name.as_bytes()) {
            if negated {
                return false;
            }
            matched = true;
        }
    }
    matched
}

enum MatchResult {
    /// A criterion rules the block out.
    No,
    /// Every criterion holds.
    Yes,
    /// Only `exec` could tell.
    NeedsExec,
    /// A criterion only `ssh` can evaluate could tell.
    Undecided,
}

/// Evaluates the criteria of a `Match` line (its value) for `original`, the
/// name as typed (in lower case), with the options obtained so far.
fn match_line(value: &str, original: &str, so_far: &EffectiveSettings) -> MatchResult {
    let mut args = split_args(value).0.into_iter();
    let mut needs_exec = false;
    let mut undecided = false;
    while let Some(arg) = args.next() {
        // `criterion=argument` is the same as two words.
        let (criterion, inline) = match arg.split_once('=') {
            Some((c, a)) => (c.to_owned(), Some(a.to_owned())),
            None => (arg, None),
        };
        let (negated, criterion) = match criterion.strip_prefix('!') {
            Some(rest) => (true, rest.to_ascii_lowercase()),
            None => (false, criterion.to_ascii_lowercase()),
        };
        if criterion == "all" || criterion == "canonical" || criterion == "final" {
            if criterion != "all" {
                undecided = true;
            } else if negated {
                return MatchResult::No;
            }
            continue;
        }
        let Some(argument) = inline.or_else(|| args.next()) else {
            // `ssh` refuses a criterion without its argument.
            undecided = true;
            continue;
        };
        let holds = match criterion.as_str() {
            "host" => Some(pattern_list_matches(
                &argument,
                &so_far
                    .get("hostname")
                    .map_or_else(|| original.to_owned(), |h| expand_host(h, original)),
                true,
            )),
            "originalhost" => Some(pattern_list_matches(&argument, original, true)),
            "user" => so_far
                .get("user")
                .map(|user| pattern_list_matches(&argument, user, false)),
            "exec" => {
                needs_exec = true;
                None
            }
            _ => {
                undecided = true;
                None
            }
        };
        if let Some(holds) = holds
            && holds == negated
        {
            return MatchResult::No;
        }
        if holds.is_none() && criterion == "user" {
            undecided = true;
        }
    }
    if needs_exec {
        MatchResult::NeedsExec
    } else if undecided {
        MatchResult::Undecided
    } else {
        MatchResult::Yes
    }
}

/// `HostName` with `%h` (the name as typed) and `%%` expanded, as `ssh` does
/// before it compares `Match host`. Other tokens are left as they are.
fn expand_host(host_name: &str, original: &str) -> String {
    let mut out = String::with_capacity(host_name.len());
    let mut chars = host_name.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('h') => out.push_str(original),
            Some(other) if other != '%' => {
                out.push('%');
                out.push(other);
            }
            // `%%`, or a `%` at the end.
            _ => out.push('%'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn effective(text: &str, host: &str) -> EffectiveSettings {
        SshConfig::parse(text).effective(host)
    }

    fn keys(settings: &EffectiveSettings) -> Vec<String> {
        settings
            .runs_code
            .iter()
            .map(|d| d.key.to_ascii_lowercase())
            .collect()
    }

    #[test]
    fn the_first_value_obtained_wins() {
        let text = "\
User global
Host web
  HostName web.example.com
  Port 2222
Host web db
  HostName other.example.com
  User second
  Port 22
Host *
  ServerAliveInterval 30
";
        let web = effective(text, "web");
        assert_eq!(web.get("hostname"), Some("web.example.com"));
        assert_eq!(web.get("HostName"), Some("web.example.com"));
        assert_eq!(web.get("user"), Some("global"));
        assert_eq!(web.get("port"), Some("2222"));
        assert_eq!(web.get("serveraliveinterval"), Some("30"));
        assert_eq!(
            web.all("hostname"),
            ["web.example.com", "other.example.com"]
        );
        let db = effective(text, "db");
        assert_eq!(db.get("hostname"), Some("other.example.com"));
        assert_eq!(db.get("port"), Some("22"));
        let other = effective(text, "cache");
        assert_eq!(other.get("hostname"), None);
        assert_eq!(other.get("user"), Some("global"));
        assert_eq!(other.get("serveraliveinterval"), Some("30"));
    }

    #[test]
    fn patterns_and_negation() {
        let text = "\
Host *.prod !bastion.prod
  User deploy
Host WEB?
  Port 2200
";
        assert_eq!(effective(text, "api.prod").get("user"), Some("deploy"));
        assert_eq!(effective(text, "bastion.prod").get("user"), None);
        assert_eq!(effective(text, "api.dev").get("user"), None);
        // `Host` patterns compare with the name as typed, case and all
        // (OpenSSH 9.9: `ssh -G WEB1` takes the block, `ssh -G web1` doesn't).
        assert_eq!(effective(text, "WEB1").get("port"), Some("2200"));
        assert_eq!(effective(text, "web1").get("port"), None);
        assert_eq!(effective(text, "WEB12").get("port"), None);
    }

    #[test]
    fn proxy_command_and_proxy_jump_share_a_slot() {
        let jump_first = "\
Host a
  ProxyJump bastion
Host *
  ProxyCommand nc %h %p
";
        let a = effective(jump_first, "a");
        assert_eq!(a.get("proxyjump"), Some("bastion"));
        assert_eq!(a.get("proxycommand"), None);
        assert_eq!(a.runs_code, []);
        // Elsewhere the ProxyCommand is in effect.
        let b = effective(jump_first, "b");
        assert_eq!(keys(&b), ["proxycommand"]);
        assert_eq!(b.runs_code[0].block.as_deref(), Some("Host *"));

        let command_first = "\
Host *
  ProxyCommand none
Host a
  ProxyJump bastion
  ProxyCommand nc %h %p
";
        let a = effective(command_first, "a");
        assert_eq!(a.get("proxycommand"), Some("none"));
        assert_eq!(a.get("proxyjump"), None);
        assert_eq!(a.runs_code, []);
    }

    #[test]
    fn programs_in_effect_are_reported() {
        let text = "\
Host safe
  PermitLocalCommand no
  LocalCommand none
  KnownHostsCommand none
Host local
  LocalCommand echo hi
Host permit
  PermitLocalCommand yes
Host known
  KnownHostsCommand /bin/cat %H
Host *
  PermitLocalCommand yes
";
        assert_eq!(effective(text, "safe").runs_code, []);
        assert_eq!(
            keys(&effective(text, "local")),
            ["localcommand", "permitlocalcommand"]
        );
        assert_eq!(keys(&effective(text, "permit")), ["permitlocalcommand"]);
        assert_eq!(
            keys(&effective(text, "known")),
            ["knownhostscommand", "permitlocalcommand"]
        );
        // Identity files are options like any other; nothing runs.
        let ids = effective("IdentityFile ~/.ssh/a\nIdentityFile ~/.ssh/b\n", "x");
        assert_eq!(ids.all("identityfile"), ["~/.ssh/a", "~/.ssh/b"]);
        assert_eq!(ids.runs_code, []);
    }

    #[test]
    fn includes_count_where_they_apply() {
        let text = "Host a\n  Include ~/.ssh/extra\nHost b\n  User b\n";
        assert_eq!(keys(&effective(text, "a")), ["include"]);
        assert_eq!(effective(text, "b").runs_code, []);
    }

    #[test]
    fn odd_lines_count_wherever_they_are() {
        // `ssh` reads `=Host web` as a `Host web` line: the ProxyCommand
        // after it is web's, though the parser sees it under `Host nothing`.
        let hidden_block = "Host nothing\n=Host web\n  ProxyCommand nc evil 22\n";
        let web = effective(hidden_block, "web");
        assert_eq!(web.odd_lines, ["=Host web"]);
        assert_eq!(web.runs_code, []);
        // And a `HostName` that seems to be web's may be another block's.
        let moved = "Host web\n  User alice\n=Host other\n  HostName evil.example.com\n";
        assert_eq!(effective(moved, "web").odd_lines, ["=Host other"]);
        // Control characters, odd keywords: reported for every host.
        let odd = "Host web \x0b\n  ProxyCommand x\nHost b\n  Proxy-Command x\n";
        for host in ["web", "b", "elsewhere"] {
            assert_eq!(effective(odd, host).odd_lines.len(), 2, "{host}");
        }
        assert_eq!(
            effective("Host a\n  User a\n", "a").odd_lines,
            Vec::<String>::new()
        );
    }

    #[test]
    fn match_blocks() {
        let text = "\
Host short
  HostName short.example.com
Match host *.example.com
  User fromhost
Match originalhost short,!other
  Port 2222
Match !host *.example.com
  Port 2200
Match all
  ServerAliveCountMax 5
";
        let short = effective(text, "short");
        assert_eq!(short.get("user"), Some("fromhost"));
        assert_eq!(short.get("port"), Some("2222"));
        assert_eq!(short.get("serveralivecountmax"), Some("5"));
        assert_eq!(short.undecided, Vec::<String>::new());
        let other = effective(text, "other.example.com");
        assert_eq!(other.get("user"), Some("fromhost"));
        assert_eq!(other.get("port"), None);
        let plain = effective(text, "plain");
        assert_eq!(plain.get("user"), None);
        assert_eq!(plain.get("port"), Some("2200"));
    }

    #[test]
    fn match_exec_and_unknown_criteria() {
        let text = "\
Match host a exec \"test -f /x\"
  ProxyCommand nc %h %p
Match exec=true host b
  User b
Match localuser alice
  Port 2222
Match user deploy
  Port 2200
";
        // Ruled out by `host` either side of `exec`: nothing reported.
        let c = effective(text, "c");
        assert!(c.runs_code.is_empty(), "{c:?}");
        assert_eq!(c.undecided, ["Match localuser alice", "Match user deploy"]);
        let a = effective(text, "a");
        assert_eq!(keys(&a), ["match", "proxycommand"]);
        let b = effective(text, "b");
        assert_eq!(keys(&b), ["match"]);
        // `user` is decided once a `User` is known.
        let known = effective("User deploy\nMatch user deploy\n  Port 2200\n", "x");
        assert_eq!(known.get("port"), Some("2200"));
        assert_eq!(known.undecided, Vec::<String>::new());
        let other = effective("User bob\nMatch user deploy\n  Port 2200\n", "x");
        assert_eq!(other.get("port"), None);
    }

    #[test]
    fn users_compare_with_case_and_a_given_user_comes_first() {
        // OpenSSH 9.9: `User deploy` then `Match !user Deploy` applies.
        let text = "User deploy\nMatch !user Deploy\n  ProxyCommand nc %h %p\n";
        assert_eq!(keys(&effective(text, "x")), ["proxycommand"]);
        // A user from the command line or a jump spec wins over `User` and
        // is what `Match user` sees.
        let jump = "Host bastion\n  User jump\nMatch user admin\n  Port 2002\n";
        let given = SshConfig::parse(jump).effective_as("bastion", Some("admin"));
        assert_eq!(given.get("user"), Some("admin"));
        assert_eq!(given.get("port"), Some("2002"));
        assert_eq!(effective(jump, "bastion").get("port"), None);
    }

    #[test]
    fn host_criteria_ignore_case() {
        // OpenSSH 9.9: `Match host big.example.com` takes `HostName
        // Big.Example.COM`, and `Match originalhost UP` takes `Up`.
        let text = "Host up2\n  HostName Big.Example.COM\nMatch host big.example.com\n  Port 1002\n\
                    Match originalhost UP\n  User u\n";
        assert_eq!(effective(text, "up2").get("port"), Some("1002"));
        assert_eq!(effective(text, "Up").get("user"), Some("u"));
    }

    #[test]
    fn host_names_expand_percent_h() {
        assert_eq!(expand_host("%h.example.com", "web"), "web.example.com");
        assert_eq!(expand_host("100%%-%h", "a"), "100%-a");
        assert_eq!(expand_host("%p", "a"), "%p");
        let text = "Host web\n  HostName %h.example.com\nMatch host web.example.com\n  User w\n";
        assert_eq!(effective(text, "web").get("user"), Some("w"));
    }
}
