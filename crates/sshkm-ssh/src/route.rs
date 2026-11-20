//! Where a connection goes: the host settings of the destination and of
//! every `ProxyJump` hop, from the host blocks the phone carries.
//!
//! The core works out the settings in effect for a name
//! ([`SshConfig::effective`]), with `ssh_config`'s first-match and pattern
//! rules. Of those, the phone honours `HostName` (with `%h` and `%%`),
//! `User`, `Port`, `ProxyJump`, `ServerAliveInterval`, `ServerAliveCountMax`
//! and `ConnectTimeout`. Everything else is ignored: `IdentityFile` (the
//! phone signs with its own key), agent and X11 forwarding (never done),
//! port forwards. A host whose settings would make `ssh` run a program on
//! the computer, or that `ssh` alone can evaluate, is
//! [`NotAvailable`]: connecting directly could reach another server than
//! the computer does, and the phone runs no programs.
//!
//! `ProxyJump a,b` is followed as `ssh` follows it (`ssh -J a -W … b`): `a`
//! is reached with its own settings, its own `ProxyJump` included; `b`
//! through `a`, with its own settings but without its `ProxyJump` or
//! `ProxyCommand` (`ssh` sets those aside for every hop after the first);
//! the destination through `b`. A user or port in the jump spec wins over
//! the hop's settings, as `-l` and `-p` would.

use std::time::Duration;

use sshkm_core::config::{EffectiveSettings, SshConfig};

use crate::error::{Error, NotAvailable};

/// Most machines one connection goes through, destination included.
pub const MAX_HOPS: usize = 8;

/// One machine on the way: a jump host or the destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// The name as typed, or as the `ProxyJump` spec names it.
    pub alias: String,
    /// What is connected to and looked up in `known_hosts`: `HostName`, or
    /// the alias.
    pub host: String,
    pub port: u16,
    /// `User`, or the user of the jump spec; `None` if neither says.
    pub user: Option<String>,
    /// `ConnectTimeout`: how long to wait for the connection and the
    /// server's key. `None`: as long as the network takes.
    pub connect_timeout: Option<Duration>,
    /// `ServerAliveInterval`: after this long without a word from the
    /// server, ask it. `None` (or `0` in the settings): off.
    pub server_alive_interval: Option<Duration>,
    /// `ServerAliveCountMax`: unanswered asks before giving up (3).
    pub server_alive_count_max: u32,
}

/// The machines a connection goes through, in the order they're reached;
/// the last is the destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub hops: Vec<Endpoint>,
}

impl Route {
    /// Works out the way to `destination` (the name as typed) from the host
    /// blocks in `config`.
    pub fn resolve(config: &SshConfig, destination: &str) -> Result<Self, Error> {
        let destination = destination.trim();
        if destination.is_empty() || !is_host_name(destination) {
            return Err(Error::BadSettings {
                alias: destination.to_owned(),
                detail: "not a host name".to_owned(),
            });
        }
        let mut hops = Vec::new();
        let mut path = Vec::new();
        resolve_into(
            config,
            &Spec {
                user: None,
                host: destination.to_owned(),
                port: None,
            },
            true,
            &mut path,
            &mut hops,
        )?;
        Ok(Self { hops })
    }

    /// The destination.
    pub fn destination(&self) -> &Endpoint {
        self.hops.last().expect("a route has a destination")
    }
}

/// One `[user@]host[:port]` of a jump spec, or the destination.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Spec {
    user: Option<String>,
    host: String,
    port: Option<u16>,
}

/// Appends the way to `spec` to `hops`: its first jump host's way (with
/// that host's own `ProxyJump` if `honour_jump`), the other jump hosts,
/// then `spec` itself. `path` holds the names being resolved, to stop a
/// circle.
fn resolve_into(
    config: &SshConfig,
    spec: &Spec,
    honour_jump: bool,
    path: &mut Vec<String>,
    hops: &mut Vec<Endpoint>,
) -> Result<(), Error> {
    let alias = spec.host.clone();
    let key = alias.to_lowercase();
    if path.contains(&key) {
        return Err(bad(&alias, "the jump hosts go round in a circle"));
    }
    // Each level of first hops adds a machine: stop before the stack grows.
    if path.len() + hops.len() >= MAX_HOPS {
        return Err(bad(&alias, "more than 8 machines on the way"));
    }
    // A user in the jump spec is given as `ssh -l` gives it: before the
    // files, and `Match user` sees it.
    let settings = config.effective_as(&alias, spec.user.as_deref());
    check_available(&alias, &settings, honour_jump)?;
    let endpoint = endpoint(&alias, spec, &settings)?;
    if honour_jump
        && let Some(jump) = settings.get("proxyjump")
        && !jump.eq_ignore_ascii_case("none")
    {
        let specs = parse_jump(&alias, jump)?;
        path.push(key);
        for (i, hop) in specs.iter().enumerate() {
            resolve_into(config, hop, i == 0, path, hops)?;
        }
        path.pop();
    }
    if hops.len() >= MAX_HOPS {
        return Err(bad(&alias, "more than 8 machines on the way"));
    }
    hops.push(endpoint);
    Ok(())
}

/// Refuses a host whose settings need `ssh` (see the module documentation):
/// every line in effect that would run a program, except those for what the
/// phone never does; every odd line in the file; a `Match` only `ssh` can
/// evaluate; `CanonicalizeHostname` (`ssh` reads the files again with the
/// name it finds, the phone can't). For a hop after the first, `ssh` sets
/// aside `ProxyCommand` and `ProxyJump` (`honour_jump` false).
///
/// The phone's host blocks come from own-device sync, which never carries
/// `Include` or options before the first block (`sync::hosts`): an
/// `Include` that makes every host unavailable means the file was made some
/// other way, and the phone can't read what it names anyway.
fn check_available(
    alias: &str,
    settings: &EffectiveSettings,
    honour_jump: bool,
) -> Result<(), Error> {
    let refuse = |reason| {
        Err(Error::NotAvailable {
            alias: alias.to_owned(),
            reason,
        })
    };
    if let Some(line) = settings.odd_lines.first() {
        return refuse(NotAvailable::OddLine { line: line.clone() });
    }
    for directive in &settings.runs_code {
        let keyword = directive.key.replace('"', "").to_ascii_lowercase();
        let harmless = match keyword.as_str() {
            "proxycommand" => !honour_jump,
            // What the phone never does: a library or an agent for keys,
            // X11, a command instead of the shell, another name for
            // `known_hosts`. Names with odd characters (`HostName`,
            // `User`, `ProxyJump`) are checked as names below.
            "remotecommand"
            | "pkcs11provider"
            | "smartcarddevice"
            | "securitykeyprovider"
            | "identityagent"
            | "xauthlocation"
            | "hostkeyalias"
            | "hostname"
            | "user"
            | "proxyjump" => true,
            _ => false,
        };
        if !harmless {
            return refuse(NotAvailable::RunsProgram {
                directive: directive.key.clone(),
                value: directive.value.clone(),
            });
        }
    }
    if let Some(line) = settings.undecided.first() {
        return refuse(NotAvailable::Undecided { line: line.clone() });
    }
    if let Some(value) = settings.get("canonicalizehostname")
        && !first_word(value).eq_ignore_ascii_case("no")
    {
        return refuse(NotAvailable::Undecided {
            line: format!("CanonicalizeHostname {value}"),
        });
    }
    Ok(())
}

/// The endpoint `spec` names, with its settings.
fn endpoint(alias: &str, spec: &Spec, settings: &EffectiveSettings) -> Result<Endpoint, Error> {
    // `ssh` connects to, and looks up, the name in lower case.
    let host = match settings.get("hostname") {
        Some(name) => expand_host_name(alias, name)?,
        None => alias.to_owned(),
    }
    .to_lowercase();
    if !is_host_name(&host) {
        return Err(bad(alias, format!("{host:?} is not a host name")));
    }
    let port = match spec.port {
        Some(port) => port,
        None => settings
            .get("port")
            .map(|p| parse_port(p).ok_or_else(|| bad(alias, format!("{p:?} is not a port"))))
            .transpose()?
            .unwrap_or(22),
    };
    let user = match &spec.user {
        Some(user) => Some(user.clone()),
        None => settings.get("user").map(str::to_owned),
    };
    if let Some(user) = &user
        && (user.is_empty() || user.contains('%') || user.chars().any(char::is_control))
    {
        return Err(bad(alias, format!("{user:?} is not a user name")));
    }
    let time = |key: &str| -> Result<Option<Duration>, Error> {
        match settings.get(key) {
            Some(value) => {
                parse_time(value).map_err(|()| bad(alias, format!("{value:?} is not a time")))
            }
            None => Ok(None),
        }
    };
    let connect_timeout = time("connecttimeout")?;
    let server_alive_interval = time("serveraliveinterval")?;
    let server_alive_count_max = settings
        .get("serveralivecountmax")
        .map(|value| {
            first_word(value)
                .parse::<u32>()
                .map_err(|_| bad(alias, format!("{value:?} is not a number")))
        })
        .transpose()?
        .unwrap_or(3);
    Ok(Endpoint {
        alias: alias.to_owned(),
        host,
        port,
        user,
        connect_timeout,
        server_alive_interval,
        server_alive_count_max,
    })
}

fn bad(alias: &str, detail: impl Into<String>) -> Error {
    Error::BadSettings {
        alias: alias.to_owned(),
        detail: detail.into(),
    }
}

/// `HostName` with `%h` (the alias) and `%%` expanded, as `ssh` expands it;
/// any other token is an error there too.
fn expand_host_name(alias: &str, name: &str) -> Result<String, Error> {
    let mut out = String::with_capacity(name.len());
    let mut chars = name.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('h') => out.push_str(alias),
            Some('%') => out.push('%'),
            _ => return Err(bad(alias, format!("{name:?} has a token other than %h"))),
        }
    }
    Ok(out)
}

/// A name or address to connect to: letters, digits, `.`, `-`, `_`, and
/// `:` for IPv6. The same characters `known_hosts` lines take.
pub(crate) fn is_host_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(['-', '.'])
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
}

/// A port number, 1 to 65535.
fn parse_port(value: &str) -> Option<u16> {
    first_word(value).parse::<u16>().ok().filter(|p| *p > 0)
}

/// The first argument of a value as written (`"30"` is `30`).
fn first_word(value: &str) -> &str {
    value.trim().trim_matches(['"', '\'']).trim()
}

/// A time as `ssh_config` writes them (`convtime()`): seconds, or numbers
/// with `s`, `m`, `h`, `d` or `w` one after another (`1h30m`). `0` and
/// `none` are off (`None`); an error if it isn't a time.
fn parse_time(value: &str) -> Result<Option<Duration>, ()> {
    let value = first_word(value);
    if value.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    if value.is_empty() {
        return Err(());
    }
    let mut total: u64 = 0;
    let mut number = String::new();
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() {
            number.push(c);
            if chars.peek().is_some() {
                continue;
            }
        }
        if number.is_empty() {
            return Err(());
        }
        let n: u64 = number.parse().map_err(|_| ())?;
        number.clear();
        let unit = if c.is_ascii_digit() {
            1
        } else {
            match c.to_ascii_lowercase() {
                's' => 1,
                'm' => 60,
                'h' => 60 * 60,
                'd' => 24 * 60 * 60,
                'w' => 7 * 24 * 60 * 60,
                _ => return Err(()),
            }
        };
        total = n
            .checked_mul(unit)
            .and_then(|t| t.checked_add(total))
            .ok_or(())?;
    }
    // `ssh` takes the time in milliseconds as an int.
    if total > u64::from(i32::MAX.unsigned_abs()) / 1000 {
        return Err(());
    }
    Ok((total > 0).then(|| Duration::from_secs(total)))
}

/// The hops of a `ProxyJump` value: `[user@]host[:port]` or
/// `ssh://[user@]host[:port]`, comma-separated, with `[…]` around an IPv6
/// address that has a port.
fn parse_jump(alias: &str, value: &str) -> Result<Vec<Spec>, Error> {
    let fail = || bad(alias, format!("ProxyJump {value:?} can't be read"));
    let mut specs = Vec::new();
    for hop in value.split(',') {
        let hop = hop.trim();
        let hop = match hop.strip_prefix("ssh://") {
            Some(rest) => rest.strip_suffix('/').unwrap_or(rest),
            None => hop,
        };
        let (user, rest) = match hop.rsplit_once('@') {
            Some((user, rest)) => (Some(user), rest),
            None => (None, hop),
        };
        let (host, port) = if let Some(bracketed) = rest.strip_prefix('[') {
            let (host, after) = bracketed.split_once(']').ok_or_else(fail)?;
            match after {
                "" => (host, None),
                _ => (host, Some(after.strip_prefix(':').ok_or_else(fail)?)),
            }
        } else {
            match rest.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (rest, None),
            }
        };
        let port = port
            .map(|p| parse_port(p).filter(|_| !p.starts_with(['"', '\''])))
            .map(|p| p.ok_or_else(fail))
            .transpose()?;
        if !is_host_name(host) || user.is_some_and(|u| u.is_empty() || !u.chars().all(is_user_char))
        {
            return Err(fail());
        }
        specs.push(Spec {
            user: user.map(str::to_owned),
            host: host.to_owned(),
            port,
        });
    }
    if specs.is_empty() {
        return Err(fail());
    }
    Ok(specs)
}

/// Characters of a user name in a jump spec.
fn is_user_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | '\\' | '$')
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    fn route(config: &str, destination: &str) -> Result<Route, Error> {
        Route::resolve(&SshConfig::parse(config), destination)
    }

    fn names(route: &Route) -> Vec<String> {
        route
            .hops
            .iter()
            .map(|h| {
                format!(
                    "{}={}@{}:{}",
                    h.alias,
                    h.user.as_deref().unwrap_or("-"),
                    h.host,
                    h.port
                )
            })
            .collect()
    }

    const CONFIG: &str = "\
Host web
  HostName 10.0.0.5
  User deploy
  Port 2222
  IdentityFile ~/.ssh/web
  ForwardAgent yes
  ServerAliveInterval 1m
  ServerAliveCountMax 5
  ConnectTimeout 10
Host db
  HostName db.internal
  ProxyJump bastion
Host deep
  ProxyJump admin@bastion:2200,db
Host bastion
  HostName bastion.example.com
  User jump
  ProxyJump edge
Host edge
  HostName %h.example.com
Host *
  User fallback
";

    #[test]
    fn the_settings_the_phone_honours() {
        let web = route(CONFIG, "web").unwrap();
        assert_eq!(
            web.hops,
            [Endpoint {
                alias: "web".into(),
                host: "10.0.0.5".into(),
                port: 2222,
                user: Some("deploy".into()),
                connect_timeout: Some(Duration::from_secs(10)),
                server_alive_interval: Some(Duration::from_secs(60)),
                server_alive_count_max: 5,
            }]
        );
        // A name without a block of its own is connected to as it is.
        let plain = route(CONFIG, "example.org").unwrap();
        assert_eq!(names(&plain), ["example.org=fallback@example.org:22"]);
        assert_eq!(plain.destination().server_alive_count_max, 3);
        assert_eq!(plain.destination().server_alive_interval, None);
        assert_eq!(plain.destination().connect_timeout, None);
    }

    #[test]
    fn jump_chains_follow_ssh() {
        // db → bastion, whose own ProxyJump (edge) is honoured: it is the
        // first hop.
        assert_eq!(
            names(&route(CONFIG, "db").unwrap()),
            [
                "edge=fallback@edge.example.com:22",
                "bastion=jump@bastion.example.com:22",
                "db=fallback@db.internal:22",
            ]
        );
        // deep → bastion (user and port from the spec), then db, whose own
        // ProxyJump is set aside after the first hop.
        assert_eq!(
            names(&route(CONFIG, "deep").unwrap()),
            [
                "edge=fallback@edge.example.com:22",
                "bastion=admin@bastion.example.com:2200",
                "db=fallback@db.internal:22",
                "deep=fallback@deep:22",
            ]
        );
    }

    #[test]
    fn the_jump_specs_user_is_what_match_user_sees() {
        let config = "\
Host db
  User me
  ProxyJump admin@bastion
Host bastion
  User jump
Match user admin
  ProxyCommand nc %h %p
";
        // OpenSSH runs `ssh -l admin bastion`: the Match applies there.
        assert!(matches!(
            route(config, "db"),
            Err(Error::NotAvailable { alias, .. }) if alias == "bastion"
        ));
        assert_eq!(
            names(&route(config, "bastion").unwrap()),
            ["bastion=jump@bastion:22"]
        );
    }

    #[test]
    fn names_are_case_sensitive_but_connect_in_lower_case() {
        let config = "Host Web\n  HostName %h.Example.COM\n  Port 2200\n";
        assert_eq!(
            names(&route(config, "Web").unwrap()),
            ["Web=-@web.example.com:2200"]
        );
        // `ssh -G web` doesn't take `Host Web`.
        assert_eq!(names(&route(config, "web").unwrap()), ["web=-@web:22"]);
        assert_eq!(
            names(&route("", "EXAMPLE.org").unwrap()),
            ["EXAMPLE.org=-@example.org:22"]
        );
    }

    #[test]
    fn circles_and_long_chains_are_refused() {
        let circle = "Host a\n  ProxyJump b\nHost b\n  ProxyJump a\n";
        assert!(matches!(
            route(circle, "a"),
            Err(Error::BadSettings { detail, .. }) if detail.contains("circle")
        ));
        let mut long = String::new();
        for i in 0..10 {
            writeln!(long, "Host h{i}\n  ProxyJump h{}", i + 1).unwrap();
        }
        assert!(matches!(route(&long, "h0"), Err(Error::BadSettings { .. })));
        // `none` turns the jump off.
        let none = "Host a\n  ProxyJump none\nHost *\n  ProxyJump b\n";
        assert_eq!(names(&route(none, "a").unwrap()), ["a=-@a:22"]);
    }

    #[test]
    fn hosts_that_need_ssh_are_not_available() {
        for (config, directive) in [
            ("Host a\n  ProxyCommand nc %h %p\n", "ProxyCommand"),
            ("Host a\n  LocalCommand echo\n", "LocalCommand"),
            ("Host a\n  PermitLocalCommand yes\n", "PermitLocalCommand"),
            (
                "Host a\n  KnownHostsCommand /bin/cat\n",
                "KnownHostsCommand",
            ),
            ("Match exec \"true\"\n  User x\n", "Match"),
            ("Host *\n  Include other\n", "Include"),
            // On a jump host.
            (
                "Host a\n  ProxyJump b\nHost b\n  ProxyCommand nc %h %p\n",
                "ProxyCommand",
            ),
        ] {
            match route(config, "a") {
                Err(Error::NotAvailable {
                    reason: NotAvailable::RunsProgram { directive: d, .. },
                    ..
                }) => assert_eq!(d, directive, "{config}"),
                other => panic!("{config}: {other:?}"),
            }
        }
        // Odd lines anywhere: `ssh` reads `=Host web` as `Host web`, so the
        // ProxyCommand below it is web's, and the HostName after `=Host
        // other` isn't web's.
        for config in [
            "Host nothing\n=Host a\n  ProxyCommand nc evil 22\n",
            "Host nothing\nHost a \x0b\n  ProxyCommand nc evil 22\n",
            "Host a\n  User alice\n=Host other\n  HostName evil.example.com\n",
            "Host a\n  User alice\nHost b\n  Proxy-Command x\n",
        ] {
            assert!(
                matches!(
                    route(config, "a"),
                    Err(Error::NotAvailable {
                        reason: NotAvailable::OddLine { .. },
                        ..
                    })
                ),
                "{config:?}"
            );
        }
        // Anything else that would run a program is refused by default.
        for config in [
            "Host a\n  ProxyCommand nc %h %p\n  Include x\n",
            "Match exec x\n",
        ] {
            assert!(
                matches!(route(config, "a"), Err(Error::NotAvailable { .. })),
                "{config}"
            );
        }
        for value in ["yes", "always", "\"yes\""] {
            assert!(
                matches!(
                    route(&format!("Host a\n  CanonicalizeHostname {value}\n"), "a"),
                    Err(Error::NotAvailable {
                        reason: NotAvailable::Undecided { .. },
                        ..
                    })
                ),
                "{value}"
            );
        }
        route("Host a\n  CanonicalizeHostname no\n", "a").unwrap();
        assert!(matches!(
            route("Match localuser bob\n  User x\n", "a"),
            Err(Error::NotAvailable {
                reason: NotAvailable::Undecided { .. },
                ..
            })
        ));
        // Harmless values, and what the phone never does, are fine.
        route(
            "Host a\n  ProxyCommand none\n  PermitLocalCommand no\n  RemoteCommand top\n  \
             PKCS11Provider /lib/p11.so\n  ForwardX11 yes\n",
            "a",
        )
        .unwrap();
        // A hop after the first: ssh sets its ProxyCommand aside.
        let second = "Host a\n  ProxyJump b,c\nHost c\n  ProxyCommand nc %h %p\n";
        assert_eq!(
            names(&route(second, "a").unwrap()),
            ["b=-@b:22", "c=-@c:22", "a=-@a:22"]
        );
    }

    #[test]
    fn bad_values_are_reported() {
        for config in [
            "Host a\n  Port 0\n",
            "Host a\n  Port ssh\n",
            "Host a\n  HostName %p.example.com\n",
            "Host a\n  HostName \"two words\"\n",
            "Host a\n  ConnectTimeout soon\n",
            "Host a\n  ServerAliveCountMax many\n",
            "Host a\n  User %u\n",
            "Host a\n  ProxyJump bad;name\n",
            "Host a\n  ProxyJump b:99999\n",
            "Host a\n  ProxyJump @b\n",
        ] {
            assert!(
                matches!(route(config, "a"), Err(Error::BadSettings { .. })),
                "{config}"
            );
        }
        assert!(matches!(route("", "a b"), Err(Error::BadSettings { .. })));
        assert!(matches!(
            route("", "-oProxyCommand=x"),
            Err(Error::BadSettings { .. })
        ));
    }

    #[test]
    fn jump_specs() {
        let spec = |user: Option<&str>, host: &str, port: Option<u16>| Spec {
            user: user.map(str::to_owned),
            host: host.to_owned(),
            port,
        };
        assert_eq!(
            parse_jump(
                "x",
                "alice@a:2222,ssh://b/,[::1]:2200,c.example.com,[fe80::1]"
            )
            .unwrap(),
            [
                spec(Some("alice"), "a", Some(2222)),
                spec(None, "b", None),
                spec(None, "::1", Some(2200)),
                spec(None, "c.example.com", None),
                spec(None, "fe80::1", None),
            ]
        );
        assert!(parse_jump("x", "").is_err());
        assert!(parse_jump("x", "a,,b").is_err());
    }

    #[test]
    fn times() {
        assert_eq!(parse_time("30"), Ok(Some(Duration::from_secs(30))));
        assert_eq!(parse_time("1h30m"), Ok(Some(Duration::from_secs(5400))));
        assert_eq!(parse_time("2W"), Ok(Some(Duration::from_secs(1_209_600))));
        assert_eq!(parse_time("0"), Ok(None));
        assert_eq!(parse_time("none"), Ok(None));
        assert_eq!(parse_time("\"15\""), Ok(Some(Duration::from_secs(15))));
        for bad in ["", "m", "10x", "1.5", "-1", "99999999999"] {
            assert_eq!(parse_time(bad), Err(()), "{bad}");
        }
    }
}
