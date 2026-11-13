//! Asking before a saved secret goes to `ssh` through a program that may
//! run another `ssh` (see [`super::Connection::through_command`]).
//!
//! - [`program_on_the_way`] finds such a program: a `ProxyCommand`, a
//!   `LocalCommand` that is allowed to run, or a `KnownHostsCommand`, of the
//!   host or of any `ProxyJump` hop (each hop read with its own `ssh -G`). A
//!   hop that can't be read counts as one.
//! - [`FillDialog`] is the session's [`FillCheck`]: a native dialog whose
//!   default (Return) and Escape are "Don't fill in", naming the host, its
//!   user and `HostName` and the program's line, shown as text (control and
//!   direction characters escaped, cut with an ellipsis). It asks for every
//!   prompt; nothing is remembered.
//! - At most [`DIALOGS_PER_HOST`] dialogs a host in [`DIALOG_WINDOW`];
//!   beyond that the answer is "don't fill in" without asking, so a program
//!   asking again and again can't bury the user in dialogs.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use tauri::AppHandle;

use super::{Connection, FillCheck, Prompt, PromptKind, Session};
use crate::confirm::{self, Localized};
use crate::process;

/// Dialogs a host may raise in [`DIALOG_WINDOW`].
pub const DIALOGS_PER_HOST: usize = 3;
pub const DIALOG_WINDOW: Duration = Duration::from_secs(60);
/// Hosts read with `ssh -G` while looking for a program on the way.
const MAX_HOPS: usize = 8;
/// How much of the host's names and the program's line the dialog shows.
const SHOWN_NAME: usize = 100;
const SHOWN_LINE: usize = 300;

static APP: OnceLock<AppHandle> = OnceLock::new();
static LIMIT: Limiter = Limiter::new();

/// Lets [`FillDialog`] show its dialog; once, at start. Until then it never
/// fills in.
pub fn attach(app: AppHandle) {
    let _ = APP.set(app);
}

/// A program on the way to a host that may run another `ssh`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    /// The host whose configuration names it: the host itself or a hop.
    pub host: String,
    /// The line, as `ssh -G` reads it (`ProxyCommand nc %h %p`), or the
    /// `ProxyJump` a hop could not be read from.
    pub line: String,
}

/// The first program on the way to `alias` that may run another `ssh` (see
/// the [module docs](self)). `first` is `ssh -G`'s output for `alias` if
/// the caller has it.
pub fn program_on_the_way(alias: &str, first: Option<&str>) -> Option<Program> {
    let mut resolve = |hop: &Hop| {
        let mut args = vec!["-G".to_owned()];
        if let Some(user) = &hop.user {
            args.extend(["-l".to_owned(), user.clone()]);
        }
        if let Some(port) = hop.port {
            args.extend(["-p".to_owned(), port.to_string()]);
        }
        args.extend(["--".to_owned(), hop.host.clone()]);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        process::run("ssh", &args, Duration::from_secs(10))
            .ok()
            .filter(|output| output.success)
            .map(|output| output.stdout)
    };
    let first = match first {
        Some(text) => Some(text.to_owned()),
        None => resolve(&Hop {
            user: None,
            host: alias.to_owned(),
            port: None,
        }),
    };
    find_program(alias, first.as_deref(), &mut resolve)
}

/// Tells `session` how `ssh` connects to `alias` (`connection`), after
/// looking for a program on the way that may run another `ssh`: through one,
/// prompts are vouched for by none and saved secrets go out only through a
/// [`FillDialog`] naming `user` and `host_name`.
pub fn expect_way(
    session: &Session,
    alias: &str,
    connection: Connection,
    user: Option<&str>,
    host_name: Option<&str>,
) {
    let program = program_on_the_way(alias, None);
    session.expect_connection(connection.through_command(program.is_some()));
    if let Some(program) = program {
        session.confirm_fills(FillDialog::new(alias, user, host_name, program));
    }
}

/// One host of a `ProxyJump`: `[user@]host[:port]`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Hop {
    user: Option<String>,
    host: String,
    port: Option<u16>,
}

/// [`program_on_the_way`] with `resolve` for `ssh -G`. A host is read
/// at most once, and at most [`MAX_HOPS`] of them; a hop with an odd name,
/// one `ssh -G` fails for, or one past the limit counts as a program.
fn find_program(
    alias: &str,
    first: Option<&str>,
    resolve: &mut dyn FnMut(&Hop) -> Option<String>,
) -> Option<Program> {
    let unread = |host: &str, line: String| Program {
        host: host.to_owned(),
        line,
    };
    let Some(first) = first else {
        return Some(unread(alias, "ssh -G".to_owned()));
    };
    let mut queue = vec![(alias.to_owned(), first.to_owned())];
    let mut seen = vec![alias.to_owned()];
    while let Some((host, text)) = queue.pop() {
        let read = Read::parse(&text);
        if let Some(line) = read.program {
            return Some(unread(&host, line));
        }
        for hop in read.jump.iter().flat_map(|jump| jump.split(',')) {
            let Some(hop) = parse_hop(hop) else {
                return Some(unread(&host, format!("ProxyJump {hop}")));
            };
            if seen.contains(&hop.host) {
                continue;
            }
            if seen.len() >= MAX_HOPS {
                return Some(unread(&hop.host, "ProxyJump".to_owned()));
            }
            seen.push(hop.host.clone());
            match resolve(&hop) {
                Some(text) => queue.push((hop.host, text)),
                None => return Some(unread(&hop.host, "ssh -G".to_owned())),
            }
        }
    }
    None
}

/// What of one `ssh -G` output matters here.
struct Read {
    /// A line that runs a program which may run another `ssh`.
    program: Option<String>,
    jump: Option<String>,
}

impl Read {
    fn parse(text: &str) -> Self {
        let mut program = None;
        let mut proxy_jump = None;
        let mut local_command = None;
        let mut permit_local = false;
        for line in text.lines() {
            let Some((key, value)) = line.split_once(' ') else {
                continue;
            };
            let value = value.trim();
            let named = match key {
                "proxycommand" if value != "none" => "ProxyCommand",
                "knownhostscommand" if value != "none" => "KnownHostsCommand",
                "localcommand" if value != "none" => {
                    local_command.get_or_insert_with(|| value.to_owned());
                    continue;
                }
                "permitlocalcommand" => {
                    permit_local = value == "yes";
                    continue;
                }
                "proxyjump" if value != "none" => {
                    proxy_jump.get_or_insert_with(|| value.to_owned());
                    continue;
                }
                _ => continue,
            };
            program.get_or_insert_with(|| format!("{named} {value}"));
        }
        if program.is_none()
            && permit_local
            && let Some(command) = local_command
        {
            program = Some(format!("LocalCommand {command}"));
        }
        Self {
            program,
            jump: proxy_jump,
        }
    }
}

/// `[ssh://][user@]host[:port]`, with a host and user the app would run
/// `ssh` with (see [`sshkm_core::tunnels::is_plain_alias`]).
fn parse_hop(hop: &str) -> Option<Hop> {
    let hop = hop.trim();
    let hop = hop.strip_prefix("ssh://").unwrap_or(hop);
    let (user, rest) = match hop.rsplit_once('@') {
        Some((user, rest)) => (Some(user), rest),
        None => (None, hop),
    };
    let (host, port) = if let Some(bracketed) = rest.strip_prefix('[') {
        let (host, after) = bracketed.split_once(']')?;
        match after.strip_prefix(':') {
            Some(port) => (host, Some(port)),
            None if after.is_empty() => (host, None),
            None => return None,
        }
    } else {
        match rest.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (host, Some(port)),
            _ => (rest, None),
        }
    };
    let port = match port {
        Some(port) => Some(port.parse::<u16>().ok().filter(|p| *p > 0)?),
        None => None,
    };
    let plain = |s: &str| sshkm_core::tunnels::is_plain_alias(s) && !s.contains('@');
    if !plain(host) || user.is_some_and(|user| !plain(user)) {
        return None;
    }
    Some(Hop {
        user: user.map(str::to_owned),
        host: host.to_owned(),
        port,
    })
}

/// The dialog that asks before a saved secret is filled in through a
/// program that may run another `ssh`.
pub struct FillDialog {
    alias: String,
    user: Option<String>,
    host_name: Option<String>,
    program: Program,
}

impl FillDialog {
    pub fn new(alias: &str, user: Option<&str>, host_name: Option<&str>, program: Program) -> Self {
        Self {
            alias: alias.to_owned(),
            user: user.map(str::to_owned),
            host_name: host_name.map(str::to_owned),
            program,
        }
    }

    /// The dialog's title and text for `prompt`.
    fn texts(&self, prompt: &Prompt) -> (Localized, Localized) {
        let alias = confirm::shown(&self.alias, SHOWN_NAME);
        let who = match (&self.user, &self.host_name) {
            (Some(user), Some(host)) => format!(
                "{alias} ({}@{})",
                confirm::shown(user, SHOWN_NAME),
                confirm::shown(host, SHOWN_NAME)
            ),
            (None, Some(host)) => format!("{alias} ({})", confirm::shown(host, SHOWN_NAME)),
            _ => alias.clone(),
        };
        let line = if self.program.host == self.alias {
            confirm::shown(&self.program.line, SHOWN_LINE)
        } else {
            format!(
                "{}: {}",
                confirm::shown(&self.program.host, SHOWN_NAME),
                confirm::shown(&self.program.line, SHOWN_LINE)
            )
        };
        let (title, what) = match &prompt.kind {
            PromptKind::OneTimeCode => (
                Localized::new(
                    "Fill in the 2FA code?",
                    "Подставить код 2FA?",
                    "2FA kodi kiritilsinmi?",
                ),
                Localized::new("The 2FA code", "Код 2FA", "2FA kodi"),
            ),
            PromptKind::Passphrase { key } => {
                let key = confirm::shown(key, SHOWN_LINE);
                (
                    Localized::new(
                        "Fill in the key’s passphrase?",
                        "Подставить парольную фразу ключа?",
                        "Kalitning parol iborasi kiritilsinmi?",
                    ),
                    Localized::new(
                        format!("The passphrase of {key}"),
                        format!("Парольная фраза ключа {key}"),
                        format!("{key} kalitining parol iborasi"),
                    ),
                )
            }
            _ => (
                Localized::new(
                    "Fill in the password?",
                    "Подставить пароль?",
                    "Parol kiritilsinmi?",
                ),
                Localized::new("The password", "Пароль", "Parol"),
            ),
        };
        let body = Localized::new(
            format!(
                "{} is asked for while connecting to {who}, which is reached through a \
                 program that may run another ssh:\n{line}\n\nSo the request may come from a \
                 server on the way rather than from {alias}. Fill it in only if you are \
                 signing in to {alias} right now.",
                what.en
            ),
            format!(
                "{} запрашивается при подключении к {who}, а путь к нему идёт через программу, \
                 которая может запускать другой ssh:\n{line}\n\nПоэтому запрос может прийти от \
                 промежуточного сервера, а не от {alias}. Подставляйте, только если вы прямо \
                 сейчас входите на {alias}.",
                what.ru
            ),
            format!(
                "{who} ga ulanishda {} soʻralmoqda; unga boshqa ssh ni ishga tushirishi mumkin \
                 boʻlgan dastur orqali ulaniladi:\n{line}\n\nShuning uchun soʻrov {alias} dan \
                 emas, yoʻldagi serverdan kelgan boʻlishi mumkin. Faqat hozir {alias} ga \
                 kirayotgan boʻlsangiz, kiriting.",
                what.uz
            ),
        );
        (title, body)
    }
}

/// The dialog's buttons: fill in, and the default, don't.
fn buttons() -> (Localized, Localized) {
    (
        Localized::new("Fill in", "Подставить", "Kiritish"),
        Localized::new("Don’t fill in", "Не подставлять", "Kiritmaslik"),
    )
}

impl FillCheck for FillDialog {
    fn allow(&self, prompt: &Prompt) -> bool {
        let Some(app) = APP.get() else {
            return false;
        };
        if !LIMIT.take(&self.alias, Instant::now()) {
            log::info!("askpass: too many fill-in questions for one host; not filling in");
            return false;
        }
        let (title, body) = self.texts(prompt);
        let (fill, keep) = buttons();
        confirm::ask_default_no(app, &title, &body, &fill, &keep)
    }
}

/// When each host's last dialogs were shown.
struct Limiter {
    shown: Mutex<Option<HashMap<String, Vec<Instant>>>>,
}

impl Limiter {
    const fn new() -> Self {
        Self {
            shown: Mutex::new(None),
        }
    }

    /// Whether `host` may show a dialog at `now`, counting it if so.
    fn take(&self, host: &str, now: Instant) -> bool {
        let mut shown = self.shown.lock().unwrap_or_else(PoisonError::into_inner);
        let shown = shown.get_or_insert_with(HashMap::new);
        shown.retain(|_, times| {
            times.retain(|at| now.saturating_duration_since(*at) < DIALOG_WINDOW);
            !times.is_empty()
        });
        let times = shown.entry(host.to_owned()).or_default();
        if times.len() >= DIALOGS_PER_HOST {
            return false;
        }
        times.push(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ssh -G` output with `lines` after the usual ones.
    fn ssh_g(lines: &str) -> String {
        format!("host x\nuser alice\nhostname 10.0.0.5\nport 22\n{lines}")
    }

    fn found(first: &str, hops: &[(&str, Option<&str>)]) -> (Option<Program>, Vec<Hop>) {
        let mut asked = Vec::new();
        let mut resolve = |hop: &Hop| {
            asked.push(hop.clone());
            hops.iter()
                .find(|(host, _)| *host == hop.host)
                .and_then(|(_, text)| text.map(ssh_g))
        };
        let program = find_program("target", Some(&ssh_g(first)), &mut resolve);
        (program, asked)
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "compared with what `find_program` returns"
    )]
    fn program(host: &str, line: &str) -> Option<Program> {
        Some(Program {
            host: host.into(),
            line: line.into(),
        })
    }

    #[test]
    fn finds_a_program_on_the_host() {
        assert_eq!(
            found("proxycommand nc %h %p\n", &[]).0,
            program("target", "ProxyCommand nc %h %p")
        );
        assert_eq!(
            found("knownhostscommand /bin/kh %H\n", &[]).0,
            program("target", "KnownHostsCommand /bin/kh %H")
        );
        // A LocalCommand runs only when allowed.
        assert_eq!(found("localcommand echo hi\n", &[]).0, None);
        assert_eq!(
            found("localcommand echo hi\npermitlocalcommand yes\n", &[]).0,
            program("target", "LocalCommand echo hi")
        );
        assert_eq!(
            found(
                "proxycommand none\nproxyjump none\nknownhostscommand none\n",
                &[]
            )
            .0,
            None
        );
        // `ssh -G` failed for the host itself.
        let mut never = |_: &Hop| -> Option<String> { panic!("nothing to resolve") };
        assert_eq!(
            find_program("target", None, &mut never),
            program("target", "ssh -G")
        );
    }

    #[test]
    fn follows_every_jump_host() {
        // A jump host's own ProxyCommand.
        let (found_program, asked) = found(
            "proxyjump admin@bastion:2222\n",
            &[("bastion", Some("proxycommand ssh -W %h:%p old\n"))],
        );
        assert_eq!(
            found_program,
            program("bastion", "ProxyCommand ssh -W %h:%p old")
        );
        assert_eq!(
            asked,
            [Hop {
                user: Some("admin".into()),
                host: "bastion".into(),
                port: Some(2222),
            }]
        );
        // Through two hops, one nested.
        let (found_program, _) = found(
            "proxyjump a,ssh://b\n",
            &[
                ("a", Some("")),
                ("b", Some("proxyjump c\n")),
                ("c", Some("proxycommand nc %h %p\n")),
            ],
        );
        assert_eq!(found_program, program("c", "ProxyCommand nc %h %p"));
        // Plain jumps all the way.
        let (found_program, asked) = found("proxyjump a,b\n", &[("a", Some("")), ("b", Some(""))]);
        assert_eq!(found_program, None);
        assert_eq!(asked.len(), 2);
        // A hop that can't be read counts as a program.
        assert_eq!(
            found("proxyjump gone\n", &[("gone", None)]).0,
            program("gone", "ssh -G")
        );
    }

    #[test]
    fn odd_or_endless_jumps_count_as_programs() {
        for jump in [
            "-oProxyCommand=x",
            "a;b",
            "x@-e",
            "host:0",
            "host:http",
            "[::1",
        ] {
            let (found_program, asked) = found(&format!("proxyjump {jump}\n"), &[]);
            assert!(found_program.is_some(), "{jump}");
            assert!(asked.is_empty(), "{jump} was read");
        }
        // A loop is read once per host.
        let (found_program, asked) = found(
            "proxyjump a\n",
            &[("a", Some("proxyjump b\n")), ("b", Some("proxyjump a\n"))],
        );
        assert_eq!(found_program, None);
        assert_eq!(asked.len(), 2);
        // A long chain stops being read.
        let chain: Vec<(String, String)> = (0..20)
            .map(|i| (format!("h{i}"), format!("proxyjump h{}\n", i + 1)))
            .collect();
        let hops: Vec<(&str, Option<&str>)> = chain
            .iter()
            .map(|(host, text)| (host.as_str(), Some(text.as_str())))
            .collect();
        let (found_program, asked) = found("proxyjump h0\n", &hops);
        assert!(found_program.is_some());
        assert!(asked.len() < MAX_HOPS);
    }

    #[test]
    fn reads_jump_hosts() {
        let hop = |user: Option<&str>, host: &str, port: Option<u16>| {
            Some(Hop {
                user: user.map(str::to_owned),
                host: host.to_owned(),
                port,
            })
        };
        assert_eq!(parse_hop("bastion"), hop(None, "bastion", None));
        assert_eq!(
            parse_hop("ssh://ops@jump.example:2222"),
            hop(Some("ops"), "jump.example", Some(2222))
        );
        assert_eq!(parse_hop("[::1]:22"), hop(None, "::1", Some(22)));
        assert_eq!(parse_hop("fe80::1"), hop(None, "fe80::1", None));
        assert_eq!(parse_hop("-x"), None);
        assert_eq!(parse_hop("a@-x"), None);
        assert_eq!(parse_hop("$(id)"), None);
    }

    fn dialog() -> FillDialog {
        FillDialog::new(
            "prod",
            Some("alice"),
            Some("10.0.0.5"),
            Program {
                host: "bastion".into(),
                line: "ProxyCommand ssh -W %h:%p old\u{202E}x\nrm".into(),
            },
        )
    }

    #[test]
    fn the_dialog_names_the_host_and_the_program_as_text() {
        let (title, body) = dialog().texts(&Prompt::parse("alice@10.0.0.5's password: ", ""));
        assert_eq!(title.en, "Fill in the password?");
        assert!(
            body.en
                .starts_with("The password is asked for while connecting to prod (alice@10.0.0.5)"),
            "{}",
            body.en
        );
        assert!(
            body.en
                .contains("bastion: ProxyCommand ssh -W %h:%p old<U+202E>x<U+000A>rm"),
            "{}",
            body.en
        );
        for text in [&title.ru, &title.uz, &body.ru, &body.uz] {
            assert_ne!(text, "");
        }
        assert!(body.ru.contains("prod (alice@10.0.0.5)"));
        assert!(body.uz.contains("prod (alice@10.0.0.5)"));

        let code = Prompt::parse("Verification code: ", "");
        assert_eq!(dialog().texts(&code).0.en, "Fill in the 2FA code?");
        let key = Prompt::parse("Enter passphrase for key '/home/u/.ssh/id_ed25519': ", "");
        let (title, body) = dialog().texts(&key);
        assert_eq!(title.en, "Fill in the key’s passphrase?");
        assert!(
            body.en
                .starts_with("The passphrase of /home/u/.ssh/id_ed25519")
        );

        // A long line is cut.
        let long = FillDialog::new(
            "prod",
            None,
            None,
            Program {
                host: "prod".into(),
                line: format!("ProxyCommand {}", "x".repeat(1000)),
            },
        );
        let (_, body) = long.texts(&Prompt::parse("Password: ", ""));
        assert!(body.en.contains("… (+713)"), "{}", body.en);
        assert!(body.en.contains("connecting to prod, which"));
    }

    #[test]
    fn the_default_button_does_not_fill_in() {
        let (fill, keep) = buttons();
        assert_eq!(fill.en, "Fill in");
        assert_eq!(keep.en, "Don’t fill in");
        for text in [&fill.ru, &fill.uz, &keep.ru, &keep.uz] {
            assert_ne!(text, "");
        }
    }

    #[test]
    fn dialogs_are_limited_per_host() {
        let limit = Limiter::new();
        let start = Instant::now();
        for _ in 0..DIALOGS_PER_HOST {
            assert!(limit.take("prod", start));
        }
        assert!(!limit.take("prod", start + Duration::from_secs(30)));
        // Another host has its own count.
        assert!(limit.take("db", start));
        // Once the window has passed, it may ask again.
        assert!(limit.take("prod", start + DIALOG_WINDOW));
    }

    /// Without the app, nothing is filled in.
    #[test]
    fn without_the_app_nothing_is_filled_in() {
        let prompt = Prompt::parse("alice@10.0.0.5's password: ", "");
        if APP.get().is_none() {
            assert!(!dialog().allow(&prompt));
        }
    }
}
