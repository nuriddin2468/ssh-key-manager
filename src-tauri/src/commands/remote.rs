//! Running `ssh` against a configured host, either in batch mode or with the
//! app answering its prompts (see [`crate::askpass`]).

use std::time::Duration;

use ssh_key::PublicKey;
use sshkm_core::SecretString;
use sshkm_core::keys::KeyInfo;
use tauri::State;

use sshkm_core::authorized_keys::{self, AuthorizedKeys};

use super::keys::find_key;
use super::{Shared, blocking};
use crate::askpass::{AskedPrompt, Connection, PromptAccount, Secrets};
use crate::error::{AppError, AppResult};
use crate::process::{self, Output};
use crate::state::AppState;
use crate::types::{KeyInstall, ServerKeys, ServerKeysAction};

/// Appends the public key of `key_id` to `~/.ssh/authorized_keys` on the host
/// `alias`, creating `~/.ssh` (0700) and the file (0600) if missing and
/// leaving the file alone if it has the key already. `password` and `otp`
/// answer the server's prompts; without them `ssh` must get in by itself (a
/// key that already works).
///
/// The server needs a POSIX `sh`; the key travels over stdin.
#[tauri::command]
pub async fn install_public_key(
    state: State<'_, Shared>,
    alias: String,
    key_id: String,
    password: Option<SecretString>,
    otp: Option<SecretString>,
) -> AppResult<KeyInstall> {
    blocking(&state, move |state| {
        install_key(state, &alias, &key_id, Secrets::new(password, otp))
    })
    .await
}

/// [`install_public_key`] with the secrets already gathered.
pub fn install_key(
    state: &AppState,
    alias: &str,
    key_id: &str,
    secrets: Secrets,
) -> AppResult<KeyInstall> {
    check_alias(alias)?;
    let line = public_line(&find_key(state, key_id)?)?;
    let remote = format!("sh -c '{INSTALL_SCRIPT}'");
    let run = run_ssh(
        state,
        alias,
        COMMAND_ONLY,
        &[&remote],
        secrets,
        Some(format!("{line}\n").into_bytes()),
        Duration::from_secs(30),
    )?;
    let added = run.output.success && has_line(&run.output.stdout, ADDED);
    let present = run.output.success && has_line(&run.output.stdout, PRESENT);
    let output = combined(&run.output)
        .lines()
        .filter(|line| *line != ADDED && *line != PRESENT)
        .collect::<Vec<_>>()
        .join("\n");
    Ok(KeyInstall {
        ok: added || present,
        added,
        output: with_timeout_note(output.trim().to_owned(), &run.output),
        prompts: run.prompts,
    })
}

/// Options of a run that only runs its command: no forwarding, no tty, no
/// configured `RemoteCommand` in the way.
const COMMAND_ONLY: &[&str] = &[
    "-o",
    "RemoteCommand=none",
    "-o",
    "RequestTTY=no",
    "-o",
    "ClearAllForwardings=yes",
    "-o",
    "ForwardAgent=no",
    "-o",
    "ForwardX11=no",
];

/// Reads `~/.ssh/authorized_keys` on the host `alias`, first adding or
/// removing a key if `action` says so. Without a saved password `ssh` must
/// get in by itself, with a key that already works.
///
/// The server needs a POSIX `sh`; a key travels over stdin.
#[tauri::command]
pub async fn server_keys(
    state: State<'_, Shared>,
    alias: String,
    action: ServerKeysAction,
) -> AppResult<ServerKeys> {
    blocking(&state, move |state| {
        read_server_keys(state, &alias, &action, Secrets::default())
    })
    .await
}

/// [`server_keys`] with the secrets already gathered. The change and the
/// read happen in one sign-in.
pub fn read_server_keys(
    state: &AppState,
    alias: &str,
    action: &ServerKeysAction,
    secrets: Secrets,
) -> AppResult<ServerKeys> {
    check_alias(alias)?;
    let (change, input) = match action {
        ServerKeysAction::List => (String::new(), None),
        ServerKeysAction::Add { key_id } => (
            format!("sh -c '{INSTALL_SCRIPT}'; "),
            Some(public_line(&find_key(state, key_id)?)?),
        ),
        ServerKeysAction::Remove { public_key } => (
            format!("sh -c '{REMOVE_SCRIPT}'; "),
            Some(key_blob(public_key)?),
        ),
    };
    let remote = format!("{change}sh -c '{READ_SCRIPT}'");
    let run = run_ssh(
        state,
        alias,
        COMMAND_ONLY,
        &[&remote],
        secrets,
        input.map(|line| format!("{line}\n").into_bytes()),
        Duration::from_secs(30),
    )?;

    let (before, file) = split_read(&run.output.stdout);
    let [done, changed]: [&[&str]; 2] = match action {
        ServerKeysAction::List => [&[], &[]],
        ServerKeysAction::Add { .. } => [&[ADDED, PRESENT], &[ADDED]],
        ServerKeysAction::Remove { .. } => [&[REMOVED, ABSENT], &[REMOVED]],
    };
    let marked = |markers: &[&str]| markers.iter().any(|marker| has_line(before, marker));
    let read = file != Read::Failed;
    let printed = before
        .lines()
        .filter(|line| !MARKERS.contains(&line.trim()))
        .chain(run.output.stderr.lines())
        .collect::<Vec<_>>()
        .join("\n");
    Ok(ServerKeys {
        ok: read && (done.is_empty() || marked(done)),
        changed: marked(changed),
        read,
        file: match file {
            Read::File(text) => authorized_keys::parse(text),
            Read::NoFile | Read::Failed => AuthorizedKeys::default(),
        },
        output: with_timeout_note(printed.trim().to_owned(), &run.output),
        prompts: run.prompts,
    })
}

/// What [`READ_SCRIPT`] printed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Read<'a> {
    /// The file's text, between the markers.
    File(&'a str),
    /// There is no `authorized_keys`.
    NoFile,
    /// Nothing, or cut short: signing in or reading failed.
    Failed,
}

/// What the commands printed before [`READ_SCRIPT`]'s output, and that
/// output.
fn split_read(stdout: &str) -> (&str, Read<'_>) {
    let mut offset = 0;
    for line in stdout.split_inclusive('\n') {
        let start = offset;
        offset += line.len();
        match line.trim_end() {
            NO_FILE => return (&stdout[..start], Read::NoFile),
            BEGIN => {
                // The script ends the file with a newline of its own.
                let rest = &stdout[offset..];
                let file = rest
                    .rfind(&format!("\n{END}"))
                    .map_or(Read::Failed, |end| Read::File(&rest[..end]));
                return (&stdout[..start], file);
            }
            _ => {}
        }
    }
    (stdout, Read::Failed)
}

/// The base64 blob of a one-line public key (`<type> <base64> [comment]`),
/// checked to be a key.
fn key_blob(public_key: &str) -> AppResult<String> {
    let key = PublicKey::from_openssh(public_key.trim())
        .map_err(|e| AppError::invalid(format!("not a public key: {e}")))?;
    let line = key
        .to_openssh()
        .map_err(|e| AppError::invalid(format!("not a public key: {e}")))?;
    line.split(' ')
        .nth(1)
        .map(str::to_owned)
        .ok_or_else(|| AppError::invalid("not a public key"))
}

/// A host alias as `ssh` takes it on the command line.
pub fn check_alias(alias: &str) -> AppResult<()> {
    if alias.is_empty() || alias.starts_with('-') || alias.chars().any(char::is_whitespace) {
        return Err(AppError::invalid("not a host alias"));
    }
    Ok(())
}

/// A finished `ssh` run.
pub struct SshRun {
    pub output: Output,
    /// What `ssh` asked through askpass; empty in batch mode.
    pub prompts: Vec<AskedPrompt>,
}

/// Runs `ssh <mode> -o ConnectTimeout=8 <options> -T -- <alias> <remote>`.
///
/// - Without secrets the mode is `-o BatchMode=yes`: `ssh` asks nothing.
/// - With secrets it is [`askpass_options`] and an askpass session answers
///   `ssh`'s prompts: each secret at most once, yes/no questions (an unknown
///   host key) always "no", and only for the account `ssh -G` says the alias
///   connects to, so a `ProxyJump` host never gets the target's password.
///   Prompts the session cannot vouch for are refused: a server's prompt
///   posing as `ssh`'s own, and with OpenSSH before 8.5 anything through a
///   `ProxyJump` or `ProxyCommand` (see [`Connection`]).
pub fn run_ssh(
    state: &AppState,
    alias: &str,
    options: &[&str],
    remote: &[&str],
    secrets: Secrets,
    input: Option<Vec<u8>>,
    timeout: Duration,
) -> AppResult<SshRun> {
    let mut command = process::command("ssh");
    let session = if secrets.is_empty() {
        command.args(["-o", "BatchMode=yes"]);
        None
    } else {
        let target = match ssh_target(alias)? {
            Ok(target) => target,
            // `ssh` cannot read its configuration for this host: report what
            // it said, as a failed run would.
            Err(output) => {
                return Ok(SshRun {
                    output,
                    prompts: Vec::new(),
                });
            }
        };
        let askpass = askpass_options(&secrets);
        let keyboard_interactive = target.keyboard_interactive
            && !askpass.contains(&"KbdInteractiveAuthentication=no")
            && !options.contains(&"KbdInteractiveAuthentication=no");
        let session = state.askpass_session(secrets)?;
        session.expect_account(target.account);
        session.expect_connection(Connection::new(
            state.openssh_version().as_deref(),
            keyboard_interactive,
            target.proxied,
        ));
        session.configure(&mut command);
        command.args(askpass);
        Some(session)
    };
    command
        .args(["-o", "ConnectTimeout=8"])
        .args(options)
        .args(["-T", "--", alias])
        .args(remote);
    let output = process::run_command(&mut command, input, timeout)?;
    Ok(SshRun {
        output,
        prompts: session.map(|s| s.asked()).unwrap_or_default(),
    })
}

/// The options of a run whose prompts an askpass session answers: `ssh` may
/// ask, once per password. With only key passphrases saved,
/// keyboard-interactive is off too, so a server cannot even put a prompt of
/// its own to the session. A saved password or 2FA code keeps it on: many
/// servers (FreeBSD, pfSense) ask for the password that way. Their prompts
/// still never get a passphrase (see [`Connection`]).
fn askpass_options(secrets: &Secrets) -> Vec<&'static str> {
    let mut options = vec!["-o", "BatchMode=no", "-o", "NumberOfPasswordPrompts=1"];
    if secrets.password.is_none() && secrets.one_time_code.is_none() {
        options.extend(["-o", "KbdInteractiveAuthentication=no"]);
    }
    options
}

/// What `ssh -G` says about the host a run connects to, as far as its
/// prompts go.
#[derive(Debug, PartialEq, Eq)]
struct Target {
    /// `User`, and `HostKeyAlias` or else `HostName`, as `ssh` names them in
    /// its prompts.
    account: PromptAccount,
    /// Through a `ProxyJump` or `ProxyCommand`.
    proxied: bool,
    /// `KbdInteractiveAuthentication` is not off.
    keyboard_interactive: bool,
}

/// What `ssh -G` says about `alias`. `Err` holds the output of a failed
/// `ssh -G`.
fn ssh_target(alias: &str) -> AppResult<Result<Target, Output>> {
    let output = process::run("ssh", &["-G", "--", alias], Duration::from_secs(10))?;
    if !output.success {
        return Ok(Err(output));
    }
    parse_ssh_g(&output.stdout)
        .map(Ok)
        .ok_or_else(|| AppError::invalid("ssh -G printed no user or host name"))
}

fn parse_ssh_g(text: &str) -> Option<Target> {
    let (mut user, mut host_name, mut host_key_alias) = (None, None, None);
    let (mut proxied, mut keyboard_interactive) = (false, true);
    for line in text.lines() {
        let Some((key, value)) = line.split_once(' ') else {
            continue;
        };
        let value = value.trim();
        let slot = match key {
            "user" => &mut user,
            "hostname" => &mut host_name,
            "hostkeyalias" => &mut host_key_alias,
            "proxyjump" | "proxycommand" => {
                proxied |= value != "none";
                continue;
            }
            "kbdinteractiveauthentication" => {
                keyboard_interactive = value != "no";
                continue;
            }
            _ => continue,
        };
        slot.get_or_insert_with(|| value.to_owned());
    }
    Some(Target {
        account: PromptAccount::new(user?, host_key_alias.or(host_name)?),
        proxied,
        keyboard_interactive,
    })
}

/// stdout then stderr, trimmed.
pub fn combined(output: &Output) -> String {
    format!("{}{}", output.stdout, output.stderr)
        .trim()
        .to_owned()
}

pub fn with_timeout_note(text: String, output: &Output) -> String {
    if output.timed_out {
        format!("{text}\n(timed out)").trim().to_owned()
    } else {
        text
    }
}

/// The key's one-line OpenSSH public key, checked so it cannot carry anything
/// but a key into `authorized_keys`.
fn public_line(info: &KeyInfo) -> AppResult<String> {
    let line = info
        .public_key
        .as_deref()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .ok_or_else(|| AppError::invalid(format!("{} has no public key", info.name)))?;
    if line.chars().any(char::is_control) {
        return Err(AppError::invalid(format!(
            "the public key of {} is not one line",
            info.name
        )));
    }
    PublicKey::from_openssh(line).map_err(|e| {
        AppError::invalid(format!("the public key of {} is invalid: {e}", info.name))
    })?;
    Ok(line.to_owned())
}

fn has_line(text: &str, wanted: &str) -> bool {
    text.lines().any(|line| line.trim() == wanted)
}

const ADDED: &str = "sshkm:added";
const PRESENT: &str = "sshkm:present";
const REMOVED: &str = "sshkm:removed";
const ABSENT: &str = "sshkm:absent";
const BEGIN: &str = "sshkm:begin";
const END: &str = "sshkm:end";
const NO_FILE: &str = "sshkm:none";
/// Lines the scripts print for the app, left out of what the user reads.
const MARKERS: &[&str] = &[ADDED, PRESENT, REMOVED, ABSENT];

/// Run by the server's `sh` with the key line on stdin. One line with no `'`
/// (it goes inside `sh -c '…'`) and no `!` (csh history expansion), so any
/// login shell passes it on unchanged.
///
/// It reads the key, takes its base64 blob, creates `~/.ssh` (0700) and
/// `authorized_keys` (0600 via the umask) if missing, and appends the key
/// unless a line already has the same blob (with other options or another
/// comment, say), first ending the last line if it has no newline.
const INSTALL_SCRIPT: &str = concat!(
    "umask 077; ",
    "IFS= read -r key || [ -n \"$key\" ] || exit 65; ",
    "set -f; set -- $key; [ -n \"$2\" ] || exit 65; ",
    "cd || exit 1; ",
    "[ -d .ssh ] || mkdir -m 700 .ssh || exit 1; ",
    "f=.ssh/authorized_keys; ",
    "if [ -f \"$f\" ] && awk -v b=\"$2\" ",
    "\"{ for (i = 1; i <= NF; i++) if (\\$i == b) found = 1 } END { exit found ? 0 : 1 }\" ",
    "\"$f\"; then echo sshkm:present; exit 0; fi; ",
    "if [ -s \"$f\" ] && [ -n \"$(tail -c 1 \"$f\")\" ]; then echo >> \"$f\" || exit 1; fi; ",
    "printf \"%s\\n\" \"$key\" >> \"$f\" || exit 1; ",
    "echo sshkm:added",
);

/// Run by the server's `sh` with a key's base64 blob on stdin; one line as
/// [`INSTALL_SCRIPT`] is.
///
/// It removes every line that has the blob as a field, so with any options
/// or comment, and keeps commented-out lines. The new file is written next
/// to the old one with its mode (`cp -p`) and renamed over it; behind a
/// symbolic link it is written in place, so the link stays.
const REMOVE_SCRIPT: &str = concat!(
    "IFS= read -r b || [ -n \"$b\" ] || exit 65; ",
    "[ -n \"$b\" ] || exit 65; ",
    "cd || exit 1; ",
    "f=.ssh/authorized_keys; ",
    "[ -f \"$f\" ] || { echo sshkm:absent; exit 0; }; ",
    "awk -v b=\"$b\" ",
    "\"/^[ \\t]*#/ { next } { for (i = 1; i <= NF; i++) if (\\$i == b) n++ } END { exit (n ? 0 : 1) }\" ",
    "\"$f\"; ",
    "s=$?; [ $s -ne 1 ] || { echo sshkm:absent; exit 0; }; [ $s -eq 0 ] || exit 1; ",
    "t=\"$f.sshkm-$$\"; ",
    "cp -p \"$f\" \"$t\" && awk -v b=\"$b\" ",
    "\"/^[ \\t]*#/ { print; next } { for (i = 1; i <= NF; i++) if (\\$i == b) next; print }\" ",
    "\"$f\" > \"$t\" && ",
    "if [ -L \"$f\" ]; then cat \"$t\" > \"$f\" && rm -f \"$t\"; else mv -f \"$t\" \"$f\"; fi ",
    "|| { rm -f \"$t\"; exit 1; }; ",
    "echo sshkm:removed",
);

/// Run by the server's `sh`: prints `~/.ssh/authorized_keys` between marker
/// lines, or a marker that there is none. One line as [`INSTALL_SCRIPT`] is.
const READ_SCRIPT: &str = concat!(
    "cd || exit 1; ",
    "f=.ssh/authorized_keys; ",
    "if [ -f \"$f\" ]; then echo sshkm:begin; cat \"$f\" || exit 1; echo; echo sshkm:end; ",
    "else echo sshkm:none; fi",
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases() {
        assert!(check_alias("prod").is_ok());
        assert!(check_alias("alice@example.com").is_ok());
        for bad in ["", "-oProxyCommand=x", "a b", "a\nb"] {
            assert!(check_alias(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn reads_ssh_g() {
        let text = "host prod\nuser alice\nhostname 10.0.0.5\nport 22\nidentityfile \
                    ~/.ssh/id_ed25519\nkbdinteractiveauthentication yes\n";
        assert_eq!(
            parse_ssh_g(text),
            Some(Target {
                account: PromptAccount::new("alice", "10.0.0.5"),
                proxied: false,
                keyboard_interactive: true,
            })
        );
        let aliased = format!("{text}hostkeyalias prod.example\n");
        assert_eq!(
            parse_ssh_g(&aliased).unwrap().account,
            PromptAccount::new("alice", "prod.example")
        );
        assert_eq!(parse_ssh_g("host prod\nport 22\n"), None);

        let jumped = "user alice\nhostname 10.0.0.5\nproxyjump bastion\n\
                      kbdinteractiveauthentication no\n";
        let target = parse_ssh_g(jumped).unwrap();
        assert!(target.proxied && !target.keyboard_interactive);
        let command = parse_ssh_g("user a\nhostname h\nproxycommand nc %h %p\n").unwrap();
        assert!(command.proxied);
        let none = parse_ssh_g("user a\nhostname h\nproxyjump none\nproxycommand none\n");
        assert!(!none.unwrap().proxied);
    }

    #[test]
    fn reads_real_ssh_g_output() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        std::fs::write(
            &config,
            "Host prod\n  HostName 10.0.0.5\n  User alice\nHost inner\n  HostName 10.0.0.6\n  \
             User bob\n  ProxyJump prod\n  KbdInteractiveAuthentication no\n",
        )
        .unwrap();
        let config = config.to_string_lossy();
        let ssh_g = |alias| {
            process::run(
                "ssh",
                &["-F", &config, "-G", "--", alias],
                Duration::from_secs(10),
            )
        };
        let Ok(output) = ssh_g("prod") else {
            return; // No ssh here.
        };
        assert!(output.success, "{}", output.stderr);
        assert_eq!(
            parse_ssh_g(&output.stdout),
            Some(Target {
                account: PromptAccount::new("alice", "10.0.0.5"),
                proxied: false,
                keyboard_interactive: true,
            })
        );
        let inner = parse_ssh_g(&ssh_g("inner").unwrap().stdout).unwrap();
        assert_eq!(inner.account, PromptAccount::new("bob", "10.0.0.6"));
        assert!(inner.proxied && !inner.keyboard_interactive);
    }

    #[test]
    fn keyboard_interactive_is_off_with_only_passphrases() {
        let off = |secrets: &Secrets| {
            askpass_options(secrets)
                .windows(2)
                .any(|pair| pair == ["-o", "KbdInteractiveAuthentication=no"])
        };
        assert!(off(&Secrets::default().with_passphrase("/k", "pp".into())));
        assert!(!off(
            &Secrets::new(Some("pw".into()), None).with_passphrase("/k", "pp".into())
        ));
        assert!(!off(&Secrets::new(
            Some("pw".into()),
            Some("123456".into())
        )));
        assert!(askpass_options(&Secrets::default()).starts_with(&[
            "-o",
            "BatchMode=no",
            "-o",
            "NumberOfPasswordPrompts=1"
        ]));
    }

    #[test]
    fn scripts_survive_any_login_shell() {
        for script in [INSTALL_SCRIPT, REMOVE_SCRIPT, READ_SCRIPT] {
            assert!(!script.contains('\''));
            assert!(!script.contains('!'));
            assert!(!script.contains('\n'));
        }
    }

    #[test]
    fn splits_the_file_from_what_came_before() {
        let printed = format!("motd\nsshkm:removed\n{BEGIN}\n{KEY} a\n\n{END}\n");
        assert_eq!(
            split_read(&printed),
            ("motd\nsshkm:removed\n", Read::File(&format!("{KEY} a\n")))
        );
        // An empty file, and one that names the marker itself.
        assert_eq!(
            split_read(&format!("{BEGIN}\n\n{END}\n")),
            ("", Read::File(""))
        );
        let tricky = format!("{BEGIN}\n{END}\nsshkm:added\n\n{END}\n");
        assert_eq!(
            split_read(&tricky).1,
            Read::File(&format!("{END}\nsshkm:added\n"))
        );
        assert_eq!(split_read("x\nsshkm:none\n"), ("x\n", Read::NoFile));
        // Cut short: no end marker.
        assert_eq!(split_read(&format!("{BEGIN}\n{KEY}")), ("", Read::Failed));
        assert_eq!(
            split_read("Permission denied"),
            ("Permission denied", Read::Failed)
        );
    }

    #[test]
    fn key_blobs() {
        assert_eq!(key_blob(&format!(" {KEY} alice\n")).unwrap(), &KEY[12..]);
        assert!(key_blob("ssh-ed25519 not-base64").is_err());
        assert!(key_blob("").is_err());
    }

    #[test]
    fn public_lines() {
        let mut info = key_info();
        assert_eq!(public_line(&info).unwrap(), format!("{KEY} alice@laptop"));
        info.public_key = None;
        assert!(public_line(&info).is_err());
        info.public_key = Some(format!("{KEY} alice@laptop\n"));
        assert_eq!(public_line(&info).unwrap(), format!("{KEY} alice@laptop"));
        info.public_key = Some(format!("{KEY} alice\nssh-ed25519 AAAA evil"));
        assert!(public_line(&info).is_err());
        info.public_key = Some("ssh-ed25519 not-base64".into());
        assert!(public_line(&info).is_err());
    }

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    fn key_info() -> KeyInfo {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.pub");
        std::fs::write(&path, format!("{KEY} alice@laptop\n")).unwrap();
        sshkm_core::keys::inspect(&path).unwrap()
    }

    #[cfg(unix)]
    mod script {
        use std::fs;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use std::path::Path;
        use std::process::{Command, Stdio};

        use super::super::{INSTALL_SCRIPT, READ_SCRIPT, REMOVE_SCRIPT, Read, split_read};
        use super::KEY;

        /// Runs the script the way a login shell would: `<shell> -c "sh -c '…'"`.
        fn install(shell: &str, home: &Path, key: &str) -> (bool, String) {
            remote(shell, home, &format!("sh -c '{INSTALL_SCRIPT}'"), key)
        }

        fn remove(home: &Path, blob: &str) -> (bool, String) {
            remote("sh", home, &format!("sh -c '{REMOVE_SCRIPT}'"), blob)
        }

        /// Runs `command` with `<shell> -c`, with `input` and a newline on stdin.
        fn remote(shell: &str, home: &Path, command: &str, input: &str) -> (bool, String) {
            let mut child = Command::new(shell)
                .arg("-c")
                .arg(command)
                .env("HOME", home)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(format!("{input}\n").as_bytes())
                .unwrap();
            let output = child.wait_with_output().unwrap();
            (
                output.status.success(),
                String::from_utf8_lossy(&output.stdout).trim().to_owned(),
            )
        }

        fn blob() -> &'static str {
            &KEY[12..]
        }

        #[test]
        fn removes_every_line_with_the_key() {
            let home = tempfile::tempdir().unwrap();
            let dir = home.path().join(".ssh");
            fs::create_dir(&dir).unwrap();
            let file = dir.join("authorized_keys");
            let other = format!("ssh-ed25519 {}AAAA bob", blob());
            fs::write(
                &file,
                format!("# {KEY} old laptop\nfrom=\"10.0.0.0/8\" {KEY} alice\n{other}\n  {KEY}\n"),
            )
            .unwrap();
            fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();

            assert_eq!(remove(home.path(), blob()), (true, "sshkm:removed".into()));
            assert_eq!(
                fs::read_to_string(&file).unwrap(),
                format!("# {KEY} old laptop\n{other}\n")
            );
            assert_eq!(mode(&file), 0o644);
            // No temporary file is left behind.
            assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);

            assert_eq!(remove(home.path(), blob()), (true, "sshkm:absent".into()));
        }

        #[test]
        fn nothing_to_remove() {
            let home = tempfile::tempdir().unwrap();
            assert_eq!(remove(home.path(), blob()), (true, "sshkm:absent".into()));
            assert!(!home.path().join(".ssh").exists());
            assert!(!remove(home.path(), "").0);
        }

        #[test]
        fn removes_behind_a_symbolic_link() {
            let home = tempfile::tempdir().unwrap();
            let dir = home.path().join(".ssh");
            fs::create_dir(&dir).unwrap();
            let target = home.path().join("keys");
            fs::write(&target, format!("{KEY} alice\nssh-rsa AAAA bob\n")).unwrap();
            std::os::unix::fs::symlink(&target, dir.join("authorized_keys")).unwrap();

            assert_eq!(remove(home.path(), blob()), (true, "sshkm:removed".into()));
            assert!(
                fs::symlink_metadata(dir.join("authorized_keys"))
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(fs::read_to_string(&target).unwrap(), "ssh-rsa AAAA bob\n");
        }

        #[test]
        fn reads_after_a_change_in_any_login_shell() {
            for shell in [
                "sh",
                "/bin/bash",
                "/bin/zsh",
                "/bin/csh",
                "/bin/tcsh",
                "/bin/dash",
            ] {
                if shell.starts_with('/') && !Path::new(shell).exists() {
                    continue;
                }
                let home = tempfile::tempdir().unwrap();
                let read = format!("sh -c '{READ_SCRIPT}'");
                let (ok, printed) = remote(shell, home.path(), &read, "");
                assert!(ok, "{shell}");
                assert_eq!(split_read(&printed), ("", Read::NoFile), "{shell}");

                let add = format!("sh -c '{INSTALL_SCRIPT}'; {read}");
                let (ok, printed) = remote(shell, home.path(), &add, &format!("{KEY} alice"));
                assert!(ok, "{shell}");
                let printed = format!("{printed}\n");
                assert_eq!(
                    split_read(&printed),
                    ("sshkm:added\n", Read::File(&format!("{KEY} alice\n"))),
                    "{shell}"
                );

                let drop = format!("sh -c '{REMOVE_SCRIPT}'; {read}");
                let (ok, printed) = remote(shell, home.path(), &drop, blob());
                assert!(ok, "{shell}");
                let printed = format!("{printed}\n");
                assert_eq!(
                    split_read(&printed),
                    ("sshkm:removed\n", Read::File("")),
                    "{shell}"
                );
            }
        }

        fn mode(path: &Path) -> u32 {
            fs::metadata(path).unwrap().permissions().mode() & 0o777
        }

        #[test]
        fn creates_appends_and_skips_duplicates() {
            let home = tempfile::tempdir().unwrap();
            let file = home.path().join(".ssh/authorized_keys");

            assert_eq!(
                install("sh", home.path(), &format!("{KEY} alice@laptop")),
                (true, "sshkm:added".into())
            );
            assert_eq!(mode(&home.path().join(".ssh")), 0o700);
            assert_eq!(mode(&file), 0o600);
            assert_eq!(
                fs::read_to_string(&file).unwrap(),
                format!("{KEY} alice@laptop\n")
            );

            // The same key with another comment is already there.
            assert_eq!(
                install("sh", home.path(), &format!("{KEY} other comment *")),
                (true, "sshkm:present".into())
            );
            assert_eq!(
                fs::read_to_string(&file).unwrap(),
                format!("{KEY} alice@laptop\n")
            );
        }

        #[test]
        fn keeps_existing_lines_and_modes() {
            let home = tempfile::tempdir().unwrap();
            let dir = home.path().join(".ssh");
            fs::create_dir(&dir).unwrap();
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
            let file = dir.join("authorized_keys");
            // An option-prefixed line with a key whose blob contains ours as
            // a prefix, and no final newline.
            let other = format!("from=\"10.0.0.0/8\" {KEY}AAAA bob");
            fs::write(&file, &other).unwrap();
            fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();

            assert_eq!(
                install("sh", home.path(), &format!("{KEY} alice")),
                (true, "sshkm:added".into())
            );
            assert_eq!(
                fs::read_to_string(&file).unwrap(),
                format!("{other}\n{KEY} alice\n")
            );
            assert_eq!(mode(&dir), 0o755);
            assert_eq!(mode(&file), 0o644);
        }

        #[test]
        fn passes_through_other_login_shells() {
            for shell in [
                "/bin/bash",
                "/bin/zsh",
                "/bin/csh",
                "/bin/tcsh",
                "/bin/dash",
            ] {
                if !Path::new(shell).exists() {
                    continue;
                }
                let home = tempfile::tempdir().unwrap();
                assert_eq!(
                    install(shell, home.path(), &format!("{KEY} alice")),
                    (true, "sshkm:added".into()),
                    "{shell}"
                );
            }
        }

        #[test]
        fn rejects_garbage() {
            let home = tempfile::tempdir().unwrap();
            assert!(!install("sh", home.path(), "").0);
            assert!(!install("sh", home.path(), "ssh-ed25519").0);
            assert!(!home.path().join(".ssh").exists());
        }
    }
}
