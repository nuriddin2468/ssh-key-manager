//! Running `ssh` against a configured host, either in batch mode or with the
//! app answering its prompts (see [`crate::askpass`]).

use std::time::Duration;

use ssh_key::PublicKey;
use sshkm_core::SecretString;
use sshkm_core::keys::KeyInfo;
use tauri::State;

use super::keys::find_key;
use super::{Shared, blocking};
use crate::askpass::{AskedPrompt, Connection, PromptAccount, Secrets};
use crate::error::{AppError, AppResult};
use crate::process::{self, Output};
use crate::state::AppState;
use crate::types::KeyInstall;

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
        &[
            // Only the command: no forwarding, no tty, no configured
            // RemoteCommand in the way.
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
        ],
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
    fn install_script_survives_any_login_shell() {
        assert!(!INSTALL_SCRIPT.contains('\''));
        assert!(!INSTALL_SCRIPT.contains('!'));
        assert!(!INSTALL_SCRIPT.contains('\n'));
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

        use super::super::INSTALL_SCRIPT;
        use super::KEY;

        /// Runs the script the way a login shell would: `<shell> -c "sh -c '…'"`.
        fn install(shell: &str, home: &Path, key: &str) -> (bool, String) {
            let mut child = Command::new(shell)
                .arg("-c")
                .arg(format!("sh -c '{INSTALL_SCRIPT}'"))
                .env("HOME", home)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(format!("{key}\n").as_bytes())
                .unwrap();
            let output = child.wait_with_output().unwrap();
            (
                output.status.success(),
                String::from_utf8_lossy(&output.stdout).trim().to_owned(),
            )
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
