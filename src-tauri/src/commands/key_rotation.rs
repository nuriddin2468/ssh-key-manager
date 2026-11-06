//! Rotating a key: checking that a host lets the user in with one key in
//! particular, before the old key is taken off it.
//!
//! `ssh` tries key after key until one works, so a sign-in that works does
//! not say which key did it: the old key, still named in the config or held
//! by the agent, would pass for the new one. `ssh -v` logs the key the
//! server accepted. The log goes to a private file (`-E`), apart from what
//! servers and jump hosts print; only the server itself, which is told the
//! new key anyway, could fake a line of it, and that only about itself.

use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rand_core::{OsRng, RngCore};
use serde::Serialize;
use tauri::{AppHandle, State};

use super::keys::{find_key, private_path};
use super::remote::{COMMAND_ONLY, check_alias, combined, run_ssh, with_timeout_note};
use super::vault_hosts::saved_secrets;
use super::{Shared, blocking};
use crate::askpass::{AskedPrompt, Secrets};
use crate::error::{AppError, AppResult};
use crate::process::Output;
use crate::state::AppState;

/// Whether a host let the user in with one key.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct KeyLoginCheck {
    /// Signed in with the key.
    pub ok: bool,
    /// Signed in, but with another key: the server turned this one down, or
    /// `ssh` could not use it.
    pub other_key: bool,
    /// What `ssh` printed, without its debug log.
    pub output: String,
    /// As in [`crate::types::ConnectionTest`].
    pub prompts: Vec<AskedPrompt>,
}

/// Signs in to `alias` offering the key `key_id` first, with password and
/// keyboard-interactive logins off, and says whether that key let the user
/// in. A key with a passphrase must be in the agent.
#[tauri::command]
pub async fn check_key_login(
    state: State<'_, Shared>,
    alias: String,
    key_id: String,
) -> AppResult<KeyLoginCheck> {
    blocking(&state, move |state| {
        key_login(state, &alias, &key_id, Secrets::default())
    })
    .await
}

/// [`check_key_login`], with the key passphrases saved in the vault.
#[tauri::command]
pub async fn vault_check_key_login(
    app: AppHandle,
    state: State<'_, Shared>,
    alias: String,
    key_id: String,
) -> AppResult<KeyLoginCheck> {
    blocking(&state, move |state| {
        check_alias(&alias)?;
        let passphrases = saved_secrets(state, &app, &alias)?.without_login_secrets();
        key_login(state, &alias, &key_id, passphrases)
    })
    .await
}

fn key_login(
    state: &AppState,
    alias: &str,
    key_id: &str,
    secrets: Secrets,
) -> AppResult<KeyLoginCheck> {
    check_alias(alias)?;
    let key = find_key(state, key_id)?;
    let path = private_path(&key)?;
    let fingerprint = key
        .fingerprint
        .clone()
        .ok_or_else(|| AppError::invalid(format!("{} has no fingerprint", key.name)))?;
    let log = LogFile::create()?;
    let log_path = log.0.to_string_lossy().into_owned();
    // `ssh` expands `%` tokens in an identity path.
    let identity = path.to_string_lossy().replace('%', "%%");
    let mut options = vec![
        "-v",
        "-E",
        &log_path,
        "-o",
        "PubkeyAuthentication=yes",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "IdentitiesOnly=yes",
        "-i",
        &identity,
    ];
    options.extend_from_slice(COMMAND_ONLY);
    let run = run_ssh(
        state,
        alias,
        &options,
        &["exit"],
        secrets,
        None,
        Duration::from_secs(30),
    )?;
    Ok(check(
        &run.output,
        &log.read(),
        &path,
        &fingerprint,
        run.prompts,
    ))
}

/// What a run says about the key at `path` with `fingerprint`.
fn check(
    output: &Output,
    log: &str,
    path: &Path,
    fingerprint: &str,
    prompts: Vec<AskedPrompt>,
) -> KeyLoginCheck {
    // As `test_connection`: 255 is `ssh`'s own failure, any other code the
    // remote command's (git services refuse `exit` after a good sign-in).
    let signed_in = output.code.is_some_and(|code| code != 255);
    let path = path.to_string_lossy();
    let with_key =
        signed_in && signing_key(log).is_some_and(|line| names(line, &path, fingerprint));
    let printed = combined(output)
        .lines()
        .chain(log.lines())
        .map(str::trim_end)
        .filter(|line| !line.is_empty() && debug_message(line).is_none())
        .collect::<Vec<_>>()
        .join("\n");
    KeyLoginCheck {
        ok: with_key,
        other_key: signed_in && !with_key,
        output: with_timeout_note(printed, output),
        prompts,
    }
}

/// `debug1: Server accepts key: …` → `Server accepts key: …`.
fn debug_message(line: &str) -> Option<&str> {
    let rest = line.trim_end().strip_prefix("debug")?;
    let rest = rest.trim_start_matches(|c: char| c.is_ascii_digit());
    rest.strip_prefix(": ")
}

/// How `ssh -v` names the key that signed in: the last key the server
/// accepted, or the last one `ssh` signed with without asking the server
/// first (a key file with no `.pub` beside it), whichever came later. Before
/// OpenSSH 8.?, "Server accepts key" names only the algorithm; the key
/// offered just before it is the one.
fn signing_key(log: &str) -> Option<&str> {
    let mut offered = None;
    let mut last = None;
    for message in log.lines().filter_map(debug_message) {
        if let Some(key) = message.strip_prefix("Offering public key: ") {
            offered = Some(key);
        } else if let Some(key) = message.strip_prefix("Server accepts key: ") {
            last = if key.starts_with("pkalg ") {
                offered
            } else {
                Some(key)
            };
        } else if let Some(key) = message.strip_prefix("Trying private key: ") {
            last = Some(key);
        }
    }
    last
}

/// Whether a key as `ssh -v` describes it is the key at `path` with
/// `fingerprint`: `<path> ED25519 SHA256:… explicit` (OpenSSH 8 and later),
/// `ED25519 SHA256:… <path>` (OpenSSH 7), or the path alone.
fn names(described: &str, path: &str, fingerprint: &str) -> bool {
    let described = described.trim();
    described.split_whitespace().any(|word| word == fingerprint)
        || described == path
        || described.starts_with(&format!("{path} "))
        || described.ends_with(&format!(" {path}"))
}

/// A new, empty file only the user can read, for `ssh -E`; removed once
/// dropped.
struct LogFile(PathBuf);

impl LogFile {
    fn create() -> AppResult<Self> {
        let dir = std::env::temp_dir();
        loop {
            let path = dir.join(format!("sshkm-ssh-{:016x}.log", OsRng.next_u64()));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            match options.open(&path) {
                Ok(_) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
    }

    fn read(&self) -> String {
        fs::read(&self.0)
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default()
    }
}

impl Drop for LogFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATH: &str = "/home/dev/.ssh/id_ed25519_2026";
    const NEW: &str = "SHA256:NewNewNewNewNewNewNewNewNewNewNewNewNewNewN";
    const OLD: &str = "SHA256:OldOldOldOldOldOldOldOldOldOldOldOldOldOldO";

    fn output(code: Option<i32>, stderr: &str) -> Output {
        Output {
            success: code == Some(0),
            code,
            stdout: String::new(),
            stderr: stderr.to_owned(),
            timed_out: code.is_none(),
        }
    }

    fn run(code: Option<i32>, stderr: &str, log: &str) -> KeyLoginCheck {
        check(&output(code, stderr), log, Path::new(PATH), NEW, Vec::new())
    }

    #[test]
    fn signed_in_with_the_new_key() {
        let log = format!(
            "debug1: Reading configuration data /home/dev/.ssh/config\r\n\
             debug1: Offering public key: {PATH} ED25519 {NEW} explicit\r\n\
             debug1: Server accepts key: {PATH} ED25519 {NEW} explicit\r\n\
             Authenticated to backup.example ([10.0.0.5]:22) using \"publickey\".\r\n"
        );
        let checked = run(Some(0), "", &log);
        assert!(checked.ok);
        assert!(!checked.other_key);
        // The debug log stays out of what the user reads.
        assert_eq!(
            checked.output,
            "Authenticated to backup.example ([10.0.0.5]:22) using \"publickey\"."
        );
    }

    #[test]
    fn the_old_key_does_not_pass_for_the_new_one() {
        let log = format!(
            "debug1: Offering public key: {PATH} ED25519 {NEW} explicit\n\
             debug1: Authentications that can continue: publickey\n\
             debug1: Offering public key: /home/dev/.ssh/id_rsa RSA {OLD}\n\
             debug1: Server accepts key: /home/dev/.ssh/id_rsa RSA {OLD}\n"
        );
        let checked = run(Some(0), "", &log);
        assert!(!checked.ok);
        assert!(checked.other_key);
    }

    #[test]
    fn a_key_accepted_but_not_usable_is_not_the_one() {
        // The server takes the new key, the agent then refuses to sign with
        // it, and the old key gets in.
        let log = format!(
            "debug1: Server accepts key: {PATH} ED25519 {NEW} explicit agent\n\
             debug1: Offering public key: /home/dev/.ssh/id_rsa RSA {OLD}\n\
             debug1: Server accepts key: /home/dev/.ssh/id_rsa RSA {OLD}\n"
        );
        assert!(run(Some(0), "", &log).other_key);
    }

    #[test]
    fn reads_openssh_7_logs() {
        let log = format!(
            "debug1: Offering public key: ED25519 {NEW} {PATH}\n\
             debug1: Server accepts key: pkalg ssh-ed25519 blen 51\n"
        );
        assert!(run(Some(0), "", &log).ok);
        let old = format!(
            "debug1: Offering public key: ED25519 {NEW} {PATH}\n\
             debug1: Offering public key: RSA {OLD} /home/dev/.ssh/id_rsa\n\
             debug1: Server accepts key: pkalg rsa-sha2-512 blen 279\n"
        );
        assert!(run(Some(0), "", &old).other_key);
    }

    #[test]
    fn a_key_signed_with_at_once_counts_by_its_path() {
        let log = format!("debug1: Trying private key: {PATH}\n");
        assert!(run(Some(0), "", &log).ok);
        // The old key after it.
        let log = format!(
            "debug1: Trying private key: {PATH}\n\
             debug1: Server accepts key: /home/dev/.ssh/id_rsa RSA {OLD}\n"
        );
        assert!(run(Some(0), "", &log).other_key);
    }

    #[test]
    fn a_git_service_refusing_the_shell_still_signed_in() {
        let log = format!("debug1: Server accepts key: {PATH} ED25519 {NEW} explicit\n");
        let checked = run(
            Some(1),
            "Hi dev! You've successfully authenticated, but GitHub does not provide shell access.",
            &log,
        );
        assert!(checked.ok);
    }

    #[test]
    fn a_failure_keeps_what_ssh_said() {
        let log = format!(
            "debug1: Offering public key: {PATH} ED25519 {NEW} explicit\r\n\
             debug1: Authentications that can continue: publickey\r\n\
             pi@192.168.1.40: Permission denied (publickey).\r\n"
        );
        let checked = run(Some(255), "debug1: from a jump host\n", &log);
        assert!(!checked.ok);
        assert!(!checked.other_key);
        assert_eq!(
            checked.output,
            "pi@192.168.1.40: Permission denied (publickey)."
        );
        let timed_out = run(None, "", "");
        assert!(!timed_out.ok && !timed_out.other_key);
        assert_eq!(timed_out.output, "(timed out)");
    }

    #[test]
    fn a_line_printed_outside_the_log_proves_nothing() {
        // A banner (or a jump host) printing what looks like the log.
        let banner = format!("debug1: Server accepts key: {PATH} ED25519 {NEW} explicit\n");
        let log = format!("debug1: Server accepts key: /home/dev/.ssh/id_rsa RSA {OLD}\n");
        assert!(run(Some(0), &banner, &log).other_key);
    }

    #[test]
    fn names_a_key_by_fingerprint_or_path() {
        assert!(names(&format!("{PATH} ED25519 {NEW} explicit"), PATH, NEW));
        assert!(names(&format!("ED25519 {NEW} {PATH}"), PATH, NEW));
        assert!(names(PATH, PATH, NEW));
        // Another hash (`FingerprintHash md5`): the path still tells.
        assert!(names(&format!("{PATH} ED25519 MD5:aa:bb"), PATH, NEW));
        assert!(!names(&format!("{PATH}_old ED25519 {OLD}"), PATH, NEW));
        assert!(!names("/home/dev/.ssh/id_rsa RSA SHA256:x", PATH, NEW));
        let spaced = "/home/my files/.ssh/key";
        assert!(names(&format!("{spaced} ED25519 SHA256:y"), spaced, NEW));
    }

    #[test]
    fn debug_lines_are_told_apart() {
        assert_eq!(debug_message("debug1: hello"), Some("hello"));
        assert_eq!(debug_message("debug3: hello\r"), Some("hello"));
        assert_eq!(debug_message("debugging: no"), None);
        assert_eq!(debug_message("Permission denied"), None);
    }

    #[test]
    fn log_files_are_private_and_removed() {
        let log = LogFile::create().unwrap();
        let path = log.0.clone();
        fs::write(&path, "debug1: x\n").unwrap();
        assert_eq!(log.read(), "debug1: x\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        drop(log);
        assert!(!path.exists());
    }
}
