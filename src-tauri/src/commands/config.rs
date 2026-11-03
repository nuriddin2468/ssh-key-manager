use std::fmt::Write as _;
use std::fs;
use std::time::Duration;

use sshkm_core::SecretString;
use sshkm_core::config::{HostEdit, RiskyDirective, SshConfig};
use sshkm_core::fsutil;
use sshkm_core::paths::display_path;
use tauri::{AppHandle, State};

use super::remote::{check_alias, combined, run_ssh, with_timeout_note};
use super::{Shared, blocking};
use crate::askpass::Secrets;
use crate::confirm::{self, Localized};
use crate::error::AppResult;
use crate::state::AppState;
use crate::types::{ConfigFile, ConnectionTest, SavedHost};

/// Directives listed in the confirmation; the rest are counted.
const SHOWN_DIRECTIVES: usize = 8;
/// Characters of a value shown in the confirmation; the rest are counted.
const SHOWN_CHARS: usize = 300;

/// `ssh` prints a server's pre-login banner and keyboard-interactive
/// instructions only at log level `INFO` and above, so the output a test
/// shows holds what the server printed after sign-in. Errors (`Permission
/// denied`, `Host key verification failed`, …) are still printed.
const NO_BANNER: &[&str] = &["-o", "LogLevel=ERROR"];

#[tauri::command]
pub async fn read_config(state: State<'_, Shared>) -> AppResult<ConfigFile> {
    blocking(&state, config_file).await
}

/// Creates or updates a block. `revision` is [`ConfigView::revision`] of the
/// file the edit was made against; the save fails with `conflict` if the file
/// changed since. A new `ProxyCommand` or other directive that runs code
/// needs the user's approval in a native dialog.
///
/// [`ConfigView::revision`]: sshkm_core::config::ConfigView::revision
#[tauri::command]
pub async fn save_host(
    app: AppHandle,
    state: State<'_, Shared>,
    edit: HostEdit,
    revision: String,
) -> AppResult<SavedHost> {
    blocking(&state, move |state| {
        let before = load_at(state, &revision)?;
        let mut config = before.clone();
        let id = config.upsert_host(&edit)?;
        if confirm_added(&app, state, &config, &before)? {
            // The dialog may have been open for a while.
            load_at(state, &revision)?;
        }
        config.save(&state.paths.config, &state.backup_dir)?;
        Ok(SavedHost {
            file: config_file(state)?,
            id,
        })
    })
    .await
}

#[tauri::command]
pub async fn delete_host(
    state: State<'_, Shared>,
    id: u32,
    revision: String,
) -> AppResult<ConfigFile> {
    blocking(&state, move |state| {
        let mut config = load_at(state, &revision)?;
        config.delete_host(id)?;
        config.save(&state.paths.config, &state.backup_dir)?;
        config_file(state)
    })
    .await
}

#[tauri::command]
pub async fn remove_identity_file(
    state: State<'_, Shared>,
    host_id: Option<u32>,
    value: String,
    revision: String,
) -> AppResult<ConfigFile> {
    blocking(&state, move |state| {
        let mut config = load_at(state, &revision)?;
        if config.remove_identity_file(host_id, &value)? {
            config.save(&state.paths.config, &state.backup_dir)?;
        }
        config_file(state)
    })
    .await
}

#[tauri::command]
pub async fn read_config_raw(state: State<'_, Shared>) -> AppResult<String> {
    blocking(&state, |state| {
        match fs::read_to_string(&state.paths.config) {
            Ok(text) => Ok(text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(e) => Err(e.into()),
        }
    })
    .await
}

/// Replaces the whole file. Directives that run code and are not in the
/// current file need the user's approval in a native dialog.
#[tauri::command]
pub async fn write_config_raw(
    app: AppHandle,
    state: State<'_, Shared>,
    text: String,
) -> AppResult<ConfigFile> {
    blocking(&state, move |state| {
        fsutil::ensure_private_dir(&state.paths.dir)?;
        // A file that cannot be read (not UTF-8, too large) counts as empty,
        // so everything in the new text that runs code is asked about.
        let before = SshConfig::load(&state.paths.config).unwrap_or_default();
        if confirm_added(&app, state, &SshConfig::parse(&text), &before)? {
            // The dialog may have been open for a while.
            let now = SshConfig::load(&state.paths.config).unwrap_or_default();
            fsutil::ensure_revision(&state.paths.config, &now.revision(), &before.revision())?;
        }
        fsutil::backup(&state.paths.config, &state.backup_dir)?;
        fsutil::atomic_write(&state.paths.config, text.as_bytes(), 0o600)?;
        config_file(state)
    })
    .await
}

/// Runs `ssh` against a host alias, so the user sees whether the key, host key
/// and network all work.
///
/// Without `password` and `otp` it never prompts (`BatchMode=yes`). With
/// either, the app answers `ssh`'s password and one-time-code prompts with
/// them through askpass, and `prompts` tells what was asked: a password asked
/// again was rejected, a code asked with none given is missing, a declined
/// host-key question means the host key is not trusted yet.
#[tauri::command]
pub async fn test_connection(
    state: State<'_, Shared>,
    alias: String,
    password: Option<SecretString>,
    otp: Option<SecretString>,
) -> AppResult<ConnectionTest> {
    blocking(&state, move |state| {
        connection_test(state, &alias, Secrets::new(password, otp))
    })
    .await
}

/// [`test_connection`] with the secrets already gathered.
pub fn connection_test(
    state: &AppState,
    alias: &str,
    secrets: Secrets,
) -> AppResult<ConnectionTest> {
    check_alias(alias)?;
    let timeout = Duration::from_secs(if secrets.is_empty() { 20 } else { 30 });
    let run = run_ssh(state, alias, NO_BANNER, &["exit"], secrets, None, timeout)?;
    let text = combined(&run.output);
    Ok(ConnectionTest {
        ok: signed_in(run.output.code),
        output: with_timeout_note(text, &run.output),
        prompts: run.prompts,
    })
}

/// `ssh` exits with 255 when it fails itself (network, host key, sign-in)
/// and otherwise with the remote command's code. Git hosts refuse shell
/// access, so `exit` fails there with another code after a good sign-in.
/// The output is not consulted: a server, or a jump host, can print anything
/// before authentication.
fn signed_in(code: Option<i32>) -> bool {
    code.is_some_and(|code| code != 255)
}

pub fn config_file(state: &AppState) -> AppResult<ConfigFile> {
    let config = SshConfig::load(&state.paths.config)?;
    Ok(ConfigFile {
        path: state.paths.config.to_string_lossy().into_owned(),
        exists: state.paths.config.exists(),
        view: config.view(),
        usage: config.identity_usage(&state.paths),
    })
}

/// The config file, if it is still at `revision`; fails with `conflict`
/// otherwise.
fn load_at(state: &AppState, revision: &str) -> AppResult<SshConfig> {
    let config = SshConfig::load(&state.paths.config)?;
    fsutil::ensure_revision(&state.paths.config, &config.revision(), revision)?;
    Ok(config)
}

/// Asks the user to approve, in a native dialog the page cannot click, the
/// directives that run or load code which `after` adds to `before`. Returns
/// whether it asked (the file may have changed meanwhile); fails with
/// `cancelled` if the user said no.
pub(crate) fn confirm_added(
    app: &AppHandle,
    state: &AppState,
    after: &SshConfig,
    before: &SshConfig,
) -> AppResult<bool> {
    let added = after.added_risky_directives(before);
    if added.is_empty() {
        return Ok(false);
    }
    let file = display_path(&state.paths.config);
    let en = directive_list(&added, "all hosts", |n| format!("…and {n} more"));
    let ru = directive_list(&added, "все хосты", |n| format!("…и ещё {n}"));
    let uz = directive_list(&added, "barcha xostlar", |n| format!("…va yana {n} ta"));
    confirm::require(
        app,
        &Localized::new(
            "Allow ssh to run this?",
            "Разрешить ssh запускать это?",
            "ssh buni ishga tushirsinmi?",
        ),
        &Localized::new(
            format!(
                "With this change to {file}, ssh runs programs, loads code or lets the server \
                 use this computer each time you connect:\n\n{en}\n\n\
                 Allow it only if you made this change yourself."
            ),
            format!(
                "После этого изменения в {file} ssh при каждом подключении запускает \
                 программы, загружает код или даёт серверу доступ к этому компьютеру:\n\n{ru}\n\n\
                 Разрешайте, только если это изменение сделали вы сами."
            ),
            format!(
                "{file} dagi bu oʻzgarishdan soʻng ssh har safar ulanganda dasturlarni ishga \
                 tushiradi, kod yuklaydi yoki serverga bu kompyuterdan foydalanishga ruxsat \
                 beradi:\n\n{uz}\n\n\
                 Faqat bu oʻzgarishni oʻzingiz qilgan boʻlsangiz, ruxsat bering."
            ),
        ),
        &Localized::new(
            "Allow and save",
            "Разрешить и сохранить",
            "Ruxsat berish va saqlash",
        ),
    )?;
    Ok(true)
}

/// One line per directive (`• Host prod: ProxyCommand …`), at most
/// [`SHOWN_DIRECTIVES`] of them. `everywhere` names the hosts of directives
/// before the first block; `more` says how many were left out.
fn directive_list(
    added: &[RiskyDirective],
    everywhere: &str,
    more: impl Fn(usize) -> String,
) -> String {
    let mut lines: Vec<String> = added
        .iter()
        .take(SHOWN_DIRECTIVES)
        .map(|d| {
            let directive = format!("{} {}", d.key, shown(&d.value));
            match &d.block {
                // `Match … exec` or an odd `Host` pattern is its own block line.
                Some(block)
                    if d.key.eq_ignore_ascii_case("match")
                        || d.key.eq_ignore_ascii_case("host") =>
                {
                    format!("• {}", shown(block))
                }
                Some(block) => format!("• {}: {directive}", shown(block)),
                None => format!("• {everywhere}: {directive}"),
            }
        })
        .collect();
    if added.len() > SHOWN_DIRECTIVES {
        lines.push(more(added.len() - SHOWN_DIRECTIVES));
    }
    lines.join("\n")
}

/// `text` as the dialog shows it: control characters and invisible or
/// direction-changing ones as `<U+…>`, so what is shown is what `ssh` runs,
/// and at most [`SHOWN_CHARS`] characters, with how many more there are.
fn shown(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (i, c) in text.chars().enumerate() {
        if i == SHOWN_CHARS {
            let rest = text.chars().count() - SHOWN_CHARS;
            let _ = write!(out, "… (+{rest})");
            break;
        }
        let invisible = matches!(
            c,
            '\u{00AD}'
                | '\u{061C}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2069}'
                | '\u{FEFF}'
        );
        if c.is_control() || invisible {
            let _ = write!(out, "<U+{:04X}>", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directive(block: Option<&str>, key: &str, value: &str) -> RiskyDirective {
        RiskyDirective {
            block: block.map(str::to_owned),
            key: key.to_owned(),
            value: value.to_owned(),
        }
    }

    #[test]
    fn lists_directives_for_the_dialog() {
        let added = [
            directive(None, "Include", "~/.ssh/extra"),
            directive(Some("Host prod"), "ProxyCommand", "ssh -W %h:%p jump"),
            directive(Some("Match exec \"true\""), "Match", "exec \"true\""),
        ];
        assert_eq!(
            directive_list(&added, "all hosts", |n| format!("+{n}")),
            "• all hosts: Include ~/.ssh/extra\n\
             • Host prod: ProxyCommand ssh -W %h:%p jump\n\
             • Match exec \"true\""
        );
        let many: Vec<_> = (0..11)
            .map(|i| directive(Some("Host x"), "LocalCommand", &format!("run {i}")))
            .collect();
        let list = directive_list(&many, "all hosts", |n| format!("…and {n} more"));
        assert_eq!(list.lines().count(), SHOWN_DIRECTIVES + 1);
        assert!(list.ends_with("…and 3 more"), "{list}");
    }

    #[test]
    fn shows_what_runs() {
        assert_eq!(shown("nc %h %p"), "nc %h %p");
        // A right-to-left override would show `curl x | sh` reversed.
        assert_eq!(
            shown("echo \u{202E}hs | x lruc"),
            "echo <U+202E>hs | x lruc"
        );
        assert_eq!(
            shown("a\tb\u{1b}[2J\u{200B}"),
            "a<U+0009>b<U+001B>[2J<U+200B>"
        );
        let long = "x".repeat(SHOWN_CHARS + 5);
        assert_eq!(shown(&long), format!("{}… (+5)", "x".repeat(SHOWN_CHARS)));
    }

    #[test]
    fn edits_name_the_revision_they_were_made_against() {
        let home = tempfile::tempdir().unwrap();
        let ssh = home.path().join(".ssh");
        let state = AppState::new(
            sshkm_core::paths::SshPaths::with_home(home.path(), &ssh),
            home.path().join("hosts"),
            home.path().join("backups"),
            home.path().join("data"),
        );
        // A missing file is empty, at the revision of no bytes.
        let read = config_file(&state).unwrap();
        load_at(&state, &read.view.revision).unwrap();
        fsutil::ensure_private_dir(&ssh).unwrap();
        fs::write(&state.paths.config, "Host a\n  User me\nHost b\n").unwrap();
        assert_eq!(
            load_at(&state, &read.view.revision).unwrap_err().code(),
            sshkm_core::ErrorCode::Conflict
        );
        let read = config_file(&state).unwrap();
        assert_eq!(
            load_at(&state, &read.view.revision).unwrap().hosts().len(),
            2
        );
    }

    #[test]
    fn connection_test_trusts_the_exit_code_only() {
        assert_eq!(NO_BANNER, ["-o", "LogLevel=ERROR"]);
        assert!(signed_in(Some(0)));
        // GitHub: "successfully authenticated, but … no shell access".
        assert!(signed_in(Some(1)));
        assert!(!signed_in(Some(255)));
        // Timed out or killed.
        assert!(!signed_in(None));
    }
}
