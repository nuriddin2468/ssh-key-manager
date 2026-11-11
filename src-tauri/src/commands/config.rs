use std::fmt::Write as _;
use std::fs;
use std::time::Duration;

use sshkm_core::config::{HostEdit, Risk, RiskyDirective, SshConfig, validate_text};
use sshkm_core::paths::display_path;
use sshkm_core::{ErrorCode, SecretString, diagnose, fsutil, keys};
use tauri::{AppHandle, State};

use super::keys::{find_key, private_path};
use super::remote::{SshRun, check_alias, combined, run_ssh, with_timeout_note};
use super::{Shared, blocking};
use crate::askpass::Secrets;
use crate::confirm::{self, Localized};
use crate::error::AppResult;
use crate::history::HostHistory;
use crate::state::AppState;
use crate::types::{ConfigFile, ConnectionTest, SavedHost};

/// Directives listed in the confirmation; the rest are counted.
const SHOWN_DIRECTIVES: usize = 8;
/// Characters of a value shown in the confirmation; the rest are counted.
const SHOWN_CHARS: usize = 300;

/// A test runs `ssh -v`, so a failure can say which keys were offered (see
/// [`diagnose`]). The output it shows leaves out what `-v` adds, the
/// server's pre-login banner among it (see [`diagnose::readable`]).
const CHECK: &[&str] = &[super::diagnose::VERBOSE];

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
        // A renamed host moves in the projects that hold it.
        if let (Some(old), Some(new)) = (edit.id.and_then(|id| before.host(id)), config.host(id)) {
            let renames =
                super::projects::block_renames(&before.hosts(), &config.hosts(), &old, &new);
            super::projects::follow_host_renames(&app, state, renames);
        }
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
/// current file need the user's approval in a native dialog. Text with a
/// control character other than a tab or a line's final carriage return
/// fails with `invalid_input`: `ssh` may read such a line differently from
/// the app.
#[tauri::command]
pub async fn write_config_raw(
    app: AppHandle,
    state: State<'_, Shared>,
    text: String,
) -> AppResult<ConfigFile> {
    blocking(&state, move |state| {
        validate_text(&text)?;
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
        // Renamed hosts move in the projects that hold them, as far as the
        // two texts tell (see `file_renames`).
        let renames =
            super::projects::file_renames(&before.hosts(), &SshConfig::parse(&text).hosts());
        super::projects::follow_host_renames(&app, state, renames);
        config_file(state)
    })
    .await
}

/// Runs `ssh` against a host alias, so the user sees whether the key, host key
/// and network all work.
///
/// The app answers `ssh`'s password and one-time-code prompts with `password`
/// and `otp` through askpass, and the passphrase prompt of the key `key_id`
/// with `passphrase`; without them only keys `ssh` can open by itself get in
/// and nothing is answered. Either way `prompts` tells what was asked: a
/// password asked again was rejected, a code asked with none given is
/// missing, a passphrase asked with none given is a key `ssh` could not open,
/// a declined host-key question means the host key is not trusted yet.
///
/// A `passphrase` that does not open the key fails with `wrong_passphrase`
/// before `ssh` runs.
#[tauri::command]
pub async fn test_connection(
    state: State<'_, Shared>,
    alias: String,
    password: Option<SecretString>,
    otp: Option<SecretString>,
    key_id: Option<String>,
    passphrase: Option<SecretString>,
) -> AppResult<ConnectionTest> {
    blocking(&state, move |state| {
        let secrets =
            with_typed_passphrase(state, Secrets::new(password, otp), key_id, passphrase)?;
        connection_test(state, &alias, secrets)
    })
    .await
}

/// `secrets` and the passphrase the user typed for the key `key_id`, once it
/// is known to open the key. An encrypted key the app cannot open itself (a
/// legacy PEM one) is left for `ssh` to try.
pub fn with_typed_passphrase(
    state: &AppState,
    secrets: Secrets,
    key_id: Option<String>,
    passphrase: Option<SecretString>,
) -> AppResult<Secrets> {
    let (Some(key_id), Some(passphrase)) = (key_id, passphrase) else {
        return Ok(secrets);
    };
    let path = private_path(&find_key(state, &key_id)?)?;
    match keys::load_private(&path, Some(&passphrase)) {
        Ok(_) => {}
        Err(error) if error.code() == ErrorCode::Unsupported => {}
        Err(error) => return Err(error.into()),
    }
    Ok(secrets.with_passphrase(path, passphrase))
}

/// [`test_connection`] with the secrets already gathered.
pub fn connection_test(
    state: &AppState,
    alias: &str,
    secrets: Secrets,
) -> AppResult<ConnectionTest> {
    check_alias(alias)?;
    let timeout = Duration::from_secs(if secrets.is_empty() { 20 } else { 30 });
    let run = run_ssh(state, alias, CHECK, &["exit"], secrets, None, timeout)?;
    let checked = checked(alias, &run, signed_in(run.output.code));
    // The check ran either way; a history that cannot be written only misses it.
    let _ = state.history.record_check(alias, &checked);
    Ok(checked)
}

/// A check's result from its run of `ssh -v`: what the user reads, and why
/// it failed if it did.
pub fn checked(alias: &str, run: &SshRun, ok: bool) -> ConnectionTest {
    let text = combined(&run.output);
    ConnectionTest {
        ok,
        output: with_timeout_note(diagnose::readable(&text), &run.output),
        prompts: run.prompts.clone(),
        diagnosis: (!ok).then(|| super::diagnose::diagnosis(alias, &text, run.output.timed_out)),
    }
}

/// What became of each host's checks and in-app terminal sessions, newest
/// first.
#[tauri::command]
pub async fn connection_history(state: State<'_, Shared>) -> AppResult<HostHistory> {
    blocking(&state, |state| Ok(state.history.all())).await
}

#[tauri::command]
pub async fn clear_connection_history(state: State<'_, Shared>, alias: String) -> AppResult<()> {
    blocking(&state, move |state| state.history.clear(&alias)).await
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
pub(crate) fn load_at(state: &AppState, revision: &str) -> AppResult<SshConfig> {
    let config = SshConfig::load(&state.paths.config)?;
    fsutil::ensure_revision(&state.paths.config, &config.revision(), revision)?;
    Ok(config)
}

/// Asks the user to approve, in a native dialog the page cannot click, the
/// directives that run or load code, give a server access to this computer,
/// say which server gets it, or check servers less strictly, which `after`
/// adds to `before` (see [`Risk`]). Returns whether it asked (the file may
/// have changed meanwhile); fails with `cancelled` if the user said no.
pub(crate) fn confirm_added(
    app: &AppHandle,
    state: &AppState,
    after: &SshConfig,
    before: &SshConfig,
) -> AppResult<bool> {
    let added = after.added_risky_directives(before);
    let Some(worst) = Risk::ALL
        .into_iter()
        .find(|risk| added.iter().any(|d| d.risk == *risk))
    else {
        return Ok(false);
    };
    let file = display_path(&state.paths.config);
    let en = directive_list(
        &added,
        "all hosts",
        |risk| heading(risk).en,
        |n| format!("…and {n} more"),
    );
    let ru = directive_list(
        &added,
        "все хосты",
        |risk| heading(risk).ru,
        |n| format!("…и ещё {n}"),
    );
    let uz = directive_list(
        &added,
        "barcha xostlar",
        |risk| heading(risk).uz,
        |n| format!("…va yana {n} ta"),
    );
    confirm::require(
        app,
        &title(worst),
        &Localized::new(
            format!(
                "This change to {file} takes effect each time you connect.\n\n{en}\n\n\
                 Allow it only if you made this change yourself."
            ),
            format!(
                "Это изменение в {file} действует при каждом подключении.\n\n{ru}\n\n\
                 Разрешайте, только если это изменение сделали вы сами."
            ),
            format!(
                "{file} dagi bu oʻzgarish har safar ulanganda amal qiladi.\n\n{uz}\n\n\
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

/// The confirmation's title, for the worst kind of directive in it.
fn title(risk: Risk) -> Localized {
    match risk {
        Risk::RunsCode => Localized::new(
            "Allow ssh to run this?",
            "Разрешить ssh запускать это?",
            "ssh buni ishga tushirsinmi?",
        ),
        Risk::ServerAccess | Risk::Destination => Localized::new(
            "Give a server access to this computer?",
            "Дать серверу доступ к этому компьютеру?",
            "Serverga bu kompyuterdan foydalanishga ruxsat berilsinmi?",
        ),
        Risk::HostKeys => Localized::new(
            "Check servers less strictly?",
            "Проверять серверы менее строго?",
            "Serverlar kamroq qatʼiy tekshirilsinmi?",
        ),
    }
}

/// What directives of one kind do, above their list in the confirmation.
fn heading(risk: Risk) -> Localized {
    match risk {
        Risk::RunsCode => Localized::new(
            "ssh runs programs or loads code:",
            "ssh запускает программы или загружает код:",
            "ssh dasturlarni ishga tushiradi yoki kod yuklaydi:",
        ),
        Risk::ServerAccess => Localized::new(
            "The server can use this computer:",
            "Сервер может пользоваться этим компьютером:",
            "Server bu kompyuterdan foydalana oladi:",
        ),
        Risk::Destination => Localized::new(
            "The server that gets access to this computer:",
            "Сервер, который получает доступ к этому компьютеру:",
            "Bu kompyuterdan foydalana oladigan server:",
        ),
        Risk::HostKeys => Localized::new(
            "ssh checks less strictly that the server is genuine:",
            "ssh менее строго проверяет подлинность сервера:",
            "ssh server haqiqiyligini kamroq qatʼiy tekshiradi:",
        ),
    }
}

/// The directives by kind ([`Risk::ALL`] order), each kind under its
/// `heading`, with one line per directive (`• Host prod: ProxyCommand …`)
/// and at most [`SHOWN_DIRECTIVES`] of them. `everywhere` names the hosts of
/// directives before the first block; `more` says how many were left out.
fn directive_list(
    added: &[RiskyDirective],
    everywhere: &str,
    heading: impl Fn(Risk) -> String,
    more: impl Fn(usize) -> String,
) -> String {
    let mut sections = Vec::new();
    for risk in Risk::ALL {
        let of_kind: Vec<&RiskyDirective> = added.iter().filter(|d| d.risk == risk).collect();
        if of_kind.is_empty() {
            continue;
        }
        let mut lines = vec![heading(risk)];
        lines.extend(of_kind.iter().take(SHOWN_DIRECTIVES).map(|d| {
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
        }));
        if of_kind.len() > SHOWN_DIRECTIVES {
            lines.push(more(of_kind.len() - SHOWN_DIRECTIVES));
        }
        sections.push(lines.join("\n"));
    }
    sections.join("\n\n")
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
            risk: Risk::RunsCode,
        }
    }

    fn en(risk: Risk) -> String {
        heading(risk).en
    }

    #[test]
    fn lists_directives_for_the_dialog() {
        let added = [
            directive(None, "Include", "~/.ssh/extra"),
            directive(Some("Host prod"), "ProxyCommand", "ssh -W %h:%p jump"),
            directive(Some("Match exec \"true\""), "Match", "exec \"true\""),
        ];
        assert_eq!(
            directive_list(&added, "all hosts", en, |n| format!("+{n}")),
            "ssh runs programs or loads code:\n\
             • all hosts: Include ~/.ssh/extra\n\
             • Host prod: ProxyCommand ssh -W %h:%p jump\n\
             • Match exec \"true\""
        );
        let many: Vec<_> = (0..11)
            .map(|i| directive(Some("Host x"), "LocalCommand", &format!("run {i}")))
            .collect();
        let list = directive_list(&many, "all hosts", en, |n| format!("…and {n} more"));
        assert_eq!(list.lines().count(), SHOWN_DIRECTIVES + 2);
        assert!(list.ends_with("…and 3 more"), "{list}");
    }

    #[test]
    fn groups_directives_by_what_they_let_happen() {
        let config = SshConfig::parse(
            "Host work\n  HostName evil.example\n  ForwardAgent yes\n  \
             StrictHostKeyChecking no\n  LocalCommand \"none\"\n",
        );
        let added = config.added_risky_directives(&SshConfig::default());
        assert_eq!(
            directive_list(&added, "all hosts", en, |n| format!("+{n}")),
            "ssh runs programs or loads code:\n\
             • Host work: LocalCommand \"none\"\n\
             \n\
             The server can use this computer:\n\
             • Host work: ForwardAgent yes\n\
             \n\
             The server that gets access to this computer:\n\
             • Host work: HostName evil.example\n\
             \n\
             ssh checks less strictly that the server is genuine:\n\
             • Host work: StrictHostKeyChecking no"
        );
        // Every kind is worded in every language.
        for risk in Risk::ALL {
            for text in [heading(risk), title(risk)] {
                assert!(
                    [&text.en, &text.ru, &text.uz].iter().all(|t| !t.is_empty()),
                    "{risk:?}"
                );
            }
        }
        // A line `ssh` may read otherwise is shown whole, control
        // characters visible.
        let odd = SshConfig::parse("Host *\n  HostName foo\r#$(id)\n");
        let added = odd.added_risky_directives(&SshConfig::default());
        assert_eq!(
            directive_list(&added, "all hosts", en, |n| format!("+{n}")),
            "ssh runs programs or loads code:\n• Host *: HostName foo<U+000D>#$(id)"
        );
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
            ErrorCode::Conflict
        );
        let read = config_file(&state).unwrap();
        assert_eq!(
            load_at(&state, &read.view.revision).unwrap().hosts().len(),
            2
        );
    }

    #[test]
    fn a_typed_passphrase_must_open_the_key() {
        let home = tempfile::tempdir().unwrap();
        let ssh = home.path().join(".ssh");
        fsutil::ensure_private_dir(&ssh).unwrap();
        let state = AppState::new(
            sshkm_core::paths::SshPaths::with_home(home.path(), &ssh),
            home.path().join("hosts"),
            home.path().join("backups"),
            home.path().join("data"),
        );
        let key = keys::generate(
            &ssh,
            &keys::GenerateRequest {
                algorithm: keys::GenerateAlgorithm::Ed25519,
                file_name: "id_work".into(),
                comment: String::new(),
                passphrase: Some("right".into()),
            },
        )
        .unwrap();
        let typed = |passphrase: &str| {
            with_typed_passphrase(
                &state,
                Secrets::default(),
                Some(key.id.clone()),
                Some(passphrase.into()),
            )
        };

        assert_eq!(
            typed("wrong").unwrap_err().code(),
            ErrorCode::WrongPassphrase
        );
        let secrets = typed("right").unwrap();
        assert_eq!(secrets.passphrases.len(), 1);
        assert_eq!(secrets.passphrases[0].0, ssh.join("id_work"));
        // Nothing typed: nothing added.
        let none = with_typed_passphrase(&state, Secrets::default(), None, None).unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn connection_test_trusts_the_exit_code_only() {
        assert_eq!(CHECK, ["-v"]);
        assert!(signed_in(Some(0)));
        // GitHub: "successfully authenticated, but … no shell access".
        assert!(signed_in(Some(1)));
        assert!(!signed_in(Some(255)));
        // Timed out or killed.
        assert!(!signed_in(None));
    }
}
