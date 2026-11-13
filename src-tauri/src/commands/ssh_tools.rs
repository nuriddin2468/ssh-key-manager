//! The SSH tools of the Tools page: tunnels, the ProxyJump wizard, the key
//! converter and the `authorized_keys` line builder. The work is in
//! `sshkm_core` (`tunnels`, `config`, `keys::convert`, `authorized_line`)
//! and in [`crate::tunnels`], which runs the tunnels.

use std::path::{Path, PathBuf};
use std::time::Duration;

use ssh_key::PublicKey;
use sshkm_core::SecretString;
use sshkm_core::authorized_keys;
use sshkm_core::authorized_line::{self, AuthorizedLine, LineOptions};
use sshkm_core::config::HostKind;
use sshkm_core::keys::convert::{self, KeyFileFormat, KeyFileInfo};
use sshkm_core::tunnels::Tunnel;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::DialogExt;

use super::config::{config_file, confirm_added, load_at};
use super::keys::find_view;
use super::remote::{
    ADDED, COMMAND_ONLY, PRESENT, check_alias, combined, has_line, run_ssh, with_timeout_note,
};
use super::vault_hosts::saved_secrets;
use super::{Shared, blocking};
use crate::askpass::Secrets;
use crate::confirm::Localized;
use crate::error::{AppError, AppResult};
use crate::terminal::types::PromptAnswer;
use crate::tunnels::{SharedTunnels, TunnelView};
use crate::types::{ConfigFile, KeyInstall, KeyView};

// --- Tunnels -----------------------------------------------------------------

#[tauri::command]
pub async fn tunnel_list(
    state: State<'_, Shared>,
    tunnels: State<'_, SharedTunnels>,
) -> AppResult<Vec<TunnelView>> {
    let tunnels = SharedTunnels::clone(&tunnels);
    blocking(&state, move |_| tunnels.list()).await
}

/// Adds a tunnel (an empty `id`) or changes one; one that is on starts again
/// as changed.
#[tauri::command]
pub async fn tunnel_save(
    state: State<'_, Shared>,
    tunnels: State<'_, SharedTunnels>,
    tunnel: Tunnel,
) -> AppResult<TunnelView> {
    let tunnels = SharedTunnels::clone(&tunnels);
    blocking(&state, move |_| tunnels.save(tunnel)).await
}

#[tauri::command]
pub async fn tunnel_delete(
    state: State<'_, Shared>,
    tunnels: State<'_, SharedTunnels>,
    id: String,
) -> AppResult<()> {
    let tunnels = SharedTunnels::clone(&tunnels);
    blocking(&state, move |_| tunnels.delete(&id)).await
}

#[tauri::command]
pub async fn tunnel_set_on(
    state: State<'_, Shared>,
    tunnels: State<'_, SharedTunnels>,
    id: String,
    on: bool,
) -> AppResult<TunnelView> {
    let tunnels = SharedTunnels::clone(&tunnels);
    blocking(&state, move |_| tunnels.set_on(&id, on)).await
}

/// Hands an answer to the tunnel's waiting prompt; false if it no longer
/// waits.
#[tauri::command]
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
pub fn tunnel_answer(
    tunnels: State<'_, SharedTunnels>,
    id: String,
    prompt: u32,
    answer: PromptAnswer,
) -> bool {
    tunnels.answer(&id, prompt, answer)
}

#[tauri::command]
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
pub fn tunnel_stop_all(tunnels: State<'_, SharedTunnels>) {
    tunnels.stop_all();
}

/// Writes the tunnel into its host's block of `~/.ssh/config` as a
/// `LocalForward`, `RemoteForward` or `DynamicForward` line, through the
/// config's edit path: `revision` must still be the file's, and a forward
/// that gives the server access to this computer is confirmed in a native
/// dialog. Needs a `Host` block that names the alias; a line already there
/// is left as it is.
#[tauri::command]
pub async fn tunnel_export(
    app: AppHandle,
    state: State<'_, Shared>,
    tunnels: State<'_, SharedTunnels>,
    id: String,
    revision: String,
) -> AppResult<ConfigFile> {
    let tunnels = SharedTunnels::clone(&tunnels);
    blocking(&state, move |state| {
        let view = tunnels
            .list()?
            .into_iter()
            .find(|v| v.tunnel.id == id)
            .ok_or_else(|| AppError::not_found("no such tunnel"))?;
        let (key, value) = view.tunnel.config_line();
        let before = load_at(state, &revision)?;
        let host = before
            .hosts()
            .into_iter()
            .find(|h| h.kind == HostKind::Host && h.patterns.contains(&view.tunnel.alias))
            .ok_or_else(|| {
                AppError::not_found(format!("no Host block names {}", view.tunnel.alias))
            })?;
        let present = host.options.iter().any(|o| {
            o.key.eq_ignore_ascii_case(&key)
                && o.value.split_whitespace().eq(value.split_whitespace())
        });
        if present {
            return config_file(state);
        }
        let mut edit = sshkm_core::config::HostEdit {
            id: Some(host.id),
            patterns: host.patterns.clone(),
            options: host.options.clone(),
        };
        edit.options
            .push(sshkm_core::config::HostOption::new(key, value));
        let mut config = before.clone();
        config.upsert_host(&edit)?;
        if confirm_added(&app, state, &config, &before)? {
            load_at(state, &revision)?;
        }
        config.save(&state.paths.config, &state.backup_dir)?;
        config_file(state)
    })
    .await
}

// --- ProxyJump ---------------------------------------------------------------

/// Sets `ProxyJump` to `jump` (`None`: removes it) in the blocks `targets`,
/// as an edit of the file at `revision` (`conflict` if it changed since). A
/// change that says which server gets access is confirmed in a native
/// dialog, as in the host editor.
#[tauri::command]
pub async fn set_proxy_jump(
    app: AppHandle,
    state: State<'_, Shared>,
    jump: Option<String>,
    targets: Vec<u32>,
    revision: String,
) -> AppResult<ConfigFile> {
    blocking(&state, move |state| {
        if targets.is_empty() {
            return Err(AppError::invalid("no host to change"));
        }
        let before = load_at(state, &revision)?;
        let mut config = before.clone();
        config.set_proxy_jump(&targets, jump.as_deref())?;
        if confirm_added(&app, state, &config, &before)? {
            load_at(state, &revision)?;
        }
        config.save(&state.paths.config, &state.backup_dir)?;
        config_file(state)
    })
    .await
}

// --- Key converter -----------------------------------------------------------

/// What the key file at `path` holds; with `passphrase`, an encrypted key is
/// opened too (`wrong_passphrase` if it doesn't open).
#[tauri::command]
pub async fn key_convert_inspect(
    state: State<'_, Shared>,
    path: String,
    passphrase: Option<SecretString>,
) -> AppResult<KeyFileInfo> {
    blocking(&state, move |_| {
        Ok(convert::inspect(Path::new(&path), passphrase.as_ref())?)
    })
    .await
}

/// Converts the key at `path` to the OpenSSH format and adds it to `~/.ssh`
/// as `file_name` (and `.pub`), as an import does: never over a file.
#[tauri::command]
pub async fn key_convert_import(
    state: State<'_, Shared>,
    path: String,
    passphrase: Option<SecretString>,
    file_name: String,
    new_passphrase: Option<SecretString>,
    comment: Option<String>,
) -> AppResult<KeyView> {
    blocking(&state, move |state| {
        let info = convert::import(
            &state.paths.dir,
            Path::new(&path),
            passphrase.as_ref(),
            &file_name,
            new_passphrase.as_ref(),
            comment.as_deref(),
        )?;
        find_view(state, &info.id)
    })
    .await
}

/// Converts the key at `path` to `format` and saves it where the user picks
/// in a system dialog; `None` if it was cancelled. Never over a file in
/// `~/.ssh`.
#[tauri::command]
pub async fn key_convert_save(
    app: AppHandle,
    state: State<'_, Shared>,
    path: String,
    passphrase: Option<SecretString>,
    format: KeyFileFormat,
    new_passphrase: Option<SecretString>,
    comment: Option<String>,
) -> AppResult<Option<String>> {
    blocking(&state, move |state| {
        let source = Path::new(&path);
        // Converted first, so a wrong passphrase shows no dialog.
        let text = convert::convert(
            source,
            passphrase.as_ref(),
            format,
            new_passphrase.as_ref(),
            comment.as_deref(),
        )?;
        let Some(target) = pick_target(&app, source, format)? else {
            return Ok(None);
        };
        if let Some(dir) = target.parent() {
            std::fs::create_dir_all(dir)?;
        }
        // A private file, never written through a link, never over one in
        // `~/.ssh` (compared by file identity).
        convert::save(&target, &text, &state.paths.dir)?;
        Ok(Some(target.to_string_lossy().into_owned()))
    })
    .await
}

/// The save dialog for a converted key, suggesting `<name>.ppk` and the
/// like.
fn pick_target(
    app: &AppHandle,
    source: &Path,
    format: KeyFileFormat,
) -> AppResult<Option<PathBuf>> {
    let stem = source
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("key");
    let name = match format.extension() {
        Some(extension) => format!("{stem}.{extension}"),
        None => format!("{stem}-openssh"),
    };
    let mut dialog = app
        .dialog()
        .file()
        .set_title(
            Localized::new(
                "Save the converted key",
                "Сохранить преобразованный ключ",
                "Oʻzgartirilgan kalitni saqlash",
            )
            .pick(),
        )
        .set_file_name(name);
    if let Some(parent) = source.parent() {
        dialog = dialog.set_directory(parent);
    }
    if let Some(extension) = format.extension() {
        let filter = match format {
            KeyFileFormat::Ppk3 | KeyFileFormat::Ppk2 => {
                Localized::new("PuTTY keys", "Ключи PuTTY", "PuTTY kalitlari")
            }
            _ => Localized::new("PEM keys", "Ключи PEM", "PEM kalitlari"),
        };
        dialog = dialog.add_filter(filter.pick(), &[extension]);
    }
    if let Some(window) = app.get_webview_window("main") {
        dialog = dialog.set_parent(&window);
    }
    dialog
        .blocking_save_file()
        .map(|picked| {
            picked
                .into_path()
                .map_err(|e| AppError::invalid(format!("not a file path: {e}")))
        })
        .transpose()
        .and_then(|path| match path {
            Some(path) if !path.is_absolute() => Err(AppError::invalid(format!(
                "not an absolute path: {}",
                path.display()
            ))),
            other => Ok(other),
        })
}

// --- authorized_keys line ----------------------------------------------------

/// The `authorized_keys` line for `public_key` with `options`, or what keeps
/// it from being made.
#[tauri::command]
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
pub fn authorized_line(public_key: String, options: LineOptions) -> AuthorizedLine {
    authorized_line::build(&public_key, &options)
}

/// Adds `line` (a line [`authorized_line`] made) to `~/.ssh/authorized_keys`
/// on `alias`, unless a line has its key already, signing in with what the
/// vault saved for the host if it is unlocked. The server needs a POSIX
/// `sh`; the line travels over stdin.
#[tauri::command]
pub async fn install_authorized_line(
    app: AppHandle,
    state: State<'_, Shared>,
    alias: String,
    line: String,
) -> AppResult<KeyInstall> {
    blocking(&state, move |state| {
        check_alias(&alias)?;
        let blob = line_blob(&line)?;
        let secrets = if state.vault.is_unlocked() {
            saved_secrets(state, &app, &alias)?
        } else {
            Secrets::default()
        };
        let remote = format!("sh -c '{INSTALL_LINE_SCRIPT}'");
        let run = run_ssh(
            state,
            &alias,
            COMMAND_ONLY,
            &[&remote],
            secrets,
            Some(format!("{blob}\n{}\n", line.trim()).into_bytes()),
            Duration::from_secs(30),
        )?;
        let added = run.output.success && has_line(&run.output.stdout, ADDED);
        let present = run.output.success && has_line(&run.output.stdout, PRESENT);
        let output = combined(&run.output)
            .lines()
            .filter(|l| *l != ADDED && *l != PRESENT)
            .collect::<Vec<_>>()
            .join("\n");
        Ok(KeyInstall {
            ok: added || present,
            added,
            output: with_timeout_note(output.trim().to_owned(), &run.output),
            prompts: run.prompts,
        })
    })
    .await
}

/// The key's base64 blob, once `line` reads as exactly one key line, as
/// `sshd` reads it.
fn line_blob(line: &str) -> AppResult<String> {
    let line = line.trim();
    let file = authorized_keys::parse(line);
    let ([key], true) = (
        file.keys.as_slice(),
        file.invalid.is_empty() && !line.contains('\n'),
    ) else {
        return Err(AppError::invalid("not one authorized_keys line"));
    };
    let public = PublicKey::from_openssh(&key.public_key)
        .map_err(|e| AppError::invalid(format!("not a public key: {e}")))?;
    let encoded = public
        .to_openssh()
        .map_err(|e| AppError::invalid(format!("not a public key: {e}")))?;
    encoded
        .split(' ')
        .nth(1)
        .map(str::to_owned)
        .ok_or_else(|| AppError::invalid("not a public key"))
}

/// Run by the server's `sh` with the key's base64 blob and then the whole
/// line on stdin; one line with no `'` and no `!`, as the install script of
/// [`super::remote`] is, which it follows: `~/.ssh` (0700) and
/// `authorized_keys` (0600) made if missing, the line added unless one has
/// the blob already, after ending a last line that has no newline.
const INSTALL_LINE_SCRIPT: &str = concat!(
    "umask 077; ",
    "IFS= read -r b || exit 65; ",
    "IFS= read -r key || [ -n \"$key\" ] || exit 65; ",
    "[ -n \"$b\" ] || exit 65; ",
    "cd || exit 1; ",
    "[ -d .ssh ] || mkdir -m 700 .ssh || exit 1; ",
    "f=.ssh/authorized_keys; ",
    "if [ -f \"$f\" ] && awk -v b=\"$b\" ",
    "\"{ for (i = 1; i <= NF; i++) if (\\$i == b) found = 1 } END { exit found ? 0 : 1 }\" ",
    "\"$f\"; then echo sshkm:present; exit 0; fi; ",
    "if [ -s \"$f\" ] && [ -n \"$(tail -c 1 \"$f\")\" ]; then echo >> \"$f\" || exit 1; fi; ",
    "printf \"%s\\n\" \"$key\" >> \"$f\" || exit 1; ",
    "echo sshkm:added",
);

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHJCszOHaI9X/yGLtjn22f0hO6VPMQDVtctkym6FJH1W a@b";

    #[test]
    fn the_install_script_stays_one_quoted_line() {
        assert!(!INSTALL_LINE_SCRIPT.contains('\''));
        assert!(!INSTALL_LINE_SCRIPT.contains('!'));
        assert!(!INSTALL_LINE_SCRIPT.contains('\n'));
    }

    #[test]
    fn only_one_key_line_is_installed() {
        let blob = KEY.split(' ').nth(1).unwrap();
        assert_eq!(line_blob(KEY).unwrap(), blob);
        assert_eq!(
            line_blob(&format!(r#"restrict,command="echo \"hi\"" {KEY}"#)).unwrap(),
            blob
        );
        for bad in ["", "nonsense", &format!("{KEY}\n{KEY}"), "ssh-ed25519 AAAA"] {
            assert!(line_blob(bad).is_err(), "{bad}");
        }
    }

    /// The script on this computer's `sh`, against a temporary home.
    #[cfg(unix)]
    #[test]
    fn the_install_script_adds_a_line_once() {
        use std::io::Write as _;

        let home = tempfile::tempdir().unwrap();
        let line = format!(r#"from="10.0.0.0/8",command="echo \"hi there\"" {KEY}"#);
        let blob = line_blob(&line).unwrap();
        let run = || {
            let mut child = std::process::Command::new("/bin/sh")
                .args(["-c", INSTALL_LINE_SCRIPT])
                .env("HOME", home.path())
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(format!("{blob}\n{line}\n").as_bytes())
                .unwrap();
            String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap()
        };
        assert_eq!(run().trim(), ADDED);
        assert_eq!(run().trim(), PRESENT);
        let file = std::fs::read_to_string(home.path().join(".ssh/authorized_keys")).unwrap();
        assert_eq!(file, format!("{line}\n"));
    }
}
