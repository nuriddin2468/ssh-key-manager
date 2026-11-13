//! The SSH tools of the Tools page: tunnels, the ProxyJump wizard, the key
//! converter and the `authorized_keys` line builder. The work is in
//! `sshkm_core` (`tunnels`, `config`, `keys::convert`, `authorized_line`)
//! and in [`crate::tunnels`], which runs the tunnels.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use ssh_key::PublicKey;
use sshkm_core::ExposeSecret;
use sshkm_core::SecretString;
use sshkm_core::authorized_keys;
use sshkm_core::authorized_line::{self, AuthorizedLine, LineOptions};
use sshkm_core::config::HostKind;
use sshkm_core::keys::{
    self,
    convert::{self, KeyFileFormat, KeyFileInfo},
};
use sshkm_core::tunnels::{Tunnel, TunnelKind};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::DialogExt;

use super::config::{config_file, confirm_added, load_at};
use super::keys::{confirm_unencrypted_copy, find_view, pick_key_file};
use super::remote::{
    ADDED, COMMAND_ONLY, PRESENT, check_alias, combined, has_line, run_ssh, with_timeout_note,
};
use super::vault_hosts::saved_secrets;
use super::{Shared, blocking};
use crate::askpass::Secrets;
use crate::confirm::Localized;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
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
/// as changed. A tunnel that lets others reach something through this
/// computer (on every address, or remote) is confirmed in a native dialog
/// that says what it opens to whom, unless it forwards as it did before;
/// `cancelled` if the user says no.
#[tauri::command]
pub async fn tunnel_save(
    app: AppHandle,
    state: State<'_, Shared>,
    tunnels: State<'_, SharedTunnels>,
    tunnel: Tunnel,
) -> AppResult<TunnelView> {
    let tunnels = SharedTunnels::clone(&tunnels);
    blocking(&state, move |_| {
        tunnels.save(tunnel, |tunnel| {
            let (title, body) = opening_prompt(tunnel);
            crate::confirm::require(
                &app,
                &title,
                &body,
                &Localized::new(
                    "Allow and save",
                    "Разрешить и сохранить",
                    "Ruxsat berish va saqlash",
                ),
            )
        })
    })
    .await
}

/// The title and text of the native dialog before saving `tunnel`, which
/// lets others reach something through this computer: who can connect,
/// where, and what they reach. Every value in it passed
/// [`Tunnel::validate`]: a plain alias, ports, addresses and host names.
fn opening_prompt(tunnel: &Tunnel) -> (Localized, Localized) {
    let alias = &tunnel.alias;
    let port = tunnel.listen_port;
    let target = format!(
        "{}:{}",
        tunnel.target_host.as_deref().unwrap_or_default(),
        tunnel.target_port.unwrap_or_default()
    );
    let (where_en, where_ru, where_uz) = match tunnel.bind_address.as_deref() {
        None | Some("*") => (
            "every address".to_owned(),
            "всех адресах".to_owned(),
            "barcha manzillarida".to_owned(),
        ),
        Some(address) => (
            format!("the address {address}"),
            format!("адресе {address}"),
            format!("{address} manzilida"),
        ),
    };
    let check = Localized::new(
        "Allow it only if you set up this tunnel yourself.",
        "Разрешайте, только если вы сами настроили этот туннель.",
        "Faqat bu tunnelni oʻzingiz sozlagan boʻlsangiz, ruxsat bering.",
    );
    let network = Localized::new(
        "Open this computer to your network?",
        "Открыть этот компьютер для вашей сети?",
        "Bu kompyuter tarmogʻingiz uchun ochilsinmi?",
    );
    let (title, en, ru, uz) = match tunnel.kind {
        TunnelKind::Local => (
            network,
            format!(
                "This tunnel listens on {where_en} of this computer, port {port}. Anyone on \
                 your network can connect to it and reach {target} through {alias}."
            ),
            format!(
                "Этот туннель принимает подключения на {where_ru} этого компьютера, порт {port}. \
                 Любой в вашей сети сможет подключиться к нему и попасть на {target} через \
                 {alias}."
            ),
            format!(
                "Bu tunnel shu kompyuterning {where_uz} {port}-portda ulanishlarni qabul qiladi. \
                 Tarmogʻingizdagi istalgan kishi unga ulanib, {alias} orqali {target} ga yeta \
                 oladi."
            ),
        ),
        TunnelKind::Dynamic => (
            network,
            format!(
                "This SOCKS proxy listens on {where_en} of this computer, port {port}. Anyone \
                 on your network can use it: their connections leave from {alias}."
            ),
            format!(
                "Этот SOCKS-прокси принимает подключения на {where_ru} этого компьютера, порт \
                 {port}. Любой в вашей сети сможет им пользоваться: его подключения будут \
                 выходить с {alias}."
            ),
            format!(
                "Bu SOCKS proksi shu kompyuterning {where_uz} {port}-portda ulanishlarni qabul \
                 qiladi. Tarmogʻingizdagi istalgan kishi undan foydalana oladi: uning ulanishlari \
                 {alias} dan chiqadi."
            ),
        ),
        TunnelKind::Remote => remote_prompt(tunnel, &target),
    };
    let body = Localized::new(
        format!("{en}\n\n{}", check.en),
        format!("{ru}\n\n{}", check.ru),
        format!("{uz}\n\n{}", check.uz),
    );
    (title, body)
}

/// [`opening_prompt`]'s title and text for a remote tunnel: who can connect
/// on the server, and what they reach from this computer.
fn remote_prompt(tunnel: &Tunnel, target: &str) -> (Localized, String, String, String) {
    let alias = &tunnel.alias;
    let port = tunnel.listen_port;
    let (who_en, who_ru, who_uz) = if tunnel.exposed() {
        (
            format!("Anyone who can reach {alias}"),
            format!("Любой, кто может подключиться к {alias}, сможет"),
            format!("{alias} ga ulana oladigan istalgan kishi"),
        )
    } else {
        (
            format!("Programs on {alias}"),
            format!("Программы на {alias} смогут"),
            format!("{alias} dagi dasturlar"),
        )
    };
    let host = tunnel.target_host.as_deref().unwrap_or_default();
    let here = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    let target_port = tunnel.target_port.unwrap_or_default();
    let (what_en, what_ru, what_uz) = if here {
        (
            format!("port {target_port} of this computer"),
            format!("порт {target_port} этого компьютера"),
            format!("shu kompyuterning {target_port}-portiga"),
        )
    } else {
        (
            format!("{target} through this computer"),
            format!("{target} через этот компьютер"),
            format!("shu kompyuter orqali {target} ga"),
        )
    };
    (
        Localized::new(
            "Give a server access to this computer?",
            "Дать серверу доступ к этому компьютеру?",
            "Serverga bu kompyuterdan foydalanishga ruxsat berilsinmi?",
        ),
        format!("{who_en} can connect to port {port} there and reach {what_en}."),
        format!("{who_ru} подключиться там к порту {port} и попасть на {what_ru}."),
        format!("{who_uz} u yerdagi {port}-portga ulanib, {what_uz} yeta oladi."),
    )
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

/// The key file picked in the converter's file dialog. Besides the private
/// keys the app lists in `~/.ssh`, the only file the converter reads
/// ([`convert_source`]).
static PICKED_KEY: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Asks for a key file to convert in a system file dialog this side opens,
/// and returns its path; `None` when the dialog was cancelled.
#[tauri::command]
pub async fn key_convert_pick(
    app: AppHandle,
    state: State<'_, Shared>,
) -> AppResult<Option<String>> {
    blocking(&state, move |state| {
        let title = Localized::new(
            "Choose a key file to convert",
            "Выберите файл ключа для преобразования",
            "Oʻzgartiriladigan kalit faylini tanlang",
        );
        let Some(path) = pick_key_file(&app, &state.paths.home, &title)? else {
            return Ok(None);
        };
        let shown = path.to_string_lossy().into_owned();
        *picked_key() = Some(path);
        Ok(Some(shown))
    })
    .await
}

/// What the key file at `path` holds; with `passphrase`, an encrypted key is
/// opened too (`wrong_passphrase` if it doesn't open). `path` is the file
/// picked in [`key_convert_pick`] or a private key in `~/.ssh`.
#[tauri::command]
pub async fn key_convert_inspect(
    state: State<'_, Shared>,
    path: String,
    passphrase: Option<SecretString>,
) -> AppResult<KeyFileInfo> {
    blocking(&state, move |state| {
        let source = convert_source(state, &path)?;
        Ok(convert::inspect(&source, passphrase.as_ref())?)
    })
    .await
}

/// Converts the key at `path` (as for [`key_convert_inspect`]) to the
/// OpenSSH format and adds it to `~/.ssh` as `file_name` (and `.pub`), as an
/// import does: never over a file. An encrypted key added without a new
/// passphrase is confirmed in a native dialog first.
#[tauri::command]
pub async fn key_convert_import(
    app: AppHandle,
    state: State<'_, Shared>,
    path: String,
    passphrase: Option<SecretString>,
    file_name: String,
    new_passphrase: Option<SecretString>,
    comment: Option<String>,
) -> AppResult<KeyView> {
    blocking(&state, move |state| {
        let source = convert_source(state, &path)?;
        // A wrong passphrase is reported before anything is asked.
        let opened = convert::inspect(&source, passphrase.as_ref())?;
        if drops_passphrase(&opened, new_passphrase.as_ref()) {
            confirm_unencrypted_copy(&app, &source, &state.paths.dir.join(&file_name))?;
        }
        let info = convert::import(
            &state.paths.dir,
            &source,
            passphrase.as_ref(),
            &file_name,
            new_passphrase.as_ref(),
            comment.as_deref(),
        )?;
        find_view(state, &info.id)
    })
    .await
}

/// Converts the key at `path` (as for [`key_convert_inspect`]) to `format`
/// and saves it where the user picks in a system dialog; `None` if it was
/// cancelled. Never over a file in `~/.ssh`. An encrypted key saved without
/// a passphrase is confirmed in a native dialog first.
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
        let source = &convert_source(state, &path)?;
        let opened = convert::inspect(source, passphrase.as_ref())?;
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
        if drops_passphrase(&opened, new_passphrase.as_ref()) {
            confirm_unencrypted_copy(&app, source, &target)?;
        }
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

/// `path` if the converter may read it: the file picked in its dialog, or a
/// private key the app lists in `~/.ssh`. Any other path the page names is
/// refused.
fn convert_source(state: &AppState, path: &str) -> AppResult<PathBuf> {
    let picked = picked_key().clone();
    convert_source_in(&state.paths.dir, path, picked.as_deref())
}

fn convert_source_in(ssh_dir: &Path, path: &str, picked: Option<&Path>) -> AppResult<PathBuf> {
    let path = PathBuf::from(path);
    if picked == Some(path.as_path()) {
        return Ok(path);
    }
    let listed = keys::scan(ssh_dir)?
        .keys
        .iter()
        .filter_map(|key| key.private_path.as_deref())
        .any(|private| Path::new(private) == path);
    if listed {
        Ok(path)
    } else {
        Err(AppError::invalid("choose the key file again"))
    }
}

/// Whether writing out the opened key `opened` with `new_passphrase` leaves
/// an encrypted key without one.
fn drops_passphrase(opened: &KeyFileInfo, new_passphrase: Option<&SecretString>) -> bool {
    opened.encrypted && opened.opened && new_passphrase.is_none_or(|p| p.expose_secret().is_empty())
}

fn picked_key() -> MutexGuard<'static, Option<PathBuf>> {
    PICKED_KEY.lock().unwrap_or_else(PoisonError::into_inner)
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

    fn tunnel(kind: TunnelKind, bind: Option<&str>) -> Tunnel {
        Tunnel {
            id: String::new(),
            name: "anything the page wrote".into(),
            alias: "bastion".into(),
            kind,
            bind_address: bind.map(str::to_owned),
            listen_port: 2222,
            target_host: (kind != TunnelKind::Dynamic).then(|| "127.0.0.1".into()),
            target_port: (kind != TunnelKind::Dynamic).then_some(22),
            auto_reconnect: false,
        }
    }

    #[test]
    fn the_confirmation_says_what_opens_to_whom() {
        let texts = |tunnel: &Tunnel| {
            let (title, body) = opening_prompt(tunnel);
            for text in [
                &title.en, &title.ru, &title.uz, &body.en, &body.ru, &body.uz,
            ] {
                assert_ne!(text, "");
                // The page's own words never reach the dialog.
                assert!(!text.contains("anything the page wrote"), "{text}");
            }
            (title.en, body.en)
        };
        let (title, body) = texts(&tunnel(TunnelKind::Local, Some("*")));
        assert_eq!(title, "Open this computer to your network?");
        assert!(body.contains("every address"), "{body}");
        assert!(body.contains("port 2222"), "{body}");
        assert!(body.contains("127.0.0.1:22 through bastion"), "{body}");

        let (_, body) = texts(&tunnel(TunnelKind::Dynamic, Some("192.168.1.5")));
        assert!(body.contains("the address 192.168.1.5"), "{body}");
        assert!(body.contains("leave from bastion"), "{body}");

        let (title, body) = texts(&tunnel(TunnelKind::Remote, None));
        assert_eq!(title, "Give a server access to this computer?");
        assert!(
            body.starts_with(
                "Programs on bastion can connect to port 2222 there and reach port 22 of \
                 this computer."
            ),
            "{body}"
        );
        let elsewhere = Tunnel {
            target_host: Some("nas.lan".into()),
            ..tunnel(TunnelKind::Remote, Some("*"))
        };
        let (_, body) = texts(&elsewhere);
        assert!(
            body.starts_with(
                "Anyone who can reach bastion can connect to port 2222 there and reach \
                 nas.lan:22 through this computer."
            ),
            "{body}"
        );
    }

    #[test]
    fn the_converter_reads_only_a_picked_file_or_a_key_in_ssh() {
        let home = tempfile::tempdir().unwrap();
        let ssh = home.path().join(".ssh");
        let key = keys::generate(
            &ssh,
            &keys::GenerateRequest {
                algorithm: keys::GenerateAlgorithm::Ed25519,
                file_name: "id_work".into(),
                comment: String::new(),
                passphrase: None,
            },
        )
        .unwrap();
        let listed = key.private_path.unwrap();
        let picked = home.path().join("Downloads").join("server.ppk");
        let elsewhere = home.path().join("other").join("id_other");

        assert_eq!(
            convert_source_in(&ssh, &listed, None).unwrap(),
            PathBuf::from(&listed)
        );
        let picked_text = picked.to_string_lossy();
        assert_eq!(
            convert_source_in(&ssh, &picked_text, Some(&picked)).unwrap(),
            picked
        );
        // A path the page made up, or a file picked before another.
        for path in [&elsewhere, &picked] {
            let error =
                convert_source_in(&ssh, &path.to_string_lossy(), Some(&elsewhere.join("x")))
                    .unwrap_err();
            assert_eq!(error.code(), sshkm_core::ErrorCode::InvalidInput);
        }
        assert!(convert_source_in(&ssh, &format!("{listed}.pub"), None).is_err());
    }

    #[test]
    fn writing_an_encrypted_key_without_a_passphrase_is_confirmed() {
        let info = |encrypted, opened| KeyFileInfo {
            format: KeyFileFormat::Openssh,
            algorithm: None,
            bits: None,
            comment: String::new(),
            encrypted,
            opened,
            fingerprints: None,
            suggested_name: "key".into(),
        };
        let new = SecretString::from("new passphrase".to_owned());
        let empty = SecretString::from(String::new());
        assert!(drops_passphrase(&info(true, true), None));
        assert!(drops_passphrase(&info(true, true), Some(&empty)));
        assert!(!drops_passphrase(&info(true, true), Some(&new)));
        // Nothing to drop; or not opened, so it can't be written at all.
        assert!(!drops_passphrase(&info(false, true), None));
        assert!(!drops_passphrase(&info(true, false), None));
    }

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
