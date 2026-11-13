use std::collections::HashSet;
use std::path::{Path, PathBuf};

use sshkm_core::agent::AgentClient;
use sshkm_core::config::{HostEdit, HostOption, IdentityUsage, SshConfig};
use sshkm_core::keys::{self, KeyInfo};
use sshkm_core::paths::display_path;
use sshkm_core::{ExposeSecret, SecretString};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::DialogExt;

use super::{Shared, blocking};
use crate::confirm::{self, Localized};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::types::{GenerateKeyRequest, KeyUsage, KeyView, KeysView, NewHost};

#[tauri::command]
pub async fn list_keys(state: State<'_, Shared>) -> AppResult<KeysView> {
    blocking(&state, key_views).await
}

#[tauri::command]
pub async fn generate_key(
    app: AppHandle,
    state: State<'_, Shared>,
    request: GenerateKeyRequest,
) -> AppResult<KeyView> {
    blocking(&state, move |state| {
        // A host name with shell syntax would run through a `ProxyCommand`
        // already in the file: ask before making anything.
        if let Some(host) = &request.host {
            let before = SshConfig::load(&state.paths.config)?;
            let mut after = before.clone();
            after.upsert_host(&host_edit(host, None))?;
            super::config::confirm_added(&app, state, &after, &before)?;
        }
        let info = keys::generate(&state.paths.dir, &request.key)?;
        let private = private_path(&info)?;

        if request.add_to_agent {
            let unlocked = keys::load_private(&private, request.key.passphrase.as_ref())?;
            let agent = AgentClient::from_env()?;
            agent.add(
                &unlocked,
                &agent_comment(&info),
                request.agent_lifetime_secs,
                false,
            )?;
            state.record_lifetime(&unlocked.fingerprint(), request.agent_lifetime_secs);
        }

        if let Some(host) = &request.host {
            let mut config = SshConfig::load(&state.paths.config)?;
            config.upsert_host(&host_edit(
                host,
                Some(&identity_file_value(state, &private)),
            ))?;
            config.save(&state.paths.config, &state.backup_dir)?;
        }

        find_view(state, &info.id)
    })
    .await
}

/// The host block made with a new key, signing in with `identity_file`
/// (`None` to check the block before the key exists).
fn host_edit(host: &NewHost, identity_file: Option<&str>) -> HostEdit {
    let mut options = Vec::new();
    if let Some(name) = host
        .host_name
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        options.push(HostOption::new("HostName", name));
    }
    if let Some(user) = host
        .user
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        options.push(HostOption::new("User", user));
    }
    if let Some(file) = identity_file {
        options.push(HostOption::new("IdentityFile", file));
        options.push(HostOption::new("IdentitiesOnly", "yes"));
    }
    HostEdit {
        id: None,
        patterns: host.alias.split_whitespace().map(str::to_owned).collect(),
        options,
    }
}

/// Changes, adds (`old` empty) or removes (`new` empty) a key's passphrase.
/// Adding one to an unencrypted key or removing it needs no secret, so the
/// user approves either in a native dialog naming the key file: a passphrase
/// nobody knows would lock the key for good (there is no copy of it), and
/// removing one leaves the key readable by anything that reads the file.
#[tauri::command]
pub async fn change_passphrase(
    app: AppHandle,
    state: State<'_, Shared>,
    key_id: String,
    old: Option<SecretString>,
    new: Option<SecretString>,
) -> AppResult<KeyView> {
    blocking(&state, move |state| {
        let info = find_key(state, &key_id)?;
        let path = private_path(&info)?;
        let new_empty = new.as_ref().is_none_or(|s| s.expose_secret().is_empty());
        let file = display_path(&path);
        let change = passphrase_change(info.encrypted, new_empty);
        if change == PassphraseChange::Add {
            confirm::require(
                &app,
                &Localized::new(
                    "Add a passphrase to this key?",
                    "Добавить парольную фразу к ключу?",
                    "Kalitga parol iborasi qoʻshilsinmi?",
                ),
                &Localized::new(
                    format!(
                        "The private key {file} will be encrypted with the new passphrase. \
                         Without it the key can't be used again: no unencrypted copy is kept."
                    ),
                    format!(
                        "Закрытый ключ {file} будет зашифрован новой парольной фразой. \
                         Без неё ключом больше нельзя будет пользоваться: \
                         незашифрованная копия не сохраняется."
                    ),
                    format!(
                        "{file} yopiq kaliti yangi parol iborasi bilan shifrlanadi. \
                         Usiz kalitdan boshqa foydalanib boʻlmaydi: shifrlanmagan nusxasi \
                         saqlanmaydi."
                    ),
                ),
                &Localized::new("Add passphrase", "Добавить фразу", "Iborani qoʻshish"),
            )?;
        } else if change == PassphraseChange::Remove {
            // A wrong passphrase is reported before anything is asked.
            keys::load_private(&path, old.as_ref())?;
            confirm::require(
                &app,
                &Localized::new(
                    "Remove the passphrase from this key?",
                    "Убрать парольную фразу с ключа?",
                    "Kalitdan parol iborasi olib tashlansinmi?",
                ),
                &Localized::new(
                    format!(
                        "The private key {file} will be stored unencrypted. Anyone who can \
                         read the file can use the key."
                    ),
                    format!(
                        "Закрытый ключ {file} будет храниться незашифрованным. \
                         Любой, кто может прочитать файл, сможет воспользоваться ключом."
                    ),
                    format!(
                        "{file} yopiq kaliti shifrlanmagan holda saqlanadi. Faylni oʻqiy \
                         oladigan har kim kalitdan foydalana oladi."
                    ),
                ),
                &Localized::new("Remove passphrase", "Убрать фразу", "Iborani olib tashlash"),
            )?;
        }
        let updated = keys::change_passphrase(&path, old.as_ref(), new.as_ref())?;
        find_view(state, &updated.id)
    })
    .await
}

/// What [`change_passphrase`] does to a key's protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PassphraseChange {
    /// An unencrypted (or unknown) key gets one.
    Add,
    /// An encrypted (or unknown) key loses it.
    Remove,
    /// One passphrase for another, or nothing for nothing.
    Keep,
}

fn passphrase_change(encrypted: Option<bool>, new_empty: bool) -> PassphraseChange {
    match (encrypted, new_empty) {
        (Some(true), false) | (Some(false), true) => PassphraseChange::Keep,
        (_, false) => PassphraseChange::Add,
        (_, true) => PassphraseChange::Remove,
    }
}

#[tauri::command]
pub async fn regenerate_public(state: State<'_, Shared>, key_id: String) -> AppResult<KeyView> {
    blocking(&state, move |state| {
        let info = find_key(state, &key_id)?;
        let updated = keys::regenerate_public(&private_path(&info)?)?;
        find_view(state, &updated.id)
    })
    .await
}

/// Asks for a private key in a system file dialog this side opens, and adds
/// it to `~/.ssh` under its own name as [`keys::import`] does. `None` when
/// the dialog was cancelled. The page never names the file.
#[tauri::command]
pub async fn import_key(app: AppHandle, state: State<'_, Shared>) -> AppResult<Option<KeyView>> {
    blocking(&state, move |state| {
        let title = Localized::new(
            "Choose a private key to import",
            "Выберите закрытый ключ для импорта",
            "Import qilinadigan yopiq kalitni tanlang",
        );
        let Some(source) = pick_key_file(&app, &state.paths.home, &title)? else {
            return Ok(None);
        };
        let info = keys::import(&state.paths.dir, &source, None)?;
        find_view(state, &info.id).map(Some)
    })
    .await
}

/// A system file dialog for one key file, opened in `folder`; `None` when it
/// was cancelled.
pub(crate) fn pick_key_file(
    app: &AppHandle,
    folder: &Path,
    title: &Localized,
) -> AppResult<Option<PathBuf>> {
    let mut dialog = app
        .dialog()
        .file()
        .set_title(title.pick())
        .set_directory(folder);
    if let Some(window) = app.get_webview_window("main") {
        dialog = dialog.set_parent(&window);
    }
    let Some(picked) = dialog.blocking_pick_file() else {
        return Ok(None);
    };
    let path = picked
        .into_path()
        .map_err(|e| AppError::invalid(format!("not a file path: {e}")))?;
    if path.is_absolute() {
        Ok(Some(path))
    } else {
        Err(AppError::invalid(format!(
            "not an absolute path: {}",
            path.display()
        )))
    }
}

/// Asks in a native dialog before an encrypted key's copy is written out
/// without a passphrase (the key converter), as removing a key's
/// passphrase is ([`change_passphrase`]). Fails with `cancelled` on a no.
pub(crate) fn confirm_unencrypted_copy(
    app: &AppHandle,
    source: &Path,
    target: &Path,
) -> AppResult<()> {
    confirm::require(
        app,
        &Localized::new(
            "Save the key without a passphrase?",
            "Сохранить ключ без парольной фразы?",
            "Kalit parol iborasisiz saqlansinmi?",
        ),
        &unencrypted_copy_body(source, target),
        &Localized::new(
            "Save without passphrase",
            "Сохранить без фразы",
            "Iborasiz saqlash",
        ),
    )
}

fn unencrypted_copy_body(source: &Path, target: &Path) -> Localized {
    let source = confirm::shown(&display_path(source), 400);
    let target = confirm::shown(&display_path(target), 400);
    Localized::new(
        format!(
            "The key {source} is encrypted, but its copy {target} won’t be. Anyone who can \
             read that file can use the key."
        ),
        format!(
            "Ключ {source} зашифрован, а его копия {target} зашифрована не будет. Любой, кто \
             может прочитать этот файл, сможет воспользоваться ключом."
        ),
        format!(
            "{source} kaliti shifrlangan, lekin uning {target} nusxasi shifrlanmaydi. Bu \
             faylni oʻqiy oladigan har kim kalitdan foydalana oladi."
        ),
    )
}

#[tauri::command]
pub async fn trash_key(state: State<'_, Shared>, key_id: String) -> AppResult<()> {
    blocking(&state, move |state| {
        let info = find_key(state, &key_id)?;
        let files: Vec<PathBuf> = [&info.private_path, &info.public_path]
            .into_iter()
            .flatten()
            .map(PathBuf::from)
            .collect();
        keys::move_to_trash(&files)?;
        Ok(())
    })
    .await
}

pub fn key_views(state: &AppState) -> AppResult<KeysView> {
    let scan = keys::scan(&state.paths.dir)?;
    let in_agent = agent_fingerprints();
    let usage = SshConfig::load(&state.paths.config)
        .map(|config| config.identity_usage(&state.paths))
        .unwrap_or_default();
    let keys = scan
        .keys
        .into_iter()
        .map(|info| view(info, &in_agent, &usage))
        .collect();
    Ok(KeysView {
        keys,
        skipped: scan.skipped,
    })
}

pub fn find_key(state: &AppState, key_id: &str) -> AppResult<KeyInfo> {
    keys::scan(&state.paths.dir)?
        .keys
        .into_iter()
        .find(|key| key.id == key_id)
        .ok_or_else(|| AppError::not_found(format!("key {key_id}")))
}

pub fn private_path(info: &KeyInfo) -> AppResult<PathBuf> {
    info.private_path
        .as_deref()
        .map(PathBuf::from)
        .ok_or_else(|| AppError::invalid(format!("{} has no private key", info.name)))
}

/// What `ssh-add -l` shows for the key: its comment, else its file name.
pub fn agent_comment(info: &KeyInfo) -> String {
    if info.comment.trim().is_empty() {
        info.private_path
            .clone()
            .unwrap_or_else(|| info.name.clone())
    } else {
        info.comment.clone()
    }
}

pub(crate) fn find_view(state: &AppState, key_id: &str) -> AppResult<KeyView> {
    key_views(state)?
        .keys
        .into_iter()
        .find(|key| key.info.id == key_id)
        .ok_or_else(|| AppError::not_found(format!("key {key_id}")))
}

fn agent_fingerprints() -> HashSet<String> {
    AgentClient::from_env()
        .and_then(|agent| agent.list())
        .map(|ids| ids.into_iter().map(|id| id.fingerprint).collect())
        .unwrap_or_default()
}

fn view(info: KeyInfo, in_agent: &HashSet<String>, usage: &[IdentityUsage]) -> KeyView {
    let loaded = info
        .fingerprint
        .as_ref()
        .is_some_and(|fp| in_agent.contains(fp));
    let used_by = usage
        .iter()
        .filter(|u| u.resolved && refers_to(&info, Path::new(&u.path)))
        .map(|u| KeyUsage {
            host_id: u.host_id,
            patterns: u.patterns.clone(),
        })
        .collect();
    KeyView {
        info,
        in_agent: loaded,
        used_by,
    }
}

/// `IdentityFile` may name the private key or its `.pub` (ssh then uses the
/// matching identity from the agent).
fn refers_to(info: &KeyInfo, target: &Path) -> bool {
    let matches = |path: &Option<String>| {
        path.as_deref()
            .is_some_and(|p| same_path(Path::new(p), target))
    };
    if matches(&info.private_path) || matches(&info.public_path) {
        return true;
    }
    info.public_path
        .as_deref()
        .and_then(|p| p.strip_suffix(".pub"))
        .is_some_and(|stem| same_path(Path::new(stem), target))
}

fn same_path(a: &Path, b: &Path) -> bool {
    if cfg!(windows) {
        a.to_string_lossy()
            .eq_ignore_ascii_case(&b.to_string_lossy())
    } else {
        a == b
    }
}

/// `~/.ssh/<name>` for keys in the default directory, the full path otherwise.
fn identity_file_value(state: &AppState, private: &Path) -> String {
    match private.strip_prefix(&state.paths.home) {
        Ok(rest) => format!("~/{}", rest.to_string_lossy().replace('\\', "/")),
        Err(_) => private.to_string_lossy().into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adding_or_removing_a_passphrase_is_confirmed() {
        use PassphraseChange::{Add, Keep, Remove};
        // (encrypted, new passphrase empty)
        assert_eq!(passphrase_change(Some(false), false), Add);
        assert_eq!(passphrase_change(None, false), Add);
        assert_eq!(passphrase_change(Some(true), true), Remove);
        assert_eq!(passphrase_change(None, true), Remove);
        // Changing one needs the old passphrase; nothing for nothing is no change.
        assert_eq!(passphrase_change(Some(true), false), Keep);
        assert_eq!(passphrase_change(Some(false), true), Keep);
    }

    #[test]
    fn an_unencrypted_copy_names_both_files() {
        let body = unencrypted_copy_body(
            Path::new("/keys/server.ppk"),
            Path::new("/backup/server\u{202E}txt.pem"),
        );
        assert!(
            body.en
                .contains("The key /keys/server.ppk is encrypted, but its copy")
        );
        assert!(body.en.contains("/backup/server<U+202E>txt.pem won’t be"));
        assert!(body.ru.contains("/keys/server.ppk"));
        assert!(body.uz.contains("/backup/server<U+202E>txt.pem"));
    }
}
