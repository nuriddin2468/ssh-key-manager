//! SSH hosts whose passwords are in the vault: test the connection and install
//! a public key with the saved password, the current 2FA code and any saved
//! key passphrases, none of which pass through the UI.

use std::thread;
use std::time::Duration;

use sshkm_core::keys;
use sshkm_core::vault::{EntryKind, EntrySummary, SecretField, Vault};
use sshkm_core::{ExposeSecret, SecretString};
use tauri::{AppHandle, State};

use super::config::{checked, connection_test, with_typed_passphrase};
use super::remote::{check_alias, install_key, read_server_keys, run_ssh};
use super::{Shared, blocking};
use crate::askpass::Secrets;
use crate::error::AppResult;
use crate::state::AppState;
use crate::types::{ConnectionTest, KeyInstall, ServerKeys, ServerKeysAction};

/// A 2FA code this close to expiring may be stale by the time the server
/// checks it; wait for the next one instead.
const MIN_CODE_LIFE: u64 = 5;

/// [`test_connection`](super::config::test_connection) with what the vault
/// saved, and the passphrase the user typed for a key whose one is not saved.
#[tauri::command]
pub async fn vault_test_connection(
    app: AppHandle,
    state: State<'_, Shared>,
    alias: String,
    key_id: Option<String>,
    passphrase: Option<SecretString>,
) -> AppResult<ConnectionTest> {
    blocking(&state, move |state| {
        check_alias(&alias)?;
        let secrets = saved_secrets(state, &app, &alias)?;
        let secrets = with_typed_passphrase(state, secrets, key_id, passphrase)?;
        connection_test(state, &alias, secrets)
    })
    .await
}

/// Installs the public key of `key_id` on `alias`, logging in with the saved
/// password — the first step from password logins to keys.
#[tauri::command]
pub async fn vault_install_public_key(
    app: AppHandle,
    state: State<'_, Shared>,
    alias: String,
    key_id: String,
) -> AppResult<KeyInstall> {
    blocking(&state, move |state| {
        check_alias(&alias)?;
        let secrets = saved_secrets(state, &app, &alias)?;
        install_key(state, &alias, &key_id, secrets)
    })
    .await
}

/// [`server_keys`](super::remote::server_keys), signing in with the saved
/// password and 2FA code.
#[tauri::command]
pub async fn vault_server_keys(
    app: AppHandle,
    state: State<'_, Shared>,
    alias: String,
    action: ServerKeysAction,
) -> AppResult<ServerKeys> {
    blocking(&state, move |state| {
        check_alias(&alias)?;
        let secrets = saved_secrets(state, &app, &alias)?;
        read_server_keys(state, &alias, &action, secrets)
    })
    .await
}

/// Tests that `alias` lets the user in with a key alone: password and
/// keyboard-interactive logins are switched off for this run, and only saved
/// key passphrases are offered. The last step of moving a host to keys.
#[tauri::command]
pub async fn vault_test_key_login(
    app: AppHandle,
    state: State<'_, Shared>,
    alias: String,
) -> AppResult<ConnectionTest> {
    blocking(&state, move |state| {
        check_alias(&alias)?;
        let passphrases = saved_secrets(state, &app, &alias)?.without_login_secrets();
        let run = run_ssh(
            state,
            &alias,
            &[
                "-o",
                "PreferredAuthentications=publickey",
                "-o",
                "PasswordAuthentication=no",
                "-o",
                "KbdInteractiveAuthentication=no",
                super::diagnose::VERBOSE,
            ],
            &["exit"],
            passphrases,
            None,
            Duration::from_secs(30),
        )?;
        Ok(checked(&alias, &run, run.output.success))
    })
    .await
}

/// The host's saved password and 2FA code, and the passphrases of keys in
/// `~/.ssh` that are saved too, in case `ssh` offers one of them. A server
/// never gets a passphrase: [`run_ssh`] switches keyboard-interactive off
/// unless a 2FA code is saved, and its session refuses a server's prompt
/// that asks for one.
pub(crate) fn saved_secrets(state: &AppState, app: &AppHandle, alias: &str) -> AppResult<Secrets> {
    let scanned = keys::scan(&state.paths.dir)
        .map(|scan| scan.keys)
        .unwrap_or_default();
    state.vault.with(app, |vault| {
        let entries = vault.entries();
        let live = |kind: EntryKind| {
            entries
                .iter()
                .filter(move |e| !e.in_trash && e.kind == kind)
        };
        let (password, otp) = match host_entry(&entries, alias) {
            Some(entry) => (
                Some(vault.secret(&entry.id, SecretField::Password)?),
                if entry.has_otp {
                    Some(fresh_code(vault, &entry.id)?)
                } else {
                    None
                },
            ),
            None => (None, None),
        };
        let mut secrets = Secrets::new(password, otp);
        for key in &scanned {
            let (Some(path), Some(fingerprint)) = (&key.private_path, &key.fingerprint) else {
                continue;
            };
            if let Some(entry) = live(EntryKind::Key)
                .find(|e| e.key_fingerprint.as_deref() == Some(fingerprint.as_str()))
            {
                let passphrase = vault.secret(&entry.id, SecretField::Password)?;
                if !passphrase.expose_secret().is_empty() {
                    secrets = secrets.with_passphrase(path, passphrase);
                }
            }
        }
        Ok(secrets)
    })
}

/// The entry for `alias`'s password: of the host entries outside the
/// recycle bin that name it, the one made first (one without a time, from
/// an older file, counts as older still; then by id). Titles don't decide,
/// so an entry made later, one another computer sent say, never takes the
/// place of the one this vault had.
pub(crate) fn host_entry<'a>(entries: &'a [EntrySummary], alias: &str) -> Option<&'a EntrySummary> {
    entries
        .iter()
        .filter(|e| !e.in_trash && e.kind == EntryKind::Host && e.host.as_deref() == Some(alias))
        .min_by(|a, b| {
            a.created
                .is_some()
                .cmp(&b.created.is_some())
                .then_with(|| a.created.cmp(&b.created))
                .then_with(|| a.id.cmp(&b.id))
        })
}

/// The entry's current 2FA code, waiting for the next one if this one is
/// about to expire.
pub(crate) fn fresh_code(vault: &Vault, id: &str) -> AppResult<SecretString> {
    let (code, valid_for) = vault.otp_code(id)?;
    if valid_for >= MIN_CODE_LIFE {
        return Ok(SecretString::from(code));
    }
    thread::sleep(Duration::from_secs(valid_for + 1));
    Ok(SecretString::from(vault.otp_code(id)?.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, title: &str, host: &str, created: Option<&str>) -> EntrySummary {
        EntrySummary {
            id: id.into(),
            title: title.into(),
            username: String::new(),
            url: String::new(),
            kind: EntryKind::Host,
            host: Some(host.into()),
            key_fingerprint: None,
            has_password: true,
            has_otp: false,
            group: None,
            in_trash: false,
            created: created.map(str::to_owned),
            modified: None,
        }
    }

    #[test]
    fn an_entry_made_later_never_takes_an_alias_over() {
        // As `Vault::entries` lists them: by title.
        let entries = [
            entry("received", "Prod DB", "prod", Some("2026-11-13T10:00:00Z")),
            entry("mine", "Work prod", "prod", Some("2026-02-01T08:00:00Z")),
        ];
        assert_eq!(host_entry(&entries, "prod").unwrap().id, "mine");
        // One from a file without times counts as older.
        let entries = [
            entry("dated", "A", "prod", Some("2020-01-01T00:00:00Z")),
            entry("undated", "B", "prod", None),
        ];
        assert_eq!(host_entry(&entries, "prod").unwrap().id, "undated");
        // Nor does the recycle bin, another kind or another alias count.
        let mut trashed = entry("trashed", "A", "prod", None);
        trashed.in_trash = true;
        let mut login = entry("login", "B", "prod", None);
        login.kind = EntryKind::Login;
        let entries = [
            trashed,
            login,
            entry("other", "C", "staging", None),
            entry("live", "D", "prod", Some("2026-01-01T00:00:00Z")),
        ];
        assert_eq!(host_entry(&entries, "prod").unwrap().id, "live");
        assert!(host_entry(&entries, "db").is_none());
    }
}
