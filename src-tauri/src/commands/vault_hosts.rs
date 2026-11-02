//! SSH hosts whose passwords are in the vault: test the connection and install
//! a public key with the saved password, the current 2FA code and any saved
//! key passphrases, none of which pass through the UI.

use std::thread;
use std::time::Duration;

use sshkm_core::keys;
use sshkm_core::vault::{EntryKind, SecretField, Vault};
use sshkm_core::{ExposeSecret, SecretString};
use tauri::{AppHandle, State};

use super::config::connection_test;
use super::remote::{check_alias, combined, install_key, run_ssh, with_timeout_note};
use super::{Shared, blocking};
use crate::askpass::Secrets;
use crate::error::AppResult;
use crate::state::AppState;
use crate::types::{ConnectionTest, KeyInstall};

/// A 2FA code this close to expiring may be stale by the time the server
/// checks it; wait for the next one instead.
const MIN_CODE_LIFE: u64 = 5;

#[tauri::command]
pub async fn vault_test_connection(
    app: AppHandle,
    state: State<'_, Shared>,
    alias: String,
) -> AppResult<ConnectionTest> {
    blocking(&state, move |state| {
        let secrets = saved_secrets(state, &app, &alias)?;
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
        let secrets = saved_secrets(state, &app, &alias)?;
        install_key(state, &alias, &key_id, secrets)
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
            ],
            &["exit"],
            passphrases,
            None,
            Duration::from_secs(30),
        )?;
        let text = combined(&run.output);
        Ok(ConnectionTest {
            ok: run.output.success,
            output: with_timeout_note(text, &run.output),
            prompts: run.prompts,
        })
    })
    .await
}

/// The host's saved password and 2FA code, and the passphrases of keys in
/// `~/.ssh` that are saved too, in case `ssh` offers one of them.
fn saved_secrets(state: &AppState, app: &AppHandle, alias: &str) -> AppResult<Secrets> {
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
        let (password, otp) = match live(EntryKind::Host).find(|e| e.host.as_deref() == Some(alias))
        {
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

fn fresh_code(vault: &Vault, id: &str) -> AppResult<SecretString> {
    let (code, valid_for) = vault.otp_code(id)?;
    if valid_for >= MIN_CODE_LIFE {
        return Ok(SecretString::from(code));
    }
    thread::sleep(Duration::from_secs(valid_for + 1));
    Ok(SecretString::from(vault.otp_code(id)?.0))
}
