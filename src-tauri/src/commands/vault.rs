//! The password vault. Secrets leave the Rust process only when the user asks
//! to see one ([`vault_reveal`]) or for a recovery key that must be shown;
//! copying goes straight from here to the clipboard ([`vault_copy`]).

use std::sync::Arc;

use sshkm_core::vault::{
    self, EntryDetail, EntryInput, EntrySummary, GenerateOptions, SecretField, Strength, Vault,
};
use sshkm_core::{ExposeSecret, SecretString};
use tauri::{AppHandle, State};

use super::{Shared, blocking};
use crate::error::{AppError, AppResult};
use crate::types::{CopyField, CopyResult, OtpCode, VaultState, VaultStatus};
use crate::vault::{LockReason, VaultSettings};

#[tauri::command]
pub async fn vault_status(state: State<'_, Shared>) -> AppResult<VaultStatus> {
    blocking(&state, status).await
}

fn status(state: &crate::state::AppState) -> AppResult<VaultStatus> {
    let paths = state.vault.paths();
    let files = vault::probe(&paths)?;
    let state_now = if state.vault.is_unlocked() {
        VaultState::Unlocked
    } else if files.exists {
        VaultState::Locked
    } else {
        VaultState::Missing
    };
    Ok(VaultStatus {
        state: state_now,
        files,
        paths,
        settings: state.vault.settings(),
    })
}

/// Creates the vault and returns its recovery key, to be shown once.
#[tauri::command]
pub async fn vault_create(state: State<'_, Shared>, master: SecretString) -> AppResult<String> {
    blocking(&state, move |state| {
        let paths = state.vault.paths();
        if let Some(dir) = paths.database.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let (vault, recovery) = Vault::create(&paths, &master)?;
        state.vault.set_unlocked(vault);
        Ok(recovery.expose_secret().to_owned())
    })
    .await
}

#[tauri::command]
pub async fn vault_unlock(state: State<'_, Shared>, master: SecretString) -> AppResult<()> {
    blocking(&state, move |state| {
        let vault = Vault::unlock(&state.vault.paths(), &master)?;
        state.vault.set_unlocked(vault);
        Ok(())
    })
    .await
}

/// Unlocks with the recovery key (or a brought KeePass file's password) and
/// sets a new master password.
#[tauri::command]
pub async fn vault_recover(
    state: State<'_, Shared>,
    recovery_key: SecretString,
    new_master: SecretString,
) -> AppResult<()> {
    blocking(&state, move |state| {
        let vault = Vault::recover(&state.vault.paths(), &recovery_key, &new_master)?;
        state.vault.set_unlocked(vault);
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn vault_lock(app: AppHandle, state: State<'_, Shared>) -> AppResult<()> {
    state.vault.lock(&app, LockReason::Manual);
    Ok(())
}

/// The UI reports user activity (throttled) to postpone the auto-lock.
#[tauri::command]
pub async fn vault_activity(state: State<'_, Shared>) -> AppResult<()> {
    if state.vault.is_unlocked() {
        state.vault.touch();
    }
    Ok(())
}

#[tauri::command]
pub async fn vault_entries(
    app: AppHandle,
    state: State<'_, Shared>,
) -> AppResult<Vec<EntrySummary>> {
    blocking(&state, move |state| {
        state.vault.with(&app, |vault| Ok(vault.entries()))
    })
    .await
}

#[tauri::command]
pub async fn vault_entry(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
) -> AppResult<EntryDetail> {
    blocking(&state, move |state| {
        state.vault.with(&app, |vault| Ok(vault.entry(&id)?))
    })
    .await
}

/// One secret, for the user to see.
#[tauri::command]
pub async fn vault_reveal(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
    field: SecretField,
) -> AppResult<String> {
    blocking(&state, move |state| {
        state.vault.with(&app, |vault| {
            Ok(vault.secret(&id, field)?.expose_secret().to_owned())
        })
    })
    .await
}

/// Copies a field without it passing through the UI. Passwords and codes
/// are kept out of clipboard history and cleared after a while.
#[tauri::command]
pub async fn vault_copy(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
    field: CopyField,
) -> AppResult<CopyResult> {
    blocking(&state, move |state| {
        let (text, secret) = state.vault.with(&app, |vault| {
            Ok(match field {
                CopyField::Username => (
                    SecretString::from(vault.entry(&id)?.summary.username),
                    false,
                ),
                CopyField::Url => (SecretString::from(vault.entry(&id)?.summary.url), false),
                CopyField::Password => (vault.secret(&id, SecretField::Password)?, true),
                CopyField::Otp => (SecretString::from(vault.otp_code(&id)?.0), true),
            })
        })?;
        if text.expose_secret().is_empty() {
            return Err(AppError::not_found("nothing to copy"));
        }
        let clears_in_secs = Arc::clone(&state.vault).copy(&text, secret)?;
        Ok(CopyResult { clears_in_secs })
    })
    .await
}

/// The current 2FA code of an entry.
#[tauri::command]
pub async fn vault_otp(app: AppHandle, state: State<'_, Shared>, id: String) -> AppResult<OtpCode> {
    blocking(&state, move |state| {
        state.vault.with(&app, |vault| {
            let (code, valid_for) = vault.otp_code(&id)?;
            Ok(OtpCode {
                code,
                valid_for: u32::try_from(valid_for).unwrap_or(u32::MAX),
            })
        })
    })
    .await
}

#[tauri::command]
pub async fn vault_add(
    app: AppHandle,
    state: State<'_, Shared>,
    input: EntryInput,
) -> AppResult<EntryDetail> {
    blocking(&state, move |state| {
        state.vault.change(&app, &state.backup_dir, |vault| {
            let id = vault.add_entry(&input)?;
            Ok(vault.entry(&id)?)
        })
    })
    .await
}

#[tauri::command]
pub async fn vault_update(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
    input: EntryInput,
) -> AppResult<EntryDetail> {
    blocking(&state, move |state| {
        state.vault.change(&app, &state.backup_dir, |vault| {
            vault.update_entry(&id, &input)?;
            Ok(vault.entry(&id)?)
        })
    })
    .await
}

#[tauri::command]
pub async fn vault_trash(app: AppHandle, state: State<'_, Shared>, id: String) -> AppResult<()> {
    blocking(&state, move |state| {
        state
            .vault
            .change(&app, &state.backup_dir, |vault| Ok(vault.trash_entry(&id)?))
    })
    .await
}

#[tauri::command]
pub async fn vault_restore(app: AppHandle, state: State<'_, Shared>, id: String) -> AppResult<()> {
    blocking(&state, move |state| {
        state.vault.change(&app, &state.backup_dir, |vault| {
            Ok(vault.restore_entry(&id)?)
        })
    })
    .await
}

/// Deletes an entry from the recycle bin for good.
#[tauri::command]
pub async fn vault_delete(app: AppHandle, state: State<'_, Shared>, id: String) -> AppResult<()> {
    blocking(&state, move |state| {
        state.vault.change(
            &app,
            &state.backup_dir,
            |vault| Ok(vault.delete_entry(&id)?),
        )
    })
    .await
}

#[tauri::command]
pub async fn vault_empty_trash(app: AppHandle, state: State<'_, Shared>) -> AppResult<usize> {
    blocking(&state, move |state| {
        state
            .vault
            .change(&app, &state.backup_dir, |vault| Ok(vault.empty_trash()?))
    })
    .await
}

/// A new random password or passphrase. Works while locked.
#[tauri::command]
pub async fn vault_generate(options: GenerateOptions) -> AppResult<String> {
    Ok(vault::generate(&options)?.expose_secret().to_owned())
}

/// How strong a password looks. `context` holds words an attacker would try
/// first (title, user name). Works while locked.
#[tauri::command]
pub async fn vault_strength(password: SecretString, context: Vec<String>) -> AppResult<Strength> {
    let context: Vec<&str> = context.iter().map(String::as_str).collect();
    Ok(vault::strength(&password, &context))
}

#[tauri::command]
pub async fn vault_change_master(
    app: AppHandle,
    state: State<'_, Shared>,
    current: SecretString,
    new: SecretString,
) -> AppResult<()> {
    blocking(&state, move |state| {
        state.vault.with(&app, |vault| {
            Ok(vault.change_master_password(&current, &new)?)
        })
    })
    .await
}

/// Replaces the recovery key and returns the new one, to be shown once.
#[tauri::command]
pub async fn vault_new_recovery_key(
    app: AppHandle,
    state: State<'_, Shared>,
    master: SecretString,
) -> AppResult<String> {
    blocking(&state, move |state| {
        state.vault.with(&app, |vault| {
            let key = vault.new_recovery_key(&master, &state.backup_dir)?;
            Ok(key.expose_secret().to_owned())
        })
    })
    .await
}

#[tauri::command]
pub async fn vault_set_settings(
    state: State<'_, Shared>,
    mut settings: VaultSettings,
) -> AppResult<VaultSettings> {
    blocking(&state, move |state| {
        // Moving or switching the database has its own commands.
        settings.database = state.vault.settings().database;
        state.vault.set_settings(settings)
    })
    .await
}
