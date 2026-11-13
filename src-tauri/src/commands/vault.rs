//! The password vault. Secrets leave the Rust process only when the user asks
//! to see a password or key passphrase ([`vault_reveal`]; never a 2FA
//! secret) or for a recovery key that must be shown; copying goes straight
//! from here to the clipboard ([`vault_copy`]).
//!
//! Reads the UI repeats by itself (the list, an entry, a 2FA code) don't
//! count as activity, so they never keep the vault unlocked. Changes that
//! weaken its protection need the user's confirmation in a native dialog,
//! whose text is built here.

use std::sync::Arc;

use sshkm_core::vault::{
    self, EntryDetail, EntryInput, EntrySummary, GenerateOptions, SecretField, Strength, Vault,
};
use sshkm_core::{ExposeSecret, SecretString};
use tauri::{AppHandle, State};

use super::{Shared, blocking};
use crate::confirm::{self, Localized};
use crate::device_unlock;
use crate::error::{AppError, AppResult};
use crate::types::{CopyField, CopyResult, OtpCode, VaultState, VaultStatus};
use crate::vault::{LockReason, VaultSettings, Weakening};

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
    let link = device_unlock::load_link(state.vault.data_dir());
    let device = device_unlock::status(
        link.as_ref(),
        files.vault_id.as_deref(),
        &files.device_slots,
    );
    Ok(VaultStatus {
        state: state_now,
        files,
        paths,
        settings: state.vault.settings(),
        device,
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
        let mut vault = Vault::unlock(&state.vault.paths(), &master)?;
        device_unlock::retire_stored_key(state.vault.data_dir(), &mut vault);
        state.vault.set_unlocked(vault);
        Ok(())
    })
    .await
}

/// Unlocks with Touch ID / Windows Hello. The prompt's text is the app's own.
#[tauri::command]
pub async fn vault_unlock_device(state: State<'_, Shared>) -> AppResult<()> {
    blocking(&state, move |state| {
        let vault = device_unlock::unlock(state.vault.data_dir(), &state.vault.paths())?;
        state.vault.set_unlocked(vault);
        Ok(())
    })
    .await
}

/// Turns on Touch ID / Windows Hello for this vault on this computer, after
/// the master password and a first successful prompt.
#[tauri::command]
pub async fn vault_enable_device(
    app: AppHandle,
    state: State<'_, Shared>,
    master: SecretString,
) -> AppResult<()> {
    blocking(&state, move |state| {
        let data_dir = state.vault.data_dir().to_path_buf();
        state.vault.with(&app, |vault| {
            vault.verify_master_password(&master)?;
            device_unlock::enable(&data_dir, vault)
        })
    })
    .await
}

/// Turns off Touch ID / Windows Hello for this vault on this computer, once
/// the user confirms in a native dialog.
#[tauri::command]
pub async fn vault_disable_device(app: AppHandle, state: State<'_, Shared>) -> AppResult<()> {
    blocking(&state, move |state| {
        let data_dir = state.vault.data_dir().to_path_buf();
        let Some(link) = device_unlock::load_link(&data_dir) else {
            return Ok(());
        };
        let method = device_method();
        confirm::require(
            &app,
            &Localized::new(
                format!("Turn off {method}?"),
                format!("Выключить {method}?"),
                format!("{method} oʻchirilsinmi?"),
            ),
            &Localized::new(
                format!(
                    "This computer will no longer open the password vault with {method}. \
                     You can turn it on again with the master password."
                ),
                format!(
                    "Этот компьютер больше не будет открывать хранилище паролей с помощью \
                     {method}. Его можно снова включить, введя мастер-пароль."
                ),
                format!(
                    "Bu kompyuter parollar omborini endi {method} orqali ochmaydi. \
                     Uni asosiy parol bilan qayta yoqish mumkin."
                ),
            ),
            &Localized::new("Turn off", "Выключить", "Oʻchirish"),
        )?;
        state.vault.with(&app, |vault| {
            if link.vault_id == vault.vault_id() {
                vault.disable_device_unlock(&link.slot_id)?;
            }
            Ok(())
        })?;
        device_unlock::disable(&data_dir, &link)
    })
    .await
}

/// The name of this system's device unlock, the same in every language.
fn device_method() -> &'static str {
    if cfg!(windows) {
        "Windows Hello"
    } else {
        "Touch ID"
    }
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
        let mut vault = Vault::recover(&state.vault.paths(), &recovery_key, &new_master)?;
        device_unlock::retire_stored_key(state.vault.data_dir(), &mut vault);
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

/// The entries. Quiet: the UI refetches the list by itself.
#[tauri::command]
pub async fn vault_entries(
    app: AppHandle,
    state: State<'_, Shared>,
) -> AppResult<Vec<EntrySummary>> {
    blocking(&state, move |state| {
        state.vault.with_quietly(&app, |vault| Ok(vault.entries()))
    })
    .await
}

/// One entry's details. Quiet, like [`vault_entries`].
#[tauri::command]
pub async fn vault_entry(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
) -> AppResult<EntryDetail> {
    blocking(&state, move |state| {
        state
            .vault
            .with_quietly(&app, |vault| Ok(vault.entry(&id)?))
    })
    .await
}

/// The password of an entry (a key's passphrase for a key entry), for the
/// user to see. A 2FA secret is never shown: it stays in this process, and
/// the 2FA code and copying go without it.
#[tauri::command]
pub async fn vault_reveal(
    app: AppHandle,
    state: State<'_, Shared>,
    id: String,
    field: SecretField,
) -> AppResult<String> {
    if field != SecretField::Password {
        return Err(AppError::invalid("only a password can be shown"));
    }
    blocking(&state, move |state| {
        // Past a few a minute, each is confirmed in a native dialog.
        crate::secret_gate::take_entry_password(
            &app,
            state,
            &id,
            crate::secret_gate::Taking::Show,
        )?;
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
    webview: tauri::Webview,
    state: State<'_, Shared>,
    id: String,
    field: CopyField,
) -> AppResult<CopyResult> {
    // The main window's page drives the terminal, which can read the
    // clipboard: a password it copies counts as shown for `vault_reveal`'s
    // limit. (The quick search window can't, and has no window for the
    // question.)
    let counted = field == CopyField::Password && webview.label() == "main";
    blocking(&state, move |state| {
        if counted {
            crate::secret_gate::take_entry_password(
                &app,
                state,
                &id,
                crate::secret_gate::Taking::Copy,
            )?;
        }
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

/// Copies a recovery key the UI is showing — once, right after it was made —
/// like a password: kept out of clipboard history and cloud clipboards, and
/// cleared after a while even if the settings say never. Only a recovery key
/// is accepted.
#[tauri::command]
pub async fn vault_copy_recovery_key(
    state: State<'_, Shared>,
    key: SecretString,
) -> AppResult<CopyResult> {
    blocking(&state, move |state| {
        let key = vault::canonical_recovery_key(&key)
            .ok_or_else(|| AppError::invalid("not a recovery key"))?;
        let clears_in_secs = Arc::clone(&state.vault).copy_recovery_key(&key)?;
        Ok(CopyResult { clears_in_secs })
    })
    .await
}

/// The current 2FA code of an entry. Quiet: the code refreshes by itself
/// every 30 seconds while the entry is open.
#[tauri::command]
pub async fn vault_otp(app: AppHandle, state: State<'_, Shared>, id: String) -> AppResult<OtpCode> {
    blocking(&state, move |state| {
        state.vault.with_quietly(&app, |vault| {
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
        let key = state.vault.with(&app, |vault| {
            Ok(vault.new_recovery_key(&master, &state.backup_dir)?)
        })?;
        // Every device slot went with the old key.
        if let Some(link) = device_unlock::load_link(state.vault.data_dir()) {
            device_unlock::disable(state.vault.data_dir(), &link)?;
        }
        Ok(key.expose_secret().to_owned())
    })
    .await
}

/// Saves the vault's preferences. A change that weakens its protection
/// (later or no auto-lock, no clipboard clearing, not locking with sleep,
/// the screen or the window) needs the user's confirmation in a native
/// dialog first.
#[tauri::command]
pub async fn vault_set_settings(
    app: AppHandle,
    state: State<'_, Shared>,
    mut settings: VaultSettings,
) -> AppResult<VaultSettings> {
    blocking(&state, move |state| {
        let current = state.vault.settings();
        // Moving or switching the database has its own commands.
        settings.database.clone_from(&current.database);
        let weakened = current.weakened_by(&settings);
        if !weakened.is_empty() {
            confirm::require(
                &app,
                &Localized::new(
                    "Weaken the vault’s protection?",
                    "Ослабить защиту хранилища?",
                    "Ombor himoyasi zaiflashtirilsinmi?",
                ),
                &weakening_text(&weakened),
                &Localized::new("Change", "Изменить", "Oʻzgartirish"),
            )?;
        }
        state.vault.set_settings(settings)
    })
    .await
}

/// The body of the confirmation for weakened settings: one line per change.
fn weakening_text(weakened: &[Weakening]) -> Localized {
    let lines: Vec<Localized> = weakened.iter().map(|w| weakening_line(*w)).collect();
    let list = |pick: fn(&Localized) -> &String| {
        lines
            .iter()
            .map(|line| format!("• {}", pick(line)))
            .collect::<Vec<_>>()
            .join("\n")
    };
    Localized::new(
        format!(
            "SSH Key Manager will change these settings:\n\n{}\n\n\
             Continue only if you made this change yourself.",
            list(|l| &l.en)
        ),
        format!(
            "SSH Key Manager изменит эти настройки:\n\n{}\n\n\
             Продолжайте, только если это изменение сделали вы.",
            list(|l| &l.ru)
        ),
        format!(
            "SSH Key Manager quyidagi sozlamalarni oʻzgartiradi:\n\n{}\n\n\
             Bu oʻzgarishni oʻzingiz qilgan boʻlsangizgina davom eting.",
            list(|l| &l.uz)
        ),
    )
}

fn weakening_line(weakening: Weakening) -> Localized {
    match weakening {
        Weakening::AutoLock { old, new: None } => Localized::new(
            format!("Lock when idle: never (was {old} min)"),
            format!("Блокировать при бездействии: никогда (было {old} мин)"),
            format!("Faoliyat boʻlmasa qulflash: hech qachon (avval {old} daqiqa)"),
        ),
        Weakening::AutoLock {
            old,
            new: Some(new),
        } => Localized::new(
            format!("Lock when idle: after {new} min (was {old} min)"),
            format!("Блокировать при бездействии: через {new} мин (было {old} мин)"),
            format!("Faoliyat boʻlmasa qulflash: {new} daqiqadan keyin (avval {old} daqiqa)"),
        ),
        Weakening::Clipboard { old, new: 0 } => Localized::new(
            format!("Clear copied passwords: never (was {old} s)"),
            format!("Очищать скопированные пароли: никогда (было {old} с)"),
            format!("Nusxalangan parollarni tozalash: hech qachon (avval {old} soniya)"),
        ),
        Weakening::Clipboard { old, new } => Localized::new(
            format!("Clear copied passwords: after {new} s (was {old} s)"),
            format!("Очищать скопированные пароли: через {new} с (было {old} с)"),
            format!("Nusxalangan parollarni tozalash: {new} soniyadan keyin (avval {old} soniya)"),
        ),
        Weakening::LockOnSleep => Localized::new(
            "Don’t lock when the computer sleeps",
            "Не блокировать при переходе в сон",
            "Kompyuter uyqu rejimiga oʻtganda qulflamaslik",
        ),
        Weakening::LockOnScreenLock => Localized::new(
            "Don’t lock when the screen locks",
            "Не блокировать вместе с экраном",
            "Ekran qulflanganda qulflamaslik",
        ),
        Weakening::LockOnMinimize => Localized::new(
            "Don’t lock when the window is minimized",
            "Не блокировать при сворачивании окна",
            "Oyna yigʻilganda qulflamaslik",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weakened_settings_are_listed_in_every_language() {
        let text = weakening_text(&[
            Weakening::AutoLock { old: 5, new: None },
            Weakening::Clipboard { old: 30, new: 90 },
            Weakening::LockOnScreenLock,
        ]);
        assert!(text.en.contains("• Lock when idle: never (was 5 min)\n"));
        assert!(
            text.en
                .contains("• Clear copied passwords: after 90 s (was 30 s)\n")
        );
        assert!(text.en.contains("• Don’t lock when the screen locks\n\n"));
        assert!(text.ru.contains("никогда (было 5 мин)"));
        assert!(text.uz.contains("90 soniyadan keyin"));
    }
}
