//! Importing the logins a browser keeps, straight from its profile (see
//! [`sshkm_core::vault::BrowserProfile`]).
//!
//! Like the CSV import it takes two steps, but reading a browser may need
//! the user's permission in a system prompt (macOS Keychain, Secret Service,
//! `KWallet`), so the logins are read once, for the preview, and kept here
//! until they are imported, for at most [`KEEP_FOR`]. They are dropped (and
//! wiped) when they are imported, when the dialog closes
//! ([`vault_browser_import_forget`]), when another profile is read, and when
//! the vault locks. The page names a profile only by the id
//! [`vault_browser_profiles`] gave it; its folder never leaves this side.

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde::Serialize;
use sshkm_core::SecretString;
use sshkm_core::vault::{
    BrowserKeyStore, BrowserLogins, BrowserProfile, BrowserReadError, ImportPreview, SafeStorage,
    browser_profiles,
};
use sshkm_os::secrecy::zeroize::Zeroizing;
use tauri::{AppHandle, State};

use super::{Shared, blocking};
use crate::error::{AppError, AppResult};

/// How long logins read for a preview are kept for the import.
const KEEP_FOR: Duration = Duration::from_secs(15 * 60);

/// The logins read for the last preview: from which profile, and when.
static READ: Mutex<Option<Held>> = Mutex::new(None);

struct Held {
    logins: BrowserLogins,
    at: Instant,
}

/// What reading a browser profile came to. Only `preview` carries logins,
/// and those without secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
// Made once per preview and sent straight to the page; never stored.
#[allow(clippy::large_enum_variant)]
pub enum BrowserImport {
    #[serde(rename_all = "camelCase")]
    Preview {
        profile: BrowserProfile,
        preview: ImportPreview,
        /// Logins that could not be decrypted (app-bound ones included).
        unreadable: u32,
        /// Logins only Chrome itself can decrypt (Windows, Chrome 127+).
        app_bound: u32,
    },
    /// The user refused the system's request for the browser's key.
    Denied,
    /// The system has no key for the browser.
    KeyUnavailable,
    /// Every login is encrypted with Chrome's app-bound key.
    AppBound,
    /// The Firefox profile has a primary password; ask for it.
    PrimaryPasswordRequired,
    /// The primary password given is wrong.
    WrongPrimaryPassword,
    /// The profile is encrypted in a way this app can't read.
    Unsupported,
}

/// The browser profiles on this computer with saved logins.
#[tauri::command]
pub async fn vault_browser_profiles(state: State<'_, Shared>) -> AppResult<Vec<BrowserProfile>> {
    blocking(&state, |_| Ok(browser_profiles())).await
}

/// Reads the saved logins of the profile `profile_id` and lists them like a
/// CSV preview, without secrets. May show a system prompt for the browser's
/// key; a Firefox profile with a primary password needs `primary_password`.
#[tauri::command]
pub async fn vault_browser_import_preview(
    app: AppHandle,
    state: State<'_, Shared>,
    profile_id: String,
    primary_password: Option<SecretString>,
) -> AppResult<BrowserImport> {
    blocking(&state, move |state| {
        // Nothing is read, and no prompt shown, while the vault is locked.
        state.vault.with(&app, |_| Ok(()))?;
        forget();
        let profile = browser_profiles()
            .into_iter()
            .find(|p| p.id == profile_id)
            .ok_or_else(|| AppError::not_found("that browser profile"))?;
        let logins = match profile.read(&OsKeys, primary_password.as_ref()) {
            Ok(logins) => logins,
            Err(error) => {
                log::info!("browser import from {}: {error}", profile.browser);
                return outcome(error);
            }
        };
        let preview = state
            .vault
            .with(&app, |vault| Ok(vault.browser_import_preview(&logins)))?;
        let unreadable = logins.unreadable();
        let app_bound = logins.app_bound();
        *held() = Some(Held {
            logins,
            at: Instant::now(),
        });
        Ok(BrowserImport::Preview {
            profile,
            preview,
            unreadable,
            app_bound,
        })
    })
    .await
}

/// Imports the logins at `indices` (from the preview) and returns how many
/// entries were added.
#[tauri::command]
pub async fn vault_browser_import(
    app: AppHandle,
    state: State<'_, Shared>,
    indices: Vec<u32>,
) -> AppResult<usize> {
    if indices.is_empty() {
        return Err(AppError::invalid("choose at least one login to import"));
    }
    blocking(&state, move |state| {
        let mut held = held();
        let logins = match held.take() {
            Some(read) if read.at.elapsed() <= KEEP_FOR => read.logins,
            _ => return Err(AppError::invalid("read the browser's logins again")),
        };
        let result = state.vault.change(&app, &state.backup_dir, |vault| {
            Ok(vault.import_browser(&logins, &indices)?)
        });
        if result.is_err() {
            // To try again, e.g. after unlocking.
            *held = Some(Held {
                logins,
                at: Instant::now(),
            });
        }
        result
    })
    .await
}

/// Drops the logins read for a preview: the dialog closed or went back.
#[tauri::command]
pub fn vault_browser_import_forget() {
    forget();
}

/// Drops (and wipes) the logins read for a preview.
pub fn forget() {
    held().take();
}

fn held() -> MutexGuard<'static, Option<Held>> {
    READ.lock().unwrap_or_else(PoisonError::into_inner)
}

fn outcome(error: BrowserReadError) -> AppResult<BrowserImport> {
    Ok(match error {
        BrowserReadError::Denied => BrowserImport::Denied,
        BrowserReadError::KeyUnavailable(_) => BrowserImport::KeyUnavailable,
        BrowserReadError::AppBound => BrowserImport::AppBound,
        BrowserReadError::PrimaryPasswordRequired => BrowserImport::PrimaryPasswordRequired,
        BrowserReadError::WrongPrimaryPassword => BrowserImport::WrongPrimaryPassword,
        BrowserReadError::Other(error) => return Err(error.into()),
        // `Unsupported`, and whatever a later version adds.
        _ => BrowserImport::Unsupported,
    })
}

/// The system's key stores, through `sshkm-os`.
struct OsKeys;

impl BrowserKeyStore for OsKeys {
    fn safe_storage(
        &self,
        storage: &SafeStorage,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, BrowserReadError> {
        sshkm_os::browser_keys::safe_storage(storage.service, storage.account, storage.application)
            .map_err(os_error)
    }

    fn unprotect(&self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, BrowserReadError> {
        sshkm_os::browser_keys::unprotect(blob).map_err(os_error)
    }
}

fn os_error(error: sshkm_os::Error) -> BrowserReadError {
    match error {
        sshkm_os::Error::Cancelled => BrowserReadError::Denied,
        other => BrowserReadError::KeyUnavailable(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_errors_become_outcomes_without_details() {
        let cases = [
            (BrowserReadError::Denied, "denied"),
            (
                BrowserReadError::KeyUnavailable("x".into()),
                "keyUnavailable",
            ),
            (BrowserReadError::AppBound, "appBound"),
            (
                BrowserReadError::PrimaryPasswordRequired,
                "primaryPasswordRequired",
            ),
            (
                BrowserReadError::WrongPrimaryPassword,
                "wrongPrimaryPassword",
            ),
            (BrowserReadError::Unsupported("x".into()), "unsupported"),
        ];
        for (error, kind) in cases {
            let json = serde_json::to_value(outcome(error).unwrap()).unwrap();
            assert_eq!(json, serde_json::json!({ "kind": kind }));
        }
        let error = outcome(sshkm_core::Error::NotFound("x".into()).into()).unwrap_err();
        assert_eq!(error.code(), sshkm_core::ErrorCode::NotFound);
    }

    #[test]
    fn refusing_the_prompt_is_denied() {
        assert!(matches!(
            os_error(sshkm_os::Error::Cancelled),
            BrowserReadError::Denied
        ));
        assert!(matches!(
            os_error(sshkm_os::Error::Unavailable("no keyring".into())),
            BrowserReadError::KeyUnavailable(_)
        ));
    }
}
