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
//!
//! Not every system asks before another app reads a browser's passwords
//! (Firefox never does without a primary password; Chromium doesn't on
//! Windows or with an open Linux keyring), so this side asks first, in a
//! native dialog naming the browser and the profile ([`confirm_read`]). The
//! yes holds for that profile until the dialog closes or the vault locks.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde::Serialize;
use sshkm_core::SecretString;
use sshkm_core::vault::{
    BrowserKeyStore, BrowserLogins, BrowserProfile, BrowserReadError, ImportOutcome, ImportPreview,
    SafeStorage, browser_profiles,
};
use sshkm_os::secrecy::ExposeSecret;
use sshkm_os::secrecy::zeroize::Zeroizing;
use tauri::{AppHandle, State};

use super::vault_files::ImportPasswords;
use super::{Shared, blocking};
use crate::confirm::{self, Localized};
use crate::error::{AppError, AppResult};

/// How long logins read for a preview are kept for the import.
const KEEP_FOR: Duration = Duration::from_secs(15 * 60);

/// The logins read for the last preview: from which profile, and when.
static READ: Mutex<Option<Held>> = Mutex::new(None);
/// The profile the user let the app read in the native dialog, by id.
static ALLOWED: Mutex<Option<String>> = Mutex::new(None);
/// Counts [`forget`] calls, so logins taken out to work with are not put
/// back after the vault locked in the meantime.
static FORGOTTEN: AtomicU64 = AtomicU64::new(0);

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
/// CSV preview, without secrets, once the user said yes in a native dialog
/// ([`confirm_read`]). May show a system prompt for the browser's key, too;
/// a Firefox profile with a primary password needs `primary_password`.
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
        drop_read();
        // Asking and reading may wait on the user; kept only if nothing was
        // forgotten (the vault didn't lock) meanwhile.
        let epoch = FORGOTTEN.load(Ordering::SeqCst);
        let profile = browser_profiles()
            .into_iter()
            .find(|p| p.id == profile_id)
            .ok_or_else(|| AppError::not_found("that browser profile"))?;
        if !allowed(&profile.id) {
            confirm_read(&app, &profile)?;
            // Not read if the vault locked while the dialog was open.
            state.vault.with(&app, |_| Ok(()))?;
            allow(&profile.id, epoch);
        }
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
        put_back(
            Held {
                logins,
                at: Instant::now(),
            },
            epoch,
        );
        Ok(BrowserImport::Preview {
            profile,
            preview,
            unreadable,
            app_bound,
        })
    })
    .await
}

/// Imports the logins at `indices` (from the preview): new ones as entries,
/// changed passwords onto the entries they update.
#[tauri::command]
pub async fn vault_browser_import(
    app: AppHandle,
    state: State<'_, Shared>,
    indices: Vec<u32>,
) -> AppResult<ImportOutcome> {
    if indices.is_empty() {
        return Err(AppError::invalid("choose at least one login to import"));
    }
    blocking(&state, move |state| {
        // Taken out, not held under the lock: locking the vault forgets them.
        let (read, epoch) = take_fresh()?;
        let result = state.vault.change(&app, &state.backup_dir, |vault| {
            Ok(vault.import_browser(&read.logins, &indices)?)
        });
        if result.is_err() {
            // To try again, unless the vault locked meanwhile.
            put_back(read, epoch);
        }
        result
    })
    .await
}

/// Both passwords of the login at `index` of the last preview, for the user
/// to compare. Only for a login whose entry has another password; see
/// [`sshkm_core::vault::Vault::browser_import_compare`].
#[tauri::command]
pub async fn vault_browser_import_compare(
    app: AppHandle,
    state: State<'_, Shared>,
    index: u32,
) -> AppResult<ImportPasswords> {
    blocking(&state, move |state| {
        // The vault's password, shown: past a few a minute, each is asked for.
        crate::secret_gate::take_secret(
            &app,
            crate::secret_gate::Taking::Show,
            &crate::secret_gate::import_password(),
        )?;
        let (read, epoch) = take_fresh()?;
        let result = state.vault.with(&app, |vault| {
            let both = vault.browser_import_compare(&read.logins, index)?;
            Ok(ImportPasswords {
                file: both.file.expose_secret().to_owned(),
                vault: both.vault.expose_secret().to_owned(),
            })
        });
        put_back(read, epoch);
        result
    })
    .await
}

/// Drops the logins read for a preview, and the user's yes to reading the
/// profile: the dialog closed or went back.
#[tauri::command]
pub fn vault_browser_import_forget() {
    forget();
}

/// Drops (and wipes) the logins read for a preview, and the user's yes to
/// reading the profile: the vault locked or unlocked, the dialog closed.
pub fn forget() {
    drop_read();
    allowed_profile().take();
}

/// Drops (and wipes) the logins read for a preview.
fn drop_read() {
    FORGOTTEN.fetch_add(1, Ordering::SeqCst);
    held().take();
}

/// Asks the user in a native dialog whether to read the logins saved in
/// `profile`, naming the browser and the profile as the browser's files
/// name it. Fails with `cancelled` on a no.
fn confirm_read(app: &AppHandle, profile: &BrowserProfile) -> AppResult<()> {
    let (title, body) = read_question(&profile.browser, &profile.name);
    confirm::require(
        app,
        &title,
        &body,
        &Localized::new("Read logins", "Прочитать логины", "Loginlarni oʻqish"),
    )
}

/// The dialog's title and text for reading `browser`'s profile `profile`.
fn read_question(browser: &str, profile: &str) -> (Localized, Localized) {
    let browser = confirm::shown(browser, 60);
    let profile = confirm::shown(profile, 80);
    (
        Localized::new(
            format!("Read the logins saved in {browser}?"),
            format!("Прочитать логины, сохранённые в {browser}?"),
            format!("{browser}’da saqlangan loginlar oʻqilsinmi?"),
        ),
        Localized::new(
            format!(
                "SSH Key Manager will read the user names and passwords saved in the {browser} \
                 profile “{profile}”, to list them for import. Nothing is imported until you \
                 choose.\n\nContinue only if you started this import yourself."
            ),
            format!(
                "SSH Key Manager прочитает имена пользователей и пароли, сохранённые в профиле \
                 {browser} «{profile}», чтобы показать их для импорта. Ничего не импортируется, \
                 пока вы не выберете.\n\nПродолжайте, только если импорт начали вы."
            ),
            format!(
                "SSH Key Manager {browser}’ning «{profile}» profilida saqlangan foydalanuvchi \
                 nomlari va parollarni import uchun roʻyxatga chiqarish maqsadida oʻqiydi. Siz \
                 tanlamaguningizcha hech narsa import qilinmaydi.\n\nBu importni oʻzingiz \
                 boshlagan boʻlsangizgina davom eting."
            ),
        ),
    )
}

/// The user said yes to reading the profile `id`, and hasn't closed the
/// dialog nor locked the vault since.
fn allowed(id: &str) -> bool {
    allowed_profile().as_deref() == Some(id)
}

/// Keeps the user's yes to reading the profile `id`, given to a question
/// asked at `epoch`, unless the logins were forgotten since.
fn allow(id: &str, epoch: u64) {
    let mut allowed = allowed_profile();
    if FORGOTTEN.load(Ordering::SeqCst) == epoch {
        *allowed = Some(id.to_owned());
    }
}

fn allowed_profile() -> MutexGuard<'static, Option<String>> {
    ALLOWED.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Takes out the logins read for the last preview, if they are not too old,
/// with the [`FORGOTTEN`] count to give [`put_back`].
fn take_fresh() -> AppResult<(Held, u64)> {
    let mut held = held();
    let epoch = FORGOTTEN.load(Ordering::SeqCst);
    match held.take() {
        Some(read) if read.at.elapsed() <= KEEP_FOR => Ok((read, epoch)),
        _ => Err(AppError::invalid("read the browser's logins again")),
    }
}

/// Puts back logins taken out with [`take_fresh`], unless they were
/// forgotten since (the vault locked, the dialog closed) or others were read.
fn put_back(read: Held, epoch: u64) {
    let mut held = held();
    if FORGOTTEN.load(Ordering::SeqCst) == epoch && held.is_none() {
        *held = Some(read);
    }
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
    fn logins_taken_out_are_not_put_back_once_forgotten() {
        let empty = || BrowserLogins::empty(sshkm_core::vault::CsvFormat::Chrome);
        forget();
        put_back(held_now(empty()), FORGOTTEN.load(Ordering::SeqCst));
        let (read, epoch) = take_fresh().unwrap();
        // The vault locks while they are out.
        forget();
        put_back(read, epoch);
        assert!(take_fresh().is_err());
    }

    fn held_now(logins: BrowserLogins) -> Held {
        Held {
            logins,
            at: Instant::now(),
        }
    }

    #[test]
    fn reading_a_profile_names_the_browser_and_the_profile() {
        let (title, body) = read_question("Firefox", "default-release");
        assert_eq!(title.en, "Read the logins saved in Firefox?");
        assert!(body.en.contains("the Firefox profile “default-release”"));
        assert!(body.ru.contains("профиле Firefox «default-release»"));
        assert!(body.uz.contains("Firefox’ning «default-release» profilida"));
        // A profile's name is the browser's to choose: it can't add lines or
        // turn the text around.
        let (_, body) = read_question("Google Chrome", "Work\n\nNothing is read\u{202E}");
        assert!(
            body.en
                .contains("“Work<U+000A><U+000A>Nothing is read<U+202E>”")
        );
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
