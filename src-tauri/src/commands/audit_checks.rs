//! The audit's fixes of `ssh_config` settings, and its check of saved
//! passwords against known breaches with Have I Been Pwned.
//!
//! The breach check is off until the user turns it on (`breaches.json` in
//! the app's data folder). It runs here, in Rust, so passwords and their
//! hashes never reach the page: only the first five hex characters of each
//! password's SHA-1 hash go to `api.pwnedpasswords.com`, one range at a
//! time and at most [`REQUESTS_PER_SECOND`] a second, and the rest of the
//! hash is compared on this computer (`sshkm_core::vault::BreachQuery`).
//! It runs when the audit reads the vault, for passwords it has no result
//! for, and on demand for all of them. Results stay in memory while the
//! vault is unlocked and are dropped when it locks.

use std::sync::{LazyLock, Mutex, MutexGuard, Once, PoisonError};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sshkm_core::audit::{self, FixAction};
use sshkm_core::config::SshConfig;
use sshkm_core::vault::{
    BreachCache, BreachQuery, MAX_RANGE_BYTES, PADDING_HEADER, RangePrefix, Vault, VaultAuditInput,
    VaultFinding,
};
use sshkm_core::{ErrorCode, fsutil};
use tauri::{AppHandle, Listener, Manager, State};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::config::config_file;
use super::{Shared, blocking};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::types::ConfigFile;

/// Applies a config fix the audit offers (removing a `StrictHostKeyChecking
/// no`, `UserKnownHostsFile /dev/null` or `ForwardAgent` line, or adding
/// `IdentitiesOnly yes`) to the file at `revision`; fails with `conflict`
/// if the file changed since, and with `invalid_input` if the audit doesn't
/// offer that fix for it.
#[tauri::command]
pub async fn fix_config(
    state: State<'_, Shared>,
    fix: FixAction,
    revision: String,
) -> AppResult<ConfigFile> {
    blocking(&state, move |state| {
        let mut config = SshConfig::load(&state.paths.config)?;
        fsutil::ensure_revision(&state.paths.config, &config.revision(), &revision)?;
        if audit::apply_config_fix(&mut config, &fix)? {
            config.save(&state.paths.config, &state.backup_dir)?;
        }
        config_file(state)
    })
    .await
}

/// Ranges asked for each second, at most.
const REQUESTS_PER_SECOND: u32 = 10;
/// Results are checked again by the audit after this long.
const REFRESH_AFTER: Duration = Duration::from_secs(24 * 60 * 60);
/// After a check failed, the audit waits this long before it tries again.
const RETRY_AFTER: Duration = Duration::from_secs(5 * 60);
const SETTINGS_FILE: &str = "breaches.json";

/// Why a breach check stopped before it was done.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum BreachError {
    /// No connection, or no answer in time.
    Offline,
    /// The service asked to slow down (HTTP 429).
    RateLimited,
    /// The service answered with another error.
    Server,
    /// The answer wasn't a range.
    BadResponse,
}

/// The breach check as the page shows it. Never a password or a hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct BreachStatus {
    /// The user turned the check on; it is off by default.
    pub enabled: bool,
    /// A check is running.
    pub running: bool,
    /// Passwords the running or last check looked up, of `total`.
    pub done: u32,
    pub total: u32,
    /// When a check last finished (RFC 3339), since the vault was unlocked.
    pub checked_at: Option<String>,
    /// Why the last check stopped early.
    pub error: Option<BreachError>,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Settings {
    enabled: bool,
}

/// The check's state: the setting, the results and the running check.
#[derive(Default)]
struct Breaches {
    /// Read from [`SETTINGS_FILE`] on first use.
    enabled: Option<bool>,
    cache: BreachCache,
    /// Bumped by each check and when results are dropped, so an older
    /// check stops.
    generation: u64,
    running: bool,
    done: u32,
    total: u32,
    checked_at: Option<OffsetDateTime>,
    error: Option<BreachError>,
    /// The audit starts no check before this, after one failed.
    retry_at: Option<Instant>,
}

static BREACHES: LazyLock<Mutex<Breaches>> = LazyLock::new(Mutex::default);
static WATCH_LOCK: Once = Once::new();

fn breaches(app: &AppHandle) -> MutexGuard<'static, Breaches> {
    // Results go when the vault locks, as the vault itself does.
    WATCH_LOCK.call_once(|| {
        app.listen_any(crate::vault::LOCKED_EVENT, |_| forget());
    });
    BREACHES.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Drops the results and stops a running check.
fn forget() {
    let mut breaches = BREACHES.lock().unwrap_or_else(PoisonError::into_inner);
    let enabled = breaches.enabled;
    let generation = breaches.generation + 1;
    *breaches = Breaches {
        enabled,
        generation,
        ..Breaches::default()
    };
}

impl Breaches {
    fn enabled(&mut self, state: &AppState) -> bool {
        *self.enabled.get_or_insert_with(|| {
            std::fs::read(state.vault.data_dir().join(SETTINGS_FILE))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Settings>(&bytes).ok())
                .is_some_and(|settings| settings.enabled)
        })
    }

    fn status(&mut self, state: &AppState) -> BreachStatus {
        BreachStatus {
            enabled: self.enabled(state),
            running: self.running,
            done: self.done,
            total: self.total,
            checked_at: self.checked_at.and_then(|t| t.format(&Rfc3339).ok()),
            error: self.error,
        }
    }

    /// Starts checking `query` in the background.
    fn start(&mut self, app: &AppHandle, query: BreachQuery) {
        self.generation += 1;
        self.done = 0;
        self.total = u32::try_from(query.passwords()).unwrap_or(u32::MAX);
        self.error = None;
        self.retry_at = None;
        if query.is_empty() {
            self.running = false;
            self.checked_at = Some(OffsetDateTime::now_utc());
            return;
        }
        self.running = true;
        tauri::async_runtime::spawn(check(app.clone(), self.generation, query));
    }

    fn finish(&mut self, error: Option<BreachError>) {
        self.running = false;
        self.error = error;
        self.checked_at = Some(OffsetDateTime::now_utc());
        self.retry_at = error.map(|_| Instant::now() + RETRY_AFTER);
    }
}

/// The vault's findings for the audit, with breached passwords while the
/// check is on. Starts a check of the passwords that have no result yet (or
/// an old one), unless one is running or failed a moment ago.
pub fn vault_findings(
    app: &AppHandle,
    state: &AppState,
    vault: &Vault,
    input: &VaultAuditInput<'_>,
) -> Vec<VaultFinding> {
    let mut breaches = breaches(app);
    if !breaches.enabled(state) {
        return vault.audit(input);
    }
    let findings = vault.audit(&VaultAuditInput {
        breaches: Some(&breaches.cache),
        ..*input
    });
    let now = Instant::now();
    if !breaches.running && breaches.retry_at.is_none_or(|at| now >= at) {
        let query = vault.breach_query(&breaches.cache, now.checked_sub(REFRESH_AFTER));
        if !query.is_empty() {
            breaches.start(app, query);
        }
    }
    findings
}

/// The audit found the vault locked: nothing of its passwords stays.
pub fn vault_locked() {
    forget();
}

#[tauri::command]
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri passes command arguments by value"
)]
pub fn breach_status(app: AppHandle, state: State<'_, Shared>) -> BreachStatus {
    breaches(&app).status(&state)
}

/// Turns the breach check on or off and saves the choice. Turning it on
/// checks the passwords at once if the vault is unlocked; turning it off
/// stops a check and drops the results.
#[tauri::command]
pub async fn breach_set_enabled(
    app: AppHandle,
    state: State<'_, Shared>,
    enabled: bool,
) -> AppResult<BreachStatus> {
    blocking(&state, move |state| {
        let mut json = serde_json::to_vec_pretty(&Settings { enabled })
            .map_err(|e| AppError::new(ErrorCode::Io, e.to_string()))?;
        json.push(b'\n');
        fsutil::atomic_write(&state.vault.data_dir().join(SETTINGS_FILE), &json, 0o600)?;
        if !enabled {
            forget();
        }
        breaches(&app).enabled = Some(enabled);
        if enabled && state.vault.is_unlocked() {
            start_now(&app, state, false)?;
        }
        Ok(breaches(&app).status(state))
    })
    .await
}

/// Checks every password again now, unless a check is running. Fails with
/// `invalid_input` while the check is off and `vault_locked` while the
/// vault is locked.
#[tauri::command]
pub async fn breach_check(app: AppHandle, state: State<'_, Shared>) -> AppResult<BreachStatus> {
    blocking(&state, move |state| {
        if !breaches(&app).enabled(state) {
            return Err(AppError::invalid("the breach check is off"));
        }
        start_now(&app, state, true)?;
        Ok(breaches(&app).status(state))
    })
    .await
}

/// Starts a check of the passwords without a result, or of all of them.
fn start_now(app: &AppHandle, state: &AppState, all: bool) -> AppResult<()> {
    state.vault.with_quietly(app, |vault| {
        let mut breaches = breaches(app);
        if !breaches.running {
            let stale_before = if all {
                Some(Instant::now())
            } else {
                Instant::now().checked_sub(REFRESH_AFTER)
            };
            let query = vault.breach_query(&breaches.cache, stale_before);
            breaches.start(app, query);
        }
        Ok(())
    })
}

/// Asks for each range of `query` in turn and records the answers, until
/// done, an error, or a newer check, turning off or locking (which drop the
/// results) stops it.
async fn check(app: AppHandle, generation: u64, mut query: BreachQuery) {
    let current = || BREACHES.lock().unwrap_or_else(PoisonError::into_inner);
    let client = match client() {
        Ok(client) => client,
        Err(error) => {
            log::warn!("breach check: no HTTP client: {error}");
            let mut breaches = current();
            if breaches.generation == generation {
                breaches.finish(Some(BreachError::Offline));
            }
            return;
        }
    };
    let pause = Duration::from_secs(1) / REQUESTS_PER_SECOND;
    let mut last: Option<Instant> = None;
    for prefix in query.prefixes() {
        if !app.state::<Shared>().vault.is_unlocked() {
            forget();
            return;
        }
        if current().generation != generation {
            return;
        }
        if let Some(last) = last {
            tokio::time::sleep(pause.saturating_sub(last.elapsed())).await;
        }
        last = Some(Instant::now());
        let answer = fetch(&client, &prefix).await;
        let mut breaches = current();
        if breaches.generation != generation {
            return;
        }
        let recorded = answer.and_then(|body| {
            query
                .answer(&prefix, &body, &mut breaches.cache, Instant::now())
                .map_err(|_| BreachError::BadResponse)
        });
        match recorded {
            Ok(count) => {
                breaches.done = breaches
                    .done
                    .saturating_add(u32::try_from(count).unwrap_or(u32::MAX));
            }
            Err(error) => {
                // The prefix is part of a password's hash: it isn't logged.
                log::warn!("breach check stopped: {error:?}");
                breaches.finish(Some(error));
                return;
            }
        }
    }
    let mut breaches = current();
    if breaches.generation == generation {
        breaches.finish(None);
    }
}

fn client() -> reqwest::Result<reqwest::Client> {
    // The updater's TLS (rustls without a default provider): use the same
    // provider it installs.
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .user_agent("SSH-Key-Manager")
        .build()
}

/// The server's answer for one range, read up to [`MAX_RANGE_BYTES`].
async fn fetch(client: &reqwest::Client, prefix: &RangePrefix) -> Result<String, BreachError> {
    let mut response = client
        .get(prefix.url())
        .header(PADDING_HEADER.0, PADDING_HEADER.1)
        .send()
        .await
        .map_err(|_| BreachError::Offline)?;
    let status = response.status();
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Err(BreachError::RateLimited);
    }
    if !status.is_success() {
        return Err(BreachError::Server);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| BreachError::Offline)? {
        if body.len() + chunk.len() > MAX_RANGE_BYTES {
            return Err(BreachError::BadResponse);
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|_| BreachError::BadResponse)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forgetting_keeps_the_setting_and_stops_a_check() {
        {
            let mut breaches = BREACHES.lock().unwrap();
            breaches.enabled = Some(true);
            breaches.running = true;
            breaches.generation = 7;
            breaches.done = 3;
            breaches.checked_at = Some(OffsetDateTime::now_utc());
            breaches.error = Some(BreachError::Offline);
        }
        forget();
        let breaches = BREACHES.lock().unwrap();
        assert_eq!(breaches.enabled, Some(true));
        assert_eq!(breaches.generation, 8);
        assert!(!breaches.running && breaches.done == 0 && breaches.error.is_none());
        assert!(breaches.checked_at.is_none() && breaches.cache.is_empty());
    }

    #[test]
    fn the_status_names_no_secret() {
        let status = BreachStatus {
            enabled: true,
            running: false,
            done: 2,
            total: 3,
            checked_at: None,
            error: Some(BreachError::RateLimited),
        };
        assert_eq!(
            serde_json::to_value(&status).unwrap(),
            serde_json::json!({
                "enabled": true,
                "running": false,
                "done": 2,
                "total": 3,
                "checkedAt": null,
                "error": "rateLimited",
            })
        );
    }
}
