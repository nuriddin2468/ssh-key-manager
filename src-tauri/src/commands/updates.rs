//! The in-app updater. The page only asks whether a newer release exists and
//! says when to install it; the release server, the public key, headers and
//! proxy all come from `tauri.conf.json`, so script in the page can't point
//! the updater anywhere else.

use std::sync::{Arc, Mutex, PoisonError};

use semver::Version;
use serde::{Deserialize, Serialize};
use sshkm_core::{ErrorCode, fsutil};
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_updater::{Update, UpdaterExt};

use super::{Shared, blocking};
use crate::env_files::EnvFiles;
use crate::error::{AppError, AppResult};

/// The release the last check found, until a later check replaces it.
static PENDING: Mutex<Option<Update>> = Mutex::new(None);

/// At most this many releases, changes per release and characters per note
/// are taken from the release server's `changelog`. Unlike the update
/// itself, `latest.json` isn't signed, so it may not fill the dialog with
/// whatever it likes.
const MAX_RELEASES: usize = 20;
const MAX_CHANGES: usize = 50;
const MAX_TEXT: usize = 1000;

/// A newer version the release server offers.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct UpdateOffer {
    pub version: String,
    /// The notes of every version after this one up to `version`, newest
    /// first, so a user a few releases behind sees what each changed. Empty
    /// if the release server didn't say.
    pub releases: Vec<Release>,
}

/// One version's release notes, as `changelog/releases.json` keeps them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct Release {
    pub version: String,
    /// The day of the release, `YYYY-MM-DD`.
    pub date: String,
    pub changes: Vec<Change>,
}

/// One note, in each language it was written in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct Change {
    pub kind: ChangeKind,
    pub en: String,
    pub ru: Option<String>,
    pub uz: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum ChangeKind {
    /// What to know before updating.
    Notice,
    Security,
    New,
    Fixed,
    /// Also any kind a later version of the app adds (serde wants it last).
    #[serde(other)]
    Improved,
}

/// Asks the release server for a version newer than this one and returns it,
/// or `None` if this is the latest.
#[tauri::command]
pub async fn update_check(app: AppHandle) -> AppResult<Option<UpdateOffer>> {
    let update = app
        .updater()
        .map_err(|e| updater_error(&e))?
        .check()
        .await
        .map_err(|e| updater_error(&e))?;
    let offer = update.as_ref().map(|update| UpdateOffer {
        version: update.version.clone(),
        releases: releases_between(&update.raw_json, &update.current_version, &update.version),
    });
    *PENDING.lock().unwrap_or_else(PoisonError::into_inner) = update;
    Ok(offer)
}

/// Saves a copy of `~/.ssh/config`, `known_hosts` and the vault's files with
/// the other backups, then downloads, verifies and installs the release the
/// last check found and restarts into it. `progress` gets the percentage
/// downloaded whenever it changes, if the server tells the size.
#[tauri::command]
pub async fn update_install(
    app: AppHandle,
    state: State<'_, Shared>,
    progress: Channel<u8>,
) -> AppResult<()> {
    let update = PENDING
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
        .ok_or_else(|| AppError::not_found("no update to install"))?;
    // The update itself leaves these files alone, but a newer version may
    // change them, and an older one may not read them after that.
    blocking(&state, |state| {
        let vault = state.vault.paths();
        for path in [
            &state.paths.config,
            &state.paths.known_hosts,
            &vault.database,
            &vault.keys,
        ] {
            fsutil::backup(path, &state.backup_dir)?;
        }
        Ok(())
    })
    .await?;
    let mut received: u64 = 0;
    let mut reported = None;
    let bytes = update
        .download(
            |chunk, total| {
                received = received.saturating_add(chunk as u64);
                let Some(total) = total.filter(|&total| total > 0) else {
                    return;
                };
                let percent = u8::try_from(received.saturating_mul(100) / total).unwrap_or(100);
                let percent = percent.min(100);
                if reported != Some(percent) {
                    reported = Some(percent);
                    let _ = progress.send(percent);
                }
            },
            // Windows quits into the installer without the app's exit.
            || state.vault.on_exit(),
        )
        .await
        .map_err(|e| updater_error(&e))?;
    // The `.env` files kept only while the vault is unlocked go first, as on
    // any quit: Windows quits into the installer without the app's own way
    // out. They come back if the update doesn't go ahead.
    let files = app
        .try_state::<Arc<EnvFiles>>()
        .map(|files| Arc::clone(&files));
    if let Some(files) = files.clone() {
        let handle = app.clone();
        blocking(&state, move |state| {
            files.put_away_for_update(&handle, state);
            Ok(())
        })
        .await?;
    }
    if let Err(error) = update.install(bytes) {
        if let Some(files) = files {
            files.resume_after_update(&state);
        }
        return Err(updater_error(&error));
    }
    // Windows has already quit into the installer; macOS and Linux restart here.
    app.request_restart();
    Ok(())
}

/// The releases in `manifest`'s `changelog` newer than `current` and no newer
/// than `offered`, newest first. A release or note that doesn't parse, or is
/// too long, is left out rather than failing the check.
fn releases_between(manifest: &serde_json::Value, current: &str, offered: &str) -> Vec<Release> {
    let (Ok(current), Ok(offered)) = (Version::parse(current), Version::parse(offered)) else {
        return Vec::new();
    };
    let Some(listed) = manifest
        .get("changelog")
        .and_then(serde_json::Value::as_array)
    else {
        return Vec::new();
    };
    let mut releases: Vec<(Version, Release)> = listed
        .iter()
        .take(MAX_RELEASES)
        .filter_map(|value| {
            let mut release = Release::deserialize(value).ok()?;
            let version = Version::parse(&release.version).ok()?;
            if version <= current || version > offered || !is_date(&release.date) {
                return None;
            }
            release.changes.truncate(MAX_CHANGES);
            release.changes.retain(|change| {
                [Some(&change.en), change.ru.as_ref(), change.uz.as_ref()]
                    .into_iter()
                    .flatten()
                    .all(|text| text.chars().count() <= MAX_TEXT)
            });
            Some((version, release))
        })
        .collect();
    releases.sort_by(|a, b| b.0.cmp(&a.0));
    releases.dedup_by(|a, b| a.0 == b.0);
    releases.into_iter().map(|(_, release)| release).collect()
}

/// `YYYY-MM-DD`, as the release script writes the date.
fn is_date(text: &str) -> bool {
    text.len() == 10
        && text.bytes().enumerate().all(|(i, byte)| {
            if i == 4 || i == 7 {
                byte == b'-'
            } else {
                byte.is_ascii_digit()
            }
        })
}

fn updater_error(error: &tauri_plugin_updater::Error) -> AppError {
    AppError::new(ErrorCode::Io, error.to_string())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn release(version: &str) -> serde_json::Value {
        json!({
            "version": version,
            "date": "2026-11-06",
            "changes": [{ "kind": "fixed", "en": format!("Fixed in {version}."), "ru": "Исправлено.", "uz": "Tuzatildi." }],
        })
    }

    fn versions(releases: &[Release]) -> Vec<&str> {
        releases
            .iter()
            .map(|release| release.version.as_str())
            .collect()
    }

    #[test]
    fn lists_the_versions_after_this_one_up_to_the_offered_one() {
        let manifest = json!({
            "changelog": [release("0.10.0"), release("0.9.0"), release("0.8.0"), release("0.7.0")],
        });
        let releases = releases_between(&manifest, "0.7.0", "0.9.0");
        assert_eq!(versions(&releases), ["0.9.0", "0.8.0"]);
        assert_eq!(releases[1].changes[0].en, "Fixed in 0.8.0.");
        assert_eq!(releases[1].changes[0].ru.as_deref(), Some("Исправлено."));
    }

    #[test]
    fn sorts_newest_first_and_drops_repeats() {
        let manifest =
            json!({ "changelog": [release("0.8.0"), release("0.9.0"), release("0.8.0")] });
        assert_eq!(
            versions(&releases_between(&manifest, "0.7.0", "0.9.0")),
            ["0.9.0", "0.8.0"]
        );
    }

    #[test]
    fn has_nothing_without_a_changelog() {
        let none: [&str; 0] = [];
        let manifest = json!({ "changelog": [release("0.8.0")] });
        assert_eq!(
            versions(&releases_between(
                &json!({ "notes": "…" }),
                "0.7.0",
                "0.8.0"
            )),
            none
        );
        assert_eq!(
            versions(&releases_between(
                &json!({ "changelog": "…" }),
                "0.7.0",
                "0.8.0"
            )),
            none
        );
        assert_eq!(
            versions(&releases_between(&manifest, "not a version", "0.8.0")),
            none
        );
    }

    #[test]
    fn skips_what_does_not_parse() {
        let manifest = json!({
            "changelog": [
                { "version": "0.9.0" },
                { "version": "soon", "date": "2026-11-06", "changes": [] },
                release("0.8.0"),
            ],
        });
        assert_eq!(
            versions(&releases_between(&manifest, "0.7.0", "0.9.0")),
            ["0.8.0"]
        );
    }

    #[test]
    fn reads_a_later_kind_as_improved_and_a_missing_language_as_none() {
        let manifest = json!({
            "changelog": [{
                "version": "0.8.0",
                "date": "2026-11-06",
                "changes": [{ "kind": "changed", "en": "Works better." }],
            }],
        });
        let releases = releases_between(&manifest, "0.7.0", "0.8.0");
        assert_eq!(releases[0].changes[0].kind, ChangeKind::Improved);
        assert_eq!(releases[0].changes[0].uz, None);
    }

    #[test]
    fn leaves_out_notes_too_long_for_the_dialog() {
        let mut long = release("0.8.0");
        long["changes"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "kind": "new", "en": "a".repeat(MAX_TEXT + 1) }));
        let releases = releases_between(&json!({ "changelog": [long] }), "0.7.0", "0.8.0");
        assert_eq!(releases[0].changes.len(), 1);
    }

    #[test]
    fn reads_the_repository_changelog() {
        let file = include_str!("../../../changelog/releases.json");
        let manifest =
            json!({ "changelog": serde_json::from_str::<serde_json::Value>(file).unwrap() });
        let releases = releases_between(&manifest, "0.0.0", "999.0.0");
        let listed = manifest["changelog"].as_array().unwrap();
        assert_ne!(listed.len(), 0);
        assert_eq!(releases.len(), listed.len().min(MAX_RELEASES));
        for (release, value) in releases.iter().zip(listed) {
            let changes = value["changes"].as_array().unwrap();
            assert_eq!(release.changes.len(), changes.len(), "{}", release.version);
        }
    }
}
