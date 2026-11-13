//! "Show in Finder" (Explorer, Files) for the files the app works with. The
//! page names a place, or a key or a leak finding by its id; the path is
//! looked up on this side, so the page can't make the file manager open a
//! path it made up (a network share, say). A project's folders are shown
//! by `projects_reveal_folder`, the same way.

use std::path::PathBuf;

use serde::Deserialize;
use sshkm_core::ErrorCode;
use tauri::{AppHandle, State};

use super::keys::find_key;
use super::{Shared, blocking};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// What to show in the file manager.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum RevealPlace {
    /// `~/.ssh`.
    SshDir,
    /// `~/.ssh/config`.
    Config,
    /// `~/.ssh/known_hosts`.
    KnownHosts,
    /// The system's hosts file.
    HostsFile,
    /// The app's backups folder.
    Backups,
    /// The vault's database file.
    Vault,
    /// A key in `~/.ssh`, by its id: its private key, else its public one.
    Key { id: String },
    /// The file of a finding of the last leak scan, by its id.
    Leak { id: String },
}

/// Shows `place` in the file manager, selected.
#[tauri::command]
pub async fn reveal_place(
    app: AppHandle,
    state: State<'_, Shared>,
    place: RevealPlace,
) -> AppResult<()> {
    let leak = match &place {
        RevealPlace::Leak { id } => Some(
            super::leaks::leaks_findings(app.clone(), state.clone())
                .into_iter()
                .find(|finding| &finding.id == id)
                .map(|finding| PathBuf::from(finding.path))
                .ok_or_else(|| AppError::not_found("that finding"))?,
        ),
        _ => None,
    };
    blocking(&state, move |state| {
        let path = match leak {
            Some(path) => path,
            None => place_path(state, &place)?,
        };
        tauri_plugin_opener::reveal_item_in_dir(&path)
            .map_err(|error| AppError::new(ErrorCode::Io, error.to_string()))
    })
    .await
}

/// Where `place` is on this computer. Leak findings are looked up by the
/// command, which holds what the last scan found.
fn place_path(state: &AppState, place: &RevealPlace) -> AppResult<PathBuf> {
    Ok(match place {
        RevealPlace::SshDir => state.paths.dir.clone(),
        RevealPlace::Config => state.paths.config.clone(),
        RevealPlace::KnownHosts => state.paths.known_hosts.clone(),
        RevealPlace::HostsFile => state.hosts_file.clone(),
        RevealPlace::Backups => state.backup_dir.clone(),
        RevealPlace::Vault => state.vault.paths().database,
        RevealPlace::Key { id } => {
            let key = find_key(state, id)?;
            key.private_path
                .or(key.public_path)
                .map(PathBuf::from)
                .ok_or_else(|| AppError::not_found(format!("key {id}")))?
        }
        RevealPlace::Leak { .. } => return Err(AppError::not_found("that finding")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn places_are_named_not_given_as_paths() {
        let place = |json: serde_json::Value| serde_json::from_value::<RevealPlace>(json);
        assert_eq!(
            place(serde_json::json!({ "kind": "knownHosts" })).unwrap(),
            RevealPlace::KnownHosts
        );
        assert_eq!(
            place(serde_json::json!({ "kind": "key", "id": "id_ed25519" })).unwrap(),
            RevealPlace::Key {
                id: "id_ed25519".into()
            }
        );
        // There is no place that takes a path.
        assert!(place(serde_json::json!({ "kind": "path", "path": "/etc" })).is_err());
        assert!(place(serde_json::json!("\\\\server\\share\\x")).is_err());
    }
}
