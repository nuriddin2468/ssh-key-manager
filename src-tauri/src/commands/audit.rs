use std::path::Path;

use sshkm_core::audit::{self, AuditReport, FixAction};
use sshkm_core::perms;
use tauri::State;

use super::{Shared, blocking};
use crate::error::AppResult;
use crate::nearby::SharedNearby;
use crate::state::AppState;
use crate::types::PermissionFix;

/// Runs the audit. Public keys received through Nearby are other people's,
/// so they aren't reported for lacking a private key.
#[tauri::command]
pub async fn run_audit(
    state: State<'_, Shared>,
    nearby: State<'_, SharedNearby>,
) -> AppResult<AuditReport> {
    let others = nearby.received_keys();
    blocking(&state, move |state| {
        Ok(audit::run_for_paths(
            &state.paths,
            &state.hosts_file,
            &others,
        )?)
    })
    .await
}

/// Applies permission fixes and returns how many paths were fixed.
///
/// Only fixes the audit offers right now are applied: the audit runs again
/// and an item is fixed only if it names the path and kind of one of its
/// `fixPermissions` actions. Others (made up, or fixed meanwhile) are skipped.
#[tauri::command]
pub async fn fix_permissions(
    state: State<'_, Shared>,
    items: Vec<PermissionFix>,
) -> AppResult<u32> {
    blocking(&state, move |state| apply_offered(state, &items)).await
}

fn apply_offered(state: &AppState, items: &[PermissionFix]) -> AppResult<u32> {
    // Received keys change no permission fix.
    let report = audit::run_for_paths(&state.paths, &state.hosts_file, &[])?;
    let offered = report
        .findings
        .into_iter()
        .filter_map(|finding| match finding.fix {
            Some(FixAction::FixPermissions { path, target }) => Some((path, target)),
            _ => None,
        });
    let mut fixed = 0;
    for (path, kind) in offered {
        if items
            .iter()
            .any(|item| item.path == path && item.kind == kind)
        {
            // The audit's paths are in `.ssh`; checked again all the same.
            perms::fix_inside(&state.paths.dir, Path::new(&path), kind)?;
            fixed += 1;
        }
    }
    Ok(fixed)
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use sshkm_core::keys::{self, GenerateAlgorithm, GenerateRequest};
    use sshkm_core::paths::SshPaths;
    use sshkm_core::perms::PermKind;

    use super::*;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn applies_only_what_the_audit_offers() {
        let home = tempfile::tempdir().unwrap();
        let ssh = home.path().join(".ssh");
        let info = keys::generate(
            &ssh,
            &GenerateRequest {
                algorithm: GenerateAlgorithm::Ed25519,
                file_name: "id".into(),
                comment: String::new(),
                passphrase: None,
            },
        )
        .unwrap();
        let key = info.private_path.unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        let outside = home.path().join("credentials");
        fs::write(&outside, "x").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o666)).unwrap();
        let state = AppState::new(
            SshPaths::with_home(home.path(), &ssh),
            home.path().join("hosts"),
            home.path().join("backups"),
            home.path().join("data"),
        );
        let item = |path: String, kind| PermissionFix { path, kind };
        let dotdot = format!("{}/../credentials", ssh.display());

        let made_up = [
            item(outside.display().to_string(), PermKind::PublicKey),
            item(dotdot, PermKind::Config),
            item(home.path().display().to_string(), PermKind::SshDir),
            // The audit's path with another kind.
            item(key.clone(), PermKind::PublicKey),
        ];
        assert_eq!(apply_offered(&state, &made_up).unwrap(), 0);
        assert_eq!(mode(&outside), 0o666);
        assert_eq!(mode(Path::new(&key)), 0o644);

        assert_eq!(
            apply_offered(&state, &[item(key.clone(), PermKind::PrivateKey)]).unwrap(),
            1
        );
        assert_eq!(mode(Path::new(&key)), 0o600);
        // Fixed already: nothing is offered any more.
        assert_eq!(
            apply_offered(&state, &[item(key, PermKind::PrivateKey)]).unwrap(),
            0
        );
    }
}
