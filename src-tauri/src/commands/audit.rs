use std::path::Path;

use sshkm_core::audit::{self, AuditReport};
use sshkm_core::perms;
use tauri::State;

use super::{Shared, blocking};
use crate::error::{AppError, AppResult};
use crate::types::PermissionFix;

#[tauri::command]
pub async fn run_audit(state: State<'_, Shared>) -> AppResult<AuditReport> {
    blocking(&state, |state| Ok(audit::run_for_paths(&state.paths)?)).await
}

/// Applies permission fixes and returns how many paths were fixed. Only paths
/// inside the `.ssh` directory are accepted.
#[tauri::command]
pub async fn fix_permissions(
    state: State<'_, Shared>,
    items: Vec<PermissionFix>,
) -> AppResult<u32> {
    blocking(&state, move |state| {
        let mut fixed = 0;
        for item in items {
            let path = Path::new(&item.path);
            if !(path == state.paths.dir || path.starts_with(&state.paths.dir)) {
                return Err(AppError::invalid(format!(
                    "{} is outside {}",
                    item.path,
                    state.paths.dir.display()
                )));
            }
            perms::fix(path, item.kind)?;
            fixed += 1;
        }
        Ok(fixed)
    })
    .await
}
