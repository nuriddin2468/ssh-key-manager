use tauri::State;

use super::{Shared, blocking};
use crate::error::AppResult;
use crate::types::{Environment, Platform};

#[tauri::command]
pub async fn get_environment(state: State<'_, Shared>) -> AppResult<Environment> {
    blocking(&state, |state| {
        Ok(Environment {
            paths: state.paths.clone(),
            platform: Platform::CURRENT,
            openssh_version: state.openssh_version(),
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            default_comment: default_comment(),
            backup_dir: state.backup_dir.to_string_lossy().into_owned(),
            hosts_file: state.hosts_file.to_string_lossy().into_owned(),
        })
    })
    .await
}

fn default_comment() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_default();
    let host = gethostname::gethostname().to_string_lossy().into_owned();
    let host = host.strip_suffix(".local").unwrap_or(&host).to_owned();
    match (user.is_empty(), host.is_empty()) {
        (false, false) => format!("{user}@{host}"),
        (false, true) => user,
        (true, _) => host,
    }
}
