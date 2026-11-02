//! SSH Key Manager desktop app: Tauri commands over [`sshkm_core`].

mod commands;
mod error;
#[cfg(target_os = "macos")]
mod menu;
mod process;
mod state;
mod types;
mod vault;
mod vault_watcher;
mod watcher;

use std::sync::Arc;

use sshkm_core::paths::SshPaths;
use tauri::{Manager, WindowEvent};

use crate::state::AppState;
use crate::vault::LockReason;

#[allow(clippy::too_many_lines, reason = "mostly the list of commands")]
pub fn run() {
    let builder = tauri::Builder::default();

    #[cfg(desktop)]
    let builder = builder
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init());

    builder
        .plugin(
            tauri_plugin_log::Builder::new()
                .level(log::LevelFilter::Info)
                .build(),
        )
        .plugin(tauri_plugin_window_state::Builder::default().build())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let paths = SshPaths::detect()?;
            let data_dir = app.path().app_data_dir()?;
            let backup_dir = data_dir.join("backups");
            watcher::start(app.handle(), &paths.dir);
            let state = Arc::new(AppState::new(paths, backup_dir, data_dir));
            state.vault.start_timer(app.handle().clone());
            vault_watcher::start(app.handle(), &state.vault.paths());
            app.manage(state);
            #[cfg(target_os = "macos")]
            menu::install(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::Resized(_) = event
                && window.is_minimized().unwrap_or(false)
                && let Some(state) = window.try_state::<Arc<AppState>>()
                && state.vault.settings().lock_on_minimize
            {
                state.vault.lock(window.app_handle(), LockReason::Minimize);
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::environment::get_environment,
            commands::keys::list_keys,
            commands::keys::generate_key,
            commands::keys::change_passphrase,
            commands::keys::regenerate_public,
            commands::keys::import_key,
            commands::keys::trash_key,
            commands::agent::agent_view,
            commands::agent::agent_add,
            commands::agent::agent_remove,
            commands::agent::agent_remove_all,
            commands::config::read_config,
            commands::config::save_host,
            commands::config::delete_host,
            commands::config::remove_identity_file,
            commands::config::read_config_raw,
            commands::config::write_config_raw,
            commands::config::test_connection,
            commands::known_hosts::read_known_hosts,
            commands::known_hosts::find_known_hosts,
            commands::known_hosts::remove_known_hosts,
            commands::known_hosts::check_host_key,
            commands::audit::run_audit,
            commands::audit::fix_permissions,
            commands::vault::vault_status,
            commands::vault::vault_create,
            commands::vault::vault_unlock,
            commands::vault::vault_recover,
            commands::vault::vault_lock,
            commands::vault::vault_activity,
            commands::vault::vault_entries,
            commands::vault::vault_entry,
            commands::vault::vault_reveal,
            commands::vault::vault_copy,
            commands::vault::vault_otp,
            commands::vault::vault_add,
            commands::vault::vault_update,
            commands::vault::vault_trash,
            commands::vault::vault_restore,
            commands::vault::vault_delete,
            commands::vault::vault_empty_trash,
            commands::vault::vault_generate,
            commands::vault::vault_strength,
            commands::vault::vault_change_master,
            commands::vault::vault_new_recovery_key,
            commands::vault::vault_set_settings,
            commands::vault_files::vault_import_preview,
            commands::vault_files::vault_import,
            commands::vault_files::vault_trash_import_file,
            commands::vault_files::vault_export_csv,
            commands::vault_files::vault_export_kdbx,
            commands::vault_files::vault_location,
            commands::vault_files::vault_move,
            commands::vault_files::vault_use_file,
            commands::vault_files::vault_use_default,
        ])
        .run(tauri::generate_context!())
        .expect("failed to start SSH Key Manager");
}
