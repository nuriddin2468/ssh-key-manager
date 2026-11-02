//! SSH Key Manager desktop app: Tauri commands over [`sshkm_core`].

pub mod askpass;
mod commands;
mod error;
#[cfg(target_os = "macos")]
mod menu;
mod process;
mod state;
mod types;
mod watcher;

use std::sync::Arc;

use sshkm_core::paths::SshPaths;
use tauri::{Manager, RunEvent};

use crate::commands::Shared;
use crate::state::AppState;

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
            let backup_dir = app.path().app_data_dir()?.join("backups");
            watcher::start(app.handle(), &paths.dir);
            app.manage(Arc::new(AppState::new(paths, backup_dir)));
            #[cfg(target_os = "macos")]
            menu::install(app)?;
            Ok(())
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
            commands::remote::install_public_key,
            commands::known_hosts::read_known_hosts,
            commands::known_hosts::find_known_hosts,
            commands::known_hosts::remove_known_hosts,
            commands::known_hosts::check_host_key,
            commands::audit::run_audit,
            commands::audit::fix_permissions,
        ])
        .build(tauri::generate_context!())
        .expect("failed to start SSH Key Manager")
        .run(|app, event| {
            if let RunEvent::Exit = event
                && let Some(state) = app.try_state::<Shared>()
            {
                state.stop_askpass();
            }
        });
}
