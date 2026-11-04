//! SSH Key Manager desktop app: Tauri commands over [`sshkm_core`].

pub mod askpass;
pub mod browser;
mod commands;
mod confirm;
mod device_unlock;
mod error;
#[cfg(target_os = "linux")]
mod gpu;
#[cfg(target_os = "macos")]
mod menu;
pub mod nearby;
mod process;
mod state;
pub mod terminal;
mod types;
mod vault;
mod vault_watcher;
mod watcher;

use std::sync::Arc;

use sshkm_core::hosts_file;
use sshkm_core::paths::SshPaths;
use tauri::plugin::TauriPlugin;
use tauri::webview::PageLoadEvent;
use tauri::{Manager, RunEvent, Runtime, Url, WindowEvent};

pub use crate::error::{AppError, AppResult};

use crate::commands::Shared;
use crate::state::AppState;
use crate::vault::LockReason;

#[allow(clippy::too_many_lines, reason = "mostly the list of commands")]
pub fn run() {
    #[cfg(target_os = "linux")]
    gpu::prefer_mesa_egl();

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
        .plugin(tauri_plugin_updater::Builder::new().build());

    builder
        .plugin(navigation_guard())
        .plugin(
            tauri_plugin_log::Builder::new()
                .level(log::LevelFilter::Info)
                .build(),
        )
        .plugin(tauri_plugin_window_state::Builder::default().build())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(setup)
        .on_window_event(lock_on_minimize)
        // A reloaded page has lost its terminals' channels: end the sessions.
        .on_page_load(|webview, payload| {
            if payload.event() == PageLoadEvent::Started
                && let Some(state) = webview.try_state::<Shared>()
            {
                state.terminals.close_all();
            }
        })
        .invoke_handler(tauri::generate_handler![
            confirm::set_ui_language,
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
            commands::remote::server_keys,
            commands::nearby::nearby_status,
            commands::nearby::nearby_set_name,
            commands::nearby::nearby_set_visible,
            commands::nearby::nearby_set_looking,
            commands::nearby::nearby_pair,
            commands::nearby::nearby_send,
            commands::nearby::nearby_answer,
            commands::nearby::nearby_close,
            commands::nearby::nearby_contacts,
            commands::nearby::nearby_remove_contact,
            commands::nearby::nearby_join,
            commands::nearby::nearby_add_device,
            commands::nearby::nearby_authorize,
            commands::nearby::nearby_finish_join,
            commands::nearby::nearby_devices,
            commands::nearby::nearby_remove_device,
            commands::nearby::nearby_set_reachable,
            commands::nearby::nearby_sync,
            commands::nearby::nearby_decide,
            commands::known_hosts::read_known_hosts,
            commands::known_hosts::find_known_hosts,
            commands::known_hosts::remove_known_hosts,
            commands::known_hosts::check_host_key,
            commands::hosts_file::read_hosts_file,
            commands::hosts_file::lookup_host,
            commands::hosts_file::preview_hosts_changes,
            commands::hosts_file::apply_hosts_changes,
            commands::hosts_file::list_hosts_backups,
            commands::hosts_file::restore_hosts_backup,
            commands::audit::run_audit,
            commands::audit::fix_permissions,
            commands::vault::vault_status,
            commands::vault::vault_create,
            commands::vault::vault_unlock,
            commands::vault::vault_recover,
            commands::vault::vault_unlock_device,
            commands::vault::vault_enable_device,
            commands::vault::vault_disable_device,
            commands::vault::vault_lock,
            commands::vault::vault_activity,
            commands::vault::vault_entries,
            commands::vault::vault_entry,
            commands::vault::vault_reveal,
            commands::vault::vault_copy,
            commands::vault::vault_copy_recovery_key,
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
            commands::vault_hosts::vault_test_connection,
            commands::vault_hosts::vault_install_public_key,
            commands::vault_hosts::vault_server_keys,
            commands::vault_hosts::vault_test_key_login,
            commands::vault_links::agent_add_from_vault,
            commands::vault_links::agent_add_all_from_vault,
            commands::vault_links::run_vault_audit,
            commands::vault_files::vault_import_preview,
            commands::vault_files::vault_import,
            commands::vault_files::vault_trash_import_file,
            commands::vault_files::vault_export_csv,
            commands::vault_files::vault_export_kdbx,
            commands::vault_files::vault_location,
            commands::vault_files::vault_move,
            commands::vault_files::vault_use_file,
            commands::vault_files::vault_use_default,
            commands::terminal::terminal_open,
            commands::terminal::terminal_write,
            commands::terminal::terminal_resize,
            commands::terminal::terminal_answer,
            commands::terminal::terminal_close,
            commands::terminal::terminal_list,
            commands::terminal::terminal_open_external,
            commands::browser::browser_status,
            commands::browser::browser_set_enabled,
            commands::browser::browser_answer_pairing,
            commands::browser::browser_revoke,
            commands::updates::update_check,
            commands::updates::update_install,
        ])
        .build(tauri::generate_context!())
        .expect("failed to start SSH Key Manager")
        .run(|app, event| {
            if let RunEvent::Exit = event
                && let Some(state) = app.try_state::<Shared>()
            {
                state.terminals.close_all();
                state.stop_askpass();
            }
            if let RunEvent::Exit = event
                && let Some(bridge) = app.try_state::<Arc<browser::Bridge>>()
            {
                bridge.stop();
            }
        });
}

/// Keeps the window on the app's own page. Script in the page could otherwise
/// load any site, with secrets in its URL; links open in the browser through
/// the opener plugin instead. New windows are refused already: no handler
/// creates them.
fn navigation_guard<R: Runtime>() -> TauriPlugin<R> {
    tauri::plugin::Builder::new("navigation-guard")
        .on_navigation(|webview, url| {
            let dev_url = webview.config().build.dev_url.as_ref();
            let allowed = is_app_url(url, dev_url.filter(|_| tauri::is_dev()));
            if !allowed {
                log::warn!(
                    "blocked navigation to {}",
                    url.origin().ascii_serialization()
                );
            }
            allowed
        })
        .build()
}

/// Whether `url` is the app's page: the bundled frontend (`tauri://localhost`,
/// or `http(s)://tauri.localhost` on Windows), or the dev server in
/// `tauri dev`.
fn is_app_url(url: &Url, dev_url: Option<&Url>) -> bool {
    let bundled = if cfg!(windows) {
        matches!(url.scheme(), "http" | "https") && url.host_str() == Some("tauri.localhost")
    } else {
        url.scheme() == "tauri" && url.host_str() == Some("localhost")
    };
    (bundled && url.port().is_none()) || dev_url.is_some_and(|dev| dev.origin() == url.origin())
}

/// Locks the vault when the window is minimised, if the settings say so.
fn lock_on_minimize(window: &tauri::Window, event: &WindowEvent) {
    if let WindowEvent::Resized(_) = event
        && window.is_minimized().unwrap_or(false)
        && let Some(state) = window.try_state::<Arc<AppState>>()
        && state.vault.settings().lock_on_minimize
    {
        state.vault.lock(window.app_handle(), LockReason::Minimize);
    }
}

/// Shared state, background watchers and the macOS menu.
fn setup(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let paths = SshPaths::detect()?;
    let hosts_file = hosts_file::system_path();
    let data_dir = app.path().app_data_dir()?;
    let backup_dir = data_dir.join("backups");
    watcher::start(app.handle(), &paths.dir, &hosts_file);
    commands::agent::check_agent_pipes();
    let bridge = Arc::new(browser::Bridge::new(&data_dir));
    let nearby = Arc::new(nearby::Nearby::new(data_dir.clone()));
    nearby.attach(app.handle().clone());
    let state = Arc::new(AppState::new(paths, hosts_file, backup_dir, data_dir));
    state.vault.start_timer(app.handle().clone());
    device_unlock::watch_screen_lock(Arc::clone(&state.vault), app.handle().clone());
    vault_watcher::start(app.handle(), &state.vault.paths());
    app.manage(state);
    bridge.start_if_enabled(app.handle());
    app.manage(bridge);
    app.manage(nearby);
    #[cfg(target_os = "macos")]
    menu::install(app)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(text: &str) -> Url {
        text.parse().unwrap()
    }

    #[test]
    fn navigation_stays_on_the_app() {
        let app = if cfg!(windows) {
            "http://tauri.localhost/index.html"
        } else {
            "tauri://localhost/index.html"
        };
        assert!(is_app_url(&url(app), None));
        for other in [
            "https://example.com/?secret=1",
            "http://localhost:1420/",
            "tauri://localhost:8080/",
            "http://tauri.localhost:8080/",
            "http://tauri.localhost.example.com/",
            "file:///etc/passwd",
            "about:blank",
            "data:text/html,hello",
        ] {
            assert!(!is_app_url(&url(other), None), "{other}");
        }
    }

    #[test]
    fn tauri_dev_also_allows_the_dev_server() {
        let dev = url("http://localhost:1420");
        assert!(is_app_url(
            &url("http://localhost:1420/?page=keys"),
            Some(&dev)
        ));
        assert!(!is_app_url(&url("http://localhost:1421/"), Some(&dev)));
        assert!(!is_app_url(&url("https://localhost:1420/"), Some(&dev)));
    }
}
