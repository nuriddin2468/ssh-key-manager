//! SSH Key Manager desktop app: Tauri commands over [`sshkm_core`].

pub mod askpass;
mod autostart;
pub mod browser;
mod commands;
mod confirm;
mod device_unlock;
mod env_files;
pub mod env_guard;
mod env_pipes;
mod error;
#[cfg(target_os = "linux")]
mod gpu;
mod history;
#[cfg(target_os = "macos")]
mod menu;
pub mod nearby;
mod process;
pub mod quick;
mod state;
pub mod terminal;
mod tray;
pub mod tunnels;
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
use tauri_plugin_window_state::StateFlags;

pub use crate::error::{AppError, AppResult};

use crate::commands::Shared;
use crate::state::AppState;
use crate::vault::LockReason;

#[allow(clippy::too_many_lines, reason = "mostly the list of commands")]
pub fn run() {
    #[cfg(target_os = "linux")]
    gpu::prefer_mesa_egl();

    let builder = tauri::Builder::default();

    // Opened by the system at login, the app doesn't take the focus from
    // the app the user went to first.
    #[cfg(target_os = "macos")]
    let builder =
        builder.activate_ignoring_other_apps(!autostart::launched_at_login(std::env::args_os()));

    #[cfg(desktop)]
    let builder = builder
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            if args.iter().any(|arg| arg == quick::ARG) {
                quick::open(app);
            } else if !autostart::launched_at_login(&args) {
                tray::show_window(app);
            }
        }))
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(quick::plugin());

    builder
        .plugin(navigation_guard())
        .plugin(
            tauri_plugin_log::Builder::new()
                .level(log::LevelFilter::Info)
                .build(),
        )
        // The window starts hidden (`visible: false` in tauri.conf.json), and
        // `setup` shows it unless the app starts in the tray.
        .plugin(
            tauri_plugin_window_state::Builder::default()
                .with_state_flags(StateFlags::all() - StateFlags::VISIBLE)
                .build(),
        )
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(setup)
        .on_window_event(|window, event| {
            lock_on_minimize(window, event);
            tray::on_window_event(window, event);
        })
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
            commands::key_rotation::check_key_login,
            commands::key_rotation::vault_check_key_login,
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
            commands::config::connection_history,
            commands::config::clear_connection_history,
            commands::diagnose::diagnose_probe,
            commands::diagnose::diagnose_fix_permissions,
            commands::remote::install_public_key,
            commands::remote::server_keys,
            commands::ssh_tools::tunnel_list,
            commands::ssh_tools::tunnel_save,
            commands::ssh_tools::tunnel_delete,
            commands::ssh_tools::tunnel_set_on,
            commands::ssh_tools::tunnel_answer,
            commands::ssh_tools::tunnel_stop_all,
            commands::ssh_tools::tunnel_export,
            commands::ssh_tools::set_proxy_jump,
            commands::ssh_tools::key_convert_inspect,
            commands::ssh_tools::key_convert_import,
            commands::ssh_tools::key_convert_save,
            commands::ssh_tools::authorized_line,
            commands::ssh_tools::install_authorized_line,
            commands::nearby::nearby_status,
            commands::nearby::nearby_set_name,
            commands::nearby::nearby_set_visible,
            commands::nearby::nearby_set_looking,
            commands::nearby::nearby_pair,
            commands::nearby::nearby_send,
            commands::nearby::nearby_answer,
            commands::nearby::nearby_close,
            commands::nearby::nearby_received_group,
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
            commands::shell_history::shell_history_status,
            commands::shell_history::shell_history_set_enabled,
            commands::shell_history::shell_history_scan,
            commands::shell_history::shell_history_dismiss,
            commands::shell_history::shell_history_forget_dismissed,
            commands::hosts_file::read_hosts_file,
            commands::hosts_file::lookup_host,
            commands::hosts_file::preview_hosts_changes,
            commands::hosts_file::apply_hosts_changes,
            commands::hosts_file::list_hosts_backups,
            commands::hosts_file::restore_hosts_backup,
            commands::tools_net::tools_generate_secret,
            commands::tools_net::tools_copy_secret,
            commands::tools_net::tools_ssh_ping,
            commands::tools_net::tools_port_check,
            commands::tools_net::tools_dns_lookup,
            commands::tools_net::tools_tls_check,
            commands::audit::run_audit,
            commands::audit::fix_permissions,
            commands::audit_checks::fix_config,
            commands::audit_checks::breach_status,
            commands::audit_checks::breach_set_enabled,
            commands::audit_checks::breach_check,
            commands::leaks::leaks_status,
            commands::leaks::leaks_set_sources,
            commands::leaks::leaks_add_folders,
            commands::leaks::leaks_remove_folder,
            commands::leaks::leaks_start,
            commands::leaks::leaks_cancel,
            commands::leaks::leaks_findings,
            commands::leaks::leaks_redact,
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
            commands::vault_files::vault_import_compare,
            commands::vault_files::vault_trash_import_file,
            commands::browser_import::vault_browser_profiles,
            commands::browser_import::vault_browser_import_preview,
            commands::browser_import::vault_browser_import,
            commands::browser_import::vault_browser_import_compare,
            commands::browser_import::vault_browser_import_forget,
            commands::vault_files::vault_export_csv,
            commands::vault_files::vault_export_kdbx,
            commands::vault_files::vault_location,
            commands::vault_files::vault_move,
            commands::vault_files::vault_use_file,
            commands::vault_files::vault_use_default,
            commands::envs::envs_list,
            commands::envs::envs_get,
            commands::envs::envs_create,
            commands::envs::envs_update,
            commands::envs::envs_set_part,
            commands::envs::envs_set_var,
            commands::envs::envs_remove_var,
            commands::envs::envs_shared_list,
            commands::envs::envs_share_var,
            commands::envs::envs_unshare_var,
            commands::envs::envs_shared_delete,
            commands::envs::envs_reveal,
            commands::envs::envs_copy,
            commands::envs::envs_trash,
            commands::envs::envs_restore,
            commands::envs::envs_delete,
            commands::envs::envs_compare,
            commands::envs::envs_import_pick,
            commands::envs::envs_import,
            commands::envs::envs_export,
            commands::envs::envs_export_anyway,
            commands::envs::envs_run,
            commands::env_files::envs_set_kind,
            commands::env_files::envs_files_status,
            commands::env_files::envs_files_bind,
            commands::env_files::envs_files_set_level,
            commands::env_files::envs_files_unbind,
            commands::env_files::envs_files_sync,
            commands::env_files::envs_files_resolve,
            commands::env_files::envs_files_compare,
            commands::env_files::envs_files_undo,
            commands::env_files::envs_files_overview,
            commands::env_files::envs_files_ignore,
            commands::env_files::envs_files_adopt_preview,
            commands::env_files::envs_files_adopt,
            commands::env_files::envs_files_check,
            commands::env_files::envs_files_risks,
            commands::env_agents::envs_agents_rules,
            commands::env_agents::envs_agents_add,
            commands::env_agents::envs_agents_decline,
            commands::projects::projects_list,
            commands::projects::projects_create,
            commands::projects::projects_update,
            commands::projects::projects_delete,
            commands::projects::projects_set_member,
            commands::projects::projects_add_folder,
            commands::projects::projects_suggestions,
            commands::projects::projects_accept_suggestion,
            commands::projects::projects_dismiss_suggestion,
            commands::projects::projects_restore_suggestions,
            commands::projects::projects_suggest_in_folder,
            commands::projects::projects_open_terminal,
            commands::projects::projects_reveal_folder,
            commands::projects::projects_missing_folders,
            commands::projects::projects_places,
            commands::projects::projects_set_part_folder,
            commands::projects::projects_pick_part_folder,
            commands::terminal::terminal_open,
            commands::terminal::terminal_write,
            commands::terminal::terminal_resize,
            commands::terminal::terminal_answer,
            commands::terminal::terminal_close,
            commands::terminal::terminal_list,
            commands::terminal::terminal_open_external,
            commands::terminal::terminal_shells,
            commands::terminal::terminal_open_local,
            commands::browser::browser_status,
            commands::browser::browser_set_enabled,
            commands::browser::browser_answer_pairing,
            commands::browser::browser_revoke,
            commands::background::background_status,
            commands::background::background_set_enabled,
            commands::autostart::autostart_status,
            commands::autostart::autostart_set_enabled,
            commands::quick::quick_status,
            commands::quick::quick_set_shortcut,
            commands::quick::quick_items,
            commands::quick::quick_connect,
            commands::quick::quick_close,
            commands::updates::update_check,
            commands::updates::update_install,
        ])
        .build(tauri::generate_context!())
        .expect("failed to start SSH Key Manager")
        .run(|app, event| {
            // The `.env` files written only while the vault is unlocked go
            // with the app, and so do the pipes of virtual ones.
            if let RunEvent::Exit = event
                && let (Some(files), Some(state)) = (
                    app.try_state::<Arc<env_files::EnvFiles>>(),
                    app.try_state::<Shared>(),
                )
            {
                files.quit(app, &state);
            }
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
            // Tunnels run on with the window in the tray, not past the app.
            if let RunEvent::Exit = event
                && let Some(tunnels) = app.try_state::<tunnels::SharedTunnels>()
            {
                tunnels.stop_all();
            }
            // The Dock icon of an app whose window is hidden.
            #[cfg(target_os = "macos")]
            if let RunEvent::Reopen {
                has_visible_windows: false,
                ..
            } = event
            {
                tray::show_window(app);
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
        vault::lock_in_background(window.app_handle(), LockReason::Minimize);
    }
}

/// Shared state, background watchers, the macOS menu, the tray icon and the
/// quick search shortcut.
fn setup(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let paths = SshPaths::detect()?;
    let hosts_file = hosts_file::system_path();
    let data_dir = app.path().app_data_dir()?;
    let backup_dir = data_dir.join("backups");
    watcher::start(app.handle(), &paths.dir, &hosts_file);
    commands::agent::check_agent_pipes();
    askpass::fill::attach(app.handle().clone());
    let bridge = Arc::new(browser::Bridge::new(&data_dir));
    let nearby = Arc::new(nearby::Nearby::new(data_dir.clone()));
    nearby.attach(app.handle().clone());
    let state = Arc::new(AppState::new(
        paths,
        hosts_file,
        backup_dir,
        data_dir.clone(),
    ));
    state.vault.start_timer(app.handle().clone());
    device_unlock::watch_screen_lock(Arc::clone(&state.vault), app.handle().clone());
    vault_watcher::start(app.handle(), &state.vault.paths());
    let env_files = Arc::new(env_files::EnvFiles::new(
        &data_dir,
        Arc::clone(&state.served_pipes),
    ));
    app.manage(Arc::clone(&env_files));
    env_files.start(app.handle(), &state);
    app.manage(state);
    bridge.start_if_enabled(app.handle());
    browser::unlock::watch(app.handle());
    app.manage(bridge);
    app.manage(nearby);
    let tunnels = Arc::new(tunnels::Tunnels::new(&data_dir));
    tunnels.attach(app.handle().clone());
    app.manage(tunnels);
    #[cfg(target_os = "macos")]
    menu::install(app)?;
    let background = tray::Background::install(app.handle(), &data_dir);
    show_main_window(app, background.enabled());
    app.manage(background);
    app.manage(quick::Quick::install(app.handle(), &data_dir));
    if std::env::args().any(|arg| arg == quick::ARG) {
        quick::open(app.handle());
    }
    Ok(())
}

/// Shows the main window, which starts hidden, unless the system opened the
/// app at login and it runs on in the tray (`in_tray`): then it starts there,
/// without the window ([`autostart`]).
fn show_main_window(app: &tauri::App, in_tray: bool) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    if autostart::starts_hidden(autostart::launched_at_login(std::env::args_os()), in_tray) {
        log::info!("opened at login: in the tray, without the window");
        // Restoring a maximised window may have shown it.
        let _ = window.hide();
    } else {
        let _ = window.show();
        let _ = window.set_focus();
    }
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

    /// The commands between `start` and the next `end` in `source`: the last
    /// path segment or quoted name on each line.
    fn command_names(source: &str, start: &str, end: &str) -> Vec<String> {
        let from = source.find(start).expect("start") + start.len();
        let to = from + source[from..].find(end).expect("end");
        let mut names: Vec<String> = source[from..to]
            .lines()
            .map(|line| line.trim().trim_end_matches(',').trim_matches('"'))
            .filter(|line| !line.is_empty() && !line.starts_with("//"))
            .map(|line| line.rsplit("::").next().unwrap_or(line).to_owned())
            .collect();
        names.sort();
        names
    }

    /// A command missing from `build.rs` would have no permission, so every
    /// window would be refused it; one listed there but not registered would
    /// be allowed to nothing.
    #[test]
    fn the_build_script_lists_every_command() {
        let registered = command_names(include_str!("lib.rs"), "generate_handler![", "])");
        let listed = command_names(
            include_str!("../build.rs"),
            "const COMMANDS: &[&str] = &[",
            "];",
        );
        assert!(registered.len() > 100, "{registered:?}");
        assert_eq!(registered, listed);
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
