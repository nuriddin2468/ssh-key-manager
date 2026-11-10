use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

/// Every command the app registers (`generate_handler!` in `src/lib.rs`; a
/// test there checks that the two agree). Tauri makes an `allow-…`
/// permission of each, and then lets a window call only the commands its
/// capability allows: the main window all of them
/// ([`write_main_window_set`]), the browser's unlock window
/// (`capabilities/unlock.json`) only those that unlock the vault, the quick
/// search window (`capabilities/quick.json`) only what it lists and does.
const COMMANDS: &[&str] = &[
    "set_ui_language",
    "get_environment",
    "list_keys",
    "generate_key",
    "change_passphrase",
    "regenerate_public",
    "import_key",
    "trash_key",
    "check_key_login",
    "vault_check_key_login",
    "agent_view",
    "agent_add",
    "agent_remove",
    "agent_remove_all",
    "read_config",
    "save_host",
    "delete_host",
    "remove_identity_file",
    "read_config_raw",
    "write_config_raw",
    "test_connection",
    "connection_history",
    "clear_connection_history",
    "diagnose_probe",
    "diagnose_fix_permissions",
    "install_public_key",
    "server_keys",
    "tunnel_list",
    "tunnel_save",
    "tunnel_delete",
    "tunnel_set_on",
    "tunnel_answer",
    "tunnel_stop_all",
    "tunnel_export",
    "set_proxy_jump",
    "key_convert_inspect",
    "key_convert_import",
    "key_convert_save",
    "authorized_line",
    "install_authorized_line",
    "nearby_status",
    "nearby_set_name",
    "nearby_set_visible",
    "nearby_set_looking",
    "nearby_pair",
    "nearby_send",
    "nearby_answer",
    "nearby_close",
    "nearby_received_group",
    "nearby_contacts",
    "nearby_remove_contact",
    "nearby_join",
    "nearby_add_device",
    "nearby_authorize",
    "nearby_finish_join",
    "nearby_devices",
    "nearby_remove_device",
    "nearby_set_reachable",
    "nearby_sync",
    "nearby_decide",
    "read_known_hosts",
    "find_known_hosts",
    "remove_known_hosts",
    "check_host_key",
    "shell_history_status",
    "shell_history_set_enabled",
    "shell_history_scan",
    "shell_history_dismiss",
    "shell_history_forget_dismissed",
    "read_hosts_file",
    "lookup_host",
    "preview_hosts_changes",
    "apply_hosts_changes",
    "list_hosts_backups",
    "restore_hosts_backup",
    "tools_generate_secret",
    "tools_copy_secret",
    "tools_ssh_ping",
    "tools_port_check",
    "tools_dns_lookup",
    "tools_tls_check",
    "run_audit",
    "fix_permissions",
    "fix_config",
    "breach_status",
    "breach_set_enabled",
    "breach_check",
    "leaks_status",
    "leaks_set_sources",
    "leaks_add_folders",
    "leaks_remove_folder",
    "leaks_start",
    "leaks_cancel",
    "leaks_findings",
    "leaks_redact",
    "vault_status",
    "vault_create",
    "vault_unlock",
    "vault_recover",
    "vault_unlock_device",
    "vault_enable_device",
    "vault_disable_device",
    "vault_lock",
    "vault_activity",
    "vault_entries",
    "vault_entry",
    "vault_reveal",
    "vault_copy",
    "vault_copy_recovery_key",
    "vault_otp",
    "vault_add",
    "vault_update",
    "vault_trash",
    "vault_restore",
    "vault_delete",
    "vault_empty_trash",
    "vault_generate",
    "vault_strength",
    "vault_change_master",
    "vault_new_recovery_key",
    "vault_set_settings",
    "vault_test_connection",
    "vault_install_public_key",
    "vault_server_keys",
    "vault_test_key_login",
    "agent_add_from_vault",
    "agent_add_all_from_vault",
    "run_vault_audit",
    "vault_import_preview",
    "vault_import",
    "vault_import_compare",
    "vault_trash_import_file",
    "vault_browser_profiles",
    "vault_browser_import_preview",
    "vault_browser_import",
    "vault_browser_import_compare",
    "vault_browser_import_forget",
    "vault_export_csv",
    "vault_export_kdbx",
    "vault_location",
    "vault_move",
    "vault_use_file",
    "vault_use_default",
    "envs_list",
    "envs_get",
    "envs_create",
    "envs_update",
    "envs_set_var",
    "envs_remove_var",
    "envs_reveal",
    "envs_copy",
    "envs_trash",
    "envs_restore",
    "envs_delete",
    "envs_compare",
    "envs_import_pick",
    "envs_import",
    "envs_export",
    "envs_export_anyway",
    "envs_run",
    "terminal_open",
    "terminal_write",
    "terminal_resize",
    "terminal_answer",
    "terminal_close",
    "terminal_list",
    "terminal_open_external",
    "terminal_shells",
    "terminal_open_local",
    "browser_status",
    "browser_set_enabled",
    "browser_answer_pairing",
    "browser_revoke",
    "background_status",
    "background_set_enabled",
    "autostart_status",
    "autostart_set_enabled",
    "quick_status",
    "quick_set_shortcut",
    "quick_items",
    "quick_connect",
    "quick_close",
    "update_check",
    "update_install",
];

fn main() {
    write_main_window_set();
    let mut windows = tauri_build::WindowsAttributes::new();
    if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        // Tauri puts its manifest, which asks for Common Controls v6 (the
        // dialog plugin's `TaskDialogIndirect`), only into the app's
        // executable. A test binary that links the native dialogs then fails
        // to start with STATUS_ENTRYPOINT_NOT_FOUND, so the linker embeds the
        // same manifest into every binary of the crate instead.
        windows = tauri_build::WindowsAttributes::new_without_app_manifest();
        let manifest = Path::new(&env::var("CARGO_MANIFEST_DIR").expect("set by cargo"))
            .join("windows-app-manifest.xml");
        println!("cargo:rerun-if-changed={}", manifest.display());
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
    }
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .windows_attributes(windows)
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("failed to run the Tauri build script");
}

/// Writes `permissions/main-window.toml`: a permission set of every command,
/// which `capabilities/default.json` gives the main window. Like the
/// `permissions/autogenerated` folder `tauri-build` writes, it is made by
/// every build and kept out of git; it is written only when it changes, since
/// Tauri rebuilds when the folder does.
fn write_main_window_set() {
    let mut toml = String::from(
        "# Written by build.rs from its list of commands; don't edit.\n\n\
         [[set]]\n\
         identifier = \"main-window\"\n\
         description = \"Every command of the app: what the main window may call.\"\n\
         permissions = [\n",
    );
    for command in COMMANDS {
        let _ = writeln!(toml, "  \"allow-{}\",", command.replace('_', "-"));
    }
    toml.push_str("]\n");
    let path = Path::new("permissions/main-window.toml");
    if fs::read_to_string(path).ok().as_deref() != Some(toml.as_str()) {
        fs::create_dir_all("permissions").expect("can't make the permissions folder");
        fs::write(path, toml).expect("can't write the main window's permissions");
    }
}
