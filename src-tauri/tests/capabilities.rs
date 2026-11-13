//! What each window may call, as the app's real capabilities say
//! (`capabilities/*.json`, with the permissions `build.rs` makes of every
//! command), on Tauri's mock runtime.
//!
//! The commands here are stand-ins with the names of the app's own: Tauri
//! checks a window's capability before it looks for the command, so their
//! arguments and work don't matter.

use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::test::{INVOKE_KEY, MockRuntime, get_ipc_response, mock_builder};
use tauri::webview::InvokeRequest;
use tauri::{WebviewUrl, WebviewWindow, WebviewWindowBuilder};

#[tauri::command]
fn vault_status() {}
#[tauri::command]
fn vault_unlock() {}
#[tauri::command]
fn vault_unlock_device() {}
#[tauri::command]
fn list_keys() {}
#[tauri::command]
fn vault_reveal() {}
#[tauri::command]
fn vault_copy() {}
#[tauri::command]
fn set_ui_language() {}
#[tauri::command]
fn quick_items() {}
#[tauri::command]
fn quick_connect() {}
#[tauri::command]
fn quick_close() {}
#[tauri::command]
fn quick_set_shortcut() {}
#[tauri::command]
fn vault_entries() {}
#[tauri::command]
fn read_config() {}
#[tauri::command]
fn vault_import_preview() {}
#[tauri::command]
fn vault_import() {}
#[tauri::command]
fn vault_import_compare() {}
#[tauri::command]
fn vault_browser_profiles() {}
#[tauri::command]
fn vault_browser_import_preview() {}
#[tauri::command]
fn vault_browser_import() {}
#[tauri::command]
fn vault_browser_import_compare() {}
#[tauri::command]
fn vault_browser_import_forget() {}

const UNLOCKING: [&str; 3] = ["vault_status", "vault_unlock", "vault_unlock_device"];
const OTHERS: [&str; 12] = [
    "list_keys",
    "vault_reveal",
    "vault_copy",
    "set_ui_language",
    "vault_import_preview",
    "vault_import",
    "vault_import_compare",
    "vault_browser_profiles",
    "vault_browser_import_preview",
    "vault_browser_import",
    "vault_browser_import_compare",
    "vault_browser_import_forget",
];
/// What the quick search window does: unlocking, its own commands and copying.
const QUICK: [&str; 7] = [
    "vault_status",
    "vault_unlock",
    "vault_unlock_device",
    "vault_copy",
    "quick_items",
    "quick_connect",
    "quick_close",
];
/// What it never needs: secrets in the clear, everything about an entry or
/// the config, its own shortcut.
const NOT_QUICK: [&str; 14] = [
    "vault_reveal",
    "vault_import_preview",
    "vault_import",
    "vault_import_compare",
    "vault_browser_profiles",
    "vault_browser_import_preview",
    "vault_browser_import",
    "vault_browser_import_compare",
    "vault_browser_import_forget",
    "vault_entries",
    "read_config",
    "list_keys",
    "quick_set_shortcut",
    "set_ui_language",
];

fn allowed(window: &WebviewWindow<MockRuntime>, cmd: &str) -> bool {
    let url = if cfg!(windows) {
        "http://tauri.localhost"
    } else {
        "tauri://localhost"
    };
    get_ipc_response(
        window,
        InvokeRequest {
            cmd: cmd.into(),
            callback: CallbackFn(0),
            error: CallbackFn(1),
            url: url.parse().unwrap(),
            body: InvokeBody::default(),
            headers: tauri::http::HeaderMap::default(),
            invoke_key: INVOKE_KEY.into(),
        },
    )
    .is_ok()
}

/// The browser's unlock window may unlock the vault and call nothing else of
/// the app; the main window may call every command.
#[test]
fn the_unlock_window_may_only_unlock() {
    let app = mock_builder()
        .invoke_handler(tauri::generate_handler![
            vault_status,
            vault_unlock,
            vault_unlock_device,
            list_keys,
            vault_reveal,
            vault_copy,
            set_ui_language,
            vault_import_preview,
            vault_import,
            vault_import_compare,
            vault_browser_profiles,
            vault_browser_import_preview,
            vault_browser_import,
            vault_browser_import_compare,
            vault_browser_import_forget,
        ])
        .build(tauri::generate_context!("tauri.conf.json", test = true))
        .unwrap();
    let main = WebviewWindowBuilder::new(&app, "main", WebviewUrl::default())
        .build()
        .unwrap();
    let unlock = WebviewWindowBuilder::new(
        &app,
        sshkm_app_lib::browser::unlock::LABEL,
        WebviewUrl::App("unlock.html".into()),
    )
    .build()
    .unwrap();

    for cmd in UNLOCKING {
        assert!(allowed(&unlock, cmd), "unlock window: {cmd}");
    }
    for cmd in OTHERS {
        assert!(!allowed(&unlock, cmd), "unlock window: {cmd}");
    }
    for cmd in UNLOCKING.iter().chain(&OTHERS) {
        assert!(allowed(&main, cmd), "main window: {cmd}");
    }
}

/// The quick search window may list, copy, unlock, connect and close, and
/// call nothing else of the app.
#[test]
fn the_quick_window_may_only_do_what_it_shows() {
    let app = mock_builder()
        .invoke_handler(tauri::generate_handler![
            vault_status,
            vault_unlock,
            vault_unlock_device,
            vault_copy,
            quick_items,
            quick_connect,
            quick_close,
            vault_reveal,
            vault_entries,
            read_config,
            list_keys,
            quick_set_shortcut,
            set_ui_language,
            vault_import_preview,
            vault_import,
            vault_import_compare,
            vault_browser_profiles,
            vault_browser_import_preview,
            vault_browser_import,
            vault_browser_import_compare,
            vault_browser_import_forget,
        ])
        .build(tauri::generate_context!("tauri.conf.json", test = true))
        .unwrap();
    let main = WebviewWindowBuilder::new(&app, "main", WebviewUrl::default())
        .build()
        .unwrap();
    let quick = WebviewWindowBuilder::new(
        &app,
        sshkm_app_lib::quick::LABEL,
        WebviewUrl::App("quick.html".into()),
    )
    .build()
    .unwrap();

    for cmd in QUICK {
        assert!(allowed(&quick, cmd), "quick window: {cmd}");
    }
    for cmd in NOT_QUICK {
        assert!(!allowed(&quick, cmd), "quick window: {cmd}");
    }
    for cmd in QUICK.iter().chain(&NOT_QUICK) {
        assert!(allowed(&main, cmd), "main window: {cmd}");
    }
}

/// Whether the main window's capability refuses a plugin command. One it
/// lets through may still fail, on the mock runtime or because its plugin
/// isn't set up here; that's not the capability's doing.
fn refused(window: &WebviewWindow<MockRuntime>, cmd: &str, body: serde_json::Value) -> bool {
    let url = if cfg!(windows) {
        "http://tauri.localhost"
    } else {
        "tauri://localhost"
    };
    let response = get_ipc_response(
        window,
        InvokeRequest {
            cmd: cmd.into(),
            callback: CallbackFn(0),
            error: CallbackFn(1),
            url: url.parse().unwrap(),
            body: InvokeBody::Json(body),
            headers: tauri::http::HeaderMap::default(),
            invoke_key: INVOKE_KEY.into(),
        },
    );
    matches!(response, Err(error) if error.to_string().contains("not allowed"))
}

/// The main window gets the plugin commands its page uses — listening to
/// events, moving and maximising the window by its drag regions, opening
/// links, copying text — and none of the rest: no tray or menu to replace,
/// no image read from a path, no event sent to the app's own listeners, no
/// file dialog or file manager opened at a path the page names.
#[test]
fn the_main_window_may_only_use_what_its_page_does() {
    use serde_json::json;

    let app = mock_builder()
        .build(tauri::generate_context!("tauri.conf.json", test = true))
        .unwrap();
    let main = WebviewWindowBuilder::new(&app, "main", WebviewUrl::default())
        .build()
        .unwrap();

    for (cmd, body) in [
        (
            "plugin:event|listen",
            json!({ "event": "vault-locked", "target": { "kind": "Any" }, "handler": 0 }),
        ),
        (
            "plugin:event|unlisten",
            json!({ "event": "vault-locked", "eventId": 0 }),
        ),
        ("plugin:window|start_dragging", json!({})),
        ("plugin:window|internal_toggle_maximize", json!({})),
        (
            "plugin:opener|open_url",
            json!({ "url": "https://example.com" }),
        ),
        (
            "plugin:clipboard-manager|write_text",
            json!({ "text": "ssh-ed25519 AAAA" }),
        ),
    ] {
        assert!(!refused(&main, cmd, body), "main window: {cmd}");
    }

    let png = concat!(env!("CARGO_MANIFEST_DIR"), "/icons/32x32.png");
    for (cmd, body) in [
        ("plugin:tray|get_by_id", json!({ "id": "main" })),
        ("plugin:tray|set_menu", json!({ "rid": 0, "menu": null })),
        (
            "plugin:tray|set_visible",
            json!({ "rid": 0, "visible": false }),
        ),
        (
            "plugin:tray|set_temp_dir_path",
            json!({ "rid": 0, "path": "/tmp/x" }),
        ),
        (
            "plugin:menu|new",
            json!({ "kind": "Menu", "options": null }),
        ),
        ("plugin:menu|set_as_app_menu", json!({ "rid": 0 })),
        ("plugin:image|from_path", json!({ "path": png })),
        ("plugin:image|rgba", json!({ "rid": 0 })),
        (
            "plugin:event|emit",
            json!({ "event": "vault-unlocked", "payload": null }),
        ),
        ("plugin:app|version", json!({})),
        ("plugin:path|resolve_directory", json!({ "directory": 1 })),
        ("plugin:window|set_title", json!({ "value": "x" })),
        (
            "plugin:webview|create_webview_window",
            json!({ "options": { "label": "x", "url": "https://example.com" } }),
        ),
        (
            "plugin:opener|reveal_item_in_dir",
            json!({ "paths": ["/etc/hosts"] }),
        ),
        ("plugin:opener|open_path", json!({ "path": "/etc/hosts" })),
        ("plugin:dialog|open", json!({ "options": {} })),
        ("plugin:clipboard-manager|read_text", json!({})),
    ] {
        assert!(refused(&main, cmd, body), "main window: {cmd}");
    }
}
