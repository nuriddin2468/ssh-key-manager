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

const UNLOCKING: [&str; 3] = ["vault_status", "vault_unlock", "vault_unlock_device"];
const OTHERS: [&str; 4] = ["list_keys", "vault_reveal", "vault_copy", "set_ui_language"];

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
