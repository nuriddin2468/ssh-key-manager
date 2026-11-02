//! The macOS menu bar. Items with an id are forwarded to the UI as a `menu`
//! event; the standard Edit items are what make ⌘C/⌘V work in text fields.

use tauri::menu::{AboutMetadata, MenuBuilder, MenuItemBuilder, SubmenuBuilder};
use tauri::{App, Emitter};

pub const EVENT: &str = "menu";

pub fn install(app: &App) -> tauri::Result<()> {
    let handle = app.handle();
    let item = |id: &str, text: &str, accelerator: &str| {
        MenuItemBuilder::with_id(id, text)
            .accelerator(accelerator)
            .build(handle)
    };

    let app_menu = SubmenuBuilder::new(handle, "SSH Key Manager")
        .about(Some(AboutMetadata::default()))
        .item(&MenuItemBuilder::with_id("check-updates", "Check for Updates…").build(handle)?)
        .separator()
        .item(&item("settings", "Settings…", "CmdOrCtrl+,")?)
        .separator()
        .services()
        .separator()
        .hide()
        .hide_others()
        .show_all()
        .separator()
        .quit()
        .build()?;

    let file = SubmenuBuilder::new(handle, "File")
        .item(&item("new-key", "New Key…", "CmdOrCtrl+N")?)
        .item(&item("import-key", "Import Key…", "CmdOrCtrl+O")?)
        .item(&item("add-host", "Add Host", "CmdOrCtrl+Shift+N")?)
        .separator()
        .close_window()
        .build()?;

    let edit = SubmenuBuilder::new(handle, "Edit")
        .undo()
        .redo()
        .separator()
        .cut()
        .copy()
        .paste()
        .select_all()
        .separator()
        .item(&item("find", "Find", "CmdOrCtrl+F")?)
        .build()?;

    let view = SubmenuBuilder::new(handle, "View")
        .item(&item("nav-overview", "Overview", "CmdOrCtrl+1")?)
        .item(&item("nav-keys", "Keys", "CmdOrCtrl+2")?)
        .item(&item("nav-hosts", "Hosts", "CmdOrCtrl+3")?)
        .item(&item("nav-agent", "Agent", "CmdOrCtrl+4")?)
        .item(&item("nav-known", "Known Hosts", "CmdOrCtrl+5")?)
        .item(&item("nav-audit", "Audit", "CmdOrCtrl+6")?)
        .separator()
        .item(&item("check", "Check Again", "CmdOrCtrl+R")?)
        .separator()
        .fullscreen()
        .build()?;

    let window = SubmenuBuilder::new(handle, "Window")
        .minimize()
        .maximize()
        .separator()
        .close_window()
        .build()?;

    let menu = MenuBuilder::new(handle)
        .items(&[&app_menu, &file, &edit, &view, &window])
        .build()?;
    app.set_menu(menu)?;
    app.on_menu_event(|app, event| {
        let _ = app.emit(EVENT, event.id().0.as_str());
    });
    Ok(())
}
