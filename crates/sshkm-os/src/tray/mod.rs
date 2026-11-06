//! Whether the system can show the app's tray icon.
//!
//! - **macOS**: the menu bar always can.
//! - **Windows**: the notification area always can.
//! - **Linux**: the icon goes through the `AppIndicator` library, which Tauri's
//!   tray code loads when the first icon is made, and without which it panics
//!   (and the release build aborts). Not every desktop has the library: plain
//!   GNOME doesn't need it. So [`available`] loads it first, under the names
//!   that code tries, in its order.

#[cfg(target_os = "linux")]
mod linux;

/// Whether a tray icon can be made on this computer.
pub fn available() -> bool {
    #[cfg(target_os = "linux")]
    {
        linux::appindicator_loads()
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}
