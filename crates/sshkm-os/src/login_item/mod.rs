//! Whether the system lets the app's login item run.
//!
//! - **macOS 13 and later**: System Settings → General → Login Items lists
//!   the launch agents in `~/Library/LaunchAgents` under "Allow in the
//!   Background", where the user can turn one off. Its file stays where it
//!   was, so only the system can tell that it no longer runs:
//!   [`launch_agent_turned_off`]. [`open_settings`] opens that pane.
//! - **macOS 12, Windows, Linux**: there is no such switch here. (Windows'
//!   Task Manager and the Linux desktops keep theirs in the entry itself,
//!   which the app reads.)

#[cfg(target_os = "macos")]
mod macos;

use std::path::Path;

/// Whether the user turned off the launch agent at `plist` in System
/// Settings, so it doesn't run at login although its file is there. `false`
/// where the system has no such setting, or doesn't know the file yet.
#[cfg_attr(not(target_os = "macos"), allow(unused_variables))]
pub fn launch_agent_turned_off(plist: &Path) -> bool {
    #[cfg(target_os = "macos")]
    {
        macos::turned_off(plist)
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Opens System Settings at Login Items, where the user allows the app's
/// launch agent again. Returns whether it could (macOS 13 and later).
pub fn open_settings() -> bool {
    #[cfg(target_os = "macos")]
    {
        macos::open_settings()
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}
