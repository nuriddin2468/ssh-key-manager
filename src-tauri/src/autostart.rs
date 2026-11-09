//! "Open at login" on the Settings page: the system starts the app when the
//! user logs in, with [`ARG`].
//!
//! - **macOS**: a launch agent, `~/Library/LaunchAgents/<bundle id>.plist`.
//!   It names the app's bundle, so System Settings → Login Items lists it
//!   under the app's name, where the user can also turn it off.
//! - **Windows**: a value under `HKCU\…\CurrentVersion\Run`, with the
//!   program's path in quotes. Task Manager's Startup apps can turn it off.
//! - **Linux**: an XDG autostart entry, `~/.config/autostart/<name>.desktop`;
//!   for an `AppImage`, it starts the image file itself.
//!
//! Started so, the app goes straight to the tray, without its window, when it
//! runs on in the background ([`crate::tray`]): browser autofill, the user's
//! devices on Nearby and the agent work from the moment the user logs in.
//! Without the tray icon (that setting off, or a Linux desktop without the
//! `AppIndicator` library) it opens its window instead, since nothing else
//! would lead back to it. Opening the app any other way, or again while it
//! runs, shows the window as before.
//!
//! How the two settings go together: turning "Open at login" on also turns on
//! running in the background where the tray can show the icon, since starting
//! in the tray needs it ([`keeps_running_too`]). Turning the background off
//! later leaves "Open at login" on; the app then opens its window at login,
//! and the Settings page says which of the two happens.
//!
//! The app saves nothing of its own: the system's entry is the setting, read
//! each time, so turning it off elsewhere (System Settings, Task Manager, a
//! desktop's startup apps, deleting the file) shows on the Settings page too.
//!
//! A copy running from a disk image, App Translocation or a temporary folder
//! isn't registered: that path goes away (see [`crate::browser::HostProgram`]).

use std::ffi::OsStr;
use std::path::PathBuf;

use auto_launch::{AutoLaunch, AutoLaunchBuilder};
use serde::Serialize;
use sshkm_core::ErrorCode;
use tauri::AppHandle;

use crate::browser::{HostProgram, host_program};
use crate::error::{AppError, AppResult};
use crate::tray::BackgroundStatus;

/// What the system starts the app with at login.
pub const ARG: &str = "--autostart";

/// Why this copy of the app can't be set to open at login.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub enum AutostartBlocker {
    /// It runs from a temporary folder: an `AppImage`'s mount, or a copy
    /// unpacked there.
    Temporary,
    /// On macOS, it runs from a disk image, another volume, or where macOS
    /// runs a downloaded app until it is moved (App Translocation).
    Mounted,
}

/// "Open at login" as the Settings page shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = crate::types::BINDINGS))]
pub struct AutostartStatus {
    /// The system opens the app at login.
    pub enabled: bool,
    /// macOS: the launch agent is there, but turned off in System Settings →
    /// Login Items, so it doesn't run.
    pub turned_off_in_settings: bool,
    /// Why this copy can't be turned on; it can still be turned off.
    pub blocker: Option<AutostartBlocker>,
}

/// Whether the system started this launch at login: [`ARG`] is among `args`.
pub fn launched_at_login<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    args.into_iter().any(|arg| arg.as_ref() == ARG)
}

/// Whether the app starts without its window: the system started it at
/// login, and the tray icon is there to open the window from.
pub fn starts_hidden(at_login: bool, in_tray: bool) -> bool {
    at_login && in_tray
}

/// Whether turning "Open at login" on (`on`) also turns on running in the
/// background: starting in the tray needs it, and the tray can show the icon.
pub fn keeps_running_too(on: bool, background: &BackgroundStatus) -> bool {
    on && background.available && !background.enabled
}

/// The app's entry among the programs the system starts at login.
pub struct LoginEntry {
    launcher: AutoLaunch,
    /// The entry's file (macOS, Linux), for what the launcher doesn't read.
    file: Option<PathBuf>,
    blocker: Option<AutostartBlocker>,
    /// This copy's path can't go into the entry (see [`program_argument`]).
    unfit_path: bool,
}

impl LoginEntry {
    /// The entry that starts this copy of the app.
    pub fn of(app: &AppHandle) -> AppResult<Self> {
        Self::new(
            &app.config().identifier,
            &app.package_info().name,
            host_program()?,
        )
    }

    /// The entry for the app with the bundle `identifier` (the name on macOS)
    /// and the `name` (elsewhere), starting `program`.
    fn new(identifier: &str, name: &str, program: HostProgram) -> AppResult<Self> {
        let (program, blocker) = match program {
            HostProgram::At(program) => (program, None),
            HostProgram::Temporary(program) => (program, Some(AutostartBlocker::Temporary)),
            HostProgram::Mounted(program) => (program, Some(AutostartBlocker::Mounted)),
        };
        // As the system shows it, links resolved.
        let program = std::fs::canonicalize(&program).unwrap_or(program);
        let argument = program.to_str().and_then(program_argument);
        let mut builder = AutoLaunchBuilder::new();
        builder
            .set_args(&[ARG])
            .set_app_path(argument.as_deref().unwrap_or_default());
        #[cfg(target_os = "macos")]
        builder
            .set_app_name(identifier)
            .set_macos_launch_mode(auto_launch::MacOSLaunchMode::LaunchAgent)
            .set_bundle_identifiers(&[identifier])
            // Run as an app the user works with, not throttled as a
            // background job.
            .set_agent_extra_config("<key>ProcessType</key>\n  <string>Interactive</string>");
        #[cfg(windows)]
        builder
            .set_app_name(name)
            // Not the machine's `Run` key, even if the app runs elevated.
            .set_windows_enable_mode(auto_launch::WindowsEnableMode::CurrentUser);
        #[cfg(target_os = "linux")]
        builder
            .set_app_name(name)
            .set_linux_launch_mode(auto_launch::LinuxLaunchMode::XdgAutostart);
        let launcher = builder.build().map_err(io_error)?;
        Ok(Self {
            launcher,
            file: entry_file(identifier, name),
            blocker,
            unfit_path: argument.is_none(),
        })
    }

    /// The system's entry as it is now.
    pub fn status(&self) -> AppResult<AutostartStatus> {
        let registered = self.launcher.is_enabled().map_err(io_error)?;
        let turned_off_in_settings = registered
            && cfg!(target_os = "macos")
            && self
                .file
                .as_deref()
                .is_some_and(sshkm_os::login_item::launch_agent_turned_off);
        let hidden_entry = registered && cfg!(target_os = "linux") && self.entry_hidden();
        Ok(AutostartStatus {
            enabled: registered && !turned_off_in_settings && !hidden_entry,
            turned_off_in_settings,
            blocker: self.blocker,
        })
    }

    /// Adds the entry for this copy, or removes it. On macOS, an entry the
    /// user turned off in System Settings stays off until they allow it
    /// there, so that pane opens.
    pub fn set_enabled(&self, on: bool) -> AppResult<AutostartStatus> {
        if !on {
            self.launcher.disable().map_err(io_error)?;
            return self.status();
        }
        if self.blocker.is_some() {
            return Err(AppError::new(
                ErrorCode::Unsupported,
                "this copy of the app runs from a place that goes away",
            ));
        }
        if self.unfit_path {
            return Err(AppError::new(
                ErrorCode::Unsupported,
                "the app's path can't go into the login entry",
            ));
        }
        self.launcher.enable().map_err(io_error)?;
        let status = self.status()?;
        if status.turned_off_in_settings {
            sshkm_os::login_item::open_settings();
        }
        Ok(status)
    }

    /// Linux: the entry is there but turned off by the desktop's settings.
    fn entry_hidden(&self) -> bool {
        self.file
            .as_deref()
            .and_then(|file| std::fs::read_to_string(file).ok())
            .is_some_and(|text| desktop_entry_turned_off(&text))
    }
}

fn io_error(e: impl std::fmt::Display) -> AppError {
    AppError::new(ErrorCode::Io, e.to_string())
}

/// Where `auto-launch` keeps the entry, when it is a file.
fn entry_file(identifier: &str, name: &str) -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    if cfg!(target_os = "macos") {
        Some(
            home.join("Library/LaunchAgents")
                .join(format!("{identifier}.plist")),
        )
    } else if cfg!(target_os = "linux") {
        Some(
            home.join(".config/autostart")
                .join(format!("{name}.desktop")),
        )
    } else {
        None
    }
}

/// The program's path as the entry's command line takes it, or `None` if it
/// can't hold it. `auto-launch` writes the path as it is given, then the
/// arguments after a space.
#[cfg(target_os = "macos")]
fn program_argument(program: &str) -> Option<String> {
    plist_string(program)
}

#[cfg(windows)]
fn program_argument(program: &str) -> Option<String> {
    windows_argument(program)
}

#[cfg(target_os = "linux")]
fn program_argument(program: &str) -> Option<String> {
    desktop_exec_argument(program)
}

/// macOS: the path goes into the launch agent's XML as it is (and must exist
/// as written), so one with markup in it is refused.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn plist_string(program: &str) -> Option<String> {
    (!program.contains(['&', '<', '>'])).then(|| program.to_owned())
}

/// Windows: in quotes, or a path with spaces would start the first program
/// along it that exists (`C:\Users\Jo Smith\…` runs `C:\Users\Jo.exe`).
/// Windows paths can't hold quotes.
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_argument(program: &str) -> Option<String> {
    (!program.contains('"')).then(|| format!("\"{program}\""))
}

/// Linux: one argument of a desktop entry's `Exec` key. In double quotes,
/// with `"`, `` ` ``, `$` and `\` escaped by a backslash, and then, by the
/// rule for every string value that applies before the quoting, each
/// backslash doubled; `%` doubled, since it starts a field code. A path with
/// a control character (a line break would end the key) is refused.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn desktop_exec_argument(program: &str) -> Option<String> {
    let mut out = String::with_capacity(program.len() + 2);
    out.push('"');
    for c in program.chars() {
        match c {
            c if c.is_control() => return None,
            '"' | '`' | '$' => {
                out.push_str("\\\\");
                out.push(c);
            }
            '\\' => out.push_str("\\\\\\\\"),
            '%' => out.push_str("%%"),
            c => out.push(c),
        }
    }
    out.push('"');
    Some(out)
}

/// Linux: whether a desktop's settings turned the autostart entry off while
/// keeping the file (`Hidden=true`, or GNOME's
/// `X-GNOME-Autostart-enabled=false`).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn desktop_entry_turned_off(text: &str) -> bool {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .any(|(key, value)| match (key.trim(), value.trim()) {
            ("Hidden", value) => value == "true",
            ("X-GNOME-Autostart-enabled", value) => value == "false",
            _ => false,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_systems_launch_at_login_starts_hidden() {
        let at_login = |args: &[&str]| launched_at_login(args);
        assert!(at_login(&[
            "/Applications/SSH Key Manager.app/Contents/MacOS/sshkm-app",
            ARG
        ]));
        assert!(at_login(&[
            r"C:\Program Files\SSH Key Manager\sshkm-app.exe",
            ARG
        ]));
        assert!(!at_login(&["/usr/bin/sshkm-app"]));
        assert!(!at_login(&["/usr/bin/sshkm-app", "--autostart=1"]));
        assert!(!at_login(&["/usr/bin/sshkm-app", "--quick"]));

        // At login with the tray icon: in the tray, no window.
        assert!(starts_hidden(true, true));
        // No tray icon (the setting off, or none on this desktop): the
        // window, or nothing would lead back to the app.
        assert!(!starts_hidden(true, false));
        // Opened by the user: the window, as always.
        assert!(!starts_hidden(false, true));
        assert!(!starts_hidden(false, false));
    }

    #[test]
    fn turning_it_on_keeps_the_app_running_where_the_tray_can() {
        let background = |enabled, available| BackgroundStatus { enabled, available };
        assert!(keeps_running_too(true, &background(false, true)));
        // Already on.
        assert!(!keeps_running_too(true, &background(true, true)));
        // No tray on this desktop: the app opens its window at login.
        assert!(!keeps_running_too(true, &background(false, false)));
        // Turning it off leaves the background as it is.
        assert!(!keeps_running_too(false, &background(true, true)));
        assert!(!keeps_running_too(false, &background(false, true)));
    }

    #[test]
    fn windows_quotes_the_program() {
        assert_eq!(
            windows_argument(r"C:\Users\Jo Smith\AppData\Local\SSH Key Manager\sshkm-app.exe")
                .as_deref(),
            Some(r#""C:\Users\Jo Smith\AppData\Local\SSH Key Manager\sshkm-app.exe""#)
        );
        assert_eq!(windows_argument(r#"C:\a"b.exe"#), None);
    }

    #[test]
    fn a_launch_agent_takes_no_markup() {
        let app = "/Applications/SSH Key Manager.app/Contents/MacOS/sshkm-app";
        assert_eq!(plist_string(app).as_deref(), Some(app));
        assert_eq!(plist_string("/Users/jo/Apps & Tools/SSH.app/x"), None);
        assert_eq!(plist_string("/Users/jo/<b>/x"), None);
    }

    #[test]
    fn a_desktop_entry_quotes_the_program() {
        let exec = |path| desktop_exec_argument(path);
        assert_eq!(
            exec("/usr/bin/sshkm-app").as_deref(),
            Some(r#""/usr/bin/sshkm-app""#)
        );
        // An AppImage's default name has spaces.
        assert_eq!(
            exec("/home/jo/Apps/SSH Key Manager_0.8.0_amd64.AppImage").as_deref(),
            Some(r#""/home/jo/Apps/SSH Key Manager_0.8.0_amd64.AppImage""#)
        );
        // Escaped for the quoting, then backslashes doubled for the string.
        assert_eq!(
            exec(r#"/home/jo/a"b`c$d\e"#).as_deref(),
            Some(r#""/home/jo/a\\"b\\`c\\$d\\\\e""#)
        );
        assert_eq!(
            exec("/home/jo/100%/app").as_deref(),
            Some(r#""/home/jo/100%%/app""#)
        );
        assert_eq!(exec("/home/jo/a\nb"), None);
    }

    /// Nothing is written: the copy is refused before the system is asked.
    #[test]
    fn a_copy_that_goes_away_is_not_registered() {
        for (program, blocker) in [
            (
                HostProgram::Temporary("/tmp/.mount_SSHabc/usr/bin/sshkm-app".into()),
                AutostartBlocker::Temporary,
            ),
            (
                HostProgram::Mounted("/Volumes/SSH Key Manager/SSH Key Manager.app".into()),
                AutostartBlocker::Mounted,
            ),
        ] {
            let entry =
                LoginEntry::new("dev.sshkeymanager.test", "SSH Key Manager test", program).unwrap();
            assert_eq!(entry.blocker, Some(blocker));
            let error = entry.set_enabled(true).unwrap_err();
            assert_eq!(error.code(), ErrorCode::Unsupported);
        }
    }

    #[test]
    fn a_desktop_can_turn_the_entry_off() {
        let entry = "[Desktop Entry]\nType=Application\nName=SSH Key Manager\nExec=\"/usr/bin/sshkm-app\" --autostart\n";
        assert!(!desktop_entry_turned_off(entry));
        assert!(desktop_entry_turned_off(&format!("{entry}Hidden=true\n")));
        assert!(desktop_entry_turned_off(&format!(
            "{entry}X-GNOME-Autostart-enabled = false\n"
        )));
        assert!(!desktop_entry_turned_off(&format!("{entry}Hidden=false\n")));
        assert!(!desktop_entry_turned_off(&format!(
            "{entry}X-GNOME-Autostart-enabled=true\n"
        )));
    }
}
