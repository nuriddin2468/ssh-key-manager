//! Opening the system terminal with `ssh <alias>`.

use std::io;
use std::process::{Command, Stdio};

use crate::commands::remote::check_alias;
use crate::error::AppResult;

/// Opens a new window of the system terminal running `ssh -- <alias>`:
/// Terminal.app on macOS, Windows Terminal (or a console window) on Windows,
/// the desktop's terminal emulator on Linux.
pub fn open_external(alias: &str) -> AppResult<()> {
    // The alias reaches a shell or a terminal's own argument parser too, so
    // only host-name characters pass.
    check_alias(alias)?;
    platform::open(alias)
}

/// Starts `command` without waiting for it, reaping it in the background.
fn spawn_detached(command: &mut Command) -> io::Result<()> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

#[cfg(target_os = "macos")]
mod platform {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    use std::time::Duration;

    use super::spawn_detached;
    use crate::error::AppResult;

    /// Terminal.app runs a `.command` file in a new window; no automation
    /// permission needed. The file is removed once Terminal has read it.
    pub fn open(alias: &str) -> AppResult<()> {
        let dir = tempfile::Builder::new()
            .prefix("sshkm-terminal-")
            .tempdir()?;
        let script = dir.path().join(format!("{alias}.command"));
        std::fs::write(
            &script,
            format!("#!/bin/sh\nclear\nexec ssh -- '{alias}'\n"),
        )?;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))?;
        spawn_detached(
            Command::new("/usr/bin/open")
                .args(["-a", "Terminal"])
                .arg(&script),
        )?;
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(30));
            drop(dir);
        });
        Ok(())
    }
}

#[cfg(windows)]
mod platform {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    use super::spawn_detached;
    use crate::error::AppResult;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    /// Windows Terminal if installed (found on `PATH`, where Windows puts
    /// it), else a console window through `cmd.exe` from the system folder.
    /// `ssh.exe` is looked up on `PATH` as usual, but never in the folder
    /// the app was started in: both start in the home folder and are told
    /// not to search the current one.
    pub fn open(alias: &str) -> AppResult<()> {
        let safe = |command: &mut Command| {
            if let Some(home) = sshkm_core::paths::home_dir() {
                command.current_dir(home);
            }
            command.env("NoDefaultCurrentDirectoryInExePath", "1");
        };
        let mut terminal = Command::new("wt.exe");
        terminal.args(["new-tab", "ssh.exe", "--", alias]);
        safe(&mut terminal);
        if spawn_detached(&mut terminal).is_ok() {
            return Ok(());
        }
        // `start` opens the new console; `cmd` itself stays hidden.
        let mut console = Command::new(sshkm_core::paths::system32("cmd.exe"));
        console
            .args(["/c", "start", "", "ssh.exe", "--", alias])
            .creation_flags(CREATE_NO_WINDOW);
        safe(&mut console);
        spawn_detached(&mut console)?;
        Ok(())
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod platform {
    use std::io;
    use std::process::Command;

    use super::spawn_detached;
    use crate::error::{AppError, AppResult};

    /// The first terminal emulator found, each with its way of running a
    /// command. They and `ssh` are found on `PATH`: the user's own programs,
    /// wherever they are installed.
    const TERMINALS: [(&str, &[&str]); 10] = [
        ("x-terminal-emulator", &["-e"]),
        ("gnome-terminal", &["--"]),
        ("ptyxis", &["--"]),
        ("konsole", &["-e"]),
        ("xfce4-terminal", &["-x"]),
        ("kitty", &[]),
        ("alacritty", &["-e"]),
        ("wezterm", &["start", "--"]),
        ("foot", &[]),
        ("xterm", &["-e"]),
    ];

    pub fn open(alias: &str) -> AppResult<()> {
        for (program, run) in TERMINALS {
            let mut command = Command::new(program);
            command.args(run).args(["ssh", "--", alias]);
            match spawn_detached(&mut command) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(AppError::not_found("no terminal emulator found"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Refused before any terminal starts; what [`check_alias`] lets through
    /// is tested with it.
    #[test]
    fn only_plain_aliases_go_out() {
        for alias in [
            "",
            "-oProxyCommand=x",
            "a b",
            "a;b",
            "a'b",
            "a&b",
            "a|b",
            "$(x)",
            "a\"b",
            "web-*",
        ] {
            assert!(open_external(alias).is_err(), "{alias}");
        }
    }
}
