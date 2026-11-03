//! Opening the system terminal with `ssh <alias>`.

use std::io;
use std::process::{Command, Stdio};

use crate::error::{AppError, AppResult};

/// Opens a new window of the system terminal running `ssh -- <alias>`:
/// Terminal.app on macOS, Windows Terminal (or a console window) on Windows,
/// the desktop's terminal emulator on Linux.
pub fn open_external(alias: &str) -> AppResult<()> {
    // The alias reaches a shell or a terminal's own argument parser, so only
    // host-name characters pass.
    if !is_plain_alias(alias) {
        return Err(AppError::invalid("not a host alias"));
    }
    platform::open(alias)
}

fn is_plain_alias(alias: &str) -> bool {
    !alias.is_empty()
        && !alias.starts_with('-')
        && alias
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-@:[]".contains(c))
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
        spawn_detached(Command::new("open").args(["-a", "Terminal"]).arg(&script))?;
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

    /// Windows Terminal if installed, else a console window.
    pub fn open(alias: &str) -> AppResult<()> {
        if spawn_detached(Command::new("wt.exe").args(["new-tab", "ssh.exe", "--", alias])).is_ok()
        {
            return Ok(());
        }
        // `start` opens the new console; `cmd` itself stays hidden.
        spawn_detached(
            Command::new("cmd.exe")
                .args(["/c", "start", "", "ssh.exe", "--", alias])
                .creation_flags(CREATE_NO_WINDOW),
        )?;
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
    /// command.
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

    #[test]
    fn only_plain_aliases_go_out() {
        for alias in [
            "prod-api",
            "bastion.example.net",
            "git@github.com",
            "[::1]:22",
            "a_b",
        ] {
            assert!(is_plain_alias(alias), "{alias}");
        }
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
        ] {
            assert!(!is_plain_alias(alias), "{alias}");
            assert!(open_external(alias).is_err());
        }
    }
}
