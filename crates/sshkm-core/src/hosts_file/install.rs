//! Writing the hosts file with administrator rights.
//!
//! The app never runs with administrator rights itself. To replace the hosts
//! file it writes the new text to a private temporary file and asks the system
//! to run one short, fixed script elevated: `osascript … with administrator
//! privileges` on macOS, `pkexec` on Linux, a UAC prompt on Windows. The
//! script copies the text somewhere the user cannot change it, checks its
//! SHA-256 against the text the user approved, and only then puts it in place,
//! so another program cannot swap the temporary file in between.

use std::{
    io::{self, Write as _},
    path::Path,
};

use super::revision_of;
use crate::{Error, Result};

/// How an install ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOutcome {
    /// The file was replaced.
    Installed,
    /// The user dismissed the password prompt; nothing changed.
    Cancelled,
}

/// Whether this system can ask for administrator rights.
pub fn can_install() -> bool {
    cfg!(any(target_os = "macos", windows)) || in_path("pkexec")
}

/// Replaces `target` with `text` with administrator rights, then clears the
/// system's DNS cache if `flush_dns` is set. `prompt` is the reason the macOS
/// password dialog shows.
pub fn install(text: &str, target: &Path, flush_dns: bool, prompt: &str) -> Result<InstallOutcome> {
    let mut staged = tempfile::Builder::new()
        .prefix("sshkm-hosts-")
        .tempfile()
        .map_err(|e| Error::io(e, &std::env::temp_dir()))?;
    staged
        .write_all(text.as_bytes())
        .and_then(|()| staged.flush())
        .map_err(|e| Error::io(e, staged.path()))?;
    // Closed before the elevated step reads it: Windows will not share a file
    // that is open for writing.
    let staged = staged.into_temp_path();
    elevated::run(
        &staged,
        target,
        &revision_of(text.as_bytes()),
        flush_dns,
        prompt,
    )
}

fn in_path(program: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(program).is_file()))
}

fn failure(message: &str) -> Error {
    Error::Io {
        context: "updating the hosts file".into(),
        source: io::Error::other(message.trim().to_owned()),
    }
}

/// The elevated step on macOS and Linux: `sh -c <script> sshkm <source>
/// <target> <sha256> <flush 0|1>`. Exit 3: checksum mismatch; 4: the target
/// is a symbolic link (managed by another tool).
#[cfg_attr(windows, allow(dead_code))]
fn posix_script(flush: &str) -> String {
    format!(
        r#"set -eu
src=$1 dst=$2 want=$3 flush=$4
if [ -L "$dst" ]; then echo "$dst is a symbolic link" >&2; exit 4; fi
staged="$dst.sshkm-new"
umask 022
rm -f "$staged"
cp "$src" "$staged"
if command -v sha256sum >/dev/null 2>&1; then got=$(sha256sum "$staged"); else got=$(shasum -a 256 "$staged"); fi
got=${{got%% *}}
if [ "$got" != "$want" ]; then rm -f "$staged"; echo "checksum mismatch" >&2; exit 3; fi
chmod 644 "$staged"
mv -f "$staged" "$dst"
if command -v restorecon >/dev/null 2>&1; then restorecon "$dst" || true; fi
if [ "$flush" = 1 ]; then {flush}; fi
"#
    )
}

/// A PowerShell single-quoted string.
#[cfg_attr(not(windows), allow(dead_code))]
fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// `-EncodedCommand` takes UTF-16LE in Base64.
#[cfg_attr(not(windows), allow(dead_code))]
fn ps_encode(script: &str) -> String {
    use base64ct::{Base64, Encoding};
    let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    Base64::encode_string(&utf16)
}

/// The elevated step on Windows. It reads the staged file once, checks those
/// bytes and writes the same bytes, which keeps the hosts file's ACL. Exit 3:
/// checksum mismatch; 4: reading or writing failed.
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_install_script(source: &Path, target: &Path, checksum: &str, flush_dns: bool) -> String {
    format!(
        "$ErrorActionPreference = 'Stop'\n\
         try {{\n\
         $bytes = [IO.File]::ReadAllBytes({src})\n\
         $sha = [Security.Cryptography.SHA256]::Create()\n\
         $got = -join ($sha.ComputeHash($bytes) | ForEach-Object {{ $_.ToString('x2') }})\n\
         if ($got -ne {sum}) {{ exit 3 }}\n\
         [IO.File]::WriteAllBytes({dst}, $bytes)\n\
         }} catch {{ exit 4 }}\n\
         if (${flush}) {{ ipconfig /flushdns | Out-Null }}\n\
         exit 0\n",
        src = ps_quote(&source.to_string_lossy()),
        dst = ps_quote(&target.to_string_lossy()),
        sum = ps_quote(checksum),
        flush = if flush_dns { "true" } else { "false" },
    )
}

/// Starts `inner` elevated through UAC and passes on its exit code; 1223
/// (`ERROR_CANCELLED`) when the prompt is declined.
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_elevate_script(inner: &str) -> String {
    format!(
        "try {{\n\
         $p = Start-Process -FilePath 'powershell.exe' -Verb RunAs -PassThru -WindowStyle Hidden \
         -ArgumentList '-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand','{encoded}'\n\
         $null = $p.Handle\n\
         $p.WaitForExit()\n\
         exit $p.ExitCode\n\
         }} catch {{\n\
         $e = $_.Exception\n\
         while ($e) {{ if ($e.NativeErrorCode -eq 1223) {{ exit 1223 }}; $e = $e.InnerException }}\n\
         [Console]::Error.WriteLine($_.Exception.Message)\n\
         exit 1\n\
         }}\n",
        encoded = ps_encode(inner),
    )
}

#[cfg(target_os = "macos")]
mod elevated {
    use std::{
        path::Path,
        process::{Command, Stdio},
    };

    use super::{InstallOutcome, failure, posix_script};
    use crate::{Error, Result};

    /// `quoted form of` does the shell quoting, so nothing user-controlled is
    /// pasted into the script.
    const SCRIPT: &str = "do shell script \"/bin/sh -c \" & quoted form of (item 1 of argv) \
        & \" sshkm \" & quoted form of (item 2 of argv) & \" \" & quoted form of (item 3 of argv) \
        & \" \" & quoted form of (item 4 of argv) & \" \" & quoted form of (item 5 of argv) \
        with prompt (item 6 of argv) with administrator privileges";

    pub(super) fn run(
        source: &Path,
        target: &Path,
        checksum: &str,
        flush_dns: bool,
        prompt: &str,
    ) -> Result<InstallOutcome> {
        let script =
            posix_script("dscacheutil -flushcache || true; killall -HUP mDNSResponder || true");
        let osascript = Path::new("/usr/bin/osascript");
        let output = Command::new(osascript)
            .args(["-e", "on run argv", "-e", SCRIPT, "-e", "end run"])
            .arg(&script)
            .arg(source)
            .arg(target)
            .arg(checksum)
            .arg(if flush_dns { "1" } else { "0" })
            .arg(prompt)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| Error::io(e, osascript))?;
        if output.status.success() {
            return Ok(InstallOutcome::Installed);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        // AppleScript error -128: "User canceled."
        if stderr.contains("(-128)") {
            return Ok(InstallOutcome::Cancelled);
        }
        Err(failure(&stderr))
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod elevated {
    use std::{
        io,
        path::Path,
        process::{Command, Stdio},
    };

    use super::{InstallOutcome, failure, posix_script};
    use crate::{Error, Result};

    pub(super) fn run(
        source: &Path,
        target: &Path,
        checksum: &str,
        flush_dns: bool,
        _prompt: &str,
    ) -> Result<InstallOutcome> {
        let script = posix_script(
            "if command -v resolvectl >/dev/null 2>&1; then resolvectl flush-caches || true; fi; \
             if command -v nscd >/dev/null 2>&1; then nscd -i hosts || true; fi",
        );
        let output = Command::new("pkexec")
            .args(["/bin/sh", "-c", &script, "sshkm"])
            .arg(source)
            .arg(target)
            .arg(checksum)
            .arg(if flush_dns { "1" } else { "0" })
            .stdin(Stdio::null())
            .output();
        let output = match output {
            Ok(output) => output,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(Error::Unsupported("pkexec is not installed".into()));
            }
            Err(e) => return Err(Error::io(e, Path::new("pkexec"))),
        };
        match output.status.code() {
            Some(0) => Ok(InstallOutcome::Installed),
            // pkexec: the user dismissed the authentication dialog.
            Some(126) => Ok(InstallOutcome::Cancelled),
            _ => Err(failure(&String::from_utf8_lossy(&output.stderr))),
        }
    }
}

#[cfg(windows)]
mod elevated {
    use std::{
        os::windows::process::CommandExt,
        path::Path,
        process::{Command, Stdio},
    };

    use super::{
        InstallOutcome, failure, ps_encode, windows_elevate_script, windows_install_script,
    };
    use crate::{Error, Result};

    /// `CREATE_NO_WINDOW`: do not flash a console window from the GUI app.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    pub(super) fn run(
        source: &Path,
        target: &Path,
        checksum: &str,
        flush_dns: bool,
        _prompt: &str,
    ) -> Result<InstallOutcome> {
        let inner = windows_install_script(source, target, checksum, flush_dns);
        let outer = windows_elevate_script(&inner);
        let output = Command::new("powershell.exe")
            .env_remove("PSModulePath")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                &ps_encode(&outer),
            ])
            .stdin(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| Error::io(e, Path::new("powershell.exe")))?;
        match output.status.code() {
            Some(0) => Ok(InstallOutcome::Installed),
            Some(1223) => Ok(InstallOutcome::Cancelled),
            Some(3) => Err(failure("checksum mismatch")),
            Some(4) => Err(Error::PermissionDenied(
                "Windows refused to write the hosts file. Security software may be blocking \
                 changes to it."
                    .into(),
            )),
            _ => Err(failure(&String::from_utf8_lossy(&output.stderr))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn powershell_quoting() {
        assert_eq!(
            ps_quote(r"C:\Users\O'Brien\hosts"),
            r"'C:\Users\O''Brien\hosts'"
        );
        let inner = windows_install_script(Path::new("a'b"), Path::new("c"), "ff", true);
        assert!(inner.contains("ReadAllBytes('a''b')"));
        assert!(inner.contains("if ($true)"));
        let outer = windows_elevate_script("exit 0");
        assert!(outer.contains(&ps_encode("exit 0")));
        assert!(!ps_encode("exit 0").contains('\''));
    }

    #[cfg(unix)]
    mod posix {
        use std::{fs, os::unix::fs::PermissionsExt, process::Command};

        use super::super::{posix_script, revision_of};

        fn run(src: &std::path::Path, dst: &std::path::Path, sum: &str) -> i32 {
            Command::new("/bin/sh")
                .args(["-c", &posix_script("echo flushed"), "sshkm"])
                .arg(src)
                .arg(dst)
                .args([sum, "0"])
                .output()
                .unwrap()
                .status
                .code()
                .unwrap()
        }

        #[test]
        fn installs_only_the_approved_text() {
            let dir = tempfile::tempdir().unwrap();
            let (src, dst) = (dir.path().join("new"), dir.path().join("hosts"));
            fs::write(&src, "10.0.0.1 box\n").unwrap();
            fs::write(&dst, "127.0.0.1 localhost\n").unwrap();

            assert_eq!(run(&src, &dst, &revision_of(b"something else")), 3);
            assert_eq!(fs::read_to_string(&dst).unwrap(), "127.0.0.1 localhost\n");
            assert!(!dir.path().join("hosts.sshkm-new").exists());

            assert_eq!(run(&src, &dst, &revision_of(b"10.0.0.1 box\n")), 0);
            assert_eq!(fs::read_to_string(&dst).unwrap(), "10.0.0.1 box\n");
            let mode = fs::metadata(&dst).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644);
        }

        #[test]
        fn refuses_a_linked_hosts_file() {
            let dir = tempfile::tempdir().unwrap();
            let (src, real, dst) = (
                dir.path().join("new"),
                dir.path().join("real"),
                dir.path().join("hosts"),
            );
            fs::write(&src, "x").unwrap();
            fs::write(&real, "managed elsewhere").unwrap();
            std::os::unix::fs::symlink(&real, &dst).unwrap();
            assert_eq!(run(&src, &dst, &revision_of(b"x")), 4);
            assert_eq!(fs::read_to_string(&real).unwrap(), "managed elsewhere");
        }
    }

    // Runs the elevated step's script without elevation against temporary
    // files, which covers everything but the UAC prompt.
    #[cfg(windows)]
    #[test]
    fn windows_script_installs_only_the_approved_text() {
        use std::{fs, process::Command};
        let dir = tempfile::tempdir().unwrap();
        let (src, dst) = (dir.path().join("new"), dir.path().join("hosts"));
        fs::write(&src, "10.0.0.1 box\r\n").unwrap();
        fs::write(&dst, "old\r\n").unwrap();
        let run = |sum: &str| {
            Command::new("powershell.exe")
                .env_remove("PSModulePath")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                ])
                .args([
                    "-EncodedCommand",
                    &ps_encode(&windows_install_script(&src, &dst, sum, false)),
                ])
                .output()
                .unwrap()
                .status
                .code()
        };
        assert_eq!(run(&revision_of(b"other")), Some(3));
        assert_eq!(fs::read_to_string(&dst).unwrap(), "old\r\n");
        assert_eq!(run(&revision_of(b"10.0.0.1 box\r\n")), Some(0));
        assert_eq!(fs::read_to_string(&dst).unwrap(), "10.0.0.1 box\r\n");
    }
}
