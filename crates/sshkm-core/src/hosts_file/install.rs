//! Writing the hosts file with administrator rights.
//!
//! The app never runs with administrator rights itself. To replace the hosts
//! file it writes the new text to a private temporary file and asks the system
//! to run one short, fixed script elevated: `osascript … with administrator
//! privileges` on macOS, `pkexec` on Linux, a UAC prompt on Windows. The
//! script copies the text somewhere the user cannot change it, checks its
//! length and SHA-256 against the text the user approved, and only then puts
//! it in place, so another program cannot swap the temporary file in between.
//! Right before that it checks that the hosts file is still the revision the
//! text was made from, so changes made while the password prompt was open are
//! not overwritten.

use std::{
    ffi::OsString,
    io::{self, Write as _},
    path::{Path, PathBuf},
};

use super::revision_of;
use crate::{Error, Result};

/// Exit code of the elevated step when the hosts file is no longer the
/// revision the new text was made from.
const STALE: i32 = 6;

/// How an install ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOutcome {
    /// The file was replaced.
    Installed,
    /// The user dismissed the password prompt; nothing changed.
    Cancelled,
    /// The file changed after it was read (while the password prompt was
    /// open, say); nothing changed.
    Stale,
}

/// Whether this system can ask for administrator rights.
pub fn can_install() -> bool {
    elevated::available()
}

/// Replaces `target` with `text` with administrator rights, then clears the
/// system's DNS cache if `flush_dns` is set. `revision` is the
/// [`HostsFile::revision`](super::HostsFile::revision) of the file `text`
/// replaces; if `target` is no longer that file, nothing changes. `prompt` is
/// the reason the macOS password dialog shows.
pub fn install(
    text: &str,
    target: &Path,
    revision: &str,
    flush_dns: bool,
    prompt: &str,
) -> Result<InstallOutcome> {
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
    let step = Step {
        source: &staged,
        target,
        checksum: revision_of(text.as_bytes()),
        len: text.len(),
        revision,
        flush_dns,
    };
    elevated::run(&step, prompt)
}

/// What the elevated step does: puts the approved text from `source` in
/// place of `target`.
struct Step<'a> {
    /// The private temporary copy of the text.
    source: &'a Path,
    target: &'a Path,
    /// SHA-256 of the approved text, in hex.
    checksum: String,
    /// Length of the approved text in bytes.
    len: usize,
    /// SHA-256 `target` must still have.
    revision: &'a str,
    flush_dns: bool,
}

impl Step<'_> {
    /// The arguments of [`posix_script`] after `$0`.
    #[cfg_attr(windows, allow(dead_code))]
    fn posix_args(&self) -> Vec<OsString> {
        vec![
            self.source.into(),
            self.target.into(),
            self.checksum.clone().into(),
            self.len.to_string().into(),
            self.revision.into(),
            if self.flush_dns { "1" } else { "0" }.into(),
        ]
    }
}

fn failure(message: &str) -> Error {
    Error::Io {
        context: "updating the hosts file".into(),
        source: io::Error::other(message.trim().to_owned()),
    }
}

/// The elevated step on macOS and Linux: `sh -c <script> sshkm <source>
/// <target> <sha256> <length> <revision> <flush 0|1>`. It reads one byte
/// more than the approved text at most, and only from a regular file. Exit 2:
/// a bad length; 3: the source is not the approved text; 4: the target is a
/// symbolic link (managed by another tool); 6 ([`STALE`]): the target is no
/// longer `revision`.
#[cfg_attr(windows, allow(dead_code))]
fn posix_script(flush: &str) -> String {
    format!(
        r#"set -eu
src=$1 dst=$2 want=$3 size=$4 was=$5 flush=$6
case $size in ''|*[!0-9]*) echo "bad length: $size" >&2; exit 2;; esac
sha256() {{ if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi; }}
if [ -L "$dst" ]; then echo "$dst is a symbolic link" >&2; exit 4; fi
if [ ! -f "$src" ] || [ -L "$src" ]; then echo "$src is not a regular file" >&2; exit 3; fi
staged="$dst.sshkm-new"
umask 022
rm -f "$staged"
head -c "$((size + 1))" "$src" > "$staged"
got=$(sha256 < "$staged")
got=${{got%% *}}
len=$(wc -c < "$staged" | tr -d ' ')
if [ "$len" != "$size" ] || [ "$got" != "$want" ]; then rm -f "$staged"; echo "checksum mismatch" >&2; exit 3; fi
chmod 644 "$staged"
if [ -e "$dst" ]; then now=$(sha256 < "$dst"); else now=$(sha256 < /dev/null); fi
now=${{now%% *}}
if [ "$now" != "$was" ]; then rm -f "$staged"; echo "the hosts file changed" >&2; exit {STALE}; fi
mv -f "$staged" "$dst"
if command -v restorecon >/dev/null 2>&1; then restorecon "$dst" || true; fi
if [ "$flush" = 1 ]; then {flush}; fi
"#
    )
}

/// `name` in `default`, or else in the first folder on `path` that only root
/// can change: the folder and the program are owned by root and writable by
/// no one else. A program the user's own processes can put first on `PATH`
/// is never started.
#[cfg(unix)]
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn system_program(name: &str, default: &Path, path: &std::ffi::OsStr) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let root_only =
        |p: &Path| std::fs::metadata(p).is_ok_and(|m| m.uid() == 0 && m.mode() & 0o022 == 0);
    std::iter::once(default.to_path_buf())
        .chain(std::env::split_paths(path))
        .filter(|dir| dir.is_absolute() && root_only(dir))
        .map(|dir| dir.join(name))
        .find(|program| program.is_file() && root_only(program))
}

/// Windows PowerShell by absolute path, so no `powershell.exe` earlier on
/// `PATH` or next to the app is started instead.
#[cfg_attr(not(windows), allow(dead_code))]
fn powershell() -> PathBuf {
    crate::paths::system32("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe")
}

/// A PowerShell expression for `s`, in parentheses so that it is evaluated as
/// a command's argument too. The text goes in as Base64, which has no quotes:
/// PowerShell ends a single-quoted string at any of five characters (`'`,
/// `‘`, `’`, `‚`, `‛`), and a path can hold all of them.
#[cfg_attr(not(windows), allow(dead_code))]
fn ps_string(s: &str) -> String {
    use base64ct::{Base64, Encoding};
    format!(
        "([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{}')))",
        Base64::encode_string(s.as_bytes())
    )
}

/// `-EncodedCommand` takes UTF-16LE in Base64.
#[cfg_attr(not(windows), allow(dead_code))]
fn ps_encode(script: &str) -> String {
    use base64ct::{Base64, Encoding};
    let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    Base64::encode_string(&utf16)
}

/// The elevated step on Windows. It reads at most one byte more than the
/// approved text from the staged file, which must be a regular file, checks
/// those bytes and writes the same bytes, which keeps the hosts file's ACL.
/// Exit 3: the staged file is not the approved text; 4: reading or writing
/// failed; 6 ([`STALE`]): the target is no longer the step's revision.
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_install_script(step: &Step<'_>) -> String {
    let ipconfig = crate::paths::system32("ipconfig.exe");
    format!(
        "$ErrorActionPreference = 'Stop'\n\
         $sha = [Security.Cryptography.SHA256]::Create()\n\
         function Hex($data) {{ -join ($sha.ComputeHash($data) | ForEach-Object {{ $_.ToString('x2') }}) }}\n\
         try {{\n\
         $src = {src}\n\
         $dst = {dst}\n\
         $file = [IO.FileInfo]::new($src)\n\
         if (-not $file.Exists -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $file.Length -ne {len}) {{ exit 3 }}\n\
         $bytes = [byte[]]::new({len} + 1)\n\
         $read = 0\n\
         $stream = [IO.File]::OpenRead($src)\n\
         try {{\n\
         do {{ $n = $stream.Read($bytes, $read, $bytes.Length - $read); $read += $n }} while ($n -gt 0 -and $read -lt $bytes.Length)\n\
         }} finally {{ $stream.Dispose() }}\n\
         if ($read -ne {len}) {{ exit 3 }}\n\
         [Array]::Resize([ref]$bytes, {len})\n\
         if ((Hex $bytes) -ne {sum}) {{ exit 3 }}\n\
         if ([IO.File]::Exists($dst)) {{ $old = [IO.File]::OpenRead($dst) }} else {{ $old = [IO.MemoryStream]::new() }}\n\
         try {{ $now = Hex $old }} finally {{ $old.Dispose() }}\n\
         if ($now -ne {was}) {{ exit {STALE} }}\n\
         [IO.File]::WriteAllBytes($dst, $bytes)\n\
         }} catch {{ exit 4 }}\n\
         if (${flush}) {{ & {ipconfig} /flushdns | Out-Null }}\n\
         exit 0\n",
        src = ps_string(&step.source.to_string_lossy()),
        dst = ps_string(&step.target.to_string_lossy()),
        len = step.len,
        sum = ps_string(&step.checksum),
        was = ps_string(step.revision),
        flush = if step.flush_dns { "true" } else { "false" },
        ipconfig = ps_string(&ipconfig.to_string_lossy()),
    )
}

/// Starts `inner` elevated through UAC with `powershell` and passes on its
/// exit code; 1223 (`ERROR_CANCELLED`) when the prompt is declined.
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_elevate_script(powershell: &Path, inner: &str) -> String {
    format!(
        "try {{\n\
         $p = Start-Process -FilePath {exe} -Verb RunAs -PassThru -WindowStyle Hidden \
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
        exe = ps_string(&powershell.to_string_lossy()),
        encoded = ps_encode(inner),
    )
}

#[cfg(target_os = "macos")]
mod elevated {
    use std::{
        path::Path,
        process::{Command, Stdio},
    };

    use super::{InstallOutcome, STALE, Step, failure, posix_script};
    use crate::{Error, Result};

    /// `quoted form of` does the shell quoting, so nothing user-controlled is
    /// pasted into the script.
    const SCRIPT: &str = "do shell script \"/bin/sh -c \" & quoted form of (item 1 of argv) \
        & \" sshkm \" & quoted form of (item 2 of argv) & \" \" & quoted form of (item 3 of argv) \
        & \" \" & quoted form of (item 4 of argv) & \" \" & quoted form of (item 5 of argv) \
        & \" \" & quoted form of (item 6 of argv) & \" \" & quoted form of (item 7 of argv) \
        with prompt (item 8 of argv) with administrator privileges";

    pub(super) fn available() -> bool {
        true
    }

    pub(super) fn run(step: &Step<'_>, prompt: &str) -> Result<InstallOutcome> {
        let script =
            posix_script("dscacheutil -flushcache || true; killall -HUP mDNSResponder || true");
        let osascript = Path::new("/usr/bin/osascript");
        let output = Command::new(osascript)
            .args(["-e", "on run argv", "-e", SCRIPT, "-e", "end run"])
            .arg(&script)
            .args(step.posix_args())
            .arg(prompt)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| Error::io(e, osascript))?;
        if output.status.success() {
            return Ok(InstallOutcome::Installed);
        }
        failed(&String::from_utf8_lossy(&output.stderr))
    }

    /// Why `osascript` failed, from its error output: error -128 is "User
    /// canceled.", and a failed shell script ends the message with its exit
    /// code.
    pub(super) fn failed(stderr: &str) -> Result<InstallOutcome> {
        if stderr.contains("(-128)") {
            Ok(InstallOutcome::Cancelled)
        } else if stderr.trim_end().ends_with(&format!("({STALE})")) {
            Ok(InstallOutcome::Stale)
        } else {
            Err(failure(stderr))
        }
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod elevated {
    use std::{
        path::{Path, PathBuf},
        process::{Command, Stdio},
    };

    use super::{InstallOutcome, STALE, Step, failure, posix_script, system_program};
    use crate::{Error, Result};

    pub(super) fn available() -> bool {
        pkexec().is_some()
    }

    /// `/usr/bin/pkexec`, or one in another folder on `PATH` that only root
    /// can change.
    fn pkexec() -> Option<PathBuf> {
        let path = std::env::var_os("PATH").unwrap_or_default();
        system_program("pkexec", Path::new("/usr/bin"), &path)
    }

    pub(super) fn run(step: &Step<'_>, _prompt: &str) -> Result<InstallOutcome> {
        let script = posix_script(
            "if command -v resolvectl >/dev/null 2>&1; then resolvectl flush-caches || true; fi; \
             if command -v nscd >/dev/null 2>&1; then nscd -i hosts || true; fi",
        );
        let pkexec =
            pkexec().ok_or_else(|| Error::Unsupported("pkexec is not installed".into()))?;
        let output = Command::new(&pkexec)
            .args(["/bin/sh", "-c", &script, "sshkm"])
            .args(step.posix_args())
            .stdin(Stdio::null())
            .output()
            .map_err(|e| Error::io(e, &pkexec))?;
        match output.status.code() {
            Some(0) => Ok(InstallOutcome::Installed),
            // pkexec: the user dismissed the authentication dialog.
            Some(126) => Ok(InstallOutcome::Cancelled),
            Some(STALE) => Ok(InstallOutcome::Stale),
            _ => Err(failure(&String::from_utf8_lossy(&output.stderr))),
        }
    }
}

#[cfg(windows)]
mod elevated {
    use std::{
        os::windows::process::CommandExt,
        process::{Command, Stdio},
    };

    use super::{
        InstallOutcome, STALE, Step, failure, powershell, ps_encode, windows_elevate_script,
        windows_install_script,
    };
    use crate::{Error, Result};

    /// `CREATE_NO_WINDOW`: do not flash a console window from the GUI app.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    pub(super) fn available() -> bool {
        true
    }

    pub(super) fn run(step: &Step<'_>, _prompt: &str) -> Result<InstallOutcome> {
        let powershell = powershell();
        let inner = windows_install_script(step);
        let outer = windows_elevate_script(&powershell, &inner);
        let output = Command::new(&powershell)
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
            .map_err(|e| Error::io(e, &powershell))?;
        match output.status.code() {
            Some(0) => Ok(InstallOutcome::Installed),
            Some(1223) => Ok(InstallOutcome::Cancelled),
            Some(3) => Err(failure("checksum mismatch")),
            Some(4) => Err(Error::PermissionDenied(
                "Windows refused to write the hosts file. Security software may be blocking \
                 changes to it."
                    .into(),
            )),
            Some(STALE) => Ok(InstallOutcome::Stale),
            _ => Err(failure(&String::from_utf8_lossy(&output.stderr))),
        }
    }
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64, Encoding};

    use super::*;

    fn step<'a>(source: &'a Path, target: &'a Path, text: &[u8], revision: &'a str) -> Step<'a> {
        Step {
            source,
            target,
            checksum: revision_of(text),
            len: text.len(),
            revision,
            flush_dns: false,
        }
    }

    /// The text inside each `FromBase64String('…')` of a script.
    fn ps_strings(script: &str) -> Vec<String> {
        script
            .split("FromBase64String('")
            .skip(1)
            .map(|rest| {
                let encoded = rest.split_once('\'').unwrap().0;
                String::from_utf8(Base64::decode_vec(encoded).unwrap()).unwrap()
            })
            .collect()
    }

    #[test]
    fn powershell_strings_hold_any_quote() {
        // PowerShell ends a single-quoted string at any of these.
        let quotes = ['\'', '\u{2018}', '\u{2019}', '\u{201a}', '\u{201b}'];
        let source = Path::new(r"C:\Users\O’Brien\AppData\Local\Temp\a'‘’‚‛b");
        let target = Path::new(r"C:\Windows\System32\drivers\etc\hosts");
        let revision = revision_of(b"old");
        let inner = windows_install_script(&step(source, target, b"new", &revision));
        assert_eq!(
            ps_strings(&inner)[..4],
            [
                source.to_string_lossy().into_owned(),
                target.to_string_lossy().into_owned(),
                revision_of(b"new"),
                revision,
            ]
        );
        assert!(!inner.contains(&quotes[1..]));
        assert!(inner.contains("$file.Length -ne 3)"));
        assert!(inner.contains("if ($false)"));

        let exe = Path::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
        let outer = windows_elevate_script(exe, "exit 0");
        assert_eq!(ps_strings(&outer), [exe.to_string_lossy()]);
        assert!(outer.contains(&ps_encode("exit 0")));
        assert!(!ps_encode("exit 0").contains(quotes));
    }

    #[test]
    fn powershell_is_found_by_absolute_path() {
        let exe = powershell();
        assert!(exe.ends_with("powershell.exe"));
        if cfg!(windows) {
            assert!(exe.is_absolute());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn osascript_errors() {
        use super::elevated::failed;
        assert_eq!(
            failed("0:254: execution error: User canceled. (-128)\n").unwrap(),
            InstallOutcome::Cancelled
        );
        assert_eq!(
            failed("0:254: execution error: the hosts file changed (6)\n").unwrap(),
            InstallOutcome::Stale
        );
        assert!(failed("0:254: execution error: checksum mismatch (3)\n").is_err());
        assert!(failed("0:254: execution error: line (6) of something (1)\n").is_err());
    }

    #[cfg(unix)]
    mod posix {
        use std::{
            ffi::OsStr,
            fs,
            os::unix::fs::{MetadataExt, PermissionsExt},
            path::{Path, PathBuf},
            process::Command,
        };

        use super::super::{Step, posix_script, revision_of, system_program};
        use super::step;

        fn run(step: &Step<'_>) -> i32 {
            Command::new("/bin/sh")
                .args(["-c", &posix_script("echo flushed"), "sshkm"])
                .args(step.posix_args())
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
            let old = revision_of(b"127.0.0.1 localhost\n");

            let mut other = step(&src, &dst, b"10.0.0.1 box\n", &old);
            other.checksum = revision_of(b"10.0.0.1 bot\n");
            assert_eq!(run(&other), 3);
            assert_eq!(fs::read_to_string(&dst).unwrap(), "127.0.0.1 localhost\n");
            assert!(!dir.path().join("hosts.sshkm-new").exists());

            assert_eq!(run(&step(&src, &dst, b"10.0.0.1 box\n", &old)), 0);
            assert_eq!(fs::read_to_string(&dst).unwrap(), "10.0.0.1 box\n");
            let mode = fs::metadata(&dst).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644);
        }

        #[test]
        fn keeps_changes_made_in_the_meantime() {
            let dir = tempfile::tempdir().unwrap();
            let (src, dst) = (dir.path().join("new"), dir.path().join("hosts"));
            fs::write(&src, "10.0.0.1 box\n").unwrap();
            // Read as "127.0.0.1 localhost", changed by another program since.
            fs::write(&dst, "127.0.0.1 localhost\n10.9.9.9 vpn\n").unwrap();
            let read = revision_of(b"127.0.0.1 localhost\n");
            assert_eq!(run(&step(&src, &dst, b"10.0.0.1 box\n", &read)), 6);
            assert_eq!(
                fs::read_to_string(&dst).unwrap(),
                "127.0.0.1 localhost\n10.9.9.9 vpn\n"
            );
            assert!(!dir.path().join("hosts.sshkm-new").exists());

            // A missing file reads as empty.
            fs::remove_file(&dst).unwrap();
            assert_eq!(run(&step(&src, &dst, b"10.0.0.1 box\n", &read)), 6);
            assert!(!dst.exists());
            let empty = revision_of(b"");
            assert_eq!(run(&step(&src, &dst, b"10.0.0.1 box\n", &empty)), 0);
            assert_eq!(fs::read_to_string(&dst).unwrap(), "10.0.0.1 box\n");
        }

        #[test]
        fn reads_only_a_regular_file_of_the_approved_length() {
            let dir = tempfile::tempdir().unwrap();
            let (src, dst) = (dir.path().join("new"), dir.path().join("hosts"));
            fs::write(&dst, "old\n").unwrap();
            let old = revision_of(b"old\n");
            let text = b"10.0.0.1 box\n";

            // The approved text with more after it.
            fs::write(&src, "10.0.0.1 box\n10.6.6.6 more\n").unwrap();
            assert_eq!(run(&step(&src, &dst, text, &old)), 3);
            fs::write(&src, "10.0.0.1 bo").unwrap();
            assert_eq!(run(&step(&src, &dst, text, &old)), 3);

            let real = dir.path().join("real");
            fs::write(&real, text).unwrap();
            fs::remove_file(&src).unwrap();
            std::os::unix::fs::symlink(&real, &src).unwrap();
            assert_eq!(run(&step(&src, &dst, text, &old)), 3);
            fs::remove_file(&src).unwrap();
            fs::create_dir(&src).unwrap();
            assert_eq!(run(&step(&src, &dst, text, &old)), 3);
            assert_eq!(fs::read_to_string(&dst).unwrap(), "old\n");
            assert!(!dir.path().join("hosts.sshkm-new").exists());

            // The length is checked before the shell does arithmetic with it.
            let mut args = step(&real, &dst, text, &old).posix_args();
            args[3] = "1+1".into();
            let code = Command::new("/bin/sh")
                .args(["-c", &posix_script("echo flushed"), "sshkm"])
                .args(args)
                .status()
                .unwrap()
                .code();
            assert_eq!(code, Some(2));
            assert_eq!(fs::read_to_string(&dst).unwrap(), "old\n");
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
            let revision = revision_of(b"managed elsewhere");
            assert_eq!(run(&step(&src, &dst, b"x", &revision)), 4);
            assert_eq!(fs::read_to_string(&real).unwrap(), "managed elsewhere");
        }

        #[test]
        fn system_programs_come_from_folders_only_root_can_change() {
            let dir = tempfile::tempdir().unwrap();
            fs::write(dir.path().join("sh"), "").unwrap();
            let none = Path::new("/nonexistent");
            let path =
                std::env::join_paths([dir.path(), Path::new("bin"), Path::new("/bin")]).unwrap();
            assert_eq!(
                system_program("sh", Path::new("/bin"), OsStr::new("")),
                Some(PathBuf::from("/bin/sh"))
            );
            assert_eq!(system_program("sh", none, OsStr::new("bin")), None);
            assert_eq!(system_program("no-such-program", none, &path), None);
            // Tests running as root own the temporary folder too.
            if fs::metadata(dir.path()).unwrap().uid() != 0 {
                assert_eq!(
                    system_program("sh", none, &path),
                    Some(PathBuf::from("/bin/sh"))
                );
                assert_eq!(system_program("sh", none, dir.path().as_os_str()), None);
                assert_eq!(
                    system_program("sh", dir.path(), OsStr::new("/bin")),
                    Some(PathBuf::from("/bin/sh"))
                );
            }
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
        let run = |step: &Step<'_>| {
            Command::new(powershell())
                .env_remove("PSModulePath")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                ])
                .args(["-EncodedCommand", &ps_encode(&windows_install_script(step))])
                .output()
                .unwrap()
                .status
                .code()
        };
        let text = b"10.0.0.1 box\r\n";
        let old = revision_of(b"old\r\n");
        let mut other = step(&src, &dst, text, &old);
        other.checksum = revision_of(b"other");
        assert_eq!(run(&other), Some(3));
        let mut longer = step(&src, &dst, text, &old);
        longer.len -= 1;
        assert_eq!(run(&longer), Some(3));
        let changed = revision_of(b"older\r\n");
        assert_eq!(run(&step(&src, &dst, text, &changed)), Some(6));
        assert_eq!(fs::read_to_string(&dst).unwrap(), "old\r\n");
        assert_eq!(run(&step(&src, &dst, text, &old)), Some(0));
        assert_eq!(fs::read_to_string(&dst).unwrap(), "10.0.0.1 box\r\n");
    }
}
