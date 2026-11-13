//! Running the OpenSSH command-line tools (`ssh -V`, `ssh-keyscan`, `ssh`).

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// How much of stdout and of stderr is kept: the last 256 KiB of each. The
/// rest is read and dropped, so a process (or the server behind `ssh`) that
/// prints without end cannot fill the app's memory. What callers look for
/// comes last: `ssh`'s errors, the markers of the key install script.
const KEEP: usize = 256 * 1024;

/// Output of a finished (or killed) process.
pub struct Output {
    pub success: bool,
    /// The exit code, if the program exited by itself.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

/// A command for `program` that runs without a console window, with stdin
/// closed and its output captured. Callers may change it (an askpass session
/// adds its environment) and run it with [`run_command`].
pub fn command(program: &str) -> Command {
    let mut command = Command::new(program);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
        // Windows looks for a program named without a path (one a
        // `ProxyCommand` runs) in the current folder first, and the app's
        // may be any folder. The child starts in the home folder instead,
        // told not to search the current one at all.
        if let Some(home) = sshkm_core::paths::home_dir() {
            command.current_dir(home);
        }
        command.env("NoDefaultCurrentDirectoryInExePath", "1");
    }
    command
}

/// Runs `program args…`, killing it after `timeout`.
pub fn run(program: &str, args: &[&str], timeout: Duration) -> std::io::Result<Output> {
    let mut command = command(program);
    command.args(args);
    run_command(&mut command, None, timeout)
}

/// Runs a prepared command (see [`command`]), killing it after `timeout`.
/// `input`, if any, is written to its stdin, which is then closed.
pub fn run_command(
    command: &mut Command,
    input: Option<Vec<u8>>,
    timeout: Duration,
) -> std::io::Result<Output> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    if input.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command.spawn()?;
    // A thread, so a child that reads its input late cannot block us.
    let writer = child.stdin.take().zip(input).map(|(mut stdin, input)| {
        thread::spawn(move || {
            let _ = stdin.write_all(&input);
        })
    });
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let out_reader = thread::spawn(move || read_tail(stdout.as_mut(), KEEP));
    let err_reader = thread::spawn(move || read_tail(stderr.as_mut(), KEEP));

    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if started.elapsed() >= timeout {
            timed_out = true;
            let _ = child.kill();
            break child.wait().ok();
        }
        thread::sleep(Duration::from_millis(50));
    };
    if let Some(writer) = writer {
        let _ = writer.join();
    }

    Ok(Output {
        success: !timed_out && status.is_some_and(|s| s.success()),
        code: status.filter(|_| !timed_out).and_then(|s| s.code()),
        stdout: out_reader.join().unwrap_or_default(),
        stderr: err_reader.join().unwrap_or_default(),
        timed_out,
    })
}

/// Reads `reader` to the end, keeping the last `keep` bytes.
fn read_tail<R: Read>(reader: Option<&mut R>, keep: usize) -> String {
    let mut kept = Vec::new();
    if let Some(reader) = reader {
        let mut buffer = [0; 8 * 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    kept.extend_from_slice(&buffer[..n]);
                    // Cut now and then rather than at every read.
                    if kept.len() > 2 * keep {
                        kept.drain(..kept.len() - keep);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
    }
    let excess = kept.len().saturating_sub(keep);
    kept.drain(..excess);
    String::from_utf8_lossy(&kept).into_owned()
}

/// `OpenSSH_9.9p1` from `ssh -V`, which prints to stderr.
pub fn openssh_version() -> Option<String> {
    let output = run("ssh", &["-V"], Duration::from_secs(5)).ok()?;
    let text = if output.stderr.trim().is_empty() {
        output.stdout
    } else {
        output.stderr
    };
    text.split([',', ' ', '\n'])
        .find(|part| part.starts_with("OpenSSH"))
        .map(str::to_owned)
}

/// A new, empty file only the user can read, in the temporary folder, for
/// `ssh -E`: what `ssh` itself logs goes there, apart from what servers and
/// jump hosts send as banners and what a `ProxyCommand` prints, which go to
/// its stderr. Removed once dropped.
pub struct LogFile(std::path::PathBuf);

impl LogFile {
    pub fn create() -> std::io::Result<Self> {
        use rand_core::RngCore as _;
        let dir = std::env::temp_dir();
        loop {
            let name = format!("sshkm-ssh-{:016x}.log", rand_core::OsRng.next_u64());
            let path = dir.join(name);
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            match options.open(&path) {
                Ok(_) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
    }

    pub fn path(&self) -> &std::path::Path {
        &self.0
    }

    /// Everything logged so far.
    pub fn read(&self) -> String {
        std::fs::read(&self.0)
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default()
    }
}

impl Drop for LogFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_tail_of_long_output() {
        let mut long = vec![b'a'; 3 * 1024 * 1024 + 17];
        long.extend_from_slice(b"\nlast line\n");
        let kept = read_tail(Some(&mut std::io::Cursor::new(long)), KEEP);
        assert_eq!(kept.len(), KEEP);
        assert!(kept.ends_with("aaa\nlast line\n"));

        let short = read_tail(Some(&mut std::io::Cursor::new(b"ok\n".to_vec())), KEEP);
        assert_eq!(short, "ok\n");
        assert_eq!(read_tail(None::<&mut std::io::Empty>, KEEP), "");
    }

    #[cfg(unix)]
    #[test]
    fn a_flood_of_output_is_cut() {
        let output = run(
            "/bin/sh",
            &["-c", "yes | head -c 2000000; echo done"],
            Duration::from_secs(20),
        )
        .unwrap();
        assert!(output.success);
        assert_eq!(output.stdout.len(), KEEP);
        assert!(output.stdout.ends_with("y\ndone\n"));
    }

    #[test]
    fn log_files_are_private_and_removed() {
        let log = LogFile::create().unwrap();
        let path = log.path().to_path_buf();
        std::fs::write(&path, "debug1: x\n").unwrap();
        assert_eq!(log.read(), "debug1: x\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        drop(log);
        assert!(!path.exists());
    }
}
