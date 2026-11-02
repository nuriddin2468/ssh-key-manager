//! Running the OpenSSH command-line tools (`ssh -V`, `ssh-keyscan`, `ssh`).

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Output of a finished (or killed) process.
pub struct Output {
    pub success: bool,
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
    let out_reader = thread::spawn(move || read_all(stdout.as_mut()));
    let err_reader = thread::spawn(move || read_all(stderr.as_mut()));

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
        stdout: out_reader.join().unwrap_or_default(),
        stderr: err_reader.join().unwrap_or_default(),
        timed_out,
    })
}

fn read_all<R: Read>(reader: Option<&mut R>) -> String {
    let mut bytes = Vec::new();
    if let Some(reader) = reader {
        let _ = reader.read_to_end(&mut bytes);
    }
    String::from_utf8_lossy(&bytes).into_owned()
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
