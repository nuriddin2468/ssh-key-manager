//! A guard for the `.env` files written only while the vault is unlocked
//! (level 2, `sshkm_core::vault::envs::files::Leftovers`): the app's own
//! program, started with [`FLAG`] and the path of the list of those files,
//! which waits on a pipe from the app. When the pipe closes — the app quit,
//! crashed or was killed — it removes the files on the list that are still
//! as the app left them, and exits. A clean quit or lock empties the list
//! first, so then it removes nothing. If the guard goes too (a power cut, a
//! whole session killed), the app's next start sweeps the list.
//!
//! The guard is in a process group of its own, so a signal to the app's
//! group (Ctrl+C in a terminal) doesn't take it along. For an `AppImage` it
//! is the `.AppImage` file that runs, since the program inside it lives on a
//! mount that goes with the app.

use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitCode, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};

use sshkm_core::vault::envs::files::Leftovers;

/// The argument that makes the app's program the guard.
pub const FLAG: &str = "--sshkm-env-guard";

/// Runs the guard when the program was started as one: waits for standard
/// input to close, then sweeps the list named after [`FLAG`]. Before Tauri
/// starts, as the askpass helper does.
pub fn run_from_args() -> Option<ExitCode> {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(OsStr::new(FLAG)) {
        return None;
    }
    let list = PathBuf::from(args.next()?);
    wait_for_eof(&mut io::stdin().lock());
    Leftovers::sweep_at(&list);
    Some(ExitCode::SUCCESS)
}

/// Reads until the other end goes, whatever it sends.
fn wait_for_eof(input: &mut impl io::Read) {
    let mut sink = [0u8; 64];
    loop {
        match input.read(&mut sink) {
            Ok(0) => return,
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

/// The guard while the app runs.
#[derive(Default)]
pub struct Guard {
    running: Mutex<Option<Running>>,
    /// Starting it failed once: not tried again, nor told again.
    failed: std::sync::atomic::AtomicBool,
}

struct Running {
    child: Child,
    /// The pipe the guard waits on; dropping it lets the guard go.
    pipe: Option<ChildStdin>,
}

impl Guard {
    /// Starts the guard for the list at `list`, unless one runs.
    /// Without one, the next start removes what a crash leaves.
    pub fn ensure(&self, list: &Path) {
        use std::sync::atomic::Ordering;
        let mut running = lock(&self.running);
        if let Some(run) = running.as_mut()
            && matches!(run.child.try_wait(), Ok(None))
        {
            return;
        }
        if self.failed.load(Ordering::SeqCst) {
            return;
        }
        *running = match spawn(list) {
            Ok(mut child) => {
                let pipe = child.stdin.take();
                Some(Running { child, pipe })
            }
            Err(error) => {
                self.failed.store(true, Ordering::SeqCst);
                log::warn!("env files: no guard for files written while unlocked: {error}");
                None
            }
        };
    }

    /// Lets the guard go: it sweeps the list (empty after a clean quit) and
    /// exits.
    pub fn stop(&self) {
        if let Some(mut run) = lock(&self.running).take() {
            drop(run.pipe.take());
            // Reaped once it exits; it doesn't keep the app waiting.
            std::thread::spawn(move || {
                let _ = run.child.wait();
            });
        }
    }
}

fn spawn(list: &Path) -> io::Result<Child> {
    let mut command = Command::new(program()?);
    command
        .arg(FLAG)
        .arg(list)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command.spawn()
}

/// This program, or the `.AppImage` that runs it.
fn program() -> io::Result<PathBuf> {
    use crate::browser::HostProgram;
    Ok(match crate::browser::host_program()? {
        HostProgram::At(path) | HostProgram::Temporary(path) | HostProgram::Mounted(path) => path,
    })
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_guard_waits_until_the_other_end_goes() {
        let mut input: &[u8] = b"anything at all";
        wait_for_eof(&mut input);
        assert_eq!(input, b"");
    }
}
