//! Running the OpenSSH command-line tools (`ssh -V`, `ssh-keyscan`, `ssh`),
//! and `git` in a project's working tree.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use sshkm_core::fsutil;
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
    }
    command
}

/// `git` run in `folder`, for a question about the working tree it is in
/// (the nearest folder above it, or itself, that has a `.git`); `None`
/// outside any. Add the subcommand and its arguments.
///
/// A working tree is a project folder, which may come from anyone (a
/// clone, an archive, a shared drive, another user), so nothing in it may
/// make Git run a program. Git finds the repository as it always does, so
/// its own check that the repository belongs to this user applies
/// (`safe.directory`), but it never takes a folder laid out like a bare
/// repository (files of the project, as a clone brings them) for one. It
/// runs no file system monitor and fetches nothing: no transport is allowed,
/// whatever the repository's config says, so not even the objects a partial
/// clone left out. And it gets none of the app's own `GIT_*` environment.
pub fn git(folder: &Path) -> Option<Command> {
    // `C:\…` rather than `\\?\C:\…` (what canonical paths look like on
    // Windows), which not every tool takes.
    let folder = fsutil::without_verbatim_prefix(folder.to_path_buf());
    sshkm_core::vault::envs::git_work_tree(&folder)?;
    let mut command = command("git");
    for (name, _) in std::env::vars_os() {
        if name
            .to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("GIT_")
        {
            command.env_remove(name);
        }
    }
    // A repository's own `protocol.<name>.allow` outweighs the
    // `protocol.allow` given here; this variable outweighs them all.
    command
        .env("GIT_ALLOW_PROTOCOL", "none")
        .env("GIT_NO_LAZY_FETCH", "1")
        .arg("-C")
        .arg(folder)
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "safe.bareRepository=explicit",
            "-c",
            "protocol.allow=never",
        ]);
    Some(command)
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

    /// Runs `git -C cwd args…`, which must succeed; its stdout.
    fn plain_git(cwd: &Path, args: &[&str], input: Option<&str>) -> String {
        let mut git = command("git");
        git.arg("-C").arg(cwd).args(args);
        let output = run_command(
            &mut git,
            input.map(|text| text.as_bytes().to_vec()),
            Duration::from_secs(10),
        )
        .unwrap();
        assert!(output.success, "git {args:?}: {}", output.stderr);
        output.stdout
    }

    /// Whether `git <args>` from `folder`, run as the app runs it, exits 0.
    fn asked(folder: &Path, args: &[&str]) -> bool {
        let mut git = git(folder).unwrap();
        git.args(args);
        run_command(&mut git, None, Duration::from_secs(10)).is_ok_and(|o| o.code == Some(0))
    }

    #[test]
    fn git_takes_no_folder_of_a_project_for_a_repository() {
        if run("git", &["--version"], Duration::from_secs(5)).is_err() {
            return; // No Git here.
        }
        let dir = tempfile::tempdir().unwrap();
        let tree = dir.path().join("tree");
        std::fs::create_dir(&tree).unwrap();
        assert!(git(&tree).is_none());
        plain_git(&tree, &["init", "-q"], None);
        std::fs::write(tree.join(".gitignore"), "*.log\n").unwrap();
        assert!(asked(&tree, &["check-ignore", "-q", "--", "app.log"]));
        assert!(!asked(&tree, &["check-ignore", "-q", "--", ".env"]));
        // A folder of the tree laid out like a repository of its own (files
        // of the project, as a clone brings them), whose rules would ignore
        // `.env`, is never asked.
        let inner = tree.join("inner");
        for folder in ["objects", "refs", "info"] {
            std::fs::create_dir_all(inner.join(folder)).unwrap();
        }
        std::fs::write(inner.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(
            inner.join("config"),
            "[core]\n\trepositoryformatversion = 0\n\tbare = false\n\tworktree = .\n",
        )
        .unwrap();
        std::fs::write(inner.join("info").join("exclude"), ".env\n").unwrap();
        std::fs::write(inner.join(".env"), "A=1\n").unwrap();
        assert!(!asked(&inner, &["check-ignore", "-q", "--", ".env"]));
    }

    #[cfg(unix)]
    #[test]
    fn git_runs_no_program_a_repository_names() {
        if run("git", &["--version"], Duration::from_secs(5)).is_err() {
            return; // No Git here.
        }
        let dir = tempfile::tempdir().unwrap();
        let tree = dir.path().join("tree");
        let sub = tree.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join(".env"), "A=1\n").unwrap();
        let ran = dir.path().join("ran");
        plain_git(&tree, &["init", "-q"], None);
        // A partial clone whose ignore file wasn't fetched: reading it would
        // fetch it, through a program the repository's config names.
        let blob = plain_git(&tree, &["hash-object", "--stdin"], Some(".env\n"));
        let entry = format!("100644,{},sub/.gitignore", blob.trim());
        plain_git(
            &tree,
            &[
                "update-index",
                "--add",
                "--info-only",
                "--cacheinfo",
                &entry,
            ],
            None,
        );
        plain_git(
            &tree,
            &["update-index", "--skip-worktree", "sub/.gitignore"],
            None,
        );
        let program = format!("touch '{}'; false", ran.display());
        let nowhere = dir.path().join("nowhere");
        for (key, value) in [
            ("core.repositoryformatversion", "1"),
            ("extensions.partialClone", "origin"),
            ("remote.origin.promisor", "true"),
            ("remote.origin.url", &nowhere.to_string_lossy()),
            ("remote.origin.uploadpack", &program),
            ("core.fsmonitor", &program),
            ("protocol.allow", "always"),
            ("protocol.file.allow", "always"),
        ] {
            plain_git(&tree, &["config", key, value], None);
        }

        asked(&sub, &["check-ignore", "-q", "--", ".env"]);
        asked(&sub, &["ls-files", "--error-unmatch", "--", ".env"]);
        asked(&sub, &["ls-files", "-z", "--others", "--exclude-standard"]);
        asked(&sub, &["status", "--porcelain"]);
        assert!(!ran.exists(), "git ran a program the repository named");
        // Whatever Git's version honours: no transport at all.
        let command = git(&sub).unwrap();
        let env: Vec<_> = command.get_envs().collect();
        assert!(env.contains(&("GIT_ALLOW_PROTOCOL".as_ref(), Some("none".as_ref()))));
        assert!(env.contains(&("GIT_NO_LAZY_FETCH".as_ref(), Some("1".as_ref()))));
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
}
