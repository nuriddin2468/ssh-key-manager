//! The askpass helper as `ssh` runs it: the built app executable.
//!
//! The `sshd` tests start an unprivileged `sshd` on a free local port with
//! throwaway keys (no system setting is touched). They are ignored by default:
//! `cargo test -p sshkm-app --test askpass -- --ignored`.

use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use sshkm_app_lib::askpass::{PromptOutcome, Secrets, Server, Session};

const APP: &str = env!("CARGO_BIN_EXE_sshkm-app");

/// Waits for `command` like `ssh` would, killing it after `timeout`.
fn run(command: &mut Command, timeout: Duration) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > timeout {
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().unwrap()
}

/// Runs the app as `ssh` runs its askpass program.
fn helper(session: &Session, prompt: &str) -> Output {
    let mut command = Command::new(APP);
    session.configure(&mut command);
    run(command.arg(prompt), Duration::from_secs(30))
}

#[test]
fn the_app_answers_as_askpass_helper() {
    let server = Server::start_with_program(APP).unwrap();
    let session = server.session(Secrets::new(Some("hunter2 with spaces".into()), None));

    let answered = helper(&session, "alice@example.com's password: ");
    assert!(answered.status.success(), "{answered:?}");
    assert_eq!(answered.stdout, b"hunter2 with spaces\n");

    // Asked again: the password was wrong, so the helper refuses.
    let repeated = helper(&session, "(alice@example.com) Password: ");
    assert_eq!(repeated.status.code(), Some(1));
    assert_eq!(repeated.stdout, b"");

    // No code was given.
    let missing = helper(&session, "(alice@example.com) Verification code: ");
    assert_eq!(missing.status.code(), Some(1));
    assert_eq!(missing.stdout, b"");

    let host_key = helper(
        &session,
        "The authenticity of host 'example.com (10.0.0.1)' can't be established.\nED25519 key \
         fingerprint is SHA256:abc.\nAre you sure you want to continue connecting \
         (yes/no/[fingerprint])? ",
    );
    assert!(host_key.status.success());
    assert_eq!(host_key.stdout, b"no\n");

    let outcomes: Vec<_> = session.asked().iter().map(|a| a.outcome).collect();
    assert_eq!(
        outcomes,
        [
            PromptOutcome::Answered,
            PromptOutcome::Repeated,
            PromptOutcome::Missing,
            PromptOutcome::Declined,
        ]
    );
}

#[test]
fn the_helper_fails_closed() {
    let server = Server::start_with_program(APP).unwrap();
    let session = server.session(Secrets::new(Some("hunter2".into()), None));
    let env = session.env();
    drop(session);

    // The session is gone, so its token is worthless.
    let mut command = Command::new(APP);
    command.envs(env.iter().cloned()).stdin(Stdio::null());
    let revoked = run(command.arg("Password: "), Duration::from_secs(30));
    assert_eq!(revoked.status.code(), Some(1));
    assert_eq!(revoked.stdout, b"");

    // No server at all.
    drop(server);
    let mut command = Command::new(APP);
    command.envs(env).stdin(Stdio::null());
    let unreachable = run(command.arg("Password: "), Duration::from_secs(30));
    assert_eq!(unreachable.status.code(), Some(1));
}

#[cfg(unix)]
mod sshd {
    use std::fs;
    use std::net::{TcpListener, TcpStream};
    use std::path::{Path, PathBuf};
    use std::process::Child;

    use sshkm_app_lib::askpass::PromptKind;
    use tempfile::TempDir;

    use super::*;

    const PASSPHRASE: &str = "correct horse battery staple";

    struct Sshd {
        child: Child,
        port: u16,
        dir: TempDir,
    }

    impl Drop for Sshd {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl Sshd {
        fn path(&self, name: &str) -> PathBuf {
            self.dir.path().join(name)
        }

        fn client_key(&self) -> PathBuf {
            self.path("client")
        }

        fn trust_host_key(&self) {
            let host = fs::read_to_string(self.path("host.pub")).unwrap();
            fs::write(
                self.path("known_hosts"),
                format!("[127.0.0.1]:{} {host}", self.port),
            )
            .unwrap();
        }

        /// `ssh … 127.0.0.1 echo sshkm-ok` with the session's environment.
        fn ssh(&self, session: &Session, options: &[&str]) -> Output {
            let mut command = Command::new("ssh");
            let known_hosts = format!("UserKnownHostsFile={}", self.path("known_hosts").display());
            let port = self.port.to_string();
            command
                .args(["-F", "/dev/null", "-o", &known_hosts])
                .args(["-o", "GlobalKnownHostsFile=/dev/null"])
                .args(["-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes"])
                .args(["-o", "PreferredAuthentications=publickey"])
                .args(["-o", "BatchMode=no", "-o", "ConnectTimeout=5"])
                .args(options)
                .arg("-i")
                .arg(self.client_key())
                .args([
                    "-p",
                    &port,
                    "-l",
                    &user(),
                    "-T",
                    "127.0.0.1",
                    "echo",
                    "sshkm-ok",
                ]);
            session.configure(&mut command);
            run(&mut command, Duration::from_secs(30))
        }
    }

    fn user() -> String {
        std::env::var("USER").expect("USER is set")
    }

    fn keygen(path: &Path, passphrase: &str) {
        let status = Command::new("ssh-keygen")
            .args([
                "-q",
                "-t",
                "ed25519",
                "-C",
                "sshkm-test",
                "-N",
                passphrase,
                "-f",
            ])
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn start() -> Sshd {
        let sshd = [
            "/usr/sbin/sshd",
            "/usr/local/sbin/sshd",
            "/opt/homebrew/sbin/sshd",
        ]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .expect("sshd is installed");
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| dir.path().join(name);
        keygen(&path("host"), "");
        keygen(&path("client"), PASSPHRASE);
        fs::copy(path("client.pub"), path("authorized_keys")).unwrap();
        fs::write(path("known_hosts"), "").unwrap();
        fs::write(
            path("sshd_config"),
            format!(
                "ListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nAuthorizedKeysFile {}\n\
                 StrictModes no\nPubkeyAuthentication yes\nPasswordAuthentication no\n\
                 KbdInteractiveAuthentication no\nUsePAM no\nLogLevel VERBOSE\n",
                path("host").display(),
                path("sshd.pid").display(),
                path("authorized_keys").display(),
            ),
        )
        .unwrap();

        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let log = fs::File::create(path("sshd.log")).unwrap();
        let child = Command::new(sshd)
            .args(["-D", "-e", "-f"])
            .arg(path("sshd_config"))
            .args(["-p", &port.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        let server = Sshd { child, port, dir };
        let started = Instant::now();
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "sshd did not start: {}",
                fs::read_to_string(server.path("sshd.log")).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        server
    }

    fn text(output: &Output) -> String {
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }

    #[test]
    #[ignore = "starts a local sshd"]
    fn passphrase_is_answered_through_askpass() {
        let sshd = start();
        sshd.trust_host_key();
        let server = Server::start_with_program(APP).unwrap();
        let session = server
            .session(Secrets::default().with_passphrase(sshd.client_key(), PASSPHRASE.into()));

        let output = sshd.ssh(&session, &["-o", "NumberOfPasswordPrompts=1"]);
        assert!(output.status.success(), "{}", text(&output));
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "sshkm-ok");

        let asked = session.asked();
        assert_eq!(asked.len(), 1, "{asked:?}");
        assert_eq!(
            asked[0].prompt.kind,
            PromptKind::Passphrase {
                key: sshd.client_key().display().to_string()
            }
        );
        assert_eq!(asked[0].outcome, PromptOutcome::Answered);
    }

    #[test]
    #[ignore = "starts a local sshd"]
    fn wrong_passphrase_is_not_retried() {
        let sshd = start();
        sshd.trust_host_key();
        let server = Server::start_with_program(APP).unwrap();
        let session =
            server.session(Secrets::default().with_passphrase(sshd.client_key(), "wrong".into()));

        // ssh would ask three times; the session answers once.
        let output = sshd.ssh(&session, &["-o", "NumberOfPasswordPrompts=3"]);
        assert!(!output.status.success(), "{}", text(&output));
        let outcomes: Vec<_> = session.asked().iter().map(|a| a.outcome).collect();
        assert_eq!(
            outcomes,
            [PromptOutcome::Answered, PromptOutcome::Repeated],
            "{}",
            text(&output)
        );
    }

    #[test]
    #[ignore = "starts a local sshd"]
    fn unknown_host_key_is_declined() {
        let sshd = start();
        let server = Server::start_with_program(APP).unwrap();
        let session = server
            .session(Secrets::default().with_passphrase(sshd.client_key(), PASSPHRASE.into()));

        let output = sshd.ssh(&session, &["-o", "StrictHostKeyChecking=ask"]);
        assert!(!output.status.success(), "{}", text(&output));
        assert!(text(&output).contains("Host key verification failed"));
        let asked = session.asked();
        assert_eq!(asked.len(), 1, "{asked:?}");
        assert_eq!(asked[0].prompt.kind, PromptKind::HostKeyConfirm);
        assert_eq!(asked[0].outcome, PromptOutcome::Declined);
        assert_eq!(fs::read_to_string(sshd.path("known_hosts")).unwrap(), "");
    }
}
