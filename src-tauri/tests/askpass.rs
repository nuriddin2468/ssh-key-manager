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

    use sshkm_app_lib::askpass::{Ask, Interactive, PromptKind, Reply};
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

    /// Trusts the host key and gives a wrong passphrase, then the right one:
    /// what a user does through the terminal's dialogs.
    struct User;

    impl Interactive for User {
        fn respond(&self, ask: &Ask<'_>) -> Reply {
            match ask.prompt.kind {
                PromptKind::HostKeyConfirm => Reply::Yes,
                PromptKind::Passphrase { .. } if ask.given == 0 => Reply::Secret("wrong".into()),
                PromptKind::Passphrase { .. } => Reply::Secret(PASSPHRASE.into()),
                _ => Reply::Refuse,
            }
        }
    }

    #[test]
    #[ignore = "starts a local sshd"]
    fn interactive_session_trusts_the_key_and_asks_again() {
        let sshd = start();
        let server = Server::start_with_program(APP).unwrap();
        let session = server.interactive_session(User);

        let output = sshd.ssh(
            &session,
            &[
                "-o",
                "StrictHostKeyChecking=ask",
                "-o",
                "NumberOfPasswordPrompts=3",
            ],
        );
        assert!(output.status.success(), "{}", text(&output));
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "sshkm-ok");
        let outcomes: Vec<_> = session.asked().iter().map(|a| a.outcome).collect();
        assert_eq!(
            outcomes,
            [
                PromptOutcome::Accepted,
                PromptOutcome::Answered,
                PromptOutcome::Answered
            ],
            "{}",
            text(&output)
        );
        // "yes" made ssh remember the key, as typing it would.
        let known = fs::read_to_string(sshd.path("known_hosts")).unwrap();
        assert!(known.contains("ssh-ed25519"), "{known}");
    }

    mod terminal {
        use std::sync::{Arc, Mutex};

        use portable_pty::CommandBuilder;
        use sshkm_app_lib::terminal::bridge::{AppResult, Bridge, Options, SaveTarget, Store};
        use sshkm_app_lib::terminal::types::{
            Phase, PromptAnswer, PromptAsk, SaveOffer, SessionState, Source, TerminalEvent,
        };
        use sshkm_app_lib::terminal::{Sink, spawn_detached};
        use sshkm_core::SecretString;

        use super::*;

        /// No vault: every secret comes from the "user".
        struct NoVault;

        impl Store for NoVault {
            fn password(&self) -> Option<SecretString> {
                None
            }
            fn one_time_code(&self) -> Option<SecretString> {
                None
            }
            fn passphrase(&self, _key: &str) -> Option<SecretString> {
                None
            }
            fn offer(&self, _target: &SaveTarget) -> SaveOffer {
                SaveOffer::NoVault
            }
            fn save(&self, _: &SaveTarget, _: &SecretString) -> AppResult<()> {
                Ok(())
            }
        }

        #[derive(Default)]
        struct Screen {
            events: Mutex<Vec<TerminalEvent>>,
            output: Mutex<Vec<u8>>,
            /// Prompts answered so far.
            answered: Mutex<usize>,
        }

        impl Sink for Screen {
            fn event(&self, event: &TerminalEvent) {
                self.events.lock().unwrap().push(event.clone());
            }
            fn output(&self, bytes: &[u8]) {
                self.output.lock().unwrap().extend_from_slice(bytes);
            }
        }

        impl Screen {
            fn text(&self) -> String {
                String::from_utf8_lossy(&self.output.lock().unwrap()).into_owned()
            }

            /// Waits for `done`, answering prompts like a user meanwhile.
            fn wait_for(&self, bridge: &Bridge, done: impl Fn(&[TerminalEvent]) -> bool) {
                let started = Instant::now();
                loop {
                    let answered = *self.answered.lock().unwrap();
                    let events = self.events.lock().unwrap().clone();
                    if done(&events) {
                        return;
                    }
                    let prompts: Vec<_> = events
                        .iter()
                        .filter_map(|e| match e {
                            TerminalEvent::Prompt { prompt } => Some(prompt.clone()),
                            _ => None,
                        })
                        .collect();
                    for prompt in prompts.iter().skip(answered) {
                        let answer = match &prompt.ask {
                            PromptAsk::HostKey { .. } => PromptAnswer::Trust { trust: true },
                            PromptAsk::Passphrase { retry: false, .. } => PromptAnswer::Secret {
                                value: "wrong".to_owned().into(),
                                save: false,
                            },
                            PromptAsk::Passphrase { retry: true, .. } => PromptAnswer::Secret {
                                value: PASSPHRASE.to_owned().into(),
                                save: false,
                            },
                            _ => PromptAnswer::Cancel,
                        };
                        assert!(bridge.answer(prompt.id, answer), "{prompt:?}");
                        *self.answered.lock().unwrap() += 1;
                    }
                    assert!(
                        started.elapsed() < Duration::from_secs(30),
                        "{events:?}\n{}",
                        self.text()
                    );
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }

        #[test]
        #[ignore = "starts a local sshd"]
        fn a_session_signs_in_runs_commands_and_ends() {
            let sshd = start();
            let server = Server::start_with_program(APP).unwrap();
            let screen = Arc::new(Screen::default());
            let bridge = Arc::new(Bridge::new(
                NoVault,
                Arc::clone(&screen) as Arc<dyn Sink>,
                Options::default(),
            ));
            let session = server.interactive_session(Arc::clone(&bridge));

            let known_hosts = format!("UserKnownHostsFile={}", sshd.path("known_hosts").display());
            let port = sshd.port.to_string();
            let mut command = CommandBuilder::new("ssh");
            command.args(["-F", "/dev/null", "-o", &known_hosts]);
            command.args(["-o", "GlobalKnownHostsFile=/dev/null"]);
            command.args(["-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes"]);
            command.args(["-o", "PreferredAuthentications=publickey"]);
            command.args(["-o", "StrictHostKeyChecking=ask"]);
            command.arg("-i");
            command.arg(sshd.client_key());
            command.args(["-p", &port, "-l", &user(), "--", "127.0.0.1"]);
            for (name, value) in session.env() {
                command.env(name, value);
            }
            let terminal = spawn_detached(
                command,
                (100, 30),
                Arc::clone(&bridge),
                session,
                Arc::clone(&screen) as Arc<dyn Sink>,
            )
            .unwrap();

            // Signed in once the remote shell put the terminal in raw mode.
            screen.wait_for(&bridge, |events| {
                events.iter().any(|e| {
                    matches!(
                        e,
                        TerminalEvent::State {
                            state: SessionState::Connected { .. }
                        }
                    )
                })
            });
            assert_eq!(terminal.phase(), Phase::Connected);
            let sign_in = screen
                .events
                .lock()
                .unwrap()
                .iter()
                .find_map(|e| match e {
                    TerminalEvent::State {
                        state: SessionState::Connected { sign_in },
                    } => Some(sign_in.clone()),
                    _ => None,
                })
                .unwrap();
            assert_eq!(sign_in.passphrase, Some(Source::User));
            assert_eq!(
                sign_in.key.as_deref(),
                Some(sshd.client_key().to_str().unwrap())
            );

            // Keystrokes reach the remote shell and its output comes back.
            terminal.write(b"echo sshkm-$((40 + 2))\r".to_vec());
            let started = Instant::now();
            while !screen.text().contains("sshkm-42") {
                assert!(
                    started.elapsed() < Duration::from_secs(10),
                    "{}",
                    screen.text()
                );
                std::thread::sleep(Duration::from_millis(20));
            }

            terminal.write(b"exit\r".to_vec());
            screen.wait_for(&bridge, |events| {
                events.iter().any(|e| {
                    matches!(
                        e,
                        TerminalEvent::State {
                            state: SessionState::Ended { .. }
                        }
                    )
                })
            });
            assert_eq!(terminal.phase(), Phase::Ended);
            let known = fs::read_to_string(sshd.path("known_hosts")).unwrap();
            assert!(known.contains("ssh-ed25519"), "{known}");
        }

        #[test]
        #[ignore = "starts a local sshd"]
        fn a_declined_host_key_fails_the_session() {
            let sshd = start();
            let server = Server::start_with_program(APP).unwrap();
            let screen = Arc::new(Screen::default());
            let bridge = Arc::new(Bridge::new(
                NoVault,
                Arc::clone(&screen) as Arc<dyn Sink>,
                Options::default(),
            ));
            let session = server.interactive_session(Arc::clone(&bridge));
            let known_hosts = format!("UserKnownHostsFile={}", sshd.path("known_hosts").display());
            let port = sshd.port.to_string();
            let mut command = CommandBuilder::new("ssh");
            command.args(["-F", "/dev/null", "-o", &known_hosts]);
            command.args([
                "-o",
                "GlobalKnownHostsFile=/dev/null",
                "-o",
                "StrictHostKeyChecking=ask",
            ]);
            command.args(["-p", &port, "-l", &user(), "--", "127.0.0.1"]);
            for (name, value) in session.env() {
                command.env(name, value);
            }
            let _terminal = spawn_detached(
                command,
                (100, 30),
                Arc::clone(&bridge),
                session,
                Arc::clone(&screen) as Arc<dyn Sink>,
            )
            .unwrap();
            let started = Instant::now();
            let failure = loop {
                let events = screen.events.lock().unwrap().clone();
                for event in &events {
                    if let TerminalEvent::Prompt { prompt } = event {
                        bridge.answer(prompt.id, PromptAnswer::Trust { trust: false });
                    }
                }
                if let Some(failure) = events.iter().find_map(|e| match e {
                    TerminalEvent::State {
                        state: SessionState::Failed { failure },
                    } => Some(failure.clone()),
                    _ => None,
                }) {
                    break failure;
                }
                assert!(started.elapsed() < Duration::from_secs(30), "{events:?}");
                std::thread::sleep(Duration::from_millis(20));
            };
            assert_eq!(
                failure.reason,
                sshkm_app_lib::terminal::types::FailReason::HostKeyNotTrusted,
                "{failure:?}"
            );
            assert!(
                failure.output.contains("Host key verification failed"),
                "{failure:?}"
            );
        }
    }
}
