//! Tunnels as the app runs them, against an unprivileged `sshd` on a free
//! local port with throwaway keys (no system setting is touched): the `ssh`
//! arguments of `sshkm_core::tunnels`, the terminal's prompt bridge behind
//! an askpass session of the built app, and the reading of why `ssh` stopped.
//! Ignored by default: `cargo test -p sshkm-app --test tunnels -- --ignored`.
#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use sshkm_app_lib::AppResult;
use sshkm_app_lib::askpass::Server;
use sshkm_app_lib::terminal::Sink;
use sshkm_app_lib::terminal::bridge::{Bridge, Options, SaveTarget, Store};
use sshkm_app_lib::terminal::types::{
    FailReason, Failure, PromptAnswer, PromptAsk, PromptRequest, SaveOffer, TerminalEvent,
};
use sshkm_app_lib::tunnels::failure::{TunnelFailReason, classify};
use sshkm_core::SecretString;
use sshkm_core::tunnels::{Tunnel, TunnelKind};
use tempfile::TempDir;

const APP: &str = env!("CARGO_BIN_EXE_sshkm-app");
const PASSPHRASE: &str = "correct horse battery staple";
const ALIAS: &str = "tunnel-test";

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

    fn trust_host_key(&self) {
        let host = fs::read_to_string(self.path("host.pub")).unwrap();
        fs::write(
            self.path("known_hosts"),
            format!("[127.0.0.1]:{} {host}", self.port),
        )
        .unwrap();
    }
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

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// An `sshd` and an `ssh` config with the host `tunnel-test` pointing at it.
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
             KbdInteractiveAuthentication no\nUsePAM no\nAllowTcpForwarding yes\n\
             LogLevel VERBOSE\n",
            path("host").display(),
            path("sshd.pid").display(),
            path("authorized_keys").display(),
        ),
    )
    .unwrap();
    let port = free_port();
    fs::write(
        path("config"),
        format!(
            "Host {ALIAS}\n  HostName 127.0.0.1\n  Port {port}\n  User {}\n  IdentityFile {}\n  \
             IdentitiesOnly yes\n  IdentityAgent none\n  UserKnownHostsFile {}\n  \
             GlobalKnownHostsFile /dev/null\n  PreferredAuthentications publickey\n",
            std::env::var("USER").expect("USER is set"),
            path("client").display(),
            path("known_hosts").display(),
        ),
    )
    .unwrap();
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
            "sshd did not start"
        );
        thread::sleep(Duration::from_millis(50));
    }
    server
}

/// The vault as a bridge sees it: the client key's passphrase, nothing else.
struct Vault;

impl Store for Vault {
    fn password(&self) -> Option<SecretString> {
        None
    }
    fn one_time_code(&self) -> Option<SecretString> {
        None
    }
    fn passphrase(&self, _key: &str) -> Option<SecretString> {
        Some(PASSPHRASE.into())
    }
    fn offer(&self, _target: &SaveTarget) -> SaveOffer {
        SaveOffer::None
    }
    fn save(&self, _target: &SaveTarget, _secret: &SecretString) -> AppResult<()> {
        Ok(())
    }
}

/// Hands the bridge's prompts to the test.
struct Prompts(Mutex<mpsc::Sender<PromptRequest>>);

impl Sink for Prompts {
    fn event(&self, event: &TerminalEvent) {
        if let TerminalEvent::Prompt { prompt } = event {
            let _ = self.0.lock().unwrap().send(prompt.clone());
        }
    }
    fn output(&self, _bytes: &[u8]) {}
}

/// `ssh` for `tunnel` with the test's config, its prompts answered by a
/// bridge as a tunnel's are.
struct Running {
    child: Child,
    lines: Receiver<String>,
    output: String,
    bridge: Arc<Bridge>,
    prompts: Receiver<PromptRequest>,
    _server: Server,
    _session: sshkm_app_lib::askpass::Session,
}

impl Running {
    fn start(sshd: &Sshd, tunnel: &Tunnel) -> Self {
        let server = Server::start_with_program(APP).unwrap();
        let (tx, prompts) = mpsc::channel();
        let bridge = Arc::new(Bridge::new(
            Vault,
            Arc::new(Prompts(Mutex::new(tx))),
            Options::default(),
        ));
        let session = server.interactive_session(Arc::clone(&bridge));
        let mut command = Command::new("ssh");
        session.configure(&mut command);
        command
            .arg("-F")
            .arg(sshd.path("config"))
            .args(tunnel.ssh_args())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        let stderr = child.stderr.take().unwrap();
        let (send, lines) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let _ = send.send(line);
            }
        });
        Self {
            child,
            lines,
            output: String::new(),
            bridge,
            prompts,
            _server: server,
            _session: session,
        }
    }

    /// Reads `ssh`'s output until a line starts with `prefix`; false if it
    /// exits or 20 seconds pass first.
    fn wait_for(&mut self, prefix: &str) -> bool {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(line) = self.lines.recv_timeout(Duration::from_millis(100)) {
                self.output.push_str(&line);
                self.output.push('\n');
                if line.starts_with(prefix) {
                    return true;
                }
            } else if self.child.try_wait().unwrap().is_some() {
                return false;
            }
        }
        false
    }

    /// Waits for `ssh` to exit, then reads why, as a tunnel does.
    fn failure(&mut self, signed_in: bool) -> TunnelFailReason {
        let deadline = Instant::now() + Duration::from_secs(20);
        while self.child.try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < deadline,
                "ssh did not exit: {}",
                self.output
            );
            thread::sleep(Duration::from_millis(50));
        }
        while let Ok(line) = self.lines.recv_timeout(Duration::from_millis(300)) {
            self.output.push_str(&line);
            self.output.push('\n');
        }
        let login = self.bridge.failure(&self.output, None);
        classify(&self.output, signed_in, &login)
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn tunnel(kind: TunnelKind, listen_port: u16, target_port: Option<u16>) -> Tunnel {
    Tunnel {
        id: "test".into(),
        name: String::new(),
        alias: ALIAS.into(),
        kind,
        bind_address: Some("127.0.0.1".into()),
        listen_port,
        target_host: target_port.map(|_| "127.0.0.1".into()),
        target_port,
        auto_reconnect: false,
    }
}

/// A server that sends back what it gets, once.
fn echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buffer = [0; 64];
            let n = stream.read(&mut buffer).unwrap_or(0);
            let _ = stream.write_all(&buffer[..n]);
        }
    });
    port
}

fn through(port: u16, text: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(text).unwrap();
    let mut reply = vec![0; text.len()];
    stream.read_exact(&mut reply).unwrap();
    reply
}

#[test]
#[ignore = "starts a local sshd"]
fn a_local_tunnel_forwards_once_the_vault_gave_the_passphrase() {
    let sshd = start();
    sshd.trust_host_key();
    let target = echo_server();
    let listen = free_port();
    let mut ssh = Running::start(&sshd, &tunnel(TunnelKind::Local, listen, Some(target)));
    assert!(ssh.wait_for("Authenticated to "), "{}", ssh.output);
    // The forward is bound right after signing in.
    thread::sleep(Duration::from_millis(500));
    assert_eq!(through(listen, b"ping"), b"ping");
    assert!(ssh.prompts.try_recv().is_err(), "the vault answered");
}

#[test]
#[ignore = "starts a local sshd"]
fn a_remote_tunnel_reaches_this_computer() {
    let sshd = start();
    sshd.trust_host_key();
    let target = echo_server();
    let listen = free_port();
    let mut ssh = Running::start(&sshd, &tunnel(TunnelKind::Remote, listen, Some(target)));
    assert!(ssh.wait_for("Authenticated to "), "{}", ssh.output);
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", listen)).is_err() {
        assert!(Instant::now() < deadline, "the server never listened");
        thread::sleep(Duration::from_millis(100));
    }
    // That probe used up the echo server; a fresh one answers the real try.
    drop(ssh);
    let target = echo_server();
    let mut ssh = Running::start(&sshd, &tunnel(TunnelKind::Remote, listen, Some(target)));
    assert!(ssh.wait_for("Authenticated to "), "{}", ssh.output);
    thread::sleep(Duration::from_secs(1));
    assert_eq!(through(listen, b"pong"), b"pong");
}

#[test]
#[ignore = "starts a local sshd"]
fn a_dynamic_tunnel_listens_for_socks() {
    let sshd = start();
    sshd.trust_host_key();
    let target = echo_server();
    let listen = free_port();
    let mut ssh = Running::start(&sshd, &tunnel(TunnelKind::Dynamic, listen, None));
    assert!(ssh.wait_for("Authenticated to "), "{}", ssh.output);
    thread::sleep(Duration::from_millis(500));
    // SOCKS5: no authentication, then CONNECT 127.0.0.1:target.
    let mut stream = TcpStream::connect(("127.0.0.1", listen)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(&[5, 1, 0]).unwrap();
    let mut reply = [0; 2];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(reply, [5, 0]);
    let [high, low] = target.to_be_bytes();
    stream
        .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, high, low])
        .unwrap();
    let mut connected = [0; 10];
    stream.read_exact(&mut connected).unwrap();
    assert_eq!(connected[1], 0, "SOCKS CONNECT failed");
    stream.write_all(b"socks").unwrap();
    let mut echoed = [0; 5];
    stream.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"socks");
}

#[test]
#[ignore = "starts a local sshd"]
fn a_taken_port_ends_the_tunnel_with_its_reason() {
    let sshd = start();
    sshd.trust_host_key();
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port();
    let mut ssh = Running::start(&sshd, &tunnel(TunnelKind::Local, port, Some(22)));
    assert!(ssh.wait_for("Authenticated to "), "{}", ssh.output);
    assert_eq!(ssh.failure(true), TunnelFailReason::PortUnavailable);

    // The server's own port is taken on the server.
    let remote = tunnel(TunnelKind::Remote, sshd.port, Some(22));
    let mut ssh = Running::start(&sshd, &remote);
    assert!(ssh.wait_for("Authenticated to "), "{}", ssh.output);
    assert_eq!(ssh.failure(true), TunnelFailReason::ForwardRefused);
}

#[test]
#[ignore = "starts a local sshd"]
fn a_new_host_key_is_asked_about_and_declining_fails_the_tunnel() {
    let sshd = start();
    let listen = free_port();
    let mut ssh = Running::start(&sshd, &tunnel(TunnelKind::Local, listen, Some(22)));
    let prompt = ssh
        .prompts
        .recv_timeout(Duration::from_secs(20))
        .expect("a host-key question");
    assert!(
        matches!(prompt.ask, PromptAsk::HostKey { .. }),
        "{prompt:?}"
    );
    assert!(
        ssh.bridge
            .answer(prompt.id, PromptAnswer::Trust { trust: false })
    );
    assert_eq!(ssh.failure(false), TunnelFailReason::HostKeyNotTrusted);
    assert_eq!(fs::read_to_string(sshd.path("known_hosts")).unwrap(), "");

    // Trusted, it is written to known_hosts and the tunnel comes up.
    let mut ssh = Running::start(&sshd, &tunnel(TunnelKind::Local, listen, Some(22)));
    let prompt = ssh.prompts.recv_timeout(Duration::from_secs(20)).unwrap();
    assert!(
        ssh.bridge
            .answer(prompt.id, PromptAnswer::Trust { trust: true })
    );
    assert!(ssh.wait_for("Authenticated to "), "{}", ssh.output);
    assert!(
        fs::read_to_string(sshd.path("known_hosts"))
            .unwrap()
            .contains("ssh-ed25519")
    );
}

/// Not run against `sshd`: the reading of an unreachable host, for the
/// record of what a tunnel says when the server is down.
#[test]
fn an_unreachable_host_is_told_apart() {
    let login = Failure {
        reason: FailReason::Unreachable,
        saved: false,
        exit_code: Some(255),
        output: String::new(),
    };
    assert_eq!(
        classify(
            "ssh: connect to host 127.0.0.1 port 9: Connection refused",
            false,
            &login
        ),
        TunnelFailReason::Unreachable
    );
}
