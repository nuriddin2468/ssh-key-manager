//! In-process SSH servers (russh's server half) and an app that answers
//! the client's questions as a test tells it to.

// Each test file uses what it needs; the server handler's methods are
// async because russh's trait is, and its switches are one per way to sign
// in.
#![allow(
    dead_code,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::unused_async_trait_impl
)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::EncodePublicKey;
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::{PrivateKey, PublicKey};
use russh::server::{self, Auth, Msg, Response, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use sshkm_ssh::{AuthPrompt, CallbackError, Callbacks, PhoneKey, SignRequest, UnknownHostKey};
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;

pub const PASSWORD: &str = "hunter2";
pub const CODE: &str = "123456";

/// How a test server signs users in.
#[derive(Debug, Clone, Default)]
pub struct Spec {
    /// Seed of the server's Ed25519 host key.
    pub seed: u8,
    /// Who may sign in.
    pub user: String,
    /// The phone key it takes.
    pub key: Option<PublicKey>,
    /// It takes `PASSWORD` with the password method.
    pub password: bool,
    /// It asks `Password:` and `Verification code:` (keyboard-interactive).
    pub interactive: bool,
    /// After the key, it asks for a code too.
    pub key_then_code: bool,
    /// It opens `direct-tcpip` channels (a jump host).
    pub forwards: bool,
    /// Keyboard-interactive asks `Password:` again after every answer.
    pub endless: bool,
}

/// What a test server saw.
#[derive(Debug, Default)]
pub struct Log {
    pub connections: usize,
    pub signed_in: Vec<String>,
    pub pty: Option<(String, u32, u32)>,
    pub resizes: Vec<(u32, u32)>,
    pub received: Vec<u8>,
    pub closed: bool,
    pub forwards: Vec<(String, u32)>,
    pub rounds: usize,
    /// Sessions that have ended, however they ended.
    pub ended: usize,
}

pub struct TestServer {
    pub port: u16,
    pub host_key: PublicKey,
    pub log: Arc<Mutex<Log>>,
}

pub fn host_key(seed: u8) -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
}

impl TestServer {
    pub async fn start(spec: Spec) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let key = host_key(spec.seed);
        let host_key = key.public_key().clone();
        let mut methods = Vec::new();
        if spec.key.is_some() {
            methods.push(MethodKind::PublicKey);
        }
        if spec.interactive || spec.key_then_code || spec.endless {
            methods.push(MethodKind::KeyboardInteractive);
        }
        if spec.password {
            methods.push(MethodKind::Password);
        }
        let config = Arc::new(server::Config {
            keys: vec![key],
            methods: MethodSet::from(methods.as_slice()),
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..server::Config::default()
        });
        let log = Arc::new(Mutex::new(Log::default()));
        let shared = Arc::clone(&log);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                shared.lock().unwrap().connections += 1;
                let handler = Handler {
                    spec: spec.clone(),
                    log: Arc::clone(&shared),
                    key_done: false,
                    sessions: Vec::new(),
                };
                let config = Arc::clone(&config);
                let log = Arc::clone(&shared);
                tokio::spawn(async move {
                    if let Ok(session) = server::run_stream(config, stream, handler).await {
                        let _ = session.await;
                    }
                    log.lock().unwrap().ended += 1;
                });
            }
        });
        Self {
            port,
            host_key,
            log,
        }
    }

    /// The `known_hosts` line for this server.
    pub fn known_line(&self) -> String {
        format!(
            "[127.0.0.1]:{} {}",
            self.port,
            self.host_key.to_openssh().unwrap()
        )
    }

    pub fn fingerprint(&self) -> String {
        sshkm_ssh::host_keys::fingerprint(&self.host_key)
    }

    /// Waits until `check` holds for the log, for up to five seconds.
    pub async fn wait_for(&self, check: impl Fn(&Log) -> bool) {
        for _ in 0..500 {
            if check(&self.log.lock().unwrap()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the server never saw it: {:?}", self.log.lock().unwrap());
    }
}

struct Handler {
    spec: Spec,
    log: Arc<Mutex<Log>>,
    key_done: bool,
    /// Session channels; `direct-tcpip` ones only carry bytes through.
    sessions: Vec<ChannelId>,
}

impl Handler {
    fn accept(&self, method: &str) -> Auth {
        self.log.lock().unwrap().signed_in.push(method.to_owned());
        Auth::Accept
    }
}

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        offer: server::PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(
            if user == self.spec.user && self.spec.key.as_ref() == Some(offer.public_key) {
                Auth::Accept
            } else {
                Auth::reject()
            },
        )
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: server::VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        if user != self.spec.user || self.spec.key.as_ref() != Some(key.public_key) {
            return Ok(Auth::reject());
        }
        if self.spec.key_then_code {
            self.key_done = true;
            self.log.lock().unwrap().signed_in.push("publickey".into());
            return Ok(Auth::Reject {
                proceed_with_methods: Some(MethodSet::from(&[MethodKind::KeyboardInteractive][..])),
                partial_success: true,
            });
        }
        Ok(self.accept("publickey"))
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(
            if self.spec.password && user == self.spec.user && password == PASSWORD {
                self.accept("password")
            } else {
                // OpenSSH lets the client try again; russh's default
                // takes the method off the list.
                Auth::Reject {
                    proceed_with_methods: Some(MethodSet::from(&[MethodKind::Password][..])),
                    partial_success: false,
                }
            },
        )
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        _submethods: &str,
        response: Option<Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        let code_only = self.spec.key_then_code;
        if self.spec.endless {
            self.log.lock().unwrap().rounds += 1;
            return Ok(Auth::Partial {
                name: "".into(),
                instructions: "".into(),
                prompts: vec![("Password: ".into(), false)].into(),
            });
        }
        if user != self.spec.user || !(self.spec.interactive || (code_only && self.key_done)) {
            return Ok(Auth::reject());
        }
        let Some(response) = response else {
            let prompts: Vec<(std::borrow::Cow<'static, str>, bool)> = if code_only {
                vec![("Verification code: ".into(), false)]
            } else {
                vec![
                    ("Password: ".into(), false),
                    ("Verification code: ".into(), false),
                ]
            };
            return Ok(Auth::Partial {
                name: "".into(),
                instructions: "".into(),
                prompts: prompts.into(),
            });
        };
        let answers: Vec<String> = response
            .map(|answer| String::from_utf8_lossy(&answer).into_owned())
            .collect();
        let expected: Vec<&str> = if code_only {
            vec![CODE]
        } else {
            vec![PASSWORD, CODE]
        };
        Ok(if answers == expected {
            self.accept("keyboard-interactive")
        } else {
            Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.sessions.push(channel.id());
        reply.accept().await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.spec.forwards {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        self.log
            .lock()
            .unwrap()
            .forwards
            .push((host_to_connect.to_owned(), port_to_connect));
        let address = format!("{host_to_connect}:{port_to_connect}");
        match TcpStream::connect(address).await {
            Ok(mut tcp) => {
                reply.accept().await;
                tokio::spawn(async move {
                    let mut stream = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
                });
            }
            Err(_) => {
                reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
            }
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        cols: u32,
        rows: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.log.lock().unwrap().pty = Some((term.to_owned(), cols, rows));
        session.channel_success(channel)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, b"welcome\r\n".to_vec())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        cols: u32,
        rows: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.log.lock().unwrap().resizes.push((cols, rows));
        session.data(channel, format!("resized {cols}x{rows}\r\n").into_bytes())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.sessions.contains(&channel) {
            return Ok(());
        }
        self.log.lock().unwrap().received.extend_from_slice(data);
        if data == b"exit\r" {
            session.exit_status_request(channel, 3)?;
            return session.close(channel);
        }
        session.data(channel, data.to_vec())
    }

    async fn channel_close(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.log.lock().unwrap().closed = true;
        Ok(())
    }
}

/// A TCP proxy to a server that can stop passing bytes on, as a network
/// that drops everything does.
pub struct Proxy {
    pub port: u16,
    pub frozen: Arc<std::sync::atomic::AtomicBool>,
}

impl Proxy {
    pub async fn start(target: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let frozen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shared = Arc::clone(&frozen);
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let Ok(server) = TcpStream::connect(("127.0.0.1", target)).await else {
                    continue;
                };
                let (client_read, client_write) = client.into_split();
                let (server_read, server_write) = server.into_split();
                tokio::spawn(pump(client_read, server_write, Arc::clone(&shared)));
                tokio::spawn(pump(server_read, client_write, Arc::clone(&shared)));
            }
        });
        Self { port, frozen }
    }

    pub fn freeze(&self) {
        self.frozen.store(true, Ordering::SeqCst);
    }
}

/// Passes bytes on, holding them while `frozen`.
async fn pump(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    frozen: Arc<std::sync::atomic::AtomicBool>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buffer = vec![0; 16 * 1024];
    while let Ok(n) = from.read(&mut buffer).await {
        if n == 0 {
            break;
        }
        while frozen.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        if to.write_all(&buffer[..n]).await.is_err() {
            break;
        }
    }
}

/// The phone's key for tests: a fixed P-256 key standing in for Keystore.
pub fn phone_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x24; 32].into()).unwrap()
}

pub fn phone_key() -> PhoneKey {
    let der = phone_signing_key()
        .verifying_key()
        .to_public_key_der()
        .unwrap();
    PhoneKey::from_spki_der(der.as_bytes()).unwrap()
}

/// The app, as a test wants it to answer.
#[derive(Default)]
pub struct App {
    /// Signs with this key, as Keystore would: DER.
    pub signer: Option<SigningKey>,
    /// The answer to an unknown host.
    pub trust: bool,
    /// Never answers an unknown host (the user walked away).
    pub hang: bool,
    /// The unanswered question went away.
    pub question_dropped: Arc<std::sync::atomic::AtomicBool>,
    /// `unknown_host` fails, as a Kotlin exception does.
    pub unknown_host_fails: bool,
    /// Storing a trusted line fails.
    pub storing_fails: bool,
    /// Answers to prompts, in order; `None` once they run out.
    pub answers: Mutex<VecDeque<Vec<&'static str>>>,
    pub asked: Mutex<Vec<AuthPrompt>>,
    pub unknown: Mutex<Vec<UnknownHostKey>>,
    pub trusted: Mutex<Vec<String>>,
    pub signed: AtomicUsize,
}

impl App {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_signer(mut self) -> Self {
        self.signer = Some(phone_signing_key());
        self
    }

    pub fn trusting(mut self) -> Self {
        self.trust = true;
        self
    }

    pub fn answering(self, answers: &[&[&'static str]]) -> Self {
        *self.answers.lock().unwrap() = answers.iter().map(|a| a.to_vec()).collect();
        self
    }

    pub fn signed(&self) -> usize {
        self.signed.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl Callbacks for App {
    async fn sign(&self, request: SignRequest) -> Result<Vec<u8>, CallbackError> {
        let key = self.signer.as_ref().ok_or(CallbackError::Cancelled)?;
        self.signed.fetch_add(1, Ordering::SeqCst);
        let signature: Signature = key.sign(&request.data);
        Ok(signature.to_der().as_bytes().to_vec())
    }

    async fn unknown_host(&self, key: UnknownHostKey) -> Result<bool, CallbackError> {
        self.unknown.lock().unwrap().push(key);
        if self.unknown_host_fails {
            return Err(CallbackError::Failed("IllegalStateException".into()));
        }
        if self.hang {
            struct Dropped(Arc<std::sync::atomic::AtomicBool>);
            impl Drop for Dropped {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::SeqCst);
                }
            }
            let _dropped = Dropped(Arc::clone(&self.question_dropped));
            std::future::pending::<()>().await;
        }
        Ok(self.trust)
    }

    fn host_key_trusted(&self, line: String) -> Result<(), CallbackError> {
        if self.storing_fails {
            return Err(CallbackError::Failed("disk full".into()));
        }
        self.trusted.lock().unwrap().push(line);
        Ok(())
    }

    async fn answer(
        &self,
        prompt: AuthPrompt,
    ) -> Result<Option<Vec<Zeroizing<String>>>, CallbackError> {
        self.asked.lock().unwrap().push(prompt);
        let Some(answers) = self.answers.lock().unwrap().pop_front() else {
            return Ok(None);
        };
        Ok(Some(
            answers
                .into_iter()
                .map(|a| Zeroizing::new(a.to_owned()))
                .collect(),
        ))
    }
}
