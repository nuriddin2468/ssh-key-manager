//! Connecting: TCP to the first machine, then each next one through a
//! `direct-tcpip` channel of the one before (`ssh -W`), checking each
//! server's key and signing in to each.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use russh::client::{self, Handle};
use russh::keys::PublicKeyOrCertificate;
use russh::{Disconnect, Preferred, kex};
use sshkm_core::config::SshConfig;
use sshkm_core::known_hosts::KnownHosts;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::oneshot;

use crate::auth::authenticate;
use crate::callbacks::{Callbacks, UnknownHostKey};
use crate::error::{Error, KeyMismatch};
use crate::host_keys::{self, Verdict};
use crate::key::PhoneKey;
use crate::route::{Endpoint, Route};
use crate::session::{PtySize, Shell};

/// Key exchanges, as current OpenSSH clients offer them (those russh has),
/// with the extensions that turn on strict key exchange and `ext-info`.
const KEX: &[kex::Name] = &[
    kex::MLKEM768X25519_SHA256,
    kex::CURVE25519,
    kex::CURVE25519_PRE_RFC_8731,
    kex::DH_GEX_SHA256,
    kex::DH_G16_SHA512,
    kex::DH_G18_SHA512,
    kex::DH_G14_SHA256,
    kex::EXTENSION_SUPPORT_AS_CLIENT,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
];

/// What the app gives besides the host's name.
#[derive(Debug, Clone, Default)]
pub struct ConnectOptions {
    /// The user for machines whose settings name none. A phone has no
    /// login name of its own to fall back on, as `ssh` does.
    pub default_user: Option<String>,
    /// The phone's key, offered to every machine that takes keys. `None`:
    /// prompts and passwords only.
    pub key: Option<PhoneKey>,
    /// Keepalive for machines whose settings set no
    /// `ServerAliveInterval`. `None`: off, as `ssh` has it.
    pub default_keepalive: Option<Duration>,
}

/// A connection to a destination, through its jump hosts, signed in.
pub struct Connection {
    /// The destination's handle last; jump hosts carry the way to it.
    handles: Vec<Handle<HopHandler>>,
    destination: Endpoint,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("destination", &self.destination.alias)
            .field("hops", &self.handles.len())
            .finish()
    }
}

impl Connection {
    /// Connects to `destination` (the name as typed) with the host blocks
    /// in `config` and the server keys in `known_hosts`, both as the phone
    /// carries them.
    pub async fn connect(
        config: &str,
        known_hosts: &str,
        destination: &str,
        options: ConnectOptions,
        callbacks: Arc<dyn Callbacks>,
    ) -> Result<Self, Error> {
        let route = Route::resolve(&SshConfig::parse(config), destination)?;
        Self::connect_route(route, KnownHosts::parse(known_hosts), options, callbacks).await
    }

    /// Connects along a route already worked out.
    pub async fn connect_route(
        route: Route,
        known_hosts: KnownHosts,
        options: ConnectOptions,
        callbacks: Arc<dyn Callbacks>,
    ) -> Result<Self, Error> {
        // Users first, so nothing goes out for a route that can't sign in.
        let users = route
            .hops
            .iter()
            .map(|hop| {
                hop.user
                    .clone()
                    .or_else(|| options.default_user.clone())
                    .filter(|u| !u.is_empty())
                    .ok_or_else(|| Error::NoUser {
                        alias: hop.alias.clone(),
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let known = Arc::new(Mutex::new(known_hosts));
        let mut handles: Vec<Handle<HopHandler>> = Vec::with_capacity(route.hops.len());
        for (i, (endpoint, user)) in route.hops.iter().zip(&users).enumerate() {
            let parts = HopParts {
                endpoint: endpoint.clone(),
                known: Arc::clone(&known),
                callbacks: Arc::clone(&callbacks),
                keepalive: endpoint.server_alive_interval.or(options.default_keepalive),
            };
            let mut handle = match handles.last() {
                None => {
                    let stream = tcp(endpoint).await?;
                    handshake(stream, parts).await?
                }
                Some(previous) => {
                    let jump = &route.hops[i - 1].alias;
                    let channel = open_way(previous, jump, endpoint).await?;
                    handshake(channel.into_stream(), parts).await?
                }
            };
            authenticate(
                &mut handle,
                endpoint,
                user,
                options.key.as_ref(),
                callbacks.as_ref(),
            )
            .await?;
            handles.push(handle);
        }
        Ok(Self {
            handles,
            destination: route.destination().clone(),
        })
    }

    /// The destination's settings.
    pub fn destination(&self) -> &Endpoint {
        &self.destination
    }

    /// Opens an interactive shell on a terminal of `size`
    /// (`TERM=xterm-256color`).
    pub async fn open_shell(self, size: PtySize) -> Result<Shell, Error> {
        let channel = self
            .destination_handle()
            .channel_open_session()
            .await
            .map_err(|e| match e {
                russh::Error::ChannelOpenFailure(_) => Error::ShellRefused {
                    alias: self.destination.alias.clone(),
                },
                other => Error::from(other),
            })?;
        Shell::start(self, channel, size).await
    }

    pub(crate) fn destination_handle(&self) -> &Handle<HopHandler> {
        self.handles.last().expect("a connection has a destination")
    }

    /// Asks every machine on the way for an answer now (when the app comes
    /// back to the front, say). A machine that doesn't answer its
    /// keepalives in time ends the connection.
    pub async fn keepalive(&self) -> Result<(), Error> {
        for handle in &self.handles {
            handle.send_keepalive(true).await?;
        }
        Ok(())
    }

    /// Says goodbye to every machine, the destination first.
    pub async fn disconnect(&self) {
        for handle in self.handles.iter().rev() {
            // A machine already gone has nothing to hear.
            let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
        }
    }

    /// Whether the connection has ended.
    pub fn is_closed(&self) -> bool {
        self.handles.iter().any(Handle::is_closed)
    }
}

/// What a machine's handler needs.
struct HopParts {
    endpoint: Endpoint,
    known: Arc<Mutex<KnownHosts>>,
    callbacks: Arc<dyn Callbacks>,
    keepalive: Option<Duration>,
}

/// Checks one machine's key, in russh's session task.
pub(crate) struct HopHandler {
    endpoint: Endpoint,
    known: Arc<Mutex<KnownHosts>>,
    callbacks: Arc<dyn Callbacks>,
    /// The connection attempt, for the first key check.
    attempt: Option<Attempt>,
}

/// Ties the first key check to the attempt that waits for it.
struct Attempt {
    /// Told when the server's key arrives: the connect timeout stops there,
    /// since the user may take a while to answer.
    arrived: oneshot::Sender<()>,
    /// Ends when the attempt is given up (timed out, or the app cancelled
    /// it): a question still on screen then goes away unanswered.
    abandoned: oneshot::Receiver<()>,
}

impl client::Handler for HopHandler {
    type Error = Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Error> {
        let mut abandoned = match self.attempt.take() {
            Some(Attempt { arrived, abandoned }) => {
                if arrived.send(()).is_err() {
                    // Nobody waits for this connection any more.
                    return Err(Error::Cancelled);
                }
                Some(abandoned)
            }
            None => None,
        };
        let PublicKeyOrCertificate::PublicKey { key, .. } = key else {
            // Certificates aren't asked for (`host_key_certificates` is
            // empty); one sent anyway is a key nobody trusted.
            return Err(Error::UnknownHostDeclined {
                alias: self.endpoint.alias.clone(),
            });
        };
        let Endpoint {
            alias, host, port, ..
        } = &self.endpoint;
        let verdict = {
            let known = self.known.lock().unwrap_or_else(PoisonError::into_inner);
            host_keys::check(&known, host, *port, key)
        };
        let fingerprint = host_keys::fingerprint(key);
        let key_type = host_keys::openssh_parts(key)
            .map(|(t, _)| t)
            .unwrap_or_default();
        match verdict {
            Verdict::Known => Ok(true),
            Verdict::Revoked => Err(Error::HostKeyRevoked {
                alias: alias.clone(),
                host: host.clone(),
                port: *port,
                fingerprint,
            }),
            Verdict::Changed { known } => Err(Error::HostKeyChanged {
                alias: alias.clone(),
                mismatch: Box::new(KeyMismatch {
                    host: host.clone(),
                    port: *port,
                    key_type,
                    fingerprint,
                    known,
                }),
            }),
            Verdict::Unknown { other_types } => {
                let question = self.callbacks.unknown_host(UnknownHostKey {
                    alias: alias.clone(),
                    host: host.clone(),
                    port: *port,
                    key_type,
                    fingerprint,
                    other_types,
                });
                let trusted = match abandoned.as_mut() {
                    Some(abandoned) => tokio::select! {
                        trusted = question => trusted,
                        _ = abandoned => return Err(Error::Cancelled),
                    },
                    None => question.await,
                };
                if !trusted {
                    return Err(Error::UnknownHostDeclined {
                        alias: alias.clone(),
                    });
                }
                if let Some((key_type, encoded)) = host_keys::openssh_parts(key) {
                    // Later machines on the way may be the same host.
                    let _ = self
                        .known
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .add_key(host, *port, &key_type, &encoded);
                }
                if let Some(line) = host_keys::line_for(host, *port, key) {
                    self.callbacks.host_key_trusted(line);
                }
                Ok(true)
            }
        }
    }
}

/// The client settings for one machine.
fn config_for(parts: &HopParts) -> client::Config {
    let host_keys = {
        let known = parts.known.lock().unwrap_or_else(PoisonError::into_inner);
        host_keys::algorithms_for(&known, &parts.endpoint.host, parts.endpoint.port)
    };
    client::Config {
        preferred: Preferred {
            kex: KEX.into(),
            key: host_keys,
            ..Preferred::DEFAULT
        },
        keepalive_interval: parts.keepalive,
        keepalive_max: usize::try_from(parts.endpoint.server_alive_count_max).unwrap_or(usize::MAX),
        // Typing goes out at once.
        nodelay: true,
        ..client::Config::default()
    }
}

/// The SSH handshake on `stream`, up to a checked server key: within
/// `ConnectTimeout` until the key arrives, then as long as the user takes.
async fn handshake<S>(stream: S, parts: HopParts) -> Result<Handle<HopHandler>, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = Arc::new(config_for(&parts));
    let (arrived, key_arrived) = oneshot::channel();
    // Dropped with this future, which ends the handler's wait for an answer.
    let (_attempt, abandoned) = oneshot::channel::<()>();
    let endpoint = parts.endpoint.clone();
    let handler = HopHandler {
        endpoint: parts.endpoint,
        known: parts.known,
        callbacks: parts.callbacks,
        attempt: Some(Attempt { arrived, abandoned }),
    };
    let connecting = client::connect_stream(config, stream, handler);
    let deadline = async {
        match endpoint.connect_timeout {
            Some(timeout) => {
                tokio::select! {
                    // The key is here (or the handshake failed): no more
                    // deadline.
                    _ = key_arrived => std::future::pending::<()>().await,
                    () = tokio::time::sleep(timeout) => {}
                }
            }
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        result = connecting => result.map_err(|e| e.about(&endpoint.alias)),
        () = deadline => Err(timed_out(&endpoint)),
    }
}

fn timed_out(endpoint: &Endpoint) -> Error {
    Error::TimedOut {
        alias: endpoint.alias.clone(),
        host: endpoint.host.clone(),
        port: endpoint.port,
    }
}

/// TCP to the first machine: every address the name has, in turn, within
/// `ConnectTimeout` in all.
async fn tcp(endpoint: &Endpoint) -> Result<TcpStream, Error> {
    let attempt = async {
        let not_found = || Error::NameNotFound {
            alias: endpoint.alias.clone(),
            host: endpoint.host.clone(),
        };
        let addresses: Vec<_> = tokio::net::lookup_host((endpoint.host.as_str(), endpoint.port))
            .await
            .map_err(|_| not_found())?
            .collect();
        let mut last = not_found();
        for address in addresses {
            match TcpStream::connect(address).await {
                Ok(stream) => return Ok(stream),
                Err(error) => {
                    last = match error.kind() {
                        std::io::ErrorKind::ConnectionRefused => Error::Refused {
                            alias: endpoint.alias.clone(),
                            host: endpoint.host.clone(),
                            port: endpoint.port,
                        },
                        std::io::ErrorKind::TimedOut => timed_out(endpoint),
                        _ => Error::Unreachable {
                            alias: endpoint.alias.clone(),
                            host: endpoint.host.clone(),
                            port: endpoint.port,
                            detail: error.to_string(),
                        },
                    };
                }
            }
        }
        Err(last)
    };
    let stream = match endpoint.connect_timeout {
        Some(timeout) => tokio::time::timeout(timeout, attempt)
            .await
            .map_err(|_| timed_out(endpoint))??,
        None => attempt.await?,
    };
    // Typing goes out at once; failing to say so changes nothing else.
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// A `direct-tcpip` channel from `previous` (the machine before, `jump`)
/// to `endpoint`, within `endpoint`'s `ConnectTimeout`.
async fn open_way(
    previous: &Handle<HopHandler>,
    jump: &str,
    endpoint: &Endpoint,
) -> Result<russh::Channel<client::Msg>, Error> {
    let opening = previous.channel_open_direct_tcpip(
        endpoint.host.as_str(),
        u32::from(endpoint.port),
        "127.0.0.1",
        0,
    );
    let result = match endpoint.connect_timeout {
        Some(timeout) => tokio::time::timeout(timeout, opening)
            .await
            .map_err(|_| timed_out(endpoint))?,
        None => opening.await,
    };
    // The jump host couldn't connect, or wouldn't: its server says no
    // more than that.
    result.map_err(|error| match error {
        russh::Error::ChannelOpenFailure(_) => Error::JumpFailed {
            jump: jump.to_owned(),
            alias: endpoint.alias.clone(),
            host: endpoint.host.clone(),
            port: endpoint.port,
        },
        other => Error::from(other),
    })
}
