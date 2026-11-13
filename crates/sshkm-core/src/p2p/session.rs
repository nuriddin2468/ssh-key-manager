//! A session between two apps: a Noise `XX` handshake, then messages.
//!
//! - **Handshake.** `Noise_XX_25519_ChaChaPoly_SHA256`: each side proves it
//!   holds its device key, and everything after is encrypted. Each Noise
//!   message travels as a big-endian `u16` length and its bytes.
//! - **Messages.** A [`Message`] is JSON, at most [`MAX_MESSAGE`] bytes,
//!   sent as its length (`u32`, big-endian) and the JSON, split over as
//!   many Noise messages as it takes.
//! - **Own devices.** Between the user's own devices the handshake is
//!   `Noise_XXpsk0_25519_ChaChaPoly_SHA256`, with a key both have from the
//!   vault ([`OwnKey::session_key`]) mixed in from the first message: a
//!   computer without the vault fails it at once and learns nothing, not
//!   even the other's device key.
//! - **Pairing code.** Six digits both users compare, from the handshake
//!   hash and a nonce from each side. The initiator commits to its nonce
//!   before it sees the responder's, and the responder sends its own before
//!   it sees the initiator's: someone in the middle runs a session with each
//!   side, but must fix one side's nonce before learning what the other's
//!   code will be, so the two codes agree by chance only, one time in a
//!   million. (Taken from the handshake hash alone, the code could be
//!   matched by trying a million keys.) The initiator does learn the code
//!   before it reveals its nonce, and could hang up and try again until the
//!   responder's code is one it wants; [`Session::gave_nonce`] tells the
//!   responder that a session ended that way, so the app can count them.
//! - **Large values.** Between own devices a value larger than a message (a
//!   vault file, a long list of hosts) goes as [`Message::Bytes`], its size
//!   and SHA-256, and then [`Message::Part`]s; the receiver sets how large it
//!   may be.
//! - **Chats.** A chat session's handshake has a prologue of its own
//!   ([`connect_with`], [`accept_with`]), and the session splits in two
//!   ([`Session::split`]): one thread reads while any other sends.
//!
//! [`OwnKey::session_key`]: super::own::OwnKey::session_key

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use base64ct::{Base64, Encoding};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::identity::{Identity, PeerKey, params};
use super::protocol::{MAX_MESSAGE, Message};
use crate::{Error, Result};

pub(crate) const PARAMS: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
/// Between own devices: see the module documentation.
pub(crate) const OWN_PARAMS: &str = "Noise_XXpsk0_25519_ChaChaPoly_SHA256";
/// Bound into the handshake: a peer speaking anything else fails it.
const PROLOGUE: &[u8] = b"sshkm-p2p/1";
const OWN_PROLOGUE: &[u8] = b"sshkm-own/1";
const CODE_LABEL: &[u8] = b"sshkm-p2p pairing code";
/// Largest Noise message, and the tag each one carries.
const NOISE_MAX: usize = 65_535;
const TAG: usize = 16;
const NONCE_LEN: usize = 32;
/// Largest piece of a large value, before base64: well within a message.
const PART: usize = 512 * 1024;

/// An open session over `S`, after the handshake.
pub struct Session<S> {
    stream: S,
    noise: snow::TransportState,
    remote: PeerKey,
    hash: Vec<u8>,
    initiator: bool,
    /// This side, the responder, sent its pairing nonce.
    gave_nonce: bool,
}

/// Opens a session as the side that connected.
pub fn connect<S: Read + Write>(stream: S, identity: &Identity) -> Result<Session<S>> {
    connect_with(stream, identity, PROLOGUE)
}

/// Opens a session as the side that was connected to.
pub fn accept<S: Read + Write>(stream: S, identity: &Identity) -> Result<Session<S>> {
    accept_with(stream, identity, PROLOGUE)
}

/// Opens a session bound to `prologue` as the side that connected: the
/// peer's must be the same, or the handshake fails.
pub fn connect_with<S: Read + Write>(
    stream: S,
    identity: &Identity,
    prologue: &[u8],
) -> Result<Session<S>> {
    initiate(stream, builder(identity, prologue, None))
}

/// Opens a session bound to `prologue` as the side that was connected to.
pub fn accept_with<S: Read + Write>(
    stream: S,
    identity: &Identity,
    prologue: &[u8],
) -> Result<Session<S>> {
    respond(stream, builder(identity, prologue, None))
}

/// Opens a session with one of the user's own devices, as the side that
/// connected; both sides have `key` from the vault.
pub fn connect_own<S: Read + Write>(
    stream: S,
    identity: &Identity,
    key: &[u8; 32],
) -> Result<Session<S>> {
    initiate(stream, builder(identity, OWN_PROLOGUE, Some(key)))
}

/// Opens a session with one of the user's own devices, as the side that
/// was connected to; a peer without `key` fails at its first message,
/// before this side sends anything.
pub fn accept_own<S: Read + Write>(
    stream: S,
    identity: &Identity,
    key: &[u8; 32],
) -> Result<Session<S>> {
    respond(stream, builder(identity, OWN_PROLOGUE, Some(key)))
}

fn initiate<S: Read + Write>(mut stream: S, builder: snow::Builder<'_>) -> Result<Session<S>> {
    let mut handshake = builder.build_initiator().map_err(noise_error)?;
    let mut buffer = vec![0; NOISE_MAX];
    // -> e
    let n = handshake
        .write_message(&[], &mut buffer)
        .map_err(noise_error)?;
    write_frame(&mut stream, &buffer[..n])?;
    // <- e, ee, s, es
    let frame = read_frame(&mut stream)?;
    handshake
        .read_message(&frame, &mut buffer)
        .map_err(noise_error)?;
    // -> s, se
    let n = handshake
        .write_message(&[], &mut buffer)
        .map_err(noise_error)?;
    write_frame(&mut stream, &buffer[..n])?;
    finish(stream, handshake, true)
}

fn respond<S: Read + Write>(mut stream: S, builder: snow::Builder<'_>) -> Result<Session<S>> {
    let mut handshake = builder.build_responder().map_err(noise_error)?;
    let mut buffer = vec![0; NOISE_MAX];
    let frame = read_frame(&mut stream)?;
    handshake
        .read_message(&frame, &mut buffer)
        .map_err(noise_error)?;
    let n = handshake
        .write_message(&[], &mut buffer)
        .map_err(noise_error)?;
    write_frame(&mut stream, &buffer[..n])?;
    let frame = read_frame(&mut stream)?;
    handshake
        .read_message(&frame, &mut buffer)
        .map_err(noise_error)?;
    finish(stream, handshake, false)
}

/// The handshake bound to `prologue`; with `own`, the one between own
/// devices, with that key mixed in.
fn builder<'a>(
    identity: &'a Identity,
    prologue: &'a [u8],
    own: Option<&'a [u8; 32]>,
) -> snow::Builder<'a> {
    match own {
        None => snow::Builder::new(params()).prologue(prologue),
        Some(key) => snow::Builder::new(own_params())
            .prologue(prologue)
            .and_then(|builder| builder.psk(0, key)),
    }
    .and_then(|builder| builder.local_private_key(identity.private()))
    .unwrap_or_else(|_| unreachable!("32-byte keys and a prologue are accepted"))
}

fn own_params() -> snow::params::NoiseParams {
    OWN_PARAMS
        .parse()
        .unwrap_or_else(|_| unreachable!("valid Noise parameters"))
}

fn finish<S>(stream: S, handshake: snow::HandshakeState, initiator: bool) -> Result<Session<S>> {
    let remote = PeerKey::from_bytes(
        handshake
            .get_remote_static()
            .ok_or_else(|| Error::Parse("the peer sent no device key".into()))?,
    )?;
    let hash = handshake.get_handshake_hash().to_vec();
    let noise = handshake.into_transport_mode().map_err(noise_error)?;
    Ok(Session {
        stream,
        noise,
        remote,
        hash,
        initiator,
        gave_nonce: false,
    })
}

impl<S> Session<S> {
    /// The same session over `f(stream)`: e.g. the socket again, once the
    /// first steps under a [`super::deadline::Deadline`] are done.
    pub fn map_stream<T>(self, f: impl FnOnce(S) -> T) -> Session<T> {
        Session {
            stream: f(self.stream),
            noise: self.noise,
            remote: self.remote,
            hash: self.hash,
            initiator: self.initiator,
            gave_nonce: self.gave_nonce,
        }
    }
}

impl<S: Read + Write> Session<S> {
    /// The peer's device key, proven in the handshake.
    pub fn remote(&self) -> PeerKey {
        self.remote
    }

    /// The stream under the session, to set its timeouts.
    pub fn stream(&self) -> &S {
        &self.stream
    }

    /// The hash of the handshake, the same on both sides and different in
    /// every session: what a proof made for this session is bound to.
    pub fn handshake_hash(&self) -> &[u8] {
        &self.hash
    }

    /// Whether this side connected.
    pub fn is_initiator(&self) -> bool {
        self.initiator
    }

    /// Whether this side, the one connected to, sent its pairing nonce:
    /// from then on the other side knows the code this side would show. A
    /// session that fails after that without a code is one the other side
    /// may have given up on because it didn't like the code.
    pub fn gave_nonce(&self) -> bool {
        self.gave_nonce
    }

    pub fn send(&mut self, message: &Message) -> Result<()> {
        // The buffers may hold a password: they are wiped when dropped.
        let json = to_json(message)?;
        self.send_json(&json)
    }

    /// Sends `message`, as a large value if it does not fit in one message;
    /// the peer reads it with [`Self::recv_large`].
    pub fn send_large(&mut self, message: &Message) -> Result<()> {
        let json = to_json(message)?;
        if json.len() <= MAX_MESSAGE {
            self.send_json(&json)
        } else {
            self.send_bytes(&json, &mut |_, _| {})
        }
    }

    /// Sends `bytes` as a large value, calling `progress` with the bytes
    /// sent so far and the total after each part.
    pub fn send_bytes(&mut self, bytes: &[u8], progress: &mut dyn FnMut(u64, u64)) -> Result<()> {
        let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        self.send(&Message::Bytes {
            size,
            sha256: Base64::encode_string(&Sha256::digest(bytes)),
        })?;
        let mut sent = 0;
        for part in bytes.chunks(PART) {
            self.send(&Message::Part {
                data: Base64::encode_string(part),
            })?;
            sent += u64::try_from(part.len()).unwrap_or(u64::MAX);
            progress(sent, size);
        }
        Ok(())
    }

    /// Reads a large value of at most `max` bytes, as [`Self::send_bytes`]
    /// sends it.
    pub fn recv_bytes(
        &mut self,
        max: u64,
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<Zeroizing<Vec<u8>>> {
        let Message::Bytes { size, sha256 } = self.recv()? else {
            return Err(unexpected("a large value"));
        };
        self.collect(size, &sha256, max, progress)
    }

    /// Reads a message [`Self::send_large`] sent: one of at most `max` bytes
    /// of JSON.
    pub fn recv_large(&mut self, max: u64) -> Result<Message> {
        match self.recv()? {
            Message::Bytes { size, sha256 } => {
                let json = self.collect(size, &sha256, max, &mut |_, _| {})?;
                match serde_json::from_slice(&json) {
                    Ok(Message::Bytes { .. } | Message::Part { .. }) => {
                        Err(unexpected("a message in the large value"))
                    }
                    Ok(message) => Ok(message),
                    Err(e) => Err(Error::Parse(format!("message: {e}"))),
                }
            }
            message => Ok(message),
        }
    }

    fn collect(
        &mut self,
        size: u64,
        sha256: &str,
        max: u64,
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<Zeroizing<Vec<u8>>> {
        if size > max {
            return Err(Error::Parse(
                "the peer sent a value that is too large".into(),
            ));
        }
        let expected = Base64::decode_vec(sha256)
            .map_err(|_| Error::Parse("the peer's hash is not base64".into()))?;
        let total = usize::try_from(size).unwrap_or(usize::MAX);
        let mut bytes = Zeroizing::new(Vec::with_capacity(total.min(16 * PART)));
        while bytes.len() < total {
            let Message::Part { data } = self.recv()? else {
                return Err(unexpected("the next part"));
            };
            let part = Zeroizing::new(
                Base64::decode_vec(&data)
                    .map_err(|_| Error::Parse("a part is not base64".into()))?,
            );
            if part.is_empty() || part.len() > PART || bytes.len() + part.len() > total {
                return Err(Error::Parse("a part of the wrong size".into()));
            }
            bytes.extend_from_slice(&part);
            progress(u64::try_from(bytes.len()).unwrap_or(u64::MAX), size);
        }
        if !bool::from(Sha256::digest(&*bytes).as_slice().ct_eq(&expected)) {
            return Err(Error::Parse(
                "the value does not match the peer's hash".into(),
            ));
        }
        Ok(bytes)
    }

    fn send_json(&mut self, json: &[u8]) -> Result<()> {
        let noise = &mut self.noise;
        write_json(&mut self.stream, json, &mut |chunk, out| {
            noise.write_message(chunk, out).map_err(noise_error)
        })
    }

    pub fn recv(&mut self) -> Result<Message> {
        let noise = &mut self.noise;
        read_message(&mut self.stream, &mut |frame, out| {
            noise.read_message(frame, out).map_err(noise_error)
        })
    }

    /// Agrees with the peer on the six-digit code both users compare; both
    /// sides call it at the same point. Fails if the peer breaks the
    /// exchange, e.g. reveals a nonce other than the one it committed to.
    pub fn pairing_code(&mut self) -> Result<String> {
        let mut mine = [0; NONCE_LEN];
        OsRng.fill_bytes(&mut mine);
        if self.initiator {
            self.send(&Message::Commit {
                hash: Base64::encode_string(&Sha256::digest(mine)),
            })?;
            let Message::Nonce { nonce } = self.recv()? else {
                return Err(unexpected("its nonce"));
            };
            let theirs = decode_nonce(&nonce)?;
            self.send(&Message::Reveal {
                nonce: Base64::encode_string(&mine),
            })?;
            Ok(code(&self.hash, &mine, &theirs))
        } else {
            let Message::Commit { hash } = self.recv()? else {
                return Err(unexpected("its commitment"));
            };
            self.gave_nonce = true;
            self.send(&Message::Nonce {
                nonce: Base64::encode_string(&mine),
            })?;
            let Message::Reveal { nonce } = self.recv()? else {
                return Err(unexpected("its nonce"));
            };
            let theirs = decode_nonce(&nonce)?;
            let committed = Base64::decode_vec(&hash)
                .map_err(|_| Error::Parse("the peer's commitment is not base64".into()))?;
            if !bool::from(Sha256::digest(theirs).as_slice().ct_eq(&committed)) {
                return Err(Error::Parse(
                    "the peer's nonce does not match its commitment".into(),
                ));
            }
            Ok(code(&self.hash, &theirs, &mine))
        }
    }
}

impl Session<TcpStream> {
    /// Splits the session in two: a [`Reader`] for one thread, and a
    /// [`Writer`] any thread may send with. Both share the session's keys;
    /// each message is sealed or opened under a short lock.
    pub fn split(self) -> Result<(Reader, Writer)> {
        let write = self.stream.try_clone().map_err(io_error)?;
        let closer = self.stream.try_clone().map_err(io_error)?;
        let noise = Arc::new(Mutex::new(self.noise));
        Ok((
            Reader {
                stream: self.stream,
                noise: Arc::clone(&noise),
                remote: self.remote,
            },
            Writer {
                stream: Mutex::new(write),
                closer,
                noise,
                sending_since: Mutex::new(None),
            },
        ))
    }
}

/// The half of a split session that reads.
pub struct Reader {
    stream: TcpStream,
    noise: Arc<Mutex<snow::TransportState>>,
    remote: PeerKey,
}

impl Reader {
    /// The peer's device key, proven in the handshake.
    pub fn remote(&self) -> PeerKey {
        self.remote
    }

    /// The stream under the session, to set its timeouts.
    pub fn stream(&self) -> &TcpStream {
        &self.stream
    }

    pub fn recv(&mut self) -> Result<Message> {
        let noise = &self.noise;
        read_message(&mut self.stream, &mut |frame, out| {
            noise
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .read_message(frame, out)
                .map_err(noise_error)
        })
    }
}

/// The half of a split session that sends; shared between threads.
pub struct Writer {
    stream: Mutex<TcpStream>,
    /// The same socket, to hang up without waiting for a send.
    closer: TcpStream,
    noise: Arc<Mutex<snow::TransportState>>,
    /// When the send going now started: a peer that reads a byte now and
    /// then can hold one for ever, each write within its timeout.
    sending_since: Mutex<Option<Instant>>,
}

impl Writer {
    /// Sends `message`. Messages from several threads go one after the
    /// other, never interleaved.
    pub fn send(&self, message: &Message) -> Result<()> {
        let json = to_json(message)?;
        let mut stream = self.stream.lock().unwrap_or_else(PoisonError::into_inner);
        *self.since() = Some(Instant::now());
        let noise = &self.noise;
        let sent = write_json(&mut *stream, &json, &mut |chunk, out| {
            noise
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .write_message(chunk, out)
                .map_err(noise_error)
        });
        *self.since() = None;
        sent
    }

    /// How long the send going now has taken; nothing when none is going.
    /// One that takes long means a peer that doesn't read: hang up.
    pub fn busy_for(&self) -> Duration {
        self.since().map_or(Duration::ZERO, |since| since.elapsed())
    }

    fn since(&self) -> MutexGuard<'_, Option<Instant>> {
        self.sending_since
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Hangs up: the [`Reader`] stops with an error, and so does a send
    /// blocked on a full socket. Never waits for a send.
    pub fn shutdown(&self) {
        let _ = self.closer.shutdown(Shutdown::Both);
    }
}

/// What seals or opens one Noise message: `(input, output) -> bytes written`.
type Seal<'a> = dyn FnMut(&[u8], &mut [u8]) -> Result<usize> + 'a;

/// Writes `json` as its length and the JSON, sealed over as many Noise
/// messages as it takes.
fn write_json(stream: &mut impl Write, json: &[u8], seal: &mut Seal<'_>) -> Result<()> {
    if json.len() > MAX_MESSAGE {
        return Err(Error::invalid("the message is too large"));
    }
    let mut plain = Zeroizing::new(Vec::with_capacity(4 + json.len()));
    plain.extend_from_slice(&u32::try_from(json.len()).unwrap_or(u32::MAX).to_be_bytes());
    plain.extend_from_slice(json);
    let mut out = Zeroizing::new(vec![0; NOISE_MAX]);
    for chunk in plain.chunks(NOISE_MAX - TAG) {
        let n = seal(chunk, &mut out)?;
        write_frame(stream, &out[..n])?;
    }
    stream.flush().map_err(io_error)
}

/// Reads one message as [`write_json`] writes it.
fn read_message(stream: &mut impl Read, open: &mut Seal<'_>) -> Result<Message> {
    let mut plain = Zeroizing::new(Vec::new());
    let mut out = Zeroizing::new(vec![0; NOISE_MAX]);
    let mut take = |stream: &mut dyn Read, plain: &mut Vec<u8>| -> Result<()> {
        let frame = read_frame(stream)?;
        let n = open(&frame, &mut out)?;
        plain.extend_from_slice(&out[..n]);
        Ok(())
    };
    take(stream, &mut plain)?;
    let header: [u8; 4] = plain
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| Error::Parse("a message without its length".into()))?;
    let len = usize::try_from(u32::from_be_bytes(header)).unwrap_or(usize::MAX);
    if len > MAX_MESSAGE {
        return Err(Error::Parse(
            "the peer sent a message that is too large".into(),
        ));
    }
    while plain.len() < 4 + len {
        take(stream, &mut plain)?;
    }
    if plain.len() != 4 + len {
        return Err(Error::Parse("a message longer than its length".into()));
    }
    serde_json::from_slice(&plain[4..]).map_err(|e| Error::Parse(format!("message: {e}")))
}

fn to_json(message: &Message) -> Result<Zeroizing<Vec<u8>>> {
    serde_json::to_vec(message)
        .map(Zeroizing::new)
        .map_err(|e| Error::Parse(format!("message: {e}")))
}

/// Six digits from the handshake hash and both nonces.
fn code(hash: &[u8], initiator: &[u8], responder: &[u8]) -> String {
    let digest = Sha256::new()
        .chain_update(CODE_LABEL)
        .chain_update(hash)
        .chain_update(initiator)
        .chain_update(responder)
        .finalize();
    let number = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    format!("{number:06}")
}

fn decode_nonce(text: &str) -> Result<[u8; NONCE_LEN]> {
    Base64::decode_vec(text)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| Error::Parse("the peer's nonce is not 32 bytes of base64".into()))
}

fn unexpected(what: &str) -> Error {
    Error::Parse(format!("the peer sent something else than {what}"))
}

fn write_frame(stream: &mut impl Write, bytes: &[u8]) -> Result<()> {
    let len = u16::try_from(bytes.len()).map_err(|_| Error::invalid("a frame is too large"))?;
    stream.write_all(&len.to_be_bytes()).map_err(io_error)?;
    stream.write_all(bytes).map_err(io_error)
}

fn read_frame(stream: &mut (impl Read + ?Sized)) -> Result<Vec<u8>> {
    let mut len = [0; 2];
    stream.read_exact(&mut len).map_err(io_error)?;
    let mut frame = vec![0; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut frame).map_err(io_error)?;
    Ok(frame)
}

#[allow(clippy::needless_pass_by_value, reason = "by value, to fit `map_err`")]
fn noise_error(error: snow::Error) -> Error {
    Error::Parse(format!("secure channel: {error}"))
}

fn io_error(source: io::Error) -> Error {
    Error::Io {
        context: "connection to another device".into(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    use super::*;
    use crate::p2p::protocol::VERSION;

    /// A connected pair of sockets on the loopback interface.
    fn pipe() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    fn hello(name: &str) -> Message {
        Message::Hello {
            version: VERSION,
            name: name.into(),
            known: false,
            own: None,
            features: Vec::new(),
        }
    }

    #[test]
    fn parameters_parse() {
        assert!(PARAMS.parse::<snow::params::NoiseParams>().is_ok());
        assert!(OWN_PARAMS.parse::<snow::params::NoiseParams>().is_ok());
    }

    #[test]
    fn both_sides_learn_the_other_and_agree_on_the_code() {
        let (alice, bob) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let (alice_key, bob_key) = (alice.public(), bob.public());
        let (client, server) = pipe();
        let responder = thread::spawn(move || {
            let mut session = accept(server, &bob).unwrap();
            assert_eq!(session.remote(), alice_key);
            assert_eq!(session.recv().unwrap(), hello("alice"));
            session.send(&hello("bob")).unwrap();
            session.pairing_code().unwrap()
        });
        let mut session = connect(client, &alice).unwrap();
        assert_eq!(session.remote(), bob_key);
        session.send(&hello("alice")).unwrap();
        assert_eq!(session.recv().unwrap(), hello("bob"));
        let code = session.pairing_code().unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
        assert_eq!(responder.join().unwrap(), code);
    }

    #[test]
    fn someone_in_the_middle_gets_two_different_codes() {
        let (alice, bob, mallory) = (
            Identity::generate().unwrap(),
            Identity::generate().unwrap(),
            Identity::generate().unwrap(),
        );
        let mallory_key = mallory.public();
        let (alice_end, mallory_from_alice) = pipe();
        let (mallory_to_bob, bob_end) = pipe();
        let bob_side = thread::spawn(move || {
            let mut session = accept(bob_end, &bob).unwrap();
            assert_eq!(session.remote(), mallory_key);
            session.pairing_code().unwrap()
        });
        let middle = thread::spawn(move || {
            let mut to_alice = accept(mallory_from_alice, &mallory).unwrap();
            let mut to_bob = connect(mallory_to_bob, &mallory).unwrap();
            to_bob.pairing_code().unwrap();
            to_alice.pairing_code().unwrap();
        });
        let mut session = connect(alice_end, &alice).unwrap();
        assert_eq!(session.remote(), mallory_key);
        let alice_code = session.pairing_code().unwrap();
        middle.join().unwrap();
        // Two independent codes match one time in a million.
        assert_ne!(alice_code, bob_side.join().unwrap());
    }

    #[test]
    fn the_side_connected_to_knows_when_it_gave_its_nonce() {
        let (alice, bob) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let (client, server) = pipe();
        let responder = thread::spawn(move || {
            let mut session = accept(server, &bob).unwrap();
            assert!(!session.gave_nonce());
            let code = session.pairing_code();
            (code.is_err(), session.gave_nonce())
        });
        // The side that connected learns the code, then hangs up before it
        // reveals its nonce.
        let mut session = connect(client, &alice).unwrap();
        session
            .send(&Message::Commit {
                hash: Base64::encode_string(&Sha256::digest([1; NONCE_LEN])),
            })
            .unwrap();
        assert!(matches!(session.recv().unwrap(), Message::Nonce { .. }));
        assert!(!session.gave_nonce());
        drop(session);
        assert_eq!(responder.join().unwrap(), (true, true));

        // One that hangs up before its commitment got nothing.
        let (alice, bob) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let (client, server) = pipe();
        let responder = thread::spawn(move || {
            let mut session = accept(server, &bob).unwrap();
            let code = session.pairing_code();
            (code.is_err(), session.gave_nonce())
        });
        drop(connect(client, &alice).unwrap());
        assert_eq!(responder.join().unwrap(), (true, false));
    }

    #[test]
    fn own_devices_hide_their_keys_from_anyone_without_the_vault() {
        let (alice, bob) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let (alice_key, bob_key) = (alice.public(), bob.public());
        let key = [7; 32];
        let (client, server) = pipe();
        let responder = thread::spawn(move || {
            let mut session = accept_own(server, &bob, &key).unwrap();
            assert_eq!(session.remote(), alice_key);
            session.send(&hello("bob")).unwrap();
        });
        let mut session = connect_own(client, &alice, &key).unwrap();
        assert_eq!(session.remote(), bob_key);
        assert_eq!(session.recv().unwrap(), hello("bob"));
        responder.join().unwrap();

        // Another key, or the plain handshake: the side connected to says
        // nothing back, so its device key stays its own.
        for (prologue, other) in [(OWN_PROLOGUE, Some([8; 32])), (PROLOGUE, None)] {
            let bob = Identity::generate().unwrap();
            let (mut client, server) = pipe();
            let responder = thread::spawn(move || accept_own(server, &bob, &key).is_err());
            let stranger = Identity::generate().unwrap();
            let mut handshake = builder(&stranger, prologue, other.as_ref())
                .build_initiator()
                .unwrap();
            let mut buffer = vec![0; NOISE_MAX];
            let n = handshake.write_message(&[], &mut buffer).unwrap();
            write_frame(&mut client, &buffer[..n]).unwrap();
            assert!(responder.join().unwrap());
            // Nothing came: the stream ends without a frame.
            assert!(read_frame(&mut client).is_err());
        }

        // Nor does the side that connects get anywhere with a plain one.
        let (client, server) = pipe();
        let bob = Identity::generate().unwrap();
        let responder = thread::spawn(move || accept(server, &bob).is_err());
        assert!(connect_own(client, &Identity::generate().unwrap(), &key).is_err());
        assert!(responder.join().unwrap());
    }

    #[test]
    fn a_nonce_other_than_the_committed_one_fails() {
        let (alice, bob) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let (client, server) = pipe();
        let responder = thread::spawn(move || accept(server, &bob).unwrap().pairing_code());
        let mut session = connect(client, &alice).unwrap();
        session
            .send(&Message::Commit {
                hash: Base64::encode_string(&Sha256::digest([1; NONCE_LEN])),
            })
            .unwrap();
        assert!(matches!(session.recv().unwrap(), Message::Nonce { .. }));
        session
            .send(&Message::Reveal {
                nonce: Base64::encode_string(&[2; NONCE_LEN]),
            })
            .unwrap();
        assert!(responder.join().unwrap().is_err());
    }

    #[test]
    fn large_messages_span_frames_and_too_large_ones_are_refused() {
        let (alice, bob) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let (client, server) = pipe();
        let long = hello(&"x".repeat(200_000));
        let expected = long.clone();
        let responder = thread::spawn(move || {
            let mut session = accept(server, &bob).unwrap();
            assert_eq!(session.recv().unwrap(), expected);
        });
        let mut session = connect(client, &alice).unwrap();
        session.send(&long).unwrap();
        responder.join().unwrap();
        assert!(session.send(&hello(&"x".repeat(MAX_MESSAGE))).is_err());
    }

    #[test]
    fn large_values_go_in_parts() {
        let (alice, bob) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let (client, server) = pipe();
        let bytes: Vec<u8> = (0..1_300_000_u32).map(|i| (i % 251) as u8).collect();
        let long = hello(&"y".repeat(MAX_MESSAGE + 10));
        let (expected_bytes, expected_long) = (bytes.clone(), long.clone());
        let responder = thread::spawn(move || {
            let mut session = accept(server, &bob).unwrap();
            let mut seen = Vec::new();
            let got = session
                .recv_bytes(2_000_000, &mut |done, total| seen.push((done, total)))
                .unwrap();
            assert_eq!(*got, expected_bytes);
            assert_eq!(seen.len(), 3);
            assert_eq!(seen.last(), Some(&(1_300_000, 1_300_000)));
            assert_eq!(session.recv_large(4 * 1024 * 1024).unwrap(), expected_long);
            assert_eq!(session.recv_large(1024).unwrap(), hello("short"));
            // Too large for what this side takes.
            assert!(session.recv_large(1024).is_err());
        });
        let mut session = connect(client, &alice).unwrap();
        session.send_bytes(&bytes, &mut |_, _| {}).unwrap();
        session.send_large(&long).unwrap();
        session.send_large(&hello("short")).unwrap();
        // The responder hangs up after the header.
        let _ = session.send_large(&long);
        responder.join().unwrap();
    }

    #[test]
    fn a_large_value_must_match_its_hash() {
        let (alice, bob) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let (client, server) = pipe();
        let responder = thread::spawn(move || {
            let mut session = accept(server, &bob).unwrap();
            session.recv_bytes(1024, &mut |_, _| {})
        });
        let mut session = connect(client, &alice).unwrap();
        session
            .send(&Message::Bytes {
                size: 3,
                sha256: Base64::encode_string(&Sha256::digest(b"abc")),
            })
            .unwrap();
        session
            .send(&Message::Part {
                data: Base64::encode_string(b"abd"),
            })
            .unwrap();
        assert!(responder.join().unwrap().is_err());
    }

    #[test]
    fn sessions_with_other_prologues_never_meet() {
        let (alice, bob) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let (client, server) = pipe();
        let responder = thread::spawn(move || accept_with(server, &bob, b"sshkm-chat/1 x").is_ok());
        assert!(connect(client, &alice).is_err());
        assert!(!responder.join().unwrap());

        let (alice, bob) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let (client, server) = pipe();
        let responder = thread::spawn(move || accept_with(server, &bob, b"same").is_ok());
        assert!(connect_with(client, &alice, b"same").is_ok());
        assert!(responder.join().unwrap());
    }

    #[test]
    fn a_split_session_reads_on_one_thread_while_others_send() {
        let (alice, bob) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let alice_key = alice.public();
        let (client, server) = pipe();
        let responder = thread::spawn(move || {
            let (mut reader, writer) = accept(server, &bob).unwrap().split().unwrap();
            assert_eq!(reader.remote(), alice_key);
            let writer = Arc::new(writer);
            // Two threads answer at once; every message arrives whole.
            let senders: Vec<_> = (0..2)
                .map(|n| {
                    let writer = Arc::clone(&writer);
                    thread::spawn(move || {
                        for i in 0..50 {
                            writer
                                .send(&hello(&format!("{n}-{i}-{}", "x".repeat(70_000))))
                                .unwrap();
                        }
                    })
                })
                .collect();
            let got = reader.recv().unwrap();
            for sender in senders {
                sender.join().unwrap();
            }
            writer.shutdown();
            got
        });
        let (mut reader, writer) = connect(client, &alice).unwrap().split().unwrap();
        writer.send(&hello("alice")).unwrap();
        let mut seen = 0;
        while let Ok(message) = reader.recv() {
            let Message::Hello { name, .. } = message else {
                panic!("not a hello")
            };
            assert!(name.ends_with(&"x".repeat(70_000)));
            seen += 1;
        }
        assert_eq!(seen, 100);
        assert_eq!(responder.join().unwrap(), hello("alice"));
    }

    #[test]
    fn a_send_to_a_peer_that_doesnt_read_shows_how_long_it_waits() {
        let (alice, bob) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let (client, server) = pipe();
        // Bob shakes hands, then reads nothing until told to go.
        let (go, wait) = std::sync::mpsc::channel::<()>();
        let responder = thread::spawn(move || {
            let session = accept(server, &bob).unwrap();
            let _ = wait.recv();
            drop(session);
        });
        let session = connect(client, &alice).unwrap();
        // As a link's: a write that waits ends by itself too (on Windows,
        // hanging up may not end one already waiting).
        session
            .stream()
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let (_reader, writer) = session.split().unwrap();
        let writer = Arc::new(writer);
        assert_eq!(writer.busy_for(), Duration::ZERO);
        let sender = {
            let writer = Arc::clone(&writer);
            thread::spawn(move || {
                let big = hello(&"x".repeat(1_000_000));
                // Until the sockets' buffers fill and a send waits.
                while writer.send(&big).is_ok() {}
            })
        };
        let started = Instant::now();
        while writer.busy_for() < Duration::from_millis(300) {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "no send waited"
            );
            thread::sleep(Duration::from_millis(20));
        }
        // Hanging up ends the send that waits.
        writer.shutdown();
        sender.join().unwrap();
        assert_eq!(writer.busy_for(), Duration::ZERO);
        go.send(()).unwrap();
        responder.join().unwrap();
    }

    #[test]
    fn a_peer_that_speaks_something_else_fails_the_handshake() {
        let (client, mut server) = pipe();
        let peer = thread::spawn(move || {
            let _ = read_frame(&mut server);
            write_frame(&mut server, &[7; 96]).unwrap();
        });
        assert!(connect(client, &Identity::generate().unwrap()).is_err());
        peer.join().unwrap();

        let (client, server) = pipe();
        drop(server);
        assert!(connect(client, &Identity::generate().unwrap()).is_err());
    }
}
