//! A session between two apps: a Noise `XX` handshake, then messages.
//!
//! - **Handshake.** `Noise_XX_25519_ChaChaPoly_SHA256`: each side proves it
//!   holds its device key, and everything after is encrypted. Each Noise
//!   message travels as a big-endian `u16` length and its bytes.
//! - **Messages.** A [`Message`] is JSON, at most [`MAX_MESSAGE`] bytes,
//!   sent as its length (`u32`, big-endian) and the JSON, split over as
//!   many Noise messages as it takes.
//! - **Pairing code.** Six digits both users compare, from the handshake
//!   hash and a nonce from each side. The initiator commits to its nonce
//!   before it sees the responder's, and the responder sends its own before
//!   it sees the initiator's: someone in the middle runs a session with each
//!   side, but must fix one side's nonce before learning what the other's
//!   code will be, so the two codes agree by chance only, one time in a
//!   million. (Taken from the handshake hash alone, the code could be
//!   matched by trying a million keys.)

use std::io::{self, Read, Write};

use base64ct::{Base64, Encoding};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::identity::{Identity, PeerKey, params};
use super::protocol::{MAX_MESSAGE, Message};
use crate::{Error, Result};

pub(crate) const PARAMS: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
/// Bound into the handshake: a peer speaking anything else fails it.
const PROLOGUE: &[u8] = b"sshkm-p2p/1";
const CODE_LABEL: &[u8] = b"sshkm-p2p pairing code";
/// Largest Noise message, and the tag each one carries.
const NOISE_MAX: usize = 65_535;
const TAG: usize = 16;
const NONCE_LEN: usize = 32;

/// An open session over `S`, after the handshake.
pub struct Session<S> {
    stream: S,
    noise: snow::TransportState,
    remote: PeerKey,
    hash: Vec<u8>,
    initiator: bool,
}

/// Opens a session as the side that connected.
pub fn connect<S: Read + Write>(mut stream: S, identity: &Identity) -> Result<Session<S>> {
    let mut handshake = builder(identity).build_initiator().map_err(noise_error)?;
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

/// Opens a session as the side that was connected to.
pub fn accept<S: Read + Write>(mut stream: S, identity: &Identity) -> Result<Session<S>> {
    let mut handshake = builder(identity).build_responder().map_err(noise_error)?;
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

fn builder(identity: &Identity) -> snow::Builder<'_> {
    snow::Builder::new(params())
        .prologue(PROLOGUE)
        .and_then(|builder| builder.local_private_key(identity.private()))
        .unwrap_or_else(|_| unreachable!("a 32-byte key and a prologue are accepted"))
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
    })
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

    pub fn send(&mut self, message: &Message) -> Result<()> {
        // The buffers may hold a password: they are wiped when dropped.
        let json = Zeroizing::new(
            serde_json::to_vec(message).map_err(|e| Error::Parse(format!("message: {e}")))?,
        );
        if json.len() > MAX_MESSAGE {
            return Err(Error::invalid("the message is too large"));
        }
        let mut plain = Zeroizing::new(Vec::with_capacity(4 + json.len()));
        plain.extend_from_slice(&u32::try_from(json.len()).unwrap_or(u32::MAX).to_be_bytes());
        plain.extend_from_slice(&json);
        let mut out = Zeroizing::new(vec![0; NOISE_MAX]);
        for chunk in plain.chunks(NOISE_MAX - TAG) {
            let n = self
                .noise
                .write_message(chunk, &mut out)
                .map_err(noise_error)?;
            write_frame(&mut self.stream, &out[..n])?;
        }
        self.stream.flush().map_err(io_error)
    }

    pub fn recv(&mut self) -> Result<Message> {
        let mut plain = Zeroizing::new(Vec::new());
        let mut out = Zeroizing::new(vec![0; NOISE_MAX]);
        let mut take = |session: &mut Self, plain: &mut Vec<u8>| -> Result<()> {
            let frame = read_frame(&mut session.stream)?;
            let n = session
                .noise
                .read_message(&frame, &mut out)
                .map_err(noise_error)?;
            plain.extend_from_slice(&out[..n]);
            Ok(())
        };
        take(self, &mut plain)?;
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
            take(self, &mut plain)?;
        }
        if plain.len() != 4 + len {
            return Err(Error::Parse("a message longer than its length".into()));
        }
        serde_json::from_slice(&plain[4..]).map_err(|e| Error::Parse(format!("message: {e}")))
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

fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>> {
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
        }
    }

    #[test]
    fn parameters_parse() {
        assert!(PARAMS.parse::<snow::params::NoiseParams>().is_ok());
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
