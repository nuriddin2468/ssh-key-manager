//! What two paired devices share without ever having sent it: the
//! [`ContactKey`], and what chats make of it.
//!
//! Pairing proved each device's key to the other, and each vault keeps the
//! other's public key. The X25519 of one device's private key and the
//! other's public key is the same on both sides and known to nobody else;
//! HKDF over it, salted and labelled for this use alone, is the contact key.
//! Nothing is stored or exchanged, so it exists for every contact, paired by
//! any version, and is gone once either side removes the other.
//!
//! - **Presence.** While chats are open the app announces itself under a
//!   random name with a set of tags, one per contact
//!   ([`ContactKey::tag`]): an HMAC of the announcing device, the name and
//!   the ten-minute window. Only that contact can tell its tag from random
//!   bytes; the set is padded with random tags to 16, 32 or 64
//!   ([`presence_txt`]), so it doesn't tell how many contacts there are
//!   beyond that.
//! - **Knock.** Before the handshake, the side that answers sends a random
//!   challenge and the side that connects answers with an HMAC of it
//!   ([`knock`], [`answer_knock`]). Someone who isn't a contact gets the
//!   challenge and nothing else: not even the device key, which the Noise
//!   `XX` responder would otherwise send to anyone. The challenge and the
//!   knock go into the session's prologue ([`Knocked::prologue`]).

use std::fmt;
use std::io::{Read, Write};

use base64ct::{Base64Unpadded, Encoding};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use snow::params::DHChoice;
use snow::resolvers::{CryptoResolver, DefaultResolver};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{Identity, PeerKey};
use crate::{Error, Result};

const SALT: &[u8] = b"sshkm contact";
const PRESENCE_LABEL: &[u8] = b"sshkm chat presence";
const KNOCK_LABEL: &[u8] = b"sshkm chat knock";
/// What a chat session's prologue starts with: never a pairing session's.
const CHAT_PROLOGUE: &[u8] = b"sshkm-chat/1";
/// Bytes of a presence tag, of a challenge and of a knock.
pub const TAG_LEN: usize = 6;
pub const CHALLENGE_LEN: usize = 16;
pub const KNOCK_LEN: usize = 16;
/// Most tags one announcement carries.
pub const MAX_TAGS: usize = 64;
/// How many tags an announcement carries: the first of these that holds them all.
const BUCKETS: [usize; 3] = [16, 32, 64];
/// Base64 characters of one tag.
const TAG_CHARS: usize = 8;
/// Tags per TXT string: 248 characters, within the 255 one may have.
const TAGS_PER_STRING: usize = 31;

/// The key two paired devices share.
pub struct ContactKey(Zeroizing<[u8; 32]>);

impl Identity {
    /// The key this device shares with `peer`; the same on both sides.
    pub fn contact_key(&self, peer: &PeerKey) -> Result<ContactKey> {
        let mut dh = DefaultResolver
            .resolve_dh(&DHChoice::Curve25519)
            .ok_or_else(|| Error::Unsupported("X25519".into()))?;
        dh.set(self.private());
        let mut shared = Zeroizing::new([0; 32]);
        dh.dh(peer.as_bytes(), shared.as_mut())
            .map_err(|_| Error::invalid("not a device key"))?;
        // A key of low order gives zeros: it proves nothing.
        if bool::from(shared.ct_eq(&[0; 32])) {
            return Err(Error::invalid("not a device key"));
        }
        let me = self.public();
        let (first, second) = if me.as_bytes() <= peer.as_bytes() {
            (me, *peer)
        } else {
            (*peer, me)
        };
        let mut info = [0; 64];
        info[..32].copy_from_slice(first.as_bytes());
        info[32..].copy_from_slice(second.as_bytes());
        let mut key = Zeroizing::new([0; 32]);
        Hkdf::<Sha256>::new(Some(SALT), shared.as_ref())
            .expand(&info, key.as_mut())
            .unwrap_or_else(|_| unreachable!("32 bytes is a valid length"));
        Ok(ContactKey(key))
    }
}

impl ContactKey {
    /// The tag `announcer` puts in its announcement named `instance` during
    /// `window` for the other device of this key.
    pub fn tag(&self, announcer: &PeerKey, instance: &str, window: u64) -> [u8; TAG_LEN] {
        let mut mac = self.mac(PRESENCE_LABEL);
        mac.update(announcer.as_bytes());
        mac.update(
            &u64::try_from(instance.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        mac.update(instance.as_bytes());
        mac.update(&window.to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let mut tag = [0; TAG_LEN];
        tag.copy_from_slice(&digest[..TAG_LEN]);
        tag
    }

    /// The knock that answers `challenge` from `responder`.
    pub fn knock(&self, responder: &PeerKey, challenge: &[u8; CHALLENGE_LEN]) -> [u8; KNOCK_LEN] {
        let mut mac = self.mac(KNOCK_LABEL);
        mac.update(responder.as_bytes());
        mac.update(challenge);
        let digest = mac.finalize().into_bytes();
        let mut knock = [0; KNOCK_LEN];
        knock.copy_from_slice(&digest[..KNOCK_LEN]);
        knock
    }

    fn mac(&self, label: &[u8]) -> Hmac<Sha256> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.0.as_ref())
            .unwrap_or_else(|_| unreachable!("HMAC takes any key length"));
        mac.update(label);
        mac
    }
}

impl fmt::Debug for ContactKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ContactKey(…)")
    }
}

/// The TXT strings of `me`'s announcement named `instance` during `window`:
/// a tag for each of `contacts` (at most [`MAX_TAGS`], the first ones),
/// random tags up to 16, 32 or 64, shuffled, in base64.
pub fn presence_txt(
    me: &PeerKey,
    contacts: &[&ContactKey],
    instance: &str,
    window: u64,
) -> Vec<String> {
    let mut tags: Vec<[u8; TAG_LEN]> = contacts
        .iter()
        .take(MAX_TAGS)
        .map(|key| key.tag(me, instance, window))
        .collect();
    let size = BUCKETS
        .iter()
        .copied()
        .find(|bucket| *bucket >= tags.len())
        .unwrap_or(MAX_TAGS);
    while tags.len() < size {
        let mut tag = [0; TAG_LEN];
        OsRng.fill_bytes(&mut tag);
        tags.push(tag);
    }
    // Fisher–Yates, so that a contact's place says nothing.
    for i in (1..tags.len()).rev() {
        let j = usize::try_from(OsRng.next_u64() % (i as u64 + 1)).unwrap_or(0);
        tags.swap(i, j);
    }
    tags.chunks(TAGS_PER_STRING)
        .map(|chunk| {
            chunk
                .iter()
                .map(|tag| Base64Unpadded::encode_string(tag))
                .collect()
        })
        .collect()
}

/// The tags in an announcement's TXT strings, as [`presence_txt`] wrote
/// them; anything else in them is skipped.
pub fn parse_tags<'a>(strings: impl IntoIterator<Item = &'a str>) -> Vec<[u8; TAG_LEN]> {
    let mut tags = Vec::new();
    for text in strings {
        for chunk in text.as_bytes().chunks(TAG_CHARS) {
            let Ok(chunk) = std::str::from_utf8(chunk) else {
                continue;
            };
            let mut tag = [0; TAG_LEN];
            if Base64Unpadded::decode(chunk, &mut tag).is_ok_and(|decoded| decoded.len() == TAG_LEN)
            {
                tags.push(tag);
            }
            if tags.len() >= MAX_TAGS {
                return tags;
            }
        }
    }
    tags
}

/// Which of `contacts` announces itself as `instance` with these `tags`
/// around `window` (the one before and after too, for clocks a little
/// apart).
pub fn recognize(
    tags: &[[u8; TAG_LEN]],
    instance: &str,
    window: u64,
    contacts: &[(PeerKey, &ContactKey)],
) -> Option<PeerKey> {
    let windows = [window.saturating_sub(1), window, window.saturating_add(1)];
    contacts.iter().find_map(|(peer, key)| {
        windows
            .iter()
            .any(|w| {
                let expected = key.tag(peer, instance, *w);
                tags.iter().any(|tag| bool::from(tag.ct_eq(&expected)))
            })
            .then_some(*peer)
    })
}

/// A knock that went through: who knocked, and the session's prologue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Knocked {
    pub peer: PeerKey,
    challenge: [u8; CHALLENGE_LEN],
    knock: [u8; KNOCK_LEN],
}

impl Knocked {
    /// What the Noise handshake of the chat session that follows is bound
    /// to: `sshkm-chat/1`, the challenge and the knock.
    pub fn prologue(&self) -> Vec<u8> {
        prologue(&self.challenge, &self.knock)
    }
}

fn prologue(challenge: &[u8; CHALLENGE_LEN], knock: &[u8; KNOCK_LEN]) -> Vec<u8> {
    [CHAT_PROLOGUE, challenge, knock].concat()
}

/// Knocks at `responder`'s chat port as the other device of `key`: reads
/// its challenge and answers it. Returns the prologue of the session that
/// follows.
pub fn knock<S: Read + Write>(
    stream: &mut S,
    key: &ContactKey,
    responder: &PeerKey,
) -> Result<Vec<u8>> {
    let mut challenge = [0; CHALLENGE_LEN];
    stream.read_exact(&mut challenge).map_err(io_error)?;
    let knock = key.knock(responder, &challenge);
    stream.write_all(&knock).map_err(io_error)?;
    stream.flush().map_err(io_error)?;
    Ok(prologue(&challenge, &knock))
}

/// Answers a connection to this device's (`me`) chat port: sends a random
/// challenge and reads the knock. `None` when it is none of `contacts`'.
pub fn answer_knock<S: Read + Write>(
    stream: &mut S,
    me: &PeerKey,
    contacts: &[(PeerKey, &ContactKey)],
) -> Result<Option<Knocked>> {
    let mut challenge = [0; CHALLENGE_LEN];
    OsRng.fill_bytes(&mut challenge);
    stream.write_all(&challenge).map_err(io_error)?;
    stream.flush().map_err(io_error)?;
    let mut knock = [0; KNOCK_LEN];
    stream.read_exact(&mut knock).map_err(io_error)?;
    // Every contact is tried, so the time taken doesn't tell which matched.
    let mut found = None;
    for (peer, key) in contacts {
        if bool::from(key.knock(me, &challenge).ct_eq(&knock)) {
            found = Some(*peer);
        }
    }
    Ok(found.map(|peer| Knocked {
        peer,
        challenge,
        knock,
    }))
}

fn io_error(source: std::io::Error) -> Error {
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

    fn pipe() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn both_sides_derive_the_same_key_and_nobody_else_does() {
        let (alice, bob, eve) = (
            Identity::generate().unwrap(),
            Identity::generate().unwrap(),
            Identity::generate().unwrap(),
        );
        let ab = alice.contact_key(&bob.public()).unwrap();
        let ba = bob.contact_key(&alice.public()).unwrap();
        let ae = alice.contact_key(&eve.public()).unwrap();
        assert_eq!(*ab.0, *ba.0);
        assert_ne!(*ab.0, *ae.0);
        assert_eq!(format!("{ab:?}"), "ContactKey(…)");
        // A key of low order is refused.
        let zero = PeerKey::from_bytes(&[0; 32]).unwrap();
        assert!(alice.contact_key(&zero).is_err());
    }

    #[test]
    fn only_the_contact_recognises_the_announcement_around_its_window() {
        let (alice, bob, carol, eve) = (
            Identity::generate().unwrap(),
            Identity::generate().unwrap(),
            Identity::generate().unwrap(),
            Identity::generate().unwrap(),
        );
        let a = alice.public();
        let alice_bob = alice.contact_key(&bob.public()).unwrap();
        let alice_carol = alice.contact_key(&carol.public()).unwrap();
        let txt = presence_txt(&a, &[&alice_bob, &alice_carol], "0f3a9c2e81b47d65", 100);
        let tags = parse_tags(txt.iter().map(String::as_str));
        assert_eq!(tags.len(), 16, "padded to the first bucket");

        let bob_alice = bob.contact_key(&a).unwrap();
        let eve_alice = eve.contact_key(&a).unwrap();
        let instance = "0f3a9c2e81b47d65";
        for window in [99, 100, 101] {
            assert_eq!(
                recognize(&tags, instance, window, &[(a, &bob_alice)]),
                Some(a)
            );
        }
        assert_eq!(recognize(&tags, instance, 102, &[(a, &bob_alice)]), None);
        assert_eq!(recognize(&tags, "another", 100, &[(a, &bob_alice)]), None);
        assert_eq!(recognize(&tags, instance, 100, &[(a, &eve_alice)]), None);
        // The same contacts give other tags in another window.
        let later = parse_tags(
            presence_txt(&a, &[&alice_bob, &alice_carol], instance, 101)
                .iter()
                .map(String::as_str),
        );
        assert!(tags.iter().all(|tag| !later.contains(tag)));
    }

    #[test]
    fn the_tag_set_is_padded_to_a_bucket_and_capped() {
        let alice = Identity::generate().unwrap();
        let keys: Vec<ContactKey> = (0..70)
            .map(|_| {
                alice
                    .contact_key(&Identity::generate().unwrap().public())
                    .unwrap()
            })
            .collect();
        let count = |n: usize| {
            let refs: Vec<&ContactKey> = keys.iter().take(n).collect();
            let txt = presence_txt(&alice.public(), &refs, "name", 1);
            assert!(txt.iter().all(|text| text.len() <= 255));
            parse_tags(txt.iter().map(String::as_str)).len()
        };
        assert_eq!(count(0), 16);
        assert_eq!(count(16), 16);
        assert_eq!(count(17), 32);
        assert_eq!(count(33), 64);
        assert_eq!(count(70), 64);
        assert_eq!(parse_tags(["not base64 at all!", "AAAAAAAA"]).len(), 1);
    }

    #[test]
    fn a_contact_knocks_and_a_stranger_gets_nothing_but_the_challenge() {
        let (alice, bob, eve) = (
            Identity::generate().unwrap(),
            Identity::generate().unwrap(),
            Identity::generate().unwrap(),
        );
        let (a, b) = (alice.public(), bob.public());
        let alice_bob = alice.contact_key(&b).unwrap();

        let (mut client, mut server) = pipe();
        let responder = thread::spawn(move || {
            let bob_side = alice_bob;
            answer_knock(&mut server, &a, &[(b, &bob_side)]).unwrap()
        });
        let bob_alice = bob.contact_key(&a).unwrap();
        let prologue = knock(&mut client, &bob_alice, &a).unwrap();
        let knocked = responder.join().unwrap().unwrap();
        assert_eq!(knocked.peer, b);
        assert_eq!(knocked.prologue(), prologue);
        assert!(prologue.starts_with(b"sshkm-chat/1"));

        // Eve knows Alice's key but is no contact of hers.
        let alice_bob = alice.contact_key(&b).unwrap();
        let (mut client, mut server) = pipe();
        let responder =
            thread::spawn(move || answer_knock(&mut server, &a, &[(b, &alice_bob)]).unwrap());
        let eve_alice = eve.contact_key(&a).unwrap();
        knock(&mut client, &eve_alice, &a).unwrap();
        assert_eq!(responder.join().unwrap(), None);
    }

    #[test]
    fn a_replayed_knock_fails_on_a_new_challenge() {
        let (alice, bob) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let (a, b) = (alice.public(), bob.public());
        let bob_alice = bob.contact_key(&a).unwrap();
        let old = bob_alice.knock(&a, &[1; CHALLENGE_LEN]);
        let alice_bob = alice.contact_key(&b).unwrap();
        let (mut client, mut server) = pipe();
        let responder =
            thread::spawn(move || answer_knock(&mut server, &a, &[(b, &alice_bob)]).unwrap());
        let mut challenge = [0; CHALLENGE_LEN];
        client.read_exact(&mut challenge).unwrap();
        client.write_all(&old).unwrap();
        assert_eq!(responder.join().unwrap(), None);
    }
}
