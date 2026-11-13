//! A conversation's file: `sshkm-chat` and a version, a random 24-byte
//! nonce, and the conversation's JSON sealed with XChaCha20-Poly1305.
//!
//! The key is derived (HKDF) from the computer's chat key, which only the
//! unlocked vault holds ([`Vault::chat_key`]), and from the other device's
//! key, so each conversation has its own. Both devices' keys are the
//! associated data: a file can't pass for another conversation's. The
//! file's name is an HMAC of the other device's key: it doesn't tell whose
//! conversation it is.
//!
//! [`Vault::chat_key`]: crate::vault::Vault::chat_key

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::Conversation;
use crate::p2p::PeerKey;
use crate::{Error, Result};

const MAGIC: &[u8] = b"sshkm-chat\x01";
const NONCE_LEN: usize = 24;
const KEY_LABEL: &[u8] = b"sshkm chat file";
const NAME_LABEL: &[u8] = b"sshkm chat file name";
/// The extension of a conversation's file.
pub const EXTENSION: &str = "chat";

/// The name of the file of the conversation with `peer`, without its
/// extension: 32 hex digits.
pub fn file_stem(chat_key: &[u8; 32], peer: &PeerKey) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(chat_key)
        .unwrap_or_else(|_| unreachable!("HMAC takes any key length"));
    mac.update(NAME_LABEL);
    mac.update(peer.as_bytes());
    let digest = mac.finalize().into_bytes();
    digest[..16]
        .iter()
        .fold(String::with_capacity(32), |mut hex, b| {
            use std::fmt::Write as _;
            let _ = write!(hex, "{b:02x}");
            hex
        })
}

/// The file of `me`'s conversation with `peer`. Leaves out the oldest
/// entries if it is too large ([`Conversation::to_json`]).
pub fn seal(
    chat_key: &[u8; 32],
    me: &PeerKey,
    peer: &PeerKey,
    conversation: &mut Conversation,
) -> Result<Vec<u8>> {
    let json = conversation.to_json()?;
    let mut nonce = [0; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let sealed = cipher(chat_key, peer)
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &json,
                aad: &aad(me, peer),
            },
        )
        .map_err(|_| Error::invalid("encryption failed"))?;
    Ok([MAGIC, &nonce, &sealed].concat())
}

/// The conversation a file holds; fails for another conversation's file,
/// another key or a changed byte.
pub fn open(
    chat_key: &[u8; 32],
    me: &PeerKey,
    peer: &PeerKey,
    bytes: &[u8],
) -> Result<Conversation> {
    let rest = bytes
        .strip_prefix(MAGIC)
        .ok_or_else(|| Error::Parse("not a chat file of this version".into()))?;
    if rest.len() < NONCE_LEN {
        return Err(Error::Parse("a chat file cut short".into()));
    }
    let (nonce, sealed) = rest.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| Error::Parse("a chat file cut short".into()))?;
    let json = Zeroizing::new(
        cipher(chat_key, peer)
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: sealed,
                    aad: &aad(me, peer),
                },
            )
            .map_err(|_| Error::Parse("the chat file doesn't open with this key".into()))?,
    );
    serde_json::from_slice(&json).map_err(|e| Error::Parse(format!("chat file: {e}")))
}

fn cipher(chat_key: &[u8; 32], peer: &PeerKey) -> XChaCha20Poly1305 {
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(KEY_LABEL), chat_key)
        .expand(peer.as_bytes(), key.as_mut())
        .unwrap_or_else(|_| unreachable!("32 bytes is a valid length"));
    XChaCha20Poly1305::new((&*key).into())
}

fn aad(me: &PeerKey, peer: &PeerKey) -> Vec<u8> {
    [MAGIC, me.as_bytes(), peer.as_bytes()].concat()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::{Body, Delivery, Entry};
    use crate::p2p::Identity;

    fn conversation() -> Conversation {
        let mut chat = Conversation::default();
        chat.receive(Entry {
            id: crate::p2p::chat::new_id(),
            mine: false,
            at: 5,
            body: Body::Text {
                text: "the plan is in the wiki".into(),
            },
            delivery: Delivery::Received,
        });
        chat
    }

    #[test]
    fn a_file_opens_only_as_its_own_conversation_with_its_key() {
        let key = [7; 32];
        let (me, peer, other) = (
            Identity::generate().unwrap().public(),
            Identity::generate().unwrap().public(),
            Identity::generate().unwrap().public(),
        );
        let mut chat = conversation();
        let bytes = seal(&key, &me, &peer, &mut chat).unwrap();
        assert!(
            !bytes
                .windows(4)
                .any(|window| window == b"plan" || window == b"wiki")
        );
        let opened = open(&key, &me, &peer, &bytes).unwrap();
        assert_eq!(opened.entries(), chat.entries());

        assert!(open(&[8; 32], &me, &peer, &bytes).is_err(), "another key");
        assert!(
            open(&key, &me, &other, &bytes).is_err(),
            "another conversation"
        );
        assert!(
            open(&key, &other, &peer, &bytes).is_err(),
            "another computer"
        );
        let mut changed = bytes.clone();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert!(open(&key, &me, &peer, &changed).is_err(), "a changed byte");
        assert!(open(&key, &me, &peer, &bytes[..20]).is_err(), "cut short");
        assert!(open(&key, &me, &peer, b"{}").is_err(), "not sealed");
        // A fresh nonce each time.
        assert_ne!(seal(&key, &me, &peer, &mut chat).unwrap(), bytes);
    }

    #[test]
    fn file_names_say_nothing_about_the_peer() {
        let peer = Identity::generate().unwrap().public();
        let stem = file_stem(&[1; 32], &peer);
        assert_eq!(stem.len(), 32);
        assert!(stem.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(stem, file_stem(&[2; 32], &peer));
        assert!(!stem.contains(&peer.to_string()));
    }
}
