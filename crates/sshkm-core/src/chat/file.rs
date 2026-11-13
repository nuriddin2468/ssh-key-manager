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

use std::collections::BTreeMap;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::Conversation;
use crate::p2p::PeerKey;
use crate::{Error, Result};

const MAGIC: &[u8] = b"sshkm-chat\x01";
const NONCE_LEN: usize = 24;
const KEY_LABEL: &[u8] = b"sshkm chat file";
const NAME_LABEL: &[u8] = b"sshkm chat file name";
/// What the index's key is derived with: never a device key (32 bytes).
const INDEX_LABEL: &[u8] = b"sshkm chat index";
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
    seal_bytes(&cipher(chat_key, peer.as_bytes()), &aad(me, peer), &json)
}

/// The conversation a file holds; fails for another conversation's file,
/// another key or a changed byte.
pub fn open(
    chat_key: &[u8; 32],
    me: &PeerKey,
    peer: &PeerKey,
    bytes: &[u8],
) -> Result<Conversation> {
    let json = open_bytes(&cipher(chat_key, peer.as_bytes()), &aad(me, peer), bytes)?;
    serde_json::from_slice(&json).map_err(|e| Error::Parse(format!("chat file: {e}")))
}

/// The conversations this computer keeps, by the other device's key: its
/// name and whether it is one of the user's devices. Kept so that a
/// conversation is found again (and its values still go at their term)
/// after its contact was removed: a file's name says nothing of whose it is.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Index {
    #[serde(default)]
    pub peers: BTreeMap<String, IndexEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexEntry {
    pub name: String,
    #[serde(default)]
    pub own: bool,
}

/// The index's file name, without its extension; never a conversation's,
/// whose names are 32 hex digits.
pub const INDEX_STEM: &str = "index";

/// The index's file, sealed with its own key derived from the chat key.
pub fn seal_index(chat_key: &[u8; 32], me: &PeerKey, index: &Index) -> Result<Vec<u8>> {
    let json = Zeroizing::new(
        serde_json::to_vec(index).map_err(|e| Error::Parse(format!("chat index: {e}")))?,
    );
    seal_bytes(&cipher(chat_key, INDEX_LABEL), &index_aad(me), &json)
}

/// The index a file holds; fails for a conversation's file or another key.
pub fn open_index(chat_key: &[u8; 32], me: &PeerKey, bytes: &[u8]) -> Result<Index> {
    let json = open_bytes(&cipher(chat_key, INDEX_LABEL), &index_aad(me), bytes)?;
    serde_json::from_slice(&json).map_err(|e| Error::Parse(format!("chat index: {e}")))
}

fn seal_bytes(cipher: &XChaCha20Poly1305, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let sealed = cipher
        .encrypt(&XNonce::from(nonce), Payload { msg: plain, aad })
        .map_err(|_| Error::invalid("encryption failed"))?;
    Ok([MAGIC, &nonce, &sealed].concat())
}

fn open_bytes(cipher: &XChaCha20Poly1305, aad: &[u8], bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
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
    cipher
        .decrypt(&XNonce::from(nonce), Payload { msg: sealed, aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::Parse("the chat file doesn't open with this key".into()))
}

/// The cipher of one file: its key derived from the chat key and `info`
/// (the other device's key, or the index's label).
fn cipher(chat_key: &[u8; 32], info: &[u8]) -> XChaCha20Poly1305 {
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(KEY_LABEL), chat_key)
        .expand(info, key.as_mut())
        .unwrap_or_else(|_| unreachable!("32 bytes is a valid length"));
    XChaCha20Poly1305::new((&*key).into())
}

fn index_aad(me: &PeerKey) -> Vec<u8> {
    [MAGIC, me.as_bytes(), INDEX_LABEL].concat()
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
    fn the_index_opens_only_as_the_index() {
        let key = [3; 32];
        let (me, peer) = (
            Identity::generate().unwrap().public(),
            Identity::generate().unwrap().public(),
        );
        let mut index = Index::default();
        index.peers.insert(
            peer.to_string(),
            IndexEntry {
                name: "ThinkPad Bob".into(),
                own: false,
            },
        );
        let bytes = seal_index(&key, &me, &index).unwrap();
        assert!(!bytes.windows(8).any(|window| window == b"ThinkPad"));
        assert_eq!(open_index(&key, &me, &bytes).unwrap(), index);
        assert!(open_index(&[4; 32], &me, &bytes).is_err(), "another key");
        assert!(
            open(&key, &me, &peer, &bytes).is_err(),
            "not a conversation"
        );
        let mut chat = conversation();
        let file = seal(&key, &me, &peer, &mut chat).unwrap();
        assert!(
            open_index(&key, &me, &file).is_err(),
            "a conversation isn't the index"
        );
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
