//! The messages two apps send each other once the handshake is done.
//!
//! Each side first sends [`Message::Hello`]. If either does not know the
//! other yet, they agree on a pairing code (see [`Session::pairing_code`])
//! and each says whether its user saw the same one
//! ([`Message::Confirm`]); only when both did are they contacts.
//!
//! The side that connected may then send one [`Item`]: it offers it
//! ([`Message::Offer`], what it is and nothing secret), the other user
//! accepts or not ([`Message::Reply`]), and only after a yes does the item
//! itself go over ([`Message::Payload`]); the receiver says whether it saved
//! it ([`Message::Received`]). The payload must be what was offered.
//!
//! Versions that know about the user's own devices add [`Own`] to their
//! `Hello`; older ones ignore it. The rest of those conversations (adding a
//! device, moving the vault, a sync) only ever goes to a peer that sent it.
//!
//! [`Session::pairing_code`]: super::Session::pairing_code

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::sync::Manifest;
use crate::{Error, Result};

/// Version of the protocol; a peer that speaks another one is turned away.
pub const VERSION: u32 = 1;
/// Largest message, in bytes of JSON.
pub const MAX_MESSAGE: usize = 1024 * 1024;
/// Longest device name, in characters.
pub const MAX_NAME: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Message {
    /// The first message each way.
    Hello {
        version: u32,
        /// The sender's device name, for the other user to read.
        name: String,
        /// The sender already has the receiver as a contact.
        known: bool,
        /// What the sender says about the user's own devices; versions
        /// before them send nothing.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        own: Option<Own>,
    },
    /// The initiator's commitment to its pairing nonce: the SHA-256 of it,
    /// in base64.
    Commit { hash: String },
    /// The responder's pairing nonce, in base64.
    Nonce { nonce: String },
    /// The initiator's pairing nonce, which must match its commitment.
    Reveal { nonce: String },
    /// Whether the sender's user saw the same pairing code.
    Confirm { matched: bool },
    /// The connecting side offers an item.
    Offer { item: ItemSummary },
    /// The other user accepted the offer, or turned it down.
    Reply { accepted: bool },
    /// The item offered, after the other user accepted it.
    Payload { item: Item },
    /// Whether the receiver saved the item.
    Received { saved: bool },
    /// A large value follows as [`Message::Part`]s: `size` bytes with this
    /// SHA-256 (base64). Only between own devices.
    Bytes { size: u64, sha256: String },
    /// The next piece of a large value, in base64.
    Part { data: String },
    /// The vault secret, after the vault file it opens.
    Secret { key: SecretText },
    /// The sender recorded the receiver as one of the user's devices.
    Added,
    /// What the sender has to sync.
    Manifest { manifest: Manifest },
    /// What the initiator's user chose for each conflict, by item id: the
    /// initiator's version or the responder's stays.
    Decisions {
        initiator: Vec<String>,
        responder: Vec<String>,
    },
    /// What the sender has after a sync, as the SHA-256 of each item, and
    /// how many changes it put off for its own user to confirm.
    Applied {
        hashes: BTreeMap<String, String>,
        deferred: u32,
    },
}

/// What a side says about the user's own devices in its `Hello`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Own {
    /// What the side that connected came for; `None` from the side that
    /// answers, and for a plain pairing or sending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<Intent>,
    pub vault: VaultState,
}

/// Why the side that connected came.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Intent {
    /// To make the other computer one of the user's devices.
    AddDevice,
    /// To sync with one of the user's devices.
    Sync,
    /// Something a later version does: turned away.
    #[serde(other)]
    Other,
}

/// The sender's vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum VaultState {
    /// There is none on this computer: it may be given one.
    Missing,
    Locked,
    /// Unlocked. `proof` shows the peer which vault it is, if it has the
    /// same one, and tells it nothing otherwise ([`super::own::OwnKey`]).
    Open {
        proof: String,
    },
}

/// Text that stays out of logs: `Debug` hides it, and it is wiped when
/// dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretText(Zeroizing<String>);

impl SecretText {
    pub fn new(text: impl Into<String>) -> Self {
        Self(Zeroizing::new(text.into()))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretText(…)")
    }
}

impl Serialize for SecretText {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

/// Something one computer sends another.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Item {
    /// A login or a server's password from the vault.
    Password {
        title: String,
        username: String,
        password: String,
        url: String,
        notes: String,
        /// The 2FA secret (`otpauth://…`), if the sender chose to send it.
        otp: Option<String>,
        /// The ssh alias the password is for, when it is a server's.
        host: Option<String>,
    },
    /// How to reach a server: a `Host` block's alias and address, and the
    /// server's keys from the sender's `known_hosts`. Never a key file or
    /// an option that runs a program.
    Host {
        alias: String,
        host_name: Option<String>,
        user: Option<String>,
        port: Option<u16>,
        proxy_jump: Option<String>,
        host_keys: Vec<HostKey>,
    },
}

/// A server's public key, as `known_hosts` has it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostKey {
    /// E.g. `ssh-ed25519`.
    pub key_type: String,
    /// Standard base64.
    pub key: String,
}

/// What an [`Item`] is, without its secrets: what the receiver sees before
/// it accepts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum ItemSummary {
    #[serde(rename_all = "camelCase")]
    Password {
        title: String,
        username: String,
        url: String,
        /// A 2FA secret comes with it.
        otp: bool,
    },
    #[serde(rename_all = "camelCase")]
    Host {
        alias: String,
        /// `user@host:port`, as far as the block says.
        address: String,
        /// How many of the server's keys come with it.
        host_keys: u32,
    },
}

/// Most host keys one host may bring.
const MAX_HOST_KEYS: usize = 16;
/// Longest text field of an item, in bytes.
const MAX_FIELD: usize = 64 * 1024;

impl Item {
    pub fn summary(&self) -> ItemSummary {
        match self {
            Self::Password {
                title,
                username,
                url,
                otp,
                ..
            } => ItemSummary::Password {
                title: title.clone(),
                username: username.clone(),
                url: url.clone(),
                otp: otp.is_some(),
            },
            Self::Host {
                alias,
                host_name,
                user,
                port,
                host_keys,
                ..
            } => {
                let mut address = String::new();
                if let Some(user) = user {
                    address.push_str(user);
                    address.push('@');
                }
                address.push_str(host_name.as_deref().unwrap_or(alias));
                if let Some(port) = port.filter(|port| *port != 22) {
                    let _ = write!(address, ":{port}");
                }
                ItemSummary::Host {
                    alias: alias.clone(),
                    address,
                    host_keys: u32::try_from(host_keys.len()).unwrap_or(u32::MAX),
                }
            }
        }
    }

    /// Fails unless every field is something the receiver may save: no
    /// control characters, sizes in bounds, and a host's names made only of
    /// the characters a name has, so none of them can carry a command.
    pub fn check(&self) -> Result<()> {
        match self {
            Self::Password {
                title,
                username,
                password,
                url,
                notes,
                otp,
                host,
            } => {
                for value in [title, username, password, url, otp.as_deref().unwrap_or("")] {
                    text(value, false)?;
                }
                text(notes, true)?;
                if let Some(host) = host {
                    name(host, "._-")?;
                }
                if title.trim().is_empty() {
                    return Err(Error::invalid("an entry needs a title"));
                }
                Ok(())
            }
            Self::Host {
                alias,
                host_name,
                user,
                port,
                proxy_jump,
                host_keys,
            } => {
                name(alias, "._-")?;
                if let Some(host_name) = host_name {
                    name(host_name, ".-_:")?;
                }
                if let Some(user) = user {
                    name(user, "._-")?;
                }
                if let Some(proxy_jump) = proxy_jump {
                    name(proxy_jump, ".-_:@,")?;
                }
                if *port == Some(0) {
                    return Err(Error::invalid("port 0"));
                }
                if host_keys.len() > MAX_HOST_KEYS {
                    return Err(Error::invalid("too many host keys"));
                }
                for key in host_keys {
                    name(&key.key_type, ".-@")?;
                    if !key
                        .key
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
                        || key.key.is_empty()
                        || key.key.len() > MAX_FIELD
                    {
                        return Err(Error::invalid("a host key is not base64"));
                    }
                }
                Ok(())
            }
        }
    }
}

impl fmt::Debug for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Item({:?})", self.summary())
    }
}

fn text(value: &str, multiline: bool) -> Result<()> {
    if value.len() > MAX_FIELD {
        return Err(Error::invalid("a value is too long"));
    }
    if value
        .chars()
        .any(|c| c.is_control() && !(multiline && matches!(c, '\n' | '\r' | '\t')))
    {
        return Err(Error::invalid("a value has control characters"));
    }
    Ok(())
}

/// A non-empty name of ASCII letters, digits and `extra`, at most 255 bytes.
fn name(value: &str, extra: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 255
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
        || value.starts_with('-')
    {
        return Err(Error::invalid(format!("not a valid name: {value:?}")));
    }
    Ok(())
}

/// `name` as a device name: control characters dropped, whitespace
/// collapsed, at most [`MAX_NAME`] characters.
pub fn clean_name(name: &str) -> String {
    let words: Vec<&str> = name.split_whitespace().collect();
    words
        .join(" ")
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_are_tagged_json() {
        let hello = Message::Hello {
            version: VERSION,
            name: "MacBook".into(),
            known: false,
            own: None,
        };
        let json = serde_json::to_string(&hello).unwrap();
        assert_eq!(
            json,
            r#"{"type":"hello","version":1,"name":"MacBook","known":false}"#
        );
        assert_eq!(serde_json::from_str::<Message>(&json).unwrap(), hello);
        assert!(serde_json::from_str::<Message>(r#"{"type":"other"}"#).is_err());
    }

    /// The `Hello` of a version before own devices, as it parses here, and
    /// this version's as such a version reads it.
    #[derive(Deserialize)]
    #[serde(tag = "type", rename_all = "camelCase")]
    enum OldMessage {
        Hello {
            version: u32,
            name: String,
            known: bool,
        },
    }

    #[test]
    fn hellos_about_own_devices_get_along_with_older_versions() {
        let hello = Message::Hello {
            version: VERSION,
            name: "MacBook".into(),
            known: true,
            own: Some(Own {
                intent: Some(Intent::Sync),
                vault: VaultState::Open {
                    proof: "cHJvb2Y=".into(),
                },
            }),
        };
        let json = serde_json::to_string(&hello).unwrap();
        assert_eq!(
            json,
            r#"{"type":"hello","version":1,"name":"MacBook","known":true,"own":{"intent":"sync","vault":{"state":"open","proof":"cHJvb2Y="}}}"#
        );
        assert_eq!(serde_json::from_str::<Message>(&json).unwrap(), hello);
        let OldMessage::Hello {
            version,
            name,
            known,
        } = serde_json::from_str(&json).unwrap();
        assert_eq!((version, name.as_str(), known), (VERSION, "MacBook", true));

        let later = r#"{"type":"hello","version":1,"name":"x","known":false,"own":{"intent":"grant","vault":{"state":"missing"}}}"#;
        let Message::Hello { own: Some(own), .. } = serde_json::from_str(later).unwrap() else {
            panic!("not a hello with own")
        };
        assert_eq!(own.intent, Some(Intent::Other));
        assert_eq!(own.vault, VaultState::Missing);
    }

    #[test]
    fn a_secret_stays_out_of_debug() {
        let message = Message::Secret {
            key: SecretText::new("ABCD-EFGH"),
        };
        assert!(!format!("{message:?}").contains("ABCD"));
        let json = serde_json::to_string(&message).unwrap();
        assert_eq!(json, r#"{"type":"secret","key":"ABCD-EFGH"}"#);
        assert_eq!(serde_json::from_str::<Message>(&json).unwrap(), message);
    }

    fn password() -> Item {
        Item::Password {
            title: "prod DB".into(),
            username: "deploy".into(),
            password: "s3cret".into(),
            url: "https://db.example.com".into(),
            notes: "line one\nline two".into(),
            otp: None,
            host: None,
        }
    }

    fn host() -> Item {
        Item::Host {
            alias: "prod".into(),
            host_name: Some("10.0.4.12".into()),
            user: Some("deploy".into()),
            port: Some(2222),
            proxy_jump: Some("bastion".into()),
            host_keys: vec![HostKey {
                key_type: "ssh-ed25519".into(),
                key: "AAAAC3NzaC1lZDI1NTE5AAAAIBIZ".into(),
            }],
        }
    }

    #[test]
    fn summaries_hold_no_secrets() {
        let summary = password().summary();
        assert_eq!(
            summary,
            ItemSummary::Password {
                title: "prod DB".into(),
                username: "deploy".into(),
                url: "https://db.example.com".into(),
                otp: false,
            }
        );
        let json = serde_json::to_string(&Message::Offer { item: summary }).unwrap();
        assert!(!json.contains("s3cret"));
        assert!(!format!("{:?}", password()).contains("s3cret"));
        assert_eq!(
            host().summary(),
            ItemSummary::Host {
                alias: "prod".into(),
                address: "deploy@10.0.4.12:2222".into(),
                host_keys: 1,
            }
        );
    }

    #[test]
    fn checks_what_may_be_saved() {
        assert!(password().check().is_ok());
        assert!(host().check().is_ok());
        let Item::Host { .. } = host() else {
            unreachable!()
        };
        let with = |change: &dyn Fn(&mut Item)| {
            let mut item = host();
            change(&mut item);
            item.check().is_err()
        };
        let set = |field: &'static str, value: &'static str| {
            move |item: &mut Item| {
                if let Item::Host {
                    alias,
                    host_name,
                    user,
                    proxy_jump,
                    ..
                } = item
                {
                    let target = match field {
                        "alias" => alias,
                        "host_name" => host_name.get_or_insert_default(),
                        "user" => user.get_or_insert_default(),
                        _ => proxy_jump.get_or_insert_default(),
                    };
                    *target = value.into();
                }
            }
        };
        assert!(with(&set("alias", "prod; rm -rf ~")));
        assert!(with(&set("alias", "-oProxyCommand=x")));
        assert!(with(&set("host_name", "$(curl evil)")));
        assert!(with(&set("user", "a b")));
        assert!(with(&set("proxy_jump", "%h")));
        assert!(!with(&set("proxy_jump", "alice@bastion:2200,jump2")));
        assert!(with(&|item| {
            if let Item::Host { host_keys, .. } = item {
                host_keys[0].key = "not base64!".into();
            }
        }));

        let Item::Password { .. } = password() else {
            unreachable!()
        };
        let mut bad = password();
        if let Item::Password { title, .. } = &mut bad {
            *title = "a\u{0}b".into();
        }
        assert!(bad.check().is_err());
    }

    #[test]
    fn cleans_names() {
        assert_eq!(clean_name("  MacBook \t of\nAziz "), "MacBook of Aziz");
        assert_eq!(clean_name("a\u{7}b"), "ab");
        assert_eq!(clean_name(&"x".repeat(100)).chars().count(), MAX_NAME);
    }
}
