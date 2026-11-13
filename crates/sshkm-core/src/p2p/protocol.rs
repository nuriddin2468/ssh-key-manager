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
//! Everything newer is named in the `Hello`'s `features` ([`FEATURES`]):
//! a message, a chat frame or an item that needs a feature only goes to a
//! peer that named it, and [`VERSION`] stays 1. A message, item or summary
//! of a kind this version doesn't know parses as `Unknown`, so that the
//! conversation can end with "the other app needs the new version" instead
//! of breaking.
//!
//! [`Session::pairing_code`]: super::Session::pairing_code

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
use std::net::IpAddr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssh_key::{HashAlg, PublicKey};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

use super::chat::ChatFrame;
use crate::hosts_file::{is_system_name, is_valid_name};
use crate::keys::validate_file_name;
use crate::sync::Manifest;
use crate::{Error, Result};

/// Version of the protocol; a peer that speaks another one is turned away.
pub const VERSION: u32 = 1;
/// Largest message, in bytes of JSON.
pub const MAX_MESSAGE: usize = 1024 * 1024;
/// Longest device name, in characters.
pub const MAX_NAME: usize = 64;

/// Chats ([`super::chat`]).
pub const CHAT: &str = "chat/1";
/// An environment in Personal without a part, whose empty project label
/// older versions refuse.
pub const PERSONAL_ENV: &str = "personal-env/1";
/// What this version can do beyond version 1, as its `Hello` says.
pub const FEATURES: &[&str] = &[CHAT, PERSONAL_ENV];

/// [`FEATURES`], as a `Hello` carries them.
pub fn features() -> Vec<String> {
    FEATURES
        .iter()
        .map(|feature| (*feature).to_owned())
        .collect()
}

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
        /// What the sender can do beyond version 1 ([`FEATURES`]); versions
        /// before features send nothing.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        features: Vec<String>,
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
    /// The other user accepted the offer, or turned it down; with
    /// `unsupported`, this version can't take what was offered. Versions
    /// before it send no `unsupported` and read a plain no.
    Reply {
        accepted: bool,
        #[serde(default, skip_serializing_if = "is_false")]
        unsupported: bool,
    },
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
    /// A frame of a chat session; only to a peer whose `Hello` named
    /// [`CHAT`].
    Chat { frame: ChatFrame },
    /// A message of a kind a later version sends: never sent.
    #[serde(other)]
    Unknown,
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde passes a reference"
)]
fn is_false(value: &bool) -> bool {
    !*value
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
    /// same one, and tells it nothing otherwise ([`super::own::OwnKey`]);
    /// empty while the vault has no key for own devices yet.
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
    /// A group of the sender's hosts file: its name and its entries. The
    /// receiver writes it only after its user reviewed the change and gave
    /// the administrator password.
    HostsGroup {
        name: String,
        entries: Vec<HostsEntry>,
    },
    /// The sender's public key as one OpenSSH line, and the name of its file
    /// there (without `.pub`).
    PublicKey { name: String, key: String },
    /// A secret environment from the vault, with its variables' values. The
    /// receiver adds it as a new environment.
    Environment {
        project: String,
        name: String,
        notes: String,
        variables: Vec<EnvVariable>,
    },
    /// An item of a kind a later version sends: never saved.
    #[serde(other)]
    Unknown,
}

/// One variable of an [`Item::Environment`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvVariable {
    pub name: String,
    pub value: String,
    pub secret: bool,
    pub note: String,
}

/// One entry of a hosts file group. A comment does not go over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostsEntry {
    /// An IPv4 or IPv6 address, without a scope.
    pub address: String,
    pub names: Vec<String>,
    /// False: the entry is there, commented out.
    pub enabled: bool,
    /// When a temporary entry expires (RFC 3339).
    pub expires: Option<String>,
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
        /// The jump hosts the connection goes through (`ProxyJump`), if
        /// any. Versions before it leave it out: then a host with one
        /// doesn't match its summary and is refused.
        #[serde(default)]
        proxy_jump: Option<String>,
        /// How many of the server's keys come with it.
        host_keys: u32,
    },
    #[serde(rename_all = "camelCase")]
    HostsGroup {
        name: String,
        /// How many entries it has.
        entries: u32,
        /// The first names of its first few entries, each once.
        names: Vec<String>,
    },
    #[serde(rename_all = "camelCase")]
    PublicKey {
        /// The key's file name on the sender's computer.
        name: String,
        /// E.g. `ssh-ed25519`; empty if the key can't be read.
        key_type: String,
        /// `SHA256:…`, as `ssh-keygen -l` prints it.
        fingerprint: String,
        comment: String,
    },
    #[serde(rename_all = "camelCase")]
    Environment {
        project: String,
        name: String,
        /// How many variables it has, and how many of them are secret.
        variables: u32,
        secrets: u32,
        /// The first few variables' names.
        names: Vec<String>,
    },
    /// An item of a kind a later version sends.
    #[serde(other)]
    Unknown,
}

impl ItemSummary {
    /// The feature ([`FEATURES`]) a peer needs to take the item, if any.
    pub fn requires(&self) -> Option<&'static str> {
        match self {
            Self::Environment { project, .. } if project.is_empty() => Some(PERSONAL_ENV),
            _ => None,
        }
    }
}

/// Most host keys one host may bring.
const MAX_HOST_KEYS: usize = 16;
/// Longest text field of an item, in bytes.
const MAX_FIELD: usize = 64 * 1024;
/// Most entries one hosts file group may bring.
pub const MAX_GROUP_ENTRIES: usize = 1000;
/// Most names one hosts file entry may list.
const MAX_ENTRY_NAMES: usize = 64;
/// Most bytes of addresses and names one group may bring.
const MAX_GROUP_BYTES: usize = 256 * 1024;
/// Longest group name, in characters (as the hosts file allows).
const MAX_GROUP_NAME: usize = 64;
/// How many entries a group's summary names.
const SUMMARY_NAMES: usize = 3;
/// Most bytes of names, values and notes one environment may bring, so its
/// message stays under [`MAX_MESSAGE`] even with every character escaped.
pub(crate) const MAX_ENVIRONMENT_BYTES: usize = 384 * 1024;

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
                proxy_jump,
                host_keys,
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
                    proxy_jump: proxy_jump.clone(),
                    host_keys: count(host_keys.len()),
                }
            }
            Self::HostsGroup { name, entries } => {
                let mut names: Vec<String> = Vec::new();
                for first in entries.iter().filter_map(|entry| entry.names.first()) {
                    if names.len() == SUMMARY_NAMES {
                        break;
                    }
                    if !names.contains(first) {
                        names.push(first.clone());
                    }
                }
                ItemSummary::HostsGroup {
                    name: name.clone(),
                    entries: count(entries.len()),
                    names,
                }
            }
            Self::PublicKey { name, key } => {
                let parsed = PublicKey::from_openssh(key).ok();
                ItemSummary::PublicKey {
                    name: name.clone(),
                    key_type: parsed
                        .as_ref()
                        .map(|key| key.algorithm().as_str().to_owned())
                        .unwrap_or_default(),
                    fingerprint: parsed
                        .as_ref()
                        .map(|key| key.fingerprint(HashAlg::Sha256).to_string())
                        .unwrap_or_default(),
                    comment: parsed
                        .as_ref()
                        .map(|key| key.comment().to_owned())
                        .unwrap_or_default(),
                }
            }
            Self::Environment {
                project,
                name,
                variables,
                ..
            } => ItemSummary::Environment {
                project: project.clone(),
                name: name.clone(),
                variables: count(variables.len()),
                secrets: count(variables.iter().filter(|var| var.secret).count()),
                names: variables
                    .iter()
                    .take(SUMMARY_NAMES)
                    .map(|var| var.name.clone())
                    .collect(),
            },
            Self::Unknown => ItemSummary::Unknown,
        }
    }

    /// The feature ([`FEATURES`]) a peer needs to take the item, if any:
    /// it is never offered to a peer that didn't name it.
    pub fn requires(&self) -> Option<&'static str> {
        self.summary().requires()
    }

    /// Fails unless every field is something the receiver may save: no
    /// control characters, sizes in bounds, and a host's names made only of
    /// the characters a name has, so none of them can carry a command. A
    /// hosts file group needs IP addresses and host names (none the system
    /// relies on, like `localhost`); a public key must be one, and its file
    /// name one a key may have.
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
            Self::HostsGroup { name, entries } => check_group(name, entries),
            Self::PublicKey { name, key } => check_public_key(name, key),
            Self::Environment {
                project,
                name,
                notes,
                variables,
            } => check_environment(project, name, notes, variables),
            Self::Unknown => Err(Error::Unsupported(
                "an item of a kind this version doesn't know".into(),
            )),
        }
    }
}

/// See [`Item::check`]: names a project, an environment and a variable may
/// have, values without control characters other than line breaks and tabs,
/// and a size that fits one message. The project label is empty for an
/// environment in Personal without a part.
fn check_environment(
    project: &str,
    name: &str,
    notes: &str,
    variables: &[EnvVariable],
) -> Result<()> {
    for (label, may_be_empty) in [(project, true), (name, false)] {
        let blank = if may_be_empty && label.is_empty() {
            false
        } else {
            label.trim().is_empty()
        };
        if blank || label.chars().count() > MAX_NAME || label.contains('/') {
            return Err(Error::invalid(format!("not a name: {label:?}")));
        }
        text(label, false)?;
    }
    text(notes, true)?;
    if variables.len() > crate::vault::envs::MAX_VARIABLES {
        return Err(Error::invalid("too many variables"));
    }
    let mut bytes = project.len() + name.len() + notes.len();
    for (index, var) in variables.iter().enumerate() {
        if !crate::vault::envs::is_valid_name(&var.name) {
            return Err(Error::invalid(format!(
                "not a variable name: {:?}",
                var.name
            )));
        }
        if variables[..index]
            .iter()
            .any(|other| other.name == var.name)
        {
            return Err(Error::invalid(format!("{} comes twice", var.name)));
        }
        text(&var.value, true)?;
        text(&var.note, false)?;
        bytes += var.name.len() + var.value.len() + var.note.len();
    }
    if bytes > MAX_ENVIRONMENT_BYTES {
        return Err(Error::invalid("the environment is too large"));
    }
    Ok(())
}

/// See [`Item::check`].
fn check_group(name: &str, entries: &[HostsEntry]) -> Result<()> {
    if name.trim() != name
        || name.is_empty()
        || name.chars().count() > MAX_GROUP_NAME
        || name.chars().any(char::is_control)
    {
        return Err(Error::invalid(format!("not a group name: {name:?}")));
    }
    if entries.is_empty() || entries.len() > MAX_GROUP_ENTRIES {
        return Err(Error::invalid(format!(
            "a group brings 1 to {MAX_GROUP_ENTRIES} entries"
        )));
    }
    let mut bytes = 0;
    for entry in entries {
        // No scope (`%en0`): it names an interface of the sender's.
        if entry.address.parse::<IpAddr>().is_err() {
            return Err(Error::invalid(format!(
                "not an IP address: {:?}",
                entry.address
            )));
        }
        if entry.names.is_empty() || entry.names.len() > MAX_ENTRY_NAMES {
            return Err(Error::invalid("an entry needs 1 to 64 names"));
        }
        if let Some(bad) = entry
            .names
            .iter()
            .find(|name| !is_valid_name(name) || is_system_name(name))
        {
            return Err(Error::invalid(format!("not a name it may set: {bad:?}")));
        }
        if let Some(expires) = &entry.expires
            && OffsetDateTime::parse(expires, &Rfc3339).is_err()
        {
            return Err(Error::invalid(format!("not a time: {expires:?}")));
        }
        bytes += entry.address.len() + entry.names.iter().map(String::len).sum::<usize>();
    }
    if bytes > MAX_GROUP_BYTES {
        return Err(Error::invalid("the group is too large"));
    }
    Ok(())
}

/// See [`Item::check`].
fn check_public_key(name: &str, key: &str) -> Result<()> {
    validate_file_name(name)?;
    text(key, false)?;
    let key_type = key.split_ascii_whitespace().next().unwrap_or_default();
    if key_type.ends_with("-cert-v01@openssh.com") {
        return Err(Error::invalid("a certificate, not a key"));
    }
    PublicKey::from_openssh(key).map_err(|_| Error::invalid("not an OpenSSH public key"))?;
    Ok(())
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

impl fmt::Debug for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Item({:?})", self.summary())
    }
}

/// Fails if `value` is longer than a field may be or has control characters
/// (but line breaks and tabs, with `multiline`).
pub(crate) fn text(value: &str, multiline: bool) -> Result<()> {
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
            features: Vec::new(),
        };
        let json = serde_json::to_string(&hello).unwrap();
        assert_eq!(
            json,
            r#"{"type":"hello","version":1,"name":"MacBook","known":false}"#
        );
        assert_eq!(serde_json::from_str::<Message>(&json).unwrap(), hello);
        assert_eq!(
            serde_json::from_str::<Message>(r#"{"type":"other"}"#).unwrap(),
            Message::Unknown
        );
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
            features: Vec::new(),
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
    fn features_get_along_with_older_versions() {
        let hello = Message::Hello {
            version: VERSION,
            name: "MacBook".into(),
            known: true,
            own: None,
            features: features(),
        };
        let json = serde_json::to_string(&hello).unwrap();
        assert_eq!(
            json,
            r#"{"type":"hello","version":1,"name":"MacBook","known":true,"features":["chat/1","personal-env/1"]}"#
        );
        assert_eq!(serde_json::from_str::<Message>(&json).unwrap(), hello);
        // An older version reads it as it always did, and its Hello has none.
        let OldMessage::Hello { known, .. } = serde_json::from_str(&json).unwrap();
        assert!(known);
        let older = r#"{"type":"hello","version":1,"name":"x","known":false}"#;
        let Message::Hello { features, .. } = serde_json::from_str(older).unwrap() else {
            panic!("not a hello")
        };
        assert_eq!(features, Vec::<String>::new());
        // A plain no, as older versions send and read it.
        let no = Message::Reply {
            accepted: false,
            unsupported: false,
        };
        assert_eq!(
            serde_json::to_string(&no).unwrap(),
            r#"{"type":"reply","accepted":false}"#
        );
        let unsupported: Message =
            serde_json::from_str(r#"{"type":"reply","accepted":false,"unsupported":true}"#)
                .unwrap();
        assert_eq!(
            unsupported,
            Message::Reply {
                accepted: false,
                unsupported: true
            }
        );
    }

    #[test]
    fn kinds_of_later_versions_parse_as_unknown() {
        assert_eq!(
            serde_json::from_str::<Message>(r#"{"type":"teleport","to":"mars"}"#).unwrap(),
            Message::Unknown
        );
        let offer: Message = serde_json::from_str(
            r#"{"type":"offer","item":{"type":"project","name":"shop","hosts":3}}"#,
        )
        .unwrap();
        assert_eq!(
            offer,
            Message::Offer {
                item: ItemSummary::Unknown
            }
        );
        let payload: Message =
            serde_json::from_str(r#"{"type":"payload","item":{"type":"project","name":"shop"}}"#)
                .unwrap();
        let Message::Payload { item } = payload else {
            panic!("not a payload")
        };
        assert_eq!(item, Item::Unknown);
        assert!(item.check().is_err());
        assert_eq!(item.summary(), ItemSummary::Unknown);
        // Known kinds still fail when they are broken.
        assert!(serde_json::from_str::<Message>(r#"{"type":"offer"}"#).is_err());
    }

    #[test]
    fn an_environment_in_personal_without_a_part_needs_a_feature() {
        let mut item = environment();
        assert_eq!(item.requires(), None);
        if let Item::Environment { project, .. } = &mut item {
            project.clear();
        }
        assert!(item.check().is_ok(), "an empty project label is Personal");
        assert_eq!(item.requires(), Some(PERSONAL_ENV));
        assert_eq!(item.summary().requires(), Some(PERSONAL_ENV));
        assert!(FEATURES.contains(&PERSONAL_ENV));
        if let Item::Environment { project, .. } = &mut item {
            *project = "  ".into();
        }
        assert!(
            item.check().is_err(),
            "a project label of spaces is not one"
        );
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
                proxy_jump: Some("bastion".into()),
                host_keys: 1,
            }
        );
        // An older version's summary, without the jump host, is not this
        // host's.
        let older: ItemSummary = serde_json::from_str(
            r#"{"type":"host","alias":"prod","address":"deploy@10.0.4.12:2222","hostKeys":1}"#,
        )
        .unwrap();
        assert_ne!(older, host().summary());
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

    fn group() -> Item {
        Item::HostsGroup {
            name: "dev stack".into(),
            entries: vec![
                HostsEntry {
                    address: "10.0.4.12".into(),
                    names: vec!["api.dev.local".into(), "api".into()],
                    enabled: true,
                    expires: None,
                },
                HostsEntry {
                    address: "fd00::7".into(),
                    names: vec!["db.dev.local".into()],
                    enabled: false,
                    expires: Some("2026-11-05T09:00:00Z".into()),
                },
            ],
        }
    }

    const PUBLIC: &str = include_str!("../keys/testdata/openssh_ed25519.pub");

    fn public_key() -> Item {
        Item::PublicKey {
            name: "id_ed25519".into(),
            key: PUBLIC.trim().into(),
        }
    }

    #[test]
    fn summarises_groups_and_keys() {
        assert_eq!(
            group().summary(),
            ItemSummary::HostsGroup {
                name: "dev stack".into(),
                entries: 2,
                names: vec!["api.dev.local".into(), "db.dev.local".into()],
            }
        );
        assert_eq!(
            public_key().summary(),
            ItemSummary::PublicKey {
                name: "id_ed25519".into(),
                key_type: "ssh-ed25519".into(),
                fingerprint: "SHA256:76vvbGumhP/HpDH4tlyySHWs5hgRZJHr2wQ7hSDwRK8".into(),
                comment: "plain@test".into(),
            }
        );
    }

    #[test]
    fn a_groups_summary_names_each_name_once() {
        let mut item = group();
        if let Item::HostsGroup { entries, .. } = &mut item {
            let first = entries[0].clone();
            entries.insert(1, first.clone());
            entries.push(first);
        }
        let ItemSummary::HostsGroup { entries, names, .. } = item.summary() else {
            unreachable!()
        };
        assert_eq!(entries, 4);
        assert_eq!(names, ["api.dev.local", "db.dev.local"]);
    }

    #[test]
    fn checks_groups() {
        assert!(group().check().is_ok());
        let with = |change: &dyn Fn(&mut String, &mut Vec<HostsEntry>)| {
            let mut item = group();
            if let Item::HostsGroup { name, entries } = &mut item {
                change(name, entries);
            }
            item.check().is_err()
        };
        assert!(with(&|name, _| *name = "a\nb".into()));
        assert!(with(&|name, _| *name = " padded".into()));
        assert!(with(&|name, _| *name = "x".repeat(65)));
        assert!(with(&|_, entries| entries.clear()));
        assert!(with(
            &|_, entries| entries[0].address = "10.0.0.1 evil".into()
        ));
        assert!(with(&|_, entries| entries[0].address = "fe80::1%en0".into()));
        assert!(with(&|_, entries| entries[0].address = "example.com".into()));
        assert!(with(&|_, entries| entries[0].names.clear()));
        assert!(with(
            &|_, entries| entries[0].names[0] = "$(curl evil)".into()
        ));
        assert!(with(&|_, entries| entries[0].names[0] = "a b".into()));
        assert!(with(&|_, entries| entries[0].names[0] = "LocalHost".into()));
        assert!(with(
            &|_, entries| entries[1].expires = Some("tomorrow".into())
        ));
        assert!(with(&|_, entries| {
            let entry = entries[0].clone();
            entries.resize(MAX_GROUP_ENTRIES + 1, entry);
        }));
    }

    #[test]
    fn checks_public_keys() {
        assert!(public_key().check().is_ok());
        let with = |name: &str, key: &str| {
            Item::PublicKey {
                name: name.into(),
                key: key.into(),
            }
            .check()
            .is_err()
        };
        let key = PUBLIC.trim();
        for name in [
            "",
            ".hidden",
            "../id",
            "a/b",
            "config",
            "Authorized_Keys",
            "id.pub",
        ] {
            assert!(with(name, key), "{name:?}");
        }
        assert!(with("id", "ssh-ed25519 AAAA not-a-key"));
        assert!(with(
            "id",
            &format!("{key}\ncommand=\"x\" ssh-ed25519 AAAA")
        ));
        assert!(with(
            "id",
            &key.replacen("ssh-ed25519", "ssh-ed25519-cert-v01@openssh.com", 1)
        ));
        assert!(with("id", "-----BEGIN OPENSSH PRIVATE KEY-----"));
    }

    fn environment() -> Item {
        let var = |name: &str, value: &str, secret: bool| EnvVariable {
            name: name.into(),
            value: value.into(),
            secret,
            note: String::new(),
        };
        Item::Environment {
            project: "shop".into(),
            name: "prod".into(),
            notes: "eu".into(),
            variables: vec![
                var("PORT", "80", false),
                var("API_KEY", "s3cret", true),
                var("CERT", "line 1\nline 2", true),
                var("EMPTY", "", false),
            ],
        }
    }

    #[test]
    fn environments_are_summarised_without_values() {
        let item = environment();
        assert_eq!(
            item.summary(),
            ItemSummary::Environment {
                project: "shop".into(),
                name: "prod".into(),
                variables: 4,
                secrets: 2,
                names: vec!["PORT".into(), "API_KEY".into(), "CERT".into()],
            }
        );
        assert!(!format!("{item:?}").contains("s3cret"));
        let json = serde_json::to_string(&item).unwrap();
        assert!(json.starts_with(r#"{"type":"environment","project":"shop""#));
        assert_eq!(serde_json::from_str::<Item>(&json).unwrap(), item);
    }

    #[test]
    fn checks_environments() {
        assert!(environment().check().is_ok());
        let with = |change: &dyn Fn(&mut String, &mut Vec<EnvVariable>)| {
            let mut item = environment();
            if let Item::Environment {
                name, variables, ..
            } = &mut item
            {
                change(name, variables);
            }
            item.check().is_err()
        };
        assert!(with(&|name, _| name.clear()));
        assert!(with(&|name, _| *name = "a/b".into()));
        assert!(with(&|name, _| *name = "a\nb".into()));
        assert!(with(&|_, vars| vars[0].name = "$(x)".into()));
        assert!(with(&|_, vars| vars[1].name = "PORT".into()));
        assert!(with(&|_, vars| vars[0].value = "a\u{1b}[2J".into()));
        assert!(with(&|_, vars| vars[0].note = "two\nlines".into()));
        assert!(with(&|_, vars| {
            for (index, var) in vars.iter_mut().enumerate() {
                var.value = "x".repeat(60 * 1024);
                var.name = format!("V{index}");
            }
            let more = vars[0].clone();
            for index in 0..4 {
                vars.push(EnvVariable {
                    name: format!("W{index}"),
                    ..more.clone()
                });
            }
        }));
    }

    #[test]
    fn cleans_names() {
        assert_eq!(clean_name("  MacBook \t of\nAziz "), "MacBook of Aziz");
        assert_eq!(clean_name("a\u{7}b"), "ab");
        assert_eq!(clean_name(&"x".repeat(100)).chars().count(), MAX_NAME);
    }
}
