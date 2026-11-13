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
use crate::vault::envs::files::CloudService;
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
/// A server's password goes with where its alias leads ([`Server`]), and
/// the receiver saves it for one of its aliases only if that one leads to
/// the same server. A peer without it gets the password for no host
/// ([`Item::for_peer`]): older versions would bind it to the sender's alias
/// whatever it leads to there.
pub const SERVER_PASSWORD: &str = "server-password/1";
/// An environment's variables that make programs run code
/// ([`crate::vault::envs::runs_code`]) are left out where it arrives, and
/// named. A peer without it gets the environment without them
/// ([`Item::for_peer`]): older versions save them, and set them in a shell
/// without asking.
pub const ENV_CODE_VARS: &str = "env-code-vars/1";
/// What this version can do beyond version 1, as its `Hello` says.
pub const FEATURES: &[&str] = &[CHAT, PERSONAL_ENV, SERVER_PASSWORD, ENV_CODE_VARS];

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
        /// The same for the vault's entries and groups, when both sides
        /// sync them ([`EntrySync::On`]).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        vault: Option<VaultDecisions>,
    },
    /// What the sender has after a sync, as the SHA-256 of each item, and
    /// how many changes it put off for its own user to confirm.
    Applied {
        hashes: BTreeMap<String, String>,
        deferred: u32,
        /// The digest of each of the vault's entries and groups, when both
        /// sides sync them.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        vault: BTreeMap<String, String>,
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

/// What the initiator's user chose for each of the vault's conflicts, by
/// item id.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultDecisions {
    /// The initiator's version stays.
    #[serde(default)]
    pub initiator: Vec<String>,
    /// The responder's version stays.
    #[serde(default)]
    pub responder: Vec<String>,
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
    /// Whether it syncs the vault's entries; versions before entry sync
    /// send nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries: Option<EntrySync>,
}

/// What a side says about syncing the vault's entries. Entries sync only
/// when both say [`Self::On`], in the lower of their versions; then each
/// sends the other its copy of the vault ([`crate::vault::Vault::sync_copy`])
/// as [`Message::Bytes`] and [`Message::Part`]s after the manifests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum EntrySync {
    /// It syncs them, speaking this version of the exchange.
    On { version: u32 },
    /// It could, but its vault is in a cloud folder, which keeps the file
    /// in step on the user's computers.
    Cloud { service: CloudService },
    /// Something a later version says: no entry sync.
    #[serde(other)]
    Other,
}

impl EntrySync {
    /// The version both sides speak, if both sync entries.
    pub fn agreed(mine: Option<Self>, theirs: Option<Self>) -> Option<u32> {
        match (mine?, theirs?) {
            (Self::On { version: a }, Self::On { version: b }) => Some(a.min(b)).filter(|v| *v > 0),
            _ => None,
        }
    }
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
        /// Where `host` leads on the sender's computer. Versions before it
        /// leave it out: the receiver then saves the password for no host.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server: Option<Server>,
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

/// Where a server's password goes: the account and the server, as
/// `ssh -G` works them out for the alias on the sender's computer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct Server {
    pub user: String,
    pub host_name: String,
    pub port: u16,
    /// The jump hosts the connection goes through (`ProxyJump`), if any.
    pub proxy_jump: Option<String>,
    /// The `SHA256:…` fingerprints of the server keys `known_hosts` trusts
    /// for it there: a name says little (two networks may each have a
    /// `db`), a key says which server it is.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_keys: Vec<String>,
}

/// Most server keys a [`Server`] names.
const MAX_SERVER_KEYS: usize = 16;

impl Server {
    /// Whether `other` is the same account on the same server, reached the
    /// same way: the same names and port, and a server key both trust.
    /// Without one in common, it can't be told, so it is not.
    pub fn same(&self, other: &Self) -> bool {
        self.user == other.user
            && self.host_name.eq_ignore_ascii_case(&other.host_name)
            && self.port == other.port
            && self.proxy_jump == other.proxy_jump
            && self
                .host_keys
                .iter()
                .any(|key| other.host_keys.contains(key))
    }

    /// Fails unless every name is made of name characters (see
    /// [`Item::check`]), the port is one, and the keys are fingerprints.
    pub fn check(&self) -> Result<()> {
        name(&self.user, "._-")?;
        name(&self.host_name, ".-_:")?;
        if self.port == 0 {
            return Err(Error::invalid("port 0"));
        }
        if let Some(proxy_jump) = &self.proxy_jump {
            // `ssh -G` writes a numeric one as `[10.0.0.1]:22`.
            name(proxy_jump, ".-_:@,[]")?;
        }
        if self.host_keys.len() > MAX_SERVER_KEYS
            || !self.host_keys.iter().all(|key| {
                key.strip_prefix("SHA256:").is_some_and(|hash| {
                    !hash.is_empty()
                        && hash.len() <= 64
                        && hash
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
                })
            })
        {
            return Err(Error::invalid("not the fingerprints of server keys"));
        }
        Ok(())
    }
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
        /// The alias a server's password is for on the sender's computer,
        /// and where it leads there. The receiver saves it for a host of its
        /// own only if that one leads to the same server. Versions before it
        /// leave both out.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server: Option<Box<Server>>,
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
                host,
                server,
                ..
            } => {
                // A host without where it leads, or without a server key
                // to know the server by, is saved for none, so the summary
                // names none either, as an older version's does.
                let server = server.clone().filter(|server| !server.host_keys.is_empty());
                let (host, server) = host.clone().zip(server).unzip();
                ItemSummary::Password {
                    title: title.clone(),
                    username: username.clone(),
                    url: url.clone(),
                    otp: otp.is_some(),
                    host,
                    server: server.map(Box::new),
                }
            }
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

    /// The names of an environment's variables that make a shell, or a
    /// program it starts, run code ([`crate::vault::envs::runs_code`]):
    /// named in the dialog that sends it, left out where it arrives.
    pub fn code_running(&self) -> Vec<String> {
        match self {
            Self::Environment { variables, .. } => variables
                .iter()
                .filter(|var| crate::vault::envs::runs_code(&var.name))
                .map(|var| var.name.clone())
                .collect(),
            _ => Vec::new(),
        }
    }

    /// The names of the variables [`Self::for_peer`] leaves out for a peer
    /// whose `Hello` named `features`: those that run code
    /// ([`Self::code_running`]), for one without [`ENV_CODE_VARS`].
    pub fn left_out_for(&self, features: &[String]) -> Vec<String> {
        if features.iter().any(|feature| feature == ENV_CODE_VARS) {
            Vec::new()
        } else {
            self.code_running()
        }
    }

    /// The item as it goes to a peer whose `Hello` named `features`: a
    /// server's password to one without [`SERVER_PASSWORD`] goes for no
    /// host, since it would bind it to the alias whatever that leads to
    /// there; an environment to one without [`ENV_CODE_VARS`] goes without
    /// its variables that run code ([`Self::left_out_for`]), since it would
    /// save them and set them in a shell without asking.
    #[must_use]
    pub fn for_peer(self, features: &[String]) -> Self {
        let left_out = self.left_out_for(features);
        match self {
            Self::Environment {
                project,
                name,
                notes,
                variables,
            } if !left_out.is_empty() => Self::Environment {
                project,
                name,
                notes,
                variables: variables
                    .into_iter()
                    .filter(|var| !left_out.contains(&var.name))
                    .collect(),
            },
            Self::Password {
                title,
                username,
                password,
                url,
                notes,
                otp,
                host: Some(_),
                ..
            } if !features.iter().any(|feature| feature == SERVER_PASSWORD) => Self::Password {
                title,
                username,
                password,
                url,
                notes,
                otp,
                host: None,
                server: None,
            },
            item => item,
        }
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
                server,
            } => {
                for value in [title, username, password, url, otp.as_deref().unwrap_or("")] {
                    text(value, false)?;
                }
                text(notes, true)?;
                if let Some(host) = host {
                    name(host, "._-")?;
                }
                if let Some(server) = server {
                    if host.is_none() {
                        return Err(Error::invalid("a server without its alias"));
                    }
                    server.check()?;
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
/// have; names and notes without control, invisible or direction-changing
/// characters, and values without control characters other than line
/// breaks and tabs; and a size that fits one message. The project label is
/// empty for an environment in Personal without a part. A variable that
/// makes programs run code may come ([`Item::code_running`]): the receiver
/// leaves it out, and says so.
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
        plain(label, false)?;
    }
    plain(notes, true)?;
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
        plain(&var.note, false)?;
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

/// [`text`] that can't mislead its reader: no character some programs take
/// for a line break (U+2028, U+2029) and none that is invisible or turns
/// the text around ([`is_invisible`]).
fn plain(value: &str, multiline: bool) -> Result<()> {
    text(value, multiline)?;
    // Joiners neither break lines nor turn text around, and emoji
    // sequences and Persian text need them.
    let joiner = |c: char| matches!(c, '\u{200C}' | '\u{200D}');
    if value.chars().any(|c| is_invisible(c) && !joiner(c)) {
        return Err(Error::invalid(
            "a name or note has invisible or line-breaking characters",
        ));
    }
    Ok(())
}

/// Whether `c` shows nothing, or changes how the text around it reads,
/// though it is not a control character: it ends a line for some programs
/// (U+2028, U+2029), changes the direction of the text (U+202E…), or takes
/// no room (U+200B…, U+FEFF, tag characters).
pub fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
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

/// `name` as a device name: control, invisible and direction-changing
/// characters ([`is_invisible`]) dropped, whitespace collapsed, at most
/// [`MAX_NAME`] characters.
pub fn clean_name(name: &str) -> String {
    let words: Vec<&str> = name.split_whitespace().collect();
    words
        .join(" ")
        .chars()
        .filter(|c| !c.is_control() && !is_invisible(*c))
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
                entries: None,
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
    fn entry_sync_is_announced_and_older_versions_ignore_it() {
        /// `Own` as a version before entry sync reads it.
        #[derive(Deserialize)]
        struct OldOwn {
            vault: VaultState,
        }
        let own = Own {
            intent: Some(Intent::Sync),
            vault: VaultState::Locked,
            entries: Some(EntrySync::On { version: 1 }),
        };
        let json = serde_json::to_string(&own).unwrap();
        assert_eq!(
            json,
            r#"{"intent":"sync","vault":{"state":"locked"},"entries":{"state":"on","version":1}}"#
        );
        assert_eq!(serde_json::from_str::<Own>(&json).unwrap(), own);
        assert_eq!(
            serde_json::from_str::<OldOwn>(&json).unwrap().vault,
            VaultState::Locked
        );
        let cloud: Own = serde_json::from_str(
            r#"{"vault":{"state":"locked"},"entries":{"state":"cloud","service":"iCloudDrive"}}"#,
        )
        .unwrap();
        assert_eq!(
            cloud.entries,
            Some(EntrySync::Cloud {
                service: CloudService::ICloudDrive
            })
        );
        let later: Own = serde_json::from_str(
            r#"{"vault":{"state":"locked"},"entries":{"state":"merged","how":2}}"#,
        )
        .unwrap();
        assert_eq!(later.entries, Some(EntrySync::Other));
        let unknown: Own = serde_json::from_str(
            r#"{"vault":{"state":"locked"},"entries":{"state":"cloud","service":"box"}}"#,
        )
        .unwrap();
        assert_eq!(
            unknown.entries,
            Some(EntrySync::Cloud {
                service: CloudService::Other
            })
        );

        let on = |version| Some(EntrySync::On { version });
        assert_eq!(EntrySync::agreed(on(1), on(3)), Some(1));
        assert_eq!(EntrySync::agreed(on(1), None), None);
        assert_eq!(EntrySync::agreed(on(1), later.entries), None);
        assert_eq!(EntrySync::agreed(on(1), cloud.entries), None);
        assert_eq!(EntrySync::agreed(on(0), on(1)), None);
    }

    #[test]
    fn sync_messages_keep_older_peers_reading() {
        let decisions = Message::Decisions {
            initiator: vec!["prod".into()],
            responder: Vec::new(),
            vault: None,
        };
        assert_eq!(
            serde_json::to_string(&decisions).unwrap(),
            r#"{"type":"decisions","initiator":["prod"],"responder":[]}"#
        );
        let applied = Message::Applied {
            hashes: BTreeMap::new(),
            deferred: 0,
            vault: BTreeMap::new(),
        };
        assert_eq!(
            serde_json::to_string(&applied).unwrap(),
            r#"{"type":"applied","hashes":{},"deferred":0}"#
        );
        let with_vault = Message::Decisions {
            initiator: Vec::new(),
            responder: Vec::new(),
            vault: Some(VaultDecisions {
                initiator: vec!["a".into()],
                responder: vec!["b".into()],
            }),
        };
        let json = serde_json::to_string(&with_vault).unwrap();
        assert_eq!(serde_json::from_str::<Message>(&json).unwrap(), with_vault);
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
            r#"{"type":"hello","version":1,"name":"MacBook","known":true,"features":["chat/1","personal-env/1","server-password/1","env-code-vars/1"]}"#
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
            server: None,
        }
    }

    fn server() -> Server {
        Server {
            user: "deploy".into(),
            host_name: "10.0.4.12".into(),
            port: 22,
            proxy_jump: None,
            host_keys: vec!["SHA256:76vvbGumhP/HpDH4tlyySHWs5hgRZJHr2wQ7hSDwRK8".into()],
        }
    }

    /// A server's password, for `prod` leading where `server` says.
    fn servers_password(server: Option<Server>) -> Item {
        let mut item = password();
        if let Item::Password {
            host, server: to, ..
        } = &mut item
        {
            *host = Some("prod".into());
            *to = server;
        }
        item
    }

    #[test]
    fn a_servers_password_says_where_it_leads_in_its_summary() {
        let bound = servers_password(Some(server()));
        assert!(bound.check().is_ok());
        let ItemSummary::Password {
            host, server: to, ..
        } = bound.summary()
        else {
            unreachable!()
        };
        assert_eq!(
            (host.as_deref(), to.as_deref()),
            (Some("prod"), Some(&server()))
        );
        // Another server is another summary: the payload must be what was
        // offered.
        let mut elsewhere = server();
        elsewhere.host_name = "203.0.113.9".into();
        assert_ne!(
            bound.summary(),
            servers_password(Some(elsewhere.clone())).summary()
        );
        assert!(!server().same(&elsewhere));
        let mut louder = server();
        louder.host_name = "10.0.4.12".to_uppercase();
        assert!(server().same(&louder));
        // The same names on two networks are two servers unless a key
        // trusted for it is the same; no key says nothing.
        let mut other_key = server();
        other_key.host_keys = vec!["SHA256:Q0RyTWFzRnJvbUFub3RoZXJTZXJ2ZXI".into()];
        assert!(!server().same(&other_key));
        let mut keyless = server();
        keyless.host_keys.clear();
        assert!(!server().same(&keyless) && !keyless.same(&keyless));
        let mut both = other_key.clone();
        both.host_keys.extend(server().host_keys);
        assert!(server().same(&both));
        // A numeric jump host as `ssh -G` writes it.
        let mut jump = server();
        jump.proxy_jump = Some("[10.0.0.1]:22".into());
        assert!(jump.check().is_ok());
        let mut odd = server();
        odd.host_keys = vec!["MD5:aa:bb".into()];
        assert!(odd.check().is_err());

        // Without where it leads (as older versions send it), it names no
        // host: it is saved for none, and its summary is an older one's.
        let older = servers_password(None);
        assert_eq!(older.summary(), password().summary());
        // Nor without a server key to know the server by: it can't bind.
        let mut keyless = server();
        keyless.host_keys.clear();
        assert_eq!(
            servers_password(Some(keyless)).summary(),
            password().summary()
        );
        let json = r#"{"type":"password","title":"prod DB","username":"deploy","url":"https://db.example.com","otp":false}"#;
        assert_eq!(
            serde_json::from_str::<ItemSummary>(json).unwrap(),
            older.summary()
        );

        // A peer that didn't name the feature gets it for no host: an older
        // version would bind it to the alias whatever it leads to there.
        assert_eq!(bound.clone().for_peer(&[]).summary(), password().summary());
        assert_eq!(
            bound.clone().for_peer(&["chat/1".to_owned()]),
            servers_password(None).for_peer(&[])
        );
        assert_eq!(bound.clone().for_peer(&features()), bound);
        assert_eq!(password().for_peer(&[]), password());

        // A server needs its alias, and names made of name characters.
        let mut alone = password();
        if let Item::Password { server: to, .. } = &mut alone {
            *to = Some(server());
        }
        assert!(alone.check().is_err());
        let mut odd = server();
        odd.host_name = "$(curl evil)".into();
        assert!(servers_password(Some(odd)).check().is_err());
        let mut odd = server();
        odd.port = 0;
        assert!(servers_password(Some(odd)).check().is_err());
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
                host: None,
                server: None,
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
        // A value may hold any text; names and notes nothing a reader of
        // the file it ends up in could take for another line, or that
        // shows something other than what is there.
        assert!(!with(&|_, vars| vars[0].value = "a\u{2028}b\u{202E}".into()));
        for odd in [
            '\u{2028}', '\u{2029}', '\u{0085}', '\u{202E}', '\u{2066}', '\u{200B}',
        ] {
            assert!(with(&|name, _| *name = format!("dev{odd}x")), "{odd:?}");
            assert!(
                with(&|_, vars| vars[0].note = format!("rotated{odd}API=1 #")),
                "{odd:?}"
            );
            let mut item = environment();
            if let Item::Environment { project, notes, .. } = &mut item {
                *project = format!("shop{odd}");
                *notes = String::new();
            }
            assert!(item.check().is_err(), "{odd:?}");
            let mut item = environment();
            if let Item::Environment { notes, .. } = &mut item {
                *notes = format!("line one\nline{odd}two");
            }
            assert!(item.check().is_err(), "{odd:?}");
        }
        assert!(!with(
            &|_, vars| vars[0].note = "rotated monthly \u{2714}\u{FE0F}".into()
        ));
        // Joiners: an emoji sequence, Persian text.
        assert!(!with(
            &|_, vars| vars[0].note = "by \u{1F469}\u{200D}\u{1F4BB}".into()
        ));
        assert!(!with(
            &|name, _| *name = "\u{0645}\u{06CC}\u{200C}\u{0634}\u{0648}\u{062F}".into()
        ));
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
    fn variables_that_make_programs_run_code_travel_named_as_such() {
        let mut item = environment();
        assert_eq!(item.code_running(), Vec::<String>::new());
        if let Item::Environment { variables, .. } = &mut item {
            variables[1].name = "NODE_OPTIONS".into();
            variables[2].name = "path".into();
            variables[3].name = "GIT_AUTHOR_NAME".into();
        }
        // Nothing refuses them: a project may rely on them.
        assert!(item.check().is_ok());
        assert_eq!(item.code_running(), ["NODE_OPTIONS", "path"]);
        assert_eq!(host().code_running(), Vec::<String>::new());

        // A peer that leaves them out where they arrive gets them all.
        assert_eq!(item.left_out_for(&features()), Vec::<String>::new());
        assert_eq!(item.clone().for_peer(&features()), item);
        // One that doesn't (an older version would set them without asking)
        // gets the environment without them, and they are named.
        for older in [
            Vec::new(),
            vec![CHAT.to_owned(), SERVER_PASSWORD.to_owned()],
        ] {
            assert_eq!(item.left_out_for(&older), ["NODE_OPTIONS", "path"]);
            let Item::Environment { variables, .. } = item.clone().for_peer(&older) else {
                panic!("an environment");
            };
            let names: Vec<&str> = variables.iter().map(|var| var.name.as_str()).collect();
            assert_eq!(names, ["PORT", "GIT_AUTHOR_NAME"]);
        }
        assert_eq!(environment().for_peer(&[]), environment());
        assert_eq!(host().left_out_for(&[]), Vec::<String>::new());
    }

    #[test]
    fn cleans_names() {
        assert_eq!(clean_name("  MacBook \t of\nAziz "), "MacBook of Aziz");
        assert_eq!(clean_name("a\u{7}b"), "ab");
        assert_eq!(clean_name(&"x".repeat(100)).chars().count(), MAX_NAME);
        // Nothing that turns the name around or hides in it.
        assert_eq!(clean_name("Mac\u{202E}koob\u{202C}"), "Mackoob");
        assert_eq!(clean_name("this\u{200B}Mac\u{2066}\u{FEFF}"), "thisMac");
        assert_eq!(clean_name("a\u{2028}b\u{2029}c"), "a b c");
    }
}
