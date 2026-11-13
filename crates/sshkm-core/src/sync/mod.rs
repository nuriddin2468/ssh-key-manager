//! Keeping the user's own computers in step.
//!
//! Each computer sends the other a [`Manifest`]: its hosts as they go to
//! another computer ([`hosts`]), the server keys it trusts for them
//! ([`host_keys`]), and the records of the user's devices and projects.
//! Each then works out by itself what to take from the other ([`plan`]).
//! The comparison is against a snapshot of what both had after they last
//! synced ([`Base`]).
//! An item only one of them changed goes the way of the change. One both
//! changed differently is a [`Conflict`] for the user. After applying, the
//! two compare what they have ([`agree`]), and what agrees becomes the next
//! snapshot.
//!
//! Each computer keeps its own snapshot of each other device. It holds
//! keyed hashes, never values.

pub mod host_keys;
pub mod hosts;
mod merge;

use serde::{Deserialize, Serialize};

pub use self::host_keys::HostKeys;
pub use self::merge::{
    Base, Change, Conflict, Field, Hasher, Hashes, Item, Outcome, Plan, agree, agree_hashed,
    digest, digests, plan, plan_hashed,
};
use crate::vault::projects::ProjectRecord;
use crate::vault::{ContactRecord, DeviceRecord, MAX_CONTACTS, check_records};
use crate::{Error, Result};

/// Most hosts one computer sends.
pub const MAX_ITEMS: usize = 4096;
const MAX_FIELDS: usize = 128;
const MAX_VALUES: usize = 64;
const MAX_VALUE: usize = 64 * 1024;
/// Largest manifest taken, in bytes of JSON.
pub const MAX_MANIFEST: u64 = 32 * 1024 * 1024;

/// What one computer has to sync.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub hosts: Vec<Item>,
    pub host_keys: Vec<HostKeys>,
    pub devices: Vec<DeviceRecord>,
    /// Missing from versions before projects.
    #[serde(default)]
    pub projects: Vec<ProjectRecord>,
    /// The contacts' records; missing from versions before entry sync.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contacts: Vec<ContactRecord>,
}

impl Manifest {
    /// Fails unless everything in it is something a sync may take: sizes in
    /// bounds, ids and keywords that `ssh_config` takes, values on one line
    /// with nothing of the sender's computer in them, and valid names and
    /// keys for `known_hosts`.
    pub fn check(&self) -> Result<()> {
        if self.hosts.len() > MAX_ITEMS || self.host_keys.len() > host_keys::MAX_HOSTS {
            return Err(Error::invalid("too many hosts"));
        }
        for item in &self.hosts {
            check_item(item)?;
        }
        if self
            .hosts
            .iter()
            .enumerate()
            .any(|(i, item)| self.hosts[..i].iter().any(|other| other.id == item.id))
        {
            return Err(Error::invalid("a host twice"));
        }
        for host in &self.host_keys {
            if !host_keys::is_name(&host.host) || host.port == 0 || host.keys.len() > 16 {
                return Err(Error::invalid("not a host's keys"));
            }
            for key in &host.keys {
                let base64 = key
                    .key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
                let kind = key
                    .key_type
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'@'));
                if !base64 || !kind || key.key.is_empty() || key.key.len() > MAX_VALUE {
                    return Err(Error::invalid("not a host key"));
                }
            }
        }
        // Project and contact records are taken one by one when they merge:
        // one this version can't read is skipped, never the whole sync.
        if self.contacts.len() > MAX_CONTACTS {
            return Err(Error::invalid("too many contacts"));
        }
        check_records(&self.devices)
    }
}

fn check_item(item: &Item) -> Result<()> {
    let bad_pattern = |p: &str| {
        p.is_empty()
            || p.len() > 255
            || p.starts_with(['#', '!', '-'])
            || p.contains(['*', '?'])
            || p.chars()
                .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '\'' | '\\'))
    };
    if item.id.split(' ').any(bad_pattern) || item.fields.len() > MAX_FIELDS {
        return Err(Error::invalid("not a host to sync"));
    }
    for (i, field) in item.fields.iter().enumerate() {
        let key_ok = field.key.len() <= 64
            && field.key.starts_with(|c: char| c.is_ascii_alphabetic())
            && field.key.chars().all(|c| c.is_ascii_alphanumeric())
            && !field.key.eq_ignore_ascii_case("host")
            && !field.key.eq_ignore_ascii_case("match")
            && !field.key.eq_ignore_ascii_case("include")
            && !item.fields[..i]
                .iter()
                .any(|f| f.key.eq_ignore_ascii_case(&field.key));
        if !key_ok || field.values.is_empty() || field.values.len() > MAX_VALUES {
            return Err(Error::invalid(format!(
                "not a host option: {:?}",
                field.key
            )));
        }
        for value in &field.values {
            let option = crate::config::HostOption::new(&field.key, value);
            if value.trim().is_empty()
                || value.trim() != value
                || value.len() > MAX_VALUE
                || value.chars().any(char::is_control)
                || hosts::is_local(&option)
            {
                return Err(Error::invalid(format!(
                    "not a value to sync for {}",
                    field.key
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::protocol::HostKey;

    fn host(id: &str, key: &str, value: &str) -> Item {
        Item {
            id: id.into(),
            fields: vec![Field {
                key: key.into(),
                values: vec![value.into()],
            }],
        }
    }

    #[test]
    fn a_manifest_takes_only_what_a_sync_may_bring() {
        let fine = Manifest {
            hosts: vec![
                host("prod", "HostName", "10.0.0.1"),
                host("db1 db2", "User", "me"),
            ],
            host_keys: vec![HostKeys {
                host: "10.0.0.1".into(),
                port: 22,
                keys: vec![HostKey {
                    key_type: "ssh-ed25519".into(),
                    key: "AAAAC3NzaC1lZDI1NTE5".into(),
                }],
            }],
            devices: Vec::new(),
            projects: Vec::new(),
            contacts: Vec::new(),
        };
        assert!(fine.check().is_ok());
        let with = |item: Item| Manifest {
            hosts: vec![item],
            ..Manifest::default()
        };
        for bad in [
            host("*", "User", "me"),
            host("prod*", "User", "me"),
            host("!prod", "User", "me"),
            host("prod", "IdentityFile", "~/.ssh/id"),
            host("prod", "ProxyCommand", "/usr/bin/nc %h %p"),
            host("prod", "Include", "other"),
            host("prod", "User", "me\nProxyCommand x"),
            host("prod", "User", " me"),
            host("prod", "Pro-xy", "x"),
        ] {
            assert!(with(bad.clone()).check().is_err(), "{bad:?}");
        }
        let twice = Manifest {
            hosts: vec![host("prod", "User", "a"), host("prod", "User", "b")],
            ..Manifest::default()
        };
        assert!(twice.check().is_err());
        let mut evil_keys = fine.clone();
        evil_keys.host_keys[0].host = "a b".into();
        assert!(evil_keys.check().is_err());
    }
}
