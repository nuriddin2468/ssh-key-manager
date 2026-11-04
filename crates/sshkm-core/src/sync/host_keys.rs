//! Server keys as they go to the user's other computers: `known_hosts`
//! grows by what the other knows, and shrinks only by hand.
//!
//! A computer sends the keys it trusts for the hosts it syncs and for every
//! plain (unhashed) name in its `known_hosts`, read through hashed lines
//! too. The other adds them for a host it has no key for. For a host it
//! has another key of the same type for, it keeps its own and reports
//! both: one of them may be a server pretending, and only the user can
//! tell which.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::Item;
use crate::known_hosts::{HostMarker, KnownHosts, fingerprint};
use crate::p2p::protocol::HostKey;

/// Most hosts whose keys one computer sends.
pub const MAX_HOSTS: usize = 4096;

/// The keys a computer trusts for a host and port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostKeys {
    pub host: String,
    pub port: u16,
    pub keys: Vec<HostKey>,
}

/// A host the two computers trust different keys for: `SHA256:…`
/// fingerprints here and there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct KeysDiffer {
    pub host: String,
    pub port: u16,
    pub here: Vec<String>,
    pub there: Vec<String>,
}

/// What [`merge`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeysMerge {
    /// Keys added.
    pub added: u32,
    pub differ: Vec<KeysDiffer>,
}

/// The keys this computer trusts for `hosts` (by `HostName`, or the alias,
/// and `Port`) and for the plain names in `known`.
pub fn collect(known: &KnownHosts, hosts: &[Item]) -> Vec<HostKeys> {
    let mut targets: BTreeSet<(String, u16)> = BTreeSet::new();
    for item in hosts {
        let name = item
            .value("hostname")
            .or_else(|| (!item.id.contains(' ')).then_some(item.id.as_str()));
        let port = item
            .value("port")
            .map_or(Some(22), |port| port.parse().ok());
        if let (Some(name), Some(port)) = (name, port)
            && is_name(name)
        {
            targets.insert((name.to_ascii_lowercase(), port));
        }
    }
    for entry in known.entries() {
        if entry.hashed || entry.marker != HostMarker::None {
            continue;
        }
        for pattern in &entry.hosts {
            if let Some((name, port)) = split_pattern(pattern) {
                targets.insert((name, port));
            }
        }
    }
    targets
        .into_iter()
        .filter_map(|(host, port)| {
            let keys: Vec<HostKey> = known
                .keys_for(&host, port)
                .into_iter()
                .map(|(key_type, key)| HostKey { key_type, key })
                .collect();
            (!keys.is_empty()).then_some(HostKeys { host, port, keys })
        })
        .take(MAX_HOSTS)
        .collect()
}

/// `host` or `[host]:port` as a name and port; `None` for a wildcard or a
/// negation.
fn split_pattern(pattern: &str) -> Option<(String, u16)> {
    let (name, port) = match pattern.strip_prefix('[') {
        Some(rest) => {
            let (name, port) = rest.split_once("]:")?;
            (name, port.parse().ok()?)
        }
        None => (pattern, 22),
    };
    is_name(name).then(|| (name.to_ascii_lowercase(), port))
}

/// A host name `known_hosts` may get a line for.
pub(crate) fn is_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
}

/// Adds the other computer's keys for hosts this one has none for, and
/// reports the hosts the two trust different keys of one type for.
pub fn merge(known: &mut KnownHosts, theirs: &[HostKeys]) -> KeysMerge {
    let mut merge = KeysMerge::default();
    for host in theirs {
        if !is_name(&host.host) {
            continue;
        }
        let mine = known.keys_for(&host.host, host.port);
        if mine.is_empty() {
            for key in &host.keys {
                if known
                    .add_key(&host.host, host.port, &key.key_type, &key.key)
                    .unwrap_or(false)
                {
                    merge.added += 1;
                }
            }
            continue;
        }
        let differs = host.keys.iter().any(|key| {
            let same_type: Vec<&String> = mine
                .iter()
                .filter(|(kind, _)| *kind == key.key_type)
                .map(|(_, blob)| blob)
                .collect();
            !same_type.is_empty() && !same_type.contains(&&key.key)
        });
        if differs {
            merge.differ.push(KeysDiffer {
                host: host.host.clone(),
                port: host.port,
                here: mine.iter().filter_map(|(_, k)| fingerprint(k)).collect(),
                there: host
                    .keys
                    .iter()
                    .filter_map(|k| fingerprint(&k.key))
                    .collect(),
            });
        }
    }
    merge
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::Field;

    use base64ct::{Base64, Encoding};
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    // Two ed25519 public keys and an ECDSA one, made for these tests.
    const ED_A: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIDHOKVWa73D68Vat8zHzUs1yrRuZU8y6kC5BAIOsXQeq";
    const ED_B: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIBgLoA2q5LxUnfhJvTWC5BepyMKwFP0uSdKxztrd2QNz";
    const ECDSA: &str = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGpoALA5QdMT35Al1UfHKFtiCp20SOCbgWJPB0rJd3R0YVj9+5XtSx+gVm0rfDPV82Seh5/LJ7yRLSMDKtCvaCk=";
    const NISTP256: &str = "ecdsa-sha2-nistp256";

    /// A hashed line, as `ssh-keygen -H` writes them.
    fn hashed(name: &str, key_type: &str, key: &str) -> String {
        let salt = [9_u8; 20];
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&salt).unwrap();
        mac.update(name.as_bytes());
        format!(
            "|1|{}|{} {key_type} {key}\n",
            Base64::encode_string(&salt),
            Base64::encode_string(&mac.finalize().into_bytes())
        )
    }

    fn item(id: &str, fields: &[(&str, &str)]) -> Item {
        Item {
            id: id.into(),
            fields: fields
                .iter()
                .map(|(k, v)| Field {
                    key: (*k).into(),
                    values: vec![(*v).into()],
                })
                .collect(),
        }
    }

    fn key(key_type: &str, key: &str) -> HostKey {
        HostKey {
            key_type: key_type.into(),
            key: key.into(),
        }
    }

    #[test]
    fn keys_are_collected_for_synced_hosts_and_plain_names() {
        let known = KnownHosts::parse(&format!(
            "[db.example.com]:2222 ssh-ed25519 {ED_A}\n\
             github.com ssh-ed25519 {ED_B}\n\
             *.wild ssh-ed25519 {ED_B}\n\
             @revoked old.example.com ssh-ed25519 {ED_B}\n{}",
            hashed("10.0.0.1", NISTP256, ECDSA)
        ));
        let hosts = [
            item("prod", &[("HostName", "10.0.0.1")]),
            item("db", &[("HostName", "db.example.com"), ("Port", "2222")]),
            item("nothing", &[]),
        ];
        let collected = collect(&known, &hosts);
        let names: Vec<(&str, u16)> = collected
            .iter()
            .map(|h| (h.host.as_str(), h.port))
            .collect();
        assert_eq!(
            names,
            [
                ("10.0.0.1", 22),
                ("db.example.com", 2222),
                ("github.com", 22)
            ]
        );
        assert_eq!(collected[0].keys, [key(NISTP256, ECDSA)]);
    }

    #[test]
    fn keys_are_added_where_there_are_none_and_differences_reported() {
        let mut known = KnownHosts::parse(&format!("prod.example.com ssh-ed25519 {ED_A}\n"));
        let theirs = [
            HostKeys {
                host: "new.example.com".into(),
                port: 2222,
                keys: vec![key("ssh-ed25519", ED_B), key(NISTP256, ECDSA)],
            },
            HostKeys {
                host: "prod.example.com".into(),
                port: 22,
                keys: vec![key("ssh-ed25519", ED_B)],
            },
            HostKeys {
                host: "evil host".into(),
                port: 22,
                keys: vec![key("ssh-ed25519", ED_B)],
            },
        ];
        let merge = merge(&mut known, &theirs);
        assert_eq!(merge.added, 2);
        assert_eq!(merge.differ.len(), 1);
        let differ = &merge.differ[0];
        assert_eq!(differ.host, "prod.example.com");
        assert_eq!(differ.here, [fingerprint(ED_A).unwrap()]);
        assert_eq!(differ.there, [fingerprint(ED_B).unwrap()]);
        // Its own key stays; the other's is not added next to it.
        assert_eq!(
            known.keys_for("prod.example.com", 22),
            [("ssh-ed25519".to_owned(), ED_A.to_owned())]
        );
        assert_eq!(known.keys_for("new.example.com", 2222).len(), 2);
        assert_eq!(known.keys_for("evil host", 22).len(), 0);

        // The same keys again: nothing to add, nothing differs.
        let again = super::merge(&mut known, &theirs[..1]);
        assert_eq!(again, KeysMerge::default());
    }

    #[test]
    fn another_key_type_for_a_known_host_is_not_a_difference() {
        let mut known = KnownHosts::parse(&format!("prod ssh-ed25519 {ED_A}\n"));
        let merge = merge(
            &mut known,
            &[HostKeys {
                host: "prod".into(),
                port: 22,
                keys: vec![key("ssh-ed25519", ED_A), key(NISTP256, ECDSA)],
            }],
        );
        assert_eq!(merge, KeysMerge::default());
        assert_eq!(known.keys_for("prod", 22).len(), 1);
    }
}
