//! Server keys as they go to the user's other computers: `known_hosts`
//! grows by what the other knows, and shrinks only by hand.
//!
//! A computer sends the keys it trusts for the hosts it syncs and for every
//! plain (unhashed) name in its `known_hosts`, read through hashed lines
//! too. The other adds them for a host it has no key for. For a host it
//! has another key of the same type for, it keeps its own and reports
//! both: one of them may be a server pretending, and only the user can
//! tell which.
//!
//! A host this computer trusts through an `@cert-authority` line has a key
//! here too, even with no plain one: nothing is added for it, since `ssh`
//! would then take the sender's key without a certificate, and a key the
//! sender has that this computer doesn't is reported. A key this computer
//! marked `@revoked` for the host is never added, and reported.

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

/// Adds the other computer's keys for hosts this one has none for (plain
/// or through a CA), never one it revoked, and reports the hosts the two
/// trust different keys for.
pub fn merge(known: &mut KnownHosts, theirs: &[HostKeys]) -> KeysMerge {
    let mut merge = KeysMerge::default();
    for host in theirs {
        if !is_name(&host.host) {
            continue;
        }
        let mine = known.keys_for(&host.host, host.port);
        let marked = |marker: HostMarker| -> Vec<String> {
            known
                .matches(&host.host, host.port)
                .into_iter()
                .filter(|entry| entry.marker == marker)
                .map(|entry| entry.fingerprint)
                .collect()
        };
        let authorities = marked(HostMarker::CertAuthority);
        let revoked = marked(HostMarker::Revoked);
        let is_revoked =
            |key: &HostKey| fingerprint(&key.key).is_some_and(|f| revoked.contains(&f));
        let differs = if mine.is_empty() && authorities.is_empty() {
            for key in host.keys.iter().filter(|key| !is_revoked(key)) {
                if known
                    .add_key(&host.host, host.port, &key.key_type, &key.key)
                    .unwrap_or(false)
                {
                    merge.added += 1;
                }
            }
            host.keys.iter().any(is_revoked)
        } else {
            host.keys.iter().any(|key| {
                let same_type: Vec<&String> = mine
                    .iter()
                    .filter(|(kind, _)| *kind == key.key_type)
                    .map(|(_, blob)| blob)
                    .collect();
                let unknown = !mine.iter().any(|(_, blob)| *blob == key.key);
                is_revoked(key)
                    || (!same_type.is_empty() && !same_type.contains(&&key.key))
                    || (!authorities.is_empty() && unknown)
            })
        };
        if differs {
            merge.differ.push(KeysDiffer {
                host: host.host.clone(),
                port: host.port,
                here: mine
                    .iter()
                    .filter_map(|(_, k)| fingerprint(k))
                    .chain(authorities)
                    .collect(),
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

/// Takes out of `known` the keys it has beyond `before`, which a [`merge`]
/// added at its end, for hosts one of `elsewhere` trusts a key for: `ssh`
/// reads those files too (`known_hosts2`, the system's
/// `ssh_known_hosts`…), and would take the other computer's key next to
/// the one, or the certificate authority, trusted there. Returns how many
/// it took out.
pub fn drop_trusted_elsewhere(
    known: &mut KnownHosts,
    before: &KnownHosts,
    elsewhere: &[KnownHosts],
) -> usize {
    let kept = before.to_string().lines().count();
    let doomed: Vec<u32> = known
        .entries()
        .into_iter()
        .filter(|entry| usize::try_from(entry.line).is_ok_and(|line| line > kept))
        .filter(|entry| {
            entry.hosts.iter().any(|pattern| {
                split_pattern(pattern)
                    .is_some_and(|(host, port)| trusted_in(elsewhere, &host, port))
            })
        })
        .map(|entry| entry.line)
        .collect();
    known.remove_lines(&doomed)
}

/// Whether one of `files` trusts a key for `host` on `port`: one of its
/// own, or a certificate authority's. A revoked key trusts nothing.
pub fn trusted_in(files: &[KnownHosts], host: &str, port: u16) -> bool {
    files.iter().any(|file| {
        file.matches(host, port)
            .iter()
            .any(|entry| entry.marker != HostMarker::Revoked)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::Field;

    #[test]
    fn keys_trusted_in_another_file_are_not_added_next_to_it() {
        let before = KnownHosts::parse(&format!("old.example.com ssh-ed25519 {ED_A}"));
        let elsewhere = [
            KnownHosts::parse(&format!(
                "@cert-authority *.corp.example.com ssh-ed25519 {ED_A}\n"
            )),
            KnownHosts::parse(&format!("[git.example.com]:2222 ssh-ed25519 {ED_A}\n")),
            KnownHosts::parse(&format!(
                "@revoked revoked.example.com ssh-ed25519 {ED_A}\n"
            )),
        ];
        let mut known = before.clone();
        let theirs = |host: &str, port: u16| HostKeys {
            host: host.into(),
            port,
            keys: vec![HostKey {
                key_type: "ssh-ed25519".into(),
                key: ED_B.into(),
            }],
        };
        let merge = merge(
            &mut known,
            &[
                theirs("db.corp.example.com", 22),
                theirs("git.example.com", 2222),
                theirs("git.example.com", 22),
                theirs("revoked.example.com", 22),
                theirs("new.example.com", 22),
            ],
        );
        assert_eq!(merge.added, 5);
        assert_eq!(drop_trusted_elsewhere(&mut known, &before, &elsewhere), 2);
        let ed_b = vec![("ssh-ed25519".to_owned(), ED_B.to_owned())];
        let none: Vec<(String, String)> = Vec::new();
        assert_eq!(known.keys_for("db.corp.example.com", 22), none);
        assert_eq!(known.keys_for("git.example.com", 2222), none);
        assert_eq!(known.keys_for("git.example.com", 22), ed_b);
        assert_eq!(known.keys_for("revoked.example.com", 22), ed_b);
        assert_eq!(known.keys_for("new.example.com", 22), ed_b);
        // What was there stays, whatever the other files say.
        let mut known = before.clone();
        let everywhere = [KnownHosts::parse(&format!("* ssh-ed25519 {ED_B}\n"))];
        assert_eq!(drop_trusted_elsewhere(&mut known, &before, &everywhere), 0);
        assert_eq!(known, before);
    }

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
    fn a_host_trusted_through_a_ca_gets_no_plain_key() {
        let ca = format!("@cert-authority *.corp.example.com ssh-ed25519 {ED_A}\n");
        let mut known = KnownHosts::parse(&ca);
        let theirs = HostKeys {
            host: "prod.corp.example.com".into(),
            port: 22,
            keys: vec![key("ssh-ed25519", ED_B)],
        };
        let merge = merge(&mut known, std::slice::from_ref(&theirs));
        assert_eq!(merge.added, 0);
        assert_eq!(known.to_string(), ca);
        assert_eq!(
            merge.differ,
            [KeysDiffer {
                host: "prod.corp.example.com".into(),
                port: 22,
                here: vec![fingerprint(ED_A).unwrap()],
                there: vec![fingerprint(ED_B).unwrap()],
            }]
        );
        // A host the CA doesn't cover gets the key as before.
        let mut other = theirs;
        other.host = "prod.example.com".into();
        assert_eq!(super::merge(&mut known, &[other]).added, 1);
    }

    #[test]
    fn a_revoked_key_is_never_added() {
        let revoked = format!("@revoked * ssh-ed25519 {ED_B}\n");
        let mut known = KnownHosts::parse(&revoked);
        let merge = merge(
            &mut known,
            &[HostKeys {
                host: "new.example.com".into(),
                port: 22,
                keys: vec![key("ssh-ed25519", ED_B), key(NISTP256, ECDSA)],
            }],
        );
        // The other key goes in; the revoked one is reported.
        assert_eq!(merge.added, 1);
        assert_eq!(
            known.keys_for("new.example.com", 22),
            [(NISTP256.to_owned(), ECDSA.to_owned())]
        );
        assert_eq!(merge.differ.len(), 1);
        assert_eq!(merge.differ[0].here, Vec::<String>::new());

        // Revoked here, trusted there, for a host with a key of another type
        // here: reported all the same.
        let mut known = KnownHosts::parse(&format!("{revoked}prod {NISTP256} {ECDSA}\n"));
        let merge = super::merge(
            &mut known,
            &[HostKeys {
                host: "prod".into(),
                port: 22,
                keys: vec![key("ssh-ed25519", ED_B)],
            }],
        );
        assert_eq!((merge.added, merge.differ.len()), (0, 1));
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
