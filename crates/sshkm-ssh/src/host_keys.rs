//! Server keys against the `known_hosts` the phone carries, with the rules
//! computers follow (OpenSSH's `check_host_key()`, `StrictHostKeyChecking
//! ask`).
//!
//! The key is looked up by the name connected to (`HostName`, or the
//! alias) and port, `[host]:port` when the port isn't 22, through hashed
//! entries too. A key marked `@revoked` for the host stops the connection.
//! A plain entry with the same key connects. A plain entry with another key
//! of the same type means the key changed: the connection stops with both
//! fingerprints and nothing resolves it here, the user does that on a
//! computer or by removing the line. Otherwise the host is unknown and the
//! app asks the user; on yes, the new line is handed to the app to store,
//! and it syncs to computers. `@cert-authority` lines are not used: the
//! phone asks for no certificates, so such a host is unknown.
//!
//! The key is checked at the first key exchange; russh doesn't hand later
//! re-exchanges (every hour or gigabyte) to the check again, where OpenSSH
//! would. The session is already bound to the key checked then.
//!
//! When `known_hosts` has keys of some types for a host, those types are
//! asked for first, as OpenSSH does, so a host known by its RSA key isn't
//! "unknown" because the phone prefers Ed25519. A host known only by other
//! types (the server stopped offering them) is unknown, and the question
//! says which types were known.

use std::borrow::Cow;

use russh::keys::{Algorithm, EcdsaCurve, HashAlg, PublicKey};
use sshkm_core::known_hosts::{HostMarker, KnownHosts};

/// Host key algorithms, as current OpenSSH clients offer them: no
/// `ssh-rsa` with SHA-1, no `ssh-dss`.
const HOST_KEY_ALGORITHMS: [Algorithm; 6] = [
    Algorithm::Ed25519,
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP384,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP521,
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha512),
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha256),
    },
];

/// What `known_hosts` says about a server's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// A plain entry has this key.
    Known,
    /// Plain entries have other keys of the same type: their fingerprints.
    Changed { known: Vec<String> },
    /// The key is marked `@revoked` for the host.
    Revoked,
    /// Nothing about this key. `other_types` are the types `known_hosts`
    /// has keys of for the host, if any.
    Unknown { other_types: Vec<String> },
}

/// The key type and standard base64 of a key, as `known_hosts` writes it.
pub(crate) fn openssh_parts(key: &PublicKey) -> Option<(String, String)> {
    let line = key.to_openssh().ok()?;
    let mut parts = line.split_whitespace();
    Some((parts.next()?.to_owned(), parts.next()?.to_owned()))
}

/// The `SHA256:…` fingerprint of a key, as `ssh-keygen -l` prints it.
pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// What `known` says about `key` for `host` on `port`.
pub fn check(known: &KnownHosts, host: &str, port: u16, key: &PublicKey) -> Verdict {
    let Some((key_type, encoded)) = openssh_parts(key) else {
        return Verdict::Unknown {
            other_types: Vec::new(),
        };
    };
    let fingerprint = fingerprint(key);
    if known
        .matches(host, port)
        .iter()
        .any(|e| e.marker == HostMarker::Revoked && e.fingerprint == fingerprint)
    {
        return Verdict::Revoked;
    }
    let plain = known.keys_for(host, port);
    if plain.iter().any(|(t, k)| *t == key_type && *k == encoded) {
        return Verdict::Known;
    }
    let same_type: Vec<String> = plain
        .iter()
        .filter(|(t, _)| *t == key_type)
        .filter_map(|(_, k)| sshkm_core::known_hosts::fingerprint(k))
        .collect();
    if !same_type.is_empty() {
        return Verdict::Changed { known: same_type };
    }
    let mut other_types: Vec<String> = Vec::new();
    for (t, _) in plain {
        if !other_types.contains(&t) {
            other_types.push(t);
        }
    }
    Verdict::Unknown { other_types }
}

/// The host key algorithms to offer for `host` on `port`: those of the
/// types `known` has for it first, then the rest, each list in the order
/// of [`HOST_KEY_ALGORITHMS`].
pub fn algorithms_for(known: &KnownHosts, host: &str, port: u16) -> Cow<'static, [Algorithm]> {
    let types: Vec<String> = known
        .keys_for(host, port)
        .into_iter()
        .map(|(t, _)| t)
        .collect();
    let is_known = |algorithm: &Algorithm| {
        let name = match algorithm {
            // Every RSA signature is made with an `ssh-rsa` key.
            Algorithm::Rsa { .. } => "ssh-rsa",
            other => other.as_str(),
        };
        types.iter().any(|t| t == name)
    };
    let (mut first, rest): (Vec<Algorithm>, Vec<Algorithm>) =
        HOST_KEY_ALGORITHMS.iter().cloned().partition(is_known);
    if first.is_empty() {
        return Cow::Borrowed(&HOST_KEY_ALGORITHMS);
    }
    first.extend(rest);
    Cow::Owned(first)
}

/// The `known_hosts` line that trusts `key` for `host` on `port`: plain,
/// `[host]:port` when the port isn't 22.
pub fn line_for(host: &str, port: u16, key: &PublicKey) -> Option<String> {
    let (key_type, encoded) = openssh_parts(key)?;
    let mut file = KnownHosts::default();
    file.add_key(host, port, &key_type, &encoded).ok()?;
    Some(file.to_string().trim_end().to_owned())
}

#[cfg(test)]
mod tests {
    use russh::keys::PrivateKey;
    use russh::keys::ssh_key::private::Ed25519Keypair;

    use super::*;

    fn key(seed: u8) -> PublicKey {
        PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
            .public_key()
            .clone()
    }

    #[test]
    fn verdicts() {
        let (a, b) = (key(1), key(2));
        let line_a = line_for("10.0.0.5", 2222, &a).unwrap();
        assert!(
            line_a.starts_with("[10.0.0.5]:2222 ssh-ed25519 "),
            "{line_a}"
        );
        let known = KnownHosts::parse(&format!("{line_a}\n"));
        assert_eq!(check(&known, "10.0.0.5", 2222, &a), Verdict::Known);
        assert_eq!(
            check(&known, "10.0.0.5", 2222, &b),
            Verdict::Changed {
                known: vec![fingerprint(&a)]
            }
        );
        // Another port is another host.
        assert_eq!(
            check(&known, "10.0.0.5", 22, &a),
            Verdict::Unknown {
                other_types: vec![]
            }
        );
        let revoked = KnownHosts::parse(&format!(
            "@revoked * {}\n{line_a}\n",
            a.to_openssh().unwrap()
        ));
        assert_eq!(check(&revoked, "10.0.0.5", 2222, &a), Verdict::Revoked);
        // A CA is not a key for the host.
        let ca = KnownHosts::parse(&format!("@cert-authority * {}\n", a.to_openssh().unwrap()));
        assert_eq!(
            check(&ca, "10.0.0.5", 2222, &a),
            Verdict::Unknown {
                other_types: vec![]
            }
        );
    }

    #[test]
    fn hashed_entries_are_read() {
        use base64ct::{Base64, Encoding};
        use hmac::{Hmac, Mac};
        let a = key(3);
        let (key_type, encoded) = openssh_parts(&a).unwrap();
        // What `ssh-keygen -H` writes for `example.com`, with a fixed salt.
        let salt = [7u8; 20];
        let mut mac = Hmac::<sha1::Sha1>::new_from_slice(&salt).unwrap();
        mac.update(b"example.com");
        let hash = mac.finalize().into_bytes();
        let line = format!(
            "|1|{}|{} {key_type} {encoded}\n",
            Base64::encode_string(&salt),
            Base64::encode_string(&hash)
        );
        let known = KnownHosts::parse(&line);
        assert_eq!(check(&known, "example.com", 22, &a), Verdict::Known);
        assert_eq!(check(&known, "EXAMPLE.com", 22, &a), Verdict::Known);
        assert_eq!(
            check(&known, "other.com", 22, &a),
            Verdict::Unknown {
                other_types: vec![]
            }
        );
    }

    #[test]
    fn other_types_are_named_and_asked_for_first() {
        let rsa = include_str!("../../sshkm-core/src/keys/testdata/rsa_pem.pub");
        let rsa = rsa.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
        let known = KnownHosts::parse(&format!("example.com {rsa}\n"));
        let a = key(4);
        assert_eq!(
            check(&known, "example.com", 22, &a),
            Verdict::Unknown {
                other_types: vec!["ssh-rsa".into()]
            }
        );
        let order = algorithms_for(&known, "example.com", 22);
        assert_eq!(
            order[..3],
            [
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha512)
                },
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha256)
                },
                Algorithm::Ed25519,
            ]
        );
    }

    #[test]
    fn the_default_order_has_no_sha1_rsa() {
        let order = algorithms_for(&KnownHosts::default(), "x", 22);
        assert_eq!(order[0], Algorithm::Ed25519);
        assert!(!order.contains(&Algorithm::Rsa { hash: None }));
        assert!(!order.iter().any(|a| a.as_str() == "ssh-dss"));
        let ed = key(5);
        let known = KnownHosts::parse(&line_for("x", 22, &ed).unwrap());
        let order = algorithms_for(&known, "x", 22);
        assert_eq!(order[0], Algorithm::Ed25519);
        assert_eq!(order.len(), HOST_KEY_ALGORITHMS.len());
    }
}
