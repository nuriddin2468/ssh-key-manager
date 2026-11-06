//! Network checks for the Tools page: how fast a host's SSH port answers and
//! what its server says ([`ssh_ping`]), whether a TCP port is open
//! ([`port_check`]), a name's DNS records ([`dns`]) and a server's TLS
//! certificate ([`tls`]).
//!
//! Every call blocks, gives up after a timeout and talks only to the host
//! the user named (DNS: to the computer's own DNS servers). Nothing here runs
//! by itself; the UI calls it when the user asks. No shell commands.

mod banner;
pub mod dns;
mod tcp;
pub mod tls;
mod x509;

use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use serde::Serialize;

pub use self::banner::SshBanner;
pub use self::tcp::{PortCheck, SshPing, port_check, ssh_ping};
pub use self::x509::CertSummary;
use crate::{Error, Result};

/// The longest timeout a caller may ask for.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(30);

/// What became of a TCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum PortState {
    /// Something accepted the connection.
    Open,
    /// The host answered that nothing listens on the port.
    Closed,
    /// No answer before the timeout: a firewall drops the packets, or the
    /// host is down.
    NoAnswer,
    /// The network or the host can't be reached from this computer.
    Unreachable,
    /// The name has no address.
    NoAddress,
}

/// A host as the user typed it: a name, or an IP address with or without
/// brackets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Host {
    /// Lowercase ASCII (IDNA), without a trailing dot.
    Name(String),
    Ip(IpAddr),
}

impl Host {
    pub(crate) fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        if input.is_empty() {
            return Err(Error::invalid("enter a host"));
        }
        let bare = input
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(input);
        if let Ok(ip) = bare.parse::<IpAddr>() {
            return Ok(Self::Ip(ip));
        }
        match url::Host::parse(input) {
            Ok(url::Host::Domain(name)) => {
                let name = name.strip_suffix('.').unwrap_or(&name).to_owned();
                if is_dns_name(&name) {
                    Ok(Self::Name(name))
                } else {
                    Err(Error::invalid("not a host name"))
                }
            }
            Ok(url::Host::Ipv4(ip)) => Ok(Self::Ip(ip.into())),
            Ok(url::Host::Ipv6(ip)) => Ok(Self::Ip(ip.into())),
            Err(_) => Err(Error::invalid("not a host name or address")),
        }
    }
}

/// Labels of 1 to 63 letters, digits, `-` and `_`, 253 characters at most.
fn is_dns_name(name: &str) -> bool {
    name.len() <= 253
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// Checks a timeout the UI sent.
pub(crate) fn check_timeout(timeout: Duration) -> Result<()> {
    if timeout.is_zero() || timeout > MAX_TIMEOUT {
        return Err(Error::invalid("timeout must be up to 30 seconds"));
    }
    Ok(())
}

/// The addresses of `host`, in the order the system resolver prefers (the
/// hosts file, then DNS, as `ssh` sees them), without repeats.
///
/// The resolver has no timeout of its own: a lookup still running after
/// `timeout` is left to finish on its thread.
pub(crate) fn resolve(
    host: &Host,
    port: u16,
    timeout: Duration,
) -> std::result::Result<Vec<SocketAddr>, String> {
    let name = match host {
        Host::Ip(ip) => return Ok(vec![SocketAddr::new(*ip, port)]),
        Host::Name(name) => name.clone(),
    };
    let (send, receive) = mpsc::channel();
    thread::spawn(move || {
        let _ = send.send((name.as_str(), port).to_socket_addrs().map(Vec::from_iter));
    });
    match receive.recv_timeout(timeout) {
        Ok(Ok(found)) => {
            let mut addresses: Vec<SocketAddr> = Vec::new();
            for address in found {
                if !addresses.contains(&address) {
                    addresses.push(address);
                }
            }
            Ok(addresses)
        }
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err("no answer".to_owned()),
    }
}

/// What a failed connect says about the port.
pub(crate) fn classify(error: &io::Error) -> PortState {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => PortState::Closed,
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => PortState::NoAnswer,
        _ => PortState::Unreachable,
    }
}

/// Milliseconds, for the UI.
pub(crate) fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

/// Certificates for the tests, made with `LibreSSL`'s `openssl req` and
/// `openssl x509 -req`: a P-256 CA, a P-256 leaf for `localhost` and
/// `127.0.0.1` that it signed (with its PKCS #8 key), and an unrelated
/// RSA 2048 root. Valid from 2026-11-06 for 20 years.
#[cfg(test)]
pub(crate) mod fixtures {
    pub(crate) const CA: &[u8] = include_bytes!("testdata/ca.der");
    pub(crate) const LEAF: &[u8] = include_bytes!("testdata/leaf.der");
    pub(crate) const KEY: &[u8] = include_bytes!("testdata/leaf-key.der");
    pub(crate) const OTHER: &[u8] = include_bytes!("testdata/other.der");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_parse_as_names_or_addresses() {
        assert_eq!(
            Host::parse(" Example.COM. ").unwrap(),
            Host::Name("example.com".into())
        );
        assert_eq!(
            Host::parse("_dmarc.example.com").unwrap(),
            Host::Name("_dmarc.example.com".into())
        );
        assert_eq!(
            Host::parse("bücher.example").unwrap(),
            Host::Name("xn--bcher-kva.example".into())
        );
        assert_eq!(
            Host::parse("192.168.1.20").unwrap(),
            Host::Ip("192.168.1.20".parse().unwrap())
        );
        assert_eq!(
            Host::parse("[::1]").unwrap(),
            Host::Ip("::1".parse().unwrap())
        );
        assert_eq!(
            Host::parse("::1").unwrap(),
            Host::Ip("::1".parse().unwrap())
        );
        for bad in ["", "  ", "a b", "-bad.example", "a..b", "host/path", "x@y"] {
            assert!(Host::parse(bad).is_err(), "{bad:?}");
        }
        assert!(Host::parse(&format!("{}.com", "a".repeat(64))).is_err());
    }

    #[test]
    fn timeouts_are_bounded() {
        assert!(check_timeout(Duration::from_secs(5)).is_ok());
        assert!(check_timeout(Duration::ZERO).is_err());
        assert!(check_timeout(Duration::from_secs(31)).is_err());
    }

    #[test]
    fn addresses_resolve_without_a_lookup() {
        let host = Host::parse("127.0.0.1").unwrap();
        assert_eq!(
            resolve(&host, 22, Duration::from_secs(1)).unwrap(),
            vec!["127.0.0.1:22".parse().unwrap()]
        );
    }

    #[test]
    fn connect_errors_say_what_happened() {
        let error = |kind| io::Error::new(kind, "x");
        assert_eq!(
            classify(&error(io::ErrorKind::ConnectionRefused)),
            PortState::Closed
        );
        assert_eq!(
            classify(&error(io::ErrorKind::TimedOut)),
            PortState::NoAnswer
        );
        assert_eq!(
            classify(&error(io::ErrorKind::HostUnreachable)),
            PortState::Unreachable
        );
    }
}
