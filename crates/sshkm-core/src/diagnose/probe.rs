//! A quick check that a TCP port answers: whether a server is there at all,
//! apart from SSH.

use std::io::ErrorKind;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde::Serialize;

/// The most addresses of a name that are tried.
const MAX_ADDRESSES: usize = 3;

/// What connecting to a port found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct PortProbe {
    pub host: String,
    pub port: u16,
    /// The addresses the name resolved to, as tried.
    pub addresses: Vec<String>,
    pub outcome: ProbeOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum ProbeOutcome {
    /// Something accepted the connection.
    Open,
    /// The computer answered that nothing listens there.
    Refused,
    /// No answer in time.
    TimedOut,
    /// No way there from this computer.
    Unreachable,
    /// The name has no address (DNS and the hosts file).
    NotResolved,
    /// Another error.
    Failed,
}

/// Connects to `host:port`, trying each of its first addresses for at most
/// `timeout`, and closes the connection at once: nothing is sent.
pub fn probe(host: &str, port: u16, timeout: Duration) -> PortProbe {
    let resolved: Vec<SocketAddr> = match (host, port).to_socket_addrs() {
        Ok(addresses) => addresses.take(MAX_ADDRESSES).collect(),
        Err(_) => Vec::new(),
    };
    let mut outcome = ProbeOutcome::NotResolved;
    for address in &resolved {
        let tried = match TcpStream::connect_timeout(address, timeout) {
            Ok(_) => ProbeOutcome::Open,
            Err(error) => failure(&error),
        };
        // An open address wins, then the most telling failure.
        if rank(tried) < rank(outcome) {
            outcome = tried;
        }
        if outcome == ProbeOutcome::Open {
            break;
        }
    }
    PortProbe {
        host: host.to_owned(),
        port,
        addresses: resolved.iter().map(|a| a.ip().to_string()).collect(),
        outcome,
    }
}

fn failure(error: &std::io::Error) -> ProbeOutcome {
    match error.kind() {
        ErrorKind::ConnectionRefused => ProbeOutcome::Refused,
        ErrorKind::TimedOut | ErrorKind::WouldBlock => ProbeOutcome::TimedOut,
        ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable | ErrorKind::NetworkDown => {
            ProbeOutcome::Unreachable
        }
        _ => ProbeOutcome::Failed,
    }
}

const fn rank(outcome: ProbeOutcome) -> u8 {
    match outcome {
        ProbeOutcome::Open => 0,
        ProbeOutcome::Refused => 1,
        ProbeOutcome::TimedOut => 2,
        ProbeOutcome::Unreachable => 3,
        ProbeOutcome::Failed => 4,
        ProbeOutcome::NotResolved => 5,
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;

    #[test]
    fn open_and_refused_ports() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let open = probe("127.0.0.1", port, Duration::from_secs(2));
        assert_eq!(open.outcome, ProbeOutcome::Open);
        assert_eq!(open.addresses, ["127.0.0.1"]);

        drop(listener);
        let closed = probe("127.0.0.1", port, Duration::from_secs(2));
        assert_eq!(closed.outcome, ProbeOutcome::Refused);
    }

    #[test]
    fn names_without_an_address() {
        // `.invalid` never resolves (RFC 6761).
        let probe = probe("sshkm-probe.invalid", 22, Duration::from_secs(1));
        assert_eq!(probe.outcome, ProbeOutcome::NotResolved);
        assert_eq!(probe.addresses, Vec::<String>::new());
    }
}
