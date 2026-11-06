//! TCP connections: whether a port is open, and how long a host's SSH port
//! takes to answer.

use std::io;
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

use super::banner::{self, Greeting, SshBanner};
use super::{Host, PortState, check_timeout, classify, millis, resolve};
use crate::{Error, Result};

/// Addresses of a name tried, at most, before giving up.
const MAX_ADDRESSES: usize = 4;
/// The pause between two samples of a ping.
const INTERVAL: Duration = Duration::from_millis(200);
pub const MAX_SAMPLES: u8 = 10;

/// Whether a TCP port takes connections.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct PortCheck {
    pub state: PortState,
    /// The address that took the connection, or the first one tried.
    pub address: Option<String>,
    /// Every address of the name, in the order the resolver gave them.
    pub addresses: Vec<String>,
    /// How long connecting took.
    pub millis: Option<f64>,
    /// The system's words for a failure.
    pub message: Option<String>,
}

/// TCP connection times to a host's port and what its SSH server says.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct SshPing {
    /// What became of the first connection. Only after it was `open` are
    /// more samples taken.
    pub state: PortState,
    pub address: Option<String>,
    pub addresses: Vec<String>,
    pub message: Option<String>,
    /// Milliseconds per attempt; `None` where it failed.
    pub samples: Vec<Option<f64>>,
    pub min: Option<f64>,
    pub avg: Option<f64>,
    pub max: Option<f64>,
    pub lost: u32,
    /// The server's identification line, if it sent one.
    pub banner: Option<SshBanner>,
    /// What spoke instead, when the port isn't SSH: its first line.
    pub other: Option<String>,
}

/// Connects to `host:port` once, trying each of the name's addresses until
/// one takes the connection.
pub fn port_check(host: &str, port: u16, timeout: Duration) -> Result<PortCheck> {
    let host = Host::parse(host)?;
    check_port(port)?;
    check_timeout(timeout)?;
    let (addresses, failure) = match resolve(&host, port, timeout) {
        Ok(found) if !found.is_empty() => (found, None),
        Ok(_) => (Vec::new(), Some("no address".to_owned())),
        Err(message) => (Vec::new(), Some(message)),
    };
    let listed = addresses.iter().map(|a| a.ip().to_string()).collect();
    if let Some(message) = failure {
        return Ok(PortCheck {
            state: PortState::NoAddress,
            address: None,
            addresses: listed,
            millis: None,
            message: Some(message),
        });
    }
    let attempt = connect_any(&addresses, timeout);
    Ok(PortCheck {
        state: attempt.state,
        address: Some(attempt.address.ip().to_string()),
        addresses: listed,
        millis: attempt.connected.as_ref().map(|(_, took)| millis(*took)),
        message: attempt.error.map(|e| e.to_string()),
    })
}

/// Connects to `host:port` `samples` times (1 to 10), timing each
/// connection, and reads the SSH server's identification line on the first.
/// Each connection is closed at once, before anything is sent.
pub fn ssh_ping(host: &str, port: u16, samples: u8, timeout: Duration) -> Result<SshPing> {
    let host = Host::parse(host)?;
    check_port(port)?;
    check_timeout(timeout)?;
    if !(1..=MAX_SAMPLES).contains(&samples) {
        return Err(Error::invalid("samples must be 1 to 10"));
    }
    let mut ping = SshPing {
        state: PortState::NoAddress,
        address: None,
        addresses: Vec::new(),
        message: None,
        samples: Vec::new(),
        min: None,
        avg: None,
        max: None,
        lost: 0,
        banner: None,
        other: None,
    };
    let addresses = match resolve(&host, port, timeout) {
        Ok(found) if !found.is_empty() => found,
        Ok(_) => {
            ping.message = Some("no address".to_owned());
            return Ok(ping);
        }
        Err(message) => {
            ping.message = Some(message);
            return Ok(ping);
        }
    };
    ping.addresses = addresses.iter().map(|a| a.ip().to_string()).collect();

    let first = connect_any(&addresses, timeout);
    ping.state = first.state;
    ping.address = Some(first.address.ip().to_string());
    ping.message = first.error.map(|e| e.to_string());
    let Some((stream, took)) = first.connected else {
        ping.samples.push(None);
        ping.lost = 1;
        return Ok(ping);
    };
    ping.samples.push(Some(millis(took)));
    match banner::read_greeting(&stream, timeout) {
        Greeting::Ssh(banner) => ping.banner = Some(banner),
        Greeting::Other(line) => ping.other = Some(line),
        Greeting::Silent => {}
    }
    let _ = stream.shutdown(Shutdown::Both);
    drop(stream);

    for _ in 1..samples {
        thread::sleep(INTERVAL);
        ping.samples
            .push(time_connect(&first.address, timeout).ok());
    }
    let times: Vec<f64> = ping.samples.iter().flatten().copied().collect();
    ping.lost = u32::try_from(ping.samples.len() - times.len()).unwrap_or(u32::MAX);
    ping.min = times.iter().copied().reduce(f64::min);
    ping.max = times.iter().copied().reduce(f64::max);
    #[allow(clippy::cast_precision_loss)]
    let avg = times.iter().sum::<f64>() / times.len() as f64;
    ping.avg = Some(avg);
    Ok(ping)
}

pub(super) fn check_port(port: u16) -> Result<()> {
    if port == 0 {
        return Err(Error::invalid("port must be 1 to 65535"));
    }
    Ok(())
}

/// One connection, closed at once; how long it took.
fn time_connect(address: &SocketAddr, timeout: Duration) -> io::Result<f64> {
    let start = Instant::now();
    let stream = TcpStream::connect_timeout(address, timeout)?;
    let took = start.elapsed();
    let _ = stream.shutdown(Shutdown::Both);
    Ok(millis(took))
}

pub(super) struct Attempt {
    pub(super) state: PortState,
    /// The address that took the connection, or else the first.
    pub(super) address: SocketAddr,
    pub(super) connected: Option<(TcpStream, Duration)>,
    /// Why the first address failed.
    pub(super) error: Option<io::Error>,
}

/// Tries the addresses in order, as `ssh` does, until one connects.
pub(super) fn connect_any(addresses: &[SocketAddr], timeout: Duration) -> Attempt {
    let mut first_failure: Option<(PortState, SocketAddr, io::Error)> = None;
    for address in addresses.iter().take(MAX_ADDRESSES) {
        let start = Instant::now();
        match TcpStream::connect_timeout(address, timeout) {
            Ok(stream) => {
                return Attempt {
                    state: PortState::Open,
                    address: *address,
                    connected: Some((stream, start.elapsed())),
                    error: None,
                };
            }
            Err(error) => {
                if first_failure.is_none() {
                    first_failure = Some((classify(&error), *address, error));
                }
            }
        }
    }
    let (state, address, error) = first_failure.expect("at least one address");
    Attempt {
        state,
        address,
        connected: None,
        error: Some(error),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::TcpListener;

    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(5);

    /// A server on a loopback port that greets each of `connections` with
    /// `greeting`.
    fn server(greeting: &'static [u8], connections: usize) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for stream in listener.incoming().take(connections) {
                let mut stream = stream.unwrap();
                let _ = stream.write_all(greeting);
            }
        });
        port
    }

    /// A port nothing listens on.
    fn closed_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    #[test]
    fn open_and_closed_ports_are_told_apart() {
        let port = server(b"", 1);
        let open = port_check("127.0.0.1", port, TIMEOUT).unwrap();
        assert_eq!(open.state, PortState::Open);
        assert_eq!(open.address.as_deref(), Some("127.0.0.1"));
        assert!(open.millis.is_some());
        assert_eq!(open.message, None);

        let closed = port_check("127.0.0.1", closed_port(), TIMEOUT).unwrap();
        assert_eq!(closed.state, PortState::Closed);
        assert!(closed.millis.is_none());
        assert!(closed.message.is_some());
    }

    #[test]
    fn bad_requests_are_refused() {
        assert!(port_check("127.0.0.1", 0, TIMEOUT).is_err());
        assert!(port_check("not a host", 22, TIMEOUT).is_err());
        assert!(port_check("127.0.0.1", 22, Duration::from_secs(60)).is_err());
        assert!(ssh_ping("127.0.0.1", 22, 0, TIMEOUT).is_err());
        assert!(ssh_ping("127.0.0.1", 22, 11, TIMEOUT).is_err());
    }

    #[test]
    fn a_ping_times_every_sample_and_reads_the_banner() {
        let port = server(b"SSH-2.0-OpenSSH_7.4\r\n", 3);
        let ping = ssh_ping("127.0.0.1", port, 3, TIMEOUT).unwrap();
        assert_eq!(ping.state, PortState::Open);
        assert_eq!(ping.samples.len(), 3);
        assert_eq!(ping.lost, 0);
        let (min, avg, max) = (ping.min.unwrap(), ping.avg.unwrap(), ping.max.unwrap());
        assert!(min <= avg && avg <= max);
        let banner = ping.banner.unwrap();
        assert_eq!(banner.openssh.as_deref(), Some("7.4"));
        assert!(banner.outdated);
        assert_eq!(ping.other, None);
    }

    #[test]
    fn a_ping_says_when_the_port_is_not_ssh() {
        let port = server(b"HTTP/1.1 400 Bad Request\r\n\r\n", 1);
        let ping = ssh_ping("127.0.0.1", port, 1, TIMEOUT).unwrap();
        assert_eq!(ping.banner, None);
        assert_eq!(ping.other.as_deref(), Some("HTTP/1.1 400 Bad Request"));
    }

    #[test]
    fn a_silent_server_times_out_without_a_banner() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let ping = ssh_ping("127.0.0.1", port, 1, Duration::from_millis(300)).unwrap();
        drop(listener);
        assert_eq!(ping.state, PortState::Open);
        assert_eq!((ping.banner, ping.other), (None, None));
    }

    #[test]
    fn a_ping_to_a_closed_port_stops_after_one_try() {
        let ping = ssh_ping("127.0.0.1", closed_port(), 5, TIMEOUT).unwrap();
        assert_eq!(ping.state, PortState::Closed);
        assert_eq!(ping.samples, vec![None]);
        assert_eq!(ping.lost, 1);
        assert_eq!(ping.avg, None);
    }

    #[test]
    fn samples_that_fail_count_as_lost() {
        // The server takes one connection, then goes away.
        let port = server(b"SSH-2.0-OpenSSH_9.9\r\n", 1);
        thread::sleep(Duration::from_millis(50));
        let ping = ssh_ping("127.0.0.1", port, 3, TIMEOUT).unwrap();
        assert_eq!(ping.samples.len(), 3);
        assert!(ping.samples[0].is_some());
        assert_eq!(ping.lost, 2);
    }
}
