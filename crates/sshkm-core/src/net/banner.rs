//! The identification line an SSH server sends first (RFC 4253 §4.2):
//! `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13`.

use std::io::{self, Read};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use serde::Serialize;

/// OpenSSH before this version (8.0, April 2019) counts as very old.
const OLD_OPENSSH: (u32, u32) = (8, 0);
/// The longest version line RFC 4253 allows, with its `\r\n`.
const MAX_LINE: usize = 255;
/// Lines a server may send before its version line, read at most.
const MAX_OTHER_LINES: usize = 20;

/// What an SSH server says about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct SshBanner {
    /// The line as the server sent it, without `\r\n`; anything but
    /// printable ASCII shows as `?`.
    pub line: String,
    /// `2.0`, or `1.99` for a server that also speaks the old protocol 1.
    pub protocol: String,
    /// `OpenSSH_9.6p1`, `dropbear_2022.83`, …
    pub software: String,
    /// What follows the software, often the system's package version.
    pub comment: Option<String>,
    /// OpenSSH's version (`9.6p1`) when the server is OpenSSH.
    pub openssh: Option<String>,
    /// OpenSSH older than 8.0, or a server that speaks only protocol 1.
    pub outdated: bool,
}

/// What came back from the port, as far as SSH goes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Greeting {
    Ssh(SshBanner),
    /// Something else spoke first: its first line.
    Other(String),
    /// Nothing before the timeout, or the server closed the connection.
    Silent,
}

/// Reads the server's greeting, for `timeout` at most.
pub(crate) fn read_greeting(stream: &TcpStream, timeout: Duration) -> Greeting {
    scan(&mut Deadline {
        stream,
        until: Instant::now() + timeout,
    })
}

/// Reads lines until the version line, skipping the other lines a server may
/// send first.
fn scan(reader: &mut impl Read) -> Greeting {
    let mut buffer: Vec<u8> = Vec::new();
    let mut first_other: Option<String> = None;
    let mut others = 0;
    let mut chunk = [0u8; 512];
    loop {
        while let Some(end) = buffer.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = buffer.drain(..=end).collect();
            let line = printable(&line[..end]);
            if line.starts_with("SSH-") {
                return parse(&line).map_or(Greeting::Other(line), Greeting::Ssh);
            }
            others += 1;
            first_other.get_or_insert(line);
            if others > MAX_OTHER_LINES {
                break;
            }
        }
        if others > MAX_OTHER_LINES || buffer.len() > MAX_LINE {
            // No version line in what a server may send first.
            let line = printable(&buffer[..buffer.len().min(MAX_LINE)]);
            return Greeting::Other(first_other.unwrap_or(line));
        }
        match reader.read(&mut chunk) {
            Ok(0) | Err(_) => {
                return match first_other {
                    Some(line) => Greeting::Other(line),
                    None if !buffer.is_empty() => Greeting::Other(printable(&buffer)),
                    None => Greeting::Silent,
                };
            }
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
        }
    }
}

/// Parses `SSH-protoversion-softwareversion SP comments`.
pub(crate) fn parse(line: &str) -> Option<SshBanner> {
    let rest = line.strip_prefix("SSH-")?;
    let (protocol, rest) = rest.split_once('-')?;
    let (software, comment) = match rest.split_once(' ') {
        Some((software, comment)) => (software, Some(comment.trim()).filter(|c| !c.is_empty())),
        None => (rest, None),
    };
    if protocol.is_empty() || software.is_empty() {
        return None;
    }
    let openssh = software
        .strip_prefix("OpenSSH_for_Windows_")
        .or_else(|| software.strip_prefix("OpenSSH_"))
        .filter(|version| version.starts_with(|c: char| c.is_ascii_digit()));
    let old_openssh = openssh
        .and_then(major_minor)
        .is_some_and(|version| version < OLD_OPENSSH);
    let protocol_1_only = protocol.starts_with("1.") && protocol != "1.99";
    Some(SshBanner {
        line: line.to_owned(),
        protocol: protocol.to_owned(),
        software: software.to_owned(),
        comment: comment.map(str::to_owned),
        openssh: openssh.map(str::to_owned),
        outdated: old_openssh || protocol_1_only,
    })
}

/// `9.6p1` → (9, 6).
fn major_minor(version: &str) -> Option<(u32, u32)> {
    let (major, rest) = version.split_once('.')?;
    let minor: String = rest.chars().take_while(char::is_ascii_digit).collect();
    Some((major.parse().ok()?, minor.parse().ok()?))
}

/// Printable ASCII; `\r` at the end dropped, anything else unprintable as `?`.
fn printable(bytes: &[u8]) -> String {
    let bytes = bytes.strip_suffix(b"\r").unwrap_or(bytes);
    bytes
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                char::from(b)
            } else {
                '?'
            }
        })
        .collect()
}

/// Reads from a stream until a point in time, whatever the server trickles.
struct Deadline<'a> {
    stream: &'a TcpStream,
    until: Instant,
}

impl Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.stream.set_read_timeout(Some(left))?;
        let mut stream = self.stream;
        stream.read(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banners_are_parsed() {
        let banner = parse("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13").unwrap();
        assert_eq!(banner.protocol, "2.0");
        assert_eq!(banner.software, "OpenSSH_9.6p1");
        assert_eq!(banner.comment.as_deref(), Some("Ubuntu-3ubuntu13"));
        assert_eq!(banner.openssh.as_deref(), Some("9.6p1"));
        assert!(!banner.outdated);

        let windows = parse("SSH-2.0-OpenSSH_for_Windows_9.5").unwrap();
        assert_eq!(windows.openssh.as_deref(), Some("9.5"));
        assert_eq!(windows.comment, None);

        let dropbear = parse("SSH-2.0-dropbear_2022.83").unwrap();
        assert_eq!(dropbear.openssh, None);
        assert!(!dropbear.outdated);

        assert!(parse("SSH-2.0-").is_none());
        assert!(parse("HTTP/1.1 400").is_none());
    }

    #[test]
    fn very_old_servers_are_flagged() {
        assert!(parse("SSH-2.0-OpenSSH_7.4").unwrap().outdated);
        assert!(
            parse("SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu7")
                .unwrap()
                .outdated
        );
        assert!(!parse("SSH-2.0-OpenSSH_8.0").unwrap().outdated);
        assert!(!parse("SSH-2.0-OpenSSH_10.0p2").unwrap().outdated);
        // Protocol 1 only; 1.99 also speaks 2.
        assert!(parse("SSH-1.5-Cisco-1.25").unwrap().outdated);
        assert!(!parse("SSH-1.99-OpenSSH_9.0").unwrap().outdated);
    }

    #[test]
    fn the_version_line_may_follow_other_lines() {
        let mut input: &[u8] = b"Welcome!\r\nNo bots.\r\nSSH-2.0-OpenSSH_9.9\r\nrest";
        let Greeting::Ssh(banner) = scan(&mut input) else {
            panic!("no banner");
        };
        assert_eq!(banner.line, "SSH-2.0-OpenSSH_9.9");
    }

    #[test]
    fn other_protocols_and_silence_are_told_apart() {
        let mut http: &[u8] = b"HTTP/1.1 400 Bad Request\r\n\r\n";
        assert_eq!(
            scan(&mut http),
            Greeting::Other("HTTP/1.1 400 Bad Request".into())
        );
        let mut nothing: &[u8] = b"";
        assert_eq!(scan(&mut nothing), Greeting::Silent);
        let mut binary: &[u8] = &[0x16, 0x03, 0x01, 0xff, b'\n'];
        assert_eq!(scan(&mut binary), Greeting::Other("????".into()));
        let mut endless: &[u8] = &[b'x'; 4000];
        assert!(matches!(scan(&mut endless), Greeting::Other(line) if line.len() == MAX_LINE));
    }
}
