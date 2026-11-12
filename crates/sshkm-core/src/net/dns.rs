//! A name's DNS records (A, AAAA, CNAME, MX, TXT), asked of the computer's
//! own DNS servers: those of `/etc/resolv.conf`, or on Windows of the network
//! adapters' settings.
//!
//! The system resolver gives only addresses, and the hosts file's before
//! DNS's, so this asks the servers directly: over UDP, again over TCP when
//! the answer didn't fit, with a random query id. An answer counts only if
//! it comes from the server asked and repeats the question asked.

use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};
use serde::Serialize;

use super::{Host, check_timeout};
use crate::{Error, Result};

/// Servers asked, at most, before giving up.
const MAX_SERVERS: usize = 3;
/// The answer size offered over UDP (EDNS), as DNS Flag Day 2020 advises.
const UDP_PAYLOAD: u16 = 1232;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum RecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
}

/// The types a lookup asks for, in this order.
pub const RECORD_TYPES: [RecordType; 5] = [
    RecordType::A,
    RecordType::Aaaa,
    RecordType::Cname,
    RecordType::Mx,
    RecordType::Txt,
];

impl RecordType {
    const fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Cname => 5,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Aaaa => 28,
        }
    }

    const fn from_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::A),
            5 => Some(Self::Cname),
            15 => Some(Self::Mx),
            16 => Some(Self::Txt),
            28 => Some(Self::Aaaa),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct DnsRecord {
    pub kind: RecordType,
    /// The name the record belongs to: the one asked, or a CNAME's target.
    pub name: String,
    /// Seconds the record may be cached.
    pub ttl: u32,
    /// An address, a name, or a TXT record's text (its strings joined).
    pub value: String,
    /// An MX record's preference: lower is tried first.
    pub priority: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum DnsStatus {
    /// The server answered with records.
    Found,
    /// The name exists but has no records of this type.
    NoRecords,
    /// The name doesn't exist (NXDOMAIN).
    NoSuchName,
    /// The server couldn't answer (SERVFAIL).
    ServerFailure,
    /// The server won't answer this computer.
    Refused,
    /// No server answered before the timeout.
    NoAnswer,
    /// Something else went wrong; see the message.
    Failed,
}

/// What the servers said about one record type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct DnsAnswer {
    pub kind: RecordType,
    pub status: DnsStatus,
    /// The records of the answer section: for an A query, the CNAMEs that
    /// lead to the addresses too.
    pub records: Vec<DnsRecord>,
    /// The server that answered (or was asked last).
    pub server: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct DnsReport {
    /// The name asked, in ASCII (IDNA).
    pub name: String,
    /// The servers that could be asked, in order.
    pub servers: Vec<String>,
    /// One answer for each of [`RECORD_TYPES`].
    pub answers: Vec<DnsAnswer>,
}

/// Looks `name` up in the computer's DNS servers; `timeout` for each server.
pub fn lookup(name: &str, timeout: Duration) -> Result<DnsReport> {
    let servers: Vec<SocketAddr> = system_servers()
        .into_iter()
        .map(|ip| SocketAddr::new(ip, 53))
        .collect();
    lookup_with(name, &servers, timeout)
}

/// Looks `name` up in the given servers, asking for every type at once.
pub fn lookup_with(name: &str, servers: &[SocketAddr], timeout: Duration) -> Result<DnsReport> {
    check_timeout(timeout)?;
    let Host::Name(name) = Host::parse(name)? else {
        return Err(Error::invalid("enter a name, not an address"));
    };
    if servers.is_empty() {
        return Err(Error::NotFound("no DNS server is set up".to_owned()));
    }
    let servers = &servers[..servers.len().min(MAX_SERVERS)];
    let answers = thread::scope(|scope| {
        let asking: Vec<_> = RECORD_TYPES
            .iter()
            .map(|&kind| {
                let name = name.as_str();
                (kind, scope.spawn(move || ask(name, kind, servers, timeout)))
            })
            .collect();
        asking
            .into_iter()
            .map(|(kind, thread)| {
                thread.join().unwrap_or_else(|_| DnsAnswer {
                    kind,
                    status: DnsStatus::Failed,
                    records: Vec::new(),
                    server: None,
                    message: Some("lookup failed".to_owned()),
                })
            })
            .collect()
    });
    Ok(DnsReport {
        servers: servers.iter().map(|s| s.ip().to_string()).collect(),
        name,
        answers,
    })
}

/// The computer's DNS servers, in order, without repeats.
pub fn system_servers() -> Vec<IpAddr> {
    #[cfg(unix)]
    {
        std::fs::read_to_string("/etc/resolv.conf")
            .map(|text| parse_resolv_conf(&text))
            .unwrap_or_default()
    }
    #[cfg(windows)]
    {
        windows_servers()
    }
    #[cfg(not(any(unix, windows)))]
    {
        Vec::new()
    }
}

/// The `nameserver` lines of `resolv.conf`. Link-local addresses with a
/// zone (`fe80::1%en0`) are left out.
#[cfg_attr(not(unix), allow(dead_code))]
fn parse_resolv_conf(text: &str) -> Vec<IpAddr> {
    let mut servers = Vec::new();
    for line in text.lines() {
        let line = line.split(['#', ';']).next().unwrap_or_default();
        let mut words = line.split_whitespace();
        if words.next() != Some("nameserver") {
            continue;
        }
        if let Some(ip) = words.next().and_then(|w| w.parse::<IpAddr>().ok())
            && !servers.contains(&ip)
        {
            servers.push(ip);
        }
    }
    servers
}

/// The servers set for the TCP/IP stacks and each network adapter: set by
/// hand (`NameServer`) or else by DHCP (`DhcpNameServer`).
#[cfg(windows)]
fn windows_servers() -> Vec<IpAddr> {
    use windows_registry::{Key, LOCAL_MACHINE};

    fn add(key: &Key, servers: &mut Vec<IpAddr>) {
        for value in ["NameServer", "DhcpNameServer"] {
            let Ok(text) = key.get_string(value) else {
                continue;
            };
            let found: Vec<IpAddr> = text
                .split([' ', ','])
                .filter_map(|word| word.trim().parse().ok())
                .collect();
            if !found.is_empty() {
                for ip in found {
                    if !servers.contains(&ip) {
                        servers.push(ip);
                    }
                }
                return;
            }
        }
    }

    let mut servers = Vec::new();
    for stack in [
        r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
        r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
    ] {
        let Ok(parameters) = LOCAL_MACHINE.open(stack) else {
            continue;
        };
        add(&parameters, &mut servers);
        let Ok(interfaces) = parameters.open("Interfaces") else {
            continue;
        };
        let Ok(names) = interfaces.keys() else {
            continue;
        };
        for name in names {
            if let Ok(interface) = interfaces.open(&name) {
                add(&interface, &mut servers);
            }
        }
    }
    servers
}

/// Asks the servers in turn until one answers, for one record type.
fn ask(name: &str, kind: RecordType, servers: &[SocketAddr], timeout: Duration) -> DnsAnswer {
    let mut answer = DnsAnswer {
        kind,
        status: DnsStatus::NoAnswer,
        records: Vec::new(),
        server: None,
        message: None,
    };
    for server in servers {
        answer.server = Some(server.ip().to_string());
        let id = u16::try_from(OsRng.next_u32() & 0xffff).unwrap_or(0);
        let query = build_query(id, name, kind.code());
        let parsed = exchange_udp(&query, *server, timeout)
            .and_then(|response| parse_response(&response, id, name, kind.code()))
            .and_then(|parsed| {
                if parsed.truncated {
                    let response = exchange_tcp(&query, *server, timeout)?;
                    parse_response(&response, id, name, kind.code())
                } else {
                    Ok(parsed)
                }
            });
        match parsed {
            Ok(parsed) => {
                answer.message = None;
                answer.status = match parsed.rcode {
                    0 if parsed.records.is_empty() => DnsStatus::NoRecords,
                    0 => DnsStatus::Found,
                    3 => DnsStatus::NoSuchName,
                    2 => DnsStatus::ServerFailure,
                    5 => DnsStatus::Refused,
                    code => {
                        answer.message = Some(format!("response code {code}"));
                        DnsStatus::Failed
                    }
                };
                answer.records = parsed.records;
                // Another server may know better.
                if !matches!(
                    answer.status,
                    DnsStatus::ServerFailure | DnsStatus::Refused | DnsStatus::Failed
                ) {
                    return answer;
                }
            }
            Err(Problem::Timeout) => {
                answer.status = DnsStatus::NoAnswer;
                answer.message = None;
            }
            Err(Problem::Failed(message)) => {
                answer.status = DnsStatus::Failed;
                answer.message = Some(message);
            }
        }
    }
    answer
}

#[derive(Debug, PartialEq, Eq)]
enum Problem {
    Timeout,
    Failed(String),
}

impl From<io::Error> for Problem {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => Self::Timeout,
            _ => Self::Failed(error.to_string()),
        }
    }
}

fn bad(what: &str) -> Problem {
    Problem::Failed(format!("malformed answer: {what}"))
}

fn exchange_udp(
    query: &[u8],
    server: SocketAddr,
    timeout: Duration,
) -> std::result::Result<Vec<u8>, Problem> {
    let local: SocketAddr = if server.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(local)?;
    // A connected socket takes datagrams from the server only.
    socket.connect(server)?;
    socket.send(query)?;
    let until = Instant::now() + timeout;
    let mut buffer = vec![0; 65_535];
    loop {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Problem::Timeout);
        }
        socket.set_read_timeout(Some(left))?;
        let n = socket.recv(&mut buffer)?;
        // A late answer to an earlier query is skipped.
        if buffer[..n].get(..2) == query.get(..2) {
            return Ok(buffer[..n].to_vec());
        }
    }
}

fn exchange_tcp(
    query: &[u8],
    server: SocketAddr,
    timeout: Duration,
) -> std::result::Result<Vec<u8>, Problem> {
    let mut stream = TcpStream::connect_timeout(&server, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let length = u16::try_from(query.len()).map_err(|_| bad("query too long"))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(query)?;
    let mut length = [0; 2];
    stream.read_exact(&mut length)?;
    let mut response = vec![0; usize::from(u16::from_be_bytes(length))];
    stream.read_exact(&mut response)?;
    Ok(response)
}

/// A recursive query for one name and type, with an EDNS record.
fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut query = Vec::with_capacity(32 + name.len());
    query.extend_from_slice(&id.to_be_bytes());
    // Recursion desired; one question and one additional (EDNS) record.
    query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1]);
    for label in name.split('.') {
        // Labels are checked to be 1 to 63 bytes (`Host::parse`).
        query.push(u8::try_from(label.len()).unwrap_or(63));
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    // OPT: root name, type 41, the UDP payload size as its class.
    query.extend_from_slice(&[0, 0, 41]);
    query.extend_from_slice(&UDP_PAYLOAD.to_be_bytes());
    query.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    query
}

#[derive(Debug)]
struct Parsed {
    rcode: u8,
    truncated: bool,
    records: Vec<DnsRecord>,
}

fn parse_response(
    message: &[u8],
    id: u16,
    name: &str,
    qtype: u16,
) -> std::result::Result<Parsed, Problem> {
    let mut reader = Reader { message, pos: 0 };
    if reader.u16()? != id {
        return Err(bad("another query's id"));
    }
    let flags = reader.u16()?;
    if flags & 0x8000 == 0 {
        return Err(bad("not a response"));
    }
    let truncated = flags & 0x0200 != 0;
    let rcode = u8::try_from(flags & 0x000f).unwrap_or(0);
    let questions = reader.u16()?;
    let records = reader.u16()?;
    reader.u16()?;
    reader.u16()?;
    if questions != 1 {
        return Err(bad("not one question"));
    }
    let asked = reader.name()?;
    let asked_type = reader.u16()?;
    reader.u16()?;
    if !asked.eq_ignore_ascii_case(name) || asked_type != qtype {
        return Err(bad("another question"));
    }
    let mut found = Vec::new();
    for _ in 0..records {
        let owner = reader.name()?;
        let rtype = reader.u16()?;
        let class = reader.u16()?;
        let ttl = reader.u32()?;
        let length = usize::from(reader.u16()?);
        let start = reader.pos;
        let data = message
            .get(start..start + length)
            .ok_or_else(|| bad("short record"))?;
        let kind = RecordType::from_code(rtype).filter(|_| class == 1);
        let mut priority = None;
        let value = match kind {
            Some(RecordType::A) => <[u8; 4]>::try_from(data)
                .ok()
                .map(|b| Ipv4Addr::from(b).to_string()),
            Some(RecordType::Aaaa) => <[u8; 16]>::try_from(data)
                .ok()
                .map(|b| Ipv6Addr::from(b).to_string()),
            Some(RecordType::Cname) => Some(reader.name_at(start)?.0),
            Some(RecordType::Mx) => {
                let preference = data.get(..2).ok_or_else(|| bad("short MX"))?;
                priority = Some(u16::from_be_bytes([preference[0], preference[1]]));
                Some(reader.name_at(start + 2)?.0)
            }
            Some(RecordType::Txt) => Some(txt(data)?),
            None => None,
        };
        reader.pos = start + length;
        if let (Some(kind), Some(value)) = (kind, value) {
            found.push(DnsRecord {
                kind,
                name: owner,
                ttl,
                value,
                priority,
            });
        }
    }
    Ok(Parsed {
        rcode,
        truncated,
        records: found,
    })
}

/// A TXT record's strings, joined: long SPF and DKIM records are split into
/// strings of 255 bytes that mean one text.
fn txt(data: &[u8]) -> std::result::Result<String, Problem> {
    let mut text = Vec::new();
    let mut rest = data;
    while let Some((&length, tail)) = rest.split_first() {
        let length = usize::from(length);
        let part = tail.get(..length).ok_or_else(|| bad("short TXT"))?;
        text.extend_from_slice(part);
        rest = &tail[length..];
    }
    Ok(String::from_utf8_lossy(&text)
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect())
}

struct Reader<'a> {
    message: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn bytes<const N: usize>(&mut self) -> std::result::Result<[u8; N], Problem> {
        let bytes = self
            .message
            .get(self.pos..self.pos + N)
            .and_then(|b| <[u8; N]>::try_from(b).ok())
            .ok_or_else(|| bad("too short"))?;
        self.pos += N;
        Ok(bytes)
    }

    fn u16(&mut self) -> std::result::Result<u16, Problem> {
        self.bytes().map(u16::from_be_bytes)
    }

    fn u32(&mut self) -> std::result::Result<u32, Problem> {
        self.bytes().map(u32::from_be_bytes)
    }

    fn name(&mut self) -> std::result::Result<String, Problem> {
        let (name, next) = self.name_at(self.pos)?;
        self.pos = next;
        Ok(name)
    }

    /// The name at `pos`, following compression pointers, and where the
    /// bytes after it start.
    fn name_at(&self, mut pos: usize) -> std::result::Result<(String, usize), Problem> {
        let mut labels: Vec<String> = Vec::new();
        let mut next = None;
        let mut length = 0;
        let mut jumps = 0;
        loop {
            let byte = *self.message.get(pos).ok_or_else(|| bad("short name"))?;
            match byte & 0xc0 {
                0x00 if byte == 0 => {
                    let after = next.unwrap_or(pos + 1);
                    let name = if labels.is_empty() {
                        ".".to_owned()
                    } else {
                        labels.join(".")
                    };
                    return Ok((name, after));
                }
                0x00 => {
                    let size = usize::from(byte);
                    let label = self
                        .message
                        .get(pos + 1..pos + 1 + size)
                        .ok_or_else(|| bad("short label"))?;
                    length += size + 1;
                    if length > 255 {
                        return Err(bad("name too long"));
                    }
                    labels.push(escape_label(label));
                    pos += 1 + size;
                }
                0xc0 => {
                    let low = *self
                        .message
                        .get(pos + 1)
                        .ok_or_else(|| bad("short pointer"))?;
                    next.get_or_insert(pos + 2);
                    jumps += 1;
                    if jumps > 32 {
                        return Err(bad("pointer loop"));
                    }
                    pos = (usize::from(byte & 0x3f) << 8) | usize::from(low);
                }
                _ => return Err(bad("label type")),
            }
        }
    }
}

/// A label as text: `\.`, `\\` and `\DDD` for what isn't printable.
fn escape_label(label: &[u8]) -> String {
    let mut text = String::with_capacity(label.len());
    for &b in label {
        match b {
            b'.' | b'\\' => {
                text.push('\\');
                text.push(char::from(b));
            }
            0x21..=0x7e => text.push(char::from(b)),
            _ => {
                let _ = write!(text, "\\{b:03}");
            }
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(5);

    /// The name and type of a query.
    fn question(query: &[u8]) -> (String, u16) {
        let reader = Reader {
            message: query,
            pos: 12,
        };
        let (name, next) = reader.name_at(12).unwrap();
        (name, u16::from_be_bytes([query[next], query[next + 1]]))
    }

    /// An answer to `query` with `rcode`, the question, and `records`
    /// (type, data), each with a pointer to the question's name.
    fn answer(query: &[u8], rcode: u8, truncated: bool, records: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut out = query[..2].to_vec();
        let flags: u16 = 0x8180 | u16::from(rcode) | if truncated { 0x0200 } else { 0 };
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&[0, 1]);
        out.extend_from_slice(&u16::try_from(records.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        // The question, copied up to its type and class.
        let end = 12 + query[12..].iter().position(|&b| b == 0).unwrap() + 5;
        out.extend_from_slice(&query[12..end]);
        for (rtype, data) in records {
            out.extend_from_slice(&[0xc0, 12]);
            out.extend_from_slice(&rtype.to_be_bytes());
            out.extend_from_slice(&[0, 1, 0, 0, 0x0e, 0x10]);
            out.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
            out.extend_from_slice(data);
        }
        out
    }

    fn name_bytes(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(u8::try_from(label.len()).unwrap());
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    /// The records of example.test, as a DNS server would answer.
    fn records_for(qtype: u16) -> (u8, Vec<(u16, Vec<u8>)>) {
        match qtype {
            1 => (0, vec![(1, vec![93, 184, 216, 34])]),
            28 => (0, vec![]),
            5 => (0, vec![(5, name_bytes("edge.example.test"))]),
            15 => {
                let mut mx = vec![0, 10];
                // A pointer to "example.test" in the question.
                mx.extend_from_slice(&[4, b'm', b'a', b'i', b'l', 0xc0, 12]);
                (0, vec![(15, mx)])
            }
            16 => {
                let mut txt = vec![6];
                txt.extend_from_slice(b"v=spf1");
                txt.push(5);
                txt.extend_from_slice(b" -all");
                (0, vec![(16, txt)])
            }
            _ => (4, vec![]),
        }
    }

    /// A DNS server on a loopback port that answers as `respond` says.
    fn server(respond: impl Fn(&[u8]) -> Option<Vec<u8>> + Send + 'static) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        thread::spawn(move || {
            let mut buffer = [0; 1500];
            while let Ok((n, from)) = socket.recv_from(&mut buffer) {
                if let Some(reply) = respond(&buffer[..n]) {
                    let _ = socket.send_to(&reply, from);
                }
            }
        });
        address
    }

    /// A TCP listener and a UDP socket on one loopback port. The port TCP
    /// gets may be taken for UDP, or reserved for it (Windows keeps ranges of
    /// ports apart per protocol), so a few ports are tried.
    fn tcp_and_udp_on_one_port() -> (TcpListener, UdpSocket) {
        // Ports that failed stay bound, so the next try gets another one.
        let mut tried = Vec::new();
        let mut last_error = None;
        for _ in 0..20 {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            match UdpSocket::bind(("127.0.0.1", port)) {
                Ok(socket) => return (listener, socket),
                Err(error) => last_error = Some(error),
            }
            tried.push(listener);
        }
        panic!("no loopback port free for both TCP and UDP: {last_error:?}");
    }

    fn records(report: &DnsReport, kind: RecordType) -> &DnsAnswer {
        report.answers.iter().find(|a| a.kind == kind).unwrap()
    }

    #[test]
    fn every_type_is_asked_and_read() {
        let address = server(|query| {
            let (name, qtype) = question(query);
            assert_eq!(name, "example.test");
            let (rcode, records) = records_for(qtype);
            Some(answer(query, rcode, false, &records))
        });
        let report = lookup_with("Example.TEST", &[address], TIMEOUT).unwrap();
        assert_eq!(report.name, "example.test");
        assert_eq!(report.servers, vec!["127.0.0.1"]);
        assert_eq!(report.answers.len(), 5);

        let a = records(&report, RecordType::A);
        assert_eq!(a.status, DnsStatus::Found);
        assert_eq!(a.records[0].value, "93.184.216.34");
        assert_eq!(a.records[0].ttl, 3600);
        assert_eq!(a.records[0].name, "example.test");
        assert_eq!(a.server.as_deref(), Some("127.0.0.1"));

        assert_eq!(
            records(&report, RecordType::Aaaa).status,
            DnsStatus::NoRecords
        );
        assert_eq!(
            records(&report, RecordType::Cname).records[0].value,
            "edge.example.test"
        );
        let mx = &records(&report, RecordType::Mx).records[0];
        assert_eq!(
            (mx.value.as_str(), mx.priority),
            ("mail.example.test", Some(10))
        );
        assert_eq!(
            records(&report, RecordType::Txt).records[0].value,
            "v=spf1 -all"
        );
    }

    #[test]
    fn a_missing_name_is_reported() {
        let address = server(|query| Some(answer(query, 3, false, &[])));
        let report = lookup_with("nowhere.test", &[address], TIMEOUT).unwrap();
        assert!(
            report
                .answers
                .iter()
                .all(|a| a.status == DnsStatus::NoSuchName)
        );
    }

    #[test]
    fn answers_to_other_queries_are_ignored() {
        let address = server(|query| {
            let mut forged = answer(query, 0, false, &[(1, vec![6, 6, 6, 6])]);
            forged[0] ^= 0xff;
            Some(forged)
        });
        let report = lookup_with("example.test", &[address], Duration::from_millis(300)).unwrap();
        assert!(
            report
                .answers
                .iter()
                .all(|a| a.status == DnsStatus::NoAnswer && a.records.is_empty())
        );
    }

    #[test]
    fn the_next_server_is_asked_when_one_fails() {
        let silent = server(|_| None);
        let failing = server(|query| Some(answer(query, 2, false, &[])));
        let working = server(|query| {
            let (_, qtype) = question(query);
            let (rcode, records) = records_for(qtype);
            Some(answer(query, rcode, false, &records))
        });
        let report = lookup_with(
            "example.test",
            &[silent, failing, working],
            Duration::from_millis(300),
        )
        .unwrap();
        let a = records(&report, RecordType::A);
        assert_eq!(a.status, DnsStatus::Found);
        assert_eq!(a.server.as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn a_truncated_answer_is_asked_again_over_tcp() {
        let (listener, socket) = tcp_and_udp_on_one_port();
        let port = listener.local_addr().unwrap().port();
        let tcp_queries = Arc::new(AtomicUsize::new(0));
        thread::spawn(move || {
            let mut buffer = [0; 1500];
            while let Ok((n, from)) = socket.recv_from(&mut buffer) {
                let _ = socket.send_to(&answer(&buffer[..n], 0, true, &[]), from);
            }
        });
        let counted = Arc::clone(&tcp_queries);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut length = [0; 2];
                stream.read_exact(&mut length).unwrap();
                let mut query = vec![0; usize::from(u16::from_be_bytes(length))];
                stream.read_exact(&mut query).unwrap();
                counted.fetch_add(1, Ordering::SeqCst);
                let (_, qtype) = question(&query);
                let (rcode, mut records) = records_for(qtype);
                if qtype == 16 {
                    let mut long = vec![255];
                    long.extend_from_slice(&[b'x'; 255]);
                    records = vec![(16, long)];
                }
                let reply = answer(&query, rcode, false, &records);
                stream
                    .write_all(&u16::try_from(reply.len()).unwrap().to_be_bytes())
                    .unwrap();
                stream.write_all(&reply).unwrap();
            }
        });
        let report = lookup_with(
            "example.test",
            &[SocketAddr::from(([127, 0, 0, 1], port))],
            TIMEOUT,
        )
        .unwrap();
        assert_eq!(tcp_queries.load(Ordering::SeqCst), 5);
        let txt = &records(&report, RecordType::Txt).records[0].value;
        assert_eq!(txt, &"x".repeat(255));
    }

    #[test]
    fn names_follow_pointers_and_stop_at_loops() {
        // "a" + pointer to itself.
        let looping = [1, b'a', 0xc0, 0];
        let reader = Reader {
            message: &looping,
            pos: 0,
        };
        assert!(reader.name_at(0).is_err());
        let odd = [3, b'a', b'.', 0x01, 0];
        let reader = Reader {
            message: &odd,
            pos: 0,
        };
        assert_eq!(reader.name_at(0).unwrap().0, "a\\.\\001");
    }

    #[test]
    fn malformed_answers_are_refused() {
        let query = build_query(7, "example.test", 1);
        assert!(parse_response(&query, 7, "example.test", 1).is_err());
        let good = answer(&query, 0, false, &[(1, vec![1, 2, 3, 4])]);
        assert!(parse_response(&good, 7, "example.test", 1).is_ok());
        assert!(parse_response(&good, 8, "example.test", 1).is_err());
        assert!(parse_response(&good, 7, "other.test", 1).is_err());
        assert!(parse_response(&good, 7, "example.test", 28).is_err());
        for cut in 0..good.len() {
            assert!(parse_response(&good[..cut], 7, "example.test", 1).is_err());
        }
    }

    #[test]
    fn addresses_and_bad_names_are_refused() {
        let servers = [SocketAddr::from(([127, 0, 0, 1], 53))];
        assert!(lookup_with("192.168.1.1", &servers, TIMEOUT).is_err());
        assert!(lookup_with("a b", &servers, TIMEOUT).is_err());
        assert!(lookup_with("example.test", &[], TIMEOUT).is_err());
    }

    #[test]
    fn resolv_conf_lists_the_servers() {
        let text = "# by NetworkManager\nsearch lan\nnameserver 192.168.1.1\nnameserver  ::1 # local\n\
                    nameserver fe80::1%en0\nnameserver 192.168.1.1\n;nameserver 9.9.9.9\noptions edns0\n";
        assert_eq!(
            parse_resolv_conf(text),
            vec![
                "192.168.1.1".parse::<IpAddr>().unwrap(),
                "::1".parse().unwrap()
            ]
        );
    }
}
