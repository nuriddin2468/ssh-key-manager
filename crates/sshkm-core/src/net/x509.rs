//! What a TLS certificate says about itself: who it is for, who issued it,
//! when it expires and its names (RFC 5280). Only reads; whether to trust
//! it is the verifier's business ([`super::tls`]).

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Serialize;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;
const OID: u8 = 0x06;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
/// `[0]` and `[3]` of a `TBSCertificate`: the version and the extensions.
const VERSION: u8 = 0xa0;
const EXTENSIONS: u8 = 0xa3;
/// `dNSName [2]` and `iPAddress [7]` of a `GeneralName`.
const DNS_NAME: u8 = 0x82;
const IP_ADDRESS: u8 = 0x87;

const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const ORGANIZATION: &[u8] = &[0x55, 0x04, 0x0a];
const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
const RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const ED25519: &[u8] = &[0x2b, 0x65, 0x70];
const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const P521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];

/// One certificate of a server's chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct CertSummary {
    /// The subject's common name, or else its organisation.
    pub subject: Option<String>,
    /// The issuer's common name, or else its organisation.
    pub issuer: Option<String>,
    pub issuer_organization: Option<String>,
    /// RFC 3339.
    pub not_before: String,
    pub not_after: String,
    /// Whole days until `not_after`; negative once it has passed.
    pub days_left: i32,
    /// The DNS names and addresses it is for (subjectAltName).
    pub names: Vec<String>,
    /// `RSA 2048`, `ECDSA P-256`, `Ed25519`.
    pub key: Option<String>,
    /// Issued by itself.
    pub self_signed: bool,
    /// The SHA-256 of the certificate, as `AB:CD:…`.
    pub sha256: String,
}

/// Reads a DER certificate; `None` if it isn't one.
pub(crate) fn summarize(der: &[u8], now: OffsetDateTime) -> Option<CertSummary> {
    let (tag, certificate, _) = tlv(der)?;
    if tag != SEQUENCE {
        return None;
    }
    let (tag, tbs, _) = tlv(certificate)?;
    if tag != SEQUENCE {
        return None;
    }
    let mut fields = Fields(tbs);
    if fields.peek() == Some(VERSION) {
        fields.next()?;
    }
    fields.expect(INTEGER)?; // serial number
    fields.expect(SEQUENCE)?; // signature algorithm
    let issuer = fields.expect(SEQUENCE)?;
    let mut validity = Fields(fields.expect(SEQUENCE)?);
    let not_before = time_of(validity.next()?)?;
    let not_after = time_of(validity.next()?)?;
    let subject = fields.expect(SEQUENCE)?;
    let key = key_of(fields.expect(SEQUENCE)?);
    let mut names = Vec::new();
    while let Some((tag, content)) = fields.next() {
        if tag == EXTENSIONS {
            names = alt_names(content).unwrap_or_default();
        }
    }
    let days = (not_after - now).whole_days();
    Some(CertSummary {
        subject: attribute(subject, COMMON_NAME).or_else(|| attribute(subject, ORGANIZATION)),
        issuer: attribute(issuer, COMMON_NAME).or_else(|| attribute(issuer, ORGANIZATION)),
        issuer_organization: attribute(issuer, ORGANIZATION),
        not_before: not_before.format(&Rfc3339).ok()?,
        not_after: not_after.format(&Rfc3339).ok()?,
        days_left: i32::try_from(days).unwrap_or(if days < 0 { i32::MIN } else { i32::MAX }),
        names,
        key,
        self_signed: issuer == subject,
        sha256: fingerprint(der),
    })
}

/// One DER element: its tag, its content and what follows it. Only the
/// single-byte tags X.509 uses and definite lengths up to 4 bytes.
fn tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let length = rest[..count]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
        (length, &rest[count..])
    };
    if rest.len() < length {
        return None;
    }
    Some((tag, &rest[..length], &rest[length..]))
}

/// The elements of a SEQUENCE or SET, one at a time.
struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    fn peek(&self) -> Option<u8> {
        self.0.first().copied()
    }

    fn next(&mut self) -> Option<(u8, &'a [u8])> {
        let (tag, content, rest) = tlv(self.0)?;
        self.0 = rest;
        Some((tag, content))
    }

    fn expect(&mut self, tag: u8) -> Option<&'a [u8]> {
        let (found, content) = self.next()?;
        (found == tag).then_some(content)
    }
}

/// The first value of attribute `oid` in a Name.
fn attribute(name: &[u8], oid: &[u8]) -> Option<String> {
    let mut rdns = Fields(name);
    while let Some((tag, rdn)) = rdns.next() {
        if tag != SET {
            continue;
        }
        let mut pairs = Fields(rdn);
        while let Some((_, pair)) = pairs.next() {
            let mut pair = Fields(pair);
            if pair.expect(OID) == Some(oid) {
                let (tag, value) = pair.next()?;
                return Some(string_of(tag, value));
            }
        }
    }
    None
}

/// A directory string as text.
fn string_of(tag: u8, value: &[u8]) -> String {
    let text = match tag {
        // BMPString: UTF-16, big-endian.
        0x1e => {
            let units: Vec<u16> = value
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_be_bytes(*pair))
                .collect();
            String::from_utf16_lossy(&units)
        }
        _ => String::from_utf8_lossy(value).into_owned(),
    };
    text.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// `UTCTime` (`YYMMDDHHMMSSZ`, years 1950 to 2049) or `GeneralizedTime`
/// (`YYYYMMDDHHMMSSZ`).
fn time_of((tag, value): (u8, &[u8])) -> Option<OffsetDateTime> {
    let text = std::str::from_utf8(value).ok()?;
    let digits = text.strip_suffix('Z')?;
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (year, rest) = match (tag, digits.len()) {
        (UTC_TIME, 12) => {
            let yy: i32 = digits[..2].parse().ok()?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, &digits[2..])
        }
        (GENERALIZED_TIME, 14) => (digits[..4].parse().ok()?, &digits[4..]),
        _ => return None,
    };
    let part = |i: usize| rest[i..i + 2].parse::<u8>().ok();
    let date = Date::from_calendar_date(year, Month::try_from(part(0)?).ok()?, part(2)?).ok()?;
    let time = Time::from_hms(part(4)?, part(6)?, part(8)?).ok()?;
    Some(PrimitiveDateTime::new(date, time).assume_utc())
}

/// The kind and size of a `SubjectPublicKeyInfo`.
fn key_of(info: &[u8]) -> Option<String> {
    let mut info = Fields(info);
    let mut algorithm = Fields(info.expect(SEQUENCE)?);
    let oid = algorithm.expect(OID)?;
    if oid == RSA {
        // RSAPublicKey: the modulus, then the exponent.
        let key = info.expect(BIT_STRING)?.get(1..)?;
        let (_, key, _) = tlv(key)?;
        let modulus = Fields(key).expect(INTEGER)?;
        let leading = modulus.iter().take_while(|&&b| b == 0).count();
        let modulus = &modulus[leading..];
        let first = *modulus.first()?;
        let unused = (0..8).take_while(|i| first & (0x80 >> i) == 0).count();
        let bits = modulus.len() * 8 - unused;
        Some(format!("RSA {bits}"))
    } else if oid == EC {
        let curve = match algorithm.expect(OID)? {
            c if c == P256 => "P-256",
            c if c == P384 => "P-384",
            c if c == P521 => "P-521",
            _ => "",
        };
        Some(format!("ECDSA {curve}").trim_end().to_owned())
    } else if oid == ED25519 {
        Some("Ed25519".to_owned())
    } else {
        None
    }
}

/// The DNS names and addresses of the subjectAltName extension.
fn alt_names(extensions: &[u8]) -> Option<Vec<String>> {
    let mut list = Fields(Fields(extensions).expect(SEQUENCE)?);
    while let Some((_, extension)) = list.next() {
        let mut extension = Fields(extension);
        if extension.expect(OID)? != SUBJECT_ALT_NAME {
            continue;
        }
        // `critical` is optional.
        let mut value = extension.next()?;
        if value.0 != OCTET_STRING {
            value = extension.next()?;
        }
        let mut names = Vec::new();
        let mut general = Fields(Fields(value.1).expect(SEQUENCE)?);
        while let Some((tag, name)) = general.next() {
            match tag {
                DNS_NAME => names.push(string_of(0x16, name)),
                IP_ADDRESS => {
                    if let Ok(v4) = <[u8; 4]>::try_from(name) {
                        names.push(Ipv4Addr::from(v4).to_string());
                    } else if let Ok(v6) = <[u8; 16]>::try_from(name) {
                        names.push(Ipv6Addr::from(v6).to_string());
                    }
                }
                _ => {}
            }
        }
        return Some(names);
    }
    Some(Vec::new())
}

fn fingerprint(der: &[u8]) -> String {
    let mut out = String::with_capacity(95);
    for (i, byte) in Sha256::digest(der).iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        let _ = write!(out, "{byte:02X}");
    }
    out
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;
    use crate::net::fixtures::{CA, LEAF, OTHER};

    const NOW: OffsetDateTime = datetime!(2027-01-01 00:00 UTC);

    #[test]
    fn a_leaf_says_who_it_is_for() {
        let leaf = summarize(LEAF, NOW).unwrap();
        assert_eq!(leaf.subject.as_deref(), Some("localhost"));
        assert_eq!(leaf.issuer.as_deref(), Some("SSHKM Test CA"));
        assert_eq!(
            leaf.issuer_organization.as_deref(),
            Some("SSH Key Manager tests")
        );
        assert_eq!(leaf.names, vec!["localhost", "127.0.0.1"]);
        assert_eq!(leaf.key.as_deref(), Some("ECDSA P-256"));
        assert!(!leaf.self_signed);
        assert!(leaf.not_before.starts_with("2026-11-06T"));
        assert!(leaf.not_after.starts_with("2046-11-01T"));
        assert_eq!(leaf.days_left, 7244);
        assert_eq!(
            leaf.sha256,
            "63:C6:75:B1:3B:32:23:D5:F7:23:12:BC:D4:9D:6C:9D:4D:CB:83:BD:05:3C:09:1E:23:CA:5A:44:7A:85:AF:DE"
        );
    }

    #[test]
    fn roots_are_self_signed() {
        let ca = summarize(CA, NOW).unwrap();
        assert!(ca.self_signed);
        assert_eq!(ca.names, Vec::<String>::new());
        let other = summarize(OTHER, NOW).unwrap();
        assert_eq!(other.subject.as_deref(), Some("Other Root"));
        assert_eq!(other.key.as_deref(), Some("RSA 2048"));
        assert!(other.self_signed);
    }

    #[test]
    fn days_left_turn_negative_after_expiry() {
        let late = summarize(LEAF, datetime!(2047-01-01 00:00 UTC)).unwrap();
        assert!(late.days_left < 0);
    }

    #[test]
    fn times_of_both_kinds_are_read() {
        assert_eq!(
            time_of((UTC_TIME, b"491231235959Z")),
            Some(datetime!(2049-12-31 23:59:59 UTC))
        );
        assert_eq!(
            time_of((UTC_TIME, b"500101000000Z")),
            Some(datetime!(1950-01-01 00:00 UTC))
        );
        assert_eq!(
            time_of((GENERALIZED_TIME, b"20500101000000Z")),
            Some(datetime!(2050-01-01 00:00 UTC))
        );
        assert_eq!(time_of((UTC_TIME, b"491331235959Z")), None);
        assert_eq!(time_of((UTC_TIME, b"4912312359+0100")), None);
    }

    #[test]
    fn anything_else_is_not_a_certificate() {
        assert_eq!(summarize(b"", NOW), None);
        assert_eq!(summarize(b"SSH-2.0-OpenSSH_9.9\r\n", NOW), None);
        for cut in 0..LEAF.len() {
            assert_eq!(summarize(&LEAF[..cut], NOW), None);
        }
    }
}
