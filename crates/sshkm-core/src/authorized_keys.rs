//! What an `authorized_keys` file says: the keys that may sign in to an
//! account, and the options each one comes with.
//!
//! The app reads the file of a server over `ssh`; this module only parses the
//! text, the way `sshd` does (`auth2-pubkeyfile.c`): a line is a key, or
//! options followed by a key. Options end at the first space or tab outside
//! double quotes, and `\"` inside quotes is a quote.

use serde::{Deserialize, Serialize};
use ssh_key::PublicKey;

use crate::keys::{KeyAlgorithm, fingerprint, key_bits};

/// One key line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct AuthorizedKey {
    /// 1-based line number.
    pub line: u32,
    pub algorithm: KeyAlgorithm,
    /// Key type, e.g. `ssh-ed25519`.
    pub key_type: String,
    /// Key size in bits as `ssh-keygen -l` reports it.
    pub bits: Option<u32>,
    /// `SHA256:…` fingerprint, as `ssh-keygen -l` prints it.
    pub fingerprint: String,
    /// What follows the key; empty if nothing does.
    pub comment: String,
    /// `<type> <base64>` without the comment: what a removal names.
    pub public_key: String,
    /// `expiry-time` as `YYYY-MM-DDTHH:MM:SS`, ending in `Z` when it was given
    /// in UTC; otherwise it is the server's local time.
    pub expires: Option<String>,
    /// `cert-authority`: the key signs the certificates that sign in, rather
    /// than signing in itself.
    pub cert_authority: bool,
    /// Every other option as written, such as `from="10.0.0.0/8"` or
    /// `restrict`.
    pub options: Vec<String>,
}

/// Everything the UI shows about an `authorized_keys` file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct AuthorizedKeys {
    /// The keys in file order.
    pub keys: Vec<AuthorizedKey>,
    /// 1-based numbers of the lines that are neither a key, a comment nor
    /// blank. `sshd` skips them.
    pub invalid: Vec<u32>,
}

/// Parses `authorized_keys` text. Never fails.
pub fn parse(text: &str) -> AuthorizedKeys {
    let mut file = AuthorizedKeys::default();
    for (i, raw) in text.lines().enumerate() {
        let number = u32::try_from(i + 1).unwrap_or(u32::MAX);
        let line = raw.trim_start_matches('\u{feff}').trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_line(line, number) {
            Some(key) => file.keys.push(key),
            None => file.invalid.push(number),
        }
    }
    file
}

/// The line as a key, or as options followed by a key.
fn parse_line(line: &str, number: u32) -> Option<AuthorizedKey> {
    if let Some(key) = read_key(line) {
        return Some(entry(number, key, ""));
    }
    let end = options_end(line);
    let key = read_key(line[end..].trim_start())?;
    Some(entry(number, key, &line[..end]))
}

/// The key, its comment and the `<type> <base64>` text at the start of `text`.
struct Key {
    public: PublicKey,
    encoded: String,
    comment: String,
}

fn read_key(text: &str) -> Option<Key> {
    let (key_type, rest) = text.split_once([' ', '\t'])?;
    let rest = rest.trim_start_matches([' ', '\t']);
    let (base64, comment) = rest.split_once([' ', '\t']).unwrap_or((rest, ""));
    let comment = comment.trim().to_owned();
    let encoded = format!("{key_type} {base64}");
    let public = PublicKey::from_openssh(&encoded).ok()?;
    Some(Key {
        public,
        encoded,
        comment,
    })
}

/// Where the options at the start of `line` end: the first space or tab
/// outside quotes, or the end of the line.
fn options_end(line: &str) -> usize {
    let mut quoted = false;
    let mut chars = line.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' if quoted && line[i + 1..].starts_with('"') => {
                chars.next();
            }
            '"' => quoted = !quoted,
            ' ' | '\t' if !quoted => return i,
            _ => {}
        }
    }
    line.len()
}

fn entry(line: u32, key: Key, options: &str) -> AuthorizedKey {
    let data = key.public.key_data();
    let mut expires = None;
    let mut cert_authority = false;
    let mut rest = Vec::new();
    for option in split_options(options) {
        let (name, value) = option.split_once('=').unwrap_or((option, ""));
        if name.eq_ignore_ascii_case("cert-authority") {
            cert_authority = true;
            continue;
        }
        if name.eq_ignore_ascii_case("expiry-time") && expires.is_none() {
            expires = expiry(value.trim_matches('"'));
            if expires.is_some() {
                continue;
            }
        }
        rest.push(option.to_owned());
    }
    AuthorizedKey {
        line,
        algorithm: KeyAlgorithm::from_ssh(&data.algorithm()),
        key_type: data.algorithm().to_string(),
        bits: key_bits(data),
        fingerprint: fingerprint(data),
        comment: key.comment,
        public_key: key.encoded,
        expires,
        cert_authority,
        options: rest,
    }
}

/// The comma-separated options, splitting outside quotes only.
fn split_options(options: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut start, mut quoted) = (0, false);
    let mut chars = options.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' if quoted && options[i + 1..].starts_with('"') => {
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => {
                parts.push(&options[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&options[start..]);
    parts.retain(|part| !part.is_empty());
    parts
}

/// `YYYYMMDD[HHMM[SS]]`, with an optional `Z` for UTC, as `sshd` reads
/// `expiry-time`; `None` if it is anything else.
fn expiry(value: &str) -> Option<String> {
    let (digits, utc) = match value.strip_suffix(['Z', 'z']) {
        Some(digits) => (digits, true),
        None => (value, false),
    };
    if !digits.bytes().all(|b| b.is_ascii_digit()) || ![8, 12, 14].contains(&digits.len()) {
        return None;
    }
    let part = |range: std::ops::Range<usize>| digits.get(range).unwrap_or("00");
    let number = |range| part(range).parse::<u32>().ok();
    let (month, day) = (number(4..6)?, number(6..8)?);
    let (hour, minute, second) = (number(8..10)?, number(10..12)?, number(12..14)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    Some(format!(
        "{}-{}-{}T{}:{}:{}{}",
        part(0..4),
        part(4..6),
        part(6..8),
        part(8..10),
        part(10..12),
        part(12..14),
        if utc { "Z" } else { "" }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    #[test]
    fn reads_plain_keys() {
        let file = parse(&format!("{ED} alice@laptop\n"));
        assert_eq!(file.invalid, Vec::<u32>::new());
        let [key] = file.keys.as_slice() else {
            panic!("{file:?}")
        };
        assert_eq!(key.line, 1);
        assert_eq!(key.algorithm, KeyAlgorithm::Ed25519);
        assert_eq!(key.key_type, "ssh-ed25519");
        assert_eq!(key.bits, Some(256));
        assert!(key.fingerprint.starts_with("SHA256:"));
        assert_eq!(key.comment, "alice@laptop");
        assert_eq!(key.public_key, ED);
        assert_eq!(key.expires, None);
        assert!(!key.cert_authority && key.options.is_empty());
    }

    #[test]
    fn keeps_whole_comments_and_skips_blank_and_comment_lines() {
        let spaced = ED.replace(' ', "  ");
        let text = format!("\n# keys of the team\n  \n{ED}\tlaptop of Alice  \n{spaced}\n");
        let file = parse(&text);
        assert_eq!(file.invalid, Vec::<u32>::new());
        let lines: Vec<_> = file
            .keys
            .iter()
            .map(|k| (k.line, k.comment.as_str()))
            .collect();
        assert_eq!(lines, [(4, "laptop of Alice"), (5, "")]);
        assert_eq!(file.keys[1].public_key, ED);
    }

    #[test]
    fn reads_options() {
        let text = format!(
            "expiry-time=\"20261201\",from=\"10.0.0.0/8,192.168.0.0/16\",no-pty {ED} bob\n\
             restrict,command=\"echo \\\"hi there\\\"\" {ED} ci\n\
             cert-authority,principals=\"alice\" {ED} ca\n"
        );
        let file = parse(&text);
        assert_eq!(file.invalid, Vec::<u32>::new());
        let [bob, ci, ca] = file.keys.as_slice() else {
            panic!("{file:?}")
        };
        assert_eq!(bob.expires.as_deref(), Some("2026-12-01T00:00:00"));
        assert_eq!(
            bob.options,
            ["from=\"10.0.0.0/8,192.168.0.0/16\"", "no-pty"]
        );
        assert_eq!(bob.comment, "bob");
        assert_eq!(
            ci.options,
            ["restrict", "command=\"echo \\\"hi there\\\"\""]
        );
        assert_eq!(ci.comment, "ci");
        assert!(ca.cert_authority);
        assert_eq!(ca.options, ["principals=\"alice\""]);
        assert_eq!(ca.public_key, ED);
    }

    #[test]
    fn reads_expiry_times() {
        assert_eq!(expiry("20261201").as_deref(), Some("2026-12-01T00:00:00"));
        assert_eq!(
            expiry("202612011330").as_deref(),
            Some("2026-12-01T13:30:00")
        );
        assert_eq!(
            expiry("20261201133005Z").as_deref(),
            Some("2026-12-01T13:30:05Z")
        );
        for bad in [
            "",
            "2026120",
            "20261301",
            "20261200",
            "202612012460",
            "2026-12-01",
            "x",
        ] {
            assert_eq!(expiry(bad), None, "{bad}");
        }
        // An expiry time sshd would not read stays an option.
        let file = parse(&format!("expiry-time=\"soon\" {ED}"));
        assert_eq!(file.keys[0].expires, None);
        assert_eq!(file.keys[0].options, ["expiry-time=\"soon\""]);
    }

    #[test]
    fn reports_lines_that_are_not_keys() {
        let text = format!(
            "{ED} ok\nssh-ed25519 not-base64\nfrom=\"x\" ssh-ed25519\nssh-rsa {}\n{ED} ok\n",
            &ED[12..]
        );
        let file = parse(&text);
        assert_eq!(file.invalid, [2, 3, 4]);
        assert_eq!(file.keys.iter().map(|k| k.line).collect::<Vec<_>>(), [1, 5]);
    }

    #[test]
    fn unterminated_quotes_run_to_the_end() {
        assert_eq!(options_end("from=\"a b"), 9);
        assert_eq!(options_end("a,b c"), 3);
        assert_eq!(split_options("a,\"b,c\",,d"), ["a", "\"b,c\"", "d"]);
    }
}
