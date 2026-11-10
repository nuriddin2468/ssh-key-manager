//! What is looked for: each secret's value in the forms it takes in files,
//! for values that mean something when found.

use std::collections::HashMap;

use aho_corasick::{AhoCorasick, MatchKind};
use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use super::{Encoding, KnownSecret, LeakSecret};

/// Fewest characters a value has to be looked for.
pub const MIN_CHARS: usize = 8;
/// Fewest different characters a value has to be looked for (`aaaaaaaa`,
/// `--------` are not).
const MIN_DISTINCT: usize = 5;
/// Fewest characters a line of a multi-line value (a private key) has to be
/// looked for on its own.
const MIN_LINE_CHARS: usize = 20;
/// Fewest different characters such a line has.
const MIN_LINE_DISTINCT: usize = 8;
/// Fewest characters of a value's base64 form looked for.
const MIN_BASE64: usize = 12;
/// Most of a value that is looked for: a longer one is found by its
/// beginning.
const MAX_CHARS: usize = 8 * 1024;
/// Values that are names, settings or words rather than secrets, compared
/// without case.
const PLAIN: &[&str] = &[
    "localhost",
    "development",
    "production",
    "staging",
    "changeme",
    "change-me",
    "change_me",
    "password",
    "undefined",
    "example",
    "placeholder",
    "secret",
    "your-secret",
    "your_secret",
    "postgres",
    "postgresql",
    "default",
    "disabled",
    "enabled",
];

/// Whether a value means something when it is found: at least
/// [`MIN_CHARS`] characters, not a number, date, version or address, not a
/// path, a plain URL, an email address or a version, not a word that
/// configs are full of, and not something zxcvbn would guess at once (score 0).
pub fn searchable(value: &str) -> bool {
    let value = value.trim();
    let chars = value.chars().count();
    if chars < MIN_CHARS {
        return false;
    }
    if value
        .chars()
        .all(|c| c.is_ascii_digit() || " .,:;-/_+()".contains(c))
    {
        return false;
    }
    if distinct(value) < MIN_DISTINCT {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    if PLAIN.contains(&lower.as_str()) {
        return false;
    }
    if is_path(value) || is_plain_url(value) || is_email(value) || is_version(value) {
        return false;
    }
    // zxcvbn is quadratic in the length; anything this long is not a word.
    if chars <= 32 {
        let estimate = zxcvbn::zxcvbn(value, &[]);
        if u8::from(estimate.score()) == 0 {
            return false;
        }
    }
    true
}

fn distinct(text: &str) -> usize {
    let mut seen: Vec<char> = text.chars().collect();
    seen.sort_unstable();
    seen.dedup();
    seen.len()
}

/// `1.2.3`, `v2.0.1-beta.1`, `10.4+build7`.
fn is_version(value: &str) -> bool {
    let value = value.strip_prefix('v').unwrap_or(value);
    let core = value.split(['-', '+']).next().unwrap_or_default();
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() >= 2
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        && value[core.len()..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-+.".contains(c))
}

fn is_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    value.starts_with('/')
        || value.starts_with("~/")
        || value.starts_with("./")
        || value.starts_with("../")
        || (bytes.len() > 2
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'\\' | b'/'))
}

/// `scheme://host[:port][/]`: an address with nothing secret in it.
fn is_plain_url(value: &str) -> bool {
    let Some((scheme, rest)) = value.split_once("://") else {
        return false;
    };
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
    {
        return false;
    }
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    !rest.is_empty()
        && rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-.:[]".contains(c))
}

fn is_email(value: &str) -> bool {
    let Some((user, domain)) = value.split_once('@') else {
        return false;
    };
    !user.is_empty()
        && !value.contains(char::is_whitespace)
        && !domain.contains('@')
        && domain.contains('.')
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-.".contains(c))
}

/// The forms `value` takes in files, with how each is encoded (`None` for
/// as it is, or escaped in JSON). A value that isn't [`searchable`] has
/// none.
///
/// - One line: as it is; escaped in JSON and percent-encoded if that
///   changes it; in base64 (standard and URL alphabets) at each of the
///   three byte alignments, so it is found inside a larger base64 string
///   (`Authorization: Basic …`) too; and for an address with a password
///   (`postgres://user:pw@host`), the password alone, as it is and decoded.
/// - Several lines (a private key): with `\n` and with `\r\n`, escaped in
///   JSON, with `\n` written out (as in a `.env` file), in base64, and each
///   long line on its own, so it is found whatever escaped the line breaks.
pub fn forms(value: &str) -> Vec<(Zeroizing<Vec<u8>>, Option<Encoding>)> {
    let mut out: Vec<(Zeroizing<Vec<u8>>, Option<Encoding>)> = Vec::new();
    if !searchable(value) {
        return out;
    }
    let value = Zeroizing::new(cap(value.trim()));
    let mut push = |bytes: Vec<u8>, encoding: Option<Encoding>| {
        let bytes = Zeroizing::new(bytes);
        if !bytes.is_empty() && !out.iter().any(|(known, _)| **known == *bytes) {
            out.push((bytes, encoding));
        }
    };
    if value.contains('\n') {
        let lf = Zeroizing::new(value.replace("\r\n", "\n"));
        push(lf.as_bytes().to_vec(), None);
        push(lf.replace('\n', "\r\n").into_bytes(), None);
        push(json_escaped(&lf).into_bytes(), None);
        push(lf.replace('\n', "\\n").into_bytes(), None);
        for core in base64_cores(lf.as_bytes()) {
            push(core, Some(Encoding::Base64));
        }
        for line in lf.lines().map(str::trim) {
            if line.chars().count() >= MIN_LINE_CHARS
                && !line.starts_with("-----")
                && distinct(line) >= MIN_LINE_DISTINCT
            {
                push(line.as_bytes().to_vec(), None);
            }
        }
    } else {
        push(value.as_bytes().to_vec(), None);
        push(json_escaped(&value).into_bytes(), None);
        push(percent_encoded(&value).into_bytes(), Some(Encoding::Url));
        for core in base64_cores(value.as_bytes()) {
            push(core, Some(Encoding::Base64));
        }
        if let Some(password) = url_password(&value) {
            let decoded = Zeroizing::new(percent_decoded(&password));
            for candidate in [&*password, &*decoded] {
                if searchable(candidate) {
                    push(candidate.as_bytes().to_vec(), None);
                }
            }
        }
    }
    out
}

/// At most [`MAX_CHARS`] characters of `value`.
fn cap(value: &str) -> String {
    match value.char_indices().nth(MAX_CHARS) {
        Some((at, _)) => value[..at].to_owned(),
        None => value.to_owned(),
    }
}

/// `value` as it is inside a JSON string, without the quotes.
fn json_escaped(value: &str) -> String {
    let quoted = serde_json::to_string(value).unwrap_or_default();
    quoted
        .strip_prefix('"')
        .and_then(|q| q.strip_suffix('"'))
        .unwrap_or_default()
        .to_owned()
}

/// Percent-encoding of everything but `A-Z a-z 0-9 - . _ ~`, in capitals.
fn percent_encoded(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    out
}

const HEX: &[u8; 16] = b"0123456789ABCDEF";

fn percent_decoded(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let digit = |b: u8| char::from(b).to_digit(16);
        if bytes[at] == b'%'
            && let (Some(&hi), Some(&lo)) = (bytes.get(at + 1), bytes.get(at + 2))
            && let (Some(hi), Some(lo)) = (digit(hi), digit(lo))
        {
            out.push(u8::try_from(hi * 16 + lo).unwrap_or_default());
            at += 3;
            continue;
        }
        out.push(bytes[at]);
        at += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| value.to_owned())
}

/// The password of `scheme://user:password@host…`, as written there.
fn url_password(value: &str) -> Option<Zeroizing<String>> {
    let (_, rest) = value.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let (user_info, _) = authority.rsplit_once('@')?;
    let (_, password) = user_info.split_once(':')?;
    (!password.is_empty()).then(|| Zeroizing::new(password.to_owned()))
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The characters of `bytes`' base64 form that don't depend on what comes
/// before or after it, at each of the three positions it can start at in a
/// larger encoded string, in both alphabets.
fn base64_cores(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for alphabet in [BASE64, BASE64_URL] {
        for offset in 0..3_usize {
            let mut padded = Zeroizing::new(vec![0_u8; offset]);
            padded.extend_from_slice(bytes);
            let encoded = Zeroizing::new(base64(&padded, alphabet));
            // Characters before `skip` mix in the bytes before; past
            // `known`, the bytes after.
            let skip = [0, 2, 3][offset];
            let known = padded.len() * 4 / 3;
            if known > skip && known - skip >= MIN_BASE64 {
                let core = encoded[skip..known].to_vec();
                if !out.contains(&core) {
                    out.push(core);
                }
            }
        }
    }
    out
}

/// Base64 of `bytes` without padding; a last partial group is encoded as if
/// zeros followed.
fn base64(bytes: &[u8], alphabet: &[u8; 64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        let chars = chunk.len() + 1;
        for i in 0..chars {
            out.push(alphabet[(n >> (18 - 6 * i) & 63) as usize]);
        }
    }
    out
}

/// Every form of every secret, searched at once. Holds the values (in the
/// automaton too), so it is neither serialisable nor shown by `Debug`;
/// drop it when the scan is done.
pub struct Matcher {
    automaton: Option<AhoCorasick>,
    /// For each pattern, the secrets whose form it is, and how.
    owners: Vec<Vec<(usize, Option<Encoding>)>>,
    secrets: Vec<LeakSecret>,
    longest: usize,
}

impl std::fmt::Debug for Matcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Matcher")
            .field("secrets", &self.secrets.len())
            .field("patterns", &self.owners.len())
            .finish_non_exhaustive()
    }
}

impl Matcher {
    /// The forms of the [`searchable`] values among `known`. Two secrets
    /// with the same value share their patterns, and both are reported.
    pub fn new(known: Vec<KnownSecret>) -> Self {
        let mut patterns: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        let mut index: HashMap<Vec<u8>, usize> = HashMap::new();
        let mut owners: Vec<Vec<(usize, Option<Encoding>)>> = Vec::new();
        let mut secrets = Vec::new();
        for KnownSecret { secret, value } in known {
            let forms = forms(value.expose_secret());
            if forms.is_empty() {
                continue;
            }
            let id = secrets.len();
            secrets.push(secret);
            for (bytes, encoding) in forms {
                let at = if let Some(&at) = index.get(bytes.as_slice()) {
                    at
                } else {
                    let at = patterns.len();
                    index.insert(bytes.to_vec(), at);
                    patterns.push(bytes);
                    owners.push(Vec::new());
                    at
                };
                if !owners[at].iter().any(|(owner, _)| *owner == id) {
                    owners[at].push((id, encoding));
                }
            }
        }
        // The index keeps copies of the values: wipe them.
        for (mut key, _) in index.drain() {
            zeroize::Zeroize::zeroize(&mut key);
        }
        let longest = patterns.iter().map(|p| p.len()).max().unwrap_or(0);
        let automaton = if patterns.is_empty() {
            None
        } else {
            AhoCorasick::builder()
                .match_kind(MatchKind::Standard)
                .build(patterns.iter().map(|p| p.as_slice()))
                .ok()
        };
        Self {
            automaton,
            owners,
            secrets,
            longest,
        }
    }

    /// Only the secret `key` names ([`LeakSecret::key`]) of `known`: for
    /// [`super::redact`].
    pub fn only(known: Vec<KnownSecret>, key: &str) -> Self {
        Self::new(
            known
                .into_iter()
                .filter(|known| known.secret.key() == key)
                .collect(),
        )
    }

    /// Secrets that are looked for.
    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.automaton.is_none()
    }

    /// The secrets searched for.
    pub fn secrets(&self) -> &[LeakSecret] {
        &self.secrets
    }

    pub(super) fn automaton(&self) -> Option<&AhoCorasick> {
        self.automaton.as_ref()
    }

    pub(super) fn longest(&self) -> usize {
        self.longest
    }

    pub(super) fn owners(&self, pattern: usize) -> &[(usize, Option<Encoding>)] {
        self.owners.get(pattern).map_or(&[], Vec::as_slice)
    }

    pub(super) fn secret(&self, id: usize) -> &LeakSecret {
        &self.secrets[id]
    }
}
