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
/// Values longer than this are not given to zxcvbn, which is quadratic in
/// the length; they are taken as strong.
const MAX_RATED: usize = 32;
/// A part of a path at least this long, with capitals, small letters and
/// digits, is random: the value is a secret that starts with `/`.
const RANDOM_PART: usize = 16;
/// The first characters of every OpenSSH private key's body (base64 of
/// `openssh-key-v1`): the same in every key, so never looked for alone.
const OPENSSH_MAGIC: &str = "b3BlbnNzaC1rZXktdjE";
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
/// path, a plain URL or an email address — by their shape, so a random
/// value that starts with `/` or has an `@` still is one (`/xK9#mQ2$vL7p`
/// is a secret, `/var/lib/data` is not) — not a word that configs are full
/// of, and not something zxcvbn guesses at once (score 0).
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
    if !distinct_at_least(value, MIN_DISTINCT) {
        return false;
    }
    if PLAIN.iter().any(|plain| value.eq_ignore_ascii_case(plain)) {
        return false;
    }
    if is_plain_url(value) || is_version(value) || is_path(value) || is_email(value) {
        return false;
    }
    chars > MAX_RATED || u8::from(zxcvbn::zxcvbn(value, &[]).score()) > 0
}

/// Whether `text` has at least `n` (at most 16) different characters. Keeps
/// no copy of it on the heap.
fn distinct_at_least(text: &str, n: usize) -> bool {
    let mut seen = [0_u32; 16];
    let mut count = 0;
    let mut enough = false;
    for c in text.chars() {
        let c = u32::from(c);
        if !seen[..count].contains(&c) {
            seen[count] = c;
            count += 1;
            if count >= n.min(seen.len()) {
                enough = true;
                break;
            }
        }
    }
    zeroize::Zeroize::zeroize(&mut seen);
    enough
}

/// `1.2.3`, `v2.0.1-beta.1`, `10.4+build7`.
fn is_version(value: &str) -> bool {
    let value = value.strip_prefix('v').unwrap_or(value);
    let core = value.split(['-', '+']).next().unwrap_or_default();
    let mut parts = 0;
    for part in core.split('.') {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        parts += 1;
    }
    parts >= 2
        && value[core.len()..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-+.".contains(c))
}

/// `/var/lib/data`, `~/.ssh/id_ed25519`, `C:\\Users\\dev`: starts like a path,
/// has only the characters paths are made of, and no part of it is random.
fn is_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    let starts = value.starts_with('/')
        || value.starts_with("~/")
        || value.starts_with("./")
        || value.starts_with("../")
        || (bytes.len() > 2
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'\\' | b'/'));
    starts
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-~/\\: ".contains(c))
        && !value.split(['/', '\\']).any(is_random_part)
}

fn is_random_part(part: &str) -> bool {
    part.len() >= RANDOM_PART
        && part.bytes().any(|b| b.is_ascii_uppercase())
        && part.bytes().any(|b| b.is_ascii_lowercase())
        && part.bytes().any(|b| b.is_ascii_digit())
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

/// `dev@example.com`: an address's characters, and a top-level domain of
/// letters only (`Tr0ub4dor@x7.Kq9z` is a password).
fn is_email(value: &str) -> bool {
    let Some((user, domain)) = value.split_once('@') else {
        return false;
    };
    let top = domain.rsplit('.').next().unwrap_or_default();
    !user.is_empty()
        && user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._%+-".contains(c))
        && domain.contains('.')
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-.".contains(c))
        && top.len() >= 2
        && top.bytes().all(|b| b.is_ascii_alphabetic())
}

/// One form of a value, as it would be in a file.
pub struct Form {
    pub bytes: Zeroizing<Vec<u8>>,
    /// How it is encoded: `None` for as it is, or escaped in JSON.
    pub encoding: Option<Encoding>,
    /// For a line of a multi-line value, which one (from 0): such a form
    /// counts only next to another line of the same value.
    pub line: Option<u32>,
}

/// The forms `value` takes in files. A value that isn't [`searchable`] has
/// none.
///
/// - One line: as it is; escaped in JSON, and again (JSON inside a JSON
///   string, as Codex keeps a tool's arguments); percent-encoded in capitals
///   and in small letters, and with `+` for spaces; in base64 (standard and
///   URL alphabets) at each of the three byte alignments, so it is found
///   inside a larger base64 string (`Authorization: Basic …`) too; and for
///   an address with a password (`postgres://user:pw@host`), the password
///   alone, as it is and decoded.
/// - Several lines (a private key): with `\n` and with `\r\n`, escaped in
///   JSON once and twice, with `\n` written out (as in a `.env` file), in
///   base64, and the long lines of its private body on their own
///   ([`body_lines`]), so it is found whatever escaped the line breaks.
pub fn forms(value: &str) -> Vec<Form> {
    let mut out: Vec<Form> = Vec::new();
    if !searchable(value) {
        return out;
    }
    let value = Zeroizing::new(cap(value.trim()));
    let mut push = |bytes: Vec<u8>, encoding: Option<Encoding>, line: Option<u32>| {
        let bytes = Zeroizing::new(bytes);
        if !bytes.is_empty() && !out.iter().any(|known| *known.bytes == *bytes) {
            out.push(Form {
                bytes,
                encoding,
                line,
            });
        }
    };
    if value.contains('\n') {
        let lf = Zeroizing::new(value.replace("\r\n", "\n"));
        push(lf.as_bytes().to_vec(), None, None);
        push(lf.replace('\n', "\r\n").into_bytes(), None, None);
        let json = json_escaped(&lf);
        push(json_escaped(&json).as_bytes().to_vec(), None, None);
        push(json.as_bytes().to_vec(), None, None);
        push(lf.replace('\n', "\\n").into_bytes(), None, None);
        for core in base64_cores(lf.as_bytes()) {
            push(core.to_vec(), Some(Encoding::Base64), None);
        }
        for (index, line) in body_lines(&lf) {
            push(line.as_bytes().to_vec(), None, Some(index));
        }
    } else {
        push(value.as_bytes().to_vec(), None, None);
        let json = json_escaped(&value);
        push(json_escaped(&json).as_bytes().to_vec(), None, None);
        push(json.as_bytes().to_vec(), None, None);
        let percent = Zeroizing::new(percent_encoded(&value, HEX));
        push(percent.as_bytes().to_vec(), Some(Encoding::Url), None);
        push(
            percent_encoded(&value, HEX_LOWER).into_bytes(),
            Some(Encoding::Url),
            None,
        );
        push(
            percent.replace("%20", "+").into_bytes(),
            Some(Encoding::Url),
            None,
        );
        for core in base64_cores(value.as_bytes()) {
            push(core.to_vec(), Some(Encoding::Base64), None);
        }
        if let Some(password) = url_password(&value) {
            let decoded = Zeroizing::new(percent_decoded(&password));
            for candidate in [&*password, &*decoded] {
                if searchable(candidate) {
                    push(candidate.as_bytes().to_vec(), None, None);
                }
            }
        }
    }
    out
}

/// The lines of a multi-line value worth looking for alone, with their
/// index: long lines of base64 in its private parts. Left out: `-----BEGIN`
/// and `-----END`, `Key: value` headers (`Proc-Type`, PuTTY's), the blocks
/// that are public anyway (a certificate, a public key, PuTTY's
/// `Public-Lines`), and the first line of an OpenSSH key, which every key
/// shares. Lines found alone still count only next to another line of the
/// same value.
fn body_lines(text: &str) -> Vec<(u32, &str)> {
    let mut out = Vec::new();
    let mut public = false;
    for (index, line) in text.lines().map(str::trim).enumerate() {
        if let Some(header) = line.strip_prefix("-----BEGIN ") {
            public = header.contains("CERTIFICATE") || header.contains("PUBLIC KEY");
            continue;
        }
        if line.starts_with("-----END ") {
            public = false;
            continue;
        }
        if line.starts_with("Public-Lines:") {
            public = true;
            continue;
        }
        if line.starts_with("Private-Lines:") {
            public = false;
            continue;
        }
        if public
            || line.starts_with(OPENSSH_MAGIC)
            || line.chars().count() < MIN_LINE_CHARS
            || !line
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/=-_".contains(&b))
            || !distinct_at_least(line, MIN_LINE_DISTINCT)
        {
            continue;
        }
        out.push((u32::try_from(index).unwrap_or(u32::MAX), line));
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
fn json_escaped(value: &str) -> Zeroizing<String> {
    let quoted = Zeroizing::new(serde_json::to_string(value).unwrap_or_default());
    Zeroizing::new(
        quoted
            .strip_prefix('"')
            .and_then(|q| q.strip_suffix('"'))
            .unwrap_or_default()
            .to_owned(),
    )
}

/// Percent-encoding of everything but `A-Z a-z 0-9 - . _ ~`, with the hex
/// digits of `hex`.
fn percent_encoded(value: &str, hex: &[u8; 16]) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(hex[usize::from(byte >> 4)]));
            out.push(char::from(hex[usize::from(byte & 15)]));
        }
    }
    out
}

const HEX: &[u8; 16] = b"0123456789ABCDEF";
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

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
fn base64_cores(bytes: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
    let mut out: Vec<Zeroizing<Vec<u8>>> = Vec::new();
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
                let core = Zeroizing::new(encoded[skip..known].to_vec());
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

/// A secret a pattern is a form of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Owner {
    /// Its index in [`Matcher::secrets`].
    pub secret: usize,
    pub encoding: Option<Encoding>,
    /// [`Form::line`].
    pub line: Option<u32>,
}

/// Every form of every secret, searched at once. Holds the values (in the
/// automaton too), so it is neither serialisable nor shown by `Debug`;
/// drop it when the scan is done.
pub struct Matcher {
    automaton: Option<AhoCorasick>,
    /// For each pattern, the secrets whose form it is, and how.
    owners: Vec<Vec<Owner>>,
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
        let mut owners: Vec<Vec<Owner>> = Vec::new();
        let mut secrets = Vec::new();
        for KnownSecret { secret, value } in known {
            let forms = forms(value.expose_secret());
            if forms.is_empty() {
                continue;
            }
            let id = secrets.len();
            secrets.push(secret);
            for Form {
                bytes,
                encoding,
                line,
            } in forms
            {
                let at = if let Some(&at) = index.get(bytes.as_slice()) {
                    at
                } else {
                    let at = patterns.len();
                    index.insert(bytes.to_vec(), at);
                    patterns.push(bytes);
                    owners.push(Vec::new());
                    at
                };
                if !owners[at].iter().any(|owner| owner.secret == id) {
                    owners[at].push(Owner {
                        secret: id,
                        encoding,
                        line,
                    });
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

    pub(super) fn owners(&self, pattern: usize) -> &[Owner] {
        self.owners.get(pattern).map_or(&[], Vec::as_slice)
    }

    pub(super) fn secret(&self, id: usize) -> &LeakSecret {
        &self.secrets[id]
    }
}
