//! Whether saved passwords appear in known data breaches, through Have I
//! Been Pwned's Pwned Passwords range API, with k-anonymity.
//!
//! Only the first five hex characters of a password's SHA-1 hash are sent
//! ([`RangePrefix::url`]). The server answers with every hash suffix it
//! knows under that prefix and how often each was seen, padded with made-up
//! suffixes seen 0 times ([`PADDING_HEADER`]) so that the answer's size says
//! nothing either. The suffixes are compared here ([`BreachQuery::answer`]).
//! This module does no networking: the app fetches each range and hands the
//! answer over, so the tests need no network.
//!
//! Results stay in a [`BreachCache`], under an HMAC-SHA-256 of each password
//! with a random key that only the cache has: an unchanged password isn't
//! asked about again, and without that key the cache says nothing about the
//! passwords. Keep it no longer than the unlocked vault.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::time::Instant;

use hmac::{Hmac, Mac};
use keepass::db::fields;
use rand_core::{OsRng, RngCore};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::Vault;
use crate::{Error, Result};

/// The range API; the prefix goes after it.
pub const RANGE_URL: &str = "https://api.pwnedpasswords.com/range/";
/// Asks the server to pad its answer (see the module documentation).
pub const PADDING_HEADER: (&str, &str) = ("Add-Padding", "true");
/// Longest answer read. Padded answers are about 40 KiB.
pub const MAX_RANGE_BYTES: usize = 1 << 20;

/// Hex characters of the hash that are sent, and that come back.
const PREFIX_LEN: usize = 5;
const SUFFIX_LEN: usize = 40 - PREFIX_LEN;

type Tag = [u8; 32];

/// The first five hex characters (upper case) of a SHA-1 hash: all that is
/// sent about a password.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RangePrefix(String);

impl RangePrefix {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The address to ask for this range.
    pub fn url(&self) -> String {
        format!("{RANGE_URL}{}", self.0)
    }
}

/// What a password's check found, and when.
#[derive(Clone, Copy)]
struct Known {
    count: u32,
    checked: Instant,
}

/// Results of earlier checks (see the module documentation).
pub struct BreachCache {
    key: Zeroizing<[u8; 32]>,
    /// Tells this cache from an earlier one, whose queries no longer apply.
    epoch: u64,
    known: HashMap<Tag, Known>,
}

impl Default for BreachCache {
    fn default() -> Self {
        let mut key = Zeroizing::new([0; 32]);
        OsRng.fill_bytes(key.as_mut());
        Self {
            key,
            epoch: OsRng.next_u64(),
            known: HashMap::new(),
        }
    }
}

impl fmt::Debug for BreachCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BreachCache")
            .field("results", &self.known.len())
            .finish_non_exhaustive()
    }
}

impl BreachCache {
    /// An empty cache with a new key.
    pub fn new() -> Self {
        Self::default()
    }

    fn tag(&self, password: &str) -> Tag {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.key.as_ref()).expect("HMAC takes any key size");
        mac.update(password.as_bytes());
        mac.finalize().into_bytes().into()
    }

    /// How many times the password was seen in breaches, if it was checked.
    pub fn count(&self, password: &str) -> Option<u32> {
        self.known.get(&self.tag(password)).map(|k| k.count)
    }

    /// Passwords with a result.
    pub fn len(&self) -> usize {
        self.known.len()
    }

    pub fn is_empty(&self) -> bool {
        self.known.is_empty()
    }
}

/// A password waiting for its range: its tag and the rest of its hash.
struct Pending {
    tag: Tag,
    suffix: Zeroizing<String>,
}

/// The passwords to check, by the range each is in. The hash suffixes stay
/// here, in memory, until their range is answered.
pub struct BreachQuery {
    epoch: u64,
    pending: BTreeMap<RangePrefix, Vec<Pending>>,
}

impl fmt::Debug for BreachQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BreachQuery")
            .field("ranges", &self.pending.len())
            .field("passwords", &self.passwords())
            .finish_non_exhaustive()
    }
}

impl BreachQuery {
    /// An empty query for `cache`.
    pub fn new(cache: &BreachCache) -> Self {
        Self {
            epoch: cache.epoch,
            pending: BTreeMap::new(),
        }
    }

    /// Adds a password, unless it is in already.
    pub fn add(&mut self, cache: &BreachCache, password: &str) {
        let tag = cache.tag(password);
        let hash = Zeroizing::new(hex_upper(&Sha1::digest(password.as_bytes())));
        let (prefix, suffix) = hash.split_at(PREFIX_LEN);
        let pending = self
            .pending
            .entry(RangePrefix(prefix.to_owned()))
            .or_default();
        if !pending.iter().any(|p| p.tag == tag) {
            pending.push(Pending {
                tag,
                suffix: Zeroizing::new(suffix.to_owned()),
            });
        }
    }

    /// The ranges to ask for, in order.
    pub fn prefixes(&self) -> Vec<RangePrefix> {
        self.pending.keys().cloned().collect()
    }

    /// Passwords still waiting.
    pub fn passwords(&self) -> usize {
        self.pending.values().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Compares the passwords in the range of `prefix` with `body`, the
    /// server's answer, and records how often each was seen in `cache` (0
    /// if it isn't in the answer). Returns how many passwords that was.
    ///
    /// Fails with `parse` on an answer that isn't a range (nothing is
    /// recorded), and with `conflict` if `cache` isn't the one the query was
    /// made for.
    pub fn answer(
        &mut self,
        prefix: &RangePrefix,
        body: &str,
        cache: &mut BreachCache,
        now: Instant,
    ) -> Result<usize> {
        if cache.epoch != self.epoch {
            return Err(Error::Conflict("the breach results were cleared".into()));
        }
        let counts = parse_range(body)?;
        let Some(pending) = self.pending.remove(prefix) else {
            return Ok(0);
        };
        for password in &pending {
            let count = counts.get(password.suffix.as_str()).copied().unwrap_or(0);
            cache.known.insert(
                password.tag,
                Known {
                    count,
                    checked: now,
                },
            );
        }
        Ok(pending.len())
    }
}

impl Vault {
    /// The passwords the audit rates (outside the recycle bin, not empty, not
    /// excluded from KeePass's quality check) that `cache` has no result
    /// for, or only one from before `stale_before`.
    pub fn breach_query(&self, cache: &BreachCache, stale_before: Option<Instant>) -> BreachQuery {
        let mut query = BreachQuery::new(cache);
        for entry in self.db.iter_all_entries() {
            let password = entry.get(fields::PASSWORD).unwrap_or_default();
            if password.is_empty() || !entry.quality_check || self.summary(&entry).in_trash {
                continue;
            }
            let fresh = cache
                .known
                .get(&cache.tag(password))
                .is_some_and(|known| stale_before.is_none_or(|time| known.checked >= time));
            if !fresh {
                query.add(cache, password);
            }
        }
        query
    }
}

/// The counts of a range answer by suffix (upper case). Each line is
/// `SUFFIX:COUNT`; padding lines have a count of 0.
fn parse_range(body: &str) -> Result<HashMap<String, u32>> {
    let invalid = || Error::Parse("the breach service sent an answer that isn't a range".into());
    if body.len() > MAX_RANGE_BYTES {
        return Err(invalid());
    }
    let mut counts = HashMap::new();
    for line in body.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let (suffix, count) = line.split_once(':').ok_or_else(invalid)?;
        let valid = suffix.len() == SUFFIX_LEN
            && suffix.bytes().all(|b| b.is_ascii_hexdigit())
            && !count.is_empty()
            && count.bytes().all(|b| b.is_ascii_digit());
        if !valid {
            return Err(invalid());
        }
        // Counts beyond u32 don't happen; they would still be "many".
        let count = count
            .parse::<u64>()
            .map_or(u32::MAX, |n| u32::try_from(n).unwrap_or(u32::MAX));
        counts.insert(suffix.to_ascii_uppercase(), count);
    }
    Ok(counts)
}

fn hex_upper(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02X}");
        s
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use secrecy::SecretString;

    use super::*;
    use crate::ErrorCode;
    use crate::vault::{EntryInput, VaultPaths};

    /// SHA-1 of "password": 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8.
    const PASSWORD_SUFFIX: &str = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    fn range(lines: &[&str]) -> String {
        lines.join("\r\n")
    }

    #[test]
    fn only_the_prefix_is_sent() {
        let cache = BreachCache::new();
        let mut query = BreachQuery::new(&cache);
        query.add(&cache, "password");
        query.add(&cache, "password");
        query.add(&cache, "correct horse battery staple");
        assert_eq!(query.passwords(), 2);
        let prefixes = query.prefixes();
        assert_eq!(prefixes.len(), 2);
        let first = &prefixes[prefixes.iter().position(|p| p.as_str() == "5BAA6").unwrap()];
        assert_eq!(first.url(), "https://api.pwnedpasswords.com/range/5BAA6");
        for prefix in &prefixes {
            assert_eq!(prefix.as_str().len(), 5);
            assert!(prefix.as_str().bytes().all(|b| b.is_ascii_hexdigit()));
        }
        assert_eq!(PADDING_HEADER, ("Add-Padding", "true"));
        // Nothing of the password or its full hash in what can be printed.
        let printed = format!("{query:?} {cache:?}");
        assert!(!printed.contains(PASSWORD_SUFFIX) && !printed.contains("5BAA6"));
    }

    #[test]
    fn suffixes_are_compared_here() {
        let mut cache = BreachCache::new();
        let mut query = BreachQuery::new(&cache);
        query.add(&cache, "password");
        query.add(&cache, "P@ssw0rd-not-in-this-range");
        let prefix = RangePrefix("5BAA6".into());
        let now = Instant::now();
        let body = range(&[
            "0018A45C4D1DEF81644B54AB7F969B88D65:10",
            &format!("{PASSWORD_SUFFIX}:10434004"),
            "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0",
            "",
        ]);
        assert_eq!(query.answer(&prefix, &body, &mut cache, now).unwrap(), 1);
        assert_eq!(cache.count("password"), Some(10_434_004));
        assert_eq!(cache.count("P@ssw0rd-not-in-this-range"), None);
        // A range answered again, or never asked for, changes nothing.
        assert_eq!(query.answer(&prefix, &body, &mut cache, now).unwrap(), 0);
        assert_eq!(query.passwords(), 1);

        let other = query.prefixes().remove(0);
        // Not in the answer, or only as padding: seen 0 times.
        query
            .answer(
                &other,
                "0018A45C4D1DEF81644B54AB7F969B88D65:3\n",
                &mut cache,
                now,
            )
            .unwrap();
        assert_eq!(cache.count("P@ssw0rd-not-in-this-range"), Some(0));
        assert!(query.is_empty());
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn padding_lines_count_as_not_found() {
        let mut cache = BreachCache::new();
        let mut query = BreachQuery::new(&cache);
        query.add(&cache, "password");
        let body = format!("{PASSWORD_SUFFIX}:0\r\n");
        query
            .answer(
                &RangePrefix("5BAA6".into()),
                &body,
                &mut cache,
                Instant::now(),
            )
            .unwrap();
        assert_eq!(cache.count("password"), Some(0));
    }

    #[test]
    fn bad_answers_record_nothing() {
        let prefix = RangePrefix("5BAA6".into());
        for body in [
            "<html>Too many requests</html>",
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8",
            "1E4C9B93F3F0682250B6CF8331B7EE68FD:5",
            "1E4C9B93F3F0682250B6CF8331B7EE68FDG:5",
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8:",
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8:-1",
            &"0".repeat(MAX_RANGE_BYTES + 1),
        ] {
            let mut cache = BreachCache::new();
            let mut query = BreachQuery::new(&cache);
            query.add(&cache, "password");
            let error = query
                .answer(&prefix, body, &mut cache, Instant::now())
                .unwrap_err();
            assert_eq!(error.code(), ErrorCode::Parse, "{body:.40}");
            assert!(cache.is_empty());
            assert_eq!(query.passwords(), 1);
        }
        // Lower case is read too, and huge counts are still counts.
        assert_eq!(
            parse_range("1e4c9b93f3f0682250b6cf8331b7ee68fd8:5").unwrap()[PASSWORD_SUFFIX],
            5
        );
        assert_eq!(
            parse_range("1E4C9B93F3F0682250B6CF8331B7EE68FD8:99999999999999999999").unwrap()
                [PASSWORD_SUFFIX],
            u32::MAX
        );
    }

    #[test]
    fn a_new_cache_ignores_old_queries() {
        let old = BreachCache::new();
        let mut query = BreachQuery::new(&old);
        query.add(&old, "password");
        let mut cache = BreachCache::new();
        let error = query
            .answer(
                &RangePrefix("5BAA6".into()),
                &format!("{PASSWORD_SUFFIX}:5"),
                &mut cache,
                Instant::now(),
            )
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::Conflict);
        assert!(cache.is_empty());
        // Tags depend on the cache's key.
        assert_ne!(old.tag("password"), cache.tag("password"));
    }

    #[test]
    fn the_vault_asks_only_about_unchecked_passwords() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("vault.kdbx"));
        let (mut vault, _) = Vault::create(&paths, &SecretString::from("master")).unwrap();
        let login = |title: &str, password: &str| EntryInput {
            title: title.into(),
            password: Some(SecretString::from(password)),
            ..EntryInput::default()
        };
        vault.add_entry(&login("a", "password")).unwrap();
        vault.add_entry(&login("b", "password")).unwrap();
        vault
            .add_entry(&login("c", "Velvet-Tundra-Rocket-91"))
            .unwrap();
        vault.add_entry(&login("empty", "")).unwrap();
        let trashed = vault.add_entry(&login("old", "trashed one")).unwrap();
        vault.trash_entry(&trashed).unwrap();

        let mut cache = BreachCache::new();
        let mut query = vault.breach_query(&cache, None);
        assert_eq!(query.passwords(), 2);
        let start = Instant::now();
        let prefix = RangePrefix("5BAA6".into());
        query
            .answer(&prefix, &format!("{PASSWORD_SUFFIX}:7"), &mut cache, start)
            .unwrap();
        // Only the unanswered one is left; a refresh asks again.
        assert_eq!(vault.breach_query(&cache, None).passwords(), 1);
        let later = start + Duration::from_secs(1);
        assert_eq!(vault.breach_query(&cache, Some(later)).passwords(), 2);
        assert_eq!(vault.breach_query(&cache, Some(start)).passwords(), 1);
    }
}
