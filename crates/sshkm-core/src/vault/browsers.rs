//! Browsers paired with the vault, and the logins they may see.
//!
//! A pairing is kept in the database's custom data as
//! `sshkm.browser.<client id>`, so it is encrypted with everything else, can
//! only be checked while the vault is unlocked, and goes away with the vault.
//! KeePassXC keeps its browser pairings the same way.
//!
//! The lookups take the page's [`Origin`] and only ever consider logins whose
//! address [fits](Origin::fit) it; one picked by id is checked again, so a
//! browser can't fill a page with another site's password by naming its id.
//!
//! A browser's keys change now and then ([`Vault::set_next_browser_keys`],
//! [`Vault::promote_browser_keys`]). The keys it gave up are kept a while,
//! retired: they open nothing any more, but a request sealed with one shows
//! that someone else holds a copy of them ([`BrowserKeys::open_request`]).

use keepass::db::{CustomDataItem, CustomDataValue, Times, Value, fields};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{EntryKind, Vault, check_field, parse_id, rfc3339};
use crate::browser::channel::{ChannelKeys, MessageNonce};
use crate::browser::origin::{Fit, Origin};
use crate::browser::protocol::{CheckReply, LoginOffer};
use crate::{Error, Result};

const BROWSER_PREFIX: &str = "sshkm.browser.";
/// Most logins offered on one page.
const MAX_OFFERS: usize = 50;
/// Longest username a browser may set on a login.
const MAX_USERNAME: usize = 256;
/// Most retired keys kept per browser: with keys changing once a day, about
/// a month of them.
const MAX_RETIRED: usize = 30;

/// A paired browser, as the app lists it. Holds no keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct PairedBrowser {
    /// The client id the extension made.
    pub id: String,
    /// The browser's name as the extension reported it, e.g. "Firefox".
    pub browser: String,
    /// The computer it was paired on.
    pub computer: String,
    /// RFC 3339, UTC.
    pub paired: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Stored {
    browser: String,
    computer: String,
    /// The extension's origin as the browser told the native host.
    caller: String,
    paired: String,
    request_key: String,
    response_key: String,
    /// Keys the browser asked to change to, until it first uses them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next: Option<StoredKeys>,
    /// Keys the browser gave up, most recent first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    retired: Vec<RetiredKeys>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredKeys {
    request_key: String,
    response_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RetiredKeys {
    request_key: String,
    response_key: String,
    /// When the browser gave them up, in milliseconds since 1970.
    retired_at: u64,
}

/// The keys of a paired browser: the ones it uses, the ones it is changing
/// to, and the ones it gave up.
#[derive(Debug)]
pub struct BrowserKeys {
    current: ChannelKeys,
    next: Option<ChannelKeys>,
    /// With when each was given up, most recent first.
    retired: Vec<(ChannelKeys, u64)>,
}

/// Which of a browser's keys sealed a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeysUsed {
    Current,
    /// The keys it is changing to: from now on they are the current ones.
    Next,
    /// Keys it gave up at `retired_at` (milliseconds since 1970). A request
    /// sent after that comes from someone else holding a copy of them.
    Retired {
        retired_at: u64,
    },
}

impl BrowserKeys {
    /// Opens a request with whichever of the keys sealed it.
    pub fn open_request(
        &self,
        client_id: &str,
        nonce: &MessageNonce,
        sealed: &[u8],
    ) -> Option<(Zeroizing<Vec<u8>>, KeysUsed)> {
        let live = [
            (Some(&self.current), KeysUsed::Current),
            (self.next.as_ref(), KeysUsed::Next),
        ];
        let live = live
            .into_iter()
            .filter_map(|(keys, used)| Some((keys?, used)));
        let retired = self.retired.iter().map(|(keys, retired_at)| {
            (
                keys,
                KeysUsed::Retired {
                    retired_at: *retired_at,
                },
            )
        });
        live.chain(retired).find_map(|(keys, used)| {
            let plain = keys.open_request(client_id, nonce, sealed).ok()?;
            Some((plain, used))
        })
    }

    /// The keys that answer a request sealed with `used`: none for retired
    /// keys, which get no answer.
    pub fn answering(&self, used: KeysUsed) -> Option<&ChannelKeys> {
        match used {
            KeysUsed::Current => Some(&self.current),
            KeysUsed::Next => self.next.as_ref(),
            KeysUsed::Retired { .. } => None,
        }
    }
}

impl Vault {
    /// The browsers paired with this vault, most recent first.
    pub fn paired_browsers(&self) -> Vec<PairedBrowser> {
        let mut browsers: Vec<PairedBrowser> = self
            .db
            .meta
            .custom_data
            .iter()
            .filter_map(|(key, item)| {
                let id = key.strip_prefix(BROWSER_PREFIX)?;
                let stored = stored(item)?;
                Some(PairedBrowser {
                    id: id.to_owned(),
                    browser: stored.browser,
                    computer: stored.computer,
                    paired: stored.paired,
                })
            })
            .collect();
        browsers.sort_by(|a, b| b.paired.cmp(&a.paired).then_with(|| a.id.cmp(&b.id)));
        browsers
    }

    /// A paired browser.
    pub fn paired_browser(&self, client_id: &str) -> Option<PairedBrowser> {
        let stored = self.stored_browser(client_id)?;
        Some(PairedBrowser {
            id: client_id.to_owned(),
            browser: stored.browser,
            computer: stored.computer,
            paired: stored.paired,
        })
    }

    /// The keys of a paired browser.
    pub fn browser_keys(&self, client_id: &str) -> Option<BrowserKeys> {
        let stored = self.stored_browser(client_id)?;
        let next = stored
            .next
            .and_then(|keys| ChannelKeys::from_base64(&keys.request_key, &keys.response_key).ok());
        let retired = stored
            .retired
            .iter()
            .filter_map(|keys| {
                let channel = ChannelKeys::from_base64(&keys.request_key, &keys.response_key);
                Some((channel.ok()?, keys.retired_at))
            })
            .collect();
        Some(BrowserKeys {
            current: ChannelKeys::from_base64(&stored.request_key, &stored.response_key).ok()?,
            next,
            retired,
        })
    }

    /// Records the keys a paired browser asked to change to. They open its
    /// requests alongside the current ones until it first uses them
    /// ([`Self::promote_browser_keys`]); asking again replaces them.
    pub fn set_next_browser_keys(&mut self, client_id: &str, keys: &ChannelKeys) -> Result<()> {
        let (request_key, response_key) = keys.to_base64();
        self.change_browser(client_id, |stored| {
            stored.next = Some(StoredKeys {
                request_key: request_key.to_string(),
                response_key: response_key.to_string(),
            });
        })
    }

    /// Makes a browser's next keys its current ones, now that it used them,
    /// and retires the old ones as of `now` (milliseconds since 1970).
    pub fn promote_browser_keys(&mut self, client_id: &str, now: u64) -> Result<()> {
        self.change_browser(client_id, |stored| {
            let Some(next) = stored.next.take() else {
                return;
            };
            let old_request = std::mem::replace(&mut stored.request_key, next.request_key);
            let old_response = std::mem::replace(&mut stored.response_key, next.response_key);
            stored.retired.insert(
                0,
                RetiredKeys {
                    request_key: old_request,
                    response_key: old_response,
                    retired_at: now,
                },
            );
            stored.retired.truncate(MAX_RETIRED);
        })
    }

    fn stored_browser(&self, client_id: &str) -> Option<Stored> {
        let item = self
            .db
            .meta
            .custom_data
            .get(&format!("{BROWSER_PREFIX}{client_id}"))?;
        stored(item)
    }

    fn change_browser(&mut self, client_id: &str, change: impl FnOnce(&mut Stored)) -> Result<()> {
        let mut stored = self
            .stored_browser(client_id)
            .ok_or_else(|| Error::NotFound(format!("browser {client_id}")))?;
        change(&mut stored);
        self.store_browser(client_id, &stored)
    }

    fn store_browser(&mut self, client_id: &str, stored: &Stored) -> Result<()> {
        let json = serde_json::to_string(stored)
            .map_err(|e| Error::Parse(format!("browser pairing: {e}")))?;
        self.db.meta.custom_data.insert(
            format!("{BROWSER_PREFIX}{client_id}"),
            CustomDataItem {
                value: Some(CustomDataValue::String(json)),
                last_modification_time: Some(Times::now()),
            },
        );
        Ok(())
    }

    /// Records a pairing the user approved, replacing one with the same id.
    /// `browser.paired` is set to now.
    pub fn add_browser(
        &mut self,
        browser: &PairedBrowser,
        caller: &str,
        keys: &ChannelKeys,
    ) -> Result<PairedBrowser> {
        crate::browser::channel::check_client_id(&browser.id)?;
        for value in [&browser.browser, &browser.computer, caller] {
            if value.len() > 256 {
                return Err(Error::invalid("a value is too long"));
            }
            check_field(value)?;
        }
        let (request_key, response_key) = keys.to_base64();
        let stored = Stored {
            browser: browser.browser.clone(),
            computer: browser.computer.clone(),
            caller: caller.to_owned(),
            paired: rfc3339(Times::now()),
            request_key: request_key.to_string(),
            response_key: response_key.to_string(),
            next: None,
            retired: Vec::new(),
        };
        self.store_browser(&browser.id, &stored)?;
        Ok(PairedBrowser {
            paired: stored.paired,
            ..browser.clone()
        })
    }

    /// Forgets a paired browser. Returns whether it was there.
    pub fn remove_browser(&mut self, client_id: &str) -> bool {
        self.db
            .meta
            .custom_data
            .remove(&format!("{BROWSER_PREFIX}{client_id}"))
            .is_some()
    }

    /// The logins to offer on a page, those for its very host first.
    pub fn logins_for(&self, page: &Origin) -> Vec<LoginOffer> {
        let mut offers: Vec<LoginOffer> = self
            .entries()
            .into_iter()
            .filter(|e| e.kind == EntryKind::Login && !e.in_trash)
            .filter_map(|e| {
                let fit = page.fit(&e.url)?;
                Some(LoginOffer {
                    id: e.id,
                    title: e.title,
                    username: e.username,
                    exact: fit == Fit::Host,
                })
            })
            .collect();
        // `entries` is sorted by title; keep that within each group.
        offers.sort_by_key(|offer| !offer.exact);
        offers.truncate(MAX_OFFERS);
        offers
    }

    /// A login picked on a page, without its password: what to ask the user
    /// about before filling it. Fails with `NotFound` if the login does not
    /// belong to the page.
    pub fn offer_for(&self, page: &Origin, id: &str) -> Result<LoginOffer> {
        let entry = self.find(id)?;
        let summary = self.summary(&entry);
        let fit = fit_of(page, &summary)?;
        Ok(LoginOffer {
            id: summary.id,
            title: summary.title,
            username: summary.username,
            exact: fit == Fit::Host,
        })
    }

    /// The username and password of a login picked on a page. Fails with
    /// `NotFound` if the login does not belong to the page.
    pub fn fill_for(&self, page: &Origin, id: &str) -> Result<(String, SecretString)> {
        let entry = self.find(id)?;
        let summary = self.summary(&entry);
        fit_of(page, &summary)?;
        let password = SecretString::from(entry.get(fields::PASSWORD).unwrap_or_default());
        Ok((summary.username, password))
    }

    /// Whether a login typed into a page is new, has a new password, or is
    /// saved already. Usernames compare without case and outer spaces.
    pub fn check_login(
        &self,
        page: &Origin,
        username: &str,
        password: &SecretString,
    ) -> CheckReply {
        let username = username.trim();
        let mut update = None;
        for offer in self.logins_for(page) {
            if offer.username.trim().to_lowercase() != username.to_lowercase() {
                continue;
            }
            let same = self
                .secret(&offer.id, super::SecretField::Password)
                .is_ok_and(|saved| saved.expose_secret() == password.expose_secret());
            if same {
                return CheckReply::Saved;
            }
            update.get_or_insert(CheckReply::Update {
                entry_id: offer.id,
                title: offer.title,
            });
        }
        update.unwrap_or(CheckReply::New)
    }

    /// Saves a new login for a page: titled after the site, with the page's
    /// origin as its address. Returns its id.
    pub fn save_login(
        &mut self,
        page: &Origin,
        username: &str,
        password: &SecretString,
    ) -> Result<String> {
        if password.expose_secret().is_empty() {
            return Err(Error::invalid("the password is empty"));
        }
        let input = super::EntryInput {
            title: page.name().to_owned(),
            username: username.trim().to_owned(),
            password: Some(SecretString::from(password.expose_secret())),
            url: page.to_string(),
            ..super::EntryInput::default()
        };
        self.add_entry(&input)
    }

    /// Sets a new password on a login of a page, keeping the old one in the
    /// entry's history.
    pub fn update_login(&mut self, page: &Origin, id: &str, password: &SecretString) -> Result<()> {
        if password.expose_secret().is_empty() {
            return Err(Error::invalid("the password is empty"));
        }
        check_field(password.expose_secret())?;
        self.fill_for(page, id)?;
        let mut entry = self
            .db
            .entry_mut(parse_id(id)?)
            .ok_or_else(|| Error::NotFound(format!("entry {id}")))?;
        if entry.get(fields::PASSWORD) == Some(password.expose_secret()) {
            return Ok(());
        }
        let mut tracked = entry.track_changes();
        tracked.set(fields::PASSWORD, Value::protected(password.expose_secret()));
        tracked.times.last_modification = Some(Times::now());
        Ok(())
    }

    /// Changes the username and/or the password of a login of a page, from
    /// the extension's popup. The previous version goes to the entry's
    /// history. `None` keeps a value as it is; a password can't be emptied.
    pub fn edit_login(
        &mut self,
        page: &Origin,
        id: &str,
        username: Option<&str>,
        password: Option<&SecretString>,
    ) -> Result<()> {
        let username = username.map(str::trim);
        if let Some(username) = username {
            if username.len() > MAX_USERNAME {
                return Err(Error::invalid("the username is too long"));
            }
            check_field(username)?;
        }
        if let Some(password) = password {
            if password.expose_secret().is_empty() {
                return Err(Error::invalid("the password is empty"));
            }
            check_field(password.expose_secret())?;
        }
        self.fill_for(page, id)?;
        let mut entry = self
            .db
            .entry_mut(parse_id(id)?)
            .ok_or_else(|| Error::NotFound(format!("entry {id}")))?;
        let username = username.filter(|u| entry.get(fields::USERNAME).unwrap_or_default() != *u);
        let password = password.filter(|p| entry.get(fields::PASSWORD) != Some(p.expose_secret()));
        if username.is_none() && password.is_none() {
            return Ok(());
        }
        let mut tracked = entry.track_changes();
        if let Some(username) = username {
            tracked.set(fields::USERNAME, Value::unprotected(username));
        }
        if let Some(password) = password {
            tracked.set(fields::PASSWORD, Value::protected(password.expose_secret()));
        }
        tracked.times.last_modification = Some(Times::now());
        Ok(())
    }

    /// Moves a login of a page to the recycle bin, where the app can restore
    /// it. Never deletes it for good.
    pub fn remove_login(&mut self, page: &Origin, id: &str) -> Result<()> {
        self.fill_for(page, id)?;
        self.trash_entry(id)
    }
}

/// How a login fits a page; `NotFound` if it is not a login of the page.
fn fit_of(page: &Origin, summary: &super::EntrySummary) -> Result<Fit> {
    if summary.kind != EntryKind::Login || summary.in_trash {
        return Err(Error::NotFound(format!("a login for {page}")));
    }
    page.fit(&summary.url)
        .ok_or_else(|| Error::NotFound(format!("a login for {page}")))
}

fn stored(item: &CustomDataItem) -> Option<Stored> {
    match item.value.as_ref()? {
        CustomDataValue::String(json) => serde_json::from_str(json).ok(),
        CustomDataValue::Binary(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use p256::SecretKey;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use rand_core::OsRng;

    use super::*;
    use crate::browser::channel::accept_pairing;
    use crate::vault::{EntryInput, VaultPaths};

    fn s(text: &str) -> SecretString {
        SecretString::from(text.to_owned())
    }

    fn login(title: &str, username: &str, url: &str, password: &str) -> EntryInput {
        EntryInput {
            title: title.into(),
            username: username.into(),
            password: Some(s(password)),
            url: url.into(),
            ..EntryInput::default()
        }
    }

    fn page(origin: &str) -> Origin {
        Origin::parse(origin).unwrap()
    }

    fn vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("vault.kdbx"));
        let (vault, _) = Vault::create(&paths, &s("master")).unwrap();
        (dir, vault)
    }

    #[test]
    fn pairings_are_saved_in_the_vault_and_can_be_revoked() {
        let (dir, mut vault) = vault();
        let public = SecretKey::random(&mut OsRng)
            .public_key()
            .to_encoded_point(false);
        let pairing = accept_pairing("client-0123456789abcdef", public.as_bytes()).unwrap();
        let browser = PairedBrowser {
            id: "client-0123456789abcdef".into(),
            browser: "Firefox".into(),
            computer: "laptop".into(),
            paired: String::new(),
        };
        let added = vault
            .add_browser(&browser, "autofill@sshkeymanager.dev", &pairing.keys)
            .unwrap();
        assert_ne!(added.paired, "");
        vault.save(&dir.path().join("backups")).unwrap();

        let paths = VaultPaths::new(dir.path().join("vault.kdbx"));
        let mut reopened = Vault::unlock(&paths, &s("master")).unwrap();
        assert_eq!(reopened.paired_browsers(), vec![added.clone()]);
        assert_eq!(
            reopened.paired_browser("client-0123456789abcdef"),
            Some(added)
        );
        let keys = reopened.browser_keys("client-0123456789abcdef").unwrap();
        assert_eq!(
            used(&keys, &pairing.keys, "client-0123456789abcdef"),
            Some(KeysUsed::Current)
        );
        assert!(reopened.browser_keys("someone-else-0123456").is_none());

        assert!(reopened.remove_browser("client-0123456789abcdef"));
        assert!(!reopened.remove_browser("client-0123456789abcdef"));
        assert_eq!(reopened.paired_browsers(), Vec::new());
        assert!(reopened.browser_keys("client-0123456789abcdef").is_none());
        assert!(
            reopened
                .add_browser(
                    &PairedBrowser {
                        id: "bad id".into(),
                        ..browser
                    },
                    "",
                    &pairing.keys
                )
                .is_err()
        );
    }

    const CLIENT: &str = "client-0123456789abcdef";

    fn new_keys() -> ChannelKeys {
        let public = SecretKey::random(&mut OsRng)
            .public_key()
            .to_encoded_point(false);
        accept_pairing(CLIENT, public.as_bytes()).unwrap().keys
    }

    /// Which of the stored keys opens a request sealed with `sealing`.
    fn used(keys: &BrowserKeys, sealing: &ChannelKeys, client: &str) -> Option<KeysUsed> {
        let (nonce, sealed) = sealing.seal_request(client, b"hi").unwrap();
        keys.open_request(client, &nonce, &sealed)
            .map(|(plain, used)| {
                assert_eq!(plain.as_slice(), b"hi");
                used
            })
    }

    #[test]
    fn keys_change_and_the_old_ones_stay_recognised() {
        let (dir, mut vault) = vault();
        let browser = PairedBrowser {
            id: CLIENT.into(),
            browser: "Chrome".into(),
            computer: "laptop".into(),
            paired: String::new(),
        };
        let first = new_keys();
        vault.add_browser(&browser, "", &first).unwrap();
        let second = new_keys();
        vault.set_next_browser_keys(CLIENT, &second).unwrap();
        let keys = vault.browser_keys(CLIENT).unwrap();
        assert_eq!(used(&keys, &first, CLIENT), Some(KeysUsed::Current));
        assert_eq!(used(&keys, &second, CLIENT), Some(KeysUsed::Next));
        assert!(keys.answering(KeysUsed::Next).is_some());

        // Once the browser uses them, the new keys are the current ones.
        vault.promote_browser_keys(CLIENT, 1_000).unwrap();
        vault.save(&dir.path().join("backups")).unwrap();
        let paths = VaultPaths::new(dir.path().join("vault.kdbx"));
        let mut vault = Vault::unlock(&paths, &s("master")).unwrap();
        let keys = vault.browser_keys(CLIENT).unwrap();
        assert_eq!(used(&keys, &second, CLIENT), Some(KeysUsed::Current));
        let retired = KeysUsed::Retired { retired_at: 1_000 };
        assert_eq!(used(&keys, &first, CLIENT), Some(retired));
        assert!(keys.answering(retired).is_none());
        assert_eq!(used(&keys, &new_keys(), CLIENT), None);
        // Nothing to promote: nothing changes.
        vault.promote_browser_keys(CLIENT, 2_000).unwrap();
        let keys = vault.browser_keys(CLIENT).unwrap();
        assert_eq!(used(&keys, &second, CLIENT), Some(KeysUsed::Current));
        assert_eq!(used(&keys, &first, CLIENT), Some(retired));

        // Only the most recent retired keys are kept.
        for n in 0..MAX_RETIRED {
            vault.set_next_browser_keys(CLIENT, &new_keys()).unwrap();
            vault
                .promote_browser_keys(CLIENT, 3_000 + n as u64)
                .unwrap();
        }
        let keys = vault.browser_keys(CLIENT).unwrap();
        assert_eq!(
            used(&keys, &second, CLIENT),
            Some(KeysUsed::Retired { retired_at: 3_000 })
        );
        assert_eq!(used(&keys, &first, CLIENT), None);

        assert!(
            vault
                .set_next_browser_keys("someone-else-0123456", &new_keys())
                .is_err()
        );
        assert!(
            vault
                .promote_browser_keys("someone-else-0123456", 1)
                .is_err()
        );
    }

    #[test]
    fn a_pairing_saved_before_keys_changed_still_reads() {
        let (_dir, mut vault) = vault();
        let keys = new_keys();
        let (request_key, response_key) = keys.to_base64();
        let old = format!(
            r#"{{"browser":"Firefox","computer":"pc","caller":"x","paired":"2026-01-01T00:00:00Z","requestKey":"{}","responseKey":"{}"}}"#,
            *request_key, *response_key
        );
        vault.db.meta.custom_data.insert(
            format!("{BROWSER_PREFIX}{CLIENT}"),
            CustomDataItem {
                value: Some(CustomDataValue::String(old)),
                last_modification_time: None,
            },
        );
        let stored = vault.browser_keys(CLIENT).unwrap();
        assert_eq!(used(&stored, &keys, CLIENT), Some(KeysUsed::Current));
        assert_eq!(vault.paired_browsers().len(), 1);
    }

    #[test]
    fn only_logins_of_the_site_are_offered() {
        let (_dir, mut vault) = vault();
        let exact = vault
            .add_entry(&login("GitHub", "me", "https://github.com", "a"))
            .unwrap();
        let site = vault
            .add_entry(&login("Gist", "me2", "gist.github.com", "b"))
            .unwrap();
        vault
            .add_entry(&login(
                "Look-alike",
                "me",
                "https://github.com.evil.io",
                "c",
            ))
            .unwrap();
        vault
            .add_entry(&login("Insecure page only", "me", "http://github.com", "d"))
            .unwrap();
        let trashed = vault
            .add_entry(&login("Old GitHub", "old", "https://github.com", "e"))
            .unwrap();
        vault.trash_entry(&trashed).unwrap();
        vault
            .add_entry(&EntryInput {
                kind: EntryKind::Host,
                host: Some("github".into()),
                ..login("SSH host", "git", "https://github.com", "f")
            })
            .unwrap();

        let offers = vault.logins_for(&page("https://github.com"));
        let ids: Vec<(&str, bool)> = offers.iter().map(|o| (o.id.as_str(), o.exact)).collect();
        // The http entry fits an https page too; exact hosts come first.
        assert_eq!(ids.len(), 3, "{offers:?}");
        assert!(ids[..2].iter().all(|(_, exact)| *exact));
        assert_eq!(ids[2], (site.as_str(), false));
        assert!(ids.iter().any(|(id, _)| *id == exact));

        assert_eq!(vault.logins_for(&page("https://githuh.com")), Vec::new());
        assert_eq!(vault.logins_for(&page("http://github.com")).len(), 1);
    }

    #[test]
    fn a_login_fills_only_its_own_site() {
        let (_dir, mut vault) = vault();
        let id = vault
            .add_entry(&login("Bank", "alice", "https://bank.example", "s3cret"))
            .unwrap();
        let (username, password) = vault
            .fill_for(&page("https://www.bank.example"), &id)
            .unwrap();
        assert_eq!(
            (username.as_str(), password.expose_secret()),
            ("alice", "s3cret")
        );
        let offer = vault
            .offer_for(&page("https://www.bank.example"), &id)
            .unwrap();
        assert_eq!(
            (offer.title.as_str(), offer.username.as_str(), offer.exact),
            ("Bank", "alice", false)
        );
        assert!(vault.offer_for(&page("https://evil.example"), &id).is_err());
        let wrong = vault
            .fill_for(&page("https://evil.example"), &id)
            .unwrap_err();
        assert_eq!(wrong.code(), crate::ErrorCode::NotFound);
        assert!(vault.fill_for(&page("http://bank.example"), &id).is_err());
        assert!(
            vault
                .fill_for(&page("https://bank.example"), "not-an-id")
                .is_err()
        );
    }

    #[test]
    fn typed_logins_are_checked_saved_and_updated() {
        let (_dir, mut vault) = vault();
        let shop = page("https://shop.example.com");
        assert_eq!(vault.check_login(&shop, "bob", &s("pw1")), CheckReply::New);

        let id = vault.save_login(&shop, " bob ", &s("pw1")).unwrap();
        let entry = vault.entry(&id).unwrap();
        assert_eq!(entry.summary.title, "example.com");
        assert_eq!(entry.summary.url, "https://shop.example.com");
        assert_eq!(entry.summary.username, "bob");
        assert_eq!(
            vault.check_login(&shop, "BOB", &s("pw1")),
            CheckReply::Saved
        );
        assert_eq!(
            vault.check_login(&shop, "bob", &s("pw2")),
            CheckReply::Update {
                entry_id: id.clone(),
                title: "example.com".into()
            }
        );
        assert_eq!(
            vault.check_login(&shop, "carol", &s("pw1")),
            CheckReply::New
        );

        vault.update_login(&shop, &id, &s("pw2")).unwrap();
        assert_eq!(
            vault
                .secret(&id, crate::vault::SecretField::Password)
                .unwrap()
                .expose_secret(),
            "pw2"
        );
        assert_eq!(vault.entry(&id).unwrap().history_len, 1);
        assert!(
            vault
                .update_login(&page("https://other.com"), &id, &s("x"))
                .is_err()
        );
        assert!(vault.save_login(&shop, "bob", &s("")).is_err());
    }

    #[test]
    fn logins_are_edited_and_removed_only_on_their_own_site() {
        let (_dir, mut vault) = vault();
        let shop = page("https://shop.example.com");
        let other = page("https://other.com");
        let id = vault.save_login(&shop, "bob", &s("pw1")).unwrap();

        // Another site can't touch it by naming its id.
        let wrong = vault
            .edit_login(&other, &id, Some("eve"), Some(&s("x")))
            .unwrap_err();
        assert_eq!(wrong.code(), crate::ErrorCode::NotFound);
        assert_eq!(
            vault.remove_login(&other, &id).unwrap_err().code(),
            crate::ErrorCode::NotFound
        );

        // The username alone: the password stays.
        vault
            .edit_login(&shop, &id, Some(" robert "), None)
            .unwrap();
        let entry = vault.entry(&id).unwrap();
        assert_eq!(entry.summary.username, "robert");
        assert_eq!(entry.history_len, 1);
        assert_eq!(
            vault.check_login(&shop, "robert", &s("pw1")),
            CheckReply::Saved
        );

        // The password alone: the old one goes to the history.
        vault.edit_login(&shop, &id, None, Some(&s("pw2"))).unwrap();
        assert_eq!(
            vault
                .secret(&id, crate::vault::SecretField::Password)
                .unwrap()
                .expose_secret(),
            "pw2"
        );
        assert_eq!(vault.entry(&id).unwrap().history_len, 2);

        // Nothing new: no new history.
        vault
            .edit_login(&shop, &id, Some("robert"), Some(&s("pw2")))
            .unwrap();
        vault.edit_login(&shop, &id, None, None).unwrap();
        assert_eq!(vault.entry(&id).unwrap().history_len, 2);

        assert!(vault.edit_login(&shop, &id, None, Some(&s(""))).is_err());
        assert!(
            vault
                .edit_login(&shop, &id, Some(&"x".repeat(MAX_USERNAME + 1)), None)
                .is_err()
        );
        assert!(vault.edit_login(&shop, &id, Some("a\0b"), None).is_err());

        // Removing moves it to the recycle bin, where it is no login of the
        // page any more.
        vault.remove_login(&shop, &id).unwrap();
        let entry = vault.entry(&id).unwrap();
        assert!(entry.summary.in_trash);
        assert_eq!(vault.logins_for(&shop), Vec::new());
        assert!(vault.remove_login(&shop, &id).is_err());
        assert!(vault.edit_login(&shop, &id, Some("x"), None).is_err());
        vault.restore_entry(&id).unwrap();
        assert_eq!(vault.logins_for(&shop).len(), 1);
    }
}
