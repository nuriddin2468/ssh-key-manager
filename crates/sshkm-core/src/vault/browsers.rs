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

use keepass::db::{CustomDataItem, CustomDataValue, Times, Value, fields};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::{EntryKind, Vault, check_field, parse_id, rfc3339};
use crate::browser::channel::ChannelKeys;
use crate::browser::origin::{Fit, Origin};
use crate::browser::protocol::{CheckReply, LoginOffer};
use crate::{Error, Result};

const BROWSER_PREFIX: &str = "sshkm.browser.";
/// Most logins offered on one page.
const MAX_OFFERS: usize = 50;

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

    /// The keys of a paired browser.
    pub fn browser_keys(&self, client_id: &str) -> Option<ChannelKeys> {
        let item = self
            .db
            .meta
            .custom_data
            .get(&format!("{BROWSER_PREFIX}{client_id}"))?;
        let stored = stored(item)?;
        ChannelKeys::from_base64(&stored.request_key, &stored.response_key).ok()
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
        let now = Times::now();
        let (request_key, response_key) = keys.to_base64();
        let stored = Stored {
            browser: browser.browser.clone(),
            computer: browser.computer.clone(),
            caller: caller.to_owned(),
            paired: rfc3339(now),
            request_key: request_key.to_string(),
            response_key: response_key.to_string(),
        };
        let json = serde_json::to_string(&stored)
            .map_err(|e| Error::Parse(format!("browser pairing: {e}")))?;
        self.db.meta.custom_data.insert(
            format!("{BROWSER_PREFIX}{}", browser.id),
            CustomDataItem {
                value: Some(CustomDataValue::String(json)),
                last_modification_time: Some(now),
            },
        );
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

    /// The username and password of a login picked on a page. Fails with
    /// `NotFound` if the login does not belong to the page.
    pub fn fill_for(&self, page: &Origin, id: &str) -> Result<(String, SecretString)> {
        let entry = self.find(id)?;
        let summary = self.summary(&entry);
        let fits = summary.kind == EntryKind::Login
            && !summary.in_trash
            && page.fit(&summary.url).is_some();
        if !fits {
            return Err(Error::NotFound(format!("a login for {page}")));
        }
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
        assert_eq!(reopened.paired_browsers(), vec![added]);
        let keys = reopened.browser_keys("client-0123456789abcdef").unwrap();
        let (nonce, sealed) = pairing
            .keys
            .seal_request("client-0123456789abcdef", b"hi")
            .unwrap();
        assert!(
            keys.open_request("client-0123456789abcdef", &nonce, &sealed)
                .is_ok()
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
}
