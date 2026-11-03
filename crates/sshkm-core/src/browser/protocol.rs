//! The messages between the browser extension and the app, as JSON.
//!
//! The extension talks to the native messaging host, which passes each
//! message on unchanged, wrapped as `{"caller": "<extension origin>",
//! "message": …}` ([`Envelope`]). Only [`Message::Hello`], [`Message::Show`],
//! [`Message::SameSite`] and [`Message::Pair`] travel in the clear; everything
//! else is a [`Message::Request`] sealed with the paired browser's keys
//! ([`super::channel`]), whose opened payload is an [`Opened`] request.
//!
//! Requests are externally tagged (`{"fill": {…}}`, or `"status"`), so serde
//! reads a password straight into its [`SecretString`] without buffering the
//! message on the way.

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

/// The most a message may weigh, either way. Chrome refuses replies over
/// 1 MiB from a native host.
pub const MAX_MESSAGE: usize = 1024 * 1024;

/// What the native messaging host hands the app.
#[derive(Debug, Deserialize)]
pub struct Envelope {
    /// The extension's origin as the browser told the host:
    /// `chrome-extension://<id>/`, or the add-on id in Firefox.
    #[serde(default)]
    pub caller: String,
    pub message: Message,
}

/// A message from the extension.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Message {
    /// Is the app there, and is the vault locked? Needs no pairing.
    Hello,
    /// Bring the app's window forward on the vault, to unlock it.
    Show,
    /// Does a page belong to another origin's site? Needs no pairing: the
    /// answer depends on the two names alone.
    SameSite(SameSite),
    /// Pair this browser. Waits until the user decides in the app.
    Pair(PairRequest),
    /// A sealed request of a paired browser.
    Request(SealedRequest),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairRequest {
    /// Random base64url id the extension made for this pairing.
    pub client_id: String,
    /// Base64 uncompressed P-256 public key.
    pub public_key: String,
    /// Base64 nonce that the sealed confirmation answers.
    pub nonce: String,
    /// The browser's name as the extension sees it, e.g. "Chrome".
    #[serde(default)]
    pub browser: String,
}

/// Would a login of `origin` be offered on `page`? The extension asks before
/// it shows a save offer on a page other than the one the login was typed on.
#[derive(Debug, Deserialize)]
pub struct SameSite {
    pub origin: String,
    pub page: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedRequest {
    pub client_id: String,
    pub nonce: String,
    pub payload: String,
}

/// An opened request.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Opened {
    /// When the extension sent it, in milliseconds since 1970.
    pub sent_at: u64,
    pub action: Action,
}

/// What a paired browser asks.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Action {
    /// Checks that the pairing still works.
    Status,
    /// The logins for a page, without secrets.
    Logins { origin: String },
    /// The username and password of one login the user picked on the page.
    Fill {
        origin: String,
        #[serde(rename = "entryId")]
        entry_id: String,
    },
    /// Whether a login typed into the page is new, changed or already saved.
    Check {
        origin: String,
        username: String,
        password: SecretString,
    },
    /// Saves a new login for the page.
    Save {
        origin: String,
        username: String,
        password: SecretString,
    },
    /// Forgets this browser's pairing: the extension's "Disconnect".
    Disconnect,
    /// Sets a new password on a login of the page.
    Update {
        origin: String,
        #[serde(rename = "entryId")]
        entry_id: String,
        password: SecretString,
    },
}

/// A reply to the extension.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Reply {
    Hello {
        app: &'static str,
        version: String,
        protocol: u32,
        vault: VaultLock,
    },
    Shown,
    /// Answers [`Message::SameSite`].
    SameSite {
        same: bool,
    },
    /// The pairing was approved. `payload` is a sealed [`PairedInfo`]
    /// answering the request's nonce.
    Paired {
        #[serde(rename = "publicKey")]
        public_key: String,
        nonce: String,
        payload: String,
    },
    /// A sealed answer to a [`Message::Request`].
    Response {
        nonce: String,
        payload: String,
    },
    Error {
        code: ReplyError,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum VaultLock {
    /// No vault yet.
    Missing,
    Locked,
    Unlocked,
}

/// Why a message was not answered. None of these carries a secret, so they
/// travel in the clear.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ReplyError {
    /// The vault is locked, so pairings can't be checked: unlock it in the app.
    Locked,
    /// There is no vault yet.
    NoVault,
    /// No pairing with this client id in the open vault: revoked, or another
    /// vault.
    UnknownClient,
    /// The user declined the pairing.
    Denied,
    /// Nobody answered the pairing in time, or the request is too old.
    Expired,
    /// Another pairing is waiting for the user.
    Busy,
    /// The entry is gone or does not belong to the page.
    NotFound,
    /// Malformed, sealed with the wrong key, or replayed.
    Invalid,
    /// The vault could not be read or written.
    Failed,
}

/// The sealed payload of [`Reply::Paired`].
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairedInfo {
    pub paired: bool,
}

/// One login offered on a page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginOffer {
    pub id: String,
    pub title: String,
    pub username: String,
    /// Saved for this very host, not just the same site.
    pub exact: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginsReply {
    pub logins: Vec<LoginOffer>,
}

/// What [`Action::Check`] found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum CheckReply {
    /// No login with this username on the site: offer to save it.
    New,
    /// A login with this username has another password: offer to update it.
    Update {
        #[serde(rename = "entryId")]
        entry_id: String,
        title: String,
    },
    /// Already saved as typed.
    Saved,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedReply {
    pub entry_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusReply {
    pub vault: VaultLock,
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn messages_parse() {
        let envelope: Envelope = serde_json::from_str(
            r#"{"caller":"chrome-extension://abc/","message":{"type":"pair","clientId":"id","publicKey":"pk","nonce":"n","browser":"Chrome"}}"#,
        )
        .unwrap();
        assert_eq!(envelope.caller, "chrome-extension://abc/");
        let Message::Pair(pair) = envelope.message else {
            panic!("not a pairing");
        };
        assert_eq!(
            (pair.client_id.as_str(), pair.browser.as_str()),
            ("id", "Chrome")
        );

        let hello: Envelope = serde_json::from_str(r#"{"message":{"type":"hello"}}"#).unwrap();
        assert!(matches!(hello.message, Message::Hello));
        let sites: Envelope = serde_json::from_str(
            r#"{"message":{"type":"sameSite","origin":"https://a.com","page":"https://b.a.com"}}"#,
        )
        .unwrap();
        let Message::SameSite(sites) = sites.message else {
            panic!("not a site comparison");
        };
        assert_eq!(
            (sites.origin.as_str(), sites.page.as_str()),
            ("https://a.com", "https://b.a.com")
        );
        assert!(serde_json::from_str::<Envelope>(r#"{"message":{"type":"dump"}}"#).is_err());
    }

    #[test]
    fn actions_parse_with_secrets() {
        let opened: Opened = serde_json::from_str(
            r#"{"sentAt":5,"action":{"save":{"origin":"https://a.com","username":"me","password":"p\"w"}}}"#,
        )
        .unwrap();
        assert_eq!(opened.sent_at, 5);
        let Action::Save { password, .. } = opened.action else {
            panic!("not a save");
        };
        assert_eq!(password.expose_secret(), "p\"w");

        let opened: Opened = serde_json::from_str(r#"{"sentAt":1,"action":"status"}"#).unwrap();
        assert!(matches!(opened.action, Action::Status));
        let opened: Opened = serde_json::from_str(
            r#"{"sentAt":1,"action":{"fill":{"origin":"https://a.com","entryId":"x"}}}"#,
        )
        .unwrap();
        assert!(matches!(opened.action, Action::Fill { entry_id, .. } if entry_id == "x"));
    }

    #[test]
    fn replies_serialize() {
        let reply = serde_json::to_string(&Reply::Error {
            code: ReplyError::UnknownClient,
        })
        .unwrap();
        assert_eq!(reply, r#"{"type":"error","code":"unknownClient"}"#);
        let check = serde_json::to_string(&CheckReply::Update {
            entry_id: "e".into(),
            title: "t".into(),
        })
        .unwrap();
        assert_eq!(check, r#"{"status":"update","entryId":"e","title":"t"}"#);
        assert_eq!(
            serde_json::to_string(&CheckReply::New).unwrap(),
            r#"{"status":"new"}"#
        );
        assert_eq!(
            serde_json::to_string(&Reply::SameSite { same: true }).unwrap(),
            r#"{"type":"sameSite","same":true}"#
        );
    }
}
