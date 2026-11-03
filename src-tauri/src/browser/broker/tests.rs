use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use serde_json::{Value, json};
use sshkm_core::SecretString;
use sshkm_core::browser::channel::{ClientPairing, decode, decode_nonce, encode};
use sshkm_core::vault::{EntryInput, VaultPaths};
use tempfile::TempDir;

use super::*;

const CLIENT: &str = "dGVzdC1jbGllbnQtaWQtMDE";

/// A vault in a temporary folder, and a record of what the broker asked of
/// the app.
struct Fake {
    _dir: TempDir,
    backups: PathBuf,
    vault: Mutex<Option<Vault>>,
    asked: Mutex<Vec<Option<PairingRequest>>>,
    shown: Mutex<u32>,
    changes: Mutex<Vec<Changed>>,
}

impl Fake {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("vault.kdbx"));
        let (vault, _) = Vault::create(&paths, &SecretString::from("master")).unwrap();
        Self {
            backups: dir.path().join("backups"),
            _dir: dir,
            vault: Mutex::new(Some(vault)),
            asked: Mutex::new(Vec::new()),
            shown: Mutex::new(0),
            changes: Mutex::new(Vec::new()),
        }
    }

    fn add(&self, title: &str, username: &str, url: &str, password: &str) -> String {
        lock(&self.vault)
            .as_mut()
            .unwrap()
            .add_entry(&EntryInput {
                title: title.into(),
                username: username.into(),
                password: Some(SecretString::from(password)),
                url: url.into(),
                ..EntryInput::default()
            })
            .unwrap()
    }
}

impl Env for Fake {
    fn vault_lock(&self) -> VaultLock {
        if lock(&self.vault).is_some() {
            VaultLock::Unlocked
        } else {
            VaultLock::Locked
        }
    }

    fn read<T>(&self, _active: bool, work: impl FnOnce(&Vault) -> AppResult<T>) -> AppResult<T> {
        let guard = lock(&self.vault);
        let vault = guard
            .as_ref()
            .ok_or_else(|| AppError::new(ErrorCode::VaultLocked, "locked"))?;
        work(vault)
    }

    fn write<T>(&self, work: impl FnOnce(&mut Vault) -> AppResult<T>) -> AppResult<T> {
        let mut guard = lock(&self.vault);
        let vault = guard
            .as_mut()
            .ok_or_else(|| AppError::new(ErrorCode::VaultLocked, "locked"))?;
        let result = work(vault)?;
        vault.save(&self.backups)?;
        Ok(result)
    }

    fn ask(&self, request: Option<&PairingRequest>) {
        lock(&self.asked).push(request.cloned());
    }

    fn show(&self) {
        *lock(&self.shown) += 1;
    }

    fn changed(&self, what: Changed) {
        lock(&self.changes).push(what);
    }

    fn computer(&self) -> String {
        "test-mac".into()
    }

    fn version(&self) -> String {
        "1.2.3".into()
    }
}

fn send(broker: &Broker, env: &Fake, message: &Value) -> Value {
    let envelope = json!({ "caller": "chrome-extension://abc/", "message": message });
    let reply = broker.handle(env, envelope.to_string().as_bytes());
    serde_json::from_slice(&reply).unwrap()
}

/// The extension: pairs, then seals requests and opens replies.
struct Extension {
    client: ClientPairing,
    keys: Option<ChannelKeys>,
}

impl Extension {
    fn new() -> Self {
        Self {
            client: ClientPairing::new(),
            keys: None,
        }
    }

    fn pair_message(&self) -> Value {
        json!({
            "type": "pair",
            "clientId": CLIENT,
            "publicKey": encode(self.client.public_key()),
            "nonce": encode(&[7; 12]),
            "browser": "Chrome\n",
        })
    }

    /// Pairs, approving or declining in the app once the dialog shows.
    fn pair(&mut self, broker: &Arc<Broker>, env: &Arc<Fake>, approve: bool) -> Value {
        let message = self.pair_message();
        let waiting = thread::spawn({
            let (broker, env) = (Arc::clone(broker), Arc::clone(env));
            move || send(&broker, &env, &message)
        });
        let request = wait_for_pending(broker);
        assert_eq!(
            request.code,
            pairing_code(CLIENT, self.client.public_key()),
            "the app shows the code the extension computes"
        );
        assert_eq!(request.browser, "Chrome");
        assert!(broker.decide(&request.id, approve));
        let reply = waiting.join().unwrap();
        if reply["type"] == "paired" {
            let app_public = decode(reply["publicKey"].as_str().unwrap(), 65).unwrap();
            let keys = self.client.complete(CLIENT, &app_public).unwrap();
            let info = keys
                .open_response(
                    CLIENT,
                    &[7; 12],
                    &decode_nonce(reply["nonce"].as_str().unwrap()).unwrap(),
                    &decode(reply["payload"].as_str().unwrap(), 4096).unwrap(),
                )
                .unwrap();
            assert_eq!(info.as_slice(), br#"{"paired":true}"#);
            self.keys = Some(keys);
        }
        reply
    }

    fn sealed(&self, action: &Value, sent_at: u64) -> (MessageNonce, Value) {
        let keys = self.keys.as_ref().unwrap();
        let plain = json!({ "sentAt": sent_at, "action": action }).to_string();
        let (nonce, sealed) = keys.seal_request(CLIENT, plain.as_bytes()).unwrap();
        let message = json!({
            "type": "request",
            "clientId": CLIENT,
            "nonce": encode(&nonce),
            "payload": encode(&sealed),
        });
        (nonce, message)
    }

    /// Sends a request; returns the opened answer, or the error reply.
    fn ask(&self, broker: &Broker, env: &Fake, action: &Value) -> Value {
        let (nonce, message) = self.sealed(action, now());
        self.open(&nonce, &send(broker, env, &message))
    }

    fn open(&self, nonce: &MessageNonce, reply: &Value) -> Value {
        if reply["type"] != "response" {
            return reply.clone();
        }
        let opened = self
            .keys
            .as_ref()
            .unwrap()
            .open_response(
                CLIENT,
                nonce,
                &decode_nonce(reply["nonce"].as_str().unwrap()).unwrap(),
                &decode(reply["payload"].as_str().unwrap(), MAX_MESSAGE).unwrap(),
            )
            .unwrap();
        serde_json::from_slice(&opened).unwrap()
    }
}

fn wait_for_pending(broker: &Broker) -> PairingRequest {
    for _ in 0..500 {
        if let Some(request) = broker.pending() {
            return request;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("no pairing request");
}

fn now() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn error(code: &str) -> Value {
    json!({ "type": "error", "code": code })
}

fn paired() -> (Arc<Broker>, Arc<Fake>, Extension) {
    let broker = Arc::new(Broker::default());
    let env = Arc::new(Fake::new());
    let mut extension = Extension::new();
    let reply = extension.pair(&broker, &env, true);
    assert_eq!(reply["type"], "paired", "{reply}");
    (broker, env, extension)
}

#[test]
fn hello_and_show_need_no_pairing() {
    let broker = Broker::default();
    let env = Fake::new();
    let reply = send(&broker, &env, &json!({ "type": "hello" }));
    assert_eq!(
        reply,
        json!({ "type": "hello", "app": "SSH Key Manager", "version": "1.2.3", "protocol": 1, "vault": "unlocked" })
    );
    assert_eq!(
        send(&broker, &env, &json!({ "type": "show" })),
        json!({ "type": "shown" })
    );
    assert_eq!(*lock(&env.shown), 1);
    assert_eq!(
        send(&broker, &env, &json!({ "type": "dump" })),
        error("invalid")
    );
    assert_eq!(
        broker.handle(&env, b"not json"),
        br#"{"type":"error","code":"invalid"}"#
    );
}

#[test]
fn an_approved_pairing_is_stored_and_its_requests_answered() {
    let (broker, env, extension) = paired();
    let browsers = env
        .read(false, |vault| Ok(vault.paired_browsers()))
        .unwrap();
    assert_eq!(browsers.len(), 1);
    assert_eq!(
        (
            browsers[0].id.as_str(),
            browsers[0].browser.as_str(),
            browsers[0].computer.as_str()
        ),
        (CLIENT, "Chrome", "test-mac")
    );
    // The dialog opened, then closed.
    let asked = lock(&env.asked).clone();
    assert_eq!(asked.len(), 2);
    assert!(asked[0].is_some() && asked[1].is_none());
    assert_eq!(*lock(&env.changes), [Changed::Browsers]);
    assert_eq!(broker.pending(), None);

    assert_eq!(
        extension.ask(&broker, &env, &json!("status")),
        json!({ "vault": "unlocked" })
    );
}

#[test]
fn declined_and_unanswered_pairings_store_nothing() {
    let broker = Arc::new(Broker::default());
    let env = Arc::new(Fake::new());
    let mut extension = Extension::new();
    assert_eq!(extension.pair(&broker, &env, false), error("denied"));

    let broker = Arc::new(Broker::new(Duration::from_millis(50)));
    assert_eq!(
        send(&broker, &env, &extension.pair_message()),
        error("expired")
    );
    assert_eq!(broker.pending(), None);
    assert_eq!(
        env.read(false, |vault| Ok(vault.paired_browsers()))
            .unwrap(),
        Vec::new()
    );
    assert!(!broker.decide("whatever", true));
}

#[test]
fn one_pairing_waits_at_a_time() {
    let broker = Arc::new(Broker::new(Duration::from_secs(5)));
    let env = Arc::new(Fake::new());
    let extension = Extension::new();
    let message = extension.pair_message();
    let first = thread::spawn({
        let (broker, env, message) = (Arc::clone(&broker), Arc::clone(&env), message.clone());
        move || send(&broker, &env, &message)
    });
    let request = wait_for_pending(&broker);
    assert_eq!(send(&broker, &env, &message), error("busy"));
    broker.decide(&request.id, false);
    assert_eq!(first.join().unwrap(), error("denied"));
}

#[test]
fn a_locked_vault_answers_nothing_but_hello() {
    let (broker, env, extension) = paired();
    let saved = lock(&env.vault).take();
    assert_eq!(
        send(&broker, &env, &json!({ "type": "hello" }))["vault"],
        "locked"
    );
    assert_eq!(
        extension.ask(&broker, &env, &json!("status")),
        error("locked")
    );
    assert_eq!(
        send(&broker, &env, &extension.pair_message()),
        error("locked")
    );
    assert_eq!(
        *lock(&env.shown),
        1,
        "pairing a locked vault brings the app forward"
    );
    *lock(&env.vault) = saved;
    assert_eq!(
        extension.ask(&broker, &env, &json!("status"))["vault"],
        "unlocked"
    );
}

#[test]
fn unknown_tampered_replayed_and_stale_requests_are_refused() {
    let (broker, env, extension) = paired();

    let stranger = Extension {
        client: ClientPairing::new(),
        keys: Some(
            ClientPairing::new()
                .complete(CLIENT, ClientPairing::new().public_key())
                .unwrap(),
        ),
    };
    assert_eq!(
        stranger.ask(&broker, &env, &json!("status")),
        error("invalid")
    );

    let (_, mut message) = extension.sealed(&json!("status"), now());
    message["clientId"] = json!("another-client-0000000");
    assert_eq!(send(&broker, &env, &message), error("unknownClient"));

    let (_, mut message) = extension.sealed(&json!("status"), now());
    let mut payload = decode(message["payload"].as_str().unwrap(), 4096).unwrap();
    payload[0] ^= 1;
    message["payload"] = json!(encode(&payload));
    assert_eq!(send(&broker, &env, &message), error("invalid"));

    let (nonce, message) = extension.sealed(&json!("status"), now());
    assert_eq!(
        extension.open(&nonce, &send(&broker, &env, &message))["vault"],
        "unlocked"
    );
    assert_eq!(send(&broker, &env, &message), error("invalid"), "a replay");

    let (_, message) = extension.sealed(&json!("status"), now() - 10 * 60 * 1000);
    assert_eq!(send(&broker, &env, &message), error("expired"));

    // Revoked in the app: refused from then on.
    env.write(|vault| Ok(vault.remove_browser(CLIENT))).unwrap();
    assert_eq!(
        extension.ask(&broker, &env, &json!("status")),
        error("unknownClient")
    );
}

#[test]
fn logins_and_fills_stay_on_their_site() {
    let (broker, env, extension) = paired();
    let github = env.add("GitHub", "octo", "https://github.com", "hunter2");
    let gist = env.add("Gist", "octo2", "https://gist.github.com", "pw2");
    env.add("Evil", "octo", "https://github.com.evil.io", "pw3");

    let logins = extension.ask(
        &broker,
        &env,
        &json!({ "logins": { "origin": "https://github.com" } }),
    );
    assert_eq!(
        logins,
        json!({ "logins": [
            { "id": github, "title": "GitHub", "username": "octo", "exact": true },
            { "id": gist, "title": "Gist", "username": "octo2", "exact": false },
        ] })
    );
    let none = extension.ask(
        &broker,
        &env,
        &json!({ "logins": { "origin": "https://github.com.evil.io:443" } }),
    );
    assert_eq!(
        none["logins"].as_array().unwrap().len(),
        1,
        "only its own login"
    );

    let fill = extension.ask(
        &broker,
        &env,
        &json!({ "fill": { "origin": "https://github.com", "entryId": github } }),
    );
    assert_eq!(fill, json!({ "username": "octo", "password": "hunter2" }));
    let stolen = extension.ask(
        &broker,
        &env,
        &json!({ "fill": { "origin": "https://github.com.evil.io", "entryId": github } }),
    );
    assert_eq!(stolen, error("notFound"));
    let bad_origin = extension.ask(
        &broker,
        &env,
        &json!({ "fill": { "origin": "null", "entryId": github } }),
    );
    assert_eq!(bad_origin, error("invalid"));
}

#[test]
fn typed_logins_are_checked_then_saved_or_updated() {
    let (broker, env, extension) = paired();
    let origin = "https://shop.example";
    let check = |password: &str| {
        extension.ask(
            &broker,
            &env,
            &json!({ "check": { "origin": origin, "username": "bob", "password": password } }),
        )
    };
    assert_eq!(check("pw1"), json!({ "status": "new" }));
    let saved = extension.ask(
        &broker,
        &env,
        &json!({ "save": { "origin": origin, "username": "bob", "password": "pw1" } }),
    );
    let id = saved["entryId"].as_str().unwrap().to_owned();
    assert_eq!(check("pw1"), json!({ "status": "saved" }));
    assert_eq!(
        check("pw2"),
        json!({ "status": "update", "entryId": id, "title": "shop.example" })
    );
    let updated = extension.ask(
        &broker,
        &env,
        &json!({ "update": { "origin": origin, "entryId": id, "password": "pw2" } }),
    );
    assert_eq!(updated["entryId"], id.as_str());
    assert_eq!(check("pw2"), json!({ "status": "saved" }));
    let elsewhere = extension.ask(
        &broker,
        &env,
        &json!({ "update": { "origin": "https://other.example", "entryId": id, "password": "x" } }),
    );
    assert_eq!(elsewhere, error("notFound"));
    assert_eq!(
        *lock(&env.changes),
        [Changed::Browsers, Changed::Entries, Changed::Entries]
    );
}

#[test]
fn fill_replies_escape_any_password() {
    let json = fill_json("me", "a\"b\\c\u{1}\u{2028}");
    let value: Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(value["password"], "a\"b\\c\u{1}\u{2028}");
    assert!(json.capacity() >= json.len());
}

#[test]
fn browser_names_are_short_and_printable() {
    assert_eq!(browser_name("  Firefox\u{7}  "), "Firefox");
    assert_eq!(browser_name(""), "Browser");
    assert_eq!(browser_name(&"x".repeat(100)).len(), 40);
}
