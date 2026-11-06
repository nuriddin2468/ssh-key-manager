use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
    unlocks: Mutex<u32>,
    /// There is no vault at all.
    missing: AtomicBool,
    changes: Mutex<Vec<Changed>>,
    session: AtomicU64,
    /// How the user answers fill prompts at once; `None` leaves them open.
    answers: Mutex<Option<bool>>,
    prompts: Mutex<Vec<FillPrompt>>,
    /// The prompt left open, to answer later.
    open_prompt: Mutex<Option<FillAnswer>>,
    copies: Mutex<Vec<PairedBrowser>>,
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
            unlocks: Mutex::new(0),
            missing: AtomicBool::new(false),
            changes: Mutex::new(Vec::new()),
            session: AtomicU64::new(0),
            answers: Mutex::new(Some(true)),
            prompts: Mutex::new(Vec::new()),
            open_prompt: Mutex::new(None),
            copies: Mutex::new(Vec::new()),
        }
    }

    /// Answers the prompt left open.
    fn answer(&self, allowed: bool) {
        let answer = lock(&self.open_prompt).take().expect("no prompt open");
        answer(allowed);
    }

    fn prompts(&self) -> usize {
        lock(&self.prompts).len()
    }

    fn end_session(&self) {
        self.session.fetch_add(1, Ordering::SeqCst);
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
        if self.missing.load(Ordering::SeqCst) {
            VaultLock::Missing
        } else if lock(&self.vault).is_some() {
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

    fn write_keys<T>(&self, work: impl FnOnce(&mut Vault) -> AppResult<T>) -> AppResult<T> {
        let mut guard = lock(&self.vault);
        let vault = guard
            .as_mut()
            .ok_or_else(|| AppError::new(ErrorCode::VaultLocked, "locked"))?;
        let result = work(vault)?;
        vault.save_without_backup(&self.backups)?;
        Ok(result)
    }

    fn ask(&self, request: Option<&PairingRequest>) {
        lock(&self.asked).push(request.cloned());
    }

    fn show(&self) {
        *lock(&self.shown) += 1;
    }

    fn unlock(&self) {
        *lock(&self.unlocks) += 1;
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

    fn session(&self) -> u64 {
        self.session.load(Ordering::SeqCst)
    }

    fn confirm_fill(&self, prompt: FillPrompt, answer: FillAnswer) {
        lock(&self.prompts).push(prompt);
        match *lock(&self.answers) {
            Some(allowed) => answer(allowed),
            None => *lock(&self.open_prompt) = Some(answer),
        }
    }

    fn copied(&self, browser: &PairedBrowser) {
        lock(&self.copies).push(browser.clone());
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

    /// Asks the app for new keys; returns them, without switching to them.
    fn rekey(&self, broker: &Broker, env: &Fake) -> ChannelKeys {
        let next = ClientPairing::new();
        let reply = self.ask(
            broker,
            env,
            &json!({ "rekey": { "publicKey": encode(next.public_key()) } }),
        );
        let app_public = decode(reply["publicKey"].as_str().unwrap(), 65).unwrap();
        next.complete(CLIENT, &app_public).unwrap()
    }

    /// The same browser with other keys: after a rekey, or a copy.
    fn with_keys(keys: ChannelKeys) -> Self {
        Self {
            client: ClientPairing::new(),
            keys: Some(keys),
        }
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
fn unlock_asks_the_app_only_while_the_vault_is_locked() {
    let broker = Broker::default();
    let env = Fake::new();
    let unlock = json!({ "type": "unlock" });
    assert_eq!(send(&broker, &env, &unlock), json!({ "type": "shown" }));
    assert_eq!(*lock(&env.unlocks), 0);

    *lock(&env.vault) = None;
    assert_eq!(send(&broker, &env, &unlock), json!({ "type": "shown" }));
    assert_eq!(*lock(&env.unlocks), 1);
    assert_eq!(*lock(&env.shown), 0);

    // Without a vault, the app's window comes up: a vault is made there.
    env.missing.store(true, Ordering::SeqCst);
    assert_eq!(send(&broker, &env, &unlock), json!({ "type": "shown" }));
    assert_eq!((*lock(&env.unlocks), *lock(&env.shown)), (1, 1));
}

#[test]
fn unlock_is_asked_for_a_few_times_a_minute_at_most() {
    let broker = Broker::default();
    let env = Fake::new();
    *lock(&env.vault) = None;
    for _ in 0..MAX_UNLOCKS {
        assert_eq!(
            send(&broker, &env, &json!({ "type": "unlock" })),
            json!({ "type": "shown" })
        );
    }
    assert_eq!(
        send(&broker, &env, &json!({ "type": "unlock" })),
        error("tooMany")
    );
    assert_eq!(*lock(&env.unlocks), u32::try_from(MAX_UNLOCKS).unwrap());
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
fn sites_are_compared_without_pairing_by_the_login_rules() {
    let broker = Broker::default();
    let env = Fake::new();
    *lock(&env.vault) = None;
    let same = |origin: &str, page: &str| {
        send(
            &broker,
            &env,
            &json!({ "type": "sameSite", "origin": origin, "page": page }),
        )
    };
    let yes = json!({ "type": "sameSite", "same": true });
    let no = json!({ "type": "sameSite", "same": false });
    assert_eq!(same("https://bank.example", "https://bank.example"), yes);
    assert_eq!(
        same("https://accounts.bank.example", "https://www.bank.example"),
        yes
    );
    assert_eq!(same("http://bank.example", "https://bank.example"), yes);
    assert_eq!(same("https://bank.example", "https://evil.example"), no);
    assert_eq!(same("https://bank.example", "http://bank.example"), no);
    assert_eq!(same("https://alice.github.io", "https://bob.github.io"), no);
    assert_eq!(same("https://bank.example", "null"), no);
    assert_eq!(same("null", "https://bank.example"), no);
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

fn fill(extension: &Extension, broker: &Broker, env: &Fake, origin: &str, id: &str) -> Value {
    extension.ask(
        broker,
        env,
        &json!({ "fill": { "origin": origin, "entryId": id } }),
    )
}

#[test]
fn a_fill_is_asked_about_once_per_page_and_session() {
    let (broker, env, extension) = paired();
    let github = env.add("GitHub", "octo", "https://github.com", "hunter2");
    let filled = json!({ "username": "octo", "password": "hunter2" });

    assert_eq!(
        fill(&extension, &broker, &env, "https://github.com", &github),
        filled
    );
    assert_eq!(
        lock(&env.prompts)[0],
        FillPrompt {
            browser: "Chrome".into(),
            title: "GitHub".into(),
            username: "octo".into(),
            site: "github.com".into(),
        }
    );
    // Allowed: the same login fills the same page without asking again.
    assert_eq!(
        fill(&extension, &broker, &env, "https://github.com", &github),
        filled
    );
    assert_eq!(env.prompts(), 1);
    // Another page of the site is asked about on its own.
    assert_eq!(
        fill(
            &extension,
            &broker,
            &env,
            "https://gist.github.com",
            &github
        ),
        filled
    );
    assert_eq!(lock(&env.prompts)[1].site, "gist.github.com");
    // Once the session ends, the user is asked again.
    env.end_session();
    assert_eq!(
        fill(&extension, &broker, &env, "https://github.com", &github),
        filled
    );
    assert_eq!(env.prompts(), 3);
    // A login of another site is refused before anyone is asked.
    assert_eq!(
        fill(&extension, &broker, &env, "https://evil.example", &github),
        error("notFound")
    );
    assert_eq!(env.prompts(), 3);
}

#[test]
fn a_declined_fill_gives_nothing_and_is_asked_again() {
    let (broker, env, extension) = paired();
    let github = env.add("GitHub", "octo", "https://github.com", "hunter2");
    *lock(&env.answers) = Some(false);
    assert_eq!(
        fill(&extension, &broker, &env, "https://github.com", &github),
        error("denied")
    );
    assert_eq!(
        fill(&extension, &broker, &env, "https://github.com", &github),
        error("denied")
    );
    assert_eq!(env.prompts(), 2);
}

#[test]
fn an_unanswered_fill_expires_and_a_late_yes_still_counts() {
    let broker = Arc::new(Broker::default().with_fill_wait(Duration::from_millis(50)));
    let env = Arc::new(Fake::new());
    let mut extension = Extension::new();
    extension.pair(&broker, &env, true);
    let github = env.add("GitHub", "octo", "https://github.com", "hunter2");
    let gist = env.add("Gist", "octo", "https://gist.github.com", "pw2");
    *lock(&env.answers) = None;

    assert_eq!(
        fill(&extension, &broker, &env, "https://github.com", &github),
        error("expired")
    );
    // While the prompt is open, another fill waits its turn.
    assert_eq!(
        fill(&extension, &broker, &env, "https://gist.github.com", &gist),
        error("busy")
    );
    assert_eq!(env.prompts(), 1);
    env.answer(true);
    assert_eq!(
        fill(&extension, &broker, &env, "https://github.com", &github),
        json!({ "username": "octo", "password": "hunter2" })
    );
    assert_eq!(env.prompts(), 1);
}

#[test]
fn a_login_picked_twice_waits_for_one_answer() {
    let (broker, env, extension) = paired();
    let github = env.add("GitHub", "octo", "https://github.com", "hunter2");
    *lock(&env.answers) = None;
    let extension = Arc::new(extension);
    let picks: Vec<_> = (0..2)
        .map(|_| {
            let (broker, env, extension) = (
                Arc::clone(&broker),
                Arc::clone(&env),
                Arc::clone(&extension),
            );
            let github = github.clone();
            thread::spawn(move || fill(&extension, &broker, &env, "https://github.com", &github))
        })
        .collect();
    for _ in 0..500 {
        if lock(&env.open_prompt).is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    thread::sleep(Duration::from_millis(50));
    env.answer(true);
    for pick in picks {
        assert_eq!(pick.join().unwrap()["password"], "hunter2");
    }
    assert_eq!(env.prompts(), 1);
}

#[test]
fn a_browser_cannot_ask_over_and_over() {
    let (broker, env, extension) = paired();
    let github = env.add("GitHub", "octo", "https://github.com", "hunter2");
    *lock(&env.answers) = Some(false);
    for _ in 0..MAX_PROMPTS {
        assert_eq!(
            fill(&extension, &broker, &env, "https://github.com", &github),
            error("denied")
        );
    }
    assert_eq!(
        fill(&extension, &broker, &env, "https://github.com", &github),
        error("tooMany")
    );
    assert_eq!(env.prompts(), MAX_PROMPTS);
}

#[test]
fn a_browser_may_check_only_a_few_logins_a_minute() {
    let (broker, env, extension) = paired();
    let check = json!({ "check": { "origin": "https://shop.example", "username": "bob", "password": "guess" } });
    for _ in 0..MAX_CHECKS {
        assert_eq!(
            extension.ask(&broker, &env, &check),
            json!({ "status": "new" })
        );
    }
    assert_eq!(extension.ask(&broker, &env, &check), error("tooMany"));
}

#[test]
fn prompt_texts_are_one_short_line() {
    assert_eq!(shown("  Bank\n\tlogin\u{7} "), "Bank login");
    let long = shown(&"x".repeat(100));
    assert_eq!(long.chars().count(), SHOWN_CHARS);
    assert!(long.ends_with('…'));
}

#[test]
fn keys_change_and_a_copy_of_the_old_ones_is_caught() {
    let (broker, env, extension) = paired();
    env.add("GitHub", "octo", "https://github.com", "hunter2");
    let status = json!({ "vault": "unlocked" });

    let next = extension.rekey(&broker, &env);
    // Until the browser uses the new keys, the old ones still work.
    assert_eq!(extension.ask(&broker, &env, &json!("status")), status);
    let renewed = Extension::with_keys(next);
    // A request sealed before the switch, but delivered after it.
    let (late_nonce, late) = extension.sealed(&json!("status"), now() - 1);
    assert_eq!(renewed.ask(&broker, &env, &json!("status")), status);
    assert_eq!(
        extension.open(&late_nonce, &send(&broker, &env, &late)),
        error("invalid"),
        "a late request of the browser itself is refused, nothing more"
    );
    assert!(lock(&env.copies).is_empty());
    assert_eq!(renewed.ask(&broker, &env, &json!("status")), status);

    // Someone else uses the old keys now: the pairing goes.
    assert_eq!(
        extension.ask(&broker, &env, &json!("status")),
        error("revoked")
    );
    let copies = lock(&env.copies).clone();
    assert_eq!(copies.len(), 1);
    assert_eq!(
        (copies[0].browser.as_str(), copies[0].computer.as_str()),
        ("Chrome", "test-mac")
    );
    assert_eq!(
        env.read(false, |vault| Ok(vault.paired_browsers()))
            .unwrap(),
        Vec::new()
    );
    assert_eq!(lock(&env.changes).last(), Some(&Changed::Browsers));
    assert_eq!(
        renewed.ask(&broker, &env, &json!("status")),
        error("unknownClient")
    );
}

#[test]
fn a_rekey_whose_answer_was_lost_changes_nothing() {
    let (broker, env, extension) = paired();
    let status = json!({ "vault": "unlocked" });
    let lost = extension.rekey(&broker, &env);
    let next = extension.rekey(&broker, &env);
    // The later rekey replaced the lost one; the old keys still work.
    assert_eq!(extension.ask(&broker, &env, &json!("status")), status);
    assert_eq!(
        Extension::with_keys(lost).ask(&broker, &env, &json!("status")),
        error("invalid")
    );
    let backups = || std::fs::read_dir(&env.backups).map_or(0, Iterator::count);
    let before = backups();
    assert_eq!(
        Extension::with_keys(next).ask(&broker, &env, &json!("status")),
        status
    );
    assert!(lock(&env.copies).is_empty());
    assert_eq!(backups(), before, "changing keys takes no backup");
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

fn nonce(n: u64) -> MessageNonce {
    let mut nonce = [0; 12];
    nonce[..8].copy_from_slice(&n.to_be_bytes());
    nonce
}

#[test]
fn nonces_are_refused_again_until_they_go_stale() {
    let mut seen = Seen::default();
    let start = Instant::now();
    assert!(seen.admit(nonce(1), 1_000, start));
    assert!(!seen.admit(nonce(1), 1_000, start + Duration::from_secs(1)));
    assert!(seen.admit(nonce(2), 1_000, start + Duration::from_secs(1)));
    // Long after any copy of it stopped being fresh.
    assert!(seen.admit(nonce(1), 1_000, start + REMEMBER));
}

#[test]
fn a_full_memory_forgets_the_oldest_but_still_refuses_their_replays() {
    let mut seen = Seen::default();
    let start = Instant::now();
    let max = u64::try_from(MAX_REMEMBERED).unwrap();
    let sent = |n: u64| 1_000_000 + n;
    for n in 0..max {
        assert!(seen.admit(nonce(n), sent(n), start));
    }
    // A flood doesn't shut every browser out: new requests still pass.
    let later = start + Duration::from_secs(1);
    for n in max..max + 10 {
        assert!(seen.admit(nonce(n), sent(n), later), "{n}");
    }
    assert_eq!(seen.nonces.len(), MAX_REMEMBERED);
    // The ten forgotten nonces stay refused, and so does one still kept.
    for n in 0..=10 {
        assert!(!seen.admit(nonce(n), sent(n), later), "{n}");
    }
    // So is anything sent before the forgotten ones, until they would have
    // gone stale anyway.
    assert!(!seen.admit(nonce(u64::MAX), sent(9), later));
    assert!(seen.admit(nonce(u64::MAX - 1), sent(max + 10), later));
    assert!(seen.admit(nonce(u64::MAX), sent(9), later + REMEMBER));
}
