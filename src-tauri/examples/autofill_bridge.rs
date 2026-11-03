//! The browser autofill bridge over a throwaway vault, for trying the
//! extension without the app's window. It approves every pairing by itself,
//! so it is a development tool only: it never opens your own vault.
//!
//! ```text
//! cargo run -p sshkm-app --example autofill_bridge -- \
//!     --login http://127.0.0.1:8765 alice s3cret
//! ```
//!
//! `--login <url> <user> <password>` adds a login titled by its address;
//! `--entry <title> <url> <user> <password>` gives it a title of its own.
//! `--approve-after <ms>` waits that long before approving a pairing
//! (default 300), to keep the code on screen for a screenshot.
//!
//! The browsers start the native host from the manifests the app writes, or
//! from ones you write for a test profile (`extension/e2e.mjs` does). The
//! bridge takes over the app's endpoint file while it runs and puts the old
//! one back when it exits, so quit the app first.
//!
//! It prints JSON lines (`ready`, `pairing`, `changed`) and reads commands
//! on stdin: `entries` prints the vault's logins, `lock` and `unlock` lock
//! and unlock it, `quit` (or end of input) exits.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use serde_json::json;
use sshkm_app_lib::browser::broker::{Broker, Changed, Env, PairingRequest};
use sshkm_app_lib::browser::{endpoint_file, serve};
use sshkm_core::browser::protocol::VaultLock;
use sshkm_core::vault::{EntryInput, SecretField, Vault, VaultPaths};
use sshkm_core::{ErrorCode, ExposeSecret, SecretString};

type AppResult<T> = Result<T, sshkm_app_lib::AppError>;

struct Harness {
    broker: Arc<Broker>,
    paths: VaultPaths,
    backups: PathBuf,
    vault: Mutex<Option<Vault>>,
    approve_after: Duration,
}

fn say(value: &serde_json::Value) {
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "{value}");
    let _ = out.flush();
}

fn locked() -> sshkm_app_lib::AppError {
    sshkm_app_lib::AppError::new(ErrorCode::VaultLocked, "the vault is locked")
}

impl Env for Harness {
    fn vault_lock(&self) -> VaultLock {
        if self
            .vault
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
        {
            VaultLock::Unlocked
        } else {
            VaultLock::Locked
        }
    }

    fn read<T>(&self, _active: bool, work: impl FnOnce(&Vault) -> AppResult<T>) -> AppResult<T> {
        let guard = self.vault.lock().unwrap_or_else(PoisonError::into_inner);
        work(guard.as_ref().ok_or_else(locked)?)
    }

    fn write<T>(&self, work: impl FnOnce(&mut Vault) -> AppResult<T>) -> AppResult<T> {
        let mut guard = self.vault.lock().unwrap_or_else(PoisonError::into_inner);
        let vault = guard.as_mut().ok_or_else(locked)?;
        let result = work(vault)?;
        vault.save(&self.backups)?;
        Ok(result)
    }

    fn ask(&self, request: Option<&PairingRequest>) {
        let Some(request) = request.cloned() else {
            return;
        };
        say(&json!({ "event": "pairing", "browser": request.browser, "code": request.code }));
        let broker = Arc::clone(&self.broker);
        let wait = self.approve_after;
        thread::spawn(move || {
            thread::sleep(wait);
            broker.decide(&request.id, true);
        });
    }

    fn show(&self) {
        say(&json!({ "event": "show" }));
    }

    fn changed(&self, what: Changed) {
        let what = match what {
            Changed::Entries => "entries",
            Changed::Browsers => "browsers",
        };
        say(&json!({ "event": "changed", "what": what }));
    }

    fn computer(&self) -> String {
        "autofill-bridge".into()
    }

    fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").into()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let paths = VaultPaths::new(dir.path().join("vault.kdbx"));
    let master = SecretString::from("master");
    let (mut vault, _) = Vault::create(&paths, &master)?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let logins = args
        .iter()
        .enumerate()
        .filter_map(|(at, arg)| match arg.as_str() {
            "--login" => args
                .get(at + 1..at + 4)
                .map(|w| (&w[0], &w[0], &w[1], &w[2])),
            "--entry" => args
                .get(at + 1..at + 5)
                .map(|w| (&w[0], &w[1], &w[2], &w[3])),
            _ => None,
        });
    let approve_after = args
        .iter()
        .position(|arg| arg == "--approve-after")
        .and_then(|at| args.get(at + 1)?.parse().ok())
        .unwrap_or(300);
    for (title, url, username, password) in logins {
        vault.add_entry(&EntryInput {
            title: title.clone(),
            username: username.clone(),
            password: Some(SecretString::from(password.clone())),
            url: url.clone(),
            ..EntryInput::default()
        })?;
    }
    let backups = dir.path().join("backups");
    vault.save(&backups)?;

    let broker = Arc::new(Broker::default());
    let harness = Arc::new(Harness {
        broker: Arc::clone(&broker),
        paths,
        backups,
        vault: Mutex::new(Some(vault)),
        approve_after: Duration::from_millis(approve_after),
    });
    let previous = std::fs::read_to_string(endpoint_file()?).ok();
    let serving = serve(broker, Arc::clone(&harness))?;
    say(&json!({ "event": "ready" }));

    for line in io::stdin().lock().lines() {
        match line?.trim() {
            "entries" => {
                let guard = harness.vault.lock().unwrap_or_else(PoisonError::into_inner);
                let entries: Vec<serde_json::Value> = guard
                    .as_ref()
                    .map(|vault| {
                        vault
                            .entries()
                            .into_iter()
                            .map(|e| {
                                let password = vault
                                    .secret(&e.id, SecretField::Password)
                                    .map(|p| p.expose_secret().to_owned())
                                    .unwrap_or_default();
                                json!({ "title": e.title, "username": e.username, "url": e.url, "password": password })
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let browsers = guard
                    .as_ref()
                    .map(Vault::paired_browsers)
                    .unwrap_or_default();
                say(&json!({ "event": "entries", "entries": entries, "browsers": browsers.len() }));
            }
            "lock" => {
                harness
                    .vault
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take();
                say(&json!({ "event": "locked" }));
            }
            "unlock" => {
                let vault = Vault::unlock(&harness.paths, &master)?;
                *harness.vault.lock().unwrap_or_else(PoisonError::into_inner) = Some(vault);
                say(&json!({ "event": "unlocked" }));
            }
            "quit" => break,
            _ => {}
        }
    }
    drop(serving);
    if let Some(previous) = previous {
        std::fs::write(endpoint_file()?, previous)?;
    }
    Ok(())
}
