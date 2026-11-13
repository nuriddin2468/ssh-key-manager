//! A stand-in for another computer on the network, to try Nearby with one
//! machine. It answers on the terminal.
//!
//! ```text
//! cargo run -p sshkm-app --example nearby_peer -- "Test peer"
//! cargo run -p sshkm-app --example nearby_peer -- "Test peer" --send password
//! cargo run -p sshkm-app --example nearby_peer -- "Test peer" --send host
//! cargo run -p sshkm-app --example nearby_peer -- "Test peer" --send group
//! cargo run -p sshkm-app --example nearby_peer -- "Test peer" --send key
//! cargo run -p sshkm-app --example nearby_peer -- "Test peer" --join /tmp/peer
//! cargo run -p sshkm-app --example nearby_peer -- "Test peer" --sync /tmp/peer
//! ```
//!
//! - Without an option it shows itself as the app does after "Show for 10
//!   minutes" and waits: pair with it or send it something from the app,
//!   and it prints the pairing code and what it got. It saves nothing.
//! - With `--send` it looks for the app (click "Show for 10 minutes" there
//!   first) and sends it a sample login, host, hosts file group or public
//!   key.
//! - With `--join <dir>` it is a new computer without a vault: in the app,
//!   click "Add as my device" next to it. It keeps the vault it gets in
//!   `<dir>`, with a master password typed here, and its device key in
//!   `<dir>/identity`.
//! - With `--sync <dir>` it is that computer later: it unlocks the vault in
//!   `<dir>`, announces itself to the user's devices, and answers a sync
//!   from the app with `<dir>/ssh/config` and `<dir>/ssh/known_hosts`.
//!
//! It does one conversation and exits.

use std::io::{self, BufRead, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use sshkm_app_lib::nearby::pairing::{
    PairingFailure, PairingPhase, Purpose, Side, VaultItems, conversation,
};
use sshkm_app_lib::nearby::sync::{SyncLocal, SyncState, SyncWrite};
use sshkm_app_lib::nearby::{BASE_LABEL, OWN_SERVICE_TYPE, SERVICE_TYPE, VAULT_BASE_LABEL};
use sshkm_core::config::SshConfig;
use sshkm_core::known_hosts::KnownHosts;
use sshkm_core::p2p::own::window;
use sshkm_core::p2p::protocol::{
    EntrySync, HostKey, HostsEntry, Intent, Item, ItemSummary, SecretText, VaultState,
};
use sshkm_core::p2p::{self, Identity, PeerKey};
use sshkm_core::sync::Hasher;
use sshkm_core::vault::sync::{
    ENTRY_SYNC_VERSION, Pairs, PeerVault, VaultApplied, VaultBase, VaultChoices, VaultPlan,
    check_moved, digests,
};
use sshkm_core::vault::{Vault, VaultPaths};
use sshkm_core::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

struct Terminal {
    name: String,
    identity: Identity,
    mode: Mode,
    /// The other device's copy of the vault during a sync.
    peer_vault: Mutex<Option<PeerVault>>,
}

enum Mode {
    Plain,
    /// Waits to be given a vault, to keep in this folder.
    Join(PathBuf),
    /// One of the user's devices, with its vault and `ssh` files here.
    Own {
        dir: PathBuf,
        vault: Box<Mutex<Vault>>,
    },
}

impl Terminal {
    fn with_vault<T>(&self, work: impl FnOnce(&mut Vault) -> T) -> Option<T> {
        match &self.mode {
            Mode::Own { vault, .. } => Some(work(&mut vault.lock().unwrap())),
            _ => None,
        }
    }

    fn dir(&self) -> Option<&Path> {
        match &self.mode {
            Mode::Own { dir, .. } => Some(dir),
            _ => None,
        }
    }
}

impl Side for Terminal {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn knows(&self, peer: PeerKey) -> Result<Option<String>, PairingFailure> {
        Ok(self
            .with_vault(|vault| {
                vault
                    .is_own_device(&peer)
                    .then(|| vault.known_name(&peer))
                    .flatten()
            })
            .flatten())
    }

    fn save(&self, peer: PeerKey, name: &str) -> Result<(), PairingFailure> {
        println!("Paired with {name} ({peer}).");
        Ok(())
    }

    fn show(&self, peer: Option<&str>, phase: &PairingPhase) {
        let peer = peer.unwrap_or("the app");
        match phase {
            PairingPhase::Compare { code } => {
                println!("Pairing code: {} {}", &code[..3], &code[3..]);
                ask(&format!("Does {peer} show the same code?"));
            }
            PairingPhase::Waiting { .. } => println!("Waiting for {peer} to confirm…"),
            PairingPhase::Offering { item } => {
                println!("Offered {}; waiting for the app to accept…", describe(item));
            }
            PairingPhase::Offered { item } => {
                ask(&format!("The app sends {}. Accept?", describe(item)));
            }
            PairingPhase::Approving => println!("Waiting for {peer} to confirm with Touch ID…"),
            PairingPhase::Transfer { done, total } => println!("Got {done} of {total} bytes."),
            PairingPhase::Syncing => println!("Syncing with {peer}…"),
            PairingPhase::Synced { summary } => println!("Synced: {summary:?}"),
            _ => {}
        }
    }

    fn answer(&self, _wait: Duration) -> Result<Option<bool>, PairingFailure> {
        // Blocks until a line comes; a "no" from the app shows up after it.
        let mut line = String::new();
        io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|_| PairingFailure::Cancelled)?;
        Ok(Some(line.trim().eq_ignore_ascii_case("y")))
    }

    fn store(&self, item: &Item) -> Result<(String, bool), PairingFailure> {
        match item {
            Item::Password {
                title,
                username,
                password,
                otp,
                ..
            } => {
                println!(
                    "Got the login \"{title}\" for {username}: a password of {} characters{}.",
                    password.chars().count(),
                    if otp.is_some() {
                        " and a 2FA secret"
                    } else {
                        ""
                    }
                );
                Ok((title.clone(), false))
            }
            Item::Host {
                alias, host_keys, ..
            } => {
                println!(
                    "Got the host {alias} ({}) with {} server key(s).",
                    match item.summary() {
                        ItemSummary::Host { address, .. } => address,
                        _ => String::new(),
                    },
                    host_keys.len()
                );
                Ok((alias.clone(), false))
            }
            Item::HostsGroup { name, entries } => {
                println!("Got the hosts file group \"{name}\":");
                for entry in entries {
                    println!(
                        "  {}{} {}{}",
                        if entry.enabled { "" } else { "# " },
                        entry.address,
                        entry.names.join(" "),
                        entry
                            .expires
                            .as_ref()
                            .map(|until| format!(" (until {until})"))
                            .unwrap_or_default()
                    );
                }
                Ok((name.clone(), false))
            }
            Item::PublicKey { name, key } => {
                println!("Got the public key {name}: {key}");
                Ok((name.clone(), false))
            }
            Item::Environment {
                project,
                name,
                variables,
                ..
            } => {
                // Names only: the values are secrets, even here.
                println!("Got the environment {project} / {name}:");
                for var in variables {
                    let secret = if var.secret { " (secret)" } else { "" };
                    println!("  {}{secret}", var.name);
                }
                Ok((format!("{project} / {name}"), false))
            }
            Item::Unknown => Err(PairingFailure::Unsupported),
        }
    }

    fn vault(&self, hash: &[u8], initiator: bool) -> Option<VaultState> {
        match &self.mode {
            Mode::Plain => None,
            Mode::Join(_) => Some(VaultState::Missing),
            Mode::Own { vault, .. } => Some(VaultState::Open {
                proof: vault
                    .lock()
                    .unwrap()
                    .own_key()
                    .map(|key| key.proof(hash, initiator))
                    .unwrap_or_default(),
            }),
        }
    }

    fn same_vault(&self, hash: &[u8], initiator: bool, proof: &str) -> bool {
        self.with_vault(|vault| {
            vault
                .own_key()
                .is_some_and(|key| key.verify(hash, initiator, proof))
        })
        .unwrap_or(false)
    }

    fn is_own(&self, peer: PeerKey) -> bool {
        self.with_vault(|vault| vault.is_own_device(&peer))
            .unwrap_or(false)
    }

    fn takes(&self, intent: Option<Intent>) -> Result<(), PairingFailure> {
        match (&self.mode, intent) {
            (Mode::Join(_), Some(Intent::AddDevice)) | (Mode::Own { .. }, Some(Intent::Sync)) => {
                Ok(())
            }
            (Mode::Plain, _) => Ok(()),
            _ => Err(PairingFailure::NotOwn),
        }
    }

    fn add_device(&self, peer: PeerKey, name: &str) -> Result<(), PairingFailure> {
        println!("{name} ({peer}) is one of your devices now.");
        Ok(())
    }

    fn take_vault(
        &self,
        file: Zeroizing<Vec<u8>>,
        secret: SecretText,
    ) -> Result<(), PairingFailure> {
        let Mode::Join(dir) = &self.mode else {
            return Err(PairingFailure::NotSaved);
        };
        let secret = SecretString::from(secret.expose().to_owned());
        check_moved(&file, &secret).map_err(|_| PairingFailure::NotSaved)?;
        print!(
            "The vault came ({} bytes). Master password for this computer: ",
            file.len()
        );
        let _ = io::stdout().flush();
        let mut master = String::new();
        io::stdin()
            .lock()
            .read_line(&mut master)
            .map_err(|_| PairingFailure::Cancelled)?;
        let master = SecretString::from(master.trim().to_owned());
        let vault = Vault::join(
            &VaultPaths::new(dir.join("vault.kdbx")),
            &file,
            &secret,
            &master,
        )
        .map_err(|error| {
            println!("Not saved: {error}");
            PairingFailure::NotSaved
        })?;
        println!(
            "Saved in {}. Your devices: {:?}",
            dir.display(),
            vault
                .own_devices()
                .into_iter()
                .map(|d| d.name)
                .collect::<Vec<_>>()
        );
        Ok(())
    }

    fn sync_load(&self, peer: PeerKey) -> Result<SyncLocal, PairingFailure> {
        let (config, known) = self.files().ok_or(PairingFailure::NotOwn)?;
        let state_file = self.dir().ok_or(PairingFailure::NotOwn)?.join(format!(
            "sync-{}.json",
            peer.to_string().replace(['/', '+', '='], "_")
        ));
        Ok(SyncLocal {
            config: SshConfig::load(&config).map_err(|_| PairingFailure::NotSaved)?,
            known: KnownHosts::load(&known).map_err(|_| PairingFailure::NotSaved)?,
            devices: self
                .with_vault(|vault| vault.device_records())
                .unwrap_or_default(),
            projects: self
                .with_vault(|vault| vault.project_records())
                .unwrap_or_default(),
            contacts: self
                .with_vault(|vault| vault.contact_records())
                .unwrap_or_default(),
            state: std::fs::read(state_file)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or_default(),
            hasher: Hasher::new(self.identity.derive_key(BASE_LABEL)),
        })
    }

    fn sync_write(&self, _: PeerKey, write: &SyncWrite) -> Result<(), PairingFailure> {
        let (config, known) = self.files().ok_or(PairingFailure::NotOwn)?;
        let backups = self.dir().ok_or(PairingFailure::NotOwn)?.join("backups");
        if let Some(new) = &write.config {
            new.save(&config, &backups)
                .map_err(|_| PairingFailure::NotSaved)?;
            println!("Wrote {}.", config.display());
        }
        if let Some(new) = &write.known {
            new.save(&known, &backups)
                .map_err(|_| PairingFailure::NotSaved)?;
            println!("Wrote {}.", known.display());
        }
        self.with_vault(|vault| {
            let devices = vault.merge_own_devices(&write.devices).unwrap_or(false);
            let projects = vault.merge_projects(&write.projects).unwrap_or(false);
            let contacts = vault.merge_contacts(&write.contacts).unwrap_or(false);
            if devices || projects || contacts {
                let _ = vault.save(&backups);
            }
        });
        Ok(())
    }

    fn sync_keep(&self, peer: PeerKey, state: &SyncState) -> Result<(), PairingFailure> {
        let dir = self.dir().ok_or(PairingFailure::NotOwn)?;
        let file = dir.join(format!(
            "sync-{}.json",
            peer.to_string().replace(['/', '+', '='], "_")
        ));
        let json = serde_json::to_vec_pretty(state).map_err(|_| PairingFailure::NotSaved)?;
        std::fs::write(file, json).map_err(|_| PairingFailure::NotSaved)
    }

    fn entry_sync(&self) -> Option<EntrySync> {
        self.with_vault(|_| EntrySync::On {
            version: ENTRY_SYNC_VERSION,
        })
    }

    fn vault_copy(&self) -> Result<Zeroizing<Vec<u8>>, PairingFailure> {
        self.with_vault(|vault| vault.sync_copy())
            .ok_or(PairingFailure::NotOwn)?
            .map_err(|_| PairingFailure::NotSaved)
    }

    fn vault_plan(&self, copy: &[u8], base: &VaultBase) -> Result<VaultPlan, PairingFailure> {
        let hasher = self.vault_hasher();
        let (plan, peer) = self
            .with_vault(|vault| {
                let peer = vault.open_sync_copy(copy).ok()?;
                Some((vault.plan_sync(&peer, base, &hasher), peer))
            })
            .flatten()
            .ok_or(PairingFailure::Broken)?;
        println!(
            "Vault: {} changes, {} conflicts.",
            plan.changes.len(),
            plan.conflicts.len()
        );
        *self.peer_vault.lock().unwrap() = Some(peer);
        Ok(plan)
    }

    fn vault_apply(
        &self,
        plan: &VaultPlan,
        choices: &VaultChoices,
    ) -> Result<VaultApplied, PairingFailure> {
        let peer = self
            .peer_vault
            .lock()
            .unwrap()
            .take()
            .ok_or(PairingFailure::Broken)?;
        let backups = self.dir().ok_or(PairingFailure::NotOwn)?.join("backups");
        let hasher = self.vault_hasher();
        let applied = self
            .with_vault(|vault| {
                let applied = vault.apply_sync(&peer, plan, &hasher, choices).ok()?;
                vault.save(&backups).ok()?;
                Some(applied)
            })
            .flatten()
            .ok_or(PairingFailure::NotSaved)?;
        println!("Vault: {:?}", applied.counts);
        Ok(applied)
    }

    fn vault_items(&self, pairs: &Pairs) -> Result<VaultItems, PairingFailure> {
        let hasher = self.vault_hasher();
        self.with_vault(|vault| {
            let shared = Hasher::new(vault.own_key()?.digest_key());
            Some(VaultItems {
                snapshots: vault.sync_items(pairs, &hasher),
                digests: digests(&vault.sync_items(pairs, &shared)),
            })
        })
        .flatten()
        .ok_or(PairingFailure::NotOwn)
    }
}

impl Terminal {
    fn vault_hasher(&self) -> Hasher {
        Hasher::new(self.identity.derive_key(VAULT_BASE_LABEL))
    }

    fn files(&self) -> Option<(PathBuf, PathBuf)> {
        let ssh = self.dir()?.join("ssh");
        Some((ssh.join("config"), ssh.join("known_hosts")))
    }
}

fn ask(question: &str) {
    print!("{question} [y/n] ");
    let _ = io::stdout().flush();
}

fn describe(item: &ItemSummary) -> String {
    match item {
        ItemSummary::Password { title, .. } => format!("the login \"{title}\""),
        ItemSummary::Host { alias, address, .. } => format!("the host {alias} ({address})"),
        ItemSummary::HostsGroup { name, entries, .. } => {
            format!("the hosts file group \"{name}\" ({entries} entries)")
        }
        ItemSummary::PublicKey {
            name, fingerprint, ..
        } => format!("the public key {name} ({fingerprint})"),
        ItemSummary::Environment {
            project,
            name,
            variables,
            ..
        } => format!("the environment {project} / {name} ({variables} variables)"),
        ItemSummary::Unknown => "something this version doesn't know".to_owned(),
    }
}

fn sample(kind: &str, name: &str) -> Item {
    if kind == "group" {
        let entry = |address: &str, names: &[&str], enabled: bool| HostsEntry {
            address: address.into(),
            names: names.iter().map(|&name| name.to_owned()).collect(),
            enabled,
            expires: None,
        };
        Item::HostsGroup {
            name: "test peer".into(),
            entries: vec![
                entry("192.0.2.10", &["api.test-peer.local", "api"], true),
                entry("192.0.2.11", &["db.test-peer.local"], true),
                entry("2001:db8::12", &["cache.test-peer.local"], false),
                HostsEntry {
                    expires: Some("2030-01-01T00:00:00Z".into()),
                    ..entry("192.0.2.13", &["preview.test-peer.local"], true)
                },
            ],
        }
    } else if kind == "key" {
        Item::PublicKey {
            name: "id_ed25519".into(),
            key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBIZFNq0hlvHGZ/oas65Ba4jkcFEy3dX/aRZy70M73oL test@peer".into(),
        }
    } else if kind == "host" {
        Item::Host {
            alias: "test-peer-host".into(),
            host_name: Some("192.0.2.10".into()),
            user: Some("deploy".into()),
            port: Some(2222),
            proxy_jump: None,
            host_keys: vec![HostKey {
                key_type: "ssh-ed25519".into(),
                key: "AAAAC3NzaC1lZDI1NTE5AAAAIBIZFNq0hlvHGZ/oas65Ba4jkcFEy3dX/aRZy70M73oL".into(),
            }],
        }
    } else {
        Item::Password {
            title: format!("Test login from {name}"),
            username: "tester".into(),
            password: "correct horse battery staple".into(),
            url: "https://example.com".into(),
            notes: "Sent by the nearby_peer example.".into(),
            otp: None,
            host: None,
        }
    }
}

/// The app's address, once it shows itself on the network.
fn find_app(daemon: &ServiceDaemon) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let events = daemon.browse(SERVICE_TYPE)?;
    let deadline = Instant::now() + Duration::from_secs(60);
    println!("Looking for the app: click \"Show for 10 minutes\" in Nearby…");
    while Instant::now() < deadline {
        if let Ok(ServiceEvent::ServiceResolved(service)) =
            events.recv_timeout(Duration::from_secs(1))
            && let Some(ip) = service
                .get_addresses_v4()
                .into_iter()
                .find(|ip| !ip.is_unspecified())
        {
            println!(
                "Found {} at {ip}:{}.",
                service.get_property_val_str("name").unwrap_or("?"),
                service.port
            );
            return Ok(SocketAddr::new(ip.into(), service.port));
        }
    }
    Err("the app did not show up within a minute".into())
}

/// The device key kept in `dir`, or a new one kept there.
fn identity_in(dir: &Path) -> Result<Identity, Box<dyn std::error::Error>> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join("identity");
    if let Ok(text) = std::fs::read_to_string(&path) {
        return Ok(Identity::from_secret(&SecretString::from(
            text.trim().to_owned(),
        ))?);
    }
    let identity = Identity::generate()?;
    std::fs::write(&path, identity.to_secret().expose_secret())?;
    Ok(identity)
}

fn option(args: &[String], name: &str) -> Option<String> {
    let i = args.iter().position(|arg| arg == name)?;
    Some(args.get(i + 1).cloned().unwrap_or_default())
}

/// How this side shows itself on `port`: to the user's devices with a vault,
/// else as the app does after "Show for 10 minutes".
fn announcement(side: &Terminal, port: u16) -> Result<ServiceInfo, Box<dyn std::error::Error>> {
    let name = side.name.as_str();
    let info = if let Some(instance) = side
        .with_vault(|vault| {
            let seconds = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            vault
                .own_key()
                .map(|key| key.presence_name(&side.identity.public(), window(seconds)))
        })
        .flatten()
    {
        println!("Announced to your devices on port {port}. Click \"Sync now\" in Nearby.");
        ServiceInfo::new(
            OWN_SERVICE_TYPE,
            &instance,
            &format!("{instance}.local."),
            (),
            port,
            &[("v", "1")][..],
        )?
    } else {
        let instance = format!("test-peer-{port}");
        let mut properties = vec![("v", "1"), ("name", name)];
        if matches!(side.mode, Mode::Join(_)) {
            properties.push(("join", "1"));
            println!("Waiting for a vault as \"{name}\": click \"Add as my device\" in Nearby.");
        } else {
            println!(
                "Shown as \"{name}\" on port {port}. Pair with it, or send it something, in Nearby."
            );
        }
        ServiceInfo::new(
            SERVICE_TYPE,
            &instance,
            &format!("{instance}.local."),
            (),
            port,
            &properties[..],
        )?
    };
    Ok(info)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let send = option(&args, "--send").map(|kind| {
        if kind.is_empty() {
            "password".into()
        } else {
            kind
        }
    });
    let join = option(&args, "--join").map(PathBuf::from);
    let own = option(&args, "--sync").map(PathBuf::from);
    let values: Vec<String> = [
        &send,
        &join.as_ref().map(|p| p.display().to_string()),
        &own.as_ref().map(|p| p.display().to_string()),
    ]
    .into_iter()
    .flatten()
    .cloned()
    .collect();
    let name = args
        .iter()
        .find(|arg| !arg.starts_with("--") && !values.contains(arg))
        .cloned()
        .unwrap_or_else(|| "Test peer".into());
    let daemon = ServiceDaemon::new()?;
    let (identity, mode) = if let Some(dir) = join {
        (identity_in(&dir)?, Mode::Join(dir))
    } else if let Some(dir) = own {
        print!("Master password of the vault in {}: ", dir.display());
        io::stdout().flush()?;
        let mut master = String::new();
        io::stdin().lock().read_line(&mut master)?;
        let vault = Vault::unlock(
            &VaultPaths::new(dir.join("vault.kdbx")),
            &SecretString::from(master.trim().to_owned()),
        )?;
        (
            identity_in(&dir)?,
            Mode::Own {
                dir,
                vault: Box::new(Mutex::new(vault)),
            },
        )
    } else {
        (Identity::generate()?, Mode::Plain)
    };
    let side = Terminal {
        name: name.clone(),
        identity,
        mode,
        peer_vault: Mutex::new(None),
    };

    let end = if let Some(kind) = send {
        let address = find_app(&daemon)?;
        let stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut session = p2p::connect(stream, &side.identity)?;
        let item = sample(&kind, &name);
        conversation(
            &mut session,
            &side,
            Some(Purpose::Send {
                item: &item,
                to: None,
            }),
        )
    } else {
        let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        let port = listener.local_addr()?.port();
        daemon.register(announcement(&side, port)?.enable_addr_auto())?;
        let (stream, from) = listener.accept()?;
        println!("{from} connected.");
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut session = p2p::accept(stream, &side.identity)?;
        conversation(&mut session, &side, None)
    };
    println!("Result: {end:?}");
    let _ = daemon.shutdown();
    Ok(())
}
