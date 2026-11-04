//! A scripted [`Side`] and two sides talking over loopback, for the tests of
//! [`pairing`](super::pairing), [`transfer`](super::transfer),
//! [`own`](super::own) and [`sync`](super::sync).

use std::collections::VecDeque;
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use sshkm_core::SecretString;
use sshkm_core::config::SshConfig;
use sshkm_core::known_hosts::KnownHosts;
use sshkm_core::p2p::own::OwnKey;
use sshkm_core::p2p::protocol::{Intent, Item, SecretText, VaultState};
use sshkm_core::p2p::{Identity, PeerKey, accept, connect};
use sshkm_core::sync::Hasher;
use sshkm_core::vault::DeviceRecord;
use zeroize::Zeroizing;

use super::pairing::{PairingFailure, PairingPhase, Purpose, Side, conversation};
use super::sync::{SyncDecisions, SyncLocal, SyncState, SyncWrite};

/// The vault a script has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vault {
    /// A version before own devices: its `Hello` says nothing of them.
    Unknown,
    /// None yet: it waits to be given one.
    Missing,
    Locked,
    /// Unlocked, with this secret.
    Open(&'static str),
}

/// The file a script gives a new device.
pub const VAULT_FILE: &[u8] = b"the vault file";

/// A side whose user gives `answers` in turn (`None`: cancels), each after
/// `delay`, then repeats the last one.
pub struct Script {
    pub name: &'static str,
    pub knows: bool,
    pub delay: Duration,
    /// `store` fails with this.
    pub store_fails: Option<PairingFailure>,
    answers: Mutex<VecDeque<Option<bool>>>,
    last: Mutex<Option<bool>>,
    asked: Mutex<Option<Instant>>,
    pub shown: Mutex<Vec<(Option<String>, PairingPhase)>>,
    pub saved: Mutex<Vec<String>>,
    pub stored: Mutex<Vec<Item>>,

    pub vault: Vault,
    /// The other side is one of the user's devices here.
    pub own_peer: bool,
    /// Announced to own devices: only a sync is taken.
    pub only_sync: bool,
    /// What this user decides on a sync's review.
    pub decisions: SyncDecisions,
    /// Devices added, by name.
    pub added: Mutex<Vec<String>>,
    /// The vault this side was given.
    pub taken: Mutex<Option<(Vec<u8>, String)>>,
    pub config: Mutex<SshConfig>,
    pub known: Mutex<KnownHosts>,
    pub sync_state: Mutex<SyncState>,
    /// Device records the other side sent in a sync.
    pub devices: Mutex<Vec<DeviceRecord>>,
}

impl Script {
    pub fn new(name: &'static str, answer: Option<bool>) -> Self {
        Self::answering(name, &[answer])
    }

    pub fn answering(name: &'static str, answers: &[Option<bool>]) -> Self {
        Self {
            name,
            knows: false,
            delay: Duration::ZERO,
            store_fails: None,
            answers: Mutex::new(answers.iter().copied().collect()),
            last: Mutex::new(Some(true)),
            asked: Mutex::default(),
            shown: Mutex::default(),
            saved: Mutex::default(),
            stored: Mutex::default(),
            vault: Vault::Unknown,
            own_peer: false,
            only_sync: false,
            decisions: SyncDecisions::default(),
            added: Mutex::default(),
            taken: Mutex::default(),
            config: Mutex::default(),
            known: Mutex::default(),
            sync_state: Mutex::default(),
            devices: Mutex::default(),
        }
    }

    /// One of the user's devices with the vault `secret` and this config.
    pub fn own(name: &'static str, secret: &'static str, config: &str) -> Self {
        let mut script = Self::new(name, Some(true));
        script.vault = Vault::Open(secret);
        script.own_peer = true;
        *script.config.get_mut().unwrap() = SshConfig::parse(config);
        script
    }

    pub fn config_text(&self) -> String {
        self.config.lock().unwrap().to_string()
    }

    fn own_key(&self) -> Option<OwnKey> {
        match self.vault {
            Vault::Open(secret) => Some(OwnKey::from_secret(&SecretString::from(secret))),
            _ => None,
        }
    }
}

impl Side for Script {
    fn name(&self) -> String {
        self.name.into()
    }
    fn knows(&self, _: PeerKey) -> Result<bool, PairingFailure> {
        Ok(self.knows)
    }
    fn save(&self, _: PeerKey, name: &str) -> Result<(), PairingFailure> {
        self.saved.lock().unwrap().push(name.into());
        Ok(())
    }
    fn show(&self, peer: Option<&str>, phase: &PairingPhase) {
        self.shown
            .lock()
            .unwrap()
            .push((peer.map(str::to_owned), phase.clone()));
    }
    fn answer(&self, wait: Duration) -> Result<Option<bool>, PairingFailure> {
        let first = *self.asked.lock().unwrap().get_or_insert_with(Instant::now);
        if first.elapsed() < self.delay {
            thread::sleep(wait);
            return Ok(None);
        }
        *self.asked.lock().unwrap() = None;
        let mut last = self.last.lock().unwrap();
        let answer = self.answers.lock().unwrap().pop_front().unwrap_or(*last);
        *last = answer;
        answer.map(Some).ok_or(PairingFailure::Cancelled)
    }
    fn store(&self, item: &Item) -> Result<(String, bool), PairingFailure> {
        if let Some(failure) = self.store_fails {
            return Err(failure);
        }
        self.stored.lock().unwrap().push(item.clone());
        let name = match item {
            Item::Password { title, .. } => title.clone(),
            Item::Host { alias, .. } => alias.clone(),
        };
        Ok((name, false))
    }

    fn vault(&self, hash: &[u8], initiator: bool) -> Option<VaultState> {
        match self.vault {
            Vault::Unknown => None,
            Vault::Missing => Some(VaultState::Missing),
            Vault::Locked => Some(VaultState::Locked),
            Vault::Open(_) => self.own_key().map(|key| VaultState::Open {
                proof: key.proof(hash, initiator),
            }),
        }
    }
    fn same_vault(&self, hash: &[u8], initiator: bool, proof: &str) -> bool {
        self.own_key()
            .is_some_and(|key| key.verify(hash, initiator, proof))
    }
    fn is_own(&self, _: PeerKey) -> bool {
        self.own_peer
    }
    fn takes(&self, intent: Option<Intent>) -> Result<(), PairingFailure> {
        if self.only_sync && intent != Some(Intent::Sync) {
            return Err(PairingFailure::NotOwn);
        }
        if self.vault == Vault::Missing && intent != Some(Intent::AddDevice) {
            return Err(PairingFailure::VaultLocked);
        }
        Ok(())
    }
    fn add_device(&self, _: PeerKey, name: &str) -> Result<(), PairingFailure> {
        self.added.lock().unwrap().push(name.into());
        Ok(())
    }
    fn share_vault(&self) -> Result<(Zeroizing<Vec<u8>>, SecretText), PairingFailure> {
        let Vault::Open(secret) = self.vault else {
            return Err(PairingFailure::Broken);
        };
        Ok((Zeroizing::new(VAULT_FILE.to_vec()), SecretText::new(secret)))
    }
    fn take_vault(
        &self,
        file: Zeroizing<Vec<u8>>,
        secret: SecretText,
    ) -> Result<(), PairingFailure> {
        *self.taken.lock().unwrap() = Some((file.to_vec(), secret.expose().to_owned()));
        Ok(())
    }
    fn sync_load(&self, _: PeerKey) -> Result<SyncLocal, PairingFailure> {
        Ok(SyncLocal {
            config: self.config.lock().unwrap().clone(),
            known: self.known.lock().unwrap().clone(),
            devices: Vec::new(),
            state: self.sync_state.lock().unwrap().clone(),
            hasher: Hasher::new(Zeroizing::new([u8::try_from(self.name.len()).unwrap(); 32])),
        })
    }
    fn sync_write(&self, _: PeerKey, write: &SyncWrite) -> Result<(), PairingFailure> {
        if let Some(config) = &write.config {
            *self.config.lock().unwrap() = config.clone();
        }
        if let Some(known) = &write.known {
            *self.known.lock().unwrap() = known.clone();
        }
        self.devices.lock().unwrap().clone_from(&write.devices);
        Ok(())
    }
    fn sync_keep(&self, _: PeerKey, state: &SyncState) -> Result<(), PairingFailure> {
        *self.sync_state.lock().unwrap() = state.clone();
        Ok(())
    }
    fn decisions(&self, _: Duration) -> Result<Option<SyncDecisions>, PairingFailure> {
        Ok(Some(self.decisions.clone()))
    }
}

/// Runs `left` as the side that connects, for `purpose`, and `right` as
/// the other; returns how each ended.
pub fn talk(
    left: Script,
    right: Script,
    purpose: Purpose<'_>,
) -> ((PairingPhase, Script), (PairingPhase, Script)) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let other = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut session = accept(stream, &Identity::generate().unwrap()).unwrap();
        (conversation(&mut session, &right, None), right)
    });
    let stream = TcpStream::connect(address).unwrap();
    let mut session = connect(stream, &Identity::generate().unwrap()).unwrap();
    let mine = (conversation(&mut session, &left, Some(purpose)), left);
    drop(session);
    (mine, other.join().unwrap())
}

/// Runs `left` as the side that connects, sending `item` if there is one,
/// and `right` as the other; returns how each ended.
pub fn run(
    left: Script,
    right: Script,
    item: Option<&Item>,
) -> ((PairingPhase, Script), (PairingPhase, Script)) {
    talk(left, right, item.map_or(Purpose::Pair, Purpose::Send))
}

/// Runs `left` against `right`, pairing only.
pub fn pair(left: Script, right: Script) -> ((PairingPhase, Script), (PairingPhase, Script)) {
    run(left, right, None)
}

/// The pairing codes a side showed.
pub fn codes(side: &Script) -> Vec<String> {
    side.shown
        .lock()
        .unwrap()
        .iter()
        .filter_map(|(_, phase)| match phase {
            PairingPhase::Compare { code } => Some(code.clone()),
            _ => None,
        })
        .collect()
}
