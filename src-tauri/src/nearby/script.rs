//! A scripted [`Side`] and two sides talking over loopback, for the tests of
//! [`pairing`](super::pairing) and [`transfer`](super::transfer).

use std::collections::VecDeque;
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use sshkm_core::p2p::protocol::Item;
use sshkm_core::p2p::{Identity, PeerKey, accept, connect};

use super::pairing::{PairingFailure, PairingPhase, Side};
use super::transfer::exchange;

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
            Item::HostsGroup { name, .. } | Item::PublicKey { name, .. } => name.clone(),
        };
        Ok((name, false))
    }
}

/// Runs `left` as the side that connects, sending `item` if there is one,
/// and `right` as the other; returns how each ended.
pub fn run(
    left: Script,
    right: Script,
    item: Option<&Item>,
) -> ((PairingPhase, Script), (PairingPhase, Script)) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let other = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut session = accept(stream, &Identity::generate().unwrap()).unwrap();
        (exchange(&mut session, &right, false, None), right)
    });
    let stream = TcpStream::connect(address).unwrap();
    let mut session = connect(stream, &Identity::generate().unwrap()).unwrap();
    let mine = (exchange(&mut session, &left, true, item), left);
    drop(session);
    (mine, other.join().unwrap())
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
