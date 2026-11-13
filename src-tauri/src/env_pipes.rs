//! The pipes of level-3 `.env` files that the app serves while it runs
//! (`sshkm_core::vault::envs::files::pipes`): one server each, started for
//! the pipes a round makes or keeps, given each round's answer, and
//! stopped when its binding goes or its level changes.
//!
//! The pipes outlive a lock: while the vault is locked each answers that it
//! is ([`Answer::Locked`]), at once. A round that read the values before a
//! lock it didn't see coming (the vault lost) doesn't hand them out after
//! it: each lock is counted, and a round started before one serves
//! "locked". The pipes go when the app quits, after answering the readers
//! waiting that the app isn't running. The list of them is kept in
//! `env-files-virtual.json` (where and which, no values) for the guard
//! ([`crate::env_guard`]), which removes them the same way after a crash,
//! and for the next start, which does it if the guard went too; a round
//! lists a pipe as soon as it makes it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use sshkm_core::vault::envs::files::pipes::{self, ListedPipe, PipeList, PipeServer};
use sshkm_core::vault::envs::files::{Answer, PipeId, VirtualFile};

/// The pipes the app serves, by id: what the core may take for the app's
/// own ([`sshkm_core::vault::envs::files::FilesContext::pipes`]).
pub type KnownPipes = Arc<Mutex<Vec<PipeId>>>;

const LIST_FILE: &str = "env-files-virtual.json";

/// Where the app keeps the list of its pipes, in its data folder `data_dir`.
pub fn list_path(data_dir: &Path) -> PathBuf {
    data_dir.join(LIST_FILE)
}

pub struct Pipes {
    list_path: PathBuf,
    servers: Mutex<BTreeMap<PathBuf, Served>>,
    known: KnownPipes,
    /// How many pipes are served, read without waiting for `servers`.
    count: AtomicUsize,
    /// Counts the times the vault locked (or was lost).
    locks: AtomicU64,
}

struct Served {
    server: PipeServer,
    /// The pipe as the project's folder names it, which the watcher may
    /// report instead.
    display: PathBuf,
}

impl Pipes {
    /// Removes the pipes a crash left, as the guard would have, before
    /// anything else.
    pub fn new(data_dir: &Path, known: KnownPipes) -> Self {
        let list_path = list_path(data_dir);
        let removed = PipeList::sweep_at(&list_path);
        if removed > 0 {
            log::info!("env files: removed {removed} pipes left by the last run");
        }
        lock(&known).clear();
        Self {
            list_path,
            servers: Mutex::new(BTreeMap::new()),
            known,
            count: AtomicUsize::new(0),
            locks: AtomicU64::new(0),
        }
    }

    pub fn list_path(&self) -> &Path {
        &self.list_path
    }

    pub fn is_empty(&self) -> bool {
        self.count() == 0
    }

    pub fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    /// Which lock the vault is past: read before a round reads the values,
    /// and given back to [`Self::follow`].
    pub fn since(&self) -> u64 {
        self.locks.load(Ordering::SeqCst)
    }

    /// Serves the pipes of a round, `served`, with their answers (or, with
    /// `locked`, or when the vault locked since `since`, that it is
    /// locked), and stops serving the others. Returns whether a pipe went:
    /// a file may be due in its place, which the next round writes.
    pub fn follow(&self, served: &[VirtualFile], locked: bool, since: u64) -> bool {
        let mut servers = lock(&self.servers);
        let locked = locked || self.since() != since;
        let stale: Vec<PathBuf> = servers
            .iter()
            .filter(|(path, running)| {
                !served
                    .iter()
                    .any(|wanted| wanted.path == **path && wanted.id == running.server.id())
            })
            .map(|(path, _)| path.clone())
            .collect();
        let stopping: Vec<Served> = stale
            .iter()
            .filter_map(|path| servers.remove(path))
            .collect();
        let went = stop_all(stopping, &Answer::Stopped);
        for wanted in served {
            let answer = if locked {
                Answer::Locked
            } else {
                wanted.answer.clone()
            };
            if let Some(running) = servers.get(&wanted.path)
                && running.server.is_serving()
            {
                running.server.set_answer(answer);
                continue;
            }
            // A server whose thread went is started again on its pipe,
            // which stays: readers may be waiting on it. The old one holds
            // the pipe until the new one does, so no other pipe gets its
            // inode number in between.
            let previous = servers.remove(&wanted.path);
            match PipeServer::start(&wanted.path, wanted.id, answer) {
                Ok(started) => {
                    servers.insert(
                        wanted.path.clone(),
                        Served {
                            server: started,
                            display: wanted.display.clone(),
                        },
                    );
                }
                Err(error) => {
                    // No pipe without a server: a reader would wait on it.
                    log::warn!("env files: a virtual file isn't served: {error}");
                    pipes::remove(&wanted.path, wanted.id, &Answer::Stopped);
                }
            }
            drop(previous);
        }
        self.keep(&servers);
        went
    }

    /// Every pipe answers that the vault is locked from now on, and a round
    /// that read the values before doesn't hand them out.
    pub fn lock(&self) {
        self.locks.fetch_add(1, Ordering::SeqCst);
        for running in lock(&self.servers).values() {
            running.server.set_answer(Answer::Locked);
        }
    }

    /// The app quits: readers waiting hear that it isn't running, and the
    /// pipes go, all at once.
    pub fn quit(&self) {
        let mut servers = lock(&self.servers);
        let all = std::mem::take(&mut *servers).into_values().collect();
        stop_all(all, &Answer::NotRunning);
        self.keep(&servers);
    }

    /// The pipes served now, as the watcher may name them, with their ids:
    /// a change it reports to one still the same pipe is the app's own
    /// answer, not an edit.
    pub fn watched(&self) -> Vec<(PathBuf, PipeId)> {
        lock(&self.servers)
            .iter()
            .flat_map(|(path, running)| {
                let id = running.server.id();
                [(path.clone(), id), (running.display.clone(), id)]
            })
            .collect()
    }

    /// Keeps the ids for the core, the count, and the list for the guard.
    fn keep(&self, servers: &BTreeMap<PathBuf, Served>) {
        *lock(&self.known) = servers
            .values()
            .map(|running| running.server.id())
            .collect();
        self.count.store(servers.len(), Ordering::SeqCst);
        let list = PipeList::new(
            servers
                .iter()
                .map(|(path, running)| ListedPipe {
                    path: path.clone(),
                    id: running.server.id(),
                })
                .collect(),
        );
        if let Err(error) = list.save(&self.list_path) {
            log::warn!("env files: the list of virtual files wasn't kept: {error}");
        }
    }
}

/// Stops the servers `stopping`, telling each first so they stop together,
/// then answering their waiting readers with `answer` and removing their
/// pipes. Returns whether a pipe went.
fn stop_all(stopping: Vec<Served>, answer: &Answer) -> bool {
    for running in &stopping {
        running.server.signal_stop(answer);
    }
    let mut went = false;
    for running in stopping {
        went |= running.server.finish(answer);
    }
    went
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
