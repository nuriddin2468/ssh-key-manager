//! The pipes of level-3 `.env` files that the app serves while it runs
//! (`sshkm_core::vault::envs::files::pipes`): one server each, started for
//! the pipes a round makes or keeps, given each round's answer, and
//! stopped when its binding goes or its level changes.
//!
//! The pipes outlive a lock: while the vault is locked each answers that it
//! is ([`Answer::Locked`]), at once. They go when the app quits, after
//! answering the readers waiting that the app isn't running. The list of
//! them is kept in `env-files-virtual.json` (where and which, no values) for
//! the guard ([`crate::env_guard`]), which removes them the same way after
//! a crash, and for the next start, which does it if the guard went too.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use sshkm_core::vault::envs::files::pipes::{ListedPipe, PipeList, PipeServer};
use sshkm_core::vault::envs::files::{Answer, PipeId, VirtualFile};

/// The pipes the app serves, by id: what the core may take for the app's
/// own ([`sshkm_core::vault::envs::files::FilesContext::pipes`]).
pub type KnownPipes = Arc<Mutex<Vec<PipeId>>>;

const LIST_FILE: &str = "env-files-virtual.json";

pub struct Pipes {
    list_path: PathBuf,
    servers: Mutex<BTreeMap<PathBuf, Served>>,
    known: KnownPipes,
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
        let list_path = data_dir.join(LIST_FILE);
        let removed = PipeList::sweep_at(&list_path);
        if removed > 0 {
            log::info!("env files: removed {removed} pipes left by the last run");
        }
        lock(&known).clear();
        Self {
            list_path,
            servers: Mutex::new(BTreeMap::new()),
            known,
        }
    }

    pub fn list_path(&self) -> &Path {
        &self.list_path
    }

    pub fn is_empty(&self) -> bool {
        lock(&self.servers).is_empty()
    }

    pub fn count(&self) -> usize {
        lock(&self.servers).len()
    }

    /// Serves the pipes of a round, `served`, with their answers (or, with
    /// `locked`, that the vault is locked), and stops serving the others.
    /// Returns whether a pipe went: a file may be due in its place, which
    /// the next round writes.
    pub fn follow(&self, served: &[VirtualFile], locked: bool) -> bool {
        let mut servers = lock(&self.servers);
        let mut went = false;
        let stale: Vec<PathBuf> = servers
            .iter()
            .filter(|(path, running)| {
                !served
                    .iter()
                    .any(|wanted| wanted.path == **path && wanted.id == running.server.id())
            })
            .map(|(path, _)| path.clone())
            .collect();
        for path in stale {
            if let Some(running) = servers.remove(&path) {
                went |= running.server.stop(&Answer::Stopped);
            }
        }
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
            if let Some(dead) = servers.remove(&wanted.path) {
                dead.server.stop(&Answer::Stopped);
            }
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
                Err(error) => log::warn!("env files: a virtual file isn't served: {error}"),
            }
        }
        self.keep(&servers);
        went
    }

    /// Every pipe answers that the vault is locked from now on.
    pub fn lock(&self) {
        for running in lock(&self.servers).values() {
            running.server.set_answer(Answer::Locked);
        }
    }

    /// The app quits: readers waiting hear that it isn't running, and the
    /// pipes go.
    pub fn quit(&self) {
        let mut servers = lock(&self.servers);
        for (_, running) in std::mem::take(&mut *servers) {
            running.server.stop(&Answer::NotRunning);
        }
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

    /// Keeps the ids for the core and the list for the guard.
    fn keep(&self, servers: &BTreeMap<PathBuf, Served>) {
        *lock(&self.known) = servers
            .values()
            .map(|running| running.server.id())
            .collect();
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

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
