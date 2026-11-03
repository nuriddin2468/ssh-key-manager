use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use sshkm_core::paths::SshPaths;
use time::OffsetDateTime;

use crate::askpass::{self, Interactive, Responder, Session};
use crate::terminal::Terminals;
use crate::vault::VaultRuntime;

/// Shared by all commands.
pub struct AppState {
    pub paths: SshPaths,
    /// The system hosts file.
    pub hosts_file: PathBuf,
    /// Backups of `config` and `known_hosts` are written here before edits.
    pub backup_dir: PathBuf,
    /// Expiry of keys this app added with a lifetime, by fingerprint. The
    /// agent protocol has no way to ask for it.
    lifetimes: Mutex<HashMap<String, OffsetDateTime>>,
    openssh_version: OnceLock<Option<String>>,
    pub vault: Arc<VaultRuntime>,
    /// Answers `ssh`'s prompts; started on first use.
    askpass: Mutex<Option<askpass::Server>>,
    /// The in-app terminal's sessions.
    pub terminals: Arc<Terminals>,
}

impl AppState {
    /// `hosts_file` is the system hosts file; `data_dir` is the app's own data
    /// folder, home of the vault by default.
    pub fn new(
        paths: SshPaths,
        hosts_file: PathBuf,
        backup_dir: PathBuf,
        data_dir: PathBuf,
    ) -> Self {
        Self {
            paths,
            hosts_file,
            backup_dir,
            lifetimes: Mutex::new(HashMap::new()),
            openssh_version: OnceLock::new(),
            vault: Arc::new(VaultRuntime::new(data_dir)),
            askpass: Mutex::new(None),
            terminals: Arc::new(Terminals::default()),
        }
    }

    pub fn record_lifetime(&self, fingerprint: &str, lifetime_secs: Option<u32>) {
        let mut lifetimes = self
            .lifetimes
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match lifetime_secs {
            Some(secs) => {
                let expires = OffsetDateTime::now_utc() + time::Duration::seconds(secs.into());
                lifetimes.insert(fingerprint.to_owned(), expires);
            }
            None => {
                lifetimes.remove(fingerprint);
            }
        }
    }

    pub fn forget_lifetime(&self, fingerprint: &str) {
        self.record_lifetime(fingerprint, None);
    }

    pub fn forget_all_lifetimes(&self) {
        self.lifetimes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    /// Expiry of a key, dropping entries that have passed.
    pub fn expires_at(&self, fingerprint: &str) -> Option<OffsetDateTime> {
        let mut lifetimes = self
            .lifetimes
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let now = OffsetDateTime::now_utc();
        lifetimes.retain(|_, expires| *expires > now);
        lifetimes.get(fingerprint).copied()
    }

    pub fn openssh_version(&self) -> Option<String> {
        self.openssh_version
            .get_or_init(crate::process::openssh_version)
            .clone()
    }

    /// A batch session of the askpass server whose prompts `responder`
    /// answers. Starts the server if it is not running.
    pub fn askpass_session(&self, responder: impl Responder) -> io::Result<Session> {
        self.with_askpass(|server| server.session(responder))
    }

    /// An interactive askpass session, for the in-app terminal.
    pub fn askpass_interactive_session(&self, responder: impl Interactive) -> io::Result<Session> {
        self.with_askpass(|server| server.interactive_session(responder))
    }

    fn with_askpass(&self, open: impl FnOnce(&askpass::Server) -> Session) -> io::Result<Session> {
        let mut server = self.askpass.lock().unwrap_or_else(PoisonError::into_inner);
        if server.is_none() {
            *server = Some(askpass::Server::start()?);
        }
        Ok(open(
            server
                .as_ref()
                .expect("the askpass server was just started"),
        ))
    }

    /// Stops the askpass server and removes its socket, when the app exits.
    pub fn stop_askpass(&self) {
        self.askpass
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }
}
