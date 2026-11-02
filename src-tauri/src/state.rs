use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock, PoisonError};

use sshkm_core::paths::SshPaths;
use time::OffsetDateTime;

/// Shared by all commands.
pub struct AppState {
    pub paths: SshPaths,
    /// Backups of `config` and `known_hosts` are written here before edits.
    pub backup_dir: PathBuf,
    /// Expiry of keys this app added with a lifetime, by fingerprint. The
    /// agent protocol has no way to ask for it.
    lifetimes: Mutex<HashMap<String, OffsetDateTime>>,
    openssh_version: OnceLock<Option<String>>,
}

impl AppState {
    pub fn new(paths: SshPaths, backup_dir: PathBuf) -> Self {
        Self {
            paths,
            backup_dir,
            lifetimes: Mutex::new(HashMap::new()),
            openssh_version: OnceLock::new(),
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
}
