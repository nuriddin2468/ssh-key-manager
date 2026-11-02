//! Views the commands return on top of the core types. With `cargo test` they
//! also derive `ts_rs::TS` and are written to the repository's `src/bindings/`.

use serde::{Deserialize, Serialize};
use sshkm_core::agent::{AgentIdentity, AgentStatus};
use sshkm_core::config::{ConfigView, IdentityUsage};
use sshkm_core::keys::{GenerateRequest, KeyInfo, SkippedFile};
use sshkm_core::known_hosts::{KnownHostEntry, KnownHostsView};
use sshkm_core::paths::SshPaths;
use sshkm_core::perms::PermKind;

use crate::askpass::AskedPrompt;

#[cfg(test)]
pub(crate) const BINDINGS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../src/bindings/");

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub enum Platform {
    Macos,
    Windows,
    Linux,
}

impl Platform {
    pub const CURRENT: Self = if cfg!(target_os = "macos") {
        Self::Macos
    } else if cfg!(windows) {
        Self::Windows
    } else {
        Self::Linux
    };
}

/// Facts about this machine the UI shows and uses for paths.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub struct Environment {
    pub paths: SshPaths,
    pub platform: Platform,
    /// `OpenSSH_9.9p1` style version, `None` if `ssh` is not installed.
    pub openssh_version: Option<String>,
    pub app_version: String,
    /// `user@host`, the comment `ssh-keygen` would give a new key.
    pub default_comment: String,
    /// Where backups of edited files are kept.
    pub backup_dir: String,
}

/// A host block that references a key.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub struct KeyUsage {
    /// `None` for an `IdentityFile` in the global section.
    pub host_id: Option<u32>,
    pub patterns: Vec<String>,
}

/// A key plus what the rest of the system says about it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub struct KeyView {
    #[serde(flatten)]
    #[cfg_attr(test, ts(flatten))]
    pub info: KeyInfo,
    /// The agent holds this key.
    pub in_agent: bool,
    /// Host blocks whose `IdentityFile` points at this key.
    pub used_by: Vec<KeyUsage>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub struct KeysView {
    pub keys: Vec<KeyView>,
    pub skipped: Vec<SkippedFile>,
}

/// A host block to create together with a new key.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub struct NewHost {
    pub alias: String,
    pub host_name: Option<String>,
    pub user: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub struct GenerateKeyRequest {
    pub key: GenerateRequest,
    pub add_to_agent: bool,
    pub agent_lifetime_secs: Option<u32>,
    pub host: Option<NewHost>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub struct AgentIdentityView {
    #[serde(flatten)]
    #[cfg_attr(test, ts(flatten))]
    pub identity: AgentIdentity,
    /// The key in `~/.ssh` this identity was loaded from, if any.
    pub key_id: Option<String>,
    /// When the agent drops the key (RFC 3339), if this app added it with a
    /// lifetime. The agent protocol cannot report lifetimes itself.
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub struct AgentView {
    pub status: AgentStatus,
    pub identities: Vec<AgentIdentityView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub struct ConfigFile {
    pub path: String,
    pub exists: bool,
    pub view: ConfigView,
    pub usage: Vec<IdentityUsage>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub struct SavedHost {
    pub file: ConfigFile,
    pub id: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub struct KnownHostsFile {
    pub path: String,
    pub exists: bool,
    pub view: KnownHostsView,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub enum HostKeyStatus {
    /// A key the server offers is in `known_hosts`.
    Match,
    /// `known_hosts` has keys for the host, but none the server offers.
    Changed,
    /// `known_hosts` has no key for the host.
    Unknown,
    /// The server could not be reached.
    Failed,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub struct OfferedKey {
    pub key_type: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub struct HostKeyCheck {
    pub status: HostKeyStatus,
    pub offered: Vec<OfferedKey>,
    pub saved: Vec<KnownHostEntry>,
    /// Why the check failed (`ssh-keyscan` output).
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub struct ConnectionTest {
    pub ok: bool,
    /// What `ssh` printed, for the user to read.
    pub output: String,
    /// What `ssh` asked the app for and what became of it, in order. Empty
    /// unless a password or one-time code was given: without one `ssh` runs in
    /// batch mode and asks nothing.
    pub prompts: Vec<AskedPrompt>,
}

/// The result of adding a public key to a server's `~/.ssh/authorized_keys`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub struct KeyInstall {
    /// The key is in `authorized_keys` now.
    pub ok: bool,
    /// It was added; `false` if it was there already or the install failed.
    pub added: bool,
    /// What `ssh` and the remote shell printed, for the user to read.
    pub output: String,
    /// As in [`ConnectionTest`].
    pub prompts: Vec<AskedPrompt>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub struct PermissionFix {
    pub path: String,
    pub kind: PermKind,
}
