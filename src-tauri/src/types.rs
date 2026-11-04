//! Views the commands return on top of the core types. With `cargo test` they
//! also derive `ts_rs::TS` and are written to the repository's `src/bindings/`.

use serde::{Deserialize, Serialize};
use sshkm_core::agent::{AgentIdentity, AgentStatus};
use sshkm_core::authorized_keys::AuthorizedKeys;
use sshkm_core::config::{ConfigView, IdentityUsage};
use sshkm_core::hosts_file::{HostsDiffLine, HostsFileView, HostsReadOnly};
use sshkm_core::keys::{GenerateRequest, KeyInfo, SkippedFile};
use sshkm_core::known_hosts::{KnownHostEntry, KnownHostsView};
use sshkm_core::paths::SshPaths;
use sshkm_core::perms::PermKind;
use sshkm_core::vault::{VaultFiles, VaultPaths};

use crate::vault::VaultSettings;

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
    /// The system hosts file.
    pub hosts_file: String,
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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub struct HostsFileInfo {
    pub path: String,
    pub exists: bool,
    /// SHA-256 of the file; edits are made against it.
    pub revision: String,
    /// Why the app cannot change the file, if it cannot.
    pub read_only: Option<HostsReadOnly>,
    pub view: HostsFileView,
}

/// What a set of changes would do to the hosts file.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub struct HostsPreview {
    /// The file changed since the changes were made, so they no longer apply.
    pub stale: bool,
    pub diff: Vec<HostsDiffLine>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub enum HostsApplyOutcome {
    /// The new file is in place.
    Applied,
    /// The password prompt was dismissed; nothing changed.
    Cancelled,
    /// The file changed since the changes were made; nothing changed.
    Stale,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub struct HostsApplyResult {
    pub outcome: HostsApplyOutcome,
    pub file: HostsFileInfo,
}

/// A copy of the hosts file saved before the app changed it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub struct HostsBackup {
    pub path: String,
    /// When it was saved (RFC 3339).
    pub saved: Option<String>,
    /// How many entries it has.
    pub entries: u32,
}

/// What the system resolver returned for a name.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub struct NameLookup {
    /// Addresses in the order the resolver prefers them.
    pub addresses: Vec<String>,
    /// Why nothing was found, as the resolver put it.
    pub error: Option<String>,
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

/// What to do to a server's `~/.ssh/authorized_keys` before reading it.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub enum ServerKeysAction {
    /// Nothing: only read it.
    List,
    /// Add the public key of one of the user's keys, as `install_public_key`
    /// does.
    Add {
        #[serde(rename = "keyId")]
        key_id: String,
    },
    /// Remove every line with this key (`<type> <base64>`), whatever its
    /// options or comment.
    Remove {
        #[serde(rename = "publicKey")]
        public_key: String,
    },
}

/// A server's `~/.ssh/authorized_keys`, read after an optional change, in
/// one sign-in: a server may take each 2FA code only once.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub struct ServerKeys {
    /// The file was read, and the change made or found already made.
    pub ok: bool,
    /// The key was added, or lines with it were removed.
    pub changed: bool,
    /// The file was read: even when the change failed, `file` is current.
    pub read: bool,
    /// What the file holds; empty unless it was read, or if there is none.
    pub file: AuthorizedKeys,
    /// What `ssh` and the remote shell printed, without the file.
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

/// Whether there is a vault and whether it is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub enum VaultState {
    /// No database file yet.
    Missing,
    Locked,
    Unlocked,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub struct VaultStatus {
    pub state: VaultState,
    pub files: VaultFiles,
    pub paths: VaultPaths,
    pub settings: VaultSettings,
    pub device: DeviceUnlockStatus,
}

/// The system's way of confirming it's the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub enum BiometricKind {
    TouchId,
    WindowsHello,
}

/// Touch ID / Windows Hello for the vault on this computer.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub struct DeviceUnlockStatus {
    /// What this computer offers; `None` when it offers nothing usable.
    pub kind: Option<BiometricKind>,
    /// Why it can't be used, in English, for logs and tooltips.
    pub unavailable_reason: Option<String>,
    /// Turned on for this vault on this computer.
    pub enabled: bool,
}

/// What [`crate::commands::vault::vault_copy`] copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub enum CopyField {
    Username,
    Password,
    Url,
    /// The current 2FA code.
    Otp,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub struct CopyResult {
    /// Seconds until the clipboard is cleared; `None` if it won't be.
    pub clears_in_secs: Option<u32>,
}

/// A 2FA code and how long it stays valid.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, export_to = BINDINGS))]
pub struct OtpCode {
    pub code: String,
    /// Seconds.
    pub valid_for: u32,
}
