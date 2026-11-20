//! The vault's logins, as the phone lists, shows and edits them.

use sshkm_core::SecretString;
use sshkm_core::vault::projects::ProjectColor;
use sshkm_core::vault::{EntryDetail, EntryInput, EntryKind, EntrySummary, SecretField};

use super::{PhoneVault, exposed};
use crate::CoreError;

/// A login as the list shows it. Holds no secret.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Login {
    /// The KeePass entry UUID.
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    /// What the entry is for: a login, or an SSH host's password or a key's
    /// passphrase that a computer saved.
    pub kind: EntryKind,
    /// For a host's password: its `Host` alias.
    pub host: Option<String>,
    /// For a key's passphrase: the key's `SHA256:…` fingerprint.
    pub key_fingerprint: Option<String>,
    pub has_password: bool,
    /// A 2FA secret is stored: the login has one-time codes.
    pub has_otp: bool,
    /// Folder inside the database, e.g. `Work/Servers`; `None` at the top
    /// level. Vaults made by the app have none, KeePass files may.
    pub group: Option<String>,
    /// In the recycle bin.
    pub in_trash: bool,
    /// RFC 3339, UTC.
    pub modified: Option<String>,
}

/// Everything about a login except its secrets.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LoginDetail {
    pub login: Login,
    pub notes: String,
    /// When the current password was set (RFC 3339, UTC).
    pub password_changed: Option<String>,
    /// RFC 3339, UTC.
    pub created: Option<String>,
}

/// A new login, or the new state of one. Its kind, host and key stay as they
/// are on an edit.
#[derive(Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct LoginInput {
    pub title: String,
    #[uniffi(default = "")]
    pub username: String,
    #[uniffi(default = "")]
    pub url: String,
    #[uniffi(default = "")]
    pub notes: String,
    /// `None` keeps the current password (none, for a new login).
    #[uniffi(default = None)]
    pub password: Option<String>,
    /// A 2FA secret: an `otpauth://` URI or the key a site shows. `None`
    /// keeps the current one; an empty string removes it.
    #[uniffi(default = None)]
    pub otp: Option<String>,
}

impl std::fmt::Debug for LoginInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginInput")
            .field("title", &self.title)
            .finish_non_exhaustive()
    }
}

/// A login's current one-time code.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct OtpCode {
    pub code: String,
    /// Seconds until it changes.
    pub valid_for: u32,
}

impl std::fmt::Debug for OtpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtpCode")
            .field("valid_for", &self.valid_for)
            .finish_non_exhaustive()
    }
}

/// A project, as a label to filter logins by.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ProjectLabel {
    pub id: String,
    pub name: String,
    pub color: ProjectColor,
    /// The ids of its logins, not counting those in the recycle bin.
    pub logins: Vec<String>,
}

/// What an entry is for, as Kotlin sees it. UniFFI checks this copy against
/// the core's when it builds.
#[uniffi::remote(Enum)]
pub enum EntryKind {
    Login,
    Host,
    Key,
}

/// A project's color, as Kotlin sees it; the app maps it to its palette.
#[uniffi::remote(Enum)]
pub enum ProjectColor {
    Teal,
    Blue,
    Indigo,
    Violet,
    Pink,
    Red,
    Orange,
    Amber,
    Green,
    Slate,
}

#[uniffi::export]
impl PhoneVault {
    /// Every login, the recycle bin's included, sorted by title.
    pub fn logins(&self) -> Result<Vec<Login>, CoreError> {
        self.read(|vault| Ok(vault.entries().into_iter().map(Login::from).collect()))
    }

    pub fn login(&self, id: &str) -> Result<LoginDetail, CoreError> {
        self.read(|vault| vault.entry(id).map(LoginDetail::from))
    }

    /// The vault's projects, to filter logins by.
    pub fn projects(&self) -> Result<Vec<ProjectLabel>, CoreError> {
        self.read(|vault| {
            Ok(vault
                .projects()
                .into_iter()
                .map(|project| ProjectLabel {
                    id: project.id,
                    name: project.name,
                    color: project.color,
                    logins: project.logins,
                })
                .collect())
        })
    }

    /// A login's password, for the user who asked to see or copy it; empty
    /// when it has none.
    pub fn password(&self, id: &str) -> Result<String, CoreError> {
        self.read(|vault| vault.secret(id, SecretField::Password))
            .map(|secret| exposed(&secret))
    }

    /// A login's current one-time code.
    pub fn otp_code(&self, id: &str) -> Result<OtpCode, CoreError> {
        let (code, valid_for) = self.read(|vault| vault.otp_code(id))?;
        Ok(OtpCode {
            code,
            valid_for: u32::try_from(valid_for).unwrap_or(u32::MAX),
        })
    }

    /// Adds a login and returns its id.
    pub fn add_login(&self, input: LoginInput) -> Result<String, CoreError> {
        let input = entry_input(input, EntryKind::Login, None, None);
        self.change(|vault| vault.add_entry(&input))
    }

    /// Updates a login; its previous version stays in its history.
    pub fn update_login(&self, id: &str, input: LoginInput) -> Result<(), CoreError> {
        self.change(|vault| {
            let current = vault.entry(id)?.summary;
            let input = entry_input(input, current.kind, current.host, current.key_fingerprint);
            vault.update_entry(id, &input)
        })
    }

    /// Moves a login to the recycle bin, as on computers; sync carries that
    /// to them.
    pub fn trash_login(&self, id: &str) -> Result<(), CoreError> {
        self.change(|vault| vault.trash_entry(id))
    }

    /// Moves a login out of the recycle bin.
    pub fn restore_login(&self, id: &str) -> Result<(), CoreError> {
        self.change(|vault| vault.restore_entry(id))
    }
}

fn entry_input(
    input: LoginInput,
    kind: EntryKind,
    host: Option<String>,
    key_fingerprint: Option<String>,
) -> EntryInput {
    EntryInput {
        title: input.title,
        username: input.username,
        password: input.password.map(SecretString::from),
        url: input.url,
        notes: input.notes,
        otp: input.otp.map(SecretString::from),
        kind,
        host,
        key_fingerprint,
    }
}

impl From<EntrySummary> for Login {
    fn from(entry: EntrySummary) -> Self {
        Self {
            id: entry.id,
            title: entry.title,
            username: entry.username,
            url: entry.url,
            kind: entry.kind,
            host: entry.host,
            key_fingerprint: entry.key_fingerprint,
            has_password: entry.has_password,
            has_otp: entry.has_otp,
            group: entry.group,
            in_trash: entry.in_trash,
            modified: entry.modified,
        }
    }
}

impl From<EntryDetail> for LoginDetail {
    fn from(detail: EntryDetail) -> Self {
        let created = detail.summary.created.clone();
        Self {
            login: detail.summary.into(),
            notes: detail.notes,
            password_changed: detail.password_changed,
            created,
        }
    }
}
