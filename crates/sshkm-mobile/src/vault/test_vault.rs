//! A made-up vault for debug builds of the app, until the phone can get the
//! real one from a computer (step E of `docs/mobile.md`).
//!
//! Only the `test-vault` feature builds this, and only the app's debug
//! variant turns it on: release builds have neither the function nor its
//! Kotlin binding. The vault is made the way a computer makes one and goes
//! through [`PhoneVault::receive`], the way a vault from a computer will, so
//! setting the phone's master password, unlocking and fingerprint unlock are
//! the real ones.

use sshkm_core::SecretString;
use sshkm_core::vault::projects::{ProjectColor, ProjectInput, ProjectMember};
use sshkm_core::vault::{EntryInput, EntryKind, GenerateOptions, Vault, VaultPaths, generate};

use super::PhoneVault;
use crate::CoreError;

/// The 2FA key of the made-up GitHub login: the usual example key, so codes
/// can be checked against any authenticator.
const EXAMPLE_OTP: &str = "JBSWY3DPEHPK3PXP";

#[uniffi::export]
impl PhoneVault {
    /// Debug builds only: receives a made-up vault, as if a computer had
    /// sent it, with a few logins, two projects and one login in the
    /// recycle bin. `scratch` is a folder of the app's own (its cache) where
    /// the vault is made; nothing is left there.
    pub fn receive_test_vault(&self, scratch: &str) -> Result<(), CoreError> {
        let (database, secret) = make(scratch)?;
        self.receive(database, secret)
    }
}

/// The made-up vault's database file and its secret.
pub(super) fn make(scratch: &str) -> sshkm_core::Result<(Vec<u8>, SecretString)> {
    let dir = tempfile::tempdir_in(scratch).map_err(|e| sshkm_core::Error::Io {
        context: "making a test vault".into(),
        source: e,
    })?;
    let paths = VaultPaths::new(dir.path().join("vault.kdbx"));
    // The computer's master password, which the phone never needs.
    let computer_master = generate(&GenerateOptions::Password {
        length: 24,
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols: false,
        avoid_ambiguous: false,
    })?;
    let (mut vault, _recovery_key) = Vault::create(&paths, &computer_master)?;

    let github = vault.add_entry(&login(
        "GitHub",
        "octo-dev@example.com",
        "https://github.com/login",
        "Recovery codes are in the desk drawer.",
        Some(EXAMPLE_OTP),
    )?)?;
    let hetzner = vault.add_entry(&login(
        "Hetzner Cloud",
        "ops@example.com",
        "https://console.hetzner.cloud",
        "",
        None,
    )?)?;
    let mail = vault.add_entry(&login(
        "Mail",
        "me@example.com",
        "https://mail.example.com",
        "",
        None,
    )?)?;
    let router = vault.add_entry(&login(
        "Home router",
        "admin",
        "http://192.168.1.1",
        "Wi-Fi: home-5G",
        None,
    )?)?;
    vault.add_entry(&EntryInput {
        kind: EntryKind::Host,
        host: Some("db-staging".into()),
        ..login("db-staging", "deploy", "", "", None)?
    })?;
    let old = vault.add_entry(&login(
        "Old forum",
        "octo",
        "https://forum.example.org",
        "",
        None,
    )?)?;
    vault.trash_entry(&old)?;

    for (name, color, logins) in [
        ("Work", ProjectColor::Teal, [github, hetzner]),
        ("Personal", ProjectColor::Violet, [mail, router]),
    ] {
        let project = vault.add_project(&ProjectInput {
            name: name.into(),
            color,
        })?;
        for id in logins {
            vault.set_project_member(&project, &ProjectMember::Login { id }, true)?;
        }
    }

    vault.save(&dir.path().join("backups"))?;
    let database = vault.saved_bytes()?.to_vec();
    Ok((database, vault.share_secret()))
}

fn login(
    title: &str,
    username: &str,
    url: &str,
    notes: &str,
    otp: Option<&str>,
) -> sshkm_core::Result<EntryInput> {
    let password = generate(&GenerateOptions::Password {
        length: 20,
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols: true,
        avoid_ambiguous: false,
    })?;
    Ok(EntryInput {
        title: title.into(),
        username: username.into(),
        password: Some(password),
        url: url.into(),
        notes: notes.into(),
        otp: otp.map(SecretString::from),
        ..EntryInput::default()
    })
}
