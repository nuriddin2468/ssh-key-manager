use std::path::Path;
use std::sync::Arc;

use sshkm_core::vault::{EntryInput, EntryKind, Vault, VaultPaths};
use sshkm_core::{ErrorCode, SecretString};
use tempfile::TempDir;

use super::*;

const PHONE_MASTER: &str = "phone master password";

/// A vault as one of the user's computers has it: its database file and
/// secret, with one login.
fn from_a_computer() -> (Vec<u8>, SecretString) {
    let dir = TempDir::new().unwrap();
    let paths = VaultPaths::new(dir.path().join("vault.kdbx"));
    let (mut vault, _) = Vault::create(&paths, &SecretString::from("computer")).unwrap();
    vault
        .add_entry(&EntryInput {
            title: "From the computer".into(),
            username: "me".into(),
            password: Some(SecretString::from("computer secret")),
            ..EntryInput::default()
        })
        .unwrap();
    vault.save(&dir.path().join("backups")).unwrap();
    (vault.saved_bytes().unwrap().to_vec(), vault.share_secret())
}

fn phone(dir: &Path) -> Arc<PhoneVault> {
    PhoneVault::new(dir.join("vault").to_string_lossy().into_owned())
}

/// A phone with the computer's vault, unlocked with its own master password.
fn unlocked_phone() -> (TempDir, Arc<PhoneVault>) {
    let dir = TempDir::new().unwrap();
    let phone = phone(dir.path());
    let (database, secret) = from_a_computer();
    phone.receive(database, secret).unwrap();
    phone.set_master_password(PHONE_MASTER.into()).unwrap();
    (dir, phone)
}

/// The code of the error `result` holds.
fn code<T: std::fmt::Debug>(result: Result<T, CoreError>) -> ErrorCode {
    let CoreError::Failed { code, .. } = result.unwrap_err();
    code
}

fn status(phone: &PhoneVault) -> VaultStatus {
    phone.info().unwrap().status
}

fn input(title: &str) -> LoginInput {
    LoginInput {
        title: title.into(),
        ..LoginInput::default()
    }
}

#[test]
fn a_new_phone_has_no_vault_until_one_is_received() {
    let dir = TempDir::new().unwrap();
    let phone = phone(dir.path());
    let info = phone.info().unwrap();
    assert_eq!(info.status, VaultStatus::Missing);
    assert_eq!(info.vault_id, None);
    assert_eq!(code(phone.logins()), ErrorCode::VaultLocked);

    let (database, secret) = from_a_computer();
    phone.receive(database, secret).unwrap();
    assert_eq!(status(&phone), VaultStatus::Received);
    // Nothing is written before the phone has its master password.
    assert!(!dir.path().join("vault").exists());
}

#[test]
fn setting_the_master_password_writes_the_vault_and_opens_it() {
    let (dir, phone) = unlocked_phone();
    let info = phone.info().unwrap();
    assert_eq!(info.status, VaultStatus::Unlocked);
    assert!(info.vault_id.is_some());
    assert!(dir.path().join("vault/vault.kdbx").is_file());
    assert!(dir.path().join("vault/vault.keys").is_file());
    let logins = phone.logins().unwrap();
    assert_eq!(logins.len(), 1);
    assert_eq!(logins[0].title, "From the computer");
    assert!(logins[0].has_password);
}

#[test]
fn a_vault_the_secret_doesnt_open_is_refused() {
    let dir = TempDir::new().unwrap();
    let phone = phone(dir.path());
    let (database, _) = from_a_computer();
    let error = phone.receive(database, SecretString::from("not the secret"));
    assert_eq!(code(error), ErrorCode::WrongPassphrase);
    assert_eq!(status(&phone), VaultStatus::Missing);
}

#[test]
fn a_phone_with_a_vault_never_takes_another() {
    let (_dir, phone) = unlocked_phone();
    let (database, secret) = from_a_computer();
    let error = phone.receive(database, secret);
    assert_eq!(code(error), ErrorCode::AlreadyExists);
}

#[test]
fn an_empty_master_password_is_refused_and_the_vault_still_waits() {
    let dir = TempDir::new().unwrap();
    let phone = phone(dir.path());
    let error = phone.set_master_password(PHONE_MASTER.into());
    assert_eq!(code(error), ErrorCode::NotFound);

    let (database, secret) = from_a_computer();
    phone.receive(database, secret).unwrap();
    let error = phone.set_master_password(String::new());
    assert_eq!(code(error), ErrorCode::InvalidInput);
    assert_eq!(status(&phone), VaultStatus::Received);
}

#[test]
fn locking_drops_the_vault_and_the_master_password_opens_it_again() {
    let (_dir, phone) = unlocked_phone();
    phone.lock();
    assert!(!phone.is_unlocked());
    assert_eq!(status(&phone), VaultStatus::Locked);
    assert_eq!(code(phone.logins()), ErrorCode::VaultLocked);
    assert_eq!(code(phone.password("x")), ErrorCode::VaultLocked);
    // Locking twice is fine.
    phone.lock();

    let error = phone.unlock("wrong".into());
    assert_eq!(code(error), ErrorCode::WrongPassphrase);
    assert!(!phone.is_unlocked());
    phone.unlock(PHONE_MASTER.into()).unwrap();
    assert_eq!(phone.logins().unwrap().len(), 1);
}

#[test]
fn the_computers_master_password_doesnt_open_the_phone() {
    let (_dir, phone) = unlocked_phone();
    phone.lock();
    let error = phone.unlock("computer".into());
    assert_eq!(code(error), ErrorCode::WrongPassphrase);
}

#[test]
fn the_master_password_is_checked_without_locking() {
    let (_dir, phone) = unlocked_phone();
    phone.verify_master_password(PHONE_MASTER.into()).unwrap();
    let error = phone.verify_master_password("wrong".into());
    assert_eq!(code(error), ErrorCode::WrongPassphrase);
    assert!(phone.is_unlocked());
}

#[test]
fn the_fingerprint_slot_opens_the_vault_with_its_key_only() {
    let (_dir, phone) = unlocked_phone();
    let device = phone.enable_device_unlock().unwrap();
    assert_eq!(device.key.len(), 32);
    assert_eq!(
        phone.info().unwrap().device_slots,
        vec![device.slot_id.clone()]
    );
    phone.lock();

    let mut wrong = device.key.clone();
    wrong[0] ^= 1;
    assert!(phone.unlock_with_device(&device.slot_id, wrong).is_err());
    let error = phone.unlock_with_device(&device.slot_id, vec![0; 16]);
    assert_eq!(code(error), ErrorCode::InvalidInput);
    assert!(!phone.is_unlocked());

    phone
        .unlock_with_device(&device.slot_id, device.key.clone())
        .unwrap();
    assert!(phone.is_unlocked());

    phone.disable_device_unlock(&device.slot_id).unwrap();
    assert_eq!(phone.info().unwrap().device_slots, Vec::<String>::new());
    phone.lock();
    assert!(
        phone
            .unlock_with_device(&device.slot_id, device.key)
            .is_err()
    );
}

#[test]
fn turning_the_fingerprint_on_needs_the_vault_open() {
    let (_dir, phone) = unlocked_phone();
    phone.lock();
    assert_eq!(code(phone.enable_device_unlock()), ErrorCode::VaultLocked);
}

#[test]
fn a_login_round_trip() {
    let (dir, phone) = unlocked_phone();
    let id = phone
        .add_login(LoginInput {
            title: "Example".into(),
            username: "alice".into(),
            url: "https://example.com".into(),
            notes: "a note".into(),
            password: Some("hunter2!".into()),
            otp: Some("JBSWY3DPEHPK3PXP".into()),
        })
        .unwrap();

    let listed = phone.logins().unwrap();
    let login = listed.iter().find(|login| login.id == id).unwrap();
    assert_eq!(login.title, "Example");
    assert_eq!(login.kind, EntryKind::Login);
    assert!(login.has_password && login.has_otp && !login.in_trash);
    assert_eq!(phone.password(&id).unwrap(), "hunter2!");
    let otp = phone.otp_code(&id).unwrap();
    assert_eq!(otp.code.len(), 6);
    assert!(otp.code.chars().all(|c| c.is_ascii_digit()));
    assert!((1..=30).contains(&otp.valid_for));

    // An edit without a password keeps it; the 2FA secret goes when emptied.
    phone
        .update_login(
            &id,
            LoginInput {
                title: "Example 2".into(),
                username: "alice".into(),
                otp: Some(String::new()),
                ..LoginInput::default()
            },
        )
        .unwrap();
    let detail = phone.login(&id).unwrap();
    assert_eq!(detail.login.title, "Example 2");
    assert_eq!(detail.notes, "");
    assert!(!detail.login.has_otp);
    assert_eq!(phone.password(&id).unwrap(), "hunter2!");
    assert_eq!(code(phone.otp_code(&id)), ErrorCode::NotFound);

    phone.trash_login(&id).unwrap();
    assert!(phone.login(&id).unwrap().login.in_trash);
    phone.restore_login(&id).unwrap();
    assert!(!phone.login(&id).unwrap().login.in_trash);

    // Every change was saved, with backups of the files before it.
    phone.lock();
    phone.unlock(PHONE_MASTER.into()).unwrap();
    assert_eq!(phone.login(&id).unwrap().login.title, "Example 2");
    let backups = std::fs::read_dir(dir.path().join("vault/backups"))
        .unwrap()
        .count();
    assert!(backups >= 4, "{backups} backups");
}

#[test]
fn a_change_that_fails_leaves_the_vault_as_it_was() {
    let (_dir, phone) = unlocked_phone();
    let id = phone.add_login(input("Kept")).unwrap();
    let error = phone.update_login(&id, input("  "));
    assert_eq!(code(error), ErrorCode::InvalidInput);
    let error = phone.update_login(
        &id,
        LoginInput {
            otp: Some("not a 2FA key".into()),
            ..input("Changed")
        },
    );
    assert_eq!(code(error), ErrorCode::InvalidInput);
    assert_eq!(phone.login(&id).unwrap().login.title, "Kept");
}

#[test]
fn an_edit_keeps_what_a_computer_linked_the_entry_to() {
    let (_dir, phone) = unlocked_phone();
    let id = phone
        .change(|vault| {
            vault.add_entry(&EntryInput {
                title: "prod".into(),
                kind: EntryKind::Host,
                host: Some("prod".into()),
                ..EntryInput::default()
            })
        })
        .unwrap();
    phone.update_login(&id, input("prod (renamed)")).unwrap();
    let login = phone.login(&id).unwrap().login;
    assert_eq!(login.kind, EntryKind::Host);
    assert_eq!(login.host.as_deref(), Some("prod"));
}

#[test]
fn an_unknown_login_is_not_found() {
    let (_dir, phone) = unlocked_phone();
    let missing = "00000000-0000-0000-0000-000000000000".to_owned();
    assert_eq!(code(phone.login(&missing)), ErrorCode::NotFound);
    assert_eq!(code(phone.password(&missing)), ErrorCode::NotFound);
}

#[test]
fn secrets_stay_out_of_debug_output() {
    let device = DeviceUnlockKey {
        slot_id: "slot".into(),
        key: vec![7; 32],
    };
    assert!(!format!("{device:?}").contains('7'));
    let input = LoginInput {
        password: Some("hunter2".into()),
        otp: Some("JBSWY3DPEHPK3PXP".into()),
        ..input("Example")
    };
    let text = format!("{input:?}");
    assert!(!text.contains("hunter2") && !text.contains("JBSW"));
    let otp = OtpCode {
        code: "492039".into(),
        valid_for: 12,
    };
    assert!(!format!("{otp:?}").contains("492039"));
}

#[cfg(feature = "test-vault")]
#[test]
fn the_test_vault_is_received_like_one_from_a_computer() {
    let dir = TempDir::new().unwrap();
    let scratch = dir.path().join("cache");
    std::fs::create_dir(&scratch).unwrap();
    let phone = phone(dir.path());
    phone
        .receive_test_vault(&scratch.to_string_lossy())
        .unwrap();
    assert_eq!(status(&phone), VaultStatus::Received);
    assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 0);

    phone.set_master_password(PHONE_MASTER.into()).unwrap();
    let logins = phone.logins().unwrap();
    assert_eq!(logins.iter().filter(|login| login.in_trash).count(), 1);
    assert!(logins.iter().any(|login| login.has_otp));
    assert!(logins.iter().any(|login| login.kind == EntryKind::Host));
    let projects = phone.projects().unwrap();
    assert_eq!(
        projects
            .iter()
            .map(|project| (project.name.as_str(), project.logins.len()))
            .collect::<Vec<_>>(),
        [("Personal", 2), ("Work", 2)]
    );
}
