use std::path::PathBuf;

use secrecy::{ExposeSecret, SecretString};
use tempfile::TempDir;

use super::*;

struct Fixture {
    dir: TempDir,
    paths: VaultPaths,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("vault.kdbx"));
        Self { dir, paths }
    }

    fn backups(&self) -> PathBuf {
        self.dir.path().join("backups")
    }
}

fn s(text: &str) -> SecretString {
    SecretString::from(text.to_owned())
}

fn login(title: &str, password: &str) -> EntryInput {
    EntryInput {
        title: title.into(),
        username: "me@example.com".into(),
        password: Some(s(password)),
        url: "https://example.com".into(),
        ..EntryInput::default()
    }
}

#[test]
fn create_writes_two_files_and_unlocks_with_the_master_password() {
    let fx = Fixture::new();
    let (vault, recovery) = Vault::create(&fx.paths, &s("master")).unwrap();
    assert_eq!(recovery.expose_secret().len(), 64);
    assert!(fx.paths.database.is_file() && fx.paths.keys.is_file());
    assert_eq!(fx.paths.keys.file_name().unwrap(), "vault.keys");
    drop(vault);

    let files = probe(&fx.paths).unwrap();
    assert!(files.exists && files.has_master_password && !files.has_device_unlock);
    assert!(Vault::unlock(&fx.paths, &s("master")).is_ok());
    let wrong = Vault::unlock(&fx.paths, &s("Master")).unwrap_err();
    assert!(matches!(wrong, Error::WrongPassphrase));
}

#[test]
fn create_refuses_to_overwrite_and_needs_a_password() {
    let fx = Fixture::new();
    Vault::create(&fx.paths, &s("master")).unwrap();
    assert!(matches!(
        Vault::create(&fx.paths, &s("master")),
        Err(Error::AlreadyExists(_))
    ));
    let other = Fixture::new();
    assert!(matches!(
        Vault::create(&other.paths, &s("")),
        Err(Error::InvalidInput(_))
    ));
}

#[test]
fn probe_reports_a_missing_vault() {
    let fx = Fixture::new();
    let files = probe(&fx.paths).unwrap();
    assert!(!files.exists && !files.has_master_password && files.vault_id.is_none());
}

#[test]
fn the_database_is_a_keepass_file_opened_by_the_recovery_key() {
    let fx = Fixture::new();
    let (mut vault, recovery) = Vault::create(&fx.paths, &s("master")).unwrap();
    vault.add_entry(&login("GitHub", "hunter2")).unwrap();
    vault.save(&fx.backups()).unwrap();

    // What KeePassXC does with the key typed exactly as printed.
    let bytes = std::fs::read(&fx.paths.database).unwrap();
    let db = Database::parse(&bytes, key(&recovery)).unwrap();
    assert!(matches!(db.config.version, DatabaseVersion::KDB4(1)));
    let entry = db.iter_all_entries().next().unwrap();
    assert_eq!(entry.get_title(), Some("GitHub"));
    assert_eq!(entry.get_password(), Some("hunter2"));
    assert!(!String::from_utf8_lossy(&bytes).contains("hunter2"));
}

#[test]
fn recover_accepts_a_sloppily_typed_key_and_sets_a_new_master_password() {
    let fx = Fixture::new();
    let (_, recovery) = Vault::create(&fx.paths, &s("forgotten")).unwrap();
    let typed = recovery.expose_secret().replace('-', " ").to_lowercase();
    assert!(matches!(
        Vault::recover(&fx.paths, &s("not the key"), &s("new")),
        Err(Error::WrongPassphrase)
    ));
    Vault::recover(&fx.paths, &s(&typed), &s("new")).unwrap();
    assert!(Vault::unlock(&fx.paths, &s("new")).is_ok());
    assert!(Vault::unlock(&fx.paths, &s("forgotten")).is_err());
}

#[test]
fn recover_opens_a_keepass_file_brought_from_elsewhere() {
    let fx = Fixture::new();
    let mut db = Database::new();
    db.root_mut()
        .add_entry()
        .set_unprotected(fields::TITLE, "From KeePassXC");
    let mut bytes = Vec::new();
    db.save(&mut bytes, key(&s("my keepass password"))).unwrap();
    std::fs::write(&fx.paths.database, bytes).unwrap();

    let files = probe(&fx.paths).unwrap();
    assert!(files.exists && !files.has_master_password);
    let vault = Vault::recover(&fx.paths, &s("my keepass password"), &s("master")).unwrap();
    assert_eq!(vault.entries()[0].title, "From KeePassXC");
    drop(vault);
    assert!(Vault::unlock(&fx.paths, &s("master")).is_ok());
}

#[test]
fn a_keys_file_from_another_vault_is_reported() {
    let a = Fixture::new();
    let b = Fixture::new();
    Vault::create(&a.paths, &s("master")).unwrap();
    Vault::create(&b.paths, &s("master")).unwrap();
    std::fs::copy(&b.paths.keys, &a.paths.keys).unwrap();
    assert!(matches!(
        Vault::unlock(&a.paths, &s("master")),
        Err(Error::Parse(_))
    ));
}

#[test]
fn entries_round_trip_without_exposing_secrets() {
    let fx = Fixture::new();
    let (mut vault, _) = Vault::create(&fx.paths, &s("master")).unwrap();
    let id = vault.add_entry(&login("GitHub", "hunter2")).unwrap();
    vault
        .add_entry(&EntryInput {
            title: "prod".into(),
            username: "root".into(),
            password: Some(s("sesame")),
            kind: EntryKind::Host,
            host: Some("prod".into()),
            ..EntryInput::default()
        })
        .unwrap();
    vault.save(&fx.backups()).unwrap();
    drop(vault);

    let vault = Vault::unlock(&fx.paths, &s("master")).unwrap();
    let entries = vault.entries();
    assert_eq!(
        entries.iter().map(|e| e.title.as_str()).collect::<Vec<_>>(),
        ["GitHub", "prod"]
    );
    let github = &entries[0];
    assert_eq!(github.id, id);
    assert_eq!(github.kind, EntryKind::Login);
    assert!(github.has_password && !github.has_otp && !github.in_trash);
    assert_eq!(entries[1].kind, EntryKind::Host);
    assert_eq!(entries[1].host.as_deref(), Some("prod"));

    let json = serde_json::to_string(&vault.entry(&id).unwrap()).unwrap();
    assert!(!json.contains("hunter2"));
    assert!(json.contains("\"title\":\"GitHub\""));
    let password = vault.secret(&id, SecretField::Password).unwrap();
    assert_eq!(password.expose_secret(), "hunter2");
}

#[test]
fn updates_keep_history_and_leave_omitted_secrets_alone() {
    let fx = Fixture::new();
    let (mut vault, _) = Vault::create(&fx.paths, &s("master")).unwrap();
    let id = vault.add_entry(&login("GitHub", "first")).unwrap();

    let mut rename = login("GitHub (work)", "ignored");
    rename.password = None;
    vault.update_entry(&id, &rename).unwrap();
    assert_eq!(
        vault
            .secret(&id, SecretField::Password)
            .unwrap()
            .expose_secret(),
        "first"
    );
    assert_eq!(vault.entry(&id).unwrap().history_len, 1);

    // Saving the same values again is not a new version.
    vault.update_entry(&id, &rename).unwrap();
    assert_eq!(vault.entry(&id).unwrap().history_len, 1);

    vault
        .update_entry(&id, &login("GitHub (work)", "second"))
        .unwrap();
    let detail = vault.entry(&id).unwrap();
    assert_eq!(detail.history_len, 2);
    assert_eq!(detail.summary.title, "GitHub (work)");
    assert!(detail.password_changed.is_some());
    assert_eq!(
        vault
            .secret(&id, SecretField::Password)
            .unwrap()
            .expose_secret(),
        "second"
    );
}

#[test]
fn links_are_validated_and_cleared_when_the_kind_changes() {
    let fx = Fixture::new();
    let (mut vault, _) = Vault::create(&fx.paths, &s("master")).unwrap();
    let missing = EntryInput {
        title: "k".into(),
        kind: EntryKind::Key,
        ..EntryInput::default()
    };
    assert!(matches!(
        vault.add_entry(&missing),
        Err(Error::InvalidInput(_))
    ));
    let id = vault
        .add_entry(&EntryInput {
            key_fingerprint: Some("SHA256:abc".into()),
            ..missing
        })
        .unwrap();
    assert_eq!(
        vault.entries()[0].key_fingerprint.as_deref(),
        Some("SHA256:abc")
    );
    vault.update_entry(&id, &login("k", "x")).unwrap();
    let entry = &vault.entries()[0];
    assert_eq!(entry.kind, EntryKind::Login);
    assert!(entry.key_fingerprint.is_none());
    assert!(matches!(
        vault.add_entry(&EntryInput::default()),
        Err(Error::InvalidInput(_))
    ));
}

#[test]
fn otp_secrets_become_uris_and_produce_codes() {
    let fx = Fixture::new();
    let (mut vault, _) = Vault::create(&fx.paths, &s("master")).unwrap();
    let mut input = login("GitHub", "x");
    input.otp = Some(s("JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP"));
    let id = vault.add_entry(&input).unwrap();
    assert!(vault.entries()[0].has_otp);
    let uri = vault.secret(&id, SecretField::Otp).unwrap();
    assert!(
        uri.expose_secret()
            .starts_with("otpauth://totp/GitHub?secret=JBSWY3DP")
    );
    let (code, valid_for) = vault.otp_code(&id).unwrap();
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
    assert!((1..=30).contains(&valid_for));

    input.otp = Some(s("not base32!"));
    assert!(matches!(
        vault.add_entry(&input),
        Err(Error::InvalidInput(_))
    ));
    input.otp = Some(s(""));
    input.password = None;
    vault.update_entry(&id, &input).unwrap();
    assert!(!vault.entries()[0].has_otp);
}

/// 2FA secrets the KeePass crate parses but can't make a code for without
/// panicking (a period of 0, 64 digits), or makes wrong codes for.
const BAD_OTP_URIS: [&str; 10] = [
    "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0",
    "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=64",
    "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=4294967295",
    "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=20",
    "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=5",
    "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=86400",
    "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
    "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1",
    "otpauth://totp/x?secret=&period=30",
    "otpauth://totp/x?period=30",
];

#[test]
fn otp_uris_no_code_can_be_made_for_are_refused() {
    let fx = Fixture::new();
    let (mut vault, _) = Vault::create(&fx.paths, &s("master")).unwrap();
    for bad in BAD_OTP_URIS {
        let mut input = login("GitHub", "x");
        input.otp = Some(s(bad));
        assert!(
            matches!(vault.add_entry(&input), Err(Error::InvalidInput(_))),
            "{bad}"
        );
        // An import keeps it as an unreadable secret instead.
        assert!(otp_uri(bad, "GitHub").is_err(), "{bad}");
    }
    assert_eq!(vault.entries(), Vec::<EntrySummary>::new());

    let mut input = login("Bank", "x");
    input.otp = Some(s(
        "otpauth://TOTP/Bank?secret=JBSWY3DPEHPK3PXP&period=60&digits=8&algorithm=SHA256",
    ));
    let id = vault.add_entry(&input).unwrap();
    let (code, valid_for) = vault.otp_code(&id).unwrap();
    assert_eq!(code.len(), 8);
    assert!((1..=60).contains(&valid_for));
}

#[test]
fn a_bad_otp_secret_in_a_keepass_file_is_an_error_not_a_crash() {
    let fx = Fixture::new();
    let mut db = Database::new();
    let mut root = db.root_mut();
    for bad in BAD_OTP_URIS {
        let mut entry = root.add_entry();
        entry.set_unprotected(fields::TITLE, bad);
        entry.set_protected(fields::OTP, bad);
    }
    let mut bytes = Vec::new();
    db.save(&mut bytes, key(&s("keepass"))).unwrap();
    std::fs::write(&fx.paths.database, bytes).unwrap();

    let vault = Vault::recover(&fx.paths, &s("keepass"), &s("master")).unwrap();
    let entries = vault.entries();
    assert_eq!(entries.len(), BAD_OTP_URIS.len());
    for entry in entries {
        assert!(
            matches!(vault.otp_code(&entry.id), Err(Error::Parse(_))),
            "{}",
            entry.title
        );
    }
}

#[test]
fn trash_restore_and_delete() {
    let fx = Fixture::new();
    let (mut vault, recovery) = Vault::create(&fx.paths, &s("master")).unwrap();
    let id = vault.add_entry(&login("Old", "x")).unwrap();
    let keep = vault.add_entry(&login("Keep", "y")).unwrap();

    assert!(matches!(
        vault.delete_entry(&id),
        Err(Error::InvalidInput(_))
    ));
    vault.trash_entry(&id).unwrap();
    let old = vault.entries().into_iter().find(|e| e.id == id).unwrap();
    assert!(old.in_trash);
    assert_eq!(old.group.as_deref(), Some("Recycle Bin"));

    vault.restore_entry(&id).unwrap();
    let old = vault.entries().into_iter().find(|e| e.id == id).unwrap();
    assert!(!old.in_trash && old.group.is_none());

    vault.trash_entry(&id).unwrap();
    assert_eq!(vault.empty_trash().unwrap(), 1);
    assert_eq!(vault.entries().len(), 1);
    assert_eq!(vault.entries()[0].id, keep);
    vault.save(&fx.backups()).unwrap();

    // KeePassXC sees the same recycle bin.
    let bytes = std::fs::read(&fx.paths.database).unwrap();
    let db = Database::parse(&bytes, key(&recovery)).unwrap();
    assert_eq!(db.recycle_bin().unwrap().name, "Recycle Bin");
    assert!(
        db.deleted_objects
            .contains_key(&uuid::Uuid::parse_str(&id).unwrap())
    );
}

#[test]
fn saves_keep_backups() {
    let fx = Fixture::new();
    let (mut vault, _) = Vault::create(&fx.paths, &s("master")).unwrap();
    vault.add_entry(&login("A", "x")).unwrap();
    vault.save(&fx.backups()).unwrap();
    vault.add_entry(&login("B", "y")).unwrap();
    vault.save(&fx.backups()).unwrap();
    assert_eq!(fsutil::list_backups(&fx.backups(), "vault.kdbx").len(), 2);
}

#[test]
fn changes_from_another_computer_are_picked_up() {
    let fx = Fixture::new();
    let (mut here, _) = Vault::create(&fx.paths, &s("master")).unwrap();
    assert!(!here.refresh().unwrap());

    let mut there = Vault::unlock(&fx.paths, &s("master")).unwrap();
    there.add_entry(&login("Added there", "x")).unwrap();
    there.save(&fx.backups()).unwrap();

    assert!(here.refresh().unwrap());
    assert_eq!(here.entries()[0].title, "Added there");
    here.add_entry(&login("Added here", "y")).unwrap();
    here.save(&fx.backups()).unwrap();
    assert!(there.refresh().unwrap());
    assert_eq!(there.entries().len(), 2);
}

#[test]
fn a_write_over_someone_elses_change_is_a_conflict() {
    let fx = Fixture::new();
    let (mut here, _) = Vault::create(&fx.paths, &s("master")).unwrap();
    let mut there = Vault::unlock(&fx.paths, &s("master")).unwrap();
    there.add_entry(&login("There", "x")).unwrap();
    there.save(&fx.backups()).unwrap();

    here.add_entry(&login("Here", "y")).unwrap();
    let Err(Error::Conflict(copy)) = here.save(&fx.backups()) else {
        panic!("expected a conflict");
    };
    let copy = PathBuf::from(copy);
    assert_eq!(copy.extension().unwrap(), "kdbx");
    assert!(copy.to_string_lossy().contains("vault-conflict-"));
    assert!(copy.is_file());
    // The other computer's version is untouched.
    let fresh = Vault::unlock(&fx.paths, &s("master")).unwrap();
    assert_eq!(fresh.entries()[0].title, "There");
}

#[test]
fn a_write_over_newer_key_slots_is_a_conflict() {
    let fx = Fixture::new();
    let (mut here, _) = Vault::create(&fx.paths, &s("old")).unwrap();
    let mut there = Vault::unlock(&fx.paths, &s("old")).unwrap();

    // Another computer changes the master password and turns on device unlock.
    there.change_master_password(&s("old"), &s("new")).unwrap();
    let laptop = there.enable_device_unlock().unwrap();

    // This copy still has the old slots: writing them would bring the old
    // password back and drop the other computer's slot.
    let Err(error) = here.enable_device_unlock() else {
        panic!("expected a conflict");
    };
    assert!(matches!(error, Error::Conflict(_)));
    assert!(matches!(
        Vault::unlock(&fx.paths, &s("old")),
        Err(Error::WrongPassphrase)
    ));
    // The conflict loaded the newer slots, so trying again keeps both.
    let desktop = here.enable_device_unlock().unwrap();
    let files = probe(&fx.paths).unwrap();
    assert_eq!(files.device_slots, [laptop.slot_id, desktop.slot_id]);
    assert!(Vault::unlock(&fx.paths, &s("new")).is_ok());
}

#[test]
fn a_refresh_picks_up_key_slots_changed_elsewhere() {
    let fx = Fixture::new();
    let (mut here, _) = Vault::create(&fx.paths, &s("old")).unwrap();
    let mut there = Vault::unlock(&fx.paths, &s("old")).unwrap();
    there.change_master_password(&s("old"), &s("new")).unwrap();

    assert!(here.refresh().unwrap());
    assert!(here.verify_master_password(&s("new")).is_ok());
    here.disable_device_unlock("not-there").unwrap();
    here.change_master_password(&s("new"), &s("newer")).unwrap();
    assert!(Vault::unlock(&fx.paths, &s("newer")).is_ok());
}

#[test]
fn a_new_recovery_key_re_encrypts_backups_and_conflict_copies() {
    let fx = Fixture::new();
    let (mut vault, old_key) = Vault::create(&fx.paths, &s("master")).unwrap();
    for title in ["A", "B", "C"] {
        vault.add_entry(&login(title, "x")).unwrap();
        vault.save(&fx.backups()).unwrap();
    }
    // A conflict copy, made under the old key.
    let mut other = Vault::unlock(&fx.paths, &s("master")).unwrap();
    other.add_entry(&login("D", "y")).unwrap();
    other.save(&fx.backups()).unwrap();
    vault.add_entry(&login("E", "z")).unwrap();
    let Err(Error::Conflict(copy)) = vault.save(&fx.backups()) else {
        panic!("expected a conflict");
    };
    vault.refresh().unwrap();
    // A backup of another vault with the same file name stays as it is.
    let stranger = fx.backups().join("vault.kdbx.20000101T000000.000Z.bak");
    let mut db = Database::new();
    db.root_mut()
        .add_entry()
        .set_unprotected(fields::TITLE, "x");
    let mut bytes = Vec::new();
    db.save(&mut bytes, key(&s("someone else"))).unwrap();
    std::fs::write(&stranger, &bytes).unwrap();

    let new_key = vault.new_recovery_key(&s("master"), &fx.backups()).unwrap();
    let mut copies = fsutil::list_backups(&fx.backups(), "vault.kdbx");
    copies.retain(|path| path != &stranger);
    copies.push(PathBuf::from(copy));
    assert!(copies.len() >= 4);
    for copy in copies {
        let bytes = std::fs::read(&copy).unwrap();
        assert!(Database::parse(&bytes, key(&old_key)).is_err(), "{copy:?}");
        assert!(Database::parse(&bytes, key(&new_key)).is_ok(), "{copy:?}");
    }
    assert_eq!(std::fs::read(&stranger).unwrap(), bytes);
}

#[test]
fn a_database_asking_for_too_much_memory_is_refused_before_deriving() {
    let fx = Fixture::new();
    let (vault, recovery) = Vault::create(&fx.paths, &s("master")).unwrap();
    drop(vault);
    let mut bytes = std::fs::read(&fx.paths.database).unwrap();
    // The Argon2 memory, in bytes, in the header's KDF parameters.
    let at = bytes
        .windows(6)
        .position(|w| w == [0x05, 1, 0, 0, 0, b'M'])
        .unwrap();
    bytes[at + 10..at + 18].copy_from_slice(&(4u64 << 40).to_le_bytes());
    std::fs::write(&fx.paths.database, &bytes).unwrap();
    assert!(matches!(
        Vault::unlock(&fx.paths, &s("master")),
        Err(Error::Unsupported(_))
    ));
    assert!(matches!(
        Vault::recover(&fx.paths, &recovery, &s("master")),
        Err(Error::Unsupported(_))
    ));
}

#[test]
fn master_password_and_recovery_key_can_be_replaced() {
    let fx = Fixture::new();
    let (mut vault, old_key) = Vault::create(&fx.paths, &s("one")).unwrap();
    vault.add_entry(&login("A", "x")).unwrap();
    vault.save(&fx.backups()).unwrap();

    assert!(matches!(
        vault.change_master_password(&s("wrong"), &s("two")),
        Err(Error::WrongPassphrase)
    ));
    vault.change_master_password(&s("one"), &s("two")).unwrap();

    vault.enable_device_unlock().unwrap();
    vault.enable_device_unlock().unwrap();
    let new_key = vault.new_recovery_key(&s("two"), &fx.backups()).unwrap();
    assert_ne!(new_key.expose_secret(), old_key.expose_secret());
    assert_eq!(vault.device_slots(), Vec::<String>::new());
    drop(vault);

    let vault = Vault::unlock(&fx.paths, &s("two")).unwrap();
    assert_eq!(vault.entries().len(), 1);
    let bytes = std::fs::read(&fx.paths.database).unwrap();
    assert!(Database::parse(&bytes, key(&new_key)).is_ok());
    assert!(Database::parse(&bytes, key(&old_key)).is_err());
}

#[test]
fn device_unlock_works_per_computer() {
    let fx = Fixture::new();
    let (mut vault, _) = Vault::create(&fx.paths, &s("master")).unwrap();
    let laptop = vault.enable_device_unlock().unwrap();
    let desktop = vault.enable_device_unlock().unwrap();
    let id = vault.vault_id().to_owned();
    drop(vault);

    let files = probe(&fx.paths).unwrap();
    assert!(files.has_device_unlock);
    assert_eq!(
        files.device_slots,
        [laptop.slot_id.clone(), desktop.slot_id.clone()]
    );
    assert_eq!(files.vault_id.as_deref(), Some(id.as_str()));
    assert!(Vault::unlock_with_device(&fx.paths, &laptop.slot_id, &laptop.key).is_ok());
    assert!(Vault::unlock_with_device(&fx.paths, &desktop.slot_id, &desktop.key).is_ok());
    assert!(matches!(
        Vault::unlock_with_device(&fx.paths, &laptop.slot_id, &[0; 32]),
        Err(Error::WrongPassphrase)
    ));

    let mut vault = Vault::unlock(&fx.paths, &s("master")).unwrap();
    vault.disable_device_unlock(&laptop.slot_id).unwrap();
    assert!(Vault::unlock_with_device(&fx.paths, &laptop.slot_id, &laptop.key).is_err());
    assert!(Vault::unlock_with_device(&fx.paths, &desktop.slot_id, &desktop.key).is_ok());
}

#[test]
fn folders_of_keepass_files_show_as_groups() {
    let fx = Fixture::new();
    let mut db = Database::new();
    let mut root = db.root_mut();
    let mut work = root.add_group();
    work.name = "Work".into();
    let mut servers = work.add_group();
    servers.name = "Servers".into();
    servers.add_entry().set_unprotected(fields::TITLE, "db1");
    let mut bytes = Vec::new();
    db.save(&mut bytes, key(&s("pw"))).unwrap();
    std::fs::write(&fx.paths.database, bytes).unwrap();

    let vault = Vault::recover(&fx.paths, &s("pw"), &s("master")).unwrap();
    assert_eq!(vault.entries()[0].group.as_deref(), Some("Work/Servers"));
}

#[test]
fn wrong_master_passwords_in_a_row_make_the_next_attempt_wait() {
    let fx = Fixture::new();
    let (vault, _) = Vault::create(&fx.paths, &s("master")).unwrap();
    for _ in 0..3 {
        assert!(matches!(
            Vault::unlock(&fx.paths, &s("guess")),
            Err(Error::WrongPassphrase)
        ));
    }
    // Right or wrong, nothing is tried until the wait is over, whichever
    // check asks.
    for attempt in [
        Vault::unlock(&fx.paths, &s("master")).map(drop),
        Vault::unlock(&fx.paths, &s("guess")).map(drop),
        vault.verify_master_password(&s("master")),
        Vault::recover(&fx.paths, &s("not the key"), &s("new")).map(drop),
    ] {
        assert!(
            matches!(attempt, Err(Error::TooManyAttempts { .. })),
            "{attempt:?}"
        );
    }
}

/// A KDBX 3 header with `fields` (id, value), then `payload`.
fn kdbx3(fields: &[(u8, &[u8])], payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5, 1, 0, 3, 0];
    for (id, value) in fields {
        bytes.push(*id);
        bytes.extend(u16::try_from(value.len()).unwrap().to_le_bytes());
        bytes.extend(*value);
    }
    bytes.extend([0, 4, 0, 0x0D, 0x0A, 0x0D, 0x0A]);
    bytes.extend(payload);
    bytes
}

/// A whole KDBX 3 file (AES, one AES-KDF round) that no key this test
/// uses opens. KDBX 3 has no check of the key before the contents.
fn kdbx3_file() -> Vec<u8> {
    const AES: [u8; 16] = [
        0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50, 0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A,
        0xFF,
    ];
    kdbx3(
        &[
            (2, &AES),
            (3, &0u32.to_le_bytes()),
            (4, &[1; 32]),
            (5, &[2; 32]),
            (6, &1u64.to_le_bytes()),
            (7, &[3; 16]),
            (8, &[4; 32]),
            (9, &[5; 32]),
            (10, &2u32.to_le_bytes()),
        ],
        &[0x55; 64],
    )
}

#[test]
fn the_wrong_key_for_a_kdbx3_file_is_a_wrong_password() {
    assert!(matches!(
        check_shared(&kdbx3_file(), &s("anything")),
        Err(Error::WrongPassphrase)
    ));
    // A vault replaced by such a file locks rather than reading it again
    // and again.
    let fx = Fixture::new();
    let (mut vault, _) = Vault::create(&fx.paths, &s("master")).unwrap();
    std::fs::write(&fx.paths.database, kdbx3_file()).unwrap();
    assert!(matches!(vault.refresh(), Err(Error::WrongPassphrase)));
}

#[test]
fn a_damaged_header_is_refused_without_stopping_the_app() {
    let fx = Fixture::new();
    Vault::create(&fx.paths, &s("master")).unwrap();
    let saved = std::fs::read(&fx.paths.database).unwrap();
    let dictionary = |kind: u8| {
        // Version 1.0, one number named `x` with no bytes, the end.
        let dict = [0x00, 0x01, kind, 1, 0, 0, 0, b'x', 0, 0, 0, 0, 0x00];
        let mut field = u32::try_from(dict.len()).unwrap().to_le_bytes().to_vec();
        field.extend(dict);
        field
    };
    for field in [
        [vec![3], vec![0, 0, 0, 0]].concat(),
        [vec![12], dictionary(0x0C)].concat(),
        [vec![11], dictionary(0x0D)].concat(),
    ] {
        let mut bytes = saved.clone();
        bytes.splice(12..12, field);
        std::fs::write(&fx.paths.database, bytes).unwrap();
        assert!(matches!(
            Vault::unlock(&fx.paths, &s("master")),
            Err(Error::Parse(_))
        ));
    }
    let short = kdbx3(&[(3, &[])], &[]);
    assert!(matches!(
        check_shared(&short, &s("anything")),
        Err(Error::Parse(_))
    ));
}

#[test]
fn a_keepass_1_file_is_refused_before_its_key_is_derived() {
    let mut kdb = vec![0x03, 0xD9, 0xA2, 0x9A, 0x65, 0xFB, 0x4B, 0xB5];
    kdb.extend(2u32.to_le_bytes());
    kdb.extend(0x0003_0002u32.to_le_bytes());
    kdb.extend([7; 32]);
    kdb.extend([0; 40]);
    kdb.extend([9; 32]);
    // About a minute of key derivation.
    kdb.extend(u32::MAX.to_le_bytes());
    kdb.extend([0; 16]);
    assert!(matches!(
        check_shared(&kdb, &s("anything")),
        Err(Error::Unsupported(_))
    ));
    let fx = Fixture::new();
    let (mut vault, _) = Vault::create(&fx.paths, &s("master")).unwrap();
    std::fs::write(&fx.paths.database, &kdb).unwrap();
    assert!(matches!(vault.refresh(), Err(Error::Unsupported(_))));
}

#[test]
fn a_database_that_does_not_open_is_not_decrypted_again_until_it_changes() {
    let fx = Fixture::new();
    let (mut vault, _) = Vault::create(&fx.paths, &s("master")).unwrap();
    vault.add_entry(&login("GitHub", "hunter2")).unwrap();
    vault.save(&fx.backups()).unwrap();
    let saved = std::fs::read(&fx.paths.database).unwrap();
    // The header, and with it the check of the key, intact and the contents
    // cut short: a sync client's half-written file.
    std::fs::write(&fx.paths.database, &saved[..saved.len() - 40]).unwrap();
    let Err(Error::Parse(first)) = vault.refresh() else {
        panic!("a cut file opened");
    };
    let Err(Error::Parse(again)) = vault.refresh() else {
        panic!("a cut file opened");
    };
    assert_ne!(first, again);
    assert!(again.contains("once it changes"), "{again}");
    // Once the file is whole again, it is read.
    std::fs::write(&fx.paths.database, &saved).unwrap();
    assert!(!vault.refresh().unwrap());
    assert_eq!(vault.entries()[0].title, "GitHub");
}

#[test]
fn a_damaged_key_slots_file_still_lets_the_recovery_key_in() {
    let too_large = vec![b' '; 70 * 1024];
    let damaged: [&[u8]; 3] = [
        b"{ not json",
        br#"{"format":"sshkm-vault-keys","version":2,"vaultId":"x","slots":[]}"#,
        &too_large,
    ];
    for keys in damaged {
        let fx = Fixture::new();
        let (vault, recovery) = Vault::create(&fx.paths, &s("master")).unwrap();
        drop(vault);
        std::fs::write(&fx.paths.keys, keys).unwrap();

        // The lock screen offers the recovery key rather than failing.
        let files = probe(&fx.paths).unwrap();
        assert!(files.exists && !files.has_master_password && files.vault_id.is_none());
        let vault = Vault::recover(&fx.paths, &recovery, &s("new master")).unwrap();
        drop(vault);
        assert!(probe(&fx.paths).unwrap().has_master_password);
        assert!(Vault::unlock(&fx.paths, &s("new master")).is_ok());
    }
}
