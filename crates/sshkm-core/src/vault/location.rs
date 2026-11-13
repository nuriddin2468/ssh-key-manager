//! Moving the vault's files, e.g. into a Dropbox or iCloud Drive folder so
//! other computers see it, and checking a KeePass file brought from
//! elsewhere before switching to it.
//!
//! A move is two steps so the caller can record the new place in between:
//! [`copy_files`] writes complete, verified copies; once the new location is
//! saved, [`remove_files`] deletes the originals. A failure or crash at any
//! point leaves a working vault where the settings point.

use std::fs;
use std::io::{self, Read};
use std::path::Path;

use sha2::{Digest, Sha256};

use super::envs::files::{CloudRoots, CloudService};
use super::{MAX_DATABASE_SIZE, Vault, VaultPaths, read_database};
use crate::{Error, Result, fsutil};

/// The first eight bytes of a KDBX file (KeePass 2 and KeePassXC).
const KDBX_SIGNATURE: [u8; 8] = [0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5];
/// The same for the old KeePass 1 format, which isn't supported.
const KDB_SIGNATURE: [u8; 8] = [0x03, 0xD9, 0xA2, 0x9A, 0x65, 0xFB, 0x4B, 0xB5];

/// The cloud service whose folder holds the vault's database, if one does
/// ([`CloudRoots::detect`]): the service then keeps the file in step on the
/// user's computers, and own devices don't sync its entries themselves.
pub fn cloud_service(paths: &VaultPaths, roots: &CloudRoots) -> Option<CloudService> {
    let folder = paths.database.parent()?;
    roots
        .service(folder)
        .or_else(|| roots.service(&fsutil::real_path(folder)))
}

/// Copies the database and, if there is one, the key slots file from `from`
/// to `to`, and checks the copies byte for byte. Refuses if either target
/// file exists or `to` is where the vault already is.
pub fn copy_files(from: &VaultPaths, to: &VaultPaths) -> Result<()> {
    if fsutil::real_path(&from.database) == fsutil::real_path(&to.database) {
        return Err(Error::invalid("the vault is already there"));
    }
    let folder = to.database.parent().unwrap_or(&to.database);
    if !folder.is_dir() {
        return Err(Error::NotFound(folder.display().to_string()));
    }
    for target in [&to.database, &to.keys] {
        if fs::symlink_metadata(target).is_ok() {
            return Err(Error::AlreadyExists(target.display().to_string()));
        }
    }
    let database = read_database(&from.database)?;
    let keys = match fs::read(&from.keys) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(Error::io(e, &from.keys)),
    };
    copy_verified(&to.database, &database)?;
    if let Some(keys) = keys
        && let Err(error) = copy_verified(&to.keys, &keys)
    {
        let _ = fs::remove_file(&to.database);
        return Err(error);
    }
    Ok(())
}

fn copy_verified(path: &Path, bytes: &[u8]) -> Result<()> {
    fsutil::write_new(path, bytes, 0o600)?;
    let written = fs::read(path).map_err(|e| Error::io(e, path))?;
    if Sha256::digest(&written) != Sha256::digest(bytes) {
        let _ = fs::remove_file(path);
        return Err(Error::Io {
            context: path.display().to_string(),
            source: io::Error::other("the copy differs from the original"),
        });
    }
    Ok(())
}

/// Deletes the vault's files at `paths`: the originals after a move.
pub fn remove_files(paths: &VaultPaths) -> Result<()> {
    for path in [&paths.database, &paths.keys] {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::io(e, path)),
        }
    }
    Ok(())
}

/// Checks that `path` is a KeePass database (KDBX 3 or 4) this app can open,
/// before switching to it. Anything but a regular file is refused before
/// it is read, without waiting on a pipe ([`fsutil::open_regular`]).
pub fn check_database(path: &Path) -> Result<()> {
    let mut file = fsutil::open_regular(path)?;
    let meta = file.metadata().map_err(|e| Error::io(e, path))?;
    if meta.len() > MAX_DATABASE_SIZE {
        return Err(Error::Parse(format!("{} is too large", path.display())));
    }
    let mut signature = [0u8; 8];
    match file.read_exact(&mut signature) {
        Ok(()) if signature == KDBX_SIGNATURE => Ok(()),
        Ok(()) if signature == KDB_SIGNATURE => Err(Error::Unsupported(
            "KeePass 1 databases (.kdb); open it in KeePassXC and save it as .kdbx".into(),
        )),
        Ok(()) => Err(Error::Parse(format!(
            "{} is not a KeePass database",
            path.display()
        ))),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Err(Error::Parse(format!(
            "{} is not a KeePass database",
            path.display()
        ))),
        Err(e) => Err(Error::io(e, path)),
    }
}

impl Vault {
    /// Points the unlocked vault at its files' new place after
    /// [`copy_files`], so later saves go there.
    pub fn relocate(&mut self, paths: VaultPaths) {
        self.paths = paths;
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;
    use crate::vault::EntryInput;

    fn s(text: &str) -> SecretString {
        SecretString::from(text.to_owned())
    }

    #[test]
    fn a_vault_in_a_cloud_folder_names_its_service() {
        let dir = tempfile::tempdir().unwrap();
        let dropbox = dir.path().join("Dropbox");
        fs::create_dir(&dropbox).unwrap();
        let roots = CloudRoots::new(vec![(dropbox.clone(), CloudService::Dropbox)]);
        let inside = VaultPaths::new(dropbox.join("vaults").join("vault.kdbx"));
        assert_eq!(cloud_service(&inside, &roots), Some(CloudService::Dropbox));
        let outside = VaultPaths::new(dir.path().join("vault.kdbx"));
        assert_eq!(cloud_service(&outside, &roots), None);
    }

    #[test]
    fn a_vault_moves_unlocked_and_keeps_saving_at_its_new_place() {
        let dir = tempfile::tempdir().unwrap();
        let from = VaultPaths::new(dir.path().join("vault.kdbx"));
        let (mut vault, _) = Vault::create(&from, &s("master")).unwrap();
        let synced = dir.path().join("Dropbox");
        fs::create_dir(&synced).unwrap();
        let to = VaultPaths::new(synced.join("vault.kdbx"));

        copy_files(&from, &to).unwrap();
        assert_eq!(
            fs::read(&from.database).unwrap(),
            fs::read(&to.database).unwrap()
        );
        assert_eq!(fs::read(&from.keys).unwrap(), fs::read(&to.keys).unwrap());
        vault.relocate(to.clone());
        remove_files(&from).unwrap();
        assert!(!from.database.exists() && !from.keys.exists());

        vault
            .add_entry(&EntryInput {
                title: "after the move".into(),
                ..EntryInput::default()
            })
            .unwrap();
        vault.save(&dir.path().join("backups")).unwrap();
        drop(vault);
        let reopened = Vault::unlock(&to, &s("master")).unwrap();
        assert_eq!(reopened.entries().len(), 1);
        assert!(!from.database.exists());
    }

    #[test]
    fn a_move_refuses_existing_files_and_the_same_place() {
        let dir = tempfile::tempdir().unwrap();
        let from = VaultPaths::new(dir.path().join("vault.kdbx"));
        Vault::create(&from, &s("master")).unwrap();
        assert!(matches!(
            copy_files(&from, &from).unwrap_err(),
            Error::InvalidInput(_)
        ));

        let other = dir.path().join("other");
        fs::create_dir(&other).unwrap();
        let to = VaultPaths::new(other.join("vault.kdbx"));
        fs::write(&to.keys, "someone else's").unwrap();
        assert!(matches!(
            copy_files(&from, &to).unwrap_err(),
            Error::AlreadyExists(_)
        ));
        assert!(!to.database.exists());
        assert_eq!(fs::read_to_string(&to.keys).unwrap(), "someone else's");

        let missing = VaultPaths::new(dir.path().join("nowhere/vault.kdbx"));
        assert!(matches!(
            copy_files(&from, &missing).unwrap_err(),
            Error::NotFound(_)
        ));
    }

    #[test]
    fn a_database_without_key_slots_moves_alone() {
        let dir = tempfile::tempdir().unwrap();
        let from = VaultPaths::new(dir.path().join("vault.kdbx"));
        Vault::create(&from, &s("master")).unwrap();
        fs::remove_file(&from.keys).unwrap();
        let to = VaultPaths::new(dir.path().join("Passwords.kdbx"));
        copy_files(&from, &to).unwrap();
        assert!(to.database.is_file() && !to.keys.exists());
    }

    #[test]
    fn only_kdbx_files_are_accepted_as_databases() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("vault.kdbx"));
        Vault::create(&paths, &s("master")).unwrap();
        check_database(&paths.database).unwrap();

        let csv = dir.path().join("passwords.csv");
        fs::write(&csv, "name,url,username,password\n").unwrap();
        assert!(matches!(check_database(&csv).unwrap_err(), Error::Parse(_)));
        assert!(matches!(
            check_database(&paths.keys).unwrap_err(),
            Error::Parse(_)
        ));
        let kdb = dir.path().join("old.kdb");
        let mut bytes = KDB_SIGNATURE.to_vec();
        bytes.extend([0; 32]);
        fs::write(&kdb, bytes).unwrap();
        assert!(matches!(
            check_database(&kdb).unwrap_err(),
            Error::Unsupported(_)
        ));
        let short = dir.path().join("short.kdbx");
        fs::write(&short, [0x03, 0xD9]).unwrap();
        assert!(matches!(
            check_database(&short).unwrap_err(),
            Error::Parse(_)
        ));
        assert!(matches!(
            check_database(&dir.path().join("missing.kdbx")).unwrap_err(),
            Error::NotFound(_)
        ));
        assert!(matches!(
            check_database(dir.path()).unwrap_err(),
            Error::InvalidInput(_)
        ));
    }

    /// A pipe is refused at once, not waited on until something writes.
    #[cfg(unix)]
    #[test]
    fn a_pipe_is_refused_without_waiting() {
        let dir = tempfile::tempdir().unwrap();
        let pipe = dir.path().join("vault.kdbx");
        let made = std::process::Command::new("mkfifo")
            .arg(&pipe)
            .status()
            .unwrap();
        assert!(made.success());
        let (done, finished) = std::sync::mpsc::channel();
        let path = pipe.clone();
        std::thread::spawn(move || {
            let _ = done.send(check_database(&path).map_err(|e| e.code()));
        });
        let result = finished.recv_timeout(std::time::Duration::from_secs(5));
        if result.is_err() {
            // Lets the stuck thread go.
            use std::os::unix::fs::OpenOptionsExt;
            let _ = fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&pipe);
        }
        assert_eq!(result, Ok(Err(crate::ErrorCode::InvalidInput)));
    }
}
