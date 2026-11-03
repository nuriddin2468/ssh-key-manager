//! Exporting the vault: as a CSV file in the format KeePassXC writes (plain
//! text, for moving to another password manager), or as a copy of the
//! KeePass database (encrypted; it opens with the recovery key).
//!
//! Neither ever replaces the vault's own files or goes into `~/.ssh`, whose
//! files `ssh` and other tools read without asking.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use keepass::db::fields;
use secrecy::SecretString;
use zeroize::Zeroizing;

use super::{Vault, VaultPaths, read_database};
use crate::{Error, Result, fsutil};

/// The columns of a KeePassXC CSV export, in its order.
const HEADER: [&str; 10] = [
    "Group",
    "Title",
    "Username",
    "Password",
    "URL",
    "Notes",
    "TOTP",
    "Icon",
    "Last Modified",
    "Created",
];

impl Vault {
    /// Writes every entry outside the recycle bin to `target` as a
    /// KeePassXC-style CSV file (mode 0600), after checking the master
    /// password. Returns how many entries were written.
    ///
    /// The file holds every password in plain text. It never replaces the
    /// vault's files and is never written inside `ssh_dir`.
    pub fn export_csv(
        &self,
        master: &SecretString,
        target: &Path,
        ssh_dir: &Path,
    ) -> Result<usize> {
        self.verify_master_password(master)?;
        let target = checked_target(target, &self.paths, ssh_dir)?;
        let (bytes, count) = self.csv()?;
        write_private(&target, &bytes)?;
        Ok(count)
    }

    fn csv(&self) -> Result<(Zeroizing<Vec<u8>>, usize)> {
        let root = self.db.root().name.clone();
        let root = if root.trim().is_empty() {
            "Root".to_owned()
        } else {
            root
        };
        let mut writer = csv::WriterBuilder::new()
            .quote_style(csv::QuoteStyle::Always)
            .from_writer(Vec::new());
        writer.write_record(HEADER).map_err(|e| csv_error(&e))?;
        let mut count = 0;
        for summary in self.entries().into_iter().filter(|e| !e.in_trash) {
            let entry = self.find(&summary.id)?;
            let group = summary
                .group
                .as_ref()
                .map_or_else(|| root.clone(), |g| format!("{root}/{g}"));
            let field = |name: &str| entry.get(name).unwrap_or_default();
            let row = [
                group.as_str(),
                &summary.title,
                &summary.username,
                field(fields::PASSWORD),
                &summary.url,
                field(fields::NOTES),
                field(fields::OTP),
                "0",
                summary.modified.as_deref().unwrap_or_default(),
                summary.created.as_deref().unwrap_or_default(),
            ];
            writer.write_record(row).map_err(|e| csv_error(&e))?;
            count += 1;
        }
        let bytes = writer
            .into_inner()
            .map_err(|e| Error::Parse(format!("writing the CSV file: {e}")))?;
        Ok((Zeroizing::new(bytes), count))
    }
}

/// Copies the vault's database to `target` (mode 0600). The copy is as
/// encrypted as the original: it opens with the recovery key, or with the
/// password of a KeePass file brought from elsewhere. Works locked, too.
/// Like the CSV export, it never replaces the vault's files and is never
/// written inside `ssh_dir`.
pub fn export_kdbx(paths: &VaultPaths, target: &Path, ssh_dir: &Path) -> Result<()> {
    let target = checked_target(target, paths, ssh_dir)?;
    let bytes = read_database(&paths.database)?;
    write_private(&target, &bytes)
}

/// `target` with symbolic links resolved, refused if it is one of the
/// vault's own files, a folder, or inside `ssh_dir`.
fn checked_target(target: &Path, paths: &VaultPaths, ssh_dir: &Path) -> Result<PathBuf> {
    if !target.is_absolute() || target.file_name().is_none() {
        return Err(Error::invalid(format!(
            "not a file path: {}",
            target.display()
        )));
    }
    let parent = target.parent().unwrap_or(target);
    if !parent.is_dir() {
        return Err(Error::NotFound(parent.display().to_string()));
    }
    let real = resolve(target);
    if real.is_dir() {
        return Err(Error::invalid(format!("{} is a folder", target.display())));
    }
    if [&paths.database, &paths.keys]
        .into_iter()
        .any(|own| resolve(own) == real)
    {
        return Err(Error::invalid(
            "an export never replaces the vault's own files",
        ));
    }
    if real.starts_with(resolve(ssh_dir)) {
        return Err(Error::invalid(
            "an export is never written into the SSH folder",
        ));
    }
    Ok(real)
}

/// The path with symbolic links resolved, for a file that may not exist yet:
/// the file itself if it exists, else its folder.
pub(super) fn resolve(path: &Path) -> PathBuf {
    if let Ok(real) = fs::canonicalize(path) {
        return real;
    }
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => {
            fs::canonicalize(parent).map_or_else(|_| path.to_path_buf(), |dir| dir.join(name))
        }
        _ => path.to_path_buf(),
    }
}

/// Writes atomically with mode 0600, also when replacing an existing file
/// (whose mode is tightened first, as the write keeps it).
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => fsutil::set_mode(path, 0o600)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::io(e, path)),
    }
    fsutil::atomic_write(path, bytes, 0o600)
}

fn csv_error(error: &csv::Error) -> Error {
    Error::Parse(format!("writing the CSV file: {error}"))
}
