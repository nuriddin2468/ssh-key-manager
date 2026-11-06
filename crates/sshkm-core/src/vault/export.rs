//! Exporting the vault: as a CSV file in the format KeePassXC writes (plain
//! text, for moving to another password manager), or as a copy of the
//! KeePass database (encrypted; it opens with the recovery key). Both need the
//! master password.
//!
//! Neither ever replaces the vault's own files or goes into `~/.ssh`, whose
//! files `ssh` and other tools read without asking. Paths are compared by the
//! file system's identity of the file and its folders (device and inode on
//! Unix), so a symbolic link, `..` or a macOS firmlink such as
//! `/System/Volumes/Data/Users/…` can't lead around the check.

use std::fs;
use std::path::{Path, PathBuf};

use keepass::db::fields;
use secrecy::SecretString;
use zeroize::Zeroizing;

use super::{UNREADABLE_OTP_FIELD, Vault, VaultPaths, read_database};
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

/// First characters that make a spreadsheet treat a cell as a formula.
pub(super) const FORMULA_STARTS: [char; 6] = ['=', '+', '-', '@', '\t', '\r'];
/// Passwords are written exactly: generated ones often start with `-` or
/// `@`, and one changed by a `'` would no longer work after the file is
/// imported elsewhere. They are the user's own, not text a site chose.
const PASSWORD_COLUMN: usize = 3;

impl Vault {
    /// Writes every entry outside the recycle bin to `target` as a
    /// KeePassXC-style CSV file (mode 0600; on Windows only the user, SYSTEM
    /// and Administrators can read it), after checking the master password.
    /// Returns how many entries were written.
    ///
    /// The file holds every password in plain text. It never replaces the
    /// vault's files and is never written inside `ssh_dir`. Cells other than
    /// passwords that a spreadsheet would run as a formula start with `'`.
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

    /// Copies the vault's database to `target` (mode 0600), after checking
    /// the master password. The copy is as encrypted as the original: it
    /// opens with the recovery key, or with the password of a KeePass file
    /// brought from elsewhere. Like the CSV export, it never replaces the
    /// vault's files and is never written inside `ssh_dir`.
    pub fn export_kdbx(&self, master: &SecretString, target: &Path, ssh_dir: &Path) -> Result<()> {
        self.verify_master_password(master)?;
        let target = checked_target(target, &self.paths, ssh_dir)?;
        let bytes = read_database(&self.paths.database)?;
        write_private(&target, &bytes)
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
            // An unreadable secret from an import goes where it came from.
            let otp = Some(field(fields::OTP))
                .filter(|otp| !otp.is_empty())
                .unwrap_or_else(|| field(UNREADABLE_OTP_FIELD));
            let row = [
                group.as_str(),
                &summary.title,
                &summary.username,
                field(fields::PASSWORD),
                &summary.url,
                field(fields::NOTES),
                otp,
                "0",
                summary.modified.as_deref().unwrap_or_default(),
                summary.created.as_deref().unwrap_or_default(),
            ];
            let row: Vec<Zeroizing<String>> = row
                .into_iter()
                .enumerate()
                .map(|(column, cell)| {
                    if column == PASSWORD_COLUMN {
                        Zeroizing::new(cell.to_owned())
                    } else {
                        neutralize(cell)
                    }
                })
                .collect();
            writer
                .write_record(row.iter().map(|cell| cell.as_bytes()))
                .map_err(|e| csv_error(&e))?;
            count += 1;
        }
        let bytes = writer
            .into_inner()
            .map_err(|e| Error::Parse(format!("writing the CSV file: {e}")))?;
        Ok((Zeroizing::new(bytes), count))
    }
}

/// A cell that a spreadsheet would run as a formula (`=IMPORTXML(…)` in a
/// title saved from a hostile site) gets a leading `'`, which spreadsheets
/// show as text. A plain number, such as a phone number used as a username
/// (`+998 90 123-45-67`), is left alone: it runs nothing, and other password
/// managers would keep the `'` on import. This app's import takes it off.
fn neutralize(cell: &str) -> Zeroizing<String> {
    let mut out = String::with_capacity(cell.len() + 1);
    if cell.starts_with(FORMULA_STARTS) && !is_plain_number(cell) {
        out.push('\'');
    }
    out.push_str(cell);
    Zeroizing::new(out)
}

/// A sign, then digits with spaces, dots, dashes and brackets between them.
fn is_plain_number(cell: &str) -> bool {
    let rest = cell.strip_prefix(['+', '-']).unwrap_or(cell);
    rest.starts_with(|c: char| c.is_ascii_digit() || c == '(')
        && rest.chars().any(|c| c.is_ascii_digit())
        && rest
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, ' ' | '.' | '-' | '(' | ')'))
}

/// `target` with symbolic links resolved, refused if it is one of the
/// vault's own files, a folder, or inside `ssh_dir`.
pub(super) fn checked_target(target: &Path, paths: &VaultPaths, ssh_dir: &Path) -> Result<PathBuf> {
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
    if let Some(id) = FileId::of(&real)
        && [&paths.database, &paths.keys]
            .into_iter()
            .any(|own| FileId::of(own).as_ref() == Some(&id))
    {
        return Err(Error::invalid(
            "an export never replaces the vault's own files",
        ));
    }
    let inside_ssh = match FileId::of(ssh_dir) {
        // Every folder the file would be in, as the file system sees it.
        Some(ssh) => [target, &real]
            .into_iter()
            .flat_map(|path| path.ancestors().skip(1))
            .any(|folder| FileId::of(folder).as_ref() == Some(&ssh)),
        None => real.starts_with(resolve(ssh_dir)),
    };
    if inside_ssh {
        return Err(Error::invalid(
            "an export is never written into the SSH folder",
        ));
    }
    Ok(real)
}

/// Which file or folder a path leads to, after links: the device and inode
/// on Unix. Windows has no firmlinks and the standard library no stable
/// file id there, so it compares canonical paths (junctions and symbolic
/// links resolved).
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileId(Identity);

#[cfg(unix)]
type Identity = (u64, u64);
#[cfg(not(unix))]
type Identity = PathBuf;

impl FileId {
    fn of(path: &Path) -> Option<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = fs::metadata(path).ok()?;
            Some(Self((meta.dev(), meta.ino())))
        }
        #[cfg(not(unix))]
        {
            fs::canonicalize(path).ok().map(Self)
        }
    }
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
/// (whose mode is tightened first, as the write keeps it). On Windows, where
/// modes mean nothing, the temporary file is created with an access list
/// for nobody but the user, SYSTEM and Administrators, as for a private key,
/// before anything is written to it; a drive that can't keep one (FAT,
/// exFAT, some network shares) is refused and nothing is left behind.
pub(super) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(windows)]
    {
        fsutil::atomic_write_private(path, bytes)
    }
    #[cfg(not(windows))]
    {
        match fs::symlink_metadata(path) {
            Ok(_) => fsutil::set_mode(path, 0o600)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::io(e, path)),
        }
        fsutil::atomic_write(path, bytes, 0o600)
    }
}

fn csv_error(error: &csv::Error) -> Error {
    Error::Parse(format!("writing the CSV file: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formula_cells_are_neutralised() {
        assert_eq!(*neutralize("=IMPORTXML(A1)"), "'=IMPORTXML(A1)");
        for cell in [
            "=1",
            "@SUM(A1)",
            "\tx",
            "\rx",
            "-2+3+cmd|' /C calc'!A0",
            "+-",
            "+",
        ] {
            assert_eq!(*neutralize(cell), format!("'{cell}"));
        }
        for cell in [
            "GitHub",
            "",
            "a=b",
            " =x",
            "'quoted",
            "+998901234567",
            "+998 90 123-45-67",
            "+1 (555) 010-9999",
            "-2",
        ] {
            assert_eq!(*neutralize(cell), cell);
        }
    }

    #[cfg(unix)]
    #[test]
    fn file_ids_see_through_links_and_dot_dot() {
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path().join(".ssh");
        fs::create_dir(&ssh).unwrap();
        std::os::unix::fs::symlink(&ssh, dir.path().join("link")).unwrap();
        let id = FileId::of(&ssh).unwrap();
        assert_eq!(FileId::of(&dir.path().join("link")), Some(id.clone()));
        assert_eq!(FileId::of(&ssh.join("..").join(".ssh")), Some(id));
        assert_eq!(FileId::of(&dir.path().join("missing")), None);
    }
}
