//! Importing the CSV files other password managers export.
//!
//! The format is recognised by the header row: Bitwarden, 1Password,
//! Chrome / Edge, Firefox, Apple Passwords and KeePassXC each have their own
//! columns; any other file falls back to common column names (`title`, `url`,
//! `username`, `password`, `notes`, `totp`, `folder`, …).
//!
//! Importing takes two steps. [`Vault::import_preview`] reads the file and
//! returns its rows without passwords or 2FA secrets, marking those an
//! existing entry already covers, and among them those whose password differs
//! from the entry's. [`Vault::import_csv`] reads the file again, adds the rows
//! the user picked and sets the new password on the entries those with a
//! different one cover, so no secret has to wait in memory or travel to the
//! UI in between.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use keepass::db::{GroupId, Times, Value, fields};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use zeroize::Zeroizing;

use super::{
    EntryInput, EntryKind, EntrySummary, SecretField, UNREADABLE_OTP_FIELD, Vault, check_field,
    otp_uri, parse_id, wanted_fields,
};
use crate::{Error, Result, fsutil};

/// Largest CSV file that is read. Exports of thousands of entries stay far
/// below it.
const MAX_CSV_SIZE: u64 = 32 * 1024 * 1024;
/// Most records read from one file.
const MAX_RECORDS: usize = 100_000;
/// Deepest folder path kept; deeper levels are dropped.
const MAX_GROUP_DEPTH: usize = 16;
/// Title of a row that has nothing to name it by.
const UNTITLED: &str = "Imported";

/// The app a CSV file came from, as recognised by its header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum CsvFormat {
    Bitwarden,
    OnePassword,
    /// Chrome and Edge, which export the same columns.
    Chrome,
    Firefox,
    /// Apple Passwords (macOS) and Safari.
    Apple,
    Keepassxc,
    /// Any other file with recognisable column names.
    Generic,
}

/// A row of a CSV file as the import preview shows it. Holds no secrets.
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent facts about the row the preview shows"
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct ImportRow {
    /// Position of the record in the file, counting from 0 after the header;
    /// what [`Vault::import_csv`] takes.
    pub index: u32,
    pub title: String,
    pub username: String,
    pub url: String,
    /// Folder path, e.g. `Work/Servers`.
    pub group: Option<String>,
    pub has_password: bool,
    /// A 2FA secret that will be stored as such.
    pub has_otp: bool,
    /// A 2FA secret this app can't use (`steam://`, HOTP, …). It is kept in a
    /// protected field that KeePassXC shows, and never sent to the UI.
    pub has_unreadable_otp: bool,
    /// An existing entry for the same site (URL host) and user name, or with
    /// the same title and user name when the row has no URL.
    pub duplicate_of: Option<String>,
    /// The row has a password and `duplicate_of` has another one. Importing
    /// the row sets it on that entry, keeping the old one in its history,
    /// instead of adding a copy.
    pub password_changed: bool,
    /// When the password was last changed, as the file says (Firefox and
    /// KeePassXC exports, and other files with such a column), RFC 3339.
    pub changed_in_file: Option<String>,
    /// When `duplicate_of` got its current password, RFC 3339: for an entry
    /// imported before, when it was imported.
    pub changed_in_vault: Option<String>,
}

/// The two passwords of a row whose entry has another one, for the user to
/// compare before importing it.
#[derive(Debug)]
pub struct ImportComparison {
    pub file: SecretString,
    pub vault: SecretString,
}

/// What a CSV file holds, without secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct ImportPreview {
    pub format: CsvFormat,
    pub rows: Vec<ImportRow>,
    /// Records left out: empty ones and ones with values too long to store.
    pub skipped: u32,
}

/// What [`Vault::import_csv`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct ImportOutcome {
    /// New entries.
    pub added: u32,
    /// Existing entries that got the row's password.
    pub updated: u32,
}

impl Vault {
    /// Reads a CSV export and lists its rows, marking duplicates of entries
    /// outside the recycle bin and those with another password.
    pub fn import_preview(&self, path: &Path) -> Result<ImportPreview> {
        Ok(self.preview_parsed(&read(path)?))
    }

    fn preview_parsed(&self, parsed: &Parsed) -> ImportPreview {
        let existing: Vec<EntrySummary> =
            self.entries().into_iter().filter(|e| !e.in_trash).collect();
        let duplicates = Duplicates::new(&existing);
        let rows = parsed
            .records
            .iter()
            .map(|record| {
                let duplicate_of = duplicates.find(record);
                ImportRow {
                    index: record.index,
                    title: record.title.clone(),
                    username: record.username.clone(),
                    url: record.url.clone(),
                    group: record.group.clone(),
                    has_password: !record.password.is_empty(),
                    has_otp: record.otp.is_some(),
                    has_unreadable_otp: record.unreadable_otp.is_some(),
                    password_changed: duplicate_of
                        .is_some_and(|id| self.password_differs(id, record)),
                    changed_in_file: record.changed_at.map(super::rfc3339),
                    changed_in_vault: duplicate_of
                        .and_then(|id| self.entry(id).ok())
                        .and_then(|detail| detail.password_changed),
                    duplicate_of: duplicate_of.map(str::to_owned),
                }
            })
            .collect();
        ImportPreview {
            format: parsed.format,
            rows,
            skipped: parsed.skipped,
        }
    }

    /// Reads the CSV file again and imports the rows at `indices`: a row
    /// whose entry has another password (see [`ImportRow::password_changed`])
    /// sets it on that entry, keeping the old one in the entry's history; any
    /// other row is added as an entry, in its folder. Nothing changes if any
    /// of them fails, or if an index no longer names a row (the file changed
    /// since the preview). The caller saves the vault.
    pub fn import_csv(&mut self, path: &Path, indices: &[u32]) -> Result<ImportOutcome> {
        self.apply_parsed(&read(path)?, indices)
    }

    fn apply_parsed(&mut self, parsed: &Parsed, indices: &[u32]) -> Result<ImportOutcome> {
        let wanted: BTreeSet<u32> = indices.iter().copied().collect();
        let records: Vec<&Record> = parsed
            .records
            .iter()
            .filter(|r| wanted.contains(&r.index))
            .collect();
        if records.len() != wanted.len() {
            return Err(Error::invalid(
                "the file changed since it was previewed; preview it again",
            ));
        }
        // Which entry each row updates, judged before anything is added, as
        // the preview judged it.
        let existing: Vec<EntrySummary> =
            self.entries().into_iter().filter(|e| !e.in_trash).collect();
        let duplicates = Duplicates::new(&existing);
        let plan: Vec<(&Record, Option<String>)> = records
            .into_iter()
            .map(|record| {
                let update = duplicates
                    .find(record)
                    .filter(|id| self.password_differs(id, record))
                    .map(str::to_owned);
                (record, update)
            })
            .collect();
        let before = self.db.clone();
        let mut outcome = ImportOutcome::default();
        let result = plan.into_iter().try_for_each(|(record, update)| {
            if let Some(id) = update {
                self.set_imported_password(&id, record)?;
                outcome.updated += 1;
            } else {
                self.add_imported(record)?;
                outcome.added += 1;
            }
            Ok(())
        });
        if let Err(error) = result {
            self.db = before;
            return Err(error);
        }
        Ok(outcome)
    }

    /// The password of the row at `index` and that of the entry it would
    /// update, for the user to compare. Only for a row the preview marked
    /// [`ImportRow::password_changed`]; any other is refused, so this never
    /// shows a password the import wouldn't replace.
    pub fn import_compare(&self, path: &Path, index: u32) -> Result<ImportComparison> {
        self.compare_parsed(&read(path)?, index)
    }

    fn compare_parsed(&self, parsed: &Parsed, index: u32) -> Result<ImportComparison> {
        let record = parsed
            .records
            .iter()
            .find(|r| r.index == index)
            .ok_or_else(|| {
                Error::invalid("the file changed since it was previewed; preview it again")
            })?;
        let existing: Vec<EntrySummary> =
            self.entries().into_iter().filter(|e| !e.in_trash).collect();
        let id = Duplicates::new(&existing)
            .find(record)
            .filter(|id| self.password_differs(id, record))
            .ok_or_else(|| Error::invalid("this row doesn't change a password in the vault"))?;
        Ok(ImportComparison {
            file: SecretString::from(record.password.as_str()),
            vault: self.secret(id, SecretField::Password)?,
        })
    }

    /// The row has a password, and the entry `id` is a login with another
    /// one. SSH hosts and keys are never updated by an import: a CSV row
    /// that happens to share a host's or key's title could otherwise replace
    /// its password or passphrase.
    fn password_differs(&self, id: &str, record: &Record) -> bool {
        !record.password.is_empty()
            && self
                .find(id)
                .is_ok_and(|entry| self.summary(&entry).kind == EntryKind::Login)
            && self
                .secret(id, SecretField::Password)
                .is_ok_and(|saved| saved.expose_secret() != record.password.as_str())
    }

    /// Sets a row's password on the entry `id`, keeping the old one in the
    /// entry's history.
    fn set_imported_password(&mut self, id: &str, record: &Record) -> Result<()> {
        check_field(record.password.as_str())?;
        let mut entry = self
            .db
            .entry_mut(parse_id(id)?)
            .ok_or_else(|| Error::NotFound(format!("entry {id}")))?;
        let mut tracked = entry.track_changes();
        tracked.set(fields::PASSWORD, Value::protected(record.password.as_str()));
        tracked.times.last_modification = Some(Times::now());
        Ok(())
    }

    fn add_imported(&mut self, record: &Record) -> Result<()> {
        let input = EntryInput {
            title: record.title.clone(),
            username: record.username.clone(),
            password: Some(SecretString::from(record.password.as_str())),
            url: record.url.clone(),
            notes: record.notes.clone(),
            otp: record
                .otp
                .as_ref()
                .map(|otp| SecretString::from(otp.as_str())),
            ..EntryInput::default()
        };
        let wanted = wanted_fields(&input, None)?;
        let group = self.import_group(record.group.as_deref());
        let mut parent = self
            .db
            .group_mut(group)
            .ok_or_else(|| Error::NotFound("folder".into()))?;
        let mut entry = parent.add_entry();
        for (name, value) in wanted {
            if let Some(value) = value {
                entry.set(name, value);
            }
        }
        if !entry.fields.contains_key(fields::PASSWORD) {
            entry.set_protected(fields::PASSWORD, "");
        }
        if let Some(otp) = &record.unreadable_otp {
            entry.set_protected(UNREADABLE_OTP_FIELD, otp.as_str());
        }
        Ok(())
    }

    /// The folder at `path` below the top level, created as needed. Never the
    /// recycle bin: rows that name it land at the top level.
    fn import_group(&mut self, path: Option<&str>) -> GroupId {
        let root = self.db.root().id();
        let Some(path) = path else {
            return root;
        };
        let bin = self.db.meta.recyclebin_uuid;
        let mut current = root;
        for name in path.split('/') {
            let existing = self.db.group(current).and_then(|group| {
                group
                    .groups()
                    .find(|child| child.name.eq_ignore_ascii_case(name))
                    .map(|child| child.id())
            });
            current = match existing {
                Some(id) if Some(id.uuid()) == bin => return root,
                Some(id) => id,
                None => {
                    let Some(mut parent) = self.db.group_mut(current) else {
                        return root;
                    };
                    let mut group = parent.add_group();
                    name.clone_into(&mut group.name);
                    group.id()
                }
            };
        }
        current
    }
}

/// A CSV file read into rows.
#[derive(Debug)]
struct Parsed {
    format: CsvFormat,
    records: Vec<Record>,
    skipped: u32,
}

/// One usable row, with its secrets; its `Debug` shows none of them.
struct Record {
    index: u32,
    title: String,
    username: String,
    url: String,
    notes: String,
    group: Option<String>,
    password: Zeroizing<String>,
    /// An `otpauth://` URI.
    otp: Option<Zeroizing<String>>,
    /// A 2FA secret as the file had it, when it isn't one this app can use.
    unreadable_otp: Option<Zeroizing<String>>,
    /// When the password was last changed, if the file says.
    changed_at: Option<chrono::NaiveDateTime>,
}

impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Record")
            .field("index", &self.index)
            .field("title", &self.title)
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

fn read(path: &Path) -> Result<Parsed> {
    let bytes = Zeroizing::new(fsutil::read_limited(path, MAX_CSV_SIZE)?);
    parse(&bytes)
}

fn parse(bytes: &[u8]) -> Result<Parsed> {
    let text = decode(bytes)?;
    let delimiter = sniff_delimiter(&text);
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(delimiter)
        .flexible(true)
        .has_headers(true)
        .from_reader(text.as_bytes());
    let headers: Vec<String> = reader
        .headers()
        .map_err(|e| csv_error(&e))?
        .iter()
        .map(normalize)
        .collect();
    if headers.iter().all(String::is_empty) {
        return Err(Error::Parse("the file is empty".into()));
    }
    let format = detect(&headers);
    let columns = Columns::new(format, &headers)?;

    let mut records = Vec::new();
    let mut skipped = 0;
    let mut row = csv::StringRecord::new();
    for index in 0.. {
        if !reader.read_record(&mut row).map_err(|e| csv_error(&e))? {
            break;
        }
        if index >= MAX_RECORDS {
            return Err(Error::invalid(format!(
                "the file has more than {MAX_RECORDS} rows"
            )));
        }
        let index = u32::try_from(index).unwrap_or(u32::MAX);
        match columns.record(&row, index) {
            Some(record) => records.push(record),
            None => skipped += 1,
        }
    }
    Ok(Parsed {
        format,
        records,
        skipped,
    })
}

/// The file as text: UTF-8 with or without a byte order mark, or UTF-16
/// with one (as some spreadsheet apps save it).
fn decode(bytes: &[u8]) -> Result<Zeroizing<String>> {
    let utf16 = |be: bool| -> Result<Zeroizing<String>> {
        let units: Zeroizing<Vec<u16>> = Zeroizing::new(
            bytes[2..]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&pair| {
                    if be {
                        u16::from_be_bytes(pair)
                    } else {
                        u16::from_le_bytes(pair)
                    }
                })
                .collect(),
        );
        String::from_utf16(&units)
            .map(Zeroizing::new)
            .map_err(|_| Error::Parse("the file is not valid UTF-16 text".into()))
    };
    match bytes {
        [0xEF, 0xBB, 0xBF, rest @ ..] => utf8(rest),
        [0xFF, 0xFE, ..] => utf16(false),
        [0xFE, 0xFF, ..] => utf16(true),
        _ => utf8(bytes),
    }
}

fn utf8(bytes: &[u8]) -> Result<Zeroizing<String>> {
    std::str::from_utf8(bytes)
        .map(|text| Zeroizing::new(text.to_owned()))
        .map_err(|_| Error::Parse("the file is not UTF-8 text; save it as UTF-8".into()))
}

/// Comma, or the semicolon or tab a spreadsheet app may have used instead,
/// judged by the header line.
fn sniff_delimiter(text: &str) -> u8 {
    let mut counts = [(b',', 0usize), (b';', 0), (b'\t', 0)];
    let mut quoted = false;
    for byte in text.bytes() {
        match byte {
            b'"' => quoted = !quoted,
            b'\n' | b'\r' if !quoted => break,
            _ if !quoted => {
                if let Some(count) = counts.iter_mut().find(|(d, _)| *d == byte) {
                    count.1 += 1;
                }
            }
            _ => {}
        }
    }
    counts
        .iter()
        .max_by_key(|(delimiter, count)| (*count, *delimiter == b','))
        .map_or(b',', |(delimiter, _)| *delimiter)
}

/// `Login Name` → `loginname`, `login_uri` → `loginuri`.
fn normalize(header: &str) -> String {
    header
        .chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn detect(headers: &[String]) -> CsvFormat {
    let has = |name: &str| headers.iter().any(|h| h == name);
    let all = |names: &[&str]| names.iter().all(|n| has(n));
    if all(&["name", "loginpassword"]) && (has("loginuri") || has("loginusername")) {
        CsvFormat::Bitwarden
    } else if all(&["url", "username", "password"])
        && (has("httprealm") || has("formactionorigin") || has("guid"))
    {
        CsvFormat::Firefox
    } else if all(&["group", "title", "username", "password", "url", "notes"]) {
        CsvFormat::Keepassxc
    } else if all(&["title", "url", "username", "password"])
        && (has("favorite") || has("archived") || has("tags"))
    {
        CsvFormat::OnePassword
    } else if all(&["title", "url", "username", "password", "otpauth"]) {
        CsvFormat::Apple
    } else if all(&["name", "url", "username", "password"])
        && headers.iter().all(|h| {
            matches!(
                h.as_str(),
                "name" | "url" | "username" | "password" | "note"
            )
        })
    {
        CsvFormat::Chrome
    } else {
        CsvFormat::Generic
    }
}

/// Column names (normalised) of other exports, best match first.
mod generic {
    pub(super) const TITLE: &[&str] = &[
        "title", "name", "account", "itemname", "item", "entry", "service",
    ];
    pub(super) const USERNAME: &[&str] = &[
        "username",
        "login",
        "loginname",
        "loginusername",
        "user",
        "username1",
        "email",
        "emailaddress",
    ];
    pub(super) const URL: &[&str] = &[
        "url",
        "uri",
        "loginuri",
        "website",
        "websiteurl",
        "webaddress",
        "web",
        "site",
        "address",
        "hostname",
    ];
    pub(super) const PASSWORD: &[&str] = &["password", "loginpassword", "pass", "passwd", "pwd"];
    pub(super) const NOTES: &[&str] = &[
        "notes",
        "note",
        "comments",
        "comment",
        "extra",
        "description",
    ];
    pub(super) const OTP: &[&str] = &[
        "totp",
        "otp",
        "otpauth",
        "logintotp",
        "otpsecret",
        "totpsecret",
        "2fa",
        "twofactor",
        "mfa",
        "authenticator",
    ];
    pub(super) const CHANGED: &[&str] = &[
        "timepasswordchanged",
        "passwordchanged",
        "passwordlastchanged",
        "passwordmodified",
        "lastmodified",
        "modified",
        "updated",
        "updatedat",
    ];
    pub(super) const GROUP: &[&str] = &[
        "group",
        "folder",
        "grouping",
        "category",
        "path",
        "collections",
        "collection",
        "vault",
    ];
}

/// Where each field is, as column indices in order of preference.
#[derive(Debug, Default)]
struct Columns {
    format: Option<CsvFormat>,
    title: Vec<usize>,
    username: Vec<usize>,
    url: Vec<usize>,
    password: Vec<usize>,
    notes: Vec<usize>,
    otp: Vec<usize>,
    group: Vec<usize>,
    /// Bitwarden's custom fields, added to the notes.
    extra: Vec<usize>,
    /// When the password (or the whole entry) last changed.
    changed: Vec<usize>,
}

impl Columns {
    fn new(format: CsvFormat, headers: &[String]) -> Result<Self> {
        let find = |aliases: &[&str]| -> Vec<usize> {
            aliases
                .iter()
                .flat_map(|alias| {
                    headers
                        .iter()
                        .enumerate()
                        .filter(move |(_, h)| h == alias)
                        .map(|(i, _)| i)
                })
                .collect()
        };
        let columns = match format {
            CsvFormat::Bitwarden => Self {
                title: find(&["name"]),
                username: find(&["loginusername"]),
                url: find(&["loginuri"]),
                password: find(&["loginpassword"]),
                notes: find(&["notes"]),
                otp: find(&["logintotp"]),
                group: find(&["folder", "collections"]),
                extra: find(&["fields"]),
                ..Self::default()
            },
            CsvFormat::OnePassword | CsvFormat::Apple => Self {
                title: find(&["title"]),
                username: find(&["username"]),
                url: find(&["url"]),
                password: find(&["password"]),
                notes: find(&["notes"]),
                otp: find(&["otpauth"]),
                ..Self::default()
            },
            CsvFormat::Chrome => Self {
                title: find(&["name"]),
                username: find(&["username"]),
                url: find(&["url"]),
                password: find(&["password"]),
                notes: find(&["note"]),
                ..Self::default()
            },
            CsvFormat::Firefox => Self {
                username: find(&["username"]),
                url: find(&["url"]),
                password: find(&["password"]),
                changed: find(&["timepasswordchanged"]),
                ..Self::default()
            },
            CsvFormat::Keepassxc => Self {
                title: find(&["title"]),
                username: find(&["username"]),
                url: find(&["url"]),
                password: find(&["password"]),
                notes: find(&["notes"]),
                otp: find(&["totp"]),
                group: find(&["group"]),
                changed: find(&["lastmodified"]),
                ..Self::default()
            },
            CsvFormat::Generic => Self {
                title: find(generic::TITLE),
                username: find(generic::USERNAME),
                url: find(generic::URL),
                password: find(generic::PASSWORD),
                notes: find(generic::NOTES),
                otp: find(generic::OTP),
                group: find(generic::GROUP),
                changed: find(generic::CHANGED),
                ..Self::default()
            },
        };
        if columns.password.is_empty() {
            return Err(Error::Unsupported(
                "this file has no password column; it does not look like a password export".into(),
            ));
        }
        Ok(Self {
            format: Some(format),
            ..columns
        })
    }

    /// The row as an entry, or `None` if it is empty or can't be stored.
    fn record(&self, row: &csv::StringRecord, index: u32) -> Option<Record> {
        let any = |columns: &[usize]| -> &str {
            columns
                .iter()
                .filter_map(|&i| row.get(i))
                .find(|value| !value.trim().is_empty())
                .unwrap_or_default()
        };
        // This app's export puts a `'` before text a spreadsheet would run;
        // passwords are written as they are.
        let first = |columns: &[usize]| -> &str { without_formula_guard(any(columns)) };
        let mut url = first(&self.url).trim();
        if self.format == Some(CsvFormat::Bitwarden) {
            // Bitwarden puts all of an item's URIs into one cell.
            url = url
                .split(',')
                .map(str::trim)
                .find(|u| !u.is_empty())
                .unwrap_or_default();
        }
        let url = url.to_owned();
        let username = first(&self.username).trim().to_owned();
        let password = Zeroizing::new(any(&self.password).to_owned());
        let mut notes = first(&self.notes).trim_end().to_owned();
        let extra = first(&self.extra).trim();
        if !extra.is_empty() {
            push_paragraph(&mut notes, extra);
        }
        let raw_otp = first(&self.otp).trim();
        let mut title = first(&self.title).trim().to_owned();

        if [&title, &username, &url, &notes, password.as_str()]
            .iter()
            .all(|v| v.is_empty())
            && raw_otp.is_empty()
        {
            return None;
        }
        if title.is_empty() {
            title = [host(&url), username.clone()]
                .into_iter()
                .find(|t| !t.is_empty())
                .unwrap_or_else(|| UNTITLED.to_owned());
        }
        let (otp, unreadable_otp) = if raw_otp.is_empty() {
            (None, None)
        } else if let Ok(uri) = otp_uri(raw_otp, &title) {
            (Some(Zeroizing::new(uri)), None)
        } else {
            // Kept, so nothing is lost, but as protected as a password: not
            // in the notes, which the UI shows.
            (None, Some(Zeroizing::new(raw_otp.to_owned())))
        };
        let group = group_path(
            first(&self.group),
            self.format == Some(CsvFormat::Keepassxc),
        );

        let values = [&title, &username, &url, &notes, password.as_str()];
        let otp_ok = [&otp, &unreadable_otp]
            .into_iter()
            .flatten()
            .all(|otp| check_field(otp).is_ok());
        let group_ok = group.as_deref().is_none_or(|g| check_field(g).is_ok());
        if !otp_ok || !group_ok || values.iter().any(|v| check_field(v).is_err()) {
            return None;
        }
        Some(Record {
            index,
            title,
            username,
            url,
            notes,
            group,
            password,
            otp,
            unreadable_otp,
            changed_at: changed_at(first(&self.changed)),
        })
    }
}

fn push_paragraph(notes: &mut String, text: &str) {
    if !notes.is_empty() {
        notes.push_str("\n\n");
    }
    notes.push_str(text);
}

/// `Work / Servers/` → `Work/Servers`. KeePassXC starts every path with the
/// name of the database's top group, which is dropped.
fn group_path(text: &str, has_root: bool) -> Option<String> {
    let mut parts: Vec<&str> = text
        .split('/')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect();
    if has_root && !parts.is_empty() {
        parts.remove(0);
    }
    parts.truncate(MAX_GROUP_DEPTH);
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// The host of a URL, lowercase and without `www.`: what makes two logins
/// the same site. Works without a scheme, too (`example.com/login`).
pub(super) fn host(url: &str) -> String {
    let rest = url.trim();
    let rest = rest.split_once("://").map_or(rest, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if authority.starts_with('[') {
        // [::1]:8080
        authority.split(']').next().map_or("", |h| &h[1..])
    } else {
        authority.split(':').next().unwrap_or_default()
    };
    let host = host.trim_end_matches('.').to_lowercase();
    host.strip_prefix("www.").map(str::to_owned).unwrap_or(host)
}

/// Existing entries by site and user name, and by title and user name.
struct Duplicates<'a> {
    by_host: HashMap<(String, String), &'a str>,
    by_title: HashMap<(String, String), &'a str>,
}

impl<'a> Duplicates<'a> {
    fn new(entries: &'a [EntrySummary]) -> Self {
        let mut by_host = HashMap::new();
        let mut by_title = HashMap::new();
        for entry in entries {
            let user = entry.username.trim().to_lowercase();
            let site = host(&entry.url);
            if !site.is_empty() {
                by_host
                    .entry((site, user.clone()))
                    .or_insert(entry.id.as_str());
            }
            by_title
                .entry((entry.title.trim().to_lowercase(), user))
                .or_insert(entry.id.as_str());
        }
        Self { by_host, by_title }
    }

    fn find(&self, record: &Record) -> Option<&'a str> {
        let user = record.username.to_lowercase();
        let site = host(&record.url);
        if site.is_empty() {
            self.by_title
                .get(&(record.title.to_lowercase(), user))
                .copied()
        } else {
            self.by_host.get(&(site, user)).copied()
        }
    }
}

/// A date as exports write it: milliseconds or seconds since 1970
/// (Firefox), or ISO 8601 with or without a zone (KeePassXC and others).
/// `None` for anything else, or a date before 1995 or in the future.
fn changed_at(cell: &str) -> Option<chrono::NaiveDateTime> {
    let cell = cell.trim();
    let time = if let Ok(number) = cell.parse::<i64>() {
        // Milliseconds since 2001 are over 10^12; seconds stay below it for
        // millennia.
        if number >= 1_000_000_000_000 {
            chrono::DateTime::from_timestamp_millis(number)?.naive_utc()
        } else {
            chrono::DateTime::from_timestamp(number, 0)?.naive_utc()
        }
    } else if let Ok(time) = chrono::DateTime::parse_from_rfc3339(cell) {
        time.naive_utc()
    } else {
        ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"]
            .iter()
            .find_map(|format| chrono::NaiveDateTime::parse_from_str(cell, format).ok())?
    };
    let earliest = chrono::NaiveDate::from_ymd_opt(1995, 1, 1)?.and_hms_opt(0, 0, 0)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    let latest = chrono::DateTime::from_timestamp(i64::try_from(now.as_secs()).ok()?, 0)?
        .naive_utc()
        + chrono::Duration::days(1);
    (earliest..=latest).contains(&time).then_some(time)
}

fn csv_error(error: &csv::Error) -> Error {
    Error::Parse(format!("reading the CSV file: {error}"))
}

/// A cell without the `'` this app's CSV export puts before text that
/// starts like a formula.
fn without_formula_guard(cell: &str) -> &str {
    match cell.strip_prefix('\'') {
        Some(rest) if rest.starts_with(super::export::FORMULA_STARTS) => rest,
        _ => cell,
    }
}

mod browser;
pub use browser::{
    BrowserFamily, BrowserKeyStore, BrowserLogins, BrowserProfile, BrowserReadError, SafeStorage,
    browser_profiles,
};

#[cfg(test)]
mod tests;
