use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use base64ct::{Base64, Encoding as _};
use secrecy::SecretString;

use super::needles::{forms, searchable};
use super::search::{self, Hit, Options};
use super::sources::{Plan, is_env_file};
use super::*;
use crate::shell_history::HistoryFile;
use crate::vault::EntryKind;

// Test values are made up here, never real-looking tokens or third-party
// keys (GitHub refuses pushes with those).
const TOKEN: &str = "Qx7-vR2m-Lp9w-Tz4k";
const PASSWORD: &str = "w8#Kd2!nV5$q";
const QUOTED: &str = r#"pa"ss\wo7rd-Zq"#;

/// A private key's shape: a header, lines of 64 base64 characters, a
/// footer; made from a counter, so nothing here is a real key.
fn pem() -> String {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut state: u32 = 0x2545_f491;
    let mut body = String::new();
    for line in 0..6 {
        if line > 0 {
            body.push('\n');
        }
        for _ in 0..64 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            body.push(char::from(alphabet[(state % 64) as usize]));
        }
    }
    format!("-----BEGIN TEST KEY-----\n{body}\n-----END TEST KEY-----")
}

fn variable(name: &str) -> LeakSecret {
    LeakSecret::Variable {
        env_id: "11111111-2222-3333-4444-555555555555".into(),
        project: "shop".into(),
        environment: "prod".into(),
        name: name.into(),
    }
}

fn known(name: &str, value: &str) -> KnownSecret {
    KnownSecret {
        secret: variable(name),
        value: SecretString::from(value),
    }
}

fn matcher() -> Matcher {
    Matcher::new(vec![
        known("API_TOKEN", TOKEN),
        KnownSecret {
            secret: LeakSecret::Password {
                entry_id: "66666666-7777-8888-9999-000000000000".into(),
                title: "GitLab".into(),
                entry_kind: EntryKind::Login,
            },
            value: SecretString::from(PASSWORD),
        },
        known("QUOTED", QUOTED),
        known("PRIVATE_KEY", &pem()),
        known("PORT", "8080"),
        known("DEBUG", "true"),
    ])
}

/// Every hit of `matcher` in `text`, read `chunk` bytes at a time.
fn hits(matcher: &Matcher, text: &[u8], chunk: usize) -> Vec<Hit> {
    let mut out = Vec::new();
    search::search(
        text,
        matcher,
        Options {
            chunk,
            ..Options::default()
        },
        |hit| out.push(hit),
    )
    .unwrap();
    out
}

fn file(dir: &Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&path, text).unwrap();
    path
}

fn scan(path: &Path, place: LeakPlace) -> Vec<LeakFinding> {
    let files = [ScanFile {
        path: path.to_path_buf(),
        place,
        size: fs::metadata(path).unwrap().len(),
    }];
    scan_files(&files, &matcher(), &ScanControl::default())
        .unwrap()
        .findings
}

fn ai() -> LeakPlace {
    LeakPlace::AiSession {
        tool: AiTool::ClaudeCode,
    }
}

#[test]
fn plain_values_are_not_looked_for() {
    for plain in [
        "",
        "short",
        "8080",
        "3000",
        "true",
        "2026-11-10",
        "10.0.0.15",
        "1.2.3-beta",
        "v2.10.0-rc.1+build7",
        "aaaaaaaaaaaa",
        "----------",
        "localhost",
        "LOCALHOST",
        "production",
        "development",
        "password",
        "password1",
        "/var/lib/postgres/data",
        "~/.ssh/id_ed25519",
        "C:\\Users\\dev\\app",
        "https://api.example.com",
        "https://api.example.com:8443/",
        "redis://cache:6379",
        "dev@example.com",
    ] {
        assert!(!searchable(plain), "{plain:?} should not be looked for");
        assert!(forms(plain).is_empty(), "{plain:?}");
    }
    // Random values with the shape of a path or an address are secrets.
    for secret in [
        TOKEN,
        PASSWORD,
        QUOTED,
        "/xK9#mQ2$vL7pR4w",
        "~/Zq8!kLm2#Vn5",
        "/7nLq0vW3+eYbZr2KcT8uHf1sJx5Pa9mDg4Rk6Bt",
        "Tr0ub4dor@x7.Kq9z",
        "postgres://app:Xq9!vL2#mT@db:5432/shop",
        "https://hooks.example.com/services/T0A1/B2C3/xY7zQ9wL",
        "correct horse battery staple",
    ] {
        assert!(searchable(secret), "{secret:?} should be looked for");
    }
}

#[test]
fn values_are_looked_for_in_the_forms_files_hold_them_in() {
    let forms_of = |value: &str| -> Vec<(String, Option<Encoding>)> {
        forms(value)
            .into_iter()
            .map(|form| {
                (
                    String::from_utf8(form.bytes.to_vec()).unwrap(),
                    form.encoding,
                )
            })
            .collect()
    };
    let found = |text: &str, value: &str| {
        forms_of(value)
            .iter()
            .any(|(form, _)| text.contains(form.as_str()))
    };

    // As it is, escaped in JSON, percent-encoded.
    let quoted = forms_of(QUOTED);
    assert!(quoted.contains(&(QUOTED.to_owned(), None)));
    assert!(quoted.contains(&(r#"pa\"ss\\wo7rd-Zq"#.to_owned(), None)));
    assert!(quoted.contains(&("pa%22ss%5Cwo7rd-Zq".to_owned(), Some(Encoding::Url))));
    assert!(quoted.contains(&("pa%22ss%5cwo7rd-Zq".to_owned(), Some(Encoding::Url))));
    // JSON inside a JSON string, as Codex keeps a tool's arguments.
    let arguments = serde_json::to_string(&serde_json::json!({
        "arguments": serde_json::to_string(&serde_json::json!({ "cmd": format!("echo {QUOTED}") })).unwrap()
    }))
    .unwrap();
    assert!(found(&arguments, QUOTED));
    let spaced = forms_of("correct horse battery staple");
    assert!(spaced.contains(&(
        "correct+horse+battery+staple".to_owned(),
        Some(Encoding::Url)
    )));
    let json =
        serde_json::to_string(&serde_json::json!({ "content": format!("KEY={QUOTED}") })).unwrap();
    assert!(found(&json, QUOTED));

    // In base64, alone and inside a longer string at every alignment.
    for prefix in ["", "u", "us", "user:", "ab:", "a:"] {
        let encoded = Base64::encode_string(format!("{prefix}{PASSWORD}").as_bytes());
        assert!(
            found(&format!("Authorization: Basic {encoded}"), PASSWORD),
            "{prefix:?}"
        );
        let url_safe = encoded.replace('+', "-").replace('/', "_");
        assert!(found(&url_safe, PASSWORD), "{prefix:?}");
    }

    // The password of an address, alone and decoded.
    let url = "postgres://app:Xq9%21vL2%23mT@db:5432/shop";
    let url_forms = forms_of(url);
    assert!(url_forms.iter().any(|(form, _)| form == "Xq9!vL2#mT"));
    assert!(url_forms.iter().any(|(form, _)| form == "Xq9%21vL2%23mT"));

    // A key by its lines, its JSON form, `\n` written out, base64.
    let key = pem();
    let key_forms = forms_of(&key);
    assert!(
        key_forms
            .iter()
            .all(|(form, _)| !form.starts_with("-----") || form.len() > 40)
    );
    let line = key.lines().nth(2).unwrap();
    assert!(key_forms.contains(&(line.to_owned(), None)));
    assert!(found(&key.replace('\n', "\\n"), &key));
    assert!(found(&serde_json::to_string(&key).unwrap(), &key));
    assert!(found(
        &Base64::encode_string(format!("{key}\n").as_bytes()),
        &key
    ));
}

#[test]
fn matches_across_chunks_are_found_once_with_their_line() {
    let matcher = matcher();
    let mut text = String::new();
    let mut lines = Vec::new();
    for n in 0..40 {
        text.push_str(&"filler text ".repeat(n % 7));
        if n % 3 == 0 {
            lines.push(u32::try_from(n + 1).unwrap());
            let _ = write!(text, "token={TOKEN};");
        }
        text.push('\n');
    }
    let expected: Vec<u32> = lines.clone();
    for chunk in [7, 16, 31, 64, 1000, 1 << 20] {
        let found: Vec<u32> = hits(&matcher, text.as_bytes(), chunk)
            .iter()
            .map(|hit| hit.line)
            .collect();
        assert_eq!(found, expected, "chunk {chunk}");
    }
}

#[test]
fn a_scan_reports_where_never_what() {
    let dir = tempfile::tempdir().unwrap();
    let key = pem();
    let session = file(
        dir.path(),
        "session.jsonl",
        &[
            serde_json::json!({ "type": "user", "text": "hello" }).to_string(),
            serde_json::json!({ "type": "tool", "content": format!("API_TOKEN={TOKEN}\nPORT=8080\nDEBUG=true") }).to_string(),
            serde_json::json!({ "type": "tool", "content": format!("PRIVATE_KEY=\"{}\"", key.replace('\n', "\\n")) }).to_string(),
            serde_json::json!({ "type": "tool", "content": key }).to_string(),
            serde_json::json!({ "type": "assistant", "text": format!("curl -u me:{PASSWORD}") }).to_string(),
            serde_json::json!({ "type": "assistant", "text": format!("again {TOKEN} and {TOKEN}") }).to_string(),
        ]
        .join("\n"),
    );
    let findings = scan(&session, ai());
    let by_name = |name: &str| {
        findings
            .iter()
            .find(|f| match &f.secret {
                LeakSecret::Variable { name: n, .. } => n == name,
                LeakSecret::Password { .. } => name == "password",
            })
            .unwrap_or_else(|| panic!("{name} not found in {findings:?}"))
    };
    assert_eq!(findings.len(), 3, "{findings:?}");
    let token = by_name("API_TOKEN");
    assert_eq!((token.line, token.occurrences), (2, 3));
    assert_eq!(token.severity, Severity::Critical);
    assert!(token.redactable);
    assert_eq!(token.place, ai());
    assert_eq!(token.path, session.display().to_string());
    assert_eq!(token.id, finding_id(&variable("API_TOKEN"), &token.path));
    let key_found = by_name("PRIVATE_KEY");
    assert_eq!((key_found.line, key_found.occurrences), (3, 2));
    assert_eq!(by_name("password").line, 5);

    let json = serde_json::to_string(&findings).unwrap();
    for value in [TOKEN, PASSWORD, &key, "8080"] {
        for form in forms(value) {
            let form = String::from_utf8(form.bytes.to_vec()).unwrap();
            assert!(!json.contains(&form), "a finding holds a form of a value");
        }
    }
    assert!(!json.contains(TOKEN) && !json.contains(PASSWORD));
    assert!(!format!("{findings:?}{:?}", matcher()).contains(TOKEN));
}

#[test]
fn a_key_in_a_file_is_one_occurrence_on_its_first_line() {
    let dir = tempfile::tempdir().unwrap();
    let key = pem();
    let path = file(
        dir.path(),
        ".env",
        &format!(
            "A=1\nPRIVATE_KEY=\"{key}\"\nB=2\nCOPY:\r\n{}\n",
            key.replace('\n', "\r\n")
        ),
    );
    let place = LeakPlace::File {
        git: GitState::Ignored,
        repository: None,
    };
    let findings = scan(&path, place);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!((findings[0].line, findings[0].occurrences), (2, 2));
    assert_eq!(findings[0].severity, Severity::Info);
    assert!(!findings[0].redactable);
}

#[test]
fn encoded_values_say_how() {
    let dir = tempfile::tempdir().unwrap();
    let basic = Base64::encode_string(format!("deploy:{PASSWORD}").as_bytes());
    let path = file(
        dir.path(),
        "notes.txt",
        &format!("Authorization: Basic {basic}\nurl: https://x.test/?t=Qx7-vR2m-Lp9w-Tz4k\n"),
    );
    let findings = scan(
        &path,
        LeakPlace::File {
            git: GitState::Tracked,
            repository: Some(dir.path().display().to_string()),
        },
    );
    assert_eq!(findings.len(), 2, "{findings:?}");
    let password = findings
        .iter()
        .find(|f| matches!(f.secret, LeakSecret::Password { .. }))
        .unwrap();
    assert_eq!(password.encodings, [Encoding::Base64]);
    assert_eq!(password.severity, Severity::Critical);
}

#[test]
fn binary_files_of_folders_are_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blob.dat");
    let mut bytes = vec![0_u8, 1, 2];
    bytes.extend_from_slice(TOKEN.as_bytes());
    fs::write(&path, &bytes).unwrap();
    let outside = LeakPlace::File {
        git: GitState::Outside,
        repository: None,
    };
    assert_eq!(scan(&path, outside), []);
    // Session histories are read whatever they hold.
    assert_eq!(scan(&path, ai()).len(), 1);
}

#[test]
fn two_secrets_with_one_value_are_both_reported() {
    let dir = tempfile::tempdir().unwrap();
    let path = file(dir.path(), "log.txt", &format!("x {TOKEN} y\n"));
    let matcher = Matcher::new(vec![known("A", TOKEN), known("B", TOKEN)]);
    let outcome = scan_files(
        &[ScanFile {
            path,
            place: ai(),
            size: 0,
        }],
        &matcher,
        &ScanControl::default(),
    )
    .unwrap();
    assert_eq!(outcome.findings.len(), 2);
}

#[test]
fn a_cancelled_scan_stops() {
    let dir = tempfile::tempdir().unwrap();
    let path = file(dir.path(), "a.txt", TOKEN);
    let control = ScanControl::default();
    control.cancel.store(true, Ordering::Relaxed);
    let files = [ScanFile {
        path,
        place: ai(),
        size: 0,
    }];
    assert_eq!(scan_files(&files, &matcher(), &control), Err(Cancelled));
}

#[test]
fn progress_counts_files_and_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let a = file(dir.path(), "a.txt", "0123456789");
    let b = file(dir.path(), "b.txt", "abc");
    let missing = dir.path().join("gone.txt");
    let control = ScanControl::default();
    let files: Vec<ScanFile> = [a, b, missing]
        .into_iter()
        .map(|path| ScanFile {
            path,
            place: ai(),
            size: 0,
        })
        .collect();
    let outcome = scan_files(&files, &matcher(), &control).unwrap();
    assert_eq!(outcome.unreadable, 1);
    assert_eq!(control.files_done.load(Ordering::Relaxed), 3);
    assert_eq!(control.bytes_done.load(Ordering::Relaxed), 13);
}

#[test]
fn redacting_replaces_the_value_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let key = pem();
    let lines = [
        serde_json::json!({ "content": format!("API_TOKEN={TOKEN}") }).to_string(),
        serde_json::json!({ "content": key }).to_string(),
        serde_json::json!({ "content": format!("{TOKEN}{TOKEN}") }).to_string(),
        serde_json::json!({ "content": format!("QUOTED={QUOTED}") }).to_string(),
    ];
    let path = file(dir.path(), "s.jsonl", &lines.join("\n"));
    let before = fs::read(&path).unwrap();

    let token = Matcher::new(vec![known("API_TOKEN", TOKEN)]);
    assert_eq!(token.len(), 1);
    let done = redact(&path, None, &token).unwrap();
    assert_eq!(
        done,
        Redacted {
            replaced: 2,
            skipped: 0,
            left: 0
        }
    );

    let after = fs::read(&path).unwrap();
    assert_eq!(after.len(), before.len());
    let text = String::from_utf8(after).unwrap();
    assert!(!text.contains(TOKEN));
    assert!(text.contains("API_TOKEN=[REDACTED________]"));
    for line in text.lines() {
        serde_json::from_str::<serde_json::Value>(line).unwrap();
    }
    // Other secrets stay.
    assert!(text.contains(r#"pa\"ss\\wo7rd-Zq"#));

    let key_matcher = Matcher::new(vec![known("PRIVATE_KEY", &key), known("Q", QUOTED)]);
    let done = redact(&path, None, &key_matcher).unwrap();
    assert_eq!(done.left, 0);
    let text = fs::read_to_string(&path).unwrap();
    assert!(!text.contains(key.lines().nth(1).unwrap()));
    assert!(!text.contains("pa\\\"ss"));
    for line in text.lines() {
        serde_json::from_str::<serde_json::Value>(line).unwrap();
    }
}

#[test]
fn markers_keep_the_length() {
    assert_eq!(marker(8), b"REDACTED");
    assert_eq!(marker(9), b"REDACTED_");
    assert_eq!(marker(10), b"[REDACTED]");
    assert_eq!(marker(14), b"[REDACTED____]");
    for len in 0..40 {
        assert_eq!(marker(len).len(), len);
    }
}

#[test]
fn severity_follows_the_place() {
    let file = |git| LeakPlace::File {
        git,
        repository: None,
    };
    assert_eq!(severity(&ai()), Severity::Critical);
    assert_eq!(severity(&file(GitState::Tracked)), Severity::Critical);
    assert_eq!(severity(&file(GitState::Untracked)), Severity::Critical);
    assert_eq!(
        severity(&LeakPlace::ShellHistory { shell: Shell::Zsh }),
        Severity::Warning
    );
    assert_eq!(severity(&file(GitState::Outside)), Severity::Warning);
    assert_eq!(severity(&file(GitState::Ignored)), Severity::Info);
}

#[test]
fn finding_ids_are_stable_and_name_nothing() {
    let id = finding_id(&variable("API_TOKEN"), "/home/dev/.zsh_history");
    assert_eq!(
        id,
        finding_id(&variable("API_TOKEN"), "/home/dev/.zsh_history")
    );
    assert_ne!(id, finding_id(&variable("OTHER"), "/home/dev/.zsh_history"));
    assert!(id.starts_with("leak:") && id.len() == 37);
    assert!(!id.contains("zsh") && !id.contains("API"));
}

#[test]
fn env_files_are_known_by_name() {
    for name in [
        ".env",
        ".env.local",
        ".env.production",
        "prod.env",
        ".envrc",
        ".dev.vars",
    ] {
        assert!(is_env_file(name), "{name}");
    }
    for name in [
        "env",
        ".environment",
        "README.md",
        ".env-cmdrc.json",
        ".env",
    ] {
        assert_eq!(is_env_file(name), name == ".env", "{name}");
    }
}

/// Git as a test sees it: tracked and untracked files listed per folder.
struct FakeGit(Vec<(PathBuf, GitFiles)>);

impl GitLister for FakeGit {
    fn list(&self, folder: &Path, _: &ScanControl) -> Option<GitFiles> {
        self.0
            .iter()
            .find(|(root, _)| root == folder)
            .map(|(_, files)| files.clone())
    }
}

#[test]
fn folders_give_what_git_would_commit_and_env_files_anywhere() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let repo = root.join("shop");
    fs::create_dir_all(repo.join(".git")).unwrap();
    file(&repo, "src/main.rs", "fn main() {}");
    file(&repo, "notes.md", "draft");
    file(&repo, ".env", "KEY=1");
    file(&repo, "config/.env.local", "KEY=2");
    file(&repo, "node_modules/pkg/.env", "KEY=3");
    file(&repo, "logo.png", "png");
    file(&repo, ".aider.chat.history.md", "chat");
    // A working tree Git can't list.
    let other = root.join("other");
    fs::create_dir_all(other.join(".git")).unwrap();
    file(&other, ".env", "KEY=4");
    file(root, "loose/.env.production", "KEY=5");
    file(
        root,
        "loose/readme.txt",
        "not read: outside any working tree",
    );
    #[cfg(unix)]
    std::os::unix::fs::symlink(repo.join(".env"), root.join("loose/.env")).unwrap();

    let git = FakeGit(vec![(
        repo.clone(),
        GitFiles {
            tracked: vec!["src/main.rs".into(), "logo.png".into()],
            untracked: vec!["notes.md".into(), "nested/".into()],
            truncated: false,
        },
    )]);
    let folders = [root.to_path_buf()];
    let listing = list_files(
        &Plan {
            ai: &[],
            history: &[],
            folders: &folders,
        },
        &git,
        &ScanControl::default(),
    )
    .unwrap();
    let repository = Some(repo.display().to_string());
    let got: Vec<(String, LeakPlace)> = listing
        .files
        .iter()
        .map(|f| {
            (
                f.path.strip_prefix(root).unwrap().display().to_string(),
                f.place.clone(),
            )
        })
        .collect();
    let file_in = |git, repository: &Option<String>| LeakPlace::File {
        git,
        repository: repository.clone(),
    };
    let expected = vec![
        (
            "shop/src/main.rs".to_owned(),
            file_in(GitState::Tracked, &repository),
        ),
        (
            "shop/notes.md".to_owned(),
            file_in(GitState::Untracked, &repository),
        ),
        (
            "loose/.env.production".to_owned(),
            file_in(GitState::Outside, &None),
        ),
        (
            "other/.env".to_owned(),
            file_in(GitState::Outside, &Some(other.display().to_string())),
        ),
        (
            "shop/.aider.chat.history.md".to_owned(),
            LeakPlace::AiSession {
                tool: AiTool::Aider,
            },
        ),
        (
            "shop/.env".to_owned(),
            file_in(GitState::Ignored, &repository),
        ),
        (
            "shop/config/.env.local".to_owned(),
            file_in(GitState::Ignored, &repository),
        ),
    ];
    let mut got_sorted = got.clone();
    got_sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut expected_sorted = expected;
    expected_sorted.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(got_sorted, expected_sorted);
    assert!(!listing.truncated);
}

#[test]
fn a_folder_inside_a_working_tree_is_listed_from_there() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("shop");
    fs::create_dir_all(repo.join(".git")).unwrap();
    file(&repo, "src/main.rs", "fn main() {}");
    let inner = [repo.join("src")];
    let git = FakeGit(vec![(
        repo.join("src"),
        GitFiles {
            tracked: vec!["main.rs".into()],
            untracked: vec![],
            truncated: false,
        },
    )]);
    let listing = list_files(
        &Plan {
            ai: &[],
            history: &[],
            folders: &inner,
        },
        &git,
        &ScanControl::default(),
    )
    .unwrap();
    assert_eq!(listing.files.len(), 1);
    assert_eq!(listing.files[0].path, repo.join("src/main.rs"));
}

#[test]
fn ai_histories_and_shell_histories_are_listed() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    file(home, ".claude/projects/-Users-dev-shop/abc.jsonl", "{}");
    file(
        home,
        ".claude/projects/-Users-dev-shop/abc/tool-results/1.txt",
        "out",
    );
    file(home, ".claude/projects/-Users-dev-shop/abc/shot.png", "img");
    file(home, ".claude/history.jsonl", "{}");
    file(home, "codex-home/sessions/2026/11/10/rollout-1.jsonl", "{}");
    file(home, ".zsh_history", ": 1:0;ls\n");
    let config = home.join("config");
    file(
        &config,
        "Cursor/User/globalStorage/saoudrizwan.claude-dev/tasks/1/ui_messages.json",
        "[]",
    );

    let locations = ai_locations(home, Some(&config), None, Some(&home.join("codex-home")));
    let tools = detect_ai_tools(&locations);
    let found: Vec<AiTool> = tools.iter().filter(|t| t.found).map(|t| t.tool).collect();
    assert_eq!(found, [AiTool::ClaudeCode, AiTool::Codex, AiTool::Cline]);
    assert!(tools.iter().all(|t| t.tool != AiTool::Aider));

    let history = [HistoryFile {
        shell: Shell::Zsh,
        path: home.join(".zsh_history"),
    }];
    let listing = list_files(
        &Plan {
            ai: &locations,
            history: &history,
            folders: &[],
        },
        &FakeGit(Vec::new()),
        &ScanControl::default(),
    )
    .unwrap();
    let mut names: Vec<(String, LeakPlace)> = listing
        .files
        .iter()
        .map(|f| {
            (
                f.path.strip_prefix(home).unwrap().display().to_string(),
                f.place.clone(),
            )
        })
        .collect();
    names.sort_by(|a, b| a.0.cmp(&b.0));
    let session = |tool| LeakPlace::AiSession { tool };
    assert_eq!(
        names,
        [
            (
                ".claude/history.jsonl".to_owned(),
                session(AiTool::ClaudeCode)
            ),
            (
                ".claude/projects/-Users-dev-shop/abc.jsonl".to_owned(),
                session(AiTool::ClaudeCode)
            ),
            (
                ".claude/projects/-Users-dev-shop/abc/tool-results/1.txt".to_owned(),
                session(AiTool::ClaudeCode)
            ),
            (
                ".zsh_history".to_owned(),
                LeakPlace::ShellHistory { shell: Shell::Zsh }
            ),
            (
                "codex-home/sessions/2026/11/10/rollout-1.jsonl".to_owned(),
                session(AiTool::Codex)
            ),
            (
                "config/Cursor/User/globalStorage/saoudrizwan.claude-dev/tasks/1/ui_messages.json"
                    .to_owned(),
                session(AiTool::Cline)
            ),
        ]
    );
}

/// Private keys as `ssh-keygen` and this app write them, generated here.
fn real_key(dir: &Path, name: &str, algorithm: crate::keys::GenerateAlgorithm) -> String {
    let info = crate::keys::generate(
        dir,
        &crate::keys::GenerateRequest {
            algorithm,
            file_name: name.into(),
            comment: String::new(),
            passphrase: None,
        },
    )
    .unwrap();
    fs::read_to_string(info.private_path.unwrap()).unwrap()
}

fn tracked() -> LeakPlace {
    LeakPlace::File {
        git: GitState::Tracked,
        repository: None,
    }
}

fn names_in(path: &Path, matcher: &Matcher) -> Vec<String> {
    let files = [ScanFile {
        path: path.to_path_buf(),
        place: tracked(),
        size: 0,
    }];
    let mut names: Vec<String> = scan_files(&files, matcher, &ScanControl::default())
        .unwrap()
        .findings
        .into_iter()
        .map(|f| match f.secret {
            LeakSecret::Variable { name, .. } => name,
            LeakSecret::Password { title, .. } => title,
        })
        .collect();
    names.sort();
    names
}

#[test]
fn other_keys_of_the_same_kind_are_not_leaks() {
    use crate::keys::GenerateAlgorithm::{Ed25519, Rsa};
    let dir = tempfile::tempdir().unwrap();
    let keys = dir.path().join("keys");
    fs::create_dir(&keys).unwrap();
    let deploy = real_key(&keys, "deploy", Ed25519);
    let backup = real_key(&keys, "backup", Ed25519);
    let other = real_key(&keys, "other", Ed25519);
    let rsa = real_key(&keys, "rsa", Rsa { bits: 3072 });
    let other_rsa = real_key(&keys, "other_rsa", Rsa { bits: 3072 });
    // Every unencrypted ed25519 key starts with the same line, and so does
    // every RSA-3072 key.
    assert_eq!(deploy.lines().nth(1), other.lines().nth(1));
    assert_eq!(rsa.lines().nth(1), other_rsa.lines().nth(1));

    let matcher = Matcher::new(vec![
        known("DEPLOY_KEY", &deploy),
        known("BACKUP_KEY", &backup),
        known("RSA_KEY", &rsa),
    ]);
    let none: Vec<String> = Vec::new();
    assert_eq!(names_in(&keys.join("other"), &matcher), none);
    assert_eq!(names_in(&keys.join("other_rsa"), &matcher), none);
    // This repository's own test key, made with ssh-keygen.
    let testdata = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/keys/testdata/openssh_ed25519");
    assert_eq!(names_in(&testdata, &matcher), none);
    assert_eq!(names_in(&keys.join("deploy"), &matcher), ["DEPLOY_KEY"]);
    assert_eq!(names_in(&keys.join("backup"), &matcher), ["BACKUP_KEY"]);
    assert_eq!(names_in(&keys.join("rsa"), &matcher), ["RSA_KEY"]);
    // Public keys are public.
    assert_eq!(names_in(&keys.join("deploy.pub"), &matcher), none);
    assert_eq!(names_in(&keys.join("rsa.pub"), &matcher), none);

    // A key read by an AI tool, as JSON, and inside a tool's JSON arguments.
    let session = file(
        dir.path(),
        "session.jsonl",
        &[
            serde_json::json!({ "content": deploy }).to_string(),
            serde_json::json!({ "content": other }).to_string(),
            serde_json::json!({
                "arguments": serde_json::json!({ "content": backup }).to_string()
            })
            .to_string(),
        ]
        .join("\n"),
    );
    assert_eq!(names_in(&session, &matcher), ["BACKUP_KEY", "DEPLOY_KEY"]);

    // Redacting one key leaves another key's shared lines alone.
    let before = fs::read(keys.join("other")).unwrap();
    let done = redact(&keys.join("other"), None, &matcher).unwrap();
    assert_eq!((done.replaced, done.left), (0, 0));
    assert_eq!(fs::read(keys.join("other")).unwrap(), before);
    let done = redact(&session, None, &matcher).unwrap();
    assert_eq!(done.left, 0);
    let text = fs::read_to_string(&session).unwrap();
    assert!(text.contains(other.lines().nth(2).unwrap()));
    assert!(!text.contains(deploy.lines().nth(2).unwrap()));
}

#[test]
fn putty_keys_are_found_by_their_private_lines_only() {
    use crate::keys::GenerateAlgorithm;
    use crate::keys::convert::{KeyFileFormat, convert};
    let dir = tempfile::tempdir().unwrap();
    real_key(dir.path(), "id", GenerateAlgorithm::Ed25519);
    let ppk = convert(
        &dir.path().join("id"),
        None,
        KeyFileFormat::Ppk3,
        None,
        None,
    )
    .unwrap();
    let matcher = Matcher::new(vec![known("PPK", &ppk)]);
    let none: Vec<String> = Vec::new();
    // The public lines are the `.pub` file's: no leak there.
    assert_eq!(names_in(&dir.path().join("id.pub"), &matcher), none);
    let copy = file(dir.path(), "copy.ppk", &ppk);
    assert_eq!(names_in(&copy, &matcher), ["PPK"]);
}

#[test]
fn a_file_rewritten_during_redaction_keeps_its_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chat.json");
    let v1 = format!("{{\"t\":\"1\",\"s\":\"{TOKEN}\",\"u\":\"{TOKEN}\"}}\n");
    // A tool rewrites the whole file: an earlier field grew by 2 bytes.
    let v2 = format!("{{\"t\":\"100\",\"s\":\"{TOKEN}\",\"u\":\"{TOKEN}\"}}\n");
    fs::write(&path, &v1).unwrap();
    let matcher = Matcher::new(vec![known("API_TOKEN", TOKEN)]);

    let mut handle = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let ranges = occurrence_ranges(&mut handle, &matcher).unwrap();
    assert_eq!(ranges.len(), 2);
    fs::write(&path, &v2).unwrap();
    let (replaced, skipped) = write_markers(&mut handle, &ranges, &matcher).unwrap();
    assert_eq!((replaced, skipped), (0, 2));
    let text = fs::read_to_string(&path).unwrap();
    assert_eq!(text, v2);
    serde_json::from_str::<serde_json::Value>(&text).unwrap();

    // Done again, it finds the values where they are now.
    let done = redact(&path, None, &matcher).unwrap();
    assert_eq!((done.replaced, done.skipped, done.left), (2, 0, 0));
    let text = fs::read_to_string(&path).unwrap();
    serde_json::from_str::<serde_json::Value>(&text).unwrap();
    assert!(!text.contains(TOKEN));
}

#[cfg(unix)]
#[test]
fn redaction_refuses_links_and_replaced_files() {
    let dir = tempfile::tempdir().unwrap();
    let real = file(
        dir.path(),
        "real.jsonl",
        &format!("{{\"c\":\"{TOKEN}\"}}\n"),
    );
    let matcher = Matcher::new(vec![known("API_TOKEN", TOKEN)]);
    let scanned = FileId::of(&fs::metadata(&real).unwrap());

    let link = dir.path().join("link.jsonl");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let refused = redact(&link, None, &matcher).unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::InvalidData);

    // Replaced since the scan, as tools that save by renaming do.
    let new = file(dir.path(), "new.jsonl", &format!("{{\"c\":\"{TOKEN}\"}}\n"));
    fs::rename(&new, &real).unwrap();
    let refused = redact(&real, scanned, &matcher).unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::InvalidData);
    assert!(fs::read_to_string(&real).unwrap().contains(TOKEN));

    let now = FileId::of(&fs::metadata(&real).unwrap());
    assert_eq!(redact(&real, now, &matcher).unwrap().replaced, 1);
}

#[test]
fn findings_remember_the_file_for_redaction_but_never_show_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = file(dir.path(), "s.jsonl", TOKEN);
    let found = scan(&path, ai());
    assert_eq!(found[0].file, FileId::of(&fs::metadata(&path).unwrap()));
    let json = serde_json::to_value(&found[0]).unwrap();
    assert!(json.get("file").is_none());
}
