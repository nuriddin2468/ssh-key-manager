use std::fmt::Write as _;

use super::invocation::{self, Target};
use super::words::{Dialect, Word, commands};
use super::*;
use crate::config::SshConfig;

/// `user@host:port -i key -J jump -A -o Key=value`, IPv6 in brackets.
fn render(target: &Target) -> String {
    let mut out = String::new();
    if let Some(user) = &target.user {
        out.push_str(user);
        out.push('@');
    }
    if target.host.contains(':') {
        let _ = write!(out, "[{}]", target.host);
    } else {
        out.push_str(&target.host);
    }
    if let Some(port) = target.port {
        let _ = write!(out, ":{port}");
    }
    for file in &target.identity_files {
        let _ = write!(out, " -i {file}");
    }
    if let Some(jump) = &target.proxy_jump {
        let _ = write!(out, " -J {jump}");
    }
    if target.forward_agent {
        out.push_str(" -A");
    }
    for option in &target.options {
        let _ = write!(out, " -o {}={}", option.key, option.value);
    }
    out
}

fn found(line: &str, dialect: Dialect) -> (Vec<String>, u32) {
    let found = invocation::find(line, dialect);
    (found.targets.iter().map(render).collect(), found.secrets)
}

fn check(dialect: Dialect, cases: &[(&str, &[&str])]) {
    for (line, expected) in cases {
        let (targets, secrets) = found(line, dialect);
        assert_eq!(targets, *expected, "{line}");
        assert_eq!(secrets, 0, "{line}");
    }
}

fn word(text: &str, literal: bool) -> Word {
    Word {
        text: text.to_owned(),
        literal,
    }
}

#[test]
fn words_follow_posix_quoting() {
    let cases: &[(&str, &[&[Word]])] = &[
        (
            r#"ssh 'a b'"c\"d"e\ f"#,
            &[&[word("ssh", true), word("a bc\"de f", true)]],
        ),
        (
            "ssh $'x\\'y' ''",
            &[&[word("ssh", true), word("x'y", true), word("", true)]],
        ),
        (
            "a; b && c || d | e & f",
            &[
                &[word("a", true)],
                &[word("b", true)],
                &[word("c", true)],
                &[word("d", true)],
                &[word("e", true)],
                &[word("f", true)],
            ],
        ),
        (
            "ssh h 2>&1 >/dev/null </tmp/in 2> err",
            &[&[word("ssh", true), word("h", true)]],
        ),
        (
            "ssh $HOST \"$USER\"@h '$LITERAL' $(hostname) `id` h* ~/k",
            &[&[
                word("ssh", true),
                word("$HOST", false),
                word("$USER@h", false),
                word("$LITERAL", true),
                word("$(hostname)", false),
                word("`id`", false),
                word("h*", false),
                word("~/k", true),
            ]],
        ),
        (
            "# ssh commented\nssh h",
            &[&[word("ssh", true), word("h", true)]],
        ),
        ("ssh a#b", &[&[word("ssh", true), word("a#b", true)]]),
        (
            "ssh \\\n  -p 1 h",
            &[&[
                word("ssh", true),
                word("-p", true),
                word("1", true),
                word("h", true),
            ]],
        ),
    ];
    for (line, expected) in cases {
        let expected: Vec<Vec<Word>> = expected.iter().map(|c| c.to_vec()).collect();
        assert_eq!(commands(line, Dialect::Posix), expected, "{line}");
    }
}

#[test]
fn words_follow_fish_and_powershell_quoting() {
    assert_eq!(
        commands(r"ssh 'it\'s' (hostname) h", Dialect::Fish),
        vec![vec![
            word("ssh", true),
            word("it's", true),
            word("(hostname)", false),
            word("h", true),
        ]]
    );
    assert_eq!(
        commands(
            r"ssh -i C:\Users\me\.ssh\id 'it''s' a`$b",
            Dialect::PowerShell
        ),
        vec![vec![
            word("ssh", true),
            word("-i", true),
            word(r"C:\Users\me\.ssh\id", true),
            word("it's", true),
            word("a$b", true),
        ]]
    );
    assert_eq!(
        commands("ssh `\n  -p 1 h; ssh \"$env:H\"", Dialect::PowerShell),
        vec![
            vec![
                word("ssh", true),
                word("-p", true),
                word("1", true),
                word("h", true)
            ],
            vec![word("ssh", true), word("$env:H", false)],
        ]
    );
}

#[test]
#[allow(clippy::too_many_lines, reason = "a table")]
fn reads_ssh_invocations() {
    check(
        Dialect::Posix,
        &[
            ("ssh host", &["host"]),
            ("ssh root@10.0.0.5", &["root@10.0.0.5"]),
            ("ssh -p 2222 root@10.0.0.5", &["root@10.0.0.5:2222"]),
            ("ssh -p2222 root@10.0.0.5", &["root@10.0.0.5:2222"]),
            ("ssh -vvAp2222 host", &["host:2222 -A"]),
            ("ssh -vvA -p 2222 host", &["host:2222 -A"]),
            // `ssh` reads options after the destination too, up to the command.
            ("ssh root@10.0.0.5 -p 2222", &["root@10.0.0.5:2222"]),
            ("ssh host ls -p 3333", &["host"]),
            ("ssh -- host -p 2222", &["host"]),
            ("ssh -p 2222 -- host", &["host:2222"]),
            // The first user wins, as in `ssh`.
            ("ssh -l admin host", &["admin@host"]),
            ("ssh -l admin bob@host", &["admin@host"]),
            ("ssh bob@host -l admin", &["bob@host"]),
            ("ssh host -l admin", &["admin@host"]),
            ("ssh -p 2200 -p 2300 host", &["host:2200"]),
            ("ssh me@corp.example@host", &["me@corp.example@host"]),
            (
                "ssh -i ~/.ssh/id_work -J jump@bastion:2200 deploy@app",
                &["deploy@app -i ~/.ssh/id_work -J jump@bastion:2200"],
            ),
            (
                "ssh -i '/Users/me/My Keys/id' -i ~/.ssh/b host",
                &["host -i /Users/me/My Keys/id -i ~/.ssh/b"],
            ),
            ("ssh \"user@host\"", &["user@host"]),
            ("ssh 'user'@\"host\"", &["user@host"]),
            ("ssh user@host 'cat /etc/passwd'", &["user@host"]),
            (
                "ssh -o Port=2022 -o User=ops -o ServerAliveInterval=30 host",
                &["ops@host:2022 -o ServerAliveInterval=30"],
            ),
            (
                "ssh -o 'ServerAliveInterval 60' -o StrictHostKeyChecking=no \
                 -o UserKnownHostsFile=/dev/null -o serveraliveinterval=5 host",
                &["host -o ServerAliveInterval=60"],
            ),
            (
                "ssh -o ForwardAgent=yes -o IdentityFile=~/.ssh/k h",
                &["h -i ~/.ssh/k -A"],
            ),
            ("ssh -o ProxyCommand='nc %h %p' -o LocalCommand=x h", &["h"]),
            (
                "ssh -X -Y -C -N -T -f -4 -L 8080:localhost:80 -D 1080 h",
                &["h"],
            ),
            (
                "ssh -J ssh://ops@bastion:2222,10.0.0.2 app",
                &["app -J ssh://ops@bastion:2222,10.0.0.2"],
            ),
            ("ssh ssh://root@10.0.0.5:2222", &["root@10.0.0.5:2222"]),
            ("ssh SSH://h", &["h"]),
            ("ssh ssh://h/path", &[]),
            // IPv6.
            ("ssh ssh://[::1]:2222", &["[::1]:2222"]),
            ("ssh root@[::1]", &["root@[::1]"]),
            ("ssh -p 2222 ::1", &["[::1]:2222"]),
            ("ssh fe80::1%en0", &["[fe80::1%en0]"]),
            ("ssh [::1]:22", &[]),
            // Not a form `ssh` understands.
            ("ssh root@10.0.0.5:2222", &[]),
            ("ssh @host", &[]),
            ("ssh user@", &[]),
            ("ssh -host", &[]),
            // Another server, config or no connection at all.
            ("ssh -o HostName=10.1.1.1 alias", &[]),
            ("ssh -F other.conf host", &[]),
            ("ssh -V", &[]),
            ("ssh -Q cipher", &[]),
            ("ssh -G host", &[]),
            ("ssh -O exit host", &[]),
            ("ssh -p http host", &[]),
            ("ssh -p 0 host", &[]),
            ("ssh -p 70000 host", &[]),
            ("ssh -Z host", &[]),
            ("ssh host -p", &[]),
            // Expansions are not made.
            ("ssh $HOST", &[]),
            ("ssh \"$USER\"@host", &[]),
            ("ssh -l $USER host", &[]),
            ("ssh -p $PORT host", &[]),
            ("ssh -i $KEY host", &["host"]),
            ("ssh $(cat host)", &[]),
            ("ssh `cat host`", &[]),
            ("ssh web{1,2}", &[]),
            ("ssh host*", &[]),
            ("ssh 'bad host'", &[]),
            ("ssh 'host;rm'", &[]),
            // Commands around it.
            (
                "cd /tmp && ssh a; ssh b || ssh c | tee log",
                &["a", "b", "c"],
            ),
            ("ssh a 2>/dev/null >log; ssh b &>/dev/null", &["a", "b"]),
            ("{ ssh a; }", &["a"]),
            ("if true; then ssh a; fi", &["a"]),
            ("while true; do ssh a; done", &["a"]),
            ("(ssh a)", &["a"]),
            ("ssh a # a note", &["a"]),
            ("ssh \\\n  -p 2222 a", &["a:2222"]),
            // Wrappers.
            ("sudo -u deploy ssh a", &["a"]),
            ("sudo -E TERM=xterm ssh a", &["a"]),
            ("env -i TERM=xterm ssh a", &["a"]),
            ("TERM=xterm-256color ssh a", &["a"]),
            ("time nohup nice -n 5 ssh a", &["a"]),
            ("timeout -s INT 10 ssh a", &["a"]),
            ("proxychains4 -q -f p.conf ssh a", &["a"]),
            ("command ssh a", &["a"]),
            ("/usr/bin/ssh a", &["a"]),
            ("\\ssh a", &["a"]),
            ("SSH.EXE a", &["a"]),
            (
                "nohup autossh -M 20000 -f -N -L 8080:localhost:80 tunnel@host",
                &["tunnel@host"],
            ),
            ("autossh -M0 -p 2200 host", &["host:2200"]),
            // Not `ssh`.
            ("echo ssh a", &[]),
            ("man ssh", &[]),
            ("git clone ssh://git@github.com/x/y", &[]),
            ("sshfs a:/ /mnt", &[]),
            ("ssh-keygen -R a", &[]),
            ("ssh-copy-id a", &[]),
            ("ssh", &[]),
        ],
    );
}

#[test]
fn reads_scp_sftp_and_mosh() {
    check(
        Dialect::Posix,
        &[
            (
                "scp -P 2222 -i key file.txt root@10.0.0.5:/tmp/",
                &["root@10.0.0.5:2222 -i key"],
            ),
            ("scp -P2222 file host:", &["host:2222"]),
            ("scp -r ./dir user@[::1]:/srv", &["user@[::1]"]),
            ("scp [::1]:/etc/hosts .", &["[::1]"]),
            ("scp alpha:x beta:y .", &["alpha", "beta"]),
            // A drive letter, not a host.
            ("scp C:/file h:", &["h"]),
            ("scp -3 u@a:x u@b:", &["u@a", "u@b"]),
            ("scp -l 100 file host:", &["host"]),
            ("scp -o User=ops f host:", &["ops@host"]),
            ("scp file ./local:name /abs:x", &[]),
            ("scp :colon file", &[]),
            (
                "scp scp://admin@host:2200/etc/hosts .",
                &["admin@host:2200"],
            ),
            ("scp -P 22 f scp://h:2200/x", &["h:22"]),
            ("scp -F cfg f h:", &[]),
            ("scp -- -file h:", &["h"]),
            ("sftp -P 2222 admin@host", &["admin@host:2222"]),
            ("sftp backup@nas:/volume1", &["backup@nas"]),
            ("sftp nas", &["nas"]),
            ("sftp [::1]", &["[::1]"]),
            (
                "sftp sftp://admin@[2001:db8::1]:2200/srv",
                &["admin@[2001:db8::1]:2200"],
            ),
            ("sftp -b batch.txt -i ~/.ssh/k h", &["h -i ~/.ssh/k"]),
            ("mosh root@host", &["root@host"]),
            ("mosh -a -p 60001 host tmux attach", &["host"]),
            (
                "mosh --ssh='ssh -p 2222 -i ~/.ssh/id_mosh' root@host -- tmux a",
                &["root@host:2222 -i ~/.ssh/id_mosh"],
            ),
            (
                "mosh --ssh \"ssh -p 2200\" --predict=always host",
                &["host:2200"],
            ),
            ("mosh --port=60001 -- host", &["host"]),
            ("mosh host:2200", &[]),
        ],
    );
}

#[test]
fn reads_powershell_and_fish_commands() {
    check(
        Dialect::PowerShell,
        &[
            ("ssh -p 2222 admin@win-server", &["admin@win-server:2222"]),
            (
                r"ssh -i C:\Users\me\.ssh\id_ed25519 admin@db",
                &[r"admin@db -i C:\Users\me\.ssh\id_ed25519"],
            ),
            (r"scp C:\Users\me\f.txt admin@win:C:/tmp", &["admin@win"]),
            (r"& 'C:\Program Files\OpenSSH\ssh.exe' h", &["h"]),
            ("ssh.exe h; Get-ChildItem", &["h"]),
            ("if ($ok) { ssh h }", &["h"]),
            ("ssh $server", &[]),
        ],
    );
    check(
        Dialect::Fish,
        &[
            ("ssh h; and ssh i; or ssh j", &["h", "i", "j"]),
            ("not ssh h", &["h"]),
            ("begin; ssh h; end", &["h"]),
            ("ssh (cat host)", &[]),
            ("ssh $host", &[]),
        ],
    );
}

#[test]
fn counts_and_drops_passwords() {
    let cases: &[(&str, &[&str], u32)] = &[
        (
            "sshpass -p 'hunter2' ssh root@10.0.0.5",
            &["root@10.0.0.5"],
            1,
        ),
        ("sshpass -phunter2 scp f root@host:/tmp", &["root@host"], 1),
        ("sshpass -v -p hunter2 -- ssh h", &["h"], 1),
        ("sshpass -f ~/.pw ssh h", &["h"], 0),
        ("SSHPASS=hunter2 sshpass -e ssh h", &["h"], 1),
        ("MY_PASSWORD=hunter2 ssh h", &["h"], 1),
        // Not a command of the `ssh` family: not this feature's business.
        ("DB_PASSWORD=hunter2 make deploy", &[], 0),
        ("ssh ssh://root:hunter2@h", &["root@h"], 1),
        ("ssh -p 2222 ssh://root:hunter2@h:22", &["root@h:2222"], 1),
        ("sftp sftp://u:p%40ss@h/x", &["u@h"], 1),
        ("scp f scp://u:hunter2@h/x", &["u@h"], 1),
        (
            "ssh -J ssh://ops:hunter2@bastion app",
            &["app -J ssh://ops@bastion"],
            1,
        ),
        (
            "ssh -o ProxyCommand='sshpass -p hunter2 ssh -W %h:%p jump' h",
            &["h"],
            1,
        ),
        ("ssh -o Password=hunter2 h", &["h"], 1),
        ("ssh -o 'pass hunter2' h", &["h"], 1),
        ("ssh -o SetEnv=API_TOKEN=hunter2 h", &["h"], 1),
        ("ssh -o SetEnv=LANG=C h", &["h"], 0),
        ("mosh --ssh='sshpass -p hunter2 ssh' h", &["h"], 1),
        (
            "ssh -o PasswordAuthentication=no h",
            &["h -o PasswordAuthentication=no"],
            0,
        ),
    ];
    for (line, expected, secrets) in cases {
        let found = invocation::find(line, Dialect::Posix);
        let targets: Vec<String> = found.targets.iter().map(render).collect();
        assert_eq!(targets, *expected, "{line}");
        assert_eq!(found.secrets, *secrets, "{line}");
        assert!(
            targets
                .iter()
                .all(|t| !t.contains("hunter2") && !t.contains("p%40ss")),
            "{line}"
        );
    }
}

#[test]
fn reads_zsh_history() {
    let mut bytes = b": 1700000000:0;ssh -p 2222 root@10.0.0.5\n\
: 1700000100:5;echo one\\\nssh two\n\
plain command\n\
: 1700000200:0;echo "
        .to_vec();
    // zsh writes `ф` (D1 84) as D1, then 0x83 and 0x84 ^ 32.
    bytes.extend_from_slice(b"\xd1\x83\xa4\n");
    let entries = formats::zsh(&bytes);
    let texts: Vec<(&str, Option<i64>)> =
        entries.iter().map(|e| (e.text.as_str(), e.when)).collect();
    assert_eq!(
        texts,
        [
            ("ssh -p 2222 root@10.0.0.5", Some(1_700_000_000)),
            ("echo one\nssh two", Some(1_700_000_100)),
            ("plain command", None),
            ("echo ф", Some(1_700_000_200)),
        ]
    );
}

#[test]
fn reads_bash_history() {
    let entries = formats::bash(b"ssh old\n#1700000000\nssh a\nls\n#1700000500\r\nssh b\r\n#\n");
    let texts: Vec<(&str, Option<i64>)> =
        entries.iter().map(|e| (e.text.as_str(), e.when)).collect();
    assert_eq!(
        texts,
        [
            ("ssh old", None),
            ("ssh a", Some(1_700_000_000)),
            ("ls", Some(1_700_000_000)),
            ("ssh b", Some(1_700_000_500)),
            ("#", Some(1_700_000_500)),
        ]
    );
}

#[test]
fn reads_fish_history() {
    let entries = formats::fish(
        b"- cmd: ssh -p 2222 root@10.0.0.5\n  when: 1700000000\n\
- cmd: echo a\\nssh b \\\\ c\n  when: 1700000001\n  paths:\n    - /tmp\n\
- cmd: ls\n",
    );
    let texts: Vec<(&str, Option<i64>)> =
        entries.iter().map(|e| (e.text.as_str(), e.when)).collect();
    assert_eq!(
        texts,
        [
            ("ssh -p 2222 root@10.0.0.5", Some(1_700_000_000)),
            ("echo a\nssh b \\ c", Some(1_700_000_001)),
            ("ls", None),
        ]
    );
}

#[test]
fn reads_powershell_history() {
    let entries = formats::powershell(
        "\u{feff}ssh -p 2222 admin@win\r\nGet-ChildItem `\r\n  -Recurse\r\nssh -i k ``\r\n-p 2200 admin@db\r\n"
            .as_bytes(),
    );
    let texts: Vec<&str> = entries.iter().map(|e| e.text.as_str()).collect();
    assert_eq!(
        texts,
        [
            "ssh -p 2222 admin@win",
            "Get-ChildItem \n  -Recurse",
            "ssh -i k `\n-p 2200 admin@db",
        ]
    );
    let found = invocation::find(texts[2], Dialect::PowerShell);
    assert_eq!(
        found.targets.iter().map(render).collect::<Vec<_>>(),
        ["admin@db:2200 -i k"]
    );
}

#[test]
fn finds_the_usual_history_files() {
    let home = Path::new("/home/me");
    let files = history_files(home, None, None);
    let paths: Vec<(Shell, PathBuf)> = files.into_iter().map(|f| (f.shell, f.path)).collect();
    assert_eq!(
        paths,
        [
            (Shell::Zsh, home.join(".zsh_history")),
            (Shell::Bash, home.join(".bash_history")),
            (Shell::Fish, home.join(".local/share/fish/fish_history")),
            (
                Shell::PowerShell,
                home.join(".local/share/powershell/PSReadLine/ConsoleHost_history.txt")
            ),
        ]
    );
    let windows = history_files(home, Some(Path::new("/x")), Some(Path::new("/roaming")));
    assert_eq!(windows[2].path, Path::new("/x/fish/fish_history"));
    assert_eq!(
        windows[3].path,
        Path::new("/roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt")
    );
}

fn prefs() -> HistoryPrefs {
    let mut prefs = HistoryPrefs::default();
    prefs.set_enabled(true);
    prefs
}

fn file(shell: Shell, text: &str) -> (Shell, String, Vec<u8>) {
    (
        shell,
        format!("/home/me/{shell:?}"),
        text.as_bytes().to_vec(),
    )
}

#[test]
fn groups_targets_and_counts_uses() {
    let files = [
        file(
            Shell::Zsh,
            ": 1700000000:0;ssh -p 2222 root@10.0.0.5\n\
             : 1700000300:0;ssh -p 2222 -i ~/.ssh/new root@10.0.0.5 uptime\n\
             : 1700000100:0;ssh -p2222 -i ~/.ssh/old -o ServerAliveInterval=30 root@10.0.0.5\n\
             : 1700000200:0;scp -P 2222 f root@10.0.0.5:/tmp && ssh -p 22 web\n",
        ),
        file(
            Shell::Bash,
            "ssh -p 2222 root@10.0.0.5\nssh web\nssh -A WEB\n",
        ),
    ];
    let scan = scan_contents(&files, &[], &prefs());
    let summary: Vec<(String, u32, Option<&str>)> = scan
        .suggestions
        .iter()
        .map(|s| (s.alias.clone(), s.uses, s.last_used.as_deref()))
        .collect();
    assert_eq!(
        summary,
        [
            ("root-10-0-0-5".to_owned(), 5, Some("2023-11-14T22:18:20Z")),
            ("web".to_owned(), 3, Some("2023-11-14T22:16:40Z")),
        ]
    );
    let root = &scan.suggestions[0];
    assert_eq!(root.user.as_deref(), Some("root"));
    assert_eq!(root.port, Some(2222));
    // The newest command's key; options it didn't give come from older ones.
    assert_eq!(root.identity_file.as_deref(), Some("~/.ssh/new"));
    assert_eq!(root.options, [HostOption::new("ServerAliveInterval", "30")]);
    assert_eq!(root.shells, [Shell::Zsh, Shell::Bash]);
    let web = &scan.suggestions[1];
    assert_eq!(
        (web.host.as_str(), web.port, web.forward_agent),
        ("web", None, true)
    );
    assert_eq!(scan.files.len(), 2);
    assert!(scan.files.iter().all(|f| f.secrets == 0));
}

#[test]
fn leaves_out_hosts_the_config_has() {
    let config = SshConfig::parse(
        "Host web w\n  HostName 10.0.0.7\n  User deploy\n  Port 2200\n\
         Host db.example.com\n\
         Host *.corp !skip\n  User x\n",
    );
    let files = [file(
        Shell::Bash,
        "ssh w\n\
         ssh deploy@10.0.0.7 -p 2200\n\
         ssh -p 2200 10.0.0.7\n\
         ssh DB.example.com\n\
         ssh root@10.0.0.7 -p 2200\n\
         ssh deploy@10.0.0.7\n\
         ssh a.corp\n\
         ssh skip\n",
    )];
    let scan = scan_contents(&files, &config.hosts(), &prefs());
    let left: Vec<String> = scan
        .suggestions
        .iter()
        .map(|s| {
            let user = s
                .user
                .as_deref()
                .map(|u| format!("{u}@"))
                .unwrap_or_default();
            let port = s.port.map(|p| format!(":{p}")).unwrap_or_default();
            format!("{user}{}{port}", s.host)
        })
        .collect();
    assert_eq!(
        left,
        ["deploy@10.0.0.7", "root@10.0.0.7:2200", "a.corp", "skip"]
    );
}

#[test]
fn suggests_aliases_no_block_uses() {
    let config = SshConfig::parse("Host web1\n  HostName 10.9.9.9\n");
    let files = [file(
        Shell::Bash,
        "ssh web1.prod.example.com\n\
         ssh git@ssh.github.com\n\
         ssh root@10.0.0.5\n\
         ssh 2001:db8::1\n\
         ssh deploy@web1.staging.example.com\n\
         ssh -p 2200 deploy@web1.staging.example.com\n\
         ssh ssh.example.com\n",
    )];
    let scan = scan_contents(&files, &config.hosts(), &prefs());
    let mut aliases: Vec<(String, String)> = scan
        .suggestions
        .iter()
        .map(|s| {
            let port = s.port.map(|p| format!(":{p}")).unwrap_or_default();
            (format!("{}{port}", s.host), s.alias.clone())
        })
        .collect();
    aliases.sort();
    assert_eq!(
        aliases,
        [
            ("10.0.0.5", "root-10-0-0-5"),
            ("2001:db8::1", "host-2001-db8-1"),
            ("ssh.example.com", "example"),
            ("ssh.github.com", "github"),
            ("web1.prod.example.com", "web1-2"),
            ("web1.staging.example.com", "web1-deploy"),
            ("web1.staging.example.com:2200", "web1-2200"),
        ]
        .map(|(a, b)| (a.to_owned(), b.to_owned()))
    );
}

#[test]
fn dismissed_targets_stay_hidden_by_hash() {
    let files = [file(Shell::Bash, "ssh a\nssh b\nssh b\n")];
    let mut prefs = prefs();
    let first = scan_contents(&files, &[], &prefs);
    assert_eq!(first.suggestions.len(), 2);
    let b = first.suggestions[0].id.clone();
    assert_eq!(first.suggestions[0].host, "b");
    assert_eq!(b.len(), 32);
    // The same target has the same id in every scan.
    assert_eq!(scan_contents(&files, &[], &prefs).suggestions[0].id, b);

    prefs.dismiss(&b).unwrap();
    prefs.dismiss(&b).unwrap();
    let after = scan_contents(&files, &[], &prefs);
    assert_eq!(after.suggestions.len(), 1);
    assert_eq!(after.suggestions[0].host, "a");
    assert_eq!(after.dismissed, 1);
    assert_eq!(prefs.status().dismissed, 1);
    let json = serde_json::to_string(&prefs).unwrap();
    assert!(!json.contains("\"b\""), "{json}");

    prefs.forget_dismissed();
    assert_eq!(scan_contents(&files, &[], &prefs).suggestions.len(), 2);

    assert!(prefs.dismiss("not-an-id").is_err());
    // Another key, other ids.
    assert_ne!(
        scan_contents(&files, &[], &self::prefs()).suggestions[0].id,
        b
    );
}

#[test]
fn passes_on_neither_commands_nor_passwords() {
    let files = [
        file(
            Shell::Zsh,
            ": 1700000000:0;sshpass -p hunter2 ssh root@10.0.0.5 'cat /etc/shadow'\n\
             : 1700000001:0;ssh ssh://root:hunter2@10.0.0.5 rm -rf /tmp/x\n\
             : 1700000002:0;ssh -o ProxyCommand='sshpass -p hunter2 ssh -W %h:%p j' h\n\
             : 1700000003:0;ssh h tmux attach -t secret-session\n",
        ),
        file(Shell::Bash, "ssh h\n"),
    ];
    let scan = scan_contents(&files, &[], &prefs());
    let json = serde_json::to_string(&scan).unwrap();
    for leak in [
        "hunter2",
        "shadow",
        "rm -rf",
        "tmux",
        "secret-session",
        "ProxyCommand",
        "%h",
    ] {
        assert!(!json.contains(leak), "{leak} in {json}");
    }
    assert_eq!(
        scan.files.iter().map(|f| f.secrets).collect::<Vec<_>>(),
        [3, 0]
    );
    assert_eq!(scan.suggestions.len(), 2);
}

#[test]
fn reads_files_that_exist() {
    let dir = tempfile::tempdir().unwrap();
    let zsh = dir.path().join(".zsh_history");
    fs::write(&zsh, ": 1700000000:0;ssh a\n").unwrap();
    let files = history_files(dir.path(), None, None);
    let scan = scan(&files, &[], &prefs());
    assert_eq!(scan.files.len(), 1);
    assert_eq!(scan.files[0].shell, Shell::Zsh);
    assert_eq!(scan.suggestions[0].host, "a");
}

#[test]
fn prefs_are_kept_in_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data").join("shell-history.json");
    let loaded = HistoryPrefs::load(&path);
    assert_eq!(loaded.status().consent, HistoryConsent::Unasked);
    assert!(!loaded.enabled());

    let mut prefs = HistoryPrefs::default();
    prefs.set_enabled(true);
    prefs.dismiss(&"a".repeat(32)).unwrap();
    prefs.save(&path).unwrap();
    let loaded = HistoryPrefs::load(&path);
    assert_eq!(loaded, prefs);
    assert_eq!(
        loaded.status(),
        HistoryStatus {
            consent: HistoryConsent::On,
            dismissed: 1
        }
    );

    let mut off = loaded.clone();
    off.set_enabled(false);
    assert_eq!(off.status().consent, HistoryConsent::Off);
    // Turning it on again keeps the key, so dismissed ids still match.
    off.set_enabled(true);
    assert_eq!(off, loaded);

    fs::write(&path, b"{not json").unwrap();
    assert_eq!(HistoryPrefs::load(&path), HistoryPrefs::default());
}
