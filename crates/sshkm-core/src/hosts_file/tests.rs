use time::macros::datetime;

use super::*;
use crate::ErrorCode;

const SAMPLE: &str = "\u{feff}##\n\
     # Host Database\n\
     #\n\
     127.0.0.1\tlocalhost\n\
     255.255.255.255\tbroadcasthost\n\
     ::1             localhost\n\
     fe80::1%lo0\tlocalhost\n\
     \n\
     10.0.4.12   api.internal  API.internal.  # staging API\n\
     # 10.0.4.13 old-api.internal\n\
     ## 192.168.1.5 nas.local nas # the NAS\n\
     # localhost is used to configure the loopback interface\n\
     10.0.9.9 api.internal\n\
     0.0.0.0 ads.example.com\n\
     100.101.102.103 tailnet-box\n\
     140.82.112.3 github.com\n\
     300.1.1.1 broken.example\n\
     10.0.0.1\n\
     10.0.0.2 bad/name\n\
     fe80::1% nowhere\n\
     \t  # indented comment\n\
     ::ffff:10.0.0.1 mapped";

fn sample() -> HostsFile {
    HostsFile::parse(SAMPLE)
}

fn lines(entries: &[HostsFileEntry]) -> Vec<u32> {
    entries.iter().map(|e| e.line).collect()
}

#[test]
fn round_trips() {
    for input in [
        SAMPLE.to_owned(),
        SAMPLE.replace('\n', "\r\n"),
        format!("{SAMPLE}\n"),
        String::new(),
    ] {
        assert_eq!(HostsFile::parse(&input).to_string(), input);
    }
}

#[test]
fn parses_entries() {
    let entries = sample().entries();
    assert_eq!(lines(&entries), [4, 5, 6, 7, 9, 10, 11, 13, 14, 15, 16, 22]);
    let by_line = |line| entries.iter().find(|e| e.line == line).unwrap();

    let localhost = by_line(4);
    assert_eq!(localhost.names, ["localhost"]);
    assert!(localhost.enabled && localhost.system);
    assert_eq!(localhost.kind, HostsAddressKind::Loopback);
    assert_eq!(by_line(5).kind, HostsAddressKind::Private);
    assert!(by_line(5).system);
    assert_eq!(by_line(7).address, "fe80::1%lo0");
    assert!(by_line(7).is_ipv6() && !by_line(4).is_ipv6());

    let api = by_line(9);
    assert_eq!(api.names, ["api.internal", "API.internal."]);
    assert_eq!(api.comment.as_deref(), Some("staging API"));
    assert_eq!(api.kind, HostsAddressKind::Private);
    assert!(!api.system);
    assert_eq!(api.group, None);

    let off = by_line(10);
    assert!(!off.enabled);
    assert_eq!(off.names, ["old-api.internal"]);
    let nas = by_line(11);
    assert!(!nas.enabled);
    assert_eq!(nas.names, ["nas.local", "nas"]);
    assert_eq!(nas.comment.as_deref(), Some("the NAS"));

    assert_eq!(by_line(14).kind, HostsAddressKind::Blocked);
    assert_eq!(by_line(15).kind, HostsAddressKind::Private, "CGNAT range");
    assert_eq!(by_line(16).kind, HostsAddressKind::Public);
    assert_eq!(by_line(22).kind, HostsAddressKind::Public);
}

#[test]
fn reports_invalid_lines() {
    let invalid: Vec<_> = sample()
        .invalid_lines()
        .into_iter()
        .map(|i| (i.line, i.problem))
        .collect();
    assert_eq!(
        invalid,
        [
            (17, HostsLineProblem::BadAddress),
            (18, HostsLineProblem::NoNames),
            (19, HostsLineProblem::BadName),
            (20, HostsLineProblem::BadAddress),
        ]
    );
}

#[test]
fn earlier_lines_shadow_later_ones_per_family() {
    let entries = sample().entries();
    let shadowed = |line| {
        entries
            .iter()
            .find(|e| e.line == line)
            .unwrap()
            .shadowed
            .clone()
    };
    // Line 9 lists the name twice (case and final dot differ).
    assert_eq!(shadowed(9), ["API.internal."]);
    assert_eq!(shadowed(13), ["api.internal"]);
    // IPv6 localhost lines: the first one counts, the scoped one does not.
    assert_eq!(shadowed(6), Vec::<String>::new());
    assert_eq!(shadowed(7), ["localhost"]);
    // Turned-off entries never shadow or get shadowed.
    assert_eq!(shadowed(10), Vec::<String>::new());
}

#[test]
fn lookup() {
    let hosts = sample();
    assert_eq!(lines(&hosts.lookup("API.Internal")), [9, 13]);
    assert_eq!(lines(&hosts.lookup("api.internal.")), [9, 13]);
    assert_eq!(lines(&hosts.lookup("localhost")), [4, 6, 7]);
    assert_eq!(lines(&hosts.lookup("old-api.internal")), Vec::<u32>::new());
    assert_eq!(lines(&hosts.lookup("nowhere")), Vec::<u32>::new());
}

#[test]
fn names() {
    let longest_label = "a".repeat(63);
    let long_label = "a".repeat(64);
    let long_name = ["a"; 128].join(".");
    for good in ["a", "a.b", "a-b_c.example.", "x1", longest_label.as_str()] {
        assert!(is_valid_name(good), "{good}");
    }
    for bad in [
        "",
        ".",
        "a..b",
        ".a",
        "a b",
        "a/b",
        "ünï.example",
        long_label.as_str(),
        long_name.as_str(),
    ] {
        assert!(!is_valid_name(bad), "{bad}");
    }
    assert_eq!(normalize_name("Git.Example.COM."), "git.example.com");
}

#[test]
fn parsing_is_total() {
    for line in [
        "#",
        "# #",
        "%",
        "::",
        ":: #",
        "1.2.3.4 #x",
        "# 1.2.3.4",
        "\u{feff}",
        "# >>> sshkm:",
        "# <<<",
    ] {
        let _ = parse_line(line);
    }
    assert!(matches!(parse_line(":: x"), LineKind::Entry { .. }));
    assert!(matches!(parse_line("# >>> sshkm:"), LineKind::Blank));
}

#[test]
fn load_missing_and_lossy() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hosts");
    let missing = HostsFile::load(&path).unwrap();
    assert_eq!(missing.entries(), []);
    assert_eq!(missing.revision(), HostsFile::parse("").revision());
    // "10.0.0.1 box # сервер" in Windows-1251.
    let mut bytes = b"10.0.0.1 box # ".to_vec();
    bytes.extend_from_slice(&[0xf1, 0xe5, 0xf0, 0xe2, 0xe5, 0xf0]);
    fs::write(&path, &bytes).unwrap();
    let file = HostsFile::load(&path).unwrap();
    assert_eq!(file.entries()[0].names, ["box"]);
    assert_eq!(file.read_only_reason(&path), Some(HostsReadOnly::NotUtf8));
    assert_eq!(file.revision(), revision_of(&bytes));
}

#[cfg(unix)]
#[test]
fn a_linked_file_is_read_only() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    let link = dir.path().join("hosts");
    fs::write(&real, "10.0.0.1 box\n").unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let file = HostsFile::load(&link).unwrap();
    assert_eq!(file.read_only_reason(&link), Some(HostsReadOnly::Link));
}

#[test]
fn system_path_is_absolute() {
    assert!(system_path().is_absolute());
    assert!(system_path().ends_with("hosts"));
}

#[test]
fn view_serializes() {
    let v = serde_json::to_value(sample().view()).unwrap();
    assert_eq!(v["entries"][0]["kind"], "loopback");
    assert_eq!(v["entries"][0]["enabled"], true);
    assert_eq!(v["entries"][8]["kind"], "blocked");
    assert_eq!(v["invalid"][0]["problem"], "badAddress");
    assert_eq!(v["groups"], serde_json::json!([]));
}

const GROUPED: &str = "127.0.0.1\tlocalhost\n\
     10.0.0.1\tloose.internal\n\
     \n\
     # >>> sshkm: Staging\n\
     10.0.8.20\tapi.staging # behind the VPN\n\
     # 10.0.8.21\tdb.staging\n\
     # <<< sshkm: Staging\n\
     # >>> sshkm: Demo\n\
     10.0.9.1\tdemo.local # sshkm-until=2026-11-02T19:00:00Z\n";

#[test]
fn groups_and_expiry() {
    let file = HostsFile::parse(GROUPED);
    assert_eq!(
        file.groups(),
        [
            HostsGroup {
                name: "Staging".into(),
                line: 4,
                end_line: Some(7)
            },
            HostsGroup {
                name: "Demo".into(),
                line: 8,
                end_line: None
            },
        ]
    );
    let entries = file.entries();
    let group = |line| {
        entries
            .iter()
            .find(|e| e.line == line)
            .unwrap()
            .group
            .clone()
    };
    assert_eq!(group(2), None);
    assert_eq!(group(5).as_deref(), Some("Staging"));
    assert_eq!(group(6).as_deref(), Some("Staging"));
    assert_eq!(group(9).as_deref(), Some("Demo"));

    let demo = entries.iter().find(|e| e.line == 9).unwrap();
    assert_eq!(demo.comment, None);
    assert_eq!(demo.expires.as_deref(), Some("2026-11-02T19:00:00Z"));
    assert!(!demo.is_expired(datetime!(2026-11-02 18:59:59 UTC)));
    assert!(demo.is_expired(datetime!(2026-11-02 19:00:00 UTC)));
    let api = entries.iter().find(|e| e.line == 5).unwrap();
    assert_eq!(api.comment.as_deref(), Some("behind the VPN"));
    assert!(!api.is_expired(datetime!(2100-01-01 0:00 UTC)));
}

fn edit(address: &str, names: &[&str]) -> HostsEntryEdit {
    HostsEntryEdit {
        address: address.into(),
        names: names.iter().map(|n| (*n).to_owned()).collect(),
        comment: None,
        enabled: true,
        expires: None,
        group: None,
    }
}

fn current(file: &HostsFile, line: u32) -> HostsEntryEdit {
    let e = file.entries().into_iter().find(|e| e.line == line).unwrap();
    HostsEntryEdit {
        address: e.address,
        names: e.names,
        comment: e.comment,
        enabled: e.enabled,
        expires: e.expires,
        group: e.group,
    }
}

fn apply(input: &str, changes: &[HostsChange]) -> String {
    HostsFile::parse(input)
        .edited(changes)
        .unwrap()
        .file
        .to_string()
}

#[test]
fn turning_entries_on_and_off_keeps_their_text() {
    let file = HostsFile::parse(GROUPED);
    let off = HostsEntryEdit {
        enabled: false,
        ..current(&file, 5)
    };
    let on = HostsEntryEdit {
        enabled: true,
        ..current(&file, 6)
    };
    let out = apply(
        GROUPED,
        &[
            HostsChange::Set {
                line: 5,
                entry: off,
            },
            HostsChange::Set { line: 6, entry: on },
        ],
    );
    assert_eq!(
        out,
        GROUPED
            .replace(
                "10.0.8.20\tapi.staging # behind the VPN",
                "# 10.0.8.20\tapi.staging # behind the VPN"
            )
            .replace("# 10.0.8.21\tdb.staging", "10.0.8.21\tdb.staging")
    );
}

#[test]
fn edits_rewrite_only_their_line() {
    let file = HostsFile::parse(GROUPED);
    let changed = HostsEntryEdit {
        address: "10.0.8.30".into(),
        comment: Some("new box".into()),
        expires: Some("2026-11-02T22:00:00+03:00".into()),
        ..current(&file, 5)
    };
    let edited = file
        .edited(&[
            HostsChange::Set {
                line: 5,
                entry: changed,
            },
            HostsChange::Remove { line: 2 },
        ])
        .unwrap();
    assert_eq!(
        edited.file.to_string(),
        GROUPED.replace("10.0.0.1\tloose.internal\n", "").replace(
            "10.0.8.20\tapi.staging # behind the VPN",
            "10.0.8.30\tapi.staging\t# new box sshkm-until=2026-11-02T19:00:00Z"
        )
    );
    let kinds: Vec<_> = edited
        .diff
        .iter()
        .map(|d| (d.kind, d.text.as_str()))
        .collect();
    assert_eq!(
        kinds,
        [
            (HostsDiffKind::Same, "127.0.0.1\tlocalhost"),
            (HostsDiffKind::Removed, "10.0.0.1\tloose.internal"),
            (HostsDiffKind::Same, ""),
            (HostsDiffKind::Same, "# >>> sshkm: Staging"),
            (
                HostsDiffKind::Removed,
                "10.0.8.20\tapi.staging # behind the VPN"
            ),
            (
                HostsDiffKind::Added,
                "10.0.8.30\tapi.staging\t# new box sshkm-until=2026-11-02T19:00:00Z"
            ),
            (HostsDiffKind::Same, "# 10.0.8.21\tdb.staging"),
            (HostsDiffKind::Same, "# <<< sshkm: Staging"),
            (HostsDiffKind::Skipped, ""),
        ]
    );
    assert_eq!(edited.diff.last().unwrap().count, 2);
    assert_eq!(edited.diff[1].old_line, Some(2));
    assert_eq!(edited.diff[5].new_line, Some(4));
    assert_ne!(edited.file.revision(), file.revision());
}

#[test]
fn additions_go_to_their_group_or_the_end() {
    let in_group = |group: &str| HostsEntryEdit {
        group: Some(group.into()),
        ..edit("10.0.8.40", &["cache.staging"])
    };
    let out = apply(
        GROUPED,
        &[
            HostsChange::Add {
                entry: in_group("Staging"),
            },
            HostsChange::Add {
                entry: edit("10.1.1.1", &["plain.local"]),
            },
            HostsChange::Add {
                entry: in_group("Fresh"),
            },
            HostsChange::Add {
                entry: in_group("Demo"),
            },
        ],
    );
    assert_eq!(
        out,
        "127.0.0.1\tlocalhost\n\
         10.0.0.1\tloose.internal\n\
         \n\
         # >>> sshkm: Staging\n\
         10.0.8.20\tapi.staging # behind the VPN\n\
         # 10.0.8.21\tdb.staging\n\
         10.0.8.40\tcache.staging\n\
         # <<< sshkm: Staging\n\
         # >>> sshkm: Demo\n\
         10.0.9.1\tdemo.local # sshkm-until=2026-11-02T19:00:00Z\n\
         10.0.8.40\tcache.staging\n\
         # <<< sshkm: Demo\n\
         10.1.1.1\tplain.local\n\
         \n\
         # >>> sshkm: Fresh\n\
         10.0.8.40\tcache.staging\n\
         # <<< sshkm: Fresh\n"
    );
}

#[test]
fn groups_can_be_renamed_dissolved_and_entries_moved() {
    let file = HostsFile::parse(GROUPED);
    let moved = HostsEntryEdit {
        group: Some("QA".into()),
        ..current(&file, 2)
    };
    let kept = HostsEntryEdit {
        enabled: false,
        group: Some("QA".into()),
        ..current(&file, 5)
    };
    let out = apply(
        GROUPED,
        &[
            HostsChange::RenameGroup {
                name: "Staging".into(),
                to: "QA".into(),
            },
            HostsChange::Ungroup {
                name: "Demo".into(),
            },
            HostsChange::Set {
                line: 2,
                entry: moved,
            },
            HostsChange::Set {
                line: 5,
                entry: kept,
            },
        ],
    );
    assert_eq!(
        out,
        "127.0.0.1\tlocalhost\n\
         \n\
         # >>> sshkm: QA\n\
         # 10.0.8.20\tapi.staging # behind the VPN\n\
         # 10.0.8.21\tdb.staging\n\
         10.0.0.1\tloose.internal\n\
         # <<< sshkm: QA\n\
         10.0.9.1\tdemo.local # sshkm-until=2026-11-02T19:00:00Z\n"
    );
}

#[test]
fn new_lines_follow_the_file() {
    // CRLF, spaces between fields and no final newline.
    let input = "127.0.0.1 localhost\r\n10.0.0.1 a.local";
    let out = apply(
        input,
        &[HostsChange::Add {
            entry: edit("10.0.0.2", &["b.local", "b"]),
        }],
    );
    assert_eq!(
        out,
        "127.0.0.1 localhost\r\n10.0.0.1 a.local\r\n10.0.0.2 b.local b\r\n"
    );
    // Removing the last line keeps "no final newline".
    let out = apply(input, &[HostsChange::Remove { line: 2 }]);
    assert_eq!(out, "127.0.0.1 localhost");
    // An empty file gets tabs and a final newline.
    assert_eq!(
        apply(
            "",
            &[HostsChange::Add {
                entry: edit("::1", &["six"])
            }]
        ),
        "::1\tsix\n"
    );
}

#[test]
fn bad_changes_change_nothing() {
    let file = HostsFile::parse(GROUPED);
    let code = |changes: &[HostsChange]| file.edited(changes).unwrap_err().code();
    let set = |line, entry| HostsChange::Set { line, entry };
    assert_eq!(
        code(&[set(1, edit("127.0.0.1", &["me"]))]),
        ErrorCode::InvalidInput,
        "system entry"
    );
    assert_eq!(
        code(&[HostsChange::Remove { line: 3 }]),
        ErrorCode::NotFound
    );
    assert_eq!(
        code(&[HostsChange::Remove { line: 0 }]),
        ErrorCode::NotFound
    );
    assert_eq!(
        code(&[
            HostsChange::Remove { line: 2 },
            HostsChange::Remove { line: 2 }
        ]),
        ErrorCode::InvalidInput
    );
    for bad in [
        edit("10.0.0.300", &["x"]),
        edit("10.0.0.1", &[]),
        edit("10.0.0.1", &["a b"]),
        edit("10.0.0.1", &["LocalHost"]),
        HostsEntryEdit {
            comment: Some("two\nlines".into()),
            ..edit("10.0.0.1", &["x"])
        },
        HostsEntryEdit {
            expires: Some("tomorrow".into()),
            ..edit("10.0.0.1", &["x"])
        },
        HostsEntryEdit {
            group: Some("  ".into()),
            ..edit("10.0.0.1", &["x"])
        },
    ] {
        assert_eq!(
            code(&[HostsChange::Add { entry: bad.clone() }]),
            ErrorCode::InvalidInput,
            "{bad:?}"
        );
    }
    assert_eq!(
        code(&[HostsChange::RenameGroup {
            name: "Staging".into(),
            to: "Demo".into()
        }]),
        ErrorCode::AlreadyExists
    );
    assert_eq!(
        code(&[HostsChange::Ungroup {
            name: "Nope".into()
        }]),
        ErrorCode::NotFound
    );
}

#[test]
fn changes_deserialize_tagged() {
    let change: HostsChange = serde_json::from_value(serde_json::json!({
        "kind": "set",
        "line": 5,
        "entry": {
            "address": "10.0.0.1",
            "names": ["a"],
            "comment": null,
            "enabled": false,
            "expires": null,
            "group": "Staging"
        }
    }))
    .unwrap();
    assert!(matches!(change, HostsChange::Set { line: 5, .. }));
    let rename: HostsChange =
        serde_json::from_value(serde_json::json!({"kind": "renameGroup", "name": "a", "to": "b"}))
            .unwrap();
    assert!(matches!(rename, HostsChange::RenameGroup { .. }));
}
