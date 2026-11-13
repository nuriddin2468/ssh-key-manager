//! Real `ssh` output: OpenSSH 9.9 on macOS (with `-v` against a local
//! `sshd`, and without), and OpenSSH 8.9–9.6 on Linux and 8.1–9.5 for
//! Windows (CRLF line ends).

use super::*;

/// A sample: where it came from, what the caller knew, and what it means.
struct Case {
    file: &'static str,
    text: &'static str,
    context: Context,
    cause: Cause,
    hop: Option<&'static str>,
    /// Lines the diagnosis must show.
    shows: &'static [&'static str],
}

macro_rules! sample {
    ($file:literal) => {
        ($file, include_str!(concat!("testdata/", $file, ".txt")))
    };
}

fn case(
    (file, text): (&'static str, &'static str),
    context: Context,
    cause: Cause,
    hop: Option<&'static str>,
    shows: &'static [&'static str],
) -> Case {
    Case {
        file,
        text,
        context,
        cause,
        hop,
        shows,
    }
}

fn direct(host: &str) -> Context {
    Context {
        host_name: Some(host.to_owned()),
        ..Context::default()
    }
}

fn jump(host: &str, proxy_jump: &str) -> Context {
    Context {
        host_name: Some(host.to_owned()),
        proxy_jump: Some(proxy_jump.to_owned()),
        timed_out: false,
    }
}

fn key(name: &str, key_type: &str, fingerprint: &str, agent: bool) -> TriedKey {
    TriedKey {
        name: name.to_owned(),
        key_type: Some(key_type.to_owned()),
        fingerprint: Some(fingerprint.to_owned()),
        agent,
    }
}

fn network(problem: NetworkProblem, host: &str, port: u16) -> Cause {
    Cause::Network {
        problem,
        host: Some(host.to_owned()),
        port: Some(port),
    }
}

fn legacy(what: Negotiation, offer: &[&str], option: &str, value: &str) -> Cause {
    Cause::Legacy {
        what,
        offer: offer.iter().map(|&a| a.to_owned()).collect(),
        option: option.to_owned(),
        value: value.to_owned(),
    }
}

fn proxy(problem: ProxyProblem, detail: Option<&str>) -> Cause {
    Cause::Proxy {
        problem,
        detail: detail.map(str::to_owned),
    }
}

const OTHER: &str = "SHA256:1fg47aGLpRr4QWeSvm/j5xZJyfbQGgF50oY1vgHimss";

#[allow(clippy::too_many_lines)]
fn cases() -> Vec<Case> {
    let local = || direct("127.0.0.1");
    vec![
        // macOS, OpenSSH 9.9p2 with -v.
        case(
            sample!("macos/publickey_denied"),
            local(),
            Cause::KeysRejected {
                offered: vec![key("/Users/alice/.ssh/other", "ED25519", OTHER, false)],
                password_allowed: false,
            },
            None,
            &[
                "debug1: Offering public key: /Users/alice/.ssh/other ED25519 \
                 SHA256:1fg47aGLpRr4QWeSvm/j5xZJyfbQGgF50oY1vgHimss explicit",
                "alice@127.0.0.1: Permission denied (publickey).",
            ],
        ),
        case(
            sample!("macos/publickey_password_denied"),
            local(),
            Cause::KeysRejected {
                offered: vec![key("/Users/alice/.ssh/other", "ED25519", OTHER, false)],
                password_allowed: true,
            },
            None,
            &["alice@127.0.0.1: Permission denied (publickey,password)."],
        ),
        case(
            sample!("macos/plain_publickey_denied"),
            Context::default(),
            Cause::KeysRejected {
                offered: Vec::new(),
                password_allowed: false,
            },
            None,
            &["alice@127.0.0.1: Permission denied (publickey)."],
        ),
        case(
            sample!("macos/passphrase_needed"),
            local(),
            Cause::KeyLocked {
                key: "/Users/alice/.ssh/locked".into(),
            },
            None,
            &[
                "debug1: Server accepts key: /Users/alice/.ssh/locked ED25519 \
                 SHA256:35XPgvIO9sWxYopXDvNSuQHk+bJuJddjzAeXa1nXMlM explicit",
            ],
        ),
        case(
            sample!("macos/no_such_identity"),
            local(),
            Cause::IdentityFileMissing {
                path: "/Users/alice/.ssh/does_not_exist".into(),
            },
            None,
            &["no such identity: /Users/alice/.ssh/does_not_exist: No such file or directory"],
        ),
        case(
            sample!("macos/too_many"),
            local(),
            Cause::TooManyAuthFailures {
                offered: vec![
                    key(
                        "/Users/alice/.ssh/k1",
                        "ED25519",
                        "SHA256:qC2oKql9UVh/xGkycKBdGu+2J7QjQtPjWJOLb+GCRxk",
                        false,
                    ),
                    key(
                        "/Users/alice/.ssh/k2",
                        "ED25519",
                        "SHA256:7jo8HstxjOaxVn3G9YaGTotc2bqJQzSU/eVl9JyG1AQ",
                        false,
                    ),
                ],
            },
            None,
            &[
                "Received disconnect from 127.0.0.1 port 56712:2: Too many authentication failures",
                "Disconnected from 127.0.0.1 port 56712",
            ],
        ),
        case(
            sample!("macos/hostkey_unknown"),
            local(),
            Cause::HostKeyUnknown {
                host: Some("[127.0.0.1]:56723".into()),
            },
            None,
            &[
                "No ED25519 host key is known for [127.0.0.1]:56723 and you have requested strict \
                 checking.",
                "Host key verification failed.",
            ],
        ),
        case(
            sample!("macos/hostkey_changed"),
            local(),
            Cause::HostKeyChanged {
                host: Some("[127.0.0.1]:56727".into()),
                key_type: Some("ED25519".into()),
                fingerprint: Some("SHA256:LEfeRJzBJFyPZhmBm/WtlM18LQP2wnqvxSp1itp9BIM".into()),
                known_hosts: Some("/Users/alice/.ssh/known_hosts:4".into()),
            },
            None,
            &[
                "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @",
                "Host key verification failed.",
            ],
        ),
        case(
            sample!("macos/plain_hostkey_changed"),
            Context::default(),
            Cause::HostKeyChanged {
                host: Some("[127.0.0.1]:56727".into()),
                key_type: Some("ED25519".into()),
                fingerprint: Some("SHA256:LEfeRJzBJFyPZhmBm/WtlM18LQP2wnqvxSp1itp9BIM".into()),
                known_hosts: Some("/Users/alice/.ssh/known_hosts:4".into()),
            },
            None,
            &["Offending ED25519 key in /Users/alice/.ssh/known_hosts:4"],
        ),
        case(
            sample!("macos/refused"),
            local(),
            network(NetworkProblem::Refused, "127.0.0.1", 56731),
            None,
            &["ssh: connect to host 127.0.0.1 port 56731: Connection refused"],
        ),
        case(
            sample!("macos/timeout"),
            direct("10.255.255.1"),
            network(NetworkProblem::TimedOut, "10.255.255.1", 22),
            None,
            &["ssh: connect to host 10.255.255.1 port 22: Operation timed out"],
        ),
        case(
            sample!("macos/resolve"),
            direct("nope.invalid"),
            Cause::NameNotResolved {
                host: "nope.invalid".into(),
            },
            None,
            &[
                "ssh: Could not resolve hostname nope.invalid: nodename nor servname provided, or \
                 not known",
            ],
        ),
        case(
            sample!("macos/closed"),
            local(),
            network(NetworkProblem::Closed, "127.0.0.1", 56784),
            None,
            &[
                "kex_exchange_identification: Connection closed by remote host",
                "Connection closed by 127.0.0.1 port 56784",
            ],
        ),
        case(
            sample!("macos/closed_after_http"),
            local(),
            network(NetworkProblem::Closed, "127.0.0.1", 56781),
            None,
            &["Connection closed by 127.0.0.1 port 56781"],
        ),
        case(
            sample!("macos/unprotected_key"),
            local(),
            Cause::BadPermissions {
                path: "/Users/alice/.ssh/badperm".into(),
                file: PermKind::PrivateKey,
            },
            None,
            &[
                "Permissions 0644 for '/Users/alice/.ssh/badperm' are too open.",
                "Load key \"/Users/alice/.ssh/badperm\": bad permissions",
            ],
        ),
        case(
            sample!("macos/legacy_hostkey"),
            local(),
            legacy(
                Negotiation::HostKey,
                &["ssh-rsa"],
                "HostKeyAlgorithms",
                "+ssh-rsa",
            ),
            None,
            &[
                "Unable to negotiate with 127.0.0.1 port 56758: no matching host key type found. \
                 Their offer: ssh-rsa",
            ],
        ),
        case(
            sample!("macos/legacy_kex"),
            local(),
            legacy(
                Negotiation::KeyExchange,
                &["diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"],
                "KexAlgorithms",
                "+diffie-hellman-group14-sha1",
            ),
            None,
            &[],
        ),
        case(
            sample!("macos/legacy_cipher"),
            local(),
            legacy(
                Negotiation::Cipher,
                &["aes128-cbc", "3des-cbc"],
                "Ciphers",
                "+aes128-cbc",
            ),
            None,
            &[],
        ),
        case(
            sample!("macos/legacy_mac"),
            local(),
            legacy(
                Negotiation::Mac,
                &["hmac-md5", "hmac-sha1-96"],
                "MACs",
                "+hmac-sha1-96",
            ),
            None,
            &[],
        ),
        // ProxyJump and ProxyCommand: the jump hosts are 127.0.0.1 too, so
        // only the proxy closing under `ssh` tells their failures apart.
        case(
            sample!("macos/proxy_via_refused"),
            jump("10.9.9.9", "jump-refused"),
            network(NetworkProblem::Refused, "127.0.0.1", 56792),
            Some("jump-refused"),
            &["ssh: connect to host 127.0.0.1 port 56792: Connection refused"],
        ),
        case(
            sample!("macos/plain_proxy_refused"),
            jump("10.9.9.9", "jump-refused"),
            network(NetworkProblem::Refused, "127.0.0.1", 56792),
            Some("jump-refused"),
            &[],
        ),
        case(
            sample!("macos/proxy_via_denied"),
            jump("10.9.9.9", "jump-denied"),
            Cause::KeysRejected {
                offered: vec![key("/Users/alice/.ssh/other", "ED25519", OTHER, false)],
                password_allowed: false,
            },
            Some("jump-denied"),
            &["alice@127.0.0.1: Permission denied (publickey)."],
        ),
        case(
            sample!("macos/plain_proxy_denied"),
            jump("10.9.9.9", "jump-denied"),
            Cause::KeysRejected {
                offered: Vec::new(),
                password_allowed: false,
            },
            Some("jump-denied"),
            &[],
        ),
        case(
            sample!("macos/proxy_via_targetdenied"),
            jump("127.0.0.1", "jump-ok"),
            Cause::KeysRejected {
                offered: vec![key("/Users/alice/.ssh/other", "ED25519", OTHER, false)],
                password_allowed: false,
            },
            None,
            &[],
        ),
        case(
            sample!("macos/proxy_via_closedtarget"),
            jump("127.0.0.1", "jump-ok"),
            proxy(ProxyProblem::NextHopUnreachable, Some("Connection refused")),
            Some("jump-ok"),
            &[
                "channel 0: open failed: connect failed: Connection refused",
                "stdio forwarding failed",
            ],
        ),
        case(
            sample!("macos/proxy_via_nofwd"),
            jump("127.0.0.1", "jump-nofwd"),
            proxy(ProxyProblem::ForwardingProhibited, None),
            Some("jump-nofwd"),
            &["channel 0: open failed: administratively prohibited: open failed"],
        ),
        case(
            sample!("macos/proxy_via_cmd"),
            direct("10.9.9.9"),
            proxy(ProxyProblem::CommandFailed, None),
            None,
            &[
                "debug1: Executing proxy command: exec sshkm-no-such-proxy 10.9.9.9 22",
                "zsh:1: command not found: sshkm-no-such-proxy",
            ],
        ),
        // Linux.
        case(
            sample!("linux/publickey_denied_agent"),
            direct("10.0.4.12"),
            Cause::KeysRejected {
                offered: vec![
                    key(
                        "alice@laptop",
                        "ED25519",
                        "SHA256:Zx9yQe1R0r9cGkT2mJb0FqgWnDk3p8a7HlU1sVwXyZ4",
                        true,
                    ),
                    key(
                        "/home/alice/.ssh/id_ed25519_work",
                        "ED25519",
                        "SHA256:7fQvYkS3u1dGm0bL2pX9wHcN4rE6tA8iO5jU0yKzMv1",
                        false,
                    ),
                ],
                password_allowed: false,
            },
            None,
            &["ubuntu@10.0.4.12: Permission denied (publickey)."],
        ),
        case(
            sample!("linux/password_rejected"),
            direct("nas.lan"),
            Cause::PasswordRejected,
            None,
            &[
                "debug1: Next authentication method: password",
                "alice@nas.lan: Permission denied (publickey,password).",
            ],
        ),
        case(
            sample!("linux/password_retry_plain"),
            Context::default(),
            Cause::PasswordRejected,
            None,
            &["Permission denied, please try again."],
        ),
        case(
            sample!("linux/password_required"),
            Context::default(),
            Cause::PasswordRequired,
            None,
            &["deploy@ftp.example.com: Permission denied (password)."],
        ),
        case(
            sample!("linux/keyboard_interactive_required"),
            Context::default(),
            Cause::PasswordRequired,
            None,
            &[],
        ),
        case(
            sample!("linux/timeout"),
            direct("203.0.113.9"),
            network(NetworkProblem::TimedOut, "203.0.113.9", 22),
            None,
            &[],
        ),
        case(
            sample!("linux/no_route"),
            Context::default(),
            network(NetworkProblem::NoRoute, "192.168.50.20", 22),
            None,
            &[],
        ),
        case(
            sample!("linux/network_unreachable"),
            Context::default(),
            network(NetworkProblem::NetworkUnreachable, "2001:db8::5", 22),
            None,
            &[],
        ),
        case(
            sample!("linux/resolve"),
            Context::default(),
            Cause::NameNotResolved {
                host: "prod-api.internal".into(),
            },
            None,
            &[],
        ),
        case(
            sample!("linux/resolve_temporary"),
            Context::default(),
            Cause::NameNotResolved {
                host: "github.com".into(),
            },
            None,
            &[],
        ),
        case(
            sample!("linux/bad_config_owner"),
            Context::default(),
            Cause::BadPermissions {
                path: "/home/alice/.ssh/config".into(),
                file: PermKind::Config,
            },
            None,
            &["Bad owner or permissions on /home/alice/.ssh/config"],
        ),
        case(
            sample!("linux/unprotected_key"),
            Context::default(),
            Cause::BadPermissions {
                path: "/home/alice/.ssh/id_rsa".into(),
                file: PermKind::PrivateKey,
            },
            None,
            &["Permissions 0664 for '/home/alice/.ssh/id_rsa' are too open."],
        ),
        case(
            sample!("linux/too_many"),
            Context::default(),
            Cause::TooManyAuthFailures {
                offered: Vec::new(),
            },
            None,
            &[],
        ),
        case(
            sample!("linux/hostkey_changed"),
            direct("10.0.4.12"),
            Cause::HostKeyChanged {
                host: Some("10.0.4.12".into()),
                key_type: Some("ECDSA".into()),
                fingerprint: Some("SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM".into()),
                known_hosts: Some("/home/alice/.ssh/known_hosts:12".into()),
            },
            None,
            &[],
        ),
        case(
            sample!("linux/hostkey_unknown_old"),
            Context::default(),
            Cause::HostKeyUnknown {
                host: Some("build.example.com".into()),
            },
            None,
            &[],
        ),
        case(
            sample!("linux/reset"),
            Context::default(),
            network(NetworkProblem::Reset, "10.0.4.12", 22),
            None,
            &["Connection reset by 10.0.4.12 port 22"],
        ),
        case(
            sample!("linux/banner_timeout"),
            Context::default(),
            network(NetworkProblem::TimedOut, "10.0.4.12", 22),
            None,
            &["Connection timed out during banner exchange"],
        ),
        case(
            sample!("linux/not_ssh"),
            Context::default(),
            network(NetworkProblem::NotSsh, "10.0.4.12", 443),
            None,
            &[],
        ),
        case(
            sample!("linux/legacy_hostkey_dss"),
            Context::default(),
            legacy(
                Negotiation::HostKey,
                &["ssh-rsa", "ssh-dss"],
                "HostKeyAlgorithms",
                "+ssh-rsa",
            ),
            None,
            &[],
        ),
        case(
            sample!("linux/legacy_kex_group1"),
            Context::default(),
            legacy(
                Negotiation::KeyExchange,
                &["diffie-hellman-group1-sha1"],
                "KexAlgorithms",
                "+diffie-hellman-group1-sha1",
            ),
            None,
            &[],
        ),
        case(
            sample!("linux/no_mutual_signature"),
            direct("old-router"),
            legacy(
                Negotiation::Signature,
                &["ssh-rsa"],
                "PubkeyAcceptedAlgorithms",
                "+ssh-rsa",
            ),
            None,
            &["debug1: send_pubkey_test: no mutual signature algorithm"],
        ),
        case(
            sample!("linux/proxy_jump_resolve"),
            jump("10.0.4.12", "alice@bastion:2222"),
            Cause::NameNotResolved {
                host: "bastion.corp.example".into(),
            },
            Some("bastion"),
            &[],
        ),
        case(
            sample!("linux/proxy_forward_name"),
            jump("db.internal", "edge,bastion"),
            proxy(
                ProxyProblem::NextHopUnreachable,
                Some("Name or service not known"),
            ),
            Some("bastion"),
            &[],
        ),
        case(
            sample!("linux/proxy_command_dash"),
            Context::default(),
            proxy(ProxyProblem::CommandFailed, None),
            None,
            &["/bin/sh: 1: exec: cloudflared: not found"],
        ),
        case(
            sample!("linux/identity_missing_plain"),
            Context::default(),
            Cause::IdentityFileMissing {
                path: "/home/alice/.ssh/id_ed25519_old".into(),
            },
            None,
            &[],
        ),
        // Windows.
        case(
            sample!("windows/resolve"),
            Context::default(),
            Cause::NameNotResolved {
                host: "prod-api".into(),
            },
            None,
            &["ssh: Could not resolve hostname prod-api: No such host is known."],
        ),
        case(
            sample!("windows/timeout"),
            Context::default(),
            network(NetworkProblem::TimedOut, "10.0.4.12", 22),
            None,
            &[],
        ),
        case(
            sample!("windows/refused"),
            Context::default(),
            network(NetworkProblem::Refused, "10.0.4.12", 22),
            None,
            &[],
        ),
        case(
            sample!("windows/bad_config"),
            Context::default(),
            Cause::BadPermissions {
                path: r"C:\\Users\\alice/.ssh/config".into(),
                file: PermKind::Config,
            },
            None,
            &[
                "Bad permissions. Try removing permissions for user: BUILTIN\\Users \
                 (S-1-5-32-545) on file C:/Users/alice/.ssh/config.",
            ],
        ),
        case(
            sample!("windows/unprotected_key"),
            Context::default(),
            Cause::BadPermissions {
                path: r"C:\Users\alice\.ssh\id_ed25519".into(),
                file: PermKind::PrivateKey,
            },
            None,
            &[
                "Bad permissions. Try removing permissions for user: NT AUTHORITY\\Authenticated \
                 Users (S-1-5-11) on file C:/Users/alice/.ssh/id_ed25519.",
            ],
        ),
        case(
            sample!("windows/publickey_denied"),
            direct("10.0.4.12"),
            Cause::KeysRejected {
                offered: vec![key(
                    r"C:\\Users\\alice/.ssh/id_ed25519",
                    "ED25519",
                    "SHA256:Lm4nB7vC2xZ9qW1eR5tY8uI0oP3aS6dF4gH2jK1lQ0w",
                    false,
                )],
                password_allowed: true,
            },
            None,
            &[],
        ),
        case(
            sample!("windows/hostkey_changed_81"),
            Context::default(),
            Cause::HostKeyChanged {
                host: Some("192.168.1.20".into()),
                key_type: Some("ECDSA".into()),
                fingerprint: Some("SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM".into()),
                known_hosts: Some(r"C:\\Users\\alice/.ssh/known_hosts:3".into()),
            },
            None,
            &[],
        ),
        case(
            sample!("windows/too_many"),
            Context::default(),
            Cause::TooManyAuthFailures {
                offered: Vec::new(),
            },
            None,
            &["Disconnected from 10.0.4.12 port 22"],
        ),
        case(
            sample!("windows/legacy_cipher"),
            Context::default(),
            legacy(
                Negotiation::Cipher,
                &["aes128-cbc", "3des-cbc", "aes192-cbc", "aes256-cbc"],
                "Ciphers",
                "+aes256-cbc",
            ),
            None,
            &[],
        ),
        case(
            sample!("windows/proxy_jump_timeout"),
            jump("10.0.4.12", "bastion"),
            network(NetworkProblem::TimedOut, "bastion.example.net", 22),
            Some("bastion"),
            &[],
        ),
        case(
            sample!("windows/closed"),
            Context::default(),
            network(NetworkProblem::Closed, "10.0.4.12", 22),
            None,
            &[],
        ),
    ]
}

#[test]
fn reads_every_sample() {
    for case in cases() {
        let diagnosis = diagnose(case.text, &case.context);
        assert_eq!(diagnosis.cause, case.cause, "{}", case.file);
        assert_eq!(diagnosis.hop.as_deref(), case.hop, "{}: hop", case.file);
        assert!(!diagnosis.lines.is_empty(), "{}: no lines", case.file);
        for line in case.shows {
            assert!(
                diagnosis.lines.iter().any(|shown| shown == line),
                "{}: {line:?} not in {:#?}",
                case.file,
                diagnosis.lines
            );
        }
        // Debug lines show only when they tell something.
        for line in &diagnosis.lines {
            for noise in [
                "Sending env",
                "Reading configuration",
                "kex: ",
                "identity file",
            ] {
                assert!(!line.contains(noise), "{}: {line}", case.file);
            }
        }
    }
}

#[test]
fn shows_what_it_does_not_recognise() {
    let text = "OpenSSH_9.9p2, LibreSSL 3.3.6\ndebug1: Connecting to h [10.0.0.5] port 22.\n\
                mux_client_request_session: read from master failed: Broken pipe\n";
    let diagnosis = diagnose(text, &Context::default());
    assert_eq!(diagnosis.cause, Cause::Unknown);
    assert_eq!(
        diagnosis.lines,
        ["mux_client_request_session: read from master failed: Broken pipe"]
    );
    assert_eq!(diagnose("", &Context::default()).cause, Cause::Unknown);

    let stopped = Context {
        timed_out: true,
        ..Context::default()
    };
    assert_eq!(
        diagnose("debug1: Connecting to h [10.0.0.5] port 22.\n", &stopped).cause,
        Cause::Network {
            problem: NetworkProblem::TimedOut,
            host: None,
            port: None,
        }
    );
}

#[test]
fn reads_keys_as_each_version_names_them() {
    assert_eq!(
        tried_key("/home/a/.ssh/id_rsa RSA SHA256:abc explicit agent"),
        key("/home/a/.ssh/id_rsa", "RSA", "SHA256:abc", true)
    );
    // An agent's key named by a comment with spaces.
    assert_eq!(
        tried_key("Work laptop key ED25519 SHA256:abc agent"),
        key("Work laptop key", "ED25519", "SHA256:abc", true)
    );
    // OpenSSH before 8.1.
    assert_eq!(
        tried_key("RSA SHA256:abc /home/a/.ssh/id_rsa"),
        key("/home/a/.ssh/id_rsa", "RSA", "SHA256:abc", false)
    );
    assert_eq!(tried_key("/k").name, "/k");
}

#[test]
fn names_jump_hosts() {
    assert_eq!(jumps("bastion"), ["bastion"]);
    assert_eq!(
        jumps("alice@a.example:2222,ssh://b@[2001:db8::1]:22,c"),
        ["a.example", "2001:db8::1", "c"]
    );
    assert_eq!(jumps("none"), Vec::<String>::new());
    assert_eq!(
        first_jump("alice@a.example:2222,b"),
        Some(("a.example".into(), Some(2222)))
    );
    assert_eq!(
        first_jump("[2001:db8::1]:2200"),
        Some(("2001:db8::1".into(), Some(2200)))
    );
    assert_eq!(first_jump("bastion"), Some(("bastion".into(), None)));
    assert_eq!(first_jump("fe80::1"), Some(("fe80::1".into(), None)));
    assert_eq!(first_jump("none"), None);
}

#[test]
fn turns_on_one_old_algorithm() {
    let offer = |names: &[&str]| names.iter().map(|&n| n.to_owned()).collect::<Vec<_>>();
    assert_eq!(
        legacy_option(Negotiation::HostKey, &offer(&["ssh-dss", "ssh-rsa"])),
        Some(("HostKeyAlgorithms".into(), "+ssh-rsa".into()))
    );
    // Something unheard of is taken as offered.
    assert_eq!(
        legacy_option(Negotiation::Cipher, &offer(&["blowfish-cbc"])),
        Some(("Ciphers".into(), "+blowfish-cbc".into()))
    );
    // Never anything that could change the config line.
    assert_eq!(legacy_option(Negotiation::Cipher, &offer(&["x y"])), None);
    assert_eq!(
        legacy_option(Negotiation::Mac, &offer(&["a\nHost *"])),
        None
    );
    assert_eq!(legacy_option(Negotiation::Mac, &[]), None);
}

#[test]
fn readable_output_drops_what_v_adds() {
    let text = include_str!("testdata/linux/publickey_denied_agent.txt");
    assert_eq!(
        readable(text),
        "ubuntu@10.0.4.12: Permission denied (publickey)."
    );

    let ok = include_str!("testdata/macos/ok.txt");
    assert_eq!(readable(ok), "");

    // A server that closes during its banner still shows that.
    let closing = "debug1: SSH2_MSG_SERVICE_ACCEPT received\nWelcome\n\
                   Connection closed by 10.0.0.5 port 22\n";
    assert_eq!(readable(closing), "Connection closed by 10.0.0.5 port 22");

    // Without -v nothing changes.
    let plain = include_str!("testdata/macos/plain_hostkey_changed.txt");
    assert_eq!(readable(plain), plain.replace('\r', "").trim());
    let windows = include_str!("testdata/windows/too_many.txt");
    assert_eq!(
        readable(windows),
        "Received disconnect from 10.0.4.12 port 22:2: Too many authentication failures\n\
         Disconnected from 10.0.4.12 port 22"
    );
}

#[test]
fn diagnoses_serialise_for_the_ui() {
    let diagnosis = diagnose(
        include_str!("testdata/macos/hostkey_changed.txt"),
        &Context::default(),
    );
    let json = serde_json::to_value(&diagnosis).unwrap();
    assert_eq!(json["cause"]["kind"], "hostKeyChanged");
    assert_eq!(json["cause"]["keyType"], "ED25519");
    assert_eq!(
        json["cause"]["knownHosts"],
        "/Users/alice/.ssh/known_hosts:4"
    );
    assert_eq!(json["hop"], serde_json::Value::Null);
}

#[test]
fn the_version_line_is_known_with_or_without_a_debug_prefix() {
    assert!(is_version("OpenSSH_9.9p2, LibreSSL 3.3.6"));
    assert!(is_version("debug1: OpenSSH_10.5p1, LibreSSL 3.3.6"));
    assert!(is_version("OpenSSH_for_Windows_9.5p1, LibreSSL 3.8.2"));
    assert!(!is_version(
        "debug1: Reading configuration data /etc/ssh/ssh_config"
    ));
    assert!(!is_version("OpenSSH_9.9p2"));
}
