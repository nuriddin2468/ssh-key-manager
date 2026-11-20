//! The client against in-process servers: host keys, every way to sign
//! in, jump chains, refused hosts and the shell.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{App, CODE, PASSWORD, Spec, TestServer, phone_key};
use sshkm_core::known_hosts::KnownHosts;
use sshkm_ssh::{
    AuthMethod, Closed, ConnectOptions, Connection, Error, NotAvailable, PtySize, ServerPrompt,
    Shell, ShellEvent,
};

fn host_block(alias: &str, port: u16, user: &str) -> String {
    format!("Host {alias}\n  HostName 127.0.0.1\n  Port {port}\n  User {user}\n")
}

fn with_key() -> ConnectOptions {
    ConnectOptions {
        key: Some(phone_key()),
        ..ConnectOptions::default()
    }
}

async fn connect(
    config: &str,
    known_hosts: &str,
    destination: &str,
    options: ConnectOptions,
    app: &Arc<App>,
) -> Result<Connection, Error> {
    let callbacks: Arc<dyn sshkm_ssh::Callbacks> = app.clone();
    tokio::time::timeout(
        Duration::from_secs(20),
        Connection::connect(config, known_hosts, destination, options, callbacks),
    )
    .await
    .expect("the connection neither opened nor failed")
}

/// Output until it holds `text`.
async fn read_until(shell: &Shell, text: &str) -> String {
    let mut seen = String::new();
    while !seen.contains(text) {
        match tokio::time::timeout(Duration::from_secs(5), shell.next_event())
            .await
            .expect("no output in time")
        {
            ShellEvent::Output(bytes) => seen.push_str(&String::from_utf8_lossy(&bytes)),
            ShellEvent::Closed(closed) => panic!("closed before {text:?}: {closed:?}"),
        }
    }
    seen
}

async fn closed(shell: &Shell) -> Closed {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), shell.next_event())
            .await
            .expect("the shell didn't end")
        {
            ShellEvent::Output(_) => {}
            ShellEvent::Closed(closed) => return closed,
        }
    }
}

fn key_server(seed: u8) -> Spec {
    Spec {
        seed,
        user: "alice".into(),
        key: Some(phone_key().public_key().clone()),
        ..Spec::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_known_host_opens_a_shell_signed_by_the_app() {
    let server = TestServer::start(key_server(1)).await;
    let app = Arc::new(App::new().with_signer());
    let connection = connect(
        &host_block("web", server.port, "alice"),
        &server.known_line(),
        "web",
        with_key(),
        &app,
    )
    .await
    .unwrap();
    assert_eq!(app.signed(), 1);
    assert!(app.unknown.lock().unwrap().is_empty());
    assert_eq!(server.log.lock().unwrap().signed_in, ["publickey"]);

    let shell = connection
        .open_shell(PtySize { cols: 80, rows: 24 })
        .await
        .unwrap();
    assert_eq!(
        server.log.lock().unwrap().pty,
        Some(("xterm-256color".to_owned(), 80, 24))
    );
    read_until(&shell, "welcome").await;

    shell.write(b"ls -la").await.unwrap();
    read_until(&shell, "ls -la").await;

    shell
        .resize(PtySize {
            cols: 120,
            rows: 40,
        })
        .await
        .unwrap();
    read_until(&shell, "resized 120x40").await;
    assert_eq!(server.log.lock().unwrap().resizes, [(120, 40)]);

    shell.keepalive().await.unwrap();
    shell.close().await;
    server.wait_for(|log| log.closed).await;
    // The shell ends, without an exit status (nothing exited), and the
    // connection with it.
    assert_eq!(closed(&shell).await.exit_status, None);
    for _ in 0..100 {
        if shell.connection().is_closed() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the connection stayed open after close");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_shell_reports_how_it_ended() {
    let server = TestServer::start(key_server(2)).await;
    let app = Arc::new(App::new().with_signer());
    let connection = connect(
        &host_block("web", server.port, "alice"),
        &server.known_line(),
        "web",
        with_key(),
        &app,
    )
    .await
    .unwrap();
    let shell = connection
        .open_shell(PtySize { cols: 80, rows: 24 })
        .await
        .unwrap();
    read_until(&shell, "welcome").await;
    shell.write(b"exit\r").await.unwrap();
    let end = closed(&shell).await;
    assert_eq!(
        end,
        Closed {
            exit_status: Some(3),
            exit_signal: None,
            connection_lost: false,
        }
    );
    // And stays ended.
    assert!(matches!(shell.next_event().await, ShellEvent::Closed(_)));
}

#[tokio::test(flavor = "multi_thread")]
async fn typing_goes_out_while_a_read_waits() {
    let server = TestServer::start(key_server(15)).await;
    let app = Arc::new(App::new().with_signer());
    let connection = connect(
        &host_block("web", server.port, "alice"),
        &server.known_line(),
        "web",
        with_key(),
        &app,
    )
    .await
    .unwrap();
    let shell = Arc::new(
        connection
            .open_shell(PtySize { cols: 80, rows: 24 })
            .await
            .unwrap(),
    );
    read_until(&shell, "welcome").await;
    // A read waits for output that only the write below brings.
    let reader = {
        let shell = Arc::clone(&shell);
        tokio::spawn(async move { read_until(&shell, "typed while waiting").await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    shell.write(b"typed while waiting").await.unwrap();
    shell.resize(PtySize { cols: 90, rows: 30 }).await.unwrap();
    reader.await.unwrap();
    read_until(&shell, "resized 90x30").await;
    shell.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_changed_host_key_stops_the_connection() {
    let server = TestServer::start(key_server(3)).await;
    let other = common::host_key(99).public_key().clone();
    let known = format!(
        "[127.0.0.1]:{} {}\n",
        server.port,
        other.to_openssh().unwrap()
    );
    let app = Arc::new(App::new().with_signer().trusting());
    let error = connect(
        &host_block("web", server.port, "alice"),
        &known,
        "web",
        with_key(),
        &app,
    )
    .await
    .unwrap_err();
    let Error::HostKeyChanged { alias, mismatch } = error else {
        panic!("{error:?}");
    };
    assert_eq!(alias, "web");
    assert_eq!(mismatch.host, "127.0.0.1");
    assert_eq!(mismatch.port, server.port);
    assert_eq!(mismatch.key_type, "ssh-ed25519");
    assert_eq!(mismatch.fingerprint, server.fingerprint());
    assert_eq!(mismatch.known, [sshkm_ssh::host_keys::fingerprint(&other)]);
    // Never asked, never signed in.
    assert!(app.unknown.lock().unwrap().is_empty());
    assert_eq!(app.signed(), 0);
    assert_eq!(server.log.lock().unwrap().signed_in, Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_host_key_stops_the_connection() {
    let server = TestServer::start(key_server(4)).await;
    let known = format!(
        "@revoked * {}\n{}\n",
        server.host_key.to_openssh().unwrap(),
        server.known_line()
    );
    let app = Arc::new(App::new().with_signer().trusting());
    let error = connect(
        &host_block("web", server.port, "alice"),
        &known,
        "web",
        with_key(),
        &app,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&error, Error::HostKeyRevoked { fingerprint, .. } if *fingerprint == server.fingerprint()),
        "{error:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_host_is_the_users_call() {
    let server = TestServer::start(key_server(5)).await;
    let config = host_block("web", server.port, "alice");

    let declining = Arc::new(App::new().with_signer());
    let error = connect(&config, "", "web", with_key(), &declining)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::UnknownHostDeclined { alias } if alias == "web"),
        "{error:?}"
    );
    let asked = declining.unknown.lock().unwrap().clone();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].alias, "web");
    assert_eq!(asked[0].host, "127.0.0.1");
    assert_eq!(asked[0].port, server.port);
    assert_eq!(asked[0].key_type, "ssh-ed25519");
    assert_eq!(asked[0].fingerprint, server.fingerprint());
    assert_eq!(asked[0].other_types, Vec::<String>::new());
    assert_eq!(*declining.trusted.lock().unwrap(), Vec::<String>::new());
    assert_eq!(declining.signed(), 0);

    let trusting = Arc::new(App::new().with_signer().trusting());
    connect(&config, "", "web", with_key(), &trusting)
        .await
        .unwrap();
    let lines = trusting.trusted.lock().unwrap().clone();
    assert_eq!(lines, [server.known_line()]);
    // The line is one the next connection knows the host by.
    let known = KnownHosts::parse(&lines[0]);
    assert_eq!(
        sshkm_ssh::host_keys::check(&known, "127.0.0.1", server.port, &server.host_key),
        sshkm_ssh::host_keys::Verdict::Known
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_connection_takes_its_question_away() {
    let server = TestServer::start(key_server(16)).await;
    let mut app = App::new().with_signer();
    app.hang = true;
    let app = Arc::new(app);
    let callbacks: Arc<dyn sshkm_ssh::Callbacks> = app.clone();
    let config = host_block("web", server.port, "alice");
    // The app cancels while the question is on screen.
    let attempt = tokio::time::timeout(
        Duration::from_millis(500),
        Connection::connect(&config, "", "web", with_key(), callbacks),
    )
    .await;
    assert!(attempt.is_err(), "the question was never answered");
    assert_eq!(app.unknown.lock().unwrap().len(), 1);
    for _ in 0..100 {
        if app
            .question_dropped
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the question stayed after the connection was given up");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_app_isnt_asked_to_sign_for_a_key_the_server_refuses() {
    // The server takes keys, but not the phone's: it answers the offer
    // without PK_OK, so nothing is signed (no screen lock for nothing).
    let server = TestServer::start(Spec {
        seed: 18,
        user: "bob".into(),
        key: Some(common::host_key(55).public_key().clone()),
        password: true,
        ..Spec::default()
    })
    .await;
    let app = Arc::new(App::new().with_signer().answering(&[&[PASSWORD]]));
    connect(
        &host_block("db", server.port, "bob"),
        &server.known_line(),
        "db",
        with_key(),
        &app,
    )
    .await
    .unwrap();
    assert_eq!(app.signed(), 0);
    assert_eq!(server.log.lock().unwrap().signed_in, ["password"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_that_keeps_asking_gets_three_answers() {
    let server = TestServer::start(Spec {
        seed: 19,
        user: "bob".into(),
        endless: true,
        ..Spec::default()
    })
    .await;
    let app = Arc::new(App::new().answering(&[&[PASSWORD], &[PASSWORD], &[PASSWORD], &[PASSWORD]]));
    let error = connect(
        &host_block("db", server.port, "bob"),
        &server.known_line(),
        "db",
        ConnectOptions::default(),
        &app,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, Error::AuthFailed { .. }), "{error:?}");
    let attempts: Vec<u32> = app
        .asked
        .lock()
        .unwrap()
        .iter()
        .map(|p| p.attempt)
        .collect();
    assert_eq!(attempts, [1, 2, 3]);
    assert_eq!(server.log.lock().unwrap().rounds, 3 + 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn failing_callbacks_fail_the_connection() {
    let server = TestServer::start(key_server(20)).await;
    let config = host_block("web", server.port, "alice");
    let mut throwing = App::new().with_signer();
    throwing.unknown_host_fails = true;
    let error = connect(&config, "", "web", with_key(), &Arc::new(throwing))
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::App { detail } if detail.contains("IllegalState")),
        "{error:?}"
    );

    // A yes that can't be stored doesn't connect: the next connection, and
    // computers, wouldn't know the key.
    let mut storing = App::new().with_signer().trusting();
    storing.storing_fails = true;
    let storing = Arc::new(storing);
    let error = connect(&config, "", "web", with_key(), &storing)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::App { detail } if detail == "disk full"),
        "{error:?}"
    );
    assert_eq!(storing.signed(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn passwords_are_asked_again_after_a_refusal() {
    let server = TestServer::start(Spec {
        seed: 6,
        user: "bob".into(),
        password: true,
        ..Spec::default()
    })
    .await;
    let config = host_block("db", server.port, "bob");
    let app = Arc::new(App::new().answering(&[&["wrong"], &[PASSWORD]]));
    connect(&config, &server.known_line(), "db", with_key(), &app)
        .await
        .unwrap();
    let asked = app.asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 2);
    for (i, prompt) in asked.iter().enumerate() {
        assert_eq!(prompt.method, AuthMethod::Password);
        assert_eq!(prompt.attempt, u32::try_from(i).unwrap() + 1);
        assert_eq!(prompt.user, "bob");
        assert_eq!(prompt.host, "127.0.0.1");
        assert_eq!(prompt.prompts.len(), 1);
        assert_eq!(prompt.prompts[0].kind, ServerPrompt::Password);
        assert!(!prompt.prompts[0].echo);
    }
    // The server doesn't take keys, so the app never signed.
    assert_eq!(app.signed(), 0);

    let wrong = Arc::new(App::new().answering(&[&["a"], &["b"], &["c"], &["d"]]));
    let error = connect(&config, &server.known_line(), "db", with_key(), &wrong)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::AuthFailed { user, alias, .. } if user == "bob" && alias == "db"),
        "{error:?}"
    );
    assert_eq!(wrong.asked.lock().unwrap().len(), 3);

    let cancelling = Arc::new(App::new());
    let error = connect(&config, &server.known_line(), "db", with_key(), &cancelling)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Cancelled), "{error:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn keyboard_interactive_with_a_one_time_code() {
    let server = TestServer::start(Spec {
        seed: 7,
        user: "carol".into(),
        interactive: true,
        ..Spec::default()
    })
    .await;
    let app = Arc::new(App::new().answering(&[&[PASSWORD, CODE]]));
    connect(
        &host_block("vpn", server.port, "carol"),
        &server.known_line(),
        "vpn",
        ConnectOptions::default(),
        &app,
    )
    .await
    .unwrap();
    let asked = app.asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].method, AuthMethod::KeyboardInteractive);
    let kinds: Vec<_> = asked[0].prompts.iter().map(|p| p.kind).collect();
    assert_eq!(kinds, [ServerPrompt::Password, ServerPrompt::OneTimeCode]);
    assert_eq!(asked[0].prompts[1].text, "Verification code: ");
    assert_eq!(
        server.log.lock().unwrap().signed_in,
        ["keyboard-interactive"]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_then_a_code() {
    let server = TestServer::start(Spec {
        key_then_code: true,
        ..key_server(8)
    })
    .await;
    let app = Arc::new(App::new().with_signer().answering(&[&[CODE]]));
    connect(
        &host_block("web", server.port, "alice"),
        &server.known_line(),
        "web",
        with_key(),
        &app,
    )
    .await
    .unwrap();
    assert_eq!(app.signed(), 1);
    let asked = app.asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].prompts[0].kind, ServerPrompt::OneTimeCode);
    assert_eq!(
        server.log.lock().unwrap().signed_in,
        ["publickey", "keyboard-interactive"]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_signature_by_another_key_is_the_signers_fault() {
    let server = TestServer::start(key_server(9)).await;
    let mut app = App::new();
    app.signer = Some(p256::ecdsa::SigningKey::from_bytes(&[0x77; 32].into()).unwrap());
    let app = Arc::new(app);
    let error = connect(
        &host_block("web", server.port, "alice"),
        &server.known_line(),
        "web",
        with_key(),
        &app,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&error, Error::Signer { alias, .. } if alias == "web"),
        "{error:?}"
    );

    // A signer the user dismissed cancels.
    let dismissed = Arc::new(App::new());
    let error = connect(
        &host_block("web", server.port, "alice"),
        &server.known_line(),
        "web",
        with_key(),
        &dismissed,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, Error::Cancelled), "{error:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_jump_chain_checks_every_hop() {
    let jump = TestServer::start(Spec {
        seed: 10,
        user: "jumper".into(),
        key: Some(phone_key().public_key().clone()),
        forwards: true,
        ..Spec::default()
    })
    .await;
    let target = TestServer::start(Spec {
        seed: 11,
        user: "bob".into(),
        password: true,
        ..Spec::default()
    })
    .await;
    let config = format!(
        "{}  ProxyJump bastion\n{}",
        host_block("db", target.port, "bob"),
        host_block("bastion", jump.port, "jumper")
    );

    // The jump host is unknown: asked, trusted, its line returned.
    let app = Arc::new(
        App::new()
            .with_signer()
            .trusting()
            .answering(&[&[PASSWORD]]),
    );
    let connection = connect(&config, &target.known_line(), "db", with_key(), &app)
        .await
        .unwrap();
    let unknown = app.unknown.lock().unwrap().clone();
    assert_eq!(unknown.len(), 1);
    assert_eq!(unknown[0].alias, "bastion");
    assert_eq!(unknown[0].port, jump.port);
    assert_eq!(unknown[0].fingerprint, jump.fingerprint());
    assert_eq!(*app.trusted.lock().unwrap(), [jump.known_line()]);
    assert_eq!(
        jump.log.lock().unwrap().forwards,
        [("127.0.0.1".to_owned(), u32::from(target.port))]
    );
    assert_eq!(jump.log.lock().unwrap().signed_in, ["publickey"]);
    assert_eq!(target.log.lock().unwrap().signed_in, ["password"]);
    assert_eq!(app.asked.lock().unwrap()[0].alias, "db");
    let shell = connection
        .open_shell(PtySize { cols: 80, rows: 24 })
        .await
        .unwrap();
    read_until(&shell, "welcome").await;
    shell.write(b"through the jump").await.unwrap();
    read_until(&shell, "through the jump").await;
    shell.close().await;

    // A changed key on the jump host stops there: the target is never
    // reached.
    let target_connections = target.log.lock().unwrap().connections;
    let wrong = format!(
        "[127.0.0.1]:{} {}\n{}\n",
        jump.port,
        common::host_key(98).public_key().to_openssh().unwrap(),
        target.known_line()
    );
    let app = Arc::new(
        App::new()
            .with_signer()
            .trusting()
            .answering(&[&[PASSWORD]]),
    );
    let error = connect(&config, &wrong, "db", with_key(), &app)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::HostKeyChanged { alias, mismatch } if alias == "bastion" && mismatch.fingerprint == jump.fingerprint()),
        "{error:?}"
    );
    assert_eq!(target.log.lock().unwrap().connections, target_connections);

    // The target's key is checked too, through the jump host.
    let wrong_target = format!(
        "{}\n[127.0.0.1]:{} {}\n",
        jump.known_line(),
        target.port,
        common::host_key(97).public_key().to_openssh().unwrap(),
    );
    let error = connect(&config, &wrong_target, "db", with_key(), &app)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::HostKeyChanged { alias, .. } if alias == "db"),
        "{error:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_jump_host_that_cant_reach_the_target() {
    let jump = TestServer::start(Spec {
        seed: 12,
        user: "jumper".into(),
        key: Some(phone_key().public_key().clone()),
        forwards: true,
        ..Spec::default()
    })
    .await;
    let closed_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let config = format!(
        "{}  ProxyJump bastion\n{}",
        host_block("db", closed_port, "bob"),
        host_block("bastion", jump.port, "jumper")
    );
    let app = Arc::new(App::new().with_signer());
    let error = connect(&config, &jump.known_line(), "db", with_key(), &app)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::JumpFailed { jump, alias, port, .. } if jump == "bastion" && alias == "db" && *port == closed_port),
        "{error:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn hosts_that_need_ssh_are_never_connected() {
    let server = TestServer::start(key_server(13)).await;
    let app = Arc::new(App::new().with_signer().trusting());
    for extra in [
        "  ProxyCommand nc %h %p\n",
        "  LocalCommand echo connected\n  PermitLocalCommand yes\n",
        "  KnownHostsCommand /bin/cat\n",
    ] {
        let config = format!("{}{extra}", host_block("web", server.port, "alice"));
        let error = connect(&config, &server.known_line(), "web", with_key(), &app)
            .await
            .unwrap_err();
        assert!(
            matches!(
                &error,
                Error::NotAvailable { alias, reason: NotAvailable::RunsProgram { .. } } if alias == "web"
            ),
            "{extra}: {error:?}"
        );
    }
    // `Match host` sees the HostName set above it.
    let config = format!(
        "{}Match host 127.0.0.1 exec \"true\"\n  User x\n",
        host_block("web", server.port, "alice")
    );
    let error = connect(&config, &server.known_line(), "web", with_key(), &app)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::NotAvailable { .. }), "{error:?}");
    // Lines `ssh` reads otherwise than the parser: `=Host web` starts a
    // block for web, so ssh would use the ProxyCommand; and the HostName
    // after `=Host other` isn't web's.
    for config in [
        format!(
            "{}Host nothing\n=Host web\n  ProxyCommand nc evil 22\n",
            host_block("web", server.port, "alice")
        ),
        format!(
            "{}=Host other\n  HostName evil.example.com\n",
            host_block("web", server.port, "alice")
        ),
    ] {
        let error = connect(&config, &server.known_line(), "web", with_key(), &app)
            .await
            .unwrap_err();
        assert!(
            matches!(
                &error,
                Error::NotAvailable {
                    reason: NotAvailable::OddLine { .. },
                    ..
                }
            ),
            "{config}: {error:?}"
        );
    }
    // Nothing went over the network.
    assert_eq!(server.log.lock().unwrap().connections, 0);
    assert!(app.unknown.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn network_failures_are_typed() {
    let app = Arc::new(App::new().with_signer().trusting());

    let closed_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let error = connect(
        &host_block("gone", closed_port, "alice"),
        "",
        "gone",
        with_key(),
        &app,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&error, Error::Refused { alias, port, .. } if alias == "gone" && *port == closed_port),
        "{error:?}"
    );

    // A server that never says hello.
    let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let silent_port = silent.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = silent.accept().await {
            held.push(stream);
        }
    });
    let config = format!(
        "{}  ConnectTimeout 1\n",
        host_block("silent", silent_port, "alice")
    );
    let started = std::time::Instant::now();
    let error = connect(&config, "", "silent", with_key(), &app)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::TimedOut { alias, .. } if alias == "silent"),
        "{error:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(10));

    let error = connect(
        "Host nowhere\n  HostName nowhere.invalid\n  User alice\n",
        "",
        "nowhere",
        with_key(),
        &app,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&error, Error::NameNotFound { host, .. } if host == "nowhere.invalid"),
        "{error:?}"
    );

    // No user anywhere: nothing goes out.
    let error = connect("", "", "127.0.0.1", with_key(), &app)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::NoUser { alias } if alias == "127.0.0.1"),
        "{error:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_default_user_applies() {
    let server = TestServer::start(key_server(14)).await;
    let app = Arc::new(App::new().with_signer());
    let connection = connect(
        &format!("Host web\n  HostName 127.0.0.1\n  Port {}\n", server.port),
        &server.known_line(),
        "web",
        ConnectOptions {
            default_user: Some("alice".into()),
            ..with_key()
        },
        &app,
    )
    .await
    .unwrap();
    assert_eq!(connection.destination().user, None);
    assert_eq!(server.log.lock().unwrap().signed_in, ["publickey"]);
    connection.disconnect().await;
}

/// A shell through a proxy that can stop passing bytes on.
async fn shell_through(
    proxy: &common::Proxy,
    server: &TestServer,
    keepalive: Option<u64>,
) -> Shell {
    let app = Arc::new(App::new().with_signer());
    let config = format!(
        "Host web\n  HostName 127.0.0.1\n  Port {}\n  User alice\n  ServerAliveCountMax 2\n",
        proxy.port
    );
    let known = format!(
        "[127.0.0.1]:{} {}\n",
        proxy.port,
        server.host_key.to_openssh().unwrap()
    );
    let connection = connect(
        &config,
        &known,
        "web",
        ConnectOptions {
            default_keepalive: keepalive.map(Duration::from_secs),
            ..with_key()
        },
        &app,
    )
    .await
    .unwrap();
    let shell = connection
        .open_shell(PtySize { cols: 80, rows: 24 })
        .await
        .unwrap();
    read_until(&shell, "welcome").await;
    shell
}

#[tokio::test(flavor = "multi_thread")]
async fn keepalives_end_a_connection_the_network_dropped() {
    let server = TestServer::start(key_server(17)).await;

    // With keepalive every second, two unanswered asks end it.
    let proxy = common::Proxy::start(server.port).await;
    let shell = shell_through(&proxy, &server, Some(1)).await;
    proxy.freeze();
    let started = std::time::Instant::now();
    let end = closed(&shell).await;
    assert!(end.connection_lost, "{end:?}");
    assert!(started.elapsed() < Duration::from_secs(5));

    // Without it, nothing notices.
    let quiet = common::Proxy::start(server.port).await;
    let shell = shell_through(&quiet, &server, None).await;
    quiet.freeze();
    assert!(
        tokio::time::timeout(Duration::from_secs(4), shell.next_event())
            .await
            .is_err()
    );
}
