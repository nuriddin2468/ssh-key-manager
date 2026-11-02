use super::*;
use crate::{
    ErrorCode,
    keys::{self, testdata as td},
};

/// Loads a fixture key through the normal file path.
fn fixture_key(dir: &Path, name: &str, contents: &str) -> UnlockedKey {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    keys::load_private(&path, None).unwrap()
}

fn fingerprint_of(public_line: &str) -> String {
    let key = ssh_key::PublicKey::from_openssh(public_line.trim()).unwrap();
    keys::fingerprint(key.key_data())
}

#[test]
fn add_request_layout() {
    let dir = tempfile::tempdir().unwrap();
    let key = fixture_key(dir.path(), "k", td::OPENSSH_ED25519);
    let plain = proto::add_identity(key.keypair(), "c", None, false).unwrap();
    assert_eq!(plain[0], proto::ADD_IDENTITY);
    // string "ssh-ed25519"
    assert_eq!(&plain[1..5], &[0, 0, 0, 11]);
    assert_eq!(&plain[5..16], b"ssh-ed25519");
    assert!(plain.ends_with(&[0, 0, 0, 1, b'c']));

    let constrained = proto::add_identity(key.keypair(), "c", Some(300), true).unwrap();
    assert_eq!(constrained[0], proto::ADD_ID_CONSTRAINED);
    assert!(constrained.ends_with(&[0, 0, 0, 1, b'c', 1, 0, 0, 1, 44, 2]));
}

#[test]
fn identities_answer_parsing() {
    let blob = proto::public_key_blob(td::OPENSSH_ED25519_PUB).unwrap();
    let mut reply = vec![proto::IDENTITIES_ANSWER, 0, 0, 0, 2];
    for (b, c) in [
        (&blob[..], "first"),
        (&[0, 0, 0, 3, b'f', b'o', b'o'][..], ""),
    ] {
        reply.extend(u32::try_from(b.len()).unwrap().to_be_bytes());
        reply.extend(b);
        reply.extend(u32::try_from(c.len()).unwrap().to_be_bytes());
        reply.extend(c.as_bytes());
    }
    let ids = proto::parse_identities(&reply).unwrap();
    assert_eq!(ids.len(), 2);
    assert_eq!(ids[0].fingerprint, fingerprint_of(td::OPENSSH_ED25519_PUB));
    assert_eq!(ids[0].algorithm, KeyAlgorithm::Ed25519);
    assert_eq!(ids[0].comment, "first");
    assert_eq!(ids[1].algorithm, KeyAlgorithm::Other);
    assert_eq!(ids[1].key_type, "foo");
    assert!(ids[1].fingerprint.starts_with("SHA256:"));

    for bad in [
        &[][..],
        &[12],
        &[12, 0, 0, 0, 1],
        &[12, 0, 0, 0, 1, 0, 0, 0, 9],
        &[42],
    ] {
        assert_eq!(
            proto::parse_identities(bad).unwrap_err().code(),
            ErrorCode::AgentUnavailable
        );
    }
    assert_eq!(
        proto::parse_identities(&[5]).unwrap_err().code(),
        ErrorCode::AgentRefused
    );
}

#[test]
fn reply_codes() {
    proto::expect_success(&[6], "x").unwrap();
    assert_eq!(
        proto::expect_success(&[5], "x").unwrap_err().code(),
        ErrorCode::AgentRefused
    );
    assert_eq!(
        proto::expect_success(&[28], "x").unwrap_err().code(),
        ErrorCode::AgentRefused
    );
    assert_eq!(
        proto::expect_success(&[99], "x").unwrap_err().code(),
        ErrorCode::AgentUnavailable
    );
    assert_eq!(
        proto::expect_success(&[], "x").unwrap_err().code(),
        ErrorCode::AgentUnavailable
    );
}

#[test]
fn public_key_lines() {
    assert!(proto::public_key_blob(td::OPENSSH_ED25519_PUB).is_ok());
    for bad in [
        "",
        "ssh-ed25519",
        "ssh-ed25519 !!!",
        "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIBIZFNq0hlvHGZ/oas65Ba4jkcFEy3dX/aRZy70M73oL",
    ] {
        assert_eq!(
            proto::public_key_blob(bad).unwrap_err().code(),
            ErrorCode::InvalidInput,
            "{bad}"
        );
    }
}

#[test]
fn missing_socket_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    // Windows reaches the agent through a named pipe; any other path is
    // `Unsupported` there (see `non_pipe_path_is_unsupported_on_windows`).
    let socket = if cfg!(windows) {
        PathBuf::from(format!(
            r"\\.\pipe\sshkm-test-missing-{}",
            std::process::id()
        ))
    } else {
        dir.path().join("nope.sock")
    };
    let client = AgentClient::new(socket);
    let status = client.status();
    assert!(!status.available);
    assert_eq!(status.error, Some(AgentProblem::NotFound));
    assert_eq!(
        client.list().unwrap_err().code(),
        ErrorCode::AgentUnavailable
    );
    let v = serde_json::to_value(&status).unwrap();
    assert_eq!(v["error"], "notFound");
}

#[cfg(windows)]
#[test]
fn non_pipe_path_is_unsupported_on_windows() {
    let dir = tempfile::tempdir().unwrap();
    let client = AgentClient::new(dir.path().join("agent.sock"));
    let status = client.status();
    assert!(!status.available);
    assert_eq!(status.error, Some(AgentProblem::Unsupported));
    assert_eq!(
        client.list().unwrap_err().code(),
        ErrorCode::AgentUnavailable
    );
}

#[cfg(unix)]
mod mock {
    use std::{
        io::{Read, Write},
        os::unix::net::{UnixListener, UnixStream},
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
        thread,
        time::Duration,
    };

    use ssh_encoding::{Decode, Encode};
    use ssh_key::{private::KeypairData, public::KeyData};

    #[derive(Debug)]
    pub(super) struct Stored {
        pub(super) blob: Vec<u8>,
        pub(super) comment: String,
        pub(super) lifetime: Option<u32>,
        pub(super) confirm: bool,
    }

    #[derive(Default)]
    pub(super) struct State {
        pub(super) keys: Vec<Stored>,
        /// Never answer (to test timeouts).
        pub(super) silent: bool,
    }

    /// An in-process agent implementing the messages the client uses.
    pub(super) fn spawn(dir: &Path) -> (PathBuf, Arc<Mutex<State>>) {
        let path = dir.join("agent.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let state = Arc::new(Mutex::new(State::default()));
        let shared = Arc::clone(&state);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let state = Arc::clone(&shared);
                thread::spawn(move || serve(stream, &state));
            }
        });
        (path, state)
    }

    fn serve(mut stream: UnixStream, state: &Mutex<State>) {
        loop {
            let mut len = [0u8; 4];
            if stream.read_exact(&mut len).is_err() {
                return;
            }
            let mut body = vec![0; usize::try_from(u32::from_be_bytes(len)).unwrap()];
            if stream.read_exact(&mut body).is_err() {
                return;
            }
            if state.lock().unwrap().silent {
                thread::sleep(Duration::from_secs(2));
                return;
            }
            let reply = handle(&body, &mut state.lock().unwrap());
            let mut frame = u32::try_from(reply.len()).unwrap().to_be_bytes().to_vec();
            frame.extend(reply);
            if stream.write_all(&frame).is_err() {
                return;
            }
        }
    }

    fn handle(body: &[u8], state: &mut State) -> Vec<u8> {
        let fail = || vec![5u8];
        let Some((&kind, mut rest)) = body.split_first() else {
            return fail();
        };
        match kind {
            11 => {
                let mut out = vec![12];
                u32::try_from(state.keys.len())
                    .unwrap()
                    .encode(&mut out)
                    .unwrap();
                for k in &state.keys {
                    k.blob.encode(&mut out).unwrap();
                    k.comment.encode(&mut out).unwrap();
                }
                out
            }
            17 | 25 => {
                let Ok(keypair) = KeypairData::decode(&mut rest) else {
                    return fail();
                };
                let Ok(comment) = String::decode(&mut rest) else {
                    return fail();
                };
                let (mut lifetime, mut confirm) = (None, false);
                while let Some((&constraint, tail)) = rest.split_first() {
                    rest = tail;
                    match constraint {
                        1 => match u32::decode(&mut rest) {
                            Ok(secs) => lifetime = Some(secs),
                            Err(_) => return fail(),
                        },
                        2 => confirm = true,
                        _ => return fail(),
                    }
                }
                if (kind == 25) != (lifetime.is_some() || confirm) {
                    return fail();
                }
                let Ok(public) = KeyData::try_from(&keypair) else {
                    return fail();
                };
                let blob = ssh_key::PublicKey::from(public).to_bytes().unwrap();
                state.keys.retain(|k| k.blob != blob);
                state.keys.push(Stored {
                    blob,
                    comment,
                    lifetime,
                    confirm,
                });
                vec![6]
            }
            18 => {
                let Ok(blob) = Vec::<u8>::decode(&mut rest) else {
                    return fail();
                };
                let before = state.keys.len();
                state.keys.retain(|k| k.blob != blob);
                if state.keys.len() < before {
                    vec![6]
                } else {
                    fail()
                }
            }
            19 => {
                state.keys.clear();
                vec![6]
            }
            _ => fail(),
        }
    }
}

#[cfg(unix)]
#[test]
fn mock_round_trip_add_list_remove() {
    let dir = tempfile::tempdir().unwrap();
    let (socket, state) = mock::spawn(dir.path());
    let client = AgentClient::new(&socket);

    let status = client.status();
    assert!(status.available, "{status:?}");
    assert_eq!(status.identities, Some(0));

    let key = fixture_key(dir.path(), "id_ed25519", td::OPENSSH_ED25519);
    client
        .add(&key, "/home/me/.ssh/id_ed25519", None, false)
        .unwrap();
    let ids = client.list().unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].fingerprint, key.fingerprint());
    assert_eq!(ids[0].fingerprint, fingerprint_of(td::OPENSSH_ED25519_PUB));
    assert_eq!(ids[0].comment, "/home/me/.ssh/id_ed25519");
    assert_eq!(ids[0].algorithm, KeyAlgorithm::Ed25519);
    assert_eq!(ids[0].bits, Some(256));
    assert!(!ids[0].certificate);
    assert!(ids[0].public_key.starts_with("ssh-ed25519 AAAA"));
    assert_eq!(client.status().identities, Some(1));

    client.remove(&ids[0].public_key).unwrap();
    assert_eq!(client.list().unwrap(), Vec::<AgentIdentity>::new());
    assert_eq!(
        client.remove(td::OPENSSH_ED25519_PUB).unwrap_err().code(),
        ErrorCode::AgentRefused
    );
    assert_eq!(state.lock().unwrap().keys.len(), 0);
}

#[cfg(unix)]
#[test]
fn mock_constraints_and_other_algorithms() {
    let dir = tempfile::tempdir().unwrap();
    let (socket, state) = mock::spawn(dir.path());
    let client = AgentClient::new(&socket);

    let rsa = fixture_key(dir.path(), "rsa", td::RSA_PEM);
    let ec = fixture_key(dir.path(), "ec", td::EC_PEM_EXPLICIT);
    client.add(&rsa, "rsa", Some(600), true).unwrap();
    client.add(&ec, "ec", None, true).unwrap();
    {
        let st = state.lock().unwrap();
        assert_eq!((st.keys[0].lifetime, st.keys[0].confirm), (Some(600), true));
        assert_eq!((st.keys[1].lifetime, st.keys[1].confirm), (None, true));
    }
    let ids = client.list().unwrap();
    assert_eq!(ids[0].fingerprint, fingerprint_of(td::RSA_PEM_PUB));
    assert_eq!(ids[0].bits, Some(2048));
    assert_eq!(ids[1].fingerprint, fingerprint_of(td::EC_PEM_EXPLICIT_PUB));
    assert_eq!(
        client.add(&rsa, "rsa", Some(0), false).unwrap_err().code(),
        ErrorCode::InvalidInput
    );

    client.remove_all().unwrap();
    assert_eq!(client.list().unwrap(), Vec::<AgentIdentity>::new());
}

#[cfg(unix)]
#[test]
fn mock_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let (socket, state) = mock::spawn(dir.path());
    state.lock().unwrap().silent = true;
    let client = AgentClient::new(&socket).with_timeout(Duration::from_millis(200));
    let status = client.status();
    assert!(!status.available);
    assert_eq!(status.error, Some(AgentProblem::Timeout));
}

#[cfg(unix)]
#[test]
fn not_a_socket() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("plain-file");
    std::fs::write(&file, "x").unwrap();
    let status = AgentClient::new(&file).status();
    assert!(!status.available);
    assert!(status.error.is_some());
}

/// Talks to a private `ssh-agent` started in a temporary directory (never the
/// user's agent). Run with `cargo test -- --ignored`.
#[cfg(unix)]
#[test]
#[ignore = "needs the ssh-agent binary"]
fn real_ssh_agent_round_trip() {
    use std::process::{Command, Stdio};
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    let mut child = Command::new("ssh-agent")
        .arg("-D")
        .arg("-a")
        .arg(&socket)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let result = std::panic::catch_unwind(|| {
        let client = AgentClient::new(&socket);
        assert!(client.status().available);
        let ed = fixture_key(dir.path(), "ed", td::OPENSSH_ED25519);
        let rsa = fixture_key(dir.path(), "rsa", td::RSA_PEM);
        let ec = fixture_key(dir.path(), "ec", td::EC_PEM_EXPLICIT);
        let enc = {
            let path = dir.path().join("enc");
            std::fs::write(&path, td::OPENSSH_ED25519_ENCRYPTED).unwrap();
            keys::load_private(
                &path,
                Some(&crate::SecretString::from(td::KEYGEN_PASSPHRASE)),
            )
            .unwrap()
        };
        client.add(&ed, "ed", None, false).unwrap();
        client.add(&rsa, "rsa", Some(300), false).unwrap();
        client.add(&ec, "ec", None, true).unwrap();
        client.add(&enc, "enc", Some(60), true).unwrap();
        let ids = client.list().unwrap();
        let fps: Vec<_> = ids.iter().map(|i| i.fingerprint.as_str()).collect();
        for expected in [
            fingerprint_of(td::OPENSSH_ED25519_PUB),
            fingerprint_of(td::RSA_PEM_PUB),
            fingerprint_of(td::EC_PEM_EXPLICIT_PUB),
            fingerprint_of(td::OPENSSH_ED25519_ENCRYPTED_PUB),
        ] {
            assert!(
                fps.contains(&expected.as_str()),
                "{expected} not in {fps:?}"
            );
        }
        client.remove(td::RSA_PEM_PUB).unwrap();
        assert_eq!(client.list().unwrap().len(), 3);
        assert_eq!(
            client.remove(td::RSA_PEM_PUB).unwrap_err().code(),
            ErrorCode::AgentRefused
        );
        client.remove_all().unwrap();
        assert_eq!(client.list().unwrap(), Vec::<AgentIdentity>::new());
    });
    let _ = child.kill();
    let _ = child.wait();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
