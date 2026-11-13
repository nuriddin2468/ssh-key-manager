//! A stand-in for another computer's chats, to try them over the network
//! with one machine: two of these chat with each other, as two apps do.
//!
//! ```text
//! cargo run -p sshkm-app --example chat_peer -- /tmp/alice
//! cargo run -p sshkm-app --example chat_peer -- /tmp/bob <alice's key> --send
//! ```
//!
//! Each keeps its device key in `<dir>/identity` and prints its public half.
//! Given the other's key, it treats it as a contact: it announces itself as
//! `_sshkm-chat._tcp` with a tag only that contact recognises, browses for
//! the same service, and recognises the contact's announcement. With
//! `--send` it then connects (knock, handshake bound to it, `Hello`s naming
//! `chat/1`), sends a text and a secret, and prints the receipts. Without,
//! it answers: it prints what comes and sends a receipt for each message.
//! Messages are printed by kind and id: never a secret's value.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use sshkm_app_lib::nearby::chat::CHAT_SERVICE_TYPE;
use sshkm_core::p2p::chat::{ChatFrame, TERMS, new_id};
use sshkm_core::p2p::contact::{self, ContactKey};
use sshkm_core::p2p::own::window;
use sshkm_core::p2p::protocol::{CHAT, SecretText, VERSION, features};
use sshkm_core::p2p::{self, Identity, Message, PeerKey, Session};
use sshkm_core::{ExposeSecret, SecretString};

const WAIT: Duration = Duration::from_secs(60);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dir = args
        .first()
        .ok_or("usage: chat_peer <dir> [<contact key>] [--send]")?;
    let identity = identity(Path::new(dir))?;
    let me = identity.public();
    println!("This device's key: {me}");
    let Some(peer) = args.get(1).filter(|arg| !arg.starts_with("--")) else {
        println!("Give the other's key to chat with it.");
        return Ok(());
    };
    let peer = PeerKey::from_base64(peer)?;
    let key = identity.contact_key(&peer)?;
    let send = args.iter().any(|arg| arg == "--send");

    // Listen and announce, as an app with Nearby open does.
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    let port = listener.local_addr()?.port();
    let daemon = ServiceDaemon::new()?;
    let instance = format!("{:016x}", now() ^ u64::from(port));
    let txt = contact::presence_txt(&me, &[&key], &instance, window(now()));
    let names: Vec<String> = (0..txt.len()).map(|i| format!("t{i}")).collect();
    let mut properties: Vec<(&str, &str)> = vec![("v", "1")];
    properties.extend(
        names
            .iter()
            .map(String::as_str)
            .zip(txt.iter().map(String::as_str)),
    );
    let info = ServiceInfo::new(
        CHAT_SERVICE_TYPE,
        &instance,
        &format!("{instance}.local."),
        (),
        port,
        &properties[..],
    )?
    .enable_addr_auto();
    let fullname = info.get_fullname().to_owned();
    daemon.register(info)?;
    println!("Announced as {instance} on port {port}, with a tag for the contact.");

    let result = if send {
        let addresses = find(&daemon, &fullname, &peer, &key)?;
        talk_to(&identity, &peer, &key, &addresses)
    } else {
        answer(&listener, &identity, &peer, &key)
    };
    let _ = daemon.unregister(&fullname);
    let _ = daemon.shutdown();
    result
}

/// Browses until the contact's announcement is recognised by its tag.
fn find(
    daemon: &ServiceDaemon,
    mine: &str,
    peer: &PeerKey,
    key: &ContactKey,
) -> Result<Vec<SocketAddr>, Box<dyn std::error::Error>> {
    let events = daemon.browse(CHAT_SERVICE_TYPE)?;
    let deadline = Instant::now() + WAIT;
    let mut strangers = 0;
    while Instant::now() < deadline {
        let Ok(ServiceEvent::ServiceResolved(service)) =
            events.recv_timeout(Duration::from_secs(1))
        else {
            continue;
        };
        if service.fullname == mine {
            continue;
        }
        let instance = service
            .fullname
            .strip_suffix(&format!(".{CHAT_SERVICE_TYPE}"))
            .unwrap_or_default();
        let names: Vec<String> = (0..3).map(|i| format!("t{i}")).collect();
        let tags = contact::parse_tags(
            names
                .iter()
                .filter_map(|name| service.get_property_val_str(name)),
        );
        if contact::recognize(&tags, instance, window(now()), &[(*peer, key)]).is_none() {
            strangers += 1;
            continue;
        }
        let addresses: Vec<SocketAddr> = service
            .get_addresses_v4()
            .into_iter()
            .filter(|ip| !ip.is_unspecified())
            .map(|ip| SocketAddr::from((ip, service.port)))
            .collect();
        if addresses.is_empty() {
            continue;
        }
        println!(
            "Recognised the contact as {instance} at {addresses:?} ({strangers} other announcements skipped)."
        );
        return Ok(addresses);
    }
    Err("the contact wasn't found on the network".into())
}

/// Connects to the contact, sends a text and a secret, and waits for the receipts.
fn talk_to(
    identity: &Identity,
    peer: &PeerKey,
    key: &ContactKey,
    addresses: &[SocketAddr],
) -> Result<(), Box<dyn std::error::Error>> {
    // As the app does: each address the announcement gave, until one answers.
    let mut stream = addresses
        .iter()
        .find_map(|address| TcpStream::connect_timeout(address, Duration::from_secs(3)).ok())
        .ok_or("none of the contact's addresses answered")?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let prologue = contact::knock(&mut stream, key, peer)?;
    let session = p2p::connect_with(stream, identity, &prologue)?;
    if session.remote() != *peer {
        return Err("someone else answered".into());
    }
    let (mut reader, writer) = hello(session)?;
    let text = ChatFrame::Text {
        id: new_id(),
        text: "Hello from chat_peer".into(),
    };
    let secret = ChatFrame::Secret {
        id: new_id(),
        label: "test secret".into(),
        value: SecretText::new("not printed anywhere"),
        ttl: TERMS[0],
        pad: String::new(),
    }
    .padded();
    let mut waiting: Vec<String> = Vec::new();
    for frame in [text, secret] {
        waiting.push(frame.id().unwrap_or_default().to_owned());
        println!("Sent {frame:?}");
        writer.send(&Message::Chat { frame })?;
    }
    while !waiting.is_empty() {
        match reader.recv()? {
            Message::Chat {
                frame: ChatFrame::Delivered { ids },
            } => {
                for id in &ids {
                    println!("Delivered: {id}");
                }
                waiting.retain(|id| !ids.contains(id));
            }
            Message::Chat { frame } => println!("Got {frame:?}"),
            other => return Err(format!("not a chat frame: {other:?}").into()),
        }
    }
    println!("Both messages were delivered.");
    writer.shutdown();
    Ok(())
}

/// Answers one chat: prints what comes, by kind, and sends receipts.
fn answer(
    listener: &TcpListener,
    identity: &Identity,
    peer: &PeerKey,
    key: &ContactKey,
) -> Result<(), Box<dyn std::error::Error>> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + WAIT;
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(error.into()),
        }
    };
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let me = identity.public();
    let Some(knocked) = contact::answer_knock(&mut stream, &me, &[(*peer, key)])? else {
        return Err("a stranger knocked: it got nothing".into());
    };
    let session = p2p::accept_with(stream, identity, &knocked.prologue())?;
    if session.remote() != knocked.peer {
        return Err("the handshake's key isn't the one that knocked".into());
    }
    println!("The contact knocked and is in.");
    let (mut reader, writer) = hello(session)?;
    while let Ok(message) = reader.recv() {
        let Message::Chat { frame } = message else {
            return Err("not a chat frame".into());
        };
        frame
            .check()
            .map_err(|reason| format!("refused: {reason:?}"))?;
        match &frame {
            ChatFrame::Text { text, .. } => println!("Text: {text}"),
            ChatFrame::Secret { label, value, .. } => {
                println!(
                    "Secret \"{label}\" of {} characters, hidden",
                    value.expose().chars().count()
                );
            }
            other => println!("Got {other:?}"),
        }
        if let Some(id) = frame.id() {
            writer.send(&Message::Chat {
                frame: ChatFrame::Delivered {
                    ids: vec![id.to_owned()],
                },
            })?;
        }
    }
    println!("The contact hung up.");
    Ok(())
}

/// The `Hello`s both ways, which must name `chat/1`; then the session in two.
fn hello(
    mut session: Session<TcpStream>,
) -> Result<(p2p::session::Reader, p2p::session::Writer), Box<dyn std::error::Error>> {
    session.send(&Message::Hello {
        version: VERSION,
        name: "chat_peer".into(),
        known: true,
        own: None,
        features: features(),
    })?;
    let Message::Hello { features, .. } = session.recv()? else {
        return Err("no hello".into());
    };
    if !features.iter().any(|feature| feature == CHAT) {
        return Err("the other side doesn't chat".into());
    }
    session
        .stream()
        .set_read_timeout(Some(Duration::from_secs(30)))?;
    Ok(session.split()?)
}

fn identity(dir: &Path) -> Result<Identity, Box<dyn std::error::Error>> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join("identity");
    if let Ok(secret) = std::fs::read_to_string(&path) {
        return Ok(Identity::from_secret(&SecretString::from(
            secret.trim().to_owned(),
        ))?);
    }
    let identity = Identity::generate()?;
    std::fs::write(&path, identity.to_secret().expose_secret())?;
    Ok(identity)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
