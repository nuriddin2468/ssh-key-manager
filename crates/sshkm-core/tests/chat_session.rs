//! A chat between two devices as the app runs one: the knock, a handshake
//! bound to it, `Hello`s naming `chat/1`, a split session, messages,
//! receipts, a message sent twice, and a stranger who gets nothing.

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use sshkm_core::chat::{Body, Conversation, Delivery, Entry};
use sshkm_core::p2p::chat::{ChatFrame, TERMS, new_id};
use sshkm_core::p2p::contact::{answer_knock, knock};
use sshkm_core::p2p::protocol::{CHAT, SecretText, VERSION, features};
use sshkm_core::p2p::{Identity, Message, accept_with, connect_with};

fn hello(name: &str) -> Message {
    Message::Hello {
        version: VERSION,
        name: name.into(),
        known: true,
        own: None,
        features: features(),
    }
}

fn says_chat(message: &Message) -> bool {
    matches!(message, Message::Hello { features, .. } if features.iter().any(|f| f == CHAT))
}

fn entry(frame: &ChatFrame) -> Entry {
    let body = match frame {
        ChatFrame::Text { text, .. } => Body::Text { text: text.clone() },
        ChatFrame::Secret {
            label, value, ttl, ..
        } => Body::Secret {
            label: label.clone(),
            value: Some(value.clone()),
            expires: i64::try_from(*ttl).unwrap(),
            gone: None,
        },
        _ => unreachable!(),
    };
    Entry {
        id: frame.id().unwrap().to_owned(),
        mine: false,
        at: 0,
        body,
        delivery: Delivery::Received,
    }
}

#[test]
fn two_contacts_chat_and_each_message_is_kept_once() {
    let (alice, bob) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let (a, b) = (alice.public(), bob.public());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();

    // Alice answers on her chat port.
    let alice_side = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let key = alice.contact_key(&b).unwrap();
        let knocked = answer_knock(&mut stream, &a, &[(b, &key)])
            .unwrap()
            .unwrap();
        assert_eq!(knocked.peer, b);
        let mut session = accept_with(stream, &alice, &knocked.prologue()).unwrap();
        assert_eq!(session.remote(), b);
        session.send(&hello("alice")).unwrap();
        assert!(says_chat(&session.recv().unwrap()));
        let (mut reader, writer) = session.split().unwrap();
        let mut chat = Conversation::default();
        let mut stored = 0;
        while let Ok(Message::Chat { frame }) = reader.recv() {
            frame.check().unwrap();
            let id = frame.id().unwrap().to_owned();
            if chat.receive(entry(&frame)) {
                stored += 1;
            }
            writer
                .send(&Message::Chat {
                    frame: ChatFrame::Delivered { ids: vec![id] },
                })
                .unwrap();
        }
        (stored, chat)
    });

    // Bob knocks and talks.
    let mut stream = TcpStream::connect(address).unwrap();
    let key = bob.contact_key(&a).unwrap();
    let prologue = knock(&mut stream, &key, &a).unwrap();
    let mut session = connect_with(stream, &bob, &prologue).unwrap();
    assert_eq!(session.remote(), a);
    session.send(&hello("bob")).unwrap();
    assert!(says_chat(&session.recv().unwrap()));
    let (mut reader, writer) = session.split().unwrap();
    let text = ChatFrame::Text {
        id: new_id(),
        text: "on my way".into(),
    };
    let secret = ChatFrame::Secret {
        id: new_id(),
        label: "staging DB".into(),
        value: SecretText::new("hunter2"),
        ttl: TERMS[0],
        pad: String::new(),
    }
    .padded();
    let mut mine = Conversation::default();
    for frame in [&text, &secret] {
        let mut sent = entry(frame);
        sent.mine = true;
        sent.delivery = Delivery::Sending;
        mine.push(sent);
        writer
            .send(&Message::Chat {
                frame: frame.clone(),
            })
            .unwrap();
    }
    // The receipt for the text got lost, say: it goes again, same id.
    writer
        .send(&Message::Chat {
            frame: text.clone(),
        })
        .unwrap();
    for _ in 0..3 {
        let Message::Chat {
            frame: ChatFrame::Delivered { ids },
        } = reader.recv().unwrap()
        else {
            panic!("not a receipt")
        };
        mine.delivered(&ids);
    }
    writer.shutdown();
    assert_eq!(mine.sending(), Vec::<String>::new());
    let (stored, chat) = alice_side.join().unwrap();
    assert_eq!(stored, 2, "the text sent twice is kept once");
    assert_eq!(chat.entries().len(), 2);
}

#[test]
fn a_stranger_at_the_chat_port_gets_a_challenge_and_nothing_else() {
    let (alice, bob, eve) = (
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
    );
    let (a, b) = (alice.public(), bob.public());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let alice_side = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let key = alice.contact_key(&b).unwrap();
        // Not a contact: she hangs up without a handshake.
        answer_knock(&mut stream, &a, &[(b, &key)]).unwrap()
    });
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let eve_key = eve.contact_key(&a).unwrap();
    knock(&mut stream, &eve_key, &a).unwrap();
    assert_eq!(alice_side.join().unwrap(), None);
    // What came was the 16-byte challenge, read by the knock: nothing more,
    // no handshake message with Alice's key in it.
    let mut rest = Vec::new();
    let _ = stream.read_to_end(&mut rest);
    assert_eq!(rest, Vec::<u8>::new());
}
