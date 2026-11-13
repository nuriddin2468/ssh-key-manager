//! Sending one item to a contact, after [`conversation`] made sure the two
//! know each other.
//!
//! The side that connected offers the item: what it is, nothing secret. The
//! other user accepts or turns it down; only after a yes does the item go
//! over, and the receiver checks that it is what was offered and that every
//! field is something it may save before it saves it.
//!
//! Any device can announce any name, so the name the user picked a device
//! under says nothing about who answers. When a contact answers that this
//! vault knows by another name, the sending user says first whether it is
//! the one they meant; until then nothing goes to it, not even the offer.
//! An item with a secret in it (a password, an environment) goes only after
//! the user's yes in a system dialog that names the device as this vault
//! knows it ([`Side::allow_send`]).
//!
//! [`conversation`]: super::pairing::conversation

use std::net::TcpStream;
use std::time::Duration;

use sshkm_core::p2p::protocol::{Item, ItemSummary};
use sshkm_core::p2p::{Message, Session};

use super::pairing::{ANSWER_TIMEOUT, PairingFailure, PairingPhase, Side, broken, wait_for_answer};

/// How long the side that was connected to waits for an offer after
/// pairing, while the other user may be asked whether it is the device
/// they meant; a side that only paired hangs up at once.
const OFFER_WAIT: Duration = Duration::from_secs(ANSWER_TIMEOUT.as_secs() + 10);
/// How long a step takes once both users have answered.
pub(super) const STEP_TIMEOUT: Duration = Duration::from_secs(30);

/// Offers `item` and sends it once the other user accepts. `known` is the
/// name this vault keeps for the other side, if it knew it before, and
/// `to` the name the user picked it under; when the two differ, this user
/// first says whether to send it all the same, and on a no nothing goes.
/// An item that needs a feature the other side didn't name (`features`) is
/// not even offered.
pub fn send(
    session: &mut Session<TcpStream>,
    side: &impl Side,
    item: &Item,
    known: Option<&str>,
    to: Option<&str>,
    features: &[String],
) -> PairingPhase {
    if let Some(needed) = item.requires()
        && !features.iter().any(|feature| feature == needed)
    {
        return PairingPhase::Failed {
            reason: PairingFailure::PeerUnsupported,
        };
    }
    if let (Some(known), Some(to)) = (known, to)
        && known != to
    {
        side.show(
            None,
            &PairingPhase::NameMismatch {
                announced: to.to_owned(),
            },
        );
        match wait_for_answer(session, side) {
            Ok((true, _)) => {}
            Ok((false, _)) => {
                return PairingPhase::Failed {
                    reason: PairingFailure::Cancelled,
                };
            }
            Err(reason) => return PairingPhase::Failed { reason },
        }
    }
    // As the other side can take it: a server's password goes for no host
    // to a version that would bind it to whatever the alias leads to there.
    let item = &item.clone().for_peer(features);
    let summary = item.summary();
    // A secret goes only after this user's yes in a system dialog that
    // names the device it goes to: what the page says (that the codes
    // match, which device was picked) is never enough for one.
    if matches!(item, Item::Password { .. } | Item::Environment { .. }) && !side.allow_send(item) {
        return PairingPhase::Failed {
            reason: PairingFailure::Cancelled,
        };
    }
    side.show(
        None,
        &PairingPhase::Offering {
            item: summary.clone(),
        },
    );
    let result = (|| {
        session
            .send(&Message::Offer {
                item: summary.clone(),
            })
            .map_err(|_| PairingFailure::Broken)?;
        let _ = session.stream().set_read_timeout(Some(ANSWER_TIMEOUT));
        match session.recv().map_err(broken)? {
            Message::Reply { accepted: true, .. } => {}
            Message::Reply {
                accepted: false,
                unsupported: true,
            } => return Err(PairingFailure::PeerUnsupported),
            Message::Reply {
                accepted: false, ..
            } => return Err(PairingFailure::Refused),
            Message::Unknown => return Err(PairingFailure::Unsupported),
            _ => return Err(PairingFailure::Broken),
        }
        // The receiver may ask its user in a system dialog before it saves.
        let _ = session
            .stream()
            .set_read_timeout(Some(ANSWER_TIMEOUT + STEP_TIMEOUT));
        session
            .send(&Message::Payload { item: item.clone() })
            .map_err(|_| PairingFailure::Broken)?;
        match session.recv().map_err(broken)? {
            Message::Received { saved: true } => Ok(PairingPhase::Sent {
                item: summary.clone(),
            }),
            Message::Received { saved: false } => Err(PairingFailure::NotSaved),
            _ => Err(PairingFailure::Broken),
        }
    })();
    result.unwrap_or_else(|reason| PairingPhase::Failed { reason })
}

/// Receives the item the other side offers, if it offers one: `None` when
/// it hung up instead (it only paired).
pub fn receive(session: &mut Session<TcpStream>, side: &impl Side) -> Option<PairingPhase> {
    let _ = session.stream().set_read_timeout(Some(OFFER_WAIT));
    let summary = match session.recv() {
        // A kind this version doesn't know: said so, never asked about.
        Ok(Message::Offer {
            item: ItemSummary::Unknown,
        }) => {
            let _ = session.send(&Message::Reply {
                accepted: false,
                unsupported: true,
            });
            return Some(PairingPhase::Failed {
                reason: PairingFailure::Unsupported,
            });
        }
        Ok(Message::Offer { item }) => item,
        Ok(Message::Unknown) => {
            return Some(PairingPhase::Failed {
                reason: PairingFailure::Unsupported,
            });
        }
        Ok(_) => {
            return Some(PairingPhase::Failed {
                reason: PairingFailure::Broken,
            });
        }
        Err(_) => return None,
    };
    side.show(
        None,
        &PairingPhase::Offered {
            item: summary.clone(),
        },
    );
    let result = (|| {
        let (accepted, _) = wait_for_answer(session, side)?;
        session
            .send(&Message::Reply {
                accepted,
                unsupported: false,
            })
            .map_err(|_| PairingFailure::Broken)?;
        if !accepted {
            return Err(PairingFailure::Turned);
        }
        let _ = session.stream().set_read_timeout(Some(STEP_TIMEOUT));
        let Message::Payload { item } = session.recv().map_err(broken)? else {
            return Err(PairingFailure::Broken);
        };
        // What was offered, and nothing a name could smuggle a command in.
        if item.summary() != summary || item.check().is_err() {
            let _ = session.send(&Message::Received { saved: false });
            return Err(PairingFailure::Broken);
        }
        match side.store(&item) {
            Ok(stored) => {
                let _ = session.send(&Message::Received { saved: true });
                Ok(PairingPhase::Received {
                    item: summary.clone(),
                    name: stored.name,
                    keys_differ: stored.keys_differ,
                    left_out: stored.left_out,
                })
            }
            Err(reason) => {
                let _ = session.send(&Message::Received { saved: false });
                Err(reason)
            }
        }
    })();
    Some(result.unwrap_or_else(|reason| PairingPhase::Failed { reason }))
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    use sshkm_core::p2p::protocol::{HostKey, HostsEntry, ItemSummary, Server, VERSION};
    use sshkm_core::p2p::{Identity, accept, connect};

    use super::super::pairing::{Purpose, conversation};
    use super::super::script::{Script, codes, peers, run, talk_as};
    use super::*;

    fn password() -> Item {
        Item::Password {
            title: "prod DB".into(),
            username: "deploy".into(),
            password: "s3cret".into(),
            url: String::new(),
            notes: String::new(),
            otp: None,
            host: None,
            server: None,
        }
    }

    fn host() -> Item {
        Item::Host {
            alias: "prod".into(),
            host_name: Some("10.0.4.12".into()),
            user: Some("deploy".into()),
            port: None,
            proxy_jump: None,
            host_keys: vec![HostKey {
                key_type: "ssh-ed25519".into(),
                key: "AAAAC3NzaC1lZDI1NTE5AAAAIBIZ".into(),
            }],
        }
    }

    fn group() -> Item {
        Item::HostsGroup {
            name: "dev".into(),
            entries: vec![HostsEntry {
                address: "10.0.4.12".into(),
                names: vec!["api.dev.local".into()],
                enabled: true,
                expires: None,
            }],
        }
    }

    fn public_key() -> Item {
        Item::PublicKey {
            name: "id_ed25519".into(),
            key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBIZFNq0hlvHGZ/oas65Ba4jkcFEy3dX/aRZy70M73oL aziz@mac".into(),
        }
    }

    fn failed(reason: PairingFailure) -> PairingPhase {
        PairingPhase::Failed { reason }
    }

    #[test]
    fn pairs_then_sends_and_the_receiver_saves() {
        let right = Script::answering("bob", &[Some(true), Some(true)]);
        let ((left_end, left), (right_end, right)) =
            run(Script::new("alice", Some(true)), right, Some(&password()));
        let summary = password().summary();
        assert_eq!(
            left_end,
            PairingPhase::Sent {
                item: summary.clone()
            }
        );
        assert_eq!(
            right_end,
            PairingPhase::Received {
                item: summary,
                name: "prod DB".into(),
                keys_differ: false,
                left_out: Vec::new(),
            }
        );
        assert_eq!(*right.stored.lock().unwrap(), [password()]);
        assert_eq!(codes(&left), codes(&right));
        assert_eq!(*right.saved.lock().unwrap(), ["alice"]);
    }

    #[test]
    fn contacts_send_without_a_code() {
        let mut left = Script::new("alice", Some(true));
        left.knows = true;
        let mut right = Script::new("bob", Some(true));
        right.knows = true;
        let ((left_end, left), (right_end, right)) = run(left, right, Some(&host()));
        assert!(matches!(left_end, PairingPhase::Sent { .. }));
        assert!(matches!(right_end, PairingPhase::Received { .. }));
        assert_eq!(codes(&left), Vec::<String>::new());
        assert!(
            right
                .shown
                .lock()
                .unwrap()
                .iter()
                .any(|(_, phase)| matches!(
                    phase,
                    PairingPhase::Offered {
                        item: ItemSummary::Host { .. }
                    }
                ))
        );
    }

    fn asked(side: &Script) -> bool {
        side.shown
            .lock()
            .unwrap()
            .iter()
            .any(|(_, phase)| matches!(phase, PairingPhase::NameMismatch { .. }))
    }

    /// Alice, who has Bob and Carol as contacts and answers `answer`, and
    /// Carol, who has Alice as a contact and calls herself by Bob's name.
    fn carol_as_bob(answer: Option<bool>) -> ((Script, Identity), (Script, Identity)) {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let carol = Identity::generate().unwrap();
        let mut left = Script::new("Alice", answer);
        left.contacts = vec![(bob.public(), "Bob's MacBook"), (carol.public(), "Carol")];
        let mut right = Script::new("Bob's MacBook", Some(true));
        right.contacts = vec![(alice.public(), "Alice")];
        ((left, alice), (right, carol))
    }

    #[test]
    fn a_contact_answering_in_another_ones_name_gets_nothing_on_a_no() {
        let (alice, carol) = carol_as_bob(Some(false));
        let item = password();
        let to = Some("Bob's MacBook");
        let ((left_end, left), (right_end, right)) =
            talk_as(alice, carol, Purpose::Send { item: &item, to });
        assert_eq!(left_end, failed(PairingFailure::Cancelled));
        // Alice's screen names Carol, by the name her vault keeps, and asks
        // before anything goes.
        assert_eq!(peers(&left), ["Carol"]);
        assert!(left.shown.lock().unwrap().iter().any(|(_, phase)| {
            *phase
                == PairingPhase::NameMismatch {
                    announced: "Bob's MacBook".into(),
                }
        }));
        assert_eq!(codes(&left), Vec::<String>::new());
        // Carol got no offer, let alone the password.
        assert_eq!(right_end, PairingPhase::Known);
        assert!(
            right
                .shown
                .lock()
                .unwrap()
                .iter()
                .all(|(_, phase)| !matches!(phase, PairingPhase::Offered { .. }))
        );
        assert_eq!(*right.stored.lock().unwrap(), Vec::<Item>::new());
    }

    #[test]
    fn a_contact_answering_in_another_ones_name_gets_it_on_a_yes() {
        let (alice, carol) = carol_as_bob(Some(true));
        let item = password();
        let to = Some("Bob's MacBook");
        let ((left_end, left), (right_end, right)) =
            talk_as(alice, carol, Purpose::Send { item: &item, to });
        assert_eq!(
            left_end,
            PairingPhase::Sent {
                item: item.summary()
            }
        );
        assert!(matches!(right_end, PairingPhase::Received { .. }));
        assert_eq!(peers(&left), ["Carol"]);
        assert_eq!(peers(&right), ["Alice"]);
        // The question came before the offer.
        let shown = left.shown.lock().unwrap();
        let position =
            |of: fn(&PairingPhase) -> bool| shown.iter().position(|(_, p)| of(p)).unwrap();
        assert!(
            position(|p| matches!(p, PairingPhase::NameMismatch { .. }))
                < position(|p| matches!(p, PairingPhase::Offering { .. }))
        );
    }

    #[test]
    fn a_contact_under_the_name_it_was_picked_by_is_not_asked_about() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        // A "no" from Alice would stop it.
        let mut left = Script::new("Alice", Some(false));
        left.contacts = vec![(bob.public(), "Bob's MacBook")];
        let mut right = Script::new("Bob's MacBook", Some(true));
        right.contacts = vec![(alice.public(), "Alice")];
        let item = host();
        let to = Some("Bob's MacBook");
        let ((left_end, left), (right_end, _)) = talk_as(
            (left, alice),
            (right, bob),
            Purpose::Send { item: &item, to },
        );
        assert_eq!(
            left_end,
            PairingPhase::Sent {
                item: item.summary()
            }
        );
        assert!(matches!(right_end, PairingPhase::Received { .. }));
        assert!(!asked(&left));

        // Reached by its address, there is no name to hold it against.
        let (alice, carol) = carol_as_bob(Some(false));
        let ((left_end, left), _) = talk_as(
            alice,
            carol,
            Purpose::Send {
                item: &item,
                to: None,
            },
        );
        assert!(matches!(left_end, PairingPhase::Sent { .. }));
        assert!(!asked(&left));
        assert_eq!(peers(&left), ["Carol"]);
    }

    #[test]
    fn an_offer_names_the_contact_it_comes_from() {
        // Carol, as "Bob's MacBook", offers Alice a host.
        let ((alice, alice_key), (carol, carol_key)) = carol_as_bob(Some(true));
        let item = host();
        let (_, (right_end, right)) = talk_as(
            (carol, carol_key),
            (alice, alice_key),
            Purpose::Send {
                item: &item,
                to: None,
            },
        );
        assert!(matches!(right_end, PairingPhase::Received { .. }));
        assert_eq!(peers(&right), ["Carol"]);
    }

    #[test]
    fn sends_hosts_groups_and_public_keys() {
        for item in [group(), public_key()] {
            let mut left = Script::new("alice", Some(true));
            left.knows = true;
            let mut right = Script::new("bob", Some(true));
            right.knows = true;
            let ((left_end, _), (right_end, right)) = run(left, right, Some(&item));
            assert_eq!(
                left_end,
                PairingPhase::Sent {
                    item: item.summary()
                }
            );
            assert!(matches!(right_end, PairingPhase::Received { .. }));
            assert_eq!(*right.stored.lock().unwrap(), [item]);
        }
    }

    #[test]
    fn a_secret_goes_only_after_the_system_dialogs_yes() {
        let environment = Item::Environment {
            project: "shop".into(),
            name: "prod".into(),
            notes: String::new(),
            variables: Vec::new(),
        };
        for item in [password(), environment] {
            // Contacts: no code, no question on the page; the system dialog
            // says no.
            let mut left = Script::new("alice", Some(true));
            left.knows = true;
            left.allows_send = false;
            let mut right = Script::new("bob", Some(true));
            right.knows = true;
            let ((left_end, left), (right_end, right)) = run(left, right, Some(&item));
            assert_eq!(left_end, failed(PairingFailure::Cancelled));
            assert_eq!(right_end, PairingPhase::Known);
            assert_eq!(*left.asked_to_send.lock().unwrap(), [item.summary()]);
            // Not even the offer went.
            assert!(
                right
                    .shown
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|(_, phase)| !matches!(phase, PairingPhase::Offered { .. }))
            );
            assert_eq!(*right.stored.lock().unwrap(), Vec::<Item>::new());
        }
        // What holds no secret goes without one.
        let mut left = Script::new("alice", Some(true));
        left.knows = true;
        left.allows_send = false;
        let mut right = Script::new("bob", Some(true));
        right.knows = true;
        let ((left_end, left), _) = run(left, right, Some(&host()));
        assert!(matches!(left_end, PairingPhase::Sent { .. }));
        assert!(left.asked_to_send.lock().unwrap().is_empty());
    }

    /// Nothing at the receiving end lets its user pick an environment's
    /// variables one by one, so those that make programs run code are left
    /// out there, and named; the sender's dialog names them too.
    #[test]
    fn variables_that_run_code_are_named_where_an_environment_arrives() {
        let var = |name: &str| sshkm_core::p2p::protocol::EnvVariable {
            name: name.into(),
            value: "x".into(),
            secret: false,
            note: String::new(),
        };
        let item = Item::Environment {
            project: "shop".into(),
            name: "dev".into(),
            notes: String::new(),
            variables: vec![var("PORT"), var("NODE_OPTIONS"), var("BASH_ENV")],
        };
        let mut left = Script::new("alice", Some(true));
        left.knows = true;
        let mut right = Script::new("bob", Some(true));
        right.knows = true;
        let ((left_end, _), (right_end, _)) = run(left, right, Some(&item));
        assert!(matches!(left_end, PairingPhase::Sent { .. }));
        let PairingPhase::Received { left_out, .. } = right_end else {
            panic!("not received: {right_end:?}")
        };
        assert_eq!(left_out, ["NODE_OPTIONS", "BASH_ENV"]);
    }

    #[test]
    fn the_receiver_may_turn_it_down() {
        let right = Script::answering("bob", &[Some(true), Some(false)]);
        let ((left_end, _), (right_end, right)) =
            run(Script::new("alice", Some(true)), right, Some(&password()));
        assert_eq!(left_end, failed(PairingFailure::Refused));
        assert_eq!(right_end, failed(PairingFailure::Turned));
        assert_eq!(*right.stored.lock().unwrap(), Vec::<Item>::new());
    }

    #[test]
    fn a_failed_save_reaches_the_sender() {
        let mut right = Script::new("bob", Some(true));
        right.store_fails = Some(PairingFailure::NotSaved);
        let ((left_end, _), (right_end, _)) =
            run(Script::new("alice", Some(true)), right, Some(&host()));
        assert_eq!(left_end, failed(PairingFailure::NotSaved));
        assert_eq!(right_end, failed(PairingFailure::NotSaved));
    }

    #[test]
    fn a_payload_other_than_the_offer_is_not_saved() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let receiver = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut session = accept(stream, &Identity::generate().unwrap()).unwrap();
            let mut side = Script::new("bob", Some(true));
            side.knows = true;
            (conversation(&mut session, &side, None), side)
        });
        // A sender that offers a password, then sends a host.
        let stream = TcpStream::connect(address).unwrap();
        let mut session = connect(stream, &Identity::generate().unwrap()).unwrap();
        let hello = Message::Hello {
            version: VERSION,
            name: "mallory".into(),
            known: true,
            own: None,
            features: Vec::new(),
        };
        session.send(&hello).unwrap();
        assert!(matches!(session.recv().unwrap(), Message::Hello { .. }));
        session
            .send(&Message::Offer {
                item: password().summary(),
            })
            .unwrap();
        assert_eq!(
            session.recv().unwrap(),
            Message::Reply {
                accepted: true,
                unsupported: false
            }
        );
        session.send(&Message::Payload { item: host() }).unwrap();
        assert_eq!(session.recv().unwrap(), Message::Received { saved: false });
        let (end, side) = receiver.join().unwrap();
        assert_eq!(end, failed(PairingFailure::Broken));
        assert_eq!(*side.stored.lock().unwrap(), Vec::<Item>::new());
    }

    #[test]
    fn a_key_other_than_the_offered_one_is_not_saved() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let receiver = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut session = accept(stream, &Identity::generate().unwrap()).unwrap();
            let mut side = Script::new("bob", Some(true));
            side.knows = true;
            (conversation(&mut session, &side, None), side)
        });
        let stream = TcpStream::connect(address).unwrap();
        let mut session = connect(stream, &Identity::generate().unwrap()).unwrap();
        session
            .send(&Message::Hello {
                version: VERSION,
                name: "mallory".into(),
                known: true,
                own: None,
                features: Vec::new(),
            })
            .unwrap();
        assert!(matches!(session.recv().unwrap(), Message::Hello { .. }));
        session
            .send(&Message::Offer {
                item: public_key().summary(),
            })
            .unwrap();
        assert_eq!(
            session.recv().unwrap(),
            Message::Reply {
                accepted: true,
                unsupported: false
            }
        );
        // Same name and comment, another key.
        let other = Item::PublicKey {
            name: "id_ed25519".into(),
            key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFR8U3VxsN3V7MFbnGqYVNCEWbAVE2k5oNMYoprkbtE8 aziz@mac".into(),
        };
        session.send(&Message::Payload { item: other }).unwrap();
        assert_eq!(session.recv().unwrap(), Message::Received { saved: false });
        let (end, side) = receiver.join().unwrap();
        assert_eq!(end, failed(PairingFailure::Broken));
        assert_eq!(*side.stored.lock().unwrap(), Vec::<Item>::new());
    }

    #[test]
    fn an_item_of_an_unknown_kind_is_answered_cleanly() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let receiver = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut session = accept(stream, &Identity::generate().unwrap()).unwrap();
            let mut side = Script::new("bob", Some(true));
            side.knows = true;
            (conversation(&mut session, &side, None), side)
        });
        // A later version offers a kind this one doesn't know.
        let stream = TcpStream::connect(address).unwrap();
        let mut session = connect(stream, &Identity::generate().unwrap()).unwrap();
        session
            .send(&Message::Hello {
                version: VERSION,
                name: "later".into(),
                known: true,
                own: None,
                features: vec!["chat/1".into(), "project/1".into()],
            })
            .unwrap();
        assert!(matches!(session.recv().unwrap(), Message::Hello { .. }));
        session
            .send(&Message::Offer {
                item: ItemSummary::Unknown,
            })
            .unwrap();
        assert_eq!(
            session.recv().unwrap(),
            Message::Reply {
                accepted: false,
                unsupported: true
            }
        );
        let (end, side) = receiver.join().unwrap();
        assert_eq!(end, failed(PairingFailure::Unsupported));
        assert!(
            side.shown
                .lock()
                .unwrap()
                .iter()
                .all(|(_, phase)| !matches!(phase, PairingPhase::Offered { .. })),
            "the user is never asked about it"
        );
    }

    /// An older version would save a server's password for the sender's
    /// alias whatever that leads to there: it gets it for no host.
    #[test]
    fn a_servers_password_goes_for_no_host_to_a_version_without_the_feature() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let older = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut session = accept(stream, &Identity::generate().unwrap()).unwrap();
            assert!(matches!(session.recv().unwrap(), Message::Hello { .. }));
            session
                .send(&Message::Hello {
                    version: VERSION,
                    name: "older".into(),
                    known: true,
                    own: None,
                    features: Vec::new(),
                })
                .unwrap();
            let Message::Offer { item: offered } = session.recv().unwrap() else {
                panic!("no offer")
            };
            session
                .send(&Message::Reply {
                    accepted: true,
                    unsupported: false,
                })
                .unwrap();
            let Message::Payload { item } = session.recv().unwrap() else {
                panic!("no payload")
            };
            session.send(&Message::Received { saved: true }).unwrap();
            (offered, item)
        });
        let login = |host: Option<&str>, server: Option<Server>| Item::Password {
            title: "prod DB".into(),
            username: "deploy".into(),
            password: "s3cret".into(),
            url: String::new(),
            notes: String::new(),
            otp: None,
            host: host.map(str::to_owned),
            server,
        };
        let item = login(
            Some("prod"),
            Some(Server {
                user: "deploy".into(),
                host_name: "10.0.4.12".into(),
                port: 22,
                proxy_jump: None,
            }),
        );
        let stream = TcpStream::connect(address).unwrap();
        let mut session = connect(stream, &Identity::generate().unwrap()).unwrap();
        let mut side = Script::new("alice", Some(true));
        side.knows = true;
        let end = conversation(
            &mut session,
            &side,
            Some(Purpose::Send {
                item: &item,
                to: None,
            }),
        );
        assert!(matches!(end, PairingPhase::Sent { .. }));
        let (offered, sent) = older.join().unwrap();
        let unbound = login(None, None);
        assert_eq!(offered, unbound.summary());
        assert_eq!(sent, unbound);
    }

    #[test]
    fn an_item_the_peer_cant_take_is_never_offered() {
        let personal = Item::Environment {
            project: String::new(),
            name: "dev".into(),
            notes: String::new(),
            variables: Vec::new(),
        };
        assert!(personal.requires().is_some());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        // A receiver of a version before features.
        let receiver = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut session = accept(stream, &Identity::generate().unwrap()).unwrap();
            session
                .send(&Message::Hello {
                    version: VERSION,
                    name: "older".into(),
                    known: true,
                    own: None,
                    features: Vec::new(),
                })
                .unwrap();
            assert!(matches!(session.recv().unwrap(), Message::Hello { .. }));
            // The sender hangs up without offering anything.
            session.recv().is_err()
        });
        let stream = TcpStream::connect(address).unwrap();
        let mut session = connect(stream, &Identity::generate().unwrap()).unwrap();
        let mut side = Script::new("alice", Some(true));
        side.knows = true;
        let end = conversation(
            &mut session,
            &side,
            Some(Purpose::Send {
                item: &personal,
                to: None,
            }),
        );
        drop(session);
        assert_eq!(end, failed(PairingFailure::PeerUnsupported));
        assert!(receiver.join().unwrap());
    }
}
