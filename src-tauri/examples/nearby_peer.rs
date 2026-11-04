//! A stand-in for another computer on the network, to try Nearby with one
//! machine. It saves nothing and answers on the terminal.
//!
//! ```text
//! cargo run -p sshkm-app --example nearby_peer -- "Test peer"
//! cargo run -p sshkm-app --example nearby_peer -- "Test peer" --send password
//! cargo run -p sshkm-app --example nearby_peer -- "Test peer" --send host
//! ```
//!
//! Without `--send` it shows itself as the app does after "Show for 10
//! minutes" and waits: pair with it or send it something from the app, and
//! it prints the pairing code and what it got. With `--send` it looks for the
//! app (click "Show for 10 minutes" there first) and sends it a sample login
//! or host. It does one exchange and exits.

use std::io::{self, BufRead, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use sshkm_app_lib::nearby::SERVICE_TYPE;
use sshkm_app_lib::nearby::pairing::{PairingFailure, PairingPhase, Side};
use sshkm_app_lib::nearby::transfer::exchange;
use sshkm_core::p2p::protocol::{HostKey, Item, ItemSummary};
use sshkm_core::p2p::{self, Identity, PeerKey};

struct Terminal {
    name: String,
}

impl Side for Terminal {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn knows(&self, _: PeerKey) -> Result<bool, PairingFailure> {
        Ok(false)
    }

    fn save(&self, peer: PeerKey, name: &str) -> Result<(), PairingFailure> {
        println!("Paired with {name} ({peer}).");
        Ok(())
    }

    fn show(&self, peer: Option<&str>, phase: &PairingPhase) {
        let peer = peer.unwrap_or("the app");
        match phase {
            PairingPhase::Compare { code } => {
                println!("Pairing code: {} {}", &code[..3], &code[3..]);
                ask(&format!("Does {peer} show the same code?"));
            }
            PairingPhase::Waiting { .. } => println!("Waiting for {peer} to confirm…"),
            PairingPhase::Offering { item } => {
                println!("Offered {}; waiting for the app to accept…", describe(item));
            }
            PairingPhase::Offered { item } => {
                ask(&format!("The app sends {}. Accept?", describe(item)));
            }
            _ => {}
        }
    }

    fn answer(&self, _wait: Duration) -> Result<Option<bool>, PairingFailure> {
        // Blocks until a line comes; a "no" from the app shows up after it.
        let mut line = String::new();
        io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|_| PairingFailure::Cancelled)?;
        Ok(Some(line.trim().eq_ignore_ascii_case("y")))
    }

    fn store(&self, item: &Item) -> Result<(String, bool), PairingFailure> {
        match item {
            Item::Password {
                title,
                username,
                password,
                otp,
                ..
            } => {
                println!(
                    "Got the login \"{title}\" for {username}: a password of {} characters{}.",
                    password.chars().count(),
                    if otp.is_some() {
                        " and a 2FA secret"
                    } else {
                        ""
                    }
                );
                Ok((title.clone(), false))
            }
            Item::Host {
                alias, host_keys, ..
            } => {
                println!(
                    "Got the host {alias} ({}) with {} server key(s).",
                    match item.summary() {
                        ItemSummary::Host { address, .. } => address,
                        ItemSummary::Password { .. } => String::new(),
                    },
                    host_keys.len()
                );
                Ok((alias.clone(), false))
            }
        }
    }
}

fn ask(question: &str) {
    print!("{question} [y/n] ");
    let _ = io::stdout().flush();
}

fn describe(item: &ItemSummary) -> String {
    match item {
        ItemSummary::Password { title, .. } => format!("the login \"{title}\""),
        ItemSummary::Host { alias, address, .. } => format!("the host {alias} ({address})"),
    }
}

fn sample(kind: &str, name: &str) -> Item {
    if kind == "host" {
        Item::Host {
            alias: "test-peer-host".into(),
            host_name: Some("192.0.2.10".into()),
            user: Some("deploy".into()),
            port: Some(2222),
            proxy_jump: None,
            host_keys: vec![HostKey {
                key_type: "ssh-ed25519".into(),
                key: "AAAAC3NzaC1lZDI1NTE5AAAAIBIZFNq0hlvHGZ/oas65Ba4jkcFEy3dX/aRZy70M73oL".into(),
            }],
        }
    } else {
        Item::Password {
            title: format!("Test login from {name}"),
            username: "tester".into(),
            password: "correct horse battery staple".into(),
            url: "https://example.com".into(),
            notes: "Sent by the nearby_peer example.".into(),
            otp: None,
            host: None,
        }
    }
}

/// The app's address, once it shows itself on the network.
fn find_app(daemon: &ServiceDaemon) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let events = daemon.browse(SERVICE_TYPE)?;
    let deadline = Instant::now() + Duration::from_secs(60);
    println!("Looking for the app: click \"Show for 10 minutes\" in Nearby…");
    while Instant::now() < deadline {
        if let Ok(ServiceEvent::ServiceResolved(service)) =
            events.recv_timeout(Duration::from_secs(1))
            && let Some(ip) = service
                .get_addresses_v4()
                .into_iter()
                .find(|ip| !ip.is_unspecified())
        {
            println!(
                "Found {} at {ip}:{}.",
                service.get_property_val_str("name").unwrap_or("?"),
                service.port
            );
            return Ok(SocketAddr::new(ip.into(), service.port));
        }
    }
    Err("the app did not show up within a minute".into())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let send = args.iter().position(|arg| arg == "--send").map(|i| {
        args.get(i + 1)
            .cloned()
            .unwrap_or_else(|| "password".into())
    });
    let name = args
        .iter()
        .find(|arg| !arg.starts_with("--") && Some(*arg) != send.as_ref())
        .cloned()
        .unwrap_or_else(|| "Test peer".into());
    let identity = Identity::generate()?;
    let daemon = ServiceDaemon::new()?;
    let side = Terminal { name: name.clone() };

    let end = if let Some(kind) = send {
        let address = find_app(&daemon)?;
        let stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut session = p2p::connect(stream, &identity)?;
        exchange(&mut session, &side, true, Some(&sample(&kind, &name)))
    } else {
        let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        let port = listener.local_addr()?.port();
        let instance = format!("test-peer-{port}");
        let properties = [("v", "1"), ("name", name.as_str())];
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            &instance,
            &format!("{instance}.local."),
            (),
            port,
            &properties[..],
        )?
        .enable_addr_auto();
        daemon.register(info)?;
        println!(
            "Shown as \"{name}\" on port {port}. Pair with it, or send it something, in Nearby."
        );
        let (stream, from) = listener.accept()?;
        println!("{from} connected.");
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut session = p2p::accept(stream, &identity)?;
        exchange(&mut session, &side, false, None)
    };
    println!("Result: {end:?}");
    let _ = daemon.shutdown();
    Ok(())
}
