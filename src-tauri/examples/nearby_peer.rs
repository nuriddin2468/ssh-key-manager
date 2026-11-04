//! A stand-in for another computer on the network, to try Nearby with one
//! machine: it shows itself as the app does when asked, waits for the app to
//! pair with it, prints the pairing code and asks on the terminal whether
//! the app shows the same one. It saves nothing.
//!
//! ```text
//! cargo run -p sshkm-app --example nearby_peer -- "Test peer"
//! ```
//!
//! Then open Nearby in the app (`pnpm app:dev`): the peer is listed under
//! "On this network". It pairs once and exits.

use std::io::{self, BufRead, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::time::Duration;

use mdns_sd::{ServiceDaemon, ServiceInfo};
use sshkm_app_lib::nearby::SERVICE_TYPE;
use sshkm_app_lib::nearby::pairing::{PairingFailure, PairingPhase, Side, converse};
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
        println!("Paired with {name} ({peer}). Nothing was saved: this is a test peer.");
        Ok(())
    }

    fn show(&self, peer: Option<&str>, phase: &PairingPhase) {
        let peer = peer.unwrap_or("the app");
        match phase {
            PairingPhase::Compare { code } => {
                println!("Pairing code: {} {}", &code[..3], &code[3..]);
                print!("Does {peer} show the same code? [y/n] ");
                let _ = io::stdout().flush();
            }
            PairingPhase::Waiting { .. } => println!("Waiting for {peer} to confirm…"),
            _ => {}
        }
    }

    fn answer(&self, _wait: Duration) -> Result<Option<bool>, PairingFailure> {
        // Blocks until a line comes; the app's "no" then shows up after it.
        let mut line = String::new();
        io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|_| PairingFailure::Cancelled)?;
        Ok(Some(line.trim().eq_ignore_ascii_case("y")))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let name = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "Test peer".to_owned());
    let identity = Identity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    let port = listener.local_addr()?.port();

    let daemon = ServiceDaemon::new()?;
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
    println!("Shown as \"{name}\" on port {port}. Open Nearby in the app and pair.");

    let (stream, from) = listener.accept()?;
    println!("{from} connected.");
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut session = p2p::accept(stream, &identity)?;
    let end = converse(&mut session, &Terminal { name });
    println!("Result: {end:?}");
    let _ = daemon.shutdown();
    Ok(())
}
