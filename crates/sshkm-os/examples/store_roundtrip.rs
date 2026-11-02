//! Stores, reads back and deletes a test secret in the OS credential store.
//!
//! ```sh
//! cargo run -p sshkm-os --example store_roundtrip
//! ```
//!
//! The item is named `dev.sshkeymanager.sshkm-os.example` / `store-roundtrip`
//! and is gone again when the program succeeds. On macOS the keychain may ask
//! for permission; on Linux a Secret Service (GNOME Keyring, KDE Wallet, …) must
//! be running.

use std::process::ExitCode;

use sshkm_os::{ExposeSecret, SecretString, secret_store};

const SERVICE: &str = "dev.sshkeymanager.sshkm-os.example";
const ACCOUNT: &str = "store-roundtrip";

fn main() -> ExitCode {
    match round_trip() {
        Ok(()) => {
            println!("ok: stored, read back and deleted");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("failed: {err} ({})", err.code());
            ExitCode::FAILURE
        }
    }
}

fn round_trip() -> sshkm_os::Result<()> {
    let secret = SecretString::from("example secret ✓");
    secret_store::set(SERVICE, ACCOUNT, &secret)?;
    println!("stored");

    let read = secret_store::get(SERVICE, ACCOUNT)?;
    let matches = read.is_some_and(|read| read.expose_secret() == secret.expose_secret());
    println!(
        "read back: {}",
        if matches { "same value" } else { "MISMATCH" }
    );

    secret_store::delete(SERVICE, ACCOUNT)?;
    let gone = secret_store::get(SERVICE, ACCOUNT)?.is_none();
    println!("deleted: {}", if gone { "yes" } else { "NO" });

    if matches && gone {
        Ok(())
    } else {
        Err(sshkm_os::Error::Failed(
            "the round trip did not match".into(),
        ))
    }
}
