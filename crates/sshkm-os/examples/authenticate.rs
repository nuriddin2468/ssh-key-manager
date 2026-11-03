//! Shows the Touch ID / Windows Hello prompt once and prints the result.
//!
//! ```sh
//! cargo run -p sshkm-os --example authenticate                  # prompt
//! cargo run -p sshkm-os --example authenticate -- "unlock the vault"
//! cargo run -p sshkm-os --example authenticate -- --check       # no prompt
//! ```
//!
//! `--check` only prints whether biometrics are available.

use std::process::ExitCode;

use sshkm_os::biometrics;

fn main() -> ExitCode {
    let arg = std::env::args().nth(1);
    println!("availability: {:?}", biometrics::availability());
    if arg.as_deref() == Some("--check") {
        return ExitCode::SUCCESS;
    }

    let reason = arg.unwrap_or_else(|| "test biometric unlock".to_owned());
    match biometrics::authenticate(&reason) {
        Ok(()) => {
            println!("confirmed");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("not confirmed: {err} ({})", err.code());
            ExitCode::FAILURE
        }
    }
}
